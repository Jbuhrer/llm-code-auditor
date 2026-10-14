"""Regression tests for bugs found while building the factorial harness."""
from __future__ import annotations
from dataclasses import replace
from types import SimpleNamespace as NS

import pytest

from auditor.agent import Auditor, FatalBackendError
from auditor.config import AuditConfig
from auditor.llm import OpenAICompatBackend
from auditor.sarif import sarif_to_findings
from auditor.tools import Workspace
from auditor.units import build_units, testcase_stem
from eval.metrics import testcase_id
from tests.conftest import FakeBackend


@pytest.mark.parametrize("stem", [
    "CWE78_X__connect_tcp_81a", "CWE78_X__connect_tcp_81_bad",
    "CWE78_X__connect_tcp_81_base", "CWE78_X__connect_tcp_81_goodG2B",
    "CWE78_X__connect_tcp_81_goodB2G"])
def test_81_family_is_one_testcase(stem):
    assert testcase_stem(stem) == "CWE78_X__connect_tcp_81"
    assert testcase_id(stem + ".java") == "CWE78_X__connect_tcp_81"


def test_plain_testcase_untouched():
    assert testcase_stem("CWE89_X__Environment_01") == "CWE89_X__Environment_01"
    assert testcase_stem("CWE89_X__Environment_54e") == "CWE89_X__Environment_54"


def test_sarif_uses_rule_cwe_tags_for_class():
    sarif = {"runs": [{
        "tool": {"driver": {"name": "Semgrep", "rules": [
            {"id": "java.lang.security.audit.tainted-cmd-from-http-request",
             "properties": {"tags": ["CWE-78: OS Command Injection"]}},
            {"id": "java.weird.rule.name", "properties": {"tags": ["CWE-89: SQLi"]}}]}},
        "results": [
            {"ruleId": "java.lang.security.audit.tainted-cmd-from-http-request",
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "A.java"},
                                                 "region": {"startLine": 3}}}]},
            {"ruleId": "java.weird.rule.name",
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "B.java"},
                                                 "region": {"startLine": 9}}}]}]}]}
    fs = sarif_to_findings(sarif)
    assert [(f["bug_class"], f["cwe"]) for f in fs] == [("cmdi", "CWE-78"), ("sqli", "CWE-89")]


def test_auth_error_stops_the_pass(toy_repo):
    root, _ = toy_repo
    ws = Workspace(str(root))

    class AuthenticationError(Exception):
        pass

    def bad_key(conv):
        raise AuthenticationError("invalid x-api-key")
    with pytest.raises(FatalBackendError):
        Auditor(ws, AuditConfig(), FakeBackend(bad_key)).run_units(
            build_units(ws, "file"), workers=1, log=lambda m: None)


def test_openai_compat_translation():
    """Tool schemas, tool calls, and tool results round-trip through the
    OpenAI-compatible backend used for open-weight models."""
    sent = []

    def create(**kw):
        sent.append({**kw, "messages": list(kw["messages"])})  # snapshot, like the SDK
        if len(sent) == 1:
            msg = NS(content=None, tool_calls=[NS(id="c1", function=NS(
                name="read_file", arguments='{"rel": "app.py"}'))])
            fin = "tool_calls"
        else:
            msg = NS(content="done", tool_calls=None)
            fin = "stop"
        return NS(choices=[NS(message=msg, finish_reason=fin)],
                  usage=NS(prompt_tokens=10, completion_tokens=5))

    client = NS(chat=NS(completions=NS(create=create)))
    b = OpenAICompatBackend("qwen", temperature=0.0, client=client)
    tools = [{"name": "read_file", "description": "d",
              "input_schema": {"type": "object", "properties": {}}}]
    conv = b.conversation("sys", tools)
    conv.user("hi")
    r = conv.step(100)
    assert r.stop_reason == "tool_use" and r.tool_calls[0].input == {"rel": "app.py"}
    assert sent[0]["tools"][0]["function"]["name"] == "read_file"
    assert sent[0]["temperature"] == 0.0
    conv.tool_results([("c1", "file text")], note="hurry up")
    r = conv.step(100)
    roles = [m["role"] for m in sent[1]["messages"]]
    assert roles == ["system", "user", "assistant", "tool", "user"]
    assert r.stop_reason == "end_turn" and r.usage["input"] == 10


def test_anthropic_backend_request_shape():
    """Caching only on multi-turn conversations, effort passed, no empty system."""
    from auditor.llm import AnthropicBackend
    sent = []

    def create(**kw):
        sent.append(kw)
        return NS(content=[NS(type="text", text="ok")], stop_reason="end_turn",
                  usage=NS(input_tokens=3, output_tokens=2, cache_read_input_tokens=None,
                           cache_creation_input_tokens=7))

    b = AnthropicBackend("claude-opus-5-5", effort="medium",
                         client=NS(messages=NS(create=create)))
    c = b.conversation("", [], cache=False)
    c.user("x")
    r = c.step(100)
    assert "system" not in sent[0] and "cache_control" not in sent[0]
    assert "temperature" not in sent[0] and sent[0]["output_config"] == {"effort": "medium"}
    assert r.usage == {"input": 3, "output": 2, "cache_read": 0, "cache_write": 7}
    c = b.conversation("sys", [{"name": "t"}], cache=True)
    c.user("x")
    c.step(100)
    assert sent[1]["cache_control"] == {"type": "ephemeral"} and sent[1]["system"] == "sys"


def test_cross_file_case_labels_the_sink_not_the_source(tmp_path):
    """Juliet flags only the source line for _66-style cross-file cases; the
    loader must label the badSink call site in the b file instead."""
    from benchmarks.juliet_loader import bad_side_sinks, sink_lines
    b = tmp_path / "CWE78_X__Environment_66b.java"
    b.write_text("public class B {\n"
                 "    public void badSink(String data) throws Throwable {\n"
                 "        // exec is the sink here\n"
                 "        Process p = Runtime.getRuntime().exec(\"ls \" + data);\n"
                 "    }\n"
                 "    public void goodG2BSink(String data) throws Throwable {\n"
                 "        Process p = Runtime.getRuntime().exec(\"ls \" + data);\n"
                 "    }\n"
                 "}\n")
    assert bad_side_sinks(b, "cmdi") == [4]
    a = tmp_path / "CWE78_X__Environment_66a.java"
    a.write_text("class A {\n  void bad() {\n    data = System.getenv(\"ADD\");\n  }\n}\n")
    assert sink_lines(a, [3], "cmdi") == []


def test_threat_model_is_in_every_prompt():
    from auditor.prompts import system_prompt, validator_prompt, THREAT_MODELS
    for tm, text in THREAT_MODELS.items():
        assert text in system_prompt(["sqli"], True, True, 1000, tm)
        assert text in system_prompt(["sqli"], False, False, 1000, tm)
        assert text in validator_prompt("{}", "code", ("poc",), tm)
    with pytest.raises(ValueError):
        system_prompt(["sqli"], threat_model="vibes")


def test_validator_sees_whole_unit_not_a_window(tmp_path):
    """Pilot bug: the validator got +-60 lines around the sink, so on split cases
    it never saw the source in the _a file and rejected real bugs."""
    from auditor.config import ValidationConfig
    from auditor.validate import validate_one
    (tmp_path / "X_66a.java").write_text("class A { void bad() { data = System.getenv(\"ADD\"); } }\n")
    (tmp_path / "X_66b.java").write_text("class B {\n" + "  // filler\n" * 200
                                         + "  void badSink() { Runtime.getRuntime().exec(data); }\n}\n")
    seen = []

    def script(conv):
        seen.append(conv.sent[0][1])
        from tests.conftest import reply
        return reply(text='{"verdict": "confirmed"}', stop="end_turn")

    ws = Workspace(str(tmp_path))
    f = {"bug_class": "cmdi", "file": "X_66b.java", "line": 202}
    rec = validate_one(FakeBackend(script), ws, f, ValidationConfig(True, ()),
                       "all-external", ["X_66a.java", "X_66b.java"])
    assert rec["confirmed"] and not rec["window_fallback"]
    assert 'System.getenv("ADD")' in seen[0] and "exec(data)" in seen[0]
    assert seen[0].index("X_66b.java") < seen[0].index("X_66a.java")   # finding's file first
    # over budget: the finding's own file falls back to a window, never dropped
    rec = validate_one(FakeBackend(script), ws, f, ValidationConfig(True, (), window=5,
                       context_budget=50), "all-external", ["X_66a.java", "X_66b.java"])
    assert rec["window_fallback"] and "exec(data)" in seen[1]


def test_budget_cap_stops_saves_and_resumes(tmp_path, monkeypatch):
    import json
    import sys
    import eval.experiment as ex
    from tests.conftest import report
    repo = tmp_path / "repo"
    repo.mkdir()
    for n in ("a", "b", "c"):
        (repo / f"{n}.py").write_text("x = 1\n")
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps([{"file": "a.py", "line": 1, "bug_class": "sqli"}]))
    out = tmp_path / "res"
    calls = []

    def backend(*_a, **_k):
        def script(conv):
            calls.append(1)
            return report([])   # 100 in / 20 out on opus = $0.0008 per unit
        return FakeBackend(script)

    monkeypatch.setattr(ex, "make_backend", backend)
    base = ["experiment.py", str(repo), str(labels), "--configs", "C0", "--runs", "1",
            "--unit", "file", "--no-baseline", "--workers", "1", "--skip-preflight",
            "--out", str(out)]
    monkeypatch.setattr(sys, "argv", base + ["--max-usd", "0.001"])
    with pytest.raises(SystemExit) as e:
        ex.main()
    assert "budget reached" in str(e.value)
    run = out / "claude-opus-5-5" / "fixed-nosa" / "run1"
    assert not (run / "audit.json").exists()
    assert len((run / "audit.partial.jsonl").read_text().splitlines()) == 2
    assert len(calls) == 2

    monkeypatch.setattr(sys, "argv", base)   # resume, no cap
    ex.main()
    assert len(calls) == 3                   # only the unfinished unit was paid for
    assert len(json.loads((run / "audit.json").read_text())["units"]) == 3
    assert not (run / "audit.partial.jsonl").exists()
