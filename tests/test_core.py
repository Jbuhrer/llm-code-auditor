"""Workspace, units, config, pricing, and the agent loop, all offline."""
from __future__ import annotations
from dataclasses import replace

import pytest

from auditor.agent import Auditor
from auditor.config import AuditConfig, PRESETS, parse_evidence, ValidationConfig
from auditor.pricing import cost_usd
from auditor.tools import Workspace, tool_schemas
from auditor import units as units_mod
from auditor.units import build_units, pack_context, est_tokens
from tests.conftest import FakeBackend, reply, report


# ------------------------------------------------------------ workspace

def test_safe_rejects_sibling_prefix(tmp_path):
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo2").mkdir()
    (tmp_path / "repo2" / "secret.txt").write_text("x")
    ws = Workspace(str(tmp_path / "repo"))
    with pytest.raises(ValueError):
        ws._safe("../repo2/secret.txt")
    assert "escapes" in __import__("auditor.tools").tools.dispatch(
        ws, "read_file", {"rel": "../repo2/secret.txt"})


def test_grep_relative_posix_and_skips_hidden(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("os.system(cmd)\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "x.py").write_text("os.system(cmd)\n")
    ws = Workspace(str(tmp_path))
    out = ws.grep(r"os\.system")
    assert out.splitlines() == ["src/a.py:1:os.system(cmd)"]
    assert ws.source_files() == ["src/a.py"]


def test_grep_bad_regex_falls_back_to_literal(tmp_path):
    (tmp_path / "a.py").write_text("x = foo(\n")
    assert "a.py:1" in Workspace(str(tmp_path)).grep("foo(")


def test_grep_glob_python_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr("auditor.tools.shutil.which", lambda name: None)  # no ripgrep
    (tmp_path / "top.java").write_text("exec(x)\n")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "deep.java").write_text("exec(x)\n")
    (tmp_path / "pkg" / "deep.py").write_text("exec(x)\n")
    ws = Workspace(str(tmp_path))
    assert len(ws.grep("exec").splitlines()) == 3
    hits = ws.grep("exec", "**/*.java").splitlines()
    assert sorted(h.split(":")[0] for h in hits) == ["pkg/deep.java", "top.java"]
    assert ws.grep("exec", "*.py").startswith("pkg/deep.py")


def test_toolset_follows_static_analysis_toggle():
    names = lambda ts: {t["name"] for t in ts}
    assert "run_semgrep" in names(tool_schemas(True, True))
    assert "run_semgrep" not in names(tool_schemas(True, False))
    assert names(tool_schemas(False, True)) == {"report_findings"}


# ------------------------------------------------------------ units

def test_testcase_units_group_split_files(tmp_path):
    for n in ("CWE89_X__a_51a.java", "CWE89_X__a_51b.java", "CWE89_X__b_01.java"):
        (tmp_path / n).write_text("class A {}\n")
    units = build_units(Workspace(str(tmp_path)), "testcase")
    assert sorted(len(u.targets) for u in units) == [1, 2]
    assert units_mod.testcase_key("d/CWE89_X__a_51b.java") == "d/CWE89_X__a_51"


def test_pack_context_respects_budget_and_flags_truncation(tmp_path):
    (tmp_path / "big.py").write_text("import helper\n" + "x = 1\n" * 2000)
    (tmp_path / "helper.py").write_text("def helper(): pass\n")
    (tmp_path / "caller.py").write_text("import big\n")
    (tmp_path / "unrelated.py").write_text("y = 2\n")
    ws = Workspace(str(tmp_path))
    unit = [u for u in build_units(ws, "file") if u.id == "big.py"][0]
    text, used, inc, trunc = pack_context(ws, unit, 500, include_related=True)
    assert trunc and used <= 500 and est_tokens(text) <= 520
    text, used, inc, trunc = pack_context(ws, unit, 100000, include_related=True)
    # callee first, then caller; the unrelated same-dir file is never packed
    assert not trunc and inc == ["big.py", "helper.py", "caller.py"]


def test_limit_spreads_across_cwes():
    from eval.experiment import spread_limit
    from auditor.units import Unit
    units = [Unit(f"CWE{c}_x_{i:02d}") for c in (23, 78, 89) for i in range(5)]
    assert [u.id[:5] for u in spread_limit(units, 4)] == ["CWE23", "CWE78", "CWE89", "CWE23"]


# ------------------------------------------------------------ config

def test_presets_ladder():
    assert PRESETS["C0"].audit.exploration == "fixed"
    assert not PRESETS["C0"].audit.static_analysis
    assert PRESETS["C3"].audit.cell() == PRESETS["C4"].audit.cell()  # shared audit pass
    assert PRESETS["C4"].validation.enabled
    assert parse_evidence("all") == ("path", "sanitizer", "conditions", "poc")
    assert ValidationConfig(True, ("path", "poc")).name() == "val-path+poc"
    with pytest.raises(ValueError):
        parse_evidence("vibes")


def test_pricing():
    assert cost_usd("claude-opus-5-5", {"input": 1_000_000, "output": 0}) == 4.0
    assert cost_usd("claude-opus-5-5", {"cache_write": 1_000_000}) == 5.0
    assert cost_usd("mystery-model", {"input": 5}) is None
    assert cost_usd("openai-compat:qwen", {"input": 5}) == 0.0


# ------------------------------------------------------------ agent loop

def _cfg(**kw):
    return replace(AuditConfig(), **kw)


def test_explore_reads_then_reports(toy_repo):
    root, _ = toy_repo
    script = [reply(calls=[("t1", "read_file", {"rel": "app.py"})]),
              report([{"bug_class": "sqli", "file": "app.py", "line": 6, "cwe": "CWE-89",
                       "confidence": 0.9}])]
    fb = FakeBackend(script)
    a = Auditor(Workspace(str(root)), _cfg(static_analysis=False), fb)
    rec = a.run_unit(build_units(a.ws, "file")[0])
    assert rec["reported"] and rec["turns"] == 2 and rec["error"] is None
    assert rec["findings"][0]["file"] == "app.py" and rec["findings"][0]["unit"] == "app.py"
    assert rec["usage"]["input"] == 200 and rec["cost_usd"] > 0
    # the read went through and was answered
    kind, results, _ = fb.conversations[0].sent[1]
    assert kind == "tool_results" and "conn.execute" in results[0][1]
    # no semgrep tool offered when static analysis is off
    assert "run_semgrep" not in {t["name"] for t in fb.conversations[0].tools}


def test_explore_budget_exhaustion(toy_repo):
    root, _ = toy_repo
    script = [reply(calls=[("t1", "grep", {"pattern": "."})]),
              reply(calls=[("t2", "read_file", {"rel": "app.py"})]),
              report([])]
    fb = FakeBackend(script)
    a = Auditor(Workspace(str(root)), _cfg(static_analysis=False, context_budget=80), fb)
    rec = a.run_unit(build_units(a.ws, "file")[0])
    assert rec["budget_exhausted"] and rec["context_tokens"] <= 80
    second = fb.conversations[0].sent[2][1][0][1]
    assert "budget exhausted" in second


def test_explore_refusal_and_no_report(toy_repo):
    root, _ = toy_repo
    ws = Workspace(str(root))
    rec = Auditor(ws, _cfg(), FakeBackend([reply(stop="refusal")])).run_unit(
        build_units(ws, "file")[0])
    assert rec["refused"] and not rec["reported"]
    # model never calls report_findings: loop ends at max_turns, nothing invented
    fb = FakeBackend(lambda conv: reply(text="thinking...", stop="end_turn"))
    rec = Auditor(ws, _cfg(max_turns=3), fb).run_unit(build_units(ws, "file")[0])
    assert not rec["reported"] and rec["turns"] == 3 and rec["findings"] == []


def test_explore_disallowed_tool_is_refused(toy_repo):
    root, _ = toy_repo
    ws = Workspace(str(root))
    fb = FakeBackend([reply(calls=[("t1", "run_semgrep", {})]), report([])])
    Auditor(ws, _cfg(static_analysis=False), fb).run_unit(build_units(ws, "file")[0])
    assert "not available" in fb.conversations[0].sent[1][1][0][1]


def test_api_error_is_recorded_not_raised(toy_repo):
    root, _ = toy_repo
    ws = Workspace(str(root))

    def boom(conv):
        raise RuntimeError("overloaded")
    rec = Auditor(ws, _cfg(), FakeBackend(boom)).run_unit(build_units(ws, "file")[0])
    assert "overloaded" in rec["error"]


def test_fixed_mode_packs_context_and_nudges_once(toy_repo):
    root, _ = toy_repo
    ws = Workspace(str(root))
    fb = FakeBackend([reply(text="I think there is SQLi", stop="end_turn"),
                      report([{"bug_class": "cmdi", "file": "app.py", "line": 10,
                               "cwe": "CWE-78", "confidence": 0.8}])])
    rec = Auditor(ws, _cfg(exploration="fixed", static_analysis=False), fb).run_unit(
        build_units(ws, "file")[0])
    conv = fb.conversations[0]
    assert [t["name"] for t in conv.tools] == ["report_findings"]
    assert "conn.execute" in conv.sent[0][1]          # code packed up front
    assert "Semgrep" not in conv.sent[0][1]
    assert rec["turns"] == 2 and len(rec["findings"]) == 1


def test_out_of_target_findings_dropped(tmp_path):
    (tmp_path / "a.py").write_text("x=1\n")
    (tmp_path / "b.py").write_text("y=2\n")
    ws = Workspace(str(tmp_path))
    unit = [u for u in build_units(ws, "file") if u.id == "a.py"][0]
    fb = FakeBackend([report([{"bug_class": "sqli", "file": "b.py", "line": 1,
                               "cwe": "CWE-89", "confidence": 1}])])
    rec = Auditor(ws, _cfg(exploration="fixed", static_analysis=False), fb).run_unit(unit)
    assert rec["findings"] == [] and rec["dropped_out_of_target"] == 1
