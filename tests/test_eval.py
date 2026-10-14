"""Validator, Juliet function scoring, stats, and an end-to-end offline experiment."""
from __future__ import annotations
import json
import sys

import pytest

from auditor.config import ValidationConfig, ALL_EVIDENCE
from auditor.tools import Workspace
from auditor.validate import extract_json, validate_one, check_path_steps
from eval.juliet_functions import function_spans, region_of, locate
from eval.metrics import score, default_mode
from eval.stats import mcnemar, bootstrap_ci, majority, _binom_two_sided
from tests.conftest import FakeBackend, reply, JULIET_FILE

JF = "CWE78_OS_Command_Injection__Environment_01.java"


# ------------------------------------------------------------ validator

def test_extract_json_tolerates_prose_and_braces_in_strings():
    t = 'Sure.\n```json\n{"verdict": "confirmed", "poc": "a}b{c"}\n``` done'
    assert extract_json(t) == {"verdict": "confirmed", "poc": "a}b{c"}
    assert extract_json("no json here") is None


def test_path_quotes_checked_against_file(juliet_repo):
    repo, _ = juliet_repo
    ws = Workspace(str(repo))
    good = [{"file": JF, "line": 11, "quote": 'data = System.getenv("ADD");'},
            {"file": JF, "line": 14, "quote": "Runtime.getRuntime().exec(osCommand + data)"}]
    assert check_path_steps(ws, good, JF) == (True, 1.0)
    made_up = good + [{"file": JF, "line": 14, "quote": "sanitize(data)"}]
    ok, frac = check_path_steps(ws, made_up, JF)
    assert not ok and frac == pytest.approx(0.667, abs=0.01)


def _verdict(**kw):
    v = {"verdict": "confirmed", "reason": "r", "adjusted_confidence": 0.9,
         "path_steps": [{"file": JF, "line": 14,
                         "quote": "Runtime.getRuntime().exec(osCommand + data)"}],
         "sanitizers": [], "sanitizer_adequate": None,
         "path_conditions": [], "conditions_satisfiable": True, "poc": "; rm -rf /tmp/x"}
    v.update(kw)
    return reply(text=json.dumps(v), stop="end_turn")


@pytest.mark.parametrize("override,evidence,confirmed,why", [
    ({}, ALL_EVIDENCE, True, []),
    ({"poc": ""}, ALL_EVIDENCE, False, ["poc"]),
    ({"poc": ""}, ("path",), True, []),              # poc not required -> passes
    ({"sanitizer_adequate": True}, ("sanitizer",), False, ["sanitizer"]),
    ({"conditions_satisfiable": False}, ("conditions",), False, ["conditions"]),
    ({"verdict": "rejected"}, (), False, ["verdict"]),
])
def test_evidence_checks(juliet_repo, override, evidence, confirmed, why):
    repo, _ = juliet_repo
    f = {"bug_class": "cmdi", "file": JF, "line": 14, "cwe": "CWE-78"}
    rec = validate_one(FakeBackend([_verdict(**override)]), Workspace(str(repo)), f,
                       ValidationConfig(True, evidence))
    assert rec["confirmed"] is confirmed and rec["rejected_by"] == why


def test_validator_failures(juliet_repo):
    repo, _ = juliet_repo
    ws = Workspace(str(repo))
    f = {"bug_class": "cmdi", "file": JF, "line": 14}
    cfg = ValidationConfig(True, ())
    assert validate_one(FakeBackend([reply("nope", stop="end_turn")]), ws, f, cfg
                        )["rejected_by"] == ["unparseable"]
    assert validate_one(FakeBackend([reply(stop="refusal")]), ws, f, cfg)["refused"]
    assert validate_one(FakeBackend([]), ws, {"file": "ghost.java", "line": 1}, cfg
                        )["rejected_by"] == ["file_not_found"]

    def boom(c):
        raise TimeoutError("slow")
    assert "slow" in validate_one(FakeBackend(boom), ws, f, cfg)["error"]


# ------------------------------------------------------------ Juliet functions

def test_function_spans_juliet():
    spans = {n: (s, e) for n, s, e in function_spans(JULIET_FILE)}
    assert spans["bad"] == (7, 16)
    assert spans["goodG2B"][0] == 24 and spans["goodG2B"][1] >= 31
    assert "main" in spans


def test_function_spans_ignore_braces_in_strings_and_comments():
    src = 'class A {\n  void bad() {\n    String s = "}{";\n    // }\n    x();\n  }\n}\n'
    assert function_spans(src) == [("bad", 2, 6)]


def test_function_spans_c_style():
    src = ("void CWE78_x_54b_badSink(char * data)\n{\n  system(data);\n}\n\n"
           "static void goodG2B()\n{\n  if (x) { y(); }\n}\n")
    assert [n for n, _, _ in function_spans(src)] == ["CWE78_x_54b_badSink", "goodG2B"]


@pytest.mark.parametrize("name,stem,region", [
    ("bad", "X_01", "bad"), ("badSink", "X_51b", "bad"), ("goodB2G", "X_01", "good"),
    ("goodG2BSink", "X", "good"), ("CWE78_x_01_bad", "X", "bad"), ("main", "X_01", "other"),
    ("action", "CWE89_x_81_bad", "bad"), ("action", "CWE89_x_81_goodG2B", "good"),
])
def test_region_of(name, stem, region):
    assert region_of(name, stem) == region


# ------------------------------------------------------------ scoring

def test_function_scoring_sees_good_side_fp(juliet_repo):
    repo, labels = juliet_repo
    bad = {"bug_class": "OS Command Injection", "file": JF, "line": 14, "cwe": "CWE-78"}
    good = {"bug_class": "cmdi", "file": JF, "line": 30, "cwe": "CWE-78"}
    s = score([bad, good], labels, "function", repo)
    assert (s["tp"], s["fp"], s["fn"]) == (1, 1, 0)
    assert s["precision"] == 0.5 and s["localization"] == 1.0
    assert s["cases"] == {"CWE78_OS_Command_Injection__Environment_01": {"hit": True, "fp": True}}
    # the old testcase mode is blind to the good-side FP
    assert score([bad, good], labels, "testcase")["fp"] == 0
    assert default_mode(labels) == "function"


def test_function_scoring_wrong_class_is_stray(juliet_repo):
    repo, labels = juliet_repo
    s = score([{"bug_class": "sqli", "file": JF, "line": 14}], labels, "function", repo)
    assert s["tp"] == 0 and s["stray_findings"] == 1


def test_line_scoring_toy(toy_repo):
    root, labels = toy_repo
    f = [{"bug_class": "cmdi", "file": "app.py", "line": 10}]
    s = score(f, labels, "line")
    assert (s["tp"], s["fp"], s["fn"]) == (1, 0, 1)
    assert default_mode(labels) == "line"


# ------------------------------------------------------------ stats

def test_binomial_and_mcnemar():
    assert _binom_two_sided(0, 6) == pytest.approx(2 / 64)
    assert _binom_two_sided(3, 6) == 1.0
    a = {str(i): False for i in range(10)}
    b = {str(i): i < 8 for i in range(10)}
    t = mcnemar(a, b)
    assert (t["a_only"], t["b_only"]) == (0, 8)
    assert t["p_value"] == pytest.approx(2 / 256, abs=1e-4)
    assert t["risk_diff"] == 0.8


def test_bootstrap_and_majority():
    runs = [{str(i): {"hit": i < 6, "fp": False} for i in range(10)} for _ in range(3)]
    p, lo, hi = bootstrap_ci(runs, "recall", n_boot=500)
    assert p == 0.6 and lo <= p <= hi
    runs[0]["0"]["hit"] = False
    assert majority(runs, "hit")["0"] is True


# ------------------------------------------------------------ end to end

def test_experiment_and_report_offline(juliet_repo, tmp_path, monkeypatch, capsys):
    """Full pipeline with a fake model: C0..C4, 2 runs, then the report."""
    repo, labels = juliet_repo
    lp = tmp_path / "labels.json"
    lp.write_text(json.dumps(labels))
    out = tmp_path / "res"

    def script(conv):
        if not conv.tools:   # validator call
            v = {"verdict": "confirmed", "path_steps": [
                {"file": JF, "line": 14, "quote": "Runtime.getRuntime().exec(osCommand + data)"}],
                "sanitizer_adequate": None, "conditions_satisfiable": True, "poc": "x;id",
                "reason": "r", "adjusted_confidence": 0.9}
            return reply(text=json.dumps(v), stop="end_turn")
        return reply(calls=[("r", "report_findings", {"findings": [
            {"bug_class": "cmdi", "file": JF, "line": 14, "cwe": "CWE-78", "confidence": .9},
            {"bug_class": "cmdi", "file": JF, "line": 30, "cwe": "CWE-78", "confidence": .5}]})])

    import eval.experiment as ex
    monkeypatch.setattr(ex, "make_backend", lambda *a, **k: FakeBackend(script))
    argv = ["experiment.py", str(repo), str(lp), "--runs", "2", "--out", str(out),
            "--no-baseline", "--workers", "1", "--skip-preflight"]
    monkeypatch.setattr(sys, "argv", argv)
    ex.main()
    # 4 audit cells (C3/C4 share) x 2 runs
    assert len(list(out.rglob("audit.json"))) == 8
    assert len(list(out.rglob("val-*.json"))) == 2

    calls_before = len(list(out.rglob("*.json")))
    monkeypatch.setattr(ex, "make_backend", lambda *a, **k: pytest.fail("should resume"))
    ex.main()   # everything already done: no backend needed
    assert len(list(out.rglob("*.json"))) == calls_before

    import eval.report as rp
    monkeypatch.setattr(sys, "argv", ["report.py", str(out), "--boot", "100"])
    rp.main()
    rep = json.loads((out / "report.json").read_text())
    assert rep["scoring"] == "function"
    c0 = next(r for r in rep["rows"] if "C0" in r["presets"])
    assert c0["recall"][0] == 1.0 and c0["fp_rate"][0] == 1.0
    assert any(t["a"] == "C3" and t["b"] == "C4" for t in rep["mcnemar"])
    assert rep["ro2"] and rep["ro2"][0]["tp_cases_lost"] == 0
    assert "surviving_fps" in rep   # the good-side finding survived the fake validator
