"""
Scoring. One harness, three notions of a correct detection:

  function  (Juliet default) each test case is a matched pair: its bad side
            (bad, badSink, ..._bad) and its good side (goodG2B, goodB2G, ...).
            TP = right bug class reported inside a bad-side function.
            FP = right bug class reported inside a good-side function, i.e. the
                 agent flagged the patched twin. Directly measurable on Juliet.
            Findings anywhere else (wrong class, helpers, unlabelled cases) are
            counted as stray findings and go into finding-level FDR.
  line      path-level: right file + class + within LINE_TOLERANCE of a labelled
            sink line. Strict; used for localization and non-Juliet benchmarks.
  testcase  the old coarse mode: right class anywhere in the right test case.
            Kept for comparing against earlier results. Cannot see good-side FPs.

Every mode returns per-case outcomes ("cases") so configs can be compared
pairwise (McNemar) in eval/stats.py.
"""
from __future__ import annotations
import re
from collections import Counter
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor.classes import canonical_class  # noqa: E402
from auditor.units import testcase_stem      # noqa: E402
from eval.juliet_functions import locate     # noqa: E402

LINE_TOLERANCE = 5


def testcase_id(file: str) -> str:
    return testcase_stem(Path(str(file).replace("\\", "/")).stem)


def _name(file: str) -> str:
    return Path(str(file).replace("\\", "/")).name


def _line(f: dict) -> int:
    try:
        return int(f.get("line", -999))
    except (TypeError, ValueError):
        return -999


def matches(finding: dict, label: dict) -> bool:
    return (
        _name(finding.get("file", "")) == _name(label["file"])
        and canonical_class(finding) == label["bug_class"]
        and abs(_line(finding) - label["line"]) <= LINE_TOLERANCE
    )


def _prf(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 3),
            "recall": round(r, 3), "f1": round(f1, 3),
            "fdr": round(1 - p, 3) if (tp + fp) else 0.0}


def score_line(findings, labels):
    tp, matched = 0, set()
    for f in findings:
        hit = next((i for i, l in enumerate(labels)
                    if i not in matched and matches(f, l)), None)
        if hit is not None:
            tp += 1
            matched.add(hit)
    s = _prf(tp, len(findings) - tp, len(labels) - tp)
    s["cases"] = {f"{l['file']}:{l['line']}:{l['bug_class']}":
                  {"hit": i in matched, "fp": False} for i, l in enumerate(labels)}
    s["findings"] = len(findings)
    return s


def score_testcase(findings, labels):
    units = {(testcase_id(l["file"]), l["bug_class"]) for l in labels}
    hit, fp = set(), 0
    for f in findings:
        key = (testcase_id(f.get("file", "")), canonical_class(f))
        if key in units:
            hit.add(key)
        else:
            fp += 1
    s = _prf(len(hit), fp, len(units) - len(hit))
    s["cases"] = {f"{tc}:{c}": {"hit": (tc, c) in hit, "fp": False} for tc, c in units}
    s["findings"] = len(findings)
    return s


def score_function(findings, labels, repo: str | Path):
    """Juliet matched-pair scoring. See module docstring."""
    repo = Path(repo)
    by_name = {p.name: p for p in repo.rglob("*") if p.is_file()}
    cases: dict[str, dict] = {}
    label_lines: dict[str, list[tuple[str, int]]] = {}
    for l in labels:
        tc = testcase_id(l["file"])
        cases.setdefault(tc, {"class": l["bug_class"], "hit": False, "fp": False,
                              "localized": False})
        label_lines.setdefault(tc, []).append((_name(l["file"]), l["line"]))

    correct, stray, good_side = 0, 0, 0
    for f in findings:
        tc = testcase_id(_name(f.get("file", "")))
        case = cases.get(tc)
        cls = canonical_class(f)
        path = by_name.get(_name(f.get("file", "")))
        if case is None or path is None or cls != case["class"]:
            stray += 1
            continue
        _, region = locate(path, _line(f))
        if region == "bad":
            correct += 1
            case["hit"] = True
            if any(n == path.name and abs(_line(f) - ln) <= LINE_TOLERANCE
                   for n, ln in label_lines[tc]):
                case["localized"] = True
        elif region == "good":
            good_side += 1
            case["fp"] = True
        else:
            stray += 1

    tp = sum(c["hit"] for c in cases.values())
    fp = sum(c["fp"] for c in cases.values())
    s = _prf(tp, fp, len(cases) - tp)
    n = len(findings)
    s.update({
        "cases": {k: {"hit": v["hit"], "fp": v["fp"]} for k, v in cases.items()},
        "findings": n,
        "good_side_findings": good_side,
        "stray_findings": stray,
        "finding_precision": round(correct / n, 3) if n else 0.0,
        "localization": round(sum(c["localized"] for c in cases.values()) / tp, 3)
        if tp else 0.0,
    })
    return s


def score_method(findings, labels, repo: str | Path):
    """Real-CVE scoring (CWE-Bench-Java). A case is one CVE. It's detected when a
    finding of the right class lands inside one of the methods its fix changed,
    located by name in the audited (vulnerable) file, since fix_info line numbers
    come from the fix commit. A class-level fix (no method) counts on the file.
    Findings outside every fixed method can't be called false (the project may
    have other real bugs), so they're reported as off-target alerts."""
    repo = Path(repo)
    cases: dict[str, dict] = {}
    targets: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for l in labels:
        cve = l.get("cve") or l.get("project") or l["file"]
        cases.setdefault(cve, {"class": l["bug_class"], "hit": False, "file_hit": False,
                               "project": l.get("project", "")})
        targets.setdefault((l["file"], l["bug_class"]), []).append((cve, l.get("method", "")))

    on_target, alerts = 0, Counter()
    for f in findings:
        path = str(f.get("file", "")).replace("\\", "/")
        alerts[path.split("/", 1)[0]] += 1
        hits = targets.get((path, canonical_class(f)))
        if not hits:
            continue
        fn, _ = locate(repo / path, _line(f))
        matched = False
        for cve, method in hits:
            cases[cve]["file_hit"] = True
            if not method or (fn and fn == method):
                cases[cve]["hit"] = True
                matched = True
        on_target += matched

    tp = sum(c["hit"] for c in cases.values())
    s = _prf(tp, 0, len(cases) - tp)
    n = len(findings)
    projects = {c["project"] for c in cases.values() if c["project"]} or set(alerts)
    s.update({
        "cases": {k: {"hit": v["hit"], "fp": False} for k, v in cases.items()},
        "findings": n,
        "file_recall": round(sum(c["file_hit"] for c in cases.values()) / len(cases), 3)
        if cases else 0.0,
        "on_target_findings": on_target,
        "off_target_findings": n - on_target,
        "alerts_per_project": round(n / len(projects), 2) if projects else 0.0,
    })
    s.pop("fdr", None)   # unknowable without triage; see off_target_findings
    return s


def score(findings, labels, mode="testcase", repo=None):
    if mode == "method":
        if repo is None:
            raise ValueError("method scoring needs the benchmark repo path")
        return score_method(findings, labels, repo)
    if mode == "function":
        if repo is None:
            raise ValueError("function scoring needs the benchmark repo path")
        return score_function(findings, labels, repo)
    if mode == "line":
        return score_line(findings, labels)
    return score_testcase(findings, labels)


def default_mode(labels) -> str:
    """Juliet labels (CWE-named files) score by function; anything else by line."""
    if labels and all("project" in l and "method" in l for l in labels):
        return "method"
    juliet = labels and all(re.match(r"CWE\d+_", _name(l["file"])) for l in labels)
    return "function" if juliet else "line"
