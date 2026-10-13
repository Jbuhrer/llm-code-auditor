"""
Scoring. Two modes:
  line      file + bug_class + within LINE_TOLERANCE lines (strict).
  testcase  (default) standard Juliet scoring: one bad flow per test case.
            Correct if the right bug class is reported in any file of the right
            test case (..._22a/_22b share one id). Extra findings in an already-hit
            test case are not penalised; findings in unlabelled test cases are FPs.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor.classes import canonical_class  # noqa: E402

LINE_TOLERANCE = 5


def testcase_id(file: str) -> str:
    return re.sub(r"(\d+)[a-z]$", r"\1", Path(file).stem)


def matches(finding: dict, label: dict) -> bool:
    return (
        Path(finding.get("file", "")).name == Path(label["file"]).name
        and canonical_class(finding) == label["bug_class"]
        and abs(finding.get("line", -999) - label["line"]) <= LINE_TOLERANCE
    )


def _prf(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3)}


def score_line(findings, labels):
    tp, matched = 0, set()
    for f in findings:
        hit = next((i for i, l in enumerate(labels)
                    if i not in matched and matches(f, l)), None)
        if hit is not None:
            tp += 1
            matched.add(hit)
    return _prf(tp, len(findings) - tp, len(labels) - tp)


def score_testcase(findings, labels):
    units = {(testcase_id(l["file"]), l["bug_class"]) for l in labels}
    hit, fp = set(), 0
    for f in findings:
        key = (testcase_id(f.get("file", "")), canonical_class(f))
        if key in units:
            hit.add(key)
        else:
            fp += 1
    return _prf(len(hit), fp, len(units) - len(hit))


def score(findings, labels, mode="testcase"):
    return score_testcase(findings, labels) if mode == "testcase" \
        else score_line(findings, labels)
