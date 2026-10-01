"""
Scoring shared by the benchmark and experiment runners.

A finding is a true positive if it matches a ground-truth label on file name +
bug_class and lands within LINE_TOLERANCE lines. Data-flow bugs are reported at
the sink, which can sit a few lines off the labelled point, hence the tolerance.
"""
from pathlib import Path

LINE_TOLERANCE = 5


def matches(finding: dict, label: dict) -> bool:
    return (
        Path(finding.get("file", "")).name == Path(label["file"]).name
        and finding.get("bug_class") == label["bug_class"]
        and abs(finding.get("line", -999) - label["line"]) <= LINE_TOLERANCE
    )


def score(findings: list[dict], labels: list[dict]) -> dict:
    tp, matched = 0, set()
    for f in findings:
        hit = next((i for i, l in enumerate(labels)
                    if i not in matched and matches(f, l)), None)
        if hit is not None:
            tp += 1
            matched.add(hit)
    fp = len(findings) - tp
    fn = len(labels) - tp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 3), "recall": round(recall, 3),
            "f1": round(f1, 3)}
