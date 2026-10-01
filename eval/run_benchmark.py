#!/usr/bin/env python3
"""
Score the auditor against a labeled benchmark (single-config convenience wrapper).
For multi-config baseline-vs-agent comparison use eval/experiment.py.

Datasets (public, reproducible):
  - NIST Juliet: labelled good/bad pairs, great for precision/FP.
  - CWE-Bench-Java: github.com/iris-sast/cwe-bench-java, real projects, 1 CVE each.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor import Auditor       # noqa: E402
from eval.metrics import score    # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("labels", help="labels.json with ground-truth findings")
    ap.add_argument("--bugs", nargs="+", default=["sqli", "cmdi", "path"])
    ap.add_argument("--no-validate", action="store_true")
    a = ap.parse_args()

    labels = json.loads(Path(a.labels).read_text())
    res = Auditor(a.repo, a.bugs, validate=not a.no_validate).run()
    s = score(res.findings, labels)
    s["tokens"] = res.input_tokens + res.output_tokens
    s["validator"] = not a.no_validate
    print(json.dumps(s, indent=2))


if __name__ == "__main__":
    main()
