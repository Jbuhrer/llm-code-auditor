#!/usr/bin/env python3
"""Re-score an OLD-format results folder (one <config>.json findings list per
config, from before the factorial harness). Zero API calls. New-format folders
are scored by eval/report.py instead.

Usage: python eval/rescore.py results/<ts> <labels.json> [--repo DIR] [--show]
--repo enables function-level (matched good/bad) scoring for Juliet."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor.classes import canonical_class  # noqa: E402
from eval.metrics import score, testcase_id  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("labels")
    ap.add_argument("--repo", default=None, help="benchmark dir, enables function mode")
    ap.add_argument("--show", action="store_true")
    a = ap.parse_args()
    labels = json.loads(Path(a.labels).read_text())
    modes = ("testcase", "line") + (("function",) if a.repo else ())
    cols = ["precision", "recall", "f1", "tp", "fp", "fn"]
    print(f"{'config':<26}{'mode':<10}" + "".join(f"{c:>10}" for c in cols))
    print("-" * 96)
    saved = {}
    for fp in sorted(Path(a.run_dir).glob("*.json")):
        if fp.name in ("summary.json", "meta.json", "report.json"):
            continue
        findings = json.loads(fp.read_text())
        if not isinstance(findings, list):
            continue
        saved[fp.stem] = findings
        for mode in modes:
            s = score(findings, labels, mode, a.repo)
            print(f"{fp.stem:<26}{mode:<10}" + "".join(f"{s[c]:>10}" for c in cols))
    if not a.show:
        return
    units = {(testcase_id(l["file"]), l["bug_class"]) for l in labels}
    for cfg, findings in saved.items():
        # same canonical class mapping the scorer uses
        keyed = [((testcase_id(f.get("file", "")), canonical_class(f)), f) for f in findings]
        hit = {k for k, _ in keyed}
        fps = [f for k, f in keyed if k not in units]
        print(f"\n== {cfg}: testcase-mode errors ==")
        print(f"  false positives ({len(fps)}):")
        for f in fps:
            print(f"    [{canonical_class(f)}] {Path(f.get('file', '')).name}:{f.get('line')}")
        missed = sorted(units - hit)
        print(f"  missed test cases ({len(missed)}):")
        for tc, cls in missed:
            print(f"    [{cls}] {tc}")


if __name__ == "__main__":
    main()
