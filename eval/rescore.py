#!/usr/bin/env python3
"""Re-score a saved results folder in both modes. Zero API calls.
Usage: python3 eval/rescore.py results/<ts> <labels.json> [--show]"""
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from eval.metrics import score, testcase_id  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir"); ap.add_argument("labels")
    ap.add_argument("--show", action="store_true")
    a = ap.parse_args()
    labels = json.loads(Path(a.labels).read_text())
    cols = ["precision", "recall", "f1", "tp", "fp", "fn"]
    print(f"{'config':<26}{'mode':<10}" + "".join(f"{c:>10}" for c in cols))
    print("-" * 96)
    saved = {}
    for fp in sorted(Path(a.run_dir).glob("*.json")):
        if fp.name == "summary.json":
            continue
        findings = json.loads(fp.read_text()); saved[fp.stem] = findings
        for mode in ("testcase", "line"):
            s = score(findings, labels, mode)
            print(f"{fp.stem:<26}{mode:<10}" + "".join(f"{s[c]:>10}" for c in cols))
    if not a.show:
        return
    units = {(testcase_id(l["file"]), l["bug_class"]) for l in labels}
    for cfg, findings in saved.items():
        hit = {(testcase_id(f.get("file", "")), f.get("bug_class")) for f in findings}
        fps = [f for f in findings
               if (testcase_id(f.get("file", "")), f.get("bug_class")) not in units]
        print(f"\n== {cfg}: testcase-mode errors ==")
        print(f"  false positives ({len(fps)}):")
        for f in fps:
            print(f"    [{f.get('bug_class')}] {Path(f.get('file','')).name}:{f.get('line')}")
        missed = sorted(units - hit)
        print(f"  missed test cases ({len(missed)}):")
        for tc, cls in missed:
            print(f"    [{cls}] {tc}")


if __name__ == "__main__":
    main()
