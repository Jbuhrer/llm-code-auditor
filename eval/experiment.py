#!/usr/bin/env python3
"""
The experiment engine.

Runs several detector configurations against ONE labelled benchmark and prints a
comparison table. This is the core apparatus of the thesis: every prompt or loop
change, and the validator ablation, becomes a row you can compare on the same
ground truth.

Configurations:
  baseline        - plain semgrep (state of practice)
  agent           - your agent, validator OFF
  agent+validator - your agent, validator ON  (should raise precision / cut FPs)

Usage:
  export ANTHROPIC_API_KEY=...
  python eval/experiment.py benchmarks/toy benchmarks/toy/labels.json --bugs sqli cmdi

Add --configs to run a subset, e.g. --configs baseline agent+validator.
Results are written to experiment_results.json for your write-up.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor import Auditor            # noqa: E402
from auditor.baseline import semgrep_baseline  # noqa: E402
from eval.metrics import score         # noqa: E402

ALL_CONFIGS = ["baseline", "agent", "agent+validator", "agent+context+variants"]


def run_config(name, repo, bugs):
    """Return (findings, cost_dict)."""
    if name == "baseline":
        return semgrep_baseline(repo), {"tokens": 0}
    # full pipeline: context pre-pass + validator + variant hunt (the ToB-adapted run)
    if name == "agent+context+variants":
        res = Auditor(repo, bugs, validate=True,
                      use_context=True, use_variants=True).run()
    else:
        validate = name.endswith("validator")
        res = Auditor(repo, bugs, validate=validate).run()
    return res.findings, {"tokens": res.input_tokens + res.output_tokens,
                          "turns": res.turns}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("labels")
    ap.add_argument("--bugs", nargs="+", default=["sqli", "cmdi", "path"])
    ap.add_argument("--configs", nargs="+", default=ALL_CONFIGS, choices=ALL_CONFIGS)
    a = ap.parse_args()

    labels = json.loads(Path(a.labels).read_text())
    rows = {}
    for cfg in a.configs:
        print(f"\n=== running {cfg} ===", flush=True)
        try:
            findings, cost = run_config(cfg, a.repo, a.bugs)
        except Exception as e:
            rows[cfg] = {"error": str(e)}
            continue
        s = score(findings, labels)
        s.update(cost)
        rows[cfg] = s

    # table
    cols = ["precision", "recall", "f1", "tp", "fp", "fn", "tokens"]
    width = max(len(c) for c in ALL_CONFIGS) + 2
    print(f"\n{'config':<{width}}" + "".join(f"{c:>11}" for c in cols))
    print("-" * (width + 11 * len(cols)))
    for cfg, r in rows.items():
        if "error" in r:
            print(f"{cfg:<{width}}  ERROR: {r['error'][:60]}")
            continue
        print(f"{cfg:<{width}}" + "".join(f"{r.get(c, '-'):>11}" for c in cols))

    Path("experiment_results.json").write_text(json.dumps(rows, indent=2))
    print("\nwritten to experiment_results.json")


if __name__ == "__main__":
    main()
