#!/usr/bin/env python3
"""
Score ONE preset on a labelled benchmark, one run (quick check).
For the real multi-config, multi-run experiment use eval/experiment.py.

  python eval/run_benchmark.py benchmarks/toy benchmarks/toy/labels.json --preset C3
"""
import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor.agent import audit_repo                   # noqa: E402
from auditor.config import PRESETS, DEFAULT_MODEL      # noqa: E402
from eval.metrics import score, default_mode           # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("labels", help="labels.json with ground-truth findings")
    ap.add_argument("--preset", default="C4", choices=list(PRESETS))
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--bugs", nargs="+", default=["sqli", "cmdi", "path"])
    ap.add_argument("--unit", default="file", choices=["file", "testcase", "repo"])
    a = ap.parse_args()

    labels = json.loads(Path(a.labels).read_text())
    p = PRESETS[a.preset]
    cfg = replace(p.audit, model=a.model, bug_classes=tuple(a.bugs), unit=a.unit)
    res = audit_repo(a.repo, cfg, validation=p.validation)
    mode = default_mode(labels)
    s = score(res.findings, labels, mode, a.repo)
    s.pop("cases", None)
    s.update({"preset": a.preset, "model": a.model, "scoring": mode,
              "tokens": res.input_tokens + res.output_tokens, "cost_usd": res.cost_usd,
              "seconds": res.seconds, "refusals": res.refusals, "errors": res.errors})
    print(json.dumps(s, indent=2))


if __name__ == "__main__":
    main()
