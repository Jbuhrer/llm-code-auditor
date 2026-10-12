#!/usr/bin/env python3
"""
The experiment engine.

Runs detector configurations against ONE labelled benchmark, prints a comparison
table, and SAVES EVERY CONFIG'S FINDINGS so they can be analysed later for free
(see eval/analyze.py). Nothing you pay for gets thrown away.

Configurations:
  baseline               - plain semgrep (state of practice, free)
  agent                  - your agent, validator OFF
  agent+validator        - your agent, validator ON
  agent+context+variants - full ToB-adapted pipeline

Cost saver + cleaner science: when `agent` and `agent+validator` are both
requested, they SHARE ONE audit pass. The validator then runs on exactly the same
candidates, so the two rows differ only by the validator (no run-to-run noise)
and you pay for the audit once instead of twice.

Usage:
  python eval/experiment.py benchmarks/mini benchmarks/mini/labels.json --bugs sqli cmdi
  python eval/experiment.py <repo> <labels> --configs agent agent+validator

Output: results/<timestamp>/  with summary.json and one <config>.json per config.
"""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor import Auditor                     # noqa: E402
from auditor.agent import AuditResult           # noqa: E402
from auditor.baseline import semgrep_baseline   # noqa: E402
from eval.metrics import score                  # noqa: E402

ALL_CONFIGS = ["baseline", "agent", "agent+validator", "agent+context+variants"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("labels")
    ap.add_argument("--bugs", nargs="+", default=["sqli", "cmdi", "path"])
    ap.add_argument("--configs", nargs="+", default=["baseline", "agent", "agent+validator"],
                    choices=ALL_CONFIGS)
    ap.add_argument("--out", default=None, help="results dir (default results/<timestamp>)")
    a = ap.parse_args()

    labels = json.loads(Path(a.labels).read_text())
    out_dir = Path(a.out or f"results/{datetime.now():%Y%m%d-%H%M%S}")
    out_dir.mkdir(parents=True, exist_ok=True)

    rows: dict[str, dict] = {}
    found: dict[str, list] = {}

    def record(cfg, findings, cost):
        s = score(findings, labels)
        s.update(cost)
        rows[cfg] = s
        found[cfg] = findings

    # ---- baseline (free) ----
    if "baseline" in a.configs:
        print("\n=== running baseline ===", flush=True)
        try:
            record("baseline", semgrep_baseline(a.repo), {"tokens": 0})
        except Exception as e:
            rows["baseline"] = {"error": str(e)}

    # ---- agent and agent+validator share ONE audit pass ----
    want_plain = "agent" in a.configs
    want_val = "agent+validator" in a.configs
    if want_plain or want_val:
        print("\n=== running agent (shared audit pass) ===", flush=True)
        try:
            auditor = Auditor(a.repo, a.bugs, validate=False)
            res = auditor.run()
            audit_tokens = res.input_tokens + res.output_tokens
            raw = res.raw_findings
            if want_plain:
                record("agent", [dict(f) for f in raw],
                       {"tokens": audit_tokens, "turns": res.turns})
            if want_val:
                print(f"\n=== validating {len(raw)} candidate(s) for agent+validator ===",
                      flush=True)
                vres = AuditResult()
                confirmed = auditor._validate([dict(f) for f in raw], vres)
                val_tokens = vres.input_tokens + vres.output_tokens
                record("agent+validator", confirmed,
                       {"tokens": audit_tokens + val_tokens,
                        "validator_tokens": val_tokens, "turns": res.turns})
        except Exception as e:
            for cfg in ("agent", "agent+validator"):
                if cfg in a.configs:
                    rows[cfg] = {"error": str(e)}

    # ---- full pipeline (separate run, it's a different audit) ----
    if "agent+context+variants" in a.configs:
        print("\n=== running agent+context+variants ===", flush=True)
        try:
            res = Auditor(a.repo, a.bugs, validate=True,
                          use_context=True, use_variants=True).run()
            record("agent+context+variants", res.findings,
                   {"tokens": res.input_tokens + res.output_tokens, "turns": res.turns})
        except Exception as e:
            rows["agent+context+variants"] = {"error": str(e)}

    # ---- table ----
    cols = ["precision", "recall", "f1", "tp", "fp", "fn", "tokens"]
    width = max(len(c) for c in ALL_CONFIGS) + 2
    print(f"\n{'config':<{width}}" + "".join(f"{c:>11}" for c in cols))
    print("-" * (width + 11 * len(cols)))
    for cfg in a.configs:
        r = rows.get(cfg, {})
        if "error" in r:
            print(f"{cfg:<{width}}  ERROR: {r['error'][:60]}")
            continue
        print(f"{cfg:<{width}}" + "".join(f"{r.get(c, '-'):>11}" for c in cols))

    # ---- save everything ----
    meta = {"repo": a.repo, "labels": a.labels, "bugs": a.bugs,
            "configs": a.configs, "timestamp": datetime.now().isoformat()}
    (out_dir / "summary.json").write_text(json.dumps({"meta": meta, "scores": rows}, indent=2))
    for cfg, fl in found.items():
        (out_dir / f"{cfg}.json").write_text(json.dumps(fl, indent=2))
    Path("experiment_results.json").write_text(json.dumps(rows, indent=2))  # back-compat
    print(f"\nresults saved to {out_dir}/  (analyse free with: "
          f"python3 eval/analyze.py {out_dir}/<config>.json {a.labels} --repo {a.repo})")


if __name__ == "__main__":
    main()
