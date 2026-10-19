#!/usr/bin/env python3
"""
Run the auditor on a real repo (no labels, no scoring).

  python run_audit.py /path/to/repo --bugs sqli cmdi path --out findings.json
  python run_audit.py /path/to/repo --exhaustive --context --variants

Defaults to the full agent (C4: exploration + semgrep + all evidence checks).
Use --preset to pick another config, e.g. --preset C0 for the model-only baseline.
"""
import argparse
import json
from dataclasses import replace

from auditor.agent import audit_repo
from auditor.config import PRESETS, DEFAULT_MODEL, ValidationConfig


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--preset", default="C4", choices=list(PRESETS))
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--bugs", nargs="+", default=["sqli", "cmdi", "path"],
                    help="bug classes, or 'all' for exhaustive open-ended hunting")
    ap.add_argument("--exhaustive", action="store_true",
                    help="hunt ANY vulnerability class (same as --bugs all)")
    ap.add_argument("--unit", default="file", choices=["file", "testcase", "repo"])
    ap.add_argument("--budget", type=int, default=24000, help="context tokens per unit")
    ap.add_argument("--max-turns", type=int, default=15, help="per unit, explore mode")
    ap.add_argument("--effort", default="medium")
    ap.add_argument("--threat-model", default="remote", choices=["remote", "all-external"],
                    help="remote: realistic web attacker (default for real repos); "
                         "all-external: every outside input is tainted (Juliet)")
    ap.add_argument("--stance", default="precise", choices=["precise", "screen"],
                    help="screen: report anything plausible (recall first) for a "
                         "verifier to check")
    ap.add_argument("--no-validate", action="store_true")
    ap.add_argument("--context", action="store_true",
                    help="build architectural context before hunting (ToB-style)")
    ap.add_argument("--variants", action="store_true",
                    help="hunt variants of each confirmed finding (ToB-style)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--out", default="findings.json")
    a = ap.parse_args()
    if a.exhaustive:
        a.bugs = ["all"]

    p = PRESETS[a.preset]
    cfg = replace(p.audit, model=a.model, bug_classes=tuple(a.bugs), unit=a.unit,
                  context_budget=a.budget, max_turns=a.max_turns, effort=a.effort,
                  threat_model=a.threat_model, stance=a.stance)
    val = ValidationConfig() if a.no_validate else p.validation
    res = audit_repo(a.repo, cfg, workers=a.workers, validation=val,
                     use_context=a.context, use_variants=a.variants)

    with open(a.out, "w") as fh:
        json.dump({"config": cfg.as_dict(), "validation": val.as_dict(),
                   "findings": res.findings, "raw_findings": res.raw_findings,
                   "usage": res.usage, "cost_usd": res.cost_usd, "seconds": res.seconds,
                   "units": res.units, "refusals": res.refusals, "errors": res.errors},
                  fh, indent=2)

    cost = "?" if res.cost_usd is None else f"${res.cost_usd:.2f}"
    print(f"{len(res.findings)} findings ({len(res.raw_findings)} before validation) | "
          f"{res.units} units | {res.turns} turns | "
          f"{res.input_tokens + res.output_tokens:,} tokens | {cost} | {res.seconds:.0f}s"
          + (f" | {res.refusals} refused" if res.refusals else "")
          + (f" | {res.errors} errors" if res.errors else ""))
    for f in res.findings:
        print(f"  [{f.get('bug_class')}] {f.get('file')}:{f.get('line')} "
              f"({f.get('cwe')}, conf={f.get('confidence')})")
    print(f"\nwritten to {a.out}")


if __name__ == "__main__":
    main()
