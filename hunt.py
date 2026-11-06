#!/usr/bin/env python3
"""
Hunt for real vulnerabilities in a project you've cloned. No labels needed.

  python hunt.py ~/targets/jspwiki --dry-run          # files, flags, cost estimate
  python hunt.py ~/targets/jspwiki --max-usd 15       # screen, triage, deep dive

Stages: a screen model flags anything plausible in every relevant file, a triage
model scores every flag (nothing is thrown out), and the strongest model
investigates the top flags with the whole repo open. Results land in
<out>/report.md, best leads first. Rerun the same command to resume; finished
work is never paid for twice.

Only test what you find against your own instance (a VM or a container), and
report real bugs through the project's security policy.
"""
import argparse
import sys
from pathlib import Path

from auditor.budget import Budget
from auditor.hunt import HuntConfig, estimate, hunt_units, run_hunt
from auditor.llm import make_backend
from auditor.prompts import BUG_CLASSES
from auditor.tools import Workspace


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    d = HuntConfig()
    ap.add_argument("repo")
    ap.add_argument("--out", type=Path, default=None,
                    help="default: results/hunt-<repo folder name>")
    ap.add_argument("--bugs", nargs="+", default=list(d.bug_classes),
                    help=f"any of {', '.join(BUG_CLASSES)}, or 'all' (no pre-filter)")
    ap.add_argument("--screen-model", default=d.screen_model,
                    help="claude-haiku-5-5 is ~20x cheaper for a first pass on a big repo")
    ap.add_argument("--triage-model", default=d.triage_model)
    ap.add_argument("--deep-model", default=d.deep_model,
                    help="claude-fable-5-1 for the strongest (and priciest) deep dives")
    ap.add_argument("--deep-top", type=int, default=d.deep_top,
                    help="how many of the best-scored flags get a deep dive")
    ap.add_argument("--min-score", type=float, default=d.min_score,
                    help="skip deep dives on flags triage scored below this")
    ap.add_argument("--deep-effort", default=d.deep_effort)
    ap.add_argument("--workers", type=int, default=d.workers)
    ap.add_argument("--exts", nargs="+", default=list(d.exts))
    ap.add_argument("--semgrep", action="store_true", help="give the screen semgrep too")
    ap.add_argument("--no-prefilter", action="store_true",
                    help="screen every product file, not just ones using a relevant API")
    ap.add_argument("--max-usd", type=float, default=20.0,
                    help="stop starting new work past this (default $20); 0 = no cap")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--skip-preflight", action="store_true")
    a = ap.parse_args()

    bugs = tuple(a.bugs)
    exhaustive = any(b in ("all", "any", "*") for b in bugs)
    bad = [b for b in bugs if b not in BUG_CLASSES and not exhaustive]
    if bad:
        sys.exit(f"unknown bug class(es) {bad}; known: {list(BUG_CLASSES)} or 'all'")
    hc = HuntConfig(bug_classes=bugs, screen_model=a.screen_model,
                    triage_model=a.triage_model, deep_model=a.deep_model,
                    deep_top=a.deep_top, min_score=a.min_score, deep_effort=a.deep_effort,
                    workers=a.workers, exts=tuple(a.exts), semgrep=a.semgrep,
                    prefilter=not (a.no_prefilter or exhaustive))
    out = a.out or Path("results") / f"hunt-{Path(a.repo).resolve().name}"

    units, stats = hunt_units(Workspace(a.repo), hc.bug_classes, hc.prefilter, hc.exts)
    est = estimate(len(units), hc)
    money = lambda v: "unpriced" if v is None else f"~${v:.2f}"   # noqa: E731
    print(f"{stats['files']} source file(s): {stats['kept']} to screen, {stats['tests']} "
          f"test, {stats['non_product']} docs/samples, {stats['no_keyword']} no relevant API")
    print(f"estimate: screen {money(est['screen'])} ({hc.screen_model}), "
          f"~{est['flags']} flags -> triage {money(est['triage'])} ({hc.triage_model}), "
          f"{est['deep_dives']} deep dive(s) {money(est['deep'])} ({hc.deep_model})")
    print("  (ballpark from the CWE-Bench-Java runs; real cost depends on the code)")
    if a.dry_run:
        return
    if not units:
        sys.exit("nothing to screen")
    if not a.skip_preflight:
        from eval.experiment import preflight
        limit = a.max_usd or None
        probs = preflight(sorted({hc.screen_model, hc.triage_model, hc.deep_model}), limit)
        if probs:
            sys.exit("preflight failed:\n  " + "\n  ".join(probs))
    budget = Budget(a.max_usd or None)
    try:
        path = run_hunt(a.repo, out, hc, budget, make_backend)
    finally:
        print(f"\n{budget.summary()}")
    print(f"report: {path}")
    if budget.exceeded:
        print("hit the cap before finishing; rerun the same command (with a higher "
              "--max-usd) to continue where it stopped")


if __name__ == "__main__":
    main()
