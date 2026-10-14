#!/usr/bin/env python3
"""
The experiment engine: configs x models x repeated runs on one benchmark.

  python eval/experiment.py <repo> <labels.json> --configs C0 C1 C2 C3 C4 \
      --models claude-opus-5-5 claude-sonnet-5-5 claude-haiku-5-5 --runs 3

Cells that differ only in validation SHARE one audit pass (C3 and C4 do), so
validation on/off is an exactly paired comparison and the audit is paid once.

Everything is saved as it finishes, and finished pieces are skipped on rerun
(pass the same --out), so a crash or Ctrl-C never re-bills completed work:

  <out>/meta.json
  <out>/<model>/<audit-cell>/run<k>/audit.json        per-unit records
  <out>/<model>/<audit-cell>/run<k>/<val-variant>.json per-finding verdicts
  <out>/baseline/semgrep.json                          tool-only baseline

Then score and tabulate (free, no API calls):
  python eval/report.py <out>
"""
from __future__ import annotations
import argparse
import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor.agent import Auditor, FatalBackendError                # noqa: E402
from auditor.baseline import semgrep_baseline                       # noqa: E402
from auditor.budget import Budget, BudgetExceeded                   # noqa: E402
from auditor.config import (AuditConfig, ValidationConfig, PRESETS,  # noqa: E402
                            full_factorial, validation_variants, EVIDENCE)
from auditor.llm import make_backend                                # noqa: E402
from auditor.pricing import cost_usd                                # noqa: E402
from auditor.prompts import PROMPT_VERSION, prompt_fingerprint, THREAT_MODELS  # noqa: E402
from auditor.tools import Workspace, semgrep_exe                    # noqa: E402
from auditor.units import build_units                               # noqa: E402
from auditor.validate import validate_one                           # noqa: E402
from eval.metrics import default_mode                               # noqa: E402

EVIDENCE_SWEEP = ["plain", *EVIDENCE, "all"]


def safe(name: str) -> str:
    return name.replace(":", "_").replace("/", "_")


def git_commit() -> str:
    try:
        root = Path(__file__).resolve().parent.parent
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                             text=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=root,
                               capture_output=True, text=True).stdout.strip()
        return sha + ("-dirty" if dirty else "")
    except Exception:
        return "unknown"


def semgrep_version() -> str:
    exe = semgrep_exe()
    if not exe:
        return "not installed"
    try:
        return subprocess.run([exe, "--version"], capture_output=True, text=True,
                              timeout=120).stdout.strip()
    except Exception as e:
        return f"error: {e}"


def preflight(models: list[str]) -> list[str]:
    """Problems that would make every call fail, caught before spending anything."""
    probs = []
    claude = [m for m in models if not m.startswith("openai-compat:")]
    if claude and not (os.environ.get("ANTHROPIC_API_KEY")
                       or os.environ.get("ANTHROPIC_AUTH_TOKEN")
                       or os.environ.get("ANTHROPIC_PROFILE")):
        probs.append("no Anthropic credentials: set ANTHROPIC_API_KEY (or log in with "
                     "the ant CLI and set ANTHROPIC_PROFILE)")
    if any(m.startswith("openai-compat:") for m in models):
        try:
            import openai  # noqa: F401
        except ImportError:
            probs.append("openai-compat models need: pip install openai")
    return probs


def write_json(path: Path, obj) -> None:
    """Atomic write so an interrupted save never leaves a half file to 'resume'."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, default=str))
    os.replace(tmp, path)


def append_jsonl(path: Path, obj) -> None:
    """One record per line, flushed right away, so a stop loses nothing finished."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, default=str) + "\n")


def read_jsonl(path: Path) -> list:
    """Records from a checkpoint file. A torn last line (killed mid-write) is skipped."""
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


def spread_limit(units, n: int):
    """First n units, round-robin across CWEs (or top-level dirs), so a smoke
    test with --limit covers every bug class instead of one alphabetical run."""
    import re
    groups: dict[str, list] = {}
    for u in units:
        m = re.search(r"CWE(\d+)_", u.id)
        groups.setdefault(m.group(1) if m else u.id.split("/")[0], []).append(u)
    queues, out = list(groups.values()), []
    while len(out) < n and any(queues):
        for q in queues:
            if q and len(out) < n:
                out.append(q.pop(0))
    return out


def plan_cells(a, base: AuditConfig) -> list[dict]:
    """[{label, model, audit, validations:[ValidationConfig]}], audit passes merged."""
    extra_vals = validation_variants(a.validation) if a.validation else []
    if a.evidence_sweep:
        extra_vals += validation_variants(EVIDENCE_SWEEP)
    wanted = []   # (label, audit_cfg, val_cfg)
    if a.factorial:
        for cfg in full_factorial(base):
            for v in [ValidationConfig(), ValidationConfig(True, tuple(EVIDENCE))]:
                wanted.append((None, cfg, v))
    for name in a.configs:
        p = PRESETS[name]
        cfg = replace(base, exploration=p.audit.exploration,
                      static_analysis=p.audit.static_analysis)
        wanted.append((name, cfg, p.validation))
    cells: dict[tuple, dict] = {}
    for model in a.models:
        for label, cfg, val in wanted:
            cfg = replace(cfg, model=model)
            key = (model, cfg.cell())
            cell = cells.setdefault(key, {"model": model, "audit": cfg, "labels": {},
                                          "validations": {}})
            for v in [val] + extra_vals:
                if v.enabled:
                    cell["validations"][v.name()] = v
            if label:
                cell["labels"][label] = val.name()
    return list(cells.values())


def run_audit_pass(cell, run_k, ws, units, out_dir, a, log) -> dict:
    path = out_dir / "audit.json"
    if path.exists():
        log(f"  (have {path}, skipping)")
        return json.loads(path.read_text())
    cfg: AuditConfig = cell["audit"]
    backend = make_backend(cfg.model, cfg.effort, cfg.temperature)
    t0 = time.monotonic()
    part = out_dir / "audit.partial.jsonl"
    done = {r["unit"]: r for r in read_jsonl(part)}
    if done:
        log(f"  resuming: {len(done)} unit(s) already done")
    lock = threading.Lock()

    def save(rec):
        a.spend.add(rec["cost_usd"])
        with lock:
            append_jsonl(part, rec)

    todo = [u for u in units if u.id not in done]
    new = Auditor(ws, cfg, backend).run_units(
        todo, a.workers, log, on_done=save, should_stop=lambda: a.spend.exceeded)
    for r in new:
        done[r["unit"]] = r
    if len(done) < len(units):
        a.spend.check()   # stopped early: partial file stays for the next run
    recs = [done[u.id] for u in units]
    total = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
    for r in recs:
        for k in total:
            total[k] += r["usage"].get(k, 0)
    data = {"config": cfg.as_dict(), "run": run_k, "units": recs,
            "wall_seconds": round(time.monotonic() - t0, 2), "usage": total,
            "cost_usd": cost_usd(cfg.model, total),
            "finished": datetime.now().isoformat()}
    write_json(path, data)
    part.unlink(missing_ok=True)
    return data


def run_validation(cell, audit, vcfg: ValidationConfig, ws, out_dir, a, log) -> None:
    path = out_dir / f"{vcfg.name()}.json"
    if path.exists():
        return
    cfg: AuditConfig = cell["audit"]
    backend = make_backend(cfg.model, cfg.effort, cfg.temperature)
    findings = [f for u in audit["units"] for f in u["findings"]]
    log(f"  validating {len(findings)} finding(s) with {vcfg.name()}")
    t0 = time.monotonic()
    part = out_dir / f"{vcfg.name()}.partial.jsonl"
    done = {e["i"]: e["rec"] for e in read_jsonl(part)}
    unit_files = {u["unit"]: u["targets"] for u in audit["units"]}
    lock = threading.Lock()

    def one(i):
        if a.spend.exceeded:
            return
        rec = validate_one(backend, ws, dict(findings[i]), vcfg, cfg.threat_model,
                           unit_files.get(findings[i].get("unit")))
        a.spend.add(cost_usd(cfg.model, rec["usage"]))
        with lock:
            append_jsonl(part, {"i": i, "rec": rec})
            done[i] = rec

    todo = [i for i in range(len(findings)) if i not in done]
    with ThreadPoolExecutor(max_workers=max(1, a.workers)) as pool:
        list(pool.map(one, todo))
    if len(done) < len(findings):
        a.spend.check()   # stopped early: partial file stays for the next run
    recs = [done[i] for i in range(len(findings))]
    total = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
    for r in recs:
        for k in total:
            total[k] += r["usage"].get(k, 0)
    write_json(path, {"validation": vcfg.as_dict(), "records": recs, "usage": total,
                      "cost_usd": cost_usd(cfg.model, total),
                      "wall_seconds": round(time.monotonic() - t0, 2)})
    part.unlink(missing_ok=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo")
    ap.add_argument("labels")
    ap.add_argument("--configs", nargs="*", default=["C0", "C1", "C2", "C3", "C4"],
                    choices=list(PRESETS))
    ap.add_argument("--factorial", action="store_true",
                    help="also run every exploration x static-analysis x validation cell")
    ap.add_argument("--models", nargs="+", default=["claude-opus-5-5"])
    ap.add_argument("--runs", type=int, default=3, help="independent repeats per cell")
    ap.add_argument("--validation", nargs="*", default=[],
                    help="extra validator variants on every audit cell: off, plain, "
                         "all, or items joined by + (path, sanitizer, conditions, poc)")
    ap.add_argument("--evidence-sweep", action="store_true",
                    help="RO2: plain, each evidence item alone, and all")
    ap.add_argument("--unit", choices=["file", "testcase", "repo"], default=None,
                    help="default: testcase for Juliet labels, file otherwise")
    ap.add_argument("--budget", type=int, default=24000, help="context tokens per unit")
    ap.add_argument("--max-turns", type=int, default=15)
    ap.add_argument("--effort", default="medium", help="Claude effort, held fixed")
    ap.add_argument("--temperature", type=float, default=None,
                    help="open-weight backends only")
    ap.add_argument("--semgrep-config", default="auto")
    ap.add_argument("--threat-model", default="all-external", choices=list(THREAT_MODELS),
                    help="who counts as the attacker; stated in every prompt "
                         "(all-external matches Juliet's ground truth)")
    ap.add_argument("--bugs", nargs="+", default=["sqli", "cmdi", "path"])
    ap.add_argument("--workers", type=int, default=4, help="parallel units per pass")
    ap.add_argument("--limit", type=int, default=None, help="first N units only (smoke tests)")
    ap.add_argument("--no-baseline", action="store_true", help="skip the semgrep baseline")
    ap.add_argument("--out", default=None, help="results dir; reuse it to resume")
    ap.add_argument("--dry-run", action="store_true", help="show the plan, call nothing")
    ap.add_argument("--skip-preflight", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--max-usd", type=float, default=None,
                    help="stop starting new work once this invocation has spent this "
                         "many dollars; finished work is saved and resumable")
    a = ap.parse_args()
    a.spend = Budget(a.max_usd)

    labels = json.loads(Path(a.labels).read_text())
    ws = Workspace(a.repo)
    unit_mode = a.unit or ("testcase" if default_mode(labels) == "function" else "file")
    units = build_units(ws, unit_mode)
    if a.limit:
        units = spread_limit(units, a.limit)
    base = AuditConfig(context_budget=a.budget, max_turns=a.max_turns, effort=a.effort,
                       temperature=a.temperature, semgrep_config=a.semgrep_config,
                       threat_model=a.threat_model,
                       unit=unit_mode, bug_classes=tuple(a.bugs))
    cells = plan_cells(a, base)

    print(f"{len(units)} unit(s) [{unit_mode}], {len(cells)} audit cell(s), "
          f"{a.runs} run(s) each")
    for c in cells:
        vals = ", ".join(c["validations"]) or "none"
        labels_s = ", ".join(f"{k}={v}" for k, v in c["labels"].items()) or "-"
        print(f"  {c['model']:<22} {c['audit'].cell():<14} validators: {vals:<30} "
              f"presets: {labels_s}")
    passes = len(cells) * a.runs
    print(f"{passes} audit pass(es) x {len(units)} unit(s) = {passes * len(units)} "
          f"unit audits, plus validation calls per finding")
    if a.dry_run:
        return
    probs = preflight(a.models)
    if probs and not a.skip_preflight:
        sys.exit("preflight failed:\n  " + "\n  ".join(probs))

    out = Path(a.out or f"results/{datetime.now():%Y%m%d-%H%M%S}")
    out.mkdir(parents=True, exist_ok=True)
    meta_path = out / "meta.json"
    meta = {"repo": str(Path(a.repo).resolve()), "labels": str(Path(a.labels).resolve()),
            "unit_mode": unit_mode, "n_units": len(units), "limit": a.limit,
            "runs": a.runs, "models": a.models, "base_config": base.as_dict(),
            "cells": [{"model": c["model"], "audit_cell": c["audit"].cell(),
                       "audit": c["audit"].as_dict(), "labels": c["labels"],
                       "validations": {k: v.as_dict() for k, v in c["validations"].items()}}
                      for c in cells],
            "prompt_version": PROMPT_VERSION, "prompt_hash": prompt_fingerprint(),
            "semgrep": {"version": semgrep_version(), "config": a.semgrep_config},
            "git": git_commit(), "started": datetime.now().isoformat()}
    if meta_path.exists():
        old = json.loads(meta_path.read_text())
        if old.get("prompt_hash") != meta["prompt_hash"]:
            sys.exit(f"{out} was started with different prompts "
                     f"({old.get('prompt_hash')} vs {meta['prompt_hash']}); "
                     "use a new --out so results don't mix")
        old_cells = {(c["model"], c["audit_cell"]): c for c in old.get("cells", [])}
        for c in meta["cells"]:   # keep validators and labels from earlier invocations
            prev = old_cells.pop((c["model"], c["audit_cell"]), None)
            if prev:
                c["labels"] = {**prev.get("labels", {}), **c["labels"]}
                c["validations"] = {**prev.get("validations", {}), **c["validations"]}
        meta["cells"] += list(old_cells.values())
        meta["runs"] = max(meta["runs"], old.get("runs", 0))
        meta["started"] = old.get("started", meta["started"])
    write_json(meta_path, meta)

    if not a.no_baseline and not (out / "baseline" / "semgrep.json").exists():
        print("\n=== baseline: semgrep (tool only) ===", flush=True)
        try:
            t0 = time.monotonic()
            fs = semgrep_baseline(a.repo, a.semgrep_config)
            write_json(out / "baseline" / "semgrep.json",
                       {"findings": fs, "wall_seconds": round(time.monotonic() - t0, 2)})
        except Exception as e:
            print(f"  ! semgrep baseline failed: {e}")

    log = lambda m: print(m, flush=True)  # noqa: E731
    try:
        for c in cells:
            for k in range(1, a.runs + 1):
                d = out / safe(c["model"]) / c["audit"].cell() / f"run{k}"
                print(f"\n=== {c['model']} {c['audit'].cell()} run {k}/{a.runs} ===",
                      flush=True)
                a.spend.check()
                audit = run_audit_pass(c, k, ws, units, d, a, log)
                for vcfg in c["validations"].values():
                    run_validation(c, audit, vcfg, ws, d, a, log)
    except BudgetExceeded as e:
        sys.exit(f"\nbudget reached: {e}\nfinished work is saved; rerun with "
                 f"--out {out} (and a new --max-usd) to continue where this stopped")
    except FatalBackendError as e:
        sys.exit(f"\nstopping: {e}\nfinished units are saved; fix it and rerun "
                 f"with --out {out} to resume")

    print(f"\ndone. {a.spend.summary()}\nresults in {out}\n"
          f"score them (free): python eval/report.py {out}")


if __name__ == "__main__":
    main()
