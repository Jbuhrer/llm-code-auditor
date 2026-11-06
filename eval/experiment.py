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
import random
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor.agent import Auditor, FatalBackendError, is_fatal, is_fatal_msg      # noqa: E402
from auditor.batch import run_batch                                 # noqa: E402
from auditor.baseline import semgrep_baseline                       # noqa: E402
from auditor.budget import Budget, BudgetExceeded                   # noqa: E402
from auditor.config import (AuditConfig, ValidationConfig, PRESETS,  # noqa: E402
                            full_factorial, validation_variants, EVIDENCE)
from auditor.llm import make_backend                                # noqa: E402
from auditor.pricing import (BATCH_DISCOUNT, compat_server_is_local,  # noqa: E402
                             cost_usd, records_cost)
from auditor.prompts import PROMPT_VERSION, prompt_fingerprint, THREAT_MODELS  # noqa: E402
from auditor.tools import Workspace, semgrep_exe                    # noqa: E402
from auditor.units import build_units, est_tokens                   # noqa: E402
from auditor.validate import (MAX_TOKENS as VALIDATE_MAX_TOKENS,    # noqa: E402
                              finish_validation, prepare_validation, validate_one, scope_to_root)
from eval.metrics import default_mode, finding_hits                 # noqa: E402

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


def preflight(models: list[str], max_usd: float | None = None) -> list[str]:
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
        if not compat_server_is_local() and not os.environ.get("OPENAI_COMPAT_API_KEY"):
            probs.append("hosted openai-compat server: set OPENAI_COMPAT_API_KEY")
    unpriced = [m for m in models if cost_usd(m, {}) is None]
    if max_usd is not None and unpriced:
        probs.append(f"--max-usd can't count {', '.join(unpriced)}: no price entry in "
                     "auditor/pricing.py, so the cap would never trip")
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
    retarget = lambda v: (replace(v, model=a.verifier_model)  # noqa: E731
                          if v.enabled and a.verifier_model else v)
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
            val = retarget(val)
            key = (model, cfg.cell())
            cell = cells.setdefault(key, {"model": model, "audit": cfg, "labels": {},
                                          "validations": {}})
            for v in [val] + [retarget(x) for x in extra_vals]:
                if v.enabled:
                    cell["validations"][v.name()] = v
            if label:
                cell["labels"][label] = val.name()
    return list(cells.values())


def run_audit_pass(cell, run_k, ws, units, out_dir, a, log) -> dict:
    path = out_dir / "audit.json"
    part = out_dir / "audit.partial.jsonl"
    prior = json.loads(path.read_text())["units"] if path.exists() else read_jsonl(part)
    # units that errored (rate limit, out of credits, outage) are retried, not kept
    done = {r["unit"]: r for r in prior if not r.get("error")}
    if path.exists() and len(done) == len(units):
        log(f"  (have {path}, skipping)")
        return json.loads(path.read_text())
    if prior:
        log(f"  resuming: {len(done)} unit(s) done, {len(prior) - len(done)} "
            f"errored unit(s) will be retried")
    if path.exists():   # rebuild it from the good records plus the retries
        for r in done.values():
            append_jsonl(part, r)
        path.unlink()
        for f in out_dir.iterdir():   # validation is indexed by finding, now stale
            if f.name not in ("audit.json", part.name) and f.suffix in (".json", ".jsonl"):
                f.unlink()
    cfg: AuditConfig = cell["audit"]
    backend = make_backend(cfg.model, cfg.effort, cfg.temperature)
    t0 = time.monotonic()
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


def pilot_sample(findings, labels, mode, repo, n: int, seed: int) -> list[int]:
    """Indices of a seeded pilot sample: half on labelled bugs (so we can see how
    many real bugs the verifier keeps), half off-target. Picked from the audit and
    labels only, so every verifier model gets the same flags."""
    hits = finding_hits(findings, labels, mode, repo)
    on = [i for i, h in enumerate(hits) if h]
    off = [i for i, h in enumerate(hits) if not h]
    rng = random.Random(seed)
    k = min(len(on), n // 2)
    return sorted(rng.sample(on, k) + rng.sample(off, min(len(off), n - k)))


def run_validation(cell, audit, vcfg: ValidationConfig, ws, out_dir, a, log) -> None:
    findings = [f for u in audit["units"] for f in u["findings"]]
    subset, stem = list(range(len(findings))), vcfg.name()
    if getattr(a, "verify_sample", None):
        subset = pilot_sample(findings, a.labels_data, a.mode, a.repo, a.verify_sample,
                              a.sample_seed)
        stem = f"pilot{a.verify_sample}-{stem}"   # report.py only reads val-*.json
    path = out_dir / f"{stem}.json"
    if path.exists() and not any(r.get("error") for r in
                                 json.loads(path.read_text())["records"]):
        return
    cfg: AuditConfig = cell["audit"]
    model = vcfg.model or cfg.model
    backend = make_backend(model, cfg.effort, cfg.temperature)
    log(f"  validating {len(subset)} of {len(findings)} finding(s) with {stem}")
    t0 = time.monotonic()
    part = out_dir / f"{stem}.partial.jsonl"
    if path.exists():
        old = json.loads(path.read_text())
        prior = [{"i": i, "rec": r} for i, r in
                 zip(old.get("indices") or range(len(old["records"])), old["records"])]
    else:
        prior = read_jsonl(part)
    done = {e["i"]: e["rec"] for e in prior if not e["rec"].get("error")}
    if path.exists():
        for i, r in done.items():
            append_jsonl(part, {"i": i, "rec": r})
        path.unlink()
    unit_files = {u["unit"]: u["targets"] for u in audit["units"]}
    unit_roots = {u["unit"]: u.get("root") for u in audit["units"]}

    def scoped(i):
        u = findings[i].get("unit")
        return scope_to_root(ws, dict(findings[i]), unit_files.get(u), unit_roots.get(u))
    lock = threading.Lock()

    stop = []

    def one(i):
        if a.spend.exceeded or stop:
            return
        sws, f, files = scoped(i)
        rec = validate_one(backend, sws, f, vcfg, cfg.threat_model, files)
        if rec.get("error") and is_fatal_msg(rec["error"]):
            stop.append(rec["error"])
            raise FatalBackendError(rec["error"])
        a.spend.add(cost_usd(model, rec["usage"]))
        with lock:
            append_jsonl(part, {"i": i, "rec": rec})
            done[i] = rec

    def save(i, rec):
        with lock:
            append_jsonl(part, {"i": i, "rec": rec})
            done[i] = rec

    todo = [i for i in subset if i not in done]
    if getattr(a, "batch", False) and todo:
        if model.startswith("openai-compat:"):
            sys.exit("--batch is for Claude models (Message Batches)")
        validate_batch(todo, scoped, vcfg, cfg, backend, model,
                       out_dir / f"{stem}.batch.json", a, log, save)
    else:
        with ThreadPoolExecutor(max_workers=max(1, a.workers)) as pool:
            list(pool.map(one, todo))
    if any(i not in done for i in subset):
        a.spend.check()   # stopped early: partial file stays for the next run
    recs = [done[i] for i in subset]
    total = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
    for r in recs:
        for k in total:
            total[k] += r["usage"].get(k, 0)
    write_json(path, {"validation": vcfg.as_dict(), "model": model,
                      "indices": subset if stem != vcfg.name() else None,
                      "records": recs, "usage": total,
                      "cost_usd": records_cost(model, recs),
                      "wall_seconds": round(time.monotonic() - t0, 2)})
    part.unlink(missing_ok=True)


def validate_batch(todo, scoped, vcfg, cfg, backend, model, state,
                   a, log, save) -> None:
    """The same validation calls through Message Batches, at half price.
    scoped(i) gives (workspace, finding, unit files) as the validator sees them."""
    pending, prompts = {}, {}
    for i in todo:
        sws, f, files = scoped(i)
        rec, prompt, file = prepare_validation(sws, f, vcfg, cfg.threat_model, files)
        if prompt is None:
            save(i, rec)
        else:
            pending[i], prompts[f"f{i}"] = (rec, file, sws), prompt
    if not prompts:
        return
    est = sum(est_tokens(p) for p in prompts.values())
    est_usd = cost_usd(model, {"input": est})
    est_usd = None if est_usd is None else est_usd * BATCH_DISCOUNT
    log(f"  {len(prompts)} request(s), ~{est:,} input tokens" +
        ("" if est_usd is None else f", ~${est_usd:.2f} for input at batch price, plus output"))
    if (not state.exists() and est_usd is not None and a.spend.limit is not None
            and a.spend.spent + est_usd > a.spend.limit):
        raise BudgetExceeded(f"the batch's input alone is ~${est_usd:.2f}, over what's "
                             f"left of the ${a.spend.limit:.2f} cap")
    try:
        replies = run_batch(backend, prompts, VALIDATE_MAX_TOKENS, state, log)
    except Exception as e:
        if is_fatal(e):
            raise FatalBackendError(f"{type(e).__name__}: {e}") from e
        raise
    fatal = None
    for key, r in replies.items():
        i = int(key[1:])
        if i not in pending:
            continue
        rec, file, sws = pending[i]
        if isinstance(r, str):
            rec["error"] = r
            fatal = fatal or (r if is_fatal_msg(r) else None)
        else:
            rec = finish_validation(rec, r, sws, vcfg, file)
            rec["price_mult"] = BATCH_DISCOUNT
            a.spend.add(records_cost(model, [rec]))
        save(i, rec)
    if fatal:
        raise FatalBackendError(fatal)


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
    ap.add_argument("--verifier-model", default=None,
                    help="validate with this model instead of the one that did the audit "
                         "(a cascade); reuse an --out to check an existing run's findings")
    ap.add_argument("--verify-sample", type=int, default=None, metavar="N",
                    help="pilot: validate only a seeded sample of N findings (half on "
                         "labelled bugs), saved as pilot<N>-*.json; summarize with "
                         "eval/pilot.py")
    ap.add_argument("--sample-seed", type=int, default=0)
    ap.add_argument("--batch", action="store_true",
                    help="send validation calls through Message Batches (half price, "
                         "can take up to 24h; Ctrl-C and rerun resumes the same batch)")
    ap.add_argument("--evidence-sweep", action="store_true",
                    help="RO2: plain, each evidence item alone, and all")
    ap.add_argument("--unit", default=None,
                    choices=["file", "testcase", "repo", "project-file", "project-file-all"],
                    help="default: testcase for Juliet, project-file (pre-filtered, one project "
                         "per unit) for CWE-Bench-Java, file otherwise")
    ap.add_argument("--budget", type=int, default=24000, help="context tokens per unit")
    ap.add_argument("--max-turns", type=int, default=15)
    ap.add_argument("--effort", default="medium", help="Claude effort, held fixed")
    ap.add_argument("--temperature", type=float, default=None,
                    help="open-weight backends only")
    ap.add_argument("--semgrep-config", default="auto")
    ap.add_argument("--stance", default="precise", choices=["precise", "screen"],
                    help="screen: recall-first first stage of a cascade (cell name "
                         "gets a -screen suffix so results don't mix)")
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
    mode = default_mode(labels)
    a.labels_data, a.mode = labels, mode
    unit_mode = a.unit or {"function": "testcase", "method": "project-file"}.get(mode, "file")
    units = build_units(ws, unit_mode, list(a.bugs))
    if a.limit:
        units = spread_limit(units, a.limit)
    base = AuditConfig(context_budget=a.budget, max_turns=a.max_turns, effort=a.effort,
                       temperature=a.temperature, semgrep_config=a.semgrep_config,
                       threat_model=a.threat_model, stance=a.stance,
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
    probs = preflight(a.models + ([a.verifier_model] if a.verifier_model else []), a.max_usd)
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
            multi = unit_mode.startswith("project-file")
            fs = semgrep_baseline(a.repo, a.semgrep_config, per_project=multi,
                                  include=["*.java"] if multi else None,
                                  timeout=1800 if multi else 600)
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
