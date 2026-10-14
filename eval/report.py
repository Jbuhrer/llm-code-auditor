#!/usr/bin/env python3
"""
Score a results folder and build the thesis tables. Zero API calls.

  python eval/report.py results/<ts> [--scoring function|line|testcase] [--boot 2000]

Writes <dir>/report.md and <dir>/report.json and prints the markdown:
  RO1  ablation table: median over runs with bootstrap 95% CIs, plus McNemar
       tests with effect sizes for each adjacent preset pair
  RO2  validator variants: false-positive cases removed vs true positives lost,
       tokens per FP removed, which checks did the rejecting, and which
       good-side findings survive every validator
  RO3  cost: tokens, dollars, wall time, and dollars per true positive
"""
from __future__ import annotations
import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from statistics import median

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor.pricing import cost_usd                       # noqa: E402
from eval.metrics import score, default_mode, _name        # noqa: E402
from eval.juliet_functions import locate                   # noqa: E402
from eval.stats import bootstrap_ci, majority, mcnemar     # noqa: E402

LADDER = [("C0", "C1"), ("C0", "C2"), ("C1", "C3"), ("C2", "C3"), ("C3", "C4"),
          ("C0", "C4")]


def safe(name: str) -> str:
    return name.replace(":", "_").replace("/", "_")


def _sum_usage(*us):
    out = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
    for u in us:
        for k in out:
            out[k] += (u or {}).get(k, 0)
    return out


def _tokens(u):
    return u["input"] + u["output"] + u["cache_read"] + u["cache_write"]


def load_runs(root: Path, meta: dict, labels, mode, repo):
    """rows[(model, cell, val)] = [per-run dict]"""
    rows: dict[tuple, list[dict]] = {}
    for cell in meta["cells"]:
        model, ac = cell["model"], cell["audit_cell"]
        cdir = root / safe(model) / ac
        for rdir in sorted(cdir.glob("run*")):
            ap = rdir / "audit.json"
            if not ap.exists():
                continue
            audit = json.loads(ap.read_text())
            findings = [f for u in audit["units"] for f in u["findings"]]
            audited = {t for u in audit["units"] for t in u["targets"]}
            labs = [l for l in labels if not audited or any(
                _name(t) == _name(l["file"]) for t in audited)]
            units = audit["units"]
            base = {
                "run": rdir.name, "findings": findings, "labels": labs,
                "audited": audited,
                "audit_usage": audit["usage"], "audit_seconds": audit["wall_seconds"],
                "refusals": sum(u["refused"] for u in units),
                "errors": sum(bool(u["error"]) for u in units),
                "unreported": sum(not u["reported"] and not u["error"] and not u["refused"]
                                  for u in units),
                "truncated": sum(u["context_truncated"] for u in units),
                "budget_exhausted": sum(u["budget_exhausted"] for u in units),
                "out_of_target": sum(u["dropped_out_of_target"] for u in units),
                "turns": sum(u["turns"] for u in units),
            }
            s = score(findings, labs, mode, repo)
            rows.setdefault((model, ac, "noval"), []).append(
                {**base, "score": s, "usage": audit["usage"],
                 "seconds": audit["wall_seconds"], "val": None})
            for vp in sorted(rdir.glob("val-*.json")):
                v = json.loads(vp.read_text())
                recs = v["records"]
                kept = [f for f, r in zip(findings, recs) if r["confirmed"]]
                rows.setdefault((model, ac, vp.stem), []).append({
                    **base, "score": score(kept, labs, mode, repo),
                    "usage": _sum_usage(audit["usage"], v["usage"]),
                    "val_usage": v["usage"], "val_records": recs,
                    "seconds": audit["wall_seconds"] + v["wall_seconds"],
                    "val_errors": sum(bool(r["error"]) for r in recs),
                    "val_refusals": sum(r["refused"] for r in recs)})
    return rows


def preset_names(meta) -> dict[tuple, list[str]]:
    out: dict[tuple, list[str]] = {}
    for cell in meta["cells"]:
        for label, val in cell.get("labels", {}).items():
            out.setdefault((cell["model"], cell["audit_cell"], val), []).append(label)
    return out


def fmt_ci(t):
    p, lo, hi = t
    return f"{p:.3f} [{lo:.3f}, {hi:.3f}]"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--scoring", default=None, choices=["function", "line", "testcase"])
    ap.add_argument("--boot", type=int, default=2000)
    a = ap.parse_args()

    root = Path(a.run_dir)
    meta = json.loads((root / "meta.json").read_text())
    labels = json.loads(Path(meta["labels"]).read_text())
    repo = meta["repo"]
    mode = a.scoring or default_mode(labels)
    rows = load_runs(root, meta, labels, mode, repo)
    names = preset_names(meta)
    md, js = [], {"scoring": mode, "rows": [], "mcnemar": [], "ro2": []}

    md.append(f"# Results: {root.name}\n")
    md.append(f"Scoring mode: `{mode}`. Units: {meta['n_units']} ({meta['unit_mode']}). "
              f"Prompt {meta['prompt_version']} ({meta['prompt_hash']}), git {meta['git']}.\n")
    md.append("Medians over runs; brackets are 95% bootstrap CIs over test cases.\n")

    # ------------------------------------------------------------ RO1 + RO3
    md.append("## RO1 / RO3: ablation table\n")
    md.append("| preset | model | cell | validation | runs | recall | precision | "
              "FP rate | finding FDR | localization | tokens | $ | $/TP | sec | "
              "refusals | errors |")
    md.append("|" + "---|" * 16)
    case_runs: dict[tuple, list[dict]] = {}
    def order(key):
        ps = names.get(key, [])
        return (min((p for p in ps), default="C9"), key)
    for key in sorted(rows, key=order):
        model, cell, val = key
        runs = rows[key]
        cr = [r["score"]["cases"] for r in runs]
        case_runs[key] = cr
        rec = bootstrap_ci(cr, "recall", a.boot)
        prec = bootstrap_ci(cr, "precision", a.boot)
        fpr = bootstrap_ci(cr, "fp_rate", a.boot)
        fdr = median(r["score"].get("fdr", 0) if mode != "function"
                     else 1 - r["score"].get("finding_precision", 0) for r in runs)
        loc = median(r["score"].get("localization", 0) for r in runs)
        toks = median(_tokens(r["usage"]) for r in runs)
        costs = [cost_usd(model, r["usage"]) for r in runs]
        cost = median(costs) if None not in costs else None
        tps = [r["score"]["tp"] for r in runs]
        cpt = median(c / t for c, t in zip(costs, tps) if t) if cost is not None and any(tps) else None
        sec = median(r["seconds"] for r in runs)
        refus = sum(r["refusals"] + r.get("val_refusals", 0) for r in runs)
        errs = sum(r["errors"] + r.get("val_errors", 0) for r in runs)
        preset = ", ".join(names.get(key, [])) or "-"
        md.append(f"| {preset} | {model} | {cell} | {val} | {len(runs)} | {fmt_ci(rec)} | "
                  f"{fmt_ci(prec)} | {fmt_ci(fpr)} | {fdr:.3f} | {loc:.3f} | {toks:,.0f} | "
                  f"{'-' if cost is None else f'{cost:.2f}'} | "
                  f"{'-' if cpt is None else f'{cpt:.3f}'} | {sec:.0f} | {refus} | {errs} |")
        js["rows"].append({"model": model, "cell": cell, "validation": val,
                           "presets": names.get(key, []), "runs": len(runs),
                           "recall": rec, "precision": prec, "fp_rate": fpr,
                           "finding_fdr": fdr, "localization": loc, "tokens": toks,
                           "cost_usd": cost, "cost_per_tp": cpt, "seconds": sec,
                           "refusals": refus, "errors": errs,
                           "per_run": [{k: r["score"][k] for k in r["score"] if k != "cases"}
                                       for r in runs]})

    warn = []
    for key, runs in rows.items():
        for r in runs:
            for k in ("unreported", "truncated", "budget_exhausted", "out_of_target"):
                if r[k]:
                    warn.append(f"{key[0]} {key[1]} {key[2]} {r['run']}: {r[k]} unit(s) {k}")
    if warn:
        md.append("\nRun health (worth a look before trusting a row):\n")
        md += [f"- {w}" for w in sorted(set(warn))[:40]]

    base_path = root / "baseline" / "semgrep.json"
    if base_path.exists():
        bf = json.loads(base_path.read_text())["findings"]
        # same file set the agent audited (all files of each unit, not only labelled ones)
        audited = {_name(t) for runs in rows.values() for r in runs for t in r["audited"]}
        bf = [f for f in bf if not audited or _name(f["file"]) in audited]
        labs = next((r["labels"] for runs in rows.values() for r in runs), labels)
        s = score(bf, labs, mode, repo)
        md.append(f"\nSemgrep tool-only baseline: recall {s['recall']:.3f}, precision "
                  f"{s['precision']:.3f}, TP {s['tp']}, FP {s['fp']}, findings {s['findings']}.")
        js["baseline_semgrep"] = {k: v for k, v in s.items() if k != "cases"}

    # ------------------------------------------------------------ McNemar
    by_preset = {(m, p): key for key, ps in names.items() for p in ps
                 for m in [key[0]] if key in case_runs}
    tests = []
    for model in meta["models"]:
        for pa, pb in LADDER:
            ka, kb = by_preset.get((model, pa)), by_preset.get((model, pb))
            if ka and kb:
                for outcome in ("hit", "fp"):
                    t = mcnemar(majority(case_runs[ka], outcome),
                                majority(case_runs[kb], outcome))
                    tests.append({"model": model, "a": pa, "b": pb, "outcome": outcome, **t})
    if tests:
        md.append("\n## RO1: paired tests (exact McNemar, per-case majority over runs)\n")
        md.append("`hit` = detected the bad side; `fp` = flagged the good side. "
                  "a_only/b_only are discordant case counts.\n")
        md.append("| model | A | B | outcome | cases | a_only | b_only | p | odds ratio | "
                  "Cohen's g | rate B - A |")
        md.append("|" + "---|" * 11)
        for t in tests:
            md.append(f"| {t['model']} | {t['a']} | {t['b']} | {t['outcome']} | "
                      f"{t['n_cases']} | {t['a_only']} | {t['b_only']} | {t['p_value']} | "
                      f"{t['odds_ratio']} | {t['cohens_g']} | {t['risk_diff']:+.3f} |")
        js["mcnemar"] = tests

    # ------------------------------------------------------------ RO2
    ro2 = []
    for (model, cell, val), runs in sorted(rows.items()):
        if val == "noval":
            continue
        base_runs = {r["run"]: r for r in rows.get((model, cell, "noval"), [])}
        removed, lost, vtok, rej = [], [], [], Counter()
        for r in runs:
            b = base_runs.get(r["run"])
            if not b:
                continue
            removed.append(b["score"]["fp"] - r["score"]["fp"])
            lost.append(b["score"]["tp"] - r["score"]["tp"])
            vtok.append(_tokens(r["val_usage"]))
            for rec in r["val_records"]:
                for why in rec["rejected_by"]:
                    rej[why] += 1
        if not removed:
            continue
        mr = median(removed)
        ro2.append({"model": model, "cell": cell, "validation": val,
                    "fp_cases_removed": mr, "tp_cases_lost": median(lost),
                    "validator_tokens": median(vtok),
                    "tokens_per_fp_removed": round(median(vtok) / mr) if mr > 0 else None,
                    "rejected_by": dict(rej.most_common())})
    if ro2:
        md.append("\n## RO2: validator variants vs the same raw findings\n")
        md.append("| model | cell | validation | FP cases removed | TP cases lost | "
                  "validator tokens | tokens per FP removed | rejected by |")
        md.append("|" + "---|" * 8)
        for r in ro2:
            rej = ", ".join(f"{k} {v}" for k, v in r["rejected_by"].items()) or "-"
            md.append(f"| {r['model']} | {r['cell']} | {r['validation']} | "
                      f"{r['fp_cases_removed']} | {r['tp_cases_lost']} | "
                      f"{r['validator_tokens']:,.0f} | {r['tokens_per_fp_removed'] or '-'} | {rej} |")
        js["ro2"] = ro2

    if mode == "function":
        survivors = Counter()
        repo_p = Path(repo)
        by_name = {p.name: p for p in repo_p.rglob("*") if p.is_file()}
        for (model, cell, val), runs in rows.items():
            if val != "val-path+sanitizer+conditions+poc":
                continue
            for r in runs:
                for f, rec in zip(r["findings"], r["val_records"]):
                    p = by_name.get(_name(f.get("file", "")))
                    if rec["confirmed"] and p and locate(p, int(f.get("line", -1)))[1] == "good":
                        survivors[f"{_name(f['file'])}:{f.get('line')} [{f.get('bug_class')}]"] += 1
        if survivors:
            md.append("\nGood-side findings that survived every evidence check "
                      "(count = runs x models):\n")
            md += [f"- {k}: {v}" for k, v in survivors.most_common(25)]
            js["surviving_fps"] = dict(survivors)

        # true positives the validator threw away, with its stated reason
        lost = []
        for (model, cell, val), runs in sorted(rows.items()):
            if val == "noval":
                continue
            for r in runs:
                for f, rec in zip(r["findings"], r["val_records"]):
                    p = by_name.get(_name(f.get("file", "")))
                    if rec["confirmed"] or not p:
                        continue
                    if locate(p, int(f.get("line", -1)))[1] != "bad":
                        continue
                    reason = str((rec.get("verdict") or {}).get("reason", "")).strip()
                    lost.append({"model": model, "validation": val, "run": r["run"],
                                 "where": f"{_name(f['file'])}:{f.get('line')}",
                                 "rejected_by": rec["rejected_by"],
                                 "reason": reason or rec.get("error") or ""})
        if lost:
            md.append("\n## RO2: true positives the validator rejected\n")
            md.append("| model | validation | finding | rejected by | validator's reason |")
            md.append("|" + "---|" * 5)
            for x in lost[:40]:
                md.append(f"| {x['model']} | {x['validation']} | {x['where']} | "
                          f"{', '.join(x['rejected_by'])} | {x['reason'][:160]} |")
            if len(lost) > 40:
                md.append(f"\n({len(lost) - 40} more in report.json)")
            js["validator_lost_tps"] = lost

    # ------------------------------------------------------------ strata
    strata = {}
    for l in labels:
        if "testcase" in l:
            src = str(l.get("source_variant", "")).split("_")[0] or "?"
            strata[l["testcase"]] = (src, bool(l.get("crosses_function")))
    if strata:
        srcs = sorted({s for s, _ in strata.values()})
        md.append("\n## Recall by stratum (median over runs)\n")
        md.append("Columns: whether the bad path crosses a function boundary, then the "
                  "Juliet source variant. Cells are recall over that stratum's cases.\n")
        head = ["preset", "model", "cell", "validation", "cross fn", "in fn"] + srcs
        md.append("| " + " | ".join(head) + " |")
        md.append("|" + "---|" * len(head))
        js["strata"] = []
        for key in sorted(rows, key=order):
            model, cell, val = key
            groups = {"cross fn": [c for c, (_, x) in strata.items() if x],
                      "in fn": [c for c, (_, x) in strata.items() if not x]}
            for s in srcs:
                groups[s] = [c for c, (src, _) in strata.items() if src == s]
            vals = {}
            for g, cs in groups.items():
                per_run = []
                for r in rows[key]:
                    cases = r["score"]["cases"]
                    have = [c for c in cs if c in cases]
                    if have:
                        per_run.append(sum(cases[c]["hit"] for c in have) / len(have))
                vals[g] = median(per_run) if per_run else None
            cells = ["-" if vals[g] is None else f"{vals[g]:.2f}" for g in groups]
            md.append(f"| {', '.join(names.get(key, [])) or '-'} | {model} | {cell} | {val} | "
                      + " | ".join(cells) + " |")
            js["strata"].append({"model": model, "cell": cell, "validation": val,
                                 "recall": vals})

    text = "\n".join(md) + "\n"
    (root / "report.md").write_text(text, encoding="utf-8")
    (root / "report.json").write_text(json.dumps(js, indent=2, default=str))
    print(text)


if __name__ == "__main__":
    main()
