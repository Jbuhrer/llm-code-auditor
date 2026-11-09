#!/usr/bin/env python3
"""
Calibrate hunt.py on known CVEs (free, no API calls).

Point hunt.py at a CWE-Bench-Java project at its vulnerable commit, then:

  python eval/hunt_check.py <labels.json> <projects_dir> results/hunt-<slug> [more ...]

For each hunt it says whether any lead lands in a method the CVE's fix changed
(the same rule as eval/report.py's method scoring), where the first such lead
ranks, and what the deep dive concluded about it. A project's folder name is
<owner>__<repo>_<CVE>_<version>; hunt.py never shows it to the model.

Caveat for the write-up: these are known CVEs, so a hit can come from training
data. It checks the pipeline, it isn't a zero-day hit rate.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from eval.metrics import finding_cves  # noqa: E402

TOP = 15


def check(hunt_dir: Path, labels: list[dict], projects: Path) -> dict:
    meta = json.loads((hunt_dir / "meta.json").read_text())
    slug = Path(meta["repo"]).name
    mine = [l for l in labels if l.get("project") == slug]
    ranked = json.loads((hunt_dir / "findings.json").read_text())["ranked"]
    flags = [dict(r["flag"], file=f"{slug}/{r['flag'].get('file', '')}") for r in ranked]
    hits = finding_cves(flags, mine, projects) if mine else [[] for _ in flags]
    files = {l["file"] for l in mine}
    first = next((i for i, h in enumerate(hits) if h), None)
    out = {"slug": slug, "cve": mine[0]["cve"] if mine else "?", "labels": len(mine),
           "flags": len(ranked), "in_file": sum(f["file"] in files for f in flags),
           "hit_flags": sum(bool(h) for h in hits), "first_rank": None,
           "deep_dived": False, "deep_verdict": None, "deep_score": None,
           "triage_score": None, "top": False, "cost": None}
    costs = json.loads((hunt_dir / "findings.json").read_text()).get("costs", {})
    out["cost"] = costs.get("total")
    if first is not None:
        r = ranked[first]
        out["first_rank"] = first + 1
        out["top"] = first < TOP
        out["triage_score"] = (r.get("triage") or {}).get("score")
        if r.get("deep"):
            out["deep_dived"] = True
            out["deep_score"] = r["deep"].get("score")
            out["deep_verdict"] = (r["deep"].get("verdict") or {}).get("verdict")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("labels", type=Path)
    ap.add_argument("projects", type=Path)
    ap.add_argument("hunts", nargs="+", type=Path)
    a = ap.parse_args()
    labels = json.loads(a.labels.read_text())
    rows = [check(h, labels, a.projects) for h in a.hunts]
    print(f"| CVE | flags | in bug file | on bug method | first rank | top {TOP} | "
          "triage | deep verdict | deep score | $ |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        dash = lambda v: "-" if v is None else v   # noqa: E731
        print(f"| {r['cve']} | {r['flags']} | {r['in_file']} | {r['hit_flags']} | "
              f"{dash(r['first_rank'])} | {'yes' if r['top'] else 'no'} | "
              f"{dash(r['triage_score'])} | {dash(r['deep_verdict'])} | "
              f"{dash(r['deep_score'])} | {dash(r['cost'])} |")
    found = [r for r in rows if r["first_rank"]]
    kept = [r for r in found if r["deep_verdict"] in ("confirmed", "likely")]
    print(f"\nscreen flagged the bug's method in {len(found)}/{len(rows)}; "
          f"in the top {TOP}: {sum(r['top'] for r in rows)}/{len(rows)}; "
          f"deep dive called it confirmed or likely: {len(kept)}/{len(rows)}")
    missing = [r["slug"] for r in rows if not r["labels"]]
    if missing:
        print(f"no labels found for: {', '.join(missing)} (wrong labels.json?)")


if __name__ == "__main__":
    main()
