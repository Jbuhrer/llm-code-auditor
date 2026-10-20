"""
Compare two results folders CVE by CVE (free; run report.py on both first).

Splits the recall change into CVEs both runs could reach (a bug file was
audited in both, so the agent made the difference) and CVEs only one run
could reach (the pre-filter made the difference).

  python eval/compare.py results/A results/B [--cell-a C2] [--cell-b C2]
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path


def load(run_dir: Path, preset: str | None) -> tuple[dict, set[str], set[str]]:
    js = json.loads((run_dir / "report.json").read_text())
    rows = [r for r in js["rows"] if not preset or preset in r.get("presets", [])]
    if len(rows) != 1:
        raise SystemExit(f"{run_dir}: {len(rows)} rows match {preset!r}; pass --cell-a/--cell-b "
                         f"with one of {[r.get('presets') for r in js['rows']]}")
    pre = js.get("prefilter", {})
    return rows[0], set(rows[0].get("hits", [])), set(pre.get("reachable", []))


def compare(a, b) -> str:
    (ra, ha, reach_a), (rb, hb, reach_b) = a, b
    both = reach_a & reach_b
    out = [f"A: {ra['cell']}  B: {rb['cell']}",
           f"reachable by both: {len(both)} CVEs; only B: {sorted(reach_b - reach_a)}; "
           f"only A: {sorted(reach_a - reach_b)}", ""]
    hb_both, ha_both = hb & both, ha & both
    out.append(f"on the {len(both)} shared CVEs: A caught {len(ha_both)}, B caught {len(hb_both)}"
               f" (B only: {sorted(hb_both - ha_both)}; A only: {sorted(ha_both - hb_both)})")
    out.append(f"B catches among CVEs only B could reach: {sorted(hb & (reach_b - reach_a))}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--cell-a", default=None, help="preset name, e.g. C2")
    ap.add_argument("--cell-b", default=None)
    x = ap.parse_args()
    print(compare(load(Path(x.a), x.cell_a), load(Path(x.b), x.cell_b)))


if __name__ == "__main__":
    main()
