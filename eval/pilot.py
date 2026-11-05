"""
Summarize a verifier pilot (experiment.py --verify-sample N). Free, no API calls.

For each pilot file: how many flags on labelled bugs the verifier kept, how many
off-target flags it rejected, refusals and errors, what it cost, and what the
full run would cost at that rate. Then how often each pair of verifiers agreed
on the same flags.

Off-target flags aren't known false positives (a project can have other real
bugs), so "rejected" there is a rejection rate, not FPs removed.

  python eval/pilot.py <results dir>
"""
from __future__ import annotations
import json
import sys
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auditor.pricing import records_cost  # noqa: E402
from eval.metrics import default_mode, finding_hits  # noqa: E402


def summarize(root: Path) -> str:
    meta = json.loads((root / "meta.json").read_text())
    labels = json.loads(Path(meta["labels"]).read_text())
    mode = default_mode(labels)
    out = ["| run | verifier | flags | real bugs kept | off-target rejected | "
           "refused | errors | unparseable | cost | full run at this rate |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    pairs = []
    for audit_path in sorted(root.glob("*/*/run*/audit.json")):
        rdir = audit_path.parent
        pilots = sorted(rdir.glob("pilot*-*.json"))
        if not pilots:
            continue
        findings = [f for u in json.loads(audit_path.read_text())["units"]
                    for f in u["findings"]]
        hits = finding_hits(findings, labels, mode, meta["repo"])
        verdicts = {}
        for p in pilots:
            v = json.loads(p.read_text())
            idx, recs = v["indices"], v["records"]
            on = [r for i, r in zip(idx, recs) if hits[i]]
            off = [r for i, r in zip(idx, recs) if not hits[i]]
            cost = records_cost(v["model"], recs)
            full = cost / len(recs) * len(findings) if cost is not None and recs else None
            name = p.stem.split("-", 1)[1]
            verdicts[name] = dict(zip(idx, (r["confirmed"] for r in recs)))
            out.append(
                f"| {rdir.relative_to(root).as_posix()} | {name} | {len(recs)} | "
                f"{sum(r['confirmed'] for r in on)}/{len(on)} | "
                f"{sum(not r['confirmed'] for r in off)}/{len(off)} | "
                f"{sum(r['refused'] for r in recs)} | {sum(bool(r['error']) for r in recs)} | "
                f"{sum('unparseable' in r['rejected_by'] for r in recs)} | "
                f"{'-' if cost is None else f'${cost:.2f}'} | "
                f"{'-' if full is None else f'${full:.2f} for {len(findings)} flags'} |")
        for a, b in combinations(sorted(verdicts), 2):
            shared = sorted(set(verdicts[a]) & set(verdicts[b]))
            if shared:
                same = sum(verdicts[a][i] == verdicts[b][i] for i in shared)
                pairs.append(f"- {a} vs {b}: agree on {same}/{len(shared)} flags")
    if len(out) == 2:
        return f"no pilot files under {root} (run experiment.py with --verify-sample N)"
    return "\n".join(out + (["\nagreement:"] + pairs if pairs else []))


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    print(summarize(Path(sys.argv[1])))


if __name__ == "__main__":
    main()
