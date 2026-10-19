"""
Why did the pre-filter drop a CVE? Free, no API calls.

For every CVE whose labelled files were all skipped by the project-file unit
builder, prints each labelled file, the reason it was skipped, and the lines
around the labelled method so the missing sink API is visible.

  python eval/prefilter_check.py <projects dir> <labels.json> --bugs path cmdi xss codei
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auditor.prefilter import drop_reason  # noqa: E402


def check(repo: Path, labels: list[dict], classes: list[str], context: int = 12) -> str:
    by_cve: dict[str, list[dict]] = {}
    for l in labels:
        by_cve.setdefault(l.get("cve") or l["file"], []).append(l)
    out, dropped = [], 0
    for cve, ls in sorted(by_cve.items()):
        rows = []
        for l in ls:
            path = repo / l["file"]
            inner = l["file"].partition("/")[2]
            if not path.exists():
                rows.append((l, "file not in workspace", []))
                continue
            text = path.read_text(errors="replace")
            rows.append((l, drop_reason(inner, text, classes), text.splitlines()))
        if any(why is None for _, why, _ in rows):
            continue
        dropped += 1
        out.append(f"\n## {cve} ({ls[0].get('bug_class')}, {ls[0].get('cwe')})")
        for l, why, lines in rows:
            out.append(f"- {l['file']}  method {l.get('method')}  line {l.get('line')}"
                       f"\n  dropped: {why}")
            n = int(l.get("line") or 0)
            if lines and n:
                lo, hi = max(0, n - 3), min(len(lines), n + context)
                out += [f"    {i + 1:5d}  {lines[i]}" for i in range(lo, hi)]
    head = f"{dropped} of {len(by_cve)} CVEs have every labelled file dropped."
    return head + "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo")
    ap.add_argument("labels")
    ap.add_argument("--bugs", nargs="+", default=["path", "cmdi", "xss", "codei"])
    a = ap.parse_args()
    print(check(Path(a.repo), json.loads(Path(a.labels).read_text()), a.bugs))


if __name__ == "__main__":
    main()
