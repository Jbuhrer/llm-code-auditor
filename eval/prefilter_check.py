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

from auditor.prefilter import KEYWORDS, drop_reason, is_non_product, is_test  # noqa: E402


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


def keyword_stats(repo: Path, labels: list[dict], classes: list[str]) -> str:
    """What each keyword costs and buys: files kept ONLY because of it (dropping
    the keyword drops exactly those), and which keywords keep each CVE's bug file."""
    words = sorted({w for c in classes for w in KEYWORDS.get(c, [])})
    sole, any_hit, kept, texts = {w: 0 for w in words}, {w: 0 for w in words}, 0, {}
    for f in sorted(repo.rglob("*.java")):
        rel = f.relative_to(repo).as_posix()
        inner = rel.partition("/")[2]
        if not inner or is_test(inner) or is_non_product(inner):
            continue
        text = f.read_text(errors="replace")
        hits = [w for w in words if w in text]
        if not hits:
            continue
        kept += 1
        texts[rel] = hits
        for w in hits:
            any_hit[w] += 1
        if len(hits) == 1:
            sole[hits[0]] += 1
    out = [f"\n# keyword stats: {kept} files kept\n",
           "| keyword | files only it keeps | files it matches |", "|---|---|---|"]
    for w in sorted(words, key=lambda w: -sole[w]):
        out.append(f"| `{w}` | {sole[w]} | {any_hit[w]} |")
    out.append("\n# keywords keeping each CVE's bug files\n")
    by_cve: dict[str, set] = {}
    for l in labels:
        by_cve.setdefault(l.get("cve") or l["file"], set()).update(texts.get(l["file"], ["(dropped)"]))
    for cve, ws in sorted(by_cve.items()):
        out.append(f"- {cve}: {', '.join(sorted(ws))}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo")
    ap.add_argument("labels")
    ap.add_argument("--bugs", nargs="+", default=["path", "cmdi", "xss", "codei"])
    ap.add_argument("--keywords", action="store_true",
                    help="also print what each keyword costs (files kept only by it)")
    a = ap.parse_args()
    labels = json.loads(Path(a.labels).read_text())
    print(check(Path(a.repo), labels, a.bugs))
    if a.keywords:
        print(keyword_stats(Path(a.repo), labels, a.bugs))


if __name__ == "__main__":
    main()
