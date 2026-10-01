"""
Variant hunting, adapted from Trail of Bits' variant-analysis skill.

One real bug usually has siblings: the same mistake repeated elsewhere. After a
finding is confirmed, this derives a search pattern from it, greps the repo for
other places that match, and returns candidate locations for a focused re-audit.
This is a cheap multiplier on real projects, where copy-paste and shared idioms
mean a single seed often uncovers several more bugs.
"""
from __future__ import annotations
import re

from .tools import Workspace

# per-bug-class search seeds: the sink shapes worth re-hunting once one is found
CLASS_PATTERNS = {
    "sqli": [r"\.execute\(", r"\.executemany\(", r"cursor\.", r"SELECT .*\+"],
    "cmdi": [r"os\.system\(", r"subprocess\.", r"os\.popen\(", r"eval\(", r"exec\("],
    "path": [r"open\(", r"os\.path\.join\(", r"\.\./", r"send_file\("],
    "npd":  [r"->", r"\bdereference\b"],
    "uaf":  [r"free\(", r"delete "],
}


def find_variants(ws: Workspace, finding: dict, max_hits: int = 40) -> list[str]:
    """Return grep hit lines for patterns matching this finding's bug class,
    excluding the file:line of the original finding."""
    cls = finding.get("bug_class", "")
    patterns = CLASS_PATTERNS.get(cls, [])
    origin_file = finding.get("file", "")
    origin_line = finding.get("line", -1)

    seen, hits = set(), []
    for pat in patterns:
        raw = ws.grep(pat)
        if raw.startswith("(no matches"):
            continue
        for line in raw.splitlines():
            # grep lines look like path:lineno:content
            m = re.match(r"^(.*?):(\d+):", line)
            if not m:
                continue
            f, n = m.group(1), int(m.group(2))
            if origin_file and f.endswith(origin_file) and n == origin_line:
                continue  # skip the exact original line only
            key = (f, n)
            if key in seen:
                continue
            seen.add(key)
            hits.append(line)
            if len(hits) >= max_hits:
                return hits
    return hits
