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
from .classes import canonical_class

# per-bug-class search seeds: the sink shapes worth re-hunting once one is found
CLASS_PATTERNS = {
    "sqli": [r"\.execute\(", r"\.executemany\(", r"cursor\.", r"addBatch\(",
             r"createStatement\(", r"SELECT .*\+"],
    "cmdi": [r"os\.system\(", r"subprocess\.", r"os\.popen\(", r"eval\(",
             r"exec\(", r"Runtime\.getRuntime", r"ProcessBuilder"],
    "path": [r"open\(", r"os\.path\.join\(", r"\.\./", r"send_file\(",
             r"FileInputStream", r"new File\(", r"Paths\.get"],
    "npd":  [r"->", r"\bdereference\b"],
    "uaf":  [r"free\(", r"delete "],
    # broader classes exhaustive mode may surface
    "ssrf": [r"requests\.(get|post)\(", r"urlopen\(", r"HttpURLConnection",
             r"\.openConnection\(", r"fetch\(", r"curl"],
    "xxe":  [r"DocumentBuilder", r"SAXParser", r"XMLReader", r"etree\.parse"],
    "deserialization": [r"pickle\.loads", r"ObjectInputStream", r"yaml\.load\(",
                        r"readObject\(", r"Marshal"],
    "xss":  [r"innerHTML", r"document\.write", r"render_template_string",
             r"\.html\(", r"dangerouslySetInnerHTML"],
    "ssti": [r"render_template_string", r"Template\(", r"\.render\("],
    "crypto": [r"\bMD5\b", r"\bSHA1\b", r"\bDES\b", r"\bECB\b", r"Random\(",
               r"math\.random", r"hardcoded", r"secret\s*="],
    "idor": [r"findById", r"get_object_or_404", r"request\.(args|params|GET)"],
}


def find_variants(ws: Workspace, finding: dict, max_hits: int = 40) -> list[str]:
    """Return grep hit lines for patterns matching this finding's bug class,
    excluding the file:line of the original finding."""
    cls = canonical_class(finding)
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
