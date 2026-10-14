"""Map any finding to a canonical bug class: by CWE first, then name keywords."""
import re

CWE_TO_CLASS = {
    "89": "sqli", "564": "sqli",
    "78": "cmdi", "77": "cmdi", "88": "cmdi",
    "22": "path", "23": "path", "36": "path",
    "476": "npd", "416": "uaf",
    "918": "ssrf", "611": "xxe", "502": "deserialization",
    "79": "xss", "80": "xss", "1336": "ssti",
    "327": "crypto", "328": "crypto", "330": "crypto", "338": "crypto",
    "798": "crypto", "321": "crypto",
    "639": "idor", "284": "idor", "285": "idor", "862": "idor", "863": "idor",
    "94": "codei", "95": "codei", "917": "codei",
}

KEYWORDS = [
    ("sqli", ("sql",)),
    ("cmdi", ("command injection", "os command", "shell injection", "cmdi")),
    ("path", ("path traversal", "directory traversal", "path manipulation")),
    ("ssrf", ("ssrf", "server-side request", "server side request")),
    ("xxe", ("xxe", "xml external")),
    ("deserialization", ("deserializ",)),
    ("ssti", ("template injection", "ssti")),
    ("xss", ("xss", "cross-site scripting", "cross site scripting")),
    ("crypto", ("crypto", "weak hash", "hardcoded key", "hard-coded",
                "weak random", "insecure random")),
    ("idor", ("idor", "access control", "authorization", "insecure direct")),
    ("npd", ("null pointer", "null dereference")),
    ("uaf", ("use after free", "use-after-free")),
    ("codei", ("code injection", "expression language", "el injection",
               "ognl", "spel", "script injection", "eval injection")),
]


def canonical_class(finding: dict) -> str:
    raw = str(finding.get("bug_class", "")).strip().lower()
    if raw in {c for c, _ in KEYWORDS}:
        return raw
    m = re.search(r"(\d+)", str(finding.get("cwe", "")))
    cwe = str(int(m.group(1))) if m else ""   # "CWE-094" and "CWE-94" are the same
    if cwe in CWE_TO_CLASS:
        return CWE_TO_CLASS[cwe]
    for cls, words in KEYWORDS:
        if any(w in raw for w in words):
            return cls
    return "other"
