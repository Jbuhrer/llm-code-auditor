"""
SARIF -> common finding schema.

SARIF is the standard output format for static-analysis tools (Semgrep, CodeQL,
and the Trail of Bits static-analysis / c-review skills all emit it). Normalizing
everything through SARIF is what lets you compare a baseline tool, a ToB skill,
and your own agent on the SAME scoring harness. This is the interoperability
layer your evaluation depends on.

A rule-id -> bug_class map is needed because every tool names checks differently.
Extend RULE_TO_CLASS as you add tools/rules; unmapped rules fall back to "other".
"""
from __future__ import annotations
import json
import re

# Map tool-specific rule ids (substring, case-insensitive) to your bug classes.
RULE_TO_CLASS = {
    "sql": "sqli",
    "tainted-sql": "sqli",
    "command-injection": "cmdi",
    "os-command": "cmdi",
    "dangerous-subprocess": "cmdi",
    "path-traversal": "path",
    "tainted-path": "path",
    "null-deref": "npd",
    "use-after-free": "uaf",
}


def _classify(rule_id: str) -> str:
    r = (rule_id or "").lower()
    for key, cls in RULE_TO_CLASS.items():
        if key in r:
            return cls
    return "other"


def sarif_to_findings(sarif: dict | str) -> list[dict]:
    if isinstance(sarif, str):
        sarif = json.loads(sarif)
    findings: list[dict] = []
    for run in sarif.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "")
            for loc in res.get("locations", []):
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine", -1)
                findings.append({
                    "bug_class": _classify(rule_id),
                    "file": uri,
                    "line": line,
                    "cwe": _extract_cwe(res),
                    "severity": res.get("level", "warning"),
                    "confidence": 1.0,   # baseline tools do not self-score
                    "source_tool": tool,
                    "rule_id": rule_id,
                })
    return findings


def _extract_cwe(result: dict) -> str:
    for tag in result.get("properties", {}).get("cwe", []) or []:
        return tag
    text = json.dumps(result)
    m = re.search(r"CWE-\d+", text)
    return m.group(0) if m else ""
