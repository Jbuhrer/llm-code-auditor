"""
SARIF -> common finding schema.

SARIF is the standard output format for static-analysis tools (Semgrep, CodeQL,
and the Trail of Bits static-analysis / c-review skills all emit it). Normalizing
everything through SARIF is what lets a baseline tool, a ToB skill, and the agent
share one scoring harness.

Class mapping: rule-id keywords first, then the rule's CWE tags (tools put those
on the rule definition under runs[].tool.driver.rules, not on each result), then
"other".
"""
from __future__ import annotations
import json
import re

from .classes import canonical_class

# Map tool-specific rule ids (substring, case-insensitive) to bug classes.
RULE_TO_CLASS = {
    "sql": "sqli",
    "command-injection": "cmdi",
    "os-command": "cmdi",
    "dangerous-subprocess": "cmdi",
    "tainted-cmd": "cmdi",
    "cmd-injection": "cmdi",
    "path-traversal": "path",
    "tainted-path": "path",
    "null-deref": "npd",
    "use-after-free": "uaf",
}


def _classify(rule_id: str, cwe: str) -> str:
    r = (rule_id or "").lower()
    for key, cls in RULE_TO_CLASS.items():
        if key in r:
            return cls
    return canonical_class({"bug_class": "", "cwe": cwe})


def _rule_cwes(run: dict) -> dict[str, str]:
    """rule id -> first CWE id found in that rule's metadata."""
    out = {}
    for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
        m = re.search(r"CWE-\d+", json.dumps(rule.get("properties", {})))
        if m:
            out[rule.get("id", "")] = m.group(0)
    return out


def sarif_to_findings(sarif: dict | str) -> list[dict]:
    if isinstance(sarif, str):
        sarif = json.loads(sarif)
    findings: list[dict] = []
    for run in sarif.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        rule_cwes = _rule_cwes(run)
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "")
            cwe = _extract_cwe(res) or rule_cwes.get(rule_id, "")
            for loc in res.get("locations", []):
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine", -1)
                findings.append({
                    "bug_class": _classify(rule_id, cwe),
                    "file": uri,
                    "line": line,
                    "cwe": cwe,
                    "severity": res.get("level", "warning"),
                    "confidence": 1.0,   # baseline tools do not self-score
                    "source_tool": tool,
                    "rule_id": rule_id,
                })
    return findings


def _extract_cwe(result: dict) -> str:
    for tag in result.get("properties", {}).get("cwe", []) or []:
        return tag
    m = re.search(r"CWE-\d+", json.dumps(result))
    return m.group(0) if m else ""
