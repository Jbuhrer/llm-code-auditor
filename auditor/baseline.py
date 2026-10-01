"""
Baseline detectors.

Your research contribution is measured RELATIVE to a strong baseline, not against
nothing. This runs plain Semgrep (and, once you wire it, CodeQL or a Trail of
Bits skill) as the "state of practice" row in your results table. Your agent has
to beat this on precision / false-positive rate to be worth anything, and showing
that with numbers is the thesis.

To use a Trail of Bits skill as the baseline instead, run it via Claude Code so it
emits SARIF, then feed that file to sarif_to_findings() the same way.
"""
from __future__ import annotations
import json
import shutil
import subprocess
from pathlib import Path

from .sarif import sarif_to_findings


def semgrep_baseline(repo: str, config: str = "auto") -> list[dict]:
    """Run semgrep with SARIF output and normalize to the common schema."""
    if not shutil.which("semgrep"):
        raise RuntimeError("semgrep not installed: pip install semgrep")
    out = subprocess.run(
        ["semgrep", "--config", config, "--sarif", "--quiet", str(Path(repo).resolve())],
        capture_output=True, text=True, timeout=600,
    )
    try:
        sarif = json.loads(out.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"semgrep did not return SARIF: {out.stderr[:300]}") from e
    findings = sarif_to_findings(sarif)
    # make paths repo-relative so they match labels
    root = str(Path(repo).resolve())
    for f in findings:
        if f["file"].startswith(root):
            f["file"] = f["file"][len(root):].lstrip("/")
    return findings
