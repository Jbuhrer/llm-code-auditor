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
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlparse

from .sarif import sarif_to_findings
from .tools import semgrep_exe


def semgrep_baseline(repo: str, config: str = "auto") -> list[dict]:
    """Run semgrep with SARIF output and normalize to the common schema."""
    exe = semgrep_exe()
    if not exe:
        raise RuntimeError("semgrep not installed: pip install semgrep")
    root = Path(repo).resolve()
    out = subprocess.run(
        [exe, "--config", config, "--sarif", "--quiet", "--no-git-ignore", str(root)],
        capture_output=True, text=True, timeout=600, encoding="utf-8", errors="replace",
    )
    try:
        sarif = json.loads(out.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"semgrep did not return SARIF: {out.stderr[:300]}") from e
    findings = sarif_to_findings(sarif)
    # make paths repo-relative POSIX so they match labels on any OS
    for f in findings:
        f["file"] = repo_relative(f["file"], root)
    return findings


def repo_relative(uri: str, root: Path) -> str:
    """SARIF uris can be relative, absolute, or file:// URIs."""
    if uri.startswith("file://"):
        uri = unquote(urlparse(uri).path)
        if re.match(r"^/[A-Za-z]:", uri):   # file:///C:/x -> C:/x
            uri = uri[1:]
    p = Path(uri)
    if p.is_absolute():
        try:
            return p.resolve().relative_to(root).as_posix()
        except ValueError:
            return p.as_posix()
    return p.as_posix().removeprefix("./")
