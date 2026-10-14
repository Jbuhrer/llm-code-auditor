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


def _semgrep_sarif(exe: str, config: str, target: Path, include: list[str],
                   timeout: int) -> list[dict]:
    cmd = [exe, "--config", config, "--sarif", "--quiet", "--no-git-ignore"]
    for pat in include:
        cmd += ["--include", pat]
    out = subprocess.run(cmd + [str(target)], capture_output=True, text=True,
                         timeout=timeout, encoding="utf-8", errors="replace")
    try:
        sarif = json.loads(out.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"semgrep did not return SARIF: {out.stderr[:300]}") from e
    findings = sarif_to_findings(sarif)
    for f in findings:   # repo-relative POSIX so they match labels on any OS
        f["file"] = repo_relative(f["file"], target)
    return findings


def semgrep_baseline(repo: str, config: str = "auto", per_project: bool = False,
                     include: list[str] | None = None, timeout: int = 600,
                     log=print) -> list[dict]:
    """Run semgrep with SARIF output and normalize to the common schema.
    per_project scans each top-level folder separately (multi-project benchmarks),
    so one huge project can't time out the whole baseline; a project that fails
    is logged and skipped, and its name goes in the returned findings' absence."""
    exe = semgrep_exe()
    if not exe:
        raise RuntimeError("semgrep not installed: pip install semgrep")
    root = Path(repo).resolve()
    include = include or []
    if not per_project:
        return _semgrep_sarif(exe, config, root, include, timeout)
    findings = []
    for proj in sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith(".")):
        try:
            fs = _semgrep_sarif(exe, config, proj, include, timeout)
        except Exception as e:   # one project failing must not lose the rest
            log(f"  ! semgrep on {proj.name}: {str(e)[:120]}")
            continue
        for f in fs:
            f["file"] = f"{proj.name}/{f['file']}"
        findings += fs
        log(f"  semgrep {proj.name}: {len(fs)} hit(s)")
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
