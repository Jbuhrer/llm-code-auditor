"""
Audit units and fixed-context packing.

A unit is what one conversation audits:
  file      each source file on its own (the old per-file agent, and C0's setup)
  testcase  Juliet-style split cases (_51a/_51b, _22a/_22b) audited together, so
            flaws that cross a function or file boundary stay in one unit
  repo      the whole repository in one conversation

Exploration and fixed context are held to the SAME context budget, measured with
the same estimator (est_tokens), so the explore-vs-fixed comparison is matched:
  fixed    the target plus related files, packed up front until the budget is full
  explore  the target up front, then the agent spends the rest via tools
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .tools import Workspace

CHARS_PER_TOKEN = 4   # rough, model-agnostic; the same estimator is used everywhere


def est_tokens(text: str) -> int:
    return (len(text) + CHARS_PER_TOKEN - 1) // CHARS_PER_TOKEN


# Juliet splits one test case across files two ways: _51a/_51b letter suffixes,
# and the _81 family (_81_bad, _81_base, _81_goodG2B, _81a). Both collapse here.
_TESTCASE_SUFFIX = re.compile(r"(_\d{2})(?:[a-z]|_bad|_base|_good\w*)$")


def testcase_stem(stem: str) -> str:
    """CWE89_X_51a, CWE89_X_51b, CWE89_X_81_goodG2B -> CWE89_X_51 / CWE89_X_81."""
    return _TESTCASE_SUFFIX.sub(r"\1", stem)


def testcase_key(path: str) -> str:
    p = PurePosixPath(path.replace("\\", "/"))
    return (p.parent / testcase_stem(p.stem)).as_posix()


@dataclass
class Unit:
    id: str
    targets: list[str] = field(default_factory=list)   # empty = whole repo


def build_units(ws: Workspace, mode: str) -> list[Unit]:
    files = ws.source_files()
    if mode == "repo":
        return [Unit("<repo>", [])]
    if mode == "file":
        return [Unit(f, [f]) for f in files]
    if mode == "testcase":
        groups: dict[str, list[str]] = {}
        for f in files:
            groups.setdefault(testcase_key(f), []).append(f)
        return [Unit(k, v) for k, v in groups.items()]
    raise ValueError(f"unknown unit mode: {mode}")


def _numbered(ws: Workspace, rel: str) -> str:
    return ws.read_file(rel, 1, 10**9)


def _mentions(text: str, stem: str) -> bool:
    return len(stem) > 2 and re.search(rf"\b{re.escape(stem)}\b", text) is not None


def _related(ws: Workspace, targets: list[str], all_files: list[str]) -> list[str]:
    """Files linked to the targets by name, best first: callees (a target
    mentions the file's class/module name), then callers (the file mentions a
    target's name). Unlinked files are never packed: in a benchmark slice the
    same directory holds unrelated test cases, which would only add noise and cost."""
    text = "\n".join("\n".join(ws.lines(t)) for t in targets)
    tset = set(targets)
    tstems = [PurePosixPath(t).stem for t in targets]
    callees, callers = [], []
    for f in all_files:
        if f in tset:
            continue
        if _mentions(text, PurePosixPath(f).stem):
            callees.append(f)
            continue
        ftext = "\n".join(ws.lines(f))
        if any(_mentions(ftext, s) for s in tstems):
            callers.append(f)
    return callees + callers


def pack_context(ws: Workspace, unit: Unit, budget: int,
                 include_related: bool) -> tuple[str, int, list[str], bool]:
    """Pack targets (and optionally related files) into one string under budget.
    Returns (text, tokens_used, files_included, truncated)."""
    all_files = ws.source_files()
    order = list(unit.targets) if unit.targets else list(all_files)
    if include_related and unit.targets:
        order += _related(ws, unit.targets, all_files)
    tset = set(unit.targets)
    parts, used, included, truncated = [], 0, [], False
    for f in order:
        block = f"=== {f} ===\n{_numbered(ws, f)}\n"
        cost = est_tokens(block)
        if used + cost <= budget:
            parts.append(block)
            used += cost
            included.append(f)
        elif not unit.targets or f in tset:
            # never silently drop part of the target: cut it and say so
            truncated = True
            room = budget - used
            if room > 0:
                parts.append(block[:room * CHARS_PER_TOKEN]
                             + "\n... (truncated: context budget reached)\n")
                used = budget
                included.append(f)
        # a related file that doesn't fit is skipped; a smaller one may still fit
    return "".join(parts), used, included, truncated


def semgrep_block(ws: Workspace, files: list[str], config: str) -> tuple[str, str | None]:
    """Semgrep hits for the given files as prompt text. Scans the repo once
    (cached) and filters, so every unit and run reuses one scan."""
    try:
        hits = ws.semgrep_results(".", config)
    except Exception as e:
        return "(semgrep unavailable)", str(e)
    fset = set(files)
    mine = [h for h in hits if h["path"] in fset]
    if not mine:
        return "Semgrep results: (no hits in this code)", None
    lines = [f"- {h['path']}:{h['line']} [{h['check_id']}] {h['message']}" for h in mine]
    return "Semgrep results:\n" + "\n".join(lines[:50]), None
