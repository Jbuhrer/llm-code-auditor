"""
Tools exposed to the auditing agent.

The agent explores the repo through these instead of being handed the whole
codebase. run_semgrep is the static-analysis factor: it's only in the toolset
when static_analysis is on (see tool_schemas()).
"""
from __future__ import annotations
import fnmatch
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

SKIP_DIRS = {"node_modules", "venv", ".venv", ".git", "__pycache__", "build", "dist",
             "target", ".idea", ".gradle"}
SOURCE_EXTS = {".py", ".java", ".c", ".cpp", ".cc", ".h", ".hpp", ".cs", ".php",
               ".js", ".ts", ".go", ".rb"}
MAX_GREP_HITS = 200


def semgrep_exe() -> str | None:
    """semgrep on PATH, or next to this Python (an unactivated venv)."""
    found = shutil.which("semgrep") or shutil.which("pysemgrep")
    if found:
        return found
    for name in ("semgrep.exe", "semgrep", "pysemgrep.exe", "pysemgrep"):
        cand = Path(sys.executable).parent / name
        if cand.is_file():
            return str(cand)
    return None


def _norm_hit(hit: str) -> str:
    """ripgrep prints ./a/b.py:3:x (or .\\a\\b.py on Windows); make it a/b.py:3:x."""
    path, sep, rest = hit.partition(":")
    path = path.replace("\\", "/")
    if path.startswith("./"):
        path = path[2:]
    return path + sep + rest


def _glob_match(rel_posix: str, glob: str) -> bool:
    """ripgrep-style glob on a repo-relative path. PurePath.match treats ** as a
    single segment on Python < 3.13, so "**/*" would skip top-level files."""
    if not glob or glob in ("*", "**", "**/*"):
        return True
    if fnmatch.fnmatch(rel_posix, glob):
        return True
    if glob.startswith("**/"):
        rest = glob[3:]
        return fnmatch.fnmatch(rel_posix, rest) or fnmatch.fnmatch(
            rel_posix.rsplit("/", 1)[-1], rest) or fnmatch.fnmatch(rel_posix, "*/" + rest)
    if "/" not in glob:   # like rg: a bare pattern matches the file name anywhere
        return fnmatch.fnmatch(rel_posix.rsplit("/", 1)[-1], glob)
    return False


def _hidden_or_skipped(rel_parts: tuple[str, ...]) -> bool:
    return any(p.startswith(".") or p in SKIP_DIRS for p in rel_parts)


class Workspace:
    """A sandbox rooted at the target repo. All tool paths are resolved
    relative to root and are prevented from escaping it."""

    def __init__(self, root: str):
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise ValueError(f"repo root not found: {self.root}")
        self._semgrep_cache: dict[tuple[str, str], list[dict]] = {}

    def _safe(self, rel: str) -> Path:
        p = (self.root / (rel or ".")).resolve()
        # is_relative_to, not a string prefix check: /repo2 must not pass for /repo
        if p != self.root and not p.is_relative_to(self.root):
            raise ValueError("path escapes repo root")
        return p

    def rel(self, p: Path | str) -> str:
        """Repo-relative POSIX path, so findings match labels on any OS."""
        p = Path(p)
        try:
            return p.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return p.as_posix()

    def list_dir(self, rel: str = ".") -> str:
        p = self._safe(rel)
        if not p.exists():
            return f"(no such path: {rel})"
        entries = []
        for c in sorted(p.iterdir()):
            if c.name.startswith(".") or c.name in SKIP_DIRS:
                continue
            entries.append(c.name + ("/" if c.is_dir() else ""))
        return "\n".join(entries) if entries else "(empty)"

    def lines(self, rel: str) -> list[str]:
        p = self._safe(rel)
        if not p.is_file():
            return []
        return p.read_text(errors="replace").splitlines()

    def read_file(self, rel: str, start: int = 1, end: int = 400) -> str:
        p = self._safe(rel)
        if not p.is_file():
            return f"(no such file: {rel})"
        lines = p.read_text(errors="replace").splitlines()
        start = max(1, int(start))
        end = min(len(lines), int(end))
        if start > end:
            return f"(empty range; file has {len(lines)} lines)"
        return "\n".join(f"{i:>5}\t{lines[i-1]}" for i in range(start, end + 1))

    def source_files(self, exts: set[str] | None = None) -> list[str]:
        """Repo-relative paths of source files, for unit building."""
        exts = exts or SOURCE_EXTS
        out = []
        for f in sorted(self.root.rglob("*")):
            if not f.is_file() or f.suffix not in exts:
                continue
            rel_parts = f.relative_to(self.root).parts
            if _hidden_or_skipped(rel_parts[:-1]):
                continue
            out.append(f.relative_to(self.root).as_posix())
        return out

    def grep(self, pattern: str, glob: str = "**/*") -> str:
        """Search the repo with ripgrep if present, else Python. A bad regex
        falls back to a literal search, and any error is returned to the agent
        as a message rather than raised, so one bad pattern never kills a run.
        Output lines are `relpath:line:text`."""
        try:
            rg = shutil.which("rg")
            if rg:
                out = subprocess.run(
                    [rg, "-n", "--no-heading", "-e", pattern, "--glob", glob, "."],
                    capture_output=True, text=True, timeout=60, cwd=self.root,
                )
                if out.returncode in (0, 1):   # 2 = regex error, fall through
                    hits = [_norm_hit(h) for h in out.stdout.splitlines()]
                    return "\n".join(hits[:MAX_GREP_HITS]) if hits else "(no matches)"
            try:
                rx = re.compile(pattern)
            except re.error:
                rx = re.compile(re.escape(pattern))
            results = []
            for f in sorted(self.root.rglob("*")):
                if not f.is_file():
                    continue
                relp = f.relative_to(self.root)
                if _hidden_or_skipped(relp.parts[:-1]) or not _glob_match(relp.as_posix(), glob):
                    continue
                try:
                    text = f.read_text(errors="replace")
                except Exception:
                    continue
                for n, line in enumerate(text.splitlines(), 1):
                    if rx.search(line):
                        results.append(f"{relp.as_posix()}:{n}:{line.strip()}")
                        if len(results) >= MAX_GREP_HITS:
                            return "\n".join(results)
            return "\n".join(results) if results else "(no matches)"
        except Exception as e:
            return f"(grep error: {e})"

    def semgrep_results(self, rel: str = ".", config: str = "auto") -> list[dict]:
        """Raw semgrep hits under rel, cached so repeated runs and units don't
        pay for the same scan twice. Raises if semgrep isn't usable."""
        key = (rel, config)
        if key in self._semgrep_cache:
            return self._semgrep_cache[key]
        exe = semgrep_exe()
        if not exe:
            raise RuntimeError("semgrep not installed (pip install semgrep)")
        p = self._safe(rel)
        out = subprocess.run([exe, "--config", config, "--json", "--quiet",
                              "--no-git-ignore", str(p)],
                             capture_output=True, text=True, timeout=600,
                             encoding="utf-8", errors="replace")
        try:
            data = json.loads(out.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"semgrep gave no JSON: {out.stderr[:300]}") from e
        hits = [{"check_id": r.get("check_id"),
                 "path": self.rel(r.get("path", "")),
                 "line": r.get("start", {}).get("line"),
                 "message": r.get("extra", {}).get("message", "")[:200]}
                for r in data.get("results", [])]
        self._semgrep_cache[key] = hits
        return hits

    def run_semgrep(self, rel: str = ".", config: str = "auto") -> str:
        try:
            hits = self.semgrep_results(rel, config)
        except Exception as e:
            return f"(semgrep error: {e})"
        return json.dumps(hits[:50], indent=2) if hits else "(no semgrep findings)"


# ---- tool schemas (Anthropic shape; llm.py translates for other backends) ----
FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "bug_class": {"type": "string"},
        "file": {"type": "string", "description": "repo-relative path of the sink"},
        "line": {"type": "integer", "description": "line of the dangerous sink"},
        "path": {"type": "string", "description": "source -> ... -> sink"},
        "cwe": {"type": "string"},
        "severity": {"type": "string"},
        "confidence": {"type": "number"},
    },
    "required": ["bug_class", "file", "line", "cwe", "confidence"],
}

REPORT_TOOL = {
    "name": "report_findings",
    "description": "Submit the final list of findings. Call exactly once when done "
                   "(empty list if nothing solid).",
    "input_schema": {
        "type": "object",
        "properties": {"findings": {"type": "array", "items": FINDING_SCHEMA}},
        "required": ["findings"],
    },
}

EXPLORE_TOOLS = [
    {
        "name": "list_dir",
        "description": "List files/dirs at a path relative to the repo root.",
        "input_schema": {
            "type": "object",
            "properties": {"rel": {"type": "string", "description": "path relative to repo root"}},
        },
    },
    {
        "name": "read_file",
        "description": "Read a file (numbered lines). Use start/end to page.",
        "input_schema": {
            "type": "object",
            "properties": {
                "rel": {"type": "string"},
                "start": {"type": "integer"},
                "end": {"type": "integer"},
            },
            "required": ["rel"],
        },
    },
    {
        "name": "grep",
        "description": "Search the repo for a regex (an invalid regex is matched "
                       "literally). Returns relpath:line:text.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "glob": {"type": "string", "description": "e.g. **/*.java"},
            },
            "required": ["pattern"],
        },
    },
]

SEMGREP_TOOL = {
    "name": "run_semgrep",
    "description": "Run semgrep static analysis on a path for an independent signal.",
    "input_schema": {
        "type": "object",
        "properties": {"rel": {"type": "string", "description": "path relative to repo root"}},
    },
}

# kept for back-compat with older imports
TOOL_SCHEMAS = EXPLORE_TOOLS + [SEMGREP_TOOL, REPORT_TOOL]


def tool_schemas(explore: bool, static_analysis: bool) -> list[dict]:
    """The toolset for one audit cell. Fixed mode only gets report_findings."""
    tools = list(EXPLORE_TOOLS) if explore else []
    if explore and static_analysis:
        tools.append(SEMGREP_TOOL)
    return tools + [REPORT_TOOL]


def dispatch(ws: Workspace, name: str, args: dict, semgrep_config: str = "auto",
             allowed: set[str] | None = None) -> str:
    """Route a tool call. Wrapped so NO tool failure can ever escape and crash a
    run: any error comes back to the agent as a message it can work around."""
    if allowed is not None and name not in allowed:
        return f"(tool {name} is not available in this configuration)"
    try:
        if name == "list_dir":
            return ws.list_dir(args.get("rel", "."))
        if name == "read_file":
            return ws.read_file(args["rel"], args.get("start", 1), args.get("end", 400))
        if name == "grep":
            return ws.grep(args["pattern"], args.get("glob", "**/*"))
        if name == "run_semgrep":
            return ws.run_semgrep(args.get("rel", "."), semgrep_config)
        return f"(unknown tool: {name})"
    except Exception as e:
        return f"(tool {name} failed: {e})"
