"""
Tools exposed to the auditing agent.

The agent explores the repo through these instead of being handed the whole
codebase, which is what keeps token cost bounded on large projects.

run_semgrep wires in a real static-analysis tool as an independent evidence
source. Swap or add CodeQL here later for deeper dataflow.
"""
from __future__ import annotations
import json
import subprocess
import shutil
from pathlib import Path


class Workspace:
    """A sandbox rooted at the target repo. All tool paths are resolved
    relative to root and are prevented from escaping it."""

    def __init__(self, root: str):
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise ValueError(f"repo root not found: {self.root}")

    def _safe(self, rel: str) -> Path:
        p = (self.root / rel).resolve()
        if not str(p).startswith(str(self.root)):
            raise ValueError("path escapes repo root")
        return p

    def list_dir(self, rel: str = ".") -> str:
        p = self._safe(rel)
        if not p.exists():
            return f"(no such path: {rel})"
        entries = []
        for c in sorted(p.iterdir()):
            if c.name.startswith(".") or c.name in {"node_modules", "venv", "__pycache__"}:
                continue
            entries.append(c.name + ("/" if c.is_dir() else ""))
        return "\n".join(entries) if entries else "(empty)"

    def read_file(self, rel: str, start: int = 1, end: int = 400) -> str:
        p = self._safe(rel)
        if not p.is_file():
            return f"(no such file: {rel})"
        lines = p.read_text(errors="replace").splitlines()
        start = max(1, start)
        end = min(len(lines), end)
        return "\n".join(f"{i:>5}\t{lines[i-1]}" for i in range(start, end + 1))

    def source_files(self, exts: set[str] | None = None) -> list[str]:
        """Repo-relative paths of source files, for per-file auditing."""
        exts = exts or {".py", ".java", ".c", ".cpp", ".cc", ".cs", ".php",
                        ".js", ".ts", ".go", ".rb"}
        skip = {"node_modules", "venv", ".git", "__pycache__", "build", "dist"}
        out = []
        for f in sorted(self.root.rglob("*")):
            if f.is_file() and f.suffix in exts and not any(s in f.parts for s in skip):
                out.append(str(f.relative_to(self.root)))
        return out

    def grep(self, pattern: str, glob: str = "**/*") -> str:
        """Search the repo using ripgrep if present, else Python. A bad regex
        falls back to a literal search, and any error is returned to the agent
        as a message rather than raised, so one bad pattern never kills a run."""
        try:
            rg = shutil.which("rg")
            if rg:
                out = subprocess.run(
                    [rg, "-n", "--no-heading", "-e", pattern, "--glob", glob,
                     str(self.root)],
                    capture_output=True, text=True, timeout=60,
                )
                hits = out.stdout.strip()
                if hits:
                    return hits[:8000]
            import re
            try:
                rx = re.compile(pattern)
            except re.error:
                rx = re.compile(re.escape(pattern))
            results = []
            for f in self.root.rglob("*"):
                if not f.is_file() or "/." in str(f) or "node_modules" in str(f):
                    continue
                try:
                    for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
                        if rx.search(line):
                            results.append(f"{f.relative_to(self.root)}:{n}:{line.strip()}")
                            if len(results) > 200:
                                break
                except Exception:
                    continue
                if len(results) > 200:
                    break
            return "\n".join(results[:200]) if results else "(no matches)"
        except Exception as e:
            return f"(grep error: {e})"

    def run_semgrep(self, rel: str = ".", config: str = "auto") -> str:
        """Run semgrep and return findings as compact JSON. Independent signal
        the agent can corroborate its own hypotheses against."""
        if not shutil.which("semgrep"):
            return "(semgrep not installed; run: pip install semgrep)"
        p = self._safe(rel)
        try:
            out = subprocess.run(
                ["semgrep", "--config", config, "--json", "--quiet", str(p)],
                capture_output=True, text=True, timeout=300,
            )
            data = json.loads(out.stdout)
        except Exception as e:
            return f"(semgrep error: {e})"
        slim = [
            {
                "check_id": r.get("check_id"),
                "path": r.get("path"),
                "line": r.get("start", {}).get("line"),
                "message": r.get("extra", {}).get("message", "")[:200],
            }
            for r in data.get("results", [])
        ]
        return json.dumps(slim[:50], indent=2) if slim else "(no semgrep findings)"


# ---- Anthropic tool schemas (native tool use) ----
TOOL_SCHEMAS = [
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
        "description": "Search the repo for a pattern. Use to find sources and sinks. "
                       "A non-regex pattern is matched literally.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "glob": {"type": "string", "description": "e.g. **/*.java"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "run_semgrep",
        "description": "Run semgrep static analysis for an independent signal.",
        "input_schema": {
            "type": "object",
            "properties": {"rel": {"type": "string"}, "config": {"type": "string"}},
        },
    },
    {
        "name": "report_findings",
        "description": "Submit the final list of confirmed findings. Call once when done.",
        "input_schema": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "bug_class": {"type": "string"},
                            "file": {"type": "string"},
                            "line": {"type": "integer"},
                            "path": {"type": "string", "description": "source -> ... -> sink"},
                            "cwe": {"type": "string"},
                            "severity": {"type": "string"},
                            "confidence": {"type": "number"},
                        },
                        "required": ["bug_class", "file", "line", "cwe", "confidence"],
                    },
                }
            },
            "required": ["findings"],
        },
    },
]


def dispatch(ws: Workspace, name: str, args: dict) -> str:
    """Route a tool call. Wrapped so NO tool failure can ever escape and crash a
    run: any error comes back to the agent as a message it can work around."""
    try:
        if name == "list_dir":
            return ws.list_dir(args.get("rel", "."))
        if name == "read_file":
            return ws.read_file(args["rel"], args.get("start", 1), args.get("end", 400))
        if name == "grep":
            return ws.grep(args["pattern"], args.get("glob", "**/*"))
        if name == "run_semgrep":
            return ws.run_semgrep(args.get("rel", "."), args.get("config", "auto"))
        return f"(unknown tool: {name})"
    except Exception as e:
        return f"(tool {name} failed: {e})"
