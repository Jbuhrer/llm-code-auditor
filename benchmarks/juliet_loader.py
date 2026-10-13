#!/usr/bin/env python3
"""
NIST Juliet -> benchmark slice + labels.json for this auditor.

Juliet is the standard labelled vulnerability dataset. Every test case contains a
vulnerable `bad()` path and one or more safe `good()` paths that look almost
identical, which is exactly what generates false positives and lets you show the
validator earning its keep.

This tool does NOT download Juliet (NIST/SARD host it). Get it yourself:
  Java:  https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-java-v1-3.zip
  C/C++: https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip
Unzip it somewhere, then point --juliet-dir at the extracted folder.

Ground truth comes from the suite's manifest (manifest.sarif or manifest.xml) when
present; otherwise it falls back to Juliet's `POTENTIAL FLAW` comment convention.

Usage:
  python benchmarks/juliet_loader.py \
      --juliet-dir ~/juliet-java \
      --cwes 89 78 22 --per-cwe 15 \
      --out-dir benchmarks/juliet_slice \
      --labels benchmarks/juliet_slice/labels.json

Then:
  python run_audit.py benchmarks/juliet_slice --bugs sqli cmdi path --context
  python eval/experiment.py benchmarks/juliet_slice \
      benchmarks/juliet_slice/labels.json --bugs sqli cmdi path
"""
from __future__ import annotations
import argparse
import json
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

# Juliet CWE -> your bug classes. Extend as you add classes.
CWE_TO_CLASS = {
    "89": "sqli",   # SQL Injection
    "78": "cmdi",   # OS Command Injection
    "22": "path",   # Path Traversal
    "476": "npd",   # NULL Pointer Dereference
    "416": "uaf",   # Use After Free
}

SRC_EXTS = {".java", ".c", ".cpp", ".cc", ".cs"}

# The sink each bug class is graded on. Juliet marks several lines per bad path
# (the tainted read AND the dangerous use); the agent reports at the USE, so we
# keep only flaw lines whose text looks like the sink. Falls back to all flaw
# lines for a file if none match, so a file is never dropped silently.
SINK_HINTS = {
    "sqli": ("execute", "executeQuery", "executeUpdate", "prepareStatement",
             "createStatement", "Statement", "addBatch"),
    "cmdi": ("exec", "Runtime", "ProcessBuilder", "getRuntime", "command",
             "os.system", "subprocess", "popen"),
    "path": ("FileInputStream", "FileReader", "FileOutputStream", "new File",
             "Paths.get", "File(", "open("),
    "npd":  ("->", ".", "["),
    "uaf":  ("free", "delete"),
}


def filter_to_sinks(src_file: Path, flaw_lines: list[int], bug_class: str) -> list[int]:
    """Keep only flaw lines whose source text matches a sink hint for this class.
    If none match, return the original set (never drop a labelled file)."""
    hints = SINK_HINTS.get(bug_class, ())
    if not hints:
        return flaw_lines
    try:
        lines = src_file.read_text(errors="replace").splitlines()
    except Exception:
        return flaw_lines
    kept = [n for n in flaw_lines
            if 1 <= n <= len(lines) and any(h in lines[n - 1] for h in hints)]
    return kept or flaw_lines


def cwe_of_path(p: Path) -> str | None:
    """Pull the CWE number from a Juliet filename/dir like CWE89_SQL_Injection__...."""
    m = re.search(r"CWE(\d+)_", str(p))
    return m.group(1) if m else None


# ---------- ground-truth extraction ----------

def flaws_from_manifest_stream(path: Path) -> dict[str, list[int]]:
    """Fault-tolerant manifest reader. Juliet's manifest.xml is one huge file and
    a single malformed entry makes a full XML tree parse fail (mismatched tag).
    We scan line by line for <file path=...> and its <flaw line=...> children,
    which is robust to a bad entry elsewhere in the file."""
    flaws: dict[str, list[int]] = {}
    current: str | None = None
    file_re = re.compile(r'<file\b[^>]*\bpath="([^"]+)"')
    flaw_re = re.compile(r'<flaw\b[^>]*\bline="(\d+)"')
    with path.open(errors="replace") as fh:
        for line in fh:
            fm = file_re.search(line)
            if fm:
                current = fm.group(1)
            if current:
                for lm in flaw_re.finditer(line):
                    flaws.setdefault(current, []).append(int(lm.group(1)))
    return flaws


def flaws_from_manifest_xml(path: Path) -> dict[str, list[int]]:
    """SARD manifest.xml -> {relative_file_path: [flaw_line, ...]}."""
    flaws: dict[str, list[int]] = {}
    tree = ET.parse(path)
    for file_el in tree.iter("file"):
        fpath = file_el.get("path")
        if not fpath:
            continue
        for flaw in file_el.findall("flaw"):
            line = flaw.get("line")
            if line:
                flaws.setdefault(fpath, []).append(int(line))
    return flaws


def flaws_from_manifest_sarif(path: Path) -> dict[str, list[int]]:
    """manifest.sarif -> {relative_file_path: [flaw_line, ...]}."""
    flaws: dict[str, list[int]] = {}
    data = json.loads(path.read_text())
    for run in data.get("runs", []):
        for res in run.get("results", []):
            for loc in res.get("locations", []):
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine")
                if uri and line:
                    flaws.setdefault(uri, []).append(int(line))
    return flaws


def flaws_from_comments(src_file: Path) -> list[int]:
    """Fallback: Juliet marks the vulnerable statement with a POTENTIAL FLAW
    comment. The flaw line is that line if it holds code, else the next code
    line. Best-effort; the manifest is authoritative when available."""
    lines = src_file.read_text(errors="replace").splitlines()
    flaw_lines: list[int] = []
    for i, line in enumerate(lines):
        if "POTENTIAL FLAW" not in line:
            continue
        # strip the comment; if code remains on the line, that's the flaw line
        code = re.sub(r"/\*.*?\*/", "", line)
        code = re.sub(r"//.*$", "", code).strip()
        if code:
            flaw_lines.append(i + 1)
        else:
            # next non-blank, non-comment line
            for j in range(i + 1, min(i + 6, len(lines))):
                nxt = lines[j].strip()
                if nxt and not nxt.startswith(("*", "/*", "//")):
                    flaw_lines.append(j + 1)
                    break
    return flaw_lines


def load_manifest(juliet_dir: Path) -> dict[str, list[int]]:
    # streaming parser first (survives Juliet's malformed manifest), then ET,
    # then SARIF, whichever yields flaws.
    for m in juliet_dir.rglob("manifest.xml"):
        flaws = flaws_from_manifest_stream(m)
        if flaws:
            return flaws
    for m in juliet_dir.rglob("manifest.sarif"):
        try:
            flaws = flaws_from_manifest_sarif(m)
            if flaws:
                return flaws
        except Exception as e:  # noqa: BLE001
            print(f"warning: failed to parse {m}: {e}")
    return {}


# ---------- slice building ----------

def _testcase_key(p: Path) -> str:
    return re.sub(r"(\d+)[a-z]$", r"\1", p.stem)


def build_slice(juliet_dir: Path, cwes: list[str], per_cwe: int,
                out_dir: Path) -> list[dict]:
    """Select up to per_cwe TEST CASES per CWE; split cases (_22a/_22b,
    _51a/_51b) are always copied together."""
    manifest = load_manifest(juliet_dir)
    print(f"using manifest with {len(manifest)} flaw files" if manifest
          else "no manifest found; falling back to POTENTIAL FLAW comments")
    out_dir.mkdir(parents=True, exist_ok=True)
    labels: list[dict] = []
    counts = {c: 0 for c in cwes}
    groups: dict[str, list[Path]] = {}
    for p in sorted(juliet_dir.rglob("*")):
        if p.suffix in SRC_EXTS and cwe_of_path(p) in cwes:
            groups.setdefault(_testcase_key(p), []).append(p)

    def flaws_for(src: Path) -> list[int]:
        for mpath, lines in manifest.items():
            if str(src).endswith(mpath) or Path(mpath).name == src.name:
                return lines
        return flaws_from_comments(src)

    for key, files in groups.items():
        cwe = cwe_of_path(files[0])
        if cwe is None or counts[cwe] >= per_cwe:
            continue
        bug_class = CWE_TO_CLASS[cwe]
        case_labels = []
        for src in files:
            fl = flaws_for(src)
            if fl:
                fl = filter_to_sinks(src, fl, bug_class)
                case_labels += [{"file": src.name, "line": ln, "bug_class": bug_class}
                                for ln in sorted(set(fl))]
        if not case_labels:
            continue
        for src in files:
            shutil.copy2(src, out_dir / src.name)
        labels += case_labels
        counts[cwe] += 1
    print("selected test cases per CWE:", {k: counts[k] for k in cwes})
    return labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--juliet-dir", required=True, type=Path)
    ap.add_argument("--cwes", nargs="+", default=list(CWE_TO_CLASS),
                    help="CWE numbers, e.g. 89 78 22")
    ap.add_argument("--per-cwe", type=int, default=15)
    ap.add_argument("--out-dir", type=Path, default=Path("benchmarks/juliet_slice"))
    ap.add_argument("--labels", type=Path,
                    default=Path("benchmarks/juliet_slice/labels.json"))
    a = ap.parse_args()

    unknown = [c for c in a.cwes if c not in CWE_TO_CLASS]
    if unknown:
        ap.error(f"no bug-class mapping for CWE(s): {unknown}. "
                 f"Known: {list(CWE_TO_CLASS)}")

    if not a.juliet_dir.is_dir():
        ap.error(f"--juliet-dir not found: {a.juliet_dir}")

    labels = build_slice(a.juliet_dir, a.cwes, a.per_cwe, a.out_dir)
    a.labels.parent.mkdir(parents=True, exist_ok=True)
    a.labels.write_text(json.dumps(labels, indent=2))
    print(f"\n{len(labels)} labelled flaws across "
          f"{len({l['file'] for l in labels})} files")
    print(f"slice -> {a.out_dir}")
    print(f"labels -> {a.labels}")


if __name__ == "__main__":
    main()
