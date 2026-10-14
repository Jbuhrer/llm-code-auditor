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

Ground truth comes from the suite's manifest (manifest.xml or manifest.sarif)
when present; otherwise it falls back to Juliet's `POTENTIAL FLAW` comments.

Sampling is stratified: per CWE, half the test cases have a bad path that
crosses a function boundary (bad -> badSink, split files, the _81 family) and half
stay inside one function, and picks rotate across Juliet's source variants
(connect_tcp, Environment, Property, ...) so no single source dominates. The draw
is seeded, so the same --seed always gives the same slice.

Juliet Java has no CWE-22 folder. Path traversal is CWE-23 (relative) and
CWE-36 (absolute); passing 22 selects both.

Usage:
  python benchmarks/juliet_loader.py \
      --juliet-dir ~/juliet-java/Java \
      --cwes 89 78 22 --per-cwe 20 --seed 0 \
      --out-dir benchmarks/juliet_slice \
      --labels benchmarks/juliet_slice/labels.json

Then:
  python eval/experiment.py benchmarks/juliet_slice \
      benchmarks/juliet_slice/labels.json --dry-run
"""
from __future__ import annotations
import argparse
import json
import random
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor.units import testcase_stem                      # noqa: E402
from eval.juliet_functions import function_spans, region_of  # noqa: E402

# Juliet CWE -> bug classes. Extend as you add classes.
CWE_TO_CLASS = {
    "89": "sqli",   # SQL Injection
    "78": "cmdi",   # OS Command Injection
    "23": "path",   # Relative Path Traversal
    "36": "path",   # Absolute Path Traversal
    "476": "npd",   # NULL Pointer Dereference
    "416": "uaf",   # Use After Free
}
CWE_ALIASES = {"22": ["23", "36"]}   # Juliet has no CWE-22 directory

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


def sink_lines(src_file: Path, lines: list[int], bug_class: str) -> list[int]:
    """The subset of lines whose code (comments stripped) matches a sink hint."""
    try:
        text = src_file.read_text(errors="replace").splitlines()
    except OSError:
        return []
    out = []
    for n in lines:
        if 1 <= n <= len(text):
            code = re.sub(r"//.*$|/\*.*?\*/", "", text[n - 1]).strip()
            if code and not code.startswith("*") and any(
                    h in code for h in SINK_HINTS.get(bug_class, ())):
                out.append(n)
    return out


# call sites only, for scanning whole functions (SINK_HINTS is too loose for that)
STRICT_SINKS = {
    "sqli": r"\.(execute|executeQuery|executeUpdate|executeBatch|addBatch)\s*\(",
    "cmdi": r"\.exec\s*\(|new\s+ProcessBuilder\s*\(",
    "path": r"new\s+(File|FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(|Paths\.get\s*\(",
}


def bad_side_sinks(src_file: Path, bug_class: str) -> list[int]:
    """Sink call sites inside bad-side functions of a file."""
    pat = STRICT_SINKS.get(bug_class)
    try:
        text = src_file.read_text(errors="replace")
    except OSError:
        return []
    if not pat:
        return []
    lines = text.splitlines()
    out = []
    for name, s, e in function_spans(text):
        if region_of(name, src_file.stem) != "bad":
            continue
        for n in range(s, min(e, len(lines)) + 1):
            code = re.sub(r"//.*$|/\*.*?\*/", "", lines[n - 1]).strip()
            if code and not code.startswith("*") and re.search(pat, code):
                out.append(n)
    return out


def cwe_of_path(p: Path) -> str | None:
    """Pull the CWE number from a Juliet filename/dir like CWE89_SQL_Injection__...."""
    m = re.search(r"CWE(\d+)_", p.name) or re.search(r"CWE(\d+)_", str(p))
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
    # streaming parser first (survives Juliet's malformed manifest), then SARIF
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

def source_variant(key: str) -> str:
    """CWE78_OS_Command_Injection__connect_tcp_01 -> connect_tcp"""
    tail = key.split("__", 1)[-1]
    return re.sub(r"_\d{2}$", "", tail)


def crosses_function(files: list[Path]) -> bool:
    """True if the bad path spans more than one function (or file)."""
    bad_fns = 0
    for f in files:
        try:
            spans = function_spans(f.read_text(errors="replace"))
        except OSError:
            continue
        bad_fns += sum(region_of(n, f.stem) == "bad" for n, _, _ in spans)
    return bad_fns > 1


def _pick(cases: list[tuple[str, list[Path]]], n: int, rng: random.Random):
    """Up to n cases, rotating across source variants so one doesn't dominate."""
    by_src: dict[str, list] = {}
    for c in cases:
        by_src.setdefault(source_variant(c[0]), []).append(c)
    pools = [by_src[k] for k in sorted(by_src)]
    for pool in pools:
        rng.shuffle(pool)
    rng.shuffle(pools)
    out = []
    while len(out) < n and any(pools):
        for pool in pools:
            if pool and len(out) < n:
                out.append(pool.pop())
    return out


def build_slice(juliet_dir: Path, cwes: list[str], per_cwe: int, out_dir: Path,
                seed: int = 0) -> list[dict]:
    """Select per_cwe TEST CASES per CWE, stratified (see module docstring). Split
    cases (_51a/_51b, the _81 family) are always copied together."""
    manifest = load_manifest(juliet_dir)
    print(f"using manifest with {len(manifest)} flaw files" if manifest
          else "no manifest found; falling back to POTENTIAL FLAW comments")
    by_name: dict[str, list[int]] = {}
    for mpath, lines in manifest.items():
        by_name.setdefault(Path(mpath).name, []).extend(lines)
    rng = random.Random(seed)
    out_dir.mkdir(parents=True, exist_ok=True)

    groups: dict[str, list[Path]] = {}
    for p in sorted(juliet_dir.rglob("*")):
        if p.suffix in SRC_EXTS and cwe_of_path(p) in cwes:
            groups.setdefault(testcase_stem(p.stem), []).append(p)

    def flaws_for(src: Path) -> list[int]:
        return by_name.get(src.name) or (flaws_from_comments(src) if not by_name else [])

    labels: list[dict] = []
    for cwe in cwes:
        bug_class = CWE_TO_CLASS[cwe]
        strata: dict[bool, list] = {True: [], False: []}
        for key in sorted(groups):
            files = groups[key]
            if cwe_of_path(files[0]) == cwe and any(flaws_for(f) for f in files):
                strata[crosses_function(files)].append((key, files))
        picked = _pick(strata[True], per_cwe // 2, rng)
        picked += _pick(strata[False], per_cwe - len(picked), rng)
        if len(picked) < per_cwe:   # one stratum ran short: top up from the other
            have = {k for k, _ in picked}
            picked += _pick([c for c in strata[True] if c[0] not in have],
                            per_cwe - len(picked), rng)
        n_cross = 0
        for key, files in sorted(picked):
            cross = crosses_function(files)
            n_cross += cross
            meta = {"bug_class": bug_class, "cwe": f"CWE-{cwe}", "testcase": key,
                    "crosses_function": cross, "source_variant": source_variant(key)}
            flagged = {src: flaws_for(src) for src in files}
            sinks = [(src, ln) for src, fl in flagged.items()
                     for ln in fl if ln in sink_lines(src, [ln], bug_class)]
            if not sinks:
                # cross-file cases: the manifest flags only the SOURCE line (in the
                # _a file). Label the sink inside the bad-side functions instead, so
                # localization doesn't penalize reporting the real sink.
                sinks = [(src, ln) for src in files for ln in bad_side_sinks(src, bug_class)]
            source_lines = sorted({f"{src.name}:{ln}" for src, fl in flagged.items()
                                   for ln in fl if (src, ln) not in set(sinks)})
            for src, ln in sorted(set(sinks)):
                labels.append({"file": src.name, "line": ln, **meta,
                               "source_lines": source_lines})
            if not sinks:   # never drop a case silently: fall back to flagged lines
                labels += [{"file": src.name, "line": ln, **meta}
                           for src, fl in flagged.items() for ln in sorted(set(fl))]
            for src in files:
                shutil.copy2(src, out_dir / src.name)
        print(f"CWE-{cwe}: {len(picked)} test cases ({n_cross} cross a function "
              f"boundary) from {len({source_variant(k) for k, _ in picked})} source "
              f"variants; available: {len(strata[True])} crossing, "
              f"{len(strata[False])} not")
    return labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--juliet-dir", required=True, type=Path)
    ap.add_argument("--cwes", nargs="+", default=["89", "78", "22"],
                    help="CWE numbers, e.g. 89 78 22 (22 means 23 + 36)")
    ap.add_argument("--per-cwe", type=int, default=20)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out-dir", type=Path, default=Path("benchmarks/juliet_slice"))
    ap.add_argument("--labels", type=Path,
                    default=Path("benchmarks/juliet_slice/labels.json"))
    a = ap.parse_args()

    cwes = [c2 for c in a.cwes for c2 in CWE_ALIASES.get(c, [c])]
    unknown = [c for c in cwes if c not in CWE_TO_CLASS]
    if unknown:
        ap.error(f"no bug-class mapping for CWE(s): {unknown}. "
                 f"Known: {list(CWE_TO_CLASS)}")
    if not a.juliet_dir.is_dir():
        ap.error(f"--juliet-dir not found: {a.juliet_dir}")
    if a.out_dir.exists() and any(p.suffix in SRC_EXTS for p in a.out_dir.iterdir()):
        ap.error(f"{a.out_dir} already has source files; delete it or pick another "
                 "--out-dir so old files don't leak into the new slice")

    labels = build_slice(a.juliet_dir, cwes, a.per_cwe, a.out_dir, a.seed)
    a.labels.parent.mkdir(parents=True, exist_ok=True)
    a.labels.write_text(json.dumps(labels, indent=2))
    print(f"\n{len(labels)} labelled flaws across "
          f"{len({l['testcase'] for l in labels})} test cases, "
          f"{len({l['file'] for l in labels})} files")
    print(f"slice -> {a.out_dir}")
    print(f"labels -> {a.labels}")


if __name__ == "__main__":
    main()
