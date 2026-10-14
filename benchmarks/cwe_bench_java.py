#!/usr/bin/env python3
"""CWE-Bench-Java loader. See README section "CWE-Bench-Java" for usage."""
from __future__ import annotations
import csv
import io
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

SOURCES = {
    "v1": "https://raw.githubusercontent.com/iris-sast/cwe-bench-java/master/data/",
    "v2": "https://raw.githubusercontent.com/iris-sast/iris/v2/data/",
}
DATA_FILES = ("project_info.csv", "fix_info.csv", "build_info.csv")


@dataclass
class FixedMethod:
    file: str
    cls: str
    method: str
    signature: str
    line: int | None


@dataclass
class Project:
    slug: str
    cve: str
    cwe: str
    repo_url: str
    tag: str
    buggy_commit: str
    fix_commits: list[str]
    advisory: str
    methods: list[FixedMethod] = field(default_factory=list)


def norm_cwe(cwe: str) -> str:
    """'CWE-022' and 'CWE-22' -> 'CWE-22'."""
    num = "".join(ch for ch in cwe if ch.isdigit())
    return f"CWE-{int(num)}" if num else cwe


def fetch_data(version: str, dest: Path) -> Path:
    """Download the CSVs for a version into dest (skips files already there)."""
    dest.mkdir(parents=True, exist_ok=True)
    for name in DATA_FILES:
        out = dest / name
        if not out.exists():
            with urllib.request.urlopen(SOURCES[version] + name, timeout=60) as r:
                out.write_bytes(r.read())
    return dest


def _rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8"))))


def _int(v: str) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def load_projects(data_dir: Path) -> dict[str, Project]:
    projects: dict[str, Project] = {}
    for r in _rows(data_dir / "project_info.csv"):
        projects[r["project_slug"]] = Project(
            slug=r["project_slug"], cve=r["cve_id"], cwe=norm_cwe(r["cwe_id"]),
            repo_url=r["github_url"], tag=r["github_tag"],
            buggy_commit=r["buggy_commit_id"],
            fix_commits=[c for c in r["fix_commit_ids"].split(";") if c],
            advisory=r.get("advisory_id", ""))
    for r in _rows(data_dir / "fix_info.csv"):
        p = projects.get(r["project_slug"])
        if p is None:
            continue
        p.methods.append(FixedMethod(
            file=r["file"], cls=r["class"], method=r["method"],
            signature=r.get("signature", ""),
            line=_int(r["method_start"]) or _int(r["class_start"])))
    return projects


def cve_year(cve: str) -> int | None:
    """'CVE-2021-1234' -> 2021. Publication-year proxy for contamination splits."""
    parts = cve.split("-")
    return _int(parts[1]) if len(parts) > 2 else None


def select(projects: dict[str, Project], cwes: list[str], per_cwe: int, seed: int,
           min_year: int | None = None, only: list[str] | None = None) -> list[Project]:
    """Seeded, CWE-stratified pick of scorable projects (ones with ground truth).
    min_year keeps only CVEs from that year on (contamination control); only
    restricts to slugs containing any of the given substrings."""
    import random
    rng = random.Random(seed)
    want = [norm_cwe(c) for c in cwes]
    picked = []
    for cwe in want:
        pool = sorted((p for p in projects.values()
                       if p.cwe == cwe and p.methods
                       and (min_year is None or (cve_year(p.cve) or 0) >= min_year)
                       and (not only or any(o in p.slug for o in only))),
                      key=lambda p: p.slug)
        rng.shuffle(pool)
        picked += pool[:per_cwe] if per_cwe > 0 else pool
    return picked


def _git(args: list[str], cwd: Path) -> bool:
    import subprocess
    # core.longpaths: deep Java paths pass Windows' 260-char limit; no-op on Linux
    r = subprocess.run(["git", "-c", "core.longpaths=true", *args], cwd=cwd,
                       capture_output=True, text=True,
                       timeout=1800)
    return r.returncode == 0


def fetch_project(p: Project, dest_root: Path) -> tuple[bool, str]:
    """Shallow-fetch exactly the vulnerable commit into dest_root/<slug>.
    Falls back to the release tag. Already-fetched projects are skipped."""
    dest = dest_root / p.slug
    if (dest / ".fetched").exists():
        return True, "already fetched"
    dest.mkdir(parents=True, exist_ok=True)
    ok = (_git(["init", "-q"], dest)
          and (_git(["remote", "add", "origin", p.repo_url], dest)
               or _git(["remote", "set-url", "origin", p.repo_url], dest)))
    if not ok:
        return False, "git init failed"
    for ref in (p.buggy_commit, f"refs/tags/{p.tag}"):
        if ref and _git(["fetch", "-q", "--depth", "1", "origin", ref], dest) \
                and _git(["checkout", "-q", "--force", "FETCH_HEAD"], dest):
            (dest / ".fetched").write_text(ref + "\n")
            return True, ref
    return False, "could not fetch commit or tag"


def project_size(root: Path) -> dict:
    files = [f for f in root.rglob("*.java") if ".git" not in f.parts]
    lines = 0
    for f in files:
        try:
            lines += f.read_bytes().count(b"\n")
        except OSError:
            pass
    return {"java_files": len(files), "java_lines": lines}


def labels_for(p: Project) -> list[dict]:
    """One label per fixed method. Paths are '<slug>/<file>' so one workspace can
    hold every project; units are later confined to their own project folder."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from auditor.classes import canonical_class
    from auditor.prefilter import is_test
    bug_class = canonical_class({"bug_class": "", "cwe": p.cwe})
    # fix commits often touch tests too; those aren't the vulnerable code
    methods = [m for m in p.methods if not is_test(m.file)] or p.methods
    seen, out = set(), []
    for m in methods:
        key = (m.file, m.cls, m.method)
        if key in seen:
            continue
        seen.add(key)
        out.append({"file": f"{p.slug}/{m.file}", "line": m.line or 0,
                    "bug_class": bug_class, "cwe": p.cwe, "cve": p.cve,
                    "project": p.slug, "class": m.cls, "method": m.method,
                    "signature": m.signature, "year": cve_year(p.cve)})
    return out


def main():
    import argparse
    import json
    ap = argparse.ArgumentParser(description="Build a CWE-Bench-Java subset.")
    ap.add_argument("--version", choices=list(SOURCES), default="v1")
    ap.add_argument("--data-dir", type=Path, default=None,
                    help="where the CSVs live (downloaded if missing)")
    ap.add_argument("--cwes", nargs="+", default=["22", "78", "79", "94"])
    ap.add_argument("--per-cwe", type=int, default=5, help="0 = all scorable")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--min-year", type=int, default=None,
                    help="only CVEs from this year on (contamination control)")
    ap.add_argument("--only", nargs="*", default=None, help="slug substrings to keep")
    ap.add_argument("--out-dir", type=Path, default=None)
    ap.add_argument("--fetch", action="store_true", help="download the project sources")
    ap.add_argument("--list", action="store_true", help="print the pick, write nothing")
    a = ap.parse_args()

    here = Path(__file__).resolve().parent / "cwe_bench_java"
    data_dir = fetch_data(a.version, a.data_dir or here / "data" / a.version)
    projects = load_projects(data_dir)
    picked = select(projects, a.cwes, a.per_cwe, a.seed, a.min_year, a.only)
    scorable = sum(1 for p in projects.values() if p.methods)
    print(f"{a.version}: {len(projects)} CVEs, {scorable} with ground truth; "
          f"picked {len(picked)}")
    for p in picked:
        print(f"  {p.cwe:<8} {p.cve:<16} {p.slug}  ({len(p.methods)} fixed methods)")
    if a.list:
        return

    name = f"{a.version}_s{a.seed}_n{a.per_cwe}" + (f"_y{a.min_year}" if a.min_year else "")
    out = a.out_dir or here / name
    proj_root = out / "projects"
    proj_root.mkdir(parents=True, exist_ok=True)
    labels, selection = [], []
    for p in picked:
        entry = {"slug": p.slug, "cve": p.cve, "cwe": p.cwe, "year": cve_year(p.cve),
                 "repo": p.repo_url, "buggy_commit": p.buggy_commit, "tag": p.tag,
                 "advisory": p.advisory, "fixed_methods": len(p.methods)}
        if a.fetch:
            ok, how = fetch_project(p, proj_root)
            entry.update({"fetched": ok, "fetch_ref": how})
            if ok:
                entry.update(project_size(proj_root / p.slug))
            print(f"  {'ok ' if ok else 'FAIL'} {p.slug}: {how}")
        selection.append(entry)
        labels += labels_for(p)
    (out / "labels.json").write_text(json.dumps(labels, indent=2))
    (out / "selection.json").write_text(json.dumps(
        {"version": a.version, "seed": a.seed, "per_cwe": a.per_cwe,
         "min_year": a.min_year, "cwes": a.cwes, "projects": selection}, indent=2))
    print(f"\n{len(labels)} labelled methods across {len(picked)} projects -> {out}")
    if not a.fetch:
        print("sources not downloaded yet; rerun with --fetch")


if __name__ == "__main__":
    main()
