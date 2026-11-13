#!/usr/bin/env python3
"""CWE-Bench-Java loader. See the README ("Running the experiment") for usage."""
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


def pools(projects: dict[str, Project], cwes: list[str], seed: int,
          min_year: int | None = None, only: list[str] | None = None,
          exclude: set[str] | None = None) -> dict[str, list[Project]]:
    """Per CWE, every scorable project (one with ground truth) in seeded order.
    min_year keeps only CVEs from that year on (contamination control); only
    restricts to slugs containing any of the given substrings; exclude drops
    these CVE ids (a held-out set that skips CVEs already used for tuning)."""
    import random
    rng = random.Random(seed)
    out = {}
    for cwe in [norm_cwe(c) for c in cwes]:
        pool = sorted((p for p in projects.values()
                       if p.cwe == cwe and p.methods
                       and (min_year is None or (cve_year(p.cve) or 0) >= min_year)
                       and (not only or any(o in p.slug for o in only))
                       and p.cve not in (exclude or ())),
                      key=lambda p: p.slug)
        rng.shuffle(pool)
        out[cwe] = pool
    return out


def select(projects: dict[str, Project], cwes: list[str], per_cwe: int, seed: int,
           min_year: int | None = None, only: list[str] | None = None,
           exclude: set[str] | None = None) -> list[Project]:
    """Seeded, CWE-stratified pick: the first per_cwe of each pool (0 = all)."""
    picked = []
    for pool in pools(projects, cwes, seed, min_year, only, exclude).values():
        picked += pool[:per_cwe] if per_cwe > 0 else pool
    return picked


def audited_files(project_dir: Path, classes=("path", "cmdi", "xss", "codei")) -> int:
    """How many files the project-file units would audit: Java, not test or demo
    code, and passing the keyword pre-filter. Same rules as auditor/units.py."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from auditor.prefilter import keep, is_test, is_non_product
    n = 0
    for f in project_dir.rglob("*.java"):
        rel = f.relative_to(project_dir).as_posix()
        if ".git" in f.parts or is_test(rel) or is_non_product(rel):
            continue
        try:
            if keep(f.read_text(encoding="utf-8", errors="replace"), list(classes)):
                n += 1
        except OSError:
            pass
    return n


def _git(args: list[str], cwd: Path) -> bool:
    import subprocess
    # core.longpaths: deep Java paths pass Windows' 260-char limit; no-op on Linux
    r = subprocess.run(["git", "-c", "core.longpaths=true", *args], cwd=cwd,
                       capture_output=True, text=True,
                       timeout=1800)
    return r.returncode == 0


def free_gb(path: Path) -> float:
    import shutil
    while not path.exists():
        path = path.parent
    return shutil.disk_usage(path).free / 1e9


def ensure_space(path: Path, min_gb: float) -> None:
    """Stop cleanly before a fetch would run the disk out. Already-fetched
    projects are kept, so rerunning after freeing space picks up where it stopped."""
    free = free_gb(path)
    if free < min_gb:
        raise SystemExit(f"\nstopping: only {free:.1f} GB free (need {min_gb:.1f}). "
                         "Free some space and rerun the same command; projects "
                         "already fetched are skipped.")


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
    # never leave a half-checked-out project where the experiment would audit it
    import shutil
    shutil.rmtree(dest, ignore_errors=True)
    return False, "could not fetch commit or tag"


def fetch_or_stop(p: Project, dest_root: Path, min_gb: float) -> tuple[bool, str]:
    """fetch_project, but a failure caused by low disk stops the run instead of
    counting as a skip. Otherwise a full disk would silently swap CVEs out of
    the sample (it did once: a project failed to fetch and its slot went to the
    next pick)."""
    if not (dest_root / p.slug / ".fetched").exists():
        ensure_space(dest_root, min_gb)
    ok, how = fetch_project(p, dest_root)
    if not ok:
        ensure_space(dest_root, min_gb)   # failed because the disk filled mid-fetch?
    return ok, how


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


def resolve_label_paths(proj_root: Path, labels: list[dict]) -> list[str]:
    """Fix-commit paths don't always exist at the vulnerable commit (a package
    renamed between them, e.g. Dubbo's com.alibaba -> org.apache). Point each
    such label at the same-named file in the project, preferring the longest
    shared path suffix. The original is kept as fix_file. Returns change notes."""
    notes, index = [], {}
    for l in labels:
        if (proj_root / l["file"]).exists():
            continue
        project, _, inner = l["file"].partition("/")
        if project not in index:
            root = proj_root / project
            index[project] = ([q.relative_to(root).as_posix() for q in root.rglob("*.java")]
                              if root.is_dir() else [])
        name = inner.rsplit("/", 1)[-1]
        same = [c for c in index[project] if c.rsplit("/", 1)[-1] == name]
        if not same:
            notes.append(f"{l.get('cve')}: {l['file']} has no same-named file; left as is")
            continue

        def shared(c, parts=inner.split("/")[::-1]):
            n = 0
            for x, y in zip(c.split("/")[::-1], parts):
                if x != y:
                    break
                n += 1
            return n
        best = max(same, key=shared)
        l.setdefault("fix_file", l["file"])
        l["file"] = f"{project}/{best}"
        notes.append(f"{l.get('cve')}: {inner} -> {best}")
    return notes


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
    ap.add_argument("--exclude", nargs="*", type=Path, default=[], metavar="LABELS_JSON",
                    help="skip every CVE in these labels.json files (held-out set)")
    ap.add_argument("--out-dir", type=Path, default=None)
    ap.add_argument("--fetch", action="store_true", help="download the project sources")
    ap.add_argument("--list", action="store_true", help="print the pick, write nothing")
    ap.add_argument("--min-free-gb", type=float, default=5.0,
                    help="stop before fetching if free disk space drops below this")
    ap.add_argument("--max-files", type=int, default=None,
                    help="size cap: skip projects that would audit more files than "
                         "this and take the next seeded pick with the same CWE "
                         "(needs --fetch; skipped ones are logged in selection.json)")
    a = ap.parse_args()
    if a.max_files and not a.fetch:
        ap.error("--max-files needs --fetch (sizes are measured on the sources)")

    here = Path(__file__).resolve().parent / "cwe_bench_java"
    data_dir = fetch_data(a.version, a.data_dir or here / "data" / a.version)
    projects = load_projects(data_dir)
    exclude = {l["cve"] for p in a.exclude for l in json.loads(p.read_text()) if l.get("cve")}
    if a.exclude:
        print(f"excluding {len(exclude)} CVE(s) from {len(a.exclude)} labels file(s)")
    picked = select(projects, a.cwes, a.per_cwe, a.seed, a.min_year, a.only, exclude)
    scorable = sum(1 for p in projects.values() if p.methods)
    print(f"{a.version}: {len(projects)} CVEs, {scorable} with ground truth; "
          + (f"{len(picked)} first candidates (the size cap may swap some; "
             "the keep/skip lines below are the real pick)" if a.max_files
             else f"picked {len(picked)}"))
    for p in picked:
        print(f"  {p.cwe:<8} {p.cve:<16} {p.slug}  ({len(p.methods)} fixed methods)")
    if a.list:
        return

    name = (f"{a.version}_s{a.seed}_n{a.per_cwe}" + (f"_y{a.min_year}" if a.min_year else "")
            + ("_heldout" if a.exclude else "")
            + (f"_m{a.max_files}" if a.max_files else ""))
    out = a.out_dir or here / name
    proj_root = out / "projects"
    proj_root.mkdir(parents=True, exist_ok=True)
    skipped = []
    if a.max_files:
        import shutil
        picked = []
        for cwe, pool in pools(projects, a.cwes, a.seed, a.min_year, a.only,
                               exclude).items():
            took = 0
            for p in pool:
                if a.per_cwe > 0 and took >= a.per_cwe:
                    break
                ok, how = fetch_or_stop(p, proj_root, a.min_free_gb)
                n = audited_files(proj_root / p.slug) if ok else None
                if ok and n <= a.max_files:
                    picked.append(p)
                    took += 1
                    print(f"  keep {p.slug}: {n} files")
                    continue
                why = f"{n} files > cap {a.max_files}" if ok else how
                skipped.append({"slug": p.slug, "cve": p.cve, "cwe": p.cwe, "why": why})
                print(f"  skip {p.slug}: {why}")
                if (proj_root / p.slug).exists():
                    # delete it: skipped projects are the giant ones, and keeping
                    # them is what filled the disk. It's logged in selection.json.
                    shutil.rmtree(proj_root / p.slug, ignore_errors=True)
            if a.per_cwe > 0 and took < a.per_cwe:
                print(f"  ! {cwe}: only {took} project(s) fit under the cap")
    labels, selection = [], []
    for p in picked:
        entry = {"slug": p.slug, "cve": p.cve, "cwe": p.cwe, "year": cve_year(p.cve),
                 "repo": p.repo_url, "buggy_commit": p.buggy_commit, "tag": p.tag,
                 "advisory": p.advisory, "fixed_methods": len(p.methods)}
        if a.fetch:
            ok, how = fetch_or_stop(p, proj_root, a.min_free_gb)
            entry.update({"fetched": ok, "fetch_ref": how})
            if ok:
                entry.update(project_size(proj_root / p.slug))
                entry["audited_files"] = audited_files(proj_root / p.slug)
            print(f"  {'ok ' if ok else 'FAIL'} {p.slug}: {how}")
        selection.append(entry)
        if a.fetch and not entry.get("fetched"):
            continue   # no code on disk: labelling it would count a miss the agent never had a chance at
        labels += labels_for(p)
    if a.fetch:
        import shutil
        keep = {e["slug"] for e in selection if e.get("fetched")}
        stale = sorted(d.name for d in proj_root.iterdir() if d.is_dir() and d.name not in keep)
        for name in stale:   # leftovers from an earlier run with other settings
            shutil.rmtree(proj_root / name, ignore_errors=True)
        if stale:
            print(f"  removed {len(stale)} project folder(s) not in this selection: "
                  + ", ".join(stale))
    failed = [e["slug"] for e in selection if a.fetch and not e.get("fetched")]
    if failed:
        print(f"  ! {len(failed)} project(s) failed to fetch and are left out of the labels: "
              + ", ".join(failed))
    if a.fetch:
        for note in dict.fromkeys(resolve_label_paths(proj_root, labels)):
            print(f"  label path: {note}")
    (out / "labels.json").write_text(json.dumps(labels, indent=2))
    (out / "selection.json").write_text(json.dumps(
        {"version": a.version, "seed": a.seed, "per_cwe": a.per_cwe,
         "min_year": a.min_year, "max_files": a.max_files, "cwes": a.cwes,
         "projects": selection, "skipped_for_size": skipped}, indent=2))
    n_proj = len({l["project"] for l in labels})
    print(f"\n{len(labels)} labelled methods across {n_proj} projects -> {out}")
    if not a.fetch:
        print("sources not downloaded yet; rerun with --fetch")


if __name__ == "__main__":
    main()
