"""
Repoint CWE-Bench-Java labels whose fix-commit path doesn't exist in the
fetched (vulnerable) source. Free, rewrites labels.json in place and keeps a
.orig copy. Newer loader runs do this automatically.

  python benchmarks/fix_label_paths.py <projects dir> <labels.json>
"""
from __future__ import annotations
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.cwe_bench_java import resolve_label_paths  # noqa: E402


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    proj_root, path = Path(sys.argv[1]), Path(sys.argv[2])
    labels = json.loads(path.read_text())
    notes = list(dict.fromkeys(resolve_label_paths(proj_root, labels)))
    for n in notes:
        print(" ", n)
    if not any("->" in n for n in notes):
        print("nothing to fix")
        return
    backup = path.with_suffix(".json.orig")
    if not backup.exists():
        shutil.copy(path, backup)
    path.write_text(json.dumps(labels, indent=2))
    print(f"updated {path} (original kept at {backup.name})")


if __name__ == "__main__":
    main()
