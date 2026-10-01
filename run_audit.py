#!/usr/bin/env python3
"""
Run the auditor on a repo.

  export ANTHROPIC_API_KEY=...
  python run_audit.py /path/to/repo --bugs sqli cmdi path --out findings.json

Add --no-validate to see the false-positive rate WITHOUT the validator pass.
Comparing the two is a clean thesis experiment.
"""
import argparse
import json
from auditor import Auditor
from auditor.prompts import BUG_CLASSES


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--bugs", nargs="+", default=["sqli", "cmdi", "path"],
                    choices=list(BUG_CLASSES))
    ap.add_argument("--max-turns", type=int, default=12,
                    help="max turns PER FILE (each file is its own conversation)")
    ap.add_argument("--no-validate", action="store_true")
    ap.add_argument("--context", action="store_true",
                    help="build architectural context before hunting (ToB-style)")
    ap.add_argument("--variants", action="store_true",
                    help="hunt variants of each confirmed finding (ToB-style)")
    ap.add_argument("--out", default="findings.json")
    a = ap.parse_args()

    auditor = Auditor(a.repo, a.bugs, max_turns=a.max_turns,
                      validate=not a.no_validate,
                      use_context=a.context, use_variants=a.variants)
    res = auditor.run()

    with open(a.out, "w") as fh:
        json.dump(res.as_dict(), fh, indent=2)

    print(f"{len(res.findings)} findings | "
          f"{res.files_audited} files | "
          f"{res.turns} turns | "
          f"{res.input_tokens + res.output_tokens} tokens "
          f"(in {res.input_tokens} / out {res.output_tokens})")
    for f in res.findings:
        print(f"  [{f.get('bug_class')}] {f.get('file')}:{f.get('line')} "
              f"({f.get('cwe')}, conf={f.get('confidence')})")
    print(f"\nwritten to {a.out}")


if __name__ == "__main__":
    main()
