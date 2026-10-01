# LLM Code-Auditing Agent (starter)

An agent that explores a code repository on its own, calls static-analysis
tools, forms source-to-sink hypotheses, and validates them to cut false
positives. Masters-scope build modeled on RepoAudit and IRIS, benchmarked
against a real baseline (semgrep now, Trail of Bits skills later). See
`ARCHITECTURE.md` for the design and research framing.

## Setup

```bash
pip install -r requirements.txt          # anthropic + semgrep
export ANTHROPIC_API_KEY=...
```

## Run the agent

```bash
python run_audit.py benchmarks/toy --bugs sqli cmdi        # planted toy repo
python run_audit.py /path/to/repo --bugs sqli cmdi path --out findings.json

# real-project mode: context pre-pass + variant hunt (adapted from Trail of Bits)
python run_audit.py /path/to/repo --bugs sqli cmdi path --context --variants
```

## Run the experiment (the thesis engine)

Compares baseline vs your agent vs agent+validator on one labelled benchmark:

```bash
python eval/experiment.py benchmarks/toy benchmarks/toy/labels.json --bugs sqli cmdi
```

Baseline only (no API key needed), using pinned local rules:

```bash
python -c "from auditor.baseline import semgrep_baseline; \
from eval.metrics import score; import json; \
labels=json.load(open('benchmarks/toy/labels.json')); \
print(score(semgrep_baseline('benchmarks/toy', config='benchmarks/semgrep-rules.yml'), labels))"
```

On the toy repo the baseline scores precision 1.0 / recall 0.5: it catches the
command-injection but misses the SQL-injection whose shape does not match the
rule. Closing that recall gap without losing precision is what your agent must
demonstrate.

## Real benchmark: NIST Juliet

Juliet is the labelled dataset for real numbers. Download it (NIST/SARD), then
build a slice and score the full pipeline against it.

```bash
# 1. download + unzip Juliet (Java shown; C/C++ also supported)
#    https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-java-v1-3.zip

# 2. build a labelled slice (15 cases each for SQLi, cmdi, path traversal)
python benchmarks/juliet_loader.py --juliet-dir ~/juliet-java \
    --cwes 89 78 22 --per-cwe 15 \
    --out-dir benchmarks/juliet_slice \
    --labels benchmarks/juliet_slice/labels.json

# 3. score baseline vs agent vs agent+validator vs full pipeline
python eval/experiment.py benchmarks/juliet_slice \
    benchmarks/juliet_slice/labels.json --bugs sqli cmdi path
```

Start small (`--per-cwe 10`) to keep token cost down, then scale up once the
numbers look sane. This slice has the near-miss `good()` functions that generate
false positives, so it is where the validator's precision gain finally shows.

## What to build next

1. Run the agent loop on the toy repo, confirm it finds both planted bugs.
2. Run `eval/experiment.py` to get the baseline-vs-agent table.
3. Iterate `auditor/prompts.py`; score every change on the same benchmark.
4. Add CodeQL alongside semgrep in `auditor/tools.py`.
5. Add Trail of Bits `static-analysis` / `fp-check` as a second baseline (run via
   Claude Code, emit SARIF, feed to `auditor/sarif.py`).
6. Scale to NIST Juliet and CWE-Bench-Java, then a real open-source project.

## Layout

```
auditor/
  prompts.py    # system + validator prompts  <- iterate here, measure everything
  tools.py      # list_dir / read_file / grep / run_semgrep, sandboxed to the repo
  agent.py      # tool-use loop + validator pass, with token accounting
  sarif.py      # normalize any tool's SARIF into the common finding schema
  baseline.py   # semgrep baseline detector (state of practice to beat)
eval/
  metrics.py       # precision / recall / F1 / FP scoring
  run_benchmark.py # single-config scoring
  experiment.py    # baseline vs agent vs agent+validator comparison table
benchmarks/
  toy/               # planted bugs + labels to smoke-test the pipeline
  semgrep-rules.yml  # pinned local rules (reproducible; no registry needed)
run_audit.py         # CLI
```
