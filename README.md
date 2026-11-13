# llm-code-auditor

An LLM agent for source-code security auditing, built as a **measured evaluation**:
which parts of the agent scaffolding actually drive detection quality?

This is the core of a master's thesis (LSU, advised by Andrew Case). Systems like
IRIS and RepoAudit change several things at once, so nobody can say which component
earns the gain. This repo isolates four factors and measures each one, holding the
benchmark, prompt structure, and scoring constant.

| factor | toggle | values |
|---|---|---|
| tool access | `static_analysis` | semgrep on / off |
| exploration | `exploration` | `explore` (agent navigates the repo) / `fixed` (context packed up front), same token budget |
| validation | `ValidationConfig` | off, or an evidence stage requiring any subset of: path, sanitizer, conditions, poc |
| model | `model` | any Claude model, or an open-weight model behind an OpenAI-compatible server |

The point is attribution, not a single leaderboard number: vary one factor at a
time, hold everything else fixed, score every cell the same way, and report which
component moved the needle and by how much, with confidence intervals and paired
significance tests.

## Configurations

| preset | exploration | static analysis | validation | what it is |
|---|---|---|---|---|
| C0 | fixed | off | off | model-only baseline (the old file-by-file prompting) |
| C1 | fixed | on | off | + static analysis |
| C2 | explore | off | off | + exploration instead |
| C3 | explore | on | off | both |
| C4 | explore | on | all evidence | full agent |

C3 and C4 share one audit pass: the validator runs on exactly the same raw
findings, so validation on/off is a paired comparison and the audit is paid once.
`--factorial` adds every exploration x static-analysis x validation cell.

## Research objectives

- **RO1 Attribute the agentic gain.** Factorial ablation (C0-C4 x models), with an
  ablation table and McNemar tests between adjacent presets.
- **RO2 Characterize validation.** Evidence items toggled independently (path with
  quoted steps, sanitizer adequacy, path-condition satisfiability, concrete input),
  via `--evidence-sweep`: how many false positives each removes, and how many true
  positives it costs.
- **RO3 Cost-quality frontier.** Tokens, wall time, and dollars per true positive,
  per config and per model, logged for every unit.
- **RO4 External and construct validity.** Real OSS projects and semantics-preserving
  edits (SecLLMHolmes-style). In progress.

## How it works

One audit cell builds units from the repo, then for each unit either packs context
up front (`fixed`) or lets the agent navigate on demand (`explore`), both held to
the same code-context token budget. See [ARCHITECTURE.md](ARCHITECTURE.md) for the
full design and how it maps to RepoAudit and IRIS.

- **Exploration.** In `explore` mode the agent reads the repo with sandboxed
  `list_dir` / `read_file` / `grep`, following callers, callees, and sanitizer
  definitions; every tool result is charged to the same budget as fixed mode, so
  the comparison is about *how* context arrives, not how much.
- **Tool access.** With `static_analysis` on, the agent can also call `run_semgrep`
  for an independent signal and is told to treat hits as leads to verify.
- **Validation (RO2).** A skeptical second model re-checks each candidate and must
  supply the required evidence. Quoted data-flow steps are checked *mechanically*
  against the file (a quote that is not in the code is a failed check), so the
  validator cannot hand-wave a path. `rejected_by` records which check killed each
  finding. An opt-in `execute` evidence item lets an execution oracle override the
  model when a PoC actually triggers; the plumbing is in place, the sandboxed
  build-and-run runner is not built yet.
- **Threat model.** Every prompt (hunter and validator) states who the attacker is.
  Without it, models silently pick their own threat model and drop real bugs; making
  it explicit is itself one of the larger effects we have measured (see below).
- **Models.** `llm.py` hides the provider. Claude runs with native tool use and
  prompt caching; open-weight models run through any OpenAI-compatible server. There
  is deliberately no automatic model fallback, since that would contaminate the
  model factor.

## Hunt mode

`hunt.py` runs the agent on a real project with no labels, as a cascade:

1. a cheap **screen** model flags anything plausible in every relevant file
   (recall-first "screen" stance),
2. a **triage** model scores every flag (nothing is discarded, it only ranks),
3. the strongest **deep-dive** model investigates the top flags with the whole repo
   open and tools in hand, and writes `<out>/report.md`, best leads first, with a
   path, a concrete input, and repro steps.

```bash
python hunt.py ~/targets/some-repo --dry-run        # files, flags, cost estimate
python hunt.py ~/targets/some-repo --max-usd 15     # screen, triage, deep dive
python hunt.py ~/targets/some-repo --since v1.2.3   # only files changed since a git ref
```

`--since <ref>` scopes the hunt to files changed since a tag, commit, or branch, so
you can chase a release regression instead of re-screening the whole tree. Rerun the
same command to resume; finished work is never paid for twice, and `--max-usd` caps
spend.

Hunt mode uses its own threat model and is kept strictly separate from the measured
evaluation (it is not a benchmark configuration). It has already surfaced
previously-unreported vulnerabilities in widely-used open-source Java libraries,
reproduced and pending coordinated disclosure. **Only test findings against an
instance you run yourself (a VM or container), and report real bugs through each
project's security policy.**

## Benchmarks

- **NIST Juliet (Java).** Stratified loader; report function-level and line-level
  scoring. Built.
- **CWE-Bench-Java.** IRIS's real-CVE benchmark; loader with a held-out split, a
  per-CWE file-size cap, and contamination controls (`--min-year`, `--exclude`).
  Built.

Benchmarks are always reported separately, never averaged together.

## Baselines

- **Semgrep tool-only** (`baseline.py` via SARIF).
- **Model-only** (C0).
- Any SARIF-emitting tool, including CodeQL and the Trail of Bits `static-analysis`
  skill, drops into the same scorer through `sarif.py`.

## Scoring

Juliet puts each test case's vulnerable path and its patched twins in the same
file. `function` scoring (the Juliet default) finds the function each finding sits
in: the right class inside `bad`/`badSink` is a true positive, the right class
inside `goodG2B`/`goodB2G` is a false positive on the patched variant. `line`
scoring (right file, class, and sink line within 5) is used for localization and
for non-Juliet benchmarks.

## Setup

```bash
python -m venv venv
venv/Scripts/python -m pip install -r requirements.txt     # Windows
export ANTHROPIC_API_KEY=...
venv/Scripts/python -m pytest                               # 115 offline tests, no API calls
```

Semgrep installs from pip and runs natively on Windows. Open-weight models also need
`pip install openai` and a server (vLLM or Ollama) exposing an OpenAI-compatible
endpoint (`OPENAI_COMPAT_BASE_URL`), then pass `--models openai-compat:<model-name>`.

## Running the experiment

1. Build a Juliet slice (download Juliet Java 1.3 from NIST SARD first):

   ```bash
   python benchmarks/juliet_loader.py --juliet-dir ~/juliet-java/Java \
       --cwes 89 78 22 --per-cwe 20 --seed 0
   ```

   Sampling is stratified by CWE and by whether the bad path crosses a function
   boundary. CWE 22 means 23 + 36, since Juliet Java has no CWE-22 folder.

2. Or build a CWE-Bench-Java subset (downloads the CSVs, then the sources with
   `--fetch`):

   ```bash
   python benchmarks/cwe_bench_java.py --version v1 --cwes 22 78 79 94 \
       --per-cwe 10 --seed 0 --fetch --max-files 300
   # held-out set: everything scorable not already used
   python benchmarks/cwe_bench_java.py --version v1 --per-cwe 0 --fetch \
       --max-files 300 --exclude benchmarks/cwe_bench_java/<dev>/labels.json
   ```

3. Look at the plan and cost before spending anything:

   ```bash
   python eval/experiment.py <repo> <labels.json> \
       --models claude-opus-5-5 claude-sonnet-5-5 claude-haiku-5-5 --runs 3 --dry-run
   ```

4. Smoke-test on a few units, then the real run. `--max-usd` caps spend, results are
   saved as they finish, and rerunning with the same `--out` skips finished work, so
   a crash or Ctrl-C never re-bills anything:

   ```bash
   python eval/experiment.py <repo> <labels.json> ... --limit 3 --runs 1 --out results/smoke
   python eval/experiment.py <repo> <labels.json> ... --runs 3 --evidence-sweep --out results/run1
   ```

5. Run the screen-then-verify cascade (a cheap screen model, then a stronger
   verifier on the same findings, optionally through Message Batches at half price):

   ```bash
   python eval/experiment.py <repo> <labels.json> --configs C2 --stance screen \
       --validation all --bugs path cmdi xss codei \
       --models claude-haiku-5-5 --verifier-model claude-sonnet-5-5 --batch --out results/cascade
   ```

   (`--verifier-model` only retargets an *enabled* validator, so the cascade needs a
   validation variant such as `--validation all`.)

6. Score and tabulate (free):

   ```bash
   python eval/report.py results/run1
   ```

   Writes `report.md` and `report.json`: the ablation table (medians over runs with
   95% bootstrap CIs over test cases), exact McNemar tests with effect sizes between
   adjacent presets, the RO2 validator table (FPs removed vs TPs lost, tokens per FP
   removed, which check rejected what), and cost per true positive.

For a single real repo with no labels: `python run_audit.py /path/to/repo` (defaults
to C4; `--exhaustive` hunts any vulnerability class). For hunting without labels,
prefer `hunt.py` above.

## Preliminary findings

Early results, from pilot runs; the full thesis runs (including the open-weight model
tier) are in progress, so treat these as directional.

- **Stating the threat model is one of the largest single effects.** On Juliet,
  making the attacker explicit moved recall roughly 18 points (Haiku); no scaffolding
  component (exploration, static analysis, validation) moved it more than a few.
- **Juliet saturates for current models once the controls are fixed.** With an
  explicit threat model and a whole-unit validator, strong models score near the
  ceiling in every cell and the apparent "exploration helps" effect disappears (it
  was an artifact of an unstated threat model). So Juliet cannot separate the
  components for current models, which is itself a reportable methodology result;
  the component effects come from CWE-Bench-Java.
- **Reporting stance moves recall more than any scaffolding component.** On
  CWE-Bench-Java, a recall-first "screen" stance roughly doubled recall over a
  precise stance, at the cost of far more alerts per project.
- **A screen-then-verify cascade trades alerts for precision.** A cheap screen
  followed by a stronger verifier cut alerts per project roughly 3 to 6x. Recall held
  up on the development set but fell by about half on the held-out set, and that gap
  is the RO2 finding: the verifier works well on application code but fails on library
  code, where the vulnerable code *is* the defense being bypassed or the attacker is
  the caller of a public API.
- **The LLM cells produce far fewer false positives than the tool-only baseline.**
  On the Juliet slice the LLM configurations hit a 0 false-positive rate where
  semgrep produced 21.

## Reproducibility

Every results folder records the git commit (with a dirty flag), prompt version and
hash, semgrep version and ruleset, full configs, and raw token counts, so dollars can
be recomputed if prices change. A results folder refuses to resume under different
prompts. Pin `--semgrep-config` to a fixed ruleset for thesis runs (`auto` changes as
the registry updates). Bump `PROMPT_VERSION` in `auditor/prompts.py` whenever a prompt
changes.

## Layout

```
auditor/
  config.py     the four factors, presets C0-C4, validation variants
  agent.py      explore loop and fixed-context mode, per-unit run records
  llm.py        Anthropic and OpenAI-compatible backends behind one interface
  units.py      audit units (file / testcase / repo) and budget-matched packing
  validate.py   evidence-stage validator with mechanical quote checking
  tools.py      sandboxed list_dir / read_file / grep / run_semgrep; workspace diff for --since
  prompts.py    shared prompt core plus per-mode sections (versioned, hashed)
  prefilter.py  keyword pre-filter: which files could plausibly hold a given bug class
  hunt.py       hunt cascade: screen -> triage -> deep dive
  batch.py      Anthropic Message Batches (half-price validation)
  pricing.py    dollars per call
  baseline.py, sarif.py    semgrep tool-only baseline via SARIF
  context.py, variant.py   optional extras for real repos (not factors)
eval/
  experiment.py   configs x models x runs, resumable, with cascade support
  report.py       tables, CIs, McNemar, RO2, RO3
  metrics.py      function / line / testcase scoring
  juliet_functions.py   compiler-free function spans for Juliet files
  stats.py        bootstrap and exact McNemar, pure Python
  hunt_check.py   score a hunt run against CWE-Bench-Java labels (calibration)
  prefilter_check.py, pilot.py, compare.py, rescore.py, run_benchmark.py
benchmarks/
  juliet_loader.py          stratified Juliet slices
  cwe_bench_java.py         real-CVE loader, held-out split, size cap
  fix_label_paths.py        fix label paths that move between buggy and fixed commits
  toy/                      tiny fixture repo for the offline tests
tests/            115 offline tests with a scripted fake model (no API calls)
```

## Responsible use

This is a security research tool. Run it only on code you are authorized to audit.
Hunt-mode findings are tested only against instances the author runs, and real bugs
are reported through each project's own security policy under coordinated disclosure.
Details of undisclosed findings are not published here.

## Status

Built and tested offline (115 tests): the four factors and presets C0-C4, explore
and fixed modes at matched budgets, the evidence-stage validator, Anthropic and
OpenAI-compatible backends, the resumable experiment runner, the report with
CIs / McNemar / RO2 / RO3, the Juliet and CWE-Bench-Java loaders, and hunt mode.
In progress: the open-weight model tier, the full thesis runs, and RO4
(semantics-preserving edits and current-version OSS runs).
