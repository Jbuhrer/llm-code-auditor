# llm-code-auditor

An LLM agent for source-code security auditing, built as a measured evaluation:
which parts of the agent scaffolding actually drive detection quality?

Systems like IRIS and RepoAudit change several things at once, so nobody can say
which component earns the gain. This repo isolates four factors and measures each
one, holding the benchmark, prompt structure, and scoring constant:

| factor | toggle | values |
|---|---|---|
| tool access | `static_analysis` | semgrep on / off |
| exploration | `exploration` | `explore` (agent navigates the repo) / `fixed` (context packed up front), same token budget |
| validation | `ValidationConfig` | off, or an evidence stage requiring any subset of: path, sanitizer, conditions, poc |
| model | `model` | any Claude model, or an open-weight model behind an OpenAI-compatible server |

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

## Setup

```bash
python -m venv venv
venv/Scripts/python -m pip install -r requirements.txt     # Windows
export ANTHROPIC_API_KEY=...
venv/Scripts/python -m pytest                               # offline, no API calls
```

Semgrep installs from pip and runs natively on Windows. Open-weight models also
need `pip install openai` and a server such as Ollama
(`OPENAI_COMPAT_BASE_URL`, default `http://localhost:11434/v1`), then pass
`--models openai-compat:<model-name>`.

## Running the experiment

1. Build a Juliet slice (download Juliet Java 1.3 from NIST SARD first):

   ```bash
   python benchmarks/juliet_loader.py --juliet-dir ~/juliet-java/Java \
       --cwes 89 78 22 --per-cwe 20 --seed 0
   ```

   Sampling is stratified by CWE and by whether the bad path crosses a function
   boundary, and rotates across Juliet's source variants. CWE 22 means 23 + 36,
   since Juliet Java has no CWE-22 folder.

2. Look at the plan and cost before spending anything:

   ```bash
   python eval/experiment.py benchmarks/juliet_slice benchmarks/juliet_slice/labels.json \
       --models claude-opus-5-5 claude-sonnet-5-5 claude-haiku-5-5 --runs 3 --dry-run
   ```

3. Smoke test on a few units, then the real run:

   ```bash
   python eval/experiment.py ... --limit 3 --runs 1 --out results/smoke
   python eval/experiment.py ... --runs 3 --evidence-sweep --out results/juliet-v1
   ```

   Results are saved as they finish. Rerunning with the same `--out` skips
   finished work, so a crash or Ctrl-C never re-bills anything. Auth errors and
   unknown model ids stop the run immediately instead of failing every unit.

4. Score and tabulate (free):

   ```bash
   python eval/report.py results/juliet-v1
   ```

   Writes `report.md` and `report.json`: the ablation table (medians over runs
   with 95% bootstrap CIs over test cases), exact McNemar tests with effect sizes
   between adjacent presets, the RO2 validator table (FPs removed vs TPs lost,
   tokens per FP removed, which check rejected what), and cost per true positive.

For a single real repo with no labels: `python run_audit.py /path/to/repo`
(defaults to C4; `--exhaustive` hunts any vulnerability class).

## Scoring

Juliet puts each test case's vulnerable path and its patched twins in the same
file. `function` scoring (the Juliet default) finds the function each finding
sits in: the right class inside `bad`/`badSink` is a true positive, the right
class inside `goodG2B`/`goodB2G` is a false positive on the patched variant.
`line` scoring (path-level: right file, class, and sink line within 5) is used
for localization and for non-Juliet benchmarks. Benchmarks are reported
separately, never averaged together.

## Layout

```
auditor/
  config.py     the four factors, presets C0-C4, validation variants
  agent.py      explore loop and fixed-context mode, per-unit run records
  llm.py        Anthropic and OpenAI-compatible backends behind one interface
  units.py      audit units (file / testcase / repo) and budget-matched packing
  validate.py   evidence-stage validator with mechanical quote checking
  tools.py      sandboxed list_dir / read_file / grep / run_semgrep
  prompts.py    shared prompt core plus per-mode sections (versioned, hashed)
  pricing.py    dollars per call
  baseline.py, sarif.py    semgrep tool-only baseline via SARIF
  context.py, variant.py   optional extras for real repos (not factors)
eval/
  experiment.py   configs x models x runs, resumable
  report.py       tables, CIs, McNemar, RO2, RO3
  metrics.py      function / line / testcase scoring
  juliet_functions.py   compiler-free function spans for Juliet files
  stats.py        bootstrap and exact McNemar, pure Python
benchmarks/
  juliet_loader.py, toy/
tests/            offline tests with a scripted fake model
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and how it maps to
RepoAudit and IRIS.
