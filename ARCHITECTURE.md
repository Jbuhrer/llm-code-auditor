# Architecture

The system is plumbing; the contribution is the measurement. Everything here
exists so the four factors (tool access, exploration, validation, model) can vary
independently while the benchmark, prompt structure, and scoring stay fixed.

## Lineage

The first version was `research.py` in PenAgent: send each line-numbered file to
the model with a bug-hunting prompt and parse JSON findings. The problem (advisor
feedback): an auditor that sees one file at a time can't look up a callee, check
a sanitizer definition, or run a tool, so it tests the model under artificial
handicaps. That setup survives here only as C0, the model-only control.

The design follows:

- **RepoAudit** (arXiv:2501.18160): the agent explores on demand instead of
  loading the repo, and a validator re-checks each candidate's data-flow facts
  and path feasibility. Here: `exploration="explore"` and `validate.py`.
- **IRIS** (arXiv:2405.17238): static analysis enumerates candidates and the LLM
  triages. Here: `static_analysis=True` (semgrep now, CodeQL later).
- ReAct / SWE-agent tool loops, and Agentless as the reminder that a fixed
  pipeline is a serious baseline (C0/C1).

## One audit cell

```
units = build_units(repo, "file" | "testcase" | "repo")
for each unit:
    fixed:    pack target + related files up to context_budget
              (+ semgrep hits if static_analysis) -> one call -> report_findings
    explore:  pack target up to context_budget -> tool loop
              list_dir / read_file / grep (+ run_semgrep if static_analysis)
              every tool result is charged to the same context_budget
              -> report_findings
    record:   findings, tokens (incl. cache), dollars, seconds, turns,
              truncation, budget exhaustion, refusals, errors
```

**Matched budgets.** Both modes get the same budget of code-context tokens per
unit, measured with one estimator (`units.est_tokens`). Fixed mode spends it up
front on the target plus files it mentions, then same-directory files. Explore
mode gets the target up front and spends the rest through tools; output past the
budget is cut and the agent is told to report. Total billed tokens (which differ,
since a loop resends history) are logged separately for RO3.

**Units.** `testcase` keeps Juliet's split cases (`_51a/_51b`, the `_81` family)
in one conversation so cross-function and cross-file flaws stay auditable.
Findings whose sink is outside the unit's targets are dropped (and counted),
since another unit owns that file.

## Validation (RO2)

Runs as a post-pass on the raw findings of an audit cell, one independent call
per finding. The validator sees the finding's whole file plus the rest of its
audit unit (up to `ValidationConfig.context_budget`), so on split cases it can
see the source in the other file. A 60-line window around the sink is only the
fallback for oversized files. Evidence items, any subset:

| item | model must give | mechanical check |
|---|---|---|
| path | steps of `{file, line, quote}` | every quote must appear within 2 lines of its cited line |
| sanitizer | sanitizers + `sanitizer_adequate` | adequate sanitizer -> reject |
| conditions | path conditions + `conditions_satisfiable` | unsatisfiable -> reject |
| poc | a concrete input | empty -> reject |

`rejected_by` on each record says which checks failed, which is what the RO2
table counts. With no items, the validator is a plain confirmed/rejected verdict.

## Threat model

Every prompt, hunter and validator, states who the attacker is
(`AuditConfig.threat_model`). `all-external` treats every outside input (env
vars, properties, config and data files, console, DB rows, network) as tainted,
which is what Juliet's ground truth assumes. `remote` is a realistic remote
attacker, the default for `run_audit.py` on real repos. Without this, models
picked their own threat model: in the pilot, Haiku and Sonnet called env vars,
config files, console input and DB rows trusted and rejected real Juliet bugs.

## Models

`llm.py` hides the provider. Claude models run with native tool use, prompt
caching on multi-turn loops, and a fixed `effort` level (current Claude models
reject `temperature`, so effort is the held-constant sampling setting). Refusals
(`stop_reason: refusal`) are recorded per unit; there is deliberately no
automatic fallback to another model, since that would contaminate the model
factor. Open-weight models go through any OpenAI-compatible server with a fixed
temperature.

## Scoring and statistics

- `function` mode (Juliet): matched pairs. TP = right class in a bad-side
  function; FP = right class in a good-side function. Verified against the full
  Juliet Java manifest for CWE 78/89/23/36: all 3,972 flaw lines land in
  bad-side functions.
- `line` mode: path-level localization within 5 lines of a labelled sink.
- Each cell runs R times. Tables report medians over runs with percentile
  bootstrap CIs that resample test cases. Paired cells are compared with exact
  McNemar on per-case majority outcomes, with odds ratio, Cohen's g, and risk
  difference.

## Reproducibility

Every results folder records the git commit (with a dirty flag), prompt version
and hash, semgrep version and ruleset, full configs, and raw token counts, so
dollars can be recomputed if prices change. A results folder refuses to resume
under different prompts. Pin `--semgrep-config` to a fixed ruleset for thesis
runs: `auto` changes as the registry updates.

## Baselines

- Semgrep tool-only (`baseline.py`, SARIF). Any SARIF-emitting tool, including
  CodeQL and the Trail of Bits `static-analysis` skill, drops into the same
  scorer through `sarif.py`.
- Model-only: C0.

## Not built yet

- CodeQL as a second static-analysis tool.
- RO4: semantics-preserving edits (SecLLMHolmes-style) and runs on current
  versions of active open-source projects.
- Chronological splits and contamination checks (PrimeVul, LessLeak-Bench) for
  the real-CVE benchmark.

(The CWE-Bench-Java loader, hunt mode, the screen-then-verify cascade, and the
opt-in `execute` evidence item are built; see the README.)

## Optional extras

`context.py` (a context-building pre-pass) and `variant.py` (variant hunting
after a confirmed bug), adapted from Trail of Bits skills, are available in
`run_audit.py --context --variants` for real repos. They are not thesis factors
and are not part of the presets.
