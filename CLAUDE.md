# Project Context: llm-code-auditor

An LLM agent for source-code security auditing, built as a **measured evaluation**
of which agent-scaffolding components actually drive detection quality. This is the
core of a master's thesis (LSU, advised by Andrew Case).

See [README.md](README.md) for the full overview, setup, and usage, and
[ARCHITECTURE.md](ARCHITECTURE.md) for the design and how it maps to IRIS and
RepoAudit.

## The contribution

Prior systems (IRIS, RepoAudit) change several things at once, so nobody can say
which component earns the gain. This repo isolates four factors and measures each
one, holding the benchmark, prompt structure, and scoring constant.

## The four factors

Vary independently; everything else is held constant.

- **Tool access**: static analysis on / off (`AuditConfig.static_analysis`).
- **Exploration**: on-demand repo exploration vs fixed context, at matched token
  budgets (`AuditConfig.exploration`, `context_budget`).
- **Validation**: evidence stage on / off, with evidence items toggled independently
  (`ValidationConfig`).
- **Model**: at least three models across capability tiers, including one open-weight
  (`--models`, `openai-compat:<name>` for open-weight).

## Research objectives

- **RO1** Attribute the agentic gain: factorial ablation (C0-C4 x models).
- **RO2** Characterize validation: evidence items (path with quoted steps, sanitizer
  adequacy, path-condition satisfiability, concrete input).
- **RO3** Cost-quality frontier: tokens, time, and cost per true positive.
- **RO4** External and construct validity: real OSS projects and semantics-preserving
  edits. In progress.

## Evaluation

- **Benchmarks**: NIST Juliet and CWE-Bench-Java, reported separately, never averaged.
- **Baselines**: semgrep tool-only, model-only (C0), and any SARIF-emitting tool
  (CodeQL, Trail of Bits) through `sarif.py`.
- **Metrics**: precision, recall, FDR, localization, tokens, cost, wall time.
- **Scoring**: `function` mode (bad vs good side) and `line` mode (path-level
  localization).

## Current state

Built and tested offline (`pytest`, 115 tests, scripted fake model, no API calls):
factor toggles and presets C0-C4, explore and fixed modes at matched budgets, the
evidence-stage validator (plus an opt-in `execute` execution oracle), Anthropic and
OpenAI-compatible backends, a resumable experiment runner, the report
(CIs / McNemar / RO2 / RO3), the Juliet and CWE-Bench-Java loaders, and hunt mode
(screen -> triage -> deep dive). In progress: the open-weight model tier, the full
thesis runs, and RO4.

## Conventions and working notes

- Venv: `venv/Scripts/python` (Windows).
- Run `venv/Scripts/python -m pytest` after changes.
- Use `--dry-run` (and `--max-usd`) before any paid run.
- Bump `PROMPT_VERSION` in `auditor/prompts.py` whenever a prompt changes.
- Writing style for docs, comments, and commit messages: casual, plainspoken,
  contractions, no em dashes.

## Responsible use

This is a security research tool; run it only on code you are authorized to audit.
Hunt-mode findings are tested only against instances the author runs, and real bugs
are reported through each project's security policy under coordinated disclosure.
Detailed working notes and any unreported findings are kept in local, gitignored
files, not in this repository.

@CLAUDE.local.md
