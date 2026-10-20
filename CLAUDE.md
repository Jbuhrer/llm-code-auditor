# Project Context: llm-code-auditor

## About me
- Jackson Buhrer (goes by Mushu), GitHub: Jbuhrer
- MS Computer Science student at LSU, cybersecurity focus. Thesis advisor: Andrew Case. Course this runs under: CSC 7900.
- Junior penetration tester at SourcePoint Security (SPS), under Scott Campbell.
- Also building PenAgent (Jbuhrer/PenAgent), an autonomous pentesting agent. This repo was split out of PenAgent and is separate from it.
- Writing style: casual, plainspoken, contractions. No em dashes in anything you write for me (docs, comments, commit messages).

## What this project is
An LLM agent for source-code security auditing. It is the core of my master's thesis.

Repo: `https://github.com/Jbuhrer/llm-code-auditor` (private)

The contribution is a **measured evaluation**, not just the agent. Prior systems (IRIS, RepoAudit) change several things at once, so nobody can say which part of the scaffolding actually drives detection quality. The thesis isolates the components and measures each one.

## How it started (history)
1. Original approach was `research.py` inside PenAgent: a file-by-file source auditor. It walked a source tree, sent each line-numbered file to Claude with a structured bug-hunting prompt, and returned JSON findings (file, lines, bug class, CWE, severity, confidence, fix). It was validated against PenAgent's own code and against DVWA.
2. Advisor feedback: the file-by-file setup wasn't the right research direction. An auditor that gets fixed context one file at a time can't look up a callee, check a sanitizer definition, or run a tool, so it's testing the model under artificial handicaps.
3. This repo is the successor. The agent works on the whole repo the way a human auditor would, and the file-by-file prompting approach is kept only as the model-only baseline (C0).

## The four factors (this is the whole point)
Must vary independently, with benchmark, prompt structure, and scoring held constant:
- **Tool access**: static analysis on vs off (`AuditConfig.static_analysis`)
- **Exploration**: on-demand repo exploration vs fixed context, at matched token budgets (`AuditConfig.exploration`, `context_budget`)
- **Validation**: evidence stage on vs off, with evidence items toggled independently (`ValidationConfig`)
- **Model**: at least three models across capability tiers, including one open-weight (`--models`, `openai-compat:<name>` for open-weight)

Each cell repeats across independent runs; report medians with bootstrap CIs, paired comparisons with McNemar plus effect sizes. All of this is implemented in `eval/experiment.py` and `eval/report.py`.

## Research objectives
- **RO1 Attribute the agentic gain**: factorial ablation (C0-C4 x models). `eval/report.py` ablation table + McNemar.
- **RO2 Characterize validation**: evidence items (a) path with quoted steps, (b) sanitizer adequacy, (c) path-condition satisfiability, (d) concrete input. `--evidence-sweep`, RO2 table, surviving-FP list.
- **RO3 Cost-quality frontier**: tokens, time, dollars per TP per config and model. Logged per unit in every run record.
- **RO4 External and construct validity**: real OSS projects + SecLLMHolmes-style edits. NOT BUILT YET.

## Evaluation
- **Benchmarks**: NIST Juliet (built, stratified loader) and CWE-Bench-Java (NOT BUILT YET). Report separately, never averaged.
- **Baselines**: semgrep tool-only (built), model-only C0 (built), CodeQL and Trail of Bits skills via SARIF (plumbing exists in `sarif.py`, not run yet).
- **Metrics**: precision, recall, FDR, localization, tokens, dollars, wall time.
- **Scoring**: `function` mode reconciles function-level (bad vs good side) and `line` mode is path-level localization.
- Dataset discipline (PrimeVul, LessLeak-Bench) applies to the real-CVE benchmark when it's added.

## Current state (as of 2026-10-13)

Built and tested offline (`pytest`, 56 tests, scripted fake model; no API calls):
- Factor toggles and presets C0-C4 (`auditor/config.py`), `--factorial` for the full grid.
- Explore loop and fixed-context mode with matched context budgets (`auditor/agent.py`, `auditor/units.py`).
- Evidence-stage validator with mechanical quote checking (`auditor/validate.py`).
- Anthropic + OpenAI-compatible backends (`auditor/llm.py`), dollar pricing (`auditor/pricing.py`).
- Resumable experiment runner, report with CIs / McNemar / RO2 / RO3.
- Juliet loader, stratified by CWE and cross-function, seeded.

Verified on real Juliet Java (not with a live model): all 3,972 manifest flaw lines for CWE 78/89/23/36 land in bad-side functions; a simulated full C0-C4 run on an 80-case slice goes end to end; semgrep baseline on that slice: recall 0.36 / precision 0.58 with `auto`.

Bugs fixed while building this (the old results in `exhaustive.json` predate these):
- Old testcase scoring could not see false positives on Juliet's good-side twins.
- Semgrep skipped gitignored dirs, so the baseline on any `benchmarks/juliet_slice*` scanned 0 files.
- `--cwes 22` selected nothing (Juliet Java uses CWE-23/36 for path traversal).
- The `_81` test-case family was split into 3 or 4 fake cases.
- Semgrep command-injection hits were classed "other" (CWE tags live on the rule, not the result).
- grep's no-ripgrep fallback missed every top-level file.
- Toy label pointed at line 11 of a 10-line file.
- Fixed-context mode packed unrelated same-directory files (other Juliet cases); now only files linked by name.
- Cross-file Juliet cases were labelled at the source line, so localization penalized reporting the real sink.
- No threat model in the prompts: models decided env vars / config / console / DB were trusted and dropped real Juliet bugs. Now explicit (`threat_model`, prompt v4).
- The validator saw only +-60 lines around the sink, so it couldn't see the source on split cases. Now it gets the whole unit.

Next:
1. Live smoke runs passed on Kali (Opus, 4 units, no refusals, no errors). Current slice: `benchmarks/juliet_slice_s0`.
   Pilot v3 (Haiku + Sonnet, 1 run): Haiku C3 recall 0.725, validator dropped 19 real bugs, "exploration hurts" C1 to C3 p=0.013.
   Pilot v4 (explicit threat model + whole-unit validator): Haiku 0.89-0.95 in every cell, Sonnet 1.00 everywhere, validator drops 1 TP, FP rate 0 for every LLM cell. The exploration effect vanished (p=0.75): it was an artifact of the unstated threat model. Methodology point for the thesis.
   Conclusion: with controls fixed, Juliet saturates for current models, so it can't separate the components. Report that, then get the RO1/RO2 effects from CWE-Bench-Java.
   Edge case worth discussing: Runtime.exec(String) uses no shell, so Juliet's "/bin/ls " + data is argument injection rather than full command injection.
   Juliet Haiku v4, 3 runs, evidence sweep (results/juliet-haiku-v4 on Kali): C0-C4 recall 0.900-0.925, CIs overlap, best McNemar 4 vs 1 (p=0.375), FP 0 everywhere vs semgrep 21 FPs.
   Threat-model wording moved recall ~18 points (v3 0.725 to v4 0.90+); no scaffolding component moved it more than ~4. Candidate headline.
   Validator removed 0 FPs (none exist) and lost 0-3 TP cases per variant. ~90% of its rejections are Runtime.exec(String) no-shell arguments: right for the /bin/ls branch, wrong for Juliet's Windows cmd.exe /c branch (platform-branch reasoning failure, RO2).
   CONFIRMED Juliet ground-truth flaw: every database-source file in the slice (6 of 6) calls resultSet.getString(1) right after executeQuery() with no resultSet.next(). Per JDBC the cursor starts before the first row, so getString throws SQLException and the tainted value never reaches the sink at runtime. The validator caught this on its own.
   Tentative: plain verdict rejected the most TPs; structured evidence fewer. Re-check on CWE-Bench-Java.
   CWE-Bench-Java v1, 40 CVEs (seed 0, 10 per CWE 22/78/79/94, max 300 files), Haiku, 1 run, results/cbj-v1-n10-haiku* on Kali:
   - Precise stance (prompt v4): C0 recall 0.371 ($0.84/TP), C2 0.257 ($0.44/TP), C0 vs C2 p=0.22. Semgrep 0.057.
   - Screen stance (prompt v5, --stance screen), C2: recall 0.526, file recall 0.553, $0.27/TP, but 43 alerts/project (vs 7.7).
     On the 34 CVEs both runs could reach: precise 9, screen 18, discordant 9 vs 0 (exact McNemar p~0.004).
     The 2 other extra catches came from the pre-filter fix. Reporting stance moved recall more than any scaffolding component. Candidate headline with the threat-model result.
   - Label path bug fixed (fix-commit path missing at the vulnerable commit, e.g. Dubbo com.alibaba -> org.apache): benchmarks/fix_label_paths.py.
   - Pre-filter reaches 37/40 CVEs. Unreachable: CVE-2018-1260 (label points at a token-header method, likely label noise), CVE-2022-20617 and CVE-2023-37582 (sink is elsewhere, no keyword can catch it).
   - Next: Opus verifier over the screen run's flags (Haiku -> Opus cascade). ~1600 flags, too costly on the $50/month budget; needs LSU plan or a cheaper triage stage.
2. Pin a semgrep ruleset for thesis runs.
3. CWE-Bench-Java loader (next build) and an open-weight model setup.
4. RO4 edits and real-repo runs.

## Working notes for Claude
- Venv: `venv/Scripts/python` (Windows). Juliet Java is extracted at `~/juliet-java/Java`.
- Run `venv/Scripts/python -m pytest` after changes. Use `--dry-run` before any paid run.
- Bump `PROMPT_VERSION` in `auditor/prompts.py` whenever a prompt changes.
