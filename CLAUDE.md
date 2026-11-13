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
   - Cascade (Haiku screen -> Claude verifier, all evidence items, Message Batches). The LSU token program turned out to be Codex only (no API key), so this was paid out of pocket.
     Pilot, same 50 flags (25 on labelled bugs): Sonnet 5.5 kept 22/25 real-bug flags, rejected 21/25 off-target, $0.49; Opus 5.5 kept 22/25, rejected 19/25, $1.26; they agree on 44/50. Sonnet chosen.
     Full run, Sonnet over all 1,633 flags ($15.55, ~8 min as a batch): recall 0.526 -> 0.474 (20 -> 18 CVEs, CIs overlap), alerts/project 43.0 -> 13.6, off-target 1,581 -> 468, $1.17/TP all in ($20.98 total). Lost CVE-2020-5405 and CVE-2022-28367 (reasons in the report's "CVEs the validator lost" table).
     Vs precise C2 (0.257, 7.7 alerts/project): ~1.8x the recall at ~1.8x the alerts. Rejections: verdict 1,114, poc 1,108, conditions 448, sanitizer 108, path 26, refusal 1. Demanding a concrete input is nearly as strong a filter as the verdict itself (RO2).
     Surviving off-target alerts aren't known FPs; they're also the zero-day candidate pool, but the projects are at old vulnerable commits, so check against current releases first.
     The 2 lost CVEs, by hand (verify both against NVD before citing):
     - CVE-2022-28367 (AntiSamy, XSS by tag smuggling in STYLE content; the serializer doesn't encode CSS output): real verifier miss. Sonnet rejected it because the CSS is "re-emitted only as parsed, policy-validated CSS", i.e. it trusted the exact component the CVE is in. Failure mode for RO2: when the audited code IS the sanitizer, the verifier assumes it works (failed the sanitizer check).
     - CVE-2020-5405 (Spring Cloud Config, traversal in the config server): likely label noise. Haiku's hit is in the client (ConfigServicePropertySourceLocator), a method the fix commit also touched, and Sonnet's reason (client config is trusted, not the attack surface) holds up. CWE-Bench-Java labels every fixed method as the bug, not just the vulnerable sink.
     So the strict count is 18/38; label-adjusted it's 19/38 vs 20/38 raw. Don't patch the prompt for the AntiSamy case and report on the same CVEs; test any fix on the held-out set.
   - Next: held-out run. CWE-Bench-Java v1 has only 113 scorable CVEs (CWE-22 53, CWE-78 12, CWE-79 28, CWE-94 20), so 25 per CWE is impossible. Instead run every scorable CVE not in the 40 above (`--per-cwe 0 --exclude <v1_s0_n10_m300 labels.json>`): 73 before the 300-file cap (22: 43, 79: 18, 94: 10, 78: 2). The prompts and pre-filter keywords were tuned looking at the 40, so the held-out set is the honest number; report it separately, and only pool with the 40 as a labelled dev+test total. CWE-78 has 2 held-out CVEs, so no per-CWE claim for cmdi.
     Same pipeline as above: Haiku screen (C2, --stance screen), then Sonnet verifier with all evidence items via --batch. Estimate at the 40-CVE rates: ~$9 screen + ~$27 verify for ~65 CVEs. Also rerun prefilter_check on it to see if the keyword list generalizes.
   - Held-out run done (benchmarks/cwe_bench_java/v1_s0_n0_heldout_m300, results/cbj-v1-heldout-haiku-screen on Kali, $24.91). 40 CVEs fetched (33 over the file cap; CWE-78 has 0 left), 39 scored.
     - Pre-filter: 38/40 (dev 37/40), keywords not touched. Misses: CVE-2021-29425 (commons-io, labels are test files only, label noise) and CVE-2022-24897 (xwiki Velocity allow-list, no file/path code to match).
     - Haiku screen: recall 0.513 [0.359, 0.667] (20/39), file recall 0.692, 50.4 alerts/project, $0.33/TP. Replicates dev (0.526). Semgrep 0 TP of 449 findings.
     - Sonnet verifier: recall 0.282 (11/39), 12.3 alerts/project, lost 9 CVEs (dev lost 2). Does NOT replicate.
     - LEAK FOUND: the verifier saw repo-relative paths, and project folders are named <owner>__<repo>_<CVE>_<version>, so every verifier prompt carried the CVE id. The screen agent was confined to the project root and never saw it. 4 of the 9 losses cite the CVE in the reason ("the real CVE-2016-9177 traversal was in the static-file handler"), i.e. the verifier used memorized CVE knowledge to reject flags on methods the fix commit touched. The dev-set verifier had the same leak. Fixed: scope_to_root() in auditor/validate.py. Both verifier runs (dev and held-out) have to be redone; the screens stand.
     - Leak-free rerun (git 2cd4ab4, $17.50): recall 0.256 [0.128, 0.410] (10/39), 8.5 alerts/project, off-target 311, lost 10 CVEs (exact McNemar 10 vs 0, p~0.002). No reason cites a CVE any more, but the outcome barely moved (leaked 11/39, clean 10/39). So the leak changed the verifier's stated reasons, not its recall; the losses are its own reasoning. The leaked verifier was looser overall (457 vs 311 off-target kept). A second leaked pass is saved as leaked2-val-*.json (same flags, for run-to-run noise). The dev-set verifier (0.474) is still the leaked number; rerun it clean before citing (~$15.50).
     - Lost CVEs, clean run: the 9 above plus ESAPI CVE-2022-23457, where Sonnet named the actual bug (startsWith without a separator boundary) and rejected it because the method "only validates" and does no file access. 5 of 10 are sanitizer/validator libraries (ESAPI, AntiSamy x2, Spring Cloud Config's '..' check, xwiki's sanitizer). Most of the rest are library/framework code (Spark, Undertow, RocketMQ, JSPWiki tags) where the attacker is the caller of a public API and no request source is visible. Dev lost 2 of 20 because it's mostly app code. Candidate RO2 headline: the verifier works on app code and fails on library code, where the vulnerable code is the defense or the source is the API caller. The threat model never says public API arguments are attacker-controlled; a prompt fix for that was found by looking at held-out losses, so it can't be scored on the held-out set.
     - Other loss reasons, as of the leaked run: sanitizer-is-the-target (AntiSamy CVE-2016-10006 and CVE-2022-29577, Spring Cloud Config CVE-2020-5410 encoded '..' check, xwiki CVE-2023-31126 find() vs matches()); the verifier trusts the check the CVE bypasses, same as CVE-2022-28367 on dev. And missing context: the verifier sees only the flagged file, so cross-file sources read as "not shown" (JSPWiki CVE-2019-10076, Undertow CVE-2014-7816). The screen can explore; the verifier can't. Verify the CVE details against NVD before citing.
   - Hunt mode (`hunt.py`, `auditor/hunt.py`) for real bugs, no labels: screen (Sonnet by default, explore, screen stance) -> triage every flag with a score (never drops) -> agentic deep dive with repo tools on the top N (Opus by default, `--deep-model claude-fable-5-1` for the strongest). Writes `<out>/report.md` ranked, with path, input, and repro steps. Uses its own threat model (HUNT_THREAT: public API callers are attackers, defenses are targets), written after reading the held-out losses, so it is for hunting only, never benchmark numbers. Not yet measured: the cheap calibration is to hunt a few held-out CVE projects at their vulnerable commits and check whether the real bug lands in the top 15.
   - Hunt calibration, 5 held-out CVEs the old Sonnet verifier lost (Sonnet screen, Sonnet triage, Opus deep dive, $18.35 total, `eval/hunt_check.py`):
     | CVE | flags | on bug method | first rank | triage | deep verdict | $ |
     | ESAPI CVE-2022-23457 | 35 | 1 | 1 | 0.12 | confirmed 0.85 | 6.65 |
     | Spark CVE-2016-9177 | 12 | 3 | 1 | 0.30 | confirmed 0.85 | 2.99 |
     | Spring Cloud Config CVE-2020-5410 | 11 | 1 | 10 | 0.20 | false_positive 0.05 | 2.80 |
     | AntiSamy CVE-2016-10006 | 12 | 0 | - | - | - | 2.69 |
     | AntiSamy CVE-2022-29577 | 13 | 0 | - | - | - | 3.22 |
     Screen hit the bug's method in 3/5, deep dive confirmed 2/5, both at rank 1. The old cascade kept 0 of these 5.
     - ESAPI: triage gave 0.12, under the old 0.2 floor, and the deep dive confirmed it. Direct evidence that triage must rank, not gate.
     - Spring Cloud Config: the deep dive trusted the '..' check the CVE bypasses (sanitizer trust again). Earlier note corrected: on CVE-2022-29577 the labelled method (processStyleTag) was never flagged; a CssScanner flag only reached it as the entry point, and Opus called that path safe.
     - Both AntiSamy misses are screen misses. Haiku's screen flagged all 5 bug methods, but these 5 were picked because Haiku caught them, so that comparison is biased by selection.
     - BIG CAVEAT: HUNT_THREAT was written after reading these exact losses, and the CVEs are public (memorization possible). This is in-sample: it shows the pipeline works and where it still fails, NOT a generalization number. A real measurement needs CVEs not used to write the prompt, ideally ones after the models' training cutoff.
   - Two confirmed novel hunt findings from this session are kept in hunt-findings.local.md (gitignored), pending coordinated disclosure; they are deliberately not in this tracked file. Loop in Andrew before any disclosure.
   - Compute: LSU has no API access (Prof. Golden, 2026-11-05: the OpenAI teams account has no API). He suggested a local high-end model. Asked him for GPU time (80GB A100/H100, department server or LSU HPC) on 2026-11-09. Plan: serve an open-weight model with vLLM (tool calling on, 64k+ context) and run it as `openai-compat:<model>`; that also fills the open-weight tier of the model factor. Claude runs stay paid out of pocket.
   - Agent upgrade (2026-11-12): `hunt.py --since <ref>` scopes a hunt to files changed since a git ref (tag, commit, branch), so you can chase a post-release regression instead of re-screening the whole repo. It diffs the ref against the working tree and also pulls in still-untracked files; renames land at the new path, deletions drop out. Only changes which files enter the pipeline, the screen/triage/deep treatment and scoring are identical, and the ref is recorded in the run config and meta.json. Hunt-only on purpose, not an eval factor: the benchmarks aren't git-diffable, so a diff factor would fire unevenly across them and break "test everything the same". New `Workspace.changed_files()`; 4 offline tests in tests/test_hunt.py, 109 green.
   - Execution oracle (2026-11-12): opt-in `execute` evidence item for the validator (RO2). It takes the finding's PoC plus a pluggable execution runner and gets the last word: a PoC that triggers confirms the finding over a skeptical model, one that runs but doesn't refutes it, abstain (can't build/run) falls back to the model verdict. That abstain=fallback rule is the uniformity guarantee: on code that won't build in place (most of CWE-Bench-Java) requiring execute is a provable no-op, exactly equal to not requiring it, so it can't skew a paired comparison. Kept out of EVIDENCE/ALL_EVIDENCE and the prompt, so C0-C4, the evidence sweep, and the prompt fingerprint (still fdbd286dd3d7) are byte-identical; request it only by name, e.g. `--evidence path+execute`. Runner defaults to abstain, so the item is inert until a real runner is passed in, and a crashing runner can only abstain. NEXT (deferred): the real runner is a sandboxed Kali/container job because it executes model-generated PoCs, with a per-bug-class oracle (sentinel file for cmdi, out-of-root read for path traversal, headless-DOM onerror for XSS), then wire it into experiment.py/validate_batch. 6 offline tests in tests/test_eval.py, 115 green.
2. Pin a semgrep ruleset for thesis runs.
3. CWE-Bench-Java loader (next build) and an open-weight model setup.
4. RO4 edits and real-repo runs.

## Working notes for Claude
- Venv: `venv/Scripts/python` (Windows). Juliet Java is extracted at `~/juliet-java/Java`.
- Run `venv/Scripts/python -m pytest` after changes. Use `--dry-run` before any paid run.
- Bump `PROMPT_VERSION` in `auditor/prompts.py` whenever a prompt changes.
