# Architecture: LLM Code-Auditing Agent

A one-page reference for the system, based on the design of RepoAudit
(Guo et al., ICML 2025, arXiv:2501.18160) and IRIS (Li et al., ICLR 2025,
arXiv:2405.17238), adapted to a masters-scope build.

## The reference design (RepoAudit)

RepoAudit is a multi-agent, neuro-symbolic framework. The parts that matter:

1. **MetaScanAgent** parses the repo with tree-sitter (compilation-free) to get
   the syntactic map: functions, call graph, where things are defined.
2. **DFBScanAgent** does inter-procedural data-flow analysis on demand. It walks
   data-flow facts along feasible paths inside functions, following a source
   (where untrusted data enters) toward a sink (where it is dangerously used).
   Agent memory lets it explore only what it needs instead of loading the whole
   repo, which is what keeps token cost bounded on large projects.
3. **Validator module** re-checks each candidate: it verifies the data-flow
   facts and tests whether the path conditions are actually satisfiable. This is
   the main false-positive killer. It is why RepoAudit reports ~78% precision
   where naive file-by-file LLM auditing does far worse.

Key properties: compilation-free, multi-lingual (C/C++, Java, Python, Go), and
LLM output is treated as a *hypothesis* that a cheaper symbolic check confirms,
not as a final answer.

## How this scaffold maps to it

This repo is a slimmed masters-scope version of that pattern:

| RepoAudit concept        | Here                                             |
|--------------------------|--------------------------------------------------|
| MetaScan / on-demand nav | `tools.py` (list_dir, grep, read_file)           |
| Independent symbolic sig | `tools.py::run_semgrep` (swap in CodeQL later)   |
| Explore -> hypothesize   | `agent.py` tool-use loop + `prompts.py` system   |
| Validator module         | `agent.py::_validate` + `prompts.py` VALIDATOR   |
| Common output format     | `sarif.py` (normalize any tool's SARIF)          |
| Strong baseline          | `baseline.py` (semgrep now, ToB skills later)    |
| Reproducible scoring     | `eval/metrics.py`, `run_benchmark.py`, `experiment.py` |

The agent explores through tools instead of being handed the whole codebase.
It forms source->sink hypotheses, corroborates with semgrep, then a second
independent validation pass drops anything it cannot confirm.

## Where the actual research lives

The system is plumbing. The contribution your advisor wants is the measured
iteration on it:

- **Prompt / loop iteration** (`prompts.py`): each change scored on the same
  benchmark for precision, false-positive rate, and token cost. Keep every
  version so numbers are reproducible.
- **Validator ablation**: run the benchmark with `--no-validate` vs with it.
  The delta in false-positive rate is a clean, defensible result.
- **Cost/latency tuning**: tokens and turns per project are logged in
  `AuditResult`. Show you cut cost without losing recall.
- **Real bugs**: point it at real open-source projects and triage what it finds.
  Even one confirmed, reproducible bug (reported and acknowledged upstream) is a
  strong masters result and mirrors how RepoAudit validated.

## Baseline: Trail of Bits skills

Trail of Bits publishes a Claude Code skills marketplace (github.com/trailofbits/skills)
that already implements the agent-plus-tools auditing pattern professionally.
Two skills overlap directly with this build: `static-analysis` (CodeQL + Semgrep
+ SARIF) and `fp-check` (systematic false-positive verification with gate
reviews, which is their version of the validator pass here).

This matters for the research framing. Since ToB ships the plumbing, "I built an
auditing agent" is not by itself a contribution. The contribution is the rigorous
evaluation they do NOT publish: precision / recall / FP-rate / token-cost across
public benchmarks, with the ToB skills (and plain semgrep) as the baseline you
measure against. `baseline.py` + `sarif.py` exist so a ToB skill, run via Claude
Code to emit SARIF, drops into the same scoring harness as your agent. Beating a
strong, real baseline on the same ground truth is far more defensible than
comparing against nothing.

Note on toy-benchmark results: semgrep with pinned local rules catches the
command-injection bug but misses the SQL-injection whose two-line shape does not
match the rule (precision 1.0, recall 0.5). That recall gap is the whole point:
static analysis is precise but brittle, and the agent's job is to raise recall
while the validator holds precision. That gap is what your numbers should show
the agent closing.

## Adapted from Trail of Bits skills

Three ideas from github.com/trailofbits/skills are adapted here to improve
real-world bug finding (all optional, all ablatable in `experiment.py`):

- **Context-building phase** (`context.py`, from `audit-context-building`): a
  pre-pass that maps entry points, trust boundaries, sinks, persistent state, and
  the highest-weight functions, then injects that map into the hunt. On real
  repos this is what lets the agent follow input across functions instead of
  guessing locally. Enable with `--context`.
- **PoC-demanding validator** (`prompts.py::VALIDATOR_PROMPT`, from `fp-check`):
  the validator now works in phases (claim, data flow, exploitability, negative
  check) and confirms a finding ONLY if it can sketch a concrete proof-of-concept
  that survives a negative check. This is a much stronger false-positive filter
  than a yes/no on messy code.
- **Variant hunting** (`variant.py`, from `variant-analysis`): after a finding is
  confirmed, derive its sink pattern, grep the repo for siblings, and re-audit
  those locations. One real bug usually has cousins, so this multiplies findings.
  Enable with `--variants`.

Note on security hygiene (from Snyk's review of the skills ecosystem): treat any
third-party skill as untrusted code and read its SKILL.md before running it. Here
we reimplement the *ideas* in your own instrumented code, so nothing external is
executed.

## Evaluation targets (public, reproducible)

- **NIST Juliet** — labelled good/bad pairs; ideal for precision and FP rate.
- **CWE-Bench-Java** — github.com/iris-sast/cwe-bench-java; real projects, one
  CVE each, what IRIS used.
- **Real OSS repos** — the "find a few new bugs" bar; validation by upstream.

## Suggested build order

1. Get the agent loop running on the toy benchmark (`benchmarks/toy`).
2. Establish the semgrep baseline (`eval/experiment.py`, config `baseline`).
3. Run the full experiment table (baseline vs agent vs agent+validator) so you
   can see the deltas before tuning anything.
4. Iterate the prompt with numbers in hand; log every run and keep old versions.
5. Add ToB `static-analysis` / `fp-check` as a second baseline via Claude Code
   (emit SARIF -> `sarif.py`).
6. Scale to Juliet / CWE-Bench-Java, then a real repo, and try to surface a
   confirmed new bug worth reporting upstream.

## Key references

- Trail of Bits skills: github.com/trailofbits/skills (baseline + prior art)
- RepoAudit: arXiv:2501.18160 (code: github.com/PurCL/RepoAudit)
- IRIS: arXiv:2405.17238 (benchmark: github.com/iris-sast/cwe-bench-java)
- REVELIO / FuzzingBrain / VulnLLM-R: recent work on confirming LLM findings by
  execution rather than static reasoning alone. The direction to cite if you
  extend toward runtime confirmation.
