"""
Prompts for the code-auditing agent.

Prompt structure is held constant across cells: every cell gets the same CORE
(role, scope, reporting bar, output format). Only the section describing HOW
context arrives changes, because fixed-context cells have no tools to describe.
Any edit here changes every number, so bump PROMPT_VERSION when you touch it;
it's written into every run record.
"""
from __future__ import annotations
import hashlib

from .config import EVIDENCE

PROMPT_VERSION = "v5"   # v5: stance switch; "precise" text is unchanged from v4

BUG_CLASSES = {
    "sqli": "SQL injection: untrusted input reaching a SQL query without parameterization.",
    "cmdi": "OS command injection: untrusted input reaching a shell/exec call.",
    "path": "Path traversal: untrusted input reaching a filesystem path.",
    "npd": "Null pointer dereference: a null/None value reaching a dereference on a feasible path.",
    "uaf": "Use-after-free: memory used after it has been freed.",
    "xss": "Cross-site scripting: untrusted input written into an HTML/JS response "
           "without context-appropriate encoding.",
    "codei": "Code injection: untrusted input evaluated as code, e.g. by a script "
             "engine, expression language (EL/OGNL/SpEL/MVEL), template engine, or "
             "dynamic class loading.",
}

EXHAUSTIVE_SCOPE = (
    "You are hunting for ANY security vulnerability, drawing on your full "
    "knowledge of software security. Do not limit yourself to a fixed list. "
    "Consider at least: injection (SQL, OS command, LDAP, XPath, template, "
    "expression-language), path traversal, SSRF, XXE, insecure "
    "deserialization, unsafe reflection, authentication and authorization "
    "flaws (missing checks, IDOR, broken access control), cryptographic "
    "misuse (weak algorithms, hardcoded keys, bad randomness, missing "
    "verification), memory-safety bugs in native code (buffer overflow, "
    "use-after-free, OOB access, integer overflow leading to one), race "
    "conditions and TOCTOU, SSTI and XSS, open redirect, unsafe file "
    "upload, secrets in source, logic flaws that break a security "
    "invariant, and any other class you can justify from the code. "
    "If you spot something that does not fit a known class but is clearly "
    "a security problem, report it with the closest CWE and explain it.")


# The threat model is stated in every prompt, hunter and validator alike. Without
# it each model guesses who the attacker is (pilot run: Haiku and Sonnet called
# env vars, config files, console, and DB rows "operator-controlled" and rejected
# real Juliet bugs), which makes the threat model an uncontrolled variable.
THREAT_MODELS = {
    "all-external": (
        "Threat model: treat EVERY value that enters the program from outside its "
        "own code as attacker-controlled. That includes network input, HTTP "
        "parameters, headers and cookies, environment variables, JVM system "
        "properties, configuration and properties files, any file contents, "
        "console input, command-line arguments, and values read from databases "
        "or remote services. Only constants written in the source are trusted. "
        "Do not dismiss a flow because exploiting it would need local access, a "
        "compromised server, or control of the deployment."),
    "remote": (
        "Threat model: the attacker is a remote, unauthenticated user. Treat "
        "network input, HTTP parameters, headers, cookies, uploaded files, and "
        "data that such a user can cause to be stored (for example DB rows they "
        "write) as attacker-controlled. Treat environment variables, deployment "
        "configuration, and the local console as trusted unless the code shows a "
        "remote user can influence them."),
}


def threat_text(threat_model: str) -> str:
    if threat_model not in THREAT_MODELS:
        raise ValueError(f"unknown threat model {threat_model!r}; "
                         f"known: {list(THREAT_MODELS)}")
    return THREAT_MODELS[threat_model]


def is_exhaustive(bug_classes) -> bool:
    return (not bug_classes) or any(b in ("all", "*", "any") for b in bug_classes)


def _scope(bug_classes) -> str:
    if is_exhaustive(bug_classes):
        return EXHAUSTIVE_SCOPE
    selected = "\n".join(f"- {k}: {BUG_CLASSES[k]}" for k in bug_classes
                         if k in BUG_CLASSES)
    return f"You are hunting for these bug classes:\n{selected}"


CORE = """You are a security code auditor. You follow data from where it enters \
the program (a source) to where it is dangerously used (a sink), and you only \
report a bug when you can trace a concrete, feasible path from source to sink.

{scope}

{threat}

Reasoning rules:
- A dangerous-looking call is a lead, not a bug. Check that the input really is
  attacker-controlled and that nothing on the path neutralizes it.
- Think about what the code is trying to guarantee (an auth check, a bound, an
  invariant) and whether an input can break that guarantee. Consider non-obvious
  sources (config, headers, environment, deserialized objects, filenames, DB rows
  written by another path) and sinks reached through helpers in other functions.
- Code that looks almost identical to a vulnerable path but uses a constant,
  validates, or parameterizes is NOT vulnerable. Do not report it.

{stance}

When done, call report_findings exactly once with your final list. Each finding \
needs: bug_class, file (repo-relative), line (the line of the dangerous SINK), a \
one-sentence data-flow path (source -> ... -> sink), a CWE id, a severity, and a \
confidence in [0,1]. {closing}"""

# How hard to lean toward reporting. "precise" is a standalone auditor; "screen"
# is the cheap first stage of a cascade, where a stronger verifier checks every
# finding, so a missed bug costs far more than a false alarm.
STANCES = {
    "precise": ("Precision matters more than recall. A false positive is worse than "
                "a missed bug.", "Report an empty list if nothing is solid."),
    "screen": ("This is a SCREENING pass. A stronger reviewer will verify every "
               "finding you report, so recall matters more than precision: a missed "
               "bug is far worse than a false alarm. Report every sink where "
               "attacker-influenced data plausibly arrives, even if you cannot see the "
               "whole path or are unsure a sanitizer is enough; say what is unverified "
               "in the path and express doubt with a low confidence instead of leaving "
               "it out. Still skip sinks fed only by constants.",
               "Report an empty list only if no sink in the target could plausibly "
               "receive attacker-influenced data."),
}

EXPLORE_MODE = """How context reaches you:
You start with the target code below and can explore the rest of the repository \
on demand with list_dir, read_file and grep: follow callers and callees, open \
sanitizer and helper definitions, check where a value really comes from. You \
have a budget of about {budget} tokens of code you can read; tool output past \
that is refused, so read what matters first.{sa}"""

EXPLORE_SA = """
You can also call run_semgrep for an independent static-analysis signal. Treat \
its hits as leads to verify, not as findings."""

FIXED_MODE = """How context reaches you:
All the code you get is included below. You cannot request more, so reason \
from what is shown.{sa}"""

FIXED_SA = """
Semgrep static-analysis results for this code are included below. Treat its \
hits as leads to verify, not as findings."""


def system_prompt(bug_classes, explore: bool = True, static_analysis: bool = True,
                  budget: int = 24000, threat_model: str = "all-external",
                  stance: str = "precise") -> str:
    if stance not in STANCES:
        raise ValueError(f"unknown stance {stance!r}; known: {list(STANCES)}")
    stance_text, closing = STANCES[stance]
    if explore:
        mode = EXPLORE_MODE.format(budget=budget, sa=EXPLORE_SA if static_analysis else "")
    else:
        mode = FIXED_MODE.format(sa=FIXED_SA if static_analysis else "")
    return (CORE.format(scope=_scope(bug_classes), threat=threat_text(threat_model),
                        stance=stance_text, closing=closing)
            + "\n\n" + mode)


def unit_task(target_files: list[str], explore: bool) -> str:
    targets = ", ".join(target_files) if target_files else "the whole repository"
    if explore:
        return (f"Audit target: {targets}.\nReport findings whose sink is in the "
                "target. You may read anything else in the repo for context.")
    return f"Audit target: {targets}.\nReport findings whose sink is in the target."


# ---------------------------------------------------------------- validator

VALIDATOR_HEAD = """You are a skeptical reviewer checking ONE candidate \
vulnerability reported by another auditor. Assume it is a false positive until \
the evidence forces you to conclude otherwise.

{threat}

Candidate finding:
{finding}

Code (the finding's file first, then the rest of its audit unit):
{code}
"""

EVIDENCE_INSTRUCTIONS = {
    "path": (
        "path_steps",
        '"path_steps": [{"file": "<path>", "line": <int>, "quote": "<exact code '
        'copied from that line>"}, ...]',
        "Reconstruct the data-flow path from source to sink, one step per "
        "statement. Each quote must be copied exactly from the code shown, on the "
        "line you give. Quotes are checked mechanically against the file."),
    "sanitizer": (
        "sanitizer",
        '"sanitizers": ["<each sanitizer, validator, or encoding on the path>"], '
        '"sanitizer_adequate": true | false | null',
        "List every sanitizer, validation, type conversion, or encoding the value "
        "passes through. sanitizer_adequate is true if one of them fully "
        "neutralizes the attack for this bug class, false if they exist but are "
        "inadequate, null if there are none."),
    "conditions": (
        "conditions",
        '"path_conditions": ["<each branch condition that must hold>"], '
        '"conditions_satisfiable": true | false',
        "List every branch condition that must hold for execution to reach the "
        "sink with tainted data, then decide whether they can all hold at once "
        "(watch for constant conditions and dead branches)."),
    "poc": (
        "poc",
        '"poc": "<one concrete attacker input that drives the path, or empty>"',
        "Give one concrete attacker-controlled input value that traverses the "
        "path and triggers the bug. Leave it empty if you cannot build one."),
}


def validator_prompt(finding_json: str, code: str, evidence: tuple[str, ...],
                     threat_model: str = "all-external") -> str:
    head = VALIDATOR_HEAD.format(finding=finding_json, code=code,
                                 threat=threat_text(threat_model))
    fields = ['"verdict": "confirmed" | "rejected"']
    steps = []
    for item in evidence:
        _, field, instr = EVIDENCE_INSTRUCTIONS[item]
        fields.append(field)
        steps.append(f"- {instr}")
    fields += ['"reason": "<one sentence>"', '"adjusted_confidence": <float 0..1>']
    body = ""
    if steps:
        body = "Required evidence (a finding without it is rejected):\n" + "\n".join(steps) + "\n\n"
    return (head + "\n" + body +
            "Confirm ONLY if the input is genuinely attacker-controlled, reaches the "
            "sink on a feasible path without adequate sanitization, and the sink is "
            "genuinely dangerous for this bug class.\n\n"
            "Answer with one JSON object and nothing else:\n{" + ", ".join(fields) + "}")


# ---------------------------------------------------------------- extras

CONTEXT_PROMPT = """You are in the CONTEXT-BUILDING phase of a security audit, \
before any bug hunting. Do not report vulnerabilities yet. Build an accurate map \
of the system so the later hunt is grounded.

Explore with the tools and produce a compact model of:
1. Entry points: where external/untrusted input enters (HTTP handlers, CLI args,
   file/network reads, message queues, deserialization).
2. Actors and trust boundaries: who can reach what, and where trust changes.
3. Dangerous sinks present: SQL exec, shell/exec, filesystem, raw pointers, etc.
4. Persistent/shared state that flows between calls.
5. The highest-weight functions: those sitting on a path from an entry point to
   a sink. List them as file:function.

Be bottom-up and concrete. Where unsure, say so. When done, call report_context
once with the structured summary."""

VARIANT_PROMPT = """A confirmed vulnerability was found. Hunt for VARIANTS: the \
same bug class and pattern occurring elsewhere in this repository.

Confirmed finding:
{finding}

Candidate locations sharing the pattern (from grep):
{candidates}

For each candidate, read enough context to decide if it is the same class of bug
with attacker-controlled input reaching the sink. Report only the ones you can
stand behind, using report_findings. Do not re-report the original."""


def prompt_fingerprint() -> str:
    """Hash of every prompt template, saved with each run for reproducibility."""
    blob = "".join([CORE, EXPLORE_MODE, EXPLORE_SA, FIXED_MODE, FIXED_SA,
                    VALIDATOR_HEAD, repr(EVIDENCE_INSTRUCTIONS), repr(EVIDENCE),
                    repr(THREAT_MODELS), repr(STANCES)])
    return hashlib.sha256(blob.encode()).hexdigest()[:12]
