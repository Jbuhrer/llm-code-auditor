"""
Bug-hunting mode: point it at a real project, get a ranked list of leads.

No labels and no scoring. Three stages, each saved as it goes and skipped on a
rerun with the same --out, so nothing is paid for twice:

  screen   a model audits every relevant file with repo tools (explore mode,
           screen stance) and flags anything plausible
  triage   one call per flag scores how likely it is a real, reachable bug.
           It ranks; it never drops anything
  deep     the top flags get an agentic investigation by the strongest model:
           it can open any file in the repo, traces the input across files,
           tries to break the defenses on the path, and writes a concrete input
           plus the steps to confirm it on your own instance

Why rank instead of filter: on CWE-Bench-Java's held-out CVEs, a skeptical
single-file verifier threw away half the real bugs, mostly in libraries where
the vulnerable code is the defense itself or the attacker is the API caller.
The hunt threat model says both of those out loud, and the deep stage can read
other files. That threat text came from reading held-out losses, so it's for
hunting only, never for benchmark numbers.
"""
from __future__ import annotations
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from .agent import MAX_TOKENS, Auditor, FatalBackendError, is_fatal
from .budget import Budget
from .config import AuditConfig, ValidationConfig
from .llm import add_usage, empty_usage
from .pricing import cost_usd
from .prompts import threat_text
from .tools import EXPLORE_TOOLS, Workspace, dispatch
from .units import CHARS_PER_TOKEN, Unit, est_tokens
from .validate import check_path_steps, extract_json, validator_code

HUNT_VERSION = "h1"

HUNT_THREAT = (
    "Threat model: the attacker is anyone who can get data into this code from "
    "outside. For an application that means remote users: HTTP parameters, paths, "
    "headers, cookies, request bodies, uploaded files and their names, and data "
    "they can get stored and read back later. For a library or framework it also "
    "means whatever an application passes into its public API, because "
    "applications routinely hand user input to it: file names and paths, URLs, "
    "HTML and CSS, templates and expressions, XML, serialized data. Trust only "
    "constants in the source and settings that a deployer controls and no user "
    "plausibly influences. A sanitizer, validator, encoder, or canonicalizer in "
    "this code is a target, not a guarantee: check whether it can be bypassed "
    "(URL or double encoding, case, backslash vs slash, Unicode, null bytes, a "
    "prefix check like startsWith without a separator, find() where matches() "
    "was meant, a denylist that misses a variant, platform differences).")

TRIAGE_PROMPT = """You are triaging ONE candidate vulnerability for a security \
researcher hunting real bugs in an open-source project. Your job is to RANK, not \
to gatekeep: a human reads the top of the list, so an honest score matters more \
than a verdict. Do not dismiss a flag just because the source is in a file you \
can't see; say what you'd need to check and score accordingly.

{threat}

Candidate (from a fast screening model, may be wrong):
{finding}

Code (the flagged file first, then related code):
{code}

Decide who controls the input, whether it reaches the sink, whether any defense \
on the path holds or can be bypassed, and what an attacker gains.

Answer with one JSON object and nothing else:
{{"score": <0..1, probability this is a real, exploitable vulnerability>,
 "attacker": "<who controls the input: remote unauthenticated user | authenticated user | caller of a public API | admin or local only | nobody>",
 "path_steps": [{{"file": "<path>", "line": <int>, "quote": "<exact code from that line>"}}, ...],
 "defenses": "<checks or encodings on the path, and whether they hold>",
 "poc": "<a concrete attacker input, or empty>",
 "impact": "<what an attacker gets>",
 "needs": "<what you'd have to look at to be sure>",
 "reason": "<one or two sentences>"}}"""

DEEP_SYSTEM = """You are a senior vulnerability researcher checking one \
candidate bug in an open-source project, the way you would before reporting it \
to the maintainers. You can read the whole repository with list_dir, read_file \
and grep.

{threat}

How to work:
- Find where an attacker's data actually enters (an HTTP handler, a public API
  method, a file or message parser) and follow it to the sink across files.
  Open every helper, sanitizer, and caller that decides the outcome.
- Don't assume a check works because it exists, and don't assume a bug because a
  dangerous call exists. Try to break each defense on the path.
- Build one concrete attacker input and say how to deliver it.
- Say how to confirm it on a local instance (a VM or a container), never against
  someone else's server.
- You have about {budget} tokens of tool output; read what matters first.

When you're done, call report_verdict exactly once."""

DEEP_TASK = """Candidate (from a screening model, may be wrong):
{finding}

Triage notes from a second model (may also be wrong):
{triage}

The flagged file:
{code}

Investigate, then call report_verdict."""

VERDICT_TOOL = {
    "name": "report_verdict",
    "description": "Submit your conclusion about this candidate. Call exactly once.",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string",
                        "enum": ["confirmed", "likely", "unlikely", "false_positive"]},
            "score": {"type": "number",
                      "description": "0..1, probability it's a real exploitable bug"},
            "title": {"type": "string", "description": "one line, like an advisory title"},
            "cwe": {"type": "string"},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "none"]},
            "attacker": {"type": "string", "description": "who controls the input"},
            "entry_point": {"type": "string",
                            "description": "where attacker data enters (file:line or endpoint)"},
            "path_steps": {"type": "array", "items": {
                "type": "object",
                "properties": {"file": {"type": "string"}, "line": {"type": "integer"},
                               "quote": {"type": "string",
                                         "description": "exact code from that line"}},
                "required": ["file", "line", "quote"]}},
            "defenses": {"type": "string",
                         "description": "each check on the path and why it holds or fails"},
            "poc": {"type": "string", "description": "concrete attacker input"},
            "reproduce": {"type": "string",
                          "description": "steps to confirm on a local VM or container"},
            "impact": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["verdict", "score", "title", "reason"],
    },
}
DEEP_TOOLS = list(EXPLORE_TOOLS) + [VERDICT_TOOL]
READ_TOOLS = {t["name"] for t in EXPLORE_TOOLS}

# Rough per-call costs for the dry-run estimate, from the CWE-Bench-Java runs:
# a Haiku screen averaged ~$0.0012 per file and 0.37 flags per file, a Sonnet
# single-shot check ~$0.018 per flag. Deep dives are a guess (~45k in, 5k out
# on Opus). Scaled by input price for other models.
EST_SCREEN_PER_FILE = (0.0012, 0.10)     # ($, Haiku input price it was measured at)
EST_FLAGS_PER_FILE = 0.37
EST_TRIAGE_PER_FLAG = (0.018, 2.00)      # Sonnet
EST_DEEP_PER_FLAG = (0.28, 4.00)         # Opus


@dataclass
class HuntConfig:
    bug_classes: tuple[str, ...] = ("path", "cmdi", "xss", "codei", "sqli")
    screen_model: str = "claude-sonnet-5-5"
    triage_model: str = "claude-sonnet-5-5"
    deep_model: str = "claude-opus-5-5"
    deep_top: int = 15               # deep-dive this many of the best-scored flags
    min_score: float = 0.0           # triage ranks; deep_top alone caps cost, so by
                                     # default triage never vetoes a flag out of the dive
    screen_effort: str | None = "medium"
    triage_effort: str | None = "medium"
    deep_effort: str | None = "high"
    screen_budget: int = 32000       # tokens of code the screen can read per file
    screen_turns: int = 15
    deep_budget: int = 80000         # tokens of tool output per deep dive
    deep_turns: int = 30
    semgrep: bool = False
    prefilter: bool = True
    exts: tuple[str, ...] = (".java",)
    workers: int = 8

    def as_dict(self):
        return asdict(self)


@dataclass
class Store:
    """Append-only JSONL per stage under out/, so a rerun resumes."""
    out: Path
    lock: threading.Lock = field(default_factory=threading.Lock)

    def read(self, stage: str) -> list[dict]:
        p = self.out / f"{stage}.jsonl"
        if not p.exists():
            return []
        rows = []
        for line in p.read_text(encoding="utf-8").splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass   # a line cut off by a crash
        return rows

    def add(self, stage: str, row: dict) -> None:
        with self.lock:
            self.out.mkdir(parents=True, exist_ok=True)
            with open(self.out / f"{stage}.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(row, default=str) + "\n")


# ---------------------------------------------------------------- units

def hunt_units(ws: Workspace, classes, prefilter: bool = True,
               exts=(".java",)) -> tuple[list[Unit], dict]:
    """One unit per product source file. Tests, docs and samples are skipped;
    with prefilter, so are files that mention no API for the bug classes."""
    from .prefilter import is_non_product, is_test, keep
    units = []
    stats = {"files": 0, "tests": 0, "non_product": 0, "no_keyword": 0, "kept": 0}
    for f in ws.source_files(set(exts)):
        stats["files"] += 1
        if is_test(f):
            stats["tests"] += 1
        elif is_non_product(f):
            stats["non_product"] += 1
        elif prefilter and not keep("\n".join(ws.lines(f)), list(classes)):
            stats["no_keyword"] += 1
        else:
            stats["kept"] += 1
            units.append(Unit(f, [f]))
    return units, stats


def _scaled(est: tuple[float, float], model: str) -> float | None:
    p = cost_usd(model, {"input": 1_000_000})
    return None if p is None else est[0] * p / est[1]


def estimate(n_files: int, hc: HuntConfig) -> dict:
    """Ballpark dollars per stage, before anything is spent."""
    flags = round(n_files * EST_FLAGS_PER_FILE)
    deep = min(hc.deep_top, flags)
    parts = {"screen": _scaled(EST_SCREEN_PER_FILE, hc.screen_model),
             "triage": _scaled(EST_TRIAGE_PER_FLAG, hc.triage_model),
             "deep": _scaled(EST_DEEP_PER_FLAG, hc.deep_model)}
    n = {"screen": n_files, "triage": flags, "deep": deep}
    out = {k: (None if v is None else round(v * n[k], 2)) for k, v in parts.items()}
    out["flags"], out["deep_dives"] = flags, deep
    return out


# ---------------------------------------------------------------- stages

def screen_auditor(ws: Workspace, hc: HuntConfig, backend) -> Auditor:
    cfg = AuditConfig(exploration="explore", static_analysis=hc.semgrep,
                      model=hc.screen_model, context_budget=hc.screen_budget,
                      max_turns=hc.screen_turns, effort=hc.screen_effort,
                      threat_model="remote", unit="file",
                      bug_classes=tuple(hc.bug_classes), stance="screen")
    a = Auditor(ws, cfg, backend)
    base = threat_text("remote")
    assert base in a.system, "screen prompt layout changed; update hunt.screen_auditor"
    a.system = a.system.replace(base, HUNT_THREAT)
    return a


def run_screen(ws, units, hc, store: Store, budget: Budget, make, log) -> list[dict]:
    done = {r["unit"]: r for r in store.read("screen") if not r.get("error")}
    todo = [u for u in units if u.id not in done]
    log(f"screen: {len(units)} file(s), {len(done)} already done, "
        f"{len(todo)} to go with {hc.screen_model}")
    if todo and not budget.exceeded:
        auditor = screen_auditor(ws, hc, make(hc.screen_model, hc.screen_effort))

        def on_done(rec):
            store.add("screen", rec)
            budget.add(rec["cost_usd"])
            if not rec.get("error"):
                done[rec["unit"]] = rec
        auditor.run_units(todo, hc.workers, log, on_done, lambda: budget.exceeded)
    return [done[u.id] for u in units if u.id in done]


def flag_id(f: dict) -> str:
    return f"{f.get('file')}:{f.get('line')}:{f.get('bug_class')}"


def collect_flags(recs: list[dict]) -> list[dict]:
    """Every screen finding once, keyed by file, line and class."""
    out, seen = [], set()
    for r in recs:
        for f in r["findings"]:
            k = flag_id(f)
            if k not in seen:
                seen.add(k)
                out.append(dict(f, id=k))
    return out


def _clamp(x) -> float:
    try:
        return max(0.0, min(1.0, float(x)))
    except (TypeError, ValueError):
        return 0.0


def _quoted(ws, steps, file) -> float:
    """Fraction of quoted path steps that really appear in the repo. A ranked
    score is cut by up to half when the model's quotes don't check out."""
    return check_path_steps(ws, steps, file)[1]


def triage_one(backend, ws: Workspace, flag: dict, model: str) -> dict:
    rec = {"id": flag["id"], "score": 0.0, "raw_score": None, "quotes_verified": 0.0,
           "verdict": None, "usage": empty_usage(), "cost_usd": 0.0,
           "error": None, "refused": False}
    file = flag.get("file", "")
    try:
        line = int(flag.get("line", 1))
    except (TypeError, ValueError):
        line = 1
    code, _ = validator_code(ws, file, line, ValidationConfig(enabled=True,
                                                              context_budget=24000), [file])
    shown = {k: v for k, v in flag.items() if k not in ("id", "unit")}
    prompt = TRIAGE_PROMPT.format(threat=HUNT_THREAT, finding=json.dumps(shown, indent=1),
                                  code=code)
    try:
        conv = backend.conversation("", [])
        conv.user(prompt)
        reply = conv.step(MAX_TOKENS)
    except Exception as e:
        if is_fatal(e):
            raise FatalBackendError(f"{type(e).__name__}: {str(e)[:300]}") from e
        rec["error"] = f"{type(e).__name__}: {str(e)[:200]}"
        return rec
    rec["usage"] = reply.usage
    rec["cost_usd"] = cost_usd(model, reply.usage)
    if reply.stop_reason == "refusal":
        rec["refused"] = True
        return rec
    v = extract_json(reply.text)
    if v is None:
        rec["error"] = "unparseable"
        return rec
    rec["verdict"] = v
    rec["raw_score"] = _clamp(v.get("score"))
    rec["quotes_verified"] = _quoted(ws, v.get("path_steps"), file)
    rec["score"] = round(rec["raw_score"] * (0.5 + 0.5 * rec["quotes_verified"]), 4)
    return rec


def run_triage(ws, flags, hc, store, budget, make, log) -> dict[str, dict]:
    done = {r["id"]: r for r in store.read("triage") if not r.get("error")}
    todo = [f for f in flags if f["id"] not in done]
    log(f"triage: {len(flags)} flag(s), {len(done)} already scored, "
        f"{len(todo)} to go with {hc.triage_model}")
    if not todo or budget.exceeded:
        return done
    backend = make(hc.triage_model, hc.triage_effort)
    stop: list[Exception] = []

    def one(f):
        if stop or budget.exceeded:
            return
        try:
            rec = triage_one(backend, ws, f, hc.triage_model)
        except FatalBackendError as e:
            stop.append(e)
            return
        store.add("triage", rec)
        budget.add(rec["cost_usd"])
        if not rec["error"]:
            done[f["id"]] = rec
    with ThreadPoolExecutor(max_workers=max(1, hc.workers)) as pool:
        list(pool.map(one, todo))
    if stop:
        raise stop[0]
    return done


def deep_one(backend, ws: Workspace, flag: dict, triage: dict | None, hc: HuntConfig) -> dict:
    rec = {"id": flag["id"], "score": None, "quotes_verified": 0.0, "verdict": None,
           "usage": empty_usage(), "cost_usd": 0.0, "turns": 0, "tool_calls": 0,
           "budget_exhausted": False, "error": None, "refused": False, "seconds": 0.0}
    t0 = time.monotonic()
    file = flag.get("file", "")
    lines = ws.lines(file)
    code = ws.read_file(file, 1, len(lines) or 1)
    if est_tokens(code) > 30000:
        code = code[:30000 * CHARS_PER_TOKEN] + "\n... (file cut; read the rest with read_file)"
    shown = {k: v for k, v in flag.items() if k not in ("id", "unit")}
    notes = "(none)" if not triage or not triage.get("verdict") else \
        json.dumps(triage["verdict"], indent=1)
    conv = backend.conversation(DEEP_SYSTEM.format(threat=HUNT_THREAT, budget=hc.deep_budget),
                                DEEP_TOOLS, cache=True)
    conv.user(DEEP_TASK.format(finding=json.dumps(shown, indent=1), triage=notes,
                               code=f"=== {file} ===\n{code}"))
    used = 0
    try:
        for turn in range(hc.deep_turns):
            reply = conv.step(MAX_TOKENS)
            rec["turns"] += 1
            add_usage(rec["usage"], reply.usage)
            if reply.stop_reason == "refusal":
                rec["refused"] = True
                break
            if not reply.tool_calls:
                conv.user("Call report_verdict now.")
                continue
            results = []
            for call in reply.tool_calls:
                if call.name == "report_verdict":
                    rec["verdict"] = dict(call.input)
                    results.append((call.id, "received"))
                    continue
                rec["tool_calls"] += 1
                if rec["budget_exhausted"]:
                    results.append((call.id, "(budget exhausted: call report_verdict now)"))
                    continue
                out = dispatch(ws, call.name, call.input, allowed=READ_TOOLS)
                cost = est_tokens(out)
                if used + cost > hc.deep_budget:
                    room = max(0, hc.deep_budget - used)
                    out = out[:room * CHARS_PER_TOKEN] + (
                        "\n... (budget exhausted: output cut. Call report_verdict now.)")
                    rec["budget_exhausted"], cost = True, room
                used += cost
                results.append((call.id, out))
            if rec["verdict"] is not None:
                break
            last = turn == hc.deep_turns - 2
            conv.tool_results(results, "This is your last turn. Call report_verdict now."
                              if last else None)
    except Exception as e:
        if is_fatal(e):
            raise FatalBackendError(f"{type(e).__name__}: {str(e)[:300]}") from e
        rec["error"] = f"{type(e).__name__}: {str(e)[:200]}"
    rec["cost_usd"] = cost_usd(hc.deep_model, rec["usage"])
    rec["seconds"] = round(time.monotonic() - t0, 2)
    v = rec["verdict"]
    if v is not None:
        rec["quotes_verified"] = _quoted(ws, v.get("path_steps"), file)
        rec["score"] = round(_clamp(v.get("score")) * (0.5 + 0.5 * rec["quotes_verified"]), 4)
    elif not rec["error"] and not rec["refused"]:
        rec["error"] = "no verdict"
    return rec


def pick_deep(flags, triage: dict, hc: HuntConfig) -> list[dict]:
    scored = [f for f in flags if f["id"] in triage
              and triage[f["id"]]["score"] >= hc.min_score]
    scored.sort(key=lambda f: -triage[f["id"]]["score"])
    return scored[:hc.deep_top]


def run_deep(ws, flags, triage, hc, store, budget, make, log) -> dict[str, dict]:
    done = {r["id"]: r for r in store.read("deep") if not r.get("error")}
    picked = pick_deep(flags, triage, hc)
    todo = [f for f in picked if f["id"] not in done]
    log(f"deep: top {len(picked)} flag(s) (triage score >= {hc.min_score}), "
        f"{len(picked) - len(todo)} already done, {len(todo)} to go with {hc.deep_model}")
    if not todo or budget.exceeded:
        return done
    backend = make(hc.deep_model, hc.deep_effort)
    stop: list[Exception] = []

    def one(f):
        if stop or budget.exceeded:
            return
        try:
            rec = deep_one(backend, ws, f, triage.get(f["id"]), hc)
        except FatalBackendError as e:
            stop.append(e)
            return
        store.add("deep", rec)
        budget.add(rec["cost_usd"])
        v = rec["verdict"] or {}
        log(f"  {f['id']}: {v.get('verdict', rec['error'] or 'refused')} "
            f"score={rec['score']} ${rec['cost_usd'] or 0:.2f}")
        if not rec["error"]:
            done[f["id"]] = rec
    with ThreadPoolExecutor(max_workers=max(1, min(hc.workers, 4))) as pool:
        list(pool.map(one, todo))
    if stop:
        raise stop[0]
    return done


# ---------------------------------------------------------------- report

def _cell(s, n=160) -> str:
    s = " ".join(str(s or "").split()).replace("|", "\\|")
    return s if len(s) <= n else s[:n - 3] + "..."


def rank(flags, triage, deep) -> list[dict]:
    """Deep-dived flags first (by their score), then the rest by triage score."""
    rows = []
    for f in flags:
        t, d = triage.get(f["id"]), deep.get(f["id"])
        rows.append({"flag": f, "triage": t, "deep": d,
                     "score": (d["score"] if d and d["score"] is not None
                               else t["score"] if t else None)})
    rows.sort(key=lambda r: (r["deep"] is None or r["deep"]["score"] is None,
                             -(r["score"] if r["score"] is not None else -1)))
    return rows


def stage_costs(store: Store) -> dict:
    out = {}
    for stage in ("screen", "triage", "deep"):
        out[stage] = round(sum(r.get("cost_usd") or 0 for r in store.read(stage)), 4)
    out["total"] = round(sum(out.values()), 4)
    return out


def write_report(out: Path, repo: str, hc: HuntConfig, stats: dict, recs, rows,
                 costs: dict, failed=()) -> Path:
    name = Path(repo).resolve().name
    L = [f"# Hunt report: {name}", "",
         f"{datetime.now():%Y-%m-%d %H:%M}. Screen {hc.screen_model}, triage "
         f"{hc.triage_model}, deep dive {hc.deep_model}. Bug classes: "
         f"{', '.join(hc.bug_classes)}. Hunt prompt {HUNT_VERSION}.", "",
         f"Files: {stats.get('files', 0)} found, {stats.get('kept', 0)} audited "
         f"({stats.get('tests', 0)} test, {stats.get('non_product', 0)} docs/samples, "
         f"{stats.get('no_keyword', 0)} with no relevant API skipped). "
         f"Screened {len(recs)}, flags {len(rows)}.", "",
         f"Cost: screen ${costs['screen']:.2f}, triage ${costs['triage']:.2f}, "
         f"deep ${costs['deep']:.2f}, total ${costs['total']:.2f}.", "",
         "Scores are model estimates, not proof. Quotes the model cited are checked "
         "against the source, and a score is cut by up to half when they don't match. "
         "Confirm every lead on your own instance (a VM or a container) before "
         "believing it, and report anything real through the project's security "
         "policy.", ""]
    deep_rows = [r for r in rows if r["deep"]]
    L += ["## Deep-dived leads", ""]
    if not deep_rows:
        L += ["(none yet)", ""]
    for i, r in enumerate(deep_rows, 1):
        f, d = r["flag"], r["deep"]
        v = d["verdict"] or {}
        L += [f"### {i}. {v.get('title') or f.get('bug_class')} "
              f"({v.get('verdict', '?')}, score {d['score']})", "",
              f"- Where: `{f.get('file')}:{f.get('line')}` "
              f"({f.get('bug_class')}, {v.get('cwe') or f.get('cwe', '')}, "
              f"severity {v.get('severity') or f.get('severity', '?')})",
              f"- Attacker: {v.get('attacker', '?')}",
              f"- Entry point: {v.get('entry_point', '?')}",
              f"- Quotes verified: {d['quotes_verified']:.0%}"]
        steps = v.get("path_steps") or []
        if steps:
            L.append("- Path:")
            for s in steps:
                if isinstance(s, dict):
                    L.append(f"  1. `{s.get('file')}:{s.get('line')}` "
                             f"`{_cell(s.get('quote'), 200)}`")
        for key, label in (("defenses", "Defenses"), ("poc", "Input"),
                           ("reproduce", "Reproduce"), ("impact", "Impact"),
                           ("reason", "Why")):
            if v.get(key):
                L.append(f"- {label}: {v[key]}")
        L.append("")
    rest = [r for r in rows if not r["deep"]]
    L += ["## Other flags, by triage score", "",
          "| # | score | where | class | attacker | triage reason |",
          "|---|---|---|---|---|---|"]
    for i, r in enumerate(rest[:100], 1):
        f, t = r["flag"], r["triage"]
        tv = (t or {}).get("verdict") or {}
        L.append(f"| {i} | {'-' if r['score'] is None else r['score']} | "
                 f"`{f.get('file')}:{f.get('line')}` | {f.get('bug_class')} | "
                 f"{_cell(tv.get('attacker'), 40)} | {_cell(tv.get('reason') or f.get('path'))} |")
    if len(rest) > 100:
        L.append(f"\n({len(rest) - 100} more in findings.json)")
    ok = {r["unit"] for r in recs}
    errs = len({r["unit"] for r in failed if r["unit"] not in ok})
    L += ["", "## Run health", "",
          f"- screen: {errs} file(s) errored (rerun to retry), "
          f"{stats.get('kept', 0) - len(ok) - errs} not reached (budget cap?), "
          f"{sum(r.get('refused', False) for r in recs)} refused, "
          f"{sum(r.get('budget_exhausted', False) for r in recs)} hit the read budget",
          f"- flags with no triage score yet: {sum(r['triage'] is None for r in rows)}"]
    path = out / "report.md"
    path.write_text("\n".join(L) + "\n", encoding="utf-8")
    (out / "findings.json").write_text(json.dumps(
        {"repo": str(repo), "config": hc.as_dict(), "costs": costs, "stats": stats,
         "ranked": rows}, indent=1, default=str), encoding="utf-8")
    return path


# ---------------------------------------------------------------- driver

def run_hunt(repo: str, out: Path, hc: HuntConfig, budget: Budget, make, log=print) -> Path:
    ws = Workspace(repo)
    store = Store(Path(out))
    units, stats = hunt_units(ws, hc.bug_classes, hc.prefilter, hc.exts)
    (Path(out)).mkdir(parents=True, exist_ok=True)
    (Path(out) / "meta.json").write_text(json.dumps(
        {"repo": str(Path(repo).resolve()), "config": hc.as_dict(), "stats": stats,
         "hunt_version": HUNT_VERSION}, indent=1), encoding="utf-8")
    try:
        recs = run_screen(ws, units, hc, store, budget, make, log)
        flags = collect_flags(recs)
        triage = run_triage(ws, flags, hc, store, budget, make, log)
        deep = run_deep(ws, flags, triage, hc, store, budget, make, log)
    finally:
        # always leave a report of whatever finished, even after a stop
        rows = store.read("screen")
        recs = list({r["unit"]: r for r in rows if not r.get("error")}.values())
        flags = collect_flags(recs)
        triage = {r["id"]: r for r in store.read("triage") if not r.get("error")}
        deep = {r["id"]: r for r in store.read("deep") if not r.get("error")}
        path = write_report(Path(out), repo, hc, stats, recs,
                            rank(flags, triage, deep), stage_costs(store),
                            [r for r in rows if r.get("error")])
    return path
