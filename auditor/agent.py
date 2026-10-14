"""
The auditing agent.

One Auditor runs one audit cell (an AuditConfig) over a list of units and returns
one record per unit. What changes between cells:

  exploration="explore"  tool-use loop: the agent reads/greps the repo on demand,
                         with tool output charged against context_budget
  exploration="fixed"    one call: target + related files packed up front to the
                         same context_budget, no tools except report_findings
  static_analysis        explore: run_semgrep is in the toolset
                         fixed: semgrep hits for the unit are in the prompt

Every unit record carries tokens (incl. cache reads/writes), dollars, wall time,
turns, refusals and errors, so cost and failures are visible per cell (RO3).
"""
from __future__ import annotations
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from .config import AuditConfig
from .llm import empty_usage, add_usage
from .pricing import cost_usd
from .prompts import system_prompt, unit_task, VARIANT_PROMPT
from .tools import Workspace, tool_schemas, dispatch, REPORT_TOOL
from .units import Unit, build_units, pack_context, semgrep_block, est_tokens, CHARS_PER_TOKEN
from .validate import resolve_file

MAX_TOKENS = 16000   # per model call; thinking models need headroom

# Errors that will hit every unit the same way (bad key, no access, unknown model
# id). These stop the pass instead of being recorded per unit, so a typo can't
# produce a results folder full of identical failures.
FATAL_ERRORS = {"AuthenticationError", "PermissionDeniedError", "NotFoundError"}


class FatalBackendError(RuntimeError):
    pass


@dataclass
class AuditResult:
    """Aggregate over units, kept for run_audit.py and older callers."""
    findings: list[dict] = field(default_factory=list)
    raw_findings: list[dict] = field(default_factory=list)
    usage: dict = field(default_factory=empty_usage)
    cost_usd: float | None = 0.0
    seconds: float = 0.0
    turns: int = 0
    units: int = 0
    refusals: int = 0
    errors: int = 0

    @property
    def input_tokens(self):
        u = self.usage
        return u["input"] + u["cache_read"] + u["cache_write"]

    @property
    def output_tokens(self):
        return self.usage["output"]


def _new_record(unit: Unit) -> dict:
    return {"unit": unit.id, "targets": unit.targets, "findings": [],
            "dropped_out_of_target": 0, "reported": False, "usage": empty_usage(),
            "cost_usd": 0.0, "seconds": 0.0, "turns": 0, "context_tokens": 0,
            "context_truncated": False, "budget_exhausted": False,
            "refused": False, "error": None, "semgrep_error": None}


class Auditor:
    def __init__(self, ws: Workspace, cfg: AuditConfig, backend):
        self.ws, self.cfg, self.backend = ws, cfg, backend
        self._sub_auditors: dict[str, "Auditor"] = {}
        self._sub_lock = threading.Lock()
        self.explore = cfg.exploration == "explore"
        self.tools = tool_schemas(self.explore, cfg.static_analysis)
        self.allowed = {t["name"] for t in self.tools}
        self.system = system_prompt(list(cfg.bug_classes), self.explore,
                                    cfg.static_analysis, cfg.context_budget,
                                    cfg.threat_model)

    # ------------------------------------------------------------ public

    def run_units(self, units: list[Unit], workers: int = 1, log=print,
                  on_done=None, should_stop=None) -> list[dict]:
        """Run every unit; returns records in unit order. on_done(rec) is called
        as each unit finishes (for checkpointing and budget). Once should_stop()
        is true, units that haven't started are skipped and left out."""
        if self.cfg.static_analysis and not any(u.root for u in units):
            # one scan up front, so worker threads share the cache instead of racing
            # (scoped units scan their own project instead, in _run_scoped)
            try:
                self.ws.semgrep_results(".", self.cfg.semgrep_config)
            except Exception as e:
                log(f"  ! semgrep unavailable: {e}")

        def one(u, i):
            if should_stop is not None and should_stop():
                return None
            rec = self._run_logged(u, i, len(units), log)
            if on_done is not None:
                on_done(rec)
            return rec

        out: list[dict | None] = [None] * len(units)
        if workers <= 1:
            for i, u in enumerate(units):
                out[i] = one(u, i)
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futs = {pool.submit(one, u, i): i for i, u in enumerate(units)}
                for fut in as_completed(futs):
                    out[futs[fut]] = fut.result()
        return [r for r in out if r is not None]

    def run_unit(self, unit: Unit) -> dict:
        if unit.root:
            return self._run_scoped(unit)
        rec = _new_record(unit)
        t0 = time.monotonic()
        try:
            if self.explore:
                self._explore(unit, rec)
            else:
                self._fixed(unit, rec)
        except Exception as e:  # one unit failing must not kill the run...
            if type(e).__name__ in FATAL_ERRORS:   # ...unless it will fail them all
                raise FatalBackendError(f"{type(e).__name__}: {str(e)[:300]}") from e
            rec["error"] = f"{type(e).__name__}: {str(e)[:300]}"
        rec["seconds"] = round(time.monotonic() - t0, 2)
        rec["cost_usd"] = cost_usd(self.cfg.model, rec["usage"])
        rec["findings"] = self._normalize(unit, rec)
        return rec

    def _run_scoped(self, unit: Unit) -> dict:
        """Run a unit with every tool confined to unit.root, then map paths back
        to repo-relative so scoring and validation see the same names."""
        prefix = unit.root.strip("/") + "/"
        with self._sub_lock:   # one sub-auditor (and one semgrep scan) per project
            sub = self._sub_auditors.get(prefix)
            if sub is None:
                sub = Auditor(Workspace(str(self.ws.root / unit.root)), self.cfg,
                              self.backend)
                if self.cfg.static_analysis:
                    try:
                        sub.ws.semgrep_results(".", self.cfg.semgrep_config)
                    except Exception:
                        pass   # recorded per unit as semgrep_error in fixed mode
                self._sub_auditors[prefix] = sub
        local = Unit(unit.id, [t[len(prefix):] if t.startswith(prefix) else t
                               for t in unit.targets])
        rec = sub.run_unit(local)
        rec["targets"] = unit.targets
        rec["root"] = unit.root
        for f in rec["findings"]:
            f["file"] = prefix + str(f.get("file", "")).lstrip("/")
        return rec

    # ------------------------------------------------------------ modes

    def _run_logged(self, unit, i, n, log):
        rec = self.run_unit(unit)
        tag = ("ERROR " + rec["error"][:80]) if rec["error"] else \
              ("REFUSED" if rec["refused"] else f"{len(rec['findings'])} finding(s)")
        log(f"  [{i + 1}/{n}] {unit.id}: {tag}")
        return rec

    def _step(self, conv, rec) -> object:
        reply = conv.step(MAX_TOKENS)
        rec["turns"] += 1
        add_usage(rec["usage"], reply.usage)
        if reply.stop_reason == "refusal":
            rec["refused"] = True
        return reply

    def _collect(self, call, rec, unit) -> None:
        rec["reported"] = True
        found = call.input.get("findings", [])
        if isinstance(found, list):
            for f in found:
                if isinstance(f, dict):
                    f.setdefault("file", unit.targets[0] if unit.targets else "")
                    rec["findings"].append(f)

    def _fixed(self, unit: Unit, rec: dict) -> None:
        text, used, _, trunc = pack_context(self.ws, unit, self.cfg.context_budget,
                                            include_related=True)
        rec["context_tokens"], rec["context_truncated"] = used, trunc
        prompt = unit_task(unit.targets, explore=False) + "\n\n" + text
        if self.cfg.static_analysis:
            sg, err = semgrep_block(self.ws, unit.targets or self.ws.source_files(),
                                    self.cfg.semgrep_config)
            rec["semgrep_error"] = err
            prompt += "\n\n" + sg
        conv = self.backend.conversation(self.system, self.tools, cache=False)
        conv.user(prompt)
        for attempt in range(2):
            reply = self._step(conv, rec)
            if rec["refused"]:
                return
            calls = [c for c in reply.tool_calls if c.name == "report_findings"]
            for c in calls:
                self._collect(c, rec, unit)
            if calls:
                return
            if reply.tool_calls:   # answer stray calls so the history stays valid
                conv.tool_results([(c.id, "(not available)") for c in reply.tool_calls],
                                  "Call report_findings now.")
            else:
                conv.user("Call report_findings now (empty list if nothing is solid).")

    def _explore(self, unit: Unit, rec: dict) -> None:
        budget = self.cfg.context_budget
        text, used, _, trunc = pack_context(self.ws, unit, budget, include_related=False)
        rec["context_tokens"], rec["context_truncated"] = used, trunc
        conv = self.backend.conversation(self.system, self.tools, cache=True)
        conv.user(unit_task(unit.targets, explore=True) + "\n\n" + text)

        for turn in range(self.cfg.max_turns):
            reply = self._step(conv, rec)
            if rec["refused"]:
                return
            if not reply.tool_calls:
                conv.user("Call report_findings now (empty list if nothing is solid).")
                continue
            results, done = [], False
            for call in reply.tool_calls:
                if call.name == "report_findings":
                    self._collect(call, rec, unit)
                    results.append((call.id, "received"))
                    done = True
                    continue
                if rec["budget_exhausted"]:
                    results.append((call.id, "(context budget exhausted: call "
                                             "report_findings now)"))
                    continue
                out = dispatch(self.ws, call.name, call.input,
                               self.cfg.semgrep_config, self.allowed)
                cost = est_tokens(out)
                if used + cost > budget:
                    room = max(0, budget - used)
                    out = out[:room * CHARS_PER_TOKEN] + (
                        "\n... (context budget exhausted: output cut. Call "
                        "report_findings now.)")
                    rec["budget_exhausted"] = True
                    cost = room
                used += cost
                results.append((call.id, out))
            rec["context_tokens"] = used
            if done:
                return
            note = None
            if turn == self.cfg.max_turns - 2:
                note = "This is your last turn. Call report_findings now."
            conv.tool_results(results, note)

    # ------------------------------------------------------------ findings

    def _normalize(self, unit: Unit, rec: dict) -> list[dict]:
        """Resolve file paths to repo-relative, tag the unit, and drop findings
        whose sink is outside the unit's targets (another unit owns that file)."""
        out, tset = [], set(unit.targets)
        for f in rec["findings"]:
            f = dict(f)
            resolved = resolve_file(self.ws, str(f.get("file", "")))
            if resolved:
                f["file"] = resolved
            try:
                f["line"] = int(f.get("line", -1))
            except (TypeError, ValueError):
                f["line"] = -1
            f["unit"] = unit.id
            if tset and f["file"] not in tset:
                rec["dropped_out_of_target"] += 1
                continue
            out.append(f)
        return out


# ---------------------------------------------------------------- extras
# Used by run_audit.py for real repos. Not part of the factorial: context
# building and variant hunting are separate, optional add-ons.

def hunt_variants(backend, ws: Workspace, cfg: AuditConfig,
                  findings: list[dict]) -> tuple[list[dict], dict]:
    from .variant import find_variants
    usage, extra = empty_usage(), []
    seen = {(f.get("file"), f.get("line")) for f in findings}
    system = system_prompt(list(cfg.bug_classes), True, cfg.static_analysis,
                           cfg.context_budget, cfg.threat_model)
    tools = tool_schemas(True, cfg.static_analysis)
    for f in findings:
        candidates = find_variants(ws, f)
        if not candidates:
            continue
        try:
            conv = backend.conversation(system, tools, cache=False)
            conv.user(VARIANT_PROMPT.format(finding=json.dumps(f),
                                            candidates="\n".join(candidates)))
            reply = conv.step(MAX_TOKENS)
        except Exception as e:
            print(f"  ! variant hunt: {str(e)[:120]}")
            continue
        add_usage(usage, reply.usage)
        for call in reply.tool_calls:
            if call.name != "report_findings":
                continue
            for nf in call.input.get("findings", []):
                key = (nf.get("file"), nf.get("line"))
                if key not in seen:
                    nf["found_via"] = "variant-analysis"
                    seen.add(key)
                    extra.append(nf)
    return extra, usage


def audit_repo(repo: str, cfg: AuditConfig, backend=None, workers: int = 1,
               validation=None, use_context: bool = False,
               use_variants: bool = False) -> AuditResult:
    """Convenience wrapper: one cell over a whole repo, aggregated."""
    from .llm import make_backend
    from .validate import validate_one
    from .context import build_context
    backend = backend or make_backend(cfg.model, cfg.effort, cfg.temperature)
    ws = Workspace(repo)
    auditor = Auditor(ws, cfg, backend)
    res = AuditResult()
    t0 = time.monotonic()
    if use_context:
        ctx, u = build_context(backend, ws)
        add_usage(res.usage, u)
        if ctx:
            auditor.system += "\n\n" + ctx + (
                "\n\nUse this map to judge whether input reaching the target is "
                "attacker-controlled.")
    recs = auditor.run_units(build_units(ws, cfg.unit), workers)
    for r in recs:
        add_usage(res.usage, r["usage"])
        res.turns += r["turns"]
        res.refusals += r["refused"]
        res.errors += bool(r["error"])
        res.raw_findings += r["findings"]
    res.units = len(recs)
    findings = [dict(f) for f in res.raw_findings]
    unit_files = {r["unit"]: r["targets"] for r in recs}
    if validation is not None and validation.enabled:
        kept = []
        for f in findings:
            v = validate_one(backend, ws, f, validation, cfg.threat_model,
                             unit_files.get(f.get("unit")))
            add_usage(res.usage, v["usage"])
            if v["confirmed"]:
                f["validator_reason"] = (v["verdict"] or {}).get("reason", "")
                kept.append(f)
        findings = kept
    if use_variants and findings:
        extra, u = hunt_variants(backend, ws, cfg, findings)
        add_usage(res.usage, u)
        if validation is not None and validation.enabled:
            kept = []
            for f in extra:
                v = validate_one(backend, ws, f, validation, cfg.threat_model)
                add_usage(res.usage, v["usage"])
                if v["confirmed"]:
                    kept.append(f)
            extra = kept
        findings += extra
    res.findings = findings
    res.seconds = round(time.monotonic() - t0, 2)
    res.cost_usd = cost_usd(cfg.model, res.usage)
    return res
