"""
Evidence-stage validator (RO2).

Each candidate gets one independent model call. Which evidence is demanded is set
by ValidationConfig.evidence, any subset of:
  path        data-flow steps, each quote checked MECHANICALLY against the file
  sanitizer   sanitizers named + adequacy judged; adequate sanitizer -> reject
  conditions  path conditions listed + satisfiability judged; unsat -> reject
  poc         a concrete input; empty -> reject

A finding is confirmed only if the model says confirmed AND every required
evidence check passes. rejected_by records which checks failed, so you can count
which evidence cuts the most false positives per token.
"""
from __future__ import annotations
import json
import re
import time

from .config import ValidationConfig
from .llm import empty_usage
from .prompts import validator_prompt
from .tools import Workspace
from .units import est_tokens

QUOTE_SLACK = 2          # a quote may sit this many lines off the cited line
MAX_TOKENS = 16000       # thinking models need room; output is short JSON


def extract_json(text: str) -> dict | None:
    """First balanced {...} object in text, tolerant of prose and code fences."""
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            c = text[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start:i + 1])
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        pass
                    break
        start = text.find("{", start + 1)
    return None


def resolve_file(ws: Workspace, name: str) -> str | None:
    """Model-reported path -> repo-relative path, or None. Accepts exact relative
    paths, absolute paths inside the repo, and unique basenames."""
    if not name:
        return None
    name = name.replace("\\", "/")
    try:
        p = ws._safe(name)
        if p.is_file():
            return ws.rel(p)
    except ValueError:
        pass
    base = name.rsplit("/", 1)[-1]
    matches = [f for f in ws.source_files() if f.rsplit("/", 1)[-1] == base]
    if len(matches) == 1:
        return matches[0]
    tail = [f for f in matches if f.endswith(name)]
    return tail[0] if len(tail) == 1 else None


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def check_path_steps(ws: Workspace, steps, default_file: str) -> tuple[bool, float]:
    """All quoted steps must appear within QUOTE_SLACK lines of their cited line.
    Returns (ok, fraction_verified)."""
    if not isinstance(steps, list) or not steps:
        return False, 0.0
    ok = 0
    for s in steps:
        if not isinstance(s, dict):
            continue
        quote = _norm(str(s.get("quote", "")))
        f = resolve_file(ws, str(s.get("file") or default_file))
        try:
            line = int(s.get("line", -1))
        except (TypeError, ValueError):
            line = -1
        if not quote or not f or line < 1:
            continue
        lines = ws.lines(f)
        lo, hi = max(0, line - 1 - QUOTE_SLACK), min(len(lines), line + QUOTE_SLACK)
        window = [_norm(x) for x in lines[lo:hi]]
        if any(quote in w for w in window) or quote in " ".join(window):
            ok += 1
    frac = ok / len(steps)
    return ok == len(steps), round(frac, 3)


def apply_checks(ws: Workspace, verdict: dict, evidence: tuple[str, ...],
                 file: str) -> tuple[dict, list[str]]:
    checks, failed = {}, []
    if "path" in evidence:
        ok, frac = check_path_steps(ws, verdict.get("path_steps"), file)
        checks["path"] = ok
        checks["path_quote_fraction"] = frac
        if not ok:
            failed.append("path")
    if "sanitizer" in evidence:
        ok = verdict.get("sanitizer_adequate") is not True and "sanitizer_adequate" in verdict
        checks["sanitizer"] = ok
        if not ok:
            failed.append("sanitizer")
    if "conditions" in evidence:
        ok = verdict.get("conditions_satisfiable") is True
        checks["conditions"] = ok
        if not ok:
            failed.append("conditions")
    if "poc" in evidence:
        ok = bool(str(verdict.get("poc", "")).strip())
        checks["poc"] = ok
        if not ok:
            failed.append("poc")
    return checks, failed


def validator_code(ws: Workspace, file: str, line: int, cfg: ValidationConfig,
                   unit_files: list[str] | None) -> tuple[str, bool]:
    """Code shown to the validator: the finding's whole file, then the rest of its
    audit unit, up to cfg.context_budget. A ±window excerpt hid the source on
    split and long Juliet cases, so the validator rejected real bugs for missing
    evidence. Falls back to the window only if the file alone is over budget.
    Returns (text, used_window_fallback)."""
    order = [file] + [f for f in (unit_files or []) if f != file]
    parts, used, fallback = [], 0, False
    for f in order:
        block = f"=== {f} ===\n{ws.read_file(f, 1, 10**9)}\n"
        cost = est_tokens(block)
        if used + cost <= cfg.context_budget:
            parts.append(block)
            used += cost
        elif f == file:
            n = len(ws.lines(file))
            start, end = max(1, line - cfg.window), min(n, line + cfg.window)
            block = f"=== {f} (lines {start}-{end} of {n}) ===\n{ws.read_file(f, start, end)}\n"
            parts.append(block)
            used += est_tokens(block)
            fallback = True
    return "".join(parts), fallback


def _strip(v, prefix: str):
    if isinstance(v, str):
        return v.replace(prefix, "")
    if isinstance(v, list):
        return [_strip(x, prefix) for x in v]
    if isinstance(v, dict):
        return {k: _strip(x, prefix) for k, x in v.items()}
    return v


def scope_to_root(ws: Workspace, finding: dict, unit_files: list[str] | None,
                  root: str | None) -> tuple[Workspace, dict, list[str] | None]:
    """Confine the validator to the unit's project, the same view the auditor had.
    In a multi-project workspace the project folder name carries the CVE id
    (e.g. apache__jspwiki_CVE-2019-10076_...), so showing repo-relative paths
    leaks the answer key to the verifier."""
    root = (root or "").strip("/")
    if not root:
        return ws, finding, unit_files
    prefix = root + "/"
    files = None if unit_files is None else [f[len(prefix):] if f.startswith(prefix) else f
                                             for f in unit_files]
    return Workspace(str(ws.root / root)), _strip(finding, prefix), files


def prepare_validation(ws: Workspace, finding: dict, cfg: ValidationConfig,
                       threat_model: str = "all-external",
                       unit_files: list[str] | None = None) -> tuple[dict, str | None, str | None]:
    """(record, prompt, resolved file). prompt is None when there's nothing to ask,
    and the record is already final."""
    rec = {"confirmed": False, "rejected_by": [], "checks": {}, "verdict": None,
           "usage": empty_usage(), "seconds": 0.0, "error": None, "refused": False,
           "window_fallback": False}
    file = resolve_file(ws, str(finding.get("file", "")))
    if not file:
        rec["rejected_by"] = ["file_not_found"]
        return rec, None, None
    try:
        line = int(finding.get("line", 1))
    except (TypeError, ValueError):
        line = 1
    code, rec["window_fallback"] = validator_code(ws, file, line, cfg, unit_files)
    prompt = validator_prompt(json.dumps(finding, sort_keys=True), code, cfg.evidence,
                              threat_model)
    return rec, prompt, file


def validate_one(backend, ws: Workspace, finding: dict, cfg: ValidationConfig,
                 threat_model: str = "all-external",
                 unit_files: list[str] | None = None) -> dict:
    """Returns a record: confirmed (bool), rejected_by, checks, verdict, usage,
    seconds, and error/refusal if the call failed."""
    rec, prompt, file = prepare_validation(ws, finding, cfg, threat_model, unit_files)
    if prompt is None:
        return rec
    t0 = time.monotonic()
    try:
        conv = backend.conversation("", [])
        conv.user(prompt)
        reply = conv.step(MAX_TOKENS)
    except Exception as e:  # one failed call must not kill the run
        rec["error"] = f"{type(e).__name__}: {str(e)[:200]}"
        rec["seconds"] = round(time.monotonic() - t0, 2)
        return rec
    rec["seconds"] = round(time.monotonic() - t0, 2)
    return finish_validation(rec, reply, ws, cfg, file)


def finish_validation(rec: dict, reply, ws: Workspace, cfg: ValidationConfig,
                      file: str) -> dict:
    """Turn the model's reply into the final record (refusal, parse, checks)."""
    rec["usage"] = reply.usage
    if reply.stop_reason == "refusal":
        rec["refused"] = True
        rec["rejected_by"] = ["refusal"]
        return rec
    verdict = extract_json(reply.text)
    if verdict is None:
        rec["rejected_by"] = ["unparseable"]
        return rec
    rec["verdict"] = verdict
    checks, failed = apply_checks(ws, verdict, cfg.evidence, file)
    rec["checks"] = checks
    if verdict.get("verdict") != "confirmed":
        failed.insert(0, "verdict")
    rec["rejected_by"] = failed
    rec["confirmed"] = not failed
    return rec
