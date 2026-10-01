"""
The auditing agent: an Anthropic native tool-use loop.

Design mirrors RepoAudit (arXiv:2501.18160):
  explore -> hypothesize (source->sink) -> corroborate (semgrep) -> validate.

Audits ONE FILE PER CONVERSATION by default and aggregates the findings. This is
how real auditors (and RepoAudit) work: it keeps every request bounded, makes
token cost scale linearly and predictably with repo size, and stops one large or
malformed file from sinking the whole run. Whole-repo-in-one-context does not
scale past a handful of files, so per-file is the default.

Token accounting is built in so every prompt/loop change can be scored on cost.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict

import anthropic

from .tools import Workspace, TOOL_SCHEMAS, dispatch
from .prompts import system_prompt, VALIDATOR_PROMPT, VARIANT_PROMPT
from .context import build_context
from .variant import find_variants

MODEL = "claude-sonnet-4-6"  # cheap+capable for the explore loop; bump for hard repos
REQUEST_TIMEOUT = 120  # seconds per API call; a hung call fails its file, not the run
MAX_RETRIES = 2        # transient errors (overload/timeout) are retried this many times


@dataclass
class AuditResult:
    findings: list[dict] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    turns: int = 0
    files_audited: int = 0

    def as_dict(self):
        return asdict(self)


class Auditor:
    def __init__(self, repo_root: str, bug_classes: list[str], max_turns: int = 12,
                 validate: bool = True, use_context: bool = False,
                 use_variants: bool = False, model: str = MODEL):
        self.ws = Workspace(repo_root)
        self.bug_classes = bug_classes
        # max_turns is now PER FILE (each file is a fresh, short conversation)
        self.max_turns = max_turns
        self.validate = validate
        self.use_context = use_context      # ToB audit-context-building pre-pass
        self.use_variants = use_variants    # ToB variant-analysis post-pass
        self.model = model
        # timeout + retries so one slow/hung request can't freeze a long run
        self.client = anthropic.Anthropic(
            timeout=REQUEST_TIMEOUT, max_retries=MAX_RETRIES)

    def _call(self, **kwargs):
        """One API call with usage accounting handled by the caller. Raises on
        failure so callers can skip just the current file/finding."""
        return self.client.messages.create(**kwargs)

    def run(self) -> AuditResult:
        res = AuditResult()

        # Optional architectural context, built once and shared across files.
        context = ""
        if self.use_context:
            context = build_context(self.client, self.ws, self.model, res)

        files = self.ws.source_files()
        raw_findings: list[dict] = []
        total = len(files)
        for i, rel in enumerate(files, 1):
            print(f"  auditing {i}/{total}: {rel}", flush=True)
            hits = self._audit_file(rel, context, res)
            if hits:
                print(f"      -> {len(hits)} candidate(s)", flush=True)
            raw_findings.extend(hits)
            res.files_audited += 1

        if raw_findings:
            print(f"  validating {len(raw_findings)} candidate(s)...", flush=True)
        findings = self._validate(raw_findings, res) if self.validate else raw_findings

        if self.use_variants and findings:
            findings = self._hunt_variants(findings, res)

        res.findings = findings
        return res

    def _audit_file(self, rel: str, context: str, res: AuditResult) -> list[dict]:
        """Audit a single file in its own fresh conversation. Bounded context,
        so cost is predictable and one bad file can't take down the run."""
        sys_prompt = system_prompt(self.bug_classes)
        if context:
            sys_prompt += "\n\n" + context + (
                "\n\nUse this map to judge whether input reaching this file is "
                "attacker-controlled.")

        file_text = self.ws.read_file(rel, 1, 4000)
        messages = [{
            "role": "user",
            "content": (
                f"Audit ONLY this one file for the target bug classes: {rel}\n\n"
                f"{file_text}\n\n"
                "Trace whether attacker-controlled input reaches a dangerous sink "
                "in this file. You may grep/read other files for context, but only "
                "report findings whose sink is in this file. Call report_findings "
                "once when done (empty list if nothing solid)."
            ),
        }]

        found: list[dict] = []
        for _ in range(self.max_turns):
            res.turns += 1
            try:
                resp = self.client.messages.create(
                    model=self.model, max_tokens=2048,
                    system=sys_prompt, tools=TOOL_SCHEMAS, messages=messages,
                )
            except Exception as e:  # one file failing must not kill the run
                print(f"  ! {rel}: {str(e)[:120]}")
                break
            res.input_tokens += resp.usage.input_tokens
            res.output_tokens += resp.usage.output_tokens
            messages.append({"role": "assistant", "content": resp.content})

            tool_results, done = [], False
            for block in resp.content:
                if block.type != "tool_use":
                    continue
                if block.name == "report_findings":
                    for f in block.input.get("findings", []):
                        f.setdefault("file", rel)
                        found.append(f)
                    done = True
                    tool_results.append({"type": "tool_result",
                                         "tool_use_id": block.id, "content": "received"})
                else:
                    out = dispatch(self.ws, block.name, block.input)
                    tool_results.append({"type": "tool_result",
                                         "tool_use_id": block.id, "content": out})
            if done:
                break
            if not tool_results:
                messages.append({"role": "user", "content":
                                 "Call report_findings now (empty list if none)."})
                continue
            messages.append({"role": "user", "content": tool_results})
        return found

    def _hunt_variants(self, findings: list[dict], res: AuditResult) -> list[dict]:
        extra: list[dict] = []
        seen = {(f.get("file"), f.get("line")) for f in findings}
        for f in list(findings):
            candidates = find_variants(self.ws, f)
            if not candidates:
                continue
            try:
                resp = self.client.messages.create(
                    model=self.model, max_tokens=2048,
                    system=system_prompt(self.bug_classes), tools=TOOL_SCHEMAS,
                    messages=[{"role": "user", "content": VARIANT_PROMPT.format(
                        finding=json.dumps(f), candidates="\n".join(candidates))}],
                )
            except Exception as e:
                print(f"  ! variant hunt: {str(e)[:120]}")
                continue
            res.input_tokens += resp.usage.input_tokens
            res.output_tokens += resp.usage.output_tokens
            res.turns += 1
            for block in resp.content:
                if block.type == "tool_use" and block.name == "report_findings":
                    for nf in block.input.get("findings", []):
                        key = (nf.get("file"), nf.get("line"))
                        if key not in seen:
                            nf["found_via"] = "variant-analysis"
                            seen.add(key)
                            extra.append(nf)
        if self.validate and extra:
            extra = self._validate(extra, res)
        return findings + extra

    def _validate(self, findings: list[dict], res: AuditResult) -> list[dict]:
        confirmed = []
        for f in findings:
            code = self.ws.read_file(
                f.get("file", ""),
                max(1, f.get("line", 1) - 30),
                f.get("line", 1) + 30,
            )
            try:
                resp = self.client.messages.create(
                    model=self.model, max_tokens=400,
                    messages=[{"role": "user", "content": VALIDATOR_PROMPT.format(
                        finding=json.dumps(f), code=code)}],
                )
            except Exception as e:
                print(f"  ! validate: {str(e)[:120]}")
                continue
            res.input_tokens += resp.usage.input_tokens
            res.output_tokens += resp.usage.output_tokens
            text = "".join(b.text for b in resp.content if b.type == "text")
            text = text.replace("```json", "").replace("```", "").strip()
            try:
                verdict = json.loads(text)
            except json.JSONDecodeError:
                continue  # unparseable -> drop, keeps precision high
            if verdict.get("verdict") == "confirmed":
                f["confidence"] = verdict.get("adjusted_confidence", f.get("confidence"))
                f["validator_reason"] = verdict.get("reason", "")
                confirmed.append(f)
        return confirmed
