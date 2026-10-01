"""
Context-building phase, adapted from Trail of Bits' audit-context-building skill.

Runs BEFORE bug hunting. The agent maps entry points, trust boundaries, sinks,
persistent state, and the highest-weight functions, then hands back a compact
summary that gets injected into the hunt's system prompt. On real repos this is
the difference between the agent guessing at a high level and actually following
input from a source to a sink across functions.

Kept token-bounded: it is a short, capped exploration that returns a summary
string, not a full second audit.
"""
from __future__ import annotations

import anthropic

from .tools import Workspace, TOOL_SCHEMAS, dispatch
from .prompts import CONTEXT_PROMPT

# a report_context tool so the phase ends with a structured hand-back
CONTEXT_TOOL = {
    "name": "report_context",
    "description": "Submit the structured context summary. Call once when done.",
    "input_schema": {
        "type": "object",
        "properties": {
            "entry_points": {"type": "array", "items": {"type": "string"}},
            "trust_boundaries": {"type": "array", "items": {"type": "string"}},
            "sinks": {"type": "array", "items": {"type": "string"}},
            "persistent_state": {"type": "array", "items": {"type": "string"}},
            "high_weight_functions": {"type": "array", "items": {"type": "string"}},
        },
    },
}

# only the read-only exploration tools during context building (no reporting bugs)
_EXPLORE_TOOLS = [t for t in TOOL_SCHEMAS if t["name"] in
                  {"list_dir", "read_file", "grep", "run_semgrep"}] + [CONTEXT_TOOL]


def build_context(client, ws: Workspace, model: str, res, max_turns: int = 15) -> str:
    """Run the context pre-pass. Returns a summary string to prime the hunt.
    Accumulates token usage into `res` (an AuditResult)."""
    messages = [{
        "role": "user",
        "content": "Map this repository for a security audit. Start at the root.",
    }]
    summary = ""
    for _ in range(max_turns):
        res.turns += 1
        resp = client.messages.create(
            model=model, max_tokens=1500,
            system=CONTEXT_PROMPT, tools=_EXPLORE_TOOLS, messages=messages,
        )
        res.input_tokens += resp.usage.input_tokens
        res.output_tokens += resp.usage.output_tokens
        messages.append({"role": "assistant", "content": resp.content})

        tool_results, done = [], False
        for block in resp.content:
            if block.type != "tool_use":
                continue
            if block.name == "report_context":
                summary = _format_context(block.input)
                done = True
                tool_results.append({"type": "tool_result",
                                     "tool_use_id": block.id, "content": "received"})
            else:
                out = dispatch(ws, block.name, block.input)
                tool_results.append({"type": "tool_result",
                                     "tool_use_id": block.id, "content": out})
        if done:
            break
        if not tool_results:
            messages.append({"role": "user",
                             "content": "Call report_context with your summary now."})
            continue
        messages.append({"role": "user", "content": tool_results})
    return summary


def _format_context(ctx: dict) -> str:
    def block(title, items):
        if not items:
            return ""
        return f"{title}:\n" + "\n".join(f"  - {i}" for i in items) + "\n"
    return (
        "## Audit context (built before hunting)\n"
        + block("Entry points", ctx.get("entry_points"))
        + block("Trust boundaries", ctx.get("trust_boundaries"))
        + block("Dangerous sinks", ctx.get("sinks"))
        + block("Persistent state", ctx.get("persistent_state"))
        + block("High-weight functions (audit these first)",
                ctx.get("high_weight_functions"))
    ).strip()
