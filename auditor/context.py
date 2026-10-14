"""
Context-building phase, adapted from Trail of Bits' audit-context-building skill.

Optional add-on for real repos (run_audit.py --context), not one of the four
thesis factors. Runs BEFORE bug hunting: the agent maps entry points, trust
boundaries, sinks, persistent state, and the highest-weight functions, and the
summary is appended to the hunt's system prompt.
"""
from __future__ import annotations

from .llm import empty_usage, add_usage
from .prompts import CONTEXT_PROMPT
from .tools import Workspace, EXPLORE_TOOLS, dispatch

MAX_TOKENS = 16000

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


def build_context(backend, ws: Workspace, max_turns: int = 15) -> tuple[str, dict]:
    """Run the context pre-pass. Returns (summary, usage). A failure returns an
    empty summary so the hunt still runs."""
    usage = empty_usage()
    conv = backend.conversation(CONTEXT_PROMPT, EXPLORE_TOOLS + [CONTEXT_TOOL], cache=True)
    conv.user("Map this repository for a security audit. Start at the root.")
    for _ in range(max_turns):
        try:
            reply = conv.step(MAX_TOKENS)
        except Exception as e:
            print(f"  ! context build: {str(e)[:120]}")
            return "", usage
        add_usage(usage, reply.usage)
        if reply.stop_reason == "refusal":
            return "", usage
        if not reply.tool_calls:
            conv.user("Call report_context with your summary now.")
            continue
        results, summary = [], None
        for call in reply.tool_calls:
            if call.name == "report_context":
                summary = _format_context(call.input)
                results.append((call.id, "received"))
            else:
                results.append((call.id, dispatch(ws, call.name, call.input)))
        if summary is not None:
            return summary, usage
        conv.tool_results(results)
    return "", usage


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
