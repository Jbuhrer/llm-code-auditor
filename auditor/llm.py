"""
Model backends behind one small interface, so the model is just another factor.

  Conversation.user(text)                    add a user turn
  Conversation.tool_results(results, note)   answer every tool call from the last turn
  Conversation.step(max_tokens) -> Reply     one model call, appended to history

Backends:
  AnthropicBackend      any claude-* id, native tool use, prompt caching on
  OpenAICompatBackend   "openai-compat:<model>" for open-weight models behind an
                        OpenAI-compatible server (Ollama, vLLM, llama.cpp, TGI).
                        Base URL from OPENAI_COMPAT_BASE_URL
                        (default http://localhost:11434/v1, Ollama's).

Tool schemas are written once in Anthropic's shape (tools.py) and translated here.
"""
from __future__ import annotations
import json
import os
from dataclasses import dataclass, field

REQUEST_TIMEOUT = 600   # seconds; thinking models can take a while on big units
MAX_RETRIES = 3         # SDK retries 429 / 5xx / connection errors with backoff


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class Reply:
    text: str
    tool_calls: list[ToolCall]
    stop_reason: str
    usage: dict = field(default_factory=dict)   # input, output, cache_read, cache_write


def empty_usage() -> dict:
    return {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}


def add_usage(total: dict, u: dict) -> None:
    for k, v in u.items():
        total[k] = total.get(k, 0) + (v or 0)


# ---------------------------------------------------------------- Anthropic

class AnthropicConversation:
    def __init__(self, backend: "AnthropicBackend", system: str, tools: list[dict],
                 cache: bool):
        self.b, self.system, self.tools, self.cache = backend, system, tools, cache
        self.messages: list[dict] = []

    def user(self, text: str) -> None:
        self.messages.append({"role": "user", "content": text})

    def tool_results(self, results: list[tuple[str, str]], note: str | None = None) -> None:
        content = [{"type": "tool_result", "tool_use_id": tid, "content": out}
                   for tid, out in results]
        if note:
            content.append({"type": "text", "text": note})
        self.messages.append({"role": "user", "content": content})

    def step(self, max_tokens: int) -> Reply:
        kwargs = dict(model=self.b.model, max_tokens=max_tokens, messages=self.messages)
        if self.system:
            kwargs["system"] = self.system
        if self.cache:
            # multi-turn loops resend a growing prefix; caching it is the big cost win.
            # one-shot calls skip it, since a cache write costs 1.25x with no reuse.
            kwargs["cache_control"] = {"type": "ephemeral"}
        if self.tools:
            kwargs["tools"] = self.tools
        if self.b.effort:
            kwargs["output_config"] = {"effort": self.b.effort}
        resp = self.b.client.messages.create(**kwargs)
        # append the full content (thinking blocks included) so history stays valid
        self.messages.append({"role": "assistant", "content": resp.content})
        u = resp.usage
        usage = {"input": u.input_tokens or 0, "output": u.output_tokens or 0,
                 "cache_read": getattr(u, "cache_read_input_tokens", 0) or 0,
                 "cache_write": getattr(u, "cache_creation_input_tokens", 0) or 0}
        text = "".join(b.text for b in resp.content if b.type == "text")
        calls = [ToolCall(b.id, b.name, dict(b.input))
                 for b in resp.content if b.type == "tool_use"]
        return Reply(text, calls, resp.stop_reason or "", usage)


class AnthropicBackend:
    def __init__(self, model: str, effort: str | None = None, client=None):
        self.model, self.effort = model, effort
        if client is None:
            import anthropic
            client = anthropic.Anthropic(timeout=REQUEST_TIMEOUT, max_retries=MAX_RETRIES)
        self.client = client

    def conversation(self, system: str, tools: list[dict],
                     cache: bool = False) -> AnthropicConversation:
        return AnthropicConversation(self, system, tools, cache)


# ---------------------------------------------------------------- OpenAI-compatible

def _to_openai_tools(tools: list[dict]) -> list[dict]:
    return [{"type": "function",
             "function": {"name": t["name"], "description": t.get("description", ""),
                          "parameters": t["input_schema"]}} for t in tools]


class OpenAICompatConversation:
    def __init__(self, backend: "OpenAICompatBackend", system: str, tools: list[dict]):
        self.b = backend
        self.tools = _to_openai_tools(tools) if tools else None
        self.messages: list[dict] = [{"role": "system", "content": system}] if system else []

    def user(self, text: str) -> None:
        self.messages.append({"role": "user", "content": text})

    def tool_results(self, results: list[tuple[str, str]], note: str | None = None) -> None:
        for tid, out in results:
            self.messages.append({"role": "tool", "tool_call_id": tid, "content": out})
        if note:
            self.messages.append({"role": "user", "content": note})

    def step(self, max_tokens: int) -> Reply:
        kwargs = dict(model=self.b.model, messages=self.messages, max_tokens=max_tokens)
        if self.tools:
            kwargs["tools"] = self.tools
        if self.b.temperature is not None:
            kwargs["temperature"] = self.b.temperature
        resp = self.b.client.chat.completions.create(**kwargs)
        msg = resp.choices[0].message
        calls, raw_calls = [], []
        for tc in msg.tool_calls or []:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {"_unparseable_arguments": tc.function.arguments}
            calls.append(ToolCall(tc.id, tc.function.name, args))
            raw_calls.append({"id": tc.id, "type": "function",
                              "function": {"name": tc.function.name,
                                           "arguments": tc.function.arguments}})
        entry = {"role": "assistant", "content": msg.content or ""}
        if raw_calls:
            entry["tool_calls"] = raw_calls
        self.messages.append(entry)
        u = resp.usage
        usage = {"input": getattr(u, "prompt_tokens", 0) or 0,
                 "output": getattr(u, "completion_tokens", 0) or 0,
                 "cache_read": 0, "cache_write": 0}
        stop = {"tool_calls": "tool_use", "stop": "end_turn",
                "length": "max_tokens"}.get(resp.choices[0].finish_reason or "",
                                            resp.choices[0].finish_reason or "")
        return Reply(msg.content or "", calls, stop, usage)


class OpenAICompatBackend:
    def __init__(self, model: str, temperature: float | None = 0.0, client=None):
        self.model, self.temperature = model, temperature
        if client is None:
            from openai import OpenAI   # pip install openai; only needed for this backend
            client = OpenAI(base_url=os.environ.get("OPENAI_COMPAT_BASE_URL",
                                                    "http://localhost:11434/v1"),
                            api_key=os.environ.get("OPENAI_COMPAT_API_KEY", "unused"),
                            timeout=REQUEST_TIMEOUT, max_retries=MAX_RETRIES)
        self.client = client

    def conversation(self, system: str, tools: list[dict],
                     cache: bool = False) -> OpenAICompatConversation:
        return OpenAICompatConversation(self, system, tools)


def make_backend(model: str, effort: str | None = None,
                 temperature: float | None = None):
    if model.startswith("openai-compat:"):
        return OpenAICompatBackend(model.split(":", 1)[1],
                                   0.0 if temperature is None else temperature)
    return AnthropicBackend(model, effort)
