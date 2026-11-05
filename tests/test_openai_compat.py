"""OpenAI-compatible backend against hosted models, and the cross-model cascade."""
from types import SimpleNamespace as NS

import pytest

from auditor.agent import is_fatal_msg
from auditor.config import AuditConfig
from auditor.llm import OpenAICompatBackend
from auditor.pricing import PRICES, cost_usd
from eval.experiment import plan_cells, preflight


class BadRequestError(Exception):
    pass


def _reply(content="ok", finish="stop", **usage):
    return NS(choices=[NS(message=NS(content=content, tool_calls=None), finish_reason=finish)],
              usage=NS(prompt_tokens=10, completion_tokens=5, **usage))


def test_learns_rejected_params(capsys):
    """Newer hosted models 400 on max_tokens and temperature. Learn it once, keep
    working, and warn, since a dropped setting is no longer held fixed."""
    sent = []

    def create(**kw):
        sent.append(kw)
        for bad in ("max_tokens", "temperature"):
            if bad in kw:
                raise BadRequestError(f"Unsupported parameter: \'{bad}\'")
        return _reply()

    b = OpenAICompatBackend("gpt", temperature=0.0, effort="medium",
                            client=NS(chat=NS(completions=NS(create=create))))
    conv = b.conversation("", [])
    conv.user("hi")
    assert conv.step(100).text == "ok"
    assert sent[-1]["max_completion_tokens"] == 100 and sent[-1]["reasoning_effort"] == "medium"
    assert "temperature" not in sent[-1] and "max_tokens" not in sent[-1]
    assert "rejects temperature" in capsys.readouterr().err
    calls = len(sent)
    conv.step(100)
    assert len(sent) == calls + 1   # remembered, no second round of 400s


def test_other_400s_still_raise():
    def create(**kw):
        raise BadRequestError("context length exceeded")
    b = OpenAICompatBackend("gpt", client=NS(chat=NS(completions=NS(create=create))))
    conv = b.conversation("", [])
    conv.user("hi")
    with pytest.raises(BadRequestError):
        conv.step(100)


def test_cached_tokens_and_refusal():
    client = NS(chat=NS(completions=NS(create=lambda **kw: _reply(
        finish="content_filter", prompt_tokens_details=NS(cached_tokens=4)))))
    conv = OpenAICompatBackend("gpt", client=client).conversation("", [])
    conv.user("hi")
    r = conv.step(100)
    assert r.stop_reason == "refusal"
    assert r.usage["input"] == 6 and r.usage["cache_read"] == 4


def test_quota_error_is_fatal():
    assert is_fatal_msg("RateLimitError: Error code: 429 - {\'code\': \'insufficient_quota\'}")
    assert not is_fatal_msg("RateLimitError: Error code: 429 - slow down")


def test_hosted_model_is_unpriced_until_it_has_an_entry(monkeypatch):
    usage = {"input": 1_000_000}
    monkeypatch.delenv("OPENAI_COMPAT_BASE_URL", raising=False)
    assert cost_usd("openai-compat:qwen", usage) == 0.0
    monkeypatch.setenv("OPENAI_COMPAT_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("OPENAI_COMPAT_API_KEY", "x")
    assert cost_usd("openai-compat:gpt", usage) is None
    assert any("--max-usd" in p for p in preflight(["openai-compat:gpt"], max_usd=5.0))
    monkeypatch.setitem(PRICES, "gpt", (2.0, 8.0, 0.5))
    assert cost_usd("openai-compat:gpt", usage) == 2.0


def test_verifier_model_gets_its_own_validation_file():
    args = NS(validation=["plain"], evidence_sweep=False, factorial=False, configs=["C2"],
              models=["claude-haiku-5-5"], verifier_model="openai-compat:gpt-x")
    cell = plan_cells(args, AuditConfig())[0]
    assert cell["model"] == "claude-haiku-5-5"
    assert list(cell["validations"]) == ["val-plain@openai-compat_gpt-x"]
    assert cell["validations"]["val-plain@openai-compat_gpt-x"].model == "openai-compat:gpt-x"
