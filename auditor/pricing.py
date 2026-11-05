"""
Dollar cost per call, for RO3 (cost-quality frontier).

Prices are USD per million tokens, first-party Anthropic API rates as of
2026-10. Re-check before you publish numbers: raw token counts are saved in every
run record, so dollars can always be recomputed with eval/report.py if a price
changes. Cache writes are billed at 1.25x input (5 minute TTL).

Open-weight models served locally cost $0 in API fees; set a price here if you
rent GPUs and want to amortize it. A hosted openai-compat model has no price until
it gets an entry here under its bare name (no "openai-compat:" prefix).
"""
from __future__ import annotations
import os
from urllib.parse import urlparse

# model: (input, output, cache_read)
PRICES = {
    "claude-fable-5-1": (10.00, 50.00, 0.25),
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-opus-5": (5.00, 25.00, 0.50),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20),
    "claude-sonnet-5": (2.00, 10.00, 0.20),
    "claude-sonnet-4-6": (3.00, 15.00, 0.30),
    "claude-haiku-5-5": (0.10, 0.50, 0.01),
    "claude-haiku-4-5": (1.00, 5.00, 0.10),
}
CACHE_WRITE_MULT = 1.25
BATCH_DISCOUNT = 0.5   # Message Batches bill every token at half price


def compat_server_is_local() -> bool:
    url = os.environ.get("OPENAI_COMPAT_BASE_URL", "http://localhost:11434/v1")
    return urlparse(url).hostname in ("localhost", "127.0.0.1", "::1")


def cost_usd(model: str, usage: dict) -> float | None:
    """usage keys: input, output, cache_read, cache_write. None if the model has
    no price entry (so an unknown model never silently shows as free)."""
    compat = model.startswith("openai-compat:")
    p = PRICES.get(model.split(":", 1)[1] if compat else model)
    if p is None:
        if compat:
            return 0.0 if compat_server_is_local() else None
        return 0.0 if model.startswith(("local:", "ollama:")) else None
    inp, out, cread = p
    return round((usage.get("input", 0) * inp
                  + usage.get("output", 0) * out
                  + usage.get("cache_read", 0) * cread
                  + usage.get("cache_write", 0) * inp * CACHE_WRITE_MULT) / 1e6, 6)


def records_cost(model: str, records: list[dict]) -> float | None:
    """Total for per-call records, each optionally carrying a price_mult (batch
    calls are half price). None if the model has no price."""
    total = 0.0
    for r in records:
        c = cost_usd(model, r.get("usage") or {})
        if c is None:
            return None
        total += c * r.get("price_mult", 1)
    return round(total, 6)
