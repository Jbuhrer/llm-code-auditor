"""
Dollar cost per call, for RO3 (cost-quality frontier).

Prices are USD per million tokens, first-party Anthropic API rates as of
2026-10. Re-check before you publish numbers: raw token counts are saved in every
run record, so dollars can always be recomputed with eval/report.py if a price
changes. Cache writes are billed at 1.25x input (5 minute TTL).

Open-weight models served locally cost $0 in API fees; set a price here if you
rent GPUs and want to amortize it.
"""
from __future__ import annotations

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


def cost_usd(model: str, usage: dict) -> float | None:
    """usage keys: input, output, cache_read, cache_write. None if the model has
    no price entry (so an unknown model never silently shows as free)."""
    p = PRICES.get(model)
    if p is None:
        return 0.0 if model.startswith(("local:", "ollama:", "openai-compat:")) else None
    inp, out, cread = p
    return round((usage.get("input", 0) * inp
                  + usage.get("output", 0) * out
                  + usage.get("cache_read", 0) * cread
                  + usage.get("cache_write", 0) * inp * CACHE_WRITE_MULT) / 1e6, 6)
