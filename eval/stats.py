"""
Statistics for the ablation tables. Pure Python, no scipy.

Each config cell is run R times. For a cell we report the MEDIAN over runs of a
metric, with a percentile bootstrap CI that resamples TEST CASES (the unit of
variation in the benchmark), recomputing the median-over-runs each time.

Paired comparisons between two cells use McNemar's exact test on per-case
outcomes. With repeated runs, each case's outcome is its majority vote across
runs (ties count as a miss), so stochastic noise doesn't inflate n. Effect sizes:
  risk difference   (rate_B - rate_A) on the paired cases
  odds ratio        b / c on the discordant pairs (Haldane +0.5 when one is 0)
  Cohen's g         b / (b + c) - 0.5
"""
from __future__ import annotations
import math
import random
from statistics import median


def _rate(outcomes: list[bool]) -> float:
    return sum(outcomes) / len(outcomes) if outcomes else 0.0


def case_metric(runs: list[dict[str, dict]], cases: list[str], metric: str) -> float:
    """Median over runs of a case-level metric restricted to `cases`.
    runs: list of {case_id: {"hit": bool, "fp": bool}}.
    metric: recall | fp_rate | precision | f1"""
    vals = []
    for r in runs:
        hits = sum(r[c]["hit"] for c in cases if c in r)
        fps = sum(r[c]["fp"] for c in cases if c in r)
        n = sum(1 for c in cases if c in r)
        if metric == "recall":
            vals.append(hits / n if n else 0.0)
        elif metric == "fp_rate":
            vals.append(fps / n if n else 0.0)
        elif metric == "precision":
            vals.append(hits / (hits + fps) if hits + fps else 0.0)
        elif metric == "f1":
            p = hits / (hits + fps) if hits + fps else 0.0
            rc = hits / n if n else 0.0
            vals.append(2 * p * rc / (p + rc) if p + rc else 0.0)
        else:
            raise ValueError(metric)
    return median(vals) if vals else 0.0


def bootstrap_ci(runs: list[dict[str, dict]], metric: str, n_boot: int = 2000,
                 alpha: float = 0.05, seed: int = 0) -> tuple[float, float, float]:
    """(point, lo, hi): median-over-runs point estimate and a case-resampling
    percentile CI."""
    cases = sorted(set().union(*[set(r) for r in runs])) if runs else []
    point = case_metric(runs, cases, metric)
    if not cases:
        return point, point, point
    rng = random.Random(seed)
    boots = []
    for _ in range(n_boot):
        sample = [rng.choice(cases) for _ in cases]
        boots.append(case_metric(runs, sample, metric))
    boots.sort()
    lo = boots[int((alpha / 2) * n_boot)]
    hi = boots[min(n_boot - 1, int((1 - alpha / 2) * n_boot))]
    return round(point, 4), round(lo, 4), round(hi, 4)


def majority(runs: list[dict[str, dict]], key: str) -> dict[str, bool]:
    """Per-case majority vote across runs; ties count as False."""
    out = {}
    for c in set().union(*[set(r) for r in runs]) if runs else set():
        votes = [r[c][key] for r in runs if c in r]
        out[c] = sum(votes) * 2 > len(votes)
    return out


def _binom_two_sided(k: int, n: int) -> float:
    """Exact two-sided binomial p-value for k successes in n trials, p=0.5."""
    if n == 0:
        return 1.0
    k = min(k, n - k)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def mcnemar(a: dict[str, bool], b: dict[str, bool]) -> dict:
    """Exact McNemar on paired binary outcomes (A vs B) over shared cases.
    b_only = cases where only B succeeds, a_only = only A succeeds."""
    shared = sorted(set(a) & set(b))
    a_only = sum(1 for c in shared if a[c] and not b[c])
    b_only = sum(1 for c in shared if b[c] and not a[c])
    n = a_only + b_only
    p = _binom_two_sided(b_only, n)
    if a_only == 0 or b_only == 0:
        odds = (b_only + 0.5) / (a_only + 0.5)
    else:
        odds = b_only / a_only
    rate_a = _rate([a[c] for c in shared])
    rate_b = _rate([b[c] for c in shared])
    return {"n_cases": len(shared), "a_only": a_only, "b_only": b_only,
            "p_value": round(p, 5), "odds_ratio": round(odds, 3),
            "cohens_g": round(b_only / n - 0.5, 3) if n else 0.0,
            "risk_diff": round(rate_b - rate_a, 4)}
