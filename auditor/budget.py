"""
Dollar cap for one invocation of the runner.

Every finished unit or validation call reports its cost here. Once spending
reaches the cap, no new work starts; work already in flight finishes and is
saved, so a rerun with the same --out picks up where this one stopped.
Calls whose model has no price entry count as $0 and are flagged once.
"""
from __future__ import annotations
import threading


class BudgetExceeded(RuntimeError):
    pass


class Budget:
    def __init__(self, limit_usd: float | None):
        self.limit = limit_usd
        self.spent = 0.0
        self.unpriced = False
        self._lock = threading.Lock()

    def add(self, cost: float | None) -> None:
        with self._lock:
            if cost is None:
                self.unpriced = True
            else:
                self.spent += cost

    @property
    def exceeded(self) -> bool:
        return self.limit is not None and self.spent >= self.limit

    def check(self) -> None:
        if self.exceeded:
            raise BudgetExceeded(f"spent ${self.spent:.2f} of the ${self.limit:.2f} cap")

    def summary(self) -> str:
        cap = "no cap" if self.limit is None else f"cap ${self.limit:.2f}"
        note = " (some calls had no price entry and were counted as $0)" if self.unpriced else ""
        return f"spent ${self.spent:.2f} this invocation, {cap}{note}"
