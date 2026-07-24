"""Thread-safe step and rate budgets."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from math import isfinite
from threading import Lock
from time import monotonic


@dataclass(frozen=True, slots=True)
class Budget:
    """Limits for one task."""

    max_actions: int = 20
    max_concurrent: int = 1
    max_fan_out: int = 1
    max_cost_units: int = 20
    max_delegation_depth: int = 1
    max_actions_per_second: float | None = None


class BudgetState:
    """Atomic action counter and concurrency limiter."""

    def __init__(self, budget: Budget) -> None:
        """Create a state object for ``budget``."""
        if (
            budget.max_actions <= 0
            or budget.max_concurrent <= 0
            or budget.max_fan_out <= 0
            or budget.max_cost_units <= 0
            or budget.max_delegation_depth <= 0
            or (
                budget.max_actions_per_second is not None
                and (
                    not isfinite(budget.max_actions_per_second)
                    or budget.max_actions_per_second <= 0
                )
            )
        ):
            raise ValueError("budget limits must be positive")
        self.budget = budget
        self._actions = 0
        self._active = 0
        self._fan_out = 0
        self._cost = 0
        self._timestamps: deque[float] = deque()
        self._lock = Lock()

    def acquire(self, cost_units: int = 1) -> bool:
        """Atomically reserve one action slot, returning ``False`` if exhausted."""
        if cost_units <= 0:
            return False
        with self._lock:
            now = monotonic()
            rate = self.budget.max_actions_per_second
            if rate is not None:
                while self._timestamps and now - self._timestamps[0] >= 1.0:
                    self._timestamps.popleft()
                if len(self._timestamps) >= rate:
                    return False
            if (
                self._actions >= self.budget.max_actions
                or self._active >= self.budget.max_concurrent
                or self._fan_out >= self.budget.max_fan_out
                or self._cost + cost_units > self.budget.max_cost_units
            ):
                return False
            self._actions += 1
            self._active += 1
            self._fan_out += 1
            self._cost += cost_units
            if rate is not None:
                self._timestamps.append(now)
            return True

    def release(self) -> None:
        """Release an active slot after execution or denial handling."""
        with self._lock:
            self._active -= 1
            self._fan_out -= 1

    @property
    def actions(self) -> int:
        """Return the number of action attempts consumed."""
        with self._lock:
            return self._actions
