"""Thread-safe step and rate budgets."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock


@dataclass(frozen=True, slots=True)
class Budget:
    """Limits for one task."""

    max_actions: int = 20
    max_concurrent: int = 1


class BudgetState:
    """Atomic action counter and concurrency limiter."""

    def __init__(self, budget: Budget) -> None:
        """Create a state object for ``budget``."""
        if budget.max_actions <= 0 or budget.max_concurrent <= 0:
            raise ValueError("budget limits must be positive")
        self.budget = budget
        self._actions = 0
        self._active = 0
        self._lock = Lock()

    def acquire(self) -> bool:
        """Atomically reserve one action slot, returning ``False`` if exhausted."""
        with self._lock:
            if (
                self._actions >= self.budget.max_actions
                or self._active >= self.budget.max_concurrent
            ):
                return False
            self._actions += 1
            self._active += 1
            return True

    def release(self) -> None:
        """Release an active slot after execution or denial handling."""
        with self._lock:
            self._active -= 1

    @property
    def actions(self) -> int:
        """Return the number of action attempts consumed."""
        with self._lock:
            return self._actions
