#!/usr/bin/env python3
"""Run bounded regional load, dependency and consistency exercise probes.

The harness owns concurrency, cardinality, aggregation and fail-closed
acceptance. Provider adapters own only individual synthetic probes and return
typed observations; they cannot supply aggregate pass/fail assertions.
"""

from __future__ import annotations

import math
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Protocol


class RegionalRecoveryExerciseError(RuntimeError):
    """Raised when measured recovery behavior misses an acceptance gate."""


@dataclass(frozen=True)
class LoadObservation:
    """Measured latency and outcome for one unique synthetic agent."""

    agent_id: str
    heartbeat_ms: float
    policy_read_ms: float
    decision_write_ms: float
    succeeded: bool


@dataclass(frozen=True)
class DependencyObservation:
    """Measured execution posture while one named dependency is unavailable."""

    dependency: str
    failure_detected: bool
    execution_allowed: bool
    bypass_observed: bool
    recovery_passed: bool


@dataclass(frozen=True)
class ConsistencyObservation:
    """Measured authority result across one failover consistency boundary."""

    control: str
    passed: bool
    authority_widened: bool
    side_effect_count: int


class RecoveryExerciseAdapter(Protocol):
    """Provider-specific synthetic probe boundary used by the harness."""

    def measure_agent(self, agent_number: int) -> LoadObservation:
        """Measure heartbeat, policy read and decision write for one agent."""

    def exercise_dependency(self, dependency: str) -> DependencyObservation:
        """Inject one bounded dependency failure and measure fail-closed behavior."""

    def exercise_consistency(self, control: str) -> ConsistencyObservation:
        """Exercise one authority or replay control across the transition."""


_DEPENDENCIES = ("audit", "cognito", "dynamodb", "kms", "queue")
_CONSISTENCY_CONTROLS = (
    "approval",
    "audit",
    "identity",
    "idempotency",
    "policy",
)


def _measurement(value: object, label: str, maximum: float) -> float:
    """Return one finite non-negative measurement within a safety bound."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RegionalRecoveryExerciseError(f"{label} is not numeric")
    result = float(value)
    if not math.isfinite(result) or not 0 <= result <= maximum:
        raise RegionalRecoveryExerciseError(f"{label} exceeds the measurement bound")
    return result


def _p99(values: list[float]) -> float:
    """Return deterministic nearest-rank p99 for a non-empty population."""
    if not values:
        raise RegionalRecoveryExerciseError("load observations are empty")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.99 * len(ordered)) - 1)]


def run_load_exercise(
    adapter: RecoveryExerciseAdapter,
    *,
    target_fleet_size: int,
    max_workers: int = 64,
) -> dict[str, object]:
    """Measure every target agent with bounded concurrency and enforce SLOs."""
    if (
        isinstance(target_fleet_size, bool)
        or not isinstance(target_fleet_size, int)
        or not 1 <= target_fleet_size <= 100_000
        or isinstance(max_workers, bool)
        or not isinstance(max_workers, int)
        or not 1 <= max_workers <= 128
    ):
        raise RegionalRecoveryExerciseError("fleet size or concurrency is outside its bound")
    observations: list[LoadObservation] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(adapter.measure_agent, number): number
            for number in range(target_fleet_size)
        }
        for future in as_completed(futures):
            try:
                observation = future.result()
            except Exception as error:
                raise RegionalRecoveryExerciseError(
                    f"agent probe {futures[future]} failed"
                ) from error
            if not isinstance(observation, LoadObservation):
                raise RegionalRecoveryExerciseError("adapter returned an invalid load observation")
            observations.append(observation)
    agent_ids = [item.agent_id for item in observations]
    if (
        len(observations) != target_fleet_size
        or any(not isinstance(item, str) or not item or len(item) > 128 for item in agent_ids)
        or len(set(agent_ids)) != target_fleet_size
    ):
        raise RegionalRecoveryExerciseError("load observations do not identify the target fleet")
    heartbeat = [
        _measurement(item.heartbeat_ms, "heartbeat latency", 60_000) for item in observations
    ]
    policy = [
        _measurement(item.policy_read_ms, "policy-read latency", 60_000) for item in observations
    ]
    decisions = [
        _measurement(item.decision_write_ms, "decision-write latency", 60_000)
        for item in observations
    ]
    failures = sum(item.succeeded is not True for item in observations)
    error_rate = failures / target_fleet_size
    heartbeat_p99 = _p99(heartbeat)
    policy_p99 = _p99(policy)
    decision_p99 = _p99(decisions)
    result: dict[str, object] = {
        "simulatedAgents": target_fleet_size,
        "p99HeartbeatMs": heartbeat_p99,
        "p99PolicyReadMs": policy_p99,
        "p99DecisionWriteMs": decision_p99,
        "errorRate": error_rate,
    }
    if heartbeat_p99 > 1_000 or policy_p99 > 1_000 or decision_p99 > 2_000 or error_rate > 0.01:
        raise RegionalRecoveryExerciseError("measured target-fleet load misses its SLO")
    return result


def run_dependency_exercise(adapter: RecoveryExerciseAdapter) -> dict[str, object]:
    """Inject every required failure sequentially and require safe recovery."""
    try:
        observations = [adapter.exercise_dependency(name) for name in _DEPENDENCIES]
    except Exception as error:
        raise RegionalRecoveryExerciseError("dependency probe failed") from error
    if any(
        not isinstance(item, DependencyObservation)
        or item.dependency != expected
        or item.failure_detected is not True
        or item.execution_allowed is not False
        or item.bypass_observed is not False
        or item.recovery_passed is not True
        for item, expected in zip(observations, _DEPENDENCIES, strict=True)
    ):
        raise RegionalRecoveryExerciseError(
            "dependency failure did not fail closed and recover safely"
        )
    return {
        "testedDependencies": list(_DEPENDENCIES),
        "failClosedPassed": True,
        "bypassObserved": False,
        "recoveryPassed": True,
    }


def run_consistency_exercise(adapter: RecoveryExerciseAdapter) -> dict[str, object]:
    """Measure policy, identity, replay, idempotency and audit consistency."""
    try:
        observations = [adapter.exercise_consistency(name) for name in _CONSISTENCY_CONTROLS]
    except Exception as error:
        raise RegionalRecoveryExerciseError("authority consistency probe failed") from error
    for item, expected in zip(observations, _CONSISTENCY_CONTROLS, strict=True):
        if (
            not isinstance(item, ConsistencyObservation)
            or item.control != expected
            or item.passed is not True
            or item.authority_widened is not False
            or isinstance(item.side_effect_count, bool)
            or not isinstance(item.side_effect_count, int)
            or not 0 <= item.side_effect_count <= 1
        ):
            raise RegionalRecoveryExerciseError(f"authority consistency failed for {expected}")
    return {
        "policyPassed": True,
        "identityPassed": True,
        "approvalReplayDenied": True,
        "idempotencyReplaySafe": True,
        "auditPassed": True,
        "authorityWideningObserved": False,
    }


def run_exercise(
    adapter: RecoveryExerciseAdapter,
    *,
    target_fleet_size: int,
    max_workers: int = 64,
) -> dict[str, dict[str, object]]:
    """Run all measured P0-11 probes and return activation-bundle sections."""
    return {
        "load": run_load_exercise(
            adapter,
            target_fleet_size=target_fleet_size,
            max_workers=max_workers,
        ),
        "dependency": run_dependency_exercise(adapter),
        "consistency": run_consistency_exercise(adapter),
    }
