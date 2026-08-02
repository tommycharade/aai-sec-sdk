"""Adversarial tests for the bounded regional recovery exercise harness."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "run_regional_recovery_exercise.py"
    spec = importlib.util.spec_from_file_location("aai_recovery_exercise", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _Adapter:
    def __init__(self, module: Any) -> None:
        self.module = module
        self.load_updates: dict[str, Any] = {}
        self.dependency_updates: dict[str, Any] = {}
        self.consistency_updates: dict[str, Any] = {}

    def measure_agent(self, number: int) -> Any:
        values = {
            "agent_id": f"agent-{number}",
            "heartbeat_ms": 400,
            "policy_read_ms": 350,
            "decision_write_ms": 700,
            "succeeded": True,
            **self.load_updates,
        }
        return self.module.LoadObservation(**values)

    def exercise_dependency(self, dependency: str) -> Any:
        values = {
            "dependency": dependency,
            "failure_detected": True,
            "execution_allowed": False,
            "bypass_observed": False,
            "recovery_passed": True,
            **self.dependency_updates,
        }
        return self.module.DependencyObservation(**values)

    def exercise_consistency(self, control: str) -> Any:
        values = {
            "control": control,
            "passed": True,
            "authority_widened": False,
            "side_effect_count": 1,
            **self.consistency_updates,
        }
        return self.module.ConsistencyObservation(**values)


def test_complete_exercise_returns_activation_evidence_sections() -> None:
    module = _load()
    evidence = module.run_exercise(_Adapter(module), target_fleet_size=100, max_workers=8)
    assert evidence["load"] == {
        "simulatedAgents": 100,
        "p99HeartbeatMs": 400.0,
        "p99PolicyReadMs": 350.0,
        "p99DecisionWriteMs": 700.0,
        "errorRate": 0.0,
    }
    assert evidence["dependency"]["testedDependencies"] == [
        "audit",
        "cognito",
        "dynamodb",
        "kms",
        "queue",
    ]
    assert evidence["consistency"]["authorityWideningObserved"] is False


def test_load_requires_unique_complete_fleet() -> None:
    module = _load()
    adapter = _Adapter(module)
    adapter.load_updates = {"agent_id": "duplicate"}
    with pytest.raises(module.RegionalRecoveryExerciseError, match="target fleet"):
        module.run_load_exercise(adapter, target_fleet_size=10, max_workers=2)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"heartbeat_ms": 1001}, "misses its SLO"),
        ({"decision_write_ms": float("nan")}, "measurement bound"),
        ({"succeeded": False}, "misses its SLO"),
    ],
)
def test_load_fails_closed_on_latency_invalid_measurement_or_errors(
    updates: dict[str, Any], message: str
) -> None:
    module = _load()
    adapter = _Adapter(module)
    adapter.load_updates = updates
    with pytest.raises(module.RegionalRecoveryExerciseError, match=message):
        module.run_load_exercise(adapter, target_fleet_size=10, max_workers=2)


@pytest.mark.parametrize(
    "updates",
    [
        {"failure_detected": False},
        {"execution_allowed": True},
        {"bypass_observed": True},
        {"recovery_passed": False},
    ],
)
def test_each_dependency_failure_must_fail_closed_and_recover(
    updates: dict[str, Any],
) -> None:
    module = _load()
    adapter = _Adapter(module)
    adapter.dependency_updates = updates
    with pytest.raises(module.RegionalRecoveryExerciseError, match="dependency failure"):
        module.run_dependency_exercise(adapter)


@pytest.mark.parametrize(
    "updates",
    [
        {"passed": False},
        {"authority_widened": True},
        {"side_effect_count": 2},
        {"side_effect_count": True},
    ],
)
def test_consistency_never_accepts_replay_or_authority_widening(
    updates: dict[str, Any],
) -> None:
    module = _load()
    adapter = _Adapter(module)
    adapter.consistency_updates = updates
    with pytest.raises(module.RegionalRecoveryExerciseError, match="consistency failed"):
        module.run_consistency_exercise(adapter)


def test_adapter_exceptions_are_normalized_as_failed_exercises() -> None:
    module = _load()

    class FailingAdapter(_Adapter):
        def exercise_dependency(self, dependency: str) -> Any:
            raise TimeoutError("synthetic provider timeout")

    with pytest.raises(module.RegionalRecoveryExerciseError, match="probe failed"):
        module.run_dependency_exercise(FailingAdapter(module))
