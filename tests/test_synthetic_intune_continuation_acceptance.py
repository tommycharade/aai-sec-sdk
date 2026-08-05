"""Acceptance contracts for the synthetic 500-target Intune harness."""

from __future__ import annotations

import importlib.util
import json
import stat
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def acceptance() -> Any:
    """Load the standalone harness without adding scripts to the package API."""
    path = Path(__file__).parents[1] / "scripts/run_synthetic_intune_continuation_acceptance.py"
    spec = importlib.util.spec_from_file_location("synthetic_intune_acceptance", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_maximum_cohort_converges_with_bounded_real_worker_steps(acceptance: Any) -> None:
    """Five hundred desired and 81 stale devices converge without an oversized step."""
    evidence = acceptance.run_acceptance(500, 81)

    assert evidence["liveProviderAcceptance"] is False
    assert evidence["pageCount"] == 13
    assert evidence["invocationCount"] == 16
    assert evidence["continuationCount"] == 15
    assert evidence["authorityReloadCount"] == 599
    assert evidence["membershipAdditionCount"] == 500
    assert evidence["membershipRemovalCount"] == 81
    assert evidence["assignmentMutationCount"] == 1
    assert evidence["maximumObservedMutationsPerInvocation"] == 40
    assert evidence["terminalStatus"] == "assigned_reported"
    assert evidence["continuationRevision"] == 15
    assert all(evidence["invariants"].values())
    assert evidence["limitations"] == [
        "in_memory_graph_contract",
        "no_live_microsoft_tenant",
        "no_network_or_cloud_capacity_measurement",
        "provider_assignment_is_not_runtime_attestation",
    ]


@pytest.mark.parametrize(
    ("target_count", "stale_member_count", "message"),
    [
        (40, 0, "target count"),
        (501, 0, "target count"),
        (41, -1, "stale-member count"),
        (41, 501, "stale-member count"),
        (True, 0, "target count"),
        (41, False, "stale-member count"),
    ],
)
def test_harness_fails_closed_outside_sealed_bounds(
    acceptance: Any, target_count: object, stale_member_count: object, message: str
) -> None:
    """Malformed or oversized scenarios cannot be relabelled as acceptance evidence."""
    with pytest.raises(ValueError, match=message):
        acceptance.run_acceptance(target_count, stale_member_count)


def test_cli_writes_content_minimised_private_evidence(
    acceptance: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The operator artifact is atomic, private, typed and explicitly synthetic."""
    output = tmp_path / "nested/evidence.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_synthetic_intune_continuation_acceptance.py",
            "--target-count",
            "41",
            "--stale-member-count",
            "0",
            "--output",
            str(output),
        ],
    )

    assert acceptance.main() == 0
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert evidence["evidenceKind"] == "synthetic_intune_continuation"
    assert evidence["liveProviderAcceptance"] is False
    assert evidence["targetCount"] == 41
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert not output.with_suffix(".json.tmp").exists()
