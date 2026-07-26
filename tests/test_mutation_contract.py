"""Negative controls for commit-bound mutation evidence."""

from __future__ import annotations

from typing import Any

import pytest
from scripts.run_mutation_check import status_diagnostics
from scripts.verify_mutation_evidence import validate_negative_controls


def _evidence(**controls: Any) -> dict[str, object]:
    return {
        "commit": "commit:test",
        "workspace_sha256": "sha:test",
        "negative_controls": {
            "commit_binding_present": True,
            "disallowed_statuses_fail": True,
            "component_thresholds_fail": True,
            "critical_mutants_fail": True,
            **controls,
        },
    }


def test_mutation_negative_controls_reject_stale_commit() -> None:
    with pytest.raises(ValueError, match="commit binding"):
        validate_negative_controls(_evidence(), "# mutation_commit=old\n", "commit:test")


def test_mutation_negative_controls_reject_disallowed_statuses() -> None:
    with pytest.raises(ValueError, match="negative control"):
        validate_negative_controls(
            _evidence(disallowed_statuses_fail=False),
            "# mutation_commit=commit:test workspace_sha256=sha:test\n",
            "commit:test",
        )


def test_mutation_negative_controls_reject_missing_critical_proof() -> None:
    with pytest.raises(ValueError, match="negative control"):
        validate_negative_controls(
            _evidence(critical_mutants_fail=False),
            "# mutation_commit=commit:test workspace_sha256=sha:test\n",
            "commit:test",
        )


def test_mutation_diagnostics_preserve_exact_incomplete_targets() -> None:
    """Execution gaps remain explicit evidence, never implicit exclusions."""
    diagnostics = status_diagnostics(
        [
            ("runtime.mutant:1", "not checked"),
            ("runtime.mutant:2", "timeout"),
            ("runtime.mutant:3", "killed"),
        ]
    )
    assert diagnostics["not_checked_targets"] == ["runtime.mutant:1"]
    assert diagnostics["timeout_targets"] == ["runtime.mutant:2"]
    assert diagnostics["status_counts"] == {"killed": 1, "timeout": 1, "not checked": 1}
