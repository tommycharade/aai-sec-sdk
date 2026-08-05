"""Static SDK/native policy conflict analysis and activation-gate tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agentic_security import (
    EnterpriseFleetStore,
    FleetConflictError,
    FleetIdentity,
    NativeControlAnalysisError,
    analyze_native_control_conflicts,
)


def _identity(subject: str) -> FleetIdentity:
    """Create one synthetic administrator for lifecycle tests."""
    return FleetIdentity(subject, "org-test", frozenset({"admin"}), frozenset())


def _approved_version(
    store: EnterpriseFleetStore, configuration: dict[str, Any]
) -> tuple[FleetIdentity, int]:
    """Create and independently approve one synthetic policy version."""
    author, reviewer = _identity("author-test"), _identity("reviewer-test")
    store.create_organization("org-test", "Test")
    created = store.create_policy(
        author,
        policy_id="policy-native-test",
        name="Native test",
        configuration=configuration,
    )
    version = int(created["latestVersion"])
    store.submit_policy_version(author, "policy-native-test", version)
    store.decide_policy_version(
        reviewer,
        "policy-native-test",
        version,
        decision="approved",
        reason="Synthetic independent review",
    )
    return reviewer, version


def test_analysis_reports_clear_policy_for_both_supported_hosts() -> None:
    """Aligned controls are clear without pretending endpoints were inspected."""
    result = analyze_native_control_conflicts(
        {
            "tools": {"builtIn": ["Read"], "fileTools": ["Read"]},
            "claudeCode": {
                "enabled": True,
                "allowedBuiltInTools": ["Read"],
                "fileTools": ["Read"],
                "allowedCommandPatterns": [r"^git status$"],
                "approvalCommandPatterns": [],
                "deniedCommandPatterns": [r"^git push"],
            },
        }
    ).to_dict()

    assert result["status"] == "clear"
    assert result["blockingCount"] == result["warningCount"] == 0
    assert result["evaluatedHosts"] == ["claude-code", "codex-cli"]
    assert result["endpointVerification"] == "required-after-activation"
    assert len(result["configurationSha256"]) == 64


def test_analysis_explains_blockers_without_echoing_sensitive_expressions() -> None:
    """Contradictions are fixed-content findings and raw patterns stay private."""
    secret_pattern = r"^deploy --token synthetic-sensitive-value$"  # noqa: S105
    result = analyze_native_control_conflicts(
        {
            "tools": {"builtIn": ["Read"]},
            "claudeCode": {
                "enabled": True,
                "allowedBuiltInTools": ["Read", "Bash"],
                "allowedCommandPatterns": [secret_pattern],
                "approvalCommandPatterns": [secret_pattern],
            },
            "managedHost": {"host": "claude-code"},
        }
    ).to_dict()

    assert result["status"] == "blocked"
    assert result["blockingCount"] == 2
    assert {item["code"] for item in result["conflicts"]} == {
        "command-decision-conflict",
        "native-authority-exceeds-sdk",
    }
    assert result["evaluatedHosts"] == ["claude-code"]
    assert secret_pattern not in str(result)
    assert "synthetic-sensitive-value" not in str(result)


def test_analysis_marks_inoperative_restrictions_as_warnings() -> None:
    """A stricter native layer is visible but does not weaken authority."""
    result = analyze_native_control_conflicts(
        {
            "tools": {"builtIn": ["Read", "Write"], "fileTools": ["Read", "Write"]},
            "claudeCode": {
                "enabled": True,
                "allowedBuiltInTools": ["Read"],
                "fileTools": ["Read"],
            },
        }
    )

    assert result.status == "warning"
    assert result.blocking_count == 0
    assert result.warning_count == 2
    assert {item.code for item in result.conflicts} == {
        "sdk-tool-unavailable-natively",
        "sdk-file-tool-unavailable-natively",
    }
    assert {item.host for item in result.conflicts} == {"shared"}


@pytest.mark.parametrize(
    "configuration",
    [
        {"claudeCode": {"allowedBuiltInTools": "Read"}},
        {"managedHost": {"host": "unsupported-agent"}},
        {"claudeCode": {"allowedCommandPatterns": [""]}},
    ],
)
def test_analysis_rejects_ambiguous_input(configuration: dict[str, Any]) -> None:
    """Malformed policy cannot receive a misleading compatibility result."""
    with pytest.raises(NativeControlAnalysisError):
        analyze_native_control_conflicts(configuration)


def test_staging_recomputes_and_blocks_native_control_conflicts(tmp_path: Path) -> None:
    """A browser cannot stage contradictory policy after approval."""
    store = EnterpriseFleetStore(tmp_path / "native-conflicts.sqlite")
    reviewer, version = _approved_version(
        store,
        {
            "tools": {"builtIn": ["Read"]},
            "claudeCode": {"enabled": True, "allowedBuiltInTools": ["Read", "Bash"]},
        },
    )

    view = store.policy_version(reviewer, "policy-native-test", version)
    assert view["nativeControlAnalysis"]["status"] == "blocked"
    with pytest.raises(FleetConflictError, match="native-control conflicts"):
        store.stage_policy_version(reviewer, "policy-native-test", version)


def test_activation_rechecks_native_conflicts_instead_of_trusting_prior_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Final activation independently enforces the immutable candidate content."""
    store = EnterpriseFleetStore(tmp_path / "native-recheck.sqlite")
    reviewer, version = _approved_version(
        store,
        {
            "tools": {"builtIn": ["Read"]},
            "claudeCode": {"enabled": True, "allowedBuiltInTools": ["Read"]},
        },
    )
    store.stage_policy_version(reviewer, "policy-native-test", version)
    original = store._assert_native_control_compatibility
    calls = 0

    def counted(configuration: dict[str, Any]) -> None:
        nonlocal calls
        calls += 1
        original(configuration)

    monkeypatch.setattr(store, "_assert_native_control_compatibility", counted)
    active = store.activate_policy_version(
        reviewer,
        "policy-native-test",
        version,
        expected_active_version=0,
    )

    assert active["version"] == 1
    assert calls == 1
