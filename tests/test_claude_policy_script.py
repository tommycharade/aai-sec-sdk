from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from scripts.onboard_claude import onboard
from scripts.test_claude_policy import run


def _arguments(project_root: Path, *, allow_untested: bool) -> SimpleNamespace:
    """Build deterministic arguments for the local hook harness."""
    return SimpleNamespace(
        project_root=project_root,
        sdk_root=Path.cwd(),
        control_plane_url=None,
        operator_token=None,
        deployment_id=None,
        agent_id="claude-code-local",
        policy_id="policy-test-script",
        report=project_root / "report.json",
        keep_config=False,
        allow_untested=allow_untested,
    )


def test_local_policy_harness_exercises_hook_and_restores_policy(tmp_path: Path) -> None:
    """The harness tests native hook controls without leaving test policy state."""
    onboard(tmp_path, Path.cwd(), python="python3", dry_run=False)
    policy_path = tmp_path / ".claude/aai-sec-config.json"
    original = policy_path.read_bytes()

    assert run(_arguments(tmp_path, allow_untested=True)) == 0
    assert policy_path.read_bytes() == original
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["summary"]["failed"] == 0
    assert report["summary"]["passed"] >= 10
    assert not (tmp_path / ".claude/policy-test-audit.jsonl").exists()


def test_local_policy_harness_reports_runtime_coverage_gap(tmp_path: Path) -> None:
    """A hook-only run fails completeness unless untested controls are allowed."""
    onboard(tmp_path, Path.cwd(), python="python3", dry_run=False)

    assert run(_arguments(tmp_path, allow_untested=False)) == 2
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["summary"]["failed"] == 0
    assert report["summary"]["notTested"] >= 1
