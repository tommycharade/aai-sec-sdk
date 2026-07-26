"""Verify that bounded mutation evidence belongs to this commit and scope."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tomllib
from pathlib import Path

try:
    from .mutation_context import target_metadata, workspace_digest
except ImportError:  # pragma: no cover - direct script execution
    from mutation_context import (  # type: ignore[import-not-found, no-redef]
        target_metadata,
        workspace_digest,
    )


def current_commit() -> str:
    """Return the checked-out commit used to bind evidence."""
    return subprocess.run(  # noqa: S603, S607 - fixed local git argv
        ["git", "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def validate_negative_controls(
    evidence: dict[str, object], raw_results: str, expected_commit: str
) -> None:
    """Reject evidence that omits the mutation runner's fail-closed controls."""
    controls = evidence.get("negative_controls")
    if not isinstance(controls, dict):
        raise ValueError("mutation negative controls are missing")
    if evidence.get("commit") != expected_commit:
        raise ValueError("mutation evidence commit binding failed")
    workspace_hash = evidence.get("workspace_sha256")
    if not isinstance(workspace_hash, str) or not raw_results.startswith(
        f"# mutation_commit={expected_commit} workspace_sha256={workspace_hash}\n"
    ):
        raise ValueError("mutation raw evidence commit binding failed")
    required_controls = (
        "commit_binding_present",
        "disallowed_statuses_fail",
        "component_thresholds_fail",
        "critical_mutants_fail",
    )
    if any(controls.get(control) is not True for control in required_controls):
        raise ValueError("mutation negative control failed")


def main() -> int:
    """Fail closed if mutation evidence is absent, stale, or inconsistent."""
    baseline = json.loads(Path("mutation-baseline.json").read_text(encoding="utf-8"))
    manifest = json.loads(Path(baseline["critical_manifest"]).read_text(encoding="utf-8"))
    evidence_path = Path(baseline["evidence_file"])
    results_path = Path(baseline["results_file"])
    if not evidence_path.is_file() or not results_path.is_file():
        raise ValueError("mutation evidence or results are missing")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    results = results_path.read_text(encoding="utf-8")
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    scope = project["tool"]["mutmut"]["only_mutate"]
    required = float(baseline["minimum_killed_percent"])
    component_required = float(baseline["minimum_component_killed_percent"])
    validate_negative_controls(evidence, results, current_commit())
    if evidence.get("workspace_sha256") != workspace_digest(baseline["source_scope"]):
        raise ValueError("mutation evidence worktree binding failed")
    if (
        evidence.get("status") != "passed"
        or evidence.get("tool") != baseline["tool"]
        or evidence.get("command") != baseline["command"]
        or evidence.get("commit") != current_commit()
        or evidence.get("source_scope") != scope
        or evidence.get("source_scope") != baseline["source_scope"]
        or float(evidence.get("required_percent", -1)) != required
        or evidence.get("disallowed_statuses")
        or not results.startswith(f"# mutation_commit={current_commit()} workspace_sha256=")
        or evidence.get("negative_controls", {}).get("commit_binding_present") is not True
        or evidence.get("negative_controls", {}).get("disallowed_statuses_fail") is not True
        or evidence.get("negative_controls", {}).get("component_thresholds_fail") is not True
        or evidence.get("negative_controls", {}).get("critical_mutants_fail") is not True
    ):
        raise ValueError("mutation evidence is stale, cross-commit, or scope-mismatched")
    killed = int(evidence.get("killed", -1))
    total = int(evidence.get("total", 0))
    score = float(evidence.get("score_percent", -1))
    if total <= 0 or killed < 0 or killed > total or score < required:
        raise ValueError("mutation evidence does not prove the required threshold")
    component_scores = evidence.get("component_scores", {})
    for name in baseline["components"]:
        component = component_scores.get(name, {})
        if (
            component.get("total", 0) <= 0
            or float(component.get("score_percent", -1)) < component_required
            or component.get("required_percent") != component_required
        ):
            raise ValueError(f"mutation component threshold not proven: {name}")
    critical = evidence.get("critical_mutants", {})
    if critical.get("total", 0) <= 0 or critical.get("killed") != critical.get("total"):
        raise ValueError("critical mutation threshold not proven")
    mappings = critical.get("mapping")
    manifest_ids = {
        item["id"] for item in manifest.get("critical_invariants", []) if isinstance(item, dict)
    }
    if not isinstance(mappings, list) or not mappings:
        raise ValueError("critical mutant mapping is missing")
    if critical.get("unmatched_symbols"):
        raise ValueError("critical manifest contains unmatched symbols")
    mapped_ids = {
        identifier for mapping in mappings for identifier in mapping.get("invariant_ids", [])
    }
    if mapped_ids != manifest_ids:
        raise ValueError("critical mutant mapping does not cover the manifest")
    if sum(mapping.get("status") == "killed" for mapping in mappings) != critical.get("killed"):
        raise ValueError("critical mutant mapping count is inconsistent")
    for mapping in mappings:
        if not isinstance(mapping, dict) or not isinstance(mapping.get("symbol"), str):
            raise ValueError("critical mutant mapping entry is malformed")
        expected = target_metadata(mapping["symbol"])
        for key in ("source", "source_span", "mutation_class", "fingerprint"):
            if mapping.get(key) != expected[key]:
                raise ValueError(f"critical mutation metadata is inconsistent: {key}")
    expected_score = round(100 * killed / total, 2)
    if (
        score != expected_score
        or evidence.get("results_sha256") != hashlib.sha256(results_path.read_bytes()).hexdigest()
    ):
        raise ValueError("mutation evidence result hash or score is invalid")
    print(
        f"Verified mutation evidence: {killed}/{total} ({score:.2f}%), "
        f"commit {evidence['commit']}, scope={len(scope)} files."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
