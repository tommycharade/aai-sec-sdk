"""Verify that bounded mutation evidence belongs to this commit and scope."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tomllib
from pathlib import Path


def current_commit() -> str:
    """Return the checked-out commit used to bind evidence."""
    return subprocess.run(  # noqa: S603, S607 - fixed local git argv
        ["git", "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def main() -> int:
    """Fail closed if mutation evidence is absent, stale, or inconsistent."""
    baseline = json.loads(Path("mutation-baseline.json").read_text(encoding="utf-8"))
    evidence_path = Path(baseline["evidence_file"])
    results_path = Path(baseline["results_file"])
    if not evidence_path.is_file() or not results_path.is_file():
        raise ValueError("mutation evidence or results are missing")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    scope = project["tool"]["mutmut"]["only_mutate"]
    required = float(baseline["minimum_killed_percent"])
    if (
        evidence.get("status") != "passed"
        or evidence.get("tool") != baseline["tool"]
        or evidence.get("command") != baseline["command"]
        or evidence.get("commit") != current_commit()
        or evidence.get("source_scope") != scope
        or evidence.get("source_scope") != baseline["source_scope"]
        or float(evidence.get("required_percent", -1)) != required
    ):
        raise ValueError("mutation evidence is stale, cross-commit, or scope-mismatched")
    killed = int(evidence.get("killed", -1))
    total = int(evidence.get("total", 0))
    score = float(evidence.get("score_percent", -1))
    if total <= 0 or killed < 0 or killed > total or score < required:
        raise ValueError("mutation evidence does not prove the required threshold")
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
