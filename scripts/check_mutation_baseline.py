"""Validate the checked-in mutation-testing enforcement contract."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path


def main() -> int:
    """Fail if the bounded mutation scope or threshold is incomplete."""
    value = json.loads(Path("mutation-baseline.json").read_text(encoding="utf-8"))
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    configured_scope = project.get("tool", {}).get("mutmut", {}).get("only_mutate")
    required = {
        "tool",
        "command",
        "time_limit_seconds",
        "security_branch_targets",
        "source_scope",
        "minimum_killed_percent",
        "results_file",
        "evidence_file",
    }
    missing = required - value.keys()
    valid = (
        not missing
        and value["tool"] == "mutmut"
        and 1 <= value["time_limit_seconds"] <= 120
        and 0 < value["minimum_killed_percent"] <= 100
        and bool(value["security_branch_targets"])
        and bool(value["source_scope"])
        and value["source_scope"] == configured_scope
        and str(value["results_file"]).endswith("results.txt")
        and str(value["evidence_file"]).endswith("evidence.json")
    )
    if not valid:
        print(f"Invalid mutation baseline: missing={sorted(missing)}")
        return 1
    print(
        "Mutation baseline is bounded; the runner must enforce "
        f"{value['minimum_killed_percent']}% killed mutants."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
