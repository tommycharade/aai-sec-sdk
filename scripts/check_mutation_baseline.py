"""Validate the bounded mutation-testing contract without running mutations in CI."""

from __future__ import annotations

import json
from pathlib import Path


def main() -> int:
    """Fail if the checked-in mutation scope becomes incomplete or unbounded."""
    value = json.loads(Path("mutation-baseline.json").read_text(encoding="utf-8"))
    required = {"tool", "command", "time_limit_seconds", "security_branch_targets"}
    missing = required - value.keys()
    if missing or value["time_limit_seconds"] > 120 or not value["security_branch_targets"]:
        print(f"Invalid mutation baseline: missing={sorted(missing)}")
        return 1
    print("Mutation baseline is bounded and covers security branches.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
