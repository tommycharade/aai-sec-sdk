"""Validate the checked-in mutation-testing enforcement contract."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path


def main() -> int:
    """Fail if the bounded mutation scope or threshold is incomplete."""
    value = json.loads(Path("mutation-baseline.json").read_text(encoding="utf-8"))
    manifest_path = Path(value.get("critical_manifest", ""))
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {}
    )
    invariants = manifest.get("critical_invariants", [])
    invariant_ids = [item.get("id") for item in invariants]
    manifest_symbols = [symbol for item in invariants for symbol in item.get("symbols", [])]
    static_contracts = manifest.get("static_contracts", [])
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
        and 1 <= value["time_limit_seconds"] <= 900
        and 0 < value["minimum_killed_percent"] <= 100
        and bool(value["security_branch_targets"])
        and bool(value["source_scope"])
        and value["source_scope"] == configured_scope
        and 75 <= value.get("minimum_component_killed_percent", 0) <= 100
        and isinstance(value.get("components"), dict)
        and all(
            isinstance(paths, list) and paths and set(paths).issubset(value["source_scope"])
            for paths in value["components"].values()
        )
        and manifest.get("schema") == 3
        and bool(invariants)
        and len(invariant_ids) == len(set(invariant_ids))
        and all(
            item.get("invariant")
            and item.get("symbols")
            and isinstance(item.get("test_ids"), list)
            and item["test_ids"]
            and item.get("required_kill_percent") == 100
            and all(
                isinstance(symbol, str) and symbol.count(".") >= 2 for symbol in item["symbols"]
            )
            for item in invariants
        )
        and len(manifest_symbols) == len(set(manifest_symbols))
        and isinstance(static_contracts, list)
        and all(
            isinstance(item, dict)
            and item.get("symbol")
            and item.get("reason")
            and isinstance(item.get("test_ids"), list)
            and item["test_ids"]
            for item in static_contracts
        )
        and not set(manifest_symbols).intersection(item.get("symbol") for item in static_contracts)
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
