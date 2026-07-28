"""Run a bounded mutmut pass and enforce the repository mutation threshold."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Any

try:
    from .mutation_context import target_metadata, workspace_digest
except ImportError:  # pragma: no cover - direct script execution
    from mutation_context import (  # type: ignore[import-not-found, no-redef]
        target_metadata,
        workspace_digest,
    )

BASELINE = Path("mutation-baseline.json")
RESULTS = Path(".mutmut-cache/results.txt")
EVIDENCE = Path(".mutmut-cache/evidence.json")
STATUS_PATTERN = re.compile(
    r"^(?P<target>.+?):\s*"
    r"(?P<status>killed|survived|timeout|not checked|suspicious|skipped)$",
    re.I | re.M,
)


def source_matches(target: str, source_path: str) -> bool:
    """Match mutmut's dotted module target to a configured source path."""
    module_name = Path(source_path).with_suffix("").as_posix().replace("/", ".")
    return (
        source_path in target or module_name in target or module_name.removeprefix("src.") in target
    )


def write_evidence(**values: object) -> None:
    """Write a complete machine-readable result, including failure outcomes."""
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    temporary = EVIDENCE.with_suffix(".tmp")
    temporary.write_text(
        json.dumps({"schema": 1, **values}, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(EVIDENCE)


def parse_records(output: str) -> list[tuple[str, str]]:
    """Parse every explicit mutmut status without treating missing rows as killed."""
    return [
        (match.group("target").strip(), match.group("status").lower())
        for match in STATUS_PATTERN.finditer(output)
    ]


def mutation_symbol(target: str) -> str:
    """Convert a mutmut target into an exact dotted module/class/method symbol."""
    target = target.strip()
    base = target.split("__mutmut_", 1)[0]
    module, encoded = base.split(".x", 1)
    if encoded.startswith("ǁ"):
        parts = encoded[1:].split("ǁ")
        if len(parts) != 2:
            raise ValueError(f"unrecognised class mutation target: {target}")
        return f"{module}.{parts[0]}.{parts[1]}"
    if not encoded.startswith("_"):
        raise ValueError(f"unrecognised module mutation target: {target}")
    return f"{module}.{encoded[1:]}"


def critical_manifest_symbols(manifest: dict[str, object]) -> dict[str, set[str]]:
    """Return exact symbol-to-invariant mappings from the reviewed manifest."""
    result: dict[str, set[str]] = {}
    raw_invariants = manifest.get("critical_invariants", [])
    if not isinstance(raw_invariants, list):
        raise ValueError("critical manifest invariants are not a list")
    for invariant in raw_invariants:
        if not isinstance(invariant, dict):
            raise ValueError("critical manifest contains a non-object invariant")
        identifier = invariant.get("id")
        symbols = invariant.get("symbols")
        if not isinstance(identifier, str) or not isinstance(symbols, list):
            raise ValueError("critical manifest invariant is malformed")
        for symbol in symbols:
            if not isinstance(symbol, str):
                raise ValueError("critical manifest symbol is not a string")
            result.setdefault(symbol, set()).add(identifier)
    return result


def status_diagnostics(records: list[tuple[str, str]]) -> dict[str, object]:
    """Return exact incomplete targets for execution/completion diagnosis."""
    return {
        "status_counts": {
            status: sum(value == status for _, value in records)
            for status in ("killed", "survived", "timeout", "not checked", "suspicious", "skipped")
            if any(value == status for _, value in records)
        },
        "not_checked_targets": [target for target, status in records if status == "not checked"],
        "timeout_targets": [target for target, status in records if status == "timeout"],
    }


def run_process(command: list[str], output: Any, timeout: float) -> int:
    """Run one command with a process-group timeout and return its exit code."""
    process = subprocess.Popen(  # noqa: S603 - fixed local tool argv
        command,
        stdout=output,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        return int(process.wait(timeout=timeout))
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise


def main() -> int:
    """Run mutmut for at most the declared budget and require the threshold."""
    import json

    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    critical_manifest = json.loads(Path(baseline["critical_manifest"]).read_text(encoding="utf-8"))
    subprocess.run([sys.executable, "scripts/check_mutation_baseline.py"], check=True)
    scope = list(baseline["source_scope"])
    commit = subprocess.run(  # noqa: S603, S607 - fixed local git argv
        ["git", "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    evidence_context = {
        "tool": baseline["tool"],
        "command": baseline["command"],
        "commit": commit,
        "source_scope": scope,
        "workspace_sha256": workspace_digest(scope),
    }
    # Mutmut keeps generated state outside the evidence file. Remove it so a
    # prior run cannot make a partial or stale result appear current.
    for generated in (Path("mutants"), RESULTS.parent):
        shutil.rmtree(generated, ignore_errors=True)
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    started_at = datetime.now(UTC)
    started_monotonic = monotonic()
    write_evidence(
        **evidence_context,
        status="running",
        started_at=started_at.isoformat(),
    )
    command = [sys.executable, "-m", "mutmut", "run", "--max-children", "2"]
    deadline = monotonic() + int(baseline["time_limit_seconds"])
    try:
        with RESULTS.open("w", encoding="utf-8") as stream:
            run_code = run_process(command, stream, max(0.1, deadline - monotonic()))
    except subprocess.TimeoutExpired:
        write_evidence(
            **evidence_context,
            status="failed",
            reason="mutation_timeout",
            started_at=started_at.isoformat(),
        )
        print("Mutation run exceeded its bounded time limit; threshold not proven.")
        return 1
    if run_code != 0:
        partial = ""
        try:
            partial_result = subprocess.run(
                [sys.executable, "-m", "mutmut", "results", "--all", "true"],
                capture_output=True,
                text=True,
                timeout=max(0.1, deadline - monotonic()),
                check=False,
            )
            partial = partial_result.stdout + partial_result.stderr
        except subprocess.TimeoutExpired:
            partial = "result collection timed out"
        partial_records = parse_records(partial)
        write_evidence(
            **evidence_context,
            status="failed",
            reason="mutmut_nonzero",
            started_at=started_at.isoformat(),
            runner_exit_code=run_code,
            runner_output_tail=RESULTS.read_text(encoding="utf-8")[-4000:],
            **status_diagnostics(partial_records),
        )
        runner_tail = RESULTS.read_text(encoding="utf-8")[-4000:]
        print("mutmut did not complete successfully; threshold not proven.")
        # Keep CI failures actionable without weakening the fail-closed gate.
        # The same bounded tail is retained in machine-readable evidence.
        if runner_tail:
            print("Mutation runner output (tail):")
            print(runner_tail)
        return 1

    try:
        results = subprocess.run(
            [sys.executable, "-m", "mutmut", "results", "--all", "true"],
            capture_output=True,
            text=True,
            timeout=max(0.1, deadline - monotonic()),
            check=False,
        )
    except subprocess.TimeoutExpired:
        write_evidence(
            **evidence_context,
            status="failed",
            reason="result_timeout",
            started_at=started_at.isoformat(),
        )
        print("Mutation result parsing exceeded its bounded time limit; threshold not proven.")
        return 1
    output = results.stdout + results.stderr
    existing = RESULTS.read_text(encoding="utf-8")
    if not output.endswith("\n") or not existing:
        write_evidence(
            **evidence_context,
            status="failed",
            reason="truncated_results",
            started_at=started_at.isoformat(),
        )
        print("Mutation results were missing or truncated; threshold not proven.")
        return 1
    # Mutmut owns the results file while it runs and may replace its initial
    # contents. Add the binding header only after the raw tool output exists.
    existing = (
        f"# mutation_commit={commit} workspace_sha256={evidence_context['workspace_sha256']}\n"
        f"{existing.lstrip()}"
    )
    RESULTS.write_text(existing + "\n" + output, encoding="utf-8")
    records = parse_records(output)
    if not records:
        write_evidence(
            **evidence_context,
            status="failed",
            reason="unparseable_results",
            started_at=started_at.isoformat(),
        )
        print("Mutation results did not contain a parseable killed/total summary.")
        print(output[-2000:])
        return 1
    statuses = [status for _, status in records]
    killed = sum(status == "killed" for status in statuses)
    total = len(statuses)
    percentage = 100.0 * killed / total if total else 0.0
    required = float(baseline["minimum_killed_percent"])
    current_commit = subprocess.run(  # noqa: S603, S607 - fixed local git argv
        ["git", "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if current_commit != commit:
        write_evidence(
            **evidence_context,
            status="failed",
            reason="commit_changed",
            started_at=started_at.isoformat(),
        )
        print("Mutation evidence was produced for a different commit; threshold not proven.")
        return 1
    # Surviving mutants are part of the aggregate score; execution gaps are
    # disallowed because they would make a score look stronger than it is.
    disallowed = [status for status in statuses if status not in {"killed", "survived"}]
    components = baseline["components"]
    component_scores: dict[str, dict[str, float | int | str]] = {}
    component_failure = False
    for name, paths in components.items():
        component_records = [
            record for record in records if any(source_matches(record[0], path) for path in paths)
        ]
        component_killed = sum(
            component_status == "killed" for _, component_status in component_records
        )
        component_total = len(component_records)
        component_score = 100.0 * component_killed / component_total if component_total else 0.0
        component_scores[name] = {
            "killed": component_killed,
            "total": component_total,
            "score_percent": round(component_score, 2),
            "required_percent": float(baseline["minimum_component_killed_percent"]),
        }
        if component_total == 0 or component_score < float(
            baseline["minimum_component_killed_percent"]
        ):
            component_failure = True
    manifest_symbols = critical_manifest_symbols(critical_manifest)
    critical_records: list[tuple[str, str, str, list[str]]] = []
    unmatched_symbols = set(manifest_symbols)
    for target, record_status in records:
        symbol = mutation_symbol(target)
        invariant_ids = sorted(manifest_symbols.get(symbol, set()))
        if invariant_ids:
            critical_records.append((target, record_status, symbol, invariant_ids))
            unmatched_symbols.discard(symbol)
    critical_failure = (
        not critical_records
        or bool(unmatched_symbols)
        or any(record_status != "killed" for _, record_status, _, _ in critical_records)
    )
    status = (
        "passed"
        if (
            total
            and percentage >= required
            and not disallowed
            and not component_failure
            and not critical_failure
        )
        else "failed"
    )
    write_evidence(
        **evidence_context,
        status=status,
        started_at=started_at.isoformat(),
        finished_at=datetime.now(UTC).isoformat(),
        elapsed_seconds=round(monotonic() - started_monotonic, 3),
        killed=killed,
        total=total,
        score_percent=round(percentage, 2),
        required_percent=required,
        disallowed_statuses=sorted(set(disallowed)),
        component_scores=component_scores,
        critical_mutants={
            "killed": sum(result_status == "killed" for _, result_status, _, _ in critical_records),
            "total": len(critical_records),
            "manifest_ids": sorted(
                {
                    identifier
                    for _, _, _, identifiers in critical_records
                    for identifier in identifiers
                }
            ),
            "unmatched_symbols": sorted(unmatched_symbols),
            "mapping": [
                {
                    "mutant_id": target,
                    "symbol": symbol,
                    "invariant_ids": identifiers,
                    "status": record_status,
                    **target_metadata(symbol),
                }
                for target, record_status, symbol, identifiers in critical_records
            ],
        },
        negative_controls={
            "disallowed_statuses_fail": not disallowed,
            "component_thresholds_fail": not component_failure,
            "critical_mutants_fail": not critical_failure,
            "commit_binding_present": existing.startswith(
                f"# mutation_commit={commit} "
                f"workspace_sha256={evidence_context['workspace_sha256']}\n"
            ),
        },
        results_sha256=hashlib.sha256(RESULTS.read_bytes()).hexdigest(),
    )
    print(f"Mutation score: {killed}/{total} killed ({percentage:.1f}%), required {required:.1f}%.")
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
