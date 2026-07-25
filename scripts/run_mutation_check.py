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

BASELINE = Path("mutation-baseline.json")
RESULTS = Path(".mutmut-cache/results.txt")
EVIDENCE = Path(".mutmut-cache/evidence.json")


def write_evidence(**values: object) -> None:
    """Write a complete machine-readable result, including failure outcomes."""
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    temporary = EVIDENCE.with_suffix(".tmp")
    temporary.write_text(
        json.dumps({"schema": 1, **values}, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(EVIDENCE)


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
        write_evidence(
            **evidence_context,
            status="failed",
            reason="mutmut_nonzero",
            started_at=started_at.isoformat(),
        )
        print("mutmut did not complete successfully; threshold not proven.")
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
    RESULTS.write_text(existing + "\n" + output, encoding="utf-8")
    statuses = re.findall(
        r":\s*(killed|survived|timeout|not checked|suspicious|skipped)$", output, re.I | re.M
    )
    if not statuses:
        write_evidence(
            **evidence_context,
            status="failed",
            reason="unparseable_results",
            started_at=started_at.isoformat(),
        )
        print("Mutation results did not contain a parseable killed/total summary.")
        print(output[-2000:])
        return 1
    killed = sum(status.lower() == "killed" for status in statuses)
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
    disallowed = [status for status in statuses if status.lower() != "killed"]
    status = "passed" if total and percentage >= required else "failed"
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
        results_sha256=hashlib.sha256(RESULTS.read_bytes()).hexdigest(),
    )
    print(f"Mutation score: {killed}/{total} killed ({percentage:.1f}%), required {required:.1f}%.")
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
