"""Run a bounded mutmut pass and enforce the repository mutation threshold."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from time import monotonic

BASELINE = Path("mutation-baseline.json")
RESULTS = Path(".mutmut-cache/results.txt")


def main() -> int:
    """Run mutmut for at most the declared budget and require the threshold."""
    import json

    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    subprocess.run([sys.executable, "scripts/check_mutation_baseline.py"], check=True)
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-m", "mutmut", "run", "--max-children", "2"]
    deadline = monotonic() + int(baseline["time_limit_seconds"])
    try:
        with RESULTS.open("w", encoding="utf-8") as stream:
            run_result = subprocess.run(  # noqa: S603 - fixed local mutmut argv
                command,
                stdout=stream,
                stderr=subprocess.STDOUT,
                timeout=max(0.1, deadline - monotonic()),
                check=False,
            )
    except subprocess.TimeoutExpired:
        print("Mutation run exceeded its bounded time limit; threshold not proven.")
        return 1
    if run_result.returncode != 0:
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
        print("Mutation result parsing exceeded its bounded time limit; threshold not proven.")
        return 1
    output = results.stdout + results.stderr
    RESULTS.write_text(RESULTS.read_text(encoding="utf-8") + "\n" + output, encoding="utf-8")
    statuses = re.findall(
        r":\s*(killed|survived|timeout|not checked|suspicious|skipped)$", output, re.I | re.M
    )
    if not statuses:
        print("Mutation results did not contain a parseable killed/total summary.")
        print(output[-2000:])
        return 1
    killed = sum(status.lower() == "killed" for status in statuses)
    total = len(statuses)
    percentage = 100.0 * killed / total if total else 0.0
    required = float(baseline["minimum_killed_percent"])
    print(f"Mutation score: {killed}/{total} killed ({percentage:.1f}%), required {required:.1f}%.")
    return 0 if total and percentage >= required else 1


if __name__ == "__main__":
    raise SystemExit(main())
