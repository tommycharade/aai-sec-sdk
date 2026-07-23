import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_guarded_runtime_example_runs() -> None:
    completed = subprocess.run(
        [sys.executable, "examples/guarded_runtime.py"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "status=<ExecutionStatus.EXECUTED: 'executed'>" in completed.stdout
    assert "status=<ExecutionStatus.DENIED: 'denied'>" in completed.stdout
    assert "audit chain valid: True" in completed.stdout
