"""Keep provider-neutral and AWS native-control conflict analysis identical."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_generated_aws_native_control_analyzer_is_current() -> None:
    """Fail CI when the deployment copy drifts from the SDK source."""
    path = ROOT / "scripts/generate_aws_native_control_conflicts.py"
    specification = importlib.util.spec_from_file_location("native_conflict_generator", path)
    assert specification is not None and specification.loader is not None
    generator = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(generator)
    target = ROOT / "infra/aws-control-plane/lambda/native_control_conflicts.py"
    assert target.read_text(encoding="utf-8") == generator.rendered()
