"""Fail-closed contracts for the not-yet-implemented Regional provider probes."""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest


def _fixtures() -> Any:
    path = Path(__file__).with_name("test_regional_fault_controller_lambda.py")
    spec = importlib.util.spec_from_file_location("aai_regional_fault_fixtures", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "regional_fault_probe_lambda.py"
    spec = importlib.util.spec_from_file_location("aai_regional_fault_probe", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _event(phase: str = "preconditions") -> dict[str, Any]:
    fixtures = _fixtures()
    return {
        "schemaVersion": 1,
        "phase": phase,
        "manifest": fixtures._manifest(),
        "faultAuthority": fixtures._authority("dynamodb"),
    }


@pytest.mark.parametrize(
    "phase",
    [
        "preconditions",
        "dependency-unavailable",
        "execution-denied-no-bypass",
        "dependency-and-target-recovered",
    ],
)
def test_every_probe_phase_validates_authority_then_fails_closed(phase: str) -> None:
    module = _load()
    with pytest.raises(module.RegionalFaultProbeError, match=f"dynamodb probe for {phase}"):
        module.probe(_event(phase), now=1000)


def test_unknown_phase_and_fields_fail_before_authority_interpretation() -> None:
    module = _load()
    with pytest.raises(module.RegionalFaultProbeError, match="schema"):
        module.probe(_event("operator-confirmed"), now=1000)
    changed = _event() | {"probeSucceeded": True}
    with pytest.raises(module.RegionalFaultProbeError, match="schema"):
        module.probe(changed, now=1000)


def test_stale_or_substituted_authority_cannot_reach_a_probe() -> None:
    module = _load()
    changed = copy.deepcopy(_event())
    changed["faultAuthority"]["targetCellRole"] = "primary"
    with pytest.raises(module.RegionalFaultProbeError, match="authority"):
        module.probe(changed, now=1000)
