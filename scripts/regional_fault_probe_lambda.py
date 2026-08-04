"""Fail-closed probe boundary for the Regional dependency-fault workflow.

The Step Functions workflow invokes this handler before any lock, watchdog or
IAM mutation and again around the bounded fault. Real provider probes are a
separate implementation tranche. Until those probes exist, this module always
rejects execution after validating the complete authority. This deliberate
gate makes the orchestration deployable without making synthetic flags or
operator assertions equivalent to dependency evidence.
"""

from __future__ import annotations

from typing import Any

from scripts.regional_fault_controller_lambda import (
    RegionalFaultControllerError,
    _parse_event,
)


class RegionalFaultProbeError(RuntimeError):
    """Report that real target-only probe evidence is unavailable."""


_FIELDS = {"schemaVersion", "phase", "manifest", "faultAuthority"}
_PHASES = {
    "preconditions",
    "dependency-unavailable",
    "execution-denied-no-bypass",
    "dependency-and-target-recovered",
}


def probe(event: object, *, now: int | None = None) -> dict[str, Any]:
    """Validate exact workflow authority and refuse synthetic probe evidence.

    This function has no provider clients and no environment-controlled bypass.
    A future implementation must replace each phase with independently observed
    AWS evidence and dedicated adversarial contract tests before returning a
    successful structured result.
    """
    if (
        not isinstance(event, dict)
        or set(event) != _FIELDS
        or event.get("schemaVersion") != 1
        or event.get("phase") not in _PHASES
    ):
        raise RegionalFaultProbeError("fault probe event schema is invalid")
    try:
        _, _, authority = _parse_event(
            {
                "schemaVersion": 1,
                "operation": "acquire",
                "manifest": event.get("manifest"),
                "faultAuthority": event.get("faultAuthority"),
            },
            now=now,
        )
    except RegionalFaultControllerError as error:
        raise RegionalFaultProbeError("fault probe authority is invalid") from error
    raise RegionalFaultProbeError(
        f"real target-only {authority.dependency} probe for {event['phase']} is not implemented"
    )


def handler(event: object, _context: object) -> dict[str, Any]:
    """AWS Lambda entry point that cannot currently authorize fault mutation."""
    return probe(event)
