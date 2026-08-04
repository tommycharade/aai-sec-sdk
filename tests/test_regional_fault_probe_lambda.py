"""Fail-closed contracts for independent Regional provider probes."""

from __future__ import annotations

import copy
import hashlib
import importlib
import importlib.util
import io
import json
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
    root = str(Path(__file__).parents[1])
    if root not in sys.path:
        sys.path.insert(0, root)
    return importlib.import_module("scripts.regional_fault_probe_lambda")


def _event(phase: str = "preconditions") -> dict[str, Any]:
    fixtures = _fixtures()
    return {
        "schemaVersion": 1,
        "phase": phase,
        "manifest": fixtures._manifest(),
        "faultAuthority": fixtures._authority("dynamodb"),
    }


def test_live_preconditions_are_required_and_return_independent_evidence(
    monkeypatch: Any,
) -> None:
    module = _load()

    class Boto:
        @staticmethod
        def client(service: str, *, region_name: str) -> tuple[str, str]:
            return service, region_name

    expected = {
        "schemaVersion": 1,
        "status": "verified-live-preconditions",
        "evidenceSha256": "b" * 64,
        "journalRevision": 4,
    }
    observed: dict[str, Any] = {}

    def verify(*args: Any, **kwargs: Any) -> dict[str, Any]:
        observed.update(kwargs)
        assert kwargs["client"]("route53", "eu-west-2") == ("route53", "eu-west-2")
        return expected

    monkeypatch.setattr(module, "boto3", Boto())
    monkeypatch.setattr(module.preconditions, "verify", verify)
    monkeypatch.setenv(
        "RECOVERY_FAULT_TARGET_FUNCTION_ARN",
        "arn:aws:lambda:eu-west-1:111111111111:function:AaiRecoveryHandler",
    )
    monkeypatch.setenv("FAULT_ROUTE53_HOSTED_ZONE_ID", "Z1234567890ABC")
    assert module.probe(_event(), now=1000) == expected
    assert observed["hosted_zone_id"] == "Z1234567890ABC"


def test_failed_live_preconditions_are_normalized(monkeypatch: Any) -> None:
    module = _load()
    monkeypatch.setattr(module, "boto3", object())
    monkeypatch.setenv("RECOVERY_FAULT_TARGET_FUNCTION_ARN", "synthetic-function")
    monkeypatch.setenv("FAULT_ROUTE53_HOSTED_ZONE_ID", "Z1234567890ABC")

    def reject(*_args: Any, **_kwargs: Any) -> None:
        raise module.preconditions.RegionalFaultPreconditionError("provider detail")

    monkeypatch.setattr(module.preconditions, "verify", reject)
    with pytest.raises(module.RegionalFaultProbeError, match="preconditions failed"):
        module.probe(_event(), now=1000)


@pytest.mark.parametrize(
    ("phase", "provider_status", "result_status"),
    [
        ("dependency-unavailable", "denied", "verified-target-provider-denied"),
        ("execution-denied-no-bypass", "denied", "verified-target-provider-denied"),
        ("dependency-and-target-recovered", "available", "verified-target-provider-recovered"),
    ],
)
def test_target_provider_observation_is_independently_verified(
    monkeypatch: Any, phase: str, provider_status: str, result_status: str
) -> None:
    module = _load()
    request = _event(phase)
    fixtures = _fixtures()
    authority = fixtures._authority("dynamodb")
    parsed = module._parse_event(
        {
            "schemaVersion": 1,
            "operation": "acquire",
            "manifest": fixtures._manifest(),
            "faultAuthority": authority,
        },
        now=1000,
    )[2]
    observed = {
        "authoritySha256": parsed.sha256(),
        "dependency": "dynamodb",
        "faultId": authority["faultId"],
        "operationCount": 0 if provider_status == "denied" else 4,
        "phase": phase,
        "providerStatus": provider_status,
    }
    if provider_status == "denied":
        observed["errorCode"] = "AccessDeniedException"
    observed["evidenceSha256"] = hashlib.sha256(
        json.dumps(observed, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    class Lambda:
        def invoke(self, **_kwargs: Any) -> dict[str, Any]:
            return {"StatusCode": 200, "Payload": io.BytesIO(json.dumps(observed).encode())}

    class Boto:
        @staticmethod
        def client(name: str, **_kwargs: Any) -> Lambda:
            assert name == "lambda"
            return Lambda()

    monkeypatch.setattr(module, "boto3", Boto())
    monkeypatch.setenv(
        "RECOVERY_FAULT_TARGET_FUNCTION_ARN",
        "arn:aws:lambda:eu-west-1:111111111111:function:AaiRecoveryHandler",
    )
    assert module.probe(request, now=1000)["status"] == result_status


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
