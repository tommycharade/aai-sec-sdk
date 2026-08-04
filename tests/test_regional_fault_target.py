"""Adversarial contracts for target-role Regional provider canaries."""

import importlib.util
from pathlib import Path
from typing import Any

import pytest

PATH = (
    Path(__file__).parents[1]
    / "infra"
    / "aws-control-plane"
    / "lambda"
    / "regional_fault_target.py"
)
SPEC = importlib.util.spec_from_file_location("regional_fault_target", PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def event(
    dependency: str = "audit", phase: str = "dependency-and-target-recovered"
) -> dict[str, Any]:
    """Return one valid synthetic internal event."""
    return {
        "source": "aai.regional-fault-target-probe",
        "schemaVersion": 1,
        "phase": phase,
        "faultId": "11111111-1111-4111-8111-111111111111",
        "authoritySha256": "a" * 64,
        "dependency": dependency,
    }


class Client:
    """Record bounded provider calls or raise one configured error."""

    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.error = error

    def __getattr__(self, name: str) -> Any:
        def call(**kwargs: Any) -> dict[str, Any]:
            self.calls.append((name, kwargs))
            if self.error:
                raise self.error
            return {}

        return call


class Denied(Exception):
    """Synthetic AWS access denial with no sensitive message dependency."""

    response = {"Error": {"Code": "AccessDeniedException"}}


@pytest.fixture(autouse=True)
def environment(monkeypatch: Any) -> None:
    """Install only synthetic deployment-owned resource identities."""
    values = {
        "AUDIT_BUCKET": "synthetic-audit",
        "CONTROL_TABLE": "SyntheticControl",
        "PRESENCE_TABLE": "SyntheticPresence",
        "IDEMPOTENCY_TABLE": "SyntheticIdempotency",
        "SCIM_TABLE": "SyntheticScim",
        "POLICY_SIGNING_KEY_ARN": "arn:aws:kms:eu-west-2:111111111111:key/mrk-" + "a" * 32,
        "REGIONAL_FAULT_CANARY_QUEUE_URL": "https://sqs.eu-west-2.amazonaws.com/111111111111/canary",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


@pytest.mark.parametrize(
    ("dependency", "client_name", "operations"),
    [("audit", "s3", 1), ("dynamodb", "dynamodb", 4), ("kms", "kms", 2), ("queue", "sqs", 1)],
)
def test_real_provider_canaries_return_content_free_evidence(
    dependency: str, client_name: str, operations: int
) -> None:
    client = Client()
    result = module.run(event(dependency), clients={client_name: client})
    assert result["providerStatus"] == "available"
    assert result["operationCount"] == operations
    assert len(result["evidenceSha256"]) == 64
    assert "errorCode" not in result
    assert len(client.calls) == operations


def test_access_denial_is_observed_without_provider_message() -> None:
    result = module.run(
        event("audit", "dependency-unavailable"), clients={"s3": Client(Denied("secret"))}
    )
    assert result["providerStatus"] == "denied"
    assert result["errorCode"] == "AccessDeniedException"
    assert "secret" not in str(result)


@pytest.mark.parametrize(
    "change",
    [
        {"source": "browser"},
        {"dependency": "cognito"},
        {"phase": "pretend-success"},
        {"authoritySha256": "bad"},
        {"extra": True},
    ],
)
def test_untrusted_or_unsupported_events_fail_before_provider_access(
    change: dict[str, Any],
) -> None:
    value = event()
    value.update(change)
    client = Client()
    with pytest.raises(module.RegionalFaultTargetError):
        module.run(value, clients={"s3": client})
    assert client.calls == []


def test_non_access_provider_failure_escapes_fail_closed() -> None:
    with pytest.raises(RuntimeError, match="synthetic outage"):
        module.run(event("queue"), clients={"sqs": Client(RuntimeError("synthetic outage"))})


def test_missing_aws_runtime_fails_closed(monkeypatch: Any) -> None:
    """Local environments cannot silently replace an unavailable AWS provider."""
    monkeypatch.setattr(module, "boto3", None)
    with pytest.raises(module.RegionalFaultTargetError, match="provider is unavailable"):
        module.run(event("audit"))
