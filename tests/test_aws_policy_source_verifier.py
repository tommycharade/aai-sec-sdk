"""Contracts for the isolated AWS GitHub policy-source verifier Lambda."""

from __future__ import annotations

import base64
import importlib.util
import io
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
LAMBDA = ROOT / "infra/aws-control-plane/lambda"


class Secrets:
    """Synthetic Secrets Manager boundary retaining requested scope."""

    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []
        self.value: object = {"token": "synthetic-installation-token"}

    def get_secret_value(self, **kwargs: str) -> dict[str, str]:
        """Return one synthetic AWSCURRENT secret version."""
        self.calls.append(kwargs)
        return {"SecretString": json.dumps(self.value)}


class LambdaInvoker:
    """Synthetic exact-function invocation boundary for App token minting."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.value: object = {
            "schemaVersion": 1,
            "token": "synthetic-installation-token",
            "expiresAt": 1_800_003_600,
        }

    def invoke(self, **kwargs: object) -> dict[str, object]:
        """Return one bounded synthetic Lambda response stream."""
        self.calls.append(kwargs)
        return {"StatusCode": 200, "Payload": io.BytesIO(json.dumps(self.value).encode())}


def load_runtime(
    monkeypatch: pytest.MonkeyPatch, *, broker: bool = False
) -> tuple[Any, Secrets, LambdaInvoker]:
    """Load the standalone module with synthetic AWS and fixed deployment inputs."""
    secrets = Secrets()
    invoker = LambdaInvoker()
    boto3 = types.ModuleType("boto3")
    boto3.client = lambda service: invoker if service == "lambda" else secrets  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.syspath_prepend(str(LAMBDA))
    if broker:
        monkeypatch.delenv("POLICY_GITHUB_SECRET_ARN", raising=False)
        monkeypatch.setenv(
            "POLICY_GITHUB_TOKEN_BROKER_ARN",
            "arn:aws:lambda:eu-west-2:111122223333:function:policy-token-broker",
        )
    else:
        monkeypatch.delenv("POLICY_GITHUB_TOKEN_BROKER_ARN", raising=False)
        monkeypatch.setenv(
            "POLICY_GITHUB_SECRET_ARN",
            "arn:aws:secretsmanager:eu-west-2:111122223333:secret:policy-github",
        )
    monkeypatch.setenv(
        "POLICY_GITHUB_ALLOWED_REPOSITORIES",
        "github.com/example/security-policy",
    )
    specification = importlib.util.spec_from_file_location(
        "aws_policy_source_verifier_runtime", LAMBDA / "policy_source_verifier.py"
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module, secrets, invoker


def test_verifier_worker_returns_only_bounded_evidence_and_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The worker resolves its own token and returns no credential or authority."""
    runtime, secrets, _invoker = load_runtime(monkeypatch)
    content = b'{"schemaVersion":1}'

    class Verified:
        evidence_digest = "a" * 64

        def __init__(self) -> None:
            self.content = content

        def evidence(self) -> dict[str, object]:
            return {"provider": "github", "signatureVerified": True}

    class Verifier:
        def __init__(self, *, token_provider: Any, transport: Any, now: Any) -> None:
            assert token_provider() == "synthetic-installation-token"

        def verify(self, request: Any) -> Verified:
            assert request.commit_sha == "b" * 40
            return Verified()

    monkeypatch.setattr(runtime, "GitHubPolicySourceVerifier", Verifier)
    result = runtime.handler(
        {
            "repository": "github.com/example/security-policy",
            "commitSha": "b" * 40,
            "path": "policies/engineering.json",
        },
        None,
    )
    assert result == {
        "schemaVersion": 1,
        "evidence": {"provider": "github", "signatureVerified": True},
        "evidenceDigest": "a" * 64,
        "contentBase64": base64.b64encode(content).decode(),
    }
    assert secrets.calls == [
        {
            "SecretId": "arn:aws:secretsmanager:eu-west-2:111122223333:secret:policy-github",
            "VersionStage": "AWSCURRENT",
        }
    ]
    assert "token" not in json.dumps(result)


@pytest.mark.parametrize(
    "event",
    [
        {},
        {
            "repository": "github.com/other/repository",
            "commitSha": "b" * 40,
            "path": "policy.json",
        },
    ],
)
def test_verifier_worker_rejects_malformed_or_unapproved_repository(
    monkeypatch: pytest.MonkeyPatch, event: dict[str, object]
) -> None:
    """Browser locators cannot select a credential or an unapproved repository."""
    runtime, secrets, _invoker = load_runtime(monkeypatch)
    with pytest.raises(RuntimeError):
        runtime.handler(event, None)
    assert secrets.calls == []


def test_secret_schema_failure_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Malformed deployment secrets fail without leaking their value."""
    runtime, secrets, _invoker = load_runtime(monkeypatch)
    secrets.value = {"token": "synthetic", "unexpected": "must-not-escape"}
    with pytest.raises(Exception, match="credential is unavailable") as error:
        runtime._github_token()
    assert "must-not-escape" not in str(error.value)


def test_verifier_uses_only_the_exact_short_lived_broker_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """App private-key authority remains behind an exact Lambda invocation."""
    runtime, secrets, invoker = load_runtime(monkeypatch, broker=True)
    monkeypatch.setattr(runtime.time, "time", lambda: 1_800_000_000)
    assert runtime._github_token() == "synthetic-installation-token"
    assert secrets.calls == []
    assert invoker.calls == [
        {
            "FunctionName": "arn:aws:lambda:eu-west-2:111122223333:function:policy-token-broker",
            "InvocationType": "RequestResponse",
            "Payload": b'{"schemaVersion":1}',
        }
    ]


@pytest.mark.parametrize(
    "value",
    [
        {"schemaVersion": 1, "token": "synthetic-installation-token", "expiresAt": 1},
        {
            "schemaVersion": 1,
            "token": "synthetic-installation-token",
            "expiresAt": 1_800_003_600,
            "privateKeyPem": "must-not-escape",
        },
    ],
)
def test_verifier_rejects_expired_or_broadened_broker_responses(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    """A malformed broker response cannot become a provider credential."""
    runtime, _secrets, invoker = load_runtime(monkeypatch, broker=True)
    monkeypatch.setattr(runtime.time, "time", lambda: 1_800_000_000)
    invoker.value = value
    with pytest.raises(Exception, match="credential is unavailable") as error:
        runtime._github_token()
    assert "must-not-escape" not in str(error.value)


def test_aws_transport_bounds_response_and_preserves_final_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The deployment HTTP adapter returns exact status/origin and rejects size bombs."""
    runtime, _secrets, _invoker = load_runtime(monkeypatch)

    class Response:
        status = 200
        headers = {"Content-Type": "application/json"}

        def __init__(self, body: bytes) -> None:
            self.body = body

        def read(self, _limit: int) -> bytes:
            return self.body

        def geturl(self) -> str:
            return "https://api.github.com/example"

    class Opener:
        def __init__(self, body: bytes) -> None:
            self.body = body

        def open(self, request: Any, timeout: float) -> Response:
            assert timeout == 10.0
            return Response(self.body)

    transport = runtime.AwsGitHubHttpTransport(Opener(b"{}"))
    response = transport.get("https://api.github.com/example", headers={}, timeout_seconds=10.0)
    assert response.status == 200 and response.body == b"{}"
    oversized = runtime.AwsGitHubHttpTransport(Opener(b"x" * (2_097_152 + 1)))
    with pytest.raises(Exception, match="too large"):
        oversized.get("https://api.github.com/example", headers={}, timeout_seconds=10.0)
