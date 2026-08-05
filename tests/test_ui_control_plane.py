"""Contract and adversarial tests for the optional UI control plane."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import threading
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from agentic_security import (
    AgentHost,
    AgentPresenceStore,
    AgentSessionCredential,
    AgentSessionStore,
    AuditEvent,
    CallbackControlPlaneAuthority,
    ControlPlaneAgentClient,
    ControlPlaneApplication,
    ControlPlaneConfigurationError,
    ControlPlaneDecisionExporter,
    ControlPlaneDependencyError,
    ControlPlaneStore,
    InMemoryAuditSink,
    InMemoryControlPlaneAuthority,
    ManagedConfigurationCompiler,
    ManagedConfigurationEvidence,
    ManagedConfigurationSource,
    ManagedDeploymentPackage,
    ManagedExecutableRequirement,
    ManagedPlatform,
    ManagedPolicyIntent,
    NativeActionDecision,
    NativeActionRule,
    OperatorIdentity,
    PolicyTrustStore,
    RuntimeRemediationClient,
    RuntimeRemediationInstruction,
    StaticBearerAuthenticator,
    TrustedPolicyKey,
    canonical_policy_payload,
    validate_configuration,
)
from agentic_security.ui_control_plane import (
    _bool,
    _command,
    _endpoint,
    _native_action_digest,
    _number,
    _pattern,
    _positive_int,
    _text,
)

TOKEN = "synthetic-local-token-1234"  # noqa: S105 - synthetic test credential
POLICY_KEY_ID = "arn:aws:kms:eu-west-2:123456789012:key/12345678-1234-1234-1234-123456789abc"


def runtime_remediation_instruction_digest(item: dict[str, object]) -> str:
    """Independently reproduce the server's immutable instruction binding."""
    fields = (
        "schemaVersion",
        "deploymentId",
        "agentId",
        "host",
        "rolloutRevision",
        "rolloutState",
        "releaseId",
        "releaseTag",
        "sdkVersion",
        "sdkRevision",
        "manifestSha256",
        "releaseEvidenceSha256",
        "packageSha256",
        "gatewaySha256",
        "hookSha256",
    )
    return sha256(
        json.dumps(
            {field: item[field] for field in fields},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def signed_policy_fixture() -> tuple[dict[str, object], PolicyTrustStore]:
    """Return one synthetic AWS wire bundle and its pinned public trust."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    configuration = {"runtime": {"allowedTools": ["read_repository"]}}
    payload, content_hash = canonical_policy_payload(
        tenant_id="tenant-a",
        policy_id="policy-aws",
        version=3,
        configuration=configuration,
    )
    signature = private_key.sign(
        hashlib.sha256(payload).digest(),
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return (
        {
            "schemaVersion": 1,
            "tenantId": "tenant-a",
            "policyId": "policy-aws",
            "version": 3,
            "configuration": configuration,
            "contentHash": content_hash,
            "integrity": {
                "algorithm": "ECDSA_SHA_256",
                "keyId": POLICY_KEY_ID,
                "signature": base64.b64encode(signature).decode("ascii"),
                "signedAt": 1_786_000_000,
            },
        },
        PolicyTrustStore((TrustedPolicyKey(POLICY_KEY_ID, public_pem),)),
    )


def deployment_package(*, with_trust: bool = False) -> ManagedDeploymentPackage:
    """Build one canonical synthetic package for agent-client response tests."""
    hook_path = "/opt/aai-security/hooks/native-policy"
    bundle = ManagedConfigurationCompiler().compile(
        ManagedPolicyIntent(
            "policy-safe",
            1,
            action_rules=(NativeActionRule("Read", NativeActionDecision.ALLOW, "synthetic read"),),
        ),
        host=AgentHost.CLAUDE_CODE,
        host_version="2.1.220",
        platform=ManagedPlatform.LINUX,
        hook_command=hook_path,
    )
    return ManagedDeploymentPackage.from_bundle(
        bundle,
        required_executables=(
            ManagedExecutableRequirement(hook_path, hashlib.sha256(b"synthetic hook").hexdigest()),
        ),
        policy_trust_store=signed_policy_fixture()[1] if with_trust else None,
    )


def store(path: Path) -> ControlPlaneStore:
    """Create a fully bound synthetic store for mutation contract tests."""
    return ControlPlaneStore(
        path,
        authority=InMemoryControlPlaneAuthority(),
        audit=InMemoryAuditSink(),
    )


def request(
    app: ControlPlaneApplication,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    token: str | None = TOKEN,
) -> tuple[str, dict[str, Any]]:
    """Call the WSGI boundary with a synthetic authenticated request."""
    encoded = json.dumps(body).encode() if body is not None else b""
    status: list[str] = []

    def start_response(value: str, _headers: list[tuple[str, str]]) -> None:
        status.append(value)

    environ: dict[str, Any] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(encoded)),
        "wsgi.input": io.BytesIO(encoded),
    }
    if token is not None:
        environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    payload = b"".join(app(environ, start_response))
    return status[0], json.loads(payload or b"{}")


def test_control_plane_requires_bearer_authentication(tmp_path: Path) -> None:
    app = ControlPlaneApplication(store(tmp_path / "config.json"), TOKEN)

    status, payload = request(app, "GET", "/api/configuration", token=None)

    assert status.startswith("401")
    assert payload == {"error": "authentication required"}


def test_reference_authenticator_is_explicit_and_constant_time() -> None:
    identity = OperatorIdentity("operator-1", frozenset({"operator"}))
    with pytest.raises(ValueError):
        OperatorIdentity("", frozenset({"operator"}))
    with pytest.raises(ValueError):
        StaticBearerAuthenticator({"short": identity})

    authenticator = StaticBearerAuthenticator({TOKEN: identity})
    assert authenticator.authenticate("Basic anything") is None
    assert authenticator.authenticate(f"Bearer {TOKEN}") == identity
    assert authenticator.authenticate("Bearer wrong-token-1234") is None
    assert authenticator.authorize(identity, "read") is True
    assert authenticator.authorize(identity, "configure") is True
    assert authenticator.authorize(identity, "emergency_stop") is False
    assert authenticator.authorize(identity, "unknown") is False


def test_callback_authority_delegates_every_runtime_control() -> None:
    calls: list[str] = []
    authority = CallbackControlPlaneAuthority(
        apply_callback=lambda _configuration: calls.append("apply"),
        stop_callback=lambda: calls.append("stop"),
        clear_stop_callback=lambda: calls.append("clear"),
        status_callback=lambda: {"healthy": True},
    )

    authority.apply_configuration({})
    authority.emergency_stop()
    authority.clear_emergency_stop()
    assert authority.status() == {"healthy": True}
    assert calls == ["apply", "stop", "clear"]


def test_command_endpoint_and_pattern_validators_reject_unsafe_input() -> None:
    with pytest.raises(ControlPlaneConfigurationError):
        _endpoint("http://policy.example.test", "policyEndpoint")
    with pytest.raises(ControlPlaneConfigurationError):
        _endpoint("https://user:pass@policy.example.test", "policyEndpoint")
    with pytest.raises(ControlPlaneConfigurationError):
        _endpoint("", "policyEndpoint", required=True)
    with pytest.raises(ControlPlaneConfigurationError):
        _command("python 'unterminated", "hookCommand")
    with pytest.raises(ControlPlaneConfigurationError):
        _pattern(r"(a)\\1", "commandPattern")
    with pytest.raises(ControlPlaneConfigurationError):
        _pattern("x" * 257, "commandPattern")


def test_unbound_mutations_fail_closed_instead_of_claiming_runtime_control(
    tmp_path: Path,
) -> None:
    app = ControlPlaneApplication(ControlPlaneStore(tmp_path / "config.json"), TOKEN)
    _, configuration = request(app, "GET", "/api/configuration")

    status, payload = request(app, "PUT", "/api/configuration", configuration)

    assert status.startswith("503")
    assert "runtime authority" in payload["error"]


def test_operator_roles_separate_read_from_configuration_and_stop(tmp_path: Path) -> None:
    viewer_token = "viewer-session-token-1234"  # noqa: S105 - synthetic test credential
    app = ControlPlaneApplication(
        store(tmp_path / "config.json"),
        authenticator=StaticBearerAuthenticator(
            {viewer_token: OperatorIdentity("viewer-1", frozenset({"viewer"}))}
        ),
    )
    _, configuration = request(app, "GET", "/api/configuration", token=viewer_token)

    status, configure_payload = request(
        app, "PUT", "/api/configuration", configuration, token=viewer_token
    )
    stop_status, stop_payload = request(app, "POST", "/api/emergency-stop", token=viewer_token)

    assert configuration["configVersion"] == 1
    assert status.startswith("403") and configure_payload["error"] == "forbidden"
    assert stop_status.startswith("403") and stop_payload["error"] == "forbidden"


def test_authenticated_agent_registration_heartbeat_and_expiry_are_live_and_audited(
    tmp_path: Path,
) -> None:
    now = [100.0]
    audit = InMemoryAuditSink()
    presence = AgentPresenceStore(clock=lambda: now[0], ttl_seconds=10, audit=audit)
    agent_token = "agent-session-token-1234"  # noqa: S105 - synthetic test credential
    operator_token = "operator-session-token-1234"  # noqa: S105 - synthetic test credential
    app = ControlPlaneApplication(
        ControlPlaneStore(
            tmp_path / "config.json",
            authority=InMemoryControlPlaneAuthority(),
            audit=audit,
            presence=presence,
        ),
        authenticator=StaticBearerAuthenticator(
            {
                agent_token: OperatorIdentity("claude-code-local", frozenset({"agent"})),
                operator_token: OperatorIdentity("operator-1", frozenset({"viewer"})),
            }
        ),
    )

    status, registered = request(
        app,
        "POST",
        "/api/agents/register",
        {
            "agentId": "claude-code-local",
            "host": "claude-code",
            "projectRoot": "/workspace/kratos",
        },
        token=agent_token,
    )
    assert status.startswith("200")
    assert registered["status"] == "connected"
    session_id = registered["sessionId"]

    heartbeat_status, heartbeat = request(
        app,
        "POST",
        "/api/agents/claude-code-local/heartbeat",
        {"sessionId": session_id},
        token=agent_token,
    )
    assert heartbeat_status.startswith("200")
    assert heartbeat["sessionId"] == session_id

    dashboard_status, dashboard = request(app, "GET", "/api/dashboard", token=operator_token)
    assert dashboard_status.startswith("200")
    assert dashboard["agents"][0]["projectRoot"] == "/workspace/kratos"
    assert "sessionId" not in dashboard["agents"][0]

    now[0] = 111.0
    expired_status, expired = request(app, "GET", "/api/agents", token=operator_token)
    assert expired_status.startswith("200")
    assert expired["agents"][0]["status"] == "offline"
    assert [event.event_type for event in audit.events()] == [
        "agent_registered",
        "agent_heartbeat",
        "agent_disconnected",
    ]


def test_agent_registration_rejects_identity_mismatch_and_bad_heartbeat(
    tmp_path: Path,
) -> None:
    token = "agent-session-token-1234"  # noqa: S105 - synthetic test credential
    app = ControlPlaneApplication(
        ControlPlaneStore(
            tmp_path / "config.json",
            authority=InMemoryControlPlaneAuthority(),
            audit=InMemoryAuditSink(),
            presence=AgentPresenceStore(),
        ),
        authenticator=StaticBearerAuthenticator(
            {token: OperatorIdentity("claude-code-local", frozenset({"agent"}))}
        ),
    )
    status, payload = request(
        app,
        "POST",
        "/api/agents/register",
        {"agentId": "other-agent", "host": "claude-code", "projectRoot": "/workspace"},
        token=token,
    )
    assert status.startswith("400")
    assert "authenticated agent identity" in payload["error"]

    status, payload = request(
        app,
        "POST",
        "/api/agents/claude-code-local/heartbeat",
        {"sessionId": "not-a-session"},
        token=token,
    )
    assert status.startswith("400")
    assert "not connected" in payload["error"]


def test_agent_can_disconnect_explicitly_with_its_session(tmp_path: Path) -> None:
    token = "agent-session-token-1234"  # noqa: S105 - synthetic test credential
    app = ControlPlaneApplication(
        ControlPlaneStore(
            tmp_path / "config.json",
            authority=InMemoryControlPlaneAuthority(),
            audit=InMemoryAuditSink(),
            presence=AgentPresenceStore(),
        ),
        authenticator=StaticBearerAuthenticator(
            {token: OperatorIdentity("claude-code-local", frozenset({"agent"}))}
        ),
    )
    _, registered = request(
        app,
        "POST",
        "/api/agents/register",
        {
            "agentId": "claude-code-local",
            "host": "claude-code",
            "projectRoot": "/workspace",
        },
        token=token,
    )
    status, disconnected = request(
        app,
        "POST",
        "/api/agents/claude-code-local/disconnect",
        {"sessionId": registered["sessionId"]},
        token=token,
    )
    assert status.startswith("200")
    assert disconnected["status"] == "offline"


def test_agent_client_sends_bounded_authenticated_registration_and_heartbeat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agentic_security.ui_control_plane as control_plane

    requests: list[tuple[str, dict[str, str], dict[str, object]]] = []

    class Response:
        def __init__(self, payload: dict[str, object]) -> None:
            self.payload = json.dumps(payload).encode()

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return self.payload

    def fake_urlopen(request: Any, *, timeout: float, **_kwargs: Any) -> Response:
        requests.append((request.full_url, dict(request.headers), json.loads(request.data)))
        if request.full_url.endswith("/register"):
            return Response({"sessionId": "opaque-session"})
        return Response({"status": "connected"})

    monkeypatch.setattr(control_plane, "urlopen", fake_urlopen)
    client = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="claude-code-local",
        project_root="/workspace/kratos",
    )

    assert client.register() == "opaque-session"
    assert client.heartbeat("opaque-session", {"actionsTotal": 3, "averageLatencyMs": 4.5}) == {
        "status": "connected"
    }
    assert client.disconnect("opaque-session") == {"status": "connected"}
    assert requests[0][0].endswith("/agents/register")
    assert requests[2][0].endswith("/agents/claude-code-local/disconnect")
    assert requests[0][2]["projectRoot"] == "/workspace/kratos"
    assert requests[1][2]["telemetry"] == {"actionsTotal": 3, "averageLatencyMs": 4.5}
    assert requests[0][1]["Authorization"] == f"Bearer {TOKEN}"

    enterprise_client = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="claude-code-local",
        project_root="/workspace/kratos",
        deployment_id="deployment-prod",
    )
    assert enterprise_client.register() == "opaque-session"
    assert requests[3][0].endswith("/enterprise/agents/register")
    assert requests[3][2]["deploymentId"] == "deployment-prod"

    codex_client = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="codex-cli-local",
        project_root="/workspace/kratos",
        deployment_id="deployment-prod",
        host=AgentHost.CODEX_CLI,
    )
    assert codex_client.register() == "opaque-session"
    assert requests[4][2]["host"] == "codex-cli"

    def effective_urlopen(request: Any, *, timeout: float, **_kwargs: Any) -> Response:
        requests.append((request.full_url, dict(request.headers), {}))
        return Response({"policy": {"id": "policy-safe"}})

    monkeypatch.setattr(control_plane, "urlopen", effective_urlopen)
    assert enterprise_client.effective_policy()["policy"]["id"] == "policy-safe"
    assert requests[-1][0].endswith(
        "/enterprise/agents/deployment-prod/claude-code-local/effective-policy"
    )

    aws_requests: list[str] = []
    policy_bundle, trust_store = signed_policy_fixture()

    def aws_urlopen(request: Any, *, timeout: float, **_kwargs: Any) -> Response:
        aws_requests.append(request.full_url)
        assert (
            request.headers["X-aai-project-root-digest"] == sha256(b"/workspace/kratos").hexdigest()
        )
        if request.full_url.endswith("/effective-policy"):
            return Response({"policyBundle": policy_bundle})
        return Response(
            {
                "status": "connected",
                "controlState": {"executionAllowed": True},
            }
        )

    monkeypatch.setattr(control_plane, "urlopen", aws_urlopen)
    aws_client = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="claude-code-local",
        project_root="/workspace/kratos",
        deployment_id="deployment-prod",
        aws_agent_session=True,
        policy_trust_store=trust_store,
        tenant_id="tenant-a",
    )
    assert aws_client.register() == TOKEN
    assert aws_client.heartbeat(TOKEN)["status"] == "connected"
    assert aws_client.effective_policy()["policy"]["id"] == "policy-aws"
    assert aws_requests == [
        "https://control.example.test/api/agent/deployment-prod/claude-code-local/heartbeat",
        "https://control.example.test/api/agent/deployment-prod/claude-code-local/heartbeat",
        "https://control.example.test/api/agent/deployment-prod/claude-code-local/effective-policy",
    ]
    assert aws_client.disconnect(TOKEN) == {"status": "disconnect_pending_expiry"}


def test_aws_agent_client_rejects_unsigned_or_cross_tenant_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Authenticated transport cannot replace pinned signing and tenant trust."""
    import agentic_security.ui_control_plane as control_plane

    policy_bundle, trust_store = signed_policy_fixture()

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps({"policyBundle": policy_bundle}).encode()

    monkeypatch.setattr(control_plane, "urlopen", lambda *_args, **_kwargs: Response())
    missing_trust = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="claude-code-local",
        project_root="/workspace/kratos",
        deployment_id="deployment-prod",
        aws_agent_session=True,
    )
    with pytest.raises(ControlPlaneDependencyError, match="pinned signing trust"):
        missing_trust.effective_policy()

    cross_tenant = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="claude-code-local",
        project_root="/workspace/kratos",
        deployment_id="deployment-prod",
        aws_agent_session=True,
        policy_trust_store=trust_store,
        tenant_id="tenant-other",
    )
    with pytest.raises(ControlPlaneDependencyError, match="signature verification"):
        cross_tenant.effective_policy()


def test_agent_client_verifies_managed_package_response_and_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The client rejects transport metadata that does not bind exact package bytes."""
    import agentic_security.ui_control_plane as control_plane

    package = deployment_package()
    response_value: dict[str, object] = {
        "schemaVersion": 1,
        "deploymentId": "deployment-prod",
        "agentId": "claude-managed",
        "revision": 1,
        "status": "current",
        "packageSha256": package.package_sha256,
        "bundleHash": package.bundle_hash,
        "host": package.host.value,
        "hostVersion": package.host_version,
        "platform": package.platform.value,
        "policyId": package.policy_id,
        "policyVersion": package.policy_version,
        "publishedAt": 100,
        "publishedBy": "platform-admin",
        "packageBase64": base64.b64encode(package.to_json()).decode(),
    }

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(response_value).encode()

    captured: list[Any] = []

    def fake_urlopen(request: Any, *_args: object, **_kwargs: object) -> Response:
        captured.append(request)
        return Response()

    monkeypatch.setattr(control_plane, "urlopen", fake_urlopen)
    client = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="claude-managed",
        project_root="/workspace/kratos",
        deployment_id="deployment-prod",
        aws_agent_session=True,
    )
    assert client.managed_deployment_package(platform=ManagedPlatform.LINUX) == package
    assert captured[0].method == "GET"
    assert captured[0].full_url.endswith("/agent/deployment-prod/claude-managed/managed-package")

    response_value["packageSha256"] = "f" * 64
    with pytest.raises(ControlPlaneDependencyError, match="verification failed"):
        client.managed_deployment_package(platform=ManagedPlatform.LINUX)
    response_value["packageSha256"] = package.package_sha256
    response_value["policyVersion"] = 2
    with pytest.raises(ControlPlaneDependencyError, match="metadata does not match"):
        client.managed_deployment_package(platform=ManagedPlatform.LINUX)
    with pytest.raises(ControlPlaneConfigurationError, match="platform is unsupported"):
        client.managed_deployment_package(platform="android")


def test_agent_client_requires_v2_trust_digest_outside_package_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Authenticated package bytes cannot self-assert their signing trust digest."""
    import agentic_security.ui_control_plane as control_plane

    package = deployment_package(with_trust=True)
    response_value: dict[str, object] = {
        "schemaVersion": 2,
        "deploymentId": "deployment-prod",
        "agentId": "claude-managed",
        "revision": 2,
        "status": "current",
        "packageSha256": package.package_sha256,
        "bundleHash": package.bundle_hash,
        "host": package.host.value,
        "hostVersion": package.host_version,
        "platform": package.platform.value,
        "policyId": package.policy_id,
        "policyVersion": package.policy_version,
        "policyTrustBundleSha256": package.policy_trust_bundle_sha256,
        "publishedAt": 100,
        "publishedBy": "platform-admin",
        "packageBase64": base64.b64encode(package.to_json()).decode(),
    }

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(response_value).encode()

    monkeypatch.setattr(control_plane, "urlopen", lambda *_args, **_kwargs: Response())
    client = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="claude-managed",
        project_root="/workspace/kratos",
        deployment_id="deployment-prod",
        aws_agent_session=True,
    )
    assert (
        client.managed_deployment_package(platform=ManagedPlatform.LINUX).policy_trust_bundle_sha256
        == package.policy_trust_bundle_sha256
    )
    response_value["policyTrustBundleSha256"] = "f" * 64
    with pytest.raises(ControlPlaneDependencyError, match="verification failed"):
        client.managed_deployment_package(platform=ManagedPlatform.LINUX)


def test_runtime_remediation_client_is_typed_content_free_and_revision_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The SDK helps an MDM worker without downloading or executing release bytes."""
    import agentic_security.ui_control_plane as control_plane

    instruction: dict[str, object] = {
        "schemaVersion": 1,
        "instructionId": "1" * 64,
        "deploymentId": "deployment-a",
        "agentId": "agent-a",
        "host": "claude-code",
        "rolloutRevision": 3,
        "rolloutState": "canary",
        "releaseId": "claude-code:1.2.0",
        "releaseTag": "v1.2.0",
        "sdkVersion": "1.2.0",
        "sdkRevision": "2" * 40,
        "manifestSha256": "3" * 64,
        "releaseEvidenceSha256": "4" * 64,
        "packageSha256": "5" * 64,
        "gatewaySha256": "6" * 64,
        "hookSha256": "7" * 64,
        "status": "pending",
        "channelStatus": "not_started",
        "runtimeVerification": "not_verified",
        "eligible": True,
        "taskRevision": 0,
        "attempts": 0,
        "claimedAt": None,
        "leaseExpiresAt": None,
        "reportedAt": None,
        "reasonCode": None,
        "evidenceObservedAt": None,
        "evidenceExpiresAt": 1_900_000_300,
    }
    instruction["instructionId"] = runtime_remediation_instruction_digest(instruction)
    responses: list[dict[str, object]] = [
        {
            "schemaVersion": 1,
            "deploymentId": "deployment-a",
            "rolloutRevision": 3,
            "rolloutState": "canary",
            "measuredAt": 1_900_000_000,
            "totalItems": 1,
            "statusCounts": {
                "pending": 1,
                "in_progress": 0,
                "awaiting_attestation": 0,
                "failed": 0,
                "verified": 0,
                "blocked": 0,
            },
            "channelStatusCounts": {
                "not_started": 1,
                "in_progress": 0,
                "installed_reported": 0,
                "failed": 0,
            },
            "runtimeVerificationCounts": {
                "not_verified": 1,
                "verified": 0,
                "blocked": 0,
            },
            "items": [instruction],
            "nextToken": None,
            "hasMore": False,
        },
        {
            **instruction,
            "status": "in_progress",
            "channelStatus": "in_progress",
            "eligible": False,
            "taskRevision": 1,
            "attempts": 1,
            "claimedAt": 1_900_000_010,
            "leaseExpiresAt": 1_900_000_910,
        },
        {
            **instruction,
            "status": "failed",
            "channelStatus": "failed",
            "eligible": True,
            "taskRevision": 2,
            "attempts": 1,
            "claimedAt": 1_900_000_010,
            "leaseExpiresAt": 1_900_000_910,
            "reportedAt": 1_900_000_020,
            "reasonCode": "privilege_unavailable",
        },
        {
            **instruction,
            "status": "awaiting_attestation",
            "channelStatus": "installed_reported",
            "eligible": False,
            "taskRevision": 2,
            "attempts": 1,
            "claimedAt": 1_900_000_010,
            "leaseExpiresAt": 1_900_000_910,
            "reportedAt": 1_900_000_020,
        },
        {
            **instruction,
            "agentId": "agent-other",
            "status": "awaiting_attestation",
            "channelStatus": "installed_reported",
            "eligible": False,
            "taskRevision": 3,
            "attempts": 1,
            "claimedAt": 1_900_000_010,
            "leaseExpiresAt": 1_900_000_910,
            "reportedAt": 1_900_000_020,
        },
    ]
    responses[-1]["instructionId"] = runtime_remediation_instruction_digest(responses[-1])

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(responses.pop(0)).encode()

    requests: list[Any] = []

    def fake_urlopen(request: Any, *_args: object, **_kwargs: object) -> Response:
        requests.append(request)
        return Response()

    monkeypatch.setattr(control_plane, "_open_remediation_https", fake_urlopen)
    client = RuntimeRemediationClient("https://control.example.test", TOKEN)
    page = client.list("deployment-a")
    assert page.total_items == 1
    assert page.items[0].package_sha256 == "5" * 64
    assert requests[0].method == "GET"
    assert "deploymentId=deployment-a" in requests[0].full_url

    claimed = client.claim(page.items[0], request_id="claim-a")
    assert claimed.status == "in_progress"
    claim_body = json.loads(requests[1].data)
    assert claim_body == {
        "expectedTaskRevision": 0,
        "instructionId": instruction["instructionId"],
        "requestId": "claim-a",
    }
    failed = client.report_failed(
        claimed, request_id="report-failed", reason_code="privilege_unavailable"
    )
    assert failed.status == "failed"
    assert json.loads(requests[2].data)["reasonCode"] == "privilege_unavailable"
    installed = client.report_installed(claimed, request_id="report-a")
    assert installed.status == "awaiting_attestation"
    assert installed.status != "verified"
    report_body = json.loads(requests[3].data)
    assert report_body["expectedTaskRevision"] == 1
    assert report_body["reasonCode"] is None
    assert all(
        marker not in json.dumps(requests_body).lower()
        for requests_body in (claim_body, report_body)
        for marker in ("command", "path", "https://", "credential", "base64")
    )
    with pytest.raises(ValueError, match="not claimable"):
        client.claim(installed, request_id="claim-again")
    with pytest.raises(ControlPlaneDependencyError, match="authority changed"):
        client.report_installed(installed, request_id="cross-authority")


def test_runtime_remediation_client_rejects_malformed_authority_and_raw_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cross-scope, contradictory and content-rich channel state fails closed."""
    import agentic_security.ui_control_plane as control_plane

    client = RuntimeRemediationClient("https://control.example.test", TOKEN)
    with pytest.raises(ValueError, match="HTTPS"):
        RuntimeRemediationClient("http://control.example.test", TOKEN)
    with pytest.raises(ValueError, match="service credential"):
        RuntimeRemediationClient("https://control.example.test", "short")
    with pytest.raises(ValueError, match="timeout"):
        RuntimeRemediationClient("https://control.example.test", TOKEN, timeout_seconds=0)
    with pytest.raises(ValueError, match="limit"):
        client.list("deployment-a", limit=0)
    with pytest.raises(ValueError, match="pagination"):
        client.list("deployment-a", next_token="")
    with pytest.raises(ValueError, match="deployment ID"):
        client.list("deployment/a")
    with pytest.raises(ValueError, match="failure reason"):
        client.report_failed(
            cast(RuntimeRemediationInstruction, object()),
            request_id="report-a",
            reason_code="raw_exception",
        )

    malformed = {
        "schemaVersion": 1,
        "deploymentId": "deployment-a",
        "rolloutRevision": 1,
        "rolloutState": "canary",
        "measuredAt": 1_900_000_000,
        "totalItems": 0,
        "statusCounts": {
            "pending": 1,
            "in_progress": 0,
            "awaiting_attestation": 0,
            "failed": 0,
            "verified": 0,
            "blocked": 0,
        },
        "channelStatusCounts": {
            "not_started": 0,
            "in_progress": 0,
            "installed_reported": 0,
            "failed": 0,
        },
        "runtimeVerificationCounts": {
            "not_verified": 0,
            "verified": 0,
            "blocked": 0,
        },
        "items": [],
        "nextToken": None,
        "hasMore": False,
    }

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(malformed).encode()

    monkeypatch.setattr(
        control_plane, "_open_remediation_https", lambda *_args, **_kwargs: Response()
    )
    with pytest.raises(ControlPlaneDependencyError, match="counts are inconsistent"):
        client.list("deployment-a")
    monkeypatch.setattr(
        control_plane,
        "_open_remediation_https",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("synthetic outage")),
    )
    with pytest.raises(ControlPlaneDependencyError, match="request failed"):
        client.list("deployment-a")


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ({"schemaVersion": 2}, "schema"),
        ({"attempts": True}, "numeric"),
        ({"instructionId": "not-a-digest"}, "digest"),
        ({"packageSha256": "8" * 64}, "binding"),
        ({"sdkRevision": "short"}, "SDK revision"),
        ({"host": "unknown-host"}, "identity"),
        ({"reasonCode": "raw provider exception"}, "failure reason"),
        ({"eligible": False}, "eligibility"),
    ],
)
def test_runtime_remediation_instruction_rejects_ambiguous_wire_state(
    replacement: dict[str, object], message: str
) -> None:
    """The public parser rejects malformed identity, evidence and eligibility."""
    instruction: dict[str, object] = {
        "schemaVersion": 1,
        "instructionId": "1" * 64,
        "deploymentId": "deployment-a",
        "agentId": "agent-a",
        "host": "claude-code",
        "rolloutRevision": 3,
        "rolloutState": "canary",
        "releaseId": "claude-code:1.2.0",
        "releaseTag": "v1.2.0",
        "sdkVersion": "1.2.0",
        "sdkRevision": "2" * 40,
        "manifestSha256": "3" * 64,
        "releaseEvidenceSha256": "4" * 64,
        "packageSha256": "5" * 64,
        "gatewaySha256": "6" * 64,
        "hookSha256": "7" * 64,
        "status": "pending",
        "channelStatus": "not_started",
        "runtimeVerification": "not_verified",
        "eligible": True,
        "taskRevision": 0,
        "attempts": 0,
        "claimedAt": None,
        "leaseExpiresAt": None,
        "reportedAt": None,
        "reasonCode": None,
        "evidenceObservedAt": None,
        "evidenceExpiresAt": None,
    }
    instruction["instructionId"] = runtime_remediation_instruction_digest(instruction)
    instruction.update(replacement)
    with pytest.raises(ControlPlaneDependencyError, match=message):
        RuntimeRemediationInstruction.from_wire(instruction)


def test_runtime_remediation_client_never_forwards_bearer_across_redirects() -> None:
    """GET and POST redirects fail before a second origin receives the bearer."""
    received_authorization: list[str | None] = []

    class TargetHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib callback name.
            received_authorization.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()

        do_POST = do_GET

        def log_message(self, *_args: object) -> None:
            return None

    target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib callback name.
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{target.server_port}/capture")
            self.end_headers()

        do_POST = do_GET

        def log_message(self, *_args: object) -> None:
            return None

    redirect = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True) for server in (target, redirect)
    ]
    for thread in threads:
        thread.start()
    try:
        client = RuntimeRemediationClient(f"http://127.0.0.1:{redirect.server_port}", TOKEN)
        with pytest.raises(ControlPlaneDependencyError, match="request failed"):
            client.list("deployment-a")
        wire: dict[str, object] = {
            "schemaVersion": 1,
            "instructionId": "0" * 64,
            "deploymentId": "deployment-a",
            "agentId": "agent-a",
            "host": "claude-code",
            "rolloutRevision": 3,
            "rolloutState": "canary",
            "releaseId": "claude-code:1.2.0",
            "releaseTag": "v1.2.0",
            "sdkVersion": "1.2.0",
            "sdkRevision": "2" * 40,
            "manifestSha256": "3" * 64,
            "releaseEvidenceSha256": "4" * 64,
            "packageSha256": "5" * 64,
            "gatewaySha256": "6" * 64,
            "hookSha256": "7" * 64,
            "status": "in_progress",
            "channelStatus": "in_progress",
            "runtimeVerification": "not_verified",
            "eligible": False,
            "taskRevision": 1,
            "attempts": 1,
            "claimedAt": 1_900_000_000,
            "leaseExpiresAt": 1_900_000_900,
            "reportedAt": None,
            "reasonCode": None,
            "evidenceObservedAt": None,
            "evidenceExpiresAt": None,
        }
        wire["instructionId"] = runtime_remediation_instruction_digest(wire)
        with pytest.raises(ControlPlaneDependencyError, match="request failed"):
            client.report_installed(
                RuntimeRemediationInstruction.from_wire(wire), request_id="report-a"
            )
        assert received_authorization == []
    finally:
        for server in (redirect, target):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


def test_agent_client_remeasures_and_reports_typed_managed_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every AWS heartbeat obtains fresh host evidence from a deployment callback."""
    import agentic_security.ui_control_plane as control_plane

    bodies: list[dict[str, object]] = []
    provider_calls = 0

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return b'{"status":"connected","controlState":{"executionAllowed":true}}'

    def fake_urlopen(request: Any, **_kwargs: object) -> Response:
        bodies.append(json.loads(request.data))
        return Response()

    def evidence_provider() -> ManagedConfigurationEvidence:
        nonlocal provider_calls
        provider_calls += 1
        return ManagedConfigurationEvidence(
            host=AgentHost.CLAUDE_CODE,
            host_version="2.1.220",
            platform=ManagedPlatform.MACOS,
            bundle_hash="a" * 64,
            policy_id="policy-safe",
            policy_version=4,
            source=ManagedConfigurationSource.MDM,
            verified_at=100 + provider_calls,
            expires_at=200 + provider_calls,
        )

    monkeypatch.setattr(control_plane, "urlopen", fake_urlopen)
    client = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="claude-managed",
        project_root="/workspace/kratos",
        deployment_id="deployment-prod",
        aws_agent_session=True,
        managed_configuration_provider=evidence_provider,
    )

    client.heartbeat(TOKEN)
    client.heartbeat(TOKEN)

    assert provider_calls == 2
    assert bodies[0]["managedConfiguration"] == {
        "host": "claude-code",
        "hostVersion": "2.1.220",
        "platform": "macos",
        "bundleHash": "a" * 64,
        "policyId": "policy-safe",
        "policyVersion": 4,
        "source": "mdm",
        "verifiedAt": 101,
        "expiresAt": 201,
    }
    assert bodies[1]["managedConfiguration"]["verifiedAt"] == 102  # type: ignore[index]


def test_agent_client_rejects_untrusted_managed_configuration_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A callback cannot report a mapping or evidence for another host."""
    import agentic_security.ui_control_plane as control_plane

    with pytest.raises(ValueError, match="requires an AWS agent session"):
        ControlPlaneAgentClient(
            "https://control.example.test/api",
            TOKEN,
            agent_id="claude-managed",
            project_root="/workspace/kratos",
            managed_configuration_provider=lambda: cast(ManagedConfigurationEvidence, {}),
        )

    monkeypatch.setattr(control_plane, "urlopen", lambda *_args, **_kwargs: None)
    client = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="claude-managed",
        project_root="/workspace/kratos",
        deployment_id="deployment-prod",
        aws_agent_session=True,
        managed_configuration_provider=lambda: cast(ManagedConfigurationEvidence, {}),
    )
    with pytest.raises(ControlPlaneConfigurationError, match="invalid evidence"):
        client.heartbeat(TOKEN)

    wrong_host = ManagedConfigurationEvidence(
        host=AgentHost.CODEX_CLI,
        host_version="0.146.0",
        platform=ManagedPlatform.MACOS,
        bundle_hash="b" * 64,
        policy_id="policy-safe",
        policy_version=1,
        source=ManagedConfigurationSource.CODEX_MDM,
        verified_at=100,
        expires_at=200,
    )
    client.managed_configuration_provider = lambda: wrong_host
    with pytest.raises(ControlPlaneConfigurationError, match="does not match"):
        client.heartbeat(TOKEN)


def test_agent_client_and_exporter_report_only_bounded_decision_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Decision evidence must omit prompts, arguments, commands, paths and policy claims."""
    import agentic_security.ui_control_plane as control_plane

    captured: list[tuple[str, dict[str, object]]] = []

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps({"accepted": True, "duplicate": False}).encode()

    def fake_urlopen(request: Any, *, timeout: float, **_kwargs: Any) -> Response:
        del timeout
        captured.append((request.full_url, json.loads(request.data)))
        return Response()

    monkeypatch.setattr(control_plane, "urlopen", fake_urlopen)
    client = ControlPlaneAgentClient(
        "https://control.example.test",
        TOKEN,
        agent_id="agent-a",
        project_root="/workspace/secret-project",
        deployment_id="dep-a",
        aws_agent_session=True,
    )
    event = AuditEvent(
        "claude_pre_tool_decision",
        "tool-use-a",
        {
            "tool_name": "Bash",
            "decision": "ask",
            "reason": "consequential command requires interactive approval",
            "tool_input_hash": "c" * 64,
            "cwd_hash": "d" * 64,
            "action_digest": "e" * 64,
        },
        "2026-07-28T12:00:00Z",
        "0" * 64,
        "a" * 64,
    )
    ControlPlaneDecisionExporter(client, source="claude_native").export(event)
    assert captured[0][0].endswith("/agent/dep-a/agent-a/decisions")
    assert captured[0][1] == {
        "decisionId": "a" * 64,
        "source": "claude_native",
        "toolName": "Bash",
        "decision": "approval_required",
        "resourceKind": "shell_command",
        "reasonCode": "approval_rule",
        "actionDigest": "e" * 64,
    }
    assert "token" not in json.dumps(captured[0][1]).lower()
    with pytest.raises(ControlPlaneConfigurationError):
        client.report_decision(
            decision_id="not-a-digest",
            source="claude_native",
            tool_name="Bash",
            decision="allowed",
            resource_kind="shell_command",
            reason_code="explicit_allow",
        )
    with pytest.raises(ControlPlaneConfigurationError, match="action digest"):
        client.report_decision(
            decision_id="d" * 64,
            source="claude_native",
            tool_name="Bash",
            decision="allowed",
            resource_kind="shell_command",
            reason_code="explicit_allow",
            action_digest="invalid",
        )


def test_native_action_digest_is_bound_to_tool_input_and_working_directory() -> None:
    """Identical native input in a different project cannot satisfy the same proof."""
    baseline = _native_action_digest("Bash", "a" * 64, "b" * 64)

    assert _native_action_digest("Read", "a" * 64, "b" * 64) != baseline
    assert _native_action_digest("Bash", "c" * 64, "b" * 64) != baseline
    assert _native_action_digest("Bash", "a" * 64, "d" * 64) != baseline


def test_mcp_decision_export_reports_only_bounded_server_identity() -> None:
    """MCP anomaly evidence identifies the server without exporting tool input."""
    reports: list[dict[str, object]] = []

    class RecordingClient:
        def report_decision(self, **report: object) -> dict[str, object]:
            reports.append(report)
            return {"accepted": True}

    event = AuditEvent(
        "action_executed",
        "tool-use-mcp",
        {"tool_name": "mcp__github__list_issues"},
        "2026-08-04T12:00:00Z",
        "0" * 64,
        "f" * 64,
    )
    ControlPlaneDecisionExporter(
        cast(ControlPlaneAgentClient, RecordingClient()), source="mcp"
    ).export(event)

    assert reports == [
        {
            "decision_id": "f" * 64,
            "source": "mcp",
            "tool_name": "mcp__github__list_issues",
            "decision": "allowed",
            "resource_kind": "mcp_tool",
            "reason_code": "explicit_allow",
            "action_digest": None,
            "mcp_server_id": "github",
        }
    ]
    assert "argument" not in json.dumps(reports).lower()


def test_decision_report_rejects_mcp_identity_on_non_mcp_evidence() -> None:
    """A caller cannot label an unrelated SDK action as an MCP observation."""
    client = ControlPlaneAgentClient(
        "https://control.example.test",
        TOKEN,
        agent_id="agent-a",
        project_root="/workspace/synthetic",
        deployment_id="dep-a",
        aws_agent_session=True,
    )

    with pytest.raises(ControlPlaneConfigurationError, match="requires MCP"):
        client.report_decision(
            decision_id="a" * 64,
            source="sdk_runtime",
            tool_name="lookup",
            decision="allowed",
            resource_kind="sdk_tool",
            reason_code="explicit_allow",
            mcp_server_id="github",
        )


def test_native_decision_export_rejects_missing_working_directory_scope() -> None:
    """Central native evidence fails closed when the host omits project scope."""

    class RecordingClient:
        def report_decision(self, **_report: str) -> dict[str, object]:
            return {"accepted": True}

    event = AuditEvent(
        "codex_pre_tool_decision",
        "request-a",
        {
            "tool_name": "Bash",
            "decision": "allow",
            "tool_input_hash": "a" * 64,
        },
        "2026-07-28T12:00:00Z",
        "0" * 64,
        "b" * 64,
    )

    with pytest.raises(ControlPlaneConfigurationError, match="working-directory"):
        ControlPlaneDecisionExporter(
            cast(ControlPlaneAgentClient, RecordingClient()), source="codex_native"
        ).export(event)


def test_native_decision_export_rejects_malformed_precomputed_correlation() -> None:
    """A host cannot smuggle malformed action correlation into central evidence."""

    class RecordingClient:
        def report_decision(self, **_report: str) -> dict[str, object]:
            return {"accepted": True}

    event = AuditEvent(
        "claude_pre_tool_decision",
        "request-a",
        {
            "tool_name": "Read",
            "decision": "allow",
            "tool_input_hash": "a" * 64,
            "cwd_hash": "b" * 64,
            "action_digest": "not-a-digest",
        },
        "2026-07-28T12:00:00Z",
        "0" * 64,
        "c" * 64,
    )

    with pytest.raises(ControlPlaneConfigurationError, match="correlation"):
        ControlPlaneDecisionExporter(
            cast(ControlPlaneAgentClient, RecordingClient()), source="claude_native"
        ).export(event)


@pytest.mark.parametrize(
    ("event_type", "decision", "reason", "source", "tool_name", "expected"),
    [
        (
            "action_executed",
            None,
            "",
            "mcp",
            "lookup_record",
            ("allowed", "mcp_tool", "explicit_allow"),
        ),
        (
            "action_denied",
            None,
            "outside approved project",
            "sdk_runtime",
            "Read",
            ("denied", "sdk_tool", "outside_project"),
        ),
        (
            "action_denied",
            None,
            "dangerous command",
            "sdk_runtime",
            "Bash",
            ("denied", "sdk_tool", "blocked_command"),
        ),
        (
            "action_denied",
            None,
            "configuration is invalid",
            "sdk_runtime",
            "Edit",
            ("denied", "sdk_tool", "invalid_configuration"),
        ),
        (
            "action_denied",
            None,
            "audit persistence failed",
            "sdk_runtime",
            "Write",
            ("denied", "sdk_tool", "audit_failure"),
        ),
        (
            "action_denied",
            None,
            "policy evaluation failed",
            "codex_native",
            "shell",
            ("denied", "sdk_tool", "policy_error"),
        ),
        (
            "action_denied",
            None,
            "unknown tool",
            "sdk_runtime",
            "Mystery",
            ("denied", "sdk_tool", "deny_by_default"),
        ),
        (
            "approval_required",
            None,
            "held",
            "sdk_runtime",
            "deploy",
            ("approval_required", "sdk_tool", "approval_rule"),
        ),
        (
            "claude_pre_tool_decision",
            "deny",
            "blocked",
            "claude_native",
            "Read",
            ("denied", "project_file", "deny_by_default"),
        ),
        (
            "codex_pre_tool_decision",
            "allow",
            "all patch targets are inside the approved project",
            "codex_native",
            "apply_patch",
            ("allowed", "project_file", "explicit_allow"),
        ),
        (
            "codex_pre_tool_decision",
            "ask",
            "command requires approval",
            "codex_native",
            "Bash",
            ("approval_required", "shell_command", "approval_rule"),
        ),
        (
            "codex_pre_tool_decision",
            "deny",
            "tool is not explicitly allowed",
            "codex_native",
            "mcp__unknown__execute",
            ("denied", "mcp_tool", "deny_by_default"),
        ),
    ],
)
def test_decision_exporter_normalizes_all_supported_host_outcomes(
    event_type: str,
    decision: str | None,
    reason: str,
    source: str,
    tool_name: str,
    expected: tuple[str, str, str],
) -> None:
    """Every source and reason branch emits only the closed evidence vocabulary."""

    class RecordingClient:
        def __init__(self) -> None:
            self.reports: list[dict[str, str]] = []

        def report_decision(self, **report: str) -> dict[str, object]:
            self.reports.append(report)
            return {"accepted": True}

    recording = RecordingClient()
    payload: dict[str, object] = {"tool_name": tool_name, "reason": reason}
    if source in {"claude_native", "codex_native"}:
        payload["tool_input_hash"] = "c" * 64
        payload["cwd_hash"] = "d" * 64
    if decision is not None:
        payload["decision"] = decision
    event = AuditEvent(
        event_type,
        "request-a",
        payload,
        "2026-07-28T12:00:00Z",
        "0" * 64,
        "b" * 64,
    )

    ControlPlaneDecisionExporter(cast(ControlPlaneAgentClient, recording), source=source).export(
        event
    )

    assert recording.reports[0]["decision"] == expected[0]
    assert recording.reports[0]["resource_kind"] == expected[1]
    assert recording.reports[0]["reason_code"] == expected[2]


def test_decision_exporter_rejects_invalid_sources_and_malformed_decisions() -> None:
    """Unknown sources and content-free events without a tool fail safely."""

    class RecordingClient:
        def __init__(self) -> None:
            self.reports: list[dict[str, str]] = []

        def report_decision(self, **report: str) -> dict[str, object]:
            self.reports.append(report)
            return {"accepted": True}

    recording = RecordingClient()
    client = cast(ControlPlaneAgentClient, recording)
    with pytest.raises(ControlPlaneConfigurationError):
        ControlPlaneDecisionExporter(client, source="browser")

    exporter = ControlPlaneDecisionExporter(client, source="claude_native")
    exporter.export(AuditEvent("heartbeat", "request-a", {}, "now", "0" * 64, "c" * 64))
    exporter.export(
        AuditEvent(
            "claude_pre_tool_decision",
            "request-b",
            {"decision": 7, "tool_name": "Bash"},
            "now",
            "0" * 64,
            "d" * 64,
        )
    )
    assert recording.reports == []

    with pytest.raises(ControlPlaneConfigurationError):
        exporter.export(
            AuditEvent(
                "claude_pre_tool_decision",
                "request-c",
                {"decision": "allow"},
                "now",
                "0" * 64,
                "e" * 64,
            )
        )


def test_agent_client_submits_content_minimised_exact_approval_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public client must not need custom HTTP glue for central review."""
    import agentic_security.ui_control_plane as control_plane

    captured: list[tuple[str, dict[str, str], dict[str, object]]] = []

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(
                {"id": "approval-a", "status": "pending", "agentKey": "dep-a:agent-a"}
            ).encode()

    def fake_urlopen(request: Any, *, timeout: float, **_kwargs: Any) -> Response:
        captured.append((request.full_url, dict(request.headers), json.loads(request.data)))
        return Response()

    monkeypatch.setattr(control_plane, "urlopen", fake_urlopen)
    client = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="agent-a",
        project_root="/workspace/synthetic",
        deployment_id="dep-a",
        aws_agent_session=True,
    )

    response = client.request_approval(
        approval_id="approval-a",
        tool_name="publish_artifact",
        proposal_id="proposal-a",
        task_id="task-a",
        principal_id="principal-a",
        action_hash="a" * 64,
        risk_class="external_egress",
        resource_ids=("artifact:synthetic-report",),
    )

    assert response["status"] == "pending"
    assert captured[0][0].endswith("/agent/dep-a/agent-a/approvals/request")
    assert captured[0][1]["Authorization"] == f"Bearer {TOKEN}"
    assert captured[0][2] == {
        "approval_id": "approval-a",
        "tool_name": "publish_artifact",
        "proposal_id": "proposal-a",
        "task_id": "task-a",
        "principal_id": "principal-a",
        "action_hash": "a" * 64,
        "risk_class": "external_egress",
        "resource_ids": ["artifact:synthetic-report"],
        "review_ttl_seconds": 900,
        "grant_ttl_seconds": 120,
    }
    assert "arguments" not in captured[0][2]
    assert "credentials" not in captured[0][2]
    with pytest.raises(ControlPlaneConfigurationError):
        client.request_approval(
            approval_id="approval-b",
            tool_name="publish_artifact",
            proposal_id="proposal-b",
            task_id="task-b",
            principal_id="principal-a",
            action_hash="b" * 64,
            risk_class="unknown-risk",
        )

    legacy = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="agent-a",
        project_root="/workspace/synthetic",
    )
    with pytest.raises(ControlPlaneDependencyError):
        legacy.request_approval(
            approval_id="approval-c",
            tool_name="publish_artifact",
            proposal_id="proposal-c",
            task_id="task-c",
            principal_id="principal-a",
            action_hash="c" * 64,
        )


@pytest.mark.parametrize(
    "override",
    [
        {"approval_id": ""},
        {"action_hash": "a" * 129},
        {"resource_ids": ["resource:a"]},
        {"resource_ids": tuple(f"resource:{index}" for index in range(21))},
        {"resource_ids": ("",)},
        {"review_ttl_seconds": True},
        {"review_ttl_seconds": 59},
        {"review_ttl_seconds": 3601},
        {"grant_ttl_seconds": True},
        {"grant_ttl_seconds": 0},
        {"grant_ttl_seconds": 601},
    ],
)
def test_agent_client_rejects_malformed_approval_bindings(
    override: dict[str, object],
) -> None:
    """Malformed or over-broad approval requests must fail before network I/O."""
    client = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="agent-a",
        project_root="/workspace/synthetic",
        deployment_id="dep-a",
        aws_agent_session=True,
    )
    request_values: dict[str, object] = {
        "approval_id": "approval-a",
        "tool_name": "publish_artifact",
        "proposal_id": "proposal-a",
        "task_id": "task-a",
        "principal_id": "principal-a",
        "action_hash": "a" * 64,
        "risk_class": "external_egress",
        "resource_ids": (),
        "review_ttl_seconds": 900,
        "grant_ttl_seconds": 120,
    }
    request_values.update(override)

    with pytest.raises(ControlPlaneConfigurationError):
        client.request_approval(**request_values)  # type: ignore[arg-type]


def test_agent_client_adopts_rotated_session_from_heartbeat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A renewed AWS bearer is kept in memory and used by later requests."""
    import agentic_security.ui_control_plane as control_plane

    seen_authorizations: list[str] = []

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(
                {
                    "status": "connected",
                    "accessToken": "new-session-token-123456",
                    "controlState": {"executionAllowed": True},
                }
            ).encode()

    def fake_urlopen(request: Any, *, timeout: float, **_kwargs: Any) -> Response:
        del timeout
        seen_authorizations.append(request.headers["Authorization"])
        return Response()

    monkeypatch.setattr(control_plane, "urlopen", fake_urlopen)
    client = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="codex-cli-local",
        project_root="/workspace/kratos",
        deployment_id="deployment-prod",
        aws_agent_session=True,
        host=AgentHost.CODEX_CLI,
    )

    response = client.heartbeat(TOKEN)
    assert response["accessToken"] == "new-session-token-123456"
    client.heartbeat("new-session-token-123456")
    assert seen_authorizations == [f"Bearer {TOKEN}", "Bearer new-session-token-123456"]


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"status": "connected"}, "no valid execution authority"),
        (
            {"status": "quarantined", "controlState": {"executionAllowed": False}},
            "withholds agent execution",
        ),
    ],
)
def test_agent_client_fails_closed_without_server_execution_authority(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
    message: str,
) -> None:
    """An AWS runtime cannot treat missing or denied authority as advisory."""
    import agentic_security.ui_control_plane as control_plane

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(payload).encode()

    monkeypatch.setattr(control_plane, "urlopen", lambda *_args, **_kwargs: Response())
    client = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="claude-code-local",
        project_root="/workspace/kratos",
        deployment_id="deployment-prod",
        aws_agent_session=True,
    )

    with pytest.raises(ControlPlaneDependencyError, match=message):
        client.heartbeat(TOKEN)


def test_agent_client_sends_fresh_challenge_bound_runtime_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AWS heartbeats measure the host only after receiving a server nonce."""
    import agentic_security.ui_control_plane as control_plane

    requests: list[tuple[str, dict[str, object]]] = []
    nonce = "synthetic-runtime-attestation-challenge-123456"

    class Evidence:
        def to_wire(self) -> dict[str, object]:
            return {"schemaVersion": 1, "nonce": nonce, "packageDigest": "a" * 64}

    class Attestor:
        def attest(self, supplied: str) -> Evidence:
            assert supplied == nonce
            return Evidence()

    class Response:
        def __init__(self, value: dict[str, object]) -> None:
            self.value = value

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(self.value).encode()

    def fake_urlopen(request: Any, **_kwargs: Any) -> Response:
        body = json.loads(request.data)
        requests.append((request.full_url, body))
        if request.full_url.endswith("/attestation/challenge"):
            return Response({"nonce": nonce, "expiresAt": 1_900_000_060})
        return Response(
            {
                "status": "connected",
                "expiresAt": 1_900_000_900,
                "controlState": {"executionAllowed": True},
            }
        )

    monkeypatch.setattr(control_plane, "urlopen", fake_urlopen)
    client = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="claude-code-local",
        project_root="/workspace/kratos",
        deployment_id="deployment-prod",
        aws_agent_session=True,
        attestor=Attestor(),  # type: ignore[arg-type]
    )

    assert client.heartbeat(TOKEN)["status"] == "connected"
    assert requests[0][0].endswith("/attestation/challenge")
    assert requests[1][1]["attestation"] == {
        "schemaVersion": 1,
        "nonce": nonce,
        "packageDigest": "a" * 64,
    }


def test_agent_client_secures_rotation_for_native_hook_processes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A successful heartbeat atomically publishes the current bearer."""
    import agentic_security.ui_control_plane as control_plane

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(
                {
                    "status": "connected",
                    "accessToken": "new-session-token-123456",
                    "expiresAt": 2_000,
                    "controlState": {"executionAllowed": True},
                }
            ).encode()

    monkeypatch.setattr(control_plane, "urlopen", lambda *_args, **_kwargs: Response())
    session_store = AgentSessionStore(
        "https://control.example.test/api",
        "deployment-prod",
        "claude-code-local",
        "/workspace/kratos",
        directory=tmp_path,
        now=lambda: 1_000,
    )
    client = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="claude-code-local",
        project_root="/workspace/kratos",
        deployment_id="deployment-prod",
        aws_agent_session=True,
        session_store=session_store,
    )

    client.heartbeat(TOKEN)

    assert session_store.load() == AgentSessionCredential(
        "new-session-token-123456",
        2_000,
    )


def test_agent_client_rejects_mismatched_session_store(tmp_path: Path) -> None:
    """A cache bound to another agent cannot receive this client's bearer."""
    mismatched = AgentSessionStore(
        "https://control.example.test/api",
        "deployment-prod",
        "different-agent",
        "/workspace/kratos",
        directory=tmp_path,
    )
    with pytest.raises(ValueError, match="identity must match"):
        ControlPlaneAgentClient(
            "https://control.example.test/api",
            TOKEN,
            agent_id="claude-code-local",
            project_root="/workspace/kratos",
            deployment_id="deployment-prod",
            aws_agent_session=True,
            session_store=mismatched,
        )

    wrong_scope = AgentSessionStore(
        "https://control.example.test/api",
        "deployment-prod",
        "claude-code-local",
        "/workspace/other",
        directory=tmp_path,
    )
    with pytest.raises(ValueError, match="identity must match"):
        ControlPlaneAgentClient(
            "https://control.example.test/api",
            TOKEN,
            agent_id="claude-code-local",
            project_root="/workspace/kratos",
            deployment_id="deployment-prod",
            aws_agent_session=True,
            session_store=wrong_scope,
        )


def test_agent_client_rejects_unsafe_endpoints_and_transport_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError):
        ControlPlaneAgentClient(
            "http://control.example.test/api",
            TOKEN,
            agent_id="agent",
            project_root="/workspace",
        )
    with pytest.raises(ValueError):
        ControlPlaneAgentClient(
            "https://control.example.test/api",
            "short",
            agent_id="agent",
            project_root="/workspace",
        )
    with pytest.raises(ValueError):
        ControlPlaneAgentClient(
            "https://control.example.test/api",
            TOKEN,
            agent_id="agent",
            project_root="/workspace",
            timeout_seconds=0,
        )
    with pytest.raises(ValueError, match="filesystem root"):
        ControlPlaneAgentClient(
            "https://control.example.test/api",
            TOKEN,
            agent_id="agent",
            project_root="/",
        )
    with pytest.raises(ValueError, match="host is not supported"):
        ControlPlaneAgentClient(
            "https://control.example.test/api",
            TOKEN,
            agent_id="agent",
            project_root="/workspace",
            host="not-a-supported-host",
        )

    import agentic_security.ui_control_plane as control_plane

    def failing_urlopen(_request: Any, *, timeout: float, **_kwargs: Any) -> Any:
        raise OSError("synthetic network outage")

    monkeypatch.setattr(control_plane, "urlopen", failing_urlopen)
    client = ControlPlaneAgentClient(
        "https://control.example.test/api",
        TOKEN,
        agent_id="agent",
        project_root="/workspace",
    )
    with pytest.raises(ControlPlaneDependencyError):
        client.register()


def test_static_authenticator_cannot_be_used_for_non_localhost_origin(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        ControlPlaneApplication(
            store(tmp_path / "config.json"), TOKEN, allowed_origin="https://ui.example"
        )


def test_control_plane_reads_saves_and_reloads_complete_configuration(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    authority = InMemoryControlPlaneAuthority()
    audit = InMemoryAuditSink()
    bound_store = ControlPlaneStore(path, authority=authority, audit=audit)
    app = ControlPlaneApplication(bound_store, TOKEN)
    _, initial = request(app, "GET", "/api/configuration")
    initial["runtime"]["maxActions"] = 7

    status, saved = request(app, "PUT", "/api/configuration", initial)
    reloaded = store(path).snapshot()

    assert status.startswith("200")
    assert saved["runtime"]["maxActions"] == 7
    assert saved["configVersion"] == 2
    assert authority.status()["configuration_active"] is True
    assert [event.event_type for event in audit.events()] == [
        "control_plane_configuration_requested",
        "control_plane_configuration_activated",
    ]
    assert reloaded["runtime"]["maxActions"] == 7


def test_restart_reconciles_persisted_controls_before_serving_runtime_state(
    tmp_path: Path,
) -> None:
    path = tmp_path / "config.json"
    first_authority = InMemoryControlPlaneAuthority()
    app = ControlPlaneApplication(
        ControlPlaneStore(
            path,
            authority=first_authority,
            audit=InMemoryAuditSink(),
        ),
        TOKEN,
    )
    _, configuration = request(app, "GET", "/api/configuration")
    configuration["runtime"]["maxActions"] = 9
    request(app, "PUT", "/api/configuration", configuration)
    request(app, "POST", "/api/emergency-stop")

    restarted_authority = InMemoryControlPlaneAuthority()
    restarted = ControlPlaneStore(
        path,
        authority=restarted_authority,
        audit=InMemoryAuditSink(),
    )

    assert restarted_authority.status() == {"stopped": True, "configuration_active": True}
    assert restarted.snapshot()["runtime"]["maxActions"] == 9


def test_configuration_rollback_is_authenticated_versioned_and_audited(tmp_path: Path) -> None:
    audit = InMemoryAuditSink()
    app = ControlPlaneApplication(
        ControlPlaneStore(
            tmp_path / "config.json",
            authority=InMemoryControlPlaneAuthority(),
            audit=audit,
        ),
        TOKEN,
    )
    _, first = request(app, "GET", "/api/configuration")
    first["runtime"]["maxActions"] = 3
    request(app, "PUT", "/api/configuration", first)
    _, second = request(app, "GET", "/api/configuration")
    second["runtime"]["maxActions"] = 8
    request(app, "PUT", "/api/configuration", second)

    status, rolled_back = request(
        app,
        "POST",
        "/api/configuration/rollback",
        {"configVersion": 2},
    )

    assert status.startswith("200")
    assert rolled_back["runtime"]["maxActions"] == 3
    assert rolled_back["configVersion"] == 4
    assert audit.events()[-1].event_type == "control_plane_configuration_rollback_activated"


def test_runtime_reconciliation_failure_blocks_startup(tmp_path: Path) -> None:
    class FailingAuthority(InMemoryControlPlaneAuthority):
        def apply_configuration(self, _configuration: object) -> None:
            raise RuntimeError("runtime unavailable")

    with pytest.raises(RuntimeError, match="could not be applied"):
        ControlPlaneStore(
            tmp_path / "config.json",
            authority=FailingAuthority(),
            audit=InMemoryAuditSink(),
        )


def test_configuration_rejects_unknown_fields_and_capture_without_redaction() -> None:
    invalid = {
        "runtime": {"unexpected": True},
        "claudeCode": {},
    }
    with pytest.raises(ControlPlaneConfigurationError):
        validate_configuration(invalid)


def test_control_plane_fails_closed_for_unsafe_capture_configuration(tmp_path: Path) -> None:
    app = ControlPlaneApplication(store(tmp_path / "config.json"), TOKEN)
    _, configuration = request(app, "GET", "/api/configuration")
    configuration["runtime"]["redactSensitiveData"] = False
    configuration["runtime"]["captureToolContent"] = True

    status, payload = request(app, "PUT", "/api/configuration", configuration)

    assert status.startswith("400")
    assert "requires sensitive-data redaction" in payload["error"]


@pytest.mark.parametrize(
    ("section", "field", "value", "message"),
    [
        ("claudeCode", "hookCommand", "python3 -c 'print(1)'", "inline code"),
        ("claudeCode", "mcpGatewayCommand", "sh -c echo unsafe", "python or python3"),
        ("claudeCode", "deniedCommandPatterns", ["(a+)+"], "backtracking"),
        ("claudeCode", "allowedCommandPatterns", ["safe"] * 101, "supported limit"),
        ("runtime", "policyProvider", "unknown", "unknown policy provider"),
        ("runtime", "isolationVerifier", "disabled", "high-risk isolation"),
    ],
)
def test_configuration_rejects_unsafe_commands_patterns_and_combinations(
    tmp_path: Path,
    section: str,
    field: str,
    value: object,
    message: str,
) -> None:
    app = ControlPlaneApplication(store(tmp_path / f"{field}.json"), TOKEN)
    _, configuration = request(app, "GET", "/api/configuration")
    configuration[section][field] = value

    status, payload = request(app, "PUT", "/api/configuration", configuration)

    assert status.startswith("400")
    assert message in payload["error"]


def test_emergency_stop_is_persisted_and_dashboard_becomes_critical(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    app = ControlPlaneApplication(store(path), TOKEN)

    status, dashboard = request(app, "POST", "/api/emergency-stop")
    reloaded = store(path)

    assert status.startswith("200")
    assert dashboard["emergencyStop"] is True
    assert dashboard["posture"] == "critical"
    assert reloaded.snapshot()["dashboard"]["emergencyStop"] is True


@pytest.mark.parametrize(
    ("validator", "value"),
    [
        (_bool, "yes"),
        (_number, "one"),
        (_number, 0),
        (_positive_int, True),
        (_positive_int, 0),
        (_positive_int, 10_000_001),
        (_text, 42),
        (
            _text,
            "",
        ),
    ],
)
def test_scalar_configuration_validators_reject_ambiguous_values(
    validator: Any, value: Any
) -> None:
    """The config boundary must not coerce values into safety settings."""
    with pytest.raises(ControlPlaneConfigurationError):
        if validator is _text:
            validator(value, "field", allow_empty=False)
        else:
            validator(value, "field")


def test_control_plane_rejects_corrupt_persisted_state_and_short_tokens(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(ControlPlaneConfigurationError):
        ControlPlaneStore(path)
    bound_store = store(tmp_path / "other.json")
    with pytest.raises(ValueError):
        ControlPlaneApplication(bound_store, "short")
    with pytest.raises(ValueError):
        ControlPlaneApplication(bound_store, TOKEN, max_body_bytes=0)


def test_wsgi_boundary_handles_options_routes_bodies_and_cors(tmp_path: Path) -> None:
    app = ControlPlaneApplication(store(tmp_path / "config.json"), TOKEN)

    status, _ = request(app, "OPTIONS", "/api/configuration", token=None)
    assert status.startswith("204")
    status, payload = request(app, "PATCH", "/api/configuration")
    assert status.startswith("405") and payload["error"] == "method not allowed"
    status, payload = request(app, "GET", "/unknown")
    assert status.startswith("404") and payload["error"] == "endpoint not found"

    status, payload = request(app, "PUT", "/api/configuration", {"bad": True})
    assert status.startswith("400") and "runtime" in payload["error"]

    encoded = b"{"  # Malformed JSON reaches the bounded body parser.
    responses: list[str] = []

    def start_response(value: str, _headers: list[tuple[str, str]]) -> None:
        responses.append(value)

    malformed = {
        "REQUEST_METHOD": "PUT",
        "PATH_INFO": "/api/configuration",
        "CONTENT_LENGTH": str(len(encoded)),
        "wsgi.input": io.BytesIO(encoded),
        "HTTP_AUTHORIZATION": f"Bearer {TOKEN}",
    }
    body = b"".join(app(malformed, start_response))
    assert responses[-1].startswith("400")
    assert json.loads(body)["error"] == "request is not valid JSON"

    status, _ = request(app, "GET", "/api/dashboard")
    assert status.startswith("200")
