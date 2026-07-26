"""Contract and adversarial tests for the optional UI control plane."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from agentic_security import (
    AgentPresenceStore,
    CallbackControlPlaneAuthority,
    ControlPlaneAgentClient,
    ControlPlaneApplication,
    ControlPlaneConfigurationError,
    ControlPlaneDependencyError,
    ControlPlaneStore,
    InMemoryAuditSink,
    InMemoryControlPlaneAuthority,
    OperatorIdentity,
    StaticBearerAuthenticator,
    validate_configuration,
)
from agentic_security.ui_control_plane import (
    _bool,
    _command,
    _endpoint,
    _number,
    _pattern,
    _positive_int,
    _text,
)

TOKEN = "synthetic-local-token-1234"  # noqa: S105 - synthetic test credential


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

    def fake_urlopen(request: Any, *, timeout: float) -> Response:
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
    assert client.heartbeat("opaque-session") == {"status": "connected"}
    assert client.disconnect("opaque-session") == {"status": "connected"}
    assert requests[0][0].endswith("/agents/register")
    assert requests[2][0].endswith("/agents/claude-code-local/disconnect")
    assert requests[0][2]["projectRoot"] == "/workspace/kratos"
    assert requests[0][1]["Authorization"] == f"Bearer {TOKEN}"


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

    import agentic_security.ui_control_plane as control_plane

    def failing_urlopen(_request: Any, *, timeout: float) -> Any:
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
