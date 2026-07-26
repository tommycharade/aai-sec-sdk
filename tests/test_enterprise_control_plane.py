"""Adversarial and contract tests for the enterprise fleet foundation."""

from __future__ import annotations

import io
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import agentic_security.enterprise_control_plane as fleet_module
from agentic_security import (
    EnterpriseFleetApplication,
    EnterpriseFleetStore,
    FleetAuthorizationError,
    FleetConfigurationError,
    FleetIdentity,
    FleetNotFoundError,
    InMemoryAuditSink,
    InMemoryControlPlaneAuthority,
    StaticFleetAuthenticator,
)


class Clock:
    """Deterministic wall clock for heartbeat expiry tests."""

    def __init__(self) -> None:
        self.value = 1_000.0

    def __call__(self) -> float:
        return self.value


def identity(organization_id: str, *, projects: frozenset[str] = frozenset()) -> FleetIdentity:
    """Build a synthetic tenant identity."""
    return FleetIdentity("operator-1", organization_id, frozenset({"admin"}), projects)


def seed(store: EnterpriseFleetStore) -> None:
    """Create two scoped tenants and one deployment in the first tenant."""
    store.create_organization("org-a", "Alpha")
    store.create_organization("org-b", "Beta")
    store.create_project("org-a", "project-a", "Payments")
    store.create_project("org-b", "project-b", "Research")
    store.create_deployment(
        "org-a", "project-a", "deploy-a", "Production", environment="prod", region="eu-west-2"
    )


def test_migrates_inventory_and_enforces_organization_scope(tmp_path: Path) -> None:
    """A tenant cannot list or address another tenant's deployment."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)

    page = store.list_inventory(identity("org-a"), "deployments")

    assert [item["id"] for item in page.items] == ["deploy-a"]
    with pytest.raises(FleetAuthorizationError):
        store.register_agent(
            identity("org-b"),
            deployment_id="deploy-a",
            agent_id="agent-a",
            host="claude-code",
            project_root="/workspace/payments",
        )


def test_fleet_validation_and_roles_fail_closed() -> None:
    """Malformed metadata, identities, and unknown actions are rejected."""
    with pytest.raises(ValueError):
        FleetIdentity("", "org-a", frozenset({"admin"}))
    with pytest.raises(ValueError):
        StaticFleetAuthenticator({"short": identity("org-a")})
    authenticator = StaticFleetAuthenticator({"fleet-admin-token-1234": identity("org-a")})
    assert authenticator.authenticate("Basic anything") is None
    assert authenticator.authenticate("Bearer wrong-token-1234") is None
    assert authenticator.authorize(identity("org-a"), "read") is True
    assert authenticator.authorize(identity("org-a"), "emergency_stop") is True
    assert (
        authenticator.authorize(
            FleetIdentity("agent", "org-a", frozenset({"agent"})), "agent_presence"
        )
        is True
    )
    assert authenticator.authorize(identity("org-a"), "unknown") is False
    with pytest.raises(FleetConfigurationError):
        fleet_module._text("", "name")
    with pytest.raises(FleetConfigurationError):
        fleet_module._optional_text(123, "name")


def test_agent_registration_heartbeat_expiry_and_disconnect_are_secret_safe(tmp_path: Path) -> None:
    """Only the opaque session authorizes heartbeats and snapshots omit it."""
    clock = Clock()
    audit = InMemoryAuditSink()
    store = EnterpriseFleetStore(
        tmp_path / "fleet.sqlite", audit=audit, now=clock, heartbeat_ttl_seconds=15
    )
    seed(store)
    agent = store.register_agent(
        identity("org-a"),
        deployment_id="deploy-a",
        agent_id="claude-a",
        host="claude-code",
        project_root="/workspace/payments",
        metadata={"team": "platform", "environment": "prod"},
    )
    session_id = agent["sessionId"]

    assert agent["status"] == "connected"
    assert session_id not in store.list_inventory(identity("org-a"), "agents").items[0]
    with pytest.raises(FleetAuthorizationError):
        store.register_agent(
            FleetIdentity("different-agent", "org-a", frozenset({"agent"})),
            deployment_id="deploy-a",
            agent_id="claude-a",
            host="claude-code",
            project_root="/workspace/payments",
        )
    with pytest.raises(FleetAuthorizationError):
        store.heartbeat(identity("org-a"), "deploy-a", "claude-a", "wrong-session-1234")

    clock.value += 16
    expired = store.list_inventory(identity("org-a"), "agents").items[0]
    assert expired["status"] == "offline"
    with pytest.raises(FleetAuthorizationError):
        store.heartbeat(identity("org-a"), "deploy-a", "claude-a", session_id)

    fresh = store.register_agent(
        identity("org-a"),
        deployment_id="deploy-a",
        agent_id="claude-a",
        host="claude-code",
        project_root="/workspace/payments",
    )
    disconnected = store.disconnect(identity("org-a"), "deploy-a", "claude-a", fresh["sessionId"])
    assert disconnected["status"] == "offline"
    assert {event.event_type for event in audit.events()} >= {
        "fleet_agent_registered",
        "fleet_agent_heartbeat",
        "fleet_agent_disconnected",
    }


def test_store_rejects_unsafe_metadata_and_invalid_configuration_limits(tmp_path: Path) -> None:
    """Metadata and template configuration never become an unbounded secret store."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    operator = identity("org-a")
    with pytest.raises(FleetConfigurationError):
        store.register_agent(
            operator,
            deployment_id="deploy-a",
            agent_id="agent-a",
            host="claude-code",
            project_root="/workspace/payments",
            metadata={"token": "not-allowed"},
        )
    with pytest.raises(FleetConfigurationError):
        store.register_agent(
            operator,
            deployment_id="deploy-a",
            agent_id="agent-a",
            host="claude-code",
            project_root="/workspace/payments",
            metadata={"labels": {"nested": "unsupported"}},
        )
    with pytest.raises(FleetConfigurationError):
        store.set_rollout(operator, "deploy-a", state="unknown", percentage=10)
    with pytest.raises(FleetConfigurationError):
        store.set_rollout(operator, "deploy-a", state="active", percentage=101)
    with pytest.raises(FleetConfigurationError):
        EnterpriseFleetStore(tmp_path / "bad.sqlite", heartbeat_ttl_seconds=1)


def test_inventory_and_duplicate_errors_are_explicit(tmp_path: Path) -> None:
    """Inventory branches and persistence conflicts fail without ambiguous success."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    operator = identity("org-a")
    assert len(store.list_inventory(operator, "organizations").items) == 1
    assert len(store.list_inventory(operator, "projects").items) == 1
    assert len(store.list_inventory(operator, "deployments").items) == 1
    with pytest.raises(FleetConfigurationError):
        store.list_inventory(operator, "unknown")
    scoped_operator = FleetIdentity("operator", "org-a", frozenset({"operator"}))
    with pytest.raises(FleetAuthorizationError):
        store.list_inventory(scoped_operator, "deployments", organization_id="org-b")
    with pytest.raises(FleetConfigurationError):
        store.create_organization("org-a", "Duplicate")
    with pytest.raises(FleetConfigurationError):
        store.create_project("org-a", "project-a", "Duplicate")
    with pytest.raises(FleetConfigurationError):
        store.create_deployment(
            "org-a", "project-a", "deploy-a", "Duplicate", environment="prod", region="eu-west-2"
        )
    with pytest.raises(FleetNotFoundError):
        store.create_project("org-missing", "missing", "Missing")
    with pytest.raises(FleetNotFoundError):
        store.register_agent(
            operator,
            deployment_id="missing",
            agent_id="agent-a",
            host="claude-code",
            project_root="/workspace",
        )
    store.close()


def test_project_scope_limits_operator_to_assigned_project(tmp_path: Path) -> None:
    """A project-scoped identity cannot enumerate another project in its tenant."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    store.create_organization("org-a", "Alpha")
    store.create_project("org-a", "project-a", "Payments")
    store.create_project("org-a", "project-b", "Research")
    store.create_deployment(
        "org-a", "project-b", "deploy-b", "Research", environment="dev", region="us-east-1"
    )

    scoped = FleetIdentity("operator-1", "org-a", frozenset({"operator"}), frozenset({"project-a"}))

    assert [item["id"] for item in store.list_inventory(scoped, "projects").items] == ["project-a"]
    assert [item["id"] for item in store.list_inventory(scoped, "deployments").items] == []
    with pytest.raises(FleetAuthorizationError):
        store.register_agent(
            scoped,
            deployment_id="deploy-b",
            agent_id="claude-b",
            host="claude-code",
            project_root="/workspace/research",
        )


def test_templates_inherit_stage_rollout_and_report_drift(tmp_path: Path) -> None:
    """Desired configuration is inherited, staged, and compared by content hash."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    operator = identity("org-a")
    store.create_template(
        operator,
        template_id="base",
        name="Production baseline",
        configuration={"runtime": {"maxActions": 20, "redactSensitiveData": True}},
    )
    child = store.create_template(
        operator,
        template_id="claude-prod",
        name="Claude production",
        parent_template_id="base",
        configuration={"runtime": {"maxActions": 10}, "host": "claude-code"},
    )
    assert child["parentId"] == "base"
    assigned = store.assign_template(operator, "deploy-a", "claude-prod")
    assert assigned["desiredConfiguration"] == {
        "runtime": {"maxActions": 10, "redactSensitiveData": True},
        "host": "claude-code",
    }
    assert assigned["drifted"] is True
    assert store.list_drift(operator).items[0]["id"] == "deploy-a"
    assert store.health(operator).items[0]["status"] == "attention"
    assert store.alerts(operator).items[0]["type"] == "configuration_drift"
    assert (
        store.set_rollout(operator, "deploy-a", state="canary", percentage=10)["rolloutState"]
        == "canary"
    )
    applied = store.record_applied_configuration(operator, "deploy-a", assigned["desiredHash"])
    assert applied["drifted"] is False
    stopped = store.set_emergency_stop(operator, "deploy-a", active=True)
    assert stopped["status"] == "critical"
    assert store.alerts(operator).items[0]["type"] == "emergency_stop"
    store.set_emergency_stop(operator, "deploy-a", active=False)
    store.assign_template(operator, "deploy-a", "base")
    batch = store.rollout_deployments(
        operator, ["deploy-a", "deploy-a"], state="canary", percentage=25
    )
    assert batch.items[0]["rolloutPercentage"] == 25
    rolled_back = store.rollback_deployment(operator, "deploy-a", 1)
    assert rolled_back["rolloutState"] == "rollback"
    assert rolled_back["desiredConfiguration"]["host"] == "claude-code"


def test_live_authority_is_required_for_activation_and_stop(tmp_path: Path) -> None:
    """Fleet mutations invoke the deployment authority before claiming activation."""
    authority = InMemoryControlPlaneAuthority()
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite", authorities={"deploy-a": authority})
    seed(store)
    operator = identity("org-a")
    template = store.create_template(
        operator,
        template_id="runtime",
        name="Runtime",
        configuration={"runtime": {"maxActions": 5}},
    )
    store.assign_template(operator, "deploy-a", template["id"])
    with pytest.raises(FleetConfigurationError):
        store.create_template(
            operator, template_id="runtime", name="Duplicate", configuration={"maxActions": 2}
        )
    store.create_template(
        identity("org-b"), template_id="other-org", name="Other", configuration={"safe": True}
    )
    with pytest.raises(FleetAuthorizationError):
        store.create_template(
            operator,
            template_id="cross-org-child",
            name="Cross org",
            parent_template_id="other-org",
            configuration={},
        )
    store.set_rollout(operator, "deploy-a", state="active", percentage=100)
    assert authority.status()["configuration_active"] is True
    store.set_emergency_stop(operator, "deploy-a", active=True)
    assert authority.status()["stopped"] is True


class FailingAuthority:
    """Synthetic runtime authority that proves fleet mutations fail closed."""

    def apply_configuration(self, _configuration: Mapping[str, Any]) -> None:
        """Reject activation."""
        raise RuntimeError("synthetic activation outage")

    def emergency_stop(self) -> None:
        """Reject emergency-stop propagation."""
        raise RuntimeError("synthetic stop outage")

    def clear_emergency_stop(self) -> None:
        """Reject stop clearing."""
        raise RuntimeError("synthetic clear outage")


def test_authority_outage_does_not_claim_activation(tmp_path: Path) -> None:
    """A runtime adapter outage leaves rollout and stop mutations unsuccessful."""
    store = EnterpriseFleetStore(
        tmp_path / "fleet.sqlite", authorities={"deploy-a": FailingAuthority()}
    )
    seed(store)
    operator = identity("org-a")
    template = store.create_template(
        operator, template_id="runtime", name="Runtime", configuration={"maxActions": 1}
    )
    store.assign_template(operator, "deploy-a", template["id"])
    with pytest.raises(FleetConfigurationError):
        store.set_rollout(operator, "deploy-a", state="active", percentage=100)
    with pytest.raises(FleetConfigurationError):
        store.set_emergency_stop(operator, "deploy-a", active=True)
    with pytest.raises(FleetConfigurationError):
        store.create_template(
            operator,
            template_id="unsafe",
            name="Unsafe",
            configuration={"token": "must-not-persist"},
        )


def call_api(
    app: EnterpriseFleetApplication,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    token: str = "fleet-admin-token-1234",  # noqa: S107 - synthetic test credential
) -> tuple[str, dict[str, Any]]:
    """Call the WSGI fleet boundary with a synthetic bearer token."""
    encoded = json.dumps(body).encode() if body is not None else b""
    status: list[str] = []

    def start_response(value: str, _headers: list[tuple[str, str]]) -> None:
        status.append(value)

    environ: dict[str, Any] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "CONTENT_LENGTH": str(len(encoded)),
        "wsgi.input": io.BytesIO(encoded),
        "HTTP_AUTHORIZATION": f"Bearer {token}",
    }
    payload = b"".join(app(environ, start_response))
    return status[0], json.loads(payload or b"{}")


def test_enterprise_api_is_authenticated_and_tenant_scoped(tmp_path: Path) -> None:
    """The HTTP boundary exposes inventory without leaking bearer sessions."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    token = "fleet-admin-token-1234"  # noqa: S105 - synthetic test credential
    identity_value = identity("org-a")
    app = EnterpriseFleetApplication(
        store,
        authenticator=StaticFleetAuthenticator({token: identity_value}),
        allowed_origin="http://localhost:5174",
    )

    status, unauthorized = call_api(
        app,
        "GET",
        "/api/enterprise/deployments",
        token="wrong-token-1234",  # noqa: S106
    )
    assert status.startswith("401")
    assert unauthorized["error"] == "authentication required"

    assert call_api(
        app, "POST", "/api/enterprise/organizations", {"organizationId": "org-a", "name": "Alpha"}
    )[0].startswith("201")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/projects",
        {"organizationId": "org-a", "projectId": "project-a", "name": "Payments"},
    )[0].startswith("201")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/deployments",
        {
            "organizationId": "org-a",
            "projectId": "project-a",
            "deploymentId": "deploy-a",
            "name": "Production",
            "environment": "prod",
            "region": "eu-west-2",
        },
    )[0].startswith("201")
    status, registered = call_api(
        app,
        "POST",
        "/api/enterprise/agents/register",
        {
            "deploymentId": "deploy-a",
            "agentId": "claude-a",
            "host": "claude-code",
            "projectRoot": "/workspace/payments",
        },
    )
    assert status.startswith("201")
    assert registered["sessionId"]
    assert "sessionId" not in call_api(app, "GET", "/api/enterprise/agents")[1]["items"][0]
    status, heartbeat = call_api(
        app,
        "POST",
        "/api/enterprise/agents/deploy-a/claude-a/heartbeat",
        {"sessionId": registered["sessionId"]},
    )
    assert status.startswith("200") and heartbeat["status"] == "connected"
    assert call_api(
        app,
        "POST",
        "/api/enterprise/templates",
        {
            "templateId": "template-prod",
            "name": "Production",
            "configuration": {"runtime": {"maxActions": 5}},
        },
    )[0].startswith("201")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/deployment-config",
        {"deploymentId": "deploy-a", "templateId": "template-prod"},
    )[0].startswith("200")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/deployment-config/rollout",
        {"deploymentId": "deploy-a", "state": "canary", "percentage": 10},
    )[0].startswith("200")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/templates",
        {
            "templateId": "template-v2",
            "name": "Production v2",
            "configuration": {"runtime": {"maxActions": 7}},
        },
    )[0].startswith("201")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/deployment-config",
        {"deploymentId": "deploy-a", "templateId": "template-v2"},
    )[0].startswith("200")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/deployment-config/batch-rollout",
        {"deploymentIds": ["deploy-a", "deploy-a"], "state": "canary", "percentage": 20},
    )[0].startswith("200")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/deployment-config/rollback",
        {"deploymentId": "deploy-a", "version": 1},
    )[0].startswith("200")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/emergency-stop",
        {"deploymentId": "deploy-a", "active": True},
    )[0].startswith("200")
    assert call_api(app, "GET", "/api/enterprise/health")[1]["items"][0]["status"] == "critical"
    assert call_api(app, "GET", "/api/enterprise/alerts")[1]["items"]
    status, drift = call_api(app, "GET", "/api/enterprise/drift")
    assert status.startswith("200") and drift["items"]
    status, disconnected = call_api(
        app,
        "POST",
        "/api/enterprise/agents/deploy-a/claude-a/disconnect",
        {"sessionId": registered["sessionId"]},
    )
    assert status.startswith("200") and disconnected["status"] == "offline"


def test_enterprise_api_rejects_forbidden_and_malformed_requests(tmp_path: Path) -> None:
    """The API never turns malformed or unauthorized browser input into mutation."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    viewer_token = "fleet-viewer-token-1234"  # noqa: S105 - synthetic test credential
    viewer = FleetIdentity("viewer", "org-a", frozenset({"viewer"}))
    app = EnterpriseFleetApplication(
        store, authenticator=StaticFleetAuthenticator({viewer_token: viewer})
    )
    status, payload = call_api(
        app,
        "POST",
        "/api/enterprise/organizations",
        {"organizationId": "org-a", "name": "Not allowed"},
        token=viewer_token,
    )
    assert status.startswith("403") and payload["error"] == "forbidden"
    status, payload = call_api(
        app, "POST", "/api/enterprise/organizations", {"name": "Missing"}, token=viewer_token
    )
    assert status.startswith("403")
    status, payload = call_api(app, "GET", "/api/enterprise/not-found", token=viewer_token)
    assert status.startswith("404") and payload["error"] == "not found"
