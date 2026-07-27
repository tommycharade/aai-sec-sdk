"""Adversarial and contract tests for the enterprise fleet foundation."""

from __future__ import annotations

import io
import json
import sqlite3
import sys
import types
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import agentic_security.enterprise_control_plane as fleet_module
from agentic_security import (
    CallbackFleetAuthenticator,
    CallbackFleetSecretResolver,
    EnterpriseFleetApplication,
    EnterpriseFleetStore,
    FleetAuthorizationError,
    FleetConfigurationError,
    FleetIdentity,
    FleetNotFoundError,
    FleetSecretReference,
    InMemoryAuditSink,
    InMemoryControlPlaneAuthority,
    PostgresFleetPersistenceAdapter,
    SQLiteFleetPersistenceAdapter,
    StaticFleetAuthenticator,
    WebhookFleetAlertSink,
)


class Clock:
    """Deterministic wall clock for heartbeat expiry tests."""

    def __init__(self) -> None:
        self.value = 1_000.0

    def __call__(self) -> float:
        return self.value


class AlertSink:
    """Synthetic redacted alert delivery adapter."""

    def __init__(self) -> None:
        self.alerts: list[dict[str, Any]] = []

    def publish(self, alert: Mapping[str, Any]) -> None:
        self.alerts.append(dict(alert))


def test_webhook_alert_sink_is_bounded_and_fail_closed() -> None:
    """The concrete alert adapter requires HTTPS and reports delivery failures."""
    requests: list[tuple[str, bytes, float]] = []

    class Response:
        status = 202

    def opener(request: Any, *, timeout: float) -> Response:
        requests.append((request.full_url, request.data, timeout))
        return Response()

    sink = WebhookFleetAlertSink("https://alerts.example.test/hook", opener=opener)
    sink.publish({"id": "alert-1", "severity": "high"})
    assert requests[0][0] == "https://alerts.example.test/hook"
    assert b"alert-1" in requests[0][1]

    with pytest.raises(FleetConfigurationError):
        WebhookFleetAlertSink("http://alerts.example.test/hook")
    with pytest.raises(FleetConfigurationError):
        WebhookFleetAlertSink("https://alerts.example.test/hook", timeout_seconds=0)

    def failed_opener(_request: Any, *, timeout: float) -> Response:
        raise OSError("synthetic outage")

    with pytest.raises(FleetConfigurationError):
        WebhookFleetAlertSink("https://alerts.example.test/hook", opener=failed_opener).publish(
            {"id": "alert-1"}
        )

    class RejectedResponse:
        status = 503

    with pytest.raises(FleetConfigurationError):
        WebhookFleetAlertSink(
            "https://alerts.example.test/hook",
            opener=lambda _request, *, timeout: RejectedResponse(),
        ).publish({"id": "alert-1"})


def test_callback_iam_adapter_fails_closed_and_preserves_verified_scope() -> None:
    """External OIDC/JWT verification and authorization remain explicit boundaries."""
    verified = FleetIdentity("iam-user", "org-a", frozenset({"viewer"}))
    authenticator = CallbackFleetAuthenticator(
        lambda authorization: verified if authorization == "valid" else None,
        lambda identity, action: identity.organization_id == "org-a" and action == "read",
    )
    assert authenticator.authenticate("valid") == verified
    assert authenticator.authenticate("invalid") is None
    assert authenticator.authorize(verified, "read") is True
    assert authenticator.authorize(verified, "manage_configuration") is False

    def fail_verification(_authorization: object) -> FleetIdentity | None:
        raise RuntimeError("IAM outage")

    def fail_authorization(_identity: FleetIdentity, _action: str) -> bool:
        raise RuntimeError("policy outage")

    failing = CallbackFleetAuthenticator(fail_verification, fail_authorization)
    assert failing.authenticate("valid") is None
    assert failing.authorize(verified, "read") is False


def test_secret_reference_resolver_never_accepts_material_as_configuration() -> None:
    """Secret managers resolve opaque references only at the deployment boundary."""
    reference = FleetSecretReference("aws-secretsmanager://prod/claude-token")
    seen: list[tuple[str, str]] = []

    def resolve(_reference: FleetSecretReference, purpose: str) -> str:
        seen.append((reference.reference, purpose))
        return "ephemeral-token"

    resolver = CallbackFleetSecretResolver(resolve)
    assert resolver.resolve(reference, "agentic-tool") == "ephemeral-token"
    assert seen == [(reference.reference, "agentic-tool")]
    with pytest.raises(FleetConfigurationError):
        FleetSecretReference("raw secret value")
    with pytest.raises(FleetConfigurationError):
        CallbackFleetSecretResolver(lambda _reference, _purpose: "").resolve(
            reference, "agentic-tool"
        )


def test_reference_persistence_is_explicitly_rejected_for_ha_requirements(tmp_path: Path) -> None:
    """A deployment cannot accidentally promote SQLite into an HA role."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    assert store.persistence_capabilities() == {
        "adapter": "sqlite-reference",
        "highAvailability": False,
        "schemaVersion": 5,
    }
    store.close()
    with pytest.raises(FleetConfigurationError):
        EnterpriseFleetStore(
            tmp_path / "ha.sqlite",
            persistence=SQLiteFleetPersistenceAdapter(),
            require_high_availability=True,
        )
    assert PostgresFleetPersistenceAdapter.supports_high_availability is True
    translated = fleet_module._PostgresFleetConnection._statement(
        "INSERT OR IGNORE INTO schema_migrations(version) VALUES(?)"
    )
    assert "INSERT INTO" in translated and "%s" in translated


def test_postgres_connection_translation_and_failure_mapping() -> None:
    """The optional adapter translates only the bounded reference SQL surface."""

    class FakeDatabase:
        def __init__(self) -> None:
            self.calls: list[tuple[str, Any]] = []
            self.fail_unique = False

        def execute(self, sql: str, params: Any = ()) -> FakeDatabase:
            self.calls.append((sql, params))
            if self.fail_unique:

                class UniqueViolation(Exception):
                    pass

                raise UniqueViolation("duplicate")
            return self

        def fetchall(self) -> list[dict[str, str]]:
            return [{"name": "team"}]

        def commit(self) -> None:
            self.calls.append(("COMMIT", ()))

        def rollback(self) -> None:
            self.calls.append(("ROLLBACK", ()))

        def close(self) -> None:
            self.calls.append(("CLOSE", ()))

    database = FakeDatabase()
    connection = fleet_module._PostgresFleetConnection(database)
    connection.execute("PRAGMA foreign_keys = ON")
    assert connection.execute("PRAGMA table_info(deployments)").fetchall() == [{"name": "team"}]
    connection.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES(?)", (4,))
    assert "ON CONFLICT DO NOTHING" in database.calls[-1][0]
    connection.execute(
        "INSERT INTO examples(id) VALUES(?) ON CONFLICT(id) DO UPDATE SET id=excluded.id",
        (1,),
    )
    assert database.calls[-1][0].count("ON CONFLICT") == 1
    connection.executescript("SELECT 1; SELECT 2;")
    connection.commit()
    connection.rollback()
    connection.close()

    database.fail_unique = True
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("INSERT INTO examples(id) VALUES(?)", (1,))
    assert any(call[0] == "ROLLBACK" for call in database.calls)


def test_postgres_adapter_connection_failure_is_normalized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Optional driver loading and connection failures abort before serving traffic."""
    fake_psycopg = types.ModuleType("psycopg")
    fake_rows = types.ModuleType("psycopg.rows")
    fake_rows.dict_row = object()  # type: ignore[attr-defined]

    def connect(**_kwargs: Any) -> Any:
        raise OSError("database unavailable")

    fake_psycopg.connect = connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "psycopg", fake_psycopg)
    monkeypatch.setitem(sys.modules, "psycopg.rows", fake_rows)
    with pytest.raises(FleetConfigurationError):
        PostgresFleetPersistenceAdapter().connect("postgresql://unavailable", 5000)


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
        "org-a",
        "project-a",
        "deploy-a",
        "Production",
        environment="prod",
        region="eu-west-2",
        team="platform",
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


def test_inventory_paginates_with_bounded_opaque_cursors(tmp_path: Path) -> None:
    """Large tenant inventories return bounded pages without crossing tenants."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    for index in range(1, 4):
        store.create_deployment(
            "org-a",
            "project-a",
            f"deploy-{index}",
            f"Deployment {index}",
            environment="staging",
            region="eu-west-2",
        )

    first = store.list_inventory(identity("org-a"), "deployments", limit=2)
    second = store.list_inventory(
        identity("org-a"), "deployments", cursor=first.next_cursor, limit=2
    )

    assert len(first.items) == 2
    assert first.next_cursor == "2"
    assert len(second.items) == 2
    assert first.items[0]["organization_id"] == "org-a"
    with pytest.raises(FleetConfigurationError):
        store.list_inventory(identity("org-a"), "deployments", limit=201)
    with pytest.raises(FleetConfigurationError):
        store.list_inventory(identity("org-a"), "deployments", cursor="not-a-cursor")

    evidence = store.compliance_evidence(identity("org-a"))
    assert evidence["deploymentCount"] == 4


def test_migrates_legacy_deployments_with_team_dimension(tmp_path: Path) -> None:
    """The schema migration preserves legacy deployments and adds team metadata."""
    database = tmp_path / "legacy.sqlite"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY);
        INSERT INTO schema_migrations(version) VALUES(1);
        CREATE TABLE organizations(
            id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at REAL NOT NULL
        );
        CREATE TABLE projects(
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, name TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        CREATE TABLE deployments(
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, project_id TEXT NOT NULL,
            name TEXT NOT NULL, environment TEXT NOT NULL, region TEXT NOT NULL,
            sdk_version TEXT, created_at REAL NOT NULL
        );
        INSERT INTO organizations VALUES('org-a', 'Alpha', 1);
        INSERT INTO projects VALUES('project-a', 'org-a', 'Platform', 1);
        INSERT INTO deployments VALUES(
            'deploy-a', 'org-a', 'project-a', 'Legacy', 'prod', 'eu', '1.0.0', 1
        );
        """
    )
    connection.commit()
    connection.close()

    store = EnterpriseFleetStore(database)
    items = store.list_inventory(identity("org-a"), "deployments").items

    assert items[0]["team"] == ""


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
    sessions = store.list_inventory(identity("org-a"), "sessions").items
    assert sessions[0]["status"] == "active"
    assert "sessionId" not in sessions[0]
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


def test_slo_samples_are_bounded_scoped_and_fail_closed(tmp_path: Path) -> None:
    """Availability uses explicit samples, excludes stale data, and isolates tenants."""
    clock = Clock()
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite", now=clock, slo_window_seconds=300)
    seed(store)

    first = store.record_slo_sample(identity("org-a"), "deploy-a")
    assert first["status"] == "healthy"
    assert store.slo(identity("org-a")).items[0]["status"] == "meeting"
    clock.value += 301
    assert store.slo(identity("org-a")).items[0]["status"] == "no_data"
    with pytest.raises(FleetAuthorizationError):
        store.record_slo_sample(identity("org-b"), "deploy-a")


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
    sink = AlertSink()
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite", alert_sink=sink)
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
    dispatched = store.dispatch_alerts(operator)
    assert dispatched.items[0]["delivered"] is True and sink.alerts
    acknowledged = store.acknowledge_alert(operator, dispatched.items[0]["id"])
    assert acknowledged["acknowledged"] is True
    assert store.dispatch_alerts(operator).items == ()
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


def test_typed_governance_sections_reject_typos_and_preserve_safe_controls(
    tmp_path: Path,
) -> None:
    """Enterprise governance fields are closed schemas without storing credentials."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    operator = identity("org-a")
    template = store.create_template(
        operator,
        template_id="governance",
        name="Governance",
        configuration={
            "policy": {"provider": "opa", "denyByDefault": True},
            "approvals": {"provider": "http", "ttlSeconds": 60},
            "tools": {"allowed": ["read_file"]},
            "budgets": {"maxActions": 10, "maxCostUnits": 100},
            "credentials": {"enabled": False, "mode": "broker"},
            "isolation": {"requiredForHighRisk": True, "verifier": "attested"},
            "audit": {"provider": "replicated", "redactSensitiveData": True},
            "telemetry": {"enabled": True, "exporter": "otlp"},
        },
    )
    assert template["configuration"]["budgets"]["maxActions"] == 10
    with pytest.raises(FleetConfigurationError):
        store.create_template(
            operator,
            template_id="typo",
            name="Typo",
            configuration={"budgets": {"maxAction": 10}},
        )


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


def test_startup_reconciles_persisted_authority_state_fail_closed(tmp_path: Path) -> None:
    """A restarted API applies persisted state before serving and aborts on outage."""
    database = tmp_path / "fleet.sqlite"
    authority = InMemoryControlPlaneAuthority()
    store = EnterpriseFleetStore(database, authorities={"deploy-a": authority})
    seed(store)
    operator = identity("org-a")
    template = store.create_template(
        operator,
        template_id="runtime",
        name="Runtime",
        configuration={"runtime": {"maxActions": 1}},
    )
    store.assign_template(operator, "deploy-a", template["id"])
    store.set_rollout(operator, "deploy-a", state="active", percentage=100)
    store.close()

    restarted_authority = InMemoryControlPlaneAuthority()
    restarted = EnterpriseFleetStore(database, authorities={"deploy-a": restarted_authority})
    EnterpriseFleetApplication(
        restarted,
        authenticator=StaticFleetAuthenticator({"fleet-admin-token-1234": identity("org-a")}),
    )
    assert restarted_authority.status()["configuration_active"] is True

    restarted.close()
    with pytest.raises(FleetConfigurationError):
        EnterpriseFleetApplication(
            EnterpriseFleetStore(database, authorities={"deploy-a": FailingAuthority()}),
            authenticator=StaticFleetAuthenticator({"fleet-admin-token-1234": identity("org-a")}),
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

    status, preflight = call_api(app, "OPTIONS", "/api/enterprise/deployments")
    assert status.startswith("204")
    assert preflight == {}

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
    status, sessions = call_api(app, "GET", "/api/enterprise/sessions")
    assert status.startswith("200")
    assert sessions["items"][0]["status"] == "active"
    assert "sessionId" not in sessions["items"][0]
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
    status, templates = call_api(app, "GET", "/api/enterprise/templates")
    assert status.startswith("200") and templates["items"][0]["id"] == "template-prod"
    status, configurations = call_api(app, "GET", "/api/enterprise/deployment-config")
    assert status.startswith("200") and configurations["items"][0]["version"] == 1
    status, validation = call_api(
        app,
        "POST",
        "/api/enterprise/templates/validate",
        {"configuration": {"runtime": {"maxActions": 8}}},
    )
    assert status.startswith("200") and validation["valid"] is True
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
    status, history = call_api(app, "GET", "/api/enterprise/deployment-config/history")
    assert status.startswith("200") and history["items"][0]["deploymentId"] == "deploy-a"
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
    status, alerts = call_api(app, "GET", "/api/enterprise/alerts")
    assert status.startswith("200") and alerts["items"]
    alert_id = alerts["items"][0]["id"]
    assert call_api(app, "POST", f"/api/enterprise/alerts/{alert_id}/ack")[0].startswith("200")
    assert call_api(app, "POST", "/api/enterprise/alerts/dispatch")[0].startswith("400")
    assert call_api(app, "GET", "/api/enterprise/health")[1]["items"][0]["status"] == "critical"
    status, sample = call_api(
        app, "POST", "/api/enterprise/slo/sample", {"deploymentId": "deploy-a"}
    )
    assert status.startswith("201") and sample["deploymentId"] == "deploy-a"
    status, slo = call_api(app, "GET", "/api/enterprise/slo")
    assert status.startswith("200") and slo["items"][0]["sampleCount"] == 1
    status, evidence = call_api(app, "GET", "/api/enterprise/compliance/evidence")
    assert status.startswith("200")
    assert evidence["organizationId"] == "org-a"
    assert evidence["redaction"]["sessionTokensIncluded"] is False
    assert evidence["audit"]
    other_evidence = store.compliance_evidence(identity("org-b"))
    assert other_evidence["deploymentCount"] == 0
    assert other_evidence["audit"] == []
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


def test_policies_groups_and_agent_membership_are_tenant_scoped(tmp_path: Path) -> None:
    """Operators can assign policies to groups and manage membership without exposing sessions."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    token = "fleet-admin-token-1234"  # noqa: S105 - synthetic test credential
    app = EnterpriseFleetApplication(
        store,
        authenticator=StaticFleetAuthenticator({token: identity("org-a")}),
    )
    assert call_api(
        app, "POST", "/api/enterprise/organizations", {"organizationId": "org-a", "name": "Alpha"}
    )[0].startswith("201")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/projects",
        {"organizationId": "org-a", "projectId": "project-a", "name": "Platform"},
    )[0].startswith("201")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/deployments",
        {
            "organizationId": "org-a",
            "projectId": "project-a",
            "deploymentId": "deploy-a",
            "name": "Local",
            "environment": "dev",
            "region": "local",
        },
    )[0].startswith("201")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/agents/register",
        {
            "deploymentId": "deploy-a",
            "agentId": "claude-a",
            "host": "claude",
            "projectRoot": "/workspace",
        },
    )[0].startswith("201")
    status, policy = call_api(
        app,
        "POST",
        "/api/enterprise/policies",
        {
            "policyId": "policy-safe",
            "name": "Safe default",
            "configuration": {"policy": {"denyByDefault": True}},
        },
    )
    assert status.startswith("201") and policy["id"] == "policy-safe"
    status, policies = call_api(app, "GET", "/api/enterprise/policies")
    assert status.startswith("200") and policies["items"][0]["id"] == "policy-safe"
    status, duplicate_policy = call_api(
        app,
        "POST",
        "/api/enterprise/policies",
        {"policyId": "policy-safe", "name": "Duplicate", "configuration": {}},
    )
    assert status.startswith("400") and duplicate_policy["error"] == "policy already exists"
    status, group = call_api(
        app,
        "POST",
        "/api/enterprise/groups",
        {"groupId": "group-platform", "name": "Platform", "policyId": "policy-safe"},
    )
    assert (
        status.startswith("201") and group["policyName"] == "Safe default" and group["agents"] == []
    )
    status, duplicate_group = call_api(
        app,
        "POST",
        "/api/enterprise/groups",
        {"groupId": "group-platform", "name": "Duplicate", "policyId": "policy-safe"},
    )
    assert status.startswith("400") and duplicate_group["error"] == "group already exists"
    status, enrolled = call_api(
        app,
        "POST",
        "/api/enterprise/groups/group-platform/agents",
        {"deploymentId": "deploy-a", "agentId": "claude-a"},
    )
    assert status.startswith("201") and enrolled["agents"][0]["id"] == "claude-a"
    status, duplicate_member = call_api(
        app,
        "POST",
        "/api/enterprise/groups/group-platform/agents",
        {"deploymentId": "deploy-a", "agentId": "claude-a"},
    )
    assert (
        status.startswith("400") and duplicate_member["error"] == "agent is already in this group"
    )
    status, groups = call_api(app, "GET", "/api/enterprise/groups")
    assert status.startswith("200") and groups["items"][0]["policyId"] == "policy-safe"
    status, removed = call_api(
        app, "DELETE", "/api/enterprise/groups/group-platform/agents/deploy-a/claude-a"
    )
    assert status.startswith("200") and removed["agents"] == []
    status, duplicate = call_api(
        app, "DELETE", "/api/enterprise/groups/group-platform/agents/deploy-a/claude-a"
    )
    assert status.startswith("404") and duplicate["error"] == "agent group membership not found"
