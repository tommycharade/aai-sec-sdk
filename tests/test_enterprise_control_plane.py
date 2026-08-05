"""Adversarial and contract tests for the enterprise fleet foundation."""

from __future__ import annotations

import base64
import hashlib
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
    AgentHost,
    CallbackFleetAuthenticator,
    CallbackFleetSecretResolver,
    EnterpriseFleetApplication,
    EnterpriseFleetStore,
    FleetAuthorizationError,
    FleetConfigurationError,
    FleetConflictError,
    FleetIdentity,
    FleetNotFoundError,
    FleetSecretReference,
    InMemoryAuditSink,
    InMemoryControlPlaneAuthority,
    ManagedConfigurationCompiler,
    ManagedDeploymentPackage,
    ManagedExecutableRequirement,
    ManagedPlatform,
    ManagedPolicyIntent,
    NativeActionDecision,
    NativeActionRule,
    PostgresFleetPersistenceAdapter,
    SQLiteFleetPersistenceAdapter,
    StaticFleetAuthenticator,
    WebhookFleetAlertSink,
)
from agentic_security.policy_sources import (
    PolicyExportSignature,
    PolicySourceRequest,
    PolicySourceVerificationError,
    VerifiedPolicySource,
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


class PolicyVerifier:
    """Synthetic deployment-owned verifier with deterministic provider evidence."""

    def __init__(self, content: bytes) -> None:
        self.content = content
        self.requests: list[PolicySourceRequest] = []
        self.failure: Exception | None = None

    def verify(self, request: PolicySourceRequest) -> VerifiedPolicySource:
        """Return reviewed and signed synthetic GitHub evidence."""
        self.requests.append(request)
        if self.failure is not None:
            raise self.failure
        return VerifiedPolicySource(
            provider="github",
            repository=request.repository,
            commit_sha=request.commit_sha,
            blob_sha="b" * 40,
            path=request.path,
            content=self.content,
            pull_request="https://github.com/acme/policies/pull/42",
            reviewed_by=("reviewer-2",),
            signer_identity="author-1",
            retrieved_at=1_000,
        )


class PolicySigner:
    """Synthetic signer retaining canonical bytes for contract assertions."""

    def __init__(self) -> None:
        self.payloads: list[bytes] = []

    def sign(self, payload: bytes) -> PolicyExportSignature:
        """Return bounded synthetic KMS-style signing evidence."""
        self.payloads.append(payload)
        return PolicyExportSignature(
            key_id="kms://synthetic/policy-export",
            algorithm="ECDSA_SHA_256",
            signature=b"synthetic-signature",
            signed_at=1_001,
        )


def policy_source_bytes(*, organization_id: str = "org-a") -> bytes:
    """Build one closed-schema policy source using only synthetic values."""
    return json.dumps(
        {
            "schemaVersion": 1,
            "policyId": "policy-from-git",
            "organizationId": organization_id,
            "name": "Reviewed Git policy",
            "componentRefs": [],
            "localConfiguration": {
                "policy": {"denyByDefault": True},
                "tools": {"allowed": ["read_repository"], "denied": ["shell"]},
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


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
        "schemaVersion": 10,
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


def identity(
    organization_id: str,
    *,
    subject: str = "operator-1",
    projects: frozenset[str] = frozenset(),
) -> FleetIdentity:
    """Build a synthetic tenant identity."""
    return FleetIdentity(subject, organization_id, frozenset({"admin"}), projects)


def create_active_policy(
    store: EnterpriseFleetStore,
    operator: FleetIdentity,
    *,
    policy_id: str,
    name: str,
    configuration: dict[str, Any],
) -> dict[str, Any]:
    """Complete the governed lifecycle with a distinct synthetic reviewer."""
    created = store.create_policy(
        operator,
        policy_id=policy_id,
        name=name,
        configuration=configuration,
    )
    version = int(created["latestVersion"])
    store.submit_policy_version(operator, policy_id, version)
    reviewer = identity(operator.organization_id, subject="reviewer-2")
    store.decide_policy_version(
        reviewer,
        policy_id,
        version,
        decision="approved",
        reason="Synthetic independent review",
    )
    store.stage_policy_version(reviewer, policy_id, version)
    return store.activate_policy_version(
        reviewer,
        policy_id,
        version,
        expected_active_version=int(created["version"]),
    )


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


def managed_package(
    *, policy_version: int = 1, host: AgentHost = AgentHost.CLAUDE_CODE
) -> tuple[ManagedDeploymentPackage, dict[str, Any]]:
    """Build one synthetic canonical host package and matching desired target."""
    hook_path = "/opt/aai-security/hooks/native-policy"
    bundle = ManagedConfigurationCompiler().compile(
        ManagedPolicyIntent(
            "policy-safe",
            policy_version,
            action_rules=(NativeActionRule("Read", NativeActionDecision.ALLOW, "synthetic read"),),
        ),
        host=host,
        host_version="0.146.0" if host is AgentHost.CODEX_CLI else "2.1.220",
        platform=ManagedPlatform.LINUX,
        hook_command=hook_path,
    )
    package = ManagedDeploymentPackage.from_bundle(
        bundle,
        required_executables=(
            ManagedExecutableRequirement(hook_path, hashlib.sha256(b"synthetic hook").hexdigest()),
        ),
    )
    return package, {
        "host": package.host.value,
        "hostVersion": package.host_version,
        "platform": package.platform.value,
        "bundleHash": package.bundle_hash,
        "policyId": package.policy_id,
        "policyVersion": package.policy_version,
    }


def native_enforced_evidence(now: int, bundle_hash: str) -> dict[str, Any]:
    """Build complete synthetic positive Codex process evidence."""
    return {
        "host": "codex-cli",
        "hostVersion": "0.146.0",
        "platform": "linux",
        "bundleHash": bundle_hash,
        "state": "enforced",
        "reason": "effective-controls-match",
        "expectedDigest": "a" * 64,
        "observedDigest": "b" * 64,
        "approvalPolicy": "on-request",
        "sandboxMode": "workspace-write",
        "defaultPermissions": ":workspace",
        "webSearchMode": "cached",
        "managedMcpServerNames": [],
        "unexpectedMcpServerCount": 0,
        "preToolHookSha256": ["c" * 64],
        "requirements": {
            "allowedApprovalPolicies": ["on-request"],
            "defaultPermissions": ":workspace",
            "allowedPermissionProfiles": {":workspace": True},
            "allowedSandboxModes": [],
            "allowedWebSearchModes": ["cached"],
            "allowManagedHooksOnly": True,
            "featureRequirements": {"hooks": True},
            "network": {
                "enabled": None,
                "managedAllowedDomainsOnly": None,
                "domains": {},
            },
        },
        "securityOrigins": {"approval_policy": "system"},
        "mismatches": [],
        "unverifiedControls": [],
        "allowedActions": ["Read"],
        "deniedActions": ["Bash(rm *)"],
        "approvalRequiredActions": [],
        "verifiedAt": now,
        "expiresAt": now + 60,
    }


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


def test_migrates_existing_active_policy_into_immutable_version_ledger(tmp_path: Path) -> None:
    """A schema upgrade preserves active fleet authority and creates review history."""
    database = tmp_path / "policy-v6.sqlite"
    store = EnterpriseFleetStore(database)
    store.create_organization("org-a", "Alpha")
    canonical = store._configuration_json({"policy": {"denyByDefault": True}})
    store._connection.execute(
        "INSERT INTO policies(id,organization_id,name,configuration,version,created_at,created_by) "
        "VALUES(?,?,?,?,?,?,?)",
        ("policy-existing", "org-a", "Existing", canonical, 3, 10.0, "legacy-author"),
    )
    store._connection.execute("DELETE FROM policy_versions WHERE policy_id=?", ("policy-existing",))
    store._connection.execute("DELETE FROM schema_migrations WHERE version=7")
    store._connection.execute("DELETE FROM schema_migrations WHERE version=8")
    store._connection.commit()
    store.close()

    migrated = EnterpriseFleetStore(database)
    policy = migrated.list_policies(identity("org-a")).items[0]
    version = migrated.policy_version(identity("org-a"), "policy-existing", 3)
    assert policy["activeVersion"] == 3 and policy["governanceState"] == "active"
    assert version["state"] == "active"
    assert version["author"] == "legacy-author"
    assert version["contentHash"] == hashlib.sha256(canonical.encode()).hexdigest()
    assert version["composition"]["localConfiguration"] == {"policy": {"denyByDefault": True}}
    assert version["composition"]["componentRefs"] == []
    assert len(version["composition"]["graphDigest"]) == 64


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
    reported = store.heartbeat(
        identity("org-a"),
        "deploy-a",
        "claude-a",
        fresh["sessionId"],
        telemetry={
            "actionsTotal": 12,
            "actionsAdmitted": 10,
            "allowed": 9,
            "denied": 2,
            "approvalRequired": 1,
            "executed": 9,
            "failed": 0,
            "timedOut": 0,
            "cancelled": 0,
            "resultRejected": 0,
            "runtimeErrors": 0,
            "costUnits": 14,
            "averageLatencyMs": 12.5,
            "maxLatencyMs": 43.0,
        },
    )
    assert reported["telemetry"]["actionsTotal"] == 12
    assert store.list_inventory(identity("org-a"), "agents").items[0]["telemetry"]["denied"] == 2
    with pytest.raises(FleetConfigurationError):
        store.heartbeat(
            identity("org-a"),
            "deploy-a",
            "claude-a",
            fresh["sessionId"],
            telemetry={"secret": 1},
        )
    disconnected = store.disconnect(identity("org-a"), "deploy-a", "claude-a", fresh["sessionId"])
    assert disconnected["status"] == "offline"
    assert {event.event_type for event in audit.events()} >= {
        "fleet_agent_registered",
        "fleet_agent_heartbeat",
        "fleet_agent_disconnected",
    }


def test_managed_configuration_posture_is_server_derived_and_fail_closed(tmp_path: Path) -> None:
    """Desired and observed managed bundles match exactly and expire predictably."""
    clock = Clock()
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite", now=clock)
    seed(store)
    operator = identity("org-a")
    registered = store.register_agent(
        operator,
        deployment_id="deploy-a",
        agent_id="codex-a",
        host="codex-cli",
        project_root="/workspace/payments",
    )
    desired = {
        "host": "codex-cli",
        "hostVersion": "0.146.0",
        "platform": "linux",
        "bundleHash": "b" * 64,
        "policyId": "policy-safe",
        "policyVersion": 4,
    }
    store.create_template(
        operator,
        template_id="managed-codex",
        name="Managed Codex",
        configuration={"managedHost": desired},
    )
    store.assign_template(operator, "deploy-a", "managed-codex")
    assert (
        store.list_inventory(operator, "agents").items[0]["managed_configuration"]["status"]
        == "missing"
    )

    report = {
        **desired,
        "source": "codex-system",
        "verifiedAt": 990,
        "expiresAt": 1_100,
    }
    enforced = store.heartbeat(
        operator,
        "deploy-a",
        "codex-a",
        registered["sessionId"],
        managed_configuration=report,
    )
    assert enforced["managed_configuration"]["status"] == "enforced"
    assert enforced["managed_configuration"]["observed"]["source"] == "codex-system"

    changed = dict(report, bundleHash="c" * 64)
    conflict = store.heartbeat(
        operator,
        "deploy-a",
        "codex-a",
        registered["sessionId"],
        managed_configuration=changed,
    )
    assert conflict["managed_configuration"]["status"] == "conflict"
    with pytest.raises(FleetConfigurationError):
        store.heartbeat(
            operator,
            "deploy-a",
            "codex-a",
            registered["sessionId"],
            managed_configuration=dict(report, source="project-file"),
        )
    store.heartbeat(
        operator,
        "deploy-a",
        "codex-a",
        registered["sessionId"],
        managed_configuration=report,
    )
    clock.value = 1_200
    assert (
        store.list_inventory(operator, "agents").items[0]["managed_configuration"]["status"]
        == "stale"
    )


def test_codex_native_effective_controls_are_validated_and_expire(tmp_path: Path) -> None:
    """Fleet reads show safe process posture and reject secret-bearing extensions."""
    clock = Clock()
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite", now=clock)
    seed(store)
    operator = identity("org-a")
    registered = store.register_agent(
        operator,
        deployment_id="deploy-a",
        agent_id="codex-a",
        host="codex-cli",
        project_root="/workspace/payments",
    )
    _package, desired = managed_package(host=AgentHost.CODEX_CLI)
    store.create_template(
        operator,
        template_id="managed-codex",
        name="Managed Codex",
        configuration={"managedHost": desired},
    )
    store.assign_template(operator, "deploy-a", "managed-codex")
    create_active_policy(
        store,
        operator,
        policy_id="policy-safe",
        name="Safe",
        configuration={"tools": {"allowed": ["lookup_record"]}},
    )
    store.create_group(
        operator, group_id="group-platform", name="Platform", policy_id="policy-safe"
    )
    store.add_agent_to_group(
        operator, group_id="group-platform", deployment_id="deploy-a", agent_id="codex-a"
    )
    evidence = {
        "host": "codex-cli",
        "hostVersion": "0.146.0",
        "platform": "linux",
        "bundleHash": desired["bundleHash"],
        "state": "missing",
        "reason": "administrator-requirements-missing",
        "expectedDigest": "a" * 64,
        "observedDigest": "b" * 64,
        "approvalPolicy": "on-request",
        "sandboxMode": "workspace-write",
        "defaultPermissions": None,
        "webSearchMode": None,
        "managedMcpServerNames": [],
        "unexpectedMcpServerCount": 1,
        "preToolHookSha256": ["c" * 64],
        "requirements": None,
        "securityOrigins": {"approval_policy": "user"},
        "mismatches": [],
        "unverifiedControls": [],
        "allowedActions": [],
        "deniedActions": ["Read"],
        "approvalRequiredActions": [],
        "verifiedAt": 1_000,
        "expiresAt": 1_060,
    }

    result = store.heartbeat(
        operator,
        "deploy-a",
        "codex-a",
        registered["sessionId"],
        managed_configuration={
            **desired,
            "source": "codex-system",
            "verifiedAt": 1_000,
            "expiresAt": 1_300,
        },
        native_effective_controls=evidence,
    )

    assert result["native_effective_controls"]["status"] == "missing"
    assert result["native_effective_controls"]["desired"] == {
        "bundleHash": desired["bundleHash"],
        "hostVersion": desired["hostVersion"],
        "platform": desired["platform"],
    }
    assert result["native_effective_controls"]["observed"] == evidence
    codex_identity = FleetIdentity("codex-a", "org-a", frozenset({"agent"}))
    with pytest.raises(FleetConfigurationError, match="Codex native effective controls"):
        store.effective_agent_policy(codex_identity, deployment_id="deploy-a", agent_id="codex-a")
    hostile = dict(evidence, rawConfig={"Authorization": "Bearer synthetic-secret"})
    with pytest.raises(FleetConfigurationError, match="invalid schema") as caught:
        store.heartbeat(
            operator,
            "deploy-a",
            "codex-a",
            registered["sessionId"],
            native_effective_controls=hostile,
        )
    assert "synthetic-secret" not in str(caught.value)
    clock.value = 1_100
    agent = store.list_inventory(operator, "agents").items[0]
    assert agent["native_effective_controls"]["status"] == "stale"

    clock.value = 1_050
    forged = dict(
        evidence,
        bundleHash="e" * 64,
        verifiedAt=1_050,
        expiresAt=1_110,
    )
    result = store.heartbeat(
        operator,
        "deploy-a",
        "codex-a",
        registered["sessionId"],
        native_effective_controls=forged,
    )
    assert result["native_effective_controls"]["status"] == "conflict"
    with pytest.raises(FleetConfigurationError, match="Codex native effective controls"):
        store.effective_agent_policy(codex_identity, deployment_id="deploy-a", agent_id="codex-a")
    result = store.heartbeat(
        operator,
        "deploy-a",
        "codex-a",
        registered["sessionId"],
        native_effective_controls=native_enforced_evidence(1_050, desired["bundleHash"]),
    )
    assert result["native_effective_controls"]["status"] == "enforced"
    assert (
        store.effective_agent_policy(codex_identity, deployment_id="deploy-a", agent_id="codex-a")[
            "policy"
        ]["id"]
        == "policy-safe"
    )
    verification = store.verify_agent(operator, deployment_id="deploy-a", agent_id="codex-a")
    assert verification["checks"]["nativeEffectiveControls"]["passed"] is True


def test_managed_package_publication_and_agent_repair_are_digest_bound(tmp_path: Path) -> None:
    """A drifted exact agent can retrieve, verify and later report its package."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    operator = identity("org-a")
    store.register_agent(
        operator,
        deployment_id="deploy-a",
        agent_id="claude-a",
        host="claude-code",
        project_root="/workspace/payments",
    )
    package, desired = managed_package()
    store.create_template(
        operator,
        template_id="managed-claude",
        name="Managed Claude",
        configuration={"managedHost": desired},
    )
    store.assign_template(operator, "deploy-a", "managed-claude")
    store.set_rollout(operator, "deploy-a", state="active", percentage=100)

    published = store.publish_managed_deployment_package(
        operator,
        "deploy-a",
        package.to_json(),
        expected_package_sha256=package.package_sha256,
        expected_revision=0,
    )
    assert published == {
        "revision": 1,
        "status": "current",
        "packageSha256": package.package_sha256,
        "bundleHash": package.bundle_hash,
        "host": "claude-code",
        "hostVersion": "2.1.220",
        "platform": "linux",
        "policyId": "policy-safe",
        "policyVersion": 1,
        "publishedAt": published["publishedAt"],
        "publishedBy": "operator-1",
    }
    assert "packageBase64" not in store.managed_deployment_package_metadata(operator, "deploy-a")

    agent = FleetIdentity("claude-a", "org-a", frozenset({"agent"}))
    response = store.agent_managed_deployment_package(
        agent, deployment_id="deploy-a", agent_id="claude-a"
    )
    assert response["status"] == "current"
    downloaded = base64.b64decode(response["packageBase64"], validate=True)
    assert (
        ManagedDeploymentPackage.from_json(
            downloaded, expected_package_sha256=response["packageSha256"]
        )
        == package
    )


def test_managed_package_rejects_stale_cross_scope_and_unselected_requests(tmp_path: Path) -> None:
    """Publication and retrieval never cross tenant, revision, target or rollout scope."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    operator = identity("org-a")
    store.register_agent(
        operator,
        deployment_id="deploy-a",
        agent_id="claude-a",
        host="claude-code",
        project_root="/workspace/payments",
    )
    package, desired = managed_package()
    store.create_template(
        operator,
        template_id="managed-claude",
        name="Managed Claude",
        configuration={"managedHost": desired},
    )
    store.assign_template(operator, "deploy-a", "managed-claude")

    with pytest.raises(FleetAuthorizationError):
        store.publish_managed_deployment_package(
            identity("org-b"),
            "deploy-a",
            package.to_json(),
            expected_package_sha256=package.package_sha256,
            expected_revision=0,
        )
    wrong, _wrong_desired = managed_package(policy_version=2)
    with pytest.raises(FleetConfigurationError, match="does not match"):
        store.publish_managed_deployment_package(
            operator,
            "deploy-a",
            wrong.to_json(),
            expected_package_sha256=wrong.package_sha256,
            expected_revision=0,
        )
    store.publish_managed_deployment_package(
        operator,
        "deploy-a",
        package.to_json(),
        expected_package_sha256=package.package_sha256,
        expected_revision=0,
    )
    with pytest.raises(FleetConfigurationError, match="revision is stale"):
        store.publish_managed_deployment_package(
            operator,
            "deploy-a",
            package.to_json(),
            expected_package_sha256=package.package_sha256,
            expected_revision=0,
        )
    agent = FleetIdentity("claude-a", "org-a", frozenset({"agent"}))
    with pytest.raises(FleetConfigurationError, match="rollout is not active"):
        store.agent_managed_deployment_package(agent, deployment_id="deploy-a", agent_id="claude-a")
    store.set_rollout(operator, "deploy-a", state="active", percentage=100)
    with pytest.raises(FleetAuthorizationError, match="does not match"):
        store.agent_managed_deployment_package(
            FleetIdentity("another-agent", "org-a", frozenset({"agent"})),
            deployment_id="deploy-a",
            agent_id="claude-a",
        )
    store.set_agent_emergency_stop(
        operator, deployment_id="deploy-a", agent_id="claude-a", active=True
    )
    with pytest.raises(FleetConfigurationError, match="emergency stop"):
        store.agent_managed_deployment_package(agent, deployment_id="deploy-a", agent_id="claude-a")


def test_managed_package_becomes_unavailable_when_desired_state_changes(tmp_path: Path) -> None:
    """A template change invalidates an old package before the next endpoint request."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    operator = identity("org-a")
    store.register_agent(
        operator,
        deployment_id="deploy-a",
        agent_id="claude-a",
        host="claude-code",
        project_root="/workspace/payments",
    )
    package, desired = managed_package()
    store.create_template(
        operator,
        template_id="managed-v1",
        name="Managed v1",
        configuration={"managedHost": desired},
    )
    store.assign_template(operator, "deploy-a", "managed-v1")
    store.publish_managed_deployment_package(
        operator,
        "deploy-a",
        package.to_json(),
        expected_package_sha256=package.package_sha256,
        expected_revision=0,
    )
    store.set_rollout(operator, "deploy-a", state="active", percentage=100)
    _next_package, next_desired = managed_package(policy_version=2)
    store.create_template(
        operator,
        template_id="managed-v2",
        name="Managed v2",
        configuration={"managedHost": next_desired},
    )
    store.assign_template(operator, "deploy-a", "managed-v2")
    store.set_rollout(operator, "deploy-a", state="active", percentage=100)
    assert store.managed_deployment_package_metadata(operator, "deploy-a")["status"] == "stale"
    with pytest.raises(FleetConfigurationError, match="does not match current"):
        store.agent_managed_deployment_package(
            FleetIdentity("claude-a", "org-a", frozenset({"agent"})),
            deployment_id="deploy-a",
            agent_id="claude-a",
        )


def test_managed_package_http_routes_separate_admin_metadata_from_agent_content(
    tmp_path: Path,
) -> None:
    """The HTTP boundary publishes by admin and returns bytes only on the agent route."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    operator = identity("org-a")
    store.register_agent(
        operator,
        deployment_id="deploy-a",
        agent_id="claude-a",
        host="claude-code",
        project_root="/workspace/payments",
    )
    package, desired = managed_package()
    store.create_template(
        operator,
        template_id="managed-claude",
        name="Managed Claude",
        configuration={"managedHost": desired},
    )
    store.assign_template(operator, "deploy-a", "managed-claude")
    store.set_rollout(operator, "deploy-a", state="active", percentage=100)
    admin_token = "fleet-admin-token-1234"  # noqa: S105 - synthetic test credential
    agent_token = "fleet-agent-token-1234"  # noqa: S105 - synthetic test credential
    app = EnterpriseFleetApplication(
        store,
        authenticator=StaticFleetAuthenticator(
            {
                admin_token: operator,
                agent_token: FleetIdentity("claude-a", "org-a", frozenset({"agent"})),
            }
        ),
    )
    body = {
        "expectedRevision": 0,
        "packageBase64": base64.b64encode(package.to_json()).decode(),
        "packageSha256": package.package_sha256,
    }
    status, published = call_api(
        app,
        "PUT",
        "/api/enterprise/deployments/deploy-a/managed-package",
        body,
        token=admin_token,
    )
    assert status.startswith("201") and published["revision"] == 1
    status, metadata = call_api(
        app,
        "GET",
        "/api/enterprise/deployments/deploy-a/managed-package",
        token=admin_token,
    )
    assert status.startswith("200") and "packageBase64" not in metadata
    status, downloaded = call_api(
        app,
        "GET",
        "/api/enterprise/agents/deploy-a/claude-a/managed-package",
        token=agent_token,
    )
    assert status.startswith("200") and downloaded["packageBase64"] == body["packageBase64"]
    status, denied = call_api(
        app,
        "PUT",
        "/api/enterprise/deployments/deploy-a/managed-package",
        body,
        token=agent_token,
    )
    assert status.startswith("403") and denied["error"] == "forbidden"


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


@pytest.mark.parametrize(
    "patterns",
    [
        ["(a+)+"],
        ["("],
        ["a" * 257],
        "not-a-list",
        ["safe"] * 101,
    ],
)
def test_fleet_configuration_rejects_unsafe_command_patterns(patterns: object) -> None:
    """Every enterprise write path rejects unbounded or backtracking hook policy."""
    with pytest.raises(FleetConfigurationError):
        fleet_module.validate_fleet_configuration(
            {"claudeCode": {"allowedCommandPatterns": patterns}}
        )


def test_fleet_configuration_accepts_bounded_command_patterns() -> None:
    """A practical full-command allow rule remains available to operators."""
    configuration = fleet_module.validate_fleet_configuration(
        {"claudeCode": {"allowedCommandPatterns": [r"^(git\s+status|git\s+status\s+--short)$"]}}
    )
    assert configuration["claudeCode"]["allowedCommandPatterns"] == [
        r"^(git\s+status|git\s+status\s+--short)$"
    ]


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


def test_local_credential_broker_lifecycle_is_tenant_scoped_and_honestly_unverified(
    tmp_path: Path,
) -> None:
    """Local lifecycle works without pretending SQLite has cloud-provider evidence."""
    store = EnterpriseFleetStore(tmp_path / "brokers.sqlite")
    token_a = "fleet-admin-token-a1234"  # noqa: S105 - synthetic test credential
    token_b = "fleet-admin-token-b1234"  # noqa: S105 - synthetic test credential
    app = EnterpriseFleetApplication(
        store,
        authenticator=StaticFleetAuthenticator(
            {token_a: identity("org-a"), token_b: identity("org-b", subject="operator-b")}
        ),
    )
    for token, organization_id in ((token_a, "org-a"), (token_b, "org-b")):
        assert call_api(
            app,
            "POST",
            "/api/enterprise/organizations",
            {"organizationId": organization_id, "name": organization_id.upper()},
            token=token,
        )[0].startswith("201")
    request = {
        "brokerId": "azure-read",
        "name": "Azure metadata read",
        "provider": "azure_workload_identity",
        "principal": ("11111111-2222-4333-8444-555555555555/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
        "audience": "https://vault.example.test",
        "allowedTools": ["read_metadata"],
        "resourceIds": ["vault:synthetic"],
        "maxTtlSeconds": 300,
    }
    status, created = call_api(
        app, "POST", "/api/enterprise/credential-brokers", request, token=token_a
    )
    assert status.startswith("201")
    assert created["verificationStatus"] == "unverified"
    assert created["executionAllowed"] is False
    assert created["revocationEpoch"] == 1
    assert "clientSecret" not in created

    _, integrations_a = call_api(app, "GET", "/api/enterprise/integrations", token=token_a)
    _, integrations_b = call_api(app, "GET", "/api/enterprise/integrations", token=token_b)
    assert [item["id"] for item in integrations_a["credentialBrokers"]] == ["azure-read"]
    assert integrations_b["credentialBrokers"] == []

    rejected_status, _ = call_api(
        app,
        "POST",
        "/api/enterprise/credential-brokers",
        {**request, "brokerId": "secret-attempt", "clientSecret": "synthetic"},  # noqa: S106
        token=token_a,
    )
    assert rejected_status.startswith("400")
    for broker_id, field, value in (
        ("bad-principal", "principal", "not-an-entra-identity"),
        ("bad-audience", "audience", "sts.amazonaws.com"),
    ):
        malformed_status, _ = call_api(
            app,
            "POST",
            "/api/enterprise/credential-brokers",
            {**request, "brokerId": broker_id, field: value},
            token=token_a,
        )
        assert malformed_status.startswith("400")
    aws_ttl_status, _ = call_api(
        app,
        "POST",
        "/api/enterprise/credential-brokers",
        {
            **request,
            "brokerId": "aws-too-short",
            "provider": "aws_sts",
            "principal": "arn:aws:iam::123456789012:role/aai-sec-scoped-tool",
            "audience": "sts.amazonaws.com",
            "maxTtlSeconds": 300,
        },
        token=token_a,
    )
    assert aws_ttl_status.startswith("400")
    revoked_status, revoked = call_api(
        app,
        "POST",
        "/api/enterprise/credential-brokers/azure-read/revoke",
        {"expectedRevision": 1, "reason": "Synthetic provider role retired."},
        token=token_a,
    )
    assert revoked_status.startswith("200")
    assert revoked["status"] == "revoked"
    assert revoked["revision"] == 2
    assert revoked["revocationEpoch"] == 2
    assert revoked["executionAllowed"] is False


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

    identity_status, identity_payload = call_api(app, "GET", "/api/enterprise/identity")
    assert identity_status.startswith("200")
    assert identity_payload["provider"] == "development_static"
    assert identity_payload["status"] == "development_only"
    assert identity_payload["activeRoles"] == ["platform-admin"]
    assert identity_payload["subject"] == "operator-1"
    assert identity_payload["scim"]["lifecycleEnforced"] is False
    integration_status, integration_payload = call_api(app, "GET", "/api/enterprise/integrations")
    assert integration_status.startswith("200")
    assert integration_payload["splunk"]["status"] == "stub"
    assert integration_payload["splunk"]["deliveryVerified"] is False
    assert integration_payload["credentialBrokers"] == []
    assert integration_payload["credentialBrokerEvidenceTtlSeconds"] == 900

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
        {
            "sessionId": registered["sessionId"],
            "telemetry": {
                "actionsTotal": 2,
                "actionsAdmitted": 2,
                "allowed": 1,
                "denied": 1,
                "approvalRequired": 0,
                "executed": 1,
                "failed": 0,
                "timedOut": 0,
                "cancelled": 0,
                "resultRejected": 0,
                "runtimeErrors": 0,
                "costUnits": 2,
                "averageLatencyMs": 5.5,
                "maxLatencyMs": 8.0,
            },
        },
    )
    assert status.startswith("200") and heartbeat["status"] == "connected"
    status, agents = call_api(app, "GET", "/api/enterprise/agents")
    assert status.startswith("200")
    assert agents["items"][0]["telemetry"]["averageLatencyMs"] == 5.5
    bad_status, _ = call_api(
        app,
        "POST",
        "/api/enterprise/agents/deploy-a/claude-a/heartbeat",
        {"sessionId": registered["sessionId"], "telemetry": {"secret": 1}},
    )
    assert bad_status.startswith("400")
    status, verification = call_api(app, "GET", "/api/enterprise/agents/deploy-a/claude-a/verify")
    assert status.startswith("200")
    assert verification["verified"] is False
    assert verification["checks"]["policyAssignment"]["passed"] is False
    status, audit = call_api(app, "GET", "/api/enterprise/audit")
    assert status.startswith("200")
    assert audit["items"]
    assert "payloadHash" in audit["items"][0]
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
    reviewer_token = "fleet-reviewer-token-1234"  # noqa: S105 - synthetic test credential
    app = EnterpriseFleetApplication(
        store,
        authenticator=StaticFleetAuthenticator(
            {
                token: identity("org-a"),
                reviewer_token: identity("org-a", subject="reviewer-2"),
            }
        ),
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
    assert policy["activeVersion"] is None and policy["governanceState"] == "draft"
    status, policies = call_api(app, "GET", "/api/enterprise/policies")
    assert status.startswith("200") and policies["items"][0]["id"] == "policy-safe"
    status, inactive_group = call_api(
        app,
        "POST",
        "/api/enterprise/groups",
        {"groupId": "group-too-early", "name": "Too early", "policyId": "policy-safe"},
    )
    assert status.startswith("409") and "active governed version" in inactive_group["error"]
    status, versions = call_api(app, "GET", "/api/enterprise/policies/policy-safe/versions")
    assert status.startswith("200") and versions["items"][0]["state"] == "draft"
    assert call_api(app, "POST", "/api/enterprise/policies/policy-safe/versions/1/submit", {})[
        0
    ].startswith("200")
    status, self_approval = call_api(
        app,
        "POST",
        "/api/enterprise/policies/policy-safe/versions/1/decision",
        {"decision": "approved", "reason": "I wrote it"},
    )
    assert status.startswith("403") and "cannot approve" in self_approval["error"]
    assert call_api(
        app,
        "POST",
        "/api/enterprise/policies/policy-safe/versions/1/decision",
        {"decision": "approved", "reason": "Independent review complete"},
        token=reviewer_token,
    )[0].startswith("200")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/policies/policy-safe/versions/1/stage",
        {},
        token=reviewer_token,
    )[0].startswith("200")
    status, activated_policy = call_api(
        app,
        "POST",
        "/api/enterprise/policies/policy-safe/versions/1/activate",
        {"expectedActiveVersion": 0},
        token=reviewer_token,
    )
    assert status.startswith("200") and activated_policy["version"] == 1
    status, updated_policy = call_api(
        app,
        "POST",
        "/api/enterprise/policies/policy-safe/versions",
        {
            "name": "Safe default v2",
            "configuration": {"policy": {"denyByDefault": True}, "budgets": {"maxActions": 10}},
        },
    )
    assert status.startswith("200") and updated_policy["version"] == 2
    assert updated_policy["author"] == "operator-1"
    assert call_api(app, "POST", "/api/enterprise/policies/policy-safe/versions/2/submit", {})[
        0
    ].startswith("200")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/policies/policy-safe/versions/2/decision",
        {"decision": "approved", "reason": "Limits independently reviewed"},
        token=reviewer_token,
    )[0].startswith("200")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/policies/policy-safe/versions/2/stage",
        {},
        token=reviewer_token,
    )[0].startswith("200")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/policies/policy-safe/versions/2/activate",
        {"expectedActiveVersion": 1},
        token=reviewer_token,
    )[0].startswith("200")
    status, skill = call_api(
        app,
        "POST",
        "/api/enterprise/skills",
        {
            "skillId": "skill-review",
            "name": "Review",
            "description": "Synthetic",
            "version": "1.0.0",
            "content": "# Review",
            "enabled": True,
        },
    )
    assert status.startswith("201") and skill["digest"].startswith("sha256:")
    status, mcp = call_api(
        app,
        "POST",
        "/api/enterprise/mcp-servers",
        {
            "serverId": "mcp-review",
            "name": "Review MCP",
            "description": "Synthetic",
            "version": "1.0.0",
            "transport": "stdio",
            "command": "python",
            "args": ["server.py"],
            "environmentReferences": ["TOKEN"],
            "enabled": True,
        },
    )
    assert status.startswith("201") and mcp["environmentReferences"] == ["TOKEN"]
    status, skills = call_api(app, "GET", "/api/enterprise/skills")
    assert status.startswith("200") and skills["items"][0]["id"] == "skill-review"
    status, mcp_servers = call_api(app, "GET", "/api/enterprise/mcp-servers")
    assert status.startswith("200") and mcp_servers["items"][0]["id"] == "mcp-review"
    status, invalid_skill = call_api(
        app,
        "POST",
        "/api/enterprise/skills",
        {
            "skillId": "skill-too-large",
            "name": "Too large",
            "description": "Synthetic",
            "content": "x" * 100001,
        },
    )
    assert status.startswith("400") and "too large" in invalid_skill["error"]
    status, invalid_empty_skill = call_api(
        app,
        "POST",
        "/api/enterprise/skills",
        {
            "skillId": "skill-empty",
            "name": "Empty",
            "description": "Synthetic",
            "content": "   ",
        },
    )
    assert status.startswith("400") and "non-empty" in invalid_empty_skill["error"]
    status, duplicate_skill = call_api(
        app,
        "POST",
        "/api/enterprise/skills",
        {
            "skillId": "skill-review",
            "name": "Duplicate",
            "description": "Synthetic",
            "content": "# Duplicate",
        },
    )
    assert status.startswith("400") and "already exists" in duplicate_skill["error"]
    status, invalid_mcp = call_api(
        app,
        "POST",
        "/api/enterprise/mcp-servers",
        {
            "serverId": "mcp-invalid",
            "name": "Invalid",
            "description": "Synthetic",
            "version": "1.0.0",
            "transport": "tcp",
        },
    )
    assert status.startswith("400") and "transport" in invalid_mcp["error"]
    status, missing_command = call_api(
        app,
        "POST",
        "/api/enterprise/mcp-servers",
        {
            "serverId": "mcp-no-command",
            "name": "No command",
            "description": "Synthetic",
            "transport": "stdio",
        },
    )
    assert status.startswith("400") and "command" in missing_command["error"]
    status, missing_url = call_api(
        app,
        "POST",
        "/api/enterprise/mcp-servers",
        {
            "serverId": "mcp-no-url",
            "name": "No URL",
            "description": "Synthetic",
            "transport": "http",
        },
    )
    assert status.startswith("400") and "URL" in missing_url["error"]
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
        status.startswith("201")
        and group["policyName"] == "Safe default v2"
        and group["agents"] == []
    )
    status, reassigned = call_api(
        app,
        "POST",
        "/api/enterprise/groups/group-platform/policy",
        {"policyId": "policy-safe"},
    )
    assert status.startswith("200") and reassigned["policyId"] == "policy-safe"
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
    status, selected_version = call_api(
        app,
        "POST",
        "/api/enterprise/policies/policy-safe/versions",
        {
            "name": "Safe default with managed resources",
            "configuration": {
                "policy": {"denyByDefault": True},
                "audit": {"redactSensitiveData": True},
                "claudeCode": {
                    "allowedSkills": ["skill-review"],
                    "allowedMcpServers": ["mcp-review"],
                    "allowedCommandPatterns": [r"^git\s+status(\s|$)"],
                },
            },
        },
    )
    assert status.startswith("200") and selected_version["version"] == 3
    assert call_api(app, "POST", "/api/enterprise/policies/policy-safe/versions/3/submit", {})[
        0
    ].startswith("200")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/policies/policy-safe/versions/3/decision",
        {"decision": "approved", "reason": "Managed resources independently reviewed"},
        token=reviewer_token,
    )[0].startswith("200")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/policies/policy-safe/versions/3/stage",
        {},
        token=reviewer_token,
    )[0].startswith("200")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/policies/policy-safe/versions/3/activate",
        {"expectedActiveVersion": 2},
        token=reviewer_token,
    )[0].startswith("200")
    status, effective = call_api(
        app, "GET", "/api/enterprise/agents/deploy-a/claude-a/effective-policy"
    )
    assert status.startswith("200")
    assert (
        effective["policy"]["configuration"]["claudeCode"]["managedSkills"][0]["id"]
        == "skill-review"
    )
    assert (
        effective["policy"]["configuration"]["claudeCode"]["managedMcpServers"][0]["id"]
        == "mcp-review"
    )
    assert effective["policy"]["configuration"]["claudeCode"]["allowedCommandPatterns"] == [
        r"^git\s+status(\s|$)"
    ]
    status, duplicate_member = call_api(
        app,
        "POST",
        "/api/enterprise/groups/group-platform/agents",
        {"deploymentId": "deploy-a", "agentId": "claude-a"},
    )
    assert (
        status.startswith("400") and duplicate_member["error"] == "agent is already in this group"
    )
    status, stopped_group = call_api(
        app,
        "POST",
        "/api/enterprise/groups/group-platform/emergency-stop",
        {"active": True},
    )
    assert status.startswith("200") and stopped_group["emergencyStop"] is True
    status, stopped_agent = call_api(
        app,
        "POST",
        "/api/enterprise/agents/deploy-a/claude-a/emergency-stop",
        {"active": True},
    )
    assert status.startswith("200") and stopped_agent["emergencyStop"] is True
    assert call_api(
        app,
        "POST",
        "/api/enterprise/agents/deploy-a/claude-a/emergency-stop",
        {"active": False},
    )[0].startswith("200")
    assert call_api(
        app,
        "POST",
        "/api/enterprise/groups/group-platform/emergency-stop",
        {"active": False},
    )[0].startswith("200")
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


def test_policy_lifecycle_is_immutable_two_person_and_fail_closed(tmp_path: Path) -> None:
    """Draft authority cannot bypass review, ordering, tenancy, or active-version CAS."""
    audit = InMemoryAuditSink()
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite", audit=audit)
    seed(store)
    author = identity("org-a", subject="author-1")
    reviewer = identity("org-a", subject="reviewer-2")
    outsider = identity("org-b", subject="reviewer-b")
    created = store.create_policy(
        author,
        policy_id="policy-governed",
        name="Governed",
        configuration={"tools": {"allowed": ["read_repository"]}},
    )
    assert created["version"] == 0
    assert created["activeVersion"] is None
    assert created["pendingVersion"] == 1
    with pytest.raises(FleetConflictError, match="pending"):
        store.update_policy(
            author,
            policy_id="policy-governed",
            name="Bypass",
            configuration={"tools": {"allowed": ["write_repository"]}},
        )
    with pytest.raises(FleetConflictError, match="not approved"):
        store.stage_policy_version(reviewer, "policy-governed", 1)
    submitted = store.submit_policy_version(author, "policy-governed", 1)
    assert submitted["state"] == "review"
    with pytest.raises(FleetAuthorizationError, match="cannot approve"):
        store.decide_policy_version(
            author,
            "policy-governed",
            1,
            decision="approved",
            reason="self approval",
        )
    with pytest.raises(FleetAuthorizationError, match="organization scope"):
        store.decide_policy_version(
            outsider,
            "policy-governed",
            1,
            decision="approved",
            reason="wrong tenant",
        )
    approved = store.decide_policy_version(
        reviewer,
        "policy-governed",
        1,
        decision="approved",
        reason="Independent change review",
    )
    assert approved["approvedBy"] == "reviewer-2" and approved["decision"] == "approved"
    with pytest.raises(FleetConflictError, match="awaiting review"):
        store.decide_policy_version(
            reviewer,
            "policy-governed",
            1,
            decision="approved",
            reason="replay",
        )
    store.stage_policy_version(reviewer, "policy-governed", 1)
    active = store.activate_policy_version(
        reviewer,
        "policy-governed",
        1,
        expected_active_version=0,
    )
    assert active["version"] == 1 and active["governanceState"] == "active"
    with pytest.raises(FleetConflictError, match="not staged"):
        store.activate_policy_version(
            reviewer,
            "policy-governed",
            1,
            expected_active_version=0,
        )
    draft = store.update_policy(
        author,
        policy_id="policy-governed",
        name="Governed v2",
        configuration={"tools": {"allowed": ["read_repository", "run_tests"]}},
    )
    assert draft["version"] == 2 and draft["baseVersion"] == 1
    assert store.list_policies(author).items[0]["version"] == 1
    assert store.policy_version(author, "policy-governed", 1)["configuration"] == {
        "tools": {"allowed": ["read_repository"]}
    }
    assert {event.event_type for event in audit.events()} >= {
        "fleet_policy_draft_created",
        "fleet_policy_submitted",
        "fleet_policy_decided",
        "fleet_policy_staged",
        "fleet_policy_activated",
    }


def test_policy_git_import_is_atomic_idempotent_and_never_grants_authority(
    tmp_path: Path,
) -> None:
    """Reviewed Git content creates only a tenant draft with immutable provenance."""
    verifier = PolicyVerifier(policy_source_bytes())
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite", policy_source_verifier=verifier)
    seed(store)
    author = identity("org-a", subject="author-1")
    request = PolicySourceRequest("github.com/acme/policies", "a" * 40, "policies/claude.json")

    imported = store.import_policy_source(author, import_id="import-42", request=request)

    assert imported["status"] == "draft_created"
    assert imported["draft"] == {
        "policyId": "policy-from-git",
        "version": 1,
        "state": "draft",
    }
    assert imported["provenance"]["providerEvidence"]["reviewVerified"] is True
    policy = store.list_policies(author).items[0]
    assert policy["activeVersion"] is None and policy["pendingVersion"] == 1
    version = store.policy_version(author, "policy-from-git", 1)
    assert version["state"] == "draft" and version["sourceProvenance"] == imported["provenance"]
    assert store.list_groups(author).items == ()

    replay = store.import_policy_source(author, import_id="import-42", request=request)
    duplicate = store.import_policy_source(author, import_id="import-duplicate", request=request)
    assert replay == imported and duplicate == imported
    assert len(verifier.requests) == 2
    assert len(store.list_policy_versions(author, "policy-from-git").items) == 1
    with pytest.raises(FleetConflictError, match="different source"):
        store.import_policy_source(
            author,
            import_id="import-42",
            request=PolicySourceRequest(
                "github.com/acme/policies", "c" * 40, "policies/claude.json"
            ),
        )


def test_policy_git_import_and_export_fail_closed_without_partial_state(
    tmp_path: Path,
) -> None:
    """Adapter failure, wrong tenancy, and missing signing never leave authority behind."""
    verifier = PolicyVerifier(policy_source_bytes())
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite", policy_source_verifier=verifier)
    seed(store)
    author = identity("org-a", subject="author-1")
    request = PolicySourceRequest("github.com/acme/policies", "a" * 40, "policies/claude.json")
    verifier.failure = PolicySourceVerificationError("synthetic verification failure")
    with pytest.raises(FleetConfigurationError, match="verification failure"):
        store.import_policy_source(author, import_id="failed", request=request)
    assert store.list_policies(author).items == ()
    with pytest.raises(FleetNotFoundError):
        store.policy_import(author, "failed")

    verifier.failure = None
    verifier.content = policy_source_bytes(organization_id="org-b")
    with pytest.raises(FleetAuthorizationError, match="organization scope"):
        store.import_policy_source(author, import_id="wrong-tenant", request=request)
    assert store.list_policies(author).items == ()

    verifier.content = policy_source_bytes()
    imported = store.import_policy_source(author, import_id="valid", request=request)
    with pytest.raises(FleetConfigurationError, match="signing is not configured"):
        store.export_policy_source(author, imported["draft"]["policyId"], 1)


def test_policy_export_signs_exact_canonical_provenance_and_api_routes(
    tmp_path: Path,
) -> None:
    """HTTP import/export/get routes preserve canonical documents and safe evidence."""
    verifier = PolicyVerifier(policy_source_bytes())
    signer = PolicySigner()
    store = EnterpriseFleetStore(
        tmp_path / "fleet.sqlite",
        now=lambda: 1_000.0,
        policy_source_verifier=verifier,
        policy_export_signer=signer,
    )
    seed(store)
    app = EnterpriseFleetApplication(
        store,
        authenticator=StaticFleetAuthenticator(
            {"fleet-admin-token-1234": identity("org-a", subject="author-1")}
        ),
    )
    body = {
        "importId": "api-import-42",
        "repository": "github.com/acme/policies",
        "commitSha": "a" * 40,
        "path": "policies/claude.json",
    }
    status, imported = call_api(app, "POST", "/api/enterprise/policies/imports", body)
    assert status.startswith("201") and imported["draft"]["state"] == "draft"
    status, fetched = call_api(app, "GET", "/api/enterprise/policies/imports/api-import-42")
    assert status.startswith("200") and fetched == imported

    status, exported = call_api(
        app,
        "POST",
        "/api/enterprise/policies/policy-from-git/versions/1/export",
        {},
    )
    assert status.startswith("200")
    assert json.loads(exported["canonicalDocument"]) == exported["document"]
    assert (
        exported["sourceSha256"]
        == hashlib.sha256(exported["canonicalDocument"].encode()).hexdigest()
    )
    signed_payload = json.loads(signer.payloads[0])
    assert signed_payload == {
        key: value for key, value in exported["provenance"].items() if key != "integrity"
    }
    assert (
        exported["provenance"]["integrity"]["signature"]
        == base64.b64encode(b"synthetic-signature").decode()
    )
    status, malformed = call_api(
        app,
        "POST",
        "/api/enterprise/policies/imports",
        {**body, "unexpected": True},
    )
    assert status.startswith("400") and "schema" in malformed["error"]


def test_policy_components_compose_exact_governed_versions_and_explain_authority(
    tmp_path: Path,
) -> None:
    """Reusable versions tighten local intent and retain reviewable provenance."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    author = identity("org-a", subject="author-1")
    create_active_policy(
        store,
        author,
        policy_id="policy-baseline",
        name="Enterprise baseline",
        configuration={
            "policy": {"denyByDefault": True},
            "tools": {"allowed": ["read_repository", "run_tests"]},
            "budgets": {"maxActions": 100},
        },
    )
    component = store.policy_version(author, "policy-baseline", 1)
    reference = {
        "policyId": "policy-baseline",
        "version": 1,
        "contentHash": component["contentHash"],
    }

    preview = store.preview_policy_composition(
        author,
        policy_id="policy-workload",
        local_configuration={
            "tools": {
                "allowed": ["read_repository", "write_repository"],
                "denied": ["shell"],
            },
            "budgets": {"maxActions": 50},
        },
        component_refs=[reference],
    )
    assert preview["configuration"] == {
        "policy": {"denyByDefault": True},
        "tools": {"allowed": ["read_repository"], "denied": ["shell"]},
        "budgets": {"maxActions": 50},
    }
    allowed = next(step for step in preview["explanation"] if step["field"] == "tools.allowed")
    assert allowed["rule"] == "allow_intersection"
    assert allowed["removed"] == ["run_tests", "write_repository"]
    assert allowed["sources"][-1] == "local"

    created = store.create_policy(
        author,
        policy_id="policy-workload",
        name="Workload",
        local_configuration={
            "tools": {
                "allowed": ["read_repository", "write_repository"],
                "denied": ["shell"],
            },
            "budgets": {"maxActions": 50},
        },
        component_refs=[reference],
    )
    version = store.policy_version(author, "policy-workload", int(created["latestVersion"]))
    assert version["configuration"] == preview["configuration"]
    assert version["composition"]["componentRefs"] == [reference]
    assert version["composition"]["graphDigest"] == preview["graphDigest"]

    middle = store.create_policy(
        author,
        policy_id="policy-engineering-baseline",
        name="Engineering baseline",
        local_configuration={
            "tools": {"allowed": ["read_repository"]},
            "budgets": {"maxActions": 75},
        },
        component_refs=[reference],
    )
    middle_version = int(middle["latestVersion"])
    reviewer = identity("org-a", subject="reviewer-2")
    store.submit_policy_version(author, "policy-engineering-baseline", middle_version)
    store.decide_policy_version(
        reviewer,
        "policy-engineering-baseline",
        middle_version,
        decision="approved",
        reason="Synthetic nested-component review",
    )
    store.stage_policy_version(reviewer, "policy-engineering-baseline", middle_version)
    store.activate_policy_version(
        reviewer,
        "policy-engineering-baseline",
        middle_version,
        expected_active_version=0,
    )
    middle_record = store.policy_version(author, "policy-engineering-baseline", middle_version)
    nested_preview = store.preview_policy_composition(
        author,
        policy_id="policy-nested-workload",
        local_configuration={"tools": {"allowed": ["read_repository", "run_tests"]}},
        component_refs=[
            {
                "policyId": "policy-engineering-baseline",
                "version": middle_version,
                "contentHash": middle_record["contentHash"],
            }
        ],
    )
    assert nested_preview["configuration"]["tools"]["allowed"] == ["read_repository"]
    assert nested_preview["configuration"]["budgets"]["maxActions"] == 75


def test_policy_components_fail_closed_on_ungoverned_stale_or_corrupt_authority(
    tmp_path: Path,
) -> None:
    """Component state, hash, tenancy, self-reference, and storage integrity are enforced."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    author = identity("org-a", subject="author-1")
    reviewer = identity("org-a", subject="reviewer-2")
    create_active_policy(
        store,
        author,
        policy_id="policy-baseline",
        name="Baseline",
        configuration={"tools": {"allowed": ["read_repository"]}},
    )
    component = store.policy_version(author, "policy-baseline", 1)
    valid_ref = {
        "policyId": "policy-baseline",
        "version": 1,
        "contentHash": component["contentHash"],
    }
    with pytest.raises(FleetConflictError, match="content hash"):
        store.preview_policy_composition(
            author,
            policy_id="policy-workload",
            local_configuration={},
            component_refs=[{**valid_ref, "contentHash": "0" * 64}],
        )
    with pytest.raises(FleetConfigurationError, match="own versions"):
        store.preview_policy_composition(
            author,
            policy_id="policy-baseline",
            local_configuration={},
            component_refs=[valid_ref],
        )

    pending = store.create_policy(
        author,
        policy_id="policy-pending",
        name="Pending",
        configuration={"tools": {"allowed": ["run_tests"]}},
    )
    pending_version = store.policy_version(author, "policy-pending", int(pending["latestVersion"]))
    with pytest.raises(FleetConflictError, match="active or retired"):
        store.preview_policy_composition(
            author,
            policy_id="policy-workload",
            local_configuration={},
            component_refs=[
                {
                    "policyId": "policy-pending",
                    "version": 1,
                    "contentHash": pending_version["contentHash"],
                }
            ],
        )

    created = store.create_policy(
        author,
        policy_id="policy-workload",
        name="Workload",
        local_configuration={"tools": {"allowed": ["read_repository"]}},
        component_refs=[valid_ref],
    )
    version = int(created["latestVersion"])
    store.submit_policy_version(author, "policy-workload", version)
    store.decide_policy_version(
        reviewer,
        "policy-workload",
        version,
        decision="approved",
        reason="Synthetic independent review",
    )
    store._connection.execute(  # noqa: SLF001 - adversarial persistence-corruption test
        "UPDATE policy_versions SET configuration=? WHERE policy_id=? AND version=?",
        ('{"tools":{"allowed":["shell"]}}', "policy-baseline", 1),
    )
    store._connection.commit()  # noqa: SLF001 - adversarial persistence-corruption test
    with pytest.raises(FleetConflictError, match="integrity"):
        store.stage_policy_version(reviewer, "policy-workload", version)


def test_policy_component_boundary_rejects_ambiguous_and_corrupt_graph_metadata(
    tmp_path: Path,
) -> None:
    """Every malformed composition shape and non-reproducible graph fails closed."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    author = identity("org-a", subject="author-1")
    create_active_policy(
        store,
        author,
        policy_id="policy-baseline",
        name="Baseline",
        configuration={"tools": {"allowed": ["read_repository"]}},
    )
    component = store.policy_version(author, "policy-baseline", 1)
    valid_ref = {
        "policyId": "policy-baseline",
        "version": 1,
        "contentHash": component["contentHash"],
    }
    compose = store._compose_policy_version  # noqa: SLF001 - adversarial boundary exercise
    with pytest.raises(FleetConfigurationError, match="not both"):
        compose(
            "org-a",
            "candidate",
            configuration={},
            local_configuration={},
            component_refs=[],
        )
    with pytest.raises(FleetConfigurationError, match="explicit localConfiguration"):
        compose(
            "org-a",
            "candidate",
            configuration={},
            local_configuration=None,
            component_refs=[valid_ref],
        )
    with pytest.raises(FleetConfigurationError, match="must be an object"):
        compose(
            "org-a",
            "candidate",
            configuration=None,
            local_configuration=None,
            component_refs=[],
        )
    with pytest.raises(FleetConfigurationError, match="must be an array"):
        compose(
            "org-a",
            "candidate",
            configuration=None,
            local_configuration={},
            component_refs="invalid",  # type: ignore[arg-type]
        )
    with pytest.raises(FleetConfigurationError, match="at most eight"):
        compose(
            "org-a",
            "candidate",
            configuration=None,
            local_configuration={},
            component_refs=[valid_ref] * 9,
        )
    with pytest.raises(FleetConfigurationError, match="SHA-256"):
        compose(
            "org-a",
            "candidate",
            configuration=None,
            local_configuration={},
            component_refs=[{**valid_ref, "contentHash": "not-a-digest"}],
        )
    with pytest.raises(FleetConfigurationError, match="duplicate or cycle"):
        compose(
            "org-a",
            "candidate",
            configuration=None,
            local_configuration={},
            component_refs=[valid_ref, valid_ref],
        )

    store._connection.execute(  # noqa: SLF001 - adversarial persistence-corruption test
        "UPDATE policy_versions SET decided_by=NULL WHERE policy_id=? AND version=?",
        ("policy-baseline", 1),
    )
    store._connection.commit()  # noqa: SLF001 - adversarial persistence-corruption test
    with pytest.raises(FleetAuthorizationError, match="independent approval"):
        compose(
            "org-a",
            "candidate",
            configuration=None,
            local_configuration={},
            component_refs=[valid_ref],
        )
    store._connection.execute(  # noqa: SLF001 - adversarial persistence-corruption test
        "UPDATE policy_versions SET decided_by=? WHERE policy_id=? AND version=?",
        ("reviewer-2", "policy-baseline", 1),
    )

    store._connection.execute(  # noqa: SLF001 - adversarial persistence-corruption test
        "UPDATE policy_versions SET graph_digest=? WHERE policy_id=? AND version=?",
        ("0" * 64, "policy-baseline", 1),
    )
    store._connection.commit()  # noqa: SLF001 - adversarial persistence-corruption test
    with pytest.raises(FleetConflictError, match="graph integrity"):
        compose(
            "org-a",
            "candidate",
            configuration=None,
            local_configuration={},
            component_refs=[valid_ref],
        )

    store._insert_policy_version(  # noqa: SLF001 - legacy migration contract
        policy_id="policy-baseline",
        organization_id="org-a",
        version=99,
        base_version=1,
        name="Legacy rejected version",
        configuration_json="{}",
        state="rejected",
        author="legacy-author",
        created_at=1.0,
    )
    legacy = store.policy_version(author, "policy-baseline", 99)
    assert legacy["composition"]["localConfiguration"] == {}
    assert len(legacy["composition"]["graphDigest"]) == 64


def test_policy_components_reject_cross_tenant_authority(tmp_path: Path) -> None:
    """An exact valid component from another organization still grants no authority."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    author_b = identity("org-b", subject="author-b")
    create_active_policy(
        store,
        author_b,
        policy_id="policy-other-tenant",
        name="Other tenant",
        configuration={"tools": {"allowed": ["read_repository"]}},
    )
    component = store.policy_version(author_b, "policy-other-tenant", 1)
    with pytest.raises(FleetAuthorizationError, match="same tenant"):
        store.preview_policy_composition(
            identity("org-a"),
            policy_id="policy-candidate",
            local_configuration={},
            component_refs=[
                {
                    "policyId": "policy-other-tenant",
                    "version": 1,
                    "contentHash": component["contentHash"],
                }
            ],
        )


def test_policy_composition_preview_http_route_is_schema_validated(tmp_path: Path) -> None:
    """The UI preview contract returns effective policy and rejects ambiguous input."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    token = "fleet-admin-token-1234"  # noqa: S105 - synthetic test credential
    operator = identity("org-a")
    app = EnterpriseFleetApplication(
        store,
        authenticator=StaticFleetAuthenticator({token: operator}),
    )
    status, preview = call_api(
        app,
        "POST",
        "/api/enterprise/policies/composition/preview",
        {
            "policyId": "policy-new",
            "localConfiguration": {"policy": {"denyByDefault": True}},
            "componentRefs": [],
        },
    )
    assert status.startswith("200")
    assert preview["configuration"] == {"policy": {"denyByDefault": True}}
    assert len(preview["graphDigest"]) == 64
    status, malformed = call_api(
        app,
        "POST",
        "/api/enterprise/policies/composition/preview",
        {"policyId": "policy-new", "localConfiguration": {}, "componentRefs": [{}]},
    )
    assert status.startswith("400")
    assert "policyId, version, and contentHash" in malformed["error"]


def test_policy_governance_rejects_invalid_versions_states_and_cross_tenant_access(
    tmp_path: Path,
) -> None:
    """Governance validation rejects malformed, stale, and cross-tenant operations."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    author = identity("org-a", subject="author-1")
    reviewer = identity("org-a", subject="reviewer-2")
    outsider = identity("org-b", subject="reviewer-b")
    store.create_policy(
        author,
        policy_id="policy-validation",
        name="Validation",
        configuration={"tools": {"allowed": ["read_repository"]}},
    )

    for invalid_version in (True, 0, -1):
        with pytest.raises(FleetConfigurationError, match="positive integer"):
            store.policy_version(author, "policy-validation", invalid_version)
    with pytest.raises(FleetNotFoundError, match="version not found"):
        store.policy_version(author, "policy-validation", 99)
    with pytest.raises(FleetAuthorizationError, match="organization scope"):
        store.list_policy_versions(outsider, "policy-validation")
    with pytest.raises(FleetAuthorizationError, match="organization scope"):
        store.policy_version(outsider, "policy-validation", 1)
    with pytest.raises(FleetAuthorizationError, match="organization scope"):
        store.update_policy(
            outsider,
            policy_id="policy-validation",
            name="Cross tenant",
            configuration={},
        )

    store.submit_policy_version(author, "policy-validation", 1)
    with pytest.raises(FleetConfigurationError, match="approved or rejected"):
        store.decide_policy_version(
            reviewer,
            "policy-validation",
            1,
            decision="maybe",
            reason="invalid decision",
        )
    rejected = store.decide_policy_version(
        reviewer,
        "policy-validation",
        1,
        decision="rejected",
        reason="Needs tighter limits",
    )
    assert rejected["state"] == "rejected" and rejected["decisionReason"] == "Needs tighter limits"
    with pytest.raises(FleetConflictError, match="must be draft"):
        store.submit_policy_version(author, "policy-validation", 1)
    with pytest.raises(FleetConflictError, match="not approved"):
        store.stage_policy_version(reviewer, "policy-validation", 1)
    with pytest.raises(FleetConfigurationError, match="must be an integer"):
        store.activate_policy_version(
            reviewer,
            "policy-validation",
            1,
            expected_active_version=True,
        )
    with pytest.raises(FleetConfigurationError, match="cannot be negative"):
        store.activate_policy_version(reviewer, "policy-validation", 1, expected_active_version=-1)

    draft = store.update_policy(
        author,
        policy_id="policy-validation",
        name="Validation v2",
        configuration={"tools": {"allowed": ["read_repository", "run_tests"]}},
    )
    page = store.list_policy_versions(author, "policy-validation", limit=1)
    assert [item["version"] for item in page.items] == [draft["version"]]
    assert page.next_cursor is not None
    with pytest.raises(FleetAuthorizationError, match="organization scope"):
        store._transition_policy_version(
            outsider,
            "policy-validation",
            2,
            expected_state="draft",
            next_state="review",
            fields={"submitted_by": outsider.subject, "submitted_at": 1.0},
            event="synthetic",
        )
    with pytest.raises(FleetConfigurationError, match="transition is invalid"):
        store._transition_policy_version(
            author,
            "policy-validation",
            2,
            expected_state="unknown",
            next_state="review",
            fields={"submitted_by": author.subject, "submitted_at": 1.0},
            event="synthetic",
        )
    with pytest.raises(FleetConfigurationError, match="metadata is invalid"):
        store._transition_policy_version(
            author,
            "policy-validation",
            2,
            expected_state="draft",
            next_state="review",
            fields={"unexpected": "value"},
            event="synthetic",
        )
    with pytest.raises(FleetConfigurationError, match="state is invalid"):
        store._insert_policy_version(
            policy_id="policy-validation",
            organization_id="org-a",
            version=3,
            base_version=0,
            name="Invalid",
            configuration_json="{}",
            state="unknown",
            author=author.subject,
            created_at=1.0,
        )


def test_policy_governance_http_routes_fail_closed_on_malformed_transitions(
    tmp_path: Path,
) -> None:
    """HTTP lifecycle routes normalize malformed versions, actions, and activation CAS input."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    seed(store)
    token = "fleet-policy-admin-token-1234"  # noqa: S105 - synthetic test credential
    operator = identity("org-a", subject="author-1")
    app = EnterpriseFleetApplication(
        store,
        authenticator=StaticFleetAuthenticator({token: operator}),
    )
    store.create_policy(
        operator,
        policy_id="policy-http-validation",
        name="HTTP validation",
        configuration={},
    )

    malformed_routes: tuple[tuple[str, str, dict[str, Any]], ...] = (
        ("GET", "/api/enterprise/policies/policy-http-validation/versions/not-a-number", {}),
        ("GET", "/api/enterprise/policies/policy-http-validation/versions/1/extra", {}),
        ("POST", "/api/enterprise/policies/policy-http-validation/versions/nope/submit", {}),
        ("POST", "/api/enterprise/policies/policy-http-validation/versions/1/unknown", {}),
        ("POST", "/api/enterprise/policies/policy-http-validation/versions/1/activate", {}),
    )
    for method, path, body in malformed_routes:
        status, response = call_api(app, method, path, body, token=token)
        assert status.startswith("400"), response


def test_effective_policy_requires_one_unambiguous_group_assignment(tmp_path: Path) -> None:
    """An enrolled agent receives only its tenant-scoped, unambiguous policy."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    operator = identity("org-a")
    seed(store)
    store.register_agent(
        operator,
        deployment_id="deploy-a",
        agent_id="claude-a",
        host="claude-code",
        project_root="/workspace/payments",
    )
    create_active_policy(
        store,
        operator,
        policy_id="policy-safe",
        name="Safe",
        configuration={"tools": {"allowed": ["lookup_record"]}},
    )
    store.create_group(
        operator, group_id="group-platform", name="Platform", policy_id="policy-safe"
    )
    agent = FleetIdentity("claude-a", "org-a", frozenset({"agent"}))
    with pytest.raises(FleetNotFoundError, match="not assigned"):
        store.effective_agent_policy(agent, deployment_id="deploy-a", agent_id="claude-a")
    store.add_agent_to_group(
        operator, group_id="group-platform", deployment_id="deploy-a", agent_id="claude-a"
    )
    effective = store.effective_agent_policy(agent, deployment_id="deploy-a", agent_id="claude-a")
    assert effective["policy"]["id"] == "policy-safe"
    assert effective["groupId"] == "group-platform"

    store.create_group(
        operator, group_id="group-same-policy", name="Same policy", policy_id="policy-safe"
    )
    store.add_agent_to_group(
        operator, group_id="group-same-policy", deployment_id="deploy-a", agent_id="claude-a"
    )
    with pytest.raises(FleetConfigurationError, match="exactly one policy group"):
        store.effective_agent_policy(agent, deployment_id="deploy-a", agent_id="claude-a")
    store.remove_agent_from_group(
        operator, group_id="group-same-policy", deployment_id="deploy-a", agent_id="claude-a"
    )

    create_active_policy(
        store,
        operator,
        policy_id="policy-restricted",
        name="Restricted",
        configuration={"tools": {"allowed": []}},
    )
    store.create_group(
        operator, group_id="group-restricted", name="Restricted", policy_id="policy-restricted"
    )
    store.add_agent_to_group(
        operator, group_id="group-restricted", deployment_id="deploy-a", agent_id="claude-a"
    )
    with pytest.raises(FleetConfigurationError, match="exactly one policy group"):
        store.effective_agent_policy(agent, deployment_id="deploy-a", agent_id="claude-a")


def test_effective_policy_http_route_is_agent_scoped(tmp_path: Path) -> None:
    """The effective-policy endpoint authenticates the agent and returns no session."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    operator_token = "fleet-admin-token-1234"  # noqa: S105 - synthetic test credential
    agent_token = "fleet-agent-token-1234"  # noqa: S105 - synthetic test credential
    operator = identity("org-a")
    agent = FleetIdentity("claude-a", "org-a", frozenset({"agent"}))
    app = EnterpriseFleetApplication(
        store,
        authenticator=StaticFleetAuthenticator({operator_token: operator, agent_token: agent}),
    )
    seed(store)
    store.register_agent(
        operator,
        deployment_id="deploy-a",
        agent_id="claude-a",
        host="claude-code",
        project_root="/workspace/payments",
    )
    create_active_policy(
        store,
        operator,
        policy_id="policy-safe",
        name="Safe",
        configuration={"tools": {"allowed": ["lookup_record"]}},
    )
    store.create_group(
        operator, group_id="group-platform", name="Platform", policy_id="policy-safe"
    )
    store.add_agent_to_group(
        operator, group_id="group-platform", deployment_id="deploy-a", agent_id="claude-a"
    )
    status, payload = call_api(
        app,
        "GET",
        "/api/enterprise/agents/deploy-a/claude-a/effective-policy",
        token=agent_token,
    )
    assert status.startswith("200")
    assert payload["policy"]["id"] == "policy-safe"
    assert "sessionId" not in json.dumps(payload)


def test_incident_stops_cover_agent_group_and_deployment_scopes(tmp_path: Path) -> None:
    """Every incident stop scope is visible to the enrolled runtime and auditable."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    operator = identity("org-a")
    seed(store)
    store.register_agent(
        operator,
        deployment_id="deploy-a",
        agent_id="claude-a",
        host="claude-code",
        project_root="/workspace/payments",
    )
    create_active_policy(
        store,
        operator,
        policy_id="policy-safe",
        name="Safe",
        configuration={"tools": {"allowed": ["lookup_record"]}},
    )
    store.create_group(
        operator, group_id="group-platform", name="Platform", policy_id="policy-safe"
    )
    store.add_agent_to_group(
        operator, group_id="group-platform", deployment_id="deploy-a", agent_id="claude-a"
    )
    assert (
        store.set_agent_emergency_stop(
            operator, deployment_id="deploy-a", agent_id="claude-a", active=True
        )["emergencyStop"]
        is True
    )
    assert (
        store.effective_agent_policy(
            FleetIdentity("claude-a", "org-a", frozenset({"agent"})),
            deployment_id="deploy-a",
            agent_id="claude-a",
        )["emergencyStop"]
        is True
    )
    store.set_agent_emergency_stop(
        operator, deployment_id="deploy-a", agent_id="claude-a", active=False
    )
    assert (
        store.set_group_emergency_stop(operator, group_id="group-platform", active=True)[
            "emergencyStop"
        ]
        is True
    )
    assert store.set_emergency_stop(operator, "deploy-a", active=True)["emergencyStop"] is True
    evidence = store.audit_evidence(operator)
    assert evidence.items
    assert all("payloadHash" in item and "sessionId" not in item for item in evidence.items)
    filtered = store.audit_evidence(operator, event_type="fleet_agent_emergency_stop_changed")
    assert all(item["eventType"] == "fleet_agent_emergency_stop_changed" for item in filtered.items)


def test_agent_verification_reports_each_enrollment_prerequisite(tmp_path: Path) -> None:
    """Operations can prove why an enrolled agent is or is not ready."""
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    operator = identity("org-a")
    seed(store)
    registered = store.register_agent(
        operator,
        deployment_id="deploy-a",
        agent_id="claude-a",
        host="claude-code",
        project_root="/workspace/payments",
    )
    create_active_policy(
        store,
        operator,
        policy_id="policy-safe",
        name="Safe",
        configuration={"tools": {"allowed": ["lookup_record"]}},
    )
    store.create_group(
        operator, group_id="group-platform", name="Platform", policy_id="policy-safe"
    )
    result = store.verify_agent(operator, deployment_id="deploy-a", agent_id="claude-a")
    assert result["verified"] is False
    assert result["checks"]["registered"]["passed"] is True
    assert result["checks"]["policyAssignment"]["passed"] is False
    store.add_agent_to_group(
        operator, group_id="group-platform", deployment_id="deploy-a", agent_id="claude-a"
    )
    desired = {
        "host": "claude-code",
        "hostVersion": "2.1.211",
        "platform": "linux",
        "bundleHash": "a" * 64,
        "policyId": "policy-safe",
        "policyVersion": 1,
    }
    store.create_template(
        operator,
        template_id="managed-claude",
        name="Managed Claude",
        configuration={"managedHost": desired},
    )
    store.assign_template(operator, "deploy-a", "managed-claude")
    with pytest.raises(FleetConfigurationError, match="not freshly enforced"):
        store.effective_agent_policy(
            operator,
            deployment_id="deploy-a",
            agent_id="claude-a",
        )
    store.heartbeat(
        operator,
        "deploy-a",
        "claude-a",
        registered["sessionId"],
        managed_configuration={
            **desired,
            "source": "endpoint-managed-file",
            "verifiedAt": 1,
            "expiresAt": 1_900_000_000,
        },
    )
    result = store.verify_agent(operator, deployment_id="deploy-a", agent_id="claude-a")
    assert result["verified"] is True
    assert result["checks"]["managedConfiguration"]["passed"] is True
    assert result["host"] == "claude-code"
    assert result["groups"] == ["group-platform"]
    assert result["policyId"] == "policy-safe"
    assert result["policyVersion"] == 1
    assert (
        store.effective_agent_policy(
            operator,
            deployment_id="deploy-a",
            agent_id="claude-a",
        )["policy"]["id"]
        == "policy-safe"
    )
    store.set_agent_emergency_stop(
        operator, deployment_id="deploy-a", agent_id="claude-a", active=True
    )
    stopped = store.verify_agent(operator, deployment_id="deploy-a", agent_id="claude-a")
    assert stopped["verified"] is False
    assert stopped["checks"]["emergencyStop"]["passed"] is False


def test_local_isolation_profile_lifecycle_is_tenant_scoped_and_honestly_unverified(
    tmp_path: Path,
) -> None:
    """SQLite manages desired profiles but never claims a sandbox was observed."""
    store = EnterpriseFleetStore(tmp_path / "isolation-profiles.sqlite")
    token_a = "fleet-admin-isolation-a1234"  # noqa: S105 - synthetic test credential
    token_b = "fleet-admin-isolation-b1234"  # noqa: S105 - synthetic test credential
    app = EnterpriseFleetApplication(
        store,
        authenticator=StaticFleetAuthenticator(
            {token_a: identity("org-a"), token_b: identity("org-b", subject="operator-b")}
        ),
    )
    for token, organization_id in ((token_a, "org-a"), (token_b, "org-b")):
        assert call_api(
            app,
            "POST",
            "/api/enterprise/organizations",
            {"organizationId": organization_id, "name": organization_id.upper()},
            token=token,
        )[0].startswith("201")
    constraints = {
        "filesystemReadOnly": True,
        "networkMode": "none",
        "allowedNetworkDestinations": [],
        "processNamespace": True,
        "maxMemoryMib": 256,
        "maxPids": 64,
        "cpuLimitMillicores": 1000,
        "maxDurationSeconds": 30,
        "credentialMode": "none",
        "noNewPrivileges": True,
        "capabilitiesDropped": True,
    }
    request = {
        "profileId": "docker-hostile-code",
        "name": "Docker hostile code",
        "provider": "docker_engine",
        "boundary": "container",
        "workloadRef": "sha256:" + "a" * 64,
        "allowedTools": ["compile_untrusted"],
        "constraints": constraints,
    }
    status, created = call_api(
        app, "POST", "/api/enterprise/isolation-profiles", request, token=token_a
    )
    assert status.startswith("201")
    assert created["verificationStatus"] == "unverified"
    assert created["executionAllowed"] is False
    assert created["revocationEpoch"] == 1
    policy = store.create_policy(
        identity("org-a"),
        policy_id="policy-attested-code",
        name="Attested code execution",
        configuration={
            "tools": {"allowed": ["compile_untrusted"]},
            "isolation": {
                "verifier": "deployment_attested",
                "requiredForHighRisk": True,
                "mode": "required",
                "acceptedProfiles": [created["id"]],
            },
        },
    )
    assert policy["pendingVersion"] == 1
    with pytest.raises(FleetConfigurationError, match="unavailable isolation profile"):
        store.create_policy(
            identity("org-a"),
            policy_id="policy-unknown-isolation",
            name="Unknown isolation",
            configuration={"isolation": {"acceptedProfiles": ["missing-profile"]}},
        )

    _, integrations_a = call_api(app, "GET", "/api/enterprise/integrations", token=token_a)
    _, integrations_b = call_api(app, "GET", "/api/enterprise/integrations", token=token_b)
    assert [item["id"] for item in integrations_a["isolationProfiles"]] == ["docker-hostile-code"]
    assert integrations_b["isolationProfiles"] == []

    rejected, _ = call_api(
        app,
        "POST",
        "/api/enterprise/isolation-profiles",
        {**request, "profileId": "mutable", "workloadRef": "worker:latest"},
        token=token_a,
    )
    assert rejected.startswith("400")
    revoked_status, revoked = call_api(
        app,
        "POST",
        "/api/enterprise/isolation-profiles/docker-hostile-code/revoke",
        {"expectedRevision": 1, "reason": "Synthetic profile retirement."},
        token=token_a,
    )
    assert revoked_status.startswith("200")
    assert revoked["verificationStatus"] == "revoked"
    assert revoked["executionAllowed"] is False
    assert revoked["revocationEpoch"] == 2
