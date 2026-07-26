"""Tenant-aware fleet control-plane primitives.

This module provides the durable, provider-neutral foundation used by an
enterprise control plane.  It deliberately stores metadata and references to
configuration rather than secrets or executable policy.  Authentication and
runtime authority remain deployment-owned adapters, while this layer enforces
organization, project, and deployment scope before returning data or changing
state.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Protocol
from urllib.parse import parse_qs

from .audit import AuditSink

_MAX_TEXT = 256
_MAX_PAGE_SIZE = 200
_FLEET_GOVERNANCE_KEYS: dict[str, frozenset[str]] = {
    "policy": frozenset({"provider", "endpoint", "allowedPrincipals", "denyByDefault"}),
    "approvals": frozenset({"provider", "endpoint", "ttlSeconds", "requiredFor"}),
    "tools": frozenset({"allowed", "denied", "builtIn", "fileTools"}),
    "budgets": frozenset(
        {
            "maxActions",
            "maxConcurrent",
            "maxFanOut",
            "maxCostUnits",
            "maxDelegationDepth",
            "maxActionsPerSecond",
            "executionTimeoutSeconds",
            "maxTimedOutWorkers",
        }
    ),
    "credentials": frozenset({"enabled", "brokerEndpoint", "scopes", "mode"}),
    "isolation": frozenset({"verifier", "requiredForHighRisk", "mode"}),
    "audit": frozenset(
        {"provider", "path", "replicaEndpoint", "redactSensitiveData", "captureToolContent"}
    ),
    "telemetry": frozenset(
        {"enabled", "endpoint", "exporter", "redactSensitiveData", "captureToolContent"}
    ),
    "runtime": frozenset(
        {
            "policyProvider",
            "approvalProvider",
            "auditProvider",
            "policyEndpoint",
            "approvalEndpoint",
            "auditPath",
            "auditReplicaEndpoint",
            "credentialBrokerEndpoint",
            "isolationVerifier",
            "telemetryEnabled",
            "allowedTools",
            "allowedPrincipals",
            "maxActions",
            "maxConcurrent",
            "maxFanOut",
            "maxCostUnits",
            "maxDelegationDepth",
            "maxActionsPerSecond",
            "executionTimeoutSeconds",
            "maxTimedOutWorkers",
            "idempotencyTtlSeconds",
            "approvalTtlSeconds",
            "credentialsEnabled",
            "isolationRequiredForHighRisk",
            "redactSensitiveData",
            "captureToolContent",
        }
    ),
    "claudeCode": frozenset(
        {
            "enabled",
            "allowedBuiltInTools",
            "deniedCommandPatterns",
            "approvalCommandPatterns",
            "fileTools",
        }
    ),
}


class FleetConfigurationError(ValueError):
    """Raised when an enterprise fleet request is malformed or out of scope."""


class FleetAuthorizationError(PermissionError):
    """Raised when an identity lacks authority for a tenant-scoped action."""


class FleetNotFoundError(LookupError):
    """Raised when a requested organization, project, deployment, or agent is absent."""


@dataclass(frozen=True, slots=True)
class FleetIdentity:
    """Authenticated enterprise identity and its organization/project scope."""

    subject: str
    organization_id: str
    roles: frozenset[str]
    project_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        """Reject empty identity data before it can influence authorization."""
        if not self.subject.strip() or not self.organization_id.strip() or not self.roles:
            raise ValueError("fleet identity requires subject, organization, and roles")


class FleetAuthenticator(Protocol):
    """Deployment-owned authentication boundary for enterprise API requests."""

    def authenticate(self, authorization: object) -> FleetIdentity | None:
        """Authenticate a request and return no identity on failure."""

    def authorize(self, identity: FleetIdentity, action: str) -> bool:
        """Return whether the identity may perform the coarse-grained action."""


class FleetDeploymentAuthority(Protocol):
    """Runtime adapter that applies controls to one independently deployed SDK."""

    def apply_configuration(self, configuration: Mapping[str, Any]) -> None:
        """Atomically apply validated configuration or raise without claiming success."""

    def emergency_stop(self) -> None:
        """Stop consequential actions for the deployment."""

    def clear_emergency_stop(self) -> None:
        """Clear the deployment stop after incident controls permit it."""


class FleetAlertSink(Protocol):
    """Provider-neutral delivery boundary for redacted fleet alerts."""

    def publish(self, alert: Mapping[str, Any]) -> None:
        """Deliver one redacted alert or raise without changing fleet state."""


class StaticFleetAuthenticator:
    """Bounded bearer authenticator for local tests and reference deployments."""

    def __init__(self, credentials: Mapping[str, FleetIdentity]) -> None:
        """Create a synthetic credential map; production uses an IdP adapter."""
        if not credentials or any(not token or len(token) < 16 for token in credentials):
            raise ValueError("fleet credentials require tokens of at least 16 characters")
        self._credentials = dict(credentials)

    def authenticate(self, authorization: object) -> FleetIdentity | None:
        """Authenticate only a Bearer header using constant-time comparison."""
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            return None
        supplied = authorization[7:].strip()
        for token, identity in self._credentials.items():
            if hmac.compare_digest(supplied, token):
                return identity
        return None

    def authorize(self, identity: FleetIdentity, action: str) -> bool:
        """Apply the reference role matrix; deployments should use their IdP policy."""
        if action == "read":
            return bool(identity.roles & {"viewer", "operator", "admin", "incident_commander"})
        if action in {"manage_inventory", "manage_configuration"}:
            return bool(identity.roles & {"operator", "admin"})
        if action == "agent_presence":
            return bool(identity.roles & {"agent", "admin"})
        if action == "emergency_stop":
            return bool(identity.roles & {"incident_commander", "admin"})
        if action in {"manage_alerts", "dispatch_alerts"}:
            return bool(identity.roles & {"incident_commander", "admin"})
        return False


@dataclass(frozen=True, slots=True)
class FleetPage:
    """Stable paginated result for fleet inventory APIs."""

    items: tuple[dict[str, Any], ...]
    next_cursor: str | None


def _text(value: object, name: str) -> str:
    """Validate bounded non-empty metadata without interpreting it as authority."""
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise FleetConfigurationError(f"{name} must be bounded non-empty text")
    return value.strip()


def _optional_text(value: object, name: str) -> str | None:
    """Validate optional bounded metadata."""
    if value is None or value == "":
        return None
    return _text(value, name)


def _json_object(value: Mapping[str, Any] | None, name: str) -> str:
    """Serialize bounded metadata while rejecting secret-like fields."""
    safe_keys = {"environment", "region", "team", "labels", "version"}
    data = dict(value or {})
    if len(data) > 20 or any(str(key) not in safe_keys for key in data):
        raise FleetConfigurationError(f"{name} contains unsupported metadata")
    for key, item in data.items():
        if not isinstance(key, str) or not isinstance(item, (str, int, float, bool, list)):
            raise FleetConfigurationError(f"{name} must contain JSON scalar metadata")
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def validate_fleet_configuration(configuration: Mapping[str, Any]) -> dict[str, Any]:
    """Validate typed enterprise governance sections without accepting authority.

    Templates remain backward compatible with small legacy objects, but any
    recognized governance section is a closed schema. This makes policy,
    approvals, tools, budgets, credentials, isolation, audit, telemetry, and
    Claude Code controls discoverable and rejects configuration typos before a
    template can be rolled out. Endpoint values are references only; secrets
    are rejected by the common recursive validator below.
    """
    if not isinstance(configuration, Mapping):
        raise FleetConfigurationError("configuration must be an object")
    normalized: dict[str, Any] = {}
    for key, value in configuration.items():
        key_text = _text(key, "configuration section")
        if key_text in _FLEET_GOVERNANCE_KEYS:
            if not isinstance(value, Mapping):
                raise FleetConfigurationError(f"{key_text} must be an object")
            unknown = set(value) - _FLEET_GOVERNANCE_KEYS[key_text]
            if unknown:
                fields = ", ".join(sorted(map(str, unknown)))
                raise FleetConfigurationError(f"{key_text} contains unsupported fields: {fields}")
            normalized[key_text] = dict(value)
        else:
            # Preserve legacy extension sections; the recursive bounded and
            # secret-safe serializer remains the final storage boundary.
            normalized[key_text] = value
    return normalized


class EnterpriseFleetStore:
    """SQLite-backed tenant inventory and authenticated agent presence store.

    SQLite is a reference persistence adapter, not a claim that every
    enterprise should use SQLite.  The schema and method contracts are the
    portable boundary for a PostgreSQL or managed database adapter.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        audit: AuditSink | None = None,
        now: Callable[[], float] | None = None,
        heartbeat_ttl_seconds: int = 90,
        slo_window_seconds: int = 86_400,
        slo_target: float = 0.99,
        authorities: Mapping[str, FleetDeploymentAuthority] | None = None,
        alert_sink: FleetAlertSink | None = None,
    ) -> None:
        """Open or create a migrated fleet database with bounded heartbeat TTL."""
        if heartbeat_ttl_seconds < 15 or heartbeat_ttl_seconds > 86_400:
            raise FleetConfigurationError("heartbeat TTL must be between 15 and 86400 seconds")
        if slo_window_seconds < 300 or slo_window_seconds > 31_536_000:
            raise FleetConfigurationError("SLO window must be between 300 and 31536000 seconds")
        if not 0.5 <= slo_target <= 1.0:
            raise FleetConfigurationError("SLO target must be between 0.5 and 1.0")
        self.path = str(path)
        self.audit = audit
        self._now = now or time.time
        self.heartbeat_ttl_seconds = heartbeat_ttl_seconds
        self.slo_window_seconds = slo_window_seconds
        self.slo_target = slo_target
        self.authorities = dict(authorities or {})
        self.alert_sink = alert_sink
        self._lock = RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._migrate()

    def close(self) -> None:
        """Close the persistence connection after callers stop serving requests."""
        with self._lock:
            self._connection.close()

    def reconcile_authorities(self) -> None:
        """Reconcile persisted controls into live authorities before serving traffic.

        The database is not an execution authority. On restart, every bound
        deployment is brought to its persisted stop state and active rollout
        configuration first; any adapter failure aborts reconciliation and
        callers must keep the API out of service.
        """
        with self._lock:
            rows = self._connection.execute(
                "SELECT d.id,c.desired_configuration,c.rollout_state,"
                "COALESCE(ctrl.emergency_stop,0) AS emergency_stop "
                "FROM deployments d LEFT JOIN deployment_configs c ON c.deployment_id=d.id "
                "LEFT JOIN deployment_controls ctrl ON ctrl.deployment_id=d.id"
            ).fetchall()
            rows = [row for row in rows if row["id"] in self.authorities]
            try:
                for row in rows:
                    authority = self.authorities[row["id"]]
                    if bool(row["emergency_stop"]):
                        authority.emergency_stop()
                    else:
                        authority.clear_emergency_stop()
                    if row["desired_configuration"] is not None and row["rollout_state"] in {
                        "canary",
                        "active",
                        "rollback",
                    }:
                        authority.apply_configuration(json.loads(row["desired_configuration"]))
            except Exception as exc:
                raise FleetConfigurationError(
                    "live deployment authority reconciliation failed"
                ) from exc

    def __del__(self) -> None:
        """Best-effort cleanup for short-lived reference applications and tests."""
        connection = getattr(self, "_connection", None)
        if connection is not None:
            try:
                connection.close()
            except Exception:  # pragma: no cover  # noqa: S110
                pass

    def create_organization(self, organization_id: str, name: str) -> dict[str, Any]:
        """Create an organization root for tenant isolation."""
        organization_id, name = _text(organization_id, "organizationId"), _text(name, "name")
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO organizations(id,name,created_at) VALUES(?,?,?)",
                    (organization_id, name, self._now()),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                raise FleetConfigurationError("organization already exists") from exc
        return {"id": organization_id, "name": name}

    def create_project(self, organization_id: str, project_id: str, name: str) -> dict[str, Any]:
        """Create a project within an existing organization."""
        organization_id, project_id, name = (
            _text(organization_id, "organizationId"),
            _text(project_id, "projectId"),
            _text(name, "name"),
        )
        with self._lock:
            self._require_org(organization_id)
            try:
                self._connection.execute(
                    "INSERT INTO projects(id,organization_id,name,created_at) VALUES(?,?,?,?)",
                    (project_id, organization_id, name, self._now()),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                raise FleetConfigurationError("project already exists") from exc
        return {"id": project_id, "organizationId": organization_id, "name": name}

    def create_deployment(
        self,
        organization_id: str,
        project_id: str,
        deployment_id: str,
        name: str,
        *,
        environment: str,
        region: str,
        sdk_version: str | None = None,
        team: str | None = None,
    ) -> dict[str, Any]:
        """Register one independently managed SDK control-plane deployment."""
        values = tuple(
            _text(value, label)
            for value, label in (
                (organization_id, "organizationId"),
                (project_id, "projectId"),
                (deployment_id, "deploymentId"),
                (name, "name"),
                (environment, "environment"),
                (region, "region"),
            )
        )
        sdk_version = _optional_text(sdk_version, "sdkVersion")
        team = _optional_text(team, "team") or ""
        with self._lock:
            self._require_project(values[0], values[1])
            try:
                self._connection.execute(
                    """INSERT INTO deployments
                    (id,organization_id,project_id,name,environment,region,sdk_version,team,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        values[2],
                        values[0],
                        values[1],
                        values[3],
                        values[4],
                        values[5],
                        sdk_version,
                        team,
                        self._now(),
                    ),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                raise FleetConfigurationError("deployment already exists") from exc
        return self._deployment(values[2])

    def list_inventory(
        self, identity: FleetIdentity, resource: str, *, organization_id: str | None = None
    ) -> FleetPage:
        """Return tenant-scoped inventory without exposing agent session secrets."""
        if resource not in {"organizations", "projects", "deployments", "agents", "sessions"}:
            raise FleetConfigurationError("unknown inventory resource")
        org = organization_id or identity.organization_id
        if org != identity.organization_id and "admin" not in identity.roles:
            raise FleetAuthorizationError("organization scope is not permitted")
        with self._lock:
            if resource == "organizations":
                rows = self._connection.execute(
                    "SELECT id,name,created_at FROM organizations WHERE id=?", (org,)
                ).fetchall()
            elif resource == "projects":
                if identity.project_ids and "admin" not in identity.roles:
                    placeholders = ",".join("?" for _ in identity.project_ids)
                    project_query = (  # noqa: S608 - placeholders are generated from a set length.
                        "SELECT id,organization_id,name,created_at FROM projects "  # noqa: S608
                        f"WHERE organization_id=? AND id IN ({placeholders})"  # noqa: S608
                    )
                    rows = self._connection.execute(
                        project_query,
                        (org, *identity.project_ids),
                    ).fetchall()
                else:
                    rows = self._connection.execute(
                        "SELECT id,organization_id,name,created_at FROM projects "
                        "WHERE organization_id=?",
                        (org,),
                    ).fetchall()
            elif resource == "deployments":
                query = (
                    "SELECT id,organization_id,project_id,name,environment,region,sdk_version,team,"
                    "created_at FROM deployments WHERE organization_id=?"
                )
                params: tuple[Any, ...] = (org,)
                if identity.project_ids and "admin" not in identity.roles:
                    placeholders = ",".join("?" for _ in identity.project_ids)
                    query += f" AND project_id IN ({placeholders})"
                    params += tuple(identity.project_ids)
                rows = self._connection.execute(query, params).fetchall()
            elif resource == "agents":
                self._expire_agents()
                rows = self._connection.execute(
                    "SELECT id,organization_id,project_id,deployment_id,host,project_root,"
                    "environment,region,status,last_heartbeat,expires_at FROM agents "
                    "WHERE organization_id=? ORDER BY last_heartbeat DESC",
                    (org,),
                ).fetchall()
            else:
                rows = self._connection.execute(
                    "SELECT s.agent_id,s.deployment_id,a.organization_id,a.project_id,"
                    "s.created_at,s.expires_at,"
                    "CASE WHEN s.expires_at<=? THEN 'expired' ELSE 'active' END AS status "
                    "FROM agent_sessions s JOIN agents a ON a.id=s.agent_id "
                    "AND a.deployment_id=s.deployment_id WHERE a.organization_id=? "
                    "ORDER BY s.created_at DESC",
                    (self._now(), org),
                ).fetchall()
                rows = [
                    row
                    for row in rows
                    if not identity.project_ids or row["project_id"] in identity.project_ids
                ]
            items = tuple(dict(row) for row in rows)
        return FleetPage(items, None)

    def create_template(
        self,
        identity: FleetIdentity,
        *,
        template_id: str,
        name: str,
        configuration: Mapping[str, Any],
        parent_template_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a tenant-scoped configuration template with optional inheritance."""
        template_id, name = _text(template_id, "templateId"), _text(name, "name")
        configuration_json = self._configuration_json(configuration)
        with self._lock:
            if parent_template_id is not None:
                parent = self._template(parent_template_id)
                if parent["organizationId"] != identity.organization_id:
                    raise FleetAuthorizationError("organization scope is not permitted")
                self._assert_no_template_cycle(parent_template_id, template_id)
            self._assert_identity_org(identity, identity.organization_id)
            try:
                self._connection.execute(
                    "INSERT INTO templates(id,organization_id,name,parent_id,configuration,version,"
                    "created_at)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (
                        template_id,
                        identity.organization_id,
                        name,
                        parent_template_id,
                        configuration_json,
                        1,
                        self._now(),
                    ),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                raise FleetConfigurationError("template already exists") from exc
        return self._template(template_id)

    def list_templates(self, identity: FleetIdentity) -> FleetPage:
        """Return tenant-scoped templates without exposing secret material."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT id FROM templates WHERE organization_id=? ORDER BY name, id",
                (identity.organization_id,),
            ).fetchall()
            items = tuple(self._template(row["id"]) for row in rows)
        return FleetPage(items, None)

    def validate_template_configuration(
        self, identity: FleetIdentity, configuration: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Validate a proposed template without persisting it or changing authority."""
        self._assert_identity_org(identity, identity.organization_id)
        normalized = json.loads(self._configuration_json(configuration))
        return {
            "valid": True,
            "configuration": normalized,
            "configurationHash": self._configuration_hash(normalized),
        }

    def assign_template(
        self, identity: FleetIdentity, deployment_id: str, template_id: str
    ) -> dict[str, Any]:
        """Set a deployment's desired configuration and stage it for rollout."""
        deployment_id, template_id = (
            _text(deployment_id, "deploymentId"),
            _text(template_id, "templateId"),
        )
        with self._lock:
            deployment = self._deployment(deployment_id)
            self._assert_identity_scope(
                identity, deployment["organizationId"], deployment["projectId"]
            )
            effective = self._effective_template(template_id)
            if effective["organizationId"] != deployment["organizationId"]:
                raise FleetAuthorizationError("organization scope is not permitted")
            desired_hash = self._configuration_hash(effective["configuration"])
            existing = self._connection.execute(
                "SELECT version,template_id,desired_configuration,desired_hash,applied_hash,"
                "rollout_state,rollout_percentage FROM deployment_configs WHERE deployment_id=?",
                (deployment_id,),
            ).fetchone()
            version = int(existing["version"] if existing else 0) + 1
            if existing is not None:
                self._connection.execute(
                    "INSERT INTO deployment_config_history(deployment_id,version,template_id,"
                    "desired_configuration,desired_hash,applied_hash,rollout_state,"
                    "rollout_percentage,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        deployment_id,
                        existing["version"],
                        existing["template_id"],
                        existing["desired_configuration"],
                        existing["desired_hash"],
                        existing["applied_hash"],
                        existing["rollout_state"],
                        existing["rollout_percentage"],
                        self._now(),
                    ),
                )
            self._connection.execute(
                """INSERT INTO deployment_configs
                (deployment_id,template_id,desired_configuration,desired_hash,applied_hash,
                 rollout_state,rollout_percentage,version,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(deployment_id) DO UPDATE SET template_id=excluded.template_id,
                desired_configuration=excluded.desired_configuration,desired_hash=excluded.desired_hash,
                rollout_state='staged',rollout_percentage=0,version=excluded.version,updated_at=excluded.updated_at""",
                (
                    deployment_id,
                    template_id,
                    json.dumps(effective["configuration"], sort_keys=True, separators=(",", ":")),
                    desired_hash,
                    existing["applied_hash"] if existing else None,
                    "staged",
                    0,
                    version,
                    self._now(),
                ),
            )
            self._connection.commit()
            result = self._deployment_configuration(deployment_id)
        self._audit(
            "fleet_configuration_staged", identity.subject, result, identity.organization_id
        )
        return result

    def set_rollout(
        self,
        identity: FleetIdentity,
        deployment_id: str,
        *,
        state: str,
        percentage: int,
    ) -> dict[str, Any]:
        """Advance or pause one deployment rollout with bounded percentage."""
        deployment_id, state = _text(deployment_id, "deploymentId"), _text(state, "state")
        if state not in {"staged", "canary", "active", "paused", "rollback"}:
            raise FleetConfigurationError("unknown rollout state")
        if (
            not isinstance(percentage, int)
            or isinstance(percentage, bool)
            or not 0 <= percentage <= 100
        ):
            raise FleetConfigurationError("rollout percentage must be between 0 and 100")
        with self._lock:
            deployment = self._deployment(deployment_id)
            self._assert_identity_scope(
                identity, deployment["organizationId"], deployment["projectId"]
            )
            configuration = self._require_configuration(deployment_id)
            authority = self.authorities.get(deployment_id)
            if authority is not None and state in {"canary", "active"}:
                try:
                    authority.apply_configuration(configuration["desiredConfiguration"])
                except Exception as exc:
                    raise FleetConfigurationError(
                        "deployment runtime rejected the configuration rollout"
                    ) from exc
            self._connection.execute(
                "UPDATE deployment_configs SET rollout_state=?,rollout_percentage=?,updated_at=? "
                "WHERE deployment_id=?",
                (state, percentage, self._now(), deployment_id),
            )
            self._connection.commit()
            result = self._deployment_configuration(deployment_id)
        self._audit(
            "fleet_configuration_rollout_changed",
            identity.subject,
            result,
            identity.organization_id,
        )
        return result

    def rollout_deployments(
        self,
        identity: FleetIdentity,
        deployment_ids: Sequence[str],
        *,
        state: str,
        percentage: int,
    ) -> FleetPage:
        """Apply one bounded rollout command to multiple scoped deployments."""
        if not deployment_ids or len(deployment_ids) > 200:
            raise FleetConfigurationError("rollout must target between 1 and 200 deployments")
        normalized = tuple(dict.fromkeys(_text(item, "deploymentId") for item in deployment_ids))
        results = tuple(
            self.set_rollout(identity, deployment_id, state=state, percentage=percentage)
            for deployment_id in normalized
        )
        self._audit(
            "fleet_batch_rollout_changed",
            identity.subject,
            {"deploymentIds": list(normalized), "state": state, "percentage": percentage},
            identity.organization_id,
        )
        return FleetPage(results, None)

    def rollback_deployment(
        self, identity: FleetIdentity, deployment_id: str, version: int
    ) -> dict[str, Any]:
        """Restore a prior desired configuration as a new staged version."""
        deployment_id = _text(deployment_id, "deploymentId")
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise FleetConfigurationError("rollback version must be a positive integer")
        with self._lock:
            deployment = self._deployment(deployment_id)
            self._assert_identity_scope(
                identity, deployment["organizationId"], deployment["projectId"]
            )
            previous = self._connection.execute(
                "SELECT template_id,desired_configuration,desired_hash,applied_hash FROM "
                "deployment_config_history WHERE deployment_id=? AND version=?",
                (deployment_id, version),
            ).fetchone()
            if previous is None:
                raise FleetNotFoundError("deployment configuration version not found")
            current = self._require_configuration(deployment_id)
            next_version = int(current["version"]) + 1
            authority = self.authorities.get(deployment_id)
            if authority is not None:
                try:
                    authority.apply_configuration(json.loads(previous["desired_configuration"]))
                except Exception as exc:
                    raise FleetConfigurationError(
                        "deployment runtime rejected the configuration rollback"
                    ) from exc
            self._connection.execute(
                "INSERT INTO deployment_config_history(deployment_id,version,template_id,"
                "desired_configuration,desired_hash,applied_hash,rollout_state,"
                "rollout_percentage,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    deployment_id,
                    current["version"],
                    current["templateId"],
                    json.dumps(
                        current["desiredConfiguration"], sort_keys=True, separators=(",", ":")
                    ),
                    current["desiredHash"],
                    current["appliedHash"],
                    current["rolloutState"],
                    current["rolloutPercentage"],
                    self._now(),
                ),
            )
            self._connection.execute(
                "UPDATE deployment_configs SET template_id=?,desired_configuration=?,"
                "desired_hash=?,applied_hash=?,rollout_state='rollback',rollout_percentage=0,"
                "version=?,updated_at=? "
                "WHERE deployment_id=?",
                (
                    previous["template_id"],
                    previous["desired_configuration"],
                    previous["desired_hash"],
                    previous["applied_hash"],
                    next_version,
                    self._now(),
                    deployment_id,
                ),
            )
            self._connection.commit()
            result = self._deployment_configuration(deployment_id)
        self._audit(
            "fleet_configuration_rollback", identity.subject, result, identity.organization_id
        )
        return result

    def list_configurations(
        self, identity: FleetIdentity, deployment_id: str | None = None
    ) -> FleetPage:
        """Return desired/applied configuration state for scoped deployments."""
        with self._lock:
            query = (
                "SELECT d.id AS deployment_id, d.project_id FROM deployments d "
                "JOIN deployment_configs c ON c.deployment_id=d.id "
                "WHERE d.organization_id=?"
            )
            params: list[Any] = [identity.organization_id]
            if deployment_id is not None:
                query += " AND d.id=?"
                params.append(_text(deployment_id, "deploymentId"))
            rows = self._connection.execute(query, params).fetchall()
            items = tuple(
                self._deployment_configuration(row["deployment_id"])
                for row in rows
                if not identity.project_ids or row["project_id"] in identity.project_ids
            )
        return FleetPage(items, None)

    def list_configuration_history(
        self, identity: FleetIdentity, deployment_id: str | None = None
    ) -> FleetPage:
        """Return bounded, tenant-scoped prior configuration versions."""
        with self._lock:
            query = (
                "SELECT h.deployment_id,h.version,h.template_id,h.desired_hash,"
                "h.applied_hash,h.rollout_state,h.rollout_percentage,h.created_at,"
                "d.project_id FROM deployment_config_history h "
                "JOIN deployments d ON d.id=h.deployment_id WHERE d.organization_id=?"
            )
            params: list[Any] = [identity.organization_id]
            if deployment_id is not None:
                query += " AND h.deployment_id=?"
                params.append(_text(deployment_id, "deploymentId"))
            query += " ORDER BY h.created_at DESC LIMIT 2000"
            rows = self._connection.execute(query, params).fetchall()
        items = tuple(
            {
                "deploymentId": row["deployment_id"],
                "version": row["version"],
                "templateId": row["template_id"],
                "desiredHash": row["desired_hash"],
                "appliedHash": row["applied_hash"],
                "rolloutState": row["rollout_state"],
                "rolloutPercentage": row["rollout_percentage"],
                "createdAt": row["created_at"],
            }
            for row in rows
            if not identity.project_ids or row["project_id"] in identity.project_ids
        )
        return FleetPage(items, None)

    def record_applied_configuration(
        self, identity: FleetIdentity, deployment_id: str, configuration_hash: str
    ) -> dict[str, Any]:
        """Record an agent-reported applied hash only when it matches desired state."""
        deployment_id, configuration_hash = (
            _text(deployment_id, "deploymentId"),
            _text(configuration_hash, "configurationHash"),
        )
        with self._lock:
            deployment = self._deployment(deployment_id)
            self._assert_identity_scope(
                identity, deployment["organizationId"], deployment["projectId"]
            )
            desired = self._require_configuration(deployment_id)
            if not hmac.compare_digest(configuration_hash, desired["desiredHash"]):
                raise FleetConfigurationError("applied configuration does not match desired state")
            self._connection.execute(
                "UPDATE deployment_configs SET applied_hash=?,updated_at=? WHERE deployment_id=?",
                (configuration_hash, self._now(), deployment_id),
            )
            self._connection.commit()
            return self._deployment_configuration(deployment_id)

    def list_drift(self, identity: FleetIdentity) -> FleetPage:
        """Return deployments whose applied configuration differs from desired state."""
        with self._lock:
            rows = self._connection.execute(
                """SELECT d.id,d.organization_id,d.project_id,d.name,d.environment,d.region,
                c.template_id,c.desired_hash,c.applied_hash,c.rollout_state,c.rollout_percentage,c.version
                FROM deployments d JOIN deployment_configs c ON c.deployment_id=d.id
                WHERE d.organization_id=? AND (c.applied_hash IS NULL OR c.applied_hash<>?)""",
                (identity.organization_id, ""),
            ).fetchall()
        items = tuple(
            dict(row)
            for row in rows
            if identity.project_ids == frozenset() or row["project_id"] in identity.project_ids
        )
        return FleetPage(items, None)

    def set_emergency_stop(
        self, identity: FleetIdentity, deployment_id: str, *, active: bool
    ) -> dict[str, Any]:
        """Activate or clear one deployment's stop state through tenant scope."""
        if not isinstance(active, bool):
            raise FleetConfigurationError("emergency stop state must be boolean")
        deployment_id = _text(deployment_id, "deploymentId")
        with self._lock:
            deployment = self._deployment(deployment_id)
            self._assert_identity_scope(
                identity, deployment["organizationId"], deployment["projectId"]
            )
            authority = self.authorities.get(deployment_id)
            if authority is not None:
                try:
                    authority.emergency_stop() if active else authority.clear_emergency_stop()
                except Exception as exc:
                    raise FleetConfigurationError(
                        "deployment runtime rejected the emergency-stop change"
                    ) from exc
            self._connection.execute(
                "INSERT INTO deployment_controls(deployment_id,emergency_stop,updated_at) "
                "VALUES(?,?,?) "
                "ON CONFLICT(deployment_id) DO UPDATE SET emergency_stop=excluded.emergency_stop,"
                "updated_at=excluded.updated_at",
                (deployment_id, int(active), self._now()),
            )
            self._connection.commit()
            result = self._deployment_health(deployment_id)
        self._audit(
            "fleet_deployment_emergency_stop_changed",
            identity.subject,
            result,
            identity.organization_id,
        )
        return result

    def health(self, identity: FleetIdentity) -> FleetPage:
        """Return deployment health and bounded operational SLO indicators."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT id FROM deployments WHERE organization_id=? ORDER BY id",
                (identity.organization_id,),
            ).fetchall()
            items = tuple(
                self._deployment_health(row["id"])
                for row in rows
                if not identity.project_ids
                or identity.project_ids & {self._deployment(row["id"])["projectId"]}
            )
        return FleetPage(items, None)

    def record_slo_sample(self, identity: FleetIdentity, deployment_id: str) -> dict[str, Any]:
        """Persist a redaction-safe health sample for one authorized deployment.

        Samples are explicit rather than hidden inside ``health`` reads so a
        scheduler or telemetry adapter controls sampling frequency and the
        read path remains side-effect free.
        """
        deployment = self._deployment(_text(deployment_id, "deploymentId"))
        self._assert_identity_scope(identity, deployment["organizationId"], deployment["projectId"])
        with self._lock:
            sample = self._deployment_health(deployment_id)
            observed_at = self._now()
            self._connection.execute(
                "INSERT INTO fleet_health_samples(deployment_id,observed_at,status,"
                "connected_agents,offline_agents,drifted,emergency_stop) VALUES(?,?,?,?,?,?,?)",
                (
                    deployment_id,
                    observed_at,
                    sample["status"],
                    sample["connectedAgents"],
                    sample["offlineAgents"],
                    int(sample["drifted"]),
                    int(sample["emergencyStop"]),
                ),
            )
            self._connection.commit()
        result = {"deploymentId": deployment_id, "observedAt": observed_at, **sample}
        self._audit(
            "fleet_health_sample_recorded", identity.subject, result, identity.organization_id
        )
        return result

    def slo(self, identity: FleetIdentity) -> FleetPage:
        """Return bounded sample-based availability for each visible deployment."""
        cutoff = self._now() - self.slo_window_seconds
        with self._lock:
            rows = self._connection.execute(
                "SELECT d.id,d.project_id,COUNT(s.observed_at) AS samples,"
                "SUM(CASE WHEN s.status='healthy' THEN 1 ELSE 0 END) AS healthy_samples "
                "FROM deployments d LEFT JOIN fleet_health_samples s "
                "ON s.deployment_id=d.id AND s.observed_at>=? "
                "WHERE d.organization_id=? GROUP BY d.id,d.project_id ORDER BY d.id",
                (cutoff, identity.organization_id),
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            if identity.project_ids and row["project_id"] not in identity.project_ids:
                continue
            samples = int(row["samples"])
            healthy = int(row["healthy_samples"] or 0)
            availability = healthy / samples if samples else None
            items.append(
                {
                    "deploymentId": row["id"],
                    "windowSeconds": self.slo_window_seconds,
                    "sampleCount": samples,
                    "healthySamples": healthy,
                    "availability": availability,
                    "target": self.slo_target,
                    "status": (
                        "no_data"
                        if availability is None
                        else "meeting"
                        if availability >= self.slo_target
                        else "breach"
                    ),
                }
            )
        return FleetPage(tuple(items), None)

    def compliance_evidence(self, identity: FleetIdentity) -> dict[str, Any]:
        """Build a redacted tenant-scoped evidence summary for review/export.

        The bundle contains identifiers, hashes, states, counts, and audit
        metadata only. It intentionally excludes desired configuration values,
        credentials, opaque sessions, and raw audit payloads.
        """
        inventory = self.list_inventory(identity, "deployments")
        configurations = {
            item["deploymentId"]: item for item in self.list_configurations(identity).items
        }
        health = {item["deploymentId"]: item for item in self.health(identity).items}
        slo = {item["deploymentId"]: item for item in self.slo(identity).items}
        with self._lock:
            audit_rows = self._connection.execute(
                "SELECT event_type,COUNT(*) AS count,MAX(occurred_at) AS last_occurred "
                "FROM fleet_audit_evidence WHERE organization_id=? GROUP BY event_type "
                "ORDER BY event_type",
                (identity.organization_id,),
            ).fetchall()
            sessions = self._connection.execute(
                "SELECT COUNT(*) AS count FROM agent_sessions s JOIN agents a "
                "ON a.id=s.agent_id AND a.deployment_id=s.deployment_id "
                "WHERE a.organization_id=? AND s.expires_at>?",
                (identity.organization_id, self._now()),
            ).fetchone()["count"]
        deployments: list[dict[str, Any]] = []
        for deployment in inventory.items:
            if identity.project_ids and deployment["project_id"] not in identity.project_ids:
                continue
            deployment_id = deployment["id"]
            config = configurations.get(deployment_id)
            deployments.append(
                {
                    "id": deployment_id,
                    "projectId": deployment["project_id"],
                    "team": deployment["team"],
                    "environment": deployment["environment"],
                    "region": deployment["region"],
                    "sdkVersion": deployment["sdk_version"],
                    "configuration": (
                        {
                            "templateId": config["templateId"],
                            "desiredHash": config["desiredHash"],
                            "appliedHash": config["appliedHash"],
                            "version": config["version"],
                            "rolloutState": config["rolloutState"],
                            "rolloutPercentage": config["rolloutPercentage"],
                        }
                        if config
                        else None
                    ),
                    "health": health.get(deployment_id),
                    "slo": slo.get(deployment_id),
                }
            )
        return {
            "schemaVersion": 1,
            "organizationId": identity.organization_id,
            "generatedAt": self._now(),
            "activeSessionCount": int(sessions),
            "deploymentCount": len(deployments),
            "deployments": deployments,
            "audit": [dict(row) for row in audit_rows],
            "redaction": {
                "configurationValuesIncluded": False,
                "sessionTokensIncluded": False,
                "credentialMaterialIncluded": False,
                "rawAuditPayloadsIncluded": False,
            },
        }

    def alerts(self, identity: FleetIdentity) -> FleetPage:
        """Return deterministic alerts derived from authoritative fleet state."""
        alerts: list[dict[str, Any]] = []
        for health in self.health(identity).items:
            deployment_id = health["deploymentId"]
            if health["emergencyStop"]:
                alerts.append(
                    {
                        "id": f"stop:{deployment_id}",
                        "severity": "critical",
                        "type": "emergency_stop",
                        "deploymentId": deployment_id,
                        "message": "Deployment emergency stop is active",
                    }
                )
            if health["drifted"]:
                alerts.append(
                    {
                        "id": f"drift:{deployment_id}",
                        "severity": "high",
                        "type": "configuration_drift",
                        "deploymentId": deployment_id,
                        "message": "Applied configuration differs from desired state",
                    }
                )
            if health["offlineAgents"] > 0:
                alerts.append(
                    {
                        "id": f"offline:{deployment_id}",
                        "severity": "medium",
                        "type": "agent_offline",
                        "deploymentId": deployment_id,
                        "message": f"{health['offlineAgents']} agent(s) are offline",
                    }
                )
        with self._lock:
            acknowledged = {
                row["alert_id"]
                for row in self._connection.execute(
                    "SELECT alert_id FROM fleet_alert_acknowledgements WHERE organization_id=?",
                    (identity.organization_id,),
                ).fetchall()
            }
        for alert in alerts:
            alert["acknowledged"] = alert["id"] in acknowledged
        return FleetPage(tuple(alerts), None)

    def acknowledge_alert(self, identity: FleetIdentity, alert_id: str) -> dict[str, Any]:
        """Acknowledge one current alert without deleting or hiding its evidence."""
        alert_id = _text(alert_id, "alertId")
        current = {item["id"]: item for item in self.alerts(identity).items}
        if alert_id not in current:
            raise FleetNotFoundError("fleet alert not found")
        with self._lock:
            self._connection.execute(
                "INSERT INTO fleet_alert_acknowledgements"
                "(organization_id,alert_id,subject,acknowledged_at) VALUES(?,?,?,?) "
                "ON CONFLICT(organization_id,alert_id) DO UPDATE SET subject=excluded.subject,"
                "acknowledged_at=excluded.acknowledged_at",
                (identity.organization_id, alert_id, identity.subject, self._now()),
            )
            self._connection.commit()
        result = {**current[alert_id], "acknowledged": True, "acknowledgedBy": identity.subject}
        self._audit("fleet_alert_acknowledged", identity.subject, result, identity.organization_id)
        return result

    def dispatch_alerts(self, identity: FleetIdentity) -> FleetPage:
        """Deliver current unacknowledged alerts through the injected alert adapter."""
        if self.alert_sink is None:
            raise FleetConfigurationError("no fleet alert sink is configured")
        delivered: list[dict[str, Any]] = []
        for alert in self.alerts(identity).items:
            if alert["acknowledged"]:
                continue
            redacted = dict(alert)
            try:
                self.alert_sink.publish(redacted)
            except Exception as exc:
                raise FleetConfigurationError("fleet alert delivery failed") from exc
            delivered.append({**redacted, "delivered": True})
        self._audit(
            "fleet_alerts_dispatched",
            identity.subject,
            {"count": len(delivered)},
            identity.organization_id,
        )
        return FleetPage(tuple(delivered), None)

    def register_agent(
        self,
        identity: FleetIdentity,
        *,
        deployment_id: str,
        agent_id: str,
        host: str,
        project_root: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Bind one authenticated agent process to a deployment and issue a session."""
        values = tuple(
            _text(value, label)
            for value, label in (
                (deployment_id, "deploymentId"),
                (agent_id, "agentId"),
                (host, "host"),
                (project_root, "projectRoot"),
            )
        )
        metadata_json = _json_object(metadata, "metadata")
        with self._lock:
            deployment = self._deployment(values[0])
            self._assert_identity_scope(
                identity, deployment["organizationId"], deployment["projectId"]
            )
            self._assert_agent_identity(identity, values[1])
            now = float(self._now())
            expires = now + self.heartbeat_ttl_seconds
            session_id = secrets.token_urlsafe(32)
            self._connection.execute(
                """INSERT INTO agents
                (id,organization_id,project_id,deployment_id,host,project_root,environment,region,
                 status,last_heartbeat,expires_at,metadata)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(deployment_id,id) DO UPDATE SET
                host=excluded.host,project_root=excluded.project_root,status='connected',
                last_heartbeat=excluded.last_heartbeat,expires_at=excluded.expires_at,
                metadata=excluded.metadata""",
                (
                    values[1],
                    deployment["organizationId"],
                    deployment["projectId"],
                    values[0],
                    values[2],
                    values[3],
                    deployment["environment"],
                    deployment["region"],
                    "connected",
                    now,
                    expires,
                    metadata_json,
                ),
            )
            self._connection.execute(
                "INSERT INTO agent_sessions(agent_id,deployment_id,session_id,created_at,"
                "expires_at)"
                " VALUES(?,?,?,?,?)",
                (values[1], values[0], session_id, now, expires),
            )
            self._connection.commit()
            result = self._agent(values[0], values[1])
        self._audit("fleet_agent_registered", identity.subject, result, identity.organization_id)
        result["sessionId"] = session_id
        return result

    def heartbeat(
        self, identity: FleetIdentity, deployment_id: str, agent_id: str, session_id: str
    ) -> dict[str, Any]:
        """Refresh a session only when its opaque session belongs to this agent."""
        deployment_id, agent_id, session_id = (
            _text(deployment_id, "deploymentId"),
            _text(agent_id, "agentId"),
            _text(session_id, "sessionId"),
        )
        with self._lock:
            agent = self._agent(deployment_id, agent_id)
            self._assert_identity_scope(identity, agent["organizationId"], agent["projectId"])
            self._assert_agent_identity(identity, agent_id)
            row = self._connection.execute(
                "SELECT session_id,expires_at FROM agent_sessions "
                "WHERE deployment_id=? AND agent_id=?"
                " AND session_id=? AND expires_at>?",
                (deployment_id, agent_id, session_id, self._now()),
            ).fetchone()
            if row is None or not hmac.compare_digest(row["session_id"], session_id):
                raise FleetAuthorizationError("agent session is invalid or expired")
            now = float(self._now())
            expires = now + self.heartbeat_ttl_seconds
            self._connection.execute(
                "UPDATE agents SET status='connected',last_heartbeat=?,expires_at=? "
                "WHERE deployment_id=? AND id=?",
                (now, expires, deployment_id, agent_id),
            )
            self._connection.execute(
                "UPDATE agent_sessions SET expires_at=? WHERE deployment_id=? "
                "AND agent_id=? AND session_id=?",
                (expires, deployment_id, agent_id, session_id),
            )
            self._connection.commit()
            result = self._agent(deployment_id, agent_id)
        self._audit("fleet_agent_heartbeat", identity.subject, result, identity.organization_id)
        return result

    def disconnect(
        self, identity: FleetIdentity, deployment_id: str, agent_id: str, session_id: str
    ) -> dict[str, Any]:
        """Mark an agent offline after validating its current opaque session."""
        self.heartbeat(identity, deployment_id, agent_id, session_id)
        with self._lock:
            self._connection.execute(
                "UPDATE agents SET status='offline' WHERE deployment_id=? AND id=?",
                (deployment_id, agent_id),
            )
            self._connection.commit()
            result = self._agent(deployment_id, agent_id)
        self._audit("fleet_agent_disconnected", identity.subject, result, identity.organization_id)
        return result

    def _migrate(self) -> None:
        """Apply idempotent schema migrations before the store serves traffic."""
        with self._lock:
            self._connection.executescript(
                """
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS organizations(
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS projects(
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
                    name TEXT NOT NULL, created_at REAL NOT NULL,
                    UNIQUE(organization_id,name));
                CREATE TABLE IF NOT EXISTS deployments(
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
                    project_id TEXT NOT NULL REFERENCES projects(id), name TEXT NOT NULL,
                    environment TEXT NOT NULL, region TEXT NOT NULL, sdk_version TEXT,
                    team TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL, UNIQUE(project_id,name));
                CREATE TABLE IF NOT EXISTS agents(
                    id TEXT NOT NULL, organization_id TEXT NOT NULL REFERENCES organizations(id),
                    project_id TEXT NOT NULL REFERENCES projects(id), deployment_id TEXT NOT NULL
                    REFERENCES deployments(id), host TEXT NOT NULL, project_root TEXT NOT NULL,
                    environment TEXT NOT NULL, region TEXT NOT NULL, status TEXT NOT NULL,
                    last_heartbeat REAL NOT NULL, expires_at REAL NOT NULL, metadata TEXT NOT NULL,
                    PRIMARY KEY(deployment_id,id));
                CREATE TABLE IF NOT EXISTS agent_sessions(
                    agent_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
                    session_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL, expires_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS templates(
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
                    name TEXT NOT NULL, parent_id TEXT REFERENCES templates(id),
                    configuration TEXT NOT NULL, version INTEGER NOT NULL, created_at REAL NOT NULL,
                    UNIQUE(organization_id,name));
                CREATE TABLE IF NOT EXISTS deployment_configs(
                    deployment_id TEXT PRIMARY KEY REFERENCES deployments(id),
                    template_id TEXT NOT NULL REFERENCES templates(id),
                    desired_configuration TEXT NOT NULL, desired_hash TEXT NOT NULL,
                    applied_hash TEXT, rollout_state TEXT NOT NULL,
                    rollout_percentage INTEGER NOT NULL, version INTEGER NOT NULL,
                    updated_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS deployment_controls(
                    deployment_id TEXT PRIMARY KEY REFERENCES deployments(id),
                    emergency_stop INTEGER NOT NULL, updated_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS deployment_config_history(
                    deployment_id TEXT NOT NULL REFERENCES deployments(id),
                    version INTEGER NOT NULL, template_id TEXT NOT NULL,
                    desired_configuration TEXT NOT NULL, desired_hash TEXT NOT NULL,
                    applied_hash TEXT, rollout_state TEXT NOT NULL,
                    rollout_percentage INTEGER NOT NULL, created_at REAL NOT NULL,
                    PRIMARY KEY(deployment_id,version));
                CREATE TABLE IF NOT EXISTS fleet_alert_acknowledgements(
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    alert_id TEXT NOT NULL, subject TEXT NOT NULL,
                    acknowledged_at REAL NOT NULL,
                    PRIMARY KEY(organization_id,alert_id));
                CREATE TABLE IF NOT EXISTS fleet_health_samples(
                    deployment_id TEXT NOT NULL REFERENCES deployments(id),
                    observed_at REAL NOT NULL, status TEXT NOT NULL,
                    connected_agents INTEGER NOT NULL, offline_agents INTEGER NOT NULL,
                    drifted INTEGER NOT NULL, emergency_stop INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_fleet_health_samples_window
                    ON fleet_health_samples(deployment_id,observed_at);
                CREATE TABLE IF NOT EXISTS fleet_audit_evidence(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    event_type TEXT NOT NULL, actor TEXT NOT NULL,
                    deployment_id TEXT, payload_hash TEXT NOT NULL,
                    occurred_at REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_fleet_audit_evidence_org
                    ON fleet_audit_evidence(organization_id,occurred_at);
                INSERT OR IGNORE INTO schema_migrations(version) VALUES(1);
                """
            )
            deployment_columns = {
                row["name"] for row in self._connection.execute("PRAGMA table_info(deployments)")
            }
            if "team" not in deployment_columns:
                self._connection.execute(
                    "ALTER TABLE deployments ADD COLUMN team TEXT NOT NULL DEFAULT ''"
                )
            self._connection.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES(2)")
            self._connection.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES(3)")
            self._connection.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES(4)")
            self._connection.commit()

    @staticmethod
    def _configuration_json(configuration: Mapping[str, Any]) -> str:
        """Validate a bounded configuration and reject secret-bearing fields."""
        secret_names = {
            "token",
            "secret",
            "password",
            "privatekey",
            "private_key",
            "clientsecret",
            "access_token",
            "refresh_token",
            "authorization",
        }

        def visit(value: Any, depth: int = 0) -> Any:
            if depth > 8:
                raise FleetConfigurationError("configuration nesting is too deep")
            if isinstance(value, Mapping):
                result: dict[str, Any] = {}
                for key, item in value.items():
                    key_text = _text(key, "configuration key")
                    if key_text.lower().replace("-", "_") in secret_names:
                        raise FleetConfigurationError("configuration must not contain secrets")
                    result[key_text] = visit(item, depth + 1)
                return result
            if isinstance(value, list):
                if len(value) > 10_000:
                    raise FleetConfigurationError("configuration list is too large")
                return [visit(item, depth + 1) for item in value]
            if value is None or isinstance(value, (str, int, float, bool)):
                return value
            raise FleetConfigurationError("configuration contains unsupported data")

        normalized = visit(validate_fleet_configuration(configuration))
        if not isinstance(normalized, dict):
            raise FleetConfigurationError("configuration must be an object")
        serialized = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        if len(serialized) > 1_000_000:
            raise FleetConfigurationError("configuration is too large")
        return serialized

    @staticmethod
    def _configuration_hash(configuration: Mapping[str, Any]) -> str:
        """Create a stable content hash for desired/applied drift comparison."""
        serialized = json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(serialized).hexdigest()

    def _template(self, template_id: str) -> dict[str, Any]:
        """Load a template without exposing raw bearer or credential material."""
        row = self._connection.execute(
            "SELECT id,organization_id,name,parent_id,configuration,version,created_at "
            "FROM templates WHERE id=?",
            (template_id,),
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("template not found")
        return {
            "id": row["id"],
            "organizationId": row["organization_id"],
            "name": row["name"],
            "parentId": row["parent_id"],
            "configuration": json.loads(row["configuration"]),
            "version": row["version"],
            "createdAt": row["created_at"],
        }

    def _effective_template(self, template_id: str) -> dict[str, Any]:
        """Resolve bounded parent inheritance and merge child values over parents."""
        chain: list[dict[str, Any]] = []
        current = template_id
        while current:
            if len(chain) >= 8 or current in {item["id"] for item in chain}:
                raise FleetConfigurationError("template inheritance is cyclic or too deep")
            template = self._template(current)
            chain.append(template)
            current = template["parentId"]
        configuration: dict[str, Any] = {}
        for template in reversed(chain):
            configuration = self._merge_configuration(configuration, template["configuration"])
        result = self._template(template_id)
        result["configuration"] = configuration
        return result

    @staticmethod
    def _merge_configuration(base: Mapping[str, Any], child: Mapping[str, Any]) -> dict[str, Any]:
        """Deep-merge JSON objects while treating lists as explicit replacements."""
        merged = dict(base)
        for key, value in child.items():
            if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
                merged[key] = EnterpriseFleetStore._merge_configuration(merged[key], value)
            else:
                merged[key] = value
        return merged

    def _assert_no_template_cycle(self, parent_id: str, child_id: str) -> None:
        """Reject a new parent link that would create a cycle."""
        current = parent_id
        for _ in range(8):
            if current == child_id:
                raise FleetConfigurationError("template inheritance is cyclic")
            parent = self._template(current)
            current = parent["parentId"]
            if current is None:
                return
        raise FleetConfigurationError("template inheritance is too deep")

    def _deployment_configuration(self, deployment_id: str) -> dict[str, Any]:
        """Return desired/applied rollout state for one deployment."""
        row = self._connection.execute(
            "SELECT deployment_id,template_id,desired_configuration,desired_hash,applied_hash,"
            "rollout_state,rollout_percentage,version,updated_at FROM deployment_configs "
            "WHERE deployment_id=?",
            (deployment_id,),
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("deployment configuration not found")
        return {
            "deploymentId": row["deployment_id"],
            "templateId": row["template_id"],
            "desiredConfiguration": json.loads(row["desired_configuration"]),
            "desiredHash": row["desired_hash"],
            "appliedHash": row["applied_hash"],
            "drifted": row["applied_hash"] != row["desired_hash"],
            "rolloutState": row["rollout_state"],
            "rolloutPercentage": row["rollout_percentage"],
            "version": row["version"],
            "updatedAt": row["updated_at"],
        }

    def _require_configuration(self, deployment_id: str) -> dict[str, Any]:
        """Load deployment configuration or fail without silently creating state."""
        return self._deployment_configuration(deployment_id)

    def _deployment_health(self, deployment_id: str) -> dict[str, Any]:
        """Compute one deployment's health without exposing session credentials."""
        deployment = self._deployment(deployment_id)
        self._expire_agents()
        counts = self._connection.execute(
            "SELECT status,COUNT(*) AS count FROM agents WHERE deployment_id=? GROUP BY status",
            (deployment_id,),
        ).fetchall()
        by_status = {row["status"]: int(row["count"]) for row in counts}
        control = self._connection.execute(
            "SELECT emergency_stop FROM deployment_controls WHERE deployment_id=?",
            (deployment_id,),
        ).fetchone()
        configuration = self._connection.execute(
            "SELECT desired_hash,applied_hash,rollout_state,rollout_percentage "
            "FROM deployment_configs WHERE deployment_id=?",
            (deployment_id,),
        ).fetchone()
        emergency_stop = bool(control and control["emergency_stop"])
        drifted = bool(
            configuration and configuration["desired_hash"] != configuration["applied_hash"]
        )
        status = (
            "critical"
            if emergency_stop
            else "attention"
            if drifted or by_status.get("offline", 0)
            else "healthy"
        )
        return {
            "deploymentId": deployment_id,
            "projectId": deployment["projectId"],
            "team": deployment["team"],
            "environment": deployment["environment"],
            "region": deployment["region"],
            "status": status,
            "emergencyStop": emergency_stop,
            "connectedAgents": by_status.get("connected", 0),
            "offlineAgents": by_status.get("offline", 0),
            "drifted": drifted,
            "rolloutState": configuration["rollout_state"] if configuration else "unmanaged",
            "rolloutPercentage": configuration["rollout_percentage"] if configuration else 0,
        }

    @staticmethod
    def _assert_identity_org(identity: FleetIdentity, organization_id: str) -> None:
        """Require an identity to operate only in its authenticated organization."""
        if identity.organization_id != organization_id:
            raise FleetAuthorizationError("organization scope is not permitted")

    def _require_org(self, organization_id: str) -> None:
        """Require an organization without revealing cross-tenant details."""
        row = self._connection.execute(
            "SELECT 1 FROM organizations WHERE id=?", (organization_id,)
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("organization not found")

    def _require_project(self, organization_id: str, project_id: str) -> None:
        """Require a project under the supplied organization."""
        row = self._connection.execute(
            "SELECT 1 FROM projects WHERE id=? AND organization_id=?", (project_id, organization_id)
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("project not found")

    def _deployment(self, deployment_id: str) -> dict[str, Any]:
        """Return a normalized deployment or a generic not-found error."""
        row = self._connection.execute(
            "SELECT id,organization_id,project_id,name,environment,region,sdk_version,team,"
            "created_at"
            " FROM deployments WHERE id=?",
            (deployment_id,),
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("deployment not found")
        return {
            "id": row["id"],
            "organizationId": row["organization_id"],
            "projectId": row["project_id"],
            "name": row["name"],
            "environment": row["environment"],
            "region": row["region"],
            "sdkVersion": row["sdk_version"],
            "team": row["team"],
            "createdAt": row["created_at"],
        }

    def _agent(self, deployment_id: str, agent_id: str) -> dict[str, Any]:
        """Return a non-secret agent snapshot without session credentials."""
        row = self._connection.execute(
            "SELECT id,organization_id,project_id,deployment_id,host,project_root,"
            "environment,region,"
            "status,last_heartbeat,expires_at FROM agents WHERE deployment_id=? AND id=?",
            (deployment_id, agent_id),
        ).fetchone()
        if row is None:
            raise FleetNotFoundError("agent not found")
        return {
            "id": row["id"],
            "organizationId": row["organization_id"],
            "projectId": row["project_id"],
            "deploymentId": row["deployment_id"],
            "host": row["host"],
            "projectRoot": row["project_root"],
            "environment": row["environment"],
            "region": row["region"],
            "status": row["status"],
            "lastHeartbeat": row["last_heartbeat"],
            "expiresAt": row["expires_at"],
        }

    def _expire_agents(self) -> None:
        """Make heartbeat expiry visible before any inventory read."""
        self._connection.execute(
            "UPDATE agents SET status='offline' WHERE status='connected' AND expires_at<=?",
            (self._now(),),
        )
        self._connection.commit()

    @staticmethod
    def _assert_identity_scope(
        identity: FleetIdentity, organization_id: str, project_id: str
    ) -> None:
        """Enforce organization and optional project scope on every object access."""
        if identity.organization_id != organization_id:
            raise FleetAuthorizationError("organization scope is not permitted")
        if (
            identity.project_ids
            and project_id not in identity.project_ids
            and "admin" not in identity.roles
        ):
            raise FleetAuthorizationError("project scope is not permitted")

    @staticmethod
    def _assert_agent_identity(identity: FleetIdentity, agent_id: str) -> None:
        """Prevent an agent bearer from registering or controlling another agent ID."""
        if (
            "agent" in identity.roles
            and "admin" not in identity.roles
            and identity.subject != agent_id
        ):
            raise FleetAuthorizationError("agent identity does not match the authenticated subject")

    def _audit(
        self,
        event_type: str,
        actor: str,
        payload: Mapping[str, Any],
        organization_id: str | None = None,
    ) -> None:
        """Write only redaction-safe lifecycle metadata when an audit sink exists."""
        organization_id = organization_id or payload.get("organizationId")
        if isinstance(organization_id, str):
            with self._lock:
                self._connection.execute(
                    "INSERT INTO fleet_audit_evidence(organization_id,event_type,actor,"
                    "deployment_id,payload_hash,occurred_at) VALUES(?,?,?,?,?,?)",
                    (
                        organization_id,
                        event_type,
                        actor,
                        payload.get("deploymentId"),
                        self._configuration_hash(payload),
                        self._now(),
                    ),
                )
                self._connection.commit()
        if self.audit is not None:
            self.audit.append(
                event_type, f"fleet-{secrets.token_hex(8)}", {"actor": actor, **dict(payload)}
            )


class EnterpriseFleetApplication:
    """Authenticated WSGI API for enterprise fleet inventory and agent presence."""

    def __init__(
        self,
        store: EnterpriseFleetStore,
        *,
        authenticator: FleetAuthenticator,
        allowed_origin: str | None = None,
    ) -> None:
        """Bind a fleet store to an external authenticator and browser origin."""
        self.store = store
        self.authenticator = authenticator
        self.allowed_origin = allowed_origin
        # Startup is fail-closed: persisted state must reach live authorities
        # before this WSGI application can accept an authenticated request.
        self.store.reconcile_authorities()

    def __call__(self, environ: Mapping[str, Any], start_response: Any) -> list[bytes]:
        """Handle one bounded JSON request and return a JSON response."""
        method = str(environ.get("REQUEST_METHOD", "GET"))
        path = str(environ.get("PATH_INFO", "/"))
        # Browser preflight carries no bearer token. It is only a transport
        # negotiation; the actual request below still authenticates and
        # authorizes against the live identity and route.
        if method == "OPTIONS":
            return self._respond(start_response, 204, {}, preflight=True)
        identity = self.authenticator.authenticate(environ.get("HTTP_AUTHORIZATION"))
        if identity is None:
            return self._respond(start_response, 401, {"error": "authentication required"})
        try:
            inventory_prefix = "/api/enterprise/"
            if method == "GET" and path.startswith(inventory_prefix):
                resource = path[len(inventory_prefix) :]
                if resource in {"health", "slo", "alerts"}:
                    self._authorize(identity, "read")
                    page = (
                        self.store.health(identity)
                        if resource == "health"
                        else self.store.slo(identity)
                        if resource == "slo"
                        else self.store.alerts(identity)
                    )
                    return self._respond(
                        start_response,
                        200,
                        {"items": list(page.items), "nextCursor": page.next_cursor},
                    )
                if resource == "compliance/evidence":
                    self._authorize(identity, "read")
                    return self._respond(
                        start_response, 200, self.store.compliance_evidence(identity)
                    )
                if resource == "drift":
                    self._authorize(identity, "read")
                    page = self.store.list_drift(identity)
                    return self._respond(
                        start_response,
                        200,
                        {"items": list(page.items), "nextCursor": page.next_cursor},
                    )
                if resource in {"templates", "deployment-config", "deployment-config/history"}:
                    self._authorize(identity, "read")
                    query = parse_qs(str(environ.get("QUERY_STRING", "")))
                    requested_deployment = query.get("deploymentId", [None])[0]
                    page = (
                        self.store.list_templates(identity)
                        if resource == "templates"
                        else self.store.list_configuration_history(identity, requested_deployment)
                        if resource == "deployment-config/history"
                        else self.store.list_configurations(identity, requested_deployment)
                    )
                    return self._respond(
                        start_response,
                        200,
                        {"items": list(page.items), "nextCursor": page.next_cursor},
                    )
                if resource in {"organizations", "projects", "deployments", "agents", "sessions"}:
                    self._authorize(identity, "read")
                    query = parse_qs(str(environ.get("QUERY_STRING", "")))
                    requested_org = query.get("organizationId", [None])[0]
                    page = self.store.list_inventory(
                        identity, resource, organization_id=requested_org
                    )
                    return self._respond(
                        start_response,
                        200,
                        {"items": list(page.items), "nextCursor": page.next_cursor},
                    )
            body = self._body(environ)
            if method == "POST" and path == "/api/enterprise/slo/sample":
                self._authorize(identity, "manage_inventory")
                deployment_id = _text(body.get("deploymentId"), "deploymentId")
                return self._respond(
                    start_response, 201, self.store.record_slo_sample(identity, deployment_id)
                )
            if method == "POST" and path == "/api/enterprise/templates/validate":
                self._authorize(identity, "manage_configuration")
                configuration = body.get("configuration")
                if not isinstance(configuration, Mapping):
                    raise FleetConfigurationError("configuration must be an object")
                return self._respond(
                    start_response,
                    200,
                    self.store.validate_template_configuration(identity, configuration),
                )
            if (
                method == "POST"
                and path.startswith("/api/enterprise/alerts/")
                and path.endswith("/ack")
            ):
                self._authorize(identity, "manage_alerts")
                alert_id = path[len("/api/enterprise/alerts/") : -len("/ack")].strip("/")
                return self._respond(
                    start_response, 200, self.store.acknowledge_alert(identity, alert_id)
                )
            if method == "POST" and path == "/api/enterprise/alerts/dispatch":
                self._authorize(identity, "dispatch_alerts")
                page = self.store.dispatch_alerts(identity)
                return self._respond(
                    start_response,
                    200,
                    {"items": list(page.items), "nextCursor": page.next_cursor},
                )
            if method == "POST" and path == "/api/enterprise/organizations":
                self._authorize(identity, "manage_inventory")
                organization_id = _text(body.get("organizationId"), "organizationId")
                if organization_id != identity.organization_id:
                    raise FleetAuthorizationError("organization scope is not permitted")
                result = self.store.create_organization(
                    organization_id, _text(body.get("name"), "name")
                )
                return self._respond(start_response, 201, result)
            if method == "POST" and path == "/api/enterprise/projects":
                self._authorize(identity, "manage_inventory")
                organization_id = _text(body.get("organizationId"), "organizationId")
                project_id = _text(body.get("projectId"), "projectId")
                self.store._assert_identity_scope(identity, organization_id, project_id)
                result = self.store.create_project(
                    organization_id, project_id, _text(body.get("name"), "name")
                )
                return self._respond(start_response, 201, result)
            if method == "POST" and path == "/api/enterprise/deployments":
                self._authorize(identity, "manage_inventory")
                organization_id = _text(body.get("organizationId"), "organizationId")
                project_id = _text(body.get("projectId"), "projectId")
                self.store._assert_identity_scope(identity, organization_id, project_id)
                result = self.store.create_deployment(
                    organization_id,
                    project_id,
                    _text(body.get("deploymentId"), "deploymentId"),
                    _text(body.get("name"), "name"),
                    environment=_text(body.get("environment"), "environment"),
                    region=_text(body.get("region"), "region"),
                    sdk_version=_optional_text(body.get("sdkVersion"), "sdkVersion"),
                    team=_optional_text(body.get("team"), "team"),
                )
                return self._respond(start_response, 201, result)
            if method == "POST" and path == "/api/enterprise/agents/register":
                self._authorize_any(identity, {"manage_inventory", "agent_presence"})
                result = self.store.register_agent(
                    identity,
                    deployment_id=_text(body.get("deploymentId"), "deploymentId"),
                    agent_id=_text(body.get("agentId"), "agentId"),
                    host=_text(body.get("host"), "host"),
                    project_root=_text(body.get("projectRoot"), "projectRoot"),
                    metadata=(
                        body.get("metadata") if isinstance(body.get("metadata"), Mapping) else None
                    ),
                )
                return self._respond(start_response, 201, result)
            if method == "POST" and path == "/api/enterprise/templates":
                self._authorize(identity, "manage_configuration")
                configuration = body.get("configuration")
                if not isinstance(configuration, Mapping):
                    raise FleetConfigurationError("configuration must be an object")
                result = self.store.create_template(
                    identity,
                    template_id=_text(body.get("templateId"), "templateId"),
                    name=_text(body.get("name"), "name"),
                    configuration=configuration,
                    parent_template_id=_optional_text(
                        body.get("parentTemplateId"), "parentTemplateId"
                    ),
                )
                return self._respond(start_response, 201, result)
            if method == "POST" and path == "/api/enterprise/deployment-config":
                self._authorize(identity, "manage_configuration")
                result = self.store.assign_template(
                    identity,
                    _text(body.get("deploymentId"), "deploymentId"),
                    _text(body.get("templateId"), "templateId"),
                )
                return self._respond(start_response, 200, result)
            if method == "POST" and path == "/api/enterprise/deployment-config/rollout":
                self._authorize(identity, "manage_configuration")
                percentage = body.get("percentage")
                if not isinstance(percentage, int) or isinstance(percentage, bool):
                    raise FleetConfigurationError("percentage must be an integer")
                result = self.store.set_rollout(
                    identity,
                    _text(body.get("deploymentId"), "deploymentId"),
                    state=_text(body.get("state"), "state"),
                    percentage=percentage,
                )
                return self._respond(start_response, 200, result)
            if method == "POST" and path == "/api/enterprise/deployment-config/batch-rollout":
                self._authorize(identity, "manage_configuration")
                deployment_ids = body.get("deploymentIds")
                if not isinstance(deployment_ids, list):
                    raise FleetConfigurationError("deploymentIds must be a list")
                percentage = body.get("percentage")
                if not isinstance(percentage, int) or isinstance(percentage, bool):
                    raise FleetConfigurationError("percentage must be an integer")
                batch_result = self.store.rollout_deployments(
                    identity,
                    deployment_ids,
                    state=_text(body.get("state"), "state"),
                    percentage=percentage,
                )
                return self._respond(
                    start_response,
                    200,
                    {"items": list(batch_result.items), "nextCursor": batch_result.next_cursor},
                )
            if method == "POST" and path == "/api/enterprise/deployment-config/rollback":
                self._authorize(identity, "manage_configuration")
                version = body.get("version")
                if not isinstance(version, int) or isinstance(version, bool):
                    raise FleetConfigurationError("version must be an integer")
                result = self.store.rollback_deployment(
                    identity,
                    _text(body.get("deploymentId"), "deploymentId"),
                    version,
                )
                return self._respond(start_response, 200, result)
            if method == "POST" and path == "/api/enterprise/deployment-config/applied":
                self._authorize_any(identity, {"manage_configuration", "agent_presence"})
                result = self.store.record_applied_configuration(
                    identity,
                    _text(body.get("deploymentId"), "deploymentId"),
                    _text(body.get("configurationHash"), "configurationHash"),
                )
                return self._respond(start_response, 200, result)
            if method == "POST" and path == "/api/enterprise/emergency-stop":
                self._authorize(identity, "emergency_stop")
                active = body.get("active")
                if not isinstance(active, bool):
                    raise FleetConfigurationError("active must be boolean")
                result = self.store.set_emergency_stop(
                    identity,
                    _text(body.get("deploymentId"), "deploymentId"),
                    active=active,
                )
                return self._respond(start_response, 200, result)
            prefix = "/api/enterprise/agents/"
            if method == "POST" and path.startswith(prefix) and path.endswith("/heartbeat"):
                self._authorize_any(identity, {"manage_inventory", "agent_presence"})
                deployment_id, agent_id = self._agent_route(path, prefix, "/heartbeat")
                result = self.store.heartbeat(
                    identity,
                    deployment_id,
                    agent_id,
                    _text(body.get("sessionId"), "sessionId"),
                )
                return self._respond(start_response, 200, result)
            if method == "POST" and path.startswith(prefix) and path.endswith("/disconnect"):
                self._authorize_any(identity, {"manage_inventory", "agent_presence"})
                deployment_id, agent_id = self._agent_route(path, prefix, "/disconnect")
                result = self.store.disconnect(
                    identity,
                    deployment_id,
                    agent_id,
                    _text(body.get("sessionId"), "sessionId"),
                )
                return self._respond(start_response, 200, result)
            return self._respond(start_response, 404, {"error": "not found"})
        except FleetAuthorizationError as exc:
            return self._respond(start_response, 403, {"error": str(exc)})
        except FleetNotFoundError as exc:
            return self._respond(start_response, 404, {"error": str(exc)})
        except (FleetConfigurationError, TypeError, ValueError) as exc:
            return self._respond(start_response, 400, {"error": str(exc)})
        except sqlite3.IntegrityError:
            return self._respond(start_response, 409, {"error": "fleet resource already exists"})

    def _authorize(self, identity: FleetIdentity, action: str) -> None:
        """Require the injected authenticator to approve an operation."""
        if not self.authenticator.authorize(identity, action):
            raise FleetAuthorizationError("forbidden")

    def _authorize_any(self, identity: FleetIdentity, actions: set[str]) -> None:
        """Permit one of several explicit role actions without broadening scope."""
        if not any(self.authenticator.authorize(identity, action) for action in actions):
            raise FleetAuthorizationError("forbidden")

    @staticmethod
    def _body(environ: Mapping[str, Any]) -> dict[str, Any]:
        """Decode one bounded JSON object without accepting arbitrary request data."""
        length = int(str(environ.get("CONTENT_LENGTH", "0") or "0"))
        if length < 0 or length > 1_000_000:
            raise FleetConfigurationError("request body is too large")
        stream = environ.get("wsgi.input")
        raw = stream.read(length) if stream is not None else b""
        value = json.loads(raw or b"{}")
        if not isinstance(value, dict):
            raise FleetConfigurationError("request body must be an object")
        return value

    @staticmethod
    def _agent_route(path: str, prefix: str, suffix: str) -> tuple[str, str]:
        """Parse ``deployment/agent/action`` without trusting body identity fields."""
        parts = path[len(prefix) : -len(suffix)].strip("/").split("/")
        if len(parts) != 2:
            raise FleetConfigurationError("agent route must include deployment and agent")
        return _text(parts[0], "deploymentId"), _text(parts[1], "agentId")

    def _respond(
        self,
        start_response: Any,
        status_code: int,
        payload: Mapping[str, Any],
        *,
        preflight: bool = False,
    ) -> list[bytes]:
        """Return compact JSON with explicit browser-origin headers."""
        statuses = {
            204: "No Content",
            200: "OK",
            201: "Created",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            409: "Conflict",
        }
        body = json.dumps(dict(payload), separators=(",", ":")).encode("utf-8")
        headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
        if self.allowed_origin is not None:
            headers.extend(
                [("Access-Control-Allow-Origin", self.allowed_origin), ("Vary", "Origin")]
            )
            if preflight:
                headers.extend(
                    [
                        ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
                        ("Access-Control-Allow-Headers", "Authorization, Content-Type"),
                    ]
                )
        start_response(f"{status_code} {statuses[status_code]}", headers)
        return [body]


__all__ = [
    "EnterpriseFleetStore",
    "FleetAuthenticator",
    "FleetAuthorizationError",
    "FleetConfigurationError",
    "FleetDeploymentAuthority",
    "FleetAlertSink",
    "FleetIdentity",
    "FleetNotFoundError",
    "FleetPage",
    "StaticFleetAuthenticator",
    "EnterpriseFleetApplication",
]
