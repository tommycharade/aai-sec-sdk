"""Minimal AWS control-plane adapter used by the hosted enterprise UI.

The Lambda is deliberately small: DynamoDB owns tenant-scoped desired state,
while S3 receives redacted lifecycle evidence. No request body is trusted for
tenant identity; the tenant is derived from the verified Cognito claims.
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import boto3
from boto3.dynamodb.conditions import Key
from policy_composition import PolicyComponent, PolicyCompositionError, compose_policy
from policy_signing import bundle_from_record, sign_policy_bundle, verify_policy_bundle
from policy_sources import (
    PolicySourceDocument,
    PolicySourceRequest,
    PolicySourceVerificationError,
    VerifiedPolicySource,
)
from regional_fault_target import run as run_regional_fault_target_probe

CONTROL_TABLE_NAME = os.environ["CONTROL_TABLE"]
TABLE = boto3.resource("dynamodb").Table(CONTROL_TABLE_NAME)
PRESENCE = boto3.resource("dynamodb").Table(os.environ["PRESENCE_TABLE"])
IDEMPOTENCY = boto3.resource("dynamodb").Table(os.environ["IDEMPOTENCY_TABLE"])
SCIM_TABLE_NAME = os.environ.get("SCIM_TABLE", "")
SCIM = boto3.resource("dynamodb").Table(SCIM_TABLE_NAME) if SCIM_TABLE_NAME else None
DYNAMODB = boto3.client("dynamodb")
S3 = boto3.client("s3")
SNS = boto3.client("sns")
SQS = boto3.client("sqs")
KMS = boto3.client("kms")
LAMBDA = boto3.client("lambda")
SECRETS_MANAGER = boto3.client("secretsmanager")
POLICY_SIGNING_KEY_ARN = os.environ.get("POLICY_SIGNING_KEY_ARN", "")
POLICY_SOURCE_VERIFIER_ARN = os.environ.get("POLICY_SOURCE_VERIFIER_ARN", "")

# Tenant list reads are deliberately finite. Callers that require complete
# security state fail closed once either bound is reached; they never authorize
# from a silently truncated result or let one request drain an unbounded table.
_LIST_PAGE_ITEM_LIMIT = 250
_MAX_LIST_PAGES = 8
_MAX_LIST_ITEMS = 2_000
_DECISION_WINDOW_LIMIT = 250
_DECISION_TIMELINE_INDEX = "DecisionTimeline"
_POLICY_SIMULATION_MAX_LOOKBACK_DAYS = 90
_ATTESTATION_MANIFEST_FIELDS = frozenset(
    {
        "schemaVersion",
        "sdkVersion",
        "sdkRevision",
        "sourceOriginDigest",
        "packageDigest",
        "gatewayDigest",
        "hookDigest",
        "host",
    }
)
_ATTESTATION_EVIDENCE_FIELDS = _ATTESTATION_MANIFEST_FIELDS | {
    "configurationDigest",
    "executableDigest",
    "launchContextDigest",
    "projectRootDigest",
    "observedAt",
    "nonce",
}
_ATTESTATION_APPROVAL_FIELDS = frozenset(
    {
        "hosts",
        "releaseEvidenceSha256",
        "releaseTag",
        "sdkRevision",
        "sdkVersion",
        "sourceOriginDigest",
    }
)

_AGENT_TELEMETRY_FIELDS = frozenset(
    {
        "actionsTotal",
        "actionsAdmitted",
        "allowed",
        "denied",
        "approvalRequired",
        "executed",
        "failed",
        "timedOut",
        "cancelled",
        "resultRejected",
        "runtimeErrors",
        "costUnits",
        "averageLatencyMs",
        "maxLatencyMs",
    }
)
_AGENT_TELEMETRY_INTEGER_FIELDS = _AGENT_TELEMETRY_FIELDS - {
    "averageLatencyMs",
    "maxLatencyMs",
}

# Presence and lifecycle are separate trust dimensions. Presence may move
# between connected and offline; lifecycle authority moves only forward from
# active to revoked to deleted and is checked on every authenticated request.
_AGENT_LIFECYCLE_STATES = frozenset({"active", "revoked", "deleted"})
_AGENT_REPLACEMENT_GROUP_LIMIT = 97

# Group membership selects runtime policy authority. Bulk changes are bounded
# so one browser request cannot create unbounded DynamoDB work or audit data.
_GROUP_MEMBERSHIP_BATCH_LIMIT = 100

# Dynamic group rules select policy authority from server-owned inventory. The
# first production-shaped contract deliberately supports a small conjunction
# over stable attributes; free-form expressions, regex and browser-supplied
# posture are excluded because they are difficult to bound and audit.
_DYNAMIC_GROUP_FIELDS = frozenset(
    {
        "criticality",
        "deploymentId",
        "environment",
        "host",
        "projectId",
        "region",
        "team",
    }
)
_DYNAMIC_GROUP_OPERATORS = frozenset({"equals_any", "not_equals_any"})
_DYNAMIC_GROUP_CONDITION_LIMIT = 7
_DYNAMIC_GROUP_VALUE_LIMIT = 20
_DYNAMIC_GROUP_MEMBER_LIMIT = 500
_DYNAMIC_GROUP_RECONCILIATION_LIMIT = 5_000
_DYNAMIC_GROUP_RECONCILIATION_ACTOR = "system:dynamic-group-reconciler"

# Ownership is operational authority metadata, not a browser label. New
# identities must carry a reviewed accountable owner and all reviews expire on
# a fixed bounded cadence so abandoned agents cannot remain silently trusted.
_AGENT_CRITICALITIES = frozenset({"low", "medium", "high", "critical"})
_AGENT_OWNERSHIP_REVIEW_SECONDS = 90 * 24 * 60 * 60

# Discovery snapshots are trusted adapter observations, not agent authority.
# A complete, fresh snapshot may reduce coverage or identify an orphan, but it
# never grants policy, revokes identity, or executes containment by itself.
_DISCOVERY_SOURCE_KINDS = frozenset({"identity", "endpoint", "source_control"})
_DISCOVERY_REQUIRED_SOURCE_KINDS = _DISCOVERY_SOURCE_KINDS
_DISCOVERY_OBSERVATION_KINDS = {
    "identity": frozenset({"identity"}),
    "endpoint": frozenset({"device", "installation"}),
    "source_control": frozenset({"repository"}),
}
_DISCOVERY_SNAPSHOT_LIMIT = 100
_DISCOVERY_GENERATION_PAGE_LIMIT = 100
# The reconciler loads committed pages synchronously. Twenty pages cap one
# request at 2,000 observations and 20 strong reads, keeping Lambda work and
# response construction bounded until pages move to dedicated object storage.
_DISCOVERY_GENERATION_MAX_PAGES = 20
_DISCOVERY_EXPECTED_HOST_LIMIT = 2
_DISCOVERY_MAX_VALIDITY_SECONDS = 24 * 60 * 60
_MANAGED_DISCOVERY_INTERVALS = frozenset({5, 15, 30, 60, 180, 360, 720, 1440})
_MANAGED_DISCOVERY_PROVIDER_KINDS = {
    "entra": "identity",
    "intune": "endpoint",
    "github": "source_control",
}
_MANAGED_GITHUB_REPOSITORY_LIMIT = 500
_MANAGED_INTUNE_BUSINESS_UNIT_LIMIT = 500

# Endpoint sensors report often enough to detect a stopped process within the
# five-minute P0 attestation target while allowing bounded MDM scheduling
# jitter. Devices never submit this health state; the server derives it.
_ENDPOINT_EVIDENCE_MAX_AGE_SECONDS = 15 * 60
_ENDPOINT_EVIDENCE_FUTURE_SKEW_SECONDS = 5 * 60
_ENDPOINT_DETECTION_INDEX = "EndpointDetectionTenants"
_ENDPOINT_DETECTION_SHARDS = 16
_ENDPOINT_DETECTION_TENANT_LIMIT = 2_000
_WEBHOOK_OUTBOX_INDEX = "WebhookOutbox"
_EVIDENCE_ASSURANCE_INDEX = "EvidenceAssuranceTenants"
_EVIDENCE_ASSURANCE_SHARDS = 16
_CASE_STATUSES = frozenset({"open", "investigating", "contained", "resolved", "closed"})
_CASE_EXPORT_ROLES = frozenset(
    {"platform-admin", "security-operator", "incident-responder", "auditor"}
)
_CASE_EXPORT_RECORD_LIMIT = 500
_CASE_EXPORT_LOOKBACK_SECONDS = 24 * 60 * 60
_EVIDENCE_RETENTION_MIN_DAYS = 365
_EVIDENCE_RETENTION_MAX_DAYS = 3_650
_EVIDENCE_RECORD_LIMIT = 250
_EVIDENCE_ASYNC_PAGE_SIZE = 10
_EVIDENCE_ASYNC_MAX_PAGES = 100_000
_EVIDENCE_JOB_RETENTION_SECONDS = 30 * 24 * 60 * 60
_EVIDENCE_JOB_FRESHNESS_SECONDS = 6 * 60 * 60
_EVIDENCE_JOB_STALE_SECONDS = 30 * 60
_EVIDENCE_QUEUE_RECOVERY_SECONDS = 5 * 60
_EVIDENCE_INITIAL_CHAIN_HASH = "0" * 64
_EVIDENCE_RETENTION_CUTOVER_SECONDS = 65
_EVIDENCE_RETENTION_JOB_RETENTION_SECONDS = 90 * 24 * 60 * 60
_EVIDENCE_RETENTION_JOB_STALE_SECONDS = 30 * 60
_RESPONSE_RULE_VERSION_STATES = frozenset(
    {"draft", "review", "approved", "active", "superseded", "rejected"}
)
_RESPONSE_RULE_PENDING_STATES = frozenset({"draft", "review", "approved"})
_RESPONSE_RULE_PREVIEW_LIMIT = 100
_BEHAVIOR_SIGNAL_TYPES = frozenset(
    {
        "new_tool",
        "new_mcp_server",
        "denied_action_spike",
        "approval_request_spike",
        "decision_volume_spike",
    }
)
_BEHAVIOR_HISTORY_LIMIT = 2_000
_BEHAVIOR_ACTIVE_RULE_LIMIT = 100
_BEHAVIOR_EVENT_REASONS = _BEHAVIOR_SIGNAL_TYPES
_ENDPOINT_EVENT_REASONS = frozenset({"signature_invalid", "report_replayed"})
_ENDPOINT_ALERT_DEFINITIONS = {
    "credential_not_configured": (
        "medium",
        "endpoint_sensor_not_enrolled",
        "Managed device has no endpoint sensor credential.",
    ),
    "credential_revoked": (
        "high",
        "endpoint_sensor_credential_revoked",
        "Endpoint sensor credential is revoked.",
    ),
    "fresh_report_required_after_rotation": (
        "high",
        "endpoint_sensor_rotation_pending",
        "Endpoint sensor has not reported with its rotated credential.",
    ),
    "report_missing": (
        "medium",
        "endpoint_report_missing",
        "Managed device has not submitted endpoint evidence.",
    ),
    "report_stale": (
        "high",
        "endpoint_report_stale",
        "Endpoint evidence is outside the freshness objective.",
    ),
    "device_unmanaged": (
        "critical",
        "endpoint_device_unmanaged",
        "Endpoint inventory reports the device as unmanaged.",
    ),
    "inventory_stale": (
        "high",
        "endpoint_inventory_stale",
        "Endpoint management inventory is stale.",
    ),
    "installation_missing": (
        "high",
        "endpoint_installation_missing",
        "No governed Claude Code or Codex installation was observed.",
    ),
    "binary_missing": (
        "critical",
        "endpoint_binary_missing",
        "An expected Claude Code or Codex binary was not observed.",
    ),
    "process_not_observed": (
        "high",
        "endpoint_process_not_observed",
        "An expected Claude Code or Codex process was not observed.",
    ),
    "signature_invalid": (
        "critical",
        "endpoint_signature_invalid",
        "Endpoint evidence failed cryptographic signature validation.",
    ),
    "report_replayed": (
        "high",
        "endpoint_report_replayed",
        "Endpoint evidence was replayed or delivered out of order.",
    ),
}

# Agent decision evidence is operationally useful but never authoritative.
# The authenticated host may report only this fixed, content-free vocabulary;
# tenant, agent, deployment, policy and timestamps are derived server-side.
_DECISION_VALUES = frozenset({"allowed", "denied", "approval_required"})
_DECISION_SOURCES = frozenset({"claude_native", "codex_native", "mcp", "sdk_runtime"})
_DECISION_RESOURCE_KINDS = frozenset(
    {"project_file", "shell_command", "mcp_tool", "sdk_tool", "unknown"}
)
_DECISION_REASON_CODES = frozenset(
    {
        "explicit_allow",
        "deny_by_default",
        "blocked_command",
        "outside_project",
        "approval_rule",
        "invalid_configuration",
        "audit_failure",
        "policy_error",
    }
)
_DECISION_REASON_LABELS = {
    "explicit_allow": "Explicitly allowed by policy",
    "deny_by_default": "Not explicitly allowed",
    "blocked_command": "Blocked command rule matched",
    "outside_project": "Outside the approved project",
    "approval_rule": "Interactive approval required",
    "invalid_configuration": "Security configuration is invalid",
    "audit_failure": "Required audit persistence failed",
    "policy_error": "Policy evaluation failed closed",
}
_DECISION_RESOURCE_LABELS = {
    "project_file": "Project file",
    "shell_command": "Shell command",
    "mcp_tool": "MCP tool call",
    "sdk_tool": "SDK tool call",
    "unknown": "Content redacted",
}

_CANONICAL_OPERATOR_ROLES = frozenset(
    {
        "platform-admin",
        "security-operator",
        "policy-author",
        "policy-approver",
        "fleet-operator",
        "incident-responder",
        "auditor",
    }
)
_ROLE_CAPABILITIES = {
    "platform-admin": frozenset({"*"}),
    "security-operator": frozenset(
        {
            "approval_decision",
            "incident_response",
            "response_rule_approval",
            "response_rule_write",
            "evidence_admin",
            "evidence_read",
        }
    ),
    "policy-author": frozenset({"policy_write", "policy_simulation"}),
    "policy-approver": frozenset({"approval_decision", "policy_approval", "policy_simulation"}),
    "fleet-operator": frozenset({"fleet_write"}),
    "incident-responder": frozenset({"incident_response"}),
    "auditor": frozenset({"access_certification_read", "evidence_read"}),
}
_DELEGATABLE_OPERATOR_ROLES = frozenset(_CANONICAL_OPERATOR_ROLES - {"platform-admin"})
_DELEGATED_SCOPE_TYPES = frozenset({"organization", "project", "deployment"})
_DELEGATED_GRANT_MAX_SECONDS = 366 * 24 * 60 * 60
_BREAK_GLASS_CAPABILITIES = frozenset(
    {
        "approval_decision",
        "fleet_write",
        "identity_admin",
        "incident_response",
        "managed_deployment",
        "policy_approval",
        "policy_write",
        "runtime_admin",
    }
)
_BREAK_GLASS_MIN_SECONDS = 5 * 60
_BREAK_GLASS_MAX_SECONDS = 60 * 60
_BREAK_GLASS_REQUEST_SECONDS = 15 * 60
_STRONG_AUTH_MAX_AGE_SECONDS = 10 * 60
_WEBHOOK_EVENT_TYPES = frozenset(
    {
        "behavior.alert.opened",
        "endpoint.alert.opened",
        "endpoint.alert.reopened",
        "webhook.test",
    }
)
_WEBHOOK_DESTINATION_LIMIT = 20
_WEBHOOK_ROTATION_MIN_SECONDS = 60 * 60
_WEBHOOK_ROTATION_MAX_SECONDS = 7 * 24 * 60 * 60

# Machine identities are deliberately narrower than human roles. They can
# automate bounded operational work but can never approve their own policy,
# alter identity governance, invoke break glass, or perform incident response.
_SERVICE_IDENTITY_CAPABILITIES = frozenset(
    {
        "evidence_read",
        "fleet_write",
        "inventory_read",
        "policy_draft_write",
        "policy_simulation",
        "runtime_write",
    }
)
_SERVICE_IDENTITY_MAX_SECONDS = 90 * 24 * 60 * 60
_SERVICE_CAPABILITY_GRANTS = {
    "evidence_read": frozenset({"evidence_read"}),
    "fleet_write": frozenset({"fleet_write"}),
    "inventory_read": frozenset(),
    "policy_draft_write": frozenset({"policy_write"}),
    "policy_simulation": frozenset({"policy_simulation"}),
    # Runtime configuration currently shares some fleet mutation routes. The
    # versioned machine allowlist below keeps this grant on those exact paths.
    "runtime_write": frozenset({"fleet_write", "runtime_admin"}),
}
_POLICY_VERSION_STATES = frozenset(
    {"draft", "review", "approved", "staged", "active", "rejected", "retired"}
)
_POLICY_PENDING_STATES = frozenset({"draft", "review", "approved", "staged"})
_POLICY_EXCEPTION_OPEN_STATES = frozenset({"draft", "review", "approved", "active"})
_POLICY_EXCEPTION_TERMINAL_STATES = frozenset({"rejected", "revoked", "expired", "invalidated"})
_POLICY_EXCEPTION_MIN_SECONDS = 15 * 60
_POLICY_EXCEPTION_MAX_SECONDS = 7 * 24 * 60 * 60
_POLICY_SECRET_KEYS = frozenset(
    {
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
)


class PolicyConflict(RuntimeError):
    """Raised when governed policy state no longer matches a requested transition."""


def _runtime_manifests():
    """Return bounded deployment-owned artifact manifests or fail closed."""
    raw = os.environ.get("RUNTIME_ATTESTATION_MANIFESTS", "")
    encoded = raw.encode("utf-8")
    if raw:
        expected_digest = os.environ.get("RUNTIME_ATTESTATION_MANIFESTS_SHA256", "")
        if not expected_digest or not secrets.compare_digest(
            hashlib.sha256(encoded).hexdigest(), expected_digest
        ):
            raise RuntimeError("runtime attestation manifest environment integrity failed")
    else:
        manifest_file = Path(__file__).with_name("runtime-manifests.json")
        try:
            encoded = manifest_file.read_bytes()
        except OSError as error:
            raise RuntimeError("runtime attestation manifest bundle is unavailable") from error
        expected_digest = os.environ.get("RUNTIME_ATTESTATION_MANIFESTS_SHA256", "")
        if expected_digest and not secrets.compare_digest(
            hashlib.sha256(encoded).hexdigest(), expected_digest
        ):
            raise RuntimeError("runtime attestation manifest bundle integrity failed")
        try:
            raw = encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeError("runtime attestation manifest bundle is malformed") from error
    if not raw:
        return []
    if len(raw) > 65_536:
        raise RuntimeError("runtime attestation manifests exceed the safe bound")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("runtime attestation manifests are malformed") from error
    if not isinstance(value, list) or len(value) > 32:
        raise RuntimeError("runtime attestation manifests must contain at most 32 entries")
    seen = set()
    manifests = []
    for manifest in value:
        if not isinstance(manifest, dict) or set(manifest) != _ATTESTATION_MANIFEST_FIELDS:
            raise RuntimeError("runtime attestation manifest schema is invalid")
        if manifest.get("schemaVersion") != 1:
            raise RuntimeError("runtime attestation manifest version is unsupported")
        if manifest.get("host") not in {"claude-code", "codex-cli"}:
            raise RuntimeError("runtime attestation manifest host is unsupported")
        if (
            not isinstance(manifest.get("sdkVersion"), str)
            or not 1 <= len(manifest["sdkVersion"]) <= 64
        ):
            raise RuntimeError("runtime attestation manifest SDK version is invalid")
        if not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("sdkRevision", ""))):
            raise RuntimeError("runtime attestation manifest revision is invalid")
        for field in (
            "sourceOriginDigest",
            "packageDigest",
            "gatewayDigest",
            "hookDigest",
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get(field, ""))):
                raise RuntimeError("runtime attestation manifest digest is invalid")
        identity = (manifest["host"], manifest["sdkVersion"])
        if identity in seen:
            raise RuntimeError("runtime attestation manifest identity is ambiguous")
        seen.add(identity)
        manifests.append(manifest)
    _validate_runtime_manifest_approvals(encoded, manifests)
    return manifests


def _validate_runtime_manifest_approvals(manifest_bundle, manifests):
    """Require every approved host/version to bind verified release evidence."""
    raw = os.environ.get("RUNTIME_ATTESTATION_APPROVALS", "")
    encoded = raw.encode("utf-8")
    if raw:
        expected_digest = os.environ.get("RUNTIME_ATTESTATION_APPROVALS_SHA256", "")
        if not expected_digest or not secrets.compare_digest(
            hashlib.sha256(encoded).hexdigest(), expected_digest
        ):
            raise RuntimeError("runtime attestation approval environment integrity failed")
    else:
        approval_file = Path(__file__).with_name("runtime-manifests.provenance.json")
        try:
            encoded = approval_file.read_bytes()
        except OSError as error:
            raise RuntimeError("runtime attestation approvals are unavailable") from error
        expected_digest = os.environ.get("RUNTIME_ATTESTATION_APPROVALS_SHA256", "")
        if expected_digest and not secrets.compare_digest(
            hashlib.sha256(encoded).hexdigest(), expected_digest
        ):
            raise RuntimeError("runtime attestation approval bundle integrity failed")
        try:
            raw = encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeError("runtime attestation approvals are malformed") from error
    if len(raw) > 65_536:
        raise RuntimeError("runtime attestation approvals exceed the safe bound")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("runtime attestation approvals are malformed") from error
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "manifestBundleSha256",
        "approvals",
    }:
        raise RuntimeError("runtime attestation approval schema is invalid")
    if value.get("schemaVersion") != 1:
        raise RuntimeError("runtime attestation approval version is unsupported")
    expected_bundle_digest = value.get("manifestBundleSha256")
    if not isinstance(expected_bundle_digest, str) or not secrets.compare_digest(
        expected_bundle_digest, hashlib.sha256(manifest_bundle).hexdigest()
    ):
        raise RuntimeError("runtime attestation approval does not bind the manifest bundle")
    approvals = value.get("approvals")
    if not isinstance(approvals, list) or len(approvals) > 32:
        raise RuntimeError("runtime attestation approvals must contain at most 32 entries")
    approved = {}
    for approval in approvals:
        if not isinstance(approval, dict) or set(approval) != _ATTESTATION_APPROVAL_FIELDS:
            raise RuntimeError("runtime attestation approval entry schema is invalid")
        hosts = approval.get("hosts")
        if (
            not isinstance(hosts, list)
            or not hosts
            or len(hosts) != len(set(hosts))
            or any(host not in {"claude-code", "codex-cli"} for host in hosts)
        ):
            raise RuntimeError("runtime attestation approval hosts are invalid")
        if not re.fullmatch(
            r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", str(approval.get("releaseTag", ""))
        ):
            raise RuntimeError("runtime attestation approval release tag is invalid")
        if (
            not isinstance(approval.get("sdkVersion"), str)
            or not 1 <= len(approval["sdkVersion"]) <= 64
            or not re.fullmatch(r"[0-9a-f]{40}", str(approval.get("sdkRevision", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(approval.get("sourceOriginDigest", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(approval.get("releaseEvidenceSha256", "")))
        ):
            raise RuntimeError("runtime attestation approval identity is invalid")
        for host in hosts:
            identity = (host, approval["sdkVersion"])
            if identity in approved:
                raise RuntimeError("runtime attestation approval identity is ambiguous")
            approved[identity] = approval
    expected = {(manifest["host"], manifest["sdkVersion"]): manifest for manifest in manifests}
    if set(approved) != set(expected):
        raise RuntimeError("runtime attestation approvals do not cover the manifest bundle")
    for identity, manifest in expected.items():
        approval = approved[identity]
        if not secrets.compare_digest(manifest["sdkRevision"], approval["sdkRevision"]):
            raise RuntimeError("runtime attestation approval revision does not match manifest")
        if not secrets.compare_digest(
            manifest["sourceOriginDigest"], approval["sourceOriginDigest"]
        ):
            raise RuntimeError("runtime attestation approval origin does not match manifest")


def _runtime_manifest(tenant, deployment_id, host, manifests=None):
    """Select one immutable manifest from deployment version and host identity."""
    manifests = _runtime_manifests() if manifests is None else manifests
    if not manifests:
        return None
    deployment = TABLE.get_item(
        Key=_item_key(tenant, "DEPLOYMENT", deployment_id), ConsistentRead=True
    ).get("Item")
    if not deployment:
        raise PermissionError("runtime attestation deployment is unavailable")
    expected_version = deployment.get("sdk_version")
    matches = [
        manifest
        for manifest in manifests
        if manifest["host"] == host and manifest["sdkVersion"] == expected_version
    ]
    if len(matches) > 1:
        raise PermissionError("runtime attestation manifest is ambiguous")
    return matches[0] if matches else None


def _issue_attestation_challenge(tenant, session, token):
    """Issue one short-lived nonce bound to the exact authenticated session."""
    now = int(time.time())
    nonce = secrets.token_urlsafe(32)
    expires_at = now + 60
    TABLE.update_item(
        Key={"pk": _token_key("AGENT_SESSION", token), "sk": "SESSION"},
        UpdateExpression="SET attestation_nonce = :nonce, attestation_nonce_expires_at = :expires",
        ConditionExpression="attribute_exists(pk) AND expires_at > :now",
        ExpressionAttributeValues={":nonce": nonce, ":expires": expires_at, ":now": now},
    )
    manifests = _runtime_manifests()
    return {
        "nonce": nonce,
        "expiresAt": expires_at,
        # Once any approved bundle is installed, an unlisted host/version is a
        # trust failure rather than a development compatibility state.
        "required": bool(manifests),
    }


def _attestation_baseline(evidence):
    """Hash project-specific evidence fields without retaining local values."""
    selected = {
        key: evidence[key]
        for key in ("configurationDigest", "executableDigest", "launchContextDigest")
    }
    return hashlib.sha256(
        json.dumps(selected, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()


def _quarantine_attestation(tenant, agent, token, reasons):
    """Revoke the live session and retain only bounded reason-code evidence."""
    now = int(time.time())
    agent.update(
        {
            "status": "quarantined",
            "expires_at": 0,
            "attestation_status": "quarantined",
            "attestation_reason_codes": sorted(set(reasons))[:16],
            "attestation_observed_at": now,
            "attestation_expires_at": now,
        }
    )
    TABLE.put_item(Item=agent)
    TABLE.delete_item(Key={"pk": _token_key("AGENT_SESSION", token), "sk": "SESSION"})
    _audit(
        tenant,
        "runtime_attestation_quarantined",
        f"agent:{agent['deployment_id']}:{agent['id']}",
        {
            "deployment_id": agent["deployment_id"],
            "agent_id": agent["id"],
            "reason_codes": agent["attestation_reason_codes"],
        },
    )
    raise PermissionError(
        "runtime attestation failed: " + ",".join(agent["attestation_reason_codes"])
    )


def _validate_runtime_attestation(tenant, deployment_id, agent, session, token, value):
    """Consume one challenge and compare fresh evidence to manifest and baseline."""
    manifests = _runtime_manifests()
    manifest = _runtime_manifest(tenant, deployment_id, agent.get("host", ""), manifests)
    if manifest is None:
        if manifests:
            _quarantine_attestation(tenant, agent, token, ["approved_manifest_missing"])
        agent.update(
            {
                "attestation_status": "not_configured",
                "attestation_reason_codes": ["approved_manifest_missing"],
                "attestation_observed_at": int(time.time()),
                "attestation_expires_at": 0,
            }
        )
        return
    reasons = []
    now = int(time.time())
    if not isinstance(value, dict) or set(value) != _ATTESTATION_EVIDENCE_FIELDS:
        _quarantine_attestation(tenant, agent, token, ["evidence_schema_invalid"])
    if value.get("schemaVersion") != 1:
        reasons.append("schema_version_mismatch")
    observed_at = value.get("observedAt")
    if (
        isinstance(observed_at, bool)
        or not isinstance(observed_at, int)
        or abs(now - observed_at) > 90
    ):
        reasons.append("evidence_stale")
    nonce = value.get("nonce")
    expected_nonce = session.get("attestation_nonce")
    if (
        not isinstance(nonce, str)
        or not isinstance(expected_nonce, str)
        or int(session.get("attestation_nonce_expires_at", 0)) <= now
        or not secrets.compare_digest(nonce, expected_nonce)
    ):
        reasons.append("challenge_invalid")
    if value.get("projectRootDigest") != session.get("project_root_hash"):
        reasons.append("project_scope_mismatch")
    for field in _ATTESTATION_MANIFEST_FIELDS - {"schemaVersion"}:
        supplied = value.get(field)
        expected = manifest.get(field)
        if not isinstance(supplied, str) or not isinstance(expected, str):
            reasons.append(f"{field}_invalid")
        elif not secrets.compare_digest(supplied, expected):
            reasons.append(f"{field}_mismatch")
    for field in ("configurationDigest", "executableDigest", "launchContextDigest"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(value.get(field, ""))):
            reasons.append(f"{field}_invalid")
    if reasons:
        _quarantine_attestation(tenant, agent, token, reasons)
    baseline = _attestation_baseline(value)
    existing_baseline = agent.get("attestation_baseline_digest")
    if isinstance(existing_baseline, str) and not secrets.compare_digest(
        existing_baseline, baseline
    ):
        _quarantine_attestation(tenant, agent, token, ["enrollment_baseline_mismatch"])
    try:
        TABLE.update_item(
            Key={"pk": _token_key("AGENT_SESSION", token), "sk": "SESSION"},
            UpdateExpression="REMOVE attestation_nonce, attestation_nonce_expires_at",
            ConditionExpression=(
                "attestation_nonce = :nonce AND attestation_nonce_expires_at > :now"
            ),
            ExpressionAttributeValues={":nonce": nonce, ":now": now},
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            _quarantine_attestation(tenant, agent, token, ["challenge_replayed"])
        raise
    agent.update(
        {
            "attestation_status": "compliant",
            "attestation_reason_codes": [],
            "attestation_observed_at": observed_at,
            "attestation_expires_at": now + 300,
            "attestation_baseline_digest": existing_baseline or baseline,
            "attestation_sdk_version": value["sdkVersion"],
            "attestation_sdk_revision": value["sdkRevision"],
        }
    )
    _audit(
        tenant,
        "runtime_attestation_verified",
        f"agent:{deployment_id}:{agent['id']}",
        {
            "deployment_id": deployment_id,
            "agent_id": agent["id"],
            "sdk_version": value["sdkVersion"],
            "sdk_revision": value["sdkRevision"],
            "expires_at": now + 300,
        },
    )


def _require_current_attestation(tenant, deployment_id, agent):
    """Deny governed agent routes when configured attestation is not current."""
    manifests = _runtime_manifests()
    if not manifests:
        return
    manifest = _runtime_manifest(tenant, deployment_id, agent.get("host", ""), manifests)
    if manifest is None:
        raise PermissionError("runtime attestation has no approved host/version manifest")
    if agent.get("attestation_status") != "compliant" or int(
        agent.get("attestation_expires_at", 0)
    ) <= int(time.time()):
        raise PermissionError("runtime attestation is missing, expired, or non-compliant")


def _require_current_managed_configuration(tenant, agent):
    """Withhold governed routes when assigned host policy is not freshly proven."""
    posture = _managed_configuration_posture(tenant, agent)
    if posture.get("desired") is not None and posture.get("status") != "enforced":
        raise PermissionError("managed host configuration is not freshly enforced")


def _json_default(value):
    """Convert DynamoDB decimals without changing integer API contracts to floats."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    return str(value)


def _json(value):
    """Return JSON-safe data while preserving integral policy/version types."""
    return json.loads(json.dumps(value, default=_json_default))


def _response(status, body):
    return {
        "statusCode": status,
        "headers": {
            "content-type": "application/json",
            "cache-control": "no-store",
            "access-control-allow-origin": "*",
            "access-control-allow-methods": "*",
            "access-control-allow-headers": "authorization,content-type",
        },
        "body": json.dumps(_json(body)),
    }


def _method_path(event):
    """Return the normalized HTTP method and path from either API Gateway shape."""
    return (
        event.get("requestContext", {})
        .get("http", {})
        .get("method", event.get("httpMethod", "GET")),
        event.get("rawPath", event.get("path", "/")),
    )


def _bearer(event):
    """Extract a bearer value without trusting any request body identity."""
    headers = {str(k).lower(): v for k, v in (event.get("headers") or {}).items()}
    value = headers.get("authorization", "")
    return (
        value[7:].strip() if isinstance(value, str) and value.lower().startswith("bearer ") else ""
    )


def _token_key(prefix, token):
    """Hash a bootstrap or session token before using it as a DynamoDB key."""
    return f"{prefix}#{hashlib.sha256(token.encode()).hexdigest()}"


def _agent_lifecycle_state(agent):
    """Return a valid lifecycle state while treating legacy records as active.

    Legacy compatibility is intentionally one-way: a missing field means the
    pre-lifecycle active state, but an unknown or malformed field fails closed.
    Mutation paths migrate legacy records to an explicit revision before a
    transition so concurrent operators cannot overwrite each other.
    """
    state = agent.get("lifecycle_state", "active") if isinstance(agent, dict) else None
    return state if state in _AGENT_LIFECYCLE_STATES else "invalid"


def _agent_session_revision(value):
    """Normalize legacy session authority to revision one and reject corruption."""
    raw = value.get("session_revision", 1) if isinstance(value, dict) else None
    if isinstance(raw, bool) or not isinstance(raw, (int, Decimal)):
        return None
    if isinstance(raw, Decimal) and raw != raw.to_integral_value():
        return None
    revision = int(raw)
    return revision if revision > 0 else None


def _require_active_agent(agent):
    """Reject any missing, revoked, deleted or malformed agent authority."""
    if not agent:
        raise LookupError("agent not found")
    if _agent_lifecycle_state(agent) != "active":
        raise PolicyConflict("agent identity is revoked or offboarded")
    return agent


def _agent_session(event):
    """Resolve an unexpired, one-time-issued agent session token."""
    token = _bearer(event)
    if not token:
        raise PermissionError("agent session token is required")
    item = TABLE.get_item(
        Key={"pk": _token_key("AGENT_SESSION", token), "sk": "SESSION"}, ConsistentRead=True
    ).get("Item")
    if not item or int(item.get("expires_at", 0)) <= int(time.time()):
        raise PermissionError("agent session is missing or expired")
    return item


def _agent_identity(path, event):
    """Require URL identity and live project scope to match the agent session."""
    parts = [part for part in path.split("/") if part]
    if len(parts) < 3 or parts[0] != "agent":
        raise PermissionError("agent identity is required")
    session = _agent_session(event)
    if session.get("deployment_id") != parts[1] or session.get("agent_id") != parts[2]:
        raise PermissionError("agent session identity mismatch")
    headers = {str(key).lower(): value for key, value in (event.get("headers") or {}).items()}
    supplied_scope = headers.get("x-aai-project-root-digest")
    session_scope = session.get("project_root_hash")
    if (
        not isinstance(supplied_scope, str)
        or not isinstance(session_scope, str)
        or not re.fullmatch(r"[0-9a-f]{64}", supplied_scope)
        or not secrets.compare_digest(supplied_scope, session_scope)
    ):
        raise PermissionError("agent session project scope mismatch")
    agent = _explicit_agent_lifecycle(session["tenant_id"], parts[1], parts[2])
    if not agent or _agent_lifecycle_state(agent) != "active":
        # Session rows are deliberately short lived and keyed only by a token
        # digest. The authoritative agent record is therefore the immediate
        # revocation point for every previously issued session.
        raise PermissionError("agent identity is revoked or offboarded")
    session_revision = _agent_session_revision(session)
    current_revision = _agent_session_revision(agent)
    if session_revision is None or current_revision is None or session_revision != current_revision:
        raise PermissionError("agent session authority has been revoked")
    registered_root = agent.get("project_root") if agent else None
    if (
        not isinstance(registered_root, str)
        or not registered_root
        or not secrets.compare_digest(
            hashlib.sha256(registered_root.encode()).hexdigest(), session_scope
        )
    ):
        raise PermissionError("registered agent project scope mismatch")
    return session, parts[1], parts[2], parts[3:]


def _claims(event):
    return event.get("requestContext", {}).get("authorizer", {}).get("jwt", {}).get("claims", {})


def _tenant(event):
    # Never infer a tenant from deployment defaults or request JSON. A missing
    # claim is an authentication/entitlement failure, not a default tenant.
    claims = _claims(event)
    tenant = claims.get("custom:tenant_id")
    if not tenant:
        # Cognito's pre-token trigger adds this provenance only after inspecting
        # the server-owned federated identity. It is still not authority: the
        # deployment-owned mapping below chooses the application tenant and the
        # tenant must have an independently provisioned root record.
        provider = claims.get("aai:identity_provider")
        entra_tenant = claims.get("aai:entra_tenant_id")
        configured_entra_tenant = os.environ.get("ENTRA_TENANT_ID", "")
        configured_aai_tenant = os.environ.get("ENTRA_AAI_TENANT_ID", "")
        if (
            provider == "microsoft_entra_id"
            and isinstance(entra_tenant, str)
            and configured_entra_tenant
            and secrets.compare_digest(entra_tenant, configured_entra_tenant)
        ):
            tenant = configured_aai_tenant
    # Self-signup users are provisioned by the Cognito post-confirmation
    # trigger. Their first token intentionally does not contain a mutable
    # tenant attribute, so resolve the immutable Cognito subject through the
    # server-owned USER# mapping instead of trusting browser input.
    if not tenant:
        subject = claims.get("sub")
        if isinstance(subject, str) and subject and len(subject) <= 128:
            mapping = TABLE.get_item(
                Key={"pk": f"USER#{subject}", "sk": "TENANT"}, ConsistentRead=True
            ).get("Item")
            tenant = mapping.get("tenant_id") if mapping else None
    if not isinstance(tenant, str) or not tenant or len(tenant) > 128:
        raise PermissionError("authenticated tenant entitlement is required")
    # A Cognito claim is necessary but not sufficient for tenancy.  The
    # control plane must have provisioned the tenant independently.  The
    # seeded development tenant is bootstrapped once; all other tenants need
    # an explicit provisioning record before they can read or mutate state.
    if (
        not TABLE.get_item(Key=_item_key(tenant, "TENANT", "root")).get("Item")
        and tenant != "tenant-demo"
    ):
        raise PermissionError("tenant is not provisioned")
    return tenant


def _bounded_claim_values(raw_value):
    """Normalize one bounded list-shaped JWT claim without substring matching."""
    values = []
    if isinstance(raw_value, list):
        values = raw_value
    elif isinstance(raw_value, str) and len(raw_value) <= 2048:
        value = raw_value.strip()
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            decoded = None
        if isinstance(decoded, list):
            values = decoded
        elif isinstance(decoded, str):
            values = [decoded]
        else:
            if value.startswith("[") and value.endswith("]"):
                value = value[1:-1]
            values = [item.strip().strip("\"'") for item in value.split(",")]
    return {value for value in values if isinstance(value, str) and value and len(value) <= 128}


def _operator_roles(event):
    """Return exact canonical roles from Cognito's server-managed groups.

    Entra authenticates the operator, but its raw claims never directly grant
    product authority. Entra users are assigned to these canonical groups by
    the deployment's controlled provisioning/group-mapping process.
    """
    return (
        _bounded_claim_values(_claims(event).get("cognito:groups", [])) & _CANONICAL_OPERATOR_ROLES
    )


def _required_mutation_capability(path):
    """Classify a mutating route into one least-privilege capability."""
    normalized = path.removeprefix("/api")
    if normalized.startswith("/enterprise/identity/service-identities"):
        return "identity_admin"
    if normalized == "/enterprise/identity/break-glass/requests":
        return "incident_response"
    if normalized.startswith("/enterprise/identity/break-glass/requests/"):
        return "identity_admin"
    if normalized in {"/emergency-stop", "/enterprise/emergency-stop"}:
        return "incident_response"
    if "/emergency-stop" in normalized or normalized.endswith("/alerts/dispatch"):
        return "incident_response"
    if normalized.startswith("/enterprise/alerts/"):
        return "incident_response"
    if normalized.startswith("/enterprise/alert-suppressions"):
        return "incident_response"
    if normalized.startswith("/enterprise/cases"):
        return "incident_response"
    if re.fullmatch(
        r"/enterprise/response-rules/[^/]+/versions/[1-9][0-9]*/(decision|activate)",
        normalized,
    ) or re.fullmatch(r"/enterprise/response-rules/[^/]+/(disable|rollback)", normalized):
        return "response_rule_approval"
    if normalized.startswith("/enterprise/response-rules"):
        return "response_rule_write"
    if normalized.startswith("/enterprise/approvals/"):
        return "approval_decision"
    if normalized.startswith("/enterprise/identity/scim"):
        return "identity_admin"
    if normalized.startswith("/enterprise/identity/delegated-grants"):
        return "identity_admin"
    if normalized.startswith("/enterprise/evidence"):
        return "evidence_admin"
    if normalized.startswith("/enterprise/webhooks"):
        # Outbound destinations and signing keys cross the tenant egress and
        # credential boundary. Only the platform-administration wildcard owns
        # this capability; it is intentionally absent from delegated grants,
        # break glass, and machine credentials.
        return "integration_admin"
    if normalized.startswith("/enterprise/discovery/sources/"):
        # Population evidence can lower measured coverage and create leaver or
        # orphan findings. Until scoped service identities are implemented,
        # only the platform-administration wildcard may publish it.
        return "discovery_write"
    if re.fullmatch(
        r"/enterprise/policies/[^/]+/versions/[1-9][0-9]*/(decision|stage|activate)",
        normalized,
    ):
        return "policy_approval"
    if re.fullmatch(
        r"/enterprise/policy-exceptions/[^/]+/(decision|activate|revoke)",
        normalized,
    ):
        return "policy_approval"
    if normalized.startswith("/enterprise/policy-exceptions"):
        return "policy_write"
    if re.fullmatch(
        r"/enterprise/policies/[^/]+/versions/[1-9][0-9]*/simulate",
        normalized,
    ):
        return "policy_simulation"
    if normalized.startswith("/enterprise/policies"):
        return "policy_write"
    if normalized.startswith("/enterprise/deployments/") and normalized.endswith(
        "/managed-package"
    ):
        # Package publication binds endpoint authority and is intentionally
        # platform-admin-only until delegated two-person governance exists.
        return "managed_deployment"
    if normalized.startswith("/enterprise/skills") or normalized.startswith(
        "/enterprise/mcp-servers"
    ):
        return "policy_write"
    if normalized.startswith("/configuration"):
        return "runtime_admin"
    return "fleet_write"


def _operator_authorized(
    event,
    capability,
    tenant=None,
    *,
    include_break_glass=True,
    resource_scope=None,
    include_delegated=True,
):
    """Authorize one live capability from normal roles or an active emergency grant.

    Break-glass authority is resolved from server-owned state for each request;
    it is never copied into a browser claim. A lookup failure therefore denies
    emergency authority rather than extending a stale or expired grant.
    """
    normally_authorized = any(
        "*" in _ROLE_CAPABILITIES[role] or capability in _ROLE_CAPABILITIES[role]
        for role in _operator_roles(event)
    )
    if normally_authorized:
        return True
    service_capabilities = _service_capabilities(event)
    if service_capabilities:
        granted = frozenset().union(
            *(_SERVICE_CAPABILITY_GRANTS[value] for value in service_capabilities)
        )
        # Machine identities never inherit delegated or emergency authority.
        # Their versioned route was already checked independently, and this
        # second capability check preserves the normal mutation boundary.
        return capability in granted
    if include_delegated and tenant is not None and resource_scope is not None:
        try:
            if _delegated_operator_authorized(tenant, event, capability, resource_scope):
                return True
        except Exception:
            # Delegated authority is live server-owned state. A malformed,
            # oversized or unavailable lookup must never widen authority.
            return False
    if not include_break_glass or tenant is None or capability not in _BREAK_GLASS_CAPABILITIES:
        return False
    try:
        return capability in _active_break_glass_capabilities(tenant, event)
    except Exception:
        return False


def _mutation_authorized(event):
    """Retain the compatibility predicate while enforcing canonical roles.

    Cognito represents ``cognito:groups`` as an array in the JWT, while HTTP
    API authorizers expose claim values as strings. Depending on the gateway
    projection, that string may be one group, JSON array text, or bounded
    bracket/comma text. Normalize only exact group names; malformed values and
    lookalike substrings grant no authority.
    """
    return bool(_operator_roles(event))


def _item_resource_scope(tenant, kind, identifier):
    """Resolve one tenant item into its organization/project/deployment lineage."""
    item = TABLE.get_item(
        Key=_item_key(tenant, kind, _bounded_identifier(identifier, "resourceId")),
        ConsistentRead=True,
    ).get("Item")
    if not item:
        return None
    organization_id = item.get("organization_id") or item.get("organizationId")
    project_id = item.get("project_id") or item.get("projectId")
    deployment_id = item.get("deployment_id") or item.get("deploymentId")
    scope = {}
    if isinstance(organization_id, str) and organization_id:
        scope["organization"] = organization_id
    if isinstance(project_id, str) and project_id:
        scope["project"] = project_id
    if kind == "DEPLOYMENT":
        scope["deployment"] = item.get("id", identifier)
    elif isinstance(deployment_id, str) and deployment_id:
        scope["deployment"] = deployment_id
    return scope or None


def _mutation_resource_scope(tenant, event, path):
    """Derive server-validated scope for delegated mutation authorization.

    Returning ``None`` is a deliberate denial for delegated operators. Tenant-
    wide controls, identity governance and unrecognized routes require normal
    directory-derived authority or break glass.
    """
    normalized = path.removeprefix("/api")
    if not normalized.startswith("/enterprise/"):
        return None
    parts = [part for part in normalized.removeprefix("/enterprise/").split("/") if part]
    body = _body(event)
    if parts == ["projects"]:
        organization_id = body.get("organizationId")
        try:
            return _delegated_scope_lineage(tenant, "organization", organization_id)
        except (ValueError, LookupError):
            return None
    if parts == ["deployments"]:
        project_id = body.get("projectId")
        try:
            return _delegated_scope_lineage(tenant, "project", project_id)
        except (ValueError, LookupError):
            return None
    if parts and parts[0] == "deployments" and len(parts) >= 2:
        try:
            return _delegated_scope_lineage(tenant, "deployment", parts[1])
        except (ValueError, LookupError):
            return None
    if parts in (["agents", "register"], ["agents", "bootstrap"]):
        try:
            return _delegated_scope_lineage(tenant, "deployment", body.get("deploymentId"))
        except (ValueError, LookupError):
            return None
    if parts and parts[0] == "agents" and len(parts) >= 3:
        try:
            return _delegated_scope_lineage(tenant, "deployment", parts[1])
        except (ValueError, LookupError):
            return None
    if parts == ["deployment-config"] or parts == ["deployment-config", "rollback"]:
        try:
            return _delegated_scope_lineage(tenant, "deployment", body.get("deploymentId"))
        except (ValueError, LookupError):
            return None
    if len(parts) == 3 and parts[0] == "deployment-config" and parts[2] == "pause":
        try:
            return _delegated_scope_lineage(tenant, "deployment", parts[1])
        except (ValueError, LookupError):
            return None
    if parts == ["deployment-config", "batch-rollout"]:
        deployment_ids = body.get("deploymentIds")
        if not isinstance(deployment_ids, list) or not 1 <= len(deployment_ids) <= 200:
            return None
        try:
            return [
                _delegated_scope_lineage(tenant, "deployment", deployment_id)
                for deployment_id in deployment_ids
            ]
        except (ValueError, LookupError):
            return None
    if parts == ["emergency-stop"] and body.get("deploymentId"):
        try:
            return _delegated_scope_lineage(tenant, "deployment", body.get("deploymentId"))
        except (ValueError, LookupError):
            return None
    if parts and parts[0] == "policies":
        if len(parts) >= 2:
            return _item_resource_scope(tenant, "POLICY", parts[1])
        try:
            organization_id = _policy_organization(tenant, body)
            return _delegated_scope_lineage(tenant, "organization", organization_id)
        except (ValueError, LookupError):
            return None
    if parts and parts[0] == "groups":
        if len(parts) >= 2:
            return _item_resource_scope(tenant, "GROUP", parts[1])
        policy_id = body.get("policyId")
        return _item_resource_scope(tenant, "POLICY", policy_id) if policy_id else None
    if parts in (["skills"], ["mcp-servers"]):
        organization_id = body.get("organizationId")
        if organization_id is None:
            organizations = _list(tenant, "ORG", consistent_read=True)
            organization_id = organizations[0].get("id") if len(organizations) == 1 else None
        try:
            return _delegated_scope_lineage(tenant, "organization", organization_id)
        except (ValueError, LookupError):
            return None
    if parts and parts[0] == "approvals":
        agent_key = body.get("agentKey")
        if len(parts) >= 2 and parts[1] not in {"consume"}:
            approval = TABLE.get_item(
                Key=_item_key(tenant, "APPROVAL", parts[1]), ConsistentRead=True
            ).get("Item")
            agent_key = approval.get("agent_key") if approval else None
        if isinstance(agent_key, str) and ":" in agent_key:
            try:
                return _delegated_scope_lineage(tenant, "deployment", agent_key.split(":", 1)[0])
            except (ValueError, LookupError):
                return None
    return None


_DELEGATED_READ_ROLES = {
    "ORG": _DELEGATABLE_OPERATOR_ROLES,
    "PROJECT": _DELEGATABLE_OPERATOR_ROLES,
    "DEPLOYMENT": frozenset(
        {"fleet-operator", "incident-responder", "security-operator", "auditor"}
    ),
    "AGENT": frozenset({"fleet-operator", "incident-responder", "security-operator", "auditor"}),
    "GROUP": frozenset(
        {"fleet-operator", "incident-responder", "policy-author", "policy-approver", "auditor"}
    ),
    "POLICY": frozenset({"fleet-operator", "policy-author", "policy-approver", "auditor"}),
    "SKILL": frozenset({"policy-author", "policy-approver", "auditor"}),
    "MCP": frozenset({"policy-author", "policy-approver", "auditor"}),
    "CONFIGURATION": frozenset({"fleet-operator", "incident-responder", "auditor"}),
    "DRIFT": frozenset({"fleet-operator", "incident-responder", "security-operator", "auditor"}),
    "HEALTH": frozenset({"fleet-operator", "incident-responder", "security-operator", "auditor"}),
    "SLO": frozenset({"fleet-operator", "incident-responder", "security-operator", "auditor"}),
    "APPROVAL": frozenset({"policy-approver", "security-operator", "auditor"}),
    "ALERT": frozenset({"incident-responder", "security-operator", "auditor"}),
    "ALERT_SUPPRESSION": frozenset({"incident-responder", "security-operator", "auditor"}),
    "CASE": frozenset({"incident-responder", "security-operator", "auditor"}),
    "AUDIT": frozenset({"security-operator", "auditor"}),
}


def _delegated_item_scope(tenant, kind, item):
    """Resolve one list item into a scope without trusting presentation fields."""
    if kind == "ORG":
        identifier = item.get("id")
        return {"organization": identifier} if isinstance(identifier, str) and identifier else None
    if kind == "PROJECT":
        identifier = item.get("id")
        try:
            return _delegated_scope_lineage(tenant, "project", identifier)
        except (ValueError, LookupError):
            return None
    if kind == "DEPLOYMENT":
        identifier = item.get("id")
        try:
            return _delegated_scope_lineage(tenant, "deployment", identifier)
        except (ValueError, LookupError):
            return None
    deployment_id = item.get("deployment_id") or item.get("deploymentId")
    if kind == "APPROVAL":
        agent_key = item.get("agent_key") or item.get("agentKey")
        deployment_id = (
            agent_key.split(":", 1)[0]
            if isinstance(agent_key, str) and ":" in agent_key
            else deployment_id
        )
    if isinstance(deployment_id, str) and deployment_id:
        try:
            return _delegated_scope_lineage(tenant, "deployment", deployment_id)
        except (ValueError, LookupError):
            return None
    organization_id = item.get("organization_id") or item.get("organizationId")
    if isinstance(organization_id, str) and organization_id:
        try:
            return _delegated_scope_lineage(tenant, "organization", organization_id)
        except (ValueError, LookupError):
            return None
    return None


def _delegated_operator_can_read(tenant, event, kind, scope):
    """Authorize scoped read visibility from live role and resource grants."""
    allowed_roles = _DELEGATED_READ_ROLES.get(kind, frozenset())
    return any(
        grant.get("role") in allowed_roles and _delegated_grant_covers(grant, scope)
        for grant in _active_delegated_grants(tenant, event)
    )


def _filter_enterprise_items(tenant, event, kind, items):
    """Filter tenant inventory for a delegated-only operator or fail closed."""
    if _operator_roles(event) or _service_capabilities(event):
        return items
    result = []
    for item in items:
        scope = _delegated_item_scope(tenant, kind, item)
        if scope is not None and _delegated_operator_can_read(tenant, event, kind, scope):
            result.append(item)
    return result


def _service_capabilities(event):
    """Return server-injected machine capabilities after bearer authentication.

    Cognito claims with similar names are intentionally ignored. Only the
    private marker created by ``_machine_request`` after a live credential
    lookup can enter this branch.
    """
    if not isinstance(event, dict) or event.get("_aai_machine_authenticated") is not True:
        return frozenset()
    raw = _claims(event).get("aai:service_capabilities", [])
    return frozenset(_bounded_claim_values(raw) & _SERVICE_IDENTITY_CAPABILITIES)


def _service_identity_view(item, *, now=None):
    """Project one service identity without bearer material or token digests."""
    current = int(time.time()) if now is None else int(now)
    stored_status = item.get("status")
    status = (
        "expired"
        if stored_status == "active" and int(item.get("expires_at", 0)) <= current
        else stored_status
    )
    return {
        "id": item.get("id", ""),
        "name": item.get("name", ""),
        "description": item.get("description", ""),
        "purpose": item.get("purpose", ""),
        "capabilities": sorted(item.get("capabilities", [])),
        "status": status,
        "revision": int(item.get("revision", 0)),
        "credentialFingerprint": item.get("credential_fingerprint", ""),
        "createdAt": int(item.get("created_at", 0)),
        "createdBy": item.get("created_by", ""),
        "rotatedAt": int(item["rotated_at"]) if item.get("rotated_at") else None,
        "expiresAt": int(item.get("expires_at", 0)),
        "revokedAt": int(item["revoked_at"]) if item.get("revoked_at") else None,
        "lastUsedAt": int(item["last_used_at"]) if item.get("last_used_at") else None,
        "lastUsedMethod": item.get("last_used_method") or None,
        "lastUsedRoute": item.get("last_used_route") or None,
        "useCount": int(item.get("use_count", 0)),
    }


def _service_identity_audit_record(tenant, event_type, actor, payload, *, now):
    """Build immutable primary evidence for a machine-authority transition."""
    event_id = str(uuid.uuid4())
    redacted = {
        "event_type": event_type,
        "actor": actor,
        "tenant_id": tenant,
        "occurred_at": now,
        "payload": payload,
    }
    return {
        **_item_key(tenant, "SERVICE_IDENTITY_AUDIT", f"{now:012d}#{event_id}"),
        **redacted,
        "id": event_id,
        "payload_hash": hashlib.sha256(
            json.dumps(redacted, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def _service_identity_duration(value):
    """Return a positive one-to-90-day credential duration in seconds."""
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 90:
        raise ValueError("expiresInDays must be an integer from 1 to 90")
    duration = value * 24 * 60 * 60
    if duration > _SERVICE_IDENTITY_MAX_SECONDS:
        raise ValueError("service identity credential exceeds the maximum lifetime")
    return duration


def _service_identity_capability_set(value):
    """Require a non-empty exact set of supported non-human capabilities."""
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= len(_SERVICE_IDENTITY_CAPABILITIES)
        or any(not isinstance(item, str) for item in value)
    ):
        raise ValueError("service identity capabilities have an invalid schema")
    capabilities = frozenset(value)
    if len(capabilities) != len(value) or not capabilities <= _SERVICE_IDENTITY_CAPABILITIES:
        raise ValueError("service identity capability is unsupported or duplicated")
    return capabilities


def _service_credential(identity_id):
    """Create one bearer and its digest-keyed server record."""
    secret = secrets.token_urlsafe(32)
    token = f"aai_si_{identity_id}.{secret}"
    digest = hashlib.sha256(token.encode()).hexdigest()
    return token, f"sha256:{digest[:12]}"


def _service_identity_issue(tenant, value, actor):
    """Create one scoped service identity and return its bearer exactly once."""
    if not isinstance(value, dict) or set(value) != {
        "serviceIdentityId",
        "name",
        "description",
        "purpose",
        "capabilities",
        "expiresInDays",
    }:
        raise ValueError("service identity request has an invalid schema")
    identity_id = _bounded_identifier(value.get("serviceIdentityId"), "serviceIdentityId")
    capabilities = _service_identity_capability_set(value.get("capabilities"))
    duration = _service_identity_duration(value.get("expiresInDays"))
    now = int(time.time())
    expires_at = now + duration
    token, fingerprint = _service_credential(identity_id)
    description_value = value.get("description")
    if (
        not isinstance(description_value, str)
        or len(description_value.strip()) > 500
        or any(ord(char) < 32 for char in description_value)
    ):
        raise ValueError("description must be bounded text")
    identity = {
        **_item_key(tenant, "SERVICE_IDENTITY", identity_id),
        "tenant_id": tenant,
        "id": identity_id,
        "name": _bounded_text(value.get("name"), "name", 120),
        "description": description_value.strip(),
        "purpose": _bounded_text(value.get("purpose"), "purpose", 500),
        "capabilities": sorted(capabilities),
        "status": "active",
        "revision": 1,
        "credential_key": _token_key("SERVICE_IDENTITY", token),
        "credential_fingerprint": fingerprint,
        "created_at": now,
        "created_by": actor,
        "expires_at": expires_at,
        "use_count": 0,
    }
    pointer = {
        "pk": _token_key("SERVICE_IDENTITY", token),
        "sk": "CREDENTIAL",
        "tenant_id": tenant,
        "service_identity_id": identity_id,
        "credential_revision": 1,
        "status": "active",
        "expires_at": expires_at,
        "ttl": expires_at,
    }
    payload = {
        "service_identity_id": identity_id,
        "capabilities": sorted(capabilities),
        "expires_at": expires_at,
        "revision": 1,
    }
    audit = _service_identity_audit_record(
        tenant, "service_identity_created", actor, payload, now=now
    )
    try:
        DYNAMODB.transact_write_items(
            TransactItems=[
                _transaction_put(identity, condition="attribute_not_exists(pk)"),
                _transaction_put(pointer, condition="attribute_not_exists(pk)"),
                _transaction_put(audit, condition="attribute_not_exists(pk)"),
            ]
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("service identity already exists") from error
        raise
    _export_identity_governance_audit(tenant, "service_identity_created", actor, payload)
    return {
        **_service_identity_view(identity, now=now),
        "credential": {
            "accessToken": token,
            "tokenType": "Bearer",
            "expiresAt": expires_at,
            "fingerprint": fingerprint,
        },
    }


def _service_identity_rotate(tenant, identity_id, value, actor):
    """Atomically replace one active bearer and revoke its previous digest."""
    if not isinstance(value, dict) or set(value) != {"expectedRevision", "expiresInDays"}:
        raise ValueError("service identity rotation has an invalid schema")
    identity_id = _bounded_identifier(identity_id, "serviceIdentityId")
    expected_revision = _discovery_integer(
        value.get("expectedRevision"), "expectedRevision", minimum=1
    )
    duration = _service_identity_duration(value.get("expiresInDays"))
    current = TABLE.get_item(
        Key=_item_key(tenant, "SERVICE_IDENTITY", identity_id), ConsistentRead=True
    ).get("Item")
    if not current:
        raise LookupError("service identity not found")
    if current.get("status") != "active" or int(current.get("revision", 0)) != expected_revision:
        raise PolicyConflict("service identity is inactive or changed")
    now = int(time.time())
    expires_at = now + duration
    token, fingerprint = _service_credential(identity_id)
    revision = expected_revision + 1
    replacement = {
        **current,
        "revision": revision,
        "credential_key": _token_key("SERVICE_IDENTITY", token),
        "credential_fingerprint": fingerprint,
        "rotated_at": now,
        "rotated_by": actor,
        "expires_at": expires_at,
    }
    old_key = {"pk": current.get("credential_key", ""), "sk": "CREDENTIAL"}
    old_pointer = TABLE.get_item(Key=old_key, ConsistentRead=True).get("Item")
    if not old_pointer:
        raise PolicyConflict("service identity credential state is incomplete")
    revoked_pointer = {**old_pointer, "status": "revoked", "revoked_at": now, "ttl": now + 86400}
    new_pointer = {
        "pk": _token_key("SERVICE_IDENTITY", token),
        "sk": "CREDENTIAL",
        "tenant_id": tenant,
        "service_identity_id": identity_id,
        "credential_revision": revision,
        "status": "active",
        "expires_at": expires_at,
        "ttl": expires_at,
    }
    payload = {
        "service_identity_id": identity_id,
        "expires_at": expires_at,
        "revision": revision,
    }
    audit = _service_identity_audit_record(
        tenant, "service_identity_rotated", actor, payload, now=now
    )
    try:
        DYNAMODB.transact_write_items(
            TransactItems=[
                _transaction_put(
                    replacement,
                    condition="#status = :active AND revision = :revision",
                    names={"#status": "status"},
                    values={":active": "active", ":revision": expected_revision},
                ),
                _transaction_put(
                    revoked_pointer,
                    condition="#status = :active AND credential_revision = :revision",
                    names={"#status": "status"},
                    values={":active": "active", ":revision": expected_revision},
                ),
                _transaction_put(new_pointer, condition="attribute_not_exists(pk)"),
                _transaction_put(audit, condition="attribute_not_exists(pk)"),
            ]
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("service identity changed during rotation") from error
        raise
    _export_identity_governance_audit(tenant, "service_identity_rotated", actor, payload)
    return {
        **_service_identity_view(replacement, now=now),
        "credential": {
            "accessToken": token,
            "tokenType": "Bearer",
            "expiresAt": expires_at,
            "fingerprint": fingerprint,
        },
    }


def _service_identity_revoke(tenant, identity_id, value, actor):
    """Atomically revoke one service identity and its current bearer."""
    if not isinstance(value, dict) or set(value) != {"expectedRevision", "reason"}:
        raise ValueError("service identity revocation has an invalid schema")
    identity_id = _bounded_identifier(identity_id, "serviceIdentityId")
    expected_revision = _discovery_integer(
        value.get("expectedRevision"), "expectedRevision", minimum=1
    )
    reason = _bounded_text(value.get("reason"), "reason", 500)
    current = TABLE.get_item(
        Key=_item_key(tenant, "SERVICE_IDENTITY", identity_id), ConsistentRead=True
    ).get("Item")
    if not current:
        raise LookupError("service identity not found")
    if current.get("status") != "active" or int(current.get("revision", 0)) != expected_revision:
        raise PolicyConflict("service identity is inactive or changed")
    now = int(time.time())
    revision = expected_revision + 1
    revoked = {
        **current,
        "status": "revoked",
        "revision": revision,
        "revoked_at": now,
        "revoked_by": actor,
        "revocation_reason": reason,
    }
    pointer_key = {"pk": current.get("credential_key", ""), "sk": "CREDENTIAL"}
    pointer = TABLE.get_item(Key=pointer_key, ConsistentRead=True).get("Item")
    if not pointer:
        raise PolicyConflict("service identity credential state is incomplete")
    revoked_pointer = {**pointer, "status": "revoked", "revoked_at": now, "ttl": now + 86400}
    payload = {
        "service_identity_id": identity_id,
        "reason_hash": hashlib.sha256(reason.encode()).hexdigest(),
        "revision": revision,
    }
    audit = _service_identity_audit_record(
        tenant, "service_identity_revoked", actor, payload, now=now
    )
    try:
        DYNAMODB.transact_write_items(
            TransactItems=[
                _transaction_put(
                    revoked,
                    condition="#status = :active AND revision = :revision",
                    names={"#status": "status"},
                    values={":active": "active", ":revision": expected_revision},
                ),
                _transaction_put(
                    revoked_pointer,
                    condition="#status = :active AND credential_revision = :revision",
                    names={"#status": "status"},
                    values={":active": "active", ":revision": expected_revision},
                ),
                _transaction_put(audit, condition="attribute_not_exists(pk)"),
            ]
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("service identity changed during revocation") from error
        raise
    _export_identity_governance_audit(tenant, "service_identity_revoked", actor, payload)
    return _service_identity_view(revoked, now=now)


def _machine_route_capability(method, path):
    """Return the exact machine scope for one versioned canonical route.

    This allowlist is intentionally independent from human routing. Adding a
    new operator endpoint therefore cannot accidentally expose it to an old
    service credential.
    """
    normalized = path.removeprefix("/api")
    inventory_paths = {
        "/enterprise/agents",
        "/enterprise/deployment-config",
        "/enterprise/deployment-config/history",
        "/enterprise/deployments",
        "/enterprise/drift",
        "/enterprise/groups",
        "/enterprise/health",
        "/enterprise/mcp-servers",
        "/enterprise/organizations",
        "/enterprise/policies",
        "/enterprise/projects",
        "/enterprise/skills",
        "/enterprise/slo",
        "/enterprise/templates",
        "/enterprise/tenant",
    }
    evidence_paths = {
        "/enterprise/audit",
        "/enterprise/discovery",
        "/enterprise/discovery/export",
        "/enterprise/evidence",
        "/enterprise/evidence/export",
        "/enterprise/reports/auditor",
        "/enterprise/reports/executive",
    }
    if method == "GET" and normalized in inventory_paths:
        return "inventory_read"
    if method == "GET" and normalized in evidence_paths:
        return "evidence_read"
    if method == "GET" and re.fullmatch(
        r"/enterprise/policies/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/versions(?:/[1-9][0-9]*)?",
        normalized,
    ):
        return "inventory_read"
    if method == "POST" and re.fullmatch(
        r"/enterprise/policies/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/versions/[1-9][0-9]*/simulate",
        normalized,
    ):
        return "policy_simulation"
    if method == "POST" and (
        normalized in {"/enterprise/policies", "/enterprise/skills", "/enterprise/mcp-servers"}
        or re.fullmatch(
            r"/enterprise/policies/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/versions",
            normalized,
        )
    ):
        return "policy_draft_write"
    if method in {"PUT", "DELETE"} and re.fullmatch(
        r"/enterprise/(?:skills|mcp-servers)/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
        normalized,
    ):
        return "policy_draft_write"
    if method == "POST" and (
        normalized
        in {
            "/enterprise/agents/bootstrap",
            "/enterprise/agents/register",
            "/enterprise/deployments",
            "/enterprise/groups",
            "/enterprise/projects",
        }
        or re.fullmatch(
            r"/enterprise/groups/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/(?:agents|dynamic-membership|policy)",
            normalized,
        )
        or re.fullmatch(
            r"/enterprise/groups/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/agents/bulk",
            normalized,
        )
    ):
        return "fleet_write"
    if method == "DELETE" and re.fullmatch(
        r"/enterprise/groups/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/agents/"
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
        normalized,
    ):
        return "fleet_write"
    if method in {"PUT", "DELETE"} and re.fullmatch(
        r"/enterprise/groups/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", normalized
    ):
        return "fleet_write"
    if method == "POST" and (
        normalized
        in {
            "/enterprise/deployment-config",
            "/enterprise/deployment-config/batch-rollout",
            "/enterprise/deployment-config/rollback",
            "/enterprise/templates",
        }
        or re.fullmatch(
            r"/enterprise/deployment-config/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/pause",
            normalized,
        )
    ):
        return "runtime_write"
    return None


def _machine_request(event, method, path):
    """Authenticate and translate one `/machine/v1` request for normal routing."""
    prefix = "/machine/v1/"
    if not path.startswith(prefix):
        raise PermissionError("versioned machine API route is required")
    canonical_path = "/api/" + path.removeprefix(prefix)
    required = _machine_route_capability(method, canonical_path)
    if required is None:
        raise PermissionError("machine API route is not available")
    token = _bearer(event)
    pointer = (
        TABLE.get_item(
            Key={"pk": _token_key("SERVICE_IDENTITY", token), "sk": "CREDENTIAL"},
            ConsistentRead=True,
        ).get("Item")
        if token
        else None
    )
    now = int(time.time())
    if not pointer or pointer.get("status") != "active" or int(pointer.get("expires_at", 0)) <= now:
        raise PermissionError("active service credential is required")
    tenant = pointer.get("tenant_id")
    identity_id = pointer.get("service_identity_id")
    if not isinstance(tenant, str) or not isinstance(identity_id, str):
        raise PermissionError("active service credential is required")
    identity = TABLE.get_item(
        Key=_item_key(tenant, "SERVICE_IDENTITY", identity_id), ConsistentRead=True
    ).get("Item")
    try:
        capabilities = _service_identity_capability_set(
            identity.get("capabilities") if identity else None
        )
    except ValueError as error:
        raise PermissionError("active service credential is required") from error
    revision = int(pointer.get("credential_revision", 0))
    if (
        not identity
        or identity.get("status") != "active"
        or int(identity.get("expires_at", 0)) <= now
        or int(identity.get("revision", 0)) != revision
        or identity.get("credential_key") != pointer.get("pk")
        or required not in capabilities
    ):
        raise PermissionError("service credential does not permit this request")
    usage_id = f"{now:012d}#{uuid.uuid4()}"
    usage = {
        **_item_key(tenant, "SERVICE_IDENTITY_USAGE", usage_id),
        "tenant_id": tenant,
        "id": usage_id,
        "service_identity_id": identity_id,
        "credential_revision": revision,
        "method": method,
        "route": canonical_path.removeprefix("/api"),
        "capability": required,
        "occurred_at": now,
        "ttl": now + _SERVICE_IDENTITY_MAX_SECONDS,
    }
    try:
        DYNAMODB.transact_write_items(
            TransactItems=[
                {
                    "ConditionCheck": {
                        "TableName": CONTROL_TABLE_NAME,
                        "Key": _ddb_item(_item_key(tenant, "SERVICE_IDENTITY", identity_id)),
                        "ConditionExpression": (
                            "#status = :active AND revision = :revision AND expires_at > :now"
                        ),
                        "ExpressionAttributeNames": {"#status": "status"},
                        "ExpressionAttributeValues": _ddb_item(
                            {":active": "active", ":revision": revision, ":now": now}
                        ),
                    }
                },
                _transaction_put(usage, condition="attribute_not_exists(pk)"),
            ]
        )
        TABLE.update_item(
            Key=_item_key(tenant, "SERVICE_IDENTITY", identity_id),
            UpdateExpression=(
                "SET last_used_at = :now, last_used_method = :method, "
                "last_used_route = :route ADD use_count :one"
            ),
            ConditionExpression=(
                "#status = :active AND revision = :revision AND expires_at > :now"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":active": "active",
                ":revision": revision,
                ":now": now,
                ":method": method,
                ":route": canonical_path.removeprefix("/api"),
                ":one": 1,
            },
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PermissionError("service credential authority changed") from error
        raise
    _audit(
        tenant,
        "service_identity_request_admitted",
        f"service:{identity_id}",
        {
            "service_identity_id": identity_id,
            "credential_revision": revision,
            "method": method,
            "route": canonical_path.removeprefix("/api"),
            "capability": required,
        },
    )
    request_context = dict(event.get("requestContext") or {})
    request_context["http"] = {
        **dict(request_context.get("http") or {}),
        "method": method,
        "path": canonical_path,
    }
    request_context["authorizer"] = {
        "jwt": {
            "claims": {
                "custom:tenant_id": tenant,
                "sub": f"service:{identity_id}",
                "aai:identity_type": "service",
                "aai:service_identity_id": identity_id,
                "aai:service_capabilities": sorted(capabilities),
            }
        }
    }
    return {
        **event,
        "rawPath": canonical_path,
        "path": canonical_path,
        "requestContext": request_context,
        "_aai_machine_authenticated": True,
    }


def _scim_lifecycle(tenant, *, include_operators=False):
    """Return a bounded, secret-free view of Entra provisioning lifecycle."""
    configured = (
        os.environ.get("SCIM_ENABLED") == "true"
        and SCIM is not None
        and os.environ.get("ENTRA_AAI_TENANT_ID") == tenant
    )
    empty = {
        "status": "not_configured",
        "lifecycleEnforced": False,
        "users": {"total": 0, "active": 0, "disabled": 0},
        "groups": {"total": 0, "mapped": 0, "unmapped": 0},
        "groupMappings": [],
        "operators": [],
        "lastProvisionedAt": None,
    }
    if not configured:
        return empty
    result = SCIM.query(
        KeyConditionExpression=Key("pk").eq(f"TENANT#{tenant}"),
        Limit=501,
        ConsistentRead=True,
    )
    items = result.get("Items", [])
    if result.get("LastEvaluatedKey") or len(items) > 500:
        # The status endpoint is not an authorization decision. Still surface
        # an explicit degraded state rather than silently reporting a subset.
        return {**empty, "status": "degraded", "error": "inventory_bound_exceeded"}
    users = [item for item in items if str(item.get("sk", "")).startswith("USER#")]
    groups = [item for item in items if str(item.get("sk", "")).startswith("GROUP#")]
    mappings = [
        {
            "groupId": group.get("id", ""),
            "displayName": group.get("display_name", ""),
            "role": group.get("mapped_role") or None,
            "active": group.get("active") is True,
            "updatedAt": group.get("updated_at"),
        }
        for group in sorted(groups, key=lambda item: str(item.get("display_name", "")).lower())
    ]
    timestamps = [
        int(item.get("updated_at", 0))
        for item in users + groups
        if int(item.get("updated_at", 0)) > 0
    ]
    mapped = sum(1 for group in groups if group.get("mapped_role") in _CANONICAL_OPERATOR_ROLES)
    active = sum(1 for user in users if user.get("active") is True)
    operators = (
        [
            {
                "principalId": str(user.get("id", "")),
                "userName": str(user.get("user_name", "")),
                "displayName": str(user.get("display_name", "")),
                "active": user.get("active") is True,
            }
            for user in sorted(users, key=lambda item: str(item.get("display_name", "")).lower())
        ]
        if include_operators
        else []
    )
    return {
        "status": "configured",
        "lifecycleEnforced": True,
        "users": {"total": len(users), "active": active, "disabled": len(users) - active},
        "groups": {"total": len(groups), "mapped": mapped, "unmapped": len(groups) - mapped},
        "groupMappings": mappings,
        "operators": operators,
        "lastProvisionedAt": max(timestamps) if timestamps else None,
    }


def _map_scim_group_role(tenant, group_id, role, actor):
    """Map one provisioned Entra group to one exact canonical product role."""
    if SCIM is None or os.environ.get("SCIM_ENABLED") != "true":
        raise ValueError("SCIM lifecycle is not configured")
    if not isinstance(group_id, str) or len(group_id) > 64:
        raise ValueError("SCIM group ID is invalid")
    try:
        group_id = str(uuid.UUID(group_id))
    except ValueError as error:
        raise ValueError("SCIM group ID is invalid") from error
    if role is not None and role not in _CANONICAL_OPERATOR_ROLES:
        raise ValueError("SCIM group role is not canonical")
    key = {"pk": f"TENANT#{tenant}", "sk": f"GROUP#{group_id}"}
    group = SCIM.get_item(Key=key, ConsistentRead=True).get("Item")
    if not group:
        return None
    now = int(time.time())
    group.update(
        {
            "mapped_role": role or "",
            "mapped_by": actor,
            "mapped_at": now,
            "updated_at": now,
            "version": int(group.get("version", 0)) + 1,
        }
    )
    SCIM.put_item(Item=group)
    _audit(
        tenant,
        "scim_group_role_mapped",
        actor,
        {"group_id": group_id, "role": role or "unmapped"},
    )
    return group


def _identity_access(tenant, event):
    """Return redaction-safe identity provenance and the enforced role matrix."""
    entra_tenant = os.environ.get("ENTRA_TENANT_ID", "")
    configured = (
        os.environ.get("ENTRA_PROVIDER_ENABLED") == "true"
        and bool(entra_tenant)
        and os.environ.get("ENTRA_AAI_TENANT_ID") == tenant
    )
    can_manage_delegation = _operator_authorized(
        event,
        "identity_admin",
        tenant,
        include_break_glass=False,
        include_delegated=False,
    )
    scim = _scim_lifecycle(tenant, include_operators=can_manage_delegation)
    all_grants = _delegated_grants(tenant)
    principal = _operator_principal(event)
    visible_grants = (
        all_grants
        if can_manage_delegation
        else [grant for grant in all_grants if grant["principalId"] == principal]
    )
    scope_catalog = (
        {
            "organizations": [
                {"id": item.get("id", ""), "name": item.get("name", item.get("id", ""))}
                for item in _list(tenant, "ORG", consistent_read=True)
            ],
            "projects": [
                {
                    "id": item.get("id", ""),
                    "name": item.get("name", item.get("id", "")),
                    "organizationId": item.get("organization_id", ""),
                }
                for item in _list(tenant, "PROJECT", consistent_read=True)
            ],
            "deployments": [
                {
                    "id": item.get("id", ""),
                    "name": item.get("name", item.get("id", "")),
                    "organizationId": item.get("organization_id", ""),
                    "projectId": item.get("project_id", ""),
                }
                for item in _list(tenant, "DEPLOYMENT", consistent_read=True)
            ],
        }
        if can_manage_delegation
        else {"organizations": [], "projects": [], "deployments": []}
    )
    return {
        "provider": "microsoft_entra_id",
        "providerLabel": "Microsoft Entra ID",
        "protocol": "oidc",
        "status": "configured" if configured else "not_configured",
        "tenantHint": f"{entra_tenant[:8]}…" if configured else None,
        "tenantBinding": "server_owned",
        "roleSource": "cognito_managed_groups",
        "strongAuthentication": {
            "status": (
                "enforced"
                if configured and os.environ.get("ENTRA_STRONG_AUTH_ENFORCED") == "true"
                else "not_configured"
            ),
            "maxAuthenticationAgeSeconds": _STRONG_AUTH_MAX_AGE_SECONDS,
        },
        "subject": _bounded_text(_claims(event).get("sub"), "subject", 256),
        "scimStatus": scim["status"],
        "scim": scim,
        "activeRoles": sorted(_operator_roles(event)),
        "delegatedAdministration": {
            "canManage": can_manage_delegation,
            "grants": visible_grants,
            "scopeCatalog": scope_catalog,
        },
        "roleMatrix": [
            {
                "role": role,
                "capabilities": sorted(capabilities),
                "delegatable": role in _DELEGATABLE_OPERATOR_ROLES,
            }
            for role, capabilities in _ROLE_CAPABILITIES.items()
        ],
    }


def _operator_subject(event):
    """Return the immutable authenticated subject used for governance actions."""
    subject = _claims(event).get("sub")
    if not isinstance(subject, str) or not subject or len(subject) > 256:
        raise PermissionError("authenticated operator subject is required")
    return subject


def _require_recent_strong_authentication(event):
    """Require recent MFA evidence from signed Cognito/Entra token claims.

    Browser input cannot satisfy this check. Native sessions may provide a
    signed ``amr`` value. Federated sessions require the pre-token trigger's
    server-owned assertion that the configured Entra application is protected
    by an MFA-enforcing Conditional Access policy.
    """
    claims = _claims(event)
    methods = set()
    for name in ("amr", "cognito:amr"):
        methods.update(value.lower() for value in _bounded_claim_values(claims.get(name, [])))
    entra_strong_auth = (
        claims.get("aai:identity_provider") == "microsoft_entra_id"
        and claims.get("aai:strong_auth_enforced") == "true"
    )
    if not entra_strong_auth and not methods.intersection(
        {"mfa", "otp", "fido", "fido2", "webauthn"}
    ):
        raise PermissionError("recent multi-factor authentication is required")
    raw_auth_time = claims.get("auth_time")
    try:
        auth_time = int(raw_auth_time)
    except (TypeError, ValueError) as error:
        raise PermissionError("recent authentication evidence is required") from error
    now = int(time.time())
    if auth_time > now + 60 or now - auth_time > _STRONG_AUTH_MAX_AGE_SECONDS:
        raise PermissionError("strong authentication is too old")


def _break_glass_view(item, *, now=None):
    """Return one secret-free emergency-access record with live effective state."""
    current = int(time.time()) if now is None else now
    status = str(item.get("status", "unknown"))
    if status == "approved" and int(item.get("grant_expires_at", 0)) <= current:
        effective_status = "expired"
    elif status == "approved" and int(item.get("grant_starts_at", 0)) <= current:
        effective_status = "active"
    else:
        effective_status = status
    return {
        "id": item.get("id", ""),
        "subject": item.get("subject", ""),
        "capabilities": sorted(item.get("capabilities", [])),
        "reason": item.get("reason", ""),
        "durationSeconds": int(item.get("duration_seconds", 0)),
        "requestedAt": int(item.get("requested_at", 0)),
        "requestExpiresAt": int(item.get("request_expires_at", 0)),
        "requestedBy": item.get("requested_by", ""),
        "decidedBy": item.get("decided_by") or None,
        "decidedAt": int(item["decided_at"]) if item.get("decided_at") else None,
        "approvedBy": item.get("approved_by") if status in {"approved", "revoked"} else None,
        "approvedAt": (
            int(item["approved_at"])
            if status in {"approved", "revoked"} and item.get("approved_at")
            else None
        ),
        "grantStartsAt": (int(item["grant_starts_at"]) if item.get("grant_starts_at") else None),
        "grantExpiresAt": (int(item["grant_expires_at"]) if item.get("grant_expires_at") else None),
        "revokedBy": item.get("revoked_by") or None,
        "revokedAt": int(item["revoked_at"]) if item.get("revoked_at") else None,
        "status": status,
        "effectiveStatus": effective_status,
    }


def _identity_governance_audit_record(tenant, event_type, actor, payload, *, now=None):
    """Build one immutable, content-minimised identity-governance audit item."""
    occurred_at = int(time.time()) if now is None else now
    event_id = str(uuid.uuid4())
    redacted = {
        "event_type": event_type,
        "actor": actor,
        "tenant_id": tenant,
        "occurred_at": occurred_at,
        "payload": payload,
    }
    return {
        **_item_key(tenant, "BREAK_GLASS_AUDIT", f"{occurred_at:012d}#{event_id}"),
        **redacted,
        "id": event_id,
        "payload_hash": hashlib.sha256(
            json.dumps(redacted, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "ttl": occurred_at + (366 * 24 * 60 * 60),
    }


def _transact_identity_governance(operations):
    """Atomically commit emergency authority and its immutable audit evidence."""
    try:
        DYNAMODB.transact_write_items(TransactItems=operations)
    except Exception as error:
        code = getattr(error, "response", {}).get("Error", {}).get("Code")
        if code in {"ConditionalCheckFailedException", "TransactionCanceledException"}:
            raise PolicyConflict("identity governance state changed concurrently") from error
        raise


def _export_identity_governance_audit(tenant, event_type, actor, payload):
    """Best-effort replicate an already durable governance event into S3 audit."""
    try:
        _audit(tenant, event_type, actor, payload)
    except Exception:
        # DynamoDB transaction evidence is already durable. Do not make a
        # committed authority change look uncommitted because its secondary
        # S3 replication failed; emit only a content-free operational signal.
        print(
            json.dumps(
                {"warning": "identity governance audit replication failed", "event": event_type}
            )
        )


def _agent_lifecycle_audit_record(tenant, event_type, actor, payload, *, now):
    """Build immutable lifecycle evidence committed with the authority change.

    This DynamoDB record is the primary durable evidence. S3 is a secondary
    export, so an audit-bucket outage can never leave a lifecycle transition
    without a reviewable record or falsely report a committed transition as
    failed.
    """
    event_id = str(uuid.uuid4())
    redacted = {
        "event_type": event_type,
        "actor": actor,
        "tenant_id": tenant,
        "occurred_at": now,
        "payload": payload,
    }
    return {
        **_item_key(tenant, "AGENT_LIFECYCLE_AUDIT", f"{now:012d}#{event_id}"),
        **redacted,
        "id": event_id,
        "payload_hash": hashlib.sha256(
            json.dumps(redacted, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def _transact_agent_lifecycle(operations):
    """Atomically commit lifecycle authority, memberships and durable audit."""
    try:
        DYNAMODB.transact_write_items(TransactItems=operations)
    except Exception as error:
        code = getattr(error, "response", {}).get("Error", {}).get("Code")
        if code in {"ConditionalCheckFailedException", "TransactionCanceledException"}:
            raise PolicyConflict("agent lifecycle state changed concurrently") from error
        raise


def _export_agent_lifecycle_audit(tenant, event_type, actor, payload):
    """Best-effort replicate an already durable lifecycle event into S3."""
    try:
        _audit(tenant, event_type, actor, payload)
    except Exception:
        print(
            json.dumps({"warning": "agent lifecycle audit replication failed", "event": event_type})
        )


def _operator_principal(event):
    """Return the server-bound principal used for delegated administration.

    Entra sessions use the immutable directory object identifier emitted by
    the pre-token trigger. Native Cognito sessions fall back to their signed
    ``sub``. Request JSON and browser state are never accepted as principals.
    """
    claims = _claims(event)
    value = claims.get("aai:operator_id") or claims.get("sub")
    if not isinstance(value, str) or not value or len(value) > 256:
        raise PermissionError("authenticated operator principal is required")
    return value


def _delegated_grant_view(item, *, now=None):
    """Return one secret-free delegated authority record with live status."""
    current = int(time.time()) if now is None else now
    status = str(item.get("status", "unknown"))
    effective_status = (
        "expired" if status == "active" and int(item.get("expires_at", 0)) <= current else status
    )
    return {
        "id": item.get("id", ""),
        "principalId": item.get("principal_id", ""),
        "role": item.get("role", ""),
        "scopeType": item.get("scope_type", ""),
        "scopeId": item.get("scope_id", ""),
        "reason": item.get("reason", ""),
        "createdAt": int(item.get("created_at", 0)),
        "createdBy": item.get("created_by", ""),
        "expiresAt": int(item.get("expires_at", 0)),
        "revokedAt": int(item["revoked_at"]) if item.get("revoked_at") else None,
        "revokedBy": item.get("revoked_by") or None,
        "status": status,
        "effectiveStatus": effective_status,
    }


def _delegated_scope_lineage(tenant, scope_type, scope_id):
    """Resolve one tenant-owned scope and its immutable parent lineage."""
    if scope_type not in _DELEGATED_SCOPE_TYPES:
        raise ValueError("delegated scope type is unsupported")
    identifier = _bounded_identifier(scope_id, "scopeId")
    if scope_type == "organization":
        item = TABLE.get_item(Key=_item_key(tenant, "ORG", identifier), ConsistentRead=True).get(
            "Item"
        )
        if not item:
            raise LookupError("delegated organization scope was not found")
        return {"organization": identifier}
    if scope_type == "project":
        item = TABLE.get_item(
            Key=_item_key(tenant, "PROJECT", identifier), ConsistentRead=True
        ).get("Item")
        if not item:
            raise LookupError("delegated project scope was not found")
        organization_id = _bounded_identifier(item.get("organization_id"), "organizationId")
        return {"organization": organization_id, "project": identifier}
    item = TABLE.get_item(Key=_item_key(tenant, "DEPLOYMENT", identifier), ConsistentRead=True).get(
        "Item"
    )
    if not item:
        raise LookupError("delegated deployment scope was not found")
    organization_id = _bounded_identifier(item.get("organization_id"), "organizationId")
    project_id = _bounded_identifier(item.get("project_id"), "projectId")
    return {
        "organization": organization_id,
        "project": project_id,
        "deployment": identifier,
    }


def _delegated_grant_covers(grant, action_scope):
    """Return whether one exact grant contains one resolved action scope."""
    scope_type = grant.get("scope_type")
    scope_id = grant.get("scope_id")
    return scope_type in _DELEGATED_SCOPE_TYPES and action_scope.get(scope_type) == scope_id


def _active_delegated_grants(tenant, event):
    """Resolve live delegated grants for the exact signed operator principal."""
    principal = _operator_principal(event)
    now = int(time.time())
    grants = []
    for item in _list(tenant, "DELEGATED_GRANT", consistent_read=True):
        if (
            item.get("principal_id") == principal
            and item.get("status") == "active"
            and int(item.get("expires_at", 0)) > now
            and item.get("role") in _DELEGATABLE_OPERATOR_ROLES
            and item.get("scope_type") in _DELEGATED_SCOPE_TYPES
        ):
            grants.append(item)
    return grants


def _delegated_operator_authorized(tenant, event, capability, resource_scope):
    """Authorize a capability only when every target is inside a live grant."""
    scopes = resource_scope if isinstance(resource_scope, list) else [resource_scope]
    if not scopes or len(scopes) > 200 or any(not isinstance(scope, dict) for scope in scopes):
        return False
    grants = [
        grant
        for grant in _active_delegated_grants(tenant, event)
        if capability in _ROLE_CAPABILITIES.get(grant.get("role"), frozenset())
    ]
    return bool(grants) and all(
        any(_delegated_grant_covers(grant, scope) for grant in grants) for scope in scopes
    )


def _delegated_grants(tenant):
    """Return the bounded delegated authority ledger ordered newest first."""
    now = int(time.time())
    return sorted(
        (
            _delegated_grant_view(item, now=now)
            for item in _list(tenant, "DELEGATED_GRANT", consistent_read=True)
        ),
        key=lambda item: item["createdAt"],
        reverse=True,
    )


def _create_delegated_grant(tenant, event, body):
    """Create one expiring, server-owned and resource-scoped operator grant."""
    actor = _operator_subject(event)
    actor_principal = _operator_principal(event)
    principal_id = _bounded_text(body.get("principalId"), "principalId", 256)
    if principal_id == actor_principal or principal_id == actor:
        raise PermissionError("an identity administrator cannot delegate authority to themselves")
    if (
        os.environ.get("SCIM_ENABLED") == "true"
        and SCIM is not None
        and os.environ.get("ENTRA_AAI_TENANT_ID") == tenant
    ):
        try:
            principal_id = str(uuid.UUID(principal_id))
        except ValueError as error:
            raise ValueError("delegated Entra principal is malformed") from error
        principal = SCIM.get_item(
            Key={"pk": f"TENANT#{tenant}", "sk": f"USER#{principal_id}"},
            ConsistentRead=True,
        ).get("Item")
        if not principal or principal.get("active") is not True:
            raise ValueError("delegated Entra principal is not actively provisioned")
    role = body.get("role")
    if role not in _DELEGATABLE_OPERATOR_ROLES:
        raise ValueError("delegated role is unsupported")
    scope_type = body.get("scopeType")
    scope_id = _bounded_identifier(body.get("scopeId"), "scopeId")
    _delegated_scope_lineage(tenant, scope_type, scope_id)
    reason = _bounded_text(body.get("reason"), "reason", 500)
    if len(reason) < 20:
        raise ValueError("reason must contain at least 20 characters")
    if re.search(
        r"(?i)(authorization\s*:\s*bearer|-----BEGIN [A-Z ]+PRIVATE KEY-----|"
        r"(?:token|secret|password|api[_ -]?key)\s*[:=]\s*\S+)",
        reason,
    ):
        raise ValueError("reason must not contain credential material")
    duration_days = body.get("durationDays")
    if isinstance(duration_days, bool) or not isinstance(duration_days, int):
        raise ValueError("durationDays must be an integer")
    duration_seconds = duration_days * 24 * 60 * 60
    if not 24 * 60 * 60 <= duration_seconds <= _DELEGATED_GRANT_MAX_SECONDS:
        raise ValueError("durationDays must be between 1 and 366")
    now = int(time.time())
    grant_id = str(uuid.uuid4())
    item = {
        **_item_key(tenant, "DELEGATED_GRANT", grant_id),
        "tenant_id": tenant,
        "id": grant_id,
        "principal_id": principal_id,
        "role": role,
        "scope_type": scope_type,
        "scope_id": scope_id,
        "reason": reason,
        "status": "active",
        "created_at": now,
        "created_by": actor,
        "expires_at": now + duration_seconds,
        "revision": 1,
        # Retain a reviewable record after authority expires.
        "ttl": now + _DELEGATED_GRANT_MAX_SECONDS + (366 * 24 * 60 * 60),
    }
    audit_payload = {
        "grant_id": grant_id,
        "principal_id": principal_id,
        "role": role,
        "scope_type": scope_type,
        "scope_id": scope_id,
        "expires_at": item["expires_at"],
    }
    audit_record = _identity_governance_audit_record(
        tenant, "delegated_grant_created", actor, audit_payload, now=now
    )
    _transact_identity_governance(
        [
            _transaction_put(item, condition="attribute_not_exists(pk)"),
            _transaction_put(audit_record, condition="attribute_not_exists(pk)"),
        ]
    )
    _export_identity_governance_audit(tenant, "delegated_grant_created", actor, audit_payload)
    return _delegated_grant_view(item, now=now)


def _revoke_delegated_grant(tenant, event, grant_id):
    """Conditionally revoke one live delegated grant and audit atomically."""
    actor = _operator_subject(event)
    now = int(time.time())
    key = _item_key(tenant, "DELEGATED_GRANT", _bounded_identifier(grant_id, "grantId"))
    current = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    if not current:
        return None
    revision = int(current.get("revision", 0))
    if (
        revision < 1
        or current.get("status") != "active"
        or int(current.get("expires_at", 0)) <= now
    ):
        raise PolicyConflict("delegated grant is not active")
    updated = {
        **current,
        "status": "revoked",
        "revoked_at": now,
        "revoked_by": actor,
        "revision": revision + 1,
    }
    audit_payload = {
        "grant_id": current.get("id", ""),
        "principal_id": current.get("principal_id", ""),
        "role": current.get("role", ""),
        "scope_type": current.get("scope_type", ""),
        "scope_id": current.get("scope_id", ""),
    }
    audit_record = _identity_governance_audit_record(
        tenant, "delegated_grant_revoked", actor, audit_payload, now=now
    )
    _transact_identity_governance(
        [
            _transaction_put(
                updated,
                condition="#status = :active AND #revision = :revision AND expires_at > :now",
                names={"#status": "status", "#revision": "revision"},
                values={":active": "active", ":revision": revision, ":now": now},
            ),
            _transaction_put(audit_record, condition="attribute_not_exists(pk)"),
        ]
    )
    _export_identity_governance_audit(tenant, "delegated_grant_revoked", actor, audit_payload)
    return _delegated_grant_view(updated, now=now)


def _active_break_glass_capabilities(tenant, event):
    """Resolve unexpired emergency capabilities for the exact signed subject."""
    subject = _operator_subject(event)
    now = int(time.time())
    capabilities = set()
    for item in _list(tenant, "BREAK_GLASS", consistent_read=True):
        if (
            item.get("subject") == subject
            and item.get("status") == "approved"
            and int(item.get("grant_starts_at", 0)) <= now
            and int(item.get("grant_expires_at", 0)) > now
        ):
            values = item.get("capabilities", [])
            if isinstance(values, list):
                capabilities.update(value for value in values if value in _BREAK_GLASS_CAPABILITIES)
    return capabilities


def _create_break_glass_request(tenant, event, body):
    """Create one MFA-bound, self-targeted and time-limited emergency request."""
    _require_recent_strong_authentication(event)
    actor = _operator_subject(event)
    reason = _bounded_text(body.get("reason"), "reason", 500)
    if len(reason) < 20:
        raise ValueError("reason must contain at least 20 characters")
    if re.search(
        r"(?i)(authorization\s*:\s*bearer|-----BEGIN [A-Z ]+PRIVATE KEY-----|"
        r"(?:token|secret|password|api[_ -]?key)\s*[:=]\s*\S+)",
        reason,
    ):
        raise ValueError("reason must not contain credential material")
    capabilities = body.get("capabilities")
    if (
        not isinstance(capabilities, list)
        or not 1 <= len(capabilities) <= len(_BREAK_GLASS_CAPABILITIES)
        or len(capabilities) != len(set(capabilities))
        or any(value not in _BREAK_GLASS_CAPABILITIES for value in capabilities)
    ):
        raise ValueError("capabilities must be a unique supported emergency capability list")
    duration_minutes = body.get("durationMinutes")
    if isinstance(duration_minutes, bool) or not isinstance(duration_minutes, int):
        raise ValueError("durationMinutes must be an integer")
    duration_seconds = duration_minutes * 60
    if not _BREAK_GLASS_MIN_SECONDS <= duration_seconds <= _BREAK_GLASS_MAX_SECONDS:
        raise ValueError("durationMinutes must be between 5 and 60")
    now = int(time.time())
    request_id = str(uuid.uuid4())
    item = {
        **_item_key(tenant, "BREAK_GLASS", request_id),
        "tenant_id": tenant,
        **{
            "id": request_id,
            "subject": actor,
            "capabilities": sorted(capabilities),
            "reason": reason,
            "duration_seconds": duration_seconds,
            "status": "pending",
            "requested_at": now,
            "request_expires_at": now + _BREAK_GLASS_REQUEST_SECONDS,
            "requested_by": actor,
            # Evidence outlives the grant. DynamoDB expiry cannot silently
            # erase a still-authoritative emergency access decision.
            "ttl": now + (366 * 24 * 60 * 60),
            "revision": 1,
        },
    }
    audit_payload = {
        "request_id": request_id,
        "capabilities": sorted(capabilities),
        "duration_seconds": duration_seconds,
    }
    audit_record = _identity_governance_audit_record(
        tenant, "break_glass_requested", actor, audit_payload, now=now
    )
    _transact_identity_governance(
        [
            _transaction_put(item, condition="attribute_not_exists(pk)"),
            _transaction_put(audit_record, condition="attribute_not_exists(pk)"),
        ]
    )
    _export_identity_governance_audit(tenant, "break_glass_requested", actor, audit_payload)
    return _break_glass_view(item, now=now)


def _decide_break_glass_request(tenant, event, request_id, decision):
    """Approve, deny or revoke emergency authority with conditional state change."""
    _require_recent_strong_authentication(event)
    actor = _operator_subject(event)
    if decision not in {"approve", "deny", "revoke"}:
        raise ValueError("break-glass decision is unsupported")
    now = int(time.time())
    key = _item_key(tenant, "BREAK_GLASS", _bounded_identifier(request_id, "requestId"))
    current = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    if not current:
        return None
    if current.get("requested_by") == actor:
        raise PermissionError("break-glass requester cannot decide their own request")
    names = {"#status": "status", "#revision": "revision"}
    expected_revision = int(current.get("revision", 0))
    if expected_revision < 1:
        raise PolicyConflict("break-glass request has no revision authority")
    updated = {**current, "revision": expected_revision + 1}
    if decision in {"approve", "deny"}:
        if current.get("status") != "pending" or int(current.get("request_expires_at", 0)) <= now:
            raise PolicyConflict("break-glass request is no longer pending")
        if decision == "approve":
            updated.update(
                {
                    "status": "approved",
                    "decided_by": actor,
                    "decided_at": now,
                    "approved_by": actor,
                    "approved_at": now,
                    "grant_starts_at": now,
                    "grant_expires_at": now + int(current.get("duration_seconds", 0)),
                }
            )
        else:
            updated.update(
                {
                    "status": "denied",
                    "decided_by": actor,
                    "decided_at": now,
                }
            )
        condition = (
            "#status = :expected_status AND #revision = :expected_revision AND "
            "request_expires_at > :now AND requested_by <> :actor"
        )
        values = {
            ":expected_status": "pending",
            ":expected_revision": expected_revision,
            ":now": now,
            ":actor": actor,
        }
    else:
        if current.get("status") != "approved" or int(current.get("grant_expires_at", 0)) <= now:
            raise PolicyConflict("break-glass grant is not active")
        updated.update({"status": "revoked", "revoked_by": actor, "revoked_at": now})
        condition = (
            "#status = :expected_status AND #revision = :expected_revision AND "
            "grant_expires_at > :now AND requested_by <> :actor"
        )
        values = {
            ":expected_status": "approved",
            ":expected_revision": expected_revision,
            ":actor": actor,
            ":now": now,
        }
    event_type = {
        "approve": "break_glass_approved",
        "deny": "break_glass_denied",
        "revoke": "break_glass_revoked",
    }[decision]
    audit_payload = {
        "request_id": request_id,
        "subject": current.get("subject", ""),
        "capabilities": sorted(current.get("capabilities", [])),
        "grant_expires_at": updated.get("grant_expires_at"),
    }
    audit_record = _identity_governance_audit_record(
        tenant, event_type, actor, audit_payload, now=now
    )
    _transact_identity_governance(
        [
            _transaction_put(updated, condition=condition, names=names, values=values),
            _transaction_put(audit_record, condition="attribute_not_exists(pk)"),
        ]
    )
    _export_identity_governance_audit(tenant, event_type, actor, audit_payload)
    return _break_glass_view(updated, now=now)


def _break_glass_requests(tenant):
    """Return bounded emergency-access evidence ordered newest first."""
    now = int(time.time())
    return sorted(
        (
            _break_glass_view(item, now=now)
            for item in _list(tenant, "BREAK_GLASS", consistent_read=True)
        ),
        key=lambda item: item["requestedAt"],
        reverse=True,
    )


def _access_certification(tenant, event):
    """Build a complete bounded access-review artifact with a stable digest."""
    generated_at = int(time.time())
    scim = _scim_lifecycle(tenant)
    operators = []
    if scim["status"] == "configured":
        result = SCIM.query(
            KeyConditionExpression=Key("pk").eq(f"TENANT#{tenant}"),
            Limit=501,
            ConsistentRead=True,
        )
        items = result.get("Items", [])
        if result.get("LastEvaluatedKey") or len(items) > 500:
            raise RuntimeError("SCIM inventory exceeds the certification bound")
        users = [item for item in items if str(item.get("sk", "")).startswith("USER#")]
        groups = {
            str(item.get("id", "")): item
            for item in items
            if str(item.get("sk", "")).startswith("GROUP#")
        }
        for user in sorted(users, key=lambda item: str(item.get("user_name", "")).lower()):
            user_id = str(user.get("id", ""))
            memberships = SCIM.query(
                KeyConditionExpression=Key("pk").eq(f"TENANT#{tenant}#USER#{user_id}")
                & Key("sk").begins_with("GROUP#"),
                Limit=33,
                ConsistentRead=True,
            )
            member_items = memberships.get("Items", [])
            if memberships.get("LastEvaluatedKey") or len(member_items) > 32:
                raise RuntimeError("SCIM membership exceeds the certification bound")
            group_ids = sorted(
                str(item.get("sk", "")).removeprefix("GROUP#") for item in member_items
            )
            roles = sorted(
                {
                    groups[group_id].get("mapped_role")
                    for group_id in group_ids
                    if group_id in groups
                    and groups[group_id].get("active") is True
                    and groups[group_id].get("mapped_role") in _CANONICAL_OPERATOR_ROLES
                }
            )
            operators.append(
                {
                    "subjectId": user_id,
                    "userName": user.get("user_name", ""),
                    "displayName": user.get("display_name", ""),
                    "active": user.get("active") is True,
                    "groupIds": group_ids,
                    "roles": roles,
                    "lastProvisionedAt": int(user.get("updated_at", 0)),
                }
            )
    artifact = {
        "schemaVersion": 2,
        "tenantId": tenant,
        "identityProvider": "microsoft_entra_id",
        "lifecycleStatus": scim["status"],
        "complete": scim["status"] == "configured",
        "operators": operators,
        "groupMappings": scim["groupMappings"],
        "breakGlass": _break_glass_requests(tenant),
        "delegatedGrants": _delegated_grants(tenant),
        "roleMatrix": [
            {"role": role, "capabilities": sorted(capabilities)}
            for role, capabilities in _ROLE_CAPABILITIES.items()
        ],
    }
    digest = hashlib.sha256(
        json.dumps(_json(artifact), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    actor = _operator_subject(event)
    audit_payload = {
        "content_hash": digest,
        "operator_count": len(operators),
        "delegated_grant_count": len(artifact["delegatedGrants"]),
    }
    audit_record = _identity_governance_audit_record(
        tenant, "access_certification_exported", actor, audit_payload, now=generated_at
    )
    TABLE.put_item(Item=audit_record, ConditionExpression="attribute_not_exists(pk)")
    _export_identity_governance_audit(tenant, "access_certification_exported", actor, audit_payload)
    return {**artifact, "generatedAt": generated_at, "contentHash": digest}


def _enterprise_integrations():
    """Return honest integration posture without exposing destination secrets."""
    return {
        "splunk": {
            "provider": "splunk_hec",
            "status": "stub" if os.environ.get("SPLUNK_STUB_ENABLED") == "true" else "disabled",
            "deliveryVerified": False,
            "description": (
                "Schema and operator workflow placeholder only; no event delivery is configured."
            ),
        }
    }


def _webhook_endpoint(value):
    """Validate one credential-free public HTTPS destination.

    The dedicated delivery worker repeats this validation and resolves DNS
    before every request. Deployment egress controls remain the final boundary
    against DNS rebinding and newly private destinations.
    """
    if not isinstance(value, str) or len(value) > 2_048:
        raise ValueError("webhook endpoint must be a bounded HTTPS URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.port not in {None, 443}
    ):
        raise ValueError("webhook endpoint must be credential-free HTTPS on port 443")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError("webhook endpoint must use a public DNS name")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host or len(host) > 253:
            raise ValueError("webhook endpoint must use a public DNS name") from None
    else:
        if not address.is_global:
            raise ValueError("webhook endpoint must not use a private address")
    return value


def _webhook_events(value):
    """Return a sorted non-empty set of supported content-minimised events."""
    if (
        not isinstance(value, list)
        or not value
        or len(value) > len(_WEBHOOK_EVENT_TYPES)
        or any(not isinstance(item, str) for item in value)
    ):
        raise ValueError("webhook eventTypes must be a bounded non-empty list")
    events = frozenset(value)
    if len(events) != len(value) or not events <= _WEBHOOK_EVENT_TYPES:
        raise ValueError("webhook eventTypes contain duplicates or unsupported values")
    return sorted(events)


def _webhook_secret_name(tenant, destination_id):
    """Return the deployment-owned tenant namespace for one signing secret."""
    prefix = os.environ.get("WEBHOOK_SECRET_PREFIX", "")
    if not prefix or not prefix.endswith("/") or len(prefix) > 256:
        raise RuntimeError("webhook secret namespace is not configured")
    return f"{prefix}{tenant}/{destination_id}"


def _webhook_key_material():
    """Generate a one-time HMAC secret and non-secret key identifier."""
    return f"key-{uuid.uuid4()}", secrets.token_urlsafe(32)


def _webhook_destination_view(item, *, health=None, now=None):
    """Project one destination without secret names, versions, or key bytes."""
    current = int(time.time()) if now is None else int(now)
    posture = health if isinstance(health, dict) else {}
    previous_until = item.get("previous_key_valid_until")
    rotating = (
        item.get("status") == "active"
        and isinstance(previous_until, int)
        and previous_until > current
    )
    return {
        "id": item.get("id", ""),
        "name": item.get("name", ""),
        "description": item.get("description", ""),
        "endpoint": item.get("endpoint", ""),
        "eventTypes": sorted(item.get("event_types", [])),
        "status": item.get("status", "disabled"),
        "revision": int(item.get("revision", 0)),
        "activeKeyId": item.get("active_key_id", ""),
        "previousKeyId": item.get("previous_key_id") if rotating else None,
        "previousKeyValidUntil": previous_until if rotating else None,
        "createdAt": int(item.get("created_at", 0)),
        "createdBy": item.get("created_by", ""),
        "updatedAt": int(item.get("updated_at", 0)),
        "updatedBy": item.get("updated_by", ""),
        "lastDeliveryAt": posture.get("last_delivery_at"),
        "lastDeliveryStatus": posture.get("last_delivery_status", "never"),
    }


def _webhook_destination(tenant, destination_id):
    """Strongly read one tenant-scoped webhook destination."""
    return TABLE.get_item(
        Key=_item_key(tenant, "WEBHOOK", _bounded_identifier(destination_id, "webhookId")),
        ConsistentRead=True,
    ).get("Item")


def _webhook_destination_health(tenant, destination_id):
    """Strongly read the worker-owned, content-free destination projection."""
    return TABLE.get_item(
        Key=_item_key(
            tenant,
            "WEBHOOK_HEALTH",
            _bounded_identifier(destination_id, "webhookId"),
        ),
        ConsistentRead=True,
    ).get("Item")


def _create_webhook_destination(tenant, value, actor):
    """Create a destination and return its signing secret exactly once."""
    if not isinstance(value, dict) or set(value) != {
        "name",
        "description",
        "endpoint",
        "eventTypes",
    }:
        raise ValueError("webhook destination request has an invalid schema")
    if len(_list(tenant, "WEBHOOK", consistent_read=True)) >= _WEBHOOK_DESTINATION_LIMIT:
        raise PolicyConflict("webhook destination limit reached")
    destination_id = str(uuid.uuid4())
    name = _bounded_text(value.get("name"), "name", 120)
    raw_description = value.get("description", "")
    if (
        not isinstance(raw_description, str)
        or len(raw_description.strip()) > 500
        or any(ord(char) < 32 for char in raw_description.strip())
    ):
        raise ValueError("description must be bounded text")
    description = raw_description.strip()
    endpoint = _webhook_endpoint(value.get("endpoint"))
    events = _webhook_events(value.get("eventTypes"))
    key_id, secret = _webhook_key_material()
    secret_name = _webhook_secret_name(tenant, destination_id)
    kms_key = os.environ.get("WEBHOOK_SECRET_KMS_KEY_ARN", "")
    if not kms_key:
        raise RuntimeError("webhook secret encryption key is not configured")
    secret_response = SECRETS_MANAGER.create_secret(
        Name=secret_name,
        Description="AAI Security tenant webhook signing key",
        KmsKeyId=kms_key,
        SecretString=json.dumps(
            {"schemaVersion": 1, "keyId": key_id, "secret": secret},
            separators=(",", ":"),
        ),
    )
    version_id = secret_response.get("VersionId")
    secret_arn = secret_response.get("ARN")
    if not isinstance(version_id, str) or not version_id or not isinstance(secret_arn, str):
        raise RuntimeError("Secrets Manager returned incomplete webhook key evidence")
    now = int(time.time())
    record = {
        **_item_key(tenant, "WEBHOOK", destination_id),
        "tenant_id": tenant,
        "id": destination_id,
        "name": name,
        "description": description,
        "endpoint": endpoint,
        "event_types": events,
        "status": "active",
        "revision": 1,
        "secret_arn": secret_arn,
        "active_key_id": key_id,
        "active_secret_version": version_id,
        "previous_key_id": None,
        "previous_secret_version": None,
        "previous_key_valid_until": None,
        "created_at": now,
        "created_by": actor,
        "updated_at": now,
        "updated_by": actor,
        "last_delivery_status": "never",
    }
    try:
        TABLE.put_item(Item=record, ConditionExpression="attribute_not_exists(pk)")
    except Exception:
        # The key has not become authority if its destination record failed.
        # Recovery-window deletion keeps the cleanup reversible.
        SECRETS_MANAGER.delete_secret(SecretId=secret_arn, RecoveryWindowInDays=7)
        raise
    _audit(
        tenant,
        "webhook_destination_created",
        actor,
        {
            "webhook_id": destination_id,
            "endpoint_host": urlsplit(endpoint).hostname,
            "event_types": events,
            "key_id": key_id,
            "revision": 1,
        },
    )
    return {
        "destination": _webhook_destination_view(record, now=now),
        "signingSecret": {"keyId": key_id, "secret": secret},
    }


def _rotate_webhook_destination(tenant, destination_id, value, actor):
    """Activate a new key while retaining the previous key for bounded overlap."""
    if not isinstance(value, dict) or set(value) != {"expectedRevision", "overlapSeconds"}:
        raise ValueError("webhook rotation request has an invalid schema")
    current = _webhook_destination(tenant, destination_id)
    if not current or current.get("status") == "retired":
        raise LookupError("webhook destination not found")
    expected = _discovery_integer(value.get("expectedRevision"), "expectedRevision", minimum=1)
    if int(current.get("revision", 0)) != expected:
        raise PolicyConflict("webhook destination revision is stale")
    overlap = _discovery_integer(
        value.get("overlapSeconds"),
        "overlapSeconds",
        minimum=_WEBHOOK_ROTATION_MIN_SECONDS,
        maximum=_WEBHOOK_ROTATION_MAX_SECONDS,
    )
    key_id, secret = _webhook_key_material()
    secret_response = SECRETS_MANAGER.put_secret_value(
        SecretId=current.get("secret_arn", ""),
        SecretString=json.dumps(
            {"schemaVersion": 1, "keyId": key_id, "secret": secret},
            separators=(",", ":"),
        ),
    )
    version_id = secret_response.get("VersionId")
    if not isinstance(version_id, str) or not version_id:
        raise RuntimeError("Secrets Manager returned incomplete webhook rotation evidence")
    now = int(time.time())
    overlap_active = (
        isinstance(current.get("previous_key_valid_until"), int)
        and current["previous_key_valid_until"] > now
        and isinstance(current.get("previous_key_id"), str)
        and isinstance(current.get("previous_secret_version"), str)
    )
    # A response can be lost after a new version becomes active. A recovery
    # rotation during the overlap must keep signing with the original receiver-
    # known key rather than replacing it with the undisclosed intermediate key.
    previous_key_id = (
        current.get("previous_key_id") if overlap_active else current.get("active_key_id")
    )
    previous_secret_version = (
        current.get("previous_secret_version")
        if overlap_active
        else current.get("active_secret_version")
    )
    previous_valid_until = max(
        int(current.get("previous_key_valid_until", 0)) if overlap_active else 0,
        now + overlap,
    )
    updated = {
        **current,
        "revision": expected + 1,
        "active_key_id": key_id,
        "active_secret_version": version_id,
        "previous_key_id": previous_key_id,
        "previous_secret_version": previous_secret_version,
        "previous_key_valid_until": previous_valid_until,
        "updated_at": now,
        "updated_by": actor,
    }
    try:
        TABLE.put_item(
            Item=updated,
            ConditionExpression="revision = :expected_revision",
            ExpressionAttributeValues={":expected_revision": expected},
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("webhook destination changed during rotation") from error
        raise
    _audit(
        tenant,
        "webhook_signing_key_rotated",
        actor,
        {
            "webhook_id": current.get("id"),
            "key_id": key_id,
            "previous_key_id": previous_key_id,
            "previous_key_valid_until": previous_valid_until,
            "revision": expected + 1,
        },
    )
    return {
        "destination": _webhook_destination_view(updated, now=now),
        "signingSecret": {"keyId": key_id, "secret": secret},
    }


def _set_webhook_destination_status(tenant, destination_id, action, value, actor):
    """Pause, resume, or retire one destination with optimistic concurrency."""
    if action not in {"pause", "resume", "retire"}:
        raise ValueError("webhook status action is unsupported")
    if not isinstance(value, dict) or set(value) != {"expectedRevision", "reason"}:
        raise ValueError("webhook status request has an invalid schema")
    current = _webhook_destination(tenant, destination_id)
    if not current:
        raise LookupError("webhook destination not found")
    expected = _discovery_integer(value.get("expectedRevision"), "expectedRevision", minimum=1)
    reason = _bounded_text(value.get("reason"), "reason", 500)
    if len(reason) < 20:
        raise ValueError("webhook status reason must contain at least 20 characters")
    if (
        action == "retire"
        and current.get("status") == "retired"
        and int(current.get("revision", 0)) == expected + 1
        and current.get("status_reason") == reason
    ):
        # Recover an API failure after retirement authority committed but
        # before secret cleanup or the response completed.
        if not current.get("secret_deletion_requested_at"):
            SECRETS_MANAGER.delete_secret(
                SecretId=current.get("secret_arn", ""), RecoveryWindowInDays=7
            )
            current = {
                **current,
                "secret_deletion_requested_at": int(time.time()),
            }
            TABLE.put_item(
                Item=current,
                ConditionExpression="revision = :expected_revision",
                ExpressionAttributeValues={":expected_revision": expected + 1},
            )
        return _webhook_destination_view(current)
    if int(current.get("revision", 0)) != expected:
        raise PolicyConflict("webhook destination revision is stale")
    target = {"pause": "paused", "resume": "active", "retire": "retired"}[action]
    if current.get("status") == "retired":
        raise PolicyConflict("retired webhook destinations cannot be changed")
    now = int(time.time())
    updated = {
        **current,
        "status": target,
        "revision": expected + 1,
        "updated_at": now,
        "updated_by": actor,
        "status_reason": reason,
    }
    try:
        TABLE.put_item(
            Item=updated,
            ConditionExpression="revision = :expected_revision",
            ExpressionAttributeValues={":expected_revision": expected},
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("webhook destination changed during status update") from error
        raise
    if target == "retired":
        SECRETS_MANAGER.delete_secret(
            SecretId=current.get("secret_arn", ""), RecoveryWindowInDays=7
        )
        updated["secret_deletion_requested_at"] = now
        TABLE.put_item(
            Item=updated,
            ConditionExpression="revision = :expected_revision",
            ExpressionAttributeValues={":expected_revision": expected + 1},
        )
    _audit(
        tenant,
        f"webhook_destination_{target}",
        actor,
        {"webhook_id": current.get("id"), "reason": reason, "revision": expected + 1},
    )
    return _webhook_destination_view(updated, now=now)


def _webhook_delivery_view(item):
    """Project content-free delivery evidence for operators."""
    return {
        "id": item.get("id", ""),
        "destinationId": item.get("destination_id", ""),
        "eventType": item.get("event_type", ""),
        "status": item.get("status", "pending"),
        "attemptCount": int(item.get("attempt_count", 0)),
        "createdAt": int(item.get("created_at", 0)),
        "lastAttemptAt": item.get("last_attempt_at"),
        "deliveredAt": item.get("delivered_at"),
        "responseStatus": item.get("response_status"),
        "failureCode": item.get("failure_code"),
    }


def _enqueue_webhook_delivery(
    tenant, destination, event_type, event_data, *, now=None, delivery_id=None
):
    """Persist one outbox record before attempting its SQS dispatch."""
    if event_type not in _WEBHOOK_EVENT_TYPES or event_type not in destination.get(
        "event_types", []
    ):
        return None
    current = int(time.time()) if now is None else int(now)
    delivery_id = (
        _bounded_identifier(delivery_id, "deliveryId")
        if delivery_id is not None
        else str(uuid.uuid4())
    )
    payload = {
        "schemaVersion": 1,
        "id": delivery_id,
        "type": event_type,
        "createdAt": current,
        "tenantId": tenant,
        "data": _json(event_data),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > 16_384:
        raise ValueError("webhook event exceeds the content-minimised delivery bound")
    record = {
        **_item_key(tenant, "WEBHOOK_DELIVERY", delivery_id),
        "tenant_id": tenant,
        "id": delivery_id,
        "destination_id": destination.get("id"),
        "event_type": event_type,
        "payload": encoded.decode(),
        "status": "pending",
        "attempt_count": 0,
        "created_at": current,
        "webhook_outbox_pk": f"WEBHOOK_OUTBOX#{tenant}",
        "webhook_outbox_sk": f"{current:010d}#{delivery_id}",
        "ttl": current + 30 * 24 * 60 * 60,
    }
    TABLE.put_item(Item=record, ConditionExpression="attribute_not_exists(pk)")
    _dispatch_webhook_delivery(record)
    return _webhook_delivery_view(record)


def _dispatch_webhook_delivery(record):
    """Send one persisted outbox identity to the dedicated worker queue."""
    queue_url = os.environ.get("WEBHOOK_QUEUE_URL", "")
    if not queue_url:
        return False
    try:
        SQS.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(
                {
                    "schemaVersion": 1,
                    "tenantId": record.get("tenant_id"),
                    "deliveryId": record.get("id"),
                },
                separators=(",", ":"),
            ),
            MessageGroupId=str(record.get("tenant_id")),
            MessageDeduplicationId=str(record.get("id")),
        )
        queued = {
            key: value
            for key, value in record.items()
            if key not in {"webhook_outbox_pk", "webhook_outbox_sk"}
        }
        queued.update({"status": "queued", "queued_at": int(time.time())})
        try:
            TABLE.put_item(
                Item=queued,
                ConditionExpression="#status = :pending",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={":pending": "pending"},
            )
        except Exception:
            # SQS already owns a deduplicated delivery identity. The worker
            # reloads the outbox and can complete it from either pending or
            # queued state; the scheduler may safely retry after dedupe expiry.
            return True
        return True
    except Exception:
        # DynamoDB is the outbox authority. A scheduled dispatcher will retry;
        # do not leak queue/provider exception text into logs.
        return False


def _test_webhook_destination(tenant, destination_id, value, actor):
    """Queue a server-owned synthetic event without accepting arbitrary content."""
    if not isinstance(value, dict) or set(value) != {"expectedRevision"}:
        raise ValueError("webhook test request has an invalid schema")
    destination = _webhook_destination(tenant, destination_id)
    if not destination or destination.get("status") == "retired":
        raise LookupError("webhook destination not found")
    expected = _discovery_integer(value.get("expectedRevision"), "expectedRevision", minimum=1)
    if int(destination.get("revision", 0)) != expected:
        raise PolicyConflict("webhook destination revision is stale")
    if destination.get("status") != "active":
        raise PolicyConflict("webhook destination must be active for testing")
    delivery = _enqueue_webhook_delivery(
        tenant,
        destination,
        "webhook.test",
        {"message": "AAI Security webhook verification event"},
    )
    if delivery is None:
        raise PolicyConflict("webhook.test is not enabled for this destination")
    _audit(
        tenant,
        "webhook_test_queued",
        actor,
        {"webhook_id": destination_id, "delivery_id": delivery["id"]},
    )
    return delivery


def _webhook_dispatch_cycle():
    """Retry bounded persisted outbox records not previously accepted by SQS."""
    registrations = []
    for shard in range(_ENDPOINT_DETECTION_SHARDS):
        result = TABLE.query(
            IndexName=_ENDPOINT_DETECTION_INDEX,
            KeyConditionExpression=Key("endpoint_detection_pk").eq(
                f"ENDPOINT_DETECTION#{shard:02d}"
            ),
            Limit=250,
        )
        if result.get("LastEvaluatedKey"):
            raise RuntimeError("webhook tenant shard exceeds its safe bound")
        registrations.extend(result.get("Items", []))
        if len(registrations) > _ENDPOINT_DETECTION_TENANT_LIMIT:
            raise RuntimeError("webhook tenant inventory exceeds its safe bound")
    dispatched = 0
    for registration in registrations:
        tenant = registration.get("endpoint_detection_sk")
        if not isinstance(tenant, str) or registration.get("pk") != f"TENANT#{tenant}":
            raise RuntimeError("webhook tenant registration is invalid")
        result = TABLE.query(
            IndexName=_WEBHOOK_OUTBOX_INDEX,
            KeyConditionExpression=Key("webhook_outbox_pk").eq(f"WEBHOOK_OUTBOX#{tenant}"),
            Limit=101,
        )
        pending = result.get("Items", [])
        if result.get("LastEvaluatedKey") or len(pending) > 100:
            raise RuntimeError("webhook outbox exceeds its per-tenant dispatch bound")
        for delivery in pending:
            if _dispatch_webhook_delivery(delivery):
                dispatched += 1
    return {"processedTenants": len(registrations), "dispatchedDeliveries": dispatched}


def _body(event):
    try:
        return json.loads(event.get("body") or "{}")
    except json.JSONDecodeError as error:
        raise ValueError("Malformed JSON") from error


def _agent_telemetry(value):
    """Validate the fixed aggregate telemetry schema stored with an agent."""
    if value is None:
        return None
    if not isinstance(value, dict) or len(value) > len(_AGENT_TELEMETRY_FIELDS):
        raise ValueError("agent telemetry must be a bounded object")
    result = {}
    for key, item in value.items():
        if key not in _AGENT_TELEMETRY_FIELDS:
            raise ValueError("agent telemetry contains an unsupported field")
        if key in _AGENT_TELEMETRY_INTEGER_FIELDS:
            if isinstance(item, bool) or not isinstance(item, int):
                raise ValueError("agent telemetry count fields must be integers")
        elif isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ValueError("agent telemetry latency fields must be numeric")
        if not math.isfinite(float(item)) or item < 0 or item > 1_000_000_000:
            raise ValueError("agent telemetry value is out of bounds")
        result[key] = item
    return result


_MANAGED_HOST_BASE_FIELDS = {
    "host",
    "hostVersion",
    "platform",
    "bundleHash",
    "policyId",
    "policyVersion",
}
_MANAGED_TRUST_FIELD = "policyTrustBundleSha256"
_MANAGED_HOST_FIELDS = _MANAGED_HOST_BASE_FIELDS | {_MANAGED_TRUST_FIELD}
_MANAGED_REPORT_BASE_FIELDS = _MANAGED_HOST_BASE_FIELDS | {
    "source",
    "verifiedAt",
    "expiresAt",
}
_MANAGED_REPORT_FIELDS = _MANAGED_HOST_FIELDS | {"source", "verifiedAt", "expiresAt"}
_MANAGED_SOURCES = {
    "claude-server-managed",
    "endpoint-managed-file",
    "mdm",
    "codex-system",
    "codex-cloud",
    "codex-mdm",
}
_MAX_MANAGED_PACKAGE_BYTES = 280 * 1024
_MANAGED_PACKAGE_FIELDS_V1 = {
    "schemaVersion",
    "host",
    "hostVersion",
    "platform",
    "policyId",
    "policyVersion",
    "bundleHash",
    "artifacts",
    "requiredExecutables",
}
_MANAGED_PACKAGE_FIELDS_V2 = _MANAGED_PACKAGE_FIELDS_V1 | {"policyTrust"}
_ROLLOUT_STATES = frozenset(
    {
        "staged",
        "scheduled",
        "canary",
        "active",
        "paused",
        "rolling_back",
        "converged",
        "drifted",
    }
)
_ROLLOUT_ACTIVE_STATES = frozenset({"canary", "active", "rolling_back"})
_ROLLOUT_CHANNELS = frozenset({"stable", "preview", "emergency"})
_ROLLOUT_RINGS = frozenset({"canary", "broad"})
_ROLLOUT_BATCH_LIMIT = 20
_ROLLOUT_CONFIGURATION_LIMIT = 5_000
_ROLLOUT_MAX_SCHEDULE_SECONDS = 30 * 24 * 60 * 60
_ROLLOUT_DEFAULT_CRITERIA = {
    "maxUnavailablePercent": 10,
    "maxDriftPercent": 10,
    "minSampleSize": 1,
    "gracePeriodSeconds": 600,
}


class ManagedPackageConflict(RuntimeError):
    """Raised when package desired state, revision or rollout state conflicts."""


class ManagedPackageNotFound(LookupError):
    """Raised when no package exists for an otherwise valid deployment."""


def _managed_integer(value, name, *, positive=False):
    """Normalize exact DynamoDB integers without accepting booleans or fractions."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be {'positive' if positive else 'non-negative'}")
    if isinstance(value, Decimal):
        if value != value.to_integral_value():
            raise ValueError(f"{name} must be {'positive' if positive else 'non-negative'}")
        value = int(value)
    if not isinstance(value, int) or value < (1 if positive else 0):
        raise ValueError(f"{name} must be {'positive' if positive else 'non-negative'}")
    return value


def _managed_host(value, *, report=False):
    """Validate desired or endpoint-observed managed host configuration."""
    expected = (
        (_MANAGED_REPORT_BASE_FIELDS, _MANAGED_REPORT_FIELDS)
        if report
        else (_MANAGED_HOST_BASE_FIELDS, _MANAGED_HOST_FIELDS)
    )
    if not isinstance(value, dict) or frozenset(value) not in {
        frozenset(fields) for fields in expected
    }:
        raise ValueError("managed host configuration has an invalid schema")
    host = _agent_host(value.get("host"))
    platform = _bounded_text(value.get("platform"), "platform", 16)
    bundle_hash = _bounded_text(value.get("bundleHash"), "bundleHash", 64)
    policy_version = _managed_integer(
        value.get("policyVersion"), "managed host policyVersion", positive=True
    )
    if platform not in {"macos", "linux", "windows"}:
        raise ValueError("managed host platform is unsupported")
    if not re.fullmatch(r"[0-9a-f]{64}", bundle_hash):
        raise ValueError("managed host bundleHash must be lowercase SHA-256")
    result = {
        "host": host,
        "hostVersion": _bounded_text(value.get("hostVersion"), "hostVersion", 64),
        "platform": platform,
        "bundleHash": bundle_hash,
        "policyId": _bounded_identifier(value.get("policyId"), "policyId"),
        "policyVersion": policy_version,
    }
    if _MANAGED_TRUST_FIELD in value:
        trust_digest = _bounded_text(value.get(_MANAGED_TRUST_FIELD), _MANAGED_TRUST_FIELD, 64)
        if not re.fullmatch(r"[0-9a-f]{64}", trust_digest):
            raise ValueError("managed host policy trust must be lowercase SHA-256")
        result[_MANAGED_TRUST_FIELD] = trust_digest
    if report:
        source = _bounded_text(value.get("source"), "source", 64)
        verified_at = _managed_integer(value.get("verifiedAt"), "managed configuration verifiedAt")
        expires_at = _managed_integer(value.get("expiresAt"), "managed configuration expiresAt")
        if source not in _MANAGED_SOURCES:
            raise ValueError("managed configuration source is unsupported")
        if expires_at <= verified_at:
            raise ValueError("managed configuration timestamps are invalid")
        result.update({"source": source, "verifiedAt": verified_at, "expiresAt": expires_at})
    return result


def _reject_duplicate_package_keys(pairs):
    """Reject duplicate keys before package fields can be interpreted as authority."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("managed package contains duplicate keys")
        result[key] = value
    return result


def _expected_managed_artifacts(host, platform):
    """Return the exact managed file paths supported by the SDK package schema."""
    if host == "claude-code":
        root = {
            "macos": "/Library/Application Support/ClaudeCode",
            "linux": "/etc/claude-code",
            "windows": r"C:\Program Files\ClaudeCode",
        }[platform]
        return (
            (f"{root}/managed-settings.json", "application/json"),
            (f"{root}/managed-mcp.json", "application/json"),
        )
    return (
        (
            r"C:\ProgramData\OpenAI\Codex\requirements.toml"
            if platform == "windows"
            else "/etc/codex/requirements.toml",
            "application/toml",
        ),
    )


def _expected_policy_trust_path(platform):
    """Return the sole administrator-owned signer trust path."""
    return (
        r"C:\Program Files\AAI Security\trust\policy-signing.json"
        if platform == "windows"
        else "/opt/aai-security/trust/policy-signing.json"
    )


def _required_policy_trust_key_ids():
    """Return the deployment-owned old/new/replica trust identities."""
    active = os.environ.get("POLICY_SIGNING_KEY_ARN", "")
    staged = os.environ.get("REGIONAL_POLICY_SIGNING_KEY_ARN", "")
    recovery_region = os.environ.get("RECOVERY_REGION", "")
    staged_match = re.fullmatch(
        r"(arn:(?:aws|aws-us-gov|aws-cn):kms:)[a-z0-9-]+(:[0-9]{12}:key/mrk-[0-9a-f]{32})",
        staged,
    )
    if (
        not re.fullmatch(
            r"arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}",
            active,
        )
        or staged_match is None
        or not re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]", recovery_region)
    ):
        raise ValueError("managed policy trust deployment authority is unavailable")
    replica = f"{staged_match.group(1)}{recovery_region}{staged_match.group(2)}"
    return {active, staged, replica}


def _managed_package(package_base64, expected_digest):
    """Decode and independently validate one canonical credential-free package."""
    if (
        not isinstance(package_base64, str)
        or len(package_base64) > (_MAX_MANAGED_PACKAGE_BYTES * 4 // 3) + 8
        or not isinstance(expected_digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_digest)
    ):
        raise ValueError("managed package transport fields are invalid")
    try:
        encoded = base64.b64decode(package_base64, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("managed package base64 is invalid") from error
    if not encoded or len(encoded) > _MAX_MANAGED_PACKAGE_BYTES:
        raise ValueError("managed package exceeds the control-plane size limit")
    if not secrets.compare_digest(hashlib.sha256(encoded).hexdigest(), expected_digest):
        raise ValueError("managed package digest does not match")
    try:
        value = json.loads(
            encoded.decode("utf-8"), object_pairs_hook=_reject_duplicate_package_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("managed package is malformed") from error
    schema_version = value.get("schemaVersion") if isinstance(value, dict) else None
    if not isinstance(value, dict) or (
        schema_version == 1
        and set(value) != _MANAGED_PACKAGE_FIELDS_V1
        or schema_version == 2
        and set(value) != _MANAGED_PACKAGE_FIELDS_V2
        or schema_version not in {1, 2}
    ):
        raise ValueError("managed package schema is invalid")
    canonical = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    if canonical != encoded:
        raise ValueError("managed package is not canonical")
    target = _managed_host(
        {
            "host": value.get("host"),
            "hostVersion": value.get("hostVersion"),
            "platform": value.get("platform"),
            "bundleHash": value.get("bundleHash"),
            "policyId": value.get("policyId"),
            "policyVersion": value.get("policyVersion"),
        }
    )
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", target["hostVersion"]):
        raise ValueError("managed package host version is invalid")
    artifacts = value.get("artifacts")
    expected_artifacts = _expected_managed_artifacts(target["host"], target["platform"])
    if not isinstance(artifacts, list) or len(artifacts) != len(expected_artifacts):
        raise ValueError("managed package artifact set is incomplete")
    for artifact, (expected_path, expected_media_type) in zip(
        artifacts, expected_artifacts, strict=True
    ):
        if not isinstance(artifact, dict) or set(artifact) != {
            "path",
            "mediaType",
            "content",
            "sha256",
        }:
            raise ValueError("managed package artifact schema is invalid")
        content = artifact.get("content")
        digest = artifact.get("sha256")
        if (
            artifact.get("path") != expected_path
            or artifact.get("mediaType") != expected_media_type
            or not isinstance(content, str)
            or not content
            or len(content.encode("utf-8")) > 1_000_000
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not secrets.compare_digest(hashlib.sha256(content.encode()).hexdigest(), digest)
        ):
            raise ValueError("managed package artifact is invalid")
    executables = value.get("requiredExecutables")
    if not isinstance(executables, list) or not 1 <= len(executables) <= 8:
        raise ValueError("managed package executables are invalid")
    expected_prefix = (
        "C:\\Program Files\\AAI Security\\"
        if target["platform"] == "windows"
        else "/opt/aai-security/"
    )
    executable_paths = []
    for executable in executables:
        if not isinstance(executable, dict) or set(executable) != {"path", "sha256"}:
            raise ValueError("managed package executable schema is invalid")
        path = executable.get("path")
        digest = executable.get("sha256")
        if (
            not isinstance(path, str)
            or not path.startswith(expected_prefix)
            or ".." in re.split(r"[/\\]", path)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ValueError("managed package executable is invalid")
        executable_paths.append(path)
    if len(executable_paths) != len(set(executable_paths)):
        raise ValueError("managed package executable paths are ambiguous")
    if schema_version == 2:
        trust = value.get("policyTrust")
        if not isinstance(trust, dict) or set(trust) != {
            "path",
            "mediaType",
            "content",
            "sha256",
        }:
            raise ValueError("managed package policy trust schema is invalid")
        trust_content = trust.get("content")
        trust_digest = trust.get("sha256")
        if (
            trust.get("path") != _expected_policy_trust_path(target["platform"])
            or trust.get("mediaType") != "application/json"
            or not isinstance(trust_content, str)
            or not trust_content
            or len(trust_content.encode("utf-8")) > 128_000
            or not isinstance(trust_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", trust_digest)
            or not secrets.compare_digest(
                hashlib.sha256(trust_content.encode("utf-8")).hexdigest(), trust_digest
            )
        ):
            raise ValueError("managed package policy trust artifact is invalid")
        try:
            trust_value = json.loads(
                trust_content, object_pairs_hook=_reject_duplicate_package_keys
            )
        except json.JSONDecodeError as error:
            raise ValueError("managed package policy trust is malformed") from error
        if (
            not isinstance(trust_value, dict)
            or set(trust_value) != {"schemaVersion", "keys"}
            or trust_value.get("schemaVersion") != 1
            or not isinstance(trust_value.get("keys"), list)
            or not 1 <= len(trust_value["keys"]) <= 8
            or json.dumps(trust_value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            != trust_content
        ):
            raise ValueError("managed package policy trust is not canonical")
        key_ids = []
        for item in trust_value["keys"]:
            if (
                not isinstance(item, dict)
                or set(item) != {"keyId", "algorithm", "publicKeyPem"}
                or item.get("algorithm") != "ECDSA_SHA_256"
                or not isinstance(item.get("keyId"), str)
                or not isinstance(item.get("publicKeyPem"), str)
                or not item["publicKeyPem"].startswith("-----BEGIN PUBLIC KEY-----\n")
                or not item["publicKeyPem"].endswith("-----END PUBLIC KEY-----\n")
                or not 100 <= len(item["publicKeyPem"]) <= 2_000
            ):
                raise ValueError("managed package policy trust key is invalid")
            key_ids.append(item["keyId"])
        if len(key_ids) != len(set(key_ids)) or set(key_ids) != _required_policy_trust_key_ids():
            raise ValueError("managed package policy trust identities are not deployment-owned")
        target[_MANAGED_TRUST_FIELD] = trust_digest
    return value, target, encoded


def _desired_managed_host(tenant, deployment_id):
    """Load current server-owned managed target for one deployment."""
    configuration = TABLE.get_item(
        Key=_item_key(tenant, "CONFIGURATION", deployment_id), ConsistentRead=True
    ).get("Item")
    desired_configuration = configuration.get("desiredConfiguration", {}) if configuration else {}
    desired = (
        desired_configuration.get("managedHost")
        if isinstance(desired_configuration, dict)
        else None
    )
    if not isinstance(desired, dict):
        raise ValueError("deployment has no managed-host desired state")
    return _managed_host(desired), configuration


def _managed_package_metadata(tenant, deployment_id, package=None):
    """Return content-free package metadata with live current/stale status."""
    package = package or TABLE.get_item(
        Key=_item_key(tenant, "MANAGED_PACKAGE", deployment_id), ConsistentRead=True
    ).get("Item")
    if not package:
        raise ManagedPackageNotFound("managed deployment package not found")
    desired, _configuration = _desired_managed_host(tenant, deployment_id)
    target = {
        "host": package.get("host"),
        "hostVersion": package.get("hostVersion"),
        "platform": package.get("platform"),
        "bundleHash": package.get("bundleHash"),
        "policyId": package.get("policyId"),
        "policyVersion": _managed_integer(
            package.get("policyVersion"), "managed package policyVersion", positive=True
        ),
        **(
            {_MANAGED_TRUST_FIELD: package.get(_MANAGED_TRUST_FIELD)}
            if package.get(_MANAGED_TRUST_FIELD) is not None
            else {}
        ),
    }
    return {
        "revision": _managed_integer(
            package.get("revision"), "managed package revision", positive=True
        ),
        "status": "current" if target == desired else "stale",
        "packageSha256": package.get("packageSha256"),
        "bundleHash": package.get("bundleHash"),
        "host": package.get("host"),
        "hostVersion": package.get("hostVersion"),
        "platform": package.get("platform"),
        "policyId": package.get("policyId"),
        "policyVersion": target["policyVersion"],
        **(
            {_MANAGED_TRUST_FIELD: target[_MANAGED_TRUST_FIELD]}
            if _MANAGED_TRUST_FIELD in target
            else {}
        ),
        "publishedAt": _managed_integer(package.get("publishedAt"), "publishedAt"),
        "publishedBy": package.get("publishedBy"),
    }


def _publish_managed_package(tenant, deployment_id, body, actor):
    """Compare-and-swap one package after exact desired-state validation."""
    if not isinstance(body, dict) or set(body) != {
        "expectedRevision",
        "packageBase64",
        "packageSha256",
    }:
        raise ValueError("managed package request schema is invalid")
    expected_revision = _managed_integer(
        body.get("expectedRevision"), "managed package expectedRevision"
    )
    package_value, target, encoded = _managed_package(
        body.get("packageBase64"), body.get("packageSha256")
    )
    desired, _configuration = _desired_managed_host(tenant, deployment_id)
    if target != desired:
        raise ValueError("managed package does not match deployment desired state")
    deployment = TABLE.get_item(
        Key=_item_key(tenant, "DEPLOYMENT", deployment_id), ConsistentRead=True
    ).get("Item")
    if not deployment:
        raise ManagedPackageNotFound("deployment not found")
    agents = [
        item
        for item in _list(tenant, "AGENT", consistent_read=True)
        if item.get("deployment_id") == deployment_id
    ]
    if any(agent.get("host") != target["host"] for agent in agents):
        raise ValueError("managed package host conflicts with an enrolled deployment agent")
    current = TABLE.get_item(
        Key=_item_key(tenant, "MANAGED_PACKAGE", deployment_id), ConsistentRead=True
    ).get("Item")
    current_revision = (
        _managed_integer(current.get("revision"), "managed package revision", positive=True)
        if current
        else 0
    )
    if current_revision != expected_revision:
        raise ManagedPackageConflict("managed package revision is stale")
    now = int(time.time())
    record = {
        **_item_key(tenant, "MANAGED_PACKAGE", deployment_id),
        "tenant_id": tenant,
        "deploymentId": deployment_id,
        "revision": current_revision + 1,
        "packageBase64": base64.b64encode(encoded).decode("ascii"),
        "packageSha256": hashlib.sha256(encoded).hexdigest(),
        "bundleHash": target["bundleHash"],
        "host": target["host"],
        "hostVersion": target["hostVersion"],
        "platform": target["platform"],
        "policyId": target["policyId"],
        "policyVersion": target["policyVersion"],
        "publishedAt": now,
        "publishedBy": actor,
        "artifactCount": len(package_value["artifacts"]),
        **(
            {_MANAGED_TRUST_FIELD: target[_MANAGED_TRUST_FIELD]}
            if _MANAGED_TRUST_FIELD in target
            else {}
        ),
    }
    revision_id = f"{deployment_id}:{record['revision']:020d}"
    immutable = {
        **record,
        **_item_key(tenant, "MANAGED_PACKAGE_VERSION", revision_id),
        "id": revision_id,
    }
    current_condition = (
        "attribute_not_exists(pk)" if current is None else "revision = :expected_revision"
    )
    current_values = None if current is None else {":expected_revision": expected_revision}
    _transact_policy_records(
        [
            _transaction_put(record, condition=current_condition, values=current_values),
            _transaction_put(immutable, condition="attribute_not_exists(pk)"),
        ]
    )
    metadata = _managed_package_metadata(tenant, deployment_id, record)
    _audit(
        tenant,
        "managed_deployment_package_published",
        actor,
        {
            "deployment_id": deployment_id,
            "revision": metadata["revision"],
            "package_sha256": metadata["packageSha256"],
            "bundle_hash": metadata["bundleHash"],
            "host": metadata["host"],
            "platform": metadata["platform"],
        },
    )
    return metadata


def _agent_managed_package(tenant, deployment_id, agent_id, agent):
    """Return a current package to one exact rollout-selected enrolled agent."""
    try:
        _require_agent_execution_authority(tenant, agent)
    except PermissionError as error:
        raise ManagedPackageConflict("response control blocks managed package retrieval") from error
    agent_key = f"{deployment_id}:{agent_id}"
    desired, configuration = _desired_managed_host(tenant, deployment_id)
    state = configuration.get("rolloutState")
    percentage = _managed_integer(
        configuration.get("rolloutPercentage", 0), "managed package rollout percentage"
    )
    if state not in {"canary", "active", "rolling_back", "converged", "drifted"}:
        raise ManagedPackageConflict("managed package rollout is not active")
    if not _rollout_agent_selected(tenant, agent_key, percentage):
        raise ManagedPackageConflict("agent is not selected for managed package rollout")
    package_revision = _managed_integer(
        configuration.get("rolloutPackageRevision", 0),
        "managed package rollout revision",
    )
    package_kind = "MANAGED_PACKAGE_VERSION" if package_revision else "MANAGED_PACKAGE"
    package_id = f"{deployment_id}:{package_revision:020d}" if package_revision else deployment_id
    package = TABLE.get_item(
        Key=_item_key(tenant, package_kind, package_id), ConsistentRead=True
    ).get("Item")
    metadata = _managed_package_metadata(tenant, deployment_id, package)
    if metadata["status"] != "current" or metadata["host"] != agent.get("host"):
        raise ManagedPackageConflict("managed package does not match current agent state")
    _value, target, _encoded = _managed_package(
        package.get("packageBase64"), package.get("packageSha256")
    )
    if target != desired:
        raise ManagedPackageConflict("managed package does not match current desired state")
    return {
        "schemaVersion": 2 if _MANAGED_TRUST_FIELD in metadata else 1,
        "deploymentId": deployment_id,
        "agentId": agent_id,
        **metadata,
        "packageBase64": package["packageBase64"],
    }


def _managed_configuration_posture(tenant, agent, *, now=None):
    """Compare server-owned desired state with the authenticated endpoint report."""
    configuration = TABLE.get_item(
        Key=_item_key(tenant, "CONFIGURATION", agent.get("deployment_id", "")),
        ConsistentRead=True,
    ).get("Item")
    desired_configuration = configuration.get("desiredConfiguration", {}) if configuration else {}
    desired_value = (
        desired_configuration.get("managedHost")
        if isinstance(desired_configuration, dict)
        else None
    )
    desired = _managed_host(desired_value) if isinstance(desired_value, dict) else None
    observed_value = agent.get("managed_configuration_report")
    observed = (
        _managed_host(observed_value, report=True) if isinstance(observed_value, dict) else None
    )
    if desired is None:
        return {"status": "not_configured", "desired": None, "observed": observed}
    if observed is None:
        return {"status": "missing", "desired": desired, "observed": None}
    identity_fields = tuple(desired)
    if agent.get("host") != desired["host"] or any(
        observed.get(field) != desired[field] for field in identity_fields
    ):
        status = "conflict"
    else:
        current = int(time.time()) if now is None else now
        status = (
            "stale"
            if observed["verifiedAt"] > current or observed["expiresAt"] <= current
            else "enforced"
        )
    return {"status": status, "desired": desired, "observed": observed}


def _policy_trust_convergence(tenant, *, now=None):
    """Return server-derived signer-trust rollout posture for active endpoints."""
    current = int(time.time()) if now is None else now
    active_agents = [
        agent
        for agent in _list(tenant, "AGENT", consistent_read=True)
        if agent.get("host") in {"claude-code", "codex-cli"}
        and _agent_lifecycle_state(agent) == "active"
    ]
    by_deployment = {}
    for agent in active_agents:
        deployment_id = agent.get("deployment_id")
        if isinstance(deployment_id, str):
            by_deployment.setdefault(deployment_id, []).append(agent)
    deployments = []
    expected_digests = set()
    for deployment_id in sorted(by_deployment):
        agents = by_deployment[deployment_id]
        configuration = TABLE.get_item(
            Key=_item_key(tenant, "CONFIGURATION", deployment_id), ConsistentRead=True
        ).get("Item")
        desired_value = (
            configuration.get("desiredConfiguration", {}).get("managedHost")
            if isinstance(configuration, dict)
            and isinstance(configuration.get("desiredConfiguration"), dict)
            else None
        )
        desired = _managed_host(desired_value) if isinstance(desired_value, dict) else None
        desired_digest = desired.get(_MANAGED_TRUST_FIELD) if desired else None
        if isinstance(desired_digest, str):
            expected_digests.add(desired_digest)
        package_current = False
        package_digest = None
        try:
            package = _managed_package_metadata(tenant, deployment_id)
            package_digest = package.get(_MANAGED_TRUST_FIELD)
            package_current = (
                package.get("status") == "current"
                and isinstance(desired_digest, str)
                and package_digest == desired_digest
            )
        except (ManagedPackageNotFound, ValueError):
            package_current = False
        postures = [_managed_configuration_posture(tenant, agent, now=current) for agent in agents]
        enforced = sum(posture.get("status") == "enforced" for posture in postures)
        rollout_converged = bool(
            configuration
            and configuration.get("rolloutState") == "converged"
            and _managed_integer(configuration.get("rolloutPercentage", 0), "rollout percentage")
            == 100
        )
        ready = bool(
            desired_digest and package_current and rollout_converged and enforced == len(agents)
        )
        deployments.append(
            {
                "deploymentId": deployment_id,
                "agentCount": len(agents),
                "enforcedAgentCount": enforced,
                "policyTrustBundleSha256": desired_digest,
                "packageTrustBundleSha256": package_digest,
                "packageCurrent": package_current,
                "rolloutConverged": rollout_converged,
                "ready": ready,
            }
        )
    try:
        required_keys = sorted(_required_policy_trust_key_ids())
        deployment_authority_configured = True
    except ValueError:
        required_keys = []
        deployment_authority_configured = False
    ready_count = sum(item["ready"] for item in deployments)
    common_digest = next(iter(expected_digests)) if len(expected_digests) == 1 else None
    return {
        "schemaVersion": 1,
        "checkedAt": current,
        "activeSigningKeyArn": os.environ.get("POLICY_SIGNING_KEY_ARN", ""),
        "stagedSigningKeyArn": os.environ.get("REGIONAL_POLICY_SIGNING_KEY_ARN", ""),
        "requiredTrustKeyArns": required_keys,
        "deploymentAuthorityConfigured": deployment_authority_configured,
        "policyTrustBundleSha256": common_digest,
        "agentCount": len(active_agents),
        "enforcedAgentCount": sum(item["enforcedAgentCount"] for item in deployments),
        "deploymentCount": len(deployments),
        "readyDeploymentCount": ready_count,
        "readyForSignerCutover": bool(
            deployment_authority_configured
            and active_agents
            and deployments
            and ready_count == len(deployments)
            and common_digest
            and os.environ.get("POLICY_SIGNING_KEY_ARN")
            != os.environ.get("REGIONAL_POLICY_SIGNING_KEY_ARN")
        ),
        "deployments": deployments,
    }


def _rollout_agent_selected(tenant, agent_key, percentage):
    """Deterministically select one endpoint without trusting browser membership."""
    value = _managed_integer(percentage, "rollout percentage")
    if value > 100:
        raise ValueError("rollout percentage must not exceed 100")
    bucket = int(hashlib.sha256(f"{tenant}:{agent_key}".encode()).hexdigest()[:8], 16) % 100
    return value > bucket


def _configuration_version_identifier(deployment_id, version):
    """Return one ordered immutable deployment-configuration version ID."""
    deployment_id = _bounded_identifier(deployment_id, "deploymentId")
    version = _managed_integer(version, "configuration version", positive=True)
    return f"{deployment_id}:{version:020d}"


def _configuration_version_document(record):
    """Project immutable desired authority fields for hashing and rollback."""
    return {
        "deploymentId": record.get("deploymentId"),
        "version": int(record.get("version", 0)),
        "templateId": record.get("templateId"),
        "desiredConfiguration": _json(record.get("desiredConfiguration", {})),
        "desiredHash": record.get("desiredHash"),
    }


def _configuration_version_record(tenant, record, actor):
    """Build one immutable desired-state version with an integrity digest."""
    document = _configuration_version_document(record)
    if document["desiredHash"] != _configuration_hash(document["desiredConfiguration"]):
        raise RuntimeError("deployment configuration desired-state integrity failed")
    identifier = _configuration_version_identifier(document["deploymentId"], document["version"])
    return {
        **_item_key(tenant, "CONFIGURATION_VERSION", identifier),
        "tenant_id": tenant,
        "id": identifier,
        **document,
        "contentHash": _configuration_hash(document),
        "createdAt": int(record.get("updatedAt", time.time())),
        "createdBy": actor,
    }


def _configuration_version(tenant, deployment_id, version):
    """Load and verify one tenant-scoped immutable desired-state version."""
    identifier = _configuration_version_identifier(deployment_id, version)
    record = TABLE.get_item(
        Key=_item_key(tenant, "CONFIGURATION_VERSION", identifier), ConsistentRead=True
    ).get("Item")
    if not record:
        raise LookupError("deployment configuration version not found")
    document = _configuration_version_document(record)
    if not secrets.compare_digest(
        str(record.get("contentHash", "")), _configuration_hash(document)
    ):
        raise RuntimeError("deployment configuration version integrity failed")
    return record


def _rollout_health_criteria(value):
    """Validate closed, bounded automatic-pause criteria."""
    if not isinstance(value, dict) or set(value) != set(_ROLLOUT_DEFAULT_CRITERIA):
        raise ValueError("rollout health criteria have an invalid schema")
    result = {
        field: _managed_integer(value.get(field), f"rollout {field}")
        for field in _ROLLOUT_DEFAULT_CRITERIA
    }
    if result["maxUnavailablePercent"] > 100 or result["maxDriftPercent"] > 100:
        raise ValueError("rollout health percentages must not exceed 100")
    if not 1 <= result["minSampleSize"] <= 100:
        raise ValueError("rollout minimum sample size must be between 1 and 100")
    if not 300 <= result["gracePeriodSeconds"] <= 3_600:
        raise ValueError("rollout grace period must be between 300 and 3600 seconds")
    return result


def _rollout_schedule(value, now):
    """Validate one absolute window with an explicit operator time zone."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"notBefore", "deadline", "timeZone"}:
        raise ValueError("rollout schedule has an invalid schema")
    not_before = _managed_integer(value.get("notBefore"), "rollout notBefore")
    deadline = _managed_integer(value.get("deadline"), "rollout deadline")
    zone = _bounded_text(value.get("timeZone"), "rollout timeZone", 64)
    try:
        ZoneInfo(zone)
    except ZoneInfoNotFoundError as error:
        raise ValueError("rollout timeZone is not recognized") from error
    if not_before < now - 60 or not_before > now + _ROLLOUT_MAX_SCHEDULE_SECONDS:
        raise ValueError("rollout notBefore is outside the 30-day scheduling bound")
    if deadline <= max(now, not_before) or deadline > not_before + (7 * 24 * 60 * 60):
        raise ValueError("rollout deadline must follow start within seven days")
    return {"notBefore": not_before, "deadline": deadline, "timeZone": zone}


def _ensure_configuration_governance(tenant, record):
    """Migrate a legacy rollout without trusting its claimed applied state."""
    if not record:
        raise LookupError("deployment configuration not found")
    deployment_id = record.get("deploymentId")
    if not deployment_id and isinstance(record.get("sk"), str):
        deployment_id = record["sk"].removeprefix("CONFIGURATION#")
    deployment_id = _bounded_identifier(deployment_id, "deploymentId")
    version = _managed_integer(record.get("version", 1), "configuration version", positive=True)
    governed = record
    if int(record.get("governanceSchemaVersion", 0)) != 1:
        state = str(record.get("rolloutState", "staged")).lower()
        if state == "rollback":
            state = "rolling_back"
        if state not in _ROLLOUT_STATES:
            state = "staged"
        governed = {
            **record,
            "deploymentId": deployment_id,
            "templateId": record.get("templateId", "legacy-migration"),
            "desiredHash": record.get("desiredHash")
            or _configuration_hash(record.get("desiredConfiguration", {})),
            "governanceSchemaVersion": 1,
            "rolloutRevision": 1,
            "rolloutState": state,
            "requestedState": state if state in _ROLLOUT_ACTIVE_STATES else None,
            "rolloutPercentage": int(record.get("rolloutPercentage", 0)),
            "rolloutChannel": "stable",
            "rolloutRing": "canary" if state == "canary" else "broad",
            "healthCriteria": _json(_ROLLOUT_DEFAULT_CRITERIA),
            "schedule": None,
            "rolloutPackageRevision": 0,
            "lastKnownGoodVersion": None,
            "lastKnownGoodPackageRevision": None,
            # Legacy presentation state is not evidence that any endpoint
            # applied the desired bytes.
            "appliedHash": None,
            "drifted": True,
            "version": version,
        }
        try:
            TABLE.put_item(
                Item=governed,
                ConditionExpression="attribute_not_exists(governanceSchemaVersion)",
            )
        except Exception as error:
            if not _is_conditional_conflict(error):
                raise
            governed = TABLE.get_item(
                Key=_item_key(tenant, "CONFIGURATION", deployment_id), ConsistentRead=True
            ).get("Item")
            if not governed:
                raise LookupError(
                    "deployment configuration disappeared during migration"
                ) from error
    identifier = _configuration_version_identifier(deployment_id, version)
    existing = TABLE.get_item(
        Key=_item_key(tenant, "CONFIGURATION_VERSION", identifier), ConsistentRead=True
    ).get("Item")
    if not existing:
        version_record = _configuration_version_record(
            tenant, governed, str(governed.get("updatedBy", "legacy-migration"))
        )
        try:
            TABLE.put_item(Item=version_record, ConditionExpression="attribute_not_exists(pk)")
        except Exception as error:
            if not _is_conditional_conflict(error):
                raise
    return governed


def _rollout_bound_package(tenant, configuration):
    """Load an immutable rollout package or report a content-free blocker."""
    deployment_id = configuration.get("deploymentId", "")
    revision = int(configuration.get("rolloutPackageRevision", 0))
    if revision <= 0:
        return None, "managed_package_not_bound"
    identifier = f"{deployment_id}:{revision:020d}"
    package = TABLE.get_item(
        Key=_item_key(tenant, "MANAGED_PACKAGE_VERSION", identifier), ConsistentRead=True
    ).get("Item")
    if not package:
        return None, "managed_package_revision_missing"
    try:
        _value, target, _encoded = _managed_package(
            package.get("packageBase64"), package.get("packageSha256")
        )
        desired = _managed_host(configuration.get("desiredConfiguration", {}).get("managedHost"))
    except ValueError:
        return None, "managed_package_integrity_invalid"
    if target != desired:
        return None, "managed_package_target_mismatch"
    return package, None


def _rollout_convergence(tenant, configuration, *, now=None):
    """Measure selected endpoints from live server-owned state."""
    current = int(time.time()) if now is None else int(now)
    deployment_id = configuration.get("deploymentId", "")
    percentage = int(configuration.get("rolloutPercentage", 0))
    agents = [
        agent
        for agent in _all_agents(tenant)
        if agent.get("deployment_id") == deployment_id and _agent_lifecycle_state(agent) == "active"
    ]
    selected = [
        agent
        for agent in agents
        if _rollout_agent_selected(
            tenant, f"{agent.get('deployment_id')}:{agent.get('id')}", percentage
        )
    ]
    desired_host = configuration.get("desiredConfiguration", {}).get("managedHost", {}).get("host")
    blockers = []
    if not agents:
        blockers.append("no_active_agents")
    if any(agent.get("host") != desired_host for agent in agents):
        blockers.append("incompatible_agent_host")
    _package, package_blocker = _rollout_bound_package(tenant, configuration)
    if package_blocker:
        blockers.append(package_blocker)
    healthy = []
    converged = []
    unavailable = []
    drifted = []
    pending = []
    for agent in selected:
        is_healthy = (
            agent.get("status") == "connected" and int(agent.get("expires_at", 0)) > current
        )
        posture = agent.get("managed_configuration", {})
        if not is_healthy:
            unavailable.append(agent)
        elif posture.get("status") == "enforced":
            healthy.append(agent)
            converged.append(agent)
        elif posture.get("status") in {"conflict", "stale"}:
            healthy.append(agent)
            drifted.append(agent)
        else:
            healthy.append(agent)
            pending.append(agent)

    def measured(count):
        return round((100 * count) / len(selected), 1) if selected else None

    schedule = configuration.get("schedule") or {}
    # Scheduled records deliberately carry a null start instant until the
    # maintenance window opens. Treating that sentinel as an integer would
    # turn a safe scheduled rollout into a control-plane failure.
    started_at_value = configuration.get("startedAt")
    started_at = int(started_at_value) if started_at_value is not None else 0
    criteria = configuration.get("healthCriteria") or _ROLLOUT_DEFAULT_CRITERIA
    grace_until = started_at + int(criteria.get("gracePeriodSeconds", 600)) if started_at else 0
    return {
        "measuredAt": current,
        "totalAgents": len(agents),
        "selectedAgents": len(selected),
        "healthyAgents": len(healthy),
        "convergedAgents": len(converged),
        "pendingAgents": len(pending),
        "unavailableAgents": len(unavailable),
        "driftedAgents": len(drifted),
        "convergedPercent": measured(len(converged)),
        "unavailablePercent": measured(len(unavailable)),
        "driftPercent": measured(len(drifted)),
        "canaryConverged": bool(selected) and len(converged) == len(selected),
        "fullConverged": bool(agents)
        and percentage == 100
        and len(selected) == len(agents)
        and len(converged) == len(selected),
        "graceUntil": grace_until or None,
        "inGracePeriod": bool(grace_until and current < grace_until),
        "deadline": schedule.get("deadline"),
        "blockers": sorted(set(blockers)),
        "ready": not blockers,
    }


def _put_reconciled_rollout(tenant, record, updated, event_type, reason):
    """CAS one server-derived rollout transition and emit exact audit evidence."""
    expected = int(record.get("rolloutRevision", 0))
    updated = {**updated, "rolloutRevision": expected + 1, "updatedAt": int(time.time())}
    try:
        TABLE.put_item(
            Item=updated,
            ConditionExpression="rolloutRevision = :expected_revision",
            ExpressionAttributeValues={":expected_revision": expected},
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            return TABLE.get_item(
                Key=_item_key(tenant, "CONFIGURATION", record["deploymentId"]),
                ConsistentRead=True,
            ).get("Item")
        raise
    _audit(
        tenant,
        event_type,
        "system:rollout-reconciler",
        {
            "deployment_id": record["deploymentId"],
            "configuration_version": int(record.get("version", 0)),
            "rollout_revision": expected + 1,
            "reason": reason,
        },
    )
    return updated


def _reconcile_deployment_rollout(tenant, record, *, now=None):
    """Apply due schedules, automatic pause and evidence-only convergence."""
    current = int(time.time()) if now is None else int(now)
    governed = _ensure_configuration_governance(tenant, record)
    state = governed.get("rolloutState")
    if state not in _ROLLOUT_STATES:
        raise RuntimeError("deployment rollout state is invalid")
    schedule = governed.get("schedule") or {}
    if state == "scheduled" and int(schedule.get("notBefore", 0)) <= current:
        requested = governed.get("requestedState")
        if requested not in {"canary", "active"}:
            raise RuntimeError("scheduled rollout target state is invalid")
        governed = _put_reconciled_rollout(
            tenant,
            governed,
            {**governed, "rolloutState": requested, "startedAt": current},
            "deployment_rollout_started",
            "maintenance window opened",
        )
        state = governed.get("rolloutState")
    convergence = _rollout_convergence(tenant, governed, now=current)
    criteria = governed.get("healthCriteria") or _ROLLOUT_DEFAULT_CRITERIA
    if state in _ROLLOUT_ACTIVE_STATES:
        pause_reason = None
        deadline = schedule.get("deadline")
        if deadline and current >= int(deadline) and not convergence["fullConverged"]:
            pause_reason = "rollout deadline elapsed before convergence"
        elif not convergence["inGracePeriod"] and convergence["selectedAgents"] >= int(
            criteria.get("minSampleSize", 1)
        ):
            if (convergence["unavailablePercent"] or 0) > int(
                criteria.get("maxUnavailablePercent", 10)
            ):
                pause_reason = "unavailable endpoint threshold exceeded"
            elif (convergence["driftPercent"] or 0) > int(criteria.get("maxDriftPercent", 10)):
                pause_reason = "managed-configuration drift threshold exceeded"
        if pause_reason:
            governed = _put_reconciled_rollout(
                tenant,
                governed,
                {
                    **governed,
                    "rolloutState": "paused",
                    "pauseReason": pause_reason,
                    "pausedAt": current,
                    "drifted": True,
                    "appliedHash": None,
                },
                "deployment_rollout_auto_paused",
                pause_reason,
            )
        elif state in {"active", "rolling_back"} and convergence["fullConverged"]:
            governed = _put_reconciled_rollout(
                tenant,
                governed,
                {
                    **governed,
                    "rolloutState": "converged",
                    "convergedAt": current,
                    "appliedHash": governed.get("desiredHash"),
                    "drifted": False,
                    "lastKnownGoodVersion": int(governed.get("version", 0)),
                    "lastKnownGoodPackageRevision": int(governed.get("rolloutPackageRevision", 0)),
                },
                "deployment_rollout_converged",
                "all selected endpoints reported exact current evidence",
            )
    elif state == "converged" and not convergence["fullConverged"]:
        governed = _put_reconciled_rollout(
            tenant,
            governed,
            {**governed, "rolloutState": "drifted", "drifted": True},
            "deployment_rollout_drift_detected",
            "endpoint evidence no longer matches the known-good configuration",
        )
    elif state == "drifted" and convergence["fullConverged"]:
        governed = _put_reconciled_rollout(
            tenant,
            governed,
            {**governed, "rolloutState": "converged", "drifted": False},
            "deployment_rollout_drift_remediated",
            "all endpoints returned to exact known-good evidence",
        )
    return {**governed, "convergence": _rollout_convergence(tenant, governed, now=current)}


def _deployment_configurations(tenant):
    """Return bounded, reconciled configuration and rollout evidence."""
    return [
        _reconcile_deployment_rollout(tenant, record)
        for record in _list(tenant, "CONFIGURATION", consistent_read=True)
    ]


def _bind_current_managed_package(tenant, configuration):
    """Bind and retain the exact package currently matching desired state."""
    deployment_id = configuration.get("deploymentId", "")
    package = TABLE.get_item(
        Key=_item_key(tenant, "MANAGED_PACKAGE", deployment_id), ConsistentRead=True
    ).get("Item")
    metadata = _managed_package_metadata(tenant, deployment_id, package)
    if metadata["status"] != "current":
        raise PolicyConflict("managed package does not match deployment desired state")
    revision = int(metadata["revision"])
    identifier = f"{deployment_id}:{revision:020d}"
    immutable_key = _item_key(tenant, "MANAGED_PACKAGE_VERSION", identifier)
    immutable = TABLE.get_item(Key=immutable_key, ConsistentRead=True).get("Item")
    if not immutable:
        immutable = {**package, **immutable_key, "id": identifier}
        try:
            TABLE.put_item(Item=immutable, ConditionExpression="attribute_not_exists(pk)")
        except Exception as error:
            if not _is_conditional_conflict(error):
                raise
    return revision


def _start_managed_rollouts(tenant, body, actor):
    """Start or expand a bounded all-or-none evidence-led rollout batch."""
    required = {
        "deploymentIds",
        "expectedRevisions",
        "targetState",
        "percentage",
        "channel",
        "ring",
        "reason",
        "healthCriteria",
        "schedule",
    }
    if not isinstance(body, dict) or set(body) != required:
        raise ValueError("managed rollout request has an invalid schema")
    raw_ids = body.get("deploymentIds")
    if (
        not isinstance(raw_ids, list)
        or not 1 <= len(raw_ids) <= _ROLLOUT_BATCH_LIMIT
        or len(raw_ids) != len(set(raw_ids))
    ):
        raise ValueError("managed rollout requires 1 to 20 unique deployments")
    deployment_ids = [_bounded_identifier(value, "deploymentId") for value in raw_ids]
    expected = body.get("expectedRevisions")
    if not isinstance(expected, dict) or set(expected) != set(deployment_ids):
        raise ValueError("managed rollout expected revisions must match deployments exactly")
    expected_revisions = {
        deployment_id: _managed_integer(
            expected.get(deployment_id), "rollout expected revision", positive=True
        )
        for deployment_id in deployment_ids
    }
    target_state = body.get("targetState")
    percentage = _managed_integer(body.get("percentage"), "rollout percentage", positive=True)
    channel = body.get("channel")
    ring = body.get("ring")
    reason = _case_reason(body.get("reason"), "rollout reason")
    criteria = _rollout_health_criteria(body.get("healthCriteria"))
    now = int(time.time())
    schedule = _rollout_schedule(body.get("schedule"), now)
    if target_state not in {"canary", "active"}:
        raise ValueError("managed rollout target must be canary or active")
    if channel not in _ROLLOUT_CHANNELS or ring not in _ROLLOUT_RINGS:
        raise ValueError("managed rollout channel or ring is invalid")
    if percentage > 100:
        raise ValueError("managed rollout percentage must not exceed 100")
    if target_state == "canary" and (ring != "canary" or percentage > 25):
        raise ValueError("canary rollouts require the canary ring at 1 to 25 percent")
    if target_state == "active" and ring != "broad":
        raise ValueError("active rollouts require the broad ring")

    records = []
    operations = []
    for deployment_id in deployment_ids:
        current = TABLE.get_item(
            Key=_item_key(tenant, "CONFIGURATION", deployment_id), ConsistentRead=True
        ).get("Item")
        current = _ensure_configuration_governance(tenant, current)
        revision = int(current.get("rolloutRevision", 0))
        if revision != expected_revisions[deployment_id]:
            raise PolicyConflict("deployment rollout revision changed")
        if current.get("rolloutState") in {"rolling_back"}:
            raise PolicyConflict("rollback must converge or pause before a new rollout")
        if percentage < int(current.get("rolloutPercentage", 0)):
            raise PolicyConflict("rollout percentage cannot decrease outside rollback")
        deployment = TABLE.get_item(
            Key=_item_key(tenant, "DEPLOYMENT", deployment_id), ConsistentRead=True
        ).get("Item")
        if not deployment:
            raise LookupError("deployment not found")
        desired = _managed_host(current.get("desiredConfiguration", {}).get("managedHost"))
        agents = [
            item
            for item in _all_agents(tenant)
            if item.get("deployment_id") == deployment_id
            and _agent_lifecycle_state(item) == "active"
        ]
        if not agents:
            raise PolicyConflict("managed rollout requires at least one active enrolled agent")
        if any(agent.get("host") != desired["host"] for agent in agents):
            raise PolicyConflict("managed rollout contains an incompatible agent host")
        package_revision = _bind_current_managed_package(tenant, current)
        state = (
            "scheduled"
            if schedule is not None and int(schedule["notBefore"]) > now
            else target_state
        )
        updated = {
            **current,
            "rolloutState": state,
            "requestedState": target_state,
            "rolloutPercentage": percentage,
            "rolloutChannel": channel,
            "rolloutRing": ring,
            "rolloutReason": reason,
            "rolloutPackageRevision": package_revision,
            "healthCriteria": criteria,
            "schedule": schedule,
            "startedAt": None if state == "scheduled" else now,
            "startedBy": actor,
            "pauseReason": None,
            "pausedAt": None,
            "convergedAt": None,
            "appliedHash": None,
            "drifted": True,
            "rolloutRevision": revision + 1,
            "updatedAt": now,
            "updatedBy": actor,
        }
        operations.append(
            _transaction_put(
                updated,
                condition="rolloutRevision = :expected_revision",
                values={":expected_revision": revision},
            )
        )
        records.append(updated)
    _transact_policy_records(operations)
    _audit(
        tenant,
        "managed_rollout_started",
        actor,
        {
            "deployment_ids": deployment_ids,
            "target_state": target_state,
            "percentage": percentage,
            "channel": channel,
            "ring": ring,
            "reason": reason,
        },
    )
    return [_reconcile_deployment_rollout(tenant, record, now=now) for record in records]


def _pause_managed_rollout(tenant, deployment_id, body, actor):
    """Pause one exact rollout without accepting browser-authored health state."""
    if not isinstance(body, dict) or set(body) != {"expectedRevision", "reason"}:
        raise ValueError("managed rollout pause request has an invalid schema")
    expected = _managed_integer(
        body.get("expectedRevision"), "rollout expected revision", positive=True
    )
    reason = _case_reason(body.get("reason"), "rollout pause reason")
    current = TABLE.get_item(
        Key=_item_key(tenant, "CONFIGURATION", deployment_id), ConsistentRead=True
    ).get("Item")
    current = _ensure_configuration_governance(tenant, current)
    if int(current.get("rolloutRevision", 0)) != expected:
        raise PolicyConflict("deployment rollout revision changed")
    if current.get("rolloutState") not in _ROLLOUT_ACTIVE_STATES | {"scheduled"}:
        raise PolicyConflict("deployment rollout is not pausable")
    now = int(time.time())
    updated = {
        **current,
        "rolloutState": "paused",
        "pauseReason": reason,
        "pausedAt": now,
        "rolloutRevision": expected + 1,
        "updatedAt": now,
        "updatedBy": actor,
        "drifted": True,
        "appliedHash": None,
    }
    try:
        TABLE.put_item(
            Item=updated,
            ConditionExpression="rolloutRevision = :expected_revision",
            ExpressionAttributeValues={":expected_revision": expected},
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("deployment rollout revision changed") from error
        raise
    _audit(
        tenant,
        "managed_rollout_paused",
        actor,
        {"deployment_id": deployment_id, "reason": reason, "rollout_revision": expected + 1},
    )
    return _reconcile_deployment_rollout(tenant, updated, now=now)


def _rollback_managed_configuration(tenant, deployment_id, body, actor):
    """Create a new rollout from the exact last-known-good desired version."""
    if not isinstance(body, dict) or set(body) != {
        "targetVersion",
        "expectedRevision",
        "reason",
    }:
        raise ValueError("managed rollback request has an invalid schema")
    target_version = _managed_integer(
        body.get("targetVersion"), "rollback target version", positive=True
    )
    expected = _managed_integer(
        body.get("expectedRevision"), "rollout expected revision", positive=True
    )
    reason = _case_reason(body.get("reason"), "rollback reason")
    current = TABLE.get_item(
        Key=_item_key(tenant, "CONFIGURATION", deployment_id), ConsistentRead=True
    ).get("Item")
    current = _ensure_configuration_governance(tenant, current)
    if int(current.get("rolloutRevision", 0)) != expected:
        raise PolicyConflict("deployment rollout revision changed")
    if target_version != int(current.get("lastKnownGoodVersion") or 0):
        raise PolicyConflict("rollback target is not the last known-good version")
    package_revision = int(current.get("lastKnownGoodPackageRevision") or 0)
    if package_revision <= 0:
        raise PolicyConflict("last known-good package evidence is unavailable")
    target = _configuration_version(tenant, deployment_id, target_version)
    package_id = f"{deployment_id}:{package_revision:020d}"
    if not TABLE.get_item(
        Key=_item_key(tenant, "MANAGED_PACKAGE_VERSION", package_id), ConsistentRead=True
    ).get("Item"):
        raise PolicyConflict("last known-good package revision is unavailable")
    now = int(time.time())
    new_version = int(current.get("version", 0)) + 1
    updated = {
        **current,
        "templateId": target.get("templateId"),
        "desiredConfiguration": _json(target.get("desiredConfiguration", {})),
        "desiredHash": target.get("desiredHash"),
        "version": new_version,
        "rolloutState": "rolling_back",
        "requestedState": "rolling_back",
        "rolloutPercentage": 100,
        "rolloutChannel": "emergency",
        "rolloutRing": "broad",
        "rolloutReason": reason,
        "rolloutPackageRevision": package_revision,
        "schedule": None,
        "startedAt": now,
        "startedBy": actor,
        "pauseReason": None,
        "pausedAt": None,
        "convergedAt": None,
        "appliedHash": None,
        "drifted": True,
        "rolloutRevision": expected + 1,
        "rollbackFromVersion": int(current.get("version", 0)),
        "rollbackTargetVersion": target_version,
        "updatedAt": now,
        "updatedBy": actor,
    }
    version_record = _configuration_version_record(tenant, updated, actor)
    _transact_policy_records(
        [
            _transaction_put(
                updated,
                condition="rolloutRevision = :expected_revision",
                values={":expected_revision": expected},
            ),
            _transaction_put(version_record, condition="attribute_not_exists(pk)"),
        ]
    )
    _audit(
        tenant,
        "managed_rollout_rollback_started",
        actor,
        {
            "deployment_id": deployment_id,
            "from_version": int(current.get("version", 0)),
            "target_version": target_version,
            "new_version": new_version,
            "package_revision": package_revision,
            "reason": reason,
        },
    )
    return _reconcile_deployment_rollout(tenant, updated, now=now)


def _key(kind, identifier):
    return {"pk": f"TENANT#{identifier}", "sk": f"{kind}#{identifier}"}


def _item_key(tenant, kind, identifier):
    return {"pk": f"TENANT#{tenant}", "sk": f"{kind}#{identifier}"}


def _configuration_hash(configuration):
    """Create a stable desired-state hash without storing configuration secrets."""
    encoded = json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _policy_configuration(tenant, value):
    """Validate one bounded, secret-free policy document at the AWS boundary."""
    if not isinstance(value, dict):
        raise ValueError("policy configuration must be an object")

    def visit(item, depth=0):
        if depth > 12:
            raise ValueError("policy configuration nesting is too deep")
        if isinstance(item, dict):
            if len(item) > 1_000:
                raise ValueError("policy configuration object is too large")
            result = {}
            for key, nested in item.items():
                if not isinstance(key, str) or not key or len(key) > 256:
                    raise ValueError("policy configuration keys must be bounded text")
                normalized_key = key.lower().replace("-", "_")
                if normalized_key in _POLICY_SECRET_KEYS:
                    raise ValueError("policy configuration must not contain secrets")
                result[key] = visit(nested, depth + 1)
            return result
        if isinstance(item, list):
            if len(item) > 10_000:
                raise ValueError("policy configuration list is too large")
            return [visit(nested, depth + 1) for nested in item]
        if item is None or isinstance(item, (str, int, bool)):
            return item
        if isinstance(item, float) and math.isfinite(item):
            return item
        raise ValueError("policy configuration contains unsupported data")

    normalized = visit(value)
    if len(json.dumps(normalized, sort_keys=True, separators=(",", ":"))) > 1_000_000:
        raise ValueError("policy configuration is too large")
    # Resolve registry references on a copy to prove every selected resource
    # exists and is enabled. Managed resource content is never stored in policy.
    _managed_policy_configuration(tenant, normalized)
    return normalized


def _positive_policy_version(value):
    """Require a positive integral policy version without accepting booleans."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("policy version must be a positive integer")
    return value


def _ddb_value(value):
    """Serialize the bounded policy data model for DynamoDB transactions."""
    if value is None:
        return {"NULL": True}
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, str):
        return {"S": value}
    if isinstance(value, (int, Decimal)) and not isinstance(value, bool):
        return {"N": str(value)}
    if isinstance(value, float) and math.isfinite(value):
        return {"N": str(value)}
    if isinstance(value, list):
        return {"L": [_ddb_value(item) for item in value]}
    if isinstance(value, dict):
        return {"M": {str(key): _ddb_value(item) for key, item in value.items()}}
    raise ValueError("transaction item contains unsupported data")


def _ddb_item(value):
    """Serialize a complete DynamoDB item for a low-level transaction call."""
    return {str(key): _ddb_value(item) for key, item in value.items()}


def _transaction_put(record, *, condition, names=None, values=None):
    """Build one explicit conditional Put operation for TransactWriteItems."""
    operation = {
        "TableName": CONTROL_TABLE_NAME,
        "Item": _ddb_item(record),
        "ConditionExpression": condition,
    }
    if names:
        operation["ExpressionAttributeNames"] = names
    if values:
        operation["ExpressionAttributeValues"] = _ddb_item(values)
    return {"Put": operation}


def _transaction_delete(key, *, condition, names=None, values=None):
    """Build one explicit conditional Delete operation for TransactWriteItems."""
    operation = {
        "TableName": CONTROL_TABLE_NAME,
        "Key": _ddb_item(key),
        "ConditionExpression": condition,
    }
    if names:
        operation["ExpressionAttributeNames"] = names
    if values:
        operation["ExpressionAttributeValues"] = _ddb_item(values)
    return {"Delete": operation}


def _transact_policy_records(operations):
    """Commit policy authority changes atomically or normalize a stale-state conflict."""
    try:
        DYNAMODB.transact_write_items(TransactItems=operations)
    except Exception as error:
        code = getattr(error, "response", {}).get("Error", {}).get("Code")
        if code in {"ConditionalCheckFailedException", "TransactionCanceledException"}:
            raise PolicyConflict("policy state changed before the operation completed") from error
        raise


def _policy_version_identifier(policy_id, version):
    """Return a lexically sortable tenant-scoped policy-version identifier."""
    return f"{policy_id}:{version:020d}"


def _policy_object(configuration, section):
    """Return one policy section when it is an object, otherwise an empty view."""
    value = configuration.get(section) if isinstance(configuration, dict) else None
    return value if isinstance(value, dict) else {}


def _policy_string_set(configuration, section, field):
    """Return a normalized set without letting malformed legacy data imply authority."""
    value = _policy_object(configuration, section).get(field, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        return frozenset()
    return frozenset(item for item in value if item)


def _policy_scalar(configuration, section, field):
    """Read one scalar from a typed section without interpreting nested input."""
    value = _policy_object(configuration, section).get(field)
    return value if value is None or isinstance(value, (str, int, float, bool)) else None


def _policy_action_decision(configuration, evidence):
    """Predict one retained action without inventing facts removed by redaction.

    Historical command text and MCP server identity are deliberately not
    persisted. A simulation must therefore report those actions as
    indeterminate unless an exact tool-level rule is sufficient. This avoids a
    reassuring but false prediction from content the control plane does not
    possess.
    """
    tool = evidence.get("tool_name")
    source = evidence.get("source")
    resource_kind = evidence.get("resource_kind")
    if not isinstance(tool, str) or source not in _DECISION_SOURCES:
        return "indeterminate", "historical_identity_unavailable"
    denied = _policy_string_set(configuration, "tools", "denied")
    allowed = _policy_string_set(configuration, "tools", "allowed")
    approvals = _policy_string_set(configuration, "approvals", "requiredFor")
    if tool in denied:
        return "denied", "explicit_tool_deny"
    if tool in approvals or resource_kind in approvals:
        return "approval_required", "explicit_approval_rule"
    if resource_kind == "shell_command":
        return "indeterminate", "redacted_command_content"
    if tool in allowed:
        return "allowed", "explicit_tool_allow"
    if source == "claude_native":
        native = _policy_string_set(configuration, "claudeCode", "allowedBuiltInTools")
        return (
            ("allowed", "explicit_native_allow")
            if tool in native
            else (
                "denied",
                "deny_by_default",
            )
        )
    if source == "mcp":
        return "indeterminate", "mcp_server_identity_unavailable"
    return "denied", "deny_by_default"


def _semantic_policy_diff(base_configuration, candidate_configuration):
    """Explain policy meaning using typed authority, limit and data changes."""
    base = base_configuration if isinstance(base_configuration, dict) else {}
    candidate = candidate_configuration if isinstance(candidate_configuration, dict) else {}
    changes = []

    def set_changes(section, field, label, added_effect, removed_effect):
        before = _policy_string_set(base, section, field)
        after = _policy_string_set(candidate, section, field)
        for value in sorted(after - before):
            changes.append(
                {
                    "category": label,
                    "field": f"{section}.{field}",
                    "value": value,
                    "change": "added",
                    "effect": added_effect,
                }
            )
        for value in sorted(before - after):
            changes.append(
                {
                    "category": label,
                    "field": f"{section}.{field}",
                    "value": value,
                    "change": "removed",
                    "effect": removed_effect,
                }
            )

    set_changes(
        "policy", "allowedPrincipals", "identity", "authority_expanded", "authority_restricted"
    )
    set_changes("tools", "allowed", "tool", "authority_expanded", "authority_restricted")
    set_changes("tools", "denied", "tool", "authority_restricted", "review_required")
    set_changes("tools", "builtIn", "native_tool", "authority_expanded", "authority_restricted")
    set_changes("tools", "fileTools", "file_tool", "authority_expanded", "authority_restricted")
    set_changes(
        "claudeCode",
        "allowedBuiltInTools",
        "claude_native_tool",
        "authority_expanded",
        "authority_restricted",
    )
    set_changes(
        "claudeCode", "allowedSkills", "skill", "authority_expanded", "authority_restricted"
    )
    set_changes(
        "claudeCode",
        "allowedMcpServers",
        "mcp_server",
        "authority_expanded",
        "authority_restricted",
    )
    set_changes(
        "claudeCode",
        "allowedCommandPatterns",
        "command_rule",
        "authority_expanded",
        "authority_restricted",
    )
    set_changes(
        "claudeCode",
        "deniedCommandPatterns",
        "command_rule",
        "authority_restricted",
        "review_required",
    )
    set_changes(
        "claudeCode", "approvalCommandPatterns", "command_rule", "approval_added", "review_required"
    )
    set_changes("approvals", "requiredFor", "approval", "approval_added", "approval_removed")
    set_changes(
        "credentials", "scopes", "credential_scope", "authority_expanded", "authority_restricted"
    )

    limits = [
        ("approvals", "ttlSeconds"),
        ("budgets", "maxActions"),
        ("budgets", "maxConcurrent"),
        ("budgets", "maxFanOut"),
        ("budgets", "maxCostUnits"),
        ("budgets", "maxDelegationDepth"),
        ("budgets", "maxActionsPerSecond"),
        ("budgets", "executionTimeoutSeconds"),
        ("budgets", "maxTimedOutWorkers"),
    ]
    for section, field in limits:
        before = _policy_scalar(base, section, field)
        after = _policy_scalar(candidate, section, field)
        if before == after:
            continue
        effect = "limit_changed"
        if isinstance(before, (int, float)) and isinstance(after, (int, float)):
            effect = "authority_expanded" if after > before else "authority_restricted"
        changes.append(
            {
                "category": "limit",
                "field": f"{section}.{field}",
                "before": before,
                "after": after,
                "change": "changed",
                "effect": effect,
            }
        )

    scalar_fields = [
        ("policy", "provider", "policy_provider"),
        ("approvals", "provider", "approval_provider"),
        ("credentials", "enabled", "credential_requirement"),
        ("credentials", "mode", "credential_requirement"),
        ("credentials", "brokerEndpoint", "credential_requirement"),
        ("isolation", "verifier", "isolation_requirement"),
        ("isolation", "requiredForHighRisk", "isolation_requirement"),
        ("isolation", "mode", "isolation_requirement"),
        ("audit", "captureToolContent", "data_capture"),
        ("telemetry", "captureToolContent", "data_capture"),
    ]
    for section, field, category in scalar_fields:
        before = _policy_scalar(base, section, field)
        after = _policy_scalar(candidate, section, field)
        if before == after:
            continue
        effect = "requirement_changed"
        if category == "data_capture":
            effect = "data_capture_increased" if after is True else "data_capture_reduced"
        elif category == "isolation_requirement" and field == "requiredForHighRisk":
            effect = "authority_restricted" if after is True else "authority_expanded"
        changes.append(
            {
                "category": category,
                "field": f"{section}.{field}",
                "before": before,
                "after": after,
                "change": "changed",
                "effect": effect,
            }
        )
    changed_sections = sorted(
        key for key in set(base) | set(candidate) if base.get(key) != candidate.get(key)
    )
    return {
        "changedSections": changed_sections,
        "changes": changes,
        "summary": {
            "total": len(changes),
            "authorityExpanded": sum(
                1 for item in changes if item["effect"] == "authority_expanded"
            ),
            "authorityRestricted": sum(
                1 for item in changes if item["effect"] == "authority_restricted"
            ),
            "approvalChanges": sum(
                1 for item in changes if item["effect"] in {"approval_added", "approval_removed"}
            ),
            "dataCaptureChanges": sum(
                1 for item in changes if str(item["effect"]).startswith("data_capture_")
            ),
            "reviewRequired": sum(
                1
                for item in changes
                if item["effect"] in {"review_required", "requirement_changed", "limit_changed"}
            ),
        },
    }


def _policy_versions(tenant, policy_id, *, consistent_read=False):
    """Return the bounded immutable version ledger for one tenant policy."""
    items = [
        item
        for item in _list(tenant, "POLICY_VERSION", consistent_read=consistent_read)
        if item.get("policy_id") == policy_id
    ]
    return sorted(items, key=lambda item: int(item.get("version", 0)), reverse=True)


def _ensure_policy_governance(tenant, policy):
    """Lazily migrate one legacy active policy into the immutable version ledger."""
    if int(policy.get("governance_schema_version", 0)) == 1:
        return policy
    active_version = int(policy.get("version", 0))
    if active_version <= 0 or not isinstance(policy.get("configuration"), dict):
        raise PolicyConflict("legacy policy cannot be migrated safely")
    now = int(policy.get("updatedAt", policy.get("createdAt", time.time())))
    author = str(policy.get("author", "legacy-migration"))
    effective_configuration = _managed_policy_configuration(tenant, policy["configuration"])
    bundle = _sign_policy_bundle(tenant, policy["id"], active_version, effective_configuration, now)
    version_record = {
        **_item_key(
            tenant,
            "POLICY_VERSION",
            _policy_version_identifier(policy["id"], active_version),
        ),
        "tenant_id": tenant,
        "id": _policy_version_identifier(policy["id"], active_version),
        "policy_id": policy["id"],
        "organization_id": policy.get("organization_id", ""),
        "version": active_version,
        "base_version": max(0, active_version - 1),
        "name": policy.get("name", policy["id"]),
        "configuration": _json(policy["configuration"]),
        "content_hash": _configuration_hash(_json(policy["configuration"])),
        **_bundle_record_fields(bundle),
        "state": "active",
        "author": author,
        "created_at": now,
        "activated_by": "legacy-migration",
        "activated_at": now,
    }
    try:
        TABLE.put_item(
            Item=version_record,
            ConditionExpression="attribute_not_exists(pk)",
        )
    except Exception as error:
        if not _is_conditional_conflict(error):
            raise
    migrated = {
        **policy,
        "activeVersion": active_version,
        "latestVersion": active_version,
        "governanceState": "active",
        "pendingVersion": None,
        "pendingAuthor": None,
        "governance_schema_version": 1,
    }
    TABLE.put_item(Item=migrated)
    return _ensure_active_policy_signature(tenant, migrated)


def _sign_policy_bundle(tenant, policy_id, version, configuration, signed_at):
    """Sign exact resolved authority through the deployment-owned KMS key."""
    if not POLICY_SIGNING_KEY_ARN:
        raise RuntimeError("policy signing key is not configured")
    return sign_policy_bundle(
        KMS,
        POLICY_SIGNING_KEY_ARN,
        tenant,
        policy_id,
        version,
        _json(configuration),
        signed_at,
    )


def _bundle_record_fields(bundle):
    """Project a signed wire bundle into immutable DynamoDB-safe fields."""
    return {
        "effective_configuration": _json(bundle["configuration"]),
        "effective_content_hash": bundle["contentHash"],
        "bundle_integrity": _json(bundle["integrity"]),
    }


def _ensure_active_policy_signature(tenant, policy):
    """Backfill exact existing active authority without changing its permissions."""
    version = int(policy.get("version", 0))
    if version <= 0:
        raise PolicyConflict("active policy has no valid version")
    record = _policy_version_record(tenant, policy["id"], version)
    try:
        bundle_from_record(tenant, policy["id"], version, _json(record))
        return policy
    except RuntimeError:
        pass
    effective = _managed_policy_configuration(tenant, record.get("configuration"))
    bundle = _sign_policy_bundle(
        tenant,
        policy["id"],
        version,
        effective,
        int(time.time()),
    )
    updated = {**record, **_bundle_record_fields(bundle)}
    try:
        TABLE.put_item(
            Item=updated,
            ConditionExpression="#state = :active AND attribute_not_exists(bundle_integrity)",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={":active": "active"},
        )
        _audit(
            tenant,
            "policy_bundle_backfilled",
            "policy-signing-migration",
            {
                "policy_id": policy["id"],
                "version": version,
                "content_hash": bundle["contentHash"],
                "key_id": bundle["integrity"]["keyId"],
            },
        )
    except Exception as error:
        if not _is_conditional_conflict(error):
            raise
        current = _policy_version_record(tenant, policy["id"], version)
        bundle_from_record(tenant, policy["id"], version, _json(current))
    return policy


def _active_policy_bundle(tenant, policy):
    """Return only persisted, internally consistent signed active authority."""
    governed = _ensure_policy_governance(tenant, policy)
    governed = _ensure_active_policy_signature(tenant, governed)
    version = int(governed.get("version", 0))
    record = _policy_version_record(tenant, governed["id"], version)
    return bundle_from_record(tenant, governed["id"], version, _json(record))


def _policy_trust_metadata():
    """Expose public signer provenance without making HTTP a runtime trust anchor."""
    if not POLICY_SIGNING_KEY_ARN:
        raise RuntimeError("policy signing key is not configured")
    result = KMS.get_public_key(KeyId=POLICY_SIGNING_KEY_ARN)
    public_key = result.get("PublicKey")
    if (
        result.get("KeyId") != POLICY_SIGNING_KEY_ARN
        or result.get("KeyUsage") != "SIGN_VERIFY"
        or result.get("KeySpec", result.get("CustomerMasterKeySpec")) != "ECC_NIST_P256"
        or result.get("SigningAlgorithms") != ["ECDSA_SHA_256"]
        or not isinstance(public_key, bytes)
    ):
        raise RuntimeError("KMS returned incompatible policy verification key metadata")
    return {
        "keyId": POLICY_SIGNING_KEY_ARN,
        "algorithm": "ECDSA_SHA_256",
        "publicKeyDer": base64.b64encode(public_key).decode("ascii"),
        "fingerprintSha256": hashlib.sha256(public_key).hexdigest(),
        "trustSource": "administrator-installation-required",
    }


def _policy_version_view(tenant, record, versions=None):
    """Project one immutable ledger record into the secret-free operator contract."""
    all_versions = (
        versions if versions is not None else _policy_versions(tenant, record["policy_id"])
    )
    base = next(
        (
            item
            for item in all_versions
            if int(item.get("version", 0)) == int(record.get("base_version", 0))
        ),
        None,
    )
    configuration = _json(record.get("configuration", {}))
    base_configuration = _json(base.get("configuration", {})) if base else {}
    semantic_change = _semantic_policy_diff(base_configuration, configuration)
    approved_by = (
        record.get("decided_by")
        if record.get("decision") == "approved"
        and record.get("state") in {"approved", "staged", "active"}
        else None
    )
    integrity = record.get("bundle_integrity")
    composition = _policy_composition_metadata(record)
    return {
        "policyId": record["policy_id"],
        "organizationId": record.get("organization_id", ""),
        "version": int(record["version"]),
        "baseVersion": int(record.get("base_version", 0)),
        "name": record["name"],
        "configuration": configuration,
        "contentHash": record["content_hash"],
        "state": record["state"],
        "author": record["author"],
        "createdAt": int(record["created_at"]),
        "submittedBy": record.get("submitted_by"),
        "submittedAt": record.get("submitted_at"),
        "decidedBy": record.get("decided_by"),
        "decidedAt": record.get("decided_at"),
        "decision": record.get("decision"),
        "decisionReason": record.get("decision_reason"),
        "approvedBy": approved_by,
        "stagedBy": record.get("staged_by"),
        "stagedAt": record.get("staged_at"),
        "activatedBy": record.get("activated_by"),
        "activatedAt": record.get("activated_at"),
        "changeSummary": semantic_change,
        "composition": composition,
        "sourceProvenance": _json(record.get("source_provenance", {})) or None,
        "integrity": {
            "status": "signed" if isinstance(integrity, dict) else "unsigned",
            "contentHash": record.get("effective_content_hash"),
            "keyId": integrity.get("keyId") if isinstance(integrity, dict) else None,
            "algorithm": integrity.get("algorithm") if isinstance(integrity, dict) else None,
            "signedAt": integrity.get("signedAt") if isinstance(integrity, dict) else None,
        },
    }


def _simulate_policy_version(tenant, policy_id, version, body):
    """Predict a candidate policy over bounded, redacted historical decisions.

    Simulation is observational: it does not execute actions, change policy
    authority, create approvals or mutate retained decision evidence. Results
    are bound to the immutable candidate hash and the exact sampled evidence.
    """
    if not isinstance(body, dict) or set(body) != {"lookbackDays"}:
        raise ValueError("policy simulation request has an invalid schema")
    lookback_days = body.get("lookbackDays")
    if (
        isinstance(lookback_days, bool)
        or not isinstance(lookback_days, int)
        or not 1 <= lookback_days <= _POLICY_SIMULATION_MAX_LOOKBACK_DAYS
    ):
        raise ValueError("lookbackDays must be an integer from 1 to 90")
    candidate = _policy_version_record(tenant, policy_id, version)
    if candidate.get("state") not in {"draft", "review", "approved", "staged"}:
        raise PolicyConflict("only a pending policy version can be simulated")
    policy = TABLE.get_item(Key=_item_key(tenant, "POLICY", policy_id), ConsistentRead=True).get(
        "Item"
    )
    if not policy:
        raise LookupError("policy not found")
    governed = _ensure_policy_governance(tenant, policy)
    if int(candidate.get("base_version", -1)) != int(governed.get("version", 0)):
        raise PolicyConflict("policy simulation base is no longer active")
    now = int(time.time())
    cutoff = now - (lookback_days * 86_400)
    decision_window, truncated = _decision_window(tenant)
    decisions = [
        item
        for item in decision_window
        if item.get("policy_id") == policy_id and int(item.get("observed_at", 0)) >= cutoff
    ]
    items = []
    for item in decisions:
        predicted, reason_code = _policy_action_decision(candidate.get("configuration", {}), item)
        previous = (
            item.get("decision") if item.get("decision") in _DECISION_VALUES else "indeterminate"
        )
        items.append(
            {
                "decisionId": item.get("id"),
                "observedAt": int(item.get("observed_at", 0)),
                "source": item.get("source"),
                "toolName": item.get("tool_name"),
                "resourceKind": item.get("resource_kind"),
                "previousDecision": previous,
                "predictedDecision": predicted,
                "reasonCode": reason_code,
                "changed": predicted != "indeterminate" and predicted != previous,
            }
        )
    transitions = {}
    for item in items:
        key = f"{item['previousDecision']}_to_{item['predictedDecision']}"
        transitions[key] = transitions.get(key, 0) + 1
    groups = [
        item
        for item in _list(tenant, "GROUP", consistent_read=True)
        if item.get("policyId") == policy_id
    ]
    agent_keys = sorted(
        {
            agent_key
            for group in groups
            for agent_key in group.get("agent_keys", [])
            if isinstance(agent_key, str)
        }
    )
    stable_evidence = {
        "policyId": policy_id,
        "version": int(candidate["version"]),
        "baseVersion": int(candidate.get("base_version", 0)),
        "contentHash": candidate["content_hash"],
        "lookbackDays": lookback_days,
        "truncated": truncated,
        "items": items,
    }
    simulation_hash = hashlib.sha256(
        json.dumps(stable_evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    determined = sum(1 for item in items if item["predictedDecision"] != "indeterminate")
    return {
        "schemaVersion": 1,
        "policyId": policy_id,
        "version": int(candidate["version"]),
        "baseVersion": int(candidate.get("base_version", 0)),
        "contentHash": candidate["content_hash"],
        "simulationHash": simulation_hash,
        "generatedAt": now,
        "window": {
            "lookbackDays": lookback_days,
            "sampled": len(items),
            "maximumSample": _DECISION_WINDOW_LIMIT,
            "truncated": truncated,
        },
        "scope": {"groupIds": sorted(group["id"] for group in groups), "agentKeys": agent_keys},
        "counts": {
            "historical": len(items),
            "determined": determined,
            "indeterminate": len(items) - determined,
            "changed": sum(1 for item in items if item["changed"]),
            "predictedAllowed": sum(1 for item in items if item["predictedDecision"] == "allowed"),
            "predictedDenied": sum(1 for item in items if item["predictedDecision"] == "denied"),
            "predictedApprovalRequired": sum(
                1 for item in items if item["predictedDecision"] == "approval_required"
            ),
        },
        "coveragePercent": round((determined * 100 / len(items)), 1) if items else 0.0,
        "transitions": dict(sorted(transitions.items())),
        "items": items,
        "mutated": False,
    }


def _policy_summary(tenant, policy, versions=None):
    """Return active authority separately from the latest pending governed change."""
    governed = _ensure_policy_governance(tenant, policy)
    all_versions = versions if versions is not None else _policy_versions(tenant, governed["id"])
    pending = next(
        (item for item in all_versions if item.get("state") in _POLICY_PENDING_STATES), None
    )
    active_version = int(governed.get("version", 0)) or None
    latest_version = max((int(item.get("version", 0)) for item in all_versions), default=0)
    return {
        **governed,
        "version": int(governed.get("version", 0)),
        "activeVersion": active_version,
        "latestVersion": latest_version,
        "governanceState": pending.get("state")
        if pending
        else ("active" if active_version else "draft"),
        "pendingVersion": int(pending["version"]) if pending else None,
        "pendingAuthor": pending.get("author") if pending else None,
    }


def _policy_organization(tenant, body):
    """Resolve policy organization only from tenant-owned inventory."""
    organizations = _list(tenant, "ORG", consistent_read=True)
    requested = body.get("organizationId")
    if requested is None and len(organizations) == 1:
        return organizations[0]["id"]
    organization_id = _bounded_identifier(requested, "organizationId")
    if not any(item.get("id") == organization_id for item in organizations):
        raise ValueError("policy organization is not in the authenticated tenant")
    return organization_id


def _policy_composition_metadata(record):
    """Return reproducible composition metadata for new and legacy versions."""
    local = record.get("local_configuration")
    references = record.get("component_refs")
    graph_digest = record.get("graph_digest")
    explanation = record.get("composition_explanation")
    if local is None and references is None and graph_digest is None:
        # Pre-composition versions had no parents; treating their signed
        # effective configuration as local intent preserves exact authority.
        result = compose_policy((), _json(record.get("configuration", {}))).to_dict()
        return {
            "localConfiguration": _json(record.get("configuration", {})),
            "componentRefs": [],
            "graphDigest": result["graphDigest"],
            "explanation": result["explanation"],
        }
    if (
        not isinstance(local, dict)
        or not isinstance(references, list)
        or not isinstance(graph_digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", graph_digest)
        or not isinstance(explanation, list)
    ):
        raise PolicyConflict("policy component composition metadata is malformed")
    return {
        "localConfiguration": _json(local),
        "componentRefs": _json(references),
        "graphDigest": graph_digest,
        "explanation": _json(explanation),
    }


def _compose_governed_policy(tenant, organization_id, policy_id, body):
    """Resolve signed exact component versions and compose restrictive authority."""
    has_configuration = "configuration" in body
    has_local = "localConfiguration" in body
    if has_configuration and has_local:
        raise ValueError("provide configuration or localConfiguration, not both")
    references = body.get("componentRefs", [])
    if has_configuration and references:
        raise ValueError("componentRefs require explicit localConfiguration")
    if not isinstance(references, list):
        raise ValueError("componentRefs must be an array")
    if len(references) > 8:
        raise ValueError("a policy may reference at most eight components")
    local = body.get("localConfiguration") if has_local else body.get("configuration", {})
    local = _policy_configuration(tenant, local)
    visited = set()

    def resolve(reference, depth, owner_policy_id):
        if depth > 4:
            raise ValueError("policy component depth exceeds four levels")
        if not isinstance(reference, dict) or set(reference) != {
            "policyId",
            "version",
            "contentHash",
        }:
            raise ValueError("component references require policyId, version, and contentHash")
        component_policy_id = _bounded_identifier(reference.get("policyId"), "policyId")
        version = _positive_policy_version(reference.get("version"))
        content_hash = reference.get("contentHash")
        if not isinstance(content_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", content_hash):
            raise ValueError("component contentHash must be SHA-256 hex")
        if secrets.compare_digest(component_policy_id, owner_policy_id):
            raise ValueError("a policy cannot reference its own versions")
        identity = (component_policy_id, version)
        if identity in visited:
            raise ValueError("policy component graph contains a duplicate or cycle")
        visited.add(identity)
        if len(visited) > 32:
            raise ValueError("policy component graph exceeds 32 versions")
        record = _policy_version_record(tenant, component_policy_id, version)
        if record.get("organization_id") != organization_id:
            raise PermissionError("policy components must belong to the same organization")
        if record.get("state") not in {"active", "retired"}:
            raise PolicyConflict("policy components must be active or retired")
        if (
            record.get("decision") != "approved"
            or not record.get("decided_by")
            or record.get("decided_by") == record.get("author")
        ):
            raise PermissionError("policy component lacks independent approval")
        if not secrets.compare_digest(str(record.get("content_hash", "")), content_hash):
            raise PolicyConflict("policy component content hash does not match")
        configuration = _json(record.get("configuration", {}))
        if not secrets.compare_digest(_configuration_hash(configuration), content_hash):
            raise PolicyConflict("policy component content integrity check failed")
        # AWS components must retain a self-consistent signed bundle from their
        # activation. Browser or database metadata alone is never sufficient.
        bundle = bundle_from_record(tenant, component_policy_id, version, _json(record))
        verify_policy_bundle(KMS, POLICY_SIGNING_KEY_ARN, bundle)
        if bundle["configuration"] != _managed_policy_configuration(tenant, configuration):
            raise PolicyConflict("policy component signed authority is inconsistent")
        metadata = _policy_composition_metadata(record)
        nested_components = []
        for nested in metadata["componentRefs"]:
            nested_record, nested_metadata = resolve(nested, depth + 1, component_policy_id)
            nested_components.append(
                PolicyComponent(
                    nested_record["policy_id"],
                    int(nested_record["version"]),
                    nested_record["content_hash"],
                    _json(nested_record["configuration"]),
                    nested_metadata["graphDigest"],
                )
            )
        try:
            reproduced = compose_policy(nested_components, metadata["localConfiguration"]).to_dict()
        except PolicyCompositionError as error:
            raise PolicyConflict("policy component cannot be reproduced") from error
        if reproduced["configuration"] != configuration:
            raise PolicyConflict("policy component effective configuration is inconsistent")
        if not secrets.compare_digest(reproduced["graphDigest"], metadata["graphDigest"]):
            raise PolicyConflict("policy component graph integrity check failed")
        return record, metadata

    components = []
    normalized_references = []
    for reference in references:
        record, metadata = resolve(reference, 1, policy_id)
        normalized_references.append(
            {
                "policyId": record["policy_id"],
                "version": int(record["version"]),
                "contentHash": record["content_hash"],
            }
        )
        components.append(
            PolicyComponent(
                record["policy_id"],
                int(record["version"]),
                record["content_hash"],
                _json(record["configuration"]),
                metadata["graphDigest"],
            )
        )
    try:
        result = compose_policy(components, local).to_dict()
    except PolicyCompositionError as error:
        raise ValueError(str(error)) from error
    effective = _policy_configuration(tenant, result["configuration"])
    return {
        "configuration": effective,
        "local_configuration": local,
        "component_refs": normalized_references,
        "graph_digest": result["graphDigest"],
        "composition_explanation": result["explanation"],
    }


def _assert_governed_policy_composition(tenant, record):
    """Reproduce one stored candidate before staging or activation."""
    metadata = _policy_composition_metadata(record)
    recomposed = _compose_governed_policy(
        tenant,
        record.get("organization_id", ""),
        record["policy_id"],
        {
            "localConfiguration": metadata["localConfiguration"],
            "componentRefs": metadata["componentRefs"],
        },
    )
    if recomposed["configuration"] != _json(record.get("configuration", {})):
        raise PolicyConflict("policy effective configuration no longer reproduces")
    if not secrets.compare_digest(recomposed["graph_digest"], metadata["graphDigest"]):
        raise PolicyConflict("policy composition provenance no longer reproduces")


def _policy_source_request(body):
    """Parse one exact Git locator without accepting browser evidence or content."""
    if not isinstance(body, dict) or set(body) != {
        "importId",
        "repository",
        "commitSha",
        "path",
    }:
        raise ValueError("policy import request schema is invalid")
    import_id = _bounded_identifier(body.get("importId"), "importId")
    try:
        request = PolicySourceRequest(
            repository=body.get("repository"),
            commit_sha=body.get("commitSha"),
            path=body.get("path"),
        )
    except PolicySourceVerificationError as error:
        raise ValueError(str(error)) from error
    return import_id, request


def _invoke_policy_source_verifier(request):
    """Invoke the isolated credential-owning worker and revalidate all evidence."""
    if not POLICY_SOURCE_VERIFIER_ARN:
        raise ValueError("policy source verification is not configured")
    try:
        response = LAMBDA.invoke(
            FunctionName=POLICY_SOURCE_VERIFIER_ARN,
            InvocationType="RequestResponse",
            Payload=json.dumps(request.wire(), sort_keys=True, separators=(",", ":")).encode(),
        )
        stream = response.get("Payload")
        payload = stream.read(2_000_001) if stream is not None else b""
    except Exception as error:
        raise ValueError("policy source verification failed") from error
    if (
        response.get("StatusCode") != 200
        or response.get("FunctionError")
        or len(payload) > 2_000_000
    ):
        raise ValueError("policy source verification failed")
    try:
        result = json.loads(payload)
        if not isinstance(result, dict) or set(result) != {
            "schemaVersion",
            "evidence",
            "evidenceDigest",
            "contentBase64",
        }:
            raise ValueError
        if result.get("schemaVersion") != 1 or not isinstance(result.get("evidence"), dict):
            raise ValueError
        evidence = result["evidence"]
        content = base64.b64decode(result["contentBase64"], validate=True)
        reviewed_by = evidence.get("reviewedBy")
        verified = VerifiedPolicySource(
            provider=evidence.get("provider"),
            repository=evidence.get("repository"),
            commit_sha=evidence.get("commitSha"),
            blob_sha=evidence.get("blobSha"),
            path=evidence.get("path"),
            content=content,
            pull_request=evidence.get("pullRequest"),
            reviewed_by=tuple(reviewed_by) if isinstance(reviewed_by, list) else (),
            signer_identity=evidence.get("signerIdentity"),
            retrieved_at=evidence.get("retrievedAt"),
            review_verified=evidence.get("reviewVerified"),
            signature_verified=evidence.get("signatureVerified"),
        )
    except Exception as error:
        raise ValueError("policy source verifier returned invalid evidence") from error
    if (
        verified.repository != request.repository
        or verified.commit_sha != request.commit_sha
        or verified.path != request.path
        or not isinstance(result.get("evidenceDigest"), str)
        or not secrets.compare_digest(verified.evidence_digest, result["evidenceDigest"])
    ):
        raise ValueError("policy source verifier returned different evidence")
    return verified


def _policy_import_view(record):
    """Project one import record without source bytes or provider credentials."""
    return {
        "organizationId": record["organization_id"],
        "importId": record["id"],
        "status": record["status"],
        "source": {
            "repository": record["repository"],
            "commitSha": record["commit_sha"],
            "blobSha": record["blob_sha"],
            "path": record["path"],
            "sourceDigest": record["source_digest"],
            "evidenceDigest": record["evidence_digest"],
        },
        "draft": {
            "policyId": record["policy_id"],
            "version": int(record["policy_version"]),
            "state": "draft",
        },
        "provenance": _json(record["provenance"]),
        "createdAt": int(record["created_at"]),
        "createdBy": record["created_by"],
    }


def _import_policy_source(tenant, body, actor):
    """Verify Git evidence and atomically create only an inactive governed draft."""
    import_id, request = _policy_source_request(body)
    request_digest = hashlib.sha256(
        json.dumps(request.wire(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    existing = TABLE.get_item(
        Key=_item_key(tenant, "POLICY_IMPORT", import_id), ConsistentRead=True
    ).get("Item")
    if existing:
        if secrets.compare_digest(str(existing.get("request_digest", "")), request_digest):
            return _policy_import_view(existing)
        raise PolicyConflict("policy import ID is bound to a different source")
    verified = _invoke_policy_source_verifier(request)
    document = PolicySourceDocument.from_bytes(verified.content)
    organizations = _list(tenant, "ORG", consistent_read=True)
    if not any(item.get("id") == document.organization_id for item in organizations):
        raise PermissionError("policy source organization scope is not permitted")
    duplicate = next(
        (
            item
            for item in _list(tenant, "POLICY_IMPORT", consistent_read=True)
            if secrets.compare_digest(
                str(item.get("evidence_digest", "")), verified.evidence_digest
            )
            and secrets.compare_digest(str(item.get("source_digest", "")), document.content_digest)
        ),
        None,
    )
    if duplicate:
        return _policy_import_view(duplicate)
    current = TABLE.get_item(
        Key=_item_key(tenant, "POLICY", document.policy_id), ConsistentRead=True
    ).get("Item")
    versions = _policy_versions(tenant, document.policy_id, consistent_read=True) if current else []
    if current and current.get("organization_id") != document.organization_id:
        raise PermissionError("policy source policy scope is not permitted")
    if any(item.get("state") in _POLICY_PENDING_STATES for item in versions):
        raise PolicyConflict("policy already has a pending governed version")
    latest = max((int(item.get("version", 0)) for item in versions), default=0)
    version_number = latest + 1
    base_version = int(current.get("version", 0)) if current else 0
    composition = _compose_governed_policy(
        tenant,
        document.organization_id,
        document.policy_id,
        {
            "localConfiguration": document.local_configuration,
            "componentRefs": list(document.component_refs),
        },
    )
    now = int(time.time())
    provenance = {
        "schemaVersion": 1,
        "importId": import_id,
        "requestDigest": request_digest,
        "canonicalSourceDigest": document.content_digest,
        "providerEvidence": verified.evidence(),
        "evidenceDigest": verified.evidence_digest,
    }
    version = {
        **_item_key(
            tenant,
            "POLICY_VERSION",
            _policy_version_identifier(document.policy_id, version_number),
        ),
        "tenant_id": tenant,
        "id": _policy_version_identifier(document.policy_id, version_number),
        "policy_id": document.policy_id,
        "organization_id": document.organization_id,
        "version": version_number,
        "base_version": base_version,
        "name": document.name,
        "configuration": composition["configuration"],
        "local_configuration": composition["local_configuration"],
        "component_refs": composition["component_refs"],
        "graph_digest": composition["graph_digest"],
        "composition_explanation": composition["composition_explanation"],
        "source_provenance": provenance,
        "content_hash": _configuration_hash(composition["configuration"]),
        "state": "draft",
        "author": actor,
        "created_at": now,
    }
    policy = (
        {
            **current,
            "latestVersion": version_number,
            "governanceState": "draft",
            "pendingVersion": version_number,
            "pendingAuthor": actor,
            "updatedAt": now,
        }
        if current
        else {
            **_item_key(tenant, "POLICY", document.policy_id),
            "tenant_id": tenant,
            "id": document.policy_id,
            "organization_id": document.organization_id,
            "name": document.name,
            "configuration": {},
            "version": 0,
            "activeVersion": None,
            "latestVersion": 1,
            "governanceState": "draft",
            "pendingVersion": 1,
            "pendingAuthor": actor,
            "governance_schema_version": 1,
            "createdAt": now,
            "author": actor,
        }
    )
    imported = {
        **_item_key(tenant, "POLICY_IMPORT", import_id),
        "tenant_id": tenant,
        "id": import_id,
        "organization_id": document.organization_id,
        "request_digest": request_digest,
        "evidence_digest": verified.evidence_digest,
        "source_digest": document.content_digest,
        "repository": verified.repository,
        "commit_sha": verified.commit_sha,
        "blob_sha": verified.blob_sha,
        "path": verified.path,
        "policy_id": document.policy_id,
        "policy_version": version_number,
        "status": "draft_created",
        "provenance": provenance,
        "created_at": now,
        "created_by": actor,
    }
    policy_condition = "attribute_not_exists(pk)" if not current else "#v = :v AND #l = :l"
    policy_names = None if not current else {"#v": "version", "#l": "latestVersion"}
    policy_values = None if not current else {":v": base_version, ":l": latest}
    _transact_policy_records(
        [
            _transaction_put(version, condition="attribute_not_exists(pk)"),
            _transaction_put(
                policy, condition=policy_condition, names=policy_names, values=policy_values
            ),
            _transaction_put(imported, condition="attribute_not_exists(pk)"),
        ]
    )
    _audit(
        tenant,
        "policy_source_imported",
        actor,
        {
            "import_id": import_id,
            "policy_id": document.policy_id,
            "version": version_number,
            "source_digest": document.content_digest,
            "evidence_digest": verified.evidence_digest,
        },
    )
    return _policy_import_view(imported)


def _export_policy_source(tenant, policy_id, version, actor):
    """Return canonical policy source with a KMS-signed provenance envelope."""
    if not POLICY_SIGNING_KEY_ARN:
        raise ValueError("policy export signing is not configured")
    record = _policy_version_record(tenant, policy_id, version)
    metadata = _policy_composition_metadata(record)
    document = PolicySourceDocument.from_bytes(
        json.dumps(
            {
                "schemaVersion": 1,
                "policyId": policy_id,
                "organizationId": record.get("organization_id"),
                "name": record.get("name"),
                "componentRefs": metadata["componentRefs"],
                "localConfiguration": metadata["localConfiguration"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    provenance = {
        "schemaVersion": 1,
        "organizationId": document.organization_id,
        "policyId": policy_id,
        "version": version,
        "contentHash": record["content_hash"],
        "graphDigest": metadata["graphDigest"],
        "sourceSha256": document.content_digest,
        "exportedBy": actor,
        "exportedAt": int(time.time()),
    }
    payload = json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode()
    try:
        signed = KMS.sign(
            KeyId=POLICY_SIGNING_KEY_ARN,
            Message=payload,
            MessageType="RAW",
            SigningAlgorithm="ECDSA_SHA_256",
        )
    except Exception as error:
        raise ValueError("policy export signing failed") from error
    if (
        signed.get("KeyId") != POLICY_SIGNING_KEY_ARN
        or signed.get("SigningAlgorithm") != "ECDSA_SHA_256"
        or not isinstance(signed.get("Signature"), bytes)
    ):
        raise ValueError("policy export signer returned invalid evidence")
    _audit(
        tenant,
        "policy_source_exported",
        actor,
        {"policy_id": policy_id, "version": version, "source_digest": document.content_digest},
    )
    return {
        "document": document.wire(),
        "canonicalDocument": document.canonical_bytes().decode(),
        "sourceSha256": document.content_digest,
        "provenance": {
            **provenance,
            "integrity": {
                "keyId": POLICY_SIGNING_KEY_ARN,
                "algorithm": "ECDSA_SHA_256",
                "signature": base64.b64encode(signed["Signature"]).decode(),
                "signedAt": provenance["exportedAt"],
            },
        },
    }


def _create_governed_policy(tenant, body, actor):
    """Atomically create a policy shell and its first inactive draft."""
    policy_id = _bounded_identifier(body.get("policyId"), "policyId")
    name = _bounded_text(body.get("name"), "name")
    organization_id = _policy_organization(tenant, body)
    composition = _compose_governed_policy(tenant, organization_id, policy_id, body)
    configuration = composition["configuration"]
    now = int(time.time())
    policy = {
        **_item_key(tenant, "POLICY", policy_id),
        "tenant_id": tenant,
        "id": policy_id,
        "organization_id": organization_id,
        "name": name,
        "configuration": {},
        "version": 0,
        "activeVersion": None,
        "latestVersion": 1,
        "governanceState": "draft",
        "pendingVersion": 1,
        "pendingAuthor": actor,
        "governance_schema_version": 1,
        "createdAt": now,
        "author": actor,
    }
    version = {
        **_item_key(
            tenant,
            "POLICY_VERSION",
            _policy_version_identifier(policy_id, 1),
        ),
        "tenant_id": tenant,
        "id": _policy_version_identifier(policy_id, 1),
        "policy_id": policy_id,
        "organization_id": organization_id,
        "version": 1,
        "base_version": 0,
        "name": name,
        "configuration": configuration,
        "local_configuration": composition["local_configuration"],
        "component_refs": composition["component_refs"],
        "graph_digest": composition["graph_digest"],
        "composition_explanation": composition["composition_explanation"],
        "content_hash": _configuration_hash(configuration),
        "state": "draft",
        "author": actor,
        "created_at": now,
    }
    _transact_policy_records(
        [
            _transaction_put(policy, condition="attribute_not_exists(pk)"),
            _transaction_put(version, condition="attribute_not_exists(pk)"),
        ]
    )
    _audit(tenant, "policy_draft_created", actor, {"policy_id": policy_id, "version": 1})
    return _policy_summary(tenant, policy, [version])


def _create_policy_draft(tenant, policy_id, body, actor):
    """Atomically append one draft without changing current active authority."""
    policy_id = _bounded_identifier(policy_id, "policyId")
    current = TABLE.get_item(Key=_item_key(tenant, "POLICY", policy_id), ConsistentRead=True).get(
        "Item"
    )
    if not current:
        raise LookupError("policy not found")
    policy = _ensure_policy_governance(tenant, current)
    versions = _policy_versions(tenant, policy_id, consistent_read=True)
    if any(item.get("state") in _POLICY_PENDING_STATES for item in versions):
        raise PolicyConflict("policy already has a pending governed version")
    latest = max((int(item.get("version", 0)) for item in versions), default=0)
    version_number = latest + 1
    name = _bounded_text(body.get("name"), "name")
    composition = _compose_governed_policy(
        tenant,
        policy.get("organization_id", ""),
        policy_id,
        body,
    )
    configuration = composition["configuration"]
    now = int(time.time())
    version = {
        **_item_key(
            tenant,
            "POLICY_VERSION",
            _policy_version_identifier(policy_id, version_number),
        ),
        "tenant_id": tenant,
        "id": _policy_version_identifier(policy_id, version_number),
        "policy_id": policy_id,
        "organization_id": policy.get("organization_id", ""),
        "version": version_number,
        "base_version": int(policy.get("version", 0)),
        "name": name,
        "configuration": configuration,
        "local_configuration": composition["local_configuration"],
        "component_refs": composition["component_refs"],
        "graph_digest": composition["graph_digest"],
        "composition_explanation": composition["composition_explanation"],
        "content_hash": _configuration_hash(configuration),
        "state": "draft",
        "author": actor,
        "created_at": now,
    }
    updated_policy = {
        **policy,
        "latestVersion": version_number,
        "governanceState": "draft",
        "pendingVersion": version_number,
        "pendingAuthor": actor,
        "updatedAt": now,
    }
    _transact_policy_records(
        [
            _transaction_put(version, condition="attribute_not_exists(pk)"),
            _transaction_put(
                updated_policy,
                condition="#version = :active AND #latest = :latest",
                names={"#version": "version", "#latest": "latestVersion"},
                values={":active": int(policy.get("version", 0)), ":latest": latest},
            ),
        ]
    )
    _audit(
        tenant,
        "policy_draft_created",
        actor,
        {"policy_id": policy_id, "version": version_number},
    )
    return _policy_version_view(tenant, version, [version, *versions])


def _policy_version_record(tenant, policy_id, version):
    """Load one exact tenant policy version with a strongly consistent read."""
    record = TABLE.get_item(
        Key=_item_key(
            tenant,
            "POLICY_VERSION",
            _policy_version_identifier(policy_id, version),
        ),
        ConsistentRead=True,
    ).get("Item")
    if not record or record.get("policy_id") != policy_id:
        raise LookupError("policy version not found")
    return record


def _put_policy_transition(tenant, record, *, expected_state, event, actor):
    """Commit one exact-state lifecycle transition without accepting request syntax."""
    try:
        TABLE.put_item(
            Item=record,
            ConditionExpression="#state = :expected",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={":expected": expected_state},
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict(
                f"policy version must be {expected_state} before this transition"
            ) from error
        raise
    _audit(
        tenant,
        event,
        actor,
        {"policy_id": record["policy_id"], "version": int(record["version"])},
    )
    return _policy_version_view(tenant, record)


def _submit_policy_version(tenant, policy_id, version, actor):
    """Freeze one draft and submit it for independent review."""
    record = _policy_version_record(tenant, policy_id, version)
    if record.get("state") != "draft":
        raise PolicyConflict("policy version is not a draft")
    updated = {
        **record,
        "state": "review",
        "submitted_by": actor,
        "submitted_at": int(time.time()),
    }
    return _put_policy_transition(
        tenant,
        updated,
        expected_state="draft",
        event="policy_submitted",
        actor=actor,
    )


def _decide_policy_version(tenant, policy_id, version, body, actor):
    """Approve or reject a submitted version with two-subject separation."""
    decision = body.get("decision")
    if decision not in {"approved", "rejected"}:
        raise ValueError("policy decision must be approved or rejected")
    reason = _bounded_text(body.get("reason"), "reason", 1_000)
    record = _policy_version_record(tenant, policy_id, version)
    if record.get("state") != "review":
        raise PolicyConflict("policy version is not awaiting review")
    if decision == "approved" and secrets.compare_digest(str(record.get("author", "")), actor):
        raise PermissionError("policy authors cannot approve their own version")
    now = int(time.time())
    updated = {
        **record,
        "state": decision,
        "decision": decision,
        "decided_by": actor,
        "decided_at": now,
        "decision_reason": reason,
    }
    return _put_policy_transition(
        tenant,
        updated,
        expected_state="review",
        event="policy_decided",
        actor=actor,
    )


def _stage_policy_version(tenant, policy_id, version, actor):
    """Stage an independently approved version against its exact active base."""
    record = _policy_version_record(tenant, policy_id, version)
    policy = TABLE.get_item(Key=_item_key(tenant, "POLICY", policy_id), ConsistentRead=True).get(
        "Item"
    )
    if not policy:
        raise LookupError("policy not found")
    policy = _ensure_policy_governance(tenant, policy)
    if record.get("state") != "approved":
        raise PolicyConflict("policy version is not approved")
    if not record.get("decided_by") or record.get("decided_by") == record.get("author"):
        raise PermissionError("policy version lacks independent approval")
    if int(record.get("base_version", -1)) != int(policy.get("version", 0)):
        raise PolicyConflict("policy active version changed before staging")
    _assert_governed_policy_composition(tenant, record)
    updated = {
        **record,
        "state": "staged",
        "staged_by": actor,
        "staged_at": int(time.time()),
    }
    return _put_policy_transition(
        tenant,
        updated,
        expected_state="approved",
        event="policy_staged",
        actor=actor,
    )


def _activate_policy_version(tenant, policy_id, version, body, actor):
    """Atomically activate a staged version and retire previous fleet authority."""
    expected = body.get("expectedActiveVersion")
    if isinstance(expected, bool) or not isinstance(expected, int) or expected < 0:
        raise ValueError("expectedActiveVersion must be a non-negative integer")
    candidate = _policy_version_record(tenant, policy_id, version)
    current = TABLE.get_item(Key=_item_key(tenant, "POLICY", policy_id), ConsistentRead=True).get(
        "Item"
    )
    if not current:
        raise LookupError("policy not found")
    policy = _ensure_policy_governance(tenant, current)
    if candidate.get("state") != "staged":
        raise PolicyConflict("policy version is not staged")
    if not candidate.get("decided_by") or candidate.get("decided_by") == candidate.get("author"):
        raise PermissionError("policy version lacks independent approval")
    if (
        int(policy.get("version", 0)) != expected
        or int(candidate.get("base_version", -1)) != expected
    ):
        raise PolicyConflict("policy active version changed before activation")
    _assert_governed_policy_composition(tenant, candidate)
    now = int(time.time())
    effective_configuration = _managed_policy_configuration(tenant, candidate["configuration"])
    bundle = _sign_policy_bundle(tenant, policy_id, version, effective_configuration, now)
    active_candidate = {
        **candidate,
        **_bundle_record_fields(bundle),
        "state": "active",
        "activated_by": actor,
        "activated_at": now,
    }
    active_policy = {
        **policy,
        "name": candidate["name"],
        "configuration": candidate["configuration"],
        "version": version,
        "activeVersion": version,
        "latestVersion": max(int(policy.get("latestVersion", 0)), version),
        "governanceState": "active",
        "pendingVersion": None,
        "pendingAuthor": None,
        "updatedAt": now,
    }
    operations = [
        _transaction_put(
            active_candidate,
            condition="#state = :staged",
            names={"#state": "state"},
            values={":staged": "staged"},
        )
    ]
    if expected > 0:
        previous = _policy_version_record(tenant, policy_id, expected)
        retired = {**previous, "state": "retired"}
        operations.append(
            _transaction_put(
                retired,
                condition="#state = :active",
                names={"#state": "state"},
                values={":active": "active"},
            )
        )
    operations.append(
        _transaction_put(
            active_policy,
            condition="#version = :expected",
            names={"#version": "version"},
            values={":expected": expected},
        )
    )
    _transact_policy_records(operations)
    _audit(
        tenant,
        "policy_activated",
        actor,
        {"policy_id": policy_id, "version": version, "previous_version": expected},
    )
    return _policy_summary(tenant, active_policy)


def _policy_exception_record(tenant, exception_id):
    """Load one tenant-scoped exception with a strongly consistent read."""
    exception_id = _bounded_identifier(exception_id, "exceptionId")
    record = TABLE.get_item(
        Key=_item_key(tenant, "POLICY_EXCEPTION", exception_id),
        ConsistentRead=True,
    ).get("Item")
    if not record:
        raise LookupError("policy exception not found")
    return record


def _policy_exception_scope(tenant, deployment_id, agent_id):
    """Resolve exact server-owned agent, group and active policy authority."""
    deployment_id = _bounded_identifier(deployment_id, "deploymentId")
    agent_id = _bounded_identifier(agent_id, "agentId")
    agent_key = f"{deployment_id}:{agent_id}"
    agent = TABLE.get_item(Key=_item_key(tenant, "AGENT", agent_key), ConsistentRead=True).get(
        "Item"
    )
    if not agent or _agent_lifecycle_state(agent) != "active":
        raise PolicyConflict("policy exception requires an active enrolled agent")
    groups = [
        group
        for group in _list(tenant, "GROUP", consistent_read=True)
        if agent_key in group.get("agent_keys", [])
    ]
    if len(groups) != 1:
        raise PolicyConflict("policy exception requires exactly one assigned policy group")
    group = groups[0]
    policy = TABLE.get_item(
        Key=_item_key(tenant, "POLICY", group.get("policyId", "")),
        ConsistentRead=True,
    ).get("Item")
    if not policy:
        raise PolicyConflict("policy exception base policy is unavailable")
    policy = _ensure_policy_governance(tenant, policy)
    version = int(policy.get("version", 0))
    if version <= 0:
        raise PolicyConflict("policy exception base policy has no active version")
    version_record = _policy_version_record(tenant, policy["id"], version)
    return agent, group, policy, version_record


def _policy_exception_view(record, now=None):
    """Return bounded lifecycle, scope and authority-change metadata."""
    current = int(time.time()) if now is None else int(now)
    state = record.get("state", "invalidated")
    if state not in _POLICY_EXCEPTION_OPEN_STATES | _POLICY_EXCEPTION_TERMINAL_STATES:
        raise RuntimeError("policy exception state is invalid")
    expires_at = int(record.get("expires_at", 0))
    return {
        "id": record.get("id", ""),
        "deploymentId": record.get("deployment_id", ""),
        "agentId": record.get("agent_id", ""),
        "agentKey": record.get("agent_key", ""),
        "groupId": record.get("group_id", ""),
        "policyId": record.get("policy_id", ""),
        "basePolicyVersion": int(record.get("base_policy_version", 0)),
        "baseContentHash": record.get("base_content_hash", ""),
        "derivedPolicyId": record.get("derived_policy_id"),
        "configuration": _json(record.get("configuration", {})),
        "contentHash": record.get("content_hash", ""),
        "changeSummary": _semantic_policy_diff(
            record.get("base_configuration", {}), record.get("configuration", {})
        ),
        "state": state,
        "effective": state == "active" and expires_at > current,
        "owner": record.get("owner", ""),
        "purpose": record.get("purpose", ""),
        "author": record.get("author", ""),
        "createdAt": int(record.get("created_at", 0)),
        "expiresAt": expires_at,
        "remainingSeconds": max(0, expires_at - current),
        "submittedBy": record.get("submitted_by"),
        "submittedAt": record.get("submitted_at"),
        "decidedBy": record.get("decided_by"),
        "decidedAt": record.get("decided_at"),
        "decisionReason": record.get("decision_reason"),
        "activatedBy": record.get("activated_by"),
        "activatedAt": record.get("activated_at"),
        "endedBy": record.get("ended_by"),
        "endedAt": record.get("ended_at"),
        "endReason": record.get("end_reason"),
    }


def _validate_policy_exception_delta(base_configuration, candidate_configuration):
    """Permit only the focused temporary authority fields exposed by the UI.

    Identity scope, approval provider, credentials, isolation, data capture,
    telemetry and every immutable safeguard remain inherited from the reviewed
    base policy. Enforcing this again at the API boundary prevents an advanced
    client from bypassing the typed editor.
    """
    base = _json(base_configuration)
    candidate = _json(candidate_configuration)
    mutable_fields = {
        "tools": {"allowed", "denied", "builtIn"},
        "claudeCode": {
            "allowedBuiltInTools",
            "allowedSkills",
            "allowedMcpServers",
            "allowedCommandPatterns",
            "deniedCommandPatterns",
            "approvalCommandPatterns",
        },
        "budgets": {"maxActions"},
    }
    for section, fields in mutable_fields.items():
        for document in (base, candidate):
            section_value = document.get(section)
            if isinstance(section_value, dict):
                for field in fields:
                    section_value.pop(field, None)
                if not section_value:
                    document.pop(section, None)
    if base != candidate:
        raise ValueError(
            "policy exception may change only temporary tool, Claude command/resource, "
            "and maximum-action fields"
        )


def _put_policy_exception_transition(tenant, record, expected_state, updated, event, actor):
    """Compare-and-swap one exception transition before emitting audit evidence."""
    if expected_state not in _POLICY_EXCEPTION_OPEN_STATES:
        raise ValueError("policy exception expected state is invalid")
    try:
        TABLE.put_item(
            Item=updated,
            ConditionExpression="#state = :expected",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={":expected": expected_state},
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("policy exception state changed concurrently") from error
        raise
    _audit(
        tenant,
        event,
        actor,
        {
            "exception_id": record["id"],
            "deployment_id": record["deployment_id"],
            "agent_id": record["agent_id"],
            "policy_id": record["policy_id"],
            "base_policy_version": int(record["base_policy_version"]),
            "expires_at": int(record["expires_at"]),
        },
    )
    return updated


def _reconcile_policy_exception(tenant, record, now=None):
    """Expire or invalidate an open exception from live server-owned facts."""
    state = record.get("state")
    if state not in _POLICY_EXCEPTION_OPEN_STATES:
        return record
    current = int(time.time()) if now is None else int(now)
    terminal_state = None
    reason = None
    if int(record.get("expires_at", 0)) <= current:
        terminal_state, reason = "expired", "server-clock expiry restored base policy"
    else:
        try:
            _, group, policy, version_record = _policy_exception_scope(
                tenant, record.get("deployment_id"), record.get("agent_id")
            )
            bindings_match = (
                group.get("id") == record.get("group_id")
                and policy.get("id") == record.get("policy_id")
                and int(policy.get("version", 0)) == int(record.get("base_policy_version", -1))
                and secrets.compare_digest(
                    str(version_record.get("content_hash", "")),
                    str(record.get("base_content_hash", "")),
                )
            )
        except (LookupError, PolicyConflict, ValueError):
            bindings_match = False
        if not bindings_match:
            terminal_state, reason = "invalidated", "agent, group or base policy changed"
    if terminal_state is None:
        return record
    updated = {
        **record,
        "state": terminal_state,
        "ended_by": "policy-exception-reconciler",
        "ended_at": current,
        "end_reason": reason,
    }
    try:
        return _put_policy_exception_transition(
            tenant,
            record,
            state,
            updated,
            f"policy_exception_{terminal_state}",
            "policy-exception-reconciler",
        )
    except PolicyConflict:
        return _policy_exception_record(tenant, record["id"])


def _create_policy_exception(tenant, body, actor):
    """Create one inactive exception bound to current exact fleet authority."""
    required = {
        "exceptionId",
        "deploymentId",
        "agentId",
        "owner",
        "purpose",
        "expiresAt",
        "configuration",
    }
    if not isinstance(body, dict) or set(body) != required:
        raise ValueError("policy exception request has an invalid schema")
    exception_id = _bounded_identifier(body.get("exceptionId"), "exceptionId")
    owner = _bounded_text(body.get("owner"), "owner", 256)
    purpose = _bounded_text(body.get("purpose"), "purpose", 512)
    expires_at = body.get("expiresAt")
    now = int(time.time())
    if isinstance(expires_at, bool) or not isinstance(expires_at, int):
        raise ValueError("expiresAt must be a server-comparable epoch second")
    if not now + _POLICY_EXCEPTION_MIN_SECONDS <= expires_at <= now + _POLICY_EXCEPTION_MAX_SECONDS:
        raise ValueError("policy exception expiry must be between 15 minutes and 7 days")
    agent, group, policy, version_record = _policy_exception_scope(
        tenant, body.get("deploymentId"), body.get("agentId")
    )
    configuration = _policy_configuration(tenant, body.get("configuration"))
    base_configuration = _json(policy.get("configuration", {}))
    _validate_policy_exception_delta(base_configuration, configuration)
    if secrets.compare_digest(
        _configuration_hash(configuration), _configuration_hash(base_configuration)
    ):
        raise ValueError("policy exception must change the effective policy")
    agent_key = f"{agent['deployment_id']}:{agent['id']}"
    slot_key = _item_key(tenant, "POLICY_EXCEPTION_SLOT", agent_key)
    slot = TABLE.get_item(Key=slot_key, ConsistentRead=True).get("Item")
    previous_id = None
    if slot:
        previous_id = slot.get("exception_id")
        previous = _policy_exception_record(tenant, previous_id)
        previous = _reconcile_policy_exception(tenant, previous, now)
        previous_state = previous.get("state")
        if previous_state in _POLICY_EXCEPTION_OPEN_STATES:
            raise PolicyConflict("agent already has an open policy exception")
        if previous_state not in _POLICY_EXCEPTION_TERMINAL_STATES:
            raise RuntimeError("existing policy exception state is invalid")
    derived_policy_id = f"exception:{hashlib.sha256(exception_id.encode()).hexdigest()[:32]}"
    record = {
        **_item_key(tenant, "POLICY_EXCEPTION", exception_id),
        "tenant_id": tenant,
        "id": exception_id,
        "deployment_id": agent["deployment_id"],
        "agent_id": agent["id"],
        "agent_key": agent_key,
        "group_id": group["id"],
        "policy_id": policy["id"],
        "base_policy_version": int(policy["version"]),
        "base_content_hash": version_record["content_hash"],
        "base_configuration": base_configuration,
        "derived_policy_id": derived_policy_id,
        "configuration": configuration,
        "content_hash": _configuration_hash(configuration),
        "state": "draft",
        "owner": owner,
        "purpose": purpose,
        "author": actor,
        "created_at": now,
        "expires_at": expires_at,
        "ttl": expires_at + (30 * 86400),
    }
    slot_record = {
        **slot_key,
        "tenant_id": tenant,
        "id": agent_key,
        "exception_id": exception_id,
        "updated_at": now,
    }
    slot_condition = (
        "attribute_not_exists(pk)" if previous_id is None else "exception_id = :previous"
    )
    slot_values = None if previous_id is None else {":previous": previous_id}
    _transact_policy_records(
        [
            _transaction_put(record, condition="attribute_not_exists(pk)"),
            _transaction_put(slot_record, condition=slot_condition, values=slot_values),
        ]
    )
    _audit(
        tenant,
        "policy_exception_draft_created",
        actor,
        {
            "exception_id": exception_id,
            "deployment_id": agent["deployment_id"],
            "agent_id": agent["id"],
            "policy_id": policy["id"],
            "base_policy_version": int(policy["version"]),
            "expires_at": expires_at,
        },
    )
    return _policy_exception_view(record, now)


def _submit_policy_exception(tenant, exception_id, actor):
    """Freeze one exception draft for independent review."""
    record = _reconcile_policy_exception(tenant, _policy_exception_record(tenant, exception_id))
    if record.get("state") != "draft":
        raise PolicyConflict("policy exception is not a draft")
    now = int(time.time())
    updated = {**record, "state": "review", "submitted_by": actor, "submitted_at": now}
    return _policy_exception_view(
        _put_policy_exception_transition(
            tenant, record, "draft", updated, "policy_exception_submitted", actor
        ),
        now,
    )


def _decide_policy_exception(tenant, exception_id, body, actor):
    """Approve or reject one exception while enforcing two-subject review."""
    if not isinstance(body, dict) or set(body) != {"decision", "reason"}:
        raise ValueError("policy exception decision has an invalid schema")
    decision = body.get("decision")
    if decision not in {"approved", "rejected"}:
        raise ValueError("policy exception decision must be approved or rejected")
    reason = _bounded_text(body.get("reason"), "reason", 512)
    record = _reconcile_policy_exception(tenant, _policy_exception_record(tenant, exception_id))
    if record.get("state") != "review":
        raise PolicyConflict("policy exception is not awaiting review")
    if decision == "approved" and secrets.compare_digest(str(record.get("author", "")), actor):
        raise PermissionError("policy exception authors cannot approve their own request")
    now = int(time.time())
    updated = {
        **record,
        "state": decision,
        "decided_by": actor,
        "decided_at": now,
        "decision_reason": reason,
    }
    return _policy_exception_view(
        _put_policy_exception_transition(
            tenant, record, "review", updated, "policy_exception_decided", actor
        ),
        now,
    )


def _activate_policy_exception(tenant, exception_id, body, actor):
    """Sign and activate an approved exception against its exact live base."""
    if body != {}:
        raise ValueError("policy exception activation accepts no mutable content")
    record = _reconcile_policy_exception(tenant, _policy_exception_record(tenant, exception_id))
    if record.get("state") != "approved":
        raise PolicyConflict("policy exception is not approved")
    if record.get("decided_by") in {None, record.get("author")}:
        raise PermissionError("policy exception lacks independent approval")
    _, group, policy, version_record = _policy_exception_scope(
        tenant, record["deployment_id"], record["agent_id"]
    )
    if not (
        group.get("id") == record.get("group_id")
        and policy.get("id") == record.get("policy_id")
        and int(policy.get("version", 0)) == int(record.get("base_policy_version", -1))
        and secrets.compare_digest(
            str(version_record.get("content_hash", "")), str(record.get("base_content_hash", ""))
        )
    ):
        raise PolicyConflict("policy exception scope or base authority changed before activation")
    now = int(time.time())
    if int(record.get("expires_at", 0)) <= now:
        raise PolicyConflict("policy exception expired before activation")
    effective = _managed_policy_configuration(tenant, record["configuration"])
    bundle = _sign_policy_bundle(tenant, record["derived_policy_id"], 1, effective, now)
    updated = {
        **record,
        **_bundle_record_fields(bundle),
        "state": "active",
        "activated_by": actor,
        "activated_at": now,
    }
    return _policy_exception_view(
        _put_policy_exception_transition(
            tenant, record, "approved", updated, "policy_exception_activated", actor
        ),
        now,
    )


def _revoke_policy_exception(tenant, exception_id, body, actor):
    """End an open exception immediately and restore normal policy resolution."""
    if not isinstance(body, dict) or set(body) != {"reason"}:
        raise ValueError("policy exception revocation has an invalid schema")
    reason = _bounded_text(body.get("reason"), "reason", 512)
    record = _reconcile_policy_exception(tenant, _policy_exception_record(tenant, exception_id))
    state = record.get("state")
    if state not in _POLICY_EXCEPTION_OPEN_STATES:
        raise PolicyConflict("policy exception is not open")
    now = int(time.time())
    updated = {
        **record,
        "state": "revoked",
        "ended_by": actor,
        "ended_at": now,
        "end_reason": reason,
    }
    return _policy_exception_view(
        _put_policy_exception_transition(
            tenant, record, state, updated, "policy_exception_revoked", actor
        ),
        now,
    )


def _policy_exceptions(tenant):
    """List reconciled exception lifecycle records newest first."""
    now = int(time.time())
    records = [
        _reconcile_policy_exception(tenant, record, now)
        for record in _list(tenant, "POLICY_EXCEPTION", consistent_read=True)
    ]
    records.sort(
        key=lambda item: (int(item.get("created_at", 0)), item.get("id", "")),
        reverse=True,
    )
    return [_policy_exception_view(record, now) for record in records]


def _active_policy_exception_bundle(tenant, deployment_id, agent_id):
    """Return one live signed derived bundle or no exception after reconciliation."""
    agent_key = f"{deployment_id}:{agent_id}"
    slot = TABLE.get_item(
        Key=_item_key(tenant, "POLICY_EXCEPTION_SLOT", agent_key), ConsistentRead=True
    ).get("Item")
    if not slot:
        return None
    record = _reconcile_policy_exception(
        tenant, _policy_exception_record(tenant, slot.get("exception_id"))
    )
    if record.get("state") != "active":
        return None
    # Reconstructing the persisted bundle is intentionally strict. Corrupted
    # signing evidence must fail the entire refresh, not silently broaden or
    # preserve uncertain authority through a browser-generated fallback.
    bundle = bundle_from_record(
        tenant,
        record["derived_policy_id"],
        1,
        _json(record),
    )
    return {"exception": _policy_exception_view(record), "policyBundle": bundle}


def _put(tenant, kind, identifier, item):
    record = {**_item_key(tenant, kind, identifier), **item, "tenant_id": tenant}
    TABLE.put_item(Item=record)
    return record


def _configuration_audit_record(tenant, event_type, actor, payload, *, now):
    """Build content-minimised primary evidence for declarative configuration."""
    event_id = str(uuid.uuid4())
    redacted = {
        "event_type": event_type,
        "actor": actor,
        "tenant_id": tenant,
        "occurred_at": now,
        "payload": payload,
    }
    return {
        **_item_key(tenant, "CONFIGURATION_AUDIT", f"{now:012d}#{event_id}"),
        **redacted,
        "id": event_id,
        "payload_hash": hashlib.sha256(
            json.dumps(redacted, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def _transact_configuration(operations):
    """Commit desired configuration and primary evidence as one transaction."""
    try:
        DYNAMODB.transact_write_items(TransactItems=operations)
    except Exception as error:
        code = getattr(error, "response", {}).get("Error", {}).get("Code")
        if code in {"ConditionalCheckFailedException", "TransactionCanceledException"}:
            raise PolicyConflict("declarative configuration changed concurrently") from error
        raise


def _export_configuration_audit(tenant, event_type, actor, payload):
    """Best-effort replicate already durable configuration evidence into S3."""
    try:
        _audit(tenant, event_type, actor, payload)
    except Exception:
        print(
            json.dumps({"warning": "configuration audit replication failed", "event": event_type})
        )


def _managed_registration_record(tenant, kind, identifier, body, actor, *, current=None):
    """Validate one declaratively managed Skill or MCP registration.

    The server owns identity, organization, revision and timestamps.  A machine
    client may only replace the bounded configuration body and therefore cannot
    move a registration across a tenant or organization trust boundary.
    """
    identifier_field = "skillId" if kind == "SKILL" else "serverId"
    identifier = _bounded_identifier(identifier, identifier_field)
    organization_id = _policy_organization(tenant, body)
    if current and current.get("organizationId") != organization_id:
        raise PolicyConflict("managed registration organization is immutable")
    name = _bounded_text(body.get("name", identifier), "name")
    description = body.get("description", "")
    if not isinstance(description, str) or len(description) > 1000:
        raise ValueError("description must be text up to 1000 characters")
    version = _bounded_text(body.get("version", "1.0.0"), "version", 64)
    enabled = body.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be a boolean")
    now = int(time.time())
    revision = int(current.get("revision", 1)) + 1 if current else 1
    common = {
        "id": identifier,
        "organizationId": organization_id,
        "name": name,
        "description": description,
        "version": version,
        "enabled": enabled,
        "status": "active" if enabled else "disabled",
        "revision": revision,
        "createdAt": int(current.get("createdAt", now)) if current else now,
        "updatedAt": now,
        "author": actor,
    }
    if kind == "SKILL":
        content = body.get("content", "")
        if not isinstance(content, str) or not content or len(content) > 100000:
            raise ValueError("valid bounded Skill content is required")
        return {
            **common,
            "content": content,
            "digest": f"sha256:{hashlib.sha256(content.encode()).hexdigest()}",
        }
    transport = body.get("transport")
    if transport not in {"stdio", "http"}:
        raise ValueError("valid MCP transport is required")
    args = body.get("args", [])
    references = body.get("environmentReferences", [])
    if (
        not isinstance(args, list)
        or len(args) > 64
        or any(not isinstance(value, str) or len(value) > 4096 for value in args)
    ):
        raise ValueError("MCP args must contain at most 64 bounded strings")
    if (
        not isinstance(references, list)
        or len(references) > 64
        or any(
            not isinstance(value, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", value)
            for value in references
        )
    ):
        raise ValueError("MCP environment references must be bounded variable names")
    command = body.get("command")
    url = body.get("url")
    if transport == "stdio" and (not isinstance(command, str) or not command.strip()):
        raise ValueError("stdio MCP server command is required")
    if transport == "http":
        try:
            parsed_url = urlsplit(url) if isinstance(url, str) else None
            hostname = parsed_url.hostname if parsed_url else None
        except ValueError as error:
            raise ValueError("HTTP MCP server URL is malformed") from error
        if (
            parsed_url is None
            or parsed_url.scheme != "https"
            or not hostname
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.query
            or parsed_url.fragment
            or len(url) > 2048
        ):
            raise ValueError(
                "HTTP MCP server URL must be bounded HTTPS without credentials, query, or fragment"
            )
    return {
        **common,
        "transport": transport,
        "command": command.strip() if transport == "stdio" else None,
        "args": args if transport == "stdio" else [],
        "url": url if transport == "http" else None,
        "environmentReferences": references,
    }


def _create_managed_registration(tenant, kind, identifier, body, actor):
    """Create one registration without allowing an existing ID to be replaced."""
    record = _managed_registration_record(tenant, kind, identifier, body, actor)
    event_name = "skill_created" if kind == "SKILL" else "mcp_server_created"
    created = {**_item_key(tenant, kind, identifier), **record, "tenant_id": tenant}
    payload = {"registration_id": identifier, "revision": 1}
    audit = _configuration_audit_record(tenant, event_name, actor, payload, now=int(time.time()))
    _transact_configuration(
        [
            _transaction_put(created, condition="attribute_not_exists(pk)"),
            _transaction_put(audit, condition="attribute_not_exists(pk)"),
        ]
    )
    _export_configuration_audit(tenant, event_name, actor, payload)
    return created


def _replace_managed_registration(tenant, kind, identifier, body, actor):
    """Replace configuration under an optimistic revision precondition."""
    current = TABLE.get_item(Key=_item_key(tenant, kind, identifier), ConsistentRead=True).get(
        "Item"
    )
    if not current:
        raise LookupError("managed registration not found")
    expected = body.get("expectedRevision")
    if not isinstance(expected, int) or isinstance(expected, bool) or expected < 1:
        raise ValueError("expectedRevision must be a positive integer")
    current_revision = int(current.get("revision", 1))
    if expected != current_revision:
        raise PolicyConflict("managed registration changed concurrently")
    replacement = {
        **_item_key(tenant, kind, identifier),
        **_managed_registration_record(tenant, kind, identifier, body, actor, current=current),
        "tenant_id": tenant,
    }
    event_name = "skill_updated" if kind == "SKILL" else "mcp_server_updated"
    payload = {"registration_id": identifier, "revision": replacement["revision"]}
    audit = _configuration_audit_record(tenant, event_name, actor, payload, now=int(time.time()))
    _transact_configuration(
        [
            _transaction_put(
                replacement,
                condition=(
                    "attribute_exists(pk) AND "
                    "(attribute_not_exists(revision) OR revision = :registration_revision)"
                ),
                values={":registration_revision": expected},
            ),
            _transaction_put(audit, condition="attribute_not_exists(pk)"),
        ]
    )
    _export_configuration_audit(tenant, event_name, actor, payload)
    return replacement


def _retire_managed_registration(tenant, kind, identifier, body, actor):
    """Disable a registration while retaining evidence and policy references."""
    current = TABLE.get_item(Key=_item_key(tenant, kind, identifier), ConsistentRead=True).get(
        "Item"
    )
    if not current:
        raise LookupError("managed registration not found")
    expected = body.get("expectedRevision")
    if not isinstance(expected, int) or isinstance(expected, bool) or expected < 1:
        raise ValueError("expectedRevision must be a positive integer")
    current_revision = int(current.get("revision", 1))
    if expected != current_revision:
        raise PolicyConflict("managed registration changed concurrently")
    if current.get("status") == "retired":
        return current
    replacement = {
        **current,
        "enabled": False,
        "status": "retired",
        "revision": current_revision + 1,
        "updatedAt": int(time.time()),
        "retiredBy": actor,
    }
    event_name = "skill_retired" if kind == "SKILL" else "mcp_server_retired"
    payload = {"registration_id": identifier, "revision": replacement["revision"]}
    audit = _configuration_audit_record(tenant, event_name, actor, payload, now=int(time.time()))
    _transact_configuration(
        [
            _transaction_put(
                replacement,
                condition=(
                    "attribute_exists(pk) AND "
                    "(attribute_not_exists(revision) OR revision = :registration_revision)"
                ),
                values={":registration_revision": expected},
            ),
            _transaction_put(audit, condition="attribute_not_exists(pk)"),
        ]
    )
    _export_configuration_audit(tenant, event_name, actor, payload)
    return replacement


def _replace_group_configuration(tenant, group_id, body, actor):
    """Replace group metadata without mutating its independently revised members."""
    group_id = _bounded_identifier(group_id, "groupId")
    group = TABLE.get_item(Key=_item_key(tenant, "GROUP", group_id), ConsistentRead=True).get(
        "Item"
    )
    if not group:
        raise LookupError("group not found")
    expected = body.get("expectedConfigurationRevision")
    current_revision = int(group.get("configuration_revision", 1))
    if not isinstance(expected, int) or isinstance(expected, bool) or expected < 1:
        raise ValueError("expectedConfigurationRevision must be a positive integer")
    if expected != current_revision:
        raise PolicyConflict("group configuration changed concurrently")
    policy_id = _bounded_identifier(body.get("policyId"), "policyId")
    policy = TABLE.get_item(Key=_item_key(tenant, "POLICY", policy_id), ConsistentRead=True).get(
        "Item"
    )
    if not policy:
        raise LookupError("policy not found")
    policy = _ensure_policy_governance(tenant, policy)
    if int(policy.get("version", 0)) <= 0:
        raise PolicyConflict("group policies must have an active governed version")
    group_organization = group.get("organizationId") or group.get("organization_id")
    policy_organization = policy.get("organization_id") or policy.get("organizationId")
    if not group_organization or group_organization != policy_organization:
        raise PolicyConflict("group and policy must belong to the same organization")
    updated = {
        **group,
        "name": _bounded_text(body.get("name"), "name"),
        "policyId": policy_id,
        "policyName": policy["name"],
        "configuration_revision": current_revision + 1,
        "updatedAt": int(time.time()),
    }
    event_name = "group_configuration_updated"
    payload = {"group_id": group_id, "configuration_revision": current_revision + 1}
    audit = _configuration_audit_record(tenant, event_name, actor, payload, now=int(time.time()))
    _transact_configuration(
        [
            _transaction_put(
                updated,
                condition=(
                    "attribute_exists(pk) AND "
                    "(attribute_not_exists(configuration_revision) "
                    "OR configuration_revision = :configuration_revision) "
                    "AND membership_revision = :membership_revision "
                    "AND agent_keys = :agent_keys"
                ),
                values={
                    ":configuration_revision": expected,
                    ":membership_revision": _group_membership_revision(group),
                    ":agent_keys": _group_agent_keys(group),
                },
            ),
            _transaction_put(audit, condition="attribute_not_exists(pk)"),
        ]
    )
    _export_configuration_audit(tenant, event_name, actor, payload)
    return next(item for item in _fleet(tenant)["groups"] if item["id"] == group_id)


def _delete_empty_group(tenant, group_id, body, actor):
    """Delete only an empty group under exact configuration and membership revisions."""
    group_id = _bounded_identifier(group_id, "groupId")
    group = TABLE.get_item(Key=_item_key(tenant, "GROUP", group_id), ConsistentRead=True).get(
        "Item"
    )
    if not group:
        return {"id": group_id, "deleted": True}
    expected = body.get("expectedConfigurationRevision")
    if not isinstance(expected, int) or isinstance(expected, bool) or expected < 1:
        raise ValueError("expectedConfigurationRevision must be a positive integer")
    current_revision = int(group.get("configuration_revision", 1))
    if expected != current_revision:
        raise PolicyConflict("group configuration changed concurrently")
    if _group_agent_keys(group):
        raise PolicyConflict("group must be empty before deletion")
    event_name = "group_deleted"
    payload = {"group_id": group_id}
    audit = _configuration_audit_record(tenant, event_name, actor, payload, now=int(time.time()))
    _transact_configuration(
        [
            _transaction_delete(
                _item_key(tenant, "GROUP", group_id),
                condition=(
                    "attribute_exists(pk) AND "
                    "(attribute_not_exists(configuration_revision) "
                    "OR configuration_revision = :configuration_revision) "
                    "AND membership_revision = :membership_revision AND agent_keys = :empty"
                ),
                values={
                    ":configuration_revision": expected,
                    ":membership_revision": _group_membership_revision(group),
                    ":empty": [],
                },
            ),
            _transaction_put(audit, condition="attribute_not_exists(pk)"),
        ]
    )
    _export_configuration_audit(tenant, event_name, actor, payload)
    return {"id": group_id, "deleted": True}


def _bounded_text(value, field, maximum=128):
    """Validate bounded operator metadata without accepting control characters."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or any(ord(char) < 32 for char in normalized):
        raise ValueError(f"{field} must be bounded non-empty text")
    return normalized


def _bounded_identifier(value, field):
    """Validate a stable tenant-scoped identifier safe for keys and routes."""
    normalized = _bounded_text(value, field)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", normalized):
        raise ValueError(f"{field} contains unsupported characters")
    return normalized


def _project_root(value):
    """Require the canonical POSIX path used as an immutable agent scope.

    The browser cannot resolve paths on a remote host, so registration accepts
    only the lexical form produced by ``pwd -P``. The host still resolves the
    live directory before enrollment and must present this exact value.
    """
    normalized = _bounded_text(value, "projectRoot", 4096)
    segments = normalized.split("/")
    if (
        not normalized.startswith("/")
        or normalized == "/"
        or normalized.endswith("/")
        or "" in segments[1:]
        or any(segment in {".", ".."} for segment in segments)
    ):
        raise ValueError("projectRoot must be a canonical absolute project path")
    return normalized


def _agent_host(value):
    """Require a host with an implemented runtime-attestation profile."""
    host = _bounded_text(value, "host", 64)
    if host not in {"claude-code", "codex-cli"}:
        raise ValueError("host must be claude-code or codex-cli")
    return host


def _business_contact(value):
    """Validate one accountable business mailbox without accepting display syntax."""
    contact = _bounded_text(value, "businessContact", 254).lower()
    if not re.fullmatch(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", contact
    ):
        raise ValueError("businessContact must be a valid email address")
    return contact


def _agent_ownership_revision(value, *, allow_zero=False):
    """Normalize an ownership compare-and-swap revision from JSON or DynamoDB."""
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise ValueError("expectedOwnershipRevision must be an integer")
    if isinstance(value, Decimal) and value != value.to_integral_value():
        raise ValueError("expectedOwnershipRevision must be an integer")
    revision = int(value)
    minimum = 0 if allow_zero else 1
    if revision < minimum:
        raise ValueError(f"expectedOwnershipRevision must be at least {minimum}")
    return revision


def _validate_accountable_owner(tenant, owner_id):
    """Require an active Entra owner when this tenant has SCIM enforcement."""
    owner_id = _bounded_identifier(owner_id, "ownerId")
    if (
        os.environ.get("SCIM_ENABLED") == "true"
        and SCIM is not None
        and os.environ.get("ENTRA_AAI_TENANT_ID") == tenant
    ):
        try:
            owner_id = str(uuid.UUID(owner_id))
        except ValueError as error:
            raise ValueError("ownerId must be an Entra object UUID") from error
        owner = SCIM.get_item(
            Key={"pk": f"TENANT#{tenant}", "sk": f"USER#{owner_id}"},
            ConsistentRead=True,
        ).get("Item")
        if not owner or owner.get("active") is not True:
            raise ValueError("ownerId is not an actively provisioned Entra user")
    return owner_id


def _new_agent_ownership(tenant, value, deployment, actor, *, now):
    """Build reviewed ownership fields from operator input and trusted deployment state."""
    required = {"ownerId", "ownerName", "businessContact", "criticality"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError(
            "ownership must contain ownerId, ownerName, businessContact and criticality"
        )
    criticality = value.get("criticality")
    if criticality not in _AGENT_CRITICALITIES:
        raise ValueError("criticality must be low, medium, high or critical")
    # Team and environment are inventory lineage, so they are copied from the
    # server-owned deployment rather than accepted from a browser request.
    return {
        "owner_id": _validate_accountable_owner(tenant, value.get("ownerId")),
        "owner_name": _bounded_text(value.get("ownerName"), "ownerName", 128),
        "business_contact": _business_contact(value.get("businessContact")),
        "team": _bounded_text(deployment.get("team"), "deployment team", 128),
        "environment": _bounded_identifier(deployment.get("environment"), "deployment environment"),
        "ownership_criticality": criticality,
        "ownership_reviewed_at": now,
        "ownership_review_due_at": now + _AGENT_OWNERSHIP_REVIEW_SECONDS,
        "ownership_reviewed_by": actor,
    }


def _agent_ownership_view(agent, *, now=None):
    """Derive a secret-free current, stale or missing ownership posture."""
    current = int(time.time()) if now is None else int(now)
    required_text = (
        "owner_id",
        "owner_name",
        "business_contact",
        "team",
        "environment",
        "ownership_reviewed_by",
    )
    missing = [
        field
        for field in required_text
        if not isinstance(agent.get(field), str) or not agent.get(field)
    ]
    try:
        revision = _agent_ownership_revision(agent.get("ownership_revision"))
        reviewed_at = _agent_ownership_revision(agent.get("ownership_reviewed_at"))
        review_due_at = _agent_ownership_revision(agent.get("ownership_review_due_at"))
        _business_contact(agent.get("business_contact"))
    except ValueError:
        revision = 0
        reviewed_at = 0
        review_due_at = 0
        missing.append("ownership_review")
    criticality = agent.get("ownership_criticality")
    if criticality not in _AGENT_CRITICALITIES:
        missing.append("criticality")
    status = "missing" if missing else ("stale" if review_due_at <= current else "current")
    return {
        "status": status,
        "revision": revision,
        "ownerId": agent.get("owner_id", ""),
        "ownerName": agent.get("owner_name", ""),
        "team": agent.get("team", ""),
        "businessContact": agent.get("business_contact", ""),
        "environment": agent.get("environment", ""),
        "criticality": criticality if criticality in _AGENT_CRITICALITIES else None,
        "reviewedAt": reviewed_at,
        "reviewDueAt": review_due_at,
        "reviewedBy": agent.get("ownership_reviewed_by", ""),
        "reasonCodes": sorted(set(missing))
        if missing
        else (["review_expired"] if status == "stale" else []),
    }


def _discovery_integer(value, field, *, minimum=0, maximum=None):
    """Normalize one exact bounded integer from JSON or DynamoDB."""
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise ValueError(f"{field} must be an integer")
    if isinstance(value, Decimal) and value != value.to_integral_value():
        raise ValueError(f"{field} must be an integer")
    result = int(value)
    if result < minimum:
        raise ValueError(f"{field} must be at least {minimum}")
    if maximum is not None and result > maximum:
        raise ValueError(f"{field} must be at most {maximum}")
    return result


def _discovery_digest(value, field="projectRootDigest"):
    """Require a lowercase SHA-256 correlation key without accepting a raw path."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _discovery_optional_identifier(value, field):
    """Validate an optional opaque inventory identifier."""
    return None if value is None else _bounded_identifier(value, field)


def _discovery_identifier_list(value, field, *, limit=20):
    """Return a unique bounded list of opaque identifiers."""
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"{field} must be a bounded list")
    result = [_bounded_identifier(item, field) for item in value]
    if len(set(result)) != len(result):
        raise ValueError(f"{field} must not contain duplicates")
    return sorted(result)


def _discovery_observation(value, source_kind):
    """Validate one source-specific, content-minimised discovery observation."""
    if not isinstance(value, dict):
        raise ValueError("discovery observation must be an object")
    kind = value.get("kind")
    if kind not in _DISCOVERY_OBSERVATION_KINDS[source_kind]:
        raise ValueError("discovery observation kind is not valid for its source")
    schemas = {
        "identity": (
            {"kind", "id", "active"},
            {"kind", "id", "active", "businessUnit"},
        ),
        "device": (
            {"kind", "id", "managed"},
            {"kind", "id", "managed", "businessUnit", "userIds"},
        ),
        "repository": (
            {"kind", "id", "projectRootDigest", "expectedHosts"},
            {"kind", "id", "projectRootDigest", "expectedHosts", "businessUnit"},
        ),
        "installation": (
            {
                "kind",
                "id",
                "deviceId",
                "host",
                "projectRootDigest",
                "binaryPresent",
                "processActive",
            },
            {
                "kind",
                "id",
                "deviceId",
                "host",
                "projectRootDigest",
                "binaryPresent",
                "processActive",
                "userId",
                "repositoryId",
                "businessUnit",
            },
        ),
    }
    required, allowed = schemas[kind]
    if not required.issubset(value) or not set(value).issubset(allowed):
        raise ValueError(f"{kind} discovery observation has an invalid schema")
    result = {"kind": kind, "id": _bounded_identifier(value.get("id"), "observation id")}
    if "businessUnit" in value:
        result["businessUnit"] = _bounded_text(value.get("businessUnit"), "businessUnit", 128)
    if kind == "identity":
        if not isinstance(value.get("active"), bool):
            raise ValueError("identity active must be boolean")
        result["active"] = value["active"]
    elif kind == "device":
        if not isinstance(value.get("managed"), bool):
            raise ValueError("device managed must be boolean")
        result["managed"] = value["managed"]
        result["userIds"] = _discovery_identifier_list(value.get("userIds", []), "userIds")
    elif kind == "repository":
        result["projectRootDigest"] = _discovery_digest(value.get("projectRootDigest"))
        hosts = value.get("expectedHosts")
        if not isinstance(hosts, list) or not 1 <= len(hosts) <= _DISCOVERY_EXPECTED_HOST_LIMIT:
            raise ValueError("expectedHosts must contain one or two supported hosts")
        result["expectedHosts"] = sorted({_agent_host(host) for host in hosts})
        if len(result["expectedHosts"]) != len(hosts):
            raise ValueError("expectedHosts must not contain duplicates")
    else:
        for field in ("binaryPresent", "processActive"):
            if not isinstance(value.get(field), bool):
                raise ValueError(f"{field} must be boolean")
            result[field] = value[field]
        result.update(
            {
                "deviceId": _bounded_identifier(value.get("deviceId"), "deviceId"),
                "host": _agent_host(value.get("host")),
                "projectRootDigest": _discovery_digest(value.get("projectRootDigest")),
                "userId": _discovery_optional_identifier(value.get("userId"), "userId"),
                "repositoryId": _discovery_optional_identifier(
                    value.get("repositoryId"), "repositoryId"
                ),
            }
        )
    return result


def _publish_discovery_snapshot(tenant, source_id, value, actor):
    """Atomically replace one trusted source snapshot with optimistic concurrency."""
    required = {
        "sourceKind",
        "generation",
        "expectedRevision",
        "observedAt",
        "expiresAt",
        "complete",
        "observations",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("discovery snapshot has an invalid schema")
    source_kind = value.get("sourceKind")
    if source_kind not in _DISCOVERY_SOURCE_KINDS:
        raise ValueError("sourceKind is unsupported")
    generation = _bounded_identifier(value.get("generation"), "generation")
    expected = _discovery_integer(value.get("expectedRevision"), "expectedRevision")
    observed_at = _discovery_integer(value.get("observedAt"), "observedAt", minimum=1)
    expires_at = _discovery_integer(value.get("expiresAt"), "expiresAt", minimum=1)
    complete = value.get("complete")
    observations = value.get("observations")
    now = int(time.time())
    if not isinstance(complete, bool):
        raise ValueError("complete must be boolean")
    if not isinstance(observations, list) or len(observations) > _DISCOVERY_SNAPSHOT_LIMIT:
        raise ValueError(f"observations must contain at most {_DISCOVERY_SNAPSHOT_LIMIT} records")
    if observed_at > now + 300 or expires_at <= now:
        raise ValueError("discovery snapshot must be current")
    if expires_at <= observed_at or expires_at - observed_at > _DISCOVERY_MAX_VALIDITY_SECONDS:
        raise ValueError("discovery snapshot validity is unsafe")
    normalized = [_discovery_observation(item, source_kind) for item in observations]
    identities = [(item["kind"], item["id"]) for item in normalized]
    if len(set(identities)) != len(identities):
        raise ValueError("discovery observations must be unique within a snapshot")
    normalized.sort(key=lambda item: (item["kind"], item["id"]))
    source_id = _bounded_identifier(source_id, "sourceId")
    existing = TABLE.get_item(
        Key=_item_key(tenant, "DISCOVERY_SOURCE", source_id), ConsistentRead=True
    ).get("Item")
    current_revision = int(existing.get("revision", 0)) if existing else 0
    if current_revision != expected:
        raise PolicyConflict("discovery source revision changed")
    content = {
        "sourceId": source_id,
        "sourceKind": source_kind,
        "generation": generation,
        "observedAt": observed_at,
        "expiresAt": expires_at,
        "complete": complete,
        "observations": normalized,
    }
    content_hash = hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    record = {
        **_item_key(tenant, "DISCOVERY_SOURCE", source_id),
        **content,
        "revision": expected + 1,
        "contentHash": content_hash,
        "publishedAt": now,
        "publishedBy": actor,
        "tenant_id": tenant,
    }
    if source_kind == "endpoint":
        # Register before the snapshot write. A harmless registry entry can be
        # retried, while registering after commit could make a successful
        # snapshot return an unsafe, non-repeatable failure to its publisher.
        _register_endpoint_detection_tenant(tenant)
    arguments = {"Item": record}
    if expected == 0:
        arguments["ConditionExpression"] = "attribute_not_exists(pk)"
    else:
        arguments.update(
            {
                "ConditionExpression": "revision = :expected_revision",
                "ExpressionAttributeValues": {":expected_revision": expected},
            }
        )
    try:
        TABLE.put_item(**arguments)
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("discovery source revision changed") from error
        raise
    _audit(
        tenant,
        "discovery_snapshot_published",
        actor,
        {
            "source_id": source_id,
            "source_kind": source_kind,
            "revision": expected + 1,
            "complete": complete,
            "observation_count": len(normalized),
            "content_hash": content_hash,
        },
    )
    return {key: item for key, item in record.items() if key not in {"pk", "sk", "observations"}}


def _rotate_discovery_connector(tenant, source_id, value, actor):
    """Issue one source-scoped connector secret and persist only its digest.

    The plaintext credential is returned once to an authenticated platform
    administrator. It cannot grant operator or agent authority and is accepted
    only on the matching tenant/source ingestion route.
    """
    if not isinstance(value, dict) or set(value) != {"sourceKind", "expectedRevision"}:
        raise ValueError("discovery connector credential has an invalid schema")
    source_id = _bounded_identifier(source_id, "sourceId")
    source_kind = value.get("sourceKind")
    if source_kind not in _DISCOVERY_SOURCE_KINDS:
        raise ValueError("sourceKind is unsupported")
    expected = _discovery_integer(value.get("expectedRevision"), "expectedRevision")
    key = _item_key(tenant, "DISCOVERY_CONNECTOR", source_id)
    existing = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    source = TABLE.get_item(
        Key=_item_key(tenant, "DISCOVERY_SOURCE", source_id), ConsistentRead=True
    ).get("Item")
    revision = int(existing.get("revision", 0)) if existing else 0
    if revision != expected:
        raise PolicyConflict("discovery connector revision changed")
    if existing and existing.get("sourceKind") != source_kind:
        # Rotation may replace secret material, never the semantic class whose
        # schema and coverage role were assigned to this stable source ID.
        raise PolicyConflict("discovery connector sourceKind is immutable")
    if source and source.get("sourceKind") != source_kind:
        # A legacy snapshot also establishes the semantic source class. A new
        # credential cannot silently reinterpret its stable source identifier.
        raise PolicyConflict("discovery sourceKind is immutable")
    token = secrets.token_urlsafe(32)
    record = {
        **key,
        "tenant_id": tenant,
        "sourceId": source_id,
        "sourceKind": source_kind,
        "tokenHash": hashlib.sha256(token.encode()).hexdigest(),
        "revision": expected + 1,
        "status": "active",
        "rotatedAt": int(time.time()),
        "rotatedBy": actor,
    }
    arguments = {"Item": record}
    if expected == 0:
        arguments["ConditionExpression"] = "attribute_not_exists(pk)"
    else:
        arguments.update(
            {
                "ConditionExpression": "revision = :expected_revision",
                "ExpressionAttributeValues": {":expected_revision": expected},
            }
        )
    try:
        TABLE.put_item(**arguments)
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("discovery connector revision changed") from error
        raise
    _audit(
        tenant,
        "discovery_connector_rotated",
        actor,
        {"source_id": source_id, "source_kind": source_kind, "revision": expected + 1},
    )
    return {
        "sourceId": source_id,
        "sourceKind": source_kind,
        "revision": expected + 1,
        "token": token,
    }


def _revoke_discovery_connector(tenant, source_id, actor):
    """Revoke a connector immediately without changing committed evidence."""
    source_id = _bounded_identifier(source_id, "sourceId")
    key = _item_key(tenant, "DISCOVERY_CONNECTOR", source_id)
    existing = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    if not existing:
        raise LookupError("discovery connector not found")
    existing.update(
        {
            "status": "revoked",
            "revision": int(existing.get("revision", 0)) + 1,
            "revokedAt": int(time.time()),
            "revokedBy": actor,
        }
    )
    TABLE.put_item(Item=existing)
    _audit(tenant, "discovery_connector_revoked", actor, {"source_id": source_id})
    return {"sourceId": source_id, "status": "revoked", "revision": existing["revision"]}


def _managed_discovery_clients():
    """Create deployment adapters lazily so core request tests stay provider-neutral."""
    return boto3.client("secretsmanager"), boto3.client("scheduler")


def _managed_discovery_environment():
    """Return immutable deployment-owned managed collector coordinates."""
    names = {
        "collectorArn": "DISCOVERY_COLLECTOR_ARN",
        "schedulerRoleArn": "DISCOVERY_SCHEDULER_ROLE_ARN",
        "deadLetterArn": "DISCOVERY_COLLECTOR_DLQ_ARN",
        "kmsKeyArn": "DISCOVERY_SECRET_KMS_KEY_ARN",
        "providerSecretPrefix": "DISCOVERY_PROVIDER_SECRET_PREFIX",
        "connectorSecretPrefix": "DISCOVERY_CONNECTOR_SECRET_PREFIX",
        "region": "AWS_REGION",
        "accountId": "AWS_ACCOUNT_ID",
        "partition": "AWS_PARTITION",
    }
    value = {key: os.environ.get(environment, "").strip() for key, environment in names.items()}
    return value if all(value.values()) else None


def _managed_discovery_capabilities():
    """Expose non-secret setup coordinates needed by an enterprise administrator."""
    environment = _managed_discovery_environment()
    if not environment:
        return {"available": False, "providers": [], "intervalMinutes": []}
    return {
        "available": True,
        "providers": sorted(_MANAGED_DISCOVERY_PROVIDER_KINDS),
        "intervalMinutes": sorted(_MANAGED_DISCOVERY_INTERVALS),
        "region": environment["region"],
        "providerSecretNamePrefix": environment["providerSecretPrefix"],
        "kmsKeyArn": environment["kmsKeyArn"],
        # Retain the original field for older Entra-only consoles while the
        # provider-specific contract gives new consoles an exact typed setup.
        "providerSecretSchema": ["tenantId", "clientId", "clientSecret"],
        "providerConfigurations": {
            "entra": {
                "sourceKind": "identity",
                "secretSchema": ["tenantId", "clientId", "clientSecret"],
                "configurationSchema": [],
            },
            "intune": {
                "sourceKind": "endpoint",
                "secretSchema": ["tenantId", "clientId", "clientSecret"],
                "configurationSchema": ["userBusinessUnits"],
                "maximumUserBusinessUnits": _MANAGED_INTUNE_BUSINESS_UNIT_LIMIT,
                "installationEvidenceRequired": True,
            },
            "github": {
                "sourceKind": "source_control",
                "secretSchema": ["token"],
                "configurationSchema": ["organization", "repositories"],
                "maximumRepositories": _MANAGED_GITHUB_REPOSITORY_LIMIT,
            },
        },
    }


def _managed_github_slug(value, field, *, maximum=100, organization=False):
    """Normalize one GitHub organization or repository slug.

    GitHub identifiers are case-insensitive. Canonical lower-case values avoid
    duplicate mappings whose only difference is case and keep comparisons
    independent of provider presentation.
    """
    pattern = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?" if organization else r"[A-Za-z0-9._-]+"
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or not re.fullmatch(pattern, value)
        or value in {".", ".."}
        or (organization and "--" in value)
    ):
        raise ValueError(f"{field} is not a safe GitHub identifier")
    return value.lower()


def _managed_github_configuration(value):
    """Validate bounded deployment-owned repository correlation configuration."""
    if not isinstance(value, dict) or set(value) != {"organization", "repositories"}:
        raise ValueError("GitHub provider configuration has an invalid schema")
    organization = _managed_github_slug(
        value.get("organization"), "organization", maximum=39, organization=True
    )
    repositories = value.get("repositories")
    if (
        not isinstance(repositories, list)
        or not 1 <= len(repositories) <= _MANAGED_GITHUB_REPOSITORY_LIMIT
    ):
        raise ValueError("GitHub repository mappings must be a non-empty bounded list")
    normalized = []
    seen = set()
    seen_digests = set()
    for item in repositories:
        if not isinstance(item, dict) or frozenset(item) not in {
            frozenset({"fullName", "projectRootDigest", "expectedHosts"}),
            frozenset({"fullName", "projectRootDigest", "expectedHosts", "businessUnit"}),
        }:
            raise ValueError("GitHub repository mapping has an invalid schema")
        full_name = item.get("fullName")
        if not isinstance(full_name, str) or full_name.count("/") != 1:
            raise ValueError("GitHub repository fullName is invalid")
        owner, repository = full_name.split("/", 1)
        owner = _managed_github_slug(owner, "repository owner", maximum=39, organization=True)
        repository = _managed_github_slug(repository, "repository name")
        if owner != organization:
            raise ValueError("GitHub repository mapping is outside the configured organization")
        canonical_name = f"{owner}/{repository}"
        if canonical_name in seen:
            raise ValueError("GitHub repository mappings must not contain duplicates")
        seen.add(canonical_name)
        hosts = item.get("expectedHosts")
        if not isinstance(hosts, list) or not 1 <= len(hosts) <= _DISCOVERY_EXPECTED_HOST_LIMIT:
            raise ValueError("GitHub expectedHosts must contain one or two supported hosts")
        normalized_hosts = sorted({_agent_host(host) for host in hosts})
        if len(normalized_hosts) != len(hosts):
            raise ValueError("GitHub expectedHosts must not contain duplicates")
        project_root_digest = _discovery_digest(item.get("projectRootDigest"))
        if project_root_digest in seen_digests:
            raise ValueError("GitHub repository mappings must not reuse a project root digest")
        seen_digests.add(project_root_digest)
        mapping = {
            "fullName": canonical_name,
            "projectRootDigest": project_root_digest,
            "expectedHosts": normalized_hosts,
        }
        if "businessUnit" in item:
            mapping["businessUnit"] = _bounded_text(item.get("businessUnit"), "businessUnit", 128)
        normalized.append(mapping)
    return {
        "organization": organization,
        "repositories": sorted(normalized, key=lambda x: x["fullName"]),
    }


def _managed_provider_configuration(provider, value):
    """Return one exact provider configuration without accepting hidden fields."""
    if provider == "entra":
        if value not in (None, {}):
            raise ValueError("Entra managed discovery does not accept provider configuration")
        return {}
    if provider == "github":
        return _managed_github_configuration(value)
    if provider == "intune":
        if not isinstance(value, dict) or set(value) != {"userBusinessUnits"}:
            raise ValueError("Intune provider configuration has an invalid schema")
        mappings = value.get("userBusinessUnits")
        if not isinstance(mappings, list) or len(mappings) > _MANAGED_INTUNE_BUSINESS_UNIT_LIMIT:
            raise ValueError("Intune business-unit mappings must be a bounded list")
        normalized = []
        seen = set()
        for item in mappings:
            if not isinstance(item, dict) or set(item) != {"userId", "businessUnit"}:
                raise ValueError("Intune business-unit mapping has an invalid schema")
            try:
                user_id = str(uuid.UUID(item.get("userId")))
            except (ValueError, TypeError, AttributeError) as error:
                raise ValueError("Intune userId must be a canonical UUID") from error
            if user_id != item.get("userId", "").lower() or user_id in seen:
                raise ValueError("Intune userIds must be canonical and unique")
            seen.add(user_id)
            normalized.append(
                {
                    "userId": user_id,
                    "businessUnit": _bounded_text(item.get("businessUnit"), "businessUnit", 128),
                }
            )
        return {"userBusinessUnits": sorted(normalized, key=lambda item: item["userId"])}
    raise ValueError("managed discovery provider is unsupported")


def _managed_discovery_secret(tenant, arn, secrets_client, environment):
    """Validate a tenant-tagged provider secret without reading its value."""
    expected_prefix = (
        f"arn:{environment['partition']}:secretsmanager:{environment['region']}:"
        f"{environment['accountId']}:secret:"
        f"{environment['providerSecretPrefix']}{tenant}/"
    )
    if not isinstance(arn, str) or len(arn) > 1024 or not arn.startswith(expected_prefix):
        raise ValueError("providerSecretArn is outside the tenant provider-secret namespace")
    try:
        description = secrets_client.describe_secret(SecretId=arn)
    except Exception as error:
        raise ValueError("provider secret is unavailable") from error
    tags = {
        item.get("Key"): item.get("Value")
        for item in description.get("Tags", [])
        if isinstance(item, dict)
    }
    if (
        description.get("ARN") != arn
        or description.get("KmsKeyId") != environment["kmsKeyArn"]
        or tags != {"aai-sec:tenant-id": tenant, "aai-sec:purpose": "discovery-provider"}
    ):
        raise ValueError("provider secret encryption or tenant tags are invalid")
    return arn


def _managed_discovery_schedule_input(
    tenant,
    source_id,
    provider,
    provider_secret_arn,
    connector_secret_arn,
    provider_configuration_digest,
    revision,
):
    """Build and bind the exact scheduler input accepted by the collector."""
    value = {
        "schemaVersion": 1,
        "tenantId": tenant,
        "sourceId": source_id,
        "provider": provider,
        "providerSecretArn": provider_secret_arn,
        "connectorSecretArn": connector_secret_arn,
        "providerConfigurationDigest": provider_configuration_digest,
        "jobRevision": revision,
        "validitySeconds": 3600,
    }
    value["configurationDigest"] = _configuration_hash(value)
    return value


def _managed_discovery_names(tenant, source_id, environment):
    """Derive opaque bounded AWS resource names without exposing tenant labels."""
    digest = hashlib.sha256(f"{tenant}\0{source_id}".encode()).hexdigest()[:32]
    return {
        "schedule": f"aai-sec-discovery-{digest}",
        "connectorSecret": f"{environment['connectorSecretPrefix']}{digest}",
    }


def _managed_discovery_audit_record(tenant, event_type, actor, payload, *, now):
    """Build primary durable evidence committed with managed job authority."""
    event_id = str(uuid.uuid4())
    redacted = {
        "event_type": event_type,
        "actor": actor,
        "tenant_id": tenant,
        "occurred_at": now,
        "payload": payload,
    }
    return {
        **_item_key(tenant, "DISCOVERY_AUDIT", f"{now:012d}#{event_id}"),
        **redacted,
        "id": event_id,
        "payload_hash": hashlib.sha256(
            json.dumps(redacted, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "ttl": now + (366 * 24 * 60 * 60),
    }


def _export_managed_discovery_audit(tenant, event_type, actor, payload):
    """Best-effort copy already-durable job evidence to the S3 audit stream."""
    try:
        _audit(tenant, event_type, actor, payload)
    except Exception:
        print(json.dumps({"warning": "managed discovery audit replication failed"}))


def _create_managed_discovery(tenant, source_id, value, actor):
    """Create one scheduled collector while keeping credentials out of the UI."""
    base_fields = {
        "provider",
        "providerSecretArn",
        "intervalMinutes",
        "expectedJobRevision",
        "expectedCredentialRevision",
    }
    if not isinstance(value, dict):
        raise ValueError("managed discovery configuration has an invalid schema")
    provider = value.get("provider")
    expected_fields = base_fields | (
        {"providerConfiguration"} if provider in {"github", "intune"} else set()
    )
    if set(value) != expected_fields:
        raise ValueError("managed discovery configuration has an invalid schema")
    source_id = _bounded_identifier(source_id, "sourceId")
    if provider not in _MANAGED_DISCOVERY_PROVIDER_KINDS:
        raise ValueError("managed discovery provider is unsupported")
    provider_configuration = _managed_provider_configuration(
        provider, value.get("providerConfiguration")
    )
    provider_configuration_digest = _configuration_hash(provider_configuration)
    source_kind = _MANAGED_DISCOVERY_PROVIDER_KINDS[provider]
    interval = _discovery_integer(value.get("intervalMinutes"), "intervalMinutes")
    if interval not in _MANAGED_DISCOVERY_INTERVALS:
        raise ValueError("managed discovery interval is unsupported")
    expected_job = _discovery_integer(value.get("expectedJobRevision"), "expectedJobRevision")
    expected_credential = _discovery_integer(
        value.get("expectedCredentialRevision"), "expectedCredentialRevision"
    )
    if expected_job != 0 or expected_credential != 0:
        raise ValueError("managed discovery creation requires zero initial revisions")
    environment = _managed_discovery_environment()
    if not environment:
        raise RuntimeError("managed discovery is not configured")
    source = TABLE.get_item(
        Key=_item_key(tenant, "DISCOVERY_SOURCE", source_id), ConsistentRead=True
    ).get("Item")
    if source and source.get("sourceKind") != source_kind:
        raise PolicyConflict("managed discovery sourceKind conflicts with existing evidence")
    secrets_client, scheduler = _managed_discovery_clients()
    provider_secret = _managed_discovery_secret(
        tenant, value.get("providerSecretArn"), secrets_client, environment
    )
    names = _managed_discovery_names(tenant, source_id, environment)
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    connector_arn = ""
    schedule_created = False
    try:
        connector = secrets_client.create_secret(
            Name=names["connectorSecret"],
            Description="AAI Security managed discovery connector credential",
            KmsKeyId=environment["kmsKeyArn"],
            SecretString=json.dumps({"token": token}, separators=(",", ":")),
            Tags=[
                {"Key": "aai-sec:tenant-id", "Value": tenant},
                {"Key": "aai-sec:purpose", "Value": "discovery-connector"},
            ],
        )
        connector_arn = connector["ARN"]
        schedule_input = _managed_discovery_schedule_input(
            tenant,
            source_id,
            provider,
            provider_secret,
            connector_arn,
            provider_configuration_digest,
            1,
        )
        scheduler.create_schedule(
            Name=names["schedule"],
            ScheduleExpression=f"rate({interval} minutes)",
            FlexibleTimeWindow={"Mode": "OFF"},
            StartDate=datetime.fromtimestamp(now + 60, tz=UTC),
            State="ENABLED",
            Description=f"AAI Security managed {provider} discovery",
            Target={
                "Arn": environment["collectorArn"],
                "RoleArn": environment["schedulerRoleArn"],
                "Input": json.dumps(schedule_input, sort_keys=True, separators=(",", ":")),
                "DeadLetterConfig": {"Arn": environment["deadLetterArn"]},
                "RetryPolicy": {"MaximumEventAgeInSeconds": 900, "MaximumRetryAttempts": 2},
            },
        )
        schedule_created = True
        connector_record = {
            **_item_key(tenant, "DISCOVERY_CONNECTOR", source_id),
            "tenant_id": tenant,
            "sourceId": source_id,
            "sourceKind": source_kind,
            "tokenHash": hashlib.sha256(token.encode()).hexdigest(),
            "revision": 1,
            "status": "active",
            "rotatedAt": now,
            "rotatedBy": actor,
            "managed": True,
        }
        job = {
            **_item_key(tenant, "DISCOVERY_JOB", source_id),
            "tenant_id": tenant,
            "sourceId": source_id,
            "sourceKind": source_kind,
            "provider": provider,
            "providerSecretArn": provider_secret,
            "connectorSecretArn": connector_arn,
            "providerConfiguration": provider_configuration,
            "providerConfigurationDigest": provider_configuration_digest,
            "scheduleName": names["schedule"],
            "configurationDigest": schedule_input["configurationDigest"],
            "intervalMinutes": interval,
            "revision": 1,
            "status": "scheduled",
            "consecutiveFailures": 0,
            "createdAt": now,
            "createdBy": actor,
        }
        audit_payload = {
            "source_id": source_id,
            "provider": provider,
            "interval_minutes": interval,
            "configuration_digest": provider_configuration_digest,
            "repository_count": len(provider_configuration.get("repositories", [])),
            "user_business_unit_count": len(provider_configuration.get("userBusinessUnits", [])),
        }
        audit_record = _managed_discovery_audit_record(
            tenant, "managed_discovery_created", actor, audit_payload, now=now
        )
        DYNAMODB.transact_write_items(
            TransactItems=[
                _transaction_put(connector_record, condition="attribute_not_exists(pk)"),
                _transaction_put(job, condition="attribute_not_exists(pk)"),
                _transaction_put(audit_record, condition="attribute_not_exists(pk)"),
            ]
        )
    except Exception as error:
        if schedule_created:
            try:
                scheduler.delete_schedule(Name=names["schedule"])
            except Exception:
                print(json.dumps({"warning": "managed discovery schedule cleanup failed"}))
        if connector_arn:
            try:
                secrets_client.delete_secret(SecretId=connector_arn, RecoveryWindowInDays=7)
            except Exception:
                print(json.dumps({"warning": "managed discovery secret cleanup failed"}))
        if getattr(error, "response", {}).get("Error", {}).get("Code") in {
            "ConditionalCheckFailedException",
            "TransactionCanceledException",
        }:
            raise PolicyConflict("managed discovery source already exists") from error
        # AWS exception text may include resource coordinates. Collapse it at
        # this trust boundary before the generic request logger sees it.
        raise RuntimeError("managed discovery provisioning failed") from error
    _export_managed_discovery_audit(tenant, "managed_discovery_created", actor, audit_payload)
    return _managed_discovery_view(job)


def _disable_managed_discovery(tenant, source_id, value, actor):
    """Revoke live authority atomically before deleting scheduled AWS resources."""
    if not isinstance(value, dict) or set(value) != {
        "expectedJobRevision",
        "expectedCredentialRevision",
    }:
        raise ValueError("managed discovery disable request has an invalid schema")
    source_id = _bounded_identifier(source_id, "sourceId")
    expected_job = _discovery_integer(value.get("expectedJobRevision"), "expectedJobRevision")
    expected_credential = _discovery_integer(
        value.get("expectedCredentialRevision"), "expectedCredentialRevision"
    )
    job_key = _item_key(tenant, "DISCOVERY_JOB", source_id)
    connector_key = _item_key(tenant, "DISCOVERY_CONNECTOR", source_id)
    job = TABLE.get_item(Key=job_key, ConsistentRead=True).get("Item")
    connector = TABLE.get_item(Key=connector_key, ConsistentRead=True).get("Item")
    if not job or not connector or job.get("status") == "disabled":
        raise LookupError("managed discovery source not found")
    now = int(time.time())
    disabled_job = {
        **job,
        "status": "disabled",
        "revision": expected_job + 1,
        "disabledAt": now,
        "disabledBy": actor,
    }
    revoked_connector = {
        **connector,
        "status": "revoked",
        "revision": expected_credential + 1,
        "revokedAt": now,
        "revokedBy": actor,
    }
    audit_payload = {"source_id": source_id, "cleanup_required": False}
    audit_record = _managed_discovery_audit_record(
        tenant, "managed_discovery_disabled", actor, audit_payload, now=now
    )
    try:
        DYNAMODB.transact_write_items(
            TransactItems=[
                _transaction_put(
                    disabled_job,
                    condition="revision = :revision AND #status <> :disabled",
                    names={"#status": "status"},
                    values={":revision": expected_job, ":disabled": "disabled"},
                ),
                _transaction_put(
                    revoked_connector,
                    condition="revision = :revision AND #status = :active",
                    names={"#status": "status"},
                    values={":revision": expected_credential, ":active": "active"},
                ),
                _transaction_put(audit_record, condition="attribute_not_exists(pk)"),
            ]
        )
    except Exception as error:
        if getattr(error, "response", {}).get("Error", {}).get("Code") in {
            "ConditionalCheckFailedException",
            "TransactionCanceledException",
        }:
            raise PolicyConflict("managed discovery source changed") from error
        raise
    secrets_client, scheduler = _managed_discovery_clients()
    cleanup_required = False
    try:
        scheduler.delete_schedule(Name=job["scheduleName"])
    except Exception:
        cleanup_required = True
    try:
        secrets_client.delete_secret(SecretId=job["connectorSecretArn"], RecoveryWindowInDays=7)
    except Exception:
        cleanup_required = True
    if cleanup_required:
        disabled_job["cleanupRequired"] = True
        TABLE.put_item(Item=disabled_job)
    _export_managed_discovery_audit(
        tenant,
        "managed_discovery_disabled",
        actor,
        {"source_id": source_id, "cleanup_required": cleanup_required},
    )
    return _managed_discovery_view(disabled_job)


def _managed_discovery_view(job):
    """Return operational posture without secret or scheduler coordinates."""
    if not job:
        return None
    configuration = job.get("providerConfiguration")
    provider_summary = None
    if job.get("provider") == "github" and isinstance(configuration, dict):
        repositories = configuration.get("repositories")
        provider_summary = {
            "organization": configuration.get("organization"),
            "repositoryCount": len(repositories) if isinstance(repositories, list) else 0,
        }
    elif job.get("provider") == "intune" and isinstance(configuration, dict):
        mappings = configuration.get("userBusinessUnits")
        provider_summary = {
            "userBusinessUnitCount": len(mappings) if isinstance(mappings, list) else 0,
            "installationEvidenceRequired": True,
        }
    return {
        "provider": job.get("provider"),
        "sourceKind": job.get("sourceKind"),
        "providerSummary": provider_summary,
        "status": job.get("status"),
        "revision": int(job.get("revision", 0)),
        "intervalMinutes": int(job.get("intervalMinutes", 0)),
        "lastAttemptAt": int(job.get("lastAttemptAt", 0)),
        "lastSuccessAt": int(job.get("lastSuccessAt", 0)),
        "lastErrorCode": job.get("lastErrorCode"),
        "consecutiveFailures": int(job.get("consecutiveFailures", 0)),
        "cleanupRequired": job.get("cleanupRequired") is True,
    }


def _discovery_connector_identity(event, tenant, source_id):
    """Authenticate one live bearer against its exact tenant and source record."""
    tenant = _bounded_identifier(tenant, "tenantId")
    source_id = _bounded_identifier(source_id, "sourceId")
    connector = TABLE.get_item(
        Key=_item_key(tenant, "DISCOVERY_CONNECTOR", source_id), ConsistentRead=True
    ).get("Item")
    token = _bearer(event)
    supplied = hashlib.sha256(token.encode()).hexdigest() if token else ""
    if (
        not connector
        or connector.get("status") != "active"
        or not isinstance(connector.get("tokenHash"), str)
        or not secrets.compare_digest(supplied, connector["tokenHash"])
    ):
        raise PermissionError("active discovery connector credential is required")
    return tenant, source_id, connector


def _discovery_snapshot_metadata(source, *, now=None):
    """Return redacted freshness metadata without loading observation content."""
    if not source:
        return None
    current_time = int(time.time()) if now is None else int(now)
    complete = source.get("complete") is True
    fresh = int(source.get("expiresAt", 0)) > current_time
    stored_count = source.get("observationCount")
    observations = source.get("observations")
    observation_count = (
        int(stored_count)
        if isinstance(stored_count, (int, Decimal)) and not isinstance(stored_count, bool)
        else len(observations)
        if isinstance(observations, list)
        else 0
    )
    status = (
        "current"
        if complete and fresh and observation_count > 0
        else "incomplete"
        if not complete
        else "stale"
        if not fresh
        else "empty"
    )
    return {
        "generation": source.get("generation"),
        "revision": int(source.get("revision", 0)),
        "status": status,
        "complete": complete,
        "observedAt": int(source.get("observedAt", 0)),
        "expiresAt": int(source.get("expiresAt", 0)),
        "observationCount": observation_count,
        "contentHash": source.get("contentHash"),
    }


def _discovery_source_directory(tenant, *, now=None):
    """List registered source credentials and committed snapshot posture.

    Secret digests, plaintext tokens and observation content never cross this
    operator read boundary. Legacy snapshot-only sources remain visible so the
    UI cannot mistake an unmanaged publication path for a missing source.
    """
    current_time = int(time.time()) if now is None else int(now)
    connectors = {
        item.get("sourceId"): item
        for item in _list(tenant, "DISCOVERY_CONNECTOR", consistent_read=True)
        if isinstance(item.get("sourceId"), str)
    }
    sources = {
        item.get("sourceId"): item
        for item in _list(tenant, "DISCOVERY_SOURCE", consistent_read=True)
        if isinstance(item.get("sourceId"), str)
    }
    jobs = {
        item.get("sourceId"): item
        for item in _list(tenant, "DISCOVERY_JOB", consistent_read=True)
        if isinstance(item.get("sourceId"), str)
    }
    items = []
    for source_id in sorted(set(connectors) | set(sources) | set(jobs)):
        connector = connectors.get(source_id)
        source = sources.get(source_id)
        job = jobs.get(source_id)
        source_kind = (connector or source or job or {}).get("sourceKind")
        if source_kind not in _DISCOVERY_SOURCE_KINDS:
            # Malformed server state must not be presented as configured.
            continue
        credential = (
            {
                "status": connector.get("status"),
                "revision": int(connector.get("revision", 0)),
                "rotatedAt": int(connector.get("rotatedAt", 0)),
                "revokedAt": int(connector.get("revokedAt", 0))
                if connector.get("revokedAt") is not None
                else None,
            }
            if connector
            else {"status": "not_configured", "revision": 0, "rotatedAt": 0, "revokedAt": None}
        )
        items.append(
            {
                "sourceId": source_id,
                "sourceKind": source_kind,
                "credential": credential,
                "snapshot": _discovery_snapshot_metadata(source, now=current_time),
                "managedCollector": _managed_discovery_view(job),
            }
        )
    return {"items": items, "nextCursor": None}


def _begin_discovery_generation(tenant, source_id, connector, value):
    """Create immutable metadata for one bounded, not-yet-visible generation."""
    required = {
        "generation",
        "expectedRevision",
        "observedAt",
        "expiresAt",
        "pageCount",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("discovery generation has an invalid schema")
    generation = _bounded_identifier(value.get("generation"), "generation")
    expected = _discovery_integer(value.get("expectedRevision"), "expectedRevision")
    observed_at = _discovery_integer(value.get("observedAt"), "observedAt", minimum=1)
    expires_at = _discovery_integer(value.get("expiresAt"), "expiresAt", minimum=1)
    page_count = _discovery_integer(value.get("pageCount"), "pageCount", minimum=1)
    now = int(time.time())
    if page_count > _DISCOVERY_GENERATION_MAX_PAGES:
        raise ValueError("pageCount exceeds the bounded generation limit")
    if observed_at > now + 300 or expires_at <= now:
        raise ValueError("discovery generation must be current")
    if expires_at <= observed_at or expires_at - observed_at > _DISCOVERY_MAX_VALIDITY_SECONDS:
        raise ValueError("discovery generation validity is unsafe")
    source = TABLE.get_item(
        Key=_item_key(tenant, "DISCOVERY_SOURCE", source_id), ConsistentRead=True
    ).get("Item")
    revision = int(source.get("revision", 0)) if source else 0
    if revision != expected:
        raise PolicyConflict("discovery source revision changed")
    record = {
        **_item_key(tenant, "DISCOVERY_GENERATION", f"{source_id}:{generation}"),
        "tenant_id": tenant,
        "sourceId": source_id,
        "sourceKind": connector["sourceKind"],
        "generation": generation,
        "expectedRevision": expected,
        "observedAt": observed_at,
        "expiresAt": expires_at,
        "pageCount": page_count,
        "state": "uploading",
        "createdAt": now,
    }
    TABLE.put_item(Item=record, ConditionExpression="attribute_not_exists(pk)")
    return {key: value for key, value in record.items() if key not in {"pk", "sk", "tenant_id"}}


def _put_discovery_generation_page(tenant, source_id, generation, page_number, value):
    """Store one normalized immutable page; duplicate uploads fail closed."""
    generation = _bounded_identifier(generation, "generation")
    page_number = _discovery_integer(page_number, "pageNumber")
    generation_record = TABLE.get_item(
        Key=_item_key(tenant, "DISCOVERY_GENERATION", f"{source_id}:{generation}"),
        ConsistentRead=True,
    ).get("Item")
    if not generation_record or generation_record.get("state") != "uploading":
        raise LookupError("uploading discovery generation not found")
    if page_number >= int(generation_record["pageCount"]):
        raise ValueError("pageNumber is outside the declared generation")
    if not isinstance(value, dict) or set(value) != {"observations"}:
        raise ValueError("discovery generation page has an invalid schema")
    observations = value.get("observations")
    if (
        not isinstance(observations, list)
        or not 1 <= len(observations) <= _DISCOVERY_GENERATION_PAGE_LIMIT
    ):
        raise ValueError("discovery generation page must contain 1 to 100 observations")
    normalized = [
        _discovery_observation(item, generation_record["sourceKind"]) for item in observations
    ]
    identities = [(item["kind"], item["id"]) for item in normalized]
    if len(set(identities)) != len(identities):
        raise ValueError("discovery observations must be unique within a page")
    normalized.sort(key=lambda item: (item["kind"], item["id"]))
    page_hash = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    record = {
        **_item_key(
            tenant,
            "DISCOVERY_PAGE",
            f"{source_id}:{generation}:{page_number:05d}",
        ),
        "tenant_id": tenant,
        "sourceId": source_id,
        "generation": generation,
        "pageNumber": page_number,
        "pageHash": page_hash,
        "observations": normalized,
    }
    TABLE.put_item(Item=record, ConditionExpression="attribute_not_exists(pk)")
    return {"pageNumber": page_number, "pageHash": page_hash, "observationCount": len(normalized)}


def _commit_discovery_generation(tenant, source_id, generation, value, actor):
    """Atomically make a complete, hash-bound generation current for its source."""
    if not isinstance(value, dict) or set(value) != {"pageHashes"}:
        raise ValueError("discovery generation commit has an invalid schema")
    generation = _bounded_identifier(generation, "generation")
    generation_key = _item_key(tenant, "DISCOVERY_GENERATION", f"{source_id}:{generation}")
    staged = TABLE.get_item(Key=generation_key, ConsistentRead=True).get("Item")
    if not staged or staged.get("state") != "uploading":
        raise LookupError("uploading discovery generation not found")
    page_hashes = value.get("pageHashes")
    if (
        not isinstance(page_hashes, list)
        or len(page_hashes) != int(staged["pageCount"])
        or any(
            not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item)
            for item in page_hashes
        )
    ):
        raise ValueError("pageHashes must exactly describe every declared page")
    pages = []
    observations = []
    for page_number, expected_hash in enumerate(page_hashes):
        page = TABLE.get_item(
            Key=_item_key(tenant, "DISCOVERY_PAGE", f"{source_id}:{generation}:{page_number:05d}"),
            ConsistentRead=True,
        ).get("Item")
        if not page or not secrets.compare_digest(str(page.get("pageHash", "")), expected_hash):
            raise ValueError("generation page is missing or its hash does not match")
        pages.append(page)
        observations.extend(page.get("observations", []))
    identities = [(item["kind"], item["id"]) for item in observations]
    if len(set(identities)) != len(identities):
        raise ValueError("discovery observations must be unique across the generation")
    # DynamoDB deserializes numbers as Decimal. Normalize the exact integer
    # metadata before canonical JSON hashing so deployed behavior matches the
    # in-memory contract and never depends on boto3 representation details.
    observed_at = _discovery_integer(staged["observedAt"], "observedAt", minimum=1)
    expires_at = _discovery_integer(staged["expiresAt"], "expiresAt", minimum=1)
    page_count = _discovery_integer(staged["pageCount"], "pageCount", minimum=1)
    content_hash = hashlib.sha256(
        json.dumps(
            {
                "sourceId": source_id,
                "sourceKind": staged["sourceKind"],
                "generation": generation,
                "observedAt": observed_at,
                "expiresAt": expires_at,
                "pageHashes": page_hashes,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    now = int(time.time())
    expected = int(staged["expectedRevision"])
    source_record = {
        **_item_key(tenant, "DISCOVERY_SOURCE", source_id),
        "tenant_id": tenant,
        "sourceId": source_id,
        "sourceKind": staged["sourceKind"],
        "generation": generation,
        "observedAt": observed_at,
        "expiresAt": expires_at,
        "complete": True,
        "pageCount": page_count,
        "observationCount": len(observations),
        "contentHash": content_hash,
        "revision": expected + 1,
        "publishedAt": now,
        "publishedBy": actor,
    }
    committed = {
        **staged,
        "state": "committed",
        "committedAt": now,
        "contentHash": content_hash,
        "observationCount": len(observations),
    }
    source_condition = "attribute_not_exists(pk)" if expected == 0 else "revision = :revision"
    source_values = None if expected == 0 else {":revision": expected}
    try:
        DYNAMODB.transact_write_items(
            TransactItems=[
                _transaction_put(source_record, condition=source_condition, values=source_values),
                _transaction_put(
                    committed,
                    condition="#state = :uploading",
                    names={"#state": "state"},
                    values={":uploading": "uploading"},
                ),
            ]
        )
    except Exception as error:
        if getattr(error, "response", {}).get("Error", {}).get("Code") in {
            "ConditionalCheckFailedException",
            "TransactionCanceledException",
        }:
            raise PolicyConflict("discovery source or generation changed") from error
        raise
    _audit(
        tenant,
        "discovery_generation_committed",
        actor,
        {
            "source_id": source_id,
            "source_kind": staged["sourceKind"],
            "generation": generation,
            "revision": expected + 1,
            "page_count": len(pages),
            "observation_count": len(observations),
            "content_hash": content_hash,
        },
    )
    return {
        key: item for key, item in source_record.items() if key not in {"pk", "sk", "tenant_id"}
    }


def _discovery_generation_observations(tenant, source):
    """Load only pages named by an atomically committed source generation."""
    if "observations" in source:
        return source.get("observations") if isinstance(source.get("observations"), list) else []
    generation = source.get("generation")
    page_count = source.get("pageCount")
    if not isinstance(generation, str) or not isinstance(page_count, (int, Decimal)):
        return []
    observations = []
    for page_number in range(int(page_count)):
        page = TABLE.get_item(
            Key=_item_key(
                tenant,
                "DISCOVERY_PAGE",
                f"{source.get('sourceId')}:{generation}:{page_number:05d}",
            ),
            ConsistentRead=True,
        ).get("Item")
        if not page:
            return []
        observations.extend(page.get("observations", []))
    return observations


def _create_item(tenant, kind, identifier, item):
    """Create one tenant-scoped record without allowing identity replacement."""
    record = {**_item_key(tenant, kind, identifier), **item, "tenant_id": tenant}
    TABLE.put_item(Item=record, ConditionExpression="attribute_not_exists(pk)")
    return record


def _is_conditional_conflict(error):
    """Return whether DynamoDB rejected a create/update precondition."""
    return (
        getattr(error, "response", {}).get("Error", {}).get("Code")
        == "ConditionalCheckFailedException"
    )


def _list(tenant, kind, *, consistent_read=False):
    """Return a complete bounded tenant list or fail instead of truncating it."""
    condition = Key("pk").eq(f"TENANT#{tenant}") & Key("sk").begins_with(f"{kind}#")
    items = []
    exclusive_start_key = None
    pages = 0
    while True:
        arguments = {
            "KeyConditionExpression": condition,
            "Limit": _LIST_PAGE_ITEM_LIMIT,
        }
        if consistent_read:
            arguments["ConsistentRead"] = True
        if exclusive_start_key is not None:
            arguments["ExclusiveStartKey"] = exclusive_start_key
        result = TABLE.query(**arguments)
        page_items = result.get("Items", [])
        if len(items) + len(page_items) > _MAX_LIST_ITEMS:
            raise RuntimeError("Tenant list exceeds the bounded item limit")
        items.extend(page_items)
        pages += 1
        exclusive_start_key = result.get("LastEvaluatedKey")
        if not exclusive_start_key:
            return items
        if pages >= _MAX_LIST_PAGES:
            raise RuntimeError("Tenant list exceeds the bounded page limit")


def _decision_window(tenant):
    """Return bounded recent decision evidence and whether older data exists.

    New evidence is ordered by a dedicated timeline index. One bounded legacy
    page preserves visibility during migration without restoring an unbounded
    dashboard read. The truncation bit tells the UI that counts are lower
    bounds rather than silently presenting an incomplete total as exact.
    """
    timeline = TABLE.query(
        IndexName=_DECISION_TIMELINE_INDEX,
        KeyConditionExpression=Key("timeline_pk").eq(f"TENANT#{tenant}#DECISION"),
        ScanIndexForward=False,
        Limit=_DECISION_WINDOW_LIMIT,
    )
    legacy = TABLE.query(
        KeyConditionExpression=Key("pk").eq(f"TENANT#{tenant}")
        & Key("sk").begins_with("DECISION#"),
        Limit=_DECISION_WINDOW_LIMIT,
    )
    by_key = {
        (item.get("pk", ""), item.get("sk", "")): item
        for item in timeline.get("Items", []) + legacy.get("Items", [])
    }
    decisions = sorted(
        by_key.values(),
        key=lambda item: int(item.get("observed_at", 0)),
        reverse=True,
    )[:_DECISION_WINDOW_LIMIT]
    truncated = bool(
        timeline.get("LastEvaluatedKey")
        or legacy.get("LastEvaluatedKey")
        or len(by_key) > _DECISION_WINDOW_LIMIT
    )
    return decisions, truncated


def _fleet_emergency_stop_active(tenant):
    """Return the tenant-wide stop state from server-owned control data.

    The value is never inferred from browser input or from a single agent
    record. Keeping the fleet stop as its own durable control means newly
    enrolled agents also fail closed while an incident is active, and clearing
    it cannot silently clear a narrower agent, group, or deployment stop.
    """
    item = TABLE.get_item(
        Key=_item_key(tenant, "CONTROL", "fleet-emergency-stop"),
        ConsistentRead=True,
    ).get("Item")
    return bool(item and item.get("active") is True)


def _scope_control_id(scope, identifier):
    """Return one unambiguous identifier for an independent response scope."""
    if scope not in {"fleet", "deployment", "group", "agent"}:
        raise ValueError("emergency-stop scope is unsupported")
    value = "all" if scope == "fleet" else _bounded_identifier(identifier, f"{scope}Id")
    return f"emergency-stop:{scope}:{value}"


def _scope_emergency_stop(tenant, scope, identifier="all"):
    """Read one server-owned stop without inferring another scope's state."""
    legacy_id = "fleet-emergency-stop" if scope == "fleet" else None
    key = _scope_control_id(scope, identifier)
    item = TABLE.get_item(
        Key=_item_key(tenant, "CONTROL", legacy_id or key),
        ConsistentRead=True,
    ).get("Item")
    return bool(item and item.get("active") is True)


def _set_scope_emergency_stop(tenant, scope, identifier, active, actor):
    """Persist an independent reversible stop and return its revisioned view."""
    control_id = _scope_control_id(scope, identifier)
    # Preserve the established fleet key so existing deployments keep the same
    # immediate authority record. Narrower scopes use separate records and can
    # therefore never erase each other by rewriting an agent flag.
    stored_id = "fleet-emergency-stop" if scope == "fleet" else control_id
    current = TABLE.get_item(Key=_item_key(tenant, "CONTROL", stored_id), ConsistentRead=True).get(
        "Item"
    )
    record = _put(
        tenant,
        "CONTROL",
        stored_id,
        {
            "id": stored_id,
            "scope": scope,
            "scopeId": "all" if scope == "fleet" else identifier,
            "active": bool(active),
            "revision": int(current.get("revision", 0)) + 1 if current else 1,
            "updatedAt": int(time.time()),
            "updatedBy": actor,
        },
    )
    return {
        "scope": scope,
        "scopeId": record["scopeId"],
        "active": record["active"],
        "revision": int(record["revision"]),
        "updatedAt": int(record["updatedAt"]),
        "updatedBy": record["updatedBy"],
    }


def _active_agent_containment(tenant, agent_key):
    """Return one active case-owned quarantine for an exact agent identity."""
    item = TABLE.get_item(Key=_item_key(tenant, "CONTAINMENT", agent_key), ConsistentRead=True).get(
        "Item"
    )
    return item if item and item.get("active") is True else None


def _agent_control_state(tenant, agent):
    """Derive exact execution authority from every independent response scope."""
    if not agent:
        return {
            "executionAllowed": False,
            "evidenceAllowed": False,
            "activeStopScopes": ["missing_agent"],
            "quarantine": None,
        }
    deployment_id = str(agent.get("deployment_id", ""))
    agent_key = f"{deployment_id}:{agent.get('id', '')}"
    scopes = []
    if _scope_emergency_stop(tenant, "fleet"):
        scopes.append("fleet")
    if deployment_id and _scope_emergency_stop(tenant, "deployment", deployment_id):
        scopes.append("deployment")
    groups = [
        group
        for group in _list(tenant, "GROUP", consistent_read=True)
        if agent_key in group.get("agent_keys", [])
    ]
    if any(
        group.get("emergencyStop") is True
        or _scope_emergency_stop(tenant, "group", group.get("id", ""))
        for group in groups
    ):
        scopes.append("group")
    if agent.get("emergencyStop") is True or _scope_emergency_stop(tenant, "agent", agent_key):
        scopes.append("agent")
    containment = _active_agent_containment(tenant, agent_key)
    quarantine = (
        {
            "active": True,
            "mode": "quarantine",
            "caseId": containment.get("caseId"),
            "revision": int(containment.get("revision", 0)),
            "activatedAt": int(containment.get("activatedAt", 0)),
        }
        if containment
        else None
    )
    return {
        "executionAllowed": not scopes and quarantine is None,
        # Quarantine intentionally preserves the signed heartbeat/attestation
        # channel. Emergency stop also preserves evidence in the current host
        # protocol but withholds all execution authority.
        "evidenceAllowed": True,
        "activeStopScopes": scopes,
        "quarantine": quarantine,
    }


def _require_agent_execution_authority(tenant, agent):
    """Fail closed before any governed authority is returned or consumed."""
    state = _agent_control_state(tenant, agent)
    if state["quarantine"] is not None:
        raise PermissionError("agent is in incident quarantine")
    if state["activeStopScopes"]:
        raise PermissionError("agent emergency stop is active")
    return state


def _set_fleet_emergency_stop(tenant, active, actor):
    """Persist a reversible fleet stop and return the authoritative state."""
    return _set_scope_emergency_stop(tenant, "fleet", "all", active, actor)


def _evidence_policy(tenant):
    """Return the tenant's future-record retention policy or a safe default.

    The bucket-level 365-day COMPLIANCE policy is the hard floor. Tenant state
    may only extend that floor; missing or malformed state never shortens it.
    """
    item = TABLE.get_item(
        Key=_item_key(tenant, "EVIDENCE_POLICY", "retention"), ConsistentRead=True
    ).get("Item")
    if not item:
        return {
            "retentionDays": _EVIDENCE_RETENTION_MIN_DAYS,
            "revision": 0,
            "updatedAt": None,
            "updatedBy": None,
            "applicationStatus": "applied",
            "applicationJobId": None,
            "applicationStartedAt": None,
            "appliedAt": None,
            "affectedRecordCount": None,
            "failureReason": None,
        }
    days = item.get("retention_days")
    revision = item.get("revision")
    if (
        isinstance(days, bool)
        or not isinstance(days, (int, Decimal))
        or (isinstance(days, Decimal) and days != days.to_integral_value())
        or int(days) < _EVIDENCE_RETENTION_MIN_DAYS
        or int(days) > _EVIDENCE_RETENTION_MAX_DAYS
        or isinstance(revision, bool)
        or not isinstance(revision, (int, Decimal))
        or (isinstance(revision, Decimal) and revision != revision.to_integral_value())
        or int(revision) < 1
    ):
        raise RuntimeError("tenant evidence retention policy is malformed")
    application_status = item.get("application_status", "applied")
    if application_status not in {"applied", "applying", "failed"}:
        raise RuntimeError("tenant evidence retention application state is malformed")
    application_job_id = item.get("application_job_id")
    if application_status in {"applying", "failed"} and (
        not isinstance(application_job_id, str) or not application_job_id
    ):
        raise RuntimeError("tenant evidence retention job binding is malformed")
    return {
        "retentionDays": int(days),
        "revision": int(revision),
        "updatedAt": int(item.get("updated_at", 0)) or None,
        "updatedBy": item.get("updated_by"),
        "applicationStatus": application_status,
        "applicationJobId": application_job_id,
        "applicationStartedAt": int(item.get("application_started_at", 0)) or None,
        "appliedAt": int(item.get("applied_at", 0)) or None,
        "affectedRecordCount": (
            int(item["affected_record_count"])
            if item.get("affected_record_count") is not None
            else None
        ),
        "failureReason": item.get("failure_reason"),
    }


def _evidence_body_bytes(response):
    """Read one bounded S3 body into bytes for integrity verification."""
    body = response.get("Body")
    value = body.read() if hasattr(body, "read") else body
    if not isinstance(value, bytes) or len(value) > 1_048_576:
        raise RuntimeError("retained evidence body is missing or exceeds the verification bound")
    return value


def _evidence_object_lock_state(method, *, key, version_id, field):
    """Read one optional legacy Object Lock property without hiding real failures.

    S3 returns ``NoSuchObjectLockConfiguration`` for versions created before a
    legal hold or explicit retention was attached.  That is evidence of a
    missing safeguard, not a control-plane outage.  Every other error remains
    fatal so denied access and unavailable assurance cannot be mistaken for a
    safe result.
    """
    try:
        return method(Bucket=os.environ["AUDIT_BUCKET"], Key=key, VersionId=version_id).get(
            field, {}
        )
    except Exception as error:
        if (
            getattr(error, "response", {}).get("Error", {}).get("Code")
            == "NoSuchObjectLockConfiguration"
        ):
            return {}
        raise


def _evidence_record(tenant, version):
    """Verify and project one exact immutable audit-object version."""
    prefix = f"tenant={tenant}/"
    key = version.get("Key")
    version_id = version.get("VersionId")
    if not isinstance(key, str) or not key.startswith(prefix) or not isinstance(version_id, str):
        raise RuntimeError("audit inventory returned an invalid tenant object identity")
    head = S3.head_object(Bucket=os.environ["AUDIT_BUCKET"], Key=key, VersionId=version_id)
    body = _evidence_body_bytes(
        S3.get_object(Bucket=os.environ["AUDIT_BUCKET"], Key=key, VersionId=version_id)
    )
    content_hash = hashlib.sha256(body).hexdigest()
    expected_hash = head.get("Metadata", {}).get("content-sha256")
    retention = _evidence_object_lock_state(
        S3.get_object_retention,
        key=key,
        version_id=version_id,
        field="Retention",
    )
    hold = _evidence_object_lock_state(
        S3.get_object_legal_hold,
        key=key,
        version_id=version_id,
        field="LegalHold",
    )
    modified = version.get("LastModified")
    return {
        "key": key,
        "versionId": version_id,
        "size": int(version.get("Size", len(body))),
        "lastModified": modified.isoformat() if hasattr(modified, "isoformat") else str(modified),
        "contentSha256": content_hash,
        "integrity": (
            "verified"
            if expected_hash and secrets.compare_digest(expected_hash, content_hash)
            else "legacy_unbound"
            if not expected_hash
            else "mismatch"
        ),
        "retentionMode": retention.get("Mode"),
        "retainUntil": (
            retention.get("RetainUntilDate").isoformat()
            if hasattr(retention.get("RetainUntilDate"), "isoformat")
            else None
        ),
        "legalHold": hold.get("Status") == "ON",
    }


def _evidence_inventory(tenant):
    """Return a complete bounded manifest of immutable tenant audit versions.

    The route refuses to call a truncated list complete. Larger tenants must use
    the future asynchronous inventory/export path rather than receive a partial
    browser artifact that looks authoritative.
    """
    prefix = f"tenant={tenant}/"
    response = S3.list_object_versions(
        Bucket=os.environ["AUDIT_BUCKET"], Prefix=prefix, MaxKeys=_EVIDENCE_RECORD_LIMIT + 1
    )
    versions = response.get("Versions", [])
    delete_markers = response.get("DeleteMarkers", [])
    observed_version_count = len(versions)
    complete = (
        not response.get("IsTruncated", False) and observed_version_count <= _EVIDENCE_RECORD_LIMIT
    )
    if not complete:
        # A sample cannot support tenant-wide assurance. Stop before any
        # per-object reads so a large tenant gets a fast, honest incomplete
        # result rather than a misleading sample or a Lambda timeout.
        return {
            "records": [],
            "complete": False,
            "observedVersionCount": observed_version_count,
            "deleteMarkerCount": len(delete_markers),
        }
    records = []
    for version in versions:
        records.append(_evidence_record(tenant, version))
    records.sort(key=lambda item: (item["lastModified"], item["key"], item["versionId"]))
    return {
        "records": records,
        "complete": complete,
        "observedVersionCount": observed_version_count,
        "deleteMarkerCount": len(delete_markers),
    }


def _evidence_assurance(tenant):
    """Derive tenant evidence posture from live object versions and lock state."""
    inventory = _evidence_inventory(tenant)
    records = inventory["records"]
    policy = _evidence_policy(tenant)
    latest_job = _latest_evidence_job(tenant, statuses={"queued", "running", "completed", "failed"})
    latest_retention_job = _latest_retention_job(tenant)
    now = datetime.now(UTC)
    at_risk = [
        item
        for item in records
        if item["integrity"] != "verified"
        or item["retentionMode"] != "COMPLIANCE"
        or not item["retainUntil"]
        or datetime.fromisoformat(item["retainUntil"]) <= now
    ]
    status = "incomplete" if not inventory["complete"] else "at_risk" if at_risk else "verified"
    return {
        "schemaVersion": 1,
        "status": status,
        "policy": policy,
        "recordCount": inventory["observedVersionCount"],
        "verifiedCount": len(records) - len(at_risk),
        "legalHoldCount": sum(1 for item in records if item["legalHold"]),
        "deleteMarkerCount": inventory["deleteMarkerCount"],
        "complete": inventory["complete"],
        "records": list(reversed(records[-100:])),
        "checkedAt": int(time.time()),
        "latestAsyncJob": _evidence_job_view(latest_job) if latest_job else None,
        "latestRetentionJob": (
            _retention_job_view(latest_retention_job) if latest_retention_job else None
        ),
        "monitor": _evidence_monitor_view(_evidence_monitor_record(tenant)),
    }


def _canonical_sha256(value):
    """Return the SHA-256 digest of one canonical JSON-safe value."""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _evidence_job_record(tenant, job_id):
    """Load one exact tenant-bound asynchronous evidence job."""
    item = TABLE.get_item(Key=_item_key(tenant, "EVIDENCE_JOB", job_id), ConsistentRead=True).get(
        "Item"
    )
    if not item:
        raise LookupError("evidence assurance job not found")
    if item.get("tenant_id") != tenant or item.get("id") != job_id:
        raise RuntimeError("evidence assurance job identity is malformed")
    return item


def _evidence_job_view(item):
    """Project job progress without exposing S3 keys, cursors or rationale."""
    view = {
        "id": item.get("id"),
        "mode": "assurance_export",
        "source": item.get("source"),
        "status": item.get("status"),
        "revision": int(item.get("revision", 0)),
        "snapshotCutoff": int(item.get("snapshot_cutoff", 0)),
        "createdAt": int(item.get("created_at", 0)),
        "startedAt": item.get("started_at"),
        "updatedAt": int(item.get("updated_at", 0)),
        "completedAt": item.get("completed_at"),
        "recordCount": int(item.get("record_count", 0)),
        "verifiedCount": int(item.get("verified_count", 0)),
        "atRiskCount": int(item.get("at_risk_count", 0)),
        "legalHoldCount": int(item.get("legal_hold_count", 0)),
        "deleteMarkerCount": int(item.get("delete_marker_count", 0)),
        "pageCount": int(item.get("page_count", 0)),
        "contentSha256": item.get("content_sha256"),
        "chainSha256": item.get("chain_sha256"),
        "failureReason": item.get("failure_reason"),
    }
    if item.get("status") == "completed" and item.get("content_sha256"):
        view["exportIndex"] = {
            **_evidence_report_index_content(item),
            "contentSha256": item["content_sha256"],
        }
    else:
        view["exportIndex"] = None
    return view


def _evidence_jobs(tenant):
    """Return recent tenant jobs in deterministic newest-first order."""
    items = _list(tenant, "EVIDENCE_JOB", consistent_read=True)
    items.sort(
        key=lambda item: (int(item.get("created_at", 0)), str(item.get("id", ""))),
        reverse=True,
    )
    return [_evidence_job_view(item) for item in items[:50]]


def _latest_evidence_job(tenant, *, statuses=None, exclude_id=None):
    """Return the newest job matching a bounded status set."""
    allowed = set(statuses or {"queued", "running", "completed", "failed"})
    candidates = [
        item
        for item in _list(tenant, "EVIDENCE_JOB", consistent_read=True)
        if item.get("status") in allowed and item.get("id") != exclude_id
    ]
    return max(
        candidates,
        key=lambda item: (int(item.get("created_at", 0)), str(item.get("id", ""))),
        default=None,
    )


def _enqueue_evidence_job(tenant, job_id, revision):
    """Send one revision-bound FIFO work item without granting tenant authority."""
    queue_url = os.environ.get("EVIDENCE_QUEUE_URL", "")
    if not queue_url:
        raise RuntimeError("asynchronous evidence queue is not configured")
    body = {
        "schemaVersion": 1,
        "tenantId": tenant,
        "jobId": job_id,
        "expectedRevision": int(revision),
    }
    SQS.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps(body, sort_keys=True, separators=(",", ":")),
        MessageGroupId=job_id,
        MessageDeduplicationId=f"{job_id}:{int(revision)}",
    )


def _create_evidence_job(tenant, request_id, actor, rationale, *, source):
    """Create one idempotent point-in-time assurance/export job."""
    if not isinstance(request_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", request_id
    ):
        raise ValueError("requestId is invalid")
    rationale = _case_reason(rationale)
    if source not in {"operator", "schedule"}:
        raise ValueError("evidence job source is invalid")
    job_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"aai:evidence:{tenant}:{request_id}"))
    request_hash = _canonical_sha256(
        {"requestId": request_id, "rationale": rationale, "source": source}
    )
    key = _item_key(tenant, "EVIDENCE_JOB", job_id)
    existing = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    if existing:
        if not secrets.compare_digest(str(existing.get("request_hash", "")), request_hash):
            raise PolicyConflict("evidence requestId was already used for different input")
        return existing
    now = int(time.time())
    baseline = _latest_evidence_job(tenant, statuses={"completed"})
    item = {
        **key,
        "tenant_id": tenant,
        "id": job_id,
        "request_id": request_id,
        "request_hash": request_hash,
        "source": source,
        "status": "queued",
        "revision": 1,
        # A two-second boundary plus strongly consistent S3 LIST semantics
        # prevents writes racing the request from being represented as part of
        # this point-in-time snapshot.
        "snapshot_cutoff": now - 2,
        "created_at": now,
        "updated_at": now,
        "created_by": actor,
        "rationale_hash": hashlib.sha256(rationale.encode()).hexdigest(),
        "record_count": 0,
        "verified_count": 0,
        "at_risk_count": 0,
        "legal_hold_count": 0,
        "delete_marker_count": 0,
        "page_count": 0,
        "chain_sha256": _EVIDENCE_INITIAL_CHAIN_HASH,
        "baseline_record_count": int(baseline.get("record_count", 0)) if baseline else None,
        "ttl": now + _EVIDENCE_JOB_RETENTION_SECONDS,
    }
    try:
        TABLE.put_item(Item=item, ConditionExpression="attribute_not_exists(pk)")
    except Exception as error:
        if _is_conditional_conflict(error):
            concurrent = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
            if concurrent and secrets.compare_digest(
                str(concurrent.get("request_hash", "")), request_hash
            ):
                return concurrent
            raise PolicyConflict("evidence assurance job changed concurrently") from error
        raise
    try:
        _enqueue_evidence_job(tenant, job_id, 1)
    except Exception:
        failed = {
            **item,
            "status": "failed",
            "revision": 2,
            "failure_reason": "queue_unavailable",
            "updated_at": int(time.time()),
        }
        TABLE.put_item(
            Item=failed,
            ConditionExpression="revision = :revision",
            ExpressionAttributeValues={":revision": 1},
        )
        _audit(
            tenant,
            "evidence_assurance_job_failed",
            actor,
            {"job_id": job_id, "reason_code": "queue_unavailable"},
        )
        _reconcile_evidence_monitor(tenant, failed)
        raise
    _audit(
        tenant,
        "evidence_assurance_job_started",
        actor,
        {"job_id": job_id, "source": source, "snapshot_cutoff": item["snapshot_cutoff"]},
    )
    return item


def _start_evidence_job(tenant, body, actor):
    """Validate an operator request and return its idempotent job projection."""
    if not isinstance(body, dict) or set(body) != {"requestId", "rationale"}:
        raise ValueError("evidence assurance job request has an invalid schema")
    return _evidence_job_view(
        _create_evidence_job(
            tenant,
            body.get("requestId"),
            actor,
            body.get("rationale"),
            source="operator",
        )
    )


def _evidence_record_at_risk(record, *, now):
    """Return whether one verified version lacks integrity or live retention."""
    if record.get("integrity") != "verified" or record.get("retentionMode") != "COMPLIANCE":
        return True
    retain_until = record.get("retainUntil")
    if not isinstance(retain_until, str):
        return True
    try:
        return datetime.fromisoformat(retain_until) <= now
    except ValueError:
        return True


def _evidence_report_page_key(tenant, job_id, page_number):
    """Return a deterministic tenant/job report key for one bounded page."""
    return f"tenant={tenant}/job={job_id}/page={int(page_number):06d}.json"


def _write_evidence_report_page(tenant, job_id, page_number, cutoff, records):
    """Persist one content-bound derived page in the private report bucket."""
    content = {
        "schemaVersion": 1,
        "tenantId": tenant,
        "jobId": job_id,
        "pageNumber": int(page_number),
        "snapshotCutoff": int(cutoff),
        "records": records,
    }
    content_hash = _canonical_sha256(content)
    body = json.dumps(
        {**content, "contentSha256": content_hash},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    if len(body) > 512_000:
        raise RuntimeError("evidence report page exceeds its safe bound")
    response = S3.put_object(
        Bucket=os.environ["EVIDENCE_REPORT_BUCKET"],
        Key=_evidence_report_page_key(tenant, job_id, page_number),
        Body=body,
        ContentType="application/json",
        Metadata={"content-sha256": hashlib.sha256(body).hexdigest(), "schema-version": "1"},
    )
    if not isinstance(response.get("VersionId"), str):
        raise RuntimeError("evidence report bucket did not return a version identity")
    return content_hash


def _evidence_report_index_content(job):
    """Return the canonical chain-bound export index content."""
    return {
        "schemaVersion": 1,
        "tenantId": job["tenant_id"],
        "jobId": job["id"],
        "snapshotCutoff": int(job["snapshot_cutoff"]),
        "generatedAt": int(job["completed_at"]),
        "recordCount": int(job["record_count"]),
        "verifiedCount": int(job["verified_count"]),
        "atRiskCount": int(job["at_risk_count"]),
        "legalHoldCount": int(job["legal_hold_count"]),
        "deleteMarkerCount": int(job["delete_marker_count"]),
        "pageCount": int(job["page_count"]),
        "chainSha256": job["chain_sha256"],
        "retentionPolicy": job["retention_policy"],
    }


def _write_evidence_report_index(job):
    """Persist the chain-bound completion index and return its canonical digest."""
    content = _evidence_report_index_content(job)
    content_hash = _canonical_sha256(content)
    body = json.dumps(
        {**content, "contentSha256": content_hash},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    response = S3.put_object(
        Bucket=os.environ["EVIDENCE_REPORT_BUCKET"],
        Key=f"tenant={job['tenant_id']}/job={job['id']}/index.json",
        Body=body,
        ContentType="application/json",
        Metadata={"content-sha256": hashlib.sha256(body).hexdigest(), "schema-version": "1"},
    )
    if not isinstance(response.get("VersionId"), str):
        raise RuntimeError("evidence report index has no immutable version identity")
    return content_hash


def _evidence_monitor_record(tenant):
    """Return the latest scheduled assurance posture when it exists."""
    return TABLE.get_item(
        Key=_item_key(tenant, "EVIDENCE_MONITOR", "current"), ConsistentRead=True
    ).get("Item")


def _evidence_monitor_view(item):
    """Project content-minimised evidence monitoring state."""
    if not item:
        return {
            "status": "not_run",
            "reasonCodes": ["scheduled_assurance_not_run"],
            "jobId": None,
            "checkedAt": None,
            "alertDelivered": False,
        }
    return {
        "status": item.get("status"),
        "reasonCodes": list(item.get("reason_codes", [])),
        "jobId": item.get("job_id"),
        "checkedAt": item.get("checked_at"),
        "alertDelivered": item.get("delivery_status") == "delivered",
    }


def _publish_evidence_monitor_alert(tenant, monitor):
    """Publish one normalized evidence-gap transition to the durable AWS channel."""
    topic_arn = os.environ.get("SECURITY_ALERTS_TOPIC_ARN", "")
    if not topic_arn:
        return False
    SNS.publish(
        TopicArn=topic_arn,
        Subject="AAI evidence assurance alert",
        Message=json.dumps(
            {
                "schemaVersion": 1,
                "tenantId": tenant,
                "source": "evidence_assurance",
                "status": monitor["status"],
                "reasonCodes": monitor["reason_codes"],
                "jobId": monitor["job_id"],
                "observedAt": int(monitor["checked_at"]),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        MessageAttributes={
            "tenantId": {"DataType": "String", "StringValue": tenant},
            "severity": {
                "DataType": "String",
                "StringValue": "critical" if monitor["status"] == "critical" else "high",
            },
            "source": {"DataType": "String", "StringValue": "evidence_assurance"},
        },
    )
    return True


def _reconcile_evidence_monitor(tenant, job):
    """Persist and deliver a deduplicated assurance/gap state transition."""
    reasons = []
    if job.get("status") == "failed":
        reasons.append(str(job.get("failure_reason", "assurance_job_failed")))
    else:
        if int(job.get("record_count", 0)) == 0:
            reasons.append("no_retained_evidence")
        baseline_count = job.get("baseline_record_count")
        if baseline_count is not None:
            baseline_count = _discovery_integer(baseline_count, "baselineRecordCount", minimum=0)
            if int(job.get("record_count", 0)) < baseline_count:
                reasons.append("retained_record_count_decreased")
        if int(job.get("at_risk_count", 0)) > 0:
            reasons.append("integrity_or_retention_gap")
        if int(job.get("delete_marker_count", 0)) > 0:
            reasons.append("delete_markers_observed")
    status = (
        "healthy" if not reasons else "critical" if job.get("status") == "failed" else "attention"
    )
    now = int(time.time())
    key = _item_key(tenant, "EVIDENCE_MONITOR", "current")
    existing = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    state_hash = _canonical_sha256({"status": status, "reasonCodes": reasons})
    changed = not existing or not secrets.compare_digest(
        str(existing.get("state_hash", "")), state_hash
    )
    previous_delivery = str(existing.get("delivery_status", "")) if existing else ""
    should_deliver = bool(reasons) and (changed or previous_delivery == "pending")
    delivery_status = (
        "pending"
        if changed and reasons
        else previous_delivery
        if reasons and previous_delivery in {"pending", "delivered"}
        else "not_required"
    )
    monitor = {
        **key,
        "tenant_id": tenant,
        "status": status,
        "reason_codes": reasons,
        "state_hash": state_hash,
        "job_id": job["id"],
        "checked_at": now,
        "delivery_status": delivery_status,
        "revision": int(existing.get("revision", 0)) + 1 if existing else 1,
    }
    if existing and existing.get("delivered_at") and delivery_status == "delivered":
        monitor["delivered_at"] = existing["delivered_at"]
    if should_deliver:
        try:
            if _publish_evidence_monitor_alert(tenant, monitor):
                monitor["delivery_status"] = "delivered"
                monitor["delivered_at"] = now
        except Exception:
            # The monitor remains visible and pending. A later scheduled cycle
            # retries without treating a delivery outage as healthy evidence.
            monitor["delivery_status"] = "pending"
    arguments = {"Item": monitor}
    if existing:
        arguments.update(
            {
                "ConditionExpression": "revision = :revision",
                "ExpressionAttributeValues": {":revision": int(existing.get("revision", 0))},
            }
        )
    else:
        arguments["ConditionExpression"] = "attribute_not_exists(pk)"
    TABLE.put_item(**arguments)
    if changed:
        _audit(
            tenant,
            "evidence_monitor_state_changed",
            "system:evidence-assurance",
            {"status": status, "reason_codes": reasons, "job_id": job["id"]},
        )
    return monitor


def _process_evidence_job(tenant, job_id, expected_revision):
    """Process one revision-bound page and enqueue only the next exact revision."""
    job = _evidence_job_record(tenant, job_id)
    revision = int(job.get("revision", 0))
    if revision != int(expected_revision):
        # Repair the same durable-outbox edge as retention work: the page may
        # be committed while its next FIFO send fails. Retrying the prior
        # message dispatches only the already-recorded next revision.
        if job.get("status") == "queued" and revision == int(expected_revision) + 1:
            _enqueue_evidence_job(tenant, job_id, revision)
            return {"status": "queue_recovered"}
        return {"status": "stale_message"}
    if job.get("status") not in {"queued", "running"}:
        return {"status": str(job.get("status"))}
    page_number = int(job.get("page_count", 0)) + 1
    if page_number > _EVIDENCE_ASYNC_MAX_PAGES:
        raise RuntimeError("evidence assurance job exceeds its maximum page bound")
    arguments = {
        "Bucket": os.environ["AUDIT_BUCKET"],
        "Prefix": f"tenant={tenant}/",
        "MaxKeys": _EVIDENCE_ASYNC_PAGE_SIZE,
    }
    if job.get("next_key_marker"):
        arguments["KeyMarker"] = job["next_key_marker"]
    if job.get("next_version_id_marker"):
        arguments["VersionIdMarker"] = job["next_version_id_marker"]
    response = S3.list_object_versions(**arguments)
    cutoff = datetime.fromtimestamp(int(job["snapshot_cutoff"]), UTC)
    versions = []
    for version in response.get("Versions", []):
        modified = version.get("LastModified")
        if not hasattr(modified, "timestamp"):
            raise RuntimeError("audit inventory version timestamp is malformed")
        if modified <= cutoff:
            versions.append(version)
    delete_markers = 0
    for marker in response.get("DeleteMarkers", []):
        modified = marker.get("LastModified")
        if not hasattr(modified, "timestamp"):
            raise RuntimeError("audit delete-marker timestamp is malformed")
        if modified <= cutoff:
            delete_markers += 1
    records = [_evidence_record(tenant, version) for version in versions]
    records.sort(key=lambda item: (item["lastModified"], item["key"], item["versionId"]))
    page_hash = _write_evidence_report_page(
        tenant, job_id, page_number, job["snapshot_cutoff"], records
    )
    now = datetime.now(UTC)
    at_risk = sum(1 for record in records if _evidence_record_at_risk(record, now=now))
    updated = {
        **job,
        "status": "queued" if response.get("IsTruncated") is True else "running",
        "revision": int(expected_revision) + 1,
        "started_at": job.get("started_at") or int(time.time()),
        "updated_at": int(time.time()),
        "record_count": int(job.get("record_count", 0)) + len(records),
        "verified_count": int(job.get("verified_count", 0)) + len(records) - at_risk,
        "at_risk_count": int(job.get("at_risk_count", 0)) + at_risk,
        "legal_hold_count": int(job.get("legal_hold_count", 0))
        + sum(1 for record in records if record["legalHold"]),
        "delete_marker_count": int(job.get("delete_marker_count", 0)) + delete_markers,
        "page_count": page_number,
        "chain_sha256": hashlib.sha256(
            f"{job.get('chain_sha256', _EVIDENCE_INITIAL_CHAIN_HASH)}:{page_hash}".encode()
        ).hexdigest(),
    }
    truncated = response.get("IsTruncated") is True
    if truncated:
        next_key = response.get("NextKeyMarker")
        next_version = response.get("NextVersionIdMarker")
        if not isinstance(next_key, str):
            raise RuntimeError("audit inventory pagination marker is missing")
        updated["next_key_marker"] = next_key
        if isinstance(next_version, str):
            updated["next_version_id_marker"] = next_version
        else:
            updated.pop("next_version_id_marker", None)
    else:
        updated.pop("next_key_marker", None)
        updated.pop("next_version_id_marker", None)
        updated["status"] = "completed"
        updated["completed_at"] = int(time.time())
        updated["retention_policy"] = _evidence_policy(tenant)
        updated["content_sha256"] = _write_evidence_report_index(updated)
    TABLE.put_item(
        Item=updated,
        ConditionExpression="revision = :revision",
        ExpressionAttributeValues={":revision": int(expected_revision)},
    )
    if truncated:
        _enqueue_evidence_job(tenant, job_id, updated["revision"])
    else:
        _audit(
            tenant,
            "evidence_assurance_job_completed",
            "system:evidence-assurance",
            {
                "job_id": job_id,
                "record_count": updated["record_count"],
                "at_risk_count": updated["at_risk_count"],
                "delete_marker_count": updated["delete_marker_count"],
                "content_hash": updated["content_sha256"],
            },
        )
        _reconcile_evidence_monitor(tenant, updated)
    return _evidence_job_view(updated)


def _evidence_failure_reason(error):
    """Map provider errors to a small non-sensitive operator reason code."""
    code = getattr(error, "response", {}).get("Error", {}).get("Code")
    if code in {"AccessDenied", "UnauthorizedOperation"}:
        return "evidence_provider_access_denied"
    if code in {"SlowDown", "ServiceUnavailable", "InternalError", "RequestTimeout"}:
        return "evidence_provider_unavailable"
    return "evidence_assurance_job_failed"


def _fail_evidence_job(tenant, job_id, expected_revision, reason):
    """Persist a terminal fail-closed job and reconcile its durable alert."""
    job = _evidence_job_record(tenant, job_id)
    if int(job.get("revision", 0)) != int(expected_revision):
        return job
    if job.get("status") not in {"queued", "running"}:
        return job
    failed = {
        **job,
        "status": "failed",
        "revision": int(expected_revision) + 1,
        "failure_reason": reason,
        "updated_at": int(time.time()),
        "completed_at": int(time.time()),
    }
    TABLE.put_item(
        Item=failed,
        ConditionExpression="revision = :revision",
        ExpressionAttributeValues={":revision": int(expected_revision)},
    )
    _audit(
        tenant,
        "evidence_assurance_job_failed",
        "system:evidence-assurance",
        {"job_id": job_id, "reason_code": reason},
    )
    _reconcile_evidence_monitor(tenant, failed)
    return failed


def process_evidence_queue_event(event):
    """Process one Lambda/SQS event with bounded retry and no browser authority.

    The SQS event-source mapping is the invocation authority. Tenant and job
    identifiers in the message are lookup keys only; the worker reloads the
    exact server-owned job and compares its optimistic revision before every
    S3 or DynamoDB mutation.
    """
    records = event.get("Records") if isinstance(event, dict) else None
    if not isinstance(records, list) or len(records) != 1:
        raise ValueError("evidence worker requires exactly one SQS record")
    record = records[0]
    if record.get("eventSource") not in {"aws:sqs", None}:
        raise ValueError("evidence worker event source is invalid")
    try:
        body = json.loads(record.get("body", ""))
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("evidence worker message is invalid") from error
    if not isinstance(body, dict) or set(body) != {
        "schemaVersion",
        "tenantId",
        "jobId",
        "expectedRevision",
    }:
        raise ValueError("evidence worker message schema is invalid")
    if body.get("schemaVersion") != 1:
        raise ValueError("evidence worker schema version is unsupported")
    tenant = _bounded_identifier(body.get("tenantId"), "tenantId")
    job_id = _bounded_identifier(body.get("jobId"), "jobId")
    expected = _discovery_integer(body.get("expectedRevision"), "expectedRevision", minimum=1)
    receive_count = int(record.get("attributes", {}).get("ApproximateReceiveCount", "1"))
    try:
        return _process_evidence_job(tenant, job_id, expected)
    except Exception as error:
        if receive_count < 3:
            raise
        return _evidence_job_view(
            _fail_evidence_job(tenant, job_id, expected, _evidence_failure_reason(error))
        )


def _evidence_job_page(tenant, job_id, page_number):
    """Load and independently verify one completed derived export page."""
    job = _evidence_job_record(tenant, job_id)
    if job.get("status") != "completed":
        raise PolicyConflict("evidence assurance job is not complete")
    if not isinstance(page_number, str) or not page_number.isdigit():
        raise ValueError("pageNumber is invalid")
    page = _discovery_integer(
        int(page_number), "pageNumber", minimum=1, maximum=int(job.get("page_count", 0))
    )
    response = S3.get_object(
        Bucket=os.environ["EVIDENCE_REPORT_BUCKET"],
        Key=_evidence_report_page_key(tenant, job_id, page),
    )
    body = _evidence_body_bytes(response)
    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise RuntimeError("evidence report page is malformed") from error
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "tenantId",
        "jobId",
        "pageNumber",
        "snapshotCutoff",
        "records",
        "contentSha256",
    }:
        raise RuntimeError("evidence report page schema is invalid")
    supplied = value.pop("contentSha256")
    if (
        value.get("schemaVersion") != 1
        or value.get("tenantId") != tenant
        or value.get("jobId") != job_id
        or value.get("pageNumber") != page
        or not isinstance(supplied, str)
        or not secrets.compare_digest(supplied, _canonical_sha256(value))
    ):
        raise RuntimeError("evidence report page integrity verification failed")
    return {**value, "contentSha256": supplied}


def _regional_transition_job_reconciliation(
    mode,
    activation_evidence_ref,
    direction,
    target_region,
    transition_id,
    authority_sha256,
):
    """Rebuild target-Region delivery under exact transition authority.

    SQS is deliberately never inspected or copied. A check can run in standby,
    while apply requires two independent activation controls and still relies
    on revision-bound FIFO messages plus DynamoDB conditional writes.
    """
    if mode not in {"check", "apply"}:
        raise ValueError("regional transition reconciliation mode is invalid")
    evidence_ref = _bounded_text(activation_evidence_ref, "activationEvidenceRef", maximum=512)
    if len(evidence_ref) < 8:
        raise ValueError("activationEvidenceRef must be at least eight characters")
    cell_role = os.environ.get("REGIONAL_CELL_ROLE")
    expected_role = {"failover": "recovery", "failback": "primary"}.get(direction)
    if (
        expected_role is None
        or cell_role != expected_role
        or target_region != os.environ.get("AWS_REGION")
        or not isinstance(transition_id, str)
        or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            transition_id,
            re.IGNORECASE,
        )
        or not isinstance(authority_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", authority_sha256)
    ):
        raise PermissionError("regional transition authority does not match this cell")
    if mode == "apply" and os.environ.get("REGIONAL_JOB_RECONCILIATION_ENABLED") != "true":
        raise PermissionError("regional transition job reconciliation is not activated")

    registrations = []
    for shard in range(_EVIDENCE_ASSURANCE_SHARDS):
        result = TABLE.query(
            IndexName=_EVIDENCE_ASSURANCE_INDEX,
            KeyConditionExpression=Key("evidence_assurance_pk").eq(
                f"EVIDENCE_ASSURANCE#{shard:02d}"
            ),
            Limit=_ENDPOINT_DETECTION_TENANT_LIMIT + 1,
        )
        if result.get("LastEvaluatedKey"):
            raise RuntimeError("regional recovery tenant shard exceeds its safe bound")
        registrations.extend(result.get("Items", []))
        if len(registrations) > _ENDPOINT_DETECTION_TENANT_LIMIT:
            raise RuntimeError("regional recovery tenant inventory exceeds its safe bound")

    now = int(time.time())
    planned = dispatched = failed_stale = deferred = conflicts = 0
    actions = []
    for registration in registrations:
        tenant = registration.get("evidence_assurance_sk")
        if not isinstance(tenant, str) or registration.get("pk") != f"TENANT#{tenant}":
            conflicts += 1
            continue
        assurance = [
            job
            for job in _list(tenant, "EVIDENCE_JOB", consistent_read=True)
            if job.get("status") in {"queued", "running"}
        ]
        retention = [
            job
            for job in _list(tenant, "EVIDENCE_RETENTION_JOB", consistent_read=True)
            if job.get("status") in {"settling", "queued", "running"}
        ]
        # More than one live job of either class is ambiguous server authority.
        # Do not choose a winner from timestamps during a recovery event.
        if len(assurance) > 1 or len(retention) > 1:
            conflicts += 1
            continue

        if assurance:
            job = assurance[0]
            revision = int(job.get("revision", 0))
            if revision < 1 or job.get("tenant_id") != tenant or not job.get("id"):
                conflicts += 1
            elif job.get("status") == "queued":
                planned += 1
                actions.append(("dispatch_assurance", tenant, job["id"], revision))
            elif now - int(job.get("updated_at", 0)) > _EVIDENCE_JOB_STALE_SECONDS:
                planned += 1
                actions.append(("fail_stale_assurance", tenant, job["id"], revision))
            else:
                deferred += 1

        if retention:
            job = retention[0]
            revision = int(job.get("revision", 0))
            policy = TABLE.get_item(
                Key=_item_key(tenant, "EVIDENCE_POLICY", "retention"), ConsistentRead=True
            ).get("Item")
            bound = bool(
                policy
                and policy.get("application_status") == "applying"
                and policy.get("application_job_id") == job.get("id")
                and int(policy.get("revision", 0)) == int(job.get("policy_revision", -1))
            )
            if revision < 1 or job.get("tenant_id") != tenant or not job.get("id") or not bound:
                conflicts += 1
            else:
                due = job.get("status") != "settling" or now >= int(job.get("cutover_at", 0))
                stale = (
                    job.get("status") == "running"
                    and now - int(job.get("updated_at", 0)) > _EVIDENCE_RETENTION_JOB_STALE_SECONDS
                )
                if due or stale:
                    planned += 1
                    actions.append(("dispatch_retention", tenant, job["id"], revision))
                else:
                    deferred += 1

    if conflicts:
        raise RuntimeError("regional recovery job authority contains conflicts")
    if mode == "apply":
        # Complete the read-only validation pass before the first side effect.
        # Workers still re-read and condition on revision if state changes
        # concurrently after this point.
        for action, tenant, job_id, revision in actions:
            if action == "dispatch_assurance":
                _enqueue_evidence_job(tenant, job_id, revision)
                dispatched += 1
            elif action == "dispatch_retention":
                _enqueue_retention_job(tenant, job_id, revision)
                dispatched += 1
            else:
                _fail_evidence_job(
                    tenant,
                    job_id,
                    revision,
                    "regional_recovery_stale_assurance_job",
                )
                failed_stale += 1
    return {
        "mode": mode,
        "activationEvidenceRefSha256": hashlib.sha256(evidence_ref.encode()).hexdigest(),
        "transitionAuthoritySha256": authority_sha256,
        "processedTenants": len(registrations),
        "plannedActions": planned,
        "dispatchedJobs": dispatched,
        "failedStaleJobs": failed_stale,
        "deferredJobs": deferred,
        "queueSource": "authoritative-dynamodb-job-records",
    }


def _evidence_schedule_cycle():
    """Start due tenant scans and fail stale jobs on the internal schedule."""
    tenants = []
    for shard in range(_EVIDENCE_ASSURANCE_SHARDS):
        result = TABLE.query(
            IndexName=_EVIDENCE_ASSURANCE_INDEX,
            KeyConditionExpression=Key("evidence_assurance_pk").eq(
                f"EVIDENCE_ASSURANCE#{shard:02d}"
            ),
            Limit=250,
        )
        if result.get("LastEvaluatedKey"):
            raise RuntimeError("evidence assurance tenant shard exceeds its safe bound")
        tenants.extend(result.get("Items", []))
        if len(tenants) > _ENDPOINT_DETECTION_TENANT_LIMIT:
            raise RuntimeError("evidence assurance tenant inventory exceeds its safe bound")
    now = int(time.time())
    started = 0
    active = 0
    failed = 0
    for registration in tenants:
        tenant = registration.get("evidence_assurance_sk")
        if not isinstance(tenant, str) or registration.get("pk") != f"TENANT#{tenant}":
            failed += 1
            continue
        try:
            running = _latest_evidence_job(tenant, statuses={"queued", "running"})
            if (
                running
                and running.get("status") == "queued"
                and now - int(running.get("updated_at", 0)) > _EVIDENCE_QUEUE_RECOVERY_SECONDS
            ):
                _enqueue_evidence_job(tenant, running["id"], int(running["revision"]))
                active += 1
                continue
            if running and now - int(running.get("updated_at", 0)) > _EVIDENCE_JOB_STALE_SECONDS:
                _fail_evidence_job(
                    tenant,
                    running["id"],
                    int(running["revision"]),
                    "evidence_assurance_job_stale",
                )
                running = None
            if running:
                active += 1
                continue
            latest = _latest_evidence_job(tenant, statuses={"completed"})
            if (
                latest
                and now - int(latest.get("completed_at", 0)) < _EVIDENCE_JOB_FRESHNESS_SECONDS
            ):
                continue
            slot = now // _EVIDENCE_JOB_FRESHNESS_SECONDS
            _create_evidence_job(
                tenant,
                f"schedule-{slot}",
                "system:evidence-assurance",
                "Scheduled tenant-wide evidence assurance and gap detection.",
                source="schedule",
            )
            started += 1
        except Exception:
            failed += 1
    if failed:
        raise RuntimeError("one or more tenant evidence assurance schedules failed")
    return {"processedTenants": len(tenants), "startedJobs": started, "activeJobs": active}


def _retention_job_record(tenant, job_id):
    """Load one exact tenant-bound asynchronous retention job."""
    item = TABLE.get_item(
        Key=_item_key(tenant, "EVIDENCE_RETENTION_JOB", job_id), ConsistentRead=True
    ).get("Item")
    if not item:
        raise LookupError("evidence retention job not found")
    if item.get("tenant_id") != tenant or item.get("id") != job_id:
        raise RuntimeError("evidence retention job identity is malformed")
    return item


def _retention_job_view(item):
    """Project retention progress without exposing rationale or S3 cursors."""
    return {
        "id": item.get("id"),
        "mode": "retention_extension",
        "status": item.get("status"),
        "revision": int(item.get("revision", 0)),
        "policyRevision": int(item.get("policy_revision", 0)),
        "previousRetentionDays": int(item.get("previous_retention_days", 0)),
        "targetRetentionDays": int(item.get("target_retention_days", 0)),
        "cutoverAt": int(item.get("cutover_at", 0)),
        "retainUntil": int(item.get("retain_until", 0)),
        "createdAt": int(item.get("created_at", 0)),
        "startedAt": item.get("started_at"),
        "updatedAt": int(item.get("updated_at", 0)),
        "completedAt": item.get("completed_at"),
        "recordCount": int(item.get("record_count", 0)),
        "extendedCount": int(item.get("extended_count", 0)),
        "alreadyCompliantCount": int(item.get("already_compliant_count", 0)),
        "deleteMarkerCount": int(item.get("delete_marker_count", 0)),
        "pageCount": int(item.get("page_count", 0)),
        "failureReason": item.get("failure_reason"),
        "alertDelivered": item.get("alert_delivery_status") == "delivered",
    }


def _retention_jobs(tenant):
    """Return the 50 newest tenant retention jobs in deterministic order."""
    items = _list(tenant, "EVIDENCE_RETENTION_JOB", consistent_read=True)
    items.sort(
        key=lambda item: (int(item.get("created_at", 0)), str(item.get("id", ""))),
        reverse=True,
    )
    return [_retention_job_view(item) for item in items[:50]]


def _latest_retention_job(tenant):
    """Return the newest retention job when one exists."""
    items = _list(tenant, "EVIDENCE_RETENTION_JOB", consistent_read=True)
    return max(
        items,
        key=lambda item: (int(item.get("created_at", 0)), str(item.get("id", ""))),
        default=None,
    )


def _enqueue_retention_job(tenant, job_id, revision):
    """Send one tenant/job/revision-bound retention work item to its FIFO queue."""
    queue_url = os.environ.get("EVIDENCE_RETENTION_QUEUE_URL", "")
    if not queue_url:
        raise RuntimeError("asynchronous evidence retention queue is not configured")
    body = {
        "schemaVersion": 1,
        "tenantId": tenant,
        "jobId": job_id,
        "expectedRevision": int(revision),
    }
    SQS.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps(body, sort_keys=True, separators=(",", ":")),
        MessageGroupId=job_id,
        MessageDeduplicationId=f"retention:{job_id}:{int(revision)}",
    )


def _transact_retention_records(operations):
    """Atomically change retention job and policy state or expose a conflict."""
    try:
        DYNAMODB.transact_write_items(TransactItems=operations)
    except Exception as error:
        code = getattr(error, "response", {}).get("Error", {}).get("Code")
        if code in {"ConditionalCheckFailedException", "TransactionCanceledException"}:
            raise PolicyConflict("evidence retention state changed concurrently") from error
        raise


def _create_retention_job(tenant, body, actor):
    """Commit an increase-only future policy and a durable backfill job atomically."""
    if not isinstance(body, dict) or set(body) != {
        "requestId",
        "expectedRevision",
        "retentionDays",
        "rationale",
    }:
        raise ValueError("evidence retention job request has an invalid schema")
    request_id = body.get("requestId")
    if not isinstance(request_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", request_id
    ):
        raise ValueError("requestId is invalid")
    expected = _discovery_integer(body.get("expectedRevision"), "expectedRevision", minimum=0)
    days = _discovery_integer(
        body.get("retentionDays"),
        "retentionDays",
        minimum=_EVIDENCE_RETENTION_MIN_DAYS,
        maximum=_EVIDENCE_RETENTION_MAX_DAYS,
    )
    rationale = _case_reason(body.get("rationale"))
    request_hash = _canonical_sha256(
        {
            "requestId": request_id,
            "expectedRevision": expected,
            "retentionDays": days,
            "rationale": rationale,
        }
    )
    job_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"aai:evidence-retention:{tenant}:{request_id}"))
    key = _item_key(tenant, "EVIDENCE_RETENTION_JOB", job_id)
    existing = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    if existing:
        if not secrets.compare_digest(str(existing.get("request_hash", "")), request_hash):
            raise PolicyConflict("retention requestId was already used for different input")
        return _retention_job_view(existing)
    current = _evidence_policy(tenant)
    if current["revision"] != expected:
        raise PolicyConflict("evidence retention policy changed before update")
    if current["applicationStatus"] == "applying":
        raise PolicyConflict("another evidence retention extension is already applying")
    if days < current["retentionDays"]:
        raise ValueError("evidence retention cannot be shortened through the control plane")
    if days == current["retentionDays"] and current["applicationStatus"] != "failed":
        raise ValueError("evidence retention extension must increase the current period")
    now = int(time.time())
    policy_revision = expected + 1
    rationale_hash = hashlib.sha256(rationale.encode()).hexdigest()
    job = {
        **key,
        "tenant_id": tenant,
        "id": job_id,
        "request_id": request_id,
        "request_hash": request_hash,
        "status": "settling",
        "revision": 1,
        "policy_revision": policy_revision,
        "previous_retention_days": current["retentionDays"],
        "target_retention_days": days,
        # Future writes use the new policy immediately. Waiting longer than the
        # longest evidence-writing Lambda timeout lets old-policy in-flight
        # writes finish before the bounded tenant scan begins.
        "cutover_at": now + _EVIDENCE_RETENTION_CUTOVER_SECONDS,
        "retain_until": now + (days * 24 * 60 * 60),
        "created_at": now,
        "updated_at": now,
        "created_by": actor,
        "rationale_hash": rationale_hash,
        "record_count": 0,
        "extended_count": 0,
        "already_compliant_count": 0,
        "delete_marker_count": 0,
        "page_count": 0,
        "ttl": now + _EVIDENCE_RETENTION_JOB_RETENTION_SECONDS,
    }
    policy = {
        **_item_key(tenant, "EVIDENCE_POLICY", "retention"),
        "tenant_id": tenant,
        "retention_days": days,
        "revision": policy_revision,
        "updated_at": now,
        "updated_by": actor,
        "rationale_hash": rationale_hash,
        "application_status": "applying",
        "application_job_id": job_id,
        "application_started_at": now,
    }
    policy_condition = (
        "attribute_not_exists(pk)"
        if expected == 0
        else (
            "revision = :expected AND "
            "(attribute_not_exists(application_status) OR application_status <> :applying)"
        )
    )
    policy_values = (
        None
        if expected == 0
        else {
            ":expected": expected,
            ":applying": "applying",
        }
    )
    _transact_retention_records(
        [
            _transaction_put(job, condition="attribute_not_exists(pk)"),
            _transaction_put(policy, condition=policy_condition, values=policy_values),
        ]
    )
    _audit(
        tenant,
        "evidence_retention_extension_started",
        actor,
        {
            "job_id": job_id,
            "retention_days": days,
            "policy_revision": policy_revision,
            "cutover_at": job["cutover_at"],
            "rationale_hash": rationale_hash,
        },
    )
    return _retention_job_view(job)


def _evidence_retention_schedule_cycle():
    """Dispatch due or recoverable retention jobs through the tenant schedule index."""
    registrations = []
    for shard in range(_EVIDENCE_ASSURANCE_SHARDS):
        result = TABLE.query(
            IndexName=_EVIDENCE_ASSURANCE_INDEX,
            KeyConditionExpression=Key("evidence_assurance_pk").eq(
                f"EVIDENCE_ASSURANCE#{shard:02d}"
            ),
            Limit=_ENDPOINT_DETECTION_TENANT_LIMIT + 1,
        )
        if result.get("LastEvaluatedKey"):
            raise RuntimeError("evidence retention tenant shard exceeds its safe bound")
        registrations.extend(result.get("Items", []))
        if len(registrations) > _ENDPOINT_DETECTION_TENANT_LIMIT:
            raise RuntimeError("evidence retention tenant inventory exceeds its safe bound")
    now = int(time.time())
    dispatched = active = failed = 0
    for registration in registrations:
        tenant = registration.get("evidence_assurance_sk")
        if not isinstance(tenant, str) or registration.get("pk") != f"TENANT#{tenant}":
            failed += 1
            continue
        try:
            policy = _evidence_policy(tenant)
            if policy["applicationStatus"] != "applying":
                continue
            job = _retention_job_record(tenant, policy["applicationJobId"])
            status = job.get("status")
            due = status == "settling" and now >= int(job.get("cutover_at", 0))
            recoverable = (
                status == "queued"
                and now - int(job.get("updated_at", 0)) > _EVIDENCE_QUEUE_RECOVERY_SECONDS
            ) or (
                status == "running"
                and now - int(job.get("updated_at", 0)) > _EVIDENCE_RETENTION_JOB_STALE_SECONDS
            )
            if due or recoverable:
                _enqueue_retention_job(tenant, job["id"], int(job["revision"]))
                dispatched += 1
            elif status in {"settling", "running"}:
                active += 1
        except Exception:
            failed += 1
    if failed:
        raise RuntimeError("one or more tenant evidence retention schedules failed")
    return {
        "processedTenants": len(registrations),
        "dispatchedJobs": dispatched,
        "activeJobs": active,
    }


def _retention_version_identity(tenant, version):
    """Validate and return one exact tenant object identity from S3 inventory."""
    key = version.get("Key")
    version_id = version.get("VersionId")
    if (
        not isinstance(key, str)
        or not key.startswith(f"tenant={tenant}/")
        or not isinstance(version_id, str)
        or not version_id
    ):
        raise RuntimeError("retention inventory returned an invalid tenant object identity")
    return key, version_id


def _complete_retention_job(tenant, job, updated):
    """Atomically publish a completed backfill and its applied policy posture."""
    policy_item = TABLE.get_item(
        Key=_item_key(tenant, "EVIDENCE_POLICY", "retention"), ConsistentRead=True
    ).get("Item")
    if not policy_item:
        raise RuntimeError("evidence retention policy disappeared during application")
    now = int(time.time())
    completed = {
        **updated,
        "status": "completed",
        "completed_at": now,
        "updated_at": now,
    }
    applied_policy = {
        **policy_item,
        "application_status": "applied",
        "applied_at": now,
        "affected_record_count": int(completed["record_count"]),
    }
    applied_policy.pop("failure_reason", None)
    _transact_retention_records(
        [
            _transaction_put(
                completed,
                condition="revision = :revision",
                values={":revision": int(job["revision"])},
            ),
            _transaction_put(
                applied_policy,
                condition=(
                    "revision = :policy_revision AND application_job_id = :job "
                    "AND application_status = :applying"
                ),
                values={
                    ":policy_revision": int(job["policy_revision"]),
                    ":job": job["id"],
                    ":applying": "applying",
                },
            ),
        ]
    )
    _audit(
        tenant,
        "evidence_retention_extension_completed",
        "system:evidence-retention",
        {
            "job_id": job["id"],
            "retention_days": int(job["target_retention_days"]),
            "record_count": int(completed["record_count"]),
            "extended_count": int(completed["extended_count"]),
            "already_compliant_count": int(completed["already_compliant_count"]),
            "policy_revision": int(job["policy_revision"]),
        },
    )
    return completed


def _process_retention_job(tenant, job_id, expected_revision):
    """Extend one bounded inventory page and enqueue only the next exact revision."""
    job = _retention_job_record(tenant, job_id)
    revision = int(job.get("revision", 0))
    if revision != int(expected_revision):
        # A page commit can succeed immediately before its next queue send
        # fails. Retrying the previous message repairs that outbox gap without
        # repeating the already committed S3 page.
        if job.get("status") == "queued" and revision == int(expected_revision) + 1:
            _enqueue_retention_job(tenant, job_id, revision)
            return {"status": "queue_recovered"}
        return {"status": "stale_message"}
    if job.get("status") == "settling" and int(time.time()) < int(job.get("cutover_at", 0)):
        return _retention_job_view(job)
    if job.get("status") not in {"settling", "queued", "running"}:
        return _retention_job_view(job)
    page_number = int(job.get("page_count", 0)) + 1
    if page_number > _EVIDENCE_ASYNC_MAX_PAGES:
        raise RuntimeError("evidence retention job exceeds its maximum page bound")
    arguments = {
        "Bucket": os.environ["AUDIT_BUCKET"],
        "Prefix": f"tenant={tenant}/",
        "MaxKeys": _EVIDENCE_ASYNC_PAGE_SIZE,
    }
    if job.get("next_key_marker"):
        arguments["KeyMarker"] = job["next_key_marker"]
    if job.get("next_version_id_marker"):
        arguments["VersionIdMarker"] = job["next_version_id_marker"]
    response = S3.list_object_versions(**arguments)
    cutoff = datetime.fromtimestamp(int(job["cutover_at"]), UTC)
    target = datetime.fromtimestamp(int(job["retain_until"]), UTC)
    examined = extended = compliant = 0
    for version in response.get("Versions", []):
        modified = version.get("LastModified")
        if not hasattr(modified, "timestamp"):
            raise RuntimeError("retention inventory version timestamp is malformed")
        if modified > cutoff:
            continue
        key, version_id = _retention_version_identity(tenant, version)
        retention = _evidence_object_lock_state(
            S3.get_object_retention,
            key=key,
            version_id=version_id,
            field="Retention",
        )
        retain_until = retention.get("RetainUntilDate")
        examined += 1
        if (
            retention.get("Mode") == "COMPLIANCE"
            and hasattr(retain_until, "timestamp")
            and retain_until >= target
        ):
            compliant += 1
            continue
        S3.put_object_retention(
            Bucket=os.environ["AUDIT_BUCKET"],
            Key=key,
            VersionId=version_id,
            Retention={"Mode": "COMPLIANCE", "RetainUntilDate": target},
        )
        extended += 1
    delete_markers = 0
    for marker in response.get("DeleteMarkers", []):
        modified = marker.get("LastModified")
        if not hasattr(modified, "timestamp"):
            raise RuntimeError("retention delete-marker timestamp is malformed")
        if modified <= cutoff:
            delete_markers += 1
    updated = {
        **job,
        "status": "queued",
        "revision": revision + 1,
        "started_at": job.get("started_at") or int(time.time()),
        "updated_at": int(time.time()),
        "record_count": int(job.get("record_count", 0)) + examined,
        "extended_count": int(job.get("extended_count", 0)) + extended,
        "already_compliant_count": int(job.get("already_compliant_count", 0)) + compliant,
        "delete_marker_count": int(job.get("delete_marker_count", 0)) + delete_markers,
        "page_count": page_number,
    }
    truncated = response.get("IsTruncated") is True
    if truncated:
        next_key = response.get("NextKeyMarker")
        next_version = response.get("NextVersionIdMarker")
        if not isinstance(next_key, str):
            raise RuntimeError("retention inventory pagination marker is missing")
        updated["next_key_marker"] = next_key
        if isinstance(next_version, str):
            updated["next_version_id_marker"] = next_version
        else:
            updated.pop("next_version_id_marker", None)
        TABLE.put_item(
            Item=updated,
            ConditionExpression="revision = :revision",
            ExpressionAttributeValues={":revision": revision},
        )
        _enqueue_retention_job(tenant, job_id, updated["revision"])
        return _retention_job_view(updated)
    updated.pop("next_key_marker", None)
    updated.pop("next_version_id_marker", None)
    return _retention_job_view(_complete_retention_job(tenant, job, updated))


def _retention_failure_reason(error):
    """Map provider failures to a bounded, non-sensitive retention reason."""
    code = getattr(error, "response", {}).get("Error", {}).get("Code")
    if code in {"AccessDenied", "UnauthorizedOperation"}:
        return "retention_provider_access_denied"
    if code in {"SlowDown", "ServiceUnavailable", "InternalError", "RequestTimeout"}:
        return "retention_provider_unavailable"
    return "retention_extension_failed"


def _fail_retention_job(tenant, job_id, expected_revision, reason):
    """Persist a terminal fail-closed job while retaining the increased future policy."""
    job = _retention_job_record(tenant, job_id)
    if int(job.get("revision", 0)) != int(expected_revision):
        return job
    if job.get("status") not in {"settling", "queued", "running"}:
        return job
    policy = TABLE.get_item(
        Key=_item_key(tenant, "EVIDENCE_POLICY", "retention"), ConsistentRead=True
    ).get("Item")
    if not policy:
        raise RuntimeError("evidence retention policy disappeared during failure handling")
    now = int(time.time())
    failed = {
        **job,
        "status": "failed",
        "revision": int(expected_revision) + 1,
        "failure_reason": reason,
        "updated_at": now,
        "completed_at": now,
        "alert_delivery_status": "pending",
    }
    failed_policy = {**policy, "application_status": "failed", "failure_reason": reason}
    _transact_retention_records(
        [
            _transaction_put(
                failed,
                condition="revision = :revision",
                values={":revision": int(expected_revision)},
            ),
            _transaction_put(
                failed_policy,
                condition=(
                    "revision = :policy_revision AND application_job_id = :job "
                    "AND application_status = :applying"
                ),
                values={
                    ":policy_revision": int(job["policy_revision"]),
                    ":job": job_id,
                    ":applying": "applying",
                },
            ),
        ]
    )
    try:
        SNS.publish(
            TopicArn=os.environ["SECURITY_ALERTS_TOPIC_ARN"],
            Subject="AAI evidence retention alert",
            Message=json.dumps(
                {
                    "schemaVersion": 1,
                    "tenantId": tenant,
                    "source": "evidence_retention",
                    "status": "failed",
                    "reasonCode": reason,
                    "jobId": job_id,
                    "observedAt": now,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            MessageAttributes={
                "tenantId": {"DataType": "String", "StringValue": tenant},
                "severity": {"DataType": "String", "StringValue": "critical"},
                "source": {"DataType": "String", "StringValue": "evidence_retention"},
            },
        )
        failed["alert_delivery_status"] = "delivered"
        failed["alert_delivered_at"] = now
        TABLE.put_item(
            Item=failed,
            ConditionExpression="revision = :revision",
            ExpressionAttributeValues={":revision": int(failed["revision"])},
        )
    except Exception:
        # The transaction already retained a visible pending receipt. A later
        # operator retry must never interpret delivery failure as success.
        failed["alert_delivery_status"] = "pending"
    _audit(
        tenant,
        "evidence_retention_extension_failed",
        "system:evidence-retention",
        {"job_id": job_id, "reason_code": reason, "policy_revision": job["policy_revision"]},
    )
    return failed


def process_retention_queue_event(event):
    """Process one dedicated retention SQS record with bounded terminal retry."""
    records = event.get("Records") if isinstance(event, dict) else None
    if not isinstance(records, list) or len(records) != 1:
        raise ValueError("retention worker requires exactly one SQS record")
    record = records[0]
    if record.get("eventSource") not in {"aws:sqs", None}:
        raise ValueError("retention worker event source is invalid")
    try:
        body = json.loads(record.get("body", ""))
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("retention worker message is invalid") from error
    if not isinstance(body, dict) or set(body) != {
        "schemaVersion",
        "tenantId",
        "jobId",
        "expectedRevision",
    }:
        raise ValueError("retention worker message schema is invalid")
    if body.get("schemaVersion") != 1:
        raise ValueError("retention worker schema version is unsupported")
    tenant = _bounded_identifier(body.get("tenantId"), "tenantId")
    job_id = _bounded_identifier(body.get("jobId"), "jobId")
    expected = _discovery_integer(body.get("expectedRevision"), "expectedRevision", minimum=1)
    receive_count = int(record.get("attributes", {}).get("ApproximateReceiveCount", "1"))
    try:
        return _process_retention_job(tenant, job_id, expected)
    except Exception as error:
        if receive_count < 3:
            raise
        return _retention_job_view(
            _fail_retention_job(tenant, job_id, expected, _retention_failure_reason(error))
        )


def _set_evidence_retention(tenant, body, actor):
    """Increase future and existing bounded tenant retention atomically enough to fail safe."""
    if not isinstance(body, dict) or set(body) != {
        "expectedRevision",
        "retentionDays",
        "rationale",
    }:
        raise ValueError("evidence retention request has an invalid schema")
    expected = _discovery_integer(body.get("expectedRevision"), "expectedRevision", minimum=0)
    days = _discovery_integer(
        body.get("retentionDays"),
        "retentionDays",
        minimum=_EVIDENCE_RETENTION_MIN_DAYS,
        maximum=_EVIDENCE_RETENTION_MAX_DAYS,
    )
    rationale = _case_reason(body.get("rationale"))
    current = _evidence_policy(tenant)
    if current["revision"] != expected:
        raise PolicyConflict("evidence retention policy changed before update")
    if days < current["retentionDays"]:
        raise ValueError("evidence retention cannot be shortened through the control plane")
    inventory = _evidence_inventory(tenant)
    if not inventory["complete"]:
        raise PolicyConflict(
            "existing evidence inventory is too large for synchronous retention update"
        )
    retain_until = datetime.now(UTC) + timedelta(days=days)
    # Extend retained versions before publishing the policy. A concurrent policy
    # conflict can leave evidence retained longer, which is the safe direction.
    for record in inventory["records"]:
        S3.put_object_retention(
            Bucket=os.environ["AUDIT_BUCKET"],
            Key=record["key"],
            VersionId=record["versionId"],
            Retention={"Mode": "COMPLIANCE", "RetainUntilDate": retain_until},
        )
    now = int(time.time())
    item = {
        **_item_key(tenant, "EVIDENCE_POLICY", "retention"),
        "tenant_id": tenant,
        "retention_days": days,
        "revision": expected + 1,
        "updated_at": now,
        "updated_by": actor,
        "rationale_hash": hashlib.sha256(rationale.encode()).hexdigest(),
    }
    condition = "attribute_not_exists(pk)" if expected == 0 else "revision = :revision"
    values = None if expected == 0 else {":revision": expected}
    try:
        kwargs = {"Item": item, "ConditionExpression": condition}
        if values:
            kwargs["ExpressionAttributeValues"] = values
        TABLE.put_item(**kwargs)
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("evidence retention policy changed before update") from error
        raise
    _audit(
        tenant,
        "evidence_retention_extended",
        actor,
        {
            "retention_days": days,
            "revision": expected + 1,
            "rationale_hash": item["rationale_hash"],
        },
    )
    return _evidence_policy(tenant)


def _set_evidence_legal_hold(tenant, body, actor):
    """Set or clear legal hold on one exact retained tenant object version."""
    if not isinstance(body, dict) or set(body) != {"key", "versionId", "active", "rationale"}:
        raise ValueError("evidence legal-hold request has an invalid schema")
    key = _bounded_text(body.get("key"), "key", 1_024)
    version_id = _bounded_text(body.get("versionId"), "versionId", 1_024)
    rationale = _case_reason(body.get("rationale"))
    active = body.get("active")
    if not isinstance(active, bool):
        raise ValueError("active must be a boolean")
    if not key.startswith(f"tenant={tenant}/"):
        raise PermissionError("evidence object is outside the authenticated tenant")
    S3.head_object(Bucket=os.environ["AUDIT_BUCKET"], Key=key, VersionId=version_id)
    S3.put_object_legal_hold(
        Bucket=os.environ["AUDIT_BUCKET"],
        Key=key,
        VersionId=version_id,
        LegalHold={"Status": "ON" if active else "OFF"},
    )
    rationale_hash = hashlib.sha256(rationale.encode()).hexdigest()
    _audit(
        tenant,
        "evidence_legal_hold_changed",
        actor,
        {
            "object_identity_hash": hashlib.sha256(f"{key}:{version_id}".encode()).hexdigest(),
            "active": active,
            "rationale_hash": rationale_hash,
        },
    )
    return {"key": key, "versionId": version_id, "active": active}


def _evidence_export(tenant, actor):
    """Return a complete, content-hashed manifest or refuse a partial export."""
    inventory = _evidence_inventory(tenant)
    if not inventory["complete"]:
        raise PolicyConflict("complete evidence export exceeds the synchronous export bound")
    if any(item["integrity"] == "mismatch" for item in inventory["records"]):
        raise RuntimeError("retained evidence integrity verification failed")
    generated_at = int(time.time())
    content = {
        "schemaVersion": 1,
        "tenantId": tenant,
        "generatedAt": generated_at,
        "recordCount": len(inventory["records"]),
        "deleteMarkerCount": inventory["deleteMarkerCount"],
        "retentionPolicy": _evidence_policy(tenant),
        "records": inventory["records"],
    }
    content_hash = hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    _audit(
        tenant,
        "evidence_manifest_exported",
        actor,
        {"record_count": content["recordCount"], "content_hash": content_hash},
    )
    return {**content, "contentSha256": content_hash}


def _audit(tenant, event_type, actor, payload):
    redacted = {
        "event_type": event_type,
        "actor": actor,
        "tenant_id": tenant,
        "occurred_at": int(time.time()),
        "payload": payload,
    }
    encoded = json.dumps(redacted, sort_keys=True).encode()
    digest = hashlib.sha256(encoded).hexdigest()
    redacted["payload_hash"] = digest
    key = (
        f"tenant={tenant}/year={time.gmtime().tm_year}/"
        f"month={time.gmtime().tm_mon:02d}/{int(time.time())}-{uuid.uuid4()}.json"
    )
    body = json.dumps(redacted, sort_keys=True, separators=(",", ":")).encode()
    retention_days = _evidence_policy(tenant)["retentionDays"]
    S3.put_object(
        Bucket=os.environ["AUDIT_BUCKET"],
        Key=key,
        Body=body,
        ContentType="application/json",
        Metadata={"content-sha256": hashlib.sha256(body).hexdigest(), "schema-version": "1"},
        ObjectLockMode="COMPLIANCE",
        ObjectLockRetainUntilDate=datetime.now(UTC) + timedelta(days=retention_days),
    )
    return {
        "event_type": event_type,
        "actor": actor,
        "tenant_id": tenant,
        "occurred_at": redacted["occurred_at"],
        "payload_hash": digest,
    }


def _positive_membership_revision(value):
    """Require an explicit positive group-membership revision."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("expectedMembershipRevision must be a positive integer")
    return value


def _group_membership_revision(group):
    """Return one valid stored revision, treating untouched legacy groups as v1."""
    if "membership_revision" not in group:
        return 1
    value = group.get("membership_revision")
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise PolicyConflict("group membership revision is malformed")
    if isinstance(value, Decimal) and value != value.to_integral_value():
        raise PolicyConflict("group membership revision is malformed")
    revision = int(value)
    if revision <= 0:
        raise PolicyConflict("group membership revision is malformed")
    return revision


def _group_agent_keys(group):
    """Return a bounded, unambiguous membership set or fail closed."""
    values = group.get("agent_keys")
    if not isinstance(values, list) or len(values) > _MAX_LIST_ITEMS:
        raise PolicyConflict("group membership record is malformed")
    keys = []
    for value in values:
        try:
            key = _bounded_identifier(value, "stored agent membership")
        except ValueError as error:
            raise PolicyConflict("group membership record is malformed") from error
        if ":" not in key:
            raise PolicyConflict("group membership record is malformed")
        keys.append(key)
    if len(keys) != len(set(keys)):
        raise PolicyConflict("group membership record is malformed")
    return sorted(keys)


def _group_membership_mode(group):
    """Return the stored membership authority mode or fail closed."""
    mode = group.get("membership_mode", "manual")
    if mode not in {"manual", "dynamic"}:
        raise PolicyConflict("group membership mode is malformed")
    return mode


def _dynamic_group_rule(raw_rule):
    """Normalize one closed, deterministic rule over trusted inventory fields."""
    if not isinstance(raw_rule, dict) or set(raw_rule) != {"match", "conditions"}:
        raise ValueError("dynamic group rule schema is invalid")
    if raw_rule.get("match") != "all":
        raise ValueError("dynamic group rules currently require match=all")
    raw_conditions = raw_rule.get("conditions")
    if (
        not isinstance(raw_conditions, list)
        or not 1 <= len(raw_conditions) <= _DYNAMIC_GROUP_CONDITION_LIMIT
    ):
        raise ValueError(
            f"dynamic group conditions must contain 1 to {_DYNAMIC_GROUP_CONDITION_LIMIT} entries"
        )
    conditions = []
    seen_fields = set()
    for raw_condition in raw_conditions:
        if not isinstance(raw_condition, dict) or set(raw_condition) != {
            "field",
            "operator",
            "values",
        }:
            raise ValueError("dynamic group condition schema is invalid")
        field = raw_condition.get("field")
        operator = raw_condition.get("operator")
        if field not in _DYNAMIC_GROUP_FIELDS:
            raise ValueError("dynamic group condition field is unsupported")
        if field in seen_fields:
            raise ValueError("dynamic group condition fields must be unique")
        if operator not in _DYNAMIC_GROUP_OPERATORS:
            raise ValueError("dynamic group condition operator is unsupported")
        raw_values = raw_condition.get("values")
        if (
            not isinstance(raw_values, list)
            or not 1 <= len(raw_values) <= _DYNAMIC_GROUP_VALUE_LIMIT
        ):
            raise ValueError(
                "dynamic group condition values must contain 1 to "
                f"{_DYNAMIC_GROUP_VALUE_LIMIT} entries"
            )
        values = sorted({_bounded_text(value, "dynamic group value", 128) for value in raw_values})
        if len(values) != len(raw_values):
            raise ValueError("dynamic group condition values must be unique")
        seen_fields.add(field)
        conditions.append({"field": field, "operator": operator, "values": values})
    return {"match": "all", "conditions": sorted(conditions, key=lambda item: item["field"])}


def _dynamic_group_request(body):
    """Validate one preview/apply request without accepting caller authority."""
    if not isinstance(body, dict) or set(body) != {
        "mode",
        "requestId",
        "expectedMembershipRevision",
        "rule",
        "reason",
    }:
        raise ValueError("dynamic group request schema is invalid")
    mode = body.get("mode")
    if mode not in {"preview", "apply"}:
        raise ValueError("mode must be preview or apply")
    request_id = _bounded_identifier(body.get("requestId"), "requestId")
    expected = _positive_membership_revision(body.get("expectedMembershipRevision"))
    reason = _bounded_text(body.get("reason"), "reason", 500)
    if len(reason) < 20:
        raise ValueError("reason must contain at least 20 characters")
    return mode, request_id, expected, _dynamic_group_rule(body.get("rule")), reason


def _dynamic_agent_attributes(agent, deployment):
    """Project only stable server-owned values used by dynamic membership."""
    ownership = agent.get("ownership")
    criticality = ownership.get("criticality") if isinstance(ownership, dict) else None
    return {
        "criticality": criticality,
        "deploymentId": deployment.get("id"),
        "environment": deployment.get("environment"),
        "host": agent.get("host"),
        "projectId": deployment.get("project_id"),
        "region": deployment.get("region"),
        "team": deployment.get("team"),
    }


def _dynamic_rule_matches(rule, attributes):
    """Evaluate a canonical conjunction; missing attributes never match."""
    for condition in rule["conditions"]:
        value = attributes.get(condition["field"])
        if not isinstance(value, str) or not value:
            return False
        included = value in condition["values"]
        if condition["operator"] == "equals_any" and not included:
            return False
        if condition["operator"] == "not_equals_any" and included:
            return False
    return True


def _dynamic_membership_evaluation(tenant, group, rule):
    """Derive desired membership and overlap conflicts from consistent state."""
    group_id = group.get("id")
    organization_id = group.get("organizationId") or group.get("organization_id")
    if not group_id or not organization_id:
        raise PolicyConflict("group organization ownership is missing")
    deployments = {
        item.get("id"): item for item in _list(tenant, "DEPLOYMENT", consistent_read=True)
    }
    all_groups = _list(tenant, "GROUP", consistent_read=True)
    memberships = {}
    for candidate_group in all_groups:
        candidate_id = candidate_group.get("id")
        if not candidate_id:
            raise PolicyConflict("group membership record is malformed")
        for key in _group_agent_keys(candidate_group):
            memberships.setdefault(key, set()).add(candidate_id)
    desired = []
    conflicts = []
    # Apply-time authority must be derived from strongly consistent inventory;
    # eventual reads could otherwise retain or grant policy access after an
    # administrator changed a trusted deployment or agent attribute.
    for agent in _all_agents(tenant, consistent_read=True):
        if _agent_lifecycle_state(agent) != "active":
            continue
        if (agent.get("organization_id") or agent.get("organizationId")) != organization_id:
            continue
        deployment_id = agent.get("deployment_id")
        agent_id = agent.get("id")
        deployment = deployments.get(deployment_id)
        if not deployment or not agent_id:
            raise PolicyConflict("dynamic group inventory lineage is incomplete")
        if (
            deployment.get("organization_id") or deployment.get("organizationId")
        ) != organization_id:
            raise PolicyConflict("dynamic group inventory lineage conflicts")
        if not _dynamic_rule_matches(rule, _dynamic_agent_attributes(agent, deployment)):
            continue
        key = f"{deployment_id}:{agent_id}"
        other_groups = sorted(memberships.get(key, set()) - {group_id})
        reference = {"deploymentId": deployment_id, "agentId": agent_id}
        if other_groups:
            conflicts.append({**reference, "groupIds": other_groups})
        else:
            desired.append(key)
    if len(desired) + len(conflicts) > _DYNAMIC_GROUP_MEMBER_LIMIT:
        raise PolicyConflict("dynamic group candidate set exceeds the supported limit")
    return sorted(desired), sorted(
        conflicts, key=lambda item: (item["deploymentId"], item["agentId"])
    )


def _agent_references(keys):
    """Convert validated internal membership keys into content-minimised references."""
    return [
        {"deploymentId": deployment_id, "agentId": agent_id}
        for deployment_id, agent_id in (key.split(":", 1) for key in sorted(keys))
    ]


def _configure_dynamic_group(tenant, group_id, body, actor):
    """Preview or atomically materialize one deterministic dynamic group rule."""
    mode, request_id, expected, rule, reason = _dynamic_group_request(body)
    canonical_rule = json.dumps(rule, sort_keys=True, separators=(",", ":"))
    rule_hash = hashlib.sha256(canonical_rule.encode()).hexdigest()
    semantic_request = {
        "actor": actor,
        "expectedMembershipRevision": expected,
        "groupId": group_id,
        "reason": reason,
        "rule": rule,
    }
    request_hash = hashlib.sha256(
        json.dumps(semantic_request, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    operation_key = _item_key(tenant, "DYNAMIC_GROUP_OPERATION", request_id)
    if mode == "apply":
        existing = TABLE.get_item(Key=operation_key, ConsistentRead=True).get("Item")
        if existing:
            if not secrets.compare_digest(str(existing.get("request_hash", "")), request_hash):
                raise PolicyConflict("requestId is already bound to a different dynamic rule")
            response = existing.get("response")
            if not isinstance(response, dict):
                raise PolicyConflict("stored dynamic group result is malformed")
            return {**response, "replayed": True}
    group = TABLE.get_item(Key=_item_key(tenant, "GROUP", group_id), ConsistentRead=True).get(
        "Item"
    )
    if not group:
        raise LookupError("group not found")
    current_revision = _group_membership_revision(group)
    if current_revision != expected:
        raise PolicyConflict("group membership revision is stale")
    current_keys = _group_agent_keys(group)
    desired_keys, conflicts = _dynamic_membership_evaluation(tenant, group, rule)
    additions = sorted(set(desired_keys) - set(current_keys))
    removals = sorted(set(current_keys) - set(desired_keys))
    unchanged = sorted(set(current_keys) & set(desired_keys))
    previous_rule_hash = str(group.get("dynamic_rule_hash", ""))
    changed = (
        _group_membership_mode(group) != "dynamic"
        or previous_rule_hash != rule_hash
        or current_keys != desired_keys
    )
    can_apply = not conflicts and changed
    next_revision = current_revision + 1 if mode == "apply" and changed else current_revision
    response = {
        "groupId": group_id,
        "requestId": request_id,
        "mode": mode,
        "membershipRevision": current_revision,
        "resultingMembershipRevision": next_revision,
        "rule": rule,
        "ruleHash": rule_hash,
        "counts": {
            "matched": len(desired_keys) + len(conflicts),
            "additions": len(additions),
            "removals": len(removals),
            "unchanged": len(unchanged),
            "conflicts": len(conflicts),
        },
        "additions": _agent_references(additions),
        "removals": _agent_references(removals),
        "unchanged": _agent_references(unchanged),
        "conflicts": conflicts,
        "canApply": mode == "preview" and can_apply,
        "replayed": False,
    }
    if mode == "preview":
        return response
    if conflicts:
        raise PolicyConflict("dynamic group rule overlaps another policy group")
    now = int(time.time())
    audit_payload = {
        "request_id": request_id,
        "request_hash": request_hash,
        "group_id": group_id,
        "rule_hash": rule_hash,
        "membership_revision_before": current_revision,
        "membership_revision_after": next_revision,
        "matched_count": len(desired_keys),
        "addition_count": len(additions),
        "removal_count": len(removals),
        "unchanged_count": len(unchanged),
        "reason": reason,
    }
    audit = _membership_audit_record(
        tenant, "dynamic_group_membership_applied", actor, audit_payload, now=now
    )
    operation = {
        **operation_key,
        "id": request_id,
        "group_id": group_id,
        "actor": actor,
        "request_hash": request_hash,
        "created_at": now,
        "response": response,
    }
    operations = []
    if changed:
        updated = {
            **group,
            "agent_keys": desired_keys,
            "membership_revision": next_revision,
            "membership_mode": "dynamic",
            "dynamic_rule": rule,
            "dynamic_rule_hash": rule_hash,
            "dynamic_last_evaluated_at": now,
            "dynamic_last_evaluated_by": actor,
        }
        if "membership_revision" in group:
            condition = "agent_keys = :agent_keys AND membership_revision = :membership_revision"
            values = {":agent_keys": current_keys, ":membership_revision": current_revision}
        else:
            condition = "agent_keys = :agent_keys AND attribute_not_exists(membership_revision)"
            values = {":agent_keys": current_keys}
        operations.append(_transaction_put(updated, condition=condition, values=values))
    operations.extend(
        [
            _transaction_put(operation, condition="attribute_not_exists(pk)"),
            _transaction_put(audit, condition="attribute_not_exists(pk)"),
        ]
    )
    _transact_group_membership(operations)
    _export_group_membership_audit(tenant, "dynamic_group_membership_applied", actor, audit_payload)
    return response


def _dynamic_reconciliation_status(tenant, group_id):
    """Return one content-minimised scheduled reconciliation status."""
    item = TABLE.get_item(
        Key=_item_key(tenant, "DYNAMIC_GROUP_STATUS", group_id), ConsistentRead=True
    ).get("Item")
    if not item:
        return None
    outcome = item.get("outcome")
    if outcome not in {"healthy", "failed"}:
        raise PolicyConflict("dynamic group reconciliation status is malformed")
    counts = item.get("counts")
    if not isinstance(counts, dict) or set(counts) != {
        "additions",
        "matched",
        "removals",
        "unchanged",
    }:
        raise PolicyConflict("dynamic group reconciliation status is malformed")
    return {
        "outcome": outcome,
        "lastAttemptAt": int(item.get("last_attempt_at", 0)),
        "lastSuccessAt": int(item.get("last_success_at", 0)) or None,
        "membershipRevision": int(item.get("membership_revision", 0)),
        "changed": bool(item.get("changed") is True),
        "counts": {key: int(value) for key, value in counts.items()},
        "errorCode": item.get("error_code") if outcome == "failed" else None,
    }


def _dynamic_status_record(
    tenant,
    group_id,
    *,
    now,
    outcome,
    membership_revision,
    counts,
    changed=False,
    error_code=None,
    previous=None,
):
    """Build bounded operational state without storing candidate membership."""
    last_success = now if outcome == "healthy" else (previous or {}).get("last_success_at", 0)
    return {
        **_item_key(tenant, "DYNAMIC_GROUP_STATUS", group_id),
        "id": group_id,
        "outcome": outcome,
        "last_attempt_at": now,
        "last_success_at": last_success,
        "membership_revision": membership_revision,
        "changed": bool(changed),
        "counts": counts,
        "error_code": error_code,
    }


def _record_dynamic_reconciliation_failure(tenant, group, error_code, *, now):
    """Persist a failed service evaluation without changing policy authority."""
    group_id = group.get("id")
    if not isinstance(group_id, str) or not group_id:
        raise PolicyConflict("dynamic group identity is malformed")
    # Failure reporting is not allowed to publish a stale authority revision
    # after a concurrent writer wins the membership compare-and-swap.
    live_group = TABLE.get_item(Key=_item_key(tenant, "GROUP", group_id), ConsistentRead=True).get(
        "Item"
    )
    if not live_group:
        raise PolicyConflict("dynamic group disappeared during reconciliation")
    group = live_group
    key = _item_key(tenant, "DYNAMIC_GROUP_STATUS", group_id)
    previous = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    status = _dynamic_status_record(
        tenant,
        group_id,
        now=now,
        outcome="failed",
        membership_revision=_group_membership_revision(group),
        counts={"matched": 0, "additions": 0, "removals": 0, "unchanged": 0},
        error_code=error_code,
        previous=previous,
    )
    transitioned = (
        not previous
        or previous.get("outcome") != "failed"
        or previous.get("error_code") != error_code
    )
    if transitioned:
        payload = {
            "group_id": group_id,
            "rule_hash": str(group.get("dynamic_rule_hash", "")),
            "membership_revision": _group_membership_revision(group),
            "error_code": error_code,
        }
        audit = _membership_audit_record(
            tenant,
            "dynamic_group_reconciliation_failed",
            _DYNAMIC_GROUP_RECONCILIATION_ACTOR,
            payload,
            now=now,
        )
        _transact_group_membership(
            [
                _transaction_put(
                    status,
                    condition="attribute_not_exists(pk) OR id = :status_id",
                    values={":status_id": group_id},
                ),
                _transaction_put(audit, condition="attribute_not_exists(pk)"),
            ]
        )
        _export_group_membership_audit(
            tenant,
            "dynamic_group_reconciliation_failed",
            _DYNAMIC_GROUP_RECONCILIATION_ACTOR,
            payload,
        )
    else:
        TABLE.put_item(Item=status)
    return status


def _reconcile_dynamic_group(tenant, group, *, now=None):
    """Materialize one approved rule under exact live revision authority."""
    now = int(time.time()) if now is None else now
    if _group_membership_mode(group) != "dynamic":
        raise PolicyConflict("only dynamic groups can be reconciled")
    group_id = group.get("id")
    if not isinstance(group_id, str) or not group_id:
        raise PolicyConflict("dynamic group identity is malformed")
    rule = _dynamic_group_rule(group.get("dynamic_rule"))
    canonical_rule = json.dumps(rule, sort_keys=True, separators=(",", ":"))
    rule_hash = hashlib.sha256(canonical_rule.encode()).hexdigest()
    if not secrets.compare_digest(str(group.get("dynamic_rule_hash", "")), rule_hash):
        raise PolicyConflict("dynamic group rule integrity check failed")
    current_revision = _group_membership_revision(group)
    current_keys = _group_agent_keys(group)
    desired_keys, conflicts = _dynamic_membership_evaluation(tenant, group, rule)
    if conflicts:
        return _record_dynamic_reconciliation_failure(
            tenant, group, "policy_group_overlap", now=now
        )
    additions = sorted(set(desired_keys) - set(current_keys))
    removals = sorted(set(current_keys) - set(desired_keys))
    unchanged = sorted(set(current_keys) & set(desired_keys))
    changed = bool(additions or removals)
    next_revision = current_revision + 1 if changed else current_revision
    counts = {
        "matched": len(desired_keys),
        "additions": len(additions),
        "removals": len(removals),
        "unchanged": len(unchanged),
    }
    status_key = _item_key(tenant, "DYNAMIC_GROUP_STATUS", group_id)
    previous = TABLE.get_item(Key=status_key, ConsistentRead=True).get("Item")
    status = _dynamic_status_record(
        tenant,
        group_id,
        now=now,
        outcome="healthy",
        membership_revision=next_revision,
        counts=counts,
        changed=changed,
        previous=previous,
    )
    if not changed:
        TABLE.put_item(Item=status)
        return status
    updated = {
        **group,
        "agent_keys": desired_keys,
        "membership_revision": next_revision,
        "dynamic_last_evaluated_at": now,
        "dynamic_last_evaluated_by": _DYNAMIC_GROUP_RECONCILIATION_ACTOR,
    }
    payload = {
        "group_id": group_id,
        "rule_hash": rule_hash,
        "membership_revision_before": current_revision,
        "membership_revision_after": next_revision,
        "matched_count": len(desired_keys),
        "addition_count": len(additions),
        "removal_count": len(removals),
        "unchanged_count": len(unchanged),
    }
    audit = _membership_audit_record(
        tenant,
        "dynamic_group_membership_reconciled",
        _DYNAMIC_GROUP_RECONCILIATION_ACTOR,
        payload,
        now=now,
    )
    _transact_group_membership(
        [
            _transaction_put(
                updated,
                condition="agent_keys = :agent_keys AND membership_revision = :membership_revision",
                values={":agent_keys": current_keys, ":membership_revision": current_revision},
            ),
            _transaction_put(
                status,
                condition="attribute_not_exists(pk) OR id = :status_id",
                values={":status_id": group_id},
            ),
            _transaction_put(audit, condition="attribute_not_exists(pk)"),
        ]
    )
    _export_group_membership_audit(
        tenant,
        "dynamic_group_membership_reconciled",
        _DYNAMIC_GROUP_RECONCILIATION_ACTOR,
        payload,
    )
    return status


def _membership_request(body):
    """Validate and normalize one closed-schema bulk assignment request."""
    if not isinstance(body, dict) or set(body) != {
        "mode",
        "requestId",
        "expectedMembershipRevision",
        "agents",
        "reason",
    }:
        raise ValueError("bulk group assignment request schema is invalid")
    mode = body.get("mode")
    if mode not in {"preview", "apply"}:
        raise ValueError("mode must be preview or apply")
    request_id = _bounded_identifier(body.get("requestId"), "requestId")
    expected = _positive_membership_revision(body.get("expectedMembershipRevision"))
    reason = _bounded_text(body.get("reason"), "reason", 500)
    if len(reason) < 20:
        raise ValueError("reason must contain at least 20 characters")
    raw_agents = body.get("agents")
    if (
        not isinstance(raw_agents, list)
        or not 1 <= len(raw_agents) <= _GROUP_MEMBERSHIP_BATCH_LIMIT
    ):
        raise ValueError(f"agents must contain 1 to {_GROUP_MEMBERSHIP_BATCH_LIMIT} entries")
    agents = []
    seen = set()
    for raw_agent in raw_agents:
        if not isinstance(raw_agent, dict) or set(raw_agent) != {"deploymentId", "agentId"}:
            raise ValueError("each bulk assignment agent must contain deploymentId and agentId")
        deployment_id = _bounded_identifier(raw_agent.get("deploymentId"), "deploymentId")
        agent_id = _bounded_identifier(raw_agent.get("agentId"), "agentId")
        key = f"{deployment_id}:{agent_id}"
        if key in seen:
            raise ValueError("bulk assignment agents must be unique")
        seen.add(key)
        agents.append({"deploymentId": deployment_id, "agentId": agent_id, "agentKey": key})
    return mode, request_id, expected, reason, sorted(agents, key=lambda item: item["agentKey"])


def _membership_outcome(deployment_id, agent_id, status, reason_code, message):
    """Build one content-minimised, typed assignment result."""
    return {
        "deploymentId": deployment_id,
        "agentId": agent_id,
        "status": status,
        "reasonCode": reason_code,
        "message": message,
    }


def _preview_group_membership(tenant, group, agents):
    """Evaluate assignment eligibility from strongly read server-owned state."""
    group_id = group.get("id")
    group_organization = group.get("organizationId") or group.get("organization_id")
    if not group_id or not group_organization:
        raise PolicyConflict("group organization ownership is missing")
    current_keys = set(_group_agent_keys(group))
    groups = _list(tenant, "GROUP", consistent_read=True)
    memberships = {}
    for candidate_group in groups:
        candidate_id = candidate_group.get("id")
        if not candidate_id:
            raise PolicyConflict("group membership record is malformed")
        for key in _group_agent_keys(candidate_group):
            memberships.setdefault(key, set()).add(candidate_id)
    outcomes = []
    ready_keys = []
    for target in agents:
        deployment_id = target["deploymentId"]
        agent_id = target["agentId"]
        key = target["agentKey"]
        if key in current_keys:
            outcomes.append(
                _membership_outcome(
                    deployment_id,
                    agent_id,
                    "unchanged",
                    "already_member",
                    "Agent is already assigned to this group.",
                )
            )
            continue
        agent = TABLE.get_item(Key=_item_key(tenant, "AGENT", key), ConsistentRead=True).get("Item")
        if not agent:
            outcomes.append(
                _membership_outcome(
                    deployment_id,
                    agent_id,
                    "rejected",
                    "agent_not_found",
                    "Agent is not enrolled in this tenant.",
                )
            )
            continue
        if _agent_lifecycle_state(agent) != "active":
            outcomes.append(
                _membership_outcome(
                    deployment_id,
                    agent_id,
                    "rejected",
                    "agent_not_active",
                    "Only an active agent can receive group authority.",
                )
            )
            continue
        agent_organization = agent.get("organization_id") or agent.get("organizationId")
        if not agent_organization or agent_organization != group_organization:
            outcomes.append(
                _membership_outcome(
                    deployment_id,
                    agent_id,
                    "rejected",
                    "organization_mismatch",
                    "Agent and group do not share the same organization.",
                )
            )
            continue
        other_groups = sorted(memberships.get(key, set()) - {group_id})
        if other_groups:
            outcomes.append(
                _membership_outcome(
                    deployment_id,
                    agent_id,
                    "rejected",
                    "already_assigned",
                    "Agent already belongs to another policy group.",
                )
            )
            continue
        ready_keys.append(key)
        outcomes.append(
            _membership_outcome(
                deployment_id,
                agent_id,
                "ready",
                "eligible",
                "Agent is eligible for assignment.",
            )
        )
    return outcomes, ready_keys


def _membership_audit_record(tenant, event_type, actor, payload, *, now):
    """Build primary immutable evidence committed with a membership batch."""
    event_id = str(uuid.uuid4())
    redacted = {
        "event_type": event_type,
        "actor": actor,
        "tenant_id": tenant,
        "occurred_at": now,
        "payload": payload,
    }
    return {
        **_item_key(tenant, "GROUP_MEMBERSHIP_AUDIT", f"{now:012d}#{event_id}"),
        **redacted,
        "id": event_id,
        "payload_hash": hashlib.sha256(
            json.dumps(redacted, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def _transact_group_membership(operations):
    """Atomically commit membership authority, idempotency and durable evidence."""
    try:
        DYNAMODB.transact_write_items(TransactItems=operations)
    except Exception as error:
        code = getattr(error, "response", {}).get("Error", {}).get("Code")
        if code in {"ConditionalCheckFailedException", "TransactionCanceledException"}:
            raise PolicyConflict("group membership changed concurrently") from error
        raise


def _export_group_membership_audit(tenant, event_type, actor, payload):
    """Best-effort replicate already durable membership evidence into S3."""
    try:
        _audit(tenant, event_type, actor, payload)
    except Exception:
        print(
            json.dumps(
                {"warning": "group membership audit replication failed", "event": event_type}
            )
        )


def _bulk_assign_group_membership(
    tenant, group_id, body, actor, *, event_type="group_membership_bulk_assigned"
):
    """Preview or atomically apply one bounded, idempotent assignment batch."""
    mode, request_id, expected, reason, agents = _membership_request(body)
    semantic_request = {
        "actor": actor,
        "agents": [
            {"deploymentId": item["deploymentId"], "agentId": item["agentId"]} for item in agents
        ],
        "expectedMembershipRevision": expected,
        "groupId": group_id,
        "reason": reason,
    }
    request_hash = hashlib.sha256(
        json.dumps(semantic_request, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    operation_key = _item_key(tenant, "GROUP_MEMBERSHIP_OPERATION", request_id)
    if mode == "apply":
        existing = TABLE.get_item(Key=operation_key, ConsistentRead=True).get("Item")
        if existing:
            if not secrets.compare_digest(str(existing.get("request_hash", "")), request_hash):
                raise PolicyConflict("requestId is already bound to a different assignment")
            response = existing.get("response")
            if not isinstance(response, dict):
                raise PolicyConflict("stored bulk assignment result is malformed")
            return int(existing.get("status_code", 200)), {**response, "replayed": True}
    group = TABLE.get_item(Key=_item_key(tenant, "GROUP", group_id), ConsistentRead=True).get(
        "Item"
    )
    if not group:
        raise LookupError("group not found")
    if _group_membership_mode(group) == "dynamic":
        raise PolicyConflict("dynamic group membership can only change by rule reevaluation")
    current_revision = _group_membership_revision(group)
    if current_revision != expected:
        raise PolicyConflict("group membership revision is stale")
    current_keys = _group_agent_keys(group)
    outcomes, ready_keys = _preview_group_membership(tenant, group, agents)
    counts = {
        "requested": len(outcomes),
        "ready": len(ready_keys) if mode == "preview" else 0,
        "applied": 0,
        "unchanged": sum(item["status"] == "unchanged" for item in outcomes),
        "rejected": sum(item["status"] == "rejected" for item in outcomes),
    }
    next_revision = current_revision
    if mode == "apply":
        outcomes = [
            {
                **item,
                "status": "applied",
                "reasonCode": "assigned",
                "message": "Agent was assigned.",
            }
            if item["status"] == "ready"
            else item
            for item in outcomes
        ]
        counts["applied"] = len(ready_keys)
        counts["ready"] = 0
        if ready_keys:
            next_revision += 1
    response = {
        "groupId": group_id,
        "requestId": request_id,
        "mode": mode,
        "membershipRevision": current_revision,
        "resultingMembershipRevision": next_revision,
        "counts": counts,
        "outcomes": outcomes,
        "canApply": mode == "preview" and bool(ready_keys),
        "partialFailure": bool(counts["rejected"]),
        "replayed": False,
    }
    if mode == "preview":
        return 200, response
    now = int(time.time())
    audit_payload = {
        "request_id": request_id,
        "request_hash": request_hash,
        "group_id": group_id,
        "membership_revision_before": current_revision,
        "membership_revision_after": next_revision,
        "requested_count": counts["requested"],
        "applied_count": counts["applied"],
        "unchanged_count": counts["unchanged"],
        "rejected_count": counts["rejected"],
        "reason": reason,
    }
    audit = _membership_audit_record(tenant, event_type, actor, audit_payload, now=now)
    status_code = 207 if counts["rejected"] else 200
    operation = {
        **operation_key,
        "id": request_id,
        "group_id": group_id,
        "actor": actor,
        "request_hash": request_hash,
        "status_code": status_code,
        "created_at": now,
        "response": response,
    }
    operations = []
    if ready_keys:
        updated = {
            **group,
            "agent_keys": sorted(set(current_keys + ready_keys)),
            "membership_revision": next_revision,
        }
        if "membership_revision" in group:
            condition = "agent_keys = :agent_keys AND membership_revision = :membership_revision"
            values = {
                ":agent_keys": current_keys,
                ":membership_revision": current_revision,
            }
        else:
            condition = "agent_keys = :agent_keys AND attribute_not_exists(membership_revision)"
            values = {":agent_keys": current_keys}
        operations.append(_transaction_put(updated, condition=condition, values=values))
    operations.extend(
        [
            _transaction_put(operation, condition="attribute_not_exists(pk)"),
            _transaction_put(audit, condition="attribute_not_exists(pk)"),
        ]
    )
    _transact_group_membership(operations)
    _export_group_membership_audit(tenant, event_type, actor, audit_payload)
    return status_code, response


def _remove_group_member(tenant, group_id, agent_key, actor):
    """Remove one membership with compare-and-swap and co-committed evidence."""
    group = TABLE.get_item(Key=_item_key(tenant, "GROUP", group_id), ConsistentRead=True).get(
        "Item"
    )
    if not group:
        raise LookupError("group not found")
    if _group_membership_mode(group) == "dynamic":
        raise PolicyConflict("dynamic group membership can only change by rule reevaluation")
    current_keys = _group_agent_keys(group)
    if agent_key not in current_keys:
        return group
    revision = _group_membership_revision(group)
    updated = {
        **group,
        "agent_keys": [key for key in current_keys if key != agent_key],
        "membership_revision": revision + 1,
    }
    now = int(time.time())
    deployment_id, agent_id = agent_key.split(":", 1)
    payload = {
        "group_id": group_id,
        "deployment_id": deployment_id,
        "agent_id": agent_id,
        "membership_revision_before": revision,
        "membership_revision_after": revision + 1,
    }
    audit = _membership_audit_record(tenant, "agent_removed_from_group", actor, payload, now=now)
    if "membership_revision" in group:
        condition = "agent_keys = :agent_keys AND membership_revision = :membership_revision"
        values = {":agent_keys": current_keys, ":membership_revision": revision}
    else:
        condition = "agent_keys = :agent_keys AND attribute_not_exists(membership_revision)"
        values = {":agent_keys": current_keys}
    _transact_group_membership(
        [
            _transaction_put(updated, condition=condition, values=values),
            _transaction_put(audit, condition="attribute_not_exists(pk)"),
        ]
    )
    _export_group_membership_audit(tenant, "agent_removed_from_group", actor, payload)
    return updated


def _decision_value(body, field, allowed):
    """Return one value from a closed decision-evidence vocabulary."""
    value = body.get(field)
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{field} is unsupported")
    return value


def _decision_view(item):
    """Return content-minimised host evidence in the dashboard contract."""
    observed_at = int(item.get("observed_at", 0))
    view = {
        "id": item["id"],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(observed_at)),
        "agent": item.get("agent_id", "unknown-agent"),
        "tool": item.get("tool_name", "unknown-tool"),
        "decision": item["decision"],
        "reason": _DECISION_REASON_LABELS.get(item.get("reason_code"), "Policy decision recorded"),
        "resource": _DECISION_RESOURCE_LABELS.get(item.get("resource_kind"), "Content redacted"),
        "source": item.get("source", "sdk_runtime"),
        "deploymentId": item.get("deployment_id", ""),
        "policyId": item.get("policy_id", ""),
        "policyVersion": int(item.get("policy_version", 0)),
        "actionDigest": item.get("action_digest"),
        "reportedByAgent": True,
    }
    if item.get("mcp_server_id"):
        view["mcpServerId"] = item["mcp_server_id"]
    return view


def _record_agent_decision(tenant, deployment_id, agent_id, body):
    """Persist one authenticated, redacted host decision as untrusted evidence.

    The session establishes which enrolled process submitted the event. It
    does not make the report an authorization decision: the server derives all
    ownership and policy metadata and marks the record as agent-reported.
    """
    required_fields = {
        "decisionId",
        "source",
        "toolName",
        "decision",
        "resourceKind",
        "reasonCode",
    }
    supplied_fields = set(body) if isinstance(body, dict) else set()
    optional_fields = {"actionDigest", "mcpServerId"}
    if (
        not isinstance(body, dict)
        or not required_fields.issubset(supplied_fields)
        or not supplied_fields.issubset(required_fields | optional_fields)
    ):
        raise ValueError("decision evidence contains unsupported fields")
    decision_id = body.get("decisionId")
    if not isinstance(decision_id, str) or not re.fullmatch(r"[0-9a-f]{64}", decision_id):
        raise ValueError("decisionId must be a SHA-256 event digest")
    tool_name = _bounded_text(body.get("toolName"), "toolName", 128)
    decision = _decision_value(body, "decision", _DECISION_VALUES)
    source = _decision_value(body, "source", _DECISION_SOURCES)
    resource_kind = _decision_value(body, "resourceKind", _DECISION_RESOURCE_KINDS)
    reason_code = _decision_value(body, "reasonCode", _DECISION_REASON_CODES)
    action_digest = body.get("actionDigest")
    if action_digest is not None and (
        not isinstance(action_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", action_digest)
    ):
        raise ValueError("actionDigest must be a SHA-256 action digest")
    mcp_server_id = body.get("mcpServerId")
    if mcp_server_id is not None:
        mcp_server_id = _bounded_identifier(mcp_server_id, "mcpServerId")
        if source != "mcp" and resource_kind != "mcp_tool":
            raise ValueError("mcpServerId requires MCP decision evidence")
    agent_key = f"{deployment_id}:{agent_id}"
    agent = TABLE.get_item(Key=_item_key(tenant, "AGENT", agent_key), ConsistentRead=True).get(
        "Item"
    )
    if not agent:
        raise PermissionError("registered agent is required")
    groups = [
        item
        for item in _list(tenant, "GROUP", consistent_read=True)
        if agent_key in item.get("agent_keys", [])
    ]
    if len(groups) != 1:
        raise PermissionError("exactly one assigned policy group is required")
    group = groups[0]
    policy = TABLE.get_item(
        Key=_item_key(tenant, "POLICY", group.get("policyId", "")),
        ConsistentRead=True,
    ).get("Item")
    if not policy:
        raise PermissionError("assigned policy is unavailable")
    record_id = f"{deployment_id}:{agent_id}:{decision_id}"
    observed_at = int(time.time())
    values = {
        "id": decision_id,
        "deployment_id": deployment_id,
        "agent_id": agent_id,
        "host": agent.get("host", ""),
        "source": source,
        "tool_name": tool_name,
        "decision": decision,
        "resource_kind": resource_kind,
        "reason_code": reason_code,
        "policy_id": policy["id"],
        "policy_version": int(policy.get("version", 0)),
        "reported_by_agent": True,
        "observed_at": observed_at,
        "timeline_pk": f"TENANT#{tenant}#DECISION",
        "timeline_sk": f"{observed_at:010d}#{record_id}",
        "ttl": observed_at + (30 * 86400),
    }
    if action_digest is not None:
        values["action_digest"] = action_digest
    if mcp_server_id is not None:
        values["mcp_server_id"] = mcp_server_id
    try:
        item = _create_item(tenant, "DECISION", record_id, values)
    except Exception as error:
        if not _is_conditional_conflict(error):
            raise
        existing = TABLE.get_item(
            Key=_item_key(tenant, "DECISION", record_id), ConsistentRead=True
        ).get("Item")
        comparable = (
            "deployment_id",
            "agent_id",
            "source",
            "tool_name",
            "decision",
            "resource_kind",
            "reason_code",
            "action_digest",
            "mcp_server_id",
        )
        if existing and all(existing.get(key) == values.get(key) for key in comparable):
            return {"accepted": True, "duplicate": True, "decisionId": decision_id}
        return {"accepted": False, "conflict": True, "decisionId": decision_id}
    _audit(
        tenant,
        "agent_decision_reported",
        f"agent:{deployment_id}:{agent_id}",
        {
            "decision_id": decision_id,
            "deployment_id": deployment_id,
            "agent_id": agent_id,
            "source": source,
            "tool_name": tool_name,
            "decision": decision,
            "resource_kind": resource_kind,
            "reason_code": reason_code,
            "action_digest": action_digest,
            "mcp_server_id": mcp_server_id,
            "policy_id": policy["id"],
            "policy_version": int(policy.get("version", 0)),
        },
    )
    try:
        _evaluate_behavior_rules_for_agent(tenant, agent_key, now=observed_at)
    except Exception:
        # Decision reporting is observational and follows the governed action.
        # Detection failure must be visible but cannot rewrite that past action
        # or leak provider details into logs.
        _record_behavior_health(tenant, "degraded", now=observed_at)
        print(json.dumps({"warning": "behavior detection evaluation remains degraded"}))
    return {"accepted": True, "duplicate": False, "decisionId": item["id"]}


def _approval_status(item, now=None):
    """Return the externally visible approval state, including expiry.

    Approval expiry is derived from the server clock rather than from browser
    state.  A pending or approved record that has passed its exact action-bound
    TTL can never be presented as actionable or consumable.
    """
    current = int(time.time()) if now is None else int(now)
    status = item.get("status", "approved" if not item.get("consumed") else "consumed")
    if status in {"pending", "approved"} and int(item.get("expires_at", 0)) <= current:
        return "expired"
    return status


def _approval_view(item, now=None):
    """Project one approval record into the secret-free operator API shape."""
    agent_key = str(item.get("agent_key", ""))
    deployment_id, _, agent_id = agent_key.partition(":")
    return {
        "id": item.get("id", ""),
        "deploymentId": deployment_id,
        "agentId": agent_id,
        "agentKey": agent_key,
        "toolName": item.get("tool_name", ""),
        "proposalId": item.get("proposal_id", ""),
        "taskId": item.get("task_id", ""),
        "principalId": item.get("principal_id", ""),
        "actionHash": item.get("action_hash", ""),
        "riskClass": item.get("risk_class", "unspecified"),
        "resourceIds": item.get("resource_ids", []),
        "status": _approval_status(item, now),
        "requestedAt": item.get("requested_at", item.get("created_at", 0)),
        "expiresAt": item.get("expires_at", 0),
        "decidedAt": item.get("decided_at"),
        "decidedBy": item.get("decided_by"),
        "decisionReason": item.get("decision_reason"),
        "consumedAt": item.get("consumed_at"),
    }


def _approval_text(value, field, maximum=256):
    """Validate one bounded approval binding supplied by an enrolled agent."""
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{field} must be a non-empty string up to {maximum} characters")
    return value.strip()


def _approval_resources(value):
    """Validate bounded resource identifiers without accepting action content."""
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 20:
        raise ValueError("resource_ids must be a list of at most 20 identifiers")
    return [_approval_text(item, "resource_ids item", 256) for item in value]


def _pending_approval_count(tenant):
    """Count only live, operator-actionable approval requests for the tenant."""
    now = int(time.time())
    return sum(1 for item in _list(tenant, "APPROVAL") if _approval_status(item, now) == "pending")


def _seed(tenant):
    # Signup provisioning creates the tenant root before the first console
    # request. Never replace that server-owned record with demo data: doing so
    # would erase trial status and its expiry metadata at the API boundary.
    tenant_root = TABLE.get_item(Key=_item_key(tenant, "TENANT", "root"), ConsistentRead=True).get(
        "Item"
    )
    if tenant_root:
        expected_pk, expected_sk = _evidence_assurance_registration(tenant)
        if (
            tenant_root.get("evidence_assurance_pk") != expected_pk
            or tenant_root.get("evidence_assurance_sk") != expected_sk
        ):
            _register_evidence_assurance_tenant(tenant)
        return
    if TABLE.get_item(Key=_item_key(tenant, "ORG", "org-demo")).get("Item"):
        now = int(time.time())
        # Older demo deployments predate the provisioned tenant-root record.
        # Recover that server-owned schedule anchor exactly once; without it,
        # asynchronous work can be committed but no scheduled worker can
        # discover the tenant.  The legacy organization is the migration
        # authority and the conditional put prevents concurrent replacement.
        try:
            TABLE.put_item(
                Item={
                    **_item_key(tenant, "TENANT", "root"),
                    "id": tenant,
                    "status": "active",
                    "created_at": now,
                },
                ConditionExpression="attribute_not_exists(pk)",
            )
        except Exception as error:
            if not _is_conditional_conflict(error):
                raise
        _register_evidence_assurance_tenant(tenant)
        if not TABLE.get_item(Key=_item_key(tenant, "SKILL", "skill-repository-review")).get(
            "Item"
        ):
            _put(
                tenant,
                "SKILL",
                "skill-repository-review",
                {
                    "id": "skill-repository-review",
                    "organizationId": "org-demo",
                    "name": "Repository review",
                    "description": "Read-only repository review guidance.",
                    "version": "1.0.0",
                    "content": (
                        "# Repository review\\nReview source changes and report findings.\\n"
                    ),
                    "digest": "sha256:synthetic-repository-review",
                    "enabled": True,
                    "createdAt": now,
                    "author": "system",
                },
            )
        if not TABLE.get_item(Key=_item_key(tenant, "MCP", "mcp-agentic-security")).get("Item"):
            _put(
                tenant,
                "MCP",
                "mcp-agentic-security",
                {
                    "id": "mcp-agentic-security",
                    "organizationId": "org-demo",
                    "name": "Agentic Security gateway",
                    "description": "SDK-owned guarded tools.",
                    "version": "1.0.0",
                    "transport": "stdio",
                    "command": "python",
                    "args": ["examples/mcp_gateway.py"],
                    "environmentReferences": ["AAI_SEC_AGENT_TOKEN"],
                    "enabled": True,
                    "createdAt": now,
                    "author": "system",
                },
            )
        return
    now = int(time.time())
    _put(tenant, "TENANT", "root", {"id": tenant, "status": "active", "created_at": now})
    _register_evidence_assurance_tenant(tenant)
    _put(
        tenant,
        "ORG",
        "org-demo",
        {"id": "org-demo", "name": "Example enterprise", "created_at": now},
    )
    _put(
        tenant,
        "PROJECT",
        "project-demo",
        {
            "id": "project-demo",
            "organization_id": "org-demo",
            "name": "Platform engineering",
            "created_at": now,
        },
    )
    _put(
        tenant,
        "DEPLOYMENT",
        "deployment-claude-local",
        {
            "id": "deployment-claude-local",
            "organization_id": "org-demo",
            "project_id": "project-demo",
            "name": "Claude Code local",
            "environment": "dev",
            "region": os.environ.get("AWS_REGION", "eu-west-2"),
            "team": "Platform",
            "sdk_version": "1.0.1",
        },
    )
    seed_policy = _put(
        tenant,
        "POLICY",
        "policy-safe-default",
        {
            "id": "policy-safe-default",
            "organization_id": "org-demo",
            "name": "Safe default policy",
            "configuration": {
                "runtime": {"maxActions": 25, "allowedTools": ["read_repository"]},
                "tools": {"allowed": ["read_repository"], "denied": []},
                "policy": {"denyByDefault": True},
                "audit": {"redactSensitiveData": True, "captureToolContent": False},
                "claudeCode": {
                    "allowedBuiltInTools": ["Read", "Glob", "Grep"],
                    "fileTools": ["Read", "Glob", "Grep"],
                    "deniedCommandPatterns": ["rm\\s+-rf"],
                    "approvalCommandPatterns": ["git\\s+push"],
                    "allowedCommandPatterns": [
                        "^pwd$",
                        "^ls$",
                        "^git[ \\t]+status$",
                        "^git[ \\t]+status[ \\t]+--short$",
                        "^git[ \\t]+diff[ \\t]+--stat$",
                        "^git[ \\t]+log[ \\t]+--oneline$",
                    ],
                },
            },
            "version": 1,
            "createdAt": now,
        },
    )
    _ensure_policy_governance(tenant, seed_policy)
    _put(
        tenant,
        "SKILL",
        "skill-repository-review",
        {
            "id": "skill-repository-review",
            "organizationId": "org-demo",
            "name": "Repository review",
            "description": "Read-only repository review guidance.",
            "version": "1.0.0",
            "content": "# Repository review\\nReview source changes and report findings.\\n",
            "digest": "sha256:synthetic-repository-review",
            "enabled": True,
            "createdAt": now,
            "author": "system",
        },
    )
    _put(
        tenant,
        "MCP",
        "mcp-agentic-security",
        {
            "id": "mcp-agentic-security",
            "organizationId": "org-demo",
            "name": "Agentic Security gateway",
            "description": "SDK-owned guarded tools.",
            "version": "1.0.0",
            "transport": "stdio",
            "command": "python",
            "args": ["examples/mcp_gateway.py"],
            "environmentReferences": ["AAI_SEC_AGENT_TOKEN"],
            "enabled": True,
            "createdAt": now,
            "author": "system",
        },
    )
    _put(
        tenant,
        "GROUP",
        "group-platform",
        {
            "id": "group-platform",
            "organizationId": "org-demo",
            "name": "Platform engineers",
            "policyId": "policy-safe-default",
            "policyName": "Safe default policy",
            "createdAt": now,
            "agent_keys": ["deployment-claude-local:agent-claude-local"],
            "membership_revision": 1,
        },
    )
    _put(
        tenant,
        "AGENT",
        "deployment-claude-local:agent-claude-local",
        {
            "id": "agent-claude-local",
            "organization_id": "org-demo",
            "project_id": "project-demo",
            "deployment_id": "deployment-claude-local",
            "host": "claude-code",
            "project_root": "/Users/example/project",
            "environment": "dev",
            "region": os.environ.get("AWS_REGION", "eu-west-2"),
            "status": "connected",
            "last_heartbeat": now,
            "expires_at": now + 300,
            "emergencyStop": False,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
            "session_revision": 1,
            "owner_id": "system-owner",
            "owner_name": "Platform owner",
            "business_contact": "platform@example.invalid",
            "team": "Platform",
            "ownership_criticality": "medium",
            "ownership_reviewed_at": now,
            "ownership_review_due_at": now + _AGENT_OWNERSHIP_REVIEW_SECONDS,
            "ownership_reviewed_by": "system",
            "ownership_revision": 1,
            "created_at": now,
        },
    )
    _audit(tenant, "bootstrap_seeded", "system", {"deployment_id": "deployment-claude-local"})


def _all_agents(tenant, *, consistent_read=False):
    """Return agent inventory with derived posture and optional strong reads."""
    agents = _list(tenant, "AGENT", consistent_read=consistent_read)
    now = int(time.time())
    for agent in agents:
        if _agent_lifecycle_state(agent) != "active":
            # Historical records remain visible as evidence but can never be
            # presented as live presence or counted as an active session.
            agent.update(
                {"status": "offline", "last_heartbeat": 0, "expires_at": 0, "emergencyStop": True}
            )
        elif agent.get("expires_at", 0) < now and agent.get("status") != "offline":
            agent["status"] = "offline"
        agent["managed_configuration"] = _managed_configuration_posture(tenant, agent, now=now)
        agent["ownership"] = _agent_ownership_view(agent, now=now)
    return agents


def _authoritative_endpoint_devices(tenant, *, now=None, require_current=True):
    """Return current, complete endpoint inventory without trusting a sensor.

    Device identity and management state come from the MDM discovery source.
    Sensor reports may describe software on a known device but can never create
    the device population against which enterprise coverage is measured.
    """
    current_time = int(time.time()) if now is None else int(now)
    devices = {}
    for source in _list(tenant, "DISCOVERY_SOURCE", consistent_read=True):
        if source.get("sourceKind") != "endpoint" or source.get("complete") is not True:
            continue
        if require_current and int(source.get("expiresAt", 0)) <= current_time:
            continue
        for observation in _discovery_generation_observations(tenant, source):
            if not isinstance(observation, dict) or observation.get("kind") != "device":
                continue
            normalized = _discovery_observation(observation, "endpoint")
            existing = devices.get(normalized["id"])
            if existing is not None and existing != normalized:
                raise PolicyConflict("endpoint inventory contains conflicting device identity")
            devices[normalized["id"]] = normalized
    return devices


def _register_endpoint_detection_tenant(tenant):
    """Put one provisioned tenant in the bounded scheduled-detection index."""
    digest = hashlib.sha256(tenant.encode()).digest()
    shard = digest[0] % _ENDPOINT_DETECTION_SHARDS
    try:
        TABLE.update_item(
            Key=_item_key(tenant, "TENANT", "root"),
            UpdateExpression=(
                "SET endpoint_detection_pk = :partition, endpoint_detection_sk = :tenant"
            ),
            ConditionExpression="attribute_exists(pk)",
            ExpressionAttributeValues={
                ":partition": f"ENDPOINT_DETECTION#{shard:02d}",
                ":tenant": tenant,
            },
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PermissionError("tenant is not provisioned for endpoint detection") from error
        raise


def _evidence_assurance_registration(tenant):
    """Return the deterministic schedule-index values for one tenant."""
    digest = hashlib.sha256(tenant.encode()).digest()
    shard = digest[1] % _EVIDENCE_ASSURANCE_SHARDS
    return f"EVIDENCE_ASSURANCE#{shard:02d}", tenant


def _register_evidence_assurance_tenant(tenant):
    """Put one provisioned tenant in the bounded evidence schedule index."""
    partition, sort_key = _evidence_assurance_registration(tenant)
    try:
        TABLE.update_item(
            Key=_item_key(tenant, "TENANT", "root"),
            UpdateExpression=(
                "SET evidence_assurance_pk = :partition, evidence_assurance_sk = :tenant"
            ),
            ConditionExpression="attribute_exists(pk)",
            ExpressionAttributeValues={
                ":partition": partition,
                ":tenant": sort_key,
            },
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PermissionError("tenant is not provisioned for evidence assurance") from error
        raise


def _endpoint_credential_view(record):
    """Project one device credential without returning its bearer digest."""
    if not record:
        return {"status": "not_configured", "revision": 0, "keyId": None}
    return {
        "status": "revoked" if record.get("revoked") is True else "active",
        "revision": int(record.get("revision", 0)),
        "keyId": record.get("keyId"),
        "rotatedAt": int(record.get("rotatedAt", 0)),
        "revokedAt": record.get("revokedAt"),
    }


def _issue_endpoint_credential(tenant, device_id, value, actor):
    """Rotate a one-time device bearer/HMAC secret for an MDM-known device."""
    if not isinstance(value, dict) or set(value) != {"expectedRevision"}:
        raise ValueError("endpoint credential request has an invalid schema")
    device_id = _bounded_identifier(device_id, "deviceId")
    device = _authoritative_endpoint_devices(tenant).get(device_id)
    if not device:
        raise LookupError("device is not present in current endpoint inventory")
    if device.get("managed") is not True:
        raise PolicyConflict("endpoint credential requires a managed device")
    _register_endpoint_detection_tenant(tenant)
    expected = _discovery_integer(value.get("expectedRevision"), "expectedRevision")
    key = _item_key(tenant, "ENDPOINT_CREDENTIAL", device_id)
    existing = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    current = int(existing.get("revision", 0)) if existing else 0
    if current != expected:
        raise PolicyConflict("endpoint credential revision changed")
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    record = {
        **key,
        "tenant_id": tenant,
        "deviceId": device_id,
        "keyId": f"endpoint-{uuid.uuid4()}",
        "tokenHash": hashlib.sha256(token.encode()).hexdigest(),
        "revision": expected + 1,
        "rotatedAt": now,
        "rotatedBy": actor,
        "revoked": False,
    }
    arguments = {"Item": record}
    if expected == 0:
        arguments["ConditionExpression"] = "attribute_not_exists(pk)"
    else:
        arguments.update(
            {
                "ConditionExpression": "revision = :expected_revision",
                "ExpressionAttributeValues": {":expected_revision": expected},
            }
        )
    try:
        TABLE.put_item(**arguments)
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("endpoint credential revision changed") from error
        raise
    _audit(
        tenant,
        "endpoint_credential_rotated",
        actor,
        {"device_id": device_id, "key_id": record["keyId"], "revision": expected + 1},
    )
    return {
        "deviceId": device_id,
        "keyId": record["keyId"],
        "secret": token,
        "revision": expected + 1,
        "issuedAt": now,
    }


def _revoke_endpoint_credential(tenant, device_id, value, actor):
    """Revoke one device credential with optimistic concurrency."""
    if not isinstance(value, dict) or set(value) != {"expectedRevision"}:
        raise ValueError("endpoint credential revocation has an invalid schema")
    device_id = _bounded_identifier(device_id, "deviceId")
    expected = _discovery_integer(value.get("expectedRevision"), "expectedRevision", minimum=1)
    key = _item_key(tenant, "ENDPOINT_CREDENTIAL", device_id)
    record = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    if not record:
        raise LookupError("endpoint credential not found")
    if int(record.get("revision", 0)) != expected:
        raise PolicyConflict("endpoint credential revision changed")
    if record.get("revoked") is True:
        return _endpoint_credential_view(record)
    now = int(time.time())
    updated = {**record, "revoked": True, "revokedAt": now, "revokedBy": actor}
    try:
        TABLE.put_item(
            Item=updated,
            ConditionExpression="revision = :expected_revision",
            ExpressionAttributeValues={":expected_revision": expected},
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("endpoint credential revision changed") from error
        raise
    _audit(
        tenant,
        "endpoint_credential_revoked",
        actor,
        {"device_id": device_id, "key_id": record.get("keyId"), "revision": expected},
    )
    return _endpoint_credential_view(updated)


def _validate_endpoint_report(report, device_id):
    """Validate exact path-free sensor evidence and return normalized content."""
    if not isinstance(report, dict) or set(report) != {"keyId", "payload", "signature"}:
        raise ValueError("endpoint report has an invalid schema")
    key_id = _bounded_identifier(report.get("keyId"), "keyId")
    signature = report.get("signature")
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
        raise ValueError("endpoint report signature is invalid")
    payload = report.get("payload")
    if not isinstance(payload, dict) or set(payload) != {
        "schemaVersion",
        "observedAt",
        "device",
        "installations",
    }:
        raise ValueError("endpoint report payload has an invalid schema")
    if payload.get("schemaVersion") != 1:
        raise ValueError("endpoint report schema version is unsupported")
    observed_at = _discovery_integer(payload.get("observedAt"), "observedAt", minimum=1)
    device = payload.get("device")
    if not isinstance(device, dict):
        raise ValueError("endpoint report device is invalid")
    normalized_device = _discovery_observation({"kind": "device", **device}, "endpoint")
    if normalized_device["id"] != device_id:
        raise PermissionError("endpoint report device identity mismatch")
    installations = payload.get("installations")
    if not isinstance(installations, list) or not 1 <= len(installations) <= 100:
        raise ValueError("endpoint report must contain 1 to 100 installations")
    normalized_installations = []
    for installation in installations:
        if not isinstance(installation, dict):
            raise ValueError("endpoint report installation is invalid")
        normalized = _discovery_observation({"kind": "installation", **installation}, "endpoint")
        if normalized["deviceId"] != device_id:
            raise PermissionError("endpoint installation device identity mismatch")
        normalized.pop("kind")
        normalized_installations.append(normalized)
    identities = [item["id"] for item in normalized_installations]
    if len(identities) != len(set(identities)):
        raise ValueError("endpoint installation identifiers must be unique")
    normalized_device.pop("kind")
    normalized_payload = {
        "schemaVersion": 1,
        "observedAt": observed_at,
        "device": normalized_device,
        "installations": sorted(normalized_installations, key=lambda item: item["id"]),
    }
    signed_payload = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return key_id, signature, normalized_payload, signed_payload


def _ingest_endpoint_report(event, tenant, device_id):
    """Authenticate, verify and atomically retain the newest device report."""
    tenant = _bounded_identifier(tenant, "tenantId")
    device_id = _bounded_identifier(device_id, "deviceId")
    credential = TABLE.get_item(
        Key=_item_key(tenant, "ENDPOINT_CREDENTIAL", device_id), ConsistentRead=True
    ).get("Item")
    if not credential or credential.get("revoked") is True:
        raise PermissionError("active endpoint credential is required")
    token = _bearer(event)
    if not token or not secrets.compare_digest(
        hashlib.sha256(token.encode()).hexdigest(), str(credential.get("tokenHash", ""))
    ):
        raise PermissionError("endpoint credential is invalid")
    key_id, signature, payload, signed_payload = _validate_endpoint_report(_body(event), device_id)
    if key_id != credential.get("keyId"):
        raise PermissionError("endpoint key identity mismatch")
    expected_signature = hmac.new(token.encode(), signed_payload, hashlib.sha256).hexdigest()
    if not secrets.compare_digest(expected_signature, signature):
        _record_endpoint_event_alert(tenant, device_id, "signature_invalid")
        _audit(
            tenant,
            "endpoint_evidence_rejected",
            f"endpoint:{device_id}",
            {"device_id": device_id, "key_id": key_id, "reason": "signature_invalid"},
        )
        raise PermissionError("endpoint report signature is invalid")
    now = int(time.time())
    observed_at = int(payload["observedAt"])
    if observed_at > now + _ENDPOINT_EVIDENCE_FUTURE_SKEW_SECONDS:
        raise ValueError("endpoint report is future-dated")
    if observed_at <= now - _ENDPOINT_EVIDENCE_MAX_AGE_SECONDS:
        raise ValueError("endpoint report is stale")
    report_digest = hashlib.sha256(signed_payload).hexdigest()
    key = _item_key(tenant, "ENDPOINT_EVIDENCE", device_id)
    existing = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    if existing:
        if int(existing.get("observedAt", 0)) == observed_at and secrets.compare_digest(
            str(existing.get("reportDigest", "")), report_digest
        ):
            return {"accepted": True, "duplicate": True, "deviceId": device_id}
        if observed_at <= int(existing.get("observedAt", 0)):
            _record_endpoint_event_alert(tenant, device_id, "report_replayed")
            raise PolicyConflict("endpoint report replay or reordering detected")
    revision = int(existing.get("revision", 0)) if existing else 0
    record = {
        **key,
        "tenant_id": tenant,
        "deviceId": device_id,
        "keyId": key_id,
        "observedAt": observed_at,
        "receivedAt": now,
        "reportDigest": report_digest,
        "payload": payload,
        "revision": revision + 1,
    }
    arguments = {"Item": record}
    if revision == 0:
        arguments["ConditionExpression"] = "attribute_not_exists(pk)"
    else:
        arguments.update(
            {
                "ConditionExpression": "revision = :expected_revision",
                "ExpressionAttributeValues": {":expected_revision": revision},
            }
        )
    try:
        TABLE.put_item(**arguments)
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("endpoint report changed concurrently") from error
        raise
    _audit(
        tenant,
        "endpoint_evidence_accepted",
        f"endpoint:{device_id}",
        {
            "device_id": device_id,
            "key_id": key_id,
            "observed_at": observed_at,
            "report_digest": report_digest,
            "installation_count": len(payload["installations"]),
        },
    )
    return {"accepted": True, "duplicate": False, "deviceId": device_id}


def _endpoint_evidence_health(tenant, *, now=None):
    """Derive per-device sensor health from MDM, credential and report state."""
    current_time = int(time.time()) if now is None else int(now)
    devices = _authoritative_endpoint_devices(tenant, now=current_time, require_current=False)
    current_device_ids = set(_authoritative_endpoint_devices(tenant, now=current_time))
    credentials = {item.get("deviceId"): item for item in _list(tenant, "ENDPOINT_CREDENTIAL")}
    reports = {item.get("deviceId"): item for item in _list(tenant, "ENDPOINT_EVIDENCE")}
    items = []
    for device_id, device in sorted(devices.items()):
        credential = credentials.get(device_id)
        report = reports.get(device_id)
        credential_view = _endpoint_credential_view(credential)
        reasons = []
        report_status = "never_reported"
        payload = report.get("payload", {}) if isinstance(report, dict) else {}
        installations = payload.get("installations", []) if isinstance(payload, dict) else []
        # Health consumers do not need the observed user identifier. Keep it in
        # the tenant-bound evidence record for reconciliation, but omit it from
        # this operational response to minimise identity-data propagation.
        health_installations = [
            {key: value for key, value in item.items() if key != "userId"} for item in installations
        ]
        if credential_view["status"] == "not_configured":
            reasons.append("credential_not_configured")
        elif credential_view["status"] == "revoked":
            reasons.append("credential_revoked")
        if report:
            if report.get("keyId") != (credential or {}).get("keyId"):
                report_status = "credential_rotated"
                reasons.append("fresh_report_required_after_rotation")
            elif (
                int(report.get("observedAt", 0))
                <= current_time - _ENDPOINT_EVIDENCE_MAX_AGE_SECONDS
            ):
                report_status = "stale"
                reasons.append("report_stale")
            else:
                report_status = "current"
        else:
            reasons.append("report_missing")
        if device.get("managed") is not True:
            reasons.append("device_unmanaged")
        if device_id not in current_device_ids:
            reasons.append("inventory_stale")
        if report_status == "current":
            if not installations:
                reasons.append("installation_missing")
            if any(item.get("binaryPresent") is not True for item in installations):
                reasons.append("binary_missing")
            if any(item.get("processActive") is not True for item in installations):
                reasons.append("process_not_observed")
        status = (
            "healthy"
            if not reasons
            else "stale"
            if {"report_stale", "inventory_stale"}.intersection(reasons)
            else "attention"
        )
        items.append(
            {
                "deviceId": device_id,
                "businessUnit": device.get("businessUnit"),
                "managed": device.get("managed") is True,
                "status": status,
                "reasonCodes": reasons,
                "credential": credential_view,
                "reportStatus": report_status,
                "observedAt": int(report.get("observedAt", 0)) if report else None,
                "receivedAt": int(report.get("receivedAt", 0)) if report else None,
                "ageSeconds": max(0, current_time - int(report.get("observedAt", 0)))
                if report
                else None,
                "reportDigest": report.get("reportDigest") if report else None,
                "installations": health_installations if report_status == "current" else [],
            }
        )
    return {
        "generatedAt": current_time,
        "freshnessSeconds": _ENDPOINT_EVIDENCE_MAX_AGE_SECONDS,
        "summary": {
            "devices": len(items),
            "healthy": sum(1 for item in items if item["status"] == "healthy"),
            "attention": sum(1 for item in items if item["status"] == "attention"),
            "stale": sum(1 for item in items if item["status"] == "stale"),
        },
        "items": items,
    }


def _endpoint_alert_id(tenant, device_id, reason_code):
    """Return a stable opaque identifier used to deduplicate one detection."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"aai:{tenant}:{device_id}:{reason_code}"))


def _endpoint_alert_view(item):
    """Project a content-minimised endpoint or behavior alert."""
    return {
        "id": item.get("id"),
        "source": item.get("source", "endpoint_evidence"),
        "severity": item.get("severity"),
        "type": item.get("type"),
        "deviceId": item.get("deviceId"),
        "deploymentId": item.get("deploymentId", ""),
        "agentId": item.get("agentId"),
        "agentKey": item.get("agentKey"),
        "host": item.get("host"),
        "message": item.get("message"),
        "reasonCode": item.get("reasonCode"),
        "behavior": _json(item.get("behavior")) if item.get("behavior") else None,
        "status": item.get("status"),
        "acknowledged": item.get("status") in {"acknowledged", "resolved"},
        "revision": int(item.get("revision", 0)),
        "firstObservedAt": int(item.get("firstObservedAt", 0)),
        "lastObservedAt": int(item.get("lastObservedAt", 0)),
        "occurrenceCount": int(item.get("occurrenceCount", 0)),
        "deduplicationKey": item.get("deduplicationKey"),
        "suppressionId": item.get("suppressionId"),
        "suppressedUntil": item.get("suppressedUntil"),
        "acknowledgedAt": item.get("acknowledgedAt"),
        "acknowledgedBy": item.get("acknowledgedBy"),
        "acknowledgementReason": item.get("acknowledgementReason"),
        "resolvedAt": item.get("resolvedAt"),
        "caseId": item.get("caseId"),
        "deliveryStatus": item.get("deliveryStatus", "pending"),
        "deliveredAt": item.get("deliveredAt"),
    }


def _alert_suppression_view(item, *, now=None):
    """Project one immutable-scope alert suppression without hidden authority."""
    current_time = int(time.time()) if now is None else int(now)
    status = item.get("status")
    if status == "active" and int(item.get("expires_at", 0)) <= current_time:
        status = "expired"
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "reason": item.get("reason"),
        "match": _json(item.get("match")),
        "status": status,
        "revision": int(item.get("revision", 0)),
        "createdAt": int(item.get("created_at", 0)),
        "createdBy": item.get("created_by"),
        "expiresAt": int(item.get("expires_at", 0)),
        "revokedAt": item.get("revoked_at"),
        "revokedBy": item.get("revoked_by"),
        "revocationReason": item.get("revocation_reason"),
        "contentHash": item.get("content_hash"),
    }


def _alert_suppression_match(value):
    """Validate the closed, exact-match language used to reduce alert noise."""
    if not isinstance(value, dict) or set(value) != {
        "sources",
        "severities",
        "reasonCodes",
        "deploymentIds",
        "agentIds",
        "deviceIds",
        "responseRuleIds",
    }:
        raise ValueError("alert suppression match has an invalid schema")
    allowed = {
        "sources": {"endpoint_evidence", "behavior_analytics"},
        "severities": {"low", "medium", "high", "critical"},
    }
    normalized = {}
    for field in (
        "sources",
        "severities",
        "reasonCodes",
        "deploymentIds",
        "agentIds",
        "deviceIds",
        "responseRuleIds",
    ):
        raw = value.get(field)
        if not isinstance(raw, list) or len(raw) > 20:
            raise ValueError(f"alert suppression {field} must be a bounded list")
        items = [_bounded_identifier(item, field) for item in raw]
        if len(set(items)) != len(items):
            raise ValueError(f"alert suppression {field} contains duplicates")
        if field in allowed and (not items or not set(items) <= allowed[field]):
            raise ValueError(f"alert suppression {field} is unsupported")
        normalized[field] = sorted(items)
    if not any(
        normalized[field]
        for field in (
            "reasonCodes",
            "deploymentIds",
            "agentIds",
            "deviceIds",
            "responseRuleIds",
        )
    ):
        raise ValueError("alert suppression requires an exact identity selector")
    return normalized


def _create_alert_suppression(tenant, body, actor):
    """Create one non-widenable, expiring suppression under responder authority."""
    if not isinstance(body, dict) or set(body) != {"id", "name", "reason", "expiresAt", "match"}:
        raise ValueError("alert suppression request has an invalid schema")
    now = int(time.time())
    suppression_id = _bounded_identifier(body.get("id"), "suppressionId")
    name = _bounded_text(body.get("name"), "name", 120)
    reason = _bounded_text(body.get("reason"), "reason", 500)
    if len(reason) < 20:
        raise ValueError("reason must contain at least 20 characters")
    if re.search(
        r"(?i)(authorization\s*:\s*bearer|-----BEGIN [A-Z ]+PRIVATE KEY-----|"
        r"(?:token|secret|password|api[_ -]?key)\s*[:=]\s*\S+)",
        reason,
    ):
        raise ValueError("reason must not contain credential material")
    expires_at = _discovery_integer(body.get("expiresAt"), "expiresAt", minimum=now + 300)
    if expires_at > now + (7 * 24 * 60 * 60):
        raise ValueError("alert suppression cannot exceed seven days")
    match = _alert_suppression_match(body.get("match"))
    active = [
        item
        for item in _list(tenant, "ALERT_SUPPRESSION", consistent_read=True)
        if item.get("status") == "active" and int(item.get("expires_at", 0)) > now
    ]
    if len(active) >= 100:
        raise ValueError("active alert suppression limit reached")
    record = {
        **_item_key(tenant, "ALERT_SUPPRESSION", suppression_id),
        "tenant_id": tenant,
        "id": suppression_id,
        "name": name,
        "reason": reason,
        "match": match,
        "status": "active",
        "revision": 1,
        "created_at": now,
        "created_by": actor,
        "expires_at": expires_at,
        "content_hash": _configuration_hash({"match": match, "expiresAt": expires_at}),
        "ttl": expires_at + (90 * 24 * 60 * 60),
    }
    try:
        TABLE.put_item(Item=record, ConditionExpression="attribute_not_exists(pk)")
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("alert suppression already exists") from error
        raise
    _audit(
        tenant,
        "alert_suppression_created",
        actor,
        {
            "suppression_id": suppression_id,
            "expires_at": expires_at,
            "match_digest": _configuration_hash(match),
        },
    )
    return _alert_suppression_view(record, now=now)


def _revoke_alert_suppression(tenant, suppression_id, body, actor):
    """Revoke a suppression without deleting its scope or evidence."""
    if not isinstance(body, dict) or set(body) != {"expectedRevision", "reason"}:
        raise ValueError("alert suppression revocation has an invalid schema")
    suppression_id = _bounded_identifier(suppression_id, "suppressionId")
    expected = _discovery_integer(body.get("expectedRevision"), "expectedRevision", minimum=1)
    reason = _bounded_text(body.get("reason"), "reason", 500)
    if len(reason) < 20:
        raise ValueError("reason must contain at least 20 characters")
    if re.search(
        r"(?i)(authorization\s*:\s*bearer|-----BEGIN [A-Z ]+PRIVATE KEY-----|"
        r"(?:token|secret|password|api[_ -]?key)\s*[:=]\s*\S+)",
        reason,
    ):
        raise ValueError("reason must not contain credential material")
    key = _item_key(tenant, "ALERT_SUPPRESSION", suppression_id)
    current = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    if not current:
        raise LookupError("alert suppression not found")
    if int(current.get("revision", 0)) != expected or current.get("status") != "active":
        raise PolicyConflict("alert suppression is no longer active at that revision")
    now = int(time.time())
    revoked = {
        **current,
        "status": "revoked",
        "revision": expected + 1,
        "revoked_at": now,
        "revoked_by": actor,
        "revocation_reason": reason,
    }
    try:
        TABLE.put_item(
            Item=revoked,
            ConditionExpression="revision = :expected_revision",
            ExpressionAttributeValues={":expected_revision": expected},
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("alert suppression revision changed") from error
        raise
    _audit(
        tenant,
        "alert_suppression_revoked",
        actor,
        {"suppression_id": suppression_id, "revision": expected + 1},
    )
    return _alert_suppression_view(revoked, now=now)


def _matching_alert_suppression(tenant, alert, *, now):
    """Return the first exact active suppression; expiry fails open for detection."""
    matches = []
    for item in _list(tenant, "ALERT_SUPPRESSION", consistent_read=True):
        try:
            expires_at = int(item.get("expires_at", 0))
            match = _alert_suppression_match(item.get("match"))
            integrity_valid = item.get("content_hash") == _configuration_hash(
                {"match": match, "expiresAt": expires_at}
            )
        except (TypeError, ValueError):
            # Invalid stored state must restore alerting, never create silence.
            continue
        if item.get("status") != "active" or expires_at <= now or not integrity_valid:
            continue
        behavior = alert.get("behavior") or {}
        comparisons = {
            "sources": alert.get("source"),
            "severities": alert.get("severity"),
            "reasonCodes": alert.get("reasonCode"),
            "deploymentIds": alert.get("deploymentId"),
            "agentIds": alert.get("agentId"),
            "deviceIds": alert.get("deviceId"),
            "responseRuleIds": behavior.get("ruleId"),
        }
        if all(
            not match.get(field) or value in match[field] for field, value in comparisons.items()
        ):
            matches.append(item)
    matches.sort(key=lambda item: (int(item.get("expires_at", 0)), str(item.get("id", ""))))
    return matches[0] if matches else None


def _publish_endpoint_alert(tenant, alert):
    """Deliver one normalized alert to the durable AWS operations channel.

    SNS/SQS is the built-in control-plane channel, not a claim of Splunk
    delivery. The deterministic alert and revision let consumers deduplicate
    SNS's intentional at-least-once delivery.
    """
    topic_arn = os.environ.get("SECURITY_ALERTS_TOPIC_ARN", "")
    if not topic_arn:
        return False
    SNS.publish(
        TopicArn=topic_arn,
        Subject=f"AAI security alert: {alert['type']}",
        Message=json.dumps(
            {
                "schemaVersion": 1,
                "tenantId": tenant,
                "alertId": alert["id"],
                "revision": int(alert["revision"]),
                "source": alert.get("source", "endpoint_evidence"),
                "severity": alert["severity"],
                "type": alert["type"],
                "deviceId": alert.get("deviceId", ""),
                "deploymentId": alert.get("deploymentId", ""),
                "agentId": alert.get("agentId", ""),
                "reasonCode": alert["reasonCode"],
                "observedAt": int(alert["lastObservedAt"]),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        MessageAttributes={
            "tenantId": {"DataType": "String", "StringValue": tenant},
            "severity": {"DataType": "String", "StringValue": alert["severity"]},
            "source": {
                "DataType": "String",
                "StringValue": alert.get("source", "endpoint_evidence"),
            },
        },
    )
    return True


def _queue_endpoint_alert_webhooks(tenant, alert):
    """Materialize one deduplicated webhook outbox record per active destination."""
    if alert.get("source") == "behavior_analytics":
        # Behavior identities include the deterministic evaluation window, so
        # a later recurrence is a new explainable alert rather than a mutation
        # of evidence from an earlier window.
        event_type = "behavior.alert.opened"
    else:
        event_type = (
            "endpoint.alert.reopened" if alert.get("reopenedAt") else "endpoint.alert.opened"
        )
    occurrence = int(alert.get("reopenedAt") or alert.get("firstObservedAt") or 0)
    for destination in _list(tenant, "WEBHOOK", consistent_read=True):
        if destination.get("status") != "active" or event_type not in destination.get(
            "event_types", []
        ):
            continue
        delivery_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"aai-webhook:{tenant}:{destination.get('id')}:{alert.get('id')}:{occurrence}",
            )
        )
        if TABLE.get_item(
            Key=_item_key(tenant, "WEBHOOK_DELIVERY", delivery_id), ConsistentRead=True
        ).get("Item"):
            continue
        try:
            _enqueue_webhook_delivery(
                tenant,
                destination,
                event_type,
                {
                    "alertId": alert.get("id"),
                    "severity": alert.get("severity"),
                    "type": alert.get("type"),
                    "deviceId": alert.get("deviceId"),
                    "deploymentId": alert.get("deploymentId"),
                    "agentId": alert.get("agentId"),
                    "reasonCode": alert.get("reasonCode"),
                    "observedAt": int(alert.get("lastObservedAt", 0)),
                },
                now=occurrence,
                delivery_id=delivery_id,
            )
        except Exception as error:
            if not _is_conditional_conflict(error):
                raise


def _deliver_pending_endpoint_alerts(tenant):
    """Retry undelivered active alerts without losing their durable record."""
    for alert in _list(tenant, "ALERT", consistent_read=True):
        if alert.get("source") in {"endpoint_evidence", "behavior_analytics"} and alert.get(
            "status"
        ) not in {"resolved", "suppressed"}:
            _queue_endpoint_alert_webhooks(tenant, alert)
        if (
            alert.get("source") not in {"endpoint_evidence", "behavior_analytics"}
            or alert.get("status") in {"resolved", "suppressed"}
            or alert.get("deliveryStatus") == "delivered"
        ):
            continue
        try:
            if not _publish_endpoint_alert(tenant, alert):
                continue
            delivered = {
                **alert,
                "deliveryStatus": "delivered",
                "deliveredAt": int(time.time()),
                "revision": int(alert.get("revision", 0)) + 1,
            }
            TABLE.put_item(
                Item=delivered,
                ConditionExpression="revision = :expected_revision",
                ExpressionAttributeValues={":expected_revision": int(alert.get("revision", 0))},
            )
        except Exception:
            # The durable alert remains pending and the scheduled reconciler
            # retries it. Never include provider exception text or alert data
            # in Lambda logs at this credential-bearing boundary.
            print(json.dumps({"warning": "security alert delivery remains pending"}))


def _open_endpoint_alert(tenant, device_id, reason_code, *, now, reopen_acknowledged=False):
    """Create or reopen one deduplicated endpoint alert."""
    definition = _ENDPOINT_ALERT_DEFINITIONS.get(reason_code)
    if not definition:
        return None
    severity, alert_type, message = definition
    alert_id = _endpoint_alert_id(tenant, device_id, reason_code)
    key = _item_key(tenant, "ALERT", alert_id)
    existing = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    if existing and existing.get("status") in {"open", "acknowledged"}:
        if existing.get("status") == "open" or not reopen_acknowledged:
            return existing
    revision = int(existing.get("revision", 0)) if existing else 0
    record = {
        **key,
        "tenant_id": tenant,
        "id": alert_id,
        "source": "endpoint_evidence",
        "severity": severity,
        "type": alert_type,
        "deviceId": device_id,
        "message": message,
        "reasonCode": reason_code,
        "status": "open",
        "revision": revision + 1,
        "firstObservedAt": int(existing.get("firstObservedAt", now)) if existing else now,
        "lastObservedAt": now,
        "occurrenceCount": int(existing.get("occurrenceCount", 0)) + 1 if existing else 1,
        "deduplicationKey": alert_id,
        "deliveryStatus": "pending",
        "reopenedAt": now if existing else None,
    }
    suppression = _matching_alert_suppression(tenant, record, now=now)
    if (
        existing
        and existing.get("status") == "suppressed"
        and suppression
        and existing.get("suppressionId") == suppression.get("id")
    ):
        return existing
    if suppression:
        record.update(
            {
                "status": "suppressed",
                "suppressionId": suppression["id"],
                "suppressedUntil": int(suppression["expires_at"]),
                "deliveryStatus": "suppressed",
            }
        )
    arguments = {"Item": record}
    if existing:
        arguments.update(
            {
                "ConditionExpression": "revision = :expected_revision",
                "ExpressionAttributeValues": {":expected_revision": revision},
            }
        )
    else:
        arguments["ConditionExpression"] = "attribute_not_exists(pk)"
    try:
        TABLE.put_item(**arguments)
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("endpoint alert changed concurrently") from error
        raise
    _audit(
        tenant,
        "endpoint_alert_suppressed"
        if suppression
        else "endpoint_alert_opened"
        if not existing
        else "endpoint_alert_reopened",
        "system:endpoint-detection",
        {
            "alert_id": alert_id,
            "device_id": device_id,
            "reason_code": reason_code,
            "severity": severity,
            "revision": revision + 1,
            "suppression_id": suppression.get("id") if suppression else None,
        },
    )
    return record


def _reconcile_endpoint_alerts(tenant, health, *, now=None, automatic_response=False):
    """Materialize endpoint health and optionally run scheduled response authority."""
    current_time = int(time.time()) if now is None else int(now)
    active_keys = set()
    for device in health.get("items", []):
        device_id = _bounded_identifier(device.get("deviceId"), "deviceId")
        reasons = set(device.get("reasonCodes", []))
        # One unenrolled device needs one actionable alert, not a second
        # derivative "report missing" alert for the same root condition.
        if "credential_not_configured" in reasons:
            reasons.discard("report_missing")
        for reason_code in sorted(reasons & set(_ENDPOINT_ALERT_DEFINITIONS)):
            active_keys.add((device_id, reason_code))
            _open_endpoint_alert(tenant, device_id, reason_code, now=current_time)
    for alert in _list(tenant, "ALERT", consistent_read=True):
        if alert.get("source") != "endpoint_evidence" or alert.get("status") == "resolved":
            continue
        identity = (alert.get("deviceId"), alert.get("reasonCode"))
        # Event alerts represent observed attacks rather than continuous
        # posture and require acknowledgement; health reconciliation must not
        # silently resolve them on the next clean report.
        if alert.get("reasonCode") in {"signature_invalid", "report_replayed"}:
            continue
        if identity in active_keys:
            continue
        revision = int(alert.get("revision", 0))
        resolved = {
            **alert,
            "status": "resolved",
            "resolvedAt": current_time,
            "resolvedBy": "system:endpoint-detection",
            "revision": revision + 1,
        }
        try:
            TABLE.put_item(
                Item=resolved,
                ConditionExpression="revision = :expected_revision",
                ExpressionAttributeValues={":expected_revision": revision},
            )
        except Exception as error:
            if _is_conditional_conflict(error):
                raise PolicyConflict("endpoint alert changed concurrently") from error
            raise
        _audit(
            tenant,
            "endpoint_alert_resolved",
            "system:endpoint-detection",
            {"alert_id": alert.get("id"), "device_id": alert.get("deviceId")},
        )
    # Consequential automatic response is reached only from the scheduled
    # detector or an authenticated security-event write. Operator GET routes
    # may reconcile display evidence but cannot trigger containment by reading.
    if automatic_response:
        _evaluate_response_rules(tenant, now=current_time)
    _deliver_pending_endpoint_alerts(tenant)
    return [
        _endpoint_alert_view(item)
        for item in sorted(
            _list(tenant, "ALERT", consistent_read=True),
            key=lambda value: (int(value.get("lastObservedAt", 0)), str(value.get("id", ""))),
            reverse=True,
        )
        if item.get("source") == "endpoint_evidence"
    ]


def _record_endpoint_event_alert(tenant, device_id, reason_code):
    """Retain one authenticated sensor security event without changing its denial."""
    try:
        _open_endpoint_alert(
            tenant,
            device_id,
            reason_code,
            now=int(time.time()),
            reopen_acknowledged=True,
        )
        _evaluate_response_rules(tenant)
        _deliver_pending_endpoint_alerts(tenant)
    except Exception:
        print(json.dumps({"warning": "endpoint security event alert persistence failed"}))


def _acknowledge_endpoint_alert(tenant, alert_id, body, actor):
    """Acknowledge one live alert with optimistic concurrency and rationale."""
    if not isinstance(body, dict) or set(body) != {"expectedRevision", "reason"}:
        raise ValueError("alert acknowledgement has an invalid schema")
    alert_id = _bounded_identifier(alert_id, "alertId")
    expected = _discovery_integer(body.get("expectedRevision"), "expectedRevision", minimum=1)
    reason = _bounded_text(body.get("reason"), "reason", 500)
    if len(reason) < 20:
        raise ValueError("reason must contain at least 20 characters")
    if re.search(
        r"(?i)(authorization\s*:\s*bearer|-----BEGIN [A-Z ]+PRIVATE KEY-----|"
        r"(?:token|secret|password|api[_ -]?key)\s*[:=]\s*\S+)",
        reason,
    ):
        raise ValueError("reason must not contain credential material")
    key = _item_key(tenant, "ALERT", alert_id)
    alert = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    if not alert or alert.get("source") not in {"endpoint_evidence", "behavior_analytics"}:
        raise LookupError("security alert not found")
    if int(alert.get("revision", 0)) != expected:
        raise PolicyConflict("security alert revision changed")
    if alert.get("status") != "open":
        raise PolicyConflict("only an open endpoint alert can be acknowledged")
    acknowledged = {
        **alert,
        "status": "acknowledged",
        "acknowledgedAt": int(time.time()),
        "acknowledgedBy": actor,
        "acknowledgementReason": reason,
        "revision": expected + 1,
    }
    try:
        TABLE.put_item(
            Item=acknowledged,
            ConditionExpression="revision = :expected_revision",
            ExpressionAttributeValues={":expected_revision": expected},
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("security alert revision changed") from error
        raise
    _audit(
        tenant,
        "security_alert_acknowledged",
        actor,
        {
            "alert_id": alert_id,
            "source": alert.get("source"),
            "device_id": alert.get("deviceId"),
            "agent_key": alert.get("agentKey"),
            "revision": expected + 1,
        },
    )
    return _endpoint_alert_view(acknowledged)


def _case_reason(value, field="reason"):
    """Return bounded investigation text after rejecting credential-shaped content."""
    reason = _bounded_text(value, field, 500)
    if len(reason) < 20:
        raise ValueError(f"{field} must contain at least 20 characters")
    if re.search(
        r"(?i)(authorization\s*:\s*bearer|-----BEGIN [A-Z ]+PRIVATE KEY-----|"
        r"(?:token|secret|password|api[_ -]?key)\s*[:=]\s*\S+)",
        reason,
    ):
        raise ValueError(f"{field} must not contain credential material")
    return reason


def _endpoint_agent_binding(tenant, device_id, *, now=None):
    """Resolve one endpoint installation to exactly one active enrolled agent.

    The device report is observational. This resolver derives correlation only
    from a current MDM device, a fresh signed report, an exact host and the
    server-side digest of a registered project root. It never accepts an agent
    identifier from an operator request or endpoint payload.
    """
    current_time = int(time.time()) if now is None else int(now)
    base = {
        "status": "unbound",
        "reasonCode": "binding_unavailable",
        "deviceId": device_id,
        "agentKey": None,
        "deploymentId": None,
        "agentId": None,
        "host": None,
        "projectRootDigest": None,
        "installationIds": [],
        "evidenceRevision": None,
        "evidenceObservedAt": None,
        "evidenceDigest": None,
        "agentLifecycleRevision": None,
        "groupIds": [],
        "policyId": None,
        "policyVersion": None,
    }
    try:
        devices = _authoritative_endpoint_devices(tenant, now=current_time)
    except (LookupError, PolicyConflict, ValueError):
        return {**base, "reasonCode": "endpoint_inventory_not_current"}
    device = devices.get(device_id)
    if not device or device.get("managed") is not True:
        return {**base, "reasonCode": "managed_device_not_current"}
    report = TABLE.get_item(
        Key=_item_key(tenant, "ENDPOINT_EVIDENCE", device_id), ConsistentRead=True
    ).get("Item")
    if not report:
        return {**base, "reasonCode": "signed_report_missing"}
    observed_at = int(report.get("observedAt", 0))
    if (
        observed_at <= current_time - _ENDPOINT_EVIDENCE_MAX_AGE_SECONDS
        or observed_at > current_time + _ENDPOINT_EVIDENCE_FUTURE_SKEW_SECONDS
    ):
        return {**base, "reasonCode": "signed_report_not_current"}
    payload = report.get("payload")
    installations = payload.get("installations", []) if isinstance(payload, dict) else []
    agents = [
        agent
        for agent in _all_agents(tenant, consistent_read=True)
        if _agent_lifecycle_state(agent) == "active"
        # Incident response must not claim a usable binding for a legacy
        # identity that lacks explicit optimistic-concurrency or session
        # authority. Those records remain visible for migration but cannot be
        # selected for a consequential response mutation.
        and _stored_agent_lifecycle_revision(agent.get("lifecycle_revision")) is not None
        and _agent_session_revision(agent) is not None
    ]
    candidates = {}
    installation_ids = {}
    for installation in installations:
        if not isinstance(installation, dict):
            continue
        digest = installation.get("projectRootDigest")
        host = installation.get("host")
        if not isinstance(digest, str) or not isinstance(host, str):
            continue
        for agent in agents:
            project_root = agent.get("project_root")
            if (
                agent.get("host") == host
                and isinstance(project_root, str)
                and project_root
                and secrets.compare_digest(
                    hashlib.sha256(project_root.encode()).hexdigest(), digest
                )
            ):
                key = f"{agent.get('deployment_id')}:{agent.get('id')}"
                candidates[key] = (agent, host, digest)
                installation_ids.setdefault(key, set()).add(installation.get("id", ""))
    if not candidates:
        return {
            **base,
            "reasonCode": "no_enrolled_agent_match",
            "evidenceRevision": int(report.get("revision", 0)),
            "evidenceObservedAt": observed_at,
            "evidenceDigest": report.get("reportDigest"),
        }
    if len(candidates) != 1:
        return {
            **base,
            "status": "ambiguous",
            "reasonCode": "multiple_enrolled_agent_matches",
            "evidenceRevision": int(report.get("revision", 0)),
            "evidenceObservedAt": observed_at,
            "evidenceDigest": report.get("reportDigest"),
        }
    agent_key, (agent, host, project_digest) = next(iter(candidates.items()))
    groups = [
        group
        for group in _list(tenant, "GROUP", consistent_read=True)
        if agent_key in group.get("agent_keys", [])
    ]
    policy = None
    if len(groups) == 1:
        policy = TABLE.get_item(
            Key=_item_key(tenant, "POLICY", groups[0].get("policyId", "")),
            ConsistentRead=True,
        ).get("Item")
    binding = {
        **base,
        "status": "bound",
        "reasonCode": "unique_current_match",
        "agentKey": agent_key,
        "deploymentId": agent.get("deployment_id"),
        "agentId": agent.get("id"),
        "host": host,
        "projectRootDigest": project_digest,
        "installationIds": sorted(value for value in installation_ids[agent_key] if value),
        "evidenceRevision": int(report.get("revision", 0)),
        "evidenceObservedAt": observed_at,
        "evidenceDigest": report.get("reportDigest"),
        "agentLifecycleRevision": int(agent.get("lifecycle_revision", 0)),
        "groupIds": sorted(str(group.get("id")) for group in groups),
        "policyId": policy.get("id") if policy else None,
        "policyVersion": int(policy.get("version", 0)) if policy else None,
    }
    digest_material = {key: value for key, value in binding.items() if key != "bindingDigest"}
    return {
        **binding,
        "bindingDigest": hashlib.sha256(
            json.dumps(digest_material, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def _behavior_agent_binding(tenant, alert):
    """Revalidate the enrolled agent identity attached to a behavior alert.

    The authenticated agent session selected the alert identity when the
    observation was received. The retained alert is still observational, so
    every consequential case action reloads lifecycle, assignment and policy
    state rather than trusting a browser or the original report.
    """
    agent_key = str(alert.get("agentKey", ""))
    base = {
        "status": "unbound",
        "reasonCode": "behavior_binding_unavailable",
        "deviceId": "",
        "agentKey": None,
        "deploymentId": None,
        "agentId": None,
        "host": None,
        "projectRootDigest": None,
        "installationIds": [],
        "evidenceRevision": None,
        "evidenceObservedAt": None,
        "evidenceDigest": None,
        "agentLifecycleRevision": None,
        "groupIds": [],
        "policyId": None,
        "policyVersion": None,
    }
    if not agent_key or ":" not in agent_key:
        return base
    agent = TABLE.get_item(Key=_item_key(tenant, "AGENT", agent_key), ConsistentRead=True).get(
        "Item"
    )
    if (
        not agent
        or _agent_lifecycle_state(agent) != "active"
        or _stored_agent_lifecycle_revision(agent.get("lifecycle_revision")) is None
        or _agent_session_revision(agent) is None
        or agent.get("deployment_id") != alert.get("deploymentId")
        or agent.get("id") != alert.get("agentId")
    ):
        return base
    groups = [
        group
        for group in _list(tenant, "GROUP", consistent_read=True)
        if agent_key in group.get("agent_keys", [])
    ]
    if len(groups) != 1:
        return {**base, "reasonCode": "behavior_policy_assignment_unavailable"}
    policy = TABLE.get_item(
        Key=_item_key(tenant, "POLICY", groups[0].get("policyId", "")),
        ConsistentRead=True,
    ).get("Item")
    if not policy or int(policy.get("version", 0)) <= 0:
        return {**base, "reasonCode": "behavior_policy_unavailable"}
    project_root = agent.get("project_root")
    binding = {
        **base,
        "status": "bound",
        "reasonCode": "authenticated_agent_activity",
        "agentKey": agent_key,
        "deploymentId": agent.get("deployment_id"),
        "agentId": agent.get("id"),
        "host": agent.get("host"),
        "projectRootDigest": hashlib.sha256(project_root.encode()).hexdigest()
        if isinstance(project_root, str) and project_root
        else None,
        # Alert lifecycle revisions change when a case is attached or the
        # alert is acknowledged. Bind response authority to the immutable rule
        # version and evidence digest instead of that presentation lifecycle.
        "evidenceRevision": int((alert.get("behavior") or {}).get("ruleVersion", 0)),
        "evidenceObservedAt": int(alert.get("lastObservedAt", 0)),
        "evidenceDigest": (alert.get("behavior") or {}).get("evidenceDigest"),
        "agentLifecycleRevision": int(agent.get("lifecycle_revision", 0)),
        "groupIds": [str(groups[0].get("id"))],
        "policyId": policy.get("id"),
        "policyVersion": int(policy.get("version", 0)),
    }
    return {
        **binding,
        "bindingDigest": _configuration_hash(binding),
    }


def _case_current_binding(tenant, case):
    """Resolve the current binding for either supported case alert source."""
    alert = TABLE.get_item(
        Key=_item_key(tenant, "ALERT", case.get("alertId", "")), ConsistentRead=True
    ).get("Item")
    if not alert:
        return {"status": "unbound", "reasonCode": "source_alert_unavailable"}
    if alert.get("source") == "behavior_analytics":
        return _behavior_agent_binding(tenant, alert)
    if alert.get("source") == "endpoint_evidence":
        return _endpoint_agent_binding(tenant, alert.get("deviceId", ""))
    return {"status": "unbound", "reasonCode": "source_alert_unsupported"}


def _case_timeline_record(tenant, case_id, event_type, actor, payload, *, now, sequence):
    """Build one append-only, content-minimised case timeline event."""
    event_id = str(uuid.uuid4())
    return {
        **_item_key(tenant, "CASE_EVENT", f"{case_id}:{sequence:08d}:{event_id}"),
        "tenant_id": tenant,
        "id": event_id,
        "case_id": case_id,
        "eventType": event_type,
        "actor": actor,
        "occurredAt": now,
        "sequence": sequence,
        "payload": payload,
        "payloadHash": hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def _transaction_condition(key, *, condition, names=None, values=None):
    """Build one explicit DynamoDB transaction condition check."""
    operation = {
        "TableName": CONTROL_TABLE_NAME,
        "Key": _ddb_item(key),
        "ConditionExpression": condition,
    }
    if names:
        operation["ExpressionAttributeNames"] = names
    if values:
        operation["ExpressionAttributeValues"] = _ddb_item(values)
    return {"ConditionCheck": operation}


def _transact_incident_response(operations):
    """Atomically commit case authority and its primary timeline evidence."""
    try:
        DYNAMODB.transact_write_items(TransactItems=operations)
    except Exception as error:
        code = getattr(error, "response", {}).get("Error", {}).get("Code")
        if code in {"ConditionalCheckFailedException", "TransactionCanceledException"}:
            raise PolicyConflict("incident response state changed concurrently") from error
        raise


def _case_events(tenant, case_id):
    """Return a bounded ordered timeline for one tenant case."""
    events = [
        item
        for item in _list(tenant, "CASE_EVENT", consistent_read=True)
        if item.get("case_id") == case_id
    ]
    if len(events) > 500:
        raise RuntimeError("case timeline exceeds its safe bound")
    return sorted(events, key=lambda item: (int(item.get("sequence", 0)), str(item.get("id"))))


def _case_view(tenant, case, *, detailed=False):
    """Project one case without raw activity, endpoint payloads or credentials."""
    binding = _json(case.get("binding", {}))
    current_binding = _case_current_binding(tenant, case)
    binding_current = bool(
        binding.get("status") == "bound"
        and current_binding.get("status") == "bound"
        and secrets.compare_digest(
            str(binding.get("bindingDigest", "")),
            str(current_binding.get("bindingDigest", "")),
        )
    )
    result = {
        "id": case.get("id"),
        "alertId": case.get("alertId"),
        "title": case.get("title"),
        "severity": case.get("severity"),
        "reasonCode": case.get("reasonCode"),
        "deviceId": case.get("deviceId"),
        "alertSource": case.get("alertSource", "endpoint_evidence"),
        "ownerId": case.get("ownerId"),
        "status": case.get("status"),
        "revision": int(case.get("revision", 0)),
        "createdAt": int(case.get("createdAt", 0)),
        "updatedAt": int(case.get("updatedAt", 0)),
        "binding": binding,
        "bindingCurrent": binding_current,
        "currentBindingStatus": current_binding.get("status"),
        "containment": case.get("containment"),
        "sessionRevokedAt": case.get("sessionRevokedAt"),
        "resolvedAt": case.get("resolvedAt"),
        "closedAt": case.get("closedAt"),
    }
    if not detailed:
        return result
    alert = TABLE.get_item(
        Key=_item_key(tenant, "ALERT", case.get("alertId", "")), ConsistentRead=True
    ).get("Item")
    agent_key = binding.get("agentKey")
    decisions, decisions_truncated = _decision_window(tenant)
    correlated_decisions = [
        _decision_view(item)
        for item in decisions
        if agent_key
        and item.get("deployment_id") == binding.get("deploymentId")
        and item.get("agent_id") == binding.get("agentId")
    ][:100]
    approvals = [
        _approval_view(item, int(time.time()))
        for item in _list(tenant, "APPROVAL", consistent_read=True)
        if agent_key and item.get("agent_key") == agent_key
    ][:100]
    return {
        **result,
        "alert": _endpoint_alert_view(alert) if alert else None,
        "timeline": [_json(item) for item in _case_events(tenant, case["id"])],
        "decisions": correlated_decisions,
        "decisionsTruncated": decisions_truncated or len(correlated_decisions) == 100,
        "approvals": approvals,
        "evidence": {
            "endpointReportDigest": binding.get("evidenceDigest"),
            "endpointReportRevision": binding.get("evidenceRevision"),
            "endpointObservedAt": binding.get("evidenceObservedAt"),
            "projectRootDigest": binding.get("projectRootDigest"),
            "rawContentIncluded": False,
            "credentialsIncluded": False,
        },
    }


def _case_export_event(item):
    """Project and verify one content-minimised timeline event for export."""
    payload = _json(item.get("payload", {}))
    expected_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    stored_hash = str(item.get("payloadHash", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", stored_hash) or not secrets.compare_digest(
        stored_hash, expected_hash
    ):
        raise RuntimeError("case timeline integrity verification failed")
    return {
        "id": item.get("id"),
        "eventType": item.get("eventType"),
        "actor": item.get("actor"),
        "occurredAt": int(item.get("occurredAt", 0)),
        "sequence": int(item.get("sequence", 0)),
        "payload": payload,
        "payloadHash": stored_hash,
    }


def _case_export_approval(item, now):
    """Project approval evidence without exporting free-form operator text.

    Approval bindings and outcomes are required to reconstruct the decision
    path. The optional decision reason is deliberately excluded because it can
    contain investigation narrative that was never approved for portability.
    """
    view = _approval_view(item, now)
    view.pop("decisionReason", None)
    view["decisionReasonIncluded"] = False
    return view


def _case_export(tenant, case_id, actor):
    """Build one complete bounded case package and retain its export digest.

    The export is assembled only from strongly read server-owned records. It
    refuses unsafe bounds or concurrent case/alert changes instead of labelling
    a partial package complete.
    """
    generated_at = int(time.time())
    evidence_cutoff = max(0, generated_at - 1)
    case = _case_record(tenant, case_id)
    case_revision = int(case.get("revision", 0))
    alert = TABLE.get_item(
        Key=_item_key(tenant, "ALERT", case.get("alertId", "")), ConsistentRead=True
    ).get("Item")
    if not alert or alert.get("source") not in {"endpoint_evidence", "behavior_analytics"}:
        raise RuntimeError("case source alert is unavailable for export")
    alert_revision = int(alert.get("revision", 0))
    timeline = [_case_export_event(item) for item in _case_events(tenant, case["id"])]
    if len(timeline) > _CASE_EXPORT_RECORD_LIMIT:
        raise RuntimeError("case timeline exceeds the export bound")

    binding = _json(case.get("binding", {}))
    first_observed = int(alert.get("firstObservedAt", case.get("createdAt", 0)))
    correlation_start = max(
        0,
        min(int(case.get("createdAt", 0)), first_observed) - _CASE_EXPORT_LOOKBACK_SECONDS,
    )
    deployment_id = binding.get("deploymentId")
    agent_id = binding.get("agentId")
    decisions = []
    approvals = []
    if isinstance(deployment_id, str) and deployment_id and isinstance(agent_id, str) and agent_id:
        decisions = [
            _decision_view(item)
            for item in _list(tenant, "DECISION", consistent_read=True)
            if item.get("deployment_id") == deployment_id
            and item.get("agent_id") == agent_id
            and correlation_start <= int(item.get("observed_at", 0)) <= evidence_cutoff
        ]
        decisions.sort(key=lambda item: (item.get("timestamp", ""), item.get("id", "")))
        agent_key = f"{deployment_id}:{agent_id}"
        approvals = [
            _case_export_approval(item, generated_at)
            for item in _list(tenant, "APPROVAL", consistent_read=True)
            if item.get("agent_key") == agent_key
            and correlation_start
            <= int(item.get("requested_at", item.get("created_at", 0)))
            <= evidence_cutoff
        ]
        approvals.sort(key=lambda item: (int(item.get("requestedAt", 0)), item.get("id", "")))
    if len(decisions) > _CASE_EXPORT_RECORD_LIMIT:
        raise RuntimeError("correlated decisions exceed the case export bound")
    if len(approvals) > _CASE_EXPORT_RECORD_LIMIT:
        raise RuntimeError("correlated approvals exceed the case export bound")

    # Re-read the revisioned roots after assembly. A concurrent mutation must
    # make the export retry rather than produce a mixed-state evidence package.
    current_case = _case_record(tenant, case_id)
    current_alert = TABLE.get_item(
        Key=_item_key(tenant, "ALERT", case.get("alertId", "")), ConsistentRead=True
    ).get("Item")
    if int(current_case.get("revision", 0)) != case_revision or not current_alert:
        raise PolicyConflict("incident case changed during export")
    if int(current_alert.get("revision", 0)) != alert_revision:
        raise PolicyConflict("source alert changed during export")

    case_snapshot = _case_view(tenant, case)
    content = {
        "artifactType": "aai.incident-case",
        "tenantId": tenant,
        "caseId": case["id"],
        "caseRevision": case_revision,
        "generatedAt": generated_at,
        "generatedBy": actor,
        "correlationWindow": {
            "startAt": correlation_start,
            "endAt": evidence_cutoff,
            "basis": "24_hours_before_first_alert_observation",
        },
        "case": case_snapshot,
        "alert": _endpoint_alert_view(alert),
        "timeline": timeline,
        "decisions": decisions,
        "approvals": approvals,
        "evidence": {
            "endpointReportDigest": binding.get("evidenceDigest"),
            "endpointReportRevision": binding.get("evidenceRevision"),
            "endpointObservedAt": binding.get("evidenceObservedAt"),
            "projectRootDigest": binding.get("projectRootDigest"),
            "behaviorEvidenceDigest": binding.get("evidenceDigest")
            if alert.get("source") == "behavior_analytics"
            else None,
        },
        "completeness": {
            "complete": True,
            "decisionsTruncated": False,
            "rawContentIncluded": False,
            "credentialsIncluded": False,
            "approvalDecisionReasonsIncluded": False,
            "counts": {
                "timelineEvents": len(timeline),
                "decisions": len(decisions),
                "approvals": len(approvals),
            },
            "recordLimitPerCollection": _CASE_EXPORT_RECORD_LIMIT,
        },
    }
    # boto3 deserializes every DynamoDB number as Decimal. Convert the complete
    # artifact at the API boundary before hashing so the digest binds exactly
    # the JSON-safe value returned to browsers and offline verifiers.
    content = _json(content)
    canonical = json.dumps(
        content,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    content_hash = hashlib.sha256(canonical).hexdigest()
    receipt = _audit(
        tenant,
        "incident_case_exported",
        actor,
        {
            "case_id": case["id"],
            "case_revision": case_revision,
            "content_hash": content_hash,
        },
    )
    return {
        "schemaVersion": 1,
        "content": content,
        "integrity": {
            "algorithm": "SHA-256",
            "canonicalization": "AAI canonical JSON v1",
            "contentHash": content_hash,
        },
        "auditReceipt": receipt,
    }


def _response_rule_version_identifier(rule_id, version):
    """Return one unambiguous immutable response-rule version identifier."""
    return f"{rule_id}:v{int(version):08d}"


def _response_rule_configuration(value):
    """Validate the closed endpoint-response or alert-only behavior language."""
    if not isinstance(value, dict) or "match" not in value:
        raise ValueError("response rule configuration has an invalid schema")
    match = value.get("match")
    if not isinstance(match, dict):
        raise ValueError("response rule match has an invalid schema")
    source = match.get("source")
    if source == "agent_activity":
        if set(value) != {"match", "action", "baseline", "priority"} or set(match) != {
            "source",
            "signalTypes",
            "hosts",
            "severity",
        }:
            raise ValueError("behavior rule configuration has an invalid schema")
        signal_types = match.get("signalTypes")
        if (
            not isinstance(signal_types, list)
            or not signal_types
            or len(signal_types) > len(_BEHAVIOR_SIGNAL_TYPES)
            or any(item not in _BEHAVIOR_SIGNAL_TYPES for item in signal_types)
        ):
            raise ValueError("behavior rule signalTypes are unsupported")
        hosts = match.get("hosts")
        if (
            not isinstance(hosts, list)
            or not hosts
            or len(hosts) > 2
            or any(item not in {"claude-code", "codex"} for item in hosts)
        ):
            raise ValueError("behavior rule hosts are unsupported")
        severity = match.get("severity")
        if severity not in {"medium", "high", "critical"}:
            raise ValueError("behavior rule severity is unsupported")
        if value.get("action") != {"type": "create_alert"}:
            raise ValueError("behavior rule action must be create_alert")
        baseline = value.get("baseline")
        if not isinstance(baseline, dict) or set(baseline) != {
            "lookbackDays",
            "currentWindowMinutes",
            "minimumBaselineEvents",
            "minimumCurrentEvents",
            "sensitivityMultiplier",
        }:
            raise ValueError("behavior rule baseline has an invalid schema")
        multiplier = baseline.get("sensitivityMultiplier")
        if (
            isinstance(multiplier, bool)
            or not isinstance(multiplier, (int, float, Decimal))
            or not math.isfinite(float(multiplier))
            or not 1.5 <= float(multiplier) <= 10.0
        ):
            raise ValueError("sensitivityMultiplier must be between 1.5 and 10")
        priority = _discovery_integer(value.get("priority"), "priority", minimum=1, maximum=1_000)
        return {
            "match": {
                "source": "agent_activity",
                "signalTypes": sorted(set(signal_types)),
                "hosts": sorted(set(hosts)),
                "severity": severity,
            },
            "action": {"type": "create_alert"},
            "baseline": {
                "lookbackDays": _discovery_integer(
                    baseline.get("lookbackDays"), "lookbackDays", minimum=1, maximum=30
                ),
                "currentWindowMinutes": _discovery_integer(
                    baseline.get("currentWindowMinutes"),
                    "currentWindowMinutes",
                    minimum=5,
                    maximum=60,
                ),
                "minimumBaselineEvents": _discovery_integer(
                    baseline.get("minimumBaselineEvents"),
                    "minimumBaselineEvents",
                    minimum=1,
                    maximum=_BEHAVIOR_HISTORY_LIMIT,
                ),
                "minimumCurrentEvents": _discovery_integer(
                    baseline.get("minimumCurrentEvents"),
                    "minimumCurrentEvents",
                    minimum=1,
                    maximum=100,
                ),
                "sensitivityMultiplier": float(multiplier),
            },
            "priority": priority,
        }
    if set(value) != {"match", "action", "safeguards", "priority"}:
        raise ValueError("response rule configuration has an invalid schema")
    action = value.get("action")
    safeguards = value.get("safeguards")
    if set(match) != {
        "source",
        "reasonCodes",
        "severities",
        "hosts",
    }:
        raise ValueError("response rule match has an invalid schema")
    if match.get("source") != "endpoint_evidence":
        raise ValueError("response rule source must be endpoint_evidence")
    reason_codes = match.get("reasonCodes")
    if (
        not isinstance(reason_codes, list)
        or not reason_codes
        or len(reason_codes) > len(_ENDPOINT_ALERT_DEFINITIONS)
        or any(
            not isinstance(item, str) or item not in _ENDPOINT_ALERT_DEFINITIONS
            for item in reason_codes
        )
    ):
        raise ValueError("response rule reasonCodes are unsupported")
    severities = match.get("severities")
    if (
        not isinstance(severities, list)
        or not severities
        or len(severities) > 3
        or any(item not in {"medium", "high", "critical"} for item in severities)
    ):
        raise ValueError("response rule severities are unsupported")
    hosts = match.get("hosts")
    if (
        not isinstance(hosts, list)
        or not hosts
        or len(hosts) > 2
        or any(item not in {"claude-code", "codex"} for item in hosts)
    ):
        raise ValueError("response rule hosts are unsupported")
    if action != {"type": "quarantine_agent"}:
        raise ValueError("response rule action must be quarantine_agent")
    if not isinstance(safeguards, dict) or set(safeguards) != {
        "maxActionsPerHour",
        "agentCooldownSeconds",
    }:
        raise ValueError("response rule safeguards have an invalid schema")
    maximum = _discovery_integer(
        safeguards.get("maxActionsPerHour"),
        "maxActionsPerHour",
        minimum=1,
        maximum=25,
    )
    cooldown = _discovery_integer(
        safeguards.get("agentCooldownSeconds"),
        "agentCooldownSeconds",
        minimum=300,
        maximum=86_400,
    )
    priority = _discovery_integer(value.get("priority"), "priority", minimum=1, maximum=1_000)
    return {
        "match": {
            "source": "endpoint_evidence",
            "reasonCodes": sorted(set(reason_codes)),
            "severities": sorted(set(severities)),
            "hosts": sorted(set(hosts)),
        },
        "action": {"type": "quarantine_agent"},
        "safeguards": {
            "maxActionsPerHour": maximum,
            "agentCooldownSeconds": cooldown,
        },
        "priority": priority,
    }


def _response_rule_versions(tenant, rule_id, *, consistent_read=False):
    """Return every bounded immutable version for one tenant response rule."""
    versions = [
        item
        for item in _list(tenant, "RESPONSE_RULE_VERSION", consistent_read=consistent_read)
        if item.get("rule_id") == rule_id
    ]
    if any(item.get("state") not in _RESPONSE_RULE_VERSION_STATES for item in versions):
        raise RuntimeError("response rule version state is malformed")
    return sorted(versions, key=lambda item: int(item.get("version", 0)), reverse=True)


def _response_rule_version_view(record):
    """Project one immutable rule version into the operator API contract."""
    return {
        "ruleId": record.get("rule_id"),
        "version": int(record.get("version", 0)),
        "baseVersion": int(record.get("base_version", 0)),
        "name": record.get("name"),
        "description": record.get("description"),
        "configuration": _json(record.get("configuration", {})),
        "contentHash": record.get("content_hash"),
        "state": record.get("state"),
        "author": record.get("author"),
        "createdAt": int(record.get("created_at", 0)),
        "submittedBy": record.get("submitted_by"),
        "submittedAt": record.get("submitted_at"),
        "decidedBy": record.get("decided_by"),
        "decidedAt": record.get("decided_at"),
        "decision": record.get("decision"),
        "decisionReason": record.get("decision_reason"),
        "activatedBy": record.get("activated_by"),
        "activatedAt": record.get("activated_at"),
    }


def _response_rule_summary(rule, versions=None):
    """Return active automatic authority separately from pending governance."""
    all_versions = versions if versions is not None else []
    pending = next(
        (item for item in all_versions if item.get("state") in _RESPONSE_RULE_PENDING_STATES),
        None,
    )
    return {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "description": rule.get("description"),
        "configuration": _json(rule.get("configuration", {})),
        "contentHash": rule.get("content_hash"),
        "activeVersion": int(rule.get("active_version", 0)) or None,
        "latestVersion": int(rule.get("latest_version", 0)),
        "enabled": rule.get("enabled") is True,
        "governanceState": pending.get("state")
        if pending
        else ("active" if int(rule.get("active_version", 0)) else "draft"),
        "pendingVersion": int(pending.get("version", 0)) if pending else None,
        "pendingAuthor": pending.get("author") if pending else None,
        "createdAt": int(rule.get("created_at", 0)),
        "createdBy": rule.get("created_by"),
        "updatedAt": int(rule.get("updated_at", rule.get("created_at", 0))),
        "disabledAt": rule.get("disabled_at"),
        "disabledBy": rule.get("disabled_by"),
        "revision": int(rule.get("revision", 1)),
    }


def _create_response_rule(tenant, body, actor):
    """Atomically create a rule shell and its first inactive draft."""
    if not isinstance(body, dict) or set(body) != {
        "ruleId",
        "name",
        "description",
        "configuration",
    }:
        raise ValueError("response rule request has an invalid schema")
    rule_id = _bounded_identifier(body.get("ruleId"), "ruleId")
    name = _bounded_text(body.get("name"), "name", 120)
    description = _case_reason(body.get("description"))
    configuration = _response_rule_configuration(body.get("configuration"))
    now = int(time.time())
    content_hash = _configuration_hash(configuration)
    rule = {
        **_item_key(tenant, "RESPONSE_RULE", rule_id),
        "tenant_id": tenant,
        "id": rule_id,
        "name": name,
        "description": description,
        "configuration": {},
        "content_hash": None,
        "active_version": 0,
        "latest_version": 1,
        "enabled": False,
        "revision": 1,
        "created_at": now,
        "created_by": actor,
        "updated_at": now,
    }
    version = {
        **_item_key(
            tenant,
            "RESPONSE_RULE_VERSION",
            _response_rule_version_identifier(rule_id, 1),
        ),
        "tenant_id": tenant,
        "id": _response_rule_version_identifier(rule_id, 1),
        "rule_id": rule_id,
        "version": 1,
        "base_version": 0,
        "name": name,
        "description": description,
        "configuration": configuration,
        "content_hash": content_hash,
        "state": "draft",
        "author": actor,
        "created_at": now,
    }
    _transact_policy_records(
        [
            _transaction_put(rule, condition="attribute_not_exists(pk)"),
            _transaction_put(version, condition="attribute_not_exists(pk)"),
        ]
    )
    _audit(tenant, "response_rule_draft_created", actor, {"rule_id": rule_id, "version": 1})
    return _response_rule_summary(rule, [version])


def _response_rule_record(tenant, rule_id):
    """Load one tenant rule summary with a strongly consistent read."""
    rule_id = _bounded_identifier(rule_id, "ruleId")
    record = TABLE.get_item(
        Key=_item_key(tenant, "RESPONSE_RULE", rule_id), ConsistentRead=True
    ).get("Item")
    if not record:
        raise LookupError("response rule not found")
    return record


def _response_rule_version_record(tenant, rule_id, version):
    """Load one exact immutable response-rule version."""
    record = TABLE.get_item(
        Key=_item_key(
            tenant,
            "RESPONSE_RULE_VERSION",
            _response_rule_version_identifier(rule_id, version),
        ),
        ConsistentRead=True,
    ).get("Item")
    if not record or record.get("rule_id") != rule_id:
        raise LookupError("response rule version not found")
    return record


def _create_response_rule_draft(tenant, rule_id, body, actor):
    """Append one governed draft without changing automatic authority."""
    if not isinstance(body, dict) or set(body) != {"name", "description", "configuration"}:
        raise ValueError("response rule draft has an invalid schema")
    rule = _response_rule_record(tenant, rule_id)
    versions = _response_rule_versions(tenant, rule_id, consistent_read=True)
    if any(item.get("state") in _RESPONSE_RULE_PENDING_STATES for item in versions):
        raise PolicyConflict("response rule already has a pending version")
    version_number = int(rule.get("latest_version", 0)) + 1
    name = _bounded_text(body.get("name"), "name", 120)
    description = _case_reason(body.get("description"))
    configuration = _response_rule_configuration(body.get("configuration"))
    active_configuration = rule.get("configuration")
    if isinstance(active_configuration, dict) and active_configuration:
        active_source = (active_configuration.get("match") or {}).get("source")
        if active_source != configuration["match"]["source"]:
            # A stable rule identity has one permanent trust boundary. This
            # prevents an alert-only rule from being upgraded into automatic
            # containment through a later version; use a distinct reviewed
            # rule ID for a different evidence source.
            raise ValueError("response rule evidence boundary cannot change")
    now = int(time.time())
    version = {
        **_item_key(
            tenant,
            "RESPONSE_RULE_VERSION",
            _response_rule_version_identifier(rule_id, version_number),
        ),
        "tenant_id": tenant,
        "id": _response_rule_version_identifier(rule_id, version_number),
        "rule_id": rule_id,
        "version": version_number,
        "base_version": int(rule.get("active_version", 0)),
        "name": name,
        "description": description,
        "configuration": configuration,
        "content_hash": _configuration_hash(configuration),
        "state": "draft",
        "author": actor,
        "created_at": now,
    }
    updated = {
        **rule,
        "latest_version": version_number,
        "revision": int(rule.get("revision", 1)) + 1,
        "updated_at": now,
    }
    _transact_policy_records(
        [
            _transaction_put(version, condition="attribute_not_exists(pk)"),
            _transaction_put(
                updated,
                condition="latest_version = :latest AND active_version = :active",
                values={
                    ":latest": int(rule.get("latest_version", 0)),
                    ":active": int(rule.get("active_version", 0)),
                },
            ),
        ]
    )
    _audit(
        tenant,
        "response_rule_draft_created",
        actor,
        {"rule_id": rule_id, "version": version_number},
    )
    return _response_rule_version_view(version)


def _put_response_rule_transition(tenant, record, expected_state, event_type, actor):
    """Commit one exact-state response-rule lifecycle transition."""
    try:
        TABLE.put_item(
            Item=record,
            ConditionExpression="#state = :expected",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={":expected": expected_state},
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict(
                f"response rule version must be {expected_state} before this transition"
            ) from error
        raise
    _audit(
        tenant,
        event_type,
        actor,
        {"rule_id": record["rule_id"], "version": int(record["version"])},
    )
    return _response_rule_version_view(record)


def _submit_response_rule_version(tenant, rule_id, version, actor):
    """Freeze a rule draft and submit it for independent review."""
    record = _response_rule_version_record(tenant, rule_id, version)
    if record.get("state") != "draft":
        raise PolicyConflict("response rule version is not a draft")
    updated = {
        **record,
        "state": "review",
        "submitted_by": actor,
        "submitted_at": int(time.time()),
    }
    return _put_response_rule_transition(tenant, updated, "draft", "response_rule_submitted", actor)


def _decide_response_rule_version(tenant, rule_id, version, body, actor):
    """Approve or reject one rule version with two-subject separation."""
    if not isinstance(body, dict) or set(body) != {"decision", "reason"}:
        raise ValueError("response rule decision has an invalid schema")
    decision = body.get("decision")
    if decision not in {"approved", "rejected"}:
        raise ValueError("response rule decision must be approved or rejected")
    reason = _case_reason(body.get("reason"))
    record = _response_rule_version_record(tenant, rule_id, version)
    if record.get("state") != "review":
        raise PolicyConflict("response rule version is not awaiting review")
    if decision == "approved" and secrets.compare_digest(str(record.get("author", "")), actor):
        raise PermissionError("response rule authors cannot approve their own version")
    now = int(time.time())
    updated = {
        **record,
        "state": decision,
        "decision": decision,
        "decided_by": actor,
        "decided_at": now,
        "decision_reason": reason,
    }
    return _put_response_rule_transition(tenant, updated, "review", "response_rule_decided", actor)


def _activate_response_rule_version(tenant, rule_id, version, body, actor):
    """Atomically activate an independently approved immutable rule version."""
    if not isinstance(body, dict) or set(body) != {"expectedActiveVersion"}:
        raise ValueError("response rule activation has an invalid schema")
    expected = _discovery_integer(
        body.get("expectedActiveVersion"), "expectedActiveVersion", minimum=0
    )
    rule = _response_rule_record(tenant, rule_id)
    record = _response_rule_version_record(tenant, rule_id, version)
    if record.get("state") != "approved":
        raise PolicyConflict("response rule version is not approved")
    if not record.get("decided_by") or record.get("decided_by") == record.get("author"):
        raise PermissionError("response rule version lacks independent approval")
    if int(rule.get("active_version", 0)) != expected:
        raise PolicyConflict("response rule active version changed")
    if int(record.get("base_version", -1)) != expected:
        raise PolicyConflict("response rule version was reviewed against another active version")
    now = int(time.time())
    active_version = {
        **record,
        "state": "active",
        "activated_by": actor,
        "activated_at": now,
    }
    updated_rule = {
        **rule,
        "name": record["name"],
        "description": record["description"],
        "configuration": _json(record["configuration"]),
        "content_hash": record["content_hash"],
        "active_version": int(record["version"]),
        "enabled": True,
        "disabled_at": None,
        "disabled_by": None,
        "revision": int(rule.get("revision", 1)) + 1,
        "updated_at": now,
    }
    operations = [
        _transaction_put(
            active_version,
            condition="#state = :approved",
            names={"#state": "state"},
            values={":approved": "approved"},
        ),
        _transaction_put(
            updated_rule,
            condition="active_version = :active AND latest_version = :latest",
            values={
                ":active": expected,
                ":latest": int(rule.get("latest_version", 0)),
            },
        ),
    ]
    if expected:
        previous = _response_rule_version_record(tenant, rule_id, expected)
        if previous.get("state") != "active":
            raise PolicyConflict("current response rule version is not active")
        operations.append(
            _transaction_put(
                {**previous, "state": "superseded", "superseded_at": now},
                condition="#state = :active",
                names={"#state": "state"},
                values={":active": "active"},
            )
        )
    _transact_policy_records(operations)
    _audit(
        tenant,
        "response_rule_activated",
        actor,
        {
            "rule_id": rule_id,
            "version": int(record["version"]),
            "content_hash": record["content_hash"],
        },
    )
    return _response_rule_summary(updated_rule, [active_version])


def _disable_response_rule(tenant, rule_id, body, actor):
    """Immediately remove automatic authority without mutating its version."""
    if not isinstance(body, dict) or set(body) != {"expectedActiveVersion", "reason"}:
        raise ValueError("response rule disable request has an invalid schema")
    expected = _discovery_integer(
        body.get("expectedActiveVersion"), "expectedActiveVersion", minimum=1
    )
    reason = _case_reason(body.get("reason"))
    rule = _response_rule_record(tenant, rule_id)
    if int(rule.get("active_version", 0)) != expected or rule.get("enabled") is not True:
        raise PolicyConflict("response rule is not active at the expected version")
    now = int(time.time())
    updated = {
        **rule,
        "enabled": False,
        "disabled_at": now,
        "disabled_by": actor,
        "disable_reason": reason,
        "revision": int(rule.get("revision", 1)) + 1,
        "updated_at": now,
    }
    try:
        TABLE.put_item(
            Item=updated,
            ConditionExpression="active_version = :active AND enabled = :enabled",
            ExpressionAttributeValues={":active": expected, ":enabled": True},
        )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise PolicyConflict("response rule authority changed before disable") from error
        raise
    _audit(
        tenant,
        "response_rule_disabled",
        actor,
        {"rule_id": rule_id, "version": expected, "reason": reason},
    )
    return _response_rule_summary(updated, _response_rule_versions(tenant, rule_id))


def _rollback_response_rule(tenant, rule_id, body, actor):
    """Atomically restore an independently approved superseded rule version."""
    if not isinstance(body, dict) or set(body) != {
        "expectedActiveVersion",
        "targetVersion",
        "reason",
    }:
        raise ValueError("response rule rollback request has an invalid schema")
    expected = _discovery_integer(
        body.get("expectedActiveVersion"), "expectedActiveVersion", minimum=1
    )
    target = _discovery_integer(body.get("targetVersion"), "targetVersion", minimum=1)
    if target == expected:
        raise ValueError("response rule rollback target must differ from the active version")
    reason = _case_reason(body.get("reason"))
    rule = _response_rule_record(tenant, rule_id)
    if int(rule.get("active_version", 0)) != expected or rule.get("enabled") is not True:
        raise PolicyConflict("response rule is not active at the expected version")
    current = _response_rule_version_record(tenant, rule_id, expected)
    restored = _response_rule_version_record(tenant, rule_id, target)
    if current.get("state") != "active":
        raise PolicyConflict("current response rule version is not active")
    if restored.get("state") != "superseded":
        raise PolicyConflict("rollback target is not a superseded version")
    if (
        restored.get("decision") != "approved"
        or not restored.get("decided_by")
        or restored.get("decided_by") == restored.get("author")
    ):
        raise PermissionError("rollback target lacks independent approval")
    configuration = _response_rule_configuration(restored.get("configuration"))
    if _configuration_hash(configuration) != restored.get("content_hash"):
        raise RuntimeError("rollback target integrity is invalid")
    now = int(time.time())
    restored_active = {
        **restored,
        "state": "active",
        "activated_by": actor,
        "activated_at": now,
        "rollback_from_version": expected,
        "rollback_reason": reason,
    }
    updated_rule = {
        **rule,
        "name": restored["name"],
        "description": restored["description"],
        "configuration": configuration,
        "content_hash": restored["content_hash"],
        "active_version": target,
        "revision": int(rule.get("revision", 1)) + 1,
        "updated_at": now,
    }
    _transact_policy_records(
        [
            _transaction_put(
                {
                    **current,
                    "state": "superseded",
                    "superseded_at": now,
                    "superseded_by_rollback": target,
                },
                condition="#state = :active",
                names={"#state": "state"},
                values={":active": "active"},
            ),
            _transaction_put(
                restored_active,
                condition="#state = :superseded",
                names={"#state": "state"},
                values={":superseded": "superseded"},
            ),
            _transaction_put(
                updated_rule,
                condition="active_version = :active AND enabled = :enabled",
                values={":active": expected, ":enabled": True},
            ),
        ]
    )
    _audit(
        tenant,
        "response_rule_rolled_back",
        actor,
        {
            "rule_id": rule_id,
            "from_version": expected,
            "target_version": target,
            "reason": reason,
            "content_hash": restored["content_hash"],
        },
    )
    return _response_rule_summary(updated_rule, [restored_active])


def _response_rule_matches(configuration, alert, binding=None):
    """Return whether fixed alert and host facts match a normalized rule."""
    matcher = configuration["match"]
    if matcher.get("source") != "endpoint_evidence":
        return False
    if alert.get("source") != "endpoint_evidence":
        return False
    if alert.get("reasonCode") not in matcher["reasonCodes"]:
        return False
    if alert.get("severity") not in matcher["severities"]:
        return False
    return binding is None or binding.get("host") in matcher["hosts"]


def _response_rule_execution_view(item):
    """Project one content-minimised automatic-response outcome."""
    return {
        "id": item.get("id"),
        "ruleId": item.get("rule_id"),
        "ruleVersion": int(item.get("rule_version", 0)),
        "alertId": item.get("alert_id"),
        "alertOccurrence": int(item.get("alert_occurrence", 0)),
        "caseId": item.get("case_id"),
        "agentKey": item.get("agent_key"),
        "outcome": item.get("outcome"),
        "reasonCode": item.get("reason_code"),
        "occurredAt": int(item.get("occurred_at", 0)),
        "contentHash": item.get("content_hash"),
    }


def _response_execution_id(tenant, rule_id, version, alert):
    """Bind one idempotent outcome to a rule version and alert occurrence."""
    occurrence = int(alert.get("occurrenceCount", 0))
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"aai-response:{tenant}:{rule_id}:{version}:{alert.get('id')}:{occurrence}",
        )
    )


def _response_rule_limit_reason(tenant, rule, binding, now):
    """Return a denial from the atomic action-reservation ledger or None."""
    configuration = _json(rule.get("configuration", {}))
    rate = TABLE.get_item(
        Key=_item_key(tenant, "RESPONSE_RATE", rule.get("id", "")),
        ConsistentRead=True,
    ).get("Item")
    action_times = rate.get("action_times", []) if rate else []
    if not isinstance(action_times, list) or any(
        not isinstance(item, (int, Decimal)) for item in action_times
    ):
        raise RuntimeError("automatic response rate evidence is malformed")
    current_actions = [int(item) for item in action_times if int(item) >= now - 3_600]
    maximum = int(configuration["safeguards"]["maxActionsPerHour"])
    if len(current_actions) >= maximum:
        return "hourly_limit"
    cooldown = int(configuration["safeguards"]["agentCooldownSeconds"])
    cooldown_record = TABLE.get_item(
        Key=_item_key(tenant, "RESPONSE_COOLDOWN", binding.get("agentKey", "")),
        ConsistentRead=True,
    ).get("Item")
    if cooldown_record and int(cooldown_record.get("last_action_at", 0)) >= now - cooldown:
        return "agent_cooldown"
    return None


def _reserve_response_rule_action(tenant, rule, alert, binding, now):
    """Atomically reserve bounded rate and cooldown authority for one trigger.

    A reservation is conservative: dependency failure after this point still
    consumes capacity and cooldown. This can reduce automatic authority but a
    race or retry can never increase it beyond the approved safeguards.
    """
    version = int(rule.get("active_version", 0))
    execution_id = _response_execution_id(tenant, rule["id"], version, alert)
    lease_key = _item_key(tenant, "RESPONSE_LEASE", execution_id)
    if TABLE.get_item(Key=lease_key, ConsistentRead=True).get("Item"):
        return None
    for _attempt in range(3):
        reason = _response_rule_limit_reason(tenant, rule, binding, now)
        if reason:
            return reason
        rate_key = _item_key(tenant, "RESPONSE_RATE", rule["id"])
        rate = TABLE.get_item(Key=rate_key, ConsistentRead=True).get("Item")
        action_times = [
            int(item)
            for item in (rate.get("action_times", []) if rate else [])
            if int(item) >= now - 3_600
        ]
        cooldown_key = _item_key(tenant, "RESPONSE_COOLDOWN", binding["agentKey"])
        cooldown = TABLE.get_item(Key=cooldown_key, ConsistentRead=True).get("Item")
        rate_revision = int(rate.get("revision", 0)) if rate else 0
        cooldown_revision = int(cooldown.get("revision", 0)) if cooldown else 0
        rate_record = {
            **rate_key,
            "tenant_id": tenant,
            "id": rule["id"],
            "rule_id": rule["id"],
            "action_times": [*action_times, now],
            "revision": rate_revision + 1,
            "updated_at": now,
        }
        cooldown_record = {
            **cooldown_key,
            "tenant_id": tenant,
            "id": binding["agentKey"],
            "agent_key": binding["agentKey"],
            "last_action_at": now,
            "revision": cooldown_revision + 1,
            "updated_at": now,
        }
        lease = {
            **lease_key,
            "tenant_id": tenant,
            "id": execution_id,
            "rule_id": rule["id"],
            "rule_version": version,
            "alert_id": alert.get("id"),
            "alert_occurrence": int(alert.get("occurrenceCount", 0)),
            "agent_key": binding["agentKey"],
            "reserved_at": now,
            "ttl": now + 86_400,
        }
        operations = [_transaction_put(lease, condition="attribute_not_exists(pk)")]
        operations.append(
            _transaction_put(
                rate_record,
                condition="revision = :revision" if rate else "attribute_not_exists(pk)",
                values={":revision": rate_revision} if rate else None,
            )
        )
        operations.append(
            _transaction_put(
                cooldown_record,
                condition="revision = :revision" if cooldown else "attribute_not_exists(pk)",
                values={":revision": cooldown_revision} if cooldown else None,
            )
        )
        try:
            _transact_policy_records(operations)
            return None
        except PolicyConflict:
            if TABLE.get_item(Key=lease_key, ConsistentRead=True).get("Item"):
                return None
    raise RuntimeError("automatic response reservation changed concurrently")


def _record_response_execution(
    tenant,
    rule,
    alert,
    *,
    outcome,
    reason_code,
    case_id=None,
    agent_key=None,
    now=None,
):
    """Persist one idempotent content-minimised automatic-response outcome."""
    occurred_at = int(time.time()) if now is None else int(now)
    version = int(rule.get("active_version", 0))
    execution_id = _response_execution_id(tenant, rule["id"], version, alert)
    content = {
        "ruleId": rule["id"],
        "ruleVersion": version,
        "alertId": alert.get("id"),
        "alertOccurrence": int(alert.get("occurrenceCount", 0)),
        "caseId": case_id,
        "agentKey": agent_key,
        "outcome": outcome,
        "reasonCode": reason_code,
        "occurredAt": occurred_at,
    }
    item = {
        **_item_key(tenant, "RESPONSE_EXECUTION", execution_id),
        "tenant_id": tenant,
        "id": execution_id,
        "rule_id": rule["id"],
        "rule_version": version,
        "alert_id": alert.get("id"),
        "alert_occurrence": int(alert.get("occurrenceCount", 0)),
        "case_id": case_id,
        "agent_key": agent_key,
        "outcome": outcome,
        "reason_code": reason_code,
        "occurred_at": occurred_at,
        "content_hash": _configuration_hash(content),
    }
    try:
        TABLE.put_item(Item=item, ConditionExpression="attribute_not_exists(pk)")
    except Exception as error:
        if _is_conditional_conflict(error):
            existing = TABLE.get_item(
                Key=_item_key(tenant, "RESPONSE_EXECUTION", execution_id),
                ConsistentRead=True,
            ).get("Item")
            return _response_rule_execution_view(existing or item)
        raise
    _audit(
        tenant,
        "automatic_response_evaluated",
        f"system:response-rule:{rule['id']}:v{version}",
        {
            "execution_id": execution_id,
            "rule_id": rule["id"],
            "rule_version": version,
            "alert_id": alert.get("id"),
            "case_id": case_id,
            "agent_key": agent_key,
            "outcome": outcome,
            "reason_code": reason_code,
            "content_hash": item["content_hash"],
        },
    )
    return _response_rule_execution_view(item)


def _record_behavior_health(tenant, status, *, now=None):
    """Persist content-free evaluator health without accepting browser input."""
    if status not in {"healthy", "degraded"}:
        raise ValueError("behavior health status is unsupported")
    observed_at = int(time.time()) if now is None else int(now)
    try:
        TABLE.put_item(
            Item={
                **_item_key(tenant, "BEHAVIOR_HEALTH", "current"),
                "tenant_id": tenant,
                "id": "current",
                "status": status,
                "observed_at": observed_at,
                "ttl": observed_at + (30 * 24 * 60 * 60),
            }
        )
    except Exception:
        print(json.dumps({"warning": "behavior detection health persistence failed"}))


def _behavior_decision_history(tenant):
    """Read a complete bounded activity history or refuse a misleading baseline."""
    result = TABLE.query(
        IndexName=_DECISION_TIMELINE_INDEX,
        KeyConditionExpression=Key("timeline_pk").eq(f"TENANT#{tenant}#DECISION"),
        ScanIndexForward=False,
        Limit=_BEHAVIOR_HISTORY_LIMIT + 1,
    )
    items = result.get("Items", [])
    truncated = bool(result.get("LastEvaluatedKey") or len(items) > _BEHAVIOR_HISTORY_LIMIT)
    return items[:_BEHAVIOR_HISTORY_LIMIT], truncated


def _behavior_signal_metrics(
    configuration,
    signal,
    agent_key,
    decisions,
    approvals,
    *,
    now,
    history_truncated=False,
):
    """Return explainable, content-minimised matches for one closed signal."""
    if signal not in _BEHAVIOR_SIGNAL_TYPES:
        raise ValueError("behavior signal is unsupported")
    baseline = configuration["baseline"]
    current_seconds = int(baseline["currentWindowMinutes"]) * 60
    current_start = now - current_seconds
    history_start = now - (int(baseline["lookbackDays"]) * 86_400)
    minimum_baseline = int(baseline["minimumBaselineEvents"])
    minimum_current = int(baseline["minimumCurrentEvents"])
    multiplier = float(baseline["sensitivityMultiplier"])
    agent_decisions = [
        item
        for item in decisions
        if f"{item.get('deployment_id')}:{item.get('agent_id')}" == agent_key
        and history_start <= int(item.get("observed_at", 0)) <= now
    ]
    current_decisions = [
        item for item in agent_decisions if int(item.get("observed_at", 0)) >= current_start
    ]
    historical_decisions = [
        item for item in agent_decisions if int(item.get("observed_at", 0)) < current_start
    ]
    agent_approvals = [
        item
        for item in approvals
        if item.get("agent_key") == agent_key
        and history_start <= int(item.get("requested_at", item.get("created_at", 0))) <= now
    ]
    current_approvals = [
        item
        for item in agent_approvals
        if int(item.get("requested_at", item.get("created_at", 0))) >= current_start
    ]
    historical_approvals = [
        item
        for item in agent_approvals
        if int(item.get("requested_at", item.get("created_at", 0))) < current_start
    ]

    if signal == "approval_request_spike":
        baseline_records = historical_approvals
        current_records = current_approvals
    else:
        baseline_records = historical_decisions
        current_records = current_decisions
    if history_truncated or len(baseline_records) < minimum_baseline:
        return [
            {
                "signalType": signal,
                "outcome": "baseline_insufficient",
                "baselineComplete": not history_truncated,
                "baselineCount": len(baseline_records),
                "minimumBaselineEvents": minimum_baseline,
                "currentCount": len(current_records),
                "threshold": None,
                "expectedCurrentCount": None,
                "dimension": None,
                "dimensionHash": None,
                "evidenceDigest": _configuration_hash(
                    sorted(str(item.get("id", "")) for item in current_records)
                ),
            }
        ]

    history_seconds = max(1, current_start - history_start)
    if signal in {"new_tool", "new_mcp_server"}:
        field = "tool_name" if signal == "new_tool" else "mcp_server_id"
        historical_values = {
            str(item.get(field))
            for item in historical_decisions
            if isinstance(item.get(field), str) and item.get(field)
        }
        current_by_value = {}
        for item in current_decisions:
            value = item.get(field)
            if signal == "new_mcp_server" and item.get("resource_kind") != "mcp_tool":
                continue
            if not isinstance(value, str) or not value:
                continue
            current_by_value.setdefault(value, []).append(item)
        matches = []
        for value, records in sorted(current_by_value.items()):
            if value in historical_values or len(records) < minimum_current:
                continue
            matches.append(
                {
                    "signalType": signal,
                    "outcome": "would_alert",
                    "baselineComplete": True,
                    "baselineCount": len(baseline_records),
                    "minimumBaselineEvents": minimum_baseline,
                    "currentCount": len(records),
                    "threshold": minimum_current,
                    "expectedCurrentCount": 0.0,
                    "dimension": value,
                    "dimensionHash": hashlib.sha256(value.encode()).hexdigest(),
                    "evidenceDigest": _configuration_hash(
                        sorted(str(item.get("id", "")) for item in records)
                    ),
                }
            )
        return matches

    if signal == "denied_action_spike":
        historical_matches = [
            item for item in historical_decisions if item.get("decision") == "denied"
        ]
        current_matches = [item for item in current_decisions if item.get("decision") == "denied"]
    elif signal == "approval_request_spike":
        historical_matches = historical_approvals
        current_matches = current_approvals
    else:
        historical_matches = historical_decisions
        current_matches = current_decisions
    expected = len(historical_matches) * (current_seconds / history_seconds)
    threshold = max(minimum_current, int(math.ceil(expected * multiplier)))
    if len(current_matches) < threshold:
        return []
    return [
        {
            "signalType": signal,
            "outcome": "would_alert",
            "baselineComplete": True,
            "baselineCount": len(baseline_records),
            "minimumBaselineEvents": minimum_baseline,
            "currentCount": len(current_matches),
            "threshold": threshold,
            "expectedCurrentCount": round(expected, 4),
            "dimension": None,
            "dimensionHash": None,
            "evidenceDigest": _configuration_hash(
                sorted(str(item.get("id", "")) for item in current_matches)
            ),
        }
    ]


_BEHAVIOR_ALERT_COPY = {
    "new_tool": ("agent_new_tool", "A tool not present in the historical baseline was observed."),
    "new_mcp_server": (
        "agent_new_mcp_server",
        "An MCP server not present in the historical baseline was observed.",
    ),
    "denied_action_spike": (
        "agent_denied_action_spike",
        "Denied agent actions exceeded the approved behavioral threshold.",
    ),
    "approval_request_spike": (
        "agent_approval_request_spike",
        "Approval requests exceeded the approved behavioral threshold.",
    ),
    "decision_volume_spike": (
        "agent_decision_volume_spike",
        "Agent decision volume exceeded the approved behavioral threshold.",
    ),
}


def _open_behavior_alert(tenant, rule, agent, metric, *, now):
    """Create one deterministic alert without granting automatic response authority."""
    configuration = _response_rule_configuration(rule.get("configuration"))
    signal = metric["signalType"]
    window_seconds = int(configuration["baseline"]["currentWindowMinutes"]) * 60
    window_start = now - (now % window_seconds)
    dimension_hash = metric.get("dimensionHash") or ("0" * 64)
    deduplication_key = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            (
                f"aai-behavior-group:{tenant}:{rule['id']}:{int(rule['active_version'])}:"
                f"{agent['deployment_id']}:{agent['id']}:{signal}:{dimension_hash}"
            ),
        )
    )
    alert_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            (
                f"aai-behavior:{tenant}:{rule['id']}:{int(rule['active_version'])}:"
                f"{agent['deployment_id']}:{agent['id']}:{signal}:{window_start}:{dimension_hash}"
            ),
        )
    )
    key = _item_key(tenant, "ALERT", alert_id)
    existing = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    if existing:
        return existing
    alert_type, message = _BEHAVIOR_ALERT_COPY[signal]
    behavior = {
        "ruleId": rule["id"],
        "ruleVersion": int(rule["active_version"]),
        "ruleContentHash": rule.get("content_hash"),
        "signalType": signal,
        "baselineComplete": True,
        "baselineCount": int(metric["baselineCount"]),
        "currentCount": int(metric["currentCount"]),
        "threshold": int(metric["threshold"]),
        "expectedCurrentCount": metric.get("expectedCurrentCount"),
        "sensitivityMultiplier": float(configuration["baseline"]["sensitivityMultiplier"]),
        "currentWindowMinutes": int(configuration["baseline"]["currentWindowMinutes"]),
        "lookbackDays": int(configuration["baseline"]["lookbackDays"]),
        "dimension": metric.get("dimension"),
        "dimensionHash": metric.get("dimensionHash"),
        "evidenceDigest": metric["evidenceDigest"],
        "reportedByAgent": True,
    }
    record = {
        **key,
        "tenant_id": tenant,
        "id": alert_id,
        "source": "behavior_analytics",
        "severity": configuration["match"]["severity"],
        "type": alert_type,
        "deviceId": "",
        "deploymentId": agent["deployment_id"],
        "agentId": agent["id"],
        "agentKey": f"{agent['deployment_id']}:{agent['id']}",
        "host": agent.get("host"),
        "message": message,
        "reasonCode": signal,
        "behavior": behavior,
        "status": "open",
        "revision": 1,
        "firstObservedAt": now,
        "lastObservedAt": now,
        "occurrenceCount": 1,
        "deduplicationKey": deduplication_key,
        "deliveryStatus": "pending",
    }
    suppression = _matching_alert_suppression(tenant, record, now=now)
    if suppression:
        record.update(
            {
                "status": "suppressed",
                "suppressionId": suppression["id"],
                "suppressedUntil": int(suppression["expires_at"]),
                "deliveryStatus": "suppressed",
            }
        )
    try:
        TABLE.put_item(Item=record, ConditionExpression="attribute_not_exists(pk)")
    except Exception as error:
        if _is_conditional_conflict(error):
            return TABLE.get_item(Key=key, ConsistentRead=True).get("Item") or record
        raise
    _audit(
        tenant,
        "behavior_alert_suppressed" if suppression else "behavior_alert_opened",
        f"system:response-rule:{rule['id']}:v{int(rule['active_version'])}",
        {
            "alert_id": alert_id,
            "agent_key": record["agentKey"],
            "signal_type": signal,
            "rule_id": rule["id"],
            "rule_version": int(rule["active_version"]),
            "evidence_digest": metric["evidenceDigest"],
            "deduplication_key": deduplication_key,
            "suppression_id": suppression.get("id") if suppression else None,
        },
    )
    _record_response_execution(
        tenant,
        rule,
        record,
        outcome="suppressed" if suppression else "alerted",
        reason_code="active_suppression" if suppression else signal,
        agent_key=record["agentKey"],
        now=now,
    )
    if not suppression:
        _deliver_pending_endpoint_alerts(tenant)
    return record


def _behavior_rule_metrics(tenant, configuration, agent_key, *, now):
    """Evaluate one normalized behavior rule without mutating alert state."""
    decisions, truncated = _behavior_decision_history(tenant)
    approvals = _list(tenant, "APPROVAL", consistent_read=True)
    matches = []
    for signal in configuration["match"]["signalTypes"]:
        matches.extend(
            _behavior_signal_metrics(
                configuration,
                signal,
                agent_key,
                decisions,
                approvals,
                now=now,
                history_truncated=truncated,
            )
        )
        if len(matches) > _RESPONSE_RULE_PREVIEW_LIMIT:
            raise RuntimeError("behavior rule evaluation exceeds its safe bound")
    return matches


def _evaluate_behavior_rules_for_agent(tenant, agent_key, *, now=None):
    """Evaluate active alert-only rules for one authenticated enrolled agent."""
    current_time = int(time.time()) if now is None else int(now)
    agent = TABLE.get_item(Key=_item_key(tenant, "AGENT", agent_key), ConsistentRead=True).get(
        "Item"
    )
    if not agent or _agent_lifecycle_state(agent) != "active":
        return []
    rules = []
    for item in _list(tenant, "RESPONSE_RULE", consistent_read=True):
        configuration = item.get("configuration")
        if (
            item.get("enabled") is True
            and int(item.get("active_version", 0)) > 0
            and isinstance(configuration, dict)
            and (configuration.get("match") or {}).get("source") == "agent_activity"
        ):
            rules.append(item)
    if len(rules) > _BEHAVIOR_ACTIVE_RULE_LIMIT:
        raise RuntimeError("active behavior rule count exceeds its safe bound")
    rules.sort(
        key=lambda item: (
            int(item.get("configuration", {}).get("priority", 1_000)),
            str(item.get("id", "")),
        )
    )
    alerts = []
    for rule in rules:
        version = int(rule["active_version"])
        version_record = _response_rule_version_record(tenant, rule["id"], version)
        configuration = _response_rule_configuration(rule.get("configuration"))
        if (
            version_record.get("state") != "active"
            or version_record.get("content_hash") != rule.get("content_hash")
            or _configuration_hash(configuration) != rule.get("content_hash")
        ):
            raise RuntimeError("active behavior rule integrity is invalid")
        if agent.get("host") not in configuration["match"]["hosts"]:
            continue
        for metric in _behavior_rule_metrics(tenant, configuration, agent_key, now=current_time):
            if metric.get("outcome") != "would_alert":
                continue
            alerts.append(_open_behavior_alert(tenant, rule, agent, metric, now=current_time))
    _record_behavior_health(tenant, "healthy", now=current_time)
    return [_endpoint_alert_view(item) for item in alerts]


def _response_rule_preview(tenant, configuration):
    """Preview current alerts without creating cases or response authority."""
    normalized = _response_rule_configuration(configuration)
    if normalized["match"]["source"] == "agent_activity":
        now = int(time.time())
        matches = []
        agents = [
            item
            for item in _all_agents(tenant, consistent_read=True)
            if _agent_lifecycle_state(item) == "active"
            and item.get("host") in normalized["match"]["hosts"]
        ]
        for agent in sorted(
            agents, key=lambda item: (str(item.get("deployment_id")), str(item.get("id")))
        ):
            agent_key = f"{agent.get('deployment_id')}:{agent.get('id')}"
            for metric in _behavior_rule_metrics(tenant, normalized, agent_key, now=now):
                matches.append(
                    {
                        "alertId": None,
                        "deviceId": "",
                        "reasonCode": metric["signalType"],
                        "severity": normalized["match"]["severity"],
                        "bindingStatus": "bound",
                        "agentKey": agent_key,
                        "outcome": metric["outcome"],
                        "baselineComplete": metric["baselineComplete"],
                        "baselineCount": metric["baselineCount"],
                        "currentCount": metric["currentCount"],
                        "threshold": metric["threshold"],
                        "expectedCurrentCount": metric["expectedCurrentCount"],
                        "dimension": metric["dimension"],
                    }
                )
                if len(matches) > _RESPONSE_RULE_PREVIEW_LIMIT:
                    raise RuntimeError("behavior rule preview exceeds its safe bound")
        return {
            "matches": matches,
            "count": sum(1 for item in matches if item["outcome"] == "would_alert"),
            "baselineInsufficient": sum(
                1 for item in matches if item["outcome"] == "baseline_insufficient"
            ),
            "mutated": False,
        }
    alerts = [
        item
        for item in _list(tenant, "ALERT", consistent_read=True)
        if item.get("source") == "endpoint_evidence" and item.get("status") == "open"
    ]
    matches = []
    synthetic_rule = {"id": "preview", "configuration": normalized}
    now = int(time.time())
    for alert in sorted(alerts, key=lambda item: str(item.get("id", ""))):
        if not _response_rule_matches(normalized, alert):
            continue
        binding = _endpoint_agent_binding(tenant, alert.get("deviceId", ""), now=now)
        if not _response_rule_matches(normalized, alert, binding):
            reason_code = (
                "host_not_selected" if binding.get("status") == "bound" else "binding_unavailable"
            )
        elif alert.get("caseId"):
            reason_code = "already_cased"
        elif binding.get("status") != "bound":
            reason_code = "binding_unavailable"
        else:
            reason_code = _response_rule_limit_reason(tenant, synthetic_rule, binding, now)
            reason_code = reason_code or "would_contain"
        matches.append(
            {
                "alertId": alert.get("id"),
                "deviceId": alert.get("deviceId"),
                "reasonCode": alert.get("reasonCode"),
                "severity": alert.get("severity"),
                "bindingStatus": binding.get("status"),
                "agentKey": binding.get("agentKey"),
                "outcome": reason_code,
            }
        )
        if len(matches) > _RESPONSE_RULE_PREVIEW_LIMIT:
            raise RuntimeError("response rule preview exceeds its safe bound")
    return {"matches": matches, "count": len(matches), "mutated": False}


def _evaluate_response_rules(tenant, *, now=None):
    """Evaluate approved active rules against retained endpoint alerts."""
    current_time = int(time.time()) if now is None else int(now)
    rules = [
        item
        for item in _list(tenant, "RESPONSE_RULE", consistent_read=True)
        if item.get("enabled") is True
        and int(item.get("active_version", 0)) > 0
        and (item.get("configuration", {}).get("match") or {}).get("source") == "endpoint_evidence"
    ]
    rules.sort(
        key=lambda item: (
            int(item.get("configuration", {}).get("priority", 1_000)),
            str(item.get("id", "")),
        )
    )
    alerts = [
        item
        for item in _list(tenant, "ALERT", consistent_read=True)
        if item.get("source") == "endpoint_evidence" and item.get("status") == "open"
    ]
    outcomes = []
    for rule in rules:
        version = int(rule.get("active_version", 0))
        try:
            version_record = _response_rule_version_record(tenant, rule["id"], version)
            configuration = _response_rule_configuration(rule.get("configuration"))
            if (
                version_record.get("state") != "active"
                or version_record.get("content_hash") != rule.get("content_hash")
                or _configuration_hash(configuration) != rule.get("content_hash")
            ):
                raise RuntimeError("active response rule integrity is invalid")
        except Exception:
            print(json.dumps({"warning": "automatic response rule failed closed"}))
            continue
        for alert in alerts:
            if not _response_rule_matches(configuration, alert):
                continue
            execution_id = _response_execution_id(tenant, rule["id"], version, alert)
            existing = TABLE.get_item(
                Key=_item_key(tenant, "RESPONSE_EXECUTION", execution_id),
                ConsistentRead=True,
            ).get("Item")
            if existing:
                outcomes.append(_response_rule_execution_view(existing))
                continue
            binding = _endpoint_agent_binding(tenant, alert.get("deviceId", ""), now=current_time)
            if binding.get("status") != "bound" or not _response_rule_matches(
                configuration, alert, binding
            ):
                outcomes.append(
                    _record_response_execution(
                        tenant,
                        rule,
                        alert,
                        outcome="skipped",
                        reason_code="binding_unavailable"
                        if binding.get("status") != "bound"
                        else "host_not_selected",
                        agent_key=binding.get("agentKey"),
                        now=current_time,
                    )
                )
                continue
            limit_reason = _reserve_response_rule_action(
                tenant,
                rule,
                alert,
                binding,
                current_time,
            )
            if limit_reason:
                outcomes.append(
                    _record_response_execution(
                        tenant,
                        rule,
                        alert,
                        outcome="skipped",
                        reason_code=limit_reason,
                        agent_key=binding["agentKey"],
                        now=current_time,
                    )
                )
                continue
            actor = f"system:response-rule:{rule['id']}:v{version}"
            case = None
            try:
                if alert.get("caseId"):
                    case = _case_record(tenant, alert["caseId"])
                    if case.get("ownerId") != actor:
                        raise PolicyConflict("alert is owned by another case")
                else:
                    case = _create_case(
                        tenant,
                        {
                            "alertId": alert["id"],
                            "expectedAlertRevision": int(alert.get("revision", 0)),
                            "reason": (
                                f"Approved automatic response rule {rule['id']} version "
                                f"{version} matched this endpoint detection."
                            ),
                        },
                        actor,
                    )
                if case.get("status") == "contained":
                    containment = case.get("containment") or {}
                    if containment.get("activatedBy") != actor:
                        raise PolicyConflict("case containment is owned by another actor")
                else:
                    case = _contain_case(
                        tenant,
                        case["id"],
                        {
                            "expectedCaseRevision": int(case.get("revision", 0)),
                            "expectedBindingDigest": binding["bindingDigest"],
                            "reason": (
                                f"Approved automatic response rule {rule['id']} version "
                                f"{version} quarantined the exactly bound agent."
                            ),
                        },
                        actor,
                    )
                outcomes.append(
                    _record_response_execution(
                        tenant,
                        rule,
                        alert,
                        outcome="contained",
                        reason_code="approved_rule_matched",
                        case_id=case["id"],
                        agent_key=binding["agentKey"],
                        now=current_time,
                    )
                )
            except PolicyConflict:
                # A concurrent rule or responder may have claimed the alert
                # after this evaluator loaded it. Re-read authority instead of
                # inferring ownership from an exception string.
                current_alert = TABLE.get_item(
                    Key=_item_key(tenant, "ALERT", alert["id"]),
                    ConsistentRead=True,
                ).get("Item")
                reason_code = (
                    "alert_already_owned"
                    if (current_alert or {}).get("caseId")
                    else "containment_precondition_failed"
                )
                outcomes.append(
                    _record_response_execution(
                        tenant,
                        rule,
                        alert,
                        outcome="skipped",
                        reason_code=reason_code,
                        case_id=case.get("id") if isinstance(case, dict) else None,
                        agent_key=binding.get("agentKey"),
                        now=current_time,
                    )
                )
            except Exception:
                # A transient dependency or audit failure cannot widen agent
                # authority. Leave the idempotent trigger eligible for retry.
                print(json.dumps({"warning": "automatic response evaluation will retry"}))
    return outcomes


def _create_case(tenant, body, actor):
    """Create one deterministic case from a live supported security alert."""
    if not isinstance(body, dict) or set(body) != {"alertId", "expectedAlertRevision", "reason"}:
        raise ValueError("case creation request has an invalid schema")
    alert_id = _bounded_identifier(body.get("alertId"), "alertId")
    expected = _discovery_integer(
        body.get("expectedAlertRevision"), "expectedAlertRevision", minimum=1
    )
    reason = _case_reason(body.get("reason"))
    alert_key = _item_key(tenant, "ALERT", alert_id)
    alert = TABLE.get_item(Key=alert_key, ConsistentRead=True).get("Item")
    if not alert or alert.get("source") not in {"endpoint_evidence", "behavior_analytics"}:
        raise LookupError("security alert not found")
    if int(alert.get("revision", 0)) != expected:
        raise PolicyConflict("security alert revision changed")
    if alert.get("status") == "resolved":
        raise PolicyConflict("a resolved security alert cannot open a case")
    case_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"aai-case:{tenant}:{alert_id}"))
    now = int(time.time())
    binding = (
        _behavior_agent_binding(tenant, alert)
        if alert.get("source") == "behavior_analytics"
        else _endpoint_agent_binding(tenant, alert.get("deviceId", ""), now=now)
    )
    case = {
        **_item_key(tenant, "CASE", case_id),
        "tenant_id": tenant,
        "id": case_id,
        "alertId": alert_id,
        "title": alert.get("message"),
        "severity": alert.get("severity"),
        "reasonCode": alert.get("reasonCode"),
        "deviceId": alert.get("deviceId", ""),
        "alertSource": alert.get("source"),
        "ownerId": actor,
        "status": "open",
        "revision": 1,
        "createdAt": now,
        "updatedAt": now,
        "binding": binding,
        "containment": None,
    }
    updated_alert = {**alert, "caseId": case_id, "revision": expected + 1}
    event = _case_timeline_record(
        tenant,
        case_id,
        "case_created",
        actor,
        {
            "alertId": alert_id,
            "reason": reason,
            "bindingStatus": binding.get("status"),
            "agentKey": binding.get("agentKey"),
        },
        now=now,
        sequence=1,
    )
    _transact_incident_response(
        [
            _transaction_put(case, condition="attribute_not_exists(pk)"),
            _transaction_put(event, condition="attribute_not_exists(pk)"),
            _transaction_put(
                updated_alert,
                condition="revision = :revision AND attribute_not_exists(caseId)",
                values={":revision": expected},
            ),
        ]
    )
    _audit(
        tenant,
        "incident_case_created",
        actor,
        {"case_id": case_id, "alert_id": alert_id, "binding_status": binding.get("status")},
    )
    return _case_view(tenant, case, detailed=True)


def _case_record(tenant, case_id):
    """Load one exact tenant case or report it as unavailable."""
    case_id = _bounded_identifier(case_id, "caseId")
    case = TABLE.get_item(Key=_item_key(tenant, "CASE", case_id), ConsistentRead=True).get("Item")
    if not case or case.get("status") not in _CASE_STATUSES:
        raise LookupError("incident case not found")
    return case


def _contain_case(tenant, case_id, body, actor):
    """Quarantine the one agent selected by a still-current server binding."""
    if not isinstance(body, dict) or set(body) != {
        "expectedCaseRevision",
        "expectedBindingDigest",
        "reason",
    }:
        raise ValueError("case containment request has an invalid schema")
    expected = _discovery_integer(
        body.get("expectedCaseRevision"), "expectedCaseRevision", minimum=1
    )
    expected_binding = body.get("expectedBindingDigest")
    if not isinstance(expected_binding, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_binding):
        raise ValueError("expectedBindingDigest must be SHA-256")
    reason = _case_reason(body.get("reason"))
    case = _case_record(tenant, case_id)
    if int(case.get("revision", 0)) != expected or case.get("status") not in {
        "open",
        "investigating",
    }:
        raise PolicyConflict("incident case is not available for containment")
    binding = _case_current_binding(tenant, case)
    stored_binding = case.get("binding", {})
    if (
        binding.get("status") != "bound"
        or stored_binding.get("status") != "bound"
        or not secrets.compare_digest(str(binding.get("bindingDigest", "")), expected_binding)
        or not secrets.compare_digest(
            str(stored_binding.get("bindingDigest", "")), expected_binding
        )
    ):
        raise PolicyConflict("security-alert-to-agent binding is unavailable or changed")
    agent_key = binding["agentKey"]
    agent_record = TABLE.get_item(
        Key=_item_key(tenant, "AGENT", agent_key), ConsistentRead=True
    ).get("Item")
    if not agent_record or _agent_lifecycle_state(agent_record) != "active":
        raise PolicyConflict("bound agent identity is not active")
    containment_key = _item_key(tenant, "CONTAINMENT", agent_key)
    existing = TABLE.get_item(Key=containment_key, ConsistentRead=True).get("Item")
    if existing and existing.get("active") is True:
        raise PolicyConflict("bound agent already has active containment")
    now = int(time.time())
    containment_revision = int(existing.get("revision", 0)) + 1 if existing else 1
    containment = {
        **containment_key,
        "tenant_id": tenant,
        "id": agent_key,
        "agentKey": agent_key,
        "deploymentId": binding["deploymentId"],
        "agentId": binding["agentId"],
        "caseId": case["id"],
        "mode": "quarantine",
        "active": True,
        "revision": containment_revision,
        "bindingDigest": expected_binding,
        "activatedAt": now,
        "activatedBy": actor,
        "reason": reason,
    }
    updated_case = {
        **case,
        "status": "contained",
        "revision": expected + 1,
        "updatedAt": now,
        "containment": {
            "mode": "quarantine",
            "active": True,
            "agentKey": agent_key,
            "revision": containment_revision,
            "activatedAt": now,
            "activatedBy": actor,
        },
    }
    event = _case_timeline_record(
        tenant,
        case["id"],
        "agent_quarantined",
        actor,
        {"agentKey": agent_key, "reason": reason, "bindingDigest": expected_binding},
        now=now,
        sequence=expected + 1,
    )
    containment_condition = (
        "revision = :revision AND active = :false" if existing else "attribute_not_exists(pk)"
    )
    containment_values = (
        {":revision": int(existing.get("revision", 0)), ":false": False} if existing else None
    )
    _transact_incident_response(
        [
            _transaction_condition(
                _item_key(tenant, "AGENT", agent_key),
                condition="lifecycle_state = :active AND lifecycle_revision = :revision",
                values={":active": "active", ":revision": int(binding["agentLifecycleRevision"])},
            ),
            _transaction_put(
                updated_case,
                condition="revision = :revision",
                values={":revision": expected},
            ),
            _transaction_put(
                containment,
                condition=containment_condition,
                values=containment_values,
            ),
            _transaction_put(event, condition="attribute_not_exists(pk)"),
        ]
    )
    _audit(
        tenant, "incident_agent_quarantined", actor, {"case_id": case["id"], "agent_key": agent_key}
    )
    return _case_view(tenant, updated_case, detailed=True)


def _case_release_ready(tenant, case, containment):
    """Prove live endpoint and agent recovery while excluding this quarantine."""
    binding = _case_current_binding(tenant, case)
    if binding.get("status") != "bound" or not secrets.compare_digest(
        str(binding.get("bindingDigest", "")), str(containment.get("bindingDigest", ""))
    ):
        raise PolicyConflict("security-alert-to-agent binding is not current")
    if case.get("alertSource", "endpoint_evidence") == "endpoint_evidence":
        health = _endpoint_evidence_health(tenant)
        device = next(
            (
                item
                for item in health.get("items", [])
                if item.get("deviceId") == case.get("deviceId")
            ),
            None,
        )
        if not device or device.get("status") != "healthy":
            raise PolicyConflict("endpoint health has not recovered")
    verification = _verify_agent(tenant, binding["deploymentId"], binding["agentId"])
    non_response_checks = [
        check for name, check in verification["checks"].items() if name != "emergencyStop"
    ]
    control = verification.get("controlState") or {}
    if not all(check.get("passed") is True for check in non_response_checks) or control.get(
        "activeStopScopes"
    ):
        raise PolicyConflict("bound agent has not passed recovery verification")
    alert = TABLE.get_item(
        Key=_item_key(tenant, "ALERT", case.get("alertId", "")), ConsistentRead=True
    ).get("Item")
    if not alert:
        raise PolicyConflict("source alert is unavailable")
    if alert.get("reasonCode") in _ENDPOINT_EVENT_REASONS | _BEHAVIOR_EVENT_REASONS:
        if alert.get("status") not in {"acknowledged", "resolved"}:
            raise PolicyConflict("security event alert has not been acknowledged")
    elif alert.get("status") != "resolved":
        raise PolicyConflict("endpoint posture alert has not resolved")
    return binding


def _release_case(tenant, case_id, body, actor):
    """Release one case-owned quarantine only after server-derived recovery."""
    if not isinstance(body, dict) or set(body) != {
        "expectedCaseRevision",
        "expectedContainmentRevision",
        "reason",
    }:
        raise ValueError("case release request has an invalid schema")
    expected_case = _discovery_integer(
        body.get("expectedCaseRevision"), "expectedCaseRevision", minimum=1
    )
    expected_containment = _discovery_integer(
        body.get("expectedContainmentRevision"), "expectedContainmentRevision", minimum=1
    )
    reason = _case_reason(body.get("reason"))
    case = _case_record(tenant, case_id)
    if int(case.get("revision", 0)) != expected_case or case.get("status") != "contained":
        raise PolicyConflict("incident case is not in contained state")
    containment_summary = case.get("containment") or {}
    agent_key = containment_summary.get("agentKey")
    containment = TABLE.get_item(
        Key=_item_key(tenant, "CONTAINMENT", agent_key or ""), ConsistentRead=True
    ).get("Item")
    if (
        not containment
        or containment.get("caseId") != case["id"]
        or containment.get("active") is not True
        or int(containment.get("revision", 0)) != expected_containment
    ):
        raise PolicyConflict("case containment revision changed")
    _case_release_ready(tenant, case, containment)
    now = int(time.time())
    released = {
        **containment,
        "active": False,
        "revision": expected_containment + 1,
        "releasedAt": now,
        "releasedBy": actor,
        "releaseReason": reason,
    }
    updated_case = {
        **case,
        "status": "investigating",
        "revision": expected_case + 1,
        "updatedAt": now,
        "containment": {
            **containment_summary,
            "active": False,
            "revision": expected_containment + 1,
            "releasedAt": now,
            "releasedBy": actor,
        },
    }
    event = _case_timeline_record(
        tenant,
        case["id"],
        "agent_quarantine_released",
        actor,
        {"agentKey": agent_key, "reason": reason},
        now=now,
        sequence=expected_case + 1,
    )
    _transact_incident_response(
        [
            _transaction_put(
                updated_case, condition="revision = :revision", values={":revision": expected_case}
            ),
            _transaction_put(
                released,
                condition="revision = :revision AND active = :true",
                values={":revision": expected_containment, ":true": True},
            ),
            _transaction_put(event, condition="attribute_not_exists(pk)"),
        ]
    )
    _audit(
        tenant,
        "incident_agent_quarantine_released",
        actor,
        {"case_id": case["id"], "agent_key": agent_key},
    )
    return _case_view(tenant, updated_case, detailed=True)


def _revoke_case_sessions(tenant, case_id, body, actor):
    """Invalidate every old session/bootstrap revision for the bound agent."""
    if not isinstance(body, dict) or set(body) != {"expectedCaseRevision", "reason"}:
        raise ValueError("case session revocation request has an invalid schema")
    expected_case = _discovery_integer(
        body.get("expectedCaseRevision"), "expectedCaseRevision", minimum=1
    )
    reason = _case_reason(body.get("reason"))
    case = _case_record(tenant, case_id)
    if int(case.get("revision", 0)) != expected_case or case.get("status") in {
        "resolved",
        "closed",
    }:
        raise PolicyConflict("incident case is not active")
    binding = _case_current_binding(tenant, case)
    stored = case.get("binding", {})
    if binding.get("status") != "bound" or not secrets.compare_digest(
        str(binding.get("bindingDigest", "")), str(stored.get("bindingDigest", ""))
    ):
        raise PolicyConflict("security-alert-to-agent binding is unavailable or changed")
    agent_key = binding["agentKey"]
    agent = TABLE.get_item(Key=_item_key(tenant, "AGENT", agent_key), ConsistentRead=True).get(
        "Item"
    )
    current_session_revision = _agent_session_revision(agent)
    if not agent or current_session_revision is None or _agent_lifecycle_state(agent) != "active":
        raise PolicyConflict("bound agent session authority is unavailable")
    now = int(time.time())
    updated_agent = {
        **agent,
        "session_revision": current_session_revision + 1,
        "status": "offline",
        "last_heartbeat": 0,
        "expires_at": 0,
    }
    updated_case = {
        **case,
        "revision": expected_case + 1,
        "updatedAt": now,
        "sessionRevokedAt": now,
        "sessionRevokedBy": actor,
    }
    event = _case_timeline_record(
        tenant,
        case["id"],
        "agent_sessions_revoked",
        actor,
        {"agentKey": agent_key, "reason": reason, "sessionRevision": current_session_revision + 1},
        now=now,
        sequence=expected_case + 1,
    )
    _transact_incident_response(
        [
            _transaction_put(
                updated_case, condition="revision = :revision", values={":revision": expected_case}
            ),
            _transaction_put(
                updated_agent,
                condition=(
                    "lifecycle_state = :active AND lifecycle_revision = :lifecycle AND "
                    "(attribute_not_exists(session_revision) OR session_revision = :session)"
                ),
                values={
                    ":active": "active",
                    ":lifecycle": int(agent["lifecycle_revision"]),
                    ":session": current_session_revision,
                },
            ),
            _transaction_put(event, condition="attribute_not_exists(pk)"),
        ]
    )
    _audit(
        tenant,
        "incident_agent_sessions_revoked",
        actor,
        {
            "case_id": case["id"],
            "agent_key": agent_key,
            "session_revision": current_session_revision + 1,
        },
    )
    return _case_view(tenant, updated_case, detailed=True)


def _transition_case(tenant, case_id, body, actor, target):
    """Resolve or close a case while preserving response-state safeguards."""
    if target not in {"resolved", "closed"}:
        raise ValueError("case transition target is unsupported")
    if not isinstance(body, dict) or set(body) != {"expectedCaseRevision", "reason"}:
        raise ValueError("case transition request has an invalid schema")
    expected = _discovery_integer(
        body.get("expectedCaseRevision"), "expectedCaseRevision", minimum=1
    )
    reason = _case_reason(body.get("reason"))
    case = _case_record(tenant, case_id)
    if int(case.get("revision", 0)) != expected:
        raise PolicyConflict("incident case revision changed")
    if case.get("containment", {}).get("active") is True:
        raise PolicyConflict("active containment must be released before case transition")
    if target == "resolved" and case.get("status") not in {"open", "investigating"}:
        raise PolicyConflict("incident case cannot be resolved from its current state")
    if target == "closed" and case.get("status") != "resolved":
        raise PolicyConflict("incident case must be resolved before closure")
    alert = TABLE.get_item(
        Key=_item_key(tenant, "ALERT", case.get("alertId", "")), ConsistentRead=True
    ).get("Item")
    if target == "resolved" and alert:
        if alert.get("reasonCode") in _ENDPOINT_EVENT_REASONS | _BEHAVIOR_EVENT_REASONS:
            ready = alert.get("status") in {"acknowledged", "resolved"}
        else:
            ready = alert.get("status") == "resolved"
        if not ready:
            raise PolicyConflict("source alert is not ready for case resolution")
    now = int(time.time())
    timestamp_field = "resolvedAt" if target == "resolved" else "closedAt"
    actor_field = "resolvedBy" if target == "resolved" else "closedBy"
    updated = {
        **case,
        "status": target,
        "revision": expected + 1,
        "updatedAt": now,
        timestamp_field: now,
        actor_field: actor,
    }
    event = _case_timeline_record(
        tenant,
        case["id"],
        f"case_{target}",
        actor,
        {"reason": reason},
        now=now,
        sequence=expected + 1,
    )
    _transact_incident_response(
        [
            _transaction_put(
                updated, condition="revision = :revision", values={":revision": expected}
            ),
            _transaction_put(event, condition="attribute_not_exists(pk)"),
        ]
    )
    _audit(tenant, f"incident_case_{target}", actor, {"case_id": case["id"]})
    return _case_view(tenant, updated, detailed=True)


def _endpoint_detection_cycle():
    """Reconcile every registered endpoint tenant on the five-minute schedule."""
    tenants = []
    for shard in range(_ENDPOINT_DETECTION_SHARDS):
        result = TABLE.query(
            IndexName=_ENDPOINT_DETECTION_INDEX,
            KeyConditionExpression=Key("endpoint_detection_pk").eq(
                f"ENDPOINT_DETECTION#{shard:02d}"
            ),
            Limit=250,
        )
        if result.get("LastEvaluatedKey"):
            raise RuntimeError("endpoint detection tenant shard exceeds its safe bound")
        tenants.extend(result.get("Items", []))
        if len(tenants) > _ENDPOINT_DETECTION_TENANT_LIMIT:
            raise RuntimeError("endpoint detection tenant inventory exceeds its safe bound")
    processed = 0
    failed = 0
    for registration in tenants:
        tenant = registration.get("endpoint_detection_sk")
        if not isinstance(tenant, str) or registration.get("pk") != f"TENANT#{tenant}":
            failed += 1
            continue
        try:
            health = _endpoint_evidence_health(tenant)
            _reconcile_endpoint_alerts(tenant, health, automatic_response=True)
            processed += 1
        except Exception:
            failed += 1
    if failed:
        raise RuntimeError("one or more endpoint tenant detection cycles failed")
    return {"processedTenants": processed, "failedTenants": 0}


def _rollout_reconciliation_cycle():
    """Reconcile bounded rollout state on the five-minute internal schedule."""
    tenants = []
    for shard in range(_ENDPOINT_DETECTION_SHARDS):
        result = TABLE.query(
            IndexName=_ENDPOINT_DETECTION_INDEX,
            KeyConditionExpression=Key("endpoint_detection_pk").eq(
                f"ENDPOINT_DETECTION#{shard:02d}"
            ),
            Limit=250,
        )
        if result.get("LastEvaluatedKey"):
            raise RuntimeError("rollout tenant shard exceeds its safe bound")
        tenants.extend(result.get("Items", []))
        if len(tenants) > _ENDPOINT_DETECTION_TENANT_LIMIT:
            raise RuntimeError("rollout tenant inventory exceeds its safe bound")
    processed_tenants = 0
    processed_rollouts = 0
    failed = 0
    for registration in tenants:
        tenant = registration.get("endpoint_detection_sk")
        if not isinstance(tenant, str) or registration.get("pk") != f"TENANT#{tenant}":
            failed += 1
            continue
        try:
            configurations = _list(tenant, "CONFIGURATION", consistent_read=True)
            processed_rollouts += len(configurations)
            if processed_rollouts > _ROLLOUT_CONFIGURATION_LIMIT:
                raise RuntimeError("scheduled rollout inventory exceeds its safe bound")
            for configuration in configurations:
                _reconcile_deployment_rollout(tenant, configuration)
            processed_tenants += 1
        except Exception:
            failed += 1
    if failed:
        raise RuntimeError("one or more tenant rollout reconciliation cycles failed")
    return {
        "processedTenants": processed_tenants,
        "processedRollouts": processed_rollouts,
        "failedTenants": 0,
    }


def _dynamic_reconciliation_error_code(error):
    """Map internal failures to fixed operator-safe reconciliation codes."""
    if isinstance(error, ValueError):
        return "malformed_approved_rule"
    if isinstance(error, PolicyConflict):
        return "policy_state_conflict"
    return "control_plane_failure"


def _dynamic_group_reconciliation_cycle():
    """Reconcile approved dynamic groups on the internal five-minute schedule."""
    tenants = []
    for shard in range(_ENDPOINT_DETECTION_SHARDS):
        result = TABLE.query(
            IndexName=_ENDPOINT_DETECTION_INDEX,
            KeyConditionExpression=Key("endpoint_detection_pk").eq(
                f"ENDPOINT_DETECTION#{shard:02d}"
            ),
            Limit=250,
        )
        if result.get("LastEvaluatedKey"):
            raise RuntimeError("dynamic group tenant shard exceeds its safe bound")
        tenants.extend(result.get("Items", []))
        if len(tenants) > _ENDPOINT_DETECTION_TENANT_LIMIT:
            raise RuntimeError("dynamic group tenant inventory exceeds its safe bound")
    processed_tenants = 0
    processed_groups = 0
    failed_groups = 0
    for registration in tenants:
        tenant = registration.get("endpoint_detection_sk")
        if not isinstance(tenant, str) or registration.get("pk") != f"TENANT#{tenant}":
            failed_groups += 1
            continue
        for group in _list(tenant, "GROUP", consistent_read=True):
            if _group_membership_mode(group) != "dynamic":
                continue
            processed_groups += 1
            if processed_groups > _DYNAMIC_GROUP_RECONCILIATION_LIMIT:
                raise RuntimeError("dynamic group schedule exceeds its safe bound")
            try:
                result = _reconcile_dynamic_group(tenant, group)
                if result.get("outcome") == "failed":
                    failed_groups += 1
            except Exception as error:
                failed_groups += 1
                _record_dynamic_reconciliation_failure(
                    tenant,
                    group,
                    _dynamic_reconciliation_error_code(error),
                    now=int(time.time()),
                )
        processed_tenants += 1
    if failed_groups:
        raise RuntimeError("one or more dynamic group reconciliations failed")
    return {
        "processedTenants": processed_tenants,
        "processedGroups": processed_groups,
        "failedGroups": 0,
    }


def _discovery_counts(instances):
    """Count target posture without allowing duplicates to inflate coverage."""
    denominator = len(instances)
    enrolled = sum(1 for item in instances if item["agentCount"] >= 1)
    healthy = sum(1 for item in instances if item["healthy"] is True)
    compliant = sum(1 for item in instances if item["compliant"] is True)
    return {
        "denominator": denominator,
        "enrolled": enrolled,
        "healthy": healthy,
        "compliant": compliant,
        "unmanaged": sum(1 for item in instances if "unmanaged" in item["reasonCodes"]),
        "duplicate": sum(
            1
            for item in instances
            if any(reason.startswith("duplicate_") for reason in item["reasonCodes"])
        ),
        "leaver": sum(1 for item in instances if "inactive_user" in item["reasonCodes"]),
    }


def _discovery_breakdown(instances, field, label):
    """Aggregate one privacy-reviewed display dimension from target records."""
    buckets = {}
    for instance in instances:
        values = instance.get(field) or ["unassigned"]
        for value in values:
            buckets.setdefault(value, []).append(instance)
    return [
        {label: value, **_discovery_counts(items)}
        for value, items in sorted(buckets.items(), key=lambda entry: entry[0].lower())
    ]


def _discovery_report(tenant, *, now=None):
    """Reconcile fresh source snapshots with server-owned enrolled-agent inventory.

    The report is deliberately observational. Source records may lower posture
    and raise findings, but they cannot create enrollment, change policy, or
    revoke an agent. Missing, incomplete, stale, or empty required population
    evidence makes percentage coverage unavailable instead of optimistic.
    """
    current_time = int(time.time()) if now is None else int(now)
    source_records = _list(tenant, "DISCOVERY_SOURCE", consistent_read=True)
    current_sources = []
    source_views = []
    for source in sorted(source_records, key=lambda item: str(item.get("sourceId", ""))):
        complete = source.get("complete") is True
        fresh = int(source.get("expiresAt", 0)) > current_time
        observations = _discovery_generation_observations(tenant, source)
        has_observations = isinstance(observations, list) and bool(observations)
        status = (
            "current"
            if complete and fresh and has_observations
            else "incomplete"
            if not complete
            else "stale"
            if not fresh
            else "empty"
        )
        if status == "current" and isinstance(observations, list):
            current_sources.append(source)
        source_views.append(
            {
                "sourceId": source.get("sourceId"),
                "sourceKind": source.get("sourceKind"),
                "generation": source.get("generation"),
                "revision": int(source.get("revision", 0)),
                "status": status,
                "complete": complete,
                "observedAt": int(source.get("observedAt", 0)),
                "expiresAt": int(source.get("expiresAt", 0)),
                "observationCount": len(observations) if isinstance(observations, list) else 0,
                "contentHash": source.get("contentHash"),
            }
        )
    current_kinds = {source.get("sourceKind") for source in current_sources}
    blind_spots = []
    for required_kind in sorted(_DISCOVERY_REQUIRED_SOURCE_KINDS):
        records = [source for source in source_views if source.get("sourceKind") == required_kind]
        if not records:
            blind_spots.append(f"missing_source:{required_kind}")
        elif not any(source["status"] == "current" for source in records):
            prefix = (
                "empty_source"
                if any(source["status"] == "empty" for source in records)
                else "non_current_source"
            )
            blind_spots.append(f"{prefix}:{required_kind}")

    observations = [
        observation
        for source in current_sources
        for observation in _discovery_generation_observations(tenant, source)
        if isinstance(observation, dict)
    ]
    identities = {
        item["id"]: item
        for item in observations
        if item.get("kind") == "identity" and isinstance(item.get("id"), str)
    }
    devices = {
        item["id"]: item
        for item in observations
        if item.get("kind") == "device" and isinstance(item.get("id"), str)
    }
    repositories = [item for item in observations if item.get("kind") == "repository"]
    installations = [item for item in observations if item.get("kind") == "installation"]

    targets = {}

    def target_for(project_digest, host):
        key = f"{project_digest}:{host}"
        return targets.setdefault(
            key,
            {
                "projectRootDigest": project_digest,
                "host": host,
                "repositories": set(),
                "devices": set(),
                "businessUnits": set(),
                "installations": [],
            },
        )

    for repository in repositories:
        for host in repository.get("expectedHosts", []):
            target = target_for(repository.get("projectRootDigest"), host)
            target["repositories"].add(repository.get("id"))
            if repository.get("businessUnit"):
                target["businessUnits"].add(repository["businessUnit"])
    for installation in installations:
        target = target_for(installation.get("projectRootDigest"), installation.get("host"))
        target["installations"].append(installation)
        target["devices"].add(installation.get("deviceId"))
        if installation.get("repositoryId"):
            target["repositories"].add(installation["repositoryId"])
        if installation.get("businessUnit"):
            target["businessUnits"].add(installation["businessUnit"])
        device = devices.get(installation.get("deviceId"))
        if device and device.get("businessUnit"):
            target["businessUnits"].add(device["businessUnit"])

    agents = [
        agent
        for agent in _all_agents(tenant, consistent_read=True)
        if _agent_lifecycle_state(agent) == "active"
    ]
    agents_by_target = {}
    agent_targets = {}
    for agent in agents:
        project_root = agent.get("project_root")
        if not isinstance(project_root, str) or not project_root:
            continue
        key = f"{hashlib.sha256(project_root.encode()).hexdigest()}:{agent.get('host')}"
        agents_by_target.setdefault(key, []).append(agent)
        agent_targets[f"{agent.get('deployment_id')}:{agent.get('id')}"] = key

    instance_views = []
    leaver_agent_keys = {
        f"{agent.get('deployment_id')}:{agent.get('id')}"
        for agent in agents
        if agent.get("owner_id") in identities
        and identities[agent.get("owner_id")].get("active") is False
    }
    duplicate_agent_keys = set()
    for target_key, target in sorted(targets.items()):
        matched_agents = agents_by_target.get(target_key, [])
        matched_installations = target["installations"]
        reasons = []
        if not matched_agents:
            reasons.append("unmanaged")
        if len(matched_agents) > 1:
            reasons.append("duplicate_enrollment")
        if len(matched_installations) > 1:
            reasons.append("duplicate_installation")
        if not matched_installations:
            reasons.append("installation_missing")
        elif not any(item.get("binaryPresent") is True for item in matched_installations):
            reasons.append("binary_missing")
        if matched_installations and not any(
            item.get("processActive") is True for item in matched_installations
        ):
            reasons.append("process_not_observed")
        if any(
            devices.get(item.get("deviceId"), {}).get("managed") is False
            for item in matched_installations
        ):
            reasons.append("unmanaged_device")
        inactive_users = {
            item.get("userId")
            for item in matched_installations
            if item.get("userId") in identities
            and identities[item.get("userId")].get("active") is False
        }
        for agent in matched_agents:
            owner_id = agent.get("owner_id")
            if owner_id in identities and identities[owner_id].get("active") is False:
                inactive_users.add(owner_id)
        if inactive_users:
            reasons.append("inactive_user")
            leaver_agent_keys.update(
                f"{agent.get('deployment_id')}:{agent.get('id')}" for agent in matched_agents
            )
        if len(matched_agents) > 1 or len(matched_installations) > 1:
            duplicate_agent_keys.update(
                f"{agent.get('deployment_id')}:{agent.get('id')}" for agent in matched_agents
            )
        exact_agent = matched_agents[0] if len(matched_agents) == 1 else None
        healthy = bool(
            exact_agent
            and exact_agent.get("status") == "connected"
            and not any(
                reason
                in {
                    "duplicate_installation",
                    "installation_missing",
                    "process_not_observed",
                    "inactive_user",
                    "unmanaged_device",
                    "binary_missing",
                }
                for reason in reasons
            )
        )
        managed = exact_agent.get("managed_configuration", {}) if exact_agent else {}
        compliant = bool(
            healthy
            and exact_agent.get("attestation_status") == "compliant"
            and isinstance(managed, dict)
            and managed.get("status") == "enforced"
        )
        agent_keys = sorted(
            f"{agent.get('deployment_id')}:{agent.get('id')}" for agent in matched_agents
        )
        instance_views.append(
            {
                "targetId": hashlib.sha256(target_key.encode()).hexdigest(),
                "host": target["host"],
                "projectRootDigest": target["projectRootDigest"],
                "businessUnits": sorted(value for value in target["businessUnits"] if value),
                "repositoryIds": sorted(value for value in target["repositories"] if value),
                "deviceIds": sorted(value for value in target["devices"] if value),
                "installationIds": sorted(item["id"] for item in matched_installations),
                "agentKeys": agent_keys,
                "agentCount": len(matched_agents),
                "installationCount": len(matched_installations),
                "healthy": healthy,
                "compliant": compliant,
                "reasonCodes": sorted(set(reasons)),
            }
        )

    endpoint_devices_present = any(item.get("kind") == "device" for item in observations)
    endpoint_installations_present = any(
        item.get("kind") == "installation" for item in observations
    )
    if "endpoint" in current_kinds and not endpoint_devices_present:
        blind_spots.append("missing_endpoint_devices")
    if "endpoint" in current_kinds and not endpoint_installations_present:
        blind_spots.append("missing_endpoint_installations")
    source_complete = (
        current_kinds == _DISCOVERY_REQUIRED_SOURCE_KINDS
        and endpoint_devices_present
        and endpoint_installations_present
    )
    orphaned_agent_keys = {
        f"{agent.get('deployment_id')}:{agent.get('id')}"
        for agent in agents
        if source_complete
        and agent_targets.get(f"{agent.get('deployment_id')}:{agent.get('id')}") not in targets
    }
    agent_findings = []
    for agent in agents:
        agent_key = f"{agent.get('deployment_id')}:{agent.get('id')}"
        reasons = []
        if agent_key in orphaned_agent_keys:
            reasons.append("orphaned_enrollment")
        if agent_key in leaver_agent_keys:
            reasons.append("inactive_owner_or_user")
        if agent_key in duplicate_agent_keys:
            reasons.append("duplicate_target")
        if reasons:
            agent_findings.append(
                {
                    "agentKey": agent_key,
                    "deploymentId": agent.get("deployment_id"),
                    "agentId": agent.get("id"),
                    "host": agent.get("host"),
                    "reasonCodes": reasons,
                }
            )

    counts = _discovery_counts(instance_views)
    population_available = source_complete and counts["denominator"] > 0
    if source_complete and counts["denominator"] == 0:
        blind_spots.append("empty_expected_population")

    def percentage(numerator):
        return round((100 * numerator) / counts["denominator"], 1) if population_available else None

    summary = {
        **counts,
        "orphaned": len(orphaned_agent_keys),
        "leaver": len(leaver_agent_keys),
        "coverageAvailable": population_available,
        "sourceComplete": source_complete,
        "coveragePercent": percentage(counts["enrolled"]),
        "healthyPercent": percentage(counts["healthy"]),
        "compliantPercent": percentage(counts["compliant"]),
    }
    return {
        "schemaVersion": 1,
        "generatedAt": current_time,
        "summary": summary,
        "blindSpots": sorted(set(blind_spots)),
        "sources": source_views,
        "instances": instance_views,
        "agentFindings": agent_findings,
        "breakdowns": {
            "businessUnits": _discovery_breakdown(instance_views, "businessUnits", "businessUnit"),
            "repositories": _discovery_breakdown(instance_views, "repositoryIds", "repositoryId"),
            "devices": _discovery_breakdown(instance_views, "deviceIds", "deviceId"),
        },
    }


def _discovery_export(tenant):
    """Return a content-addressed discovery report without raw paths or user names."""
    report = _discovery_report(tenant)
    digest = hashlib.sha256(
        json.dumps(_json(report), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {**report, "contentHash": digest}


def _assurance_report(tenant, profile, *, now=None):
    """Build one content-addressed, read-only enterprise assurance summary.

    The report derives every fact from bounded server-owned records. It does
    not reconcile lifecycle state or write an audit event because a read-only
    report must never change the authority or evidence it is describing.
    """
    if profile not in {"executive", "auditor"}:
        raise ValueError("assurance report profile is unsupported")
    current = int(time.time()) if now is None else int(now)
    discovery = _discovery_report(tenant, now=current)
    endpoint = _endpoint_evidence_health(tenant, now=current)
    agents = [
        item
        for item in _all_agents(tenant, consistent_read=True)
        if _agent_lifecycle_state(item) == "active"
    ]
    groups = _list(tenant, "GROUP", consistent_read=True)
    policies = _list(tenant, "POLICY", consistent_read=True)
    versions = _list(tenant, "POLICY_VERSION", consistent_read=True)
    exceptions = _list(tenant, "POLICY_EXCEPTION", consistent_read=True)
    approvals = _list(tenant, "APPROVAL", consistent_read=True)
    alerts = _list(tenant, "ALERT", consistent_read=True)
    cases = _list(tenant, "CASE", consistent_read=True)
    decisions, decisions_truncated = _decision_window(tenant)

    active_policy_ids = {
        str(item.get("id"))
        for item in policies
        if isinstance(item.get("id"), str) and int(item.get("version", 0)) > 0
    }
    pending_states = {"draft", "review", "approved", "staged"}
    policy_state_counts = {
        state: sum(1 for item in versions if item.get("state") == state)
        for state in sorted(_POLICY_VERSION_STATES)
    }
    connected = sum(
        1
        for item in agents
        if item.get("status") == "connected" and int(item.get("expires_at", 0)) > current
    )
    attested = sum(
        1
        for item in agents
        if item.get("attestation_status") == "compliant"
        and int(item.get("attestation_expires_at", 0)) > current
    )
    managed = sum(
        1
        for item in agents
        if isinstance(item.get("managed_configuration"), dict)
        and item["managed_configuration"].get("status") == "enforced"
    )
    active_exceptions = sum(
        1
        for item in exceptions
        if item.get("state") == "active" and int(item.get("expires_at", 0)) > current
    )
    expiring_exceptions = sum(
        1
        for item in exceptions
        if item.get("state") == "active"
        and current < int(item.get("expires_at", 0)) <= current + (7 * 24 * 60 * 60)
    )
    approval_counts = {
        state: sum(1 for item in approvals if _approval_status(item, current) == state)
        for state in ("pending", "approved", "consumed", "denied", "expired")
    }
    open_alerts = sum(1 for item in alerts if item.get("status") not in {"resolved", "closed"})
    open_cases = sum(1 for item in cases if item.get("status") not in {"resolved", "closed"})
    evidence_monitor = _evidence_monitor_view(_evidence_monitor_record(tenant))

    population = _json(discovery["summary"])
    runtime = {
        "activeAgents": len(agents),
        "connected": connected,
        "runtimeAttested": attested,
        "managedConfigurationEnforced": managed,
        "endpointDevices": int(endpoint["summary"]["devices"]),
        "healthyEndpointDevices": int(endpoint["summary"]["healthy"]),
    }
    policy = {
        "policies": len(policies),
        "activePolicies": len(active_policy_ids),
        "pendingVersions": sum(policy_state_counts[state] for state in pending_states),
        "groups": len(groups),
        "groupsWithActivePolicy": sum(
            1 for item in groups if item.get("policyId") in active_policy_ids
        ),
        "versionStates": policy_state_counts,
    }
    exception = {
        "active": active_exceptions,
        "expiringWithinSevenDays": expiring_exceptions,
        "totalRetained": len(exceptions),
    }
    operations = {
        "openAlerts": open_alerts,
        "openCases": open_cases,
        "approvalStates": approval_counts,
        "recentDecisions": len(decisions),
        "recentDecisionWindowTruncated": decisions_truncated,
        "fleetEmergencyStop": _fleet_emergency_stop_active(tenant),
    }
    evidence = {
        "status": evidence_monitor["status"],
        "reasonCodes": evidence_monitor["reasonCodes"],
        "lastCheckedAt": evidence_monitor["checkedAt"],
        "durableAlertDelivered": evidence_monitor["alertDelivered"],
        "immutableStore": "s3-object-lock",
    }

    blind_spots = list(discovery["blindSpots"])
    if agents and connected < len(agents):
        blind_spots.append("agent_heartbeat_incomplete")
    if agents and attested < len(agents):
        blind_spots.append("runtime_attestation_incomplete")
    if agents and managed < len(agents):
        blind_spots.append("managed_configuration_incomplete")
    if agents and endpoint["summary"]["devices"] == 0:
        blind_spots.append("endpoint_evidence_unavailable")
    if evidence_monitor["status"] != "verified":
        blind_spots.append("immutable_evidence_not_verified")
    blind_spots = sorted(set(blind_spots))
    attention = bool(
        open_alerts
        or open_cases
        or active_exceptions
        or connected < len(agents)
        or attested < len(agents)
        or managed < len(agents)
    )
    posture = (
        "evidence_incomplete"
        if blind_spots or population.get("coverageAvailable") is not True
        else "attention"
        if attention
        else "ready"
    )
    sections = {
        "population": population,
        "runtime": runtime,
        "policy": policy,
        "exceptions": exception,
        "operations": operations,
        "evidence": evidence,
    }
    routes = {
        "population": "/api/enterprise/discovery/export",
        "runtime": "/api/enterprise/endpoint-evidence",
        "policy": "/api/enterprise/policies",
        "exceptions": "/api/enterprise/policy-exceptions",
        "operations": "/api/enterprise/cases",
        "evidence": "/api/enterprise/evidence/export",
    }
    trace = [
        {
            "section": name,
            "contentHash": _canonical_sha256(value),
            **({"evidenceRoute": routes[name]} if profile == "auditor" else {}),
        }
        for name, value in sections.items()
    ]
    report = {
        "schemaVersion": 1,
        "profile": profile,
        "generatedAt": current,
        "posture": posture,
        "sections": sections,
        "blindSpots": blind_spots,
        "nonGuarantees": [
            "This report is not a compliance certification.",
            "Agent and endpoint reports are operational evidence, not authorization facts.",
            "The content hash is not a digital signature or trusted timestamp.",
        ],
        "trace": trace,
    }
    if profile == "auditor":
        report["details"] = {
            "breakdowns": _json(discovery["breakdowns"]),
            "policies": [
                {
                    "policyId": item.get("id"),
                    "activeVersion": int(item.get("version", 0)),
                }
                for item in sorted(policies, key=lambda value: str(value.get("id", "")))
            ],
            "groups": [
                {
                    "groupId": item.get("id"),
                    "policyId": item.get("policyId"),
                    "membershipMode": _group_membership_mode(item),
                    "memberCount": len(item.get("agent_keys", [])),
                }
                for item in sorted(groups, key=lambda value: str(value.get("id", "")))
            ],
            "accessCertificationRoute": "/api/enterprise/identity/access-certification",
        }
    return {**report, "contentHash": _canonical_sha256(report)}


def _fleet(tenant):
    agents = _all_agents(tenant)
    groups = []
    for group in _list(tenant, "GROUP"):
        group["emergencyStop"] = bool(
            group.get("emergencyStop") is True
            or _scope_emergency_stop(tenant, "group", group.get("id", ""))
        )
        group["membershipRevision"] = _group_membership_revision(group)
        group["configurationRevision"] = int(group.get("configuration_revision", 1))
        group["membershipMode"] = _group_membership_mode(group)
        group["dynamicRule"] = group.get("dynamic_rule")
        group["dynamicRuleHash"] = group.get("dynamic_rule_hash")
        group["dynamicLastEvaluatedAt"] = group.get("dynamic_last_evaluated_at")
        group["dynamicLastEvaluatedBy"] = group.get("dynamic_last_evaluated_by")
        group["dynamicReconciliation"] = (
            _dynamic_reconciliation_status(tenant, group.get("id", ""))
            if group["membershipMode"] == "dynamic"
            else None
        )
        group["agents"] = [
            a for a in agents if f"{a['deployment_id']}:{a['id']}" in group.get("agent_keys", [])
        ]
        groups.append(group)
    for agent in agents:
        control_state = _agent_control_state(tenant, agent)
        agent["controlState"] = control_state
        # Preserve the established summary field while deriving it from exact
        # independent controls rather than a browser-mutated presentation flag.
        agent["effectiveEmergencyStop"] = bool(control_state["activeStopScopes"])
    policy_versions = _list(tenant, "POLICY_VERSION")
    policies = []
    for policy in _list(tenant, "POLICY"):
        governed = _ensure_policy_governance(tenant, policy)
        versions = [item for item in policy_versions if item.get("policy_id") == governed.get("id")]
        # A legacy migration may have created the first ledger record after
        # the snapshot above. Reload only that one policy's ledger when needed.
        if not versions:
            versions = _policy_versions(tenant, governed["id"])
        policies.append(_policy_summary(tenant, governed, versions))
    configurations = _deployment_configurations(tenant)
    skills = _list(tenant, "SKILL")
    mcp_servers = _list(tenant, "MCP")
    for registration in [*skills, *mcp_servers]:
        registration["revision"] = int(registration.get("revision", 1))
        registration["status"] = registration.get(
            "status", "active" if registration.get("enabled", True) else "disabled"
        )
    return {
        "organizations": _list(tenant, "ORG"),
        "projects": _list(tenant, "PROJECT"),
        "deployments": _list(tenant, "DEPLOYMENT"),
        "agents": agents,
        "sessions": [],
        "drift": [item for item in configurations if item.get("drifted")],
        "templates": _list(tenant, "TEMPLATE"),
        "policies": policies,
        "groups": groups,
        "skills": skills,
        "mcpServers": mcp_servers,
        "configurations": configurations,
        "configurationHistory": _list(tenant, "CONFIGURATION_VERSION"),
        "health": [
            {
                "deploymentId": d["id"],
                "emergencyStop": any(
                    not a.get("controlState", {}).get("executionAllowed", True)
                    for a in agents
                    if a["deployment_id"] == d["id"]
                ),
                "status": "healthy",
            }
            for d in _list(tenant, "DEPLOYMENT")
        ],
        "slo": [],
        "alerts": [],
        "cases": [_case_view(tenant, item) for item in _list(tenant, "CASE")],
        "complianceEvidence": {
            "schemaVersion": 1,
            "organizationId": "org-demo",
            "generatedAt": int(time.time()),
            "activeSessionCount": sum(
                1
                for agent in agents
                if _agent_lifecycle_state(agent) == "active"
                and agent.get("status") == "connected"
                and int(agent.get("expires_at", 0)) > int(time.time())
            ),
            "deploymentCount": len(_list(tenant, "DEPLOYMENT")),
            "deployments": [],
            "audit": [],
        },
        "auditEvidence": [],
        "capabilities": {
            "persistence": "dynamodb",
            "highAvailability": True,
            "audit": "s3-object-lock",
        },
    }


def _verify_agent(tenant, deployment_id, agent_id):
    """Return live enrollment checks used by the operator console.

    Verification is an operational assertion, not a record-existence check:
    an agent is ready only when its identity exists, its heartbeat is current,
    a valid policy group is assigned, and no emergency stop is active.
    """
    # One clock snapshot keeps the readiness boolean, explanation and evidence
    # timestamp internally consistent at the session-expiry boundary.
    checked_at = int(time.time())
    agent = TABLE.get_item(
        Key=_item_key(tenant, "AGENT", f"{deployment_id}:{agent_id}"),
        ConsistentRead=True,
    ).get("Item")
    groups = [
        group
        for group in _list(tenant, "GROUP", consistent_read=True)
        if f"{deployment_id}:{agent_id}" in group.get("agent_keys", [])
    ]
    policy = None
    policy_assigned = False
    if len(groups) == 1:
        policy = TABLE.get_item(
            Key=_item_key(tenant, "POLICY", groups[0].get("policyId", "")),
            ConsistentRead=True,
        ).get("Item")
        policy_assigned = bool(policy)
    control_state = _agent_control_state(tenant, agent) if agent else None
    registered = bool(agent)
    lifecycle_active = bool(agent and _agent_lifecycle_state(agent) == "active")
    heartbeat_current = bool(
        agent
        and lifecycle_active
        and agent.get("status") == "connected"
        and int(agent.get("expires_at", 0)) > checked_at
    )
    attestation_manifest = (
        _runtime_manifest(tenant, deployment_id, agent.get("host", "")) if agent else None
    )
    attestation_current = bool(
        agent
        and attestation_manifest
        and agent.get("attestation_status") == "compliant"
        and int(agent.get("attestation_expires_at", 0)) > checked_at
    )
    managed_configuration = (
        _managed_configuration_posture(tenant, agent, now=checked_at) if agent else None
    )
    managed_configuration_current = bool(
        managed_configuration and managed_configuration.get("status") == "enforced"
    )
    ownership = _agent_ownership_view(agent, now=checked_at) if agent else None
    ownership_current = bool(ownership and ownership.get("status") == "current")
    if not agent:
        heartbeat_detail = "Agent is not registered to this deployment."
    elif agent.get("status") != "connected":
        heartbeat_detail = "Agent is offline or disconnected."
    elif int(agent.get("expires_at", 0)) <= checked_at:
        heartbeat_detail = "The agent heartbeat session has expired."
    else:
        heartbeat_detail = "Heartbeat is current and the session is connected."
    if len(groups) > 1:
        policy_detail = "Conflicting policy-group assignments must be resolved."
    elif policy_assigned:
        policy_detail = "Exactly one valid policy group is assigned."
    else:
        policy_detail = "No valid policy group is assigned."
    checks = {
        "registered": {
            "passed": registered,
            "detail": (
                "Agent is registered to this deployment."
                if registered
                else "Agent is not registered to this deployment."
            ),
        },
        "lifecycle": {
            "passed": lifecycle_active,
            "detail": (
                "Agent identity is active."
                if lifecycle_active
                else "Agent identity is revoked, offboarded, or malformed."
            ),
        },
        "heartbeat": {
            "passed": heartbeat_current,
            "detail": heartbeat_detail,
        },
        "runtimeAttestation": {
            "passed": attestation_current,
            "detail": (
                "Runtime artifacts match the approved manifest and enrollment baseline."
                if attestation_current
                else (
                    "No deployment-owned runtime manifest matches this host and SDK version."
                    if agent and not attestation_manifest
                    else "Runtime attestation is missing, expired, or non-compliant."
                )
            ),
        },
        "managedConfiguration": {
            "passed": managed_configuration_current,
            "detail": (
                "Exact managed host bundle is freshly observed."
                if managed_configuration_current
                else "Managed host configuration is not freshly proven."
            ),
        },
        "ownership": {
            "passed": ownership_current,
            "detail": (
                "Accountable ownership has a current review."
                if ownership_current
                else (
                    "Agent ownership review is stale."
                    if ownership and ownership.get("status") == "stale"
                    else "Accountable agent ownership is missing or malformed."
                )
            ),
        },
        "policyAssignment": {
            "passed": policy_assigned,
            "detail": policy_detail,
        },
        "emergencyStop": {
            "passed": bool(agent and control_state and control_state["executionAllowed"]),
            "detail": (
                "No emergency stop or incident quarantine is active."
                if agent and control_state and control_state["executionAllowed"]
                else "A server-owned response control withholds execution authority."
            ),
        },
    }
    return {
        "agentId": agent_id,
        "deploymentId": deployment_id,
        "verified": all(check["passed"] for check in checks.values()),
        "checkedAt": checked_at,
        "checks": checks,
        "host": agent.get("host", "") if agent else "",
        "status": agent.get("status", "offline") if agent else "offline",
        "groups": [group["id"] for group in groups],
        "policyId": policy.get("id") if policy else None,
        "policyVersion": int(policy.get("version", 0)) if policy else None,
        "attestation": {
            "status": agent.get("attestation_status", "pending") if agent else "missing",
            "observedAt": int(agent.get("attestation_observed_at", 0)) if agent else 0,
            "expiresAt": int(agent.get("attestation_expires_at", 0)) if agent else 0,
            "reasonCodes": list(agent.get("attestation_reason_codes", [])) if agent else [],
            "sdkVersion": agent.get("attestation_sdk_version") if agent else None,
            "sdkRevision": agent.get("attestation_sdk_revision") if agent else None,
        },
        "managedConfiguration": managed_configuration,
        "ownership": ownership,
        "controlState": control_state,
    }


def _managed_policy_configuration(tenant, configuration):
    """Resolve enabled registry resources into an effective Claude manifest."""
    # DynamoDB returns numeric values as Decimal. Normalize through the same
    # boundary used by API responses before resolving managed resources.
    value = _json(configuration)
    claude = value.get("claudeCode")
    if not isinstance(claude, dict):
        return value
    skills = []
    for resource_id in claude.get("allowedSkills", []):
        item = TABLE.get_item(Key=_item_key(tenant, "SKILL", resource_id)).get("Item")
        if not item or item.get("enabled") is not True:
            raise ValueError("policy references an unavailable Skill")
        skills.append(item)
    servers = []
    for resource_id in claude.get("allowedMcpServers", []):
        item = TABLE.get_item(Key=_item_key(tenant, "MCP", resource_id)).get("Item")
        if not item or item.get("enabled") is not True:
            raise ValueError("policy references an unavailable MCP server")
        servers.append(item)
    claude["managedSkills"] = skills
    claude["managedMcpServers"] = servers
    return value


def _configuration(tenant):
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    fleet_stopped = _fleet_emergency_stop_active(tenant)
    decisions, decisions_truncated = _decision_window(tenant)
    utc = time.gmtime()
    today_start = int(time.time()) - (utc.tm_hour * 3600 + utc.tm_min * 60 + utc.tm_sec)
    decisions_today = [item for item in decisions if int(item.get("observed_at", 0)) >= today_start]
    agents = _all_agents(tenant)
    active_sessions = sum(
        1
        for agent in agents
        if _agent_lifecycle_state(agent) == "active"
        and agent.get("status") == "connected"
        and int(agent.get("expires_at", 0)) > int(time.time())
    )
    return {
        "dashboard": {
            "generatedAt": now,
            "posture": "critical" if fleet_stopped else "healthy",
            "activeSessions": active_sessions,
            "decisionsToday": len(decisions_today),
            "decisionCountsTruncated": decisions_truncated,
            "deniedToday": sum(1 for item in decisions_today if item.get("decision") == "denied"),
            "approvalQueue": _pending_approval_count(tenant),
            "timedOutWorkers": 0,
            "emergencyStop": fleet_stopped,
            "agents": [
                {
                    "id": a["id"],
                    "name": a["host"],
                    "host": a["host"],
                    "status": a["status"],
                    "lastSeen": str(a.get("last_heartbeat")),
                    "tools": 0,
                    "projectRoot": a.get("project_root"),
                }
                for a in agents
            ],
            "recentAudit": [_decision_view(item) for item in decisions[:50]],
        },
        "runtime": {
            "policyProvider": "local_allow_list",
            "approvalProvider": "in_memory",
            "auditProvider": "replicated",
            "policyEndpoint": "",
            "approvalEndpoint": "",
            "auditPath": "",
            "auditReplicaEndpoint": "",
            "credentialBrokerEndpoint": "",
            "isolationVerifier": "deployment_attested",
            "telemetryEnabled": True,
            "allowedTools": ["read_repository"],
            "allowedPrincipals": [],
            "maxActions": 25,
            "maxConcurrent": 1,
            "maxFanOut": 1,
            "maxCostUnits": 25,
            "maxDelegationDepth": 1,
            "maxActionsPerSecond": None,
            "executionTimeoutSeconds": 30,
            "maxTimedOutWorkers": 5,
            "idempotencyTtlSeconds": 86400,
            "approvalTtlSeconds": 120,
            "credentialsEnabled": False,
            "isolationRequiredForHighRisk": True,
            "redactSensitiveData": True,
            "captureToolContent": False,
        },
        "claudeCode": {
            "enabled": True,
            "projectRoot": "/Users/example/project",
            "hookCommand": "python examples/claude_code_hook.py",
            "hookConfigPath": ".claude/settings.json",
            "mcpServerName": "agentic-security-gateway",
            "mcpGatewayCommand": "python examples/mcp_gateway.py",
            "allowedBuiltInTools": ["Read", "Glob", "Grep"],
            "deniedCommandPatterns": ["rm\\s+-rf"],
            "approvalCommandPatterns": ["git\\s+push"],
            "fileTools": ["Read", "Glob", "Grep"],
        },
        "configVersion": 1,
        "history": [],
        "lastSavedAt": now,
    }


def _agent_lifecycle_revision(value):
    """Require an explicit positive revision for optimistic concurrency."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("expectedLifecycleRevision must be a positive integer")
    return value


def _stored_agent_lifecycle_revision(value):
    """Normalize one DynamoDB integral revision without accepting booleans."""
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        return None
    if isinstance(value, Decimal) and value != value.to_integral_value():
        return None
    normalized = int(value)
    return normalized if normalized > 0 else None


def _agent_lifecycle_reason(value):
    """Require enough operator context for a useful retained evidence record."""
    reason = _bounded_text(value, "reason", 500)
    if len(reason) < 20:
        raise ValueError("reason must contain at least 20 characters")
    return reason


def _explicit_agent_lifecycle(tenant, deployment_id, agent_id):
    """Load an agent and migrate a legacy active record without replacing it."""
    key = _item_key(tenant, "AGENT", f"{deployment_id}:{agent_id}")
    agent = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    if not agent:
        return None
    state = _agent_lifecycle_state(agent)
    revision = _stored_agent_lifecycle_revision(agent.get("lifecycle_revision"))
    if state != "invalid" and revision is not None:
        return agent
    if "lifecycle_state" in agent or "lifecycle_revision" in agent:
        raise PolicyConflict("agent lifecycle record is malformed")
    try:
        updated = TABLE.update_item(
            Key=key,
            UpdateExpression="SET lifecycle_state = :active, lifecycle_revision = :one",
            ConditionExpression=(
                "attribute_exists(pk) AND attribute_not_exists(lifecycle_state) "
                "AND attribute_not_exists(lifecycle_revision)"
            ),
            ExpressionAttributeValues={":active": "active", ":one": 1},
            ReturnValues="ALL_NEW",
        ).get("Attributes")
    except Exception as error:
        if not _is_conditional_conflict(error):
            raise
        updated = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    if (
        not updated
        or _agent_lifecycle_state(updated) == "invalid"
        or _stored_agent_lifecycle_revision(updated.get("lifecycle_revision")) is None
    ):
        raise PolicyConflict("agent lifecycle record is malformed")
    return updated


def _agent_lifecycle_condition(record, expected_revision, expected_state):
    """Build a compare-and-swap Put for one explicit lifecycle revision."""
    return _transaction_put(
        record,
        condition="#lifecycle_state = :expected_state AND #lifecycle_revision = :revision",
        names={
            "#lifecycle_state": "lifecycle_state",
            "#lifecycle_revision": "lifecycle_revision",
        },
        values={":expected_state": expected_state, ":revision": expected_revision},
    )


def _update_agent_ownership(tenant, deployment_id, agent_id, body, actor):
    """Review accountable ownership with optimistic concurrency and durable evidence."""
    if not isinstance(body, dict) or set(body) != {
        "expectedOwnershipRevision",
        "ownership",
        "reason",
    }:
        raise ValueError("agent ownership review request schema is invalid")
    expected = _agent_ownership_revision(body.get("expectedOwnershipRevision"), allow_zero=True)
    reason = _agent_lifecycle_reason(body.get("reason"))
    agent = _explicit_agent_lifecycle(tenant, deployment_id, agent_id)
    if not agent:
        return None
    if _agent_lifecycle_state(agent) != "active":
        raise PolicyConflict("only an active agent can receive an ownership review")
    current_revision = agent.get("ownership_revision")
    if current_revision is None:
        if expected != 0:
            raise PolicyConflict("agent ownership revision is stale")
    elif _agent_ownership_revision(current_revision) != expected:
        raise PolicyConflict("agent ownership revision is stale")
    deployment = TABLE.get_item(
        Key=_item_key(tenant, "DEPLOYMENT", deployment_id),
        ConsistentRead=True,
    ).get("Item")
    if (
        not deployment
        or deployment.get("organization_id") != agent.get("organization_id")
        or deployment.get("project_id") != agent.get("project_id")
    ):
        raise PolicyConflict("agent deployment ownership lineage is invalid")
    now = int(time.time())
    ownership = _new_agent_ownership(tenant, body.get("ownership"), deployment, actor, now=now)
    updated = {
        **agent,
        **ownership,
        "ownership_revision": expected + 1,
    }
    if expected == 0:
        condition = "#lifecycle_state = :active AND attribute_not_exists(ownership_revision)"
        values = {":active": "active"}
    else:
        condition = "#lifecycle_state = :active AND ownership_revision = :ownership_revision"
        values = {":active": "active", ":ownership_revision": expected}
    payload = {
        "deployment_id": deployment_id,
        "agent_id": agent_id,
        "owner_id": ownership["owner_id"],
        "team": ownership["team"],
        "criticality": ownership["ownership_criticality"],
        "ownership_revision": expected + 1,
        "review_due_at": ownership["ownership_review_due_at"],
        "reason": reason,
    }
    audit = _agent_lifecycle_audit_record(
        tenant, "agent_ownership_reviewed", actor, payload, now=now
    )
    _transact_agent_lifecycle(
        [
            _transaction_put(
                updated,
                condition=condition,
                names={"#lifecycle_state": "lifecycle_state"},
                values=values,
            ),
            _transaction_put(audit, condition="attribute_not_exists(pk)"),
        ]
    )
    _export_agent_lifecycle_audit(tenant, "agent_ownership_reviewed", actor, payload)
    return {**updated, "ownership": _agent_ownership_view(updated, now=now)}


def _revoke_agent(tenant, deployment_id, agent_id, body, actor):
    """Irreversibly revoke one identity and every old session/bootstrap token."""
    if not isinstance(body, dict) or set(body) != {"expectedLifecycleRevision", "reason"}:
        raise ValueError("agent revoke request schema is invalid")
    expected = _agent_lifecycle_revision(body.get("expectedLifecycleRevision"))
    reason = _agent_lifecycle_reason(body.get("reason"))
    agent = _explicit_agent_lifecycle(tenant, deployment_id, agent_id)
    if not agent:
        return None
    if _agent_lifecycle_state(agent) != "active":
        raise PolicyConflict("only an active agent can be revoked")
    if int(agent["lifecycle_revision"]) != expected:
        raise PolicyConflict("agent lifecycle revision is stale")
    now = int(time.time())
    updated = {
        **agent,
        "lifecycle_state": "revoked",
        "lifecycle_revision": expected + 1,
        "revoked_at": now,
        "revoked_by": actor,
        "revocation_reason": reason,
        "status": "offline",
        "last_heartbeat": 0,
        "expires_at": 0,
        "emergencyStop": True,
    }
    payload = {
        "deployment_id": deployment_id,
        "agent_id": agent_id,
        "lifecycle_revision": expected + 1,
        "reason": reason,
    }
    audit = _agent_lifecycle_audit_record(tenant, "agent_identity_revoked", actor, payload, now=now)
    _transact_agent_lifecycle(
        [
            _agent_lifecycle_condition(updated, expected, "active"),
            _transaction_put(audit, condition="attribute_not_exists(pk)"),
        ]
    )
    _export_agent_lifecycle_audit(tenant, "agent_identity_revoked", actor, payload)
    return updated


def _offboard_agent(tenant, deployment_id, agent_id, body, actor):
    """Tombstone a revoked identity while retaining content-minimised evidence."""
    if not isinstance(body, dict) or set(body) != {"expectedLifecycleRevision", "reason"}:
        raise ValueError("agent offboard request schema is invalid")
    expected = _agent_lifecycle_revision(body.get("expectedLifecycleRevision"))
    reason = _agent_lifecycle_reason(body.get("reason"))
    agent = _explicit_agent_lifecycle(tenant, deployment_id, agent_id)
    if not agent:
        return None
    if _agent_lifecycle_state(agent) != "revoked":
        raise PolicyConflict("an agent must be revoked before it can be offboarded")
    if int(agent["lifecycle_revision"]) != expected:
        raise PolicyConflict("agent lifecycle revision is stale")
    now = int(time.time())
    project_root = agent.get("project_root", "")
    tombstone = {
        **_item_key(tenant, "AGENT", f"{deployment_id}:{agent_id}"),
        "tenant_id": tenant,
        "id": agent_id,
        "organization_id": agent.get("organization_id", ""),
        "project_id": agent.get("project_id", ""),
        "deployment_id": deployment_id,
        "host": agent.get("host", ""),
        "project_root": "",
        "project_root_hash": (
            hashlib.sha256(project_root.encode()).hexdigest() if project_root else ""
        ),
        "environment": agent.get("environment", ""),
        "region": agent.get("region", ""),
        "status": "offline",
        "last_heartbeat": 0,
        "expires_at": 0,
        "emergencyStop": True,
        "created_at": int(agent.get("created_at", 0)),
        "lifecycle_state": "deleted",
        "lifecycle_revision": expected + 1,
        "revoked_at": int(agent.get("revoked_at", 0)),
        "revoked_by": agent.get("revoked_by", ""),
        "revocation_reason": agent.get("revocation_reason", ""),
        "deleted_at": now,
        "deleted_by": actor,
        "deletion_reason": reason,
        "replacement_agent_id": agent.get("replacement_agent_id", ""),
        "successor_of": agent.get("successor_of", ""),
        "owner_id": agent.get("owner_id", ""),
        "team": agent.get("team", ""),
        "ownership_criticality": agent.get("ownership_criticality", ""),
        "ownership_reviewed_at": int(agent.get("ownership_reviewed_at", 0)),
        "ownership_review_due_at": int(agent.get("ownership_review_due_at", 0)),
        "ownership_revision": int(agent.get("ownership_revision", 0)),
        "business_contact_hash": (
            hashlib.sha256(str(agent.get("business_contact", "")).encode()).hexdigest()
            if agent.get("business_contact")
            else ""
        ),
    }
    payload = {
        "deployment_id": deployment_id,
        "agent_id": agent_id,
        "lifecycle_revision": expected + 1,
        "reason": reason,
        "project_root_hash": tombstone["project_root_hash"],
    }
    audit = _agent_lifecycle_audit_record(
        tenant, "agent_identity_offboarded", actor, payload, now=now
    )
    _transact_agent_lifecycle(
        [
            _agent_lifecycle_condition(tombstone, expected, "revoked"),
            _transaction_put(audit, condition="attribute_not_exists(pk)"),
        ]
    )
    _export_agent_lifecycle_audit(tenant, "agent_identity_offboarded", actor, payload)
    return tombstone


def _replace_agent(tenant, deployment_id, agent_id, body, actor):
    """Create a successor and revoke its predecessor in one bounded transaction."""
    required = {"expectedLifecycleRevision", "reason", "replacementAgentId"}
    if not isinstance(body, dict) or set(body) != required:
        raise ValueError("agent replacement request schema is invalid")
    expected = _agent_lifecycle_revision(body.get("expectedLifecycleRevision"))
    reason = _agent_lifecycle_reason(body.get("reason"))
    replacement_id = _bounded_identifier(body.get("replacementAgentId"), "replacementAgentId")
    if replacement_id == agent_id:
        raise ValueError("replacementAgentId must create a new identity")
    agent = _explicit_agent_lifecycle(tenant, deployment_id, agent_id)
    if not agent:
        return None
    if _agent_lifecycle_state(agent) != "active":
        raise PolicyConflict("only an active agent can be replaced")
    if int(agent["lifecycle_revision"]) != expected:
        raise PolicyConflict("agent lifecycle revision is stale")
    replacement_key = f"{deployment_id}:{replacement_id}"
    if TABLE.get_item(Key=_item_key(tenant, "AGENT", replacement_key), ConsistentRead=True).get(
        "Item"
    ):
        raise PolicyConflict("replacement agent identity already exists")
    old_key = f"{deployment_id}:{agent_id}"
    groups = [
        group
        for group in _list(tenant, "GROUP", consistent_read=True)
        if old_key in group.get("agent_keys", [])
    ]
    if len(groups) > _AGENT_REPLACEMENT_GROUP_LIMIT:
        raise PolicyConflict("agent belongs to too many groups for atomic replacement")
    now = int(time.time())
    predecessor = {
        **agent,
        "lifecycle_state": "revoked",
        "lifecycle_revision": expected + 1,
        "revoked_at": now,
        "revoked_by": actor,
        "revocation_reason": reason,
        "replacement_agent_id": replacement_id,
        "status": "offline",
        "last_heartbeat": 0,
        "expires_at": 0,
        "emergencyStop": True,
    }
    successor = {
        **_item_key(tenant, "AGENT", replacement_key),
        "tenant_id": tenant,
        "id": replacement_id,
        "organization_id": agent.get("organization_id", ""),
        "project_id": agent.get("project_id", ""),
        "deployment_id": deployment_id,
        "host": agent.get("host", ""),
        "project_root": agent.get("project_root", ""),
        "environment": agent.get("environment", ""),
        "region": agent.get("region", ""),
        "status": "offline",
        "last_heartbeat": 0,
        "expires_at": 0,
        "emergencyStop": False,
        "created_at": now,
        "lifecycle_state": "active",
        "lifecycle_revision": 1,
        "session_revision": 1,
        "successor_of": agent_id,
        "owner_id": agent.get("owner_id", ""),
        "owner_name": agent.get("owner_name", ""),
        "business_contact": agent.get("business_contact", ""),
        "team": agent.get("team", ""),
        "ownership_criticality": agent.get("ownership_criticality", ""),
        "ownership_reviewed_at": agent.get("ownership_reviewed_at", 0),
        "ownership_review_due_at": agent.get("ownership_review_due_at", 0),
        "ownership_reviewed_by": agent.get("ownership_reviewed_by", ""),
        "ownership_revision": agent.get("ownership_revision", 0),
    }
    payload = {
        "deployment_id": deployment_id,
        "agent_id": agent_id,
        "replacement_agent_id": replacement_id,
        "lifecycle_revision": expected + 1,
        "inherited_group_ids": sorted(group.get("id", "") for group in groups),
        "reason": reason,
    }
    operations = [
        _agent_lifecycle_condition(predecessor, expected, "active"),
        _transaction_put(successor, condition="attribute_not_exists(pk)"),
    ]
    for group in groups:
        current_keys = _group_agent_keys(group)
        membership_revision = _group_membership_revision(group)
        updated_group = {
            **group,
            # Keep the revoked predecessor as retained assignment evidence;
            # only the new active identity can exercise authority.
            "agent_keys": sorted(set(current_keys + [replacement_key])),
            "membership_revision": membership_revision + 1,
        }
        if "membership_revision" in group:
            condition = "agent_keys = :agent_keys AND membership_revision = :membership_revision"
            values = {
                ":agent_keys": current_keys,
                ":membership_revision": membership_revision,
            }
        else:
            condition = "agent_keys = :agent_keys AND attribute_not_exists(membership_revision)"
            values = {":agent_keys": current_keys}
        operations.append(
            _transaction_put(
                updated_group,
                condition=condition,
                values=values,
            )
        )
    audit = _agent_lifecycle_audit_record(
        tenant, "agent_identity_replaced", actor, payload, now=now
    )
    operations.append(_transaction_put(audit, condition="attribute_not_exists(pk)"))
    _transact_agent_lifecycle(operations)
    _export_agent_lifecycle_audit(tenant, "agent_identity_replaced", actor, payload)
    return {"predecessor": predecessor, "replacement": successor, "requiresBootstrap": True}


def _issue_agent_bootstrap(tenant, body, actor):
    """Create a one-time enrollment secret for an already registered agent."""
    deployment_id = body.get("deploymentId")
    agent_id = body.get("agentId")
    if (
        not isinstance(deployment_id, str)
        or not isinstance(agent_id, str)
        or not deployment_id
        or not agent_id
    ):
        raise ValueError("deploymentId and agentId are required")
    agent_key = f"{deployment_id}:{agent_id}"
    agent = TABLE.get_item(Key=_item_key(tenant, "AGENT", agent_key), ConsistentRead=True).get(
        "Item"
    )
    if not agent:
        raise ValueError("agent must be registered before enrollment")
    _require_active_agent(agent)
    session_revision = _agent_session_revision(agent)
    if session_revision is None:
        raise PolicyConflict("agent session authority record is malformed")
    if _active_agent_containment(tenant, agent_key):
        raise PolicyConflict("incident quarantine blocks new enrollment material")
    project_root = agent.get("project_root")
    if not isinstance(project_root, str) or not project_root:
        raise ValueError("agent must have a project root before enrollment")
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + min(max(int(body.get("ttlSeconds", 600)), 60), 3600)
    TABLE.put_item(
        Item={
            "pk": _token_key("AGENT_BOOTSTRAP", token),
            "sk": "TOKEN",
            "tenant_id": tenant,
            "deployment_id": deployment_id,
            "agent_id": agent_id,
            "project_root_hash": hashlib.sha256(project_root.encode()).hexdigest(),
            "session_revision": session_revision,
            "expires_at": expires_at,
            "ttl": expires_at,
        }
    )
    _audit(
        tenant,
        "agent_bootstrap_issued",
        actor,
        {"deployment_id": deployment_id, "agent_id": agent_id, "expires_at": expires_at},
    )
    return {
        "bootstrapToken": token,
        "deploymentId": deployment_id,
        "agentId": agent_id,
        "expiresAt": expires_at,
    }


def _enroll_agent(event):
    """Consume a bootstrap secret once and issue a short-lived session token."""
    body = _body(event)
    token = body.get("bootstrapToken")
    if not isinstance(token, str) or not token:
        raise PermissionError("bootstrap token is required")
    key = {"pk": _token_key("AGENT_BOOTSTRAP", token), "sk": "TOKEN"}
    item = TABLE.get_item(Key=key, ConsistentRead=True).get("Item")
    if not item or int(item.get("expires_at", 0)) <= int(time.time()):
        raise PermissionError("bootstrap token is missing or expired")
    deployment_id = item["deployment_id"]
    agent_id = item["agent_id"]
    tenant = item["tenant_id"]
    project_root = _project_root(body.get("projectRoot"))
    project_root_hash = hashlib.sha256(project_root.encode()).hexdigest()
    bootstrap_scope = item.get("project_root_hash")
    if not isinstance(bootstrap_scope, str) or not secrets.compare_digest(
        project_root_hash, bootstrap_scope
    ):
        raise PermissionError("bootstrap project scope mismatch")
    agent = TABLE.get_item(
        Key=_item_key(tenant, "AGENT", f"{deployment_id}:{agent_id}"),
        ConsistentRead=True,
    ).get("Item")
    if not agent or _agent_lifecycle_state(agent) != "active":
        raise PermissionError("agent identity is revoked or offboarded")
    if agent.get("project_root") != project_root:
        raise PermissionError("registered agent project scope mismatch")
    if _active_agent_containment(tenant, f"{deployment_id}:{agent_id}"):
        raise PermissionError("incident quarantine blocks agent enrollment")
    current_session_revision = _agent_session_revision(agent)
    bootstrap_session_revision = _agent_session_revision(item)
    if (
        current_session_revision is None
        or bootstrap_session_revision is None
        or current_session_revision != bootstrap_session_revision
    ):
        raise PermissionError("bootstrap session authority has been revoked")
    # Validate immutable scope before consuming the one-time secret. The
    # conditional delete then makes successful exchange one-shot under races.
    TABLE.delete_item(
        Key=key,
        ConditionExpression="attribute_exists(pk) AND expires_at > :now",
        ExpressionAttributeValues={":now": int(time.time())},
    )
    now = int(time.time())
    session_token = secrets.token_urlsafe(32)
    session_expires = now + 900
    TABLE.put_item(
        Item={
            "pk": _token_key("AGENT_SESSION", session_token),
            "sk": "SESSION",
            "tenant_id": tenant,
            "deployment_id": deployment_id,
            "agent_id": agent_id,
            "project_root_hash": project_root_hash,
            "session_revision": current_session_revision,
            "issued_at": now,
            "expires_at": session_expires,
            "ttl": session_expires,
        }
    )
    # Exchanging a bootstrap proves possession of enrollment material, not
    # that the runtime process is alive. Enrollment deliberately does not
    # rewrite the agent record: doing so would create a second authority
    # mutation after the session was issued and would make legacy agents fail
    # enrollment merely because they pre-date lifecycle revision fields. Only
    # an authenticated heartbeat may transition presence to connected.
    _audit(
        tenant,
        "agent_enrolled",
        f"agent:{deployment_id}:{agent_id}",
        {"deployment_id": deployment_id, "agent_id": agent_id, "expires_at": session_expires},
    )
    return {
        "accessToken": session_token,
        "tokenType": "Bearer",
        "expiresAt": session_expires,
        "tenantId": tenant,
        "deploymentId": deployment_id,
        "agentId": agent_id,
    }


def _renew_agent_session(tenant, session, current_token):
    """Rotate an AWS agent session only when it is approaching expiry.

    Heartbeats prove the process is still live. Rotation keeps the bearer
    short-lived while allowing a healthy Claude Code or Codex gateway to run
    indefinitely without persisting a new secret in host configuration.
    """
    now = int(time.time())
    if int(session.get("expires_at", 0)) - now > 300:
        return {"status": "connected", "expiresAt": int(session["expires_at"])}
    refreshed_token = secrets.token_urlsafe(32)
    refreshed_expires = now + 900
    TABLE.put_item(
        Item={
            "pk": _token_key("AGENT_SESSION", refreshed_token),
            "sk": "SESSION",
            "tenant_id": tenant,
            "deployment_id": session["deployment_id"],
            "agent_id": session["agent_id"],
            "project_root_hash": session["project_root_hash"],
            "session_revision": session.get("session_revision", 1),
            "issued_at": now,
            "expires_at": refreshed_expires,
            "ttl": refreshed_expires,
        }
    )
    TABLE.delete_item(Key={"pk": _token_key("AGENT_SESSION", current_token), "sk": "SESSION"})
    return {"status": "connected", "accessToken": refreshed_token, "expiresAt": refreshed_expires}


def handler(event, context):
    """Route one API Gateway request through agent or operator trust boundaries."""
    # This exact direct-invocation contract cannot be formed through API
    # Gateway. It intentionally runs under this function's live role so a
    # Regional exercise observes the same IAM deny as production execution.
    if isinstance(event, dict) and event.get("source") == "aai.regional-fault-target-probe":
        return run_regional_fault_target_probe(event)
    # Scheduled reconciliation is an internal invocation contract. Let its
    # failures escape Lambda so EventBridge performs bounded retries and moves
    # exhausted events to the monitored DLQ; an HTTP-shaped 500 would look like
    # a successful invocation to EventBridge and silently disable that safety.
    if isinstance(event, dict) and event.get("source") == "aai.endpoint-detection":
        if set(event) != {"source", "schemaVersion"} or event.get("schemaVersion") != 1:
            raise ValueError("endpoint detection schedule event is invalid")
        return _endpoint_detection_cycle()
    if isinstance(event, dict) and event.get("source") == "aai.rollout-reconciliation":
        if set(event) != {"source", "schemaVersion"} or event.get("schemaVersion") != 1:
            raise ValueError("rollout reconciliation schedule event is invalid")
        return _rollout_reconciliation_cycle()
    if isinstance(event, dict) and event.get("source") == "aai.dynamic-group-reconciliation":
        if set(event) != {"source", "schemaVersion"} or event.get("schemaVersion") != 1:
            raise ValueError("dynamic group reconciliation schedule event is invalid")
        return _dynamic_group_reconciliation_cycle()
    if isinstance(event, dict) and event.get("source") == "aai.webhook-dispatch":
        if set(event) != {"source", "schemaVersion"} or event.get("schemaVersion") != 1:
            raise ValueError("webhook dispatch schedule event is invalid")
        return _webhook_dispatch_cycle()
    if isinstance(event, dict) and event.get("source") == "aai.evidence-assurance":
        if set(event) != {"source", "schemaVersion"} or event.get("schemaVersion") != 1:
            raise ValueError("evidence assurance schedule event is invalid")
        return _evidence_schedule_cycle()
    if isinstance(event, dict) and event.get("source") == "aai.evidence-retention":
        if set(event) != {"source", "schemaVersion"} or event.get("schemaVersion") != 1:
            raise ValueError("evidence retention schedule event is invalid")
        return _evidence_retention_schedule_cycle()
    if isinstance(event, dict) and event.get("source") == "aai.regional-transition-jobs":
        if (
            set(event)
            != {
                "source",
                "schemaVersion",
                "mode",
                "activationEvidenceRef",
                "direction",
                "targetRegion",
                "transitionId",
                "authoritySha256",
            }
            or event.get("schemaVersion") != 2
        ):
            raise ValueError("regional transition job reconciliation event is invalid")
        return _regional_transition_job_reconciliation(
            event.get("mode"),
            event.get("activationEvidenceRef"),
            event.get("direction"),
            event.get("targetRegion"),
            event.get("transitionId"),
            event.get("authoritySha256"),
        )
    try:
        method, path = _method_path(event)
        if method == "OPTIONS":
            return _response(204, {})
        if path.startswith("/machine/"):
            # API Gateway does not apply the human JWT authorizer to this
            # route. Translate it only after a live digest-keyed bearer check,
            # immutable admission evidence and an explicit v1 allowlist match.
            return handler(_machine_request(event, method, path), context)
        if path in ("/agent/enroll", "/api/agent/enroll"):
            if method != "POST":
                return _response(405, {"error": "method not allowed"})
            return _response(201, _enroll_agent(event))
        if path.startswith("/endpoint-evidence/") or path.startswith("/api/endpoint-evidence/"):
            normalized = path.removeprefix("/api")
            parts = [
                part for part in normalized.removeprefix("/endpoint-evidence/").split("/") if part
            ]
            if method != "POST" or len(parts) != 2:
                return _response(404, {"error": "endpoint evidence route not found"})
            return _response(202, _ingest_endpoint_report(event, parts[0], parts[1]))
        if path.startswith("/discovery-ingest/") or path.startswith("/api/discovery-ingest/"):
            normalized = path.removeprefix("/api")
            parts = [
                part for part in normalized.removeprefix("/discovery-ingest/").split("/") if part
            ]
            if len(parts) < 3 or parts[2] != "generations":
                return _response(404, {"error": "discovery ingestion route not found"})
            tenant, source_id, connector = _discovery_connector_identity(event, parts[0], parts[1])
            actor = f"connector:{source_id}:revision:{connector['revision']}"
            if method == "POST" and len(parts) == 3:
                return _response(
                    201,
                    _begin_discovery_generation(tenant, source_id, connector, _body(event)),
                )
            if method == "PUT" and len(parts) == 6 and parts[4] == "pages":
                if not re.fullmatch(r"0|[1-9][0-9]*", parts[5]):
                    raise ValueError("pageNumber must be a non-negative integer")
                return _response(
                    201,
                    _put_discovery_generation_page(
                        tenant,
                        source_id,
                        parts[3],
                        int(parts[5]),
                        _body(event),
                    ),
                )
            if method == "POST" and len(parts) == 5 and parts[4] == "commit":
                return _response(
                    200,
                    _commit_discovery_generation(tenant, source_id, parts[3], _body(event), actor),
                )
            return _response(404, {"error": "discovery ingestion route not found"})
        if path.startswith("/agent/") or path.startswith("/api/agent/"):
            # Agent routes are not operator JWT routes.  The session token is
            # resolved here and the URL identity is checked against it.
            normalized = path.replace("/api/", "/", 1)
            session, deployment_id, agent_id, action = _agent_identity(normalized, event)
            tenant = session["tenant_id"]
            _seed(tenant)
            agent_key = f"{deployment_id}:{agent_id}"
            if method == "POST" and action == ["attestation", "challenge"]:
                return _response(
                    200,
                    _issue_attestation_challenge(tenant, session, _bearer(event)),
                )
            if method == "POST" and action == ["heartbeat"]:
                item = TABLE.get_item(
                    Key=_item_key(tenant, "AGENT", agent_key), ConsistentRead=True
                ).get("Item")
                if not item:
                    return _response(404, {"error": "agent not found"})
                body = _body(event)
                _validate_runtime_attestation(
                    tenant,
                    deployment_id,
                    item,
                    session,
                    _bearer(event),
                    body.get("attestation"),
                )
                telemetry = _agent_telemetry(body.get("telemetry"))
                if telemetry is not None:
                    item["telemetry"] = telemetry
                managed_configuration = body.get("managedConfiguration")
                if managed_configuration is not None:
                    item["managed_configuration_report"] = _managed_host(
                        managed_configuration, report=True
                    )
                item.update(
                    {
                        "status": "connected",
                        "last_heartbeat": int(time.time()),
                        "expires_at": int(time.time()) + 300,
                    }
                )
                try:
                    session_revision = _agent_session_revision(item)
                    if session_revision is None:
                        raise PermissionError("agent session authority record is malformed")
                    TABLE.put_item(
                        Item=item,
                        ConditionExpression=(
                            "lifecycle_state = :active AND lifecycle_revision = :revision "
                            "AND (attribute_not_exists(session_revision) OR "
                            "session_revision = :session_revision)"
                        ),
                        ExpressionAttributeValues={
                            ":active": "active",
                            ":revision": int(item["lifecycle_revision"]),
                            ":session_revision": session_revision,
                        },
                    )
                except Exception as error:
                    if _is_conditional_conflict(error):
                        raise PermissionError(
                            "agent identity changed while heartbeat was processed"
                        ) from error
                    raise
                control_state = _agent_control_state(tenant, item)
                heartbeat_status = (
                    "quarantined"
                    if control_state["quarantine"]
                    else "stopped"
                    if control_state["activeStopScopes"]
                    else "connected"
                )
                return _response(
                    200,
                    {
                        **item,
                        **_renew_agent_session(tenant, session, _bearer(event)),
                        "status": heartbeat_status,
                        "controlState": control_state,
                    },
                )
            governed_agent = TABLE.get_item(
                Key=_item_key(tenant, "AGENT", agent_key), ConsistentRead=True
            ).get("Item")
            if not governed_agent:
                return _response(404, {"error": "agent not found"})
            control_state = _agent_control_state(tenant, governed_agent)
            if not control_state["executionAllowed"]:
                return _response(
                    409,
                    {
                        "error": "server-owned response control withholds agent execution",
                        "controlState": control_state,
                    },
                )
            _require_current_attestation(tenant, deployment_id, governed_agent)
            if method == "GET" and action == ["managed-package"]:
                return _response(
                    200,
                    _agent_managed_package(tenant, deployment_id, agent_id, governed_agent),
                )
            _require_current_managed_configuration(tenant, governed_agent)
            if method == "POST" and action == ["decisions"]:
                recorded = _record_agent_decision(tenant, deployment_id, agent_id, _body(event))
                return _response(409 if recorded.get("conflict") else 202, recorded)
            if method == "GET" and action == ["effective-policy"]:
                agent = governed_agent
                groups = [
                    group
                    for group in _fleet(tenant)["groups"]
                    if agent_key in group.get("agent_keys", [])
                ]
                if not groups:
                    return _response(409, {"error": "agent has no assigned policy"})
                if len(groups) != 1:
                    return _response(
                        409, {"error": "agent has conflicting policy-group assignments"}
                    )
                group = groups[0]
                policy = TABLE.get_item(Key=_item_key(tenant, "POLICY", group["policyId"])).get(
                    "Item"
                )
                if not policy:
                    return _response(409, {"error": "assigned policy is unavailable"})
                policy = _ensure_policy_governance(tenant, policy)
                if int(policy.get("version", 0)) <= 0:
                    return _response(409, {"error": "assigned policy has no active version"})
                exception = _active_policy_exception_bundle(tenant, deployment_id, agent_id)
                return _response(
                    200,
                    {
                        "agentId": agent_id,
                        "deploymentId": deployment_id,
                        "groupId": group["id"],
                        "policyBundle": exception["policyBundle"]
                        if exception
                        else _active_policy_bundle(tenant, policy),
                        "effectiveSource": "temporary_exception" if exception else "active_policy",
                        "exception": exception["exception"] if exception else None,
                    },
                )
            if method == "POST" and action == ["approvals", "request"]:
                body = _body(event)
                approval_id = _approval_text(body.get("approval_id"), "approval_id")
                now = int(time.time())
                review_ttl = min(max(int(body.get("review_ttl_seconds", 900)), 60), 3600)
                grant_ttl = min(max(int(body.get("grant_ttl_seconds", 120)), 1), 600)
                risk_class = body.get("risk_class", "unspecified")
                if risk_class not in {
                    "write",
                    "destructive",
                    "external_egress",
                    "code_execution",
                    "secret_read",
                    "unspecified",
                }:
                    raise ValueError("risk_class is unsupported")
                item = {
                    **_item_key(tenant, "APPROVAL", approval_id),
                    "tenant_id": tenant,
                    "id": approval_id,
                    # Agent identity comes from the authenticated session, not
                    # from the request body or model-generated metadata.
                    "agent_key": agent_key,
                    "tool_name": _approval_text(body.get("tool_name"), "tool_name"),
                    "proposal_id": _approval_text(body.get("proposal_id"), "proposal_id"),
                    "task_id": _approval_text(body.get("task_id"), "task_id"),
                    "principal_id": _approval_text(body.get("principal_id"), "principal_id"),
                    "action_hash": _approval_text(body.get("action_hash"), "action_hash", 128),
                    "risk_class": risk_class,
                    "resource_ids": _approval_resources(body.get("resource_ids")),
                    "status": "pending",
                    "consumed": False,
                    "requested_at": now,
                    "expires_at": now + review_ttl,
                    "grant_ttl_seconds": grant_ttl,
                    "ttl": now + review_ttl,
                }
                try:
                    # Approval IDs are one-shot action capabilities.  Never
                    # allow an agent to replace a reviewed or consumed record.
                    TABLE.put_item(
                        Item=item,
                        ConditionExpression="attribute_not_exists(pk)",
                    )
                except Exception as error:
                    if (
                        getattr(error, "response", {}).get("Error", {}).get("Code")
                        == "ConditionalCheckFailedException"
                    ):
                        return _response(409, {"error": "approval request already exists"})
                    raise
                _audit(
                    tenant,
                    "approval_requested",
                    f"agent:{agent_key}",
                    {
                        "approval_id": approval_id,
                        "agent_key": agent_key,
                        "tool_name": item["tool_name"],
                        "risk_class": risk_class,
                        "expires_at": item["expires_at"],
                    },
                )
                try:
                    _evaluate_behavior_rules_for_agent(tenant, agent_key, now=now)
                except Exception:
                    _record_behavior_health(tenant, "degraded", now=now)
                    print(json.dumps({"warning": "behavior approval detection remains degraded"}))
                return _response(201, _approval_view(item, now))
            if method == "POST" and action == ["approvals", "consume"]:
                body = _body(event)
                approval_id = body.get("approval_id")
                if not isinstance(approval_id, str) or not approval_id:
                    raise ValueError("approval_id is required")
                try:
                    updated = TABLE.update_item(
                        Key=_item_key(tenant, "APPROVAL", approval_id),
                        UpdateExpression=(
                            "SET #consumed = :true, #status = :consumed_status, consumed_at = :now"
                        ),
                        ConditionExpression=(
                            "attribute_exists(pk) AND #status = :approved_status AND "
                            "#consumed = :false AND #expires_at > :now AND "
                            "#agent_key = :agent AND #action_hash = :action_hash AND "
                            "#tool_name = :tool_name AND #proposal_id = :proposal_id AND "
                            "#task_id = :task_id AND #principal_id = :principal_id"
                        ),
                        ExpressionAttributeNames={
                            "#consumed": "consumed",
                            "#status": "status",
                            "#expires_at": "expires_at",
                            "#agent_key": "agent_key",
                            "#action_hash": "action_hash",
                            "#tool_name": "tool_name",
                            "#proposal_id": "proposal_id",
                            "#task_id": "task_id",
                            "#principal_id": "principal_id",
                        },
                        ExpressionAttributeValues={
                            ":true": True,
                            ":false": False,
                            ":approved_status": "approved",
                            ":consumed_status": "consumed",
                            ":now": int(time.time()),
                            ":agent": agent_key,
                            ":action_hash": body.get("action_hash", ""),
                            ":tool_name": body.get("tool_name", ""),
                            ":proposal_id": body.get("proposal_id", ""),
                            ":task_id": body.get("task_id", ""),
                            ":principal_id": body.get("principal_id", ""),
                        },
                        ReturnValues="ALL_NEW",
                    )
                    approval = updated.get("Attributes", {})
                    _audit(
                        tenant,
                        "approval_consumed",
                        f"agent:{agent_key}",
                        {
                            "approval_id": approval_id,
                            "agent_key": agent_key,
                            "tool_name": approval.get("tool_name", ""),
                        },
                    )
                    return _response(200, {"approved": True, "approval": approval})
                except Exception as error:
                    if (
                        getattr(error, "response", {}).get("Error", {}).get("Code")
                        == "ConditionalCheckFailedException"
                    ):
                        return _response(200, {"approved": False})
                    raise
            return _response(404, {"error": "agent route not found"})

        tenant = _tenant(event)
        _seed(tenant)
        actor = _bounded_text(_claims(event).get("sub", "cognito-operator"), "actor", 256)
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            capability = _required_mutation_capability(path)
            is_break_glass_governance = "/enterprise/identity/break-glass/requests" in path
            is_response_rule_governance = "/enterprise/response-rules" in path
            is_identity_governance = is_break_glass_governance or any(
                marker in path
                for marker in (
                    "/enterprise/identity/scim",
                    "/enterprise/identity/delegated-grants",
                )
            )
            if not _operator_authorized(
                event,
                capability,
                tenant,
                include_break_glass=not (is_break_glass_governance or is_response_rule_governance),
                resource_scope=_mutation_resource_scope(tenant, event, path),
                include_delegated=not (is_identity_governance or is_response_rule_governance),
            ):
                return _response(
                    403,
                    {
                        "error": "operator role does not permit this action",
                        "requiredCapability": capability,
                    },
                )
        if path in ("/configuration", "/api/configuration") and method == "GET":
            return _response(200, _configuration(tenant))
        if path in ("/dashboard", "/api/dashboard") and method == "GET":
            return _response(200, _configuration(tenant)["dashboard"])
        if path in ("/emergency-stop", "/api/emergency-stop") and method == "POST":
            body = _body(event)
            active = bool(body.get("active", True))
            _set_fleet_emergency_stop(tenant, active, actor)
            _audit(
                tenant,
                "fleet_emergency_stop",
                actor,
                {"active": active, "agent_count": len(_all_agents(tenant))},
            )
            return _response(200, _configuration(tenant)["dashboard"])
        if path.startswith("/enterprise/") or path.startswith("/api/enterprise/"):
            suffix = path.split("/enterprise/", 1)[1]
            parts = [p for p in suffix.split("/") if p]
            if parts[:2] == ["identity", "service-identities"]:
                # Canonical tenant roles may inspect secret-free posture and
                # usage. Only the platform-admin wildcard may change machine
                # authority; delegated and emergency grants never qualify.
                authorized = (
                    bool(_operator_roles(event))
                    if method == "GET"
                    else _operator_authorized(
                        event,
                        "identity_admin",
                        tenant,
                        include_break_glass=False,
                        include_delegated=False,
                    )
                )
                if not authorized:
                    return _response(
                        403,
                        {
                            "error": (
                                "service identity posture requires a tenant role"
                                if method == "GET"
                                else "service identity administration requires platform authority"
                            )
                        },
                    )
                if method == "GET" and len(parts) == 2:
                    identities = [
                        _service_identity_view(item)
                        for item in _list(tenant, "SERVICE_IDENTITY", consistent_read=True)
                    ]
                    identities.sort(key=lambda item: (item["name"].lower(), item["id"]))
                    return _response(200, {"items": identities, "nextCursor": None})
                if method == "POST" and len(parts) == 2:
                    return _response(201, _service_identity_issue(tenant, _body(event), actor))
                if method == "POST" and len(parts) == 4 and parts[3] == "rotate":
                    return _response(
                        201,
                        _service_identity_rotate(tenant, parts[2], _body(event), actor),
                    )
                if method == "POST" and len(parts) == 4 and parts[3] == "revoke":
                    return _response(
                        200,
                        _service_identity_revoke(tenant, parts[2], _body(event), actor),
                    )
                if method == "GET" and len(parts) == 4 and parts[3] == "usage":
                    identity_id = _bounded_identifier(parts[2], "serviceIdentityId")
                    if not TABLE.get_item(
                        Key=_item_key(tenant, "SERVICE_IDENTITY", identity_id),
                        ConsistentRead=True,
                    ).get("Item"):
                        raise LookupError("service identity not found")
                    usage = [
                        {
                            "id": item.get("id", ""),
                            "method": item.get("method", ""),
                            "route": item.get("route", ""),
                            "capability": item.get("capability", ""),
                            "credentialRevision": int(item.get("credential_revision", 0)),
                            "occurredAt": int(item.get("occurred_at", 0)),
                        }
                        for item in _list(tenant, "SERVICE_IDENTITY_USAGE", consistent_read=True)
                        if item.get("service_identity_id") == identity_id
                    ]
                    usage.sort(key=lambda item: (item["occurredAt"], item["id"]), reverse=True)
                    return _response(200, {"items": usage[:100], "truncated": len(usage) > 100})
            if (
                method == "GET"
                and len(parts) == 2
                and parts[0] == "reports"
                and parts[1] in {"executive", "auditor"}
            ):
                if not (_operator_roles(event) or _service_capabilities(event)):
                    return _response(
                        403,
                        {"error": "enterprise assurance reports require a tenant role"},
                    )
                if parts[1] == "auditor" and not _operator_authorized(
                    event, "evidence_read", tenant
                ):
                    return _response(
                        403,
                        {"error": "auditor assurance requires evidence-read authority"},
                    )
                return _response(200, _assurance_report(tenant, parts[1]))
            if method == "GET" and parts in (["evidence"], ["evidence", "export"]):
                if not _operator_authorized(event, "evidence_read", tenant):
                    return _response(
                        403,
                        {"error": "evidence assurance requires an authorized evidence role"},
                    )
                return _response(
                    200,
                    _evidence_export(tenant, actor)
                    if parts == ["evidence", "export"]
                    else _evidence_assurance(tenant),
                )
            if method == "PUT" and parts == ["evidence", "retention"]:
                return _response(200, _set_evidence_retention(tenant, _body(event), actor))
            if parts[:2] == ["evidence", "retention-jobs"]:
                if method == "POST" and len(parts) == 2:
                    return _response(202, _create_retention_job(tenant, _body(event), actor))
                if method == "GET":
                    if not _operator_authorized(event, "evidence_read", tenant):
                        return _response(
                            403,
                            {"error": "evidence retention requires an authorized evidence role"},
                        )
                    if len(parts) == 2:
                        return _response(200, {"items": _retention_jobs(tenant)})
                    if len(parts) == 3:
                        return _response(
                            200,
                            _retention_job_view(_retention_job_record(tenant, parts[2])),
                        )
            if method == "POST" and parts == ["evidence", "legal-hold"]:
                return _response(200, _set_evidence_legal_hold(tenant, _body(event), actor))
            if parts[:2] == ["evidence", "jobs"]:
                if method == "POST" and len(parts) == 2:
                    return _response(202, _start_evidence_job(tenant, _body(event), actor))
                if method == "GET":
                    if not _operator_authorized(event, "evidence_read", tenant):
                        return _response(
                            403,
                            {"error": "evidence assurance requires an authorized evidence role"},
                        )
                    if len(parts) == 2:
                        return _response(200, {"items": _evidence_jobs(tenant)})
                    if len(parts) == 3:
                        return _response(
                            200, _evidence_job_view(_evidence_job_record(tenant, parts[2]))
                        )
                    if len(parts) == 5 and parts[3] == "pages":
                        return _response(200, _evidence_job_page(tenant, parts[2], parts[4]))
            if method == "GET" and parts == ["policy-trust"]:
                return _response(200, _policy_trust_metadata())
            if (
                method == "GET"
                and len(parts) == 1
                and parts
                and parts[0]
                in {
                    "organizations",
                    "projects",
                    "deployments",
                    "agents",
                    "policies",
                    "policy-exceptions",
                    "groups",
                    "skills",
                    "mcp-servers",
                    "templates",
                    "sessions",
                    "drift",
                    "health",
                    "slo",
                    "alerts",
                    "alert-suppressions",
                    "cases",
                    "response-rules",
                    "response-executions",
                    "audit",
                    "approvals",
                }
            ):
                key = {
                    "organizations": "ORG",
                    "projects": "PROJECT",
                    "deployments": "DEPLOYMENT",
                    "agents": "AGENT",
                    "policies": "POLICY",
                    "policy-exceptions": "POLICY_EXCEPTION",
                    "groups": "GROUP",
                    "skills": "SKILL",
                    "mcp-servers": "MCP",
                    "templates": "TEMPLATE",
                    "sessions": "SESSION",
                    "drift": "DRIFT",
                    "health": "HEALTH",
                    "slo": "SLO",
                    "alerts": "ALERT",
                    "alert-suppressions": "ALERT_SUPPRESSION",
                    "cases": "CASE",
                    "response-rules": "RESPONSE_RULE",
                    "response-executions": "RESPONSE_EXECUTION",
                    "audit": "AUDIT",
                    "approvals": "APPROVAL",
                }[parts[0]]
                if parts[0] == "policy-exceptions":
                    items = _policy_exceptions(tenant)
                elif parts[0] == "alerts":
                    _reconcile_endpoint_alerts(tenant, _endpoint_evidence_health(tenant))
                    items = [
                        _endpoint_alert_view(item)
                        for item in _list(tenant, "ALERT", consistent_read=True)
                        if item.get("source") in {"endpoint_evidence", "behavior_analytics"}
                    ]
                    items.sort(
                        key=lambda item: (
                            int(item.get("lastObservedAt", 0)),
                            str(item.get("id", "")),
                        ),
                        reverse=True,
                    )
                elif parts[0] == "cases":
                    items = [
                        _case_view(tenant, item)
                        for item in _list(tenant, "CASE", consistent_read=True)
                    ]
                    items.sort(
                        key=lambda item: (int(item.get("updatedAt", 0)), str(item.get("id", ""))),
                        reverse=True,
                    )
                elif parts[0] == "alert-suppressions":
                    items = [
                        _alert_suppression_view(item)
                        for item in _list(tenant, "ALERT_SUPPRESSION", consistent_read=True)
                    ]
                    items.sort(
                        key=lambda item: (int(item.get("expiresAt", 0)), str(item.get("id", ""))),
                        reverse=True,
                    )
                elif parts[0] == "response-rules":
                    items = [
                        _response_rule_summary(
                            item,
                            _response_rule_versions(tenant, item["id"]),
                        )
                        for item in _list(tenant, "RESPONSE_RULE", consistent_read=True)
                    ]
                    items.sort(
                        key=lambda item: (int(item.get("updatedAt", 0)), item.get("id", "")),
                        reverse=True,
                    )
                elif parts[0] == "response-executions":
                    items = [
                        _response_rule_execution_view(item)
                        for item in _list(tenant, "RESPONSE_EXECUTION", consistent_read=True)
                    ]
                    items.sort(
                        key=lambda item: (
                            int(item.get("occurredAt", 0)),
                            item.get("id", ""),
                        ),
                        reverse=True,
                    )
                else:
                    items = (
                        _fleet(tenant).get(
                            "mcpServers" if parts[0] == "mcp-servers" else parts[0], []
                        )
                        if parts[0]
                        in {
                            "groups",
                            "agents",
                            "health",
                            "policies",
                            "drift",
                            "skills",
                            "mcp-servers",
                        }
                        else _list(tenant, key)
                    )
                items = _filter_enterprise_items(tenant, event, key, items)
                if parts[0] == "approvals":
                    items = sorted(
                        (_approval_view(item) for item in items),
                        key=lambda item: int(item.get("requestedAt", 0)),
                        reverse=True,
                    )
                return _response(200, {"items": items, "nextCursor": None})
            if method == "POST" and parts == ["policy-exceptions"]:
                return _response(201, _create_policy_exception(tenant, _body(event), actor))
            if method == "POST" and parts == ["alert-suppressions"]:
                return _response(201, _create_alert_suppression(tenant, _body(event), actor))
            if (
                method == "POST"
                and len(parts) == 3
                and parts[0] == "alert-suppressions"
                and parts[2] == "revoke"
            ):
                return _response(
                    200,
                    _revoke_alert_suppression(tenant, parts[1], _body(event), actor),
                )
            if (
                method == "POST"
                and len(parts) == 3
                and parts[0] == "policy-exceptions"
                and parts[2] in {"submit", "decision", "activate", "revoke"}
            ):
                action = parts[2]
                if action == "submit":
                    if _body(event) != {}:
                        raise ValueError("policy exception submission accepts no mutable content")
                    result = _submit_policy_exception(tenant, parts[1], actor)
                elif action == "decision":
                    result = _decide_policy_exception(tenant, parts[1], _body(event), actor)
                elif action == "activate":
                    result = _activate_policy_exception(tenant, parts[1], _body(event), actor)
                else:
                    result = _revoke_policy_exception(tenant, parts[1], _body(event), actor)
                return _response(200, result)
            if method == "GET" and parts == ["capabilities"]:
                return _response(200, _fleet(tenant)["capabilities"])
            if method == "GET" and parts in (["discovery"], ["discovery", "export"]):
                if not (_operator_roles(event) or _service_capabilities(event)):
                    return _response(
                        403,
                        {"error": "tenant-wide discovery requires a tenant operator role"},
                    )
                report = (
                    _discovery_export(tenant)
                    if parts == ["discovery", "export"]
                    else _discovery_report(tenant)
                )
                return _response(200, report)
            if method == "GET" and parts == ["discovery", "sources"]:
                if not _operator_roles(event):
                    return _response(
                        403,
                        {"error": "discovery sources require a tenant operator role"},
                    )
                return _response(200, _discovery_source_directory(tenant))
            if method == "GET" and parts == ["discovery", "managed-collector-capabilities"]:
                if not _operator_roles(event):
                    return _response(
                        403,
                        {"error": "managed discovery requires a tenant operator role"},
                    )
                return _response(200, _managed_discovery_capabilities())
            if method == "GET" and parts == ["endpoint-evidence"]:
                if not _operator_roles(event):
                    return _response(
                        403,
                        {"error": "endpoint evidence requires a tenant operator role"},
                    )
                health = _endpoint_evidence_health(tenant)
                _reconcile_endpoint_alerts(tenant, health)
                return _response(200, health)
            if method == "POST" and parts == ["response-rules", "preview"]:
                body = _body(event)
                if not isinstance(body, dict) or set(body) != {"configuration"}:
                    raise ValueError("response rule preview request has an invalid schema")
                return _response(
                    200,
                    _response_rule_preview(tenant, body.get("configuration")),
                )
            if method == "POST" and parts == ["response-rules"]:
                return _response(201, _create_response_rule(tenant, _body(event), actor))
            if method == "GET" and len(parts) == 2 and parts[0] == "response-rules":
                rule = _response_rule_record(tenant, parts[1])
                versions = _response_rule_versions(tenant, parts[1], consistent_read=True)
                executions = [
                    _response_rule_execution_view(item)
                    for item in _list(tenant, "RESPONSE_EXECUTION", consistent_read=True)
                    if item.get("rule_id") == parts[1]
                ]
                executions.sort(
                    key=lambda item: (int(item.get("occurredAt", 0)), item.get("id", "")),
                    reverse=True,
                )
                return _response(
                    200,
                    {
                        **_response_rule_summary(rule, versions),
                        "versions": [_response_rule_version_view(item) for item in versions],
                        "executions": executions,
                    },
                )
            if method == "POST" and parts == ["policies", "composition", "preview"]:
                body = _body(event)
                policy_id = _bounded_identifier(body.get("policyId"), "policyId")
                organization_id = _policy_organization(tenant, body)
                composition = _compose_governed_policy(tenant, organization_id, policy_id, body)
                return _response(
                    200,
                    {
                        "configuration": composition["configuration"],
                        "localConfiguration": composition["local_configuration"],
                        "componentRefs": composition["component_refs"],
                        "graphDigest": composition["graph_digest"],
                        "explanation": composition["composition_explanation"],
                    },
                )
            if (
                method == "GET"
                and len(parts) == 3
                and parts[0] == "policies"
                and parts[1] == "imports"
            ):
                import_id = _bounded_identifier(parts[2], "importId")
                imported = TABLE.get_item(
                    Key=_item_key(tenant, "POLICY_IMPORT", import_id),
                    ConsistentRead=True,
                ).get("Item")
                if not imported:
                    return _response(404, {"error": "policy import not found"})
                return _response(200, _policy_import_view(imported))
            if (
                method == "GET"
                and len(parts) == 3
                and parts[0] == "response-rules"
                and parts[2] == "versions"
            ):
                _response_rule_record(tenant, parts[1])
                return _response(
                    200,
                    {
                        "items": [
                            _response_rule_version_view(item)
                            for item in _response_rule_versions(
                                tenant, parts[1], consistent_read=True
                            )
                        ],
                        "nextCursor": None,
                    },
                )
            if (
                method == "POST"
                and len(parts) == 3
                and parts[0] == "response-rules"
                and parts[2] == "versions"
            ):
                return _response(
                    201,
                    _create_response_rule_draft(tenant, parts[1], _body(event), actor),
                )
            if (
                method == "POST"
                and len(parts) == 5
                and parts[0] == "response-rules"
                and parts[2] == "versions"
            ):
                version = _discovery_integer(int(parts[3]), "version", minimum=1)
                if parts[4] == "submit":
                    return _response(
                        200,
                        _submit_response_rule_version(tenant, parts[1], version, actor),
                    )
                if parts[4] == "decision":
                    return _response(
                        200,
                        _decide_response_rule_version(
                            tenant, parts[1], version, _body(event), actor
                        ),
                    )
                if parts[4] == "activate":
                    return _response(
                        200,
                        _activate_response_rule_version(
                            tenant, parts[1], version, _body(event), actor
                        ),
                    )
            if method == "POST" and len(parts) == 3 and parts[0] == "response-rules":
                if parts[2] == "disable":
                    return _response(
                        200,
                        _disable_response_rule(tenant, parts[1], _body(event), actor),
                    )
                if parts[2] == "rollback":
                    return _response(
                        200,
                        _rollback_response_rule(tenant, parts[1], _body(event), actor),
                    )
            if method == "POST" and parts == ["cases"]:
                return _response(201, _create_case(tenant, _body(event), actor))
            if method == "GET" and len(parts) == 3 and parts[0] == "cases" and parts[2] == "export":
                if not (_operator_roles(event) & _CASE_EXPORT_ROLES):
                    return _response(
                        403,
                        {"error": "incident case export requires an authorized evidence role"},
                    )
                return _response(200, _case_export(tenant, parts[1], actor))
            if method == "GET" and len(parts) == 2 and parts[0] == "cases":
                return _response(
                    200, _case_view(tenant, _case_record(tenant, parts[1]), detailed=True)
                )
            if method == "POST" and len(parts) == 3 and parts[0] == "cases":
                operation = parts[2]
                if operation == "contain":
                    return _response(200, _contain_case(tenant, parts[1], _body(event), actor))
                if operation == "release":
                    return _response(200, _release_case(tenant, parts[1], _body(event), actor))
                if operation == "resolve":
                    return _response(
                        200, _transition_case(tenant, parts[1], _body(event), actor, "resolved")
                    )
                if operation == "close":
                    return _response(
                        200, _transition_case(tenant, parts[1], _body(event), actor, "closed")
                    )
            if (
                method == "POST"
                and len(parts) == 4
                and parts[0] == "cases"
                and parts[2:] == ["sessions", "revoke"]
            ):
                return _response(200, _revoke_case_sessions(tenant, parts[1], _body(event), actor))
            if (
                method == "POST"
                and len(parts) == 3
                and parts[0] == "alerts"
                and parts[2] == "acknowledge"
            ):
                return _response(
                    200,
                    _acknowledge_endpoint_alert(tenant, parts[1], _body(event), actor),
                )
            if (
                len(parts) == 4
                and parts[:2] == ["endpoint-evidence", "devices"]
                and parts[3] == "credential"
            ):
                if method == "POST":
                    return _response(
                        201,
                        _issue_endpoint_credential(tenant, parts[2], _body(event), actor),
                    )
                if method == "DELETE":
                    return _response(
                        200,
                        _revoke_endpoint_credential(tenant, parts[2], _body(event), actor),
                    )
            if (
                method == "POST"
                and len(parts) == 4
                and parts[:2] == ["discovery", "sources"]
                and parts[3] == "snapshots"
            ):
                return _response(
                    201,
                    _publish_discovery_snapshot(tenant, parts[2], _body(event), actor),
                )
            if (
                len(parts) == 4
                and parts[:2] == ["discovery", "sources"]
                and parts[3] == "connector-credential"
            ):
                if method == "POST":
                    return _response(
                        201,
                        _rotate_discovery_connector(tenant, parts[2], _body(event), actor),
                    )
                if method == "DELETE":
                    return _response(200, _revoke_discovery_connector(tenant, parts[2], actor))
            if (
                len(parts) == 4
                and parts[:2] == ["discovery", "sources"]
                and parts[3] == "managed-collector"
            ):
                if method == "POST":
                    return _response(
                        201,
                        _create_managed_discovery(tenant, parts[2], _body(event), actor),
                    )
                if method == "DELETE":
                    return _response(
                        200,
                        _disable_managed_discovery(tenant, parts[2], _body(event), actor),
                    )
            if method == "GET" and parts == ["identity"]:
                return _response(200, _identity_access(tenant, event))
            if method == "GET" and parts == ["identity", "break-glass", "requests"]:
                if not (
                    _operator_authorized(event, "incident_response", tenant)
                    or _operator_authorized(event, "identity_admin", tenant)
                ):
                    return _response(
                        403,
                        {
                            "error": "operator role does not permit this action",
                            "requiredCapability": "incident_response or identity_admin",
                        },
                    )
                return _response(200, {"items": _break_glass_requests(tenant)})
            if method == "POST" and parts == ["identity", "break-glass", "requests"]:
                return _response(201, _create_break_glass_request(tenant, event, _body(event)))
            if (
                method == "POST"
                and len(parts) == 5
                and parts[:3] == ["identity", "break-glass", "requests"]
                and parts[4] in {"approve", "deny", "revoke"}
            ):
                request = _decide_break_glass_request(tenant, event, parts[3], parts[4])
                if request is None:
                    return _response(404, {"error": "break-glass request not found"})
                return _response(200, request)
            if method == "GET" and parts == ["identity", "access-certification"]:
                if not _operator_authorized(event, "access_certification_read", tenant):
                    return _response(
                        403,
                        {
                            "error": "operator role does not permit this action",
                            "requiredCapability": "access_certification_read",
                        },
                    )
                return _response(200, _access_certification(tenant, event))
            if method == "GET" and parts == ["identity", "delegated-grants"]:
                if not _operator_authorized(
                    event,
                    "identity_admin",
                    tenant,
                    include_break_glass=False,
                    include_delegated=False,
                ):
                    return _response(
                        403,
                        {
                            "error": "operator role does not permit this action",
                            "requiredCapability": "identity_admin",
                        },
                    )
                return _response(200, {"items": _delegated_grants(tenant), "nextCursor": None})
            if method == "POST" and parts == ["identity", "delegated-grants"]:
                return _response(201, _create_delegated_grant(tenant, event, _body(event)))
            if (
                method == "POST"
                and len(parts) == 4
                and parts[:2] == ["identity", "delegated-grants"]
                and parts[3] == "revoke"
            ):
                grant = _revoke_delegated_grant(tenant, event, parts[2])
                if grant is None:
                    return _response(404, {"error": "delegated grant not found"})
                return _response(200, grant)
            if (
                method == "PUT"
                and len(parts) == 5
                and parts[:3] == ["identity", "scim", "groups"]
                and parts[4] == "role"
            ):
                body = _body(event)
                role = body.get("role")
                if role == "":
                    role = None
                group = _map_scim_group_role(tenant, parts[3], role, actor)
                if group is None:
                    return _response(404, {"error": "SCIM group not found"})
                return _response(200, _identity_access(tenant, event))
            if method == "GET" and parts == ["integrations"]:
                return _response(200, _enterprise_integrations())
            if parts and parts[0] == "webhooks":
                # Secret-free posture is visible to authenticated tenant roles;
                # all mutations were already restricted to platform authority
                # by the central capability classifier above.
                if not _operator_roles(event):
                    return _response(403, {"error": "webhook posture requires a tenant role"})
                if method == "GET" and len(parts) == 1:
                    health_by_destination = {
                        item.get("destination_id"): item
                        for item in _list(tenant, "WEBHOOK_HEALTH", consistent_read=True)
                    }
                    destinations = [
                        _webhook_destination_view(
                            item, health=health_by_destination.get(item.get("id"))
                        )
                        for item in _list(tenant, "WEBHOOK", consistent_read=True)
                    ]
                    destinations.sort(key=lambda item: (item["name"].lower(), item["id"]))
                    return _response(
                        200,
                        {
                            "items": destinations,
                            "supportedEventTypes": sorted(_WEBHOOK_EVENT_TYPES),
                            "nextCursor": None,
                        },
                    )
                if method == "POST" and len(parts) == 1:
                    return _response(201, _create_webhook_destination(tenant, _body(event), actor))
                if method == "GET" and len(parts) == 2:
                    destination = _webhook_destination(tenant, parts[1])
                    if not destination:
                        return _response(404, {"error": "webhook destination not found"})
                    return _response(
                        200,
                        _webhook_destination_view(
                            destination,
                            health=_webhook_destination_health(tenant, parts[1]),
                        ),
                    )
                if method == "GET" and len(parts) == 3 and parts[2] == "deliveries":
                    destination = _webhook_destination(tenant, parts[1])
                    if not destination:
                        return _response(404, {"error": "webhook destination not found"})
                    deliveries = [
                        _webhook_delivery_view(item)
                        for item in _list(tenant, "WEBHOOK_DELIVERY", consistent_read=True)
                        if item.get("destination_id") == destination.get("id")
                    ]
                    deliveries.sort(key=lambda item: (item["createdAt"], item["id"]), reverse=True)
                    return _response(200, {"items": deliveries[:100], "nextCursor": None})
                if method == "POST" and len(parts) == 3:
                    if parts[2] == "rotate":
                        return _response(
                            201,
                            _rotate_webhook_destination(tenant, parts[1], _body(event), actor),
                        )
                    if parts[2] == "test":
                        return _response(
                            202,
                            _test_webhook_destination(tenant, parts[1], _body(event), actor),
                        )
                    if parts[2] in {"pause", "resume", "retire"}:
                        return _response(
                            200,
                            _set_webhook_destination_status(
                                tenant, parts[1], parts[2], _body(event), actor
                            ),
                        )
                return _response(404, {"error": "webhook route not found"})
            if method == "GET" and parts == ["resilience", "policy-trust"]:
                if not _operator_roles(event):
                    return _response(403, {"error": "tenant-wide trust posture requires a role"})
                return _response(200, _policy_trust_convergence(tenant))
            if method == "GET" and parts == ["tenant"]:
                root = TABLE.get_item(
                    Key=_item_key(tenant, "TENANT", "root"), ConsistentRead=True
                ).get("Item", {})
                return _response(
                    200,
                    {
                        "id": tenant,
                        "status": root.get("status", "active"),
                        "trial": bool(root.get("trial", False)),
                        "trialExpiresAt": root.get("trial_expires_at"),
                        "createdAt": root.get("created_at"),
                    },
                )
            if (
                method == "GET"
                and len(parts) == 3
                and parts[0] == "deployments"
                and parts[2] == "managed-package"
            ):
                deployment_id = _bounded_identifier(parts[1], "deploymentId")
                deployment = TABLE.get_item(
                    Key=_item_key(tenant, "DEPLOYMENT", deployment_id),
                    ConsistentRead=True,
                ).get("Item")
                if not deployment:
                    return _response(404, {"error": "deployment not found"})
                scope = _delegated_item_scope(tenant, "DEPLOYMENT", deployment)
                if not (_operator_roles(event) or _service_capabilities(event)) and (
                    scope is None
                    or not _delegated_operator_can_read(tenant, event, "DEPLOYMENT", scope)
                ):
                    return _response(403, {"error": "operator scope does not permit this read"})
                return _response(200, _managed_package_metadata(tenant, deployment_id))
            if method == "GET" and parts == ["compliance", "evidence"]:
                if not _operator_roles(event):
                    return _response(403, {"error": "tenant-wide evidence requires a tenant role"})
                return _response(200, _fleet(tenant)["complianceEvidence"])
            if method == "POST" and parts == ["projects"]:
                body = _body(event)
                organization_id = _bounded_identifier(body.get("organizationId"), "organizationId")
                project_id = _bounded_identifier(body.get("projectId"), "projectId")
                organization = TABLE.get_item(
                    Key=_item_key(tenant, "ORG", organization_id),
                    ConsistentRead=True,
                ).get("Item")
                if not organization:
                    return _response(400, {"error": "organization not found"})
                try:
                    item = _create_item(
                        tenant,
                        "PROJECT",
                        project_id,
                        {
                            "id": project_id,
                            "organization_id": organization_id,
                            "name": _bounded_text(body.get("name"), "name"),
                            "created_at": int(time.time()),
                        },
                    )
                except Exception as error:
                    if _is_conditional_conflict(error):
                        return _response(409, {"error": "project already exists"})
                    raise
                _audit(tenant, "project_created", actor, {"project_id": project_id})
                return _response(201, item)
            if method == "POST" and parts == ["deployments"]:
                body = _body(event)
                organization_id = _bounded_identifier(body.get("organizationId"), "organizationId")
                project_id = _bounded_identifier(body.get("projectId"), "projectId")
                deployment_id = _bounded_identifier(body.get("deploymentId"), "deploymentId")
                project = TABLE.get_item(
                    Key=_item_key(tenant, "PROJECT", project_id),
                    ConsistentRead=True,
                ).get("Item")
                if not project or project.get("organization_id") != organization_id:
                    return _response(400, {"error": "project is not in the selected organization"})
                item_values = {
                    "id": deployment_id,
                    "organization_id": organization_id,
                    "project_id": project_id,
                    "name": _bounded_text(body.get("name"), "name"),
                    "environment": _bounded_text(body.get("environment"), "environment", 64),
                    "region": _bounded_text(body.get("region"), "region", 64),
                    "team": _bounded_text(body.get("team", "Unassigned"), "team", 128),
                    "sdk_version": _bounded_text(
                        body.get("sdkVersion", "not-reported"), "sdkVersion", 64
                    ),
                    "created_at": int(time.time()),
                }
                try:
                    item = _create_item(tenant, "DEPLOYMENT", deployment_id, item_values)
                except Exception as error:
                    if _is_conditional_conflict(error):
                        return _response(409, {"error": "deployment already exists"})
                    raise
                _audit(
                    tenant,
                    "deployment_created",
                    actor,
                    {"deployment_id": deployment_id, "project_id": project_id},
                )
                return _response(201, item)
            if (
                method == "PUT"
                and len(parts) == 3
                and parts[0] == "deployments"
                and parts[2] == "managed-package"
            ):
                deployment_id = _bounded_identifier(parts[1], "deploymentId")
                return _response(
                    201,
                    _publish_managed_package(tenant, deployment_id, _body(event), actor),
                )
            if method == "GET" and parts in (
                ["deployment-config"],
                ["deployment-config", "history"],
            ):
                kind = (
                    "CONFIGURATION" if parts == ["deployment-config"] else "CONFIGURATION_VERSION"
                )
                source_items = (
                    _deployment_configurations(tenant)
                    if kind == "CONFIGURATION"
                    else _list(tenant, kind, consistent_read=True)
                )
                items = _filter_enterprise_items(tenant, event, "CONFIGURATION", source_items)
                return _response(200, {"items": items, "nextCursor": None})
            if method == "POST" and parts == ["templates"]:
                body = _body(event)
                template_id = body.get("templateId")
                configuration = body.get("configuration", {})
                if not isinstance(template_id, str) or not template_id:
                    raise ValueError("templateId is required")
                if not isinstance(configuration, dict):
                    raise ValueError("template configuration must be an object")
                if "managedHost" in configuration:
                    configuration = {
                        **configuration,
                        "managedHost": _managed_host(configuration["managedHost"]),
                    }
                item = _put(
                    tenant,
                    "TEMPLATE",
                    template_id,
                    {
                        "id": template_id,
                        "name": body.get("name", template_id),
                        "configuration": configuration,
                        "version": 1,
                        "createdAt": int(time.time()),
                    },
                )
                _audit(tenant, "template_created", actor, {"template_id": template_id})
                return _response(201, item)
            if method == "POST" and parts == ["deployment-config"]:
                body = _body(event)
                if not isinstance(body, dict) or set(body) != {"deploymentId", "templateId"}:
                    raise ValueError("deployment configuration request has an invalid schema")
                deployment_id = body.get("deploymentId")
                template_id = body.get("templateId")
                template = TABLE.get_item(Key=_item_key(tenant, "TEMPLATE", template_id or "")).get(
                    "Item"
                )
                deployment = TABLE.get_item(
                    Key=_item_key(tenant, "DEPLOYMENT", deployment_id or ""),
                    ConsistentRead=True,
                ).get("Item")
                if (
                    not isinstance(deployment_id, str)
                    or not deployment_id
                    or not template
                    or not deployment
                ):
                    return _response(
                        400, {"error": "deploymentId and an existing templateId are required"}
                    )
                configuration = _json(template.get("configuration", {}))
                if not isinstance(configuration.get("managedHost"), dict):
                    raise ValueError("managed rollout template requires managedHost desired state")
                _managed_host(configuration["managedHost"])
                desired_hash = _configuration_hash(configuration)
                current = TABLE.get_item(
                    Key=_item_key(tenant, "CONFIGURATION", deployment_id), ConsistentRead=True
                ).get("Item")
                current = _ensure_configuration_governance(tenant, current) if current else None
                current_revision = int(current.get("rolloutRevision", 0)) if current else 0
                now = int(time.time())
                item = {
                    **_item_key(tenant, "CONFIGURATION", deployment_id),
                    "tenant_id": tenant,
                    "deploymentId": deployment_id,
                    "templateId": template_id,
                    "desiredConfiguration": configuration,
                    "desiredHash": desired_hash,
                    "appliedHash": None,
                    "drifted": True,
                    "rolloutState": "staged",
                    "requestedState": None,
                    "rolloutPercentage": 0,
                    "rolloutChannel": "stable",
                    "rolloutRing": "canary",
                    "healthCriteria": _json(_ROLLOUT_DEFAULT_CRITERIA),
                    "schedule": None,
                    "rolloutPackageRevision": 0,
                    "lastKnownGoodVersion": current.get("lastKnownGoodVersion")
                    if current
                    else None,
                    "lastKnownGoodPackageRevision": current.get("lastKnownGoodPackageRevision")
                    if current
                    else None,
                    "governanceSchemaVersion": 1,
                    "rolloutRevision": current_revision + 1,
                    "version": int(current.get("version", 0)) + 1 if current else 1,
                    "updatedAt": now,
                    "updatedBy": actor,
                }
                version_record = _configuration_version_record(tenant, item, actor)
                condition = (
                    "attribute_not_exists(pk)"
                    if current is None
                    else "rolloutRevision = :expected_revision"
                )
                values = None if current is None else {":expected_revision": current_revision}
                _transact_policy_records(
                    [
                        _transaction_put(item, condition=condition, values=values),
                        _transaction_put(version_record, condition="attribute_not_exists(pk)"),
                    ]
                )
                _audit(
                    tenant,
                    "deployment_configuration_staged",
                    actor,
                    {
                        "deployment_id": deployment_id,
                        "template_id": template_id,
                        "desired_hash": desired_hash,
                        "configuration_version": item["version"],
                        "rollout_revision": item["rolloutRevision"],
                    },
                )
                return _response(201, _reconcile_deployment_rollout(tenant, item, now=now))
            if method == "POST" and parts == ["deployment-config", "batch-rollout"]:
                return _response(
                    200, {"items": _start_managed_rollouts(tenant, _body(event), actor)}
                )
            if (
                method == "POST"
                and len(parts) == 3
                and parts[0] == "deployment-config"
                and parts[2] == "pause"
            ):
                return _response(
                    200,
                    _pause_managed_rollout(tenant, parts[1], _body(event), actor),
                )
            if method == "POST" and parts == ["deployment-config", "rollback"]:
                body = _body(event)
                if not isinstance(body, dict) or set(body) != {
                    "deploymentId",
                    "targetVersion",
                    "expectedRevision",
                    "reason",
                }:
                    raise ValueError("managed rollback request has an invalid schema")
                deployment_id = _bounded_identifier(body.get("deploymentId"), "deploymentId")
                return _response(
                    200,
                    _rollback_managed_configuration(
                        tenant,
                        deployment_id,
                        {key: value for key, value in body.items() if key != "deploymentId"},
                        actor,
                    ),
                )
            if method == "POST" and parts == ["emergency-stop"]:
                body = _body(event)
                deployment_id = _bounded_identifier(body.get("deploymentId"), "deploymentId")
                active = bool(body.get("active", True))
                deployment = TABLE.get_item(
                    Key=_item_key(tenant, "DEPLOYMENT", deployment_id), ConsistentRead=True
                ).get("Item")
                if not deployment:
                    return _response(404, {"error": "deployment not found"})
                agents = [
                    item
                    for item in _list(tenant, "AGENT")
                    if item.get("deployment_id") == deployment_id
                ]
                control = _set_scope_emergency_stop(
                    tenant, "deployment", deployment_id, active, actor
                )
                _audit(
                    tenant,
                    "deployment_emergency_stop",
                    actor,
                    {
                        "deployment_id": deployment_id,
                        "active": active,
                        "agent_count": len(agents),
                        "control_revision": control["revision"],
                    },
                )
                return _response(
                    200,
                    {
                        "deploymentId": deployment_id,
                        "active": active,
                        "agentCount": len(agents),
                        "control": control,
                    },
                )
            if (
                method == "POST"
                and len(parts) == 3
                and parts[0] == "groups"
                and parts[2] == "emergency-stop"
            ):
                body = _body(event)
                group = TABLE.get_item(Key=_item_key(tenant, "GROUP", parts[1])).get("Item")
                active = bool(body.get("active", True))
                if not group:
                    return _response(404, {"error": "group not found"})
                control = _set_scope_emergency_stop(tenant, "group", parts[1], active, actor)
                _audit(
                    tenant,
                    "group_emergency_stop",
                    actor,
                    {
                        "group_id": parts[1],
                        "active": active,
                        "control_revision": control["revision"],
                    },
                )
                return _response(
                    200,
                    {
                        **group,
                        "emergencyStop": active,
                        "active": active,
                        "agents": group.get("agent_keys", []),
                        "control": control,
                    },
                )
            if (
                method == "GET"
                and len(parts) == 3
                and parts[0] == "policies"
                and parts[2] == "versions"
            ):
                policy_id = _bounded_identifier(parts[1], "policyId")
                policy = TABLE.get_item(
                    Key=_item_key(tenant, "POLICY", policy_id), ConsistentRead=True
                ).get("Item")
                if not policy:
                    return _response(404, {"error": "policy not found"})
                scope = _delegated_item_scope(tenant, "POLICY", policy)
                if not (_operator_roles(event) or _service_capabilities(event)) and (
                    scope is None
                    or not _delegated_operator_can_read(tenant, event, "POLICY", scope)
                ):
                    return _response(403, {"error": "operator scope does not permit this read"})
                _ensure_policy_governance(tenant, policy)
                versions = _policy_versions(tenant, policy_id, consistent_read=True)
                return _response(
                    200,
                    {
                        "items": [
                            _policy_version_view(tenant, item, versions) for item in versions
                        ],
                        "nextCursor": None,
                    },
                )
            if (
                method == "GET"
                and len(parts) == 4
                and parts[0] == "policies"
                and parts[2] == "versions"
            ):
                policy_id = _bounded_identifier(parts[1], "policyId")
                version = _positive_policy_version(int(parts[3]))
                policy = TABLE.get_item(
                    Key=_item_key(tenant, "POLICY", policy_id), ConsistentRead=True
                ).get("Item")
                scope = _delegated_item_scope(tenant, "POLICY", policy or {})
                if not (_operator_roles(event) or _service_capabilities(event)) and (
                    scope is None
                    or not _delegated_operator_can_read(tenant, event, "POLICY", scope)
                ):
                    return _response(403, {"error": "operator scope does not permit this read"})
                return _response(
                    200,
                    _policy_version_view(
                        tenant, _policy_version_record(tenant, policy_id, version)
                    ),
                )
            if (
                method == "POST"
                and len(parts) == 5
                and parts[0] == "policies"
                and parts[2] == "versions"
            ):
                policy_id = _bounded_identifier(parts[1], "policyId")
                version = _positive_policy_version(int(parts[3]))
                action = parts[4]
                if action == "export":
                    result = _export_policy_source(tenant, policy_id, version, actor)
                elif action == "submit":
                    result = _submit_policy_version(tenant, policy_id, version, actor)
                elif action == "simulate":
                    result = _simulate_policy_version(tenant, policy_id, version, _body(event))
                elif action == "decision":
                    result = _decide_policy_version(tenant, policy_id, version, _body(event), actor)
                elif action == "stage":
                    result = _stage_policy_version(tenant, policy_id, version, actor)
                elif action == "activate":
                    result = _activate_policy_version(
                        tenant, policy_id, version, _body(event), actor
                    )
                else:
                    raise ValueError("policy transition is unsupported")
                return _response(200, result)
            if method == "POST" and parts == ["policies", "imports"]:
                return _response(201, _import_policy_source(tenant, _body(event), actor))
            if (
                method == "POST"
                and len(parts) == 3
                and parts[0] == "policies"
                and parts[2] == "versions"
            ):
                return _response(
                    200,
                    _create_policy_draft(tenant, parts[1], _body(event), actor),
                )
            if method == "POST" and parts == ["skills"]:
                body = _body(event)
                skill_id = _bounded_identifier(body.get("skillId"), "skillId")
                return _response(
                    201,
                    _create_managed_registration(tenant, "SKILL", skill_id, body, actor),
                )
            if method == "POST" and parts == ["mcp-servers"]:
                body = _body(event)
                server_id = _bounded_identifier(body.get("serverId"), "serverId")
                return _response(
                    201,
                    _create_managed_registration(tenant, "MCP", server_id, body, actor),
                )
            if (
                method in {"PUT", "DELETE"}
                and len(parts) == 2
                and parts[0] in {"skills", "mcp-servers"}
            ):
                identifier = _bounded_identifier(
                    parts[1], "skillId" if parts[0] == "skills" else "serverId"
                )
                kind = "SKILL" if parts[0] == "skills" else "MCP"
                result = (
                    _replace_managed_registration(tenant, kind, identifier, _body(event), actor)
                    if method == "PUT"
                    else _retire_managed_registration(tenant, kind, identifier, _body(event), actor)
                )
                return _response(200, result)
            if method == "POST" and parts == ["policies"]:
                return _response(201, _create_governed_policy(tenant, _body(event), actor))
            if method == "POST" and parts == ["agents", "bootstrap"]:
                return _response(201, _issue_agent_bootstrap(tenant, _body(event), actor))
            if method == "POST" and parts == ["approvals"]:
                body = _body(event)
                approval_id = body.get("approvalId")
                required = (
                    "approvalId",
                    "agentKey",
                    "toolName",
                    "proposalId",
                    "taskId",
                    "principalId",
                    "actionHash",
                )
                if not approval_id or any(
                    not isinstance(body.get(key), str) or not body.get(key) for key in required
                ):
                    raise ValueError("approval identity and action binding are required")
                agent_key = _approval_text(body["agentKey"], "agentKey")
                if not TABLE.get_item(
                    Key=_item_key(tenant, "AGENT", agent_key),
                    ConsistentRead=True,
                ).get("Item"):
                    return _response(400, {"error": "approval agent is not enrolled"})
                risk_class = body.get("riskClass", "unspecified")
                if risk_class not in {
                    "write",
                    "destructive",
                    "external_egress",
                    "code_execution",
                    "secret_read",
                    "unspecified",
                }:
                    raise ValueError("riskClass is unsupported")
                expires_at = int(time.time()) + min(max(int(body.get("ttlSeconds", 120)), 1), 3600)
                item = {
                    **_item_key(tenant, "APPROVAL", approval_id),
                    "tenant_id": tenant,
                    "id": approval_id,
                    "agent_key": agent_key,
                    "tool_name": _approval_text(body["toolName"], "toolName"),
                    "proposal_id": _approval_text(body["proposalId"], "proposalId"),
                    "task_id": _approval_text(body["taskId"], "taskId"),
                    "principal_id": _approval_text(body["principalId"], "principalId"),
                    "action_hash": _approval_text(body["actionHash"], "actionHash", 128),
                    "risk_class": risk_class,
                    "resource_ids": _approval_resources(body.get("resourceIds")),
                    "status": "approved",
                    "consumed": False,
                    "expires_at": expires_at,
                    "ttl": expires_at,
                    "created_at": int(time.time()),
                    "requested_at": int(time.time()),
                    "decided_at": int(time.time()),
                    "decided_by": actor,
                    "decision_reason": "Direct operator grant",
                }
                try:
                    TABLE.put_item(
                        Item=item,
                        ConditionExpression="attribute_not_exists(pk)",
                    )
                except Exception as error:
                    if (
                        getattr(error, "response", {}).get("Error", {}).get("Code")
                        == "ConditionalCheckFailedException"
                    ):
                        return _response(409, {"error": "approval ID already exists"})
                    raise
                _audit(
                    tenant,
                    "approval_created",
                    actor,
                    {
                        "approval_id": approval_id,
                        "agent_key": agent_key,
                        "expires_at": expires_at,
                    },
                )
                return _response(201, {"id": item["id"], "expiresAt": expires_at})
            if (
                method == "POST"
                and len(parts) == 3
                and parts[0] == "approvals"
                and parts[2] == "decision"
            ):
                approval_id = parts[1]
                body = _body(event)
                decision = body.get("decision")
                reason = body.get("reason")
                if decision not in {"approved", "denied"}:
                    raise ValueError("decision must be approved or denied")
                reason = _approval_text(reason, "reason", 500)
                now = int(time.time())
                current = TABLE.get_item(
                    Key=_item_key(tenant, "APPROVAL", approval_id),
                    ConsistentRead=True,
                ).get("Item")
                if not current:
                    return _response(404, {"error": "approval request not found"})
                grant_expiry = now + int(current.get("grant_ttl_seconds", 120))
                try:
                    updated = TABLE.update_item(
                        Key=_item_key(tenant, "APPROVAL", approval_id),
                        UpdateExpression=(
                            "SET #status = :decision, decided_at = :now, "
                            "decided_by = :actor, decision_reason = :reason, "
                            "expires_at = :expires_at, #ttl = :ttl"
                        ),
                        ConditionExpression=(
                            "attribute_exists(pk) AND #status = :pending AND expires_at > :now"
                        ),
                        ExpressionAttributeNames={"#status": "status", "#ttl": "ttl"},
                        ExpressionAttributeValues={
                            ":decision": decision,
                            ":pending": "pending",
                            ":now": now,
                            ":actor": actor,
                            ":reason": reason,
                            ":expires_at": grant_expiry if decision == "approved" else now,
                            ":ttl": grant_expiry if decision == "approved" else now + 86400,
                        },
                        ReturnValues="ALL_NEW",
                    )
                except Exception as error:
                    if (
                        getattr(error, "response", {}).get("Error", {}).get("Code")
                        == "ConditionalCheckFailedException"
                    ):
                        return _response(
                            409,
                            {"error": "approval request is expired or already decided"},
                        )
                    raise
                item = updated.get("Attributes", {})
                _audit(
                    tenant,
                    "approval_decided",
                    actor,
                    {
                        "approval_id": approval_id,
                        "agent_key": item.get("agent_key", ""),
                        "decision": decision,
                    },
                )
                return _response(200, _approval_view(item, now))
            if method == "POST" and parts == ["groups"]:
                body = _body(event)
                group_id = _bounded_identifier(body.get("groupId"), "groupId")
                policy_id = _bounded_identifier(body.get("policyId"), "policyId")
                policy = next((p for p in _list(tenant, "POLICY") if p["id"] == policy_id), None)
                if not policy:
                    return _response(400, {"error": "policy not found"})
                policy = _ensure_policy_governance(tenant, policy)
                if int(policy.get("version", 0)) <= 0:
                    raise PolicyConflict("group policies must have an active governed version")
                now = int(time.time())
                item = {
                    **_item_key(tenant, "GROUP", group_id),
                    "tenant_id": tenant,
                    "id": group_id,
                    "organizationId": policy.get("organization_id", ""),
                    "name": _bounded_text(body.get("name"), "name"),
                    "policyId": policy["id"],
                    "policyName": policy["name"],
                    "createdAt": now,
                    "agent_keys": [],
                    "membership_revision": 1,
                    "membership_mode": "manual",
                    "configuration_revision": 1,
                }
                payload = {"group_id": group_id, "configuration_revision": 1}
                audit = _configuration_audit_record(
                    tenant, "group_created", actor, payload, now=now
                )
                _transact_configuration(
                    [
                        _transaction_put(item, condition="attribute_not_exists(pk)"),
                        _transaction_put(audit, condition="attribute_not_exists(pk)"),
                    ]
                )
                _export_configuration_audit(tenant, "group_created", actor, payload)
                return _response(
                    201,
                    {
                        **item,
                        "membershipRevision": 1,
                        "configurationRevision": 1,
                        "agents": [],
                    },
                )
            if method in {"PUT", "DELETE"} and len(parts) == 2 and parts[0] == "groups":
                result = (
                    _replace_group_configuration(tenant, parts[1], _body(event), actor)
                    if method == "PUT"
                    else _delete_empty_group(tenant, parts[1], _body(event), actor)
                )
                return _response(200, result)
            if (
                method == "POST"
                and len(parts) == 3
                and parts[0] == "groups"
                and parts[2] == "policy"
            ):
                body = _body(event)
                group = TABLE.get_item(
                    Key=_item_key(tenant, "GROUP", parts[1]), ConsistentRead=True
                ).get("Item")
                policy_id = _bounded_identifier(body.get("policyId"), "policyId")
                policy = TABLE.get_item(
                    Key=_item_key(tenant, "POLICY", policy_id), ConsistentRead=True
                ).get("Item")
                if not group or not policy:
                    return _response(404, {"error": "group or policy not found"})
                # Group policy is an authority edge. Resolve both organization
                # owners from server records so a browser or delegated operator
                # cannot bridge two business-unit boundaries by identifier.
                group_organization = group.get("organizationId") or group.get("organization_id")
                policy_organization = policy.get("organization_id") or policy.get("organizationId")
                if (
                    not group_organization
                    or not policy_organization
                    or group_organization != policy_organization
                ):
                    return _response(
                        409,
                        {"error": "group and policy must belong to the same organization"},
                    )
                policy = _ensure_policy_governance(tenant, policy)
                if int(policy.get("version", 0)) <= 0:
                    raise PolicyConflict("group policies must have an active governed version")
                current_agent_keys = _group_agent_keys(group)
                current_policy_id = group.get("policyId")
                group.update({"policyId": policy["id"], "policyName": policy["name"]})
                try:
                    TABLE.put_item(
                        Item=group,
                        ConditionExpression="agent_keys = :agent_keys AND policyId = :policy_id",
                        ExpressionAttributeValues={
                            ":agent_keys": current_agent_keys,
                            ":policy_id": current_policy_id,
                        },
                    )
                except Exception as error:
                    if _is_conditional_conflict(error):
                        raise PolicyConflict("group authority changed concurrently") from error
                    raise
                _audit(
                    tenant,
                    "group_policy_changed",
                    actor,
                    {"group_id": parts[1], "policy_id": policy["id"]},
                )
                return _response(
                    200, next(g for g in _fleet(tenant)["groups"] if g["id"] == parts[1])
                )
            if (
                method == "POST"
                and len(parts) == 3
                and parts[0] == "groups"
                and parts[2] == "dynamic-membership"
            ):
                result = _configure_dynamic_group(
                    tenant,
                    _bounded_identifier(parts[1], "groupId"),
                    _body(event),
                    actor,
                )
                return _response(200, result)
            if (
                method == "POST"
                and len(parts) == 4
                and parts[0] == "groups"
                and parts[2:] == ["agents", "bulk"]
            ):
                status_code, result = _bulk_assign_group_membership(
                    tenant,
                    _bounded_identifier(parts[1], "groupId"),
                    _body(event),
                    actor,
                )
                return _response(status_code, result)
            if (
                method == "POST"
                and len(parts) == 3
                and parts[0] == "groups"
                and parts[2] == "agents"
            ):
                body = _body(event)
                deployment_id = _bounded_identifier(body.get("deploymentId"), "deploymentId")
                agent_id = _bounded_identifier(body.get("agentId"), "agentId")
                group = TABLE.get_item(
                    Key=_item_key(tenant, "GROUP", parts[1]), ConsistentRead=True
                ).get("Item")
                key = f"{deployment_id}:{agent_id}"
                if not group:
                    return _response(404, {"error": "group not found"})
                agent = TABLE.get_item(
                    Key=_item_key(tenant, "AGENT", key), ConsistentRead=True
                ).get("Item")
                if not agent:
                    return _response(404, {"error": "agent not found"})
                if _agent_lifecycle_state(agent) != "active":
                    return _response(
                        409, {"error": "only an active agent can receive group authority"}
                    )
                # Membership changes policy authority. The enrolled agent's
                # immutable server-owned organization must exactly match the
                # group's owner; missing legacy ownership fails closed.
                group_organization = group.get("organizationId") or group.get("organization_id")
                agent_organization = agent.get("organization_id") or agent.get("organizationId")
                if (
                    not group_organization
                    or not agent_organization
                    or group_organization != agent_organization
                ):
                    return _response(
                        409,
                        {"error": "group and agent must belong to the same organization"},
                    )
                status_code, result = _bulk_assign_group_membership(
                    tenant,
                    parts[1],
                    {
                        "mode": "apply",
                        "requestId": str(uuid.uuid4()),
                        "expectedMembershipRevision": _group_membership_revision(group),
                        "agents": [{"deploymentId": deployment_id, "agentId": agent_id}],
                        "reason": "Single-agent assignment requested by an authorized operator.",
                    },
                    actor,
                    event_type="agent_added_to_group",
                )
                if status_code == 207:
                    outcome = result["outcomes"][0]
                    return _response(409, {"error": outcome["message"]})
                return _response(
                    200, next(g for g in _fleet(tenant)["groups"] if g["id"] == parts[1])
                )
            if (
                method == "DELETE"
                and len(parts) == 5
                and parts[0] == "groups"
                and parts[2] == "agents"
            ):
                group = TABLE.get_item(
                    Key=_item_key(tenant, "GROUP", parts[1]), ConsistentRead=True
                ).get("Item")
                key = f"{parts[3]}:{parts[4]}"
                if not group:
                    return _response(404, {"error": "group not found"})
                _remove_group_member(tenant, parts[1], key, actor)
                return _response(
                    200, next(g for g in _fleet(tenant)["groups"] if g["id"] == parts[1])
                )
            if method == "POST" and parts == ["agents", "register"]:
                body = _body(event)
                agent_id = _bounded_identifier(body.get("agentId"), "agentId")
                deployment_id = _bounded_identifier(body.get("deploymentId"), "deploymentId")
                deployment = TABLE.get_item(
                    Key=_item_key(tenant, "DEPLOYMENT", deployment_id),
                    ConsistentRead=True,
                ).get("Item")
                if not deployment:
                    return _response(400, {"error": "deployment not found"})
                project_root = _project_root(body.get("projectRoot"))
                agent_key = f"{deployment_id}:{agent_id}"
                existing = TABLE.get_item(
                    Key=_item_key(tenant, "AGENT", agent_key),
                    ConsistentRead=True,
                ).get("Item")
                if existing:
                    existing = _explicit_agent_lifecycle(tenant, deployment_id, agent_id)
                    if _agent_lifecycle_state(existing) != "active":
                        return _response(
                            409,
                            {"error": "revoked or offboarded agent identities cannot be reused"},
                        )
                    existing_root = existing.get("project_root")
                    if existing_root:
                        if existing_root != project_root:
                            return _response(
                                409, {"error": "agent project scope is immutable after enrollment"}
                            )
                        return _response(
                            200,
                            {
                                **existing,
                                "ownership": _agent_ownership_view(existing),
                            },
                        )
                    # Legacy records could omit scope. Permit only the one-way
                    # transition from empty to a bounded root; later scope
                    # changes require a new agent identity and enrollment.
                    try:
                        updated = TABLE.update_item(
                            Key=_item_key(tenant, "AGENT", agent_key),
                            UpdateExpression="SET project_root = :project_root",
                            ConditionExpression=(
                                "attribute_exists(pk) AND "
                                "(attribute_not_exists(project_root) OR project_root = :empty)"
                            ),
                            ExpressionAttributeValues={
                                ":project_root": project_root,
                                ":empty": "",
                            },
                            ReturnValues="ALL_NEW",
                        )
                    except Exception as error:
                        if not _is_conditional_conflict(error):
                            raise
                        # Another operator may have won the one-time repair
                        # after our consistent read. The same root is
                        # idempotent; a different root is an immutable-scope
                        # conflict and must never become last-writer-wins.
                        current = TABLE.get_item(
                            Key=_item_key(tenant, "AGENT", agent_key),
                            ConsistentRead=True,
                        ).get("Item")
                        if current and current.get("project_root") == project_root:
                            return _response(
                                200,
                                {
                                    **current,
                                    "ownership": _agent_ownership_view(current),
                                },
                            )
                        return _response(
                            409, {"error": "agent project scope is immutable after enrollment"}
                        )
                    repaired = updated.get("Attributes", {**existing, "project_root": project_root})
                    _audit(
                        tenant,
                        "agent_project_scope_recorded",
                        actor,
                        {"deployment_id": deployment_id, "agent_id": agent_id},
                    )
                    return _response(
                        200,
                        {
                            **repaired,
                            "ownership": _agent_ownership_view(repaired),
                        },
                    )
                now = int(time.time())
                ownership = _new_agent_ownership(
                    tenant,
                    body.get("ownership"),
                    deployment,
                    actor,
                    now=now,
                )
                try:
                    item = _create_item(
                        tenant,
                        "AGENT",
                        agent_key,
                        {
                            "id": agent_id,
                            # Ownership and environment come from the trusted
                            # deployment record, never browser-supplied values.
                            "organization_id": deployment["organization_id"],
                            "project_id": deployment["project_id"],
                            "deployment_id": deployment_id,
                            "host": _agent_host(body.get("host")),
                            "project_root": project_root,
                            "environment": deployment["environment"],
                            "region": deployment["region"],
                            "status": "offline",
                            "last_heartbeat": 0,
                            "expires_at": 0,
                            "emergencyStop": False,
                            "created_at": now,
                            "lifecycle_state": "active",
                            "lifecycle_revision": 1,
                            "session_revision": 1,
                            **ownership,
                            "ownership_revision": 1,
                        },
                    )
                except Exception as error:
                    if _is_conditional_conflict(error):
                        return _response(409, {"error": "agent already exists"})
                    raise
                _audit(
                    tenant,
                    "agent_registered",
                    actor,
                    {"deployment_id": deployment_id, "agent_id": agent_id},
                )
                return _response(
                    201,
                    {
                        **item,
                        "ownership": _agent_ownership_view(item, now=now),
                    },
                )
            if (
                method == "PUT"
                and len(parts) == 4
                and parts[0] == "agents"
                and parts[3] == "ownership"
            ):
                deployment_id = _bounded_identifier(parts[1], "deploymentId")
                agent_id = _bounded_identifier(parts[2], "agentId")
                result = _update_agent_ownership(
                    tenant,
                    deployment_id,
                    agent_id,
                    _body(event),
                    actor,
                )
                if result is None:
                    return _response(404, {"error": "agent not found"})
                return _response(200, result)
            if (
                method == "POST"
                and len(parts) == 4
                and parts[0] == "agents"
                and parts[3] in {"revoke", "replace", "offboard"}
            ):
                deployment_id = _bounded_identifier(parts[1], "deploymentId")
                agent_id = _bounded_identifier(parts[2], "agentId")
                operation = parts[3]
                lifecycle_handler = {
                    "revoke": _revoke_agent,
                    "replace": _replace_agent,
                    "offboard": _offboard_agent,
                }[operation]
                result = lifecycle_handler(tenant, deployment_id, agent_id, _body(event), actor)
                if result is None:
                    return _response(404, {"error": "agent not found"})
                return _response(201 if operation == "replace" else 200, result)
            if (
                method == "GET"
                and len(parts) == 4
                and parts[0] == "agents"
                and parts[3] == "effective-policy"
            ):
                agent_key = f"{parts[1]}:{parts[2]}"
                agent = TABLE.get_item(Key=_item_key(tenant, "AGENT", agent_key)).get("Item")
                if not agent:
                    return _response(404, {"error": "agent not found"})
                if _agent_lifecycle_state(agent) != "active":
                    return _response(409, {"error": "agent identity is revoked or offboarded"})
                scope = _delegated_item_scope(tenant, "AGENT", agent)
                if not _operator_roles(event) and (
                    scope is None or not _delegated_operator_can_read(tenant, event, "AGENT", scope)
                ):
                    return _response(403, {"error": "operator scope does not permit this read"})
                control_state = _agent_control_state(tenant, agent)
                if not control_state["executionAllowed"]:
                    return _response(
                        409,
                        {
                            "error": "server-owned response control withholds agent execution",
                            "controlState": control_state,
                        },
                    )
                groups = [
                    group
                    for group in _fleet(tenant)["groups"]
                    if agent_key in group.get("agent_keys", [])
                ]
                if not groups:
                    return _response(409, {"error": "agent has no assigned policy"})
                if len(groups) != 1:
                    return _response(
                        409, {"error": "agent has conflicting policy-group assignments"}
                    )
                group = groups[0]
                policy = TABLE.get_item(Key=_item_key(tenant, "POLICY", group["policyId"])).get(
                    "Item"
                )
                if not policy:
                    return _response(409, {"error": "assigned policy is unavailable"})
                policy = _ensure_policy_governance(tenant, policy)
                if int(policy.get("version", 0)) <= 0:
                    return _response(409, {"error": "assigned policy has no active version"})
                exception = _active_policy_exception_bundle(tenant, parts[1], parts[2])
                return _response(
                    200,
                    {
                        "agentId": parts[2],
                        "deploymentId": parts[1],
                        "groupId": group["id"],
                        "policyBundle": exception["policyBundle"]
                        if exception
                        else _active_policy_bundle(tenant, policy),
                        "effectiveSource": "temporary_exception" if exception else "active_policy",
                        "exception": exception["exception"] if exception else None,
                    },
                )
            if (
                method == "POST"
                and len(parts) >= 4
                and parts[0] == "agents"
                and parts[-1] == "emergency-stop"
            ):
                agent = TABLE.get_item(
                    Key=_item_key(tenant, "AGENT", f"{parts[1]}:{parts[2]}"),
                    ConsistentRead=True,
                ).get("Item")
                if not agent:
                    return _response(404, {"error": "agent not found"})
                if _agent_lifecycle_state(agent) != "active":
                    return _response(409, {"error": "agent identity is revoked or offboarded"})
                agent = _require_active_agent(_explicit_agent_lifecycle(tenant, parts[1], parts[2]))
                active = bool(_body(event).get("active", True))
                control = _set_scope_emergency_stop(
                    tenant, "agent", f"{parts[1]}:{parts[2]}", active, actor
                )
                # An old agent-scoped stop used this field directly. Clear it
                # only through the exact agent endpoint; broader scope clears
                # never touch agent records.
                if not active and agent.get("emergencyStop") is True:
                    agent["emergencyStop"] = False
                    TABLE.put_item(
                        Item=agent,
                        ConditionExpression=(
                            "lifecycle_state = :active AND lifecycle_revision = :revision"
                        ),
                        ExpressionAttributeValues={
                            ":active": "active",
                            ":revision": int(agent["lifecycle_revision"]),
                        },
                    )
                _audit(
                    tenant,
                    "agent_emergency_stop",
                    actor,
                    {
                        "deployment_id": parts[1],
                        "agent_id": parts[2],
                        "active": active,
                        "control_revision": control["revision"],
                    },
                )
                return _response(
                    200,
                    {
                        **agent,
                        "emergencyStop": active,
                        "controlState": _agent_control_state(tenant, agent),
                    },
                )
            if (
                method == "GET"
                and len(parts) == 4
                and parts[0] == "agents"
                and parts[3] == "verify"
            ):
                agent = TABLE.get_item(
                    Key=_item_key(tenant, "AGENT", f"{parts[1]}:{parts[2]}"),
                    ConsistentRead=True,
                ).get("Item")
                if not agent and not _operator_roles(event):
                    return _response(404, {"error": "agent not found"})
                scope = _delegated_item_scope(tenant, "AGENT", agent or {})
                if not _operator_roles(event) and (
                    scope is None or not _delegated_operator_can_read(tenant, event, "AGENT", scope)
                ):
                    return _response(403, {"error": "operator scope does not permit this read"})
                return _response(200, _verify_agent(tenant, parts[1], parts[2]))
        return _response(404, {"error": "not found"})
    except ValueError as exc:
        return _response(400, {"error": str(exc)})
    except PermissionError as exc:
        return _response(403, {"error": str(exc)})
    except LookupError as exc:
        return _response(404, {"error": str(exc)})
    except PolicyConflict as exc:
        return _response(409, {"error": str(exc)})
    except ManagedPackageConflict as exc:
        return _response(409, {"error": str(exc)})
    except ManagedPackageNotFound as exc:
        return _response(404, {"error": str(exc)})
    except Exception as exc:
        print(json.dumps({"error": str(exc), "path": event.get("rawPath")}))
        return _response(500, {"error": "control plane unavailable"})
