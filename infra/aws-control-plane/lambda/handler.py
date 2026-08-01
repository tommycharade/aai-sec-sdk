"""Minimal AWS control-plane adapter used by the hosted enterprise UI.

The Lambda is deliberately small: DynamoDB owns tenant-scoped desired state,
while S3 receives redacted lifecycle evidence. No request body is trusted for
tenant identity; the tenant is derived from the verified Cognito claims.
"""

import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import time
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import boto3
from boto3.dynamodb.conditions import Key
from policy_signing import bundle_from_record, sign_policy_bundle

CONTROL_TABLE_NAME = os.environ["CONTROL_TABLE"]
TABLE = boto3.resource("dynamodb").Table(CONTROL_TABLE_NAME)
PRESENCE = boto3.resource("dynamodb").Table(os.environ["PRESENCE_TABLE"])
IDEMPOTENCY = boto3.resource("dynamodb").Table(os.environ["IDEMPOTENCY_TABLE"])
SCIM_TABLE_NAME = os.environ.get("SCIM_TABLE", "")
SCIM = boto3.resource("dynamodb").Table(SCIM_TABLE_NAME) if SCIM_TABLE_NAME else None
DYNAMODB = boto3.client("dynamodb")
S3 = boto3.client("s3")
SNS = boto3.client("sns")
KMS = boto3.client("kms")
POLICY_SIGNING_KEY_ARN = os.environ.get("POLICY_SIGNING_KEY_ARN", "")

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
_CASE_STATUSES = frozenset({"open", "investigating", "contained", "resolved", "closed"})
_CASE_EXPORT_ROLES = frozenset(
    {"platform-admin", "security-operator", "incident-responder", "auditor"}
)
_CASE_EXPORT_RECORD_LIMIT = 500
_CASE_EXPORT_LOOKBACK_SECONDS = 24 * 60 * 60
_RESPONSE_RULE_VERSION_STATES = frozenset(
    {"draft", "review", "approved", "active", "superseded", "rejected"}
)
_RESPONSE_RULE_PENDING_STATES = frozenset({"draft", "review", "approved"})
_RESPONSE_RULE_PREVIEW_LIMIT = 100
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
        }
    ),
    "policy-author": frozenset({"policy_write", "policy_simulation"}),
    "policy-approver": frozenset({"approval_decision", "policy_approval", "policy_simulation"}),
    "fleet-operator": frozenset({"fleet_write"}),
    "incident-responder": frozenset({"incident_response"}),
    "auditor": frozenset({"access_certification_read"}),
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
_POLICY_VERSION_STATES = frozenset(
    {"draft", "review", "approved", "staged", "active", "rejected", "retired"}
)
_POLICY_PENDING_STATES = frozenset({"draft", "review", "approved", "staged"})
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
    if _operator_roles(event):
        return items
    result = []
    for item in items:
        scope = _delegated_item_scope(tenant, kind, item)
        if scope is not None and _delegated_operator_can_read(tenant, event, kind, scope):
            result.append(item)
    return result


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


_MANAGED_HOST_FIELDS = {
    "host",
    "hostVersion",
    "platform",
    "bundleHash",
    "policyId",
    "policyVersion",
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
_MANAGED_PACKAGE_FIELDS = {
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
    expected = _MANAGED_REPORT_FIELDS if report else _MANAGED_HOST_FIELDS
    if not isinstance(value, dict) or set(value) != expected:
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
    if (
        not isinstance(value, dict)
        or set(value) != _MANAGED_PACKAGE_FIELDS
        or value.get("schemaVersion") != 1
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
    }
    try:
        if current is None:
            TABLE.put_item(Item=record, ConditionExpression="attribute_not_exists(pk)")
        else:
            TABLE.put_item(
                Item=record,
                ConditionExpression="revision = :expected_revision",
                ExpressionAttributeValues={":expected_revision": expected_revision},
            )
    except Exception as error:
        if _is_conditional_conflict(error):
            raise ManagedPackageConflict("managed package revision is stale") from error
        raise
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
    if state not in {"canary", "active", "rollback"}:
        raise ManagedPackageConflict("managed package rollout is not active")
    bucket = int(hashlib.sha256(agent_key.encode()).hexdigest()[:8], 16) % 100
    if percentage > 100 or percentage <= bucket:
        raise ManagedPackageConflict("agent is not selected for managed package rollout")
    package = TABLE.get_item(
        Key=_item_key(tenant, "MANAGED_PACKAGE", deployment_id), ConsistentRead=True
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
        "schemaVersion": 1,
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
    identity_fields = tuple(_MANAGED_HOST_FIELDS)
    if agent.get("host") != desired["host"] or any(
        observed[field] != desired[field] for field in identity_fields
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
    bundle = _sign_policy_bundle(
        tenant, policy["id"], active_version, effective_configuration, now
    )
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
        bundle_from_record(tenant, policy["id"], version, record)
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
        bundle_from_record(tenant, policy["id"], version, current)
    return policy


def _active_policy_bundle(tenant, policy):
    """Return only persisted, internally consistent signed active authority."""
    governed = _ensure_policy_governance(tenant, policy)
    governed = _ensure_active_policy_signature(tenant, governed)
    version = int(governed.get("version", 0))
    record = _policy_version_record(tenant, governed["id"], version)
    return bundle_from_record(tenant, governed["id"], version, record)


def _policy_trust_metadata():
    """Expose public signer provenance without making HTTP a runtime trust anchor."""
    if not POLICY_SIGNING_KEY_ARN:
        raise RuntimeError("policy signing key is not configured")
    result = KMS.get_public_key(KeyId=POLICY_SIGNING_KEY_ARN)
    public_key = result.get("PublicKey")
    if (
        result.get("KeyId") != POLICY_SIGNING_KEY_ARN
        or result.get("KeyUsage") != "SIGN_VERIFY"
        or result.get("KeySpec", result.get("CustomerMasterKeySpec"))
        != "ECC_NIST_P256"
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


def _create_governed_policy(tenant, body, actor):
    """Atomically create a policy shell and its first inactive draft."""
    policy_id = _bounded_identifier(body.get("policyId"), "policyId")
    name = _bounded_text(body.get("name"), "name")
    configuration = _policy_configuration(tenant, body.get("configuration", {}))
    organization_id = _policy_organization(tenant, body)
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
    configuration = _policy_configuration(tenant, body.get("configuration", {}))
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
    now = int(time.time())
    effective_configuration = _managed_policy_configuration(tenant, candidate["configuration"])
    bundle = _sign_policy_bundle(
        tenant, policy_id, version, effective_configuration, now
    )
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


def _put(tenant, kind, identifier, item):
    record = {**_item_key(tenant, kind, identifier), **item, "tenant_id": tenant}
    TABLE.put_item(Item=record)
    return record


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
    S3.put_object(
        Bucket=os.environ["AUDIT_BUCKET"],
        Key=key,
        Body=json.dumps(redacted).encode(),
        ContentType="application/json",
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
    return {
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
    if not isinstance(body, dict) or (
        supplied_fields != required_fields and supplied_fields != required_fields | {"actionDigest"}
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
            "policy_id": policy["id"],
            "policy_version": int(policy.get("version", 0)),
        },
    )
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
    if TABLE.get_item(Key=_item_key(tenant, "TENANT", "root"), ConsistentRead=True).get("Item"):
        return
    if TABLE.get_item(Key=_item_key(tenant, "ORG", "org-demo")).get("Item"):
        now = int(time.time())
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
    """Project a content-minimised endpoint alert for operator APIs."""
    return {
        "id": item.get("id"),
        "source": "endpoint_evidence",
        "severity": item.get("severity"),
        "type": item.get("type"),
        "deviceId": item.get("deviceId"),
        "deploymentId": "",
        "message": item.get("message"),
        "reasonCode": item.get("reasonCode"),
        "status": item.get("status"),
        "acknowledged": item.get("status") in {"acknowledged", "resolved"},
        "revision": int(item.get("revision", 0)),
        "firstObservedAt": int(item.get("firstObservedAt", 0)),
        "lastObservedAt": int(item.get("lastObservedAt", 0)),
        "occurrenceCount": int(item.get("occurrenceCount", 0)),
        "acknowledgedAt": item.get("acknowledgedAt"),
        "acknowledgedBy": item.get("acknowledgedBy"),
        "acknowledgementReason": item.get("acknowledgementReason"),
        "resolvedAt": item.get("resolvedAt"),
        "caseId": item.get("caseId"),
        "deliveryStatus": item.get("deliveryStatus", "pending"),
        "deliveredAt": item.get("deliveredAt"),
    }


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
        Subject=f"AAI endpoint alert: {alert['type']}",
        Message=json.dumps(
            {
                "schemaVersion": 1,
                "tenantId": tenant,
                "alertId": alert["id"],
                "revision": int(alert["revision"]),
                "source": "endpoint_evidence",
                "severity": alert["severity"],
                "type": alert["type"],
                "deviceId": alert["deviceId"],
                "reasonCode": alert["reasonCode"],
                "observedAt": int(alert["lastObservedAt"]),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        MessageAttributes={
            "tenantId": {"DataType": "String", "StringValue": tenant},
            "severity": {"DataType": "String", "StringValue": alert["severity"]},
            "source": {"DataType": "String", "StringValue": "endpoint_evidence"},
        },
    )
    return True


def _deliver_pending_endpoint_alerts(tenant):
    """Retry undelivered active alerts without losing their durable record."""
    for alert in _list(tenant, "ALERT", consistent_read=True):
        if (
            alert.get("source") != "endpoint_evidence"
            or alert.get("status") == "resolved"
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
            print(json.dumps({"warning": "endpoint alert delivery remains pending"}))


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
        "deliveryStatus": "pending",
        "reopenedAt": now if existing else None,
    }
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
        "endpoint_alert_opened" if not existing else "endpoint_alert_reopened",
        "system:endpoint-detection",
        {
            "alert_id": alert_id,
            "device_id": device_id,
            "reason_code": reason_code,
            "severity": severity,
            "revision": revision + 1,
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
    if not alert or alert.get("source") != "endpoint_evidence":
        raise LookupError("endpoint alert not found")
    if int(alert.get("revision", 0)) != expected:
        raise PolicyConflict("endpoint alert revision changed")
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
            raise PolicyConflict("endpoint alert revision changed") from error
        raise
    _audit(
        tenant,
        "endpoint_alert_acknowledged",
        actor,
        {"alert_id": alert_id, "device_id": alert.get("deviceId"), "revision": expected + 1},
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
    """Project one case without endpoint payloads, project roots or credentials."""
    binding = _json(case.get("binding", {}))
    current_binding = _endpoint_agent_binding(tenant, case.get("deviceId", ""))
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
    if not alert or alert.get("source") != "endpoint_evidence":
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
    """Validate and normalize the closed automatic-response rule language."""
    if not isinstance(value, dict) or set(value) != {
        "match",
        "action",
        "safeguards",
        "priority",
    }:
        raise ValueError("response rule configuration has an invalid schema")
    match = value.get("match")
    action = value.get("action")
    safeguards = value.get("safeguards")
    if not isinstance(match, dict) or set(match) != {
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


def _response_rule_preview(tenant, configuration):
    """Preview current alerts without creating cases or response authority."""
    normalized = _response_rule_configuration(configuration)
    alerts = [
        item
        for item in _list(tenant, "ALERT", consistent_read=True)
        if item.get("source") == "endpoint_evidence" and item.get("status") != "resolved"
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
        if item.get("enabled") is True and int(item.get("active_version", 0)) > 0
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
        if item.get("source") == "endpoint_evidence" and item.get("status") != "resolved"
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
    """Create one deterministic case from a live endpoint alert."""
    if not isinstance(body, dict) or set(body) != {"alertId", "expectedAlertRevision", "reason"}:
        raise ValueError("case creation request has an invalid schema")
    alert_id = _bounded_identifier(body.get("alertId"), "alertId")
    expected = _discovery_integer(
        body.get("expectedAlertRevision"), "expectedAlertRevision", minimum=1
    )
    reason = _case_reason(body.get("reason"))
    alert_key = _item_key(tenant, "ALERT", alert_id)
    alert = TABLE.get_item(Key=alert_key, ConsistentRead=True).get("Item")
    if not alert or alert.get("source") != "endpoint_evidence":
        raise LookupError("endpoint alert not found")
    if int(alert.get("revision", 0)) != expected:
        raise PolicyConflict("endpoint alert revision changed")
    if alert.get("status") == "resolved":
        raise PolicyConflict("a resolved endpoint alert cannot open a case")
    case_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"aai-case:{tenant}:{alert_id}"))
    now = int(time.time())
    binding = _endpoint_agent_binding(tenant, alert.get("deviceId", ""), now=now)
    case = {
        **_item_key(tenant, "CASE", case_id),
        "tenant_id": tenant,
        "id": case_id,
        "alertId": alert_id,
        "title": alert.get("message"),
        "severity": alert.get("severity"),
        "reasonCode": alert.get("reasonCode"),
        "deviceId": alert.get("deviceId"),
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
    binding = _endpoint_agent_binding(tenant, case.get("deviceId", ""))
    stored_binding = case.get("binding", {})
    if (
        binding.get("status") != "bound"
        or stored_binding.get("status") != "bound"
        or not secrets.compare_digest(str(binding.get("bindingDigest", "")), expected_binding)
        or not secrets.compare_digest(
            str(stored_binding.get("bindingDigest", "")), expected_binding
        )
    ):
        raise PolicyConflict("endpoint-to-agent binding is unavailable, ambiguous, or changed")
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
    binding = _endpoint_agent_binding(tenant, case.get("deviceId", ""))
    if binding.get("status") != "bound" or not secrets.compare_digest(
        str(binding.get("bindingDigest", "")), str(containment.get("bindingDigest", ""))
    ):
        raise PolicyConflict("endpoint-to-agent binding is not current")
    health = _endpoint_evidence_health(tenant)
    device = next(
        (item for item in health.get("items", []) if item.get("deviceId") == case.get("deviceId")),
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
    if alert.get("reasonCode") in _ENDPOINT_EVENT_REASONS:
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
    binding = _endpoint_agent_binding(tenant, case.get("deviceId", ""))
    stored = case.get("binding", {})
    if binding.get("status") != "bound" or not secrets.compare_digest(
        str(binding.get("bindingDigest", "")), str(stored.get("bindingDigest", ""))
    ):
        raise PolicyConflict("endpoint-to-agent binding is unavailable or changed")
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
        if alert.get("reasonCode") in _ENDPOINT_EVENT_REASONS:
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


def _fleet(tenant):
    agents = _all_agents(tenant)
    groups = []
    for group in _list(tenant, "GROUP"):
        group["emergencyStop"] = bool(
            group.get("emergencyStop") is True
            or _scope_emergency_stop(tenant, "group", group.get("id", ""))
        )
        group["membershipRevision"] = _group_membership_revision(group)
        group["membershipMode"] = _group_membership_mode(group)
        group["dynamicRule"] = group.get("dynamic_rule")
        group["dynamicRuleHash"] = group.get("dynamic_rule_hash")
        group["dynamicLastEvaluatedAt"] = group.get("dynamic_last_evaluated_at")
        group["dynamicLastEvaluatedBy"] = group.get("dynamic_last_evaluated_by")
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
    return {
        "organizations": _list(tenant, "ORG"),
        "projects": _list(tenant, "PROJECT"),
        "deployments": _list(tenant, "DEPLOYMENT"),
        "agents": agents,
        "sessions": [],
        "drift": [item for item in _list(tenant, "CONFIGURATION") if item.get("drifted")],
        "templates": _list(tenant, "TEMPLATE"),
        "policies": policies,
        "groups": groups,
        "skills": _list(tenant, "SKILL"),
        "mcpServers": _list(tenant, "MCP"),
        "configurations": _list(tenant, "CONFIGURATION"),
        "configurationHistory": [],
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
    # Scheduled reconciliation is an internal invocation contract. Let its
    # failures escape Lambda so EventBridge performs bounded retries and moves
    # exhausted events to the monitored DLQ; an HTTP-shaped 500 would look like
    # a successful invocation to EventBridge and silently disable that safety.
    if isinstance(event, dict) and event.get("source") == "aai.endpoint-detection":
        if set(event) != {"source", "schemaVersion"} or event.get("schemaVersion") != 1:
            raise ValueError("endpoint detection schedule event is invalid")
        return _endpoint_detection_cycle()
    try:
        method, path = _method_path(event)
        if method == "OPTIONS":
            return _response(204, {})
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
                return _response(
                    200,
                    {
                        "agentId": agent_id,
                        "deploymentId": deployment_id,
                        "groupId": group["id"],
                        "policyBundle": _active_policy_bundle(tenant, policy),
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
                    "groups",
                    "skills",
                    "mcp-servers",
                    "templates",
                    "sessions",
                    "drift",
                    "health",
                    "slo",
                    "alerts",
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
                    "groups": "GROUP",
                    "skills": "SKILL",
                    "mcp-servers": "MCP",
                    "templates": "TEMPLATE",
                    "sessions": "SESSION",
                    "drift": "DRIFT",
                    "health": "HEALTH",
                    "slo": "SLO",
                    "alerts": "ALERT",
                    "cases": "CASE",
                    "response-rules": "RESPONSE_RULE",
                    "response-executions": "RESPONSE_EXECUTION",
                    "audit": "AUDIT",
                    "approvals": "APPROVAL",
                }[parts[0]]
                if parts[0] == "alerts":
                    _reconcile_endpoint_alerts(tenant, _endpoint_evidence_health(tenant))
                    items = [
                        _endpoint_alert_view(item)
                        for item in _list(tenant, "ALERT", consistent_read=True)
                        if item.get("source") == "endpoint_evidence"
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
            if method == "GET" and parts == ["capabilities"]:
                return _response(200, _fleet(tenant)["capabilities"])
            if method == "GET" and parts in (["discovery"], ["discovery", "export"]):
                if not _operator_roles(event):
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
                if not _operator_roles(event) and (
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
                items = _filter_enterprise_items(
                    tenant, event, "CONFIGURATION", _list(tenant, "CONFIGURATION")
                )
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
                deployment_id = body.get("deploymentId")
                template_id = body.get("templateId")
                template = TABLE.get_item(Key=_item_key(tenant, "TEMPLATE", template_id or "")).get(
                    "Item"
                )
                if not isinstance(deployment_id, str) or not deployment_id or not template:
                    return _response(
                        400, {"error": "deploymentId and an existing templateId are required"}
                    )
                configuration = _json(template.get("configuration", {}))
                desired_hash = _configuration_hash(configuration)
                item = _put(
                    tenant,
                    "CONFIGURATION",
                    deployment_id,
                    {
                        "deploymentId": deployment_id,
                        "templateId": template_id,
                        "desiredConfiguration": configuration,
                        "desiredHash": desired_hash,
                        "appliedHash": None,
                        "drifted": True,
                        "rolloutState": "staged",
                        "rolloutPercentage": 0,
                        "version": 1,
                        "updatedAt": int(time.time()),
                    },
                )
                _audit(
                    tenant,
                    "deployment_configuration_staged",
                    actor,
                    {
                        "deployment_id": deployment_id,
                        "template_id": template_id,
                        "desired_hash": desired_hash,
                    },
                )
                return _response(201, item)
            if method == "POST" and parts == ["deployment-config", "batch-rollout"]:
                body = _body(event)
                state = body.get("state")
                percentage = body.get("percentage")
                deployment_ids = body.get("deploymentIds")
                if (
                    state not in {"staged", "canary", "active", "paused", "rollback"}
                    or not isinstance(percentage, (int, float))
                    or isinstance(percentage, bool)
                    or not 0 <= percentage <= 100
                    or not isinstance(deployment_ids, list)
                ):
                    raise ValueError("rollout state, percentage and deploymentIds are invalid")
                updated = []
                for deployment_id in deployment_ids[:200]:
                    item = TABLE.get_item(
                        Key=_item_key(tenant, "CONFIGURATION", deployment_id)
                    ).get("Item")
                    if not item:
                        continue
                    item.update(
                        {
                            "rolloutState": state,
                            "rolloutPercentage": percentage,
                            "updatedAt": int(time.time()),
                        }
                    )
                    if state == "active" and percentage == 100:
                        item.update({"appliedHash": item.get("desiredHash"), "drifted": False})
                    TABLE.put_item(Item=item)
                    updated.append(item)
                _audit(
                    tenant,
                    "deployment_configuration_rollout",
                    actor,
                    {
                        "deployment_ids": deployment_ids[:200],
                        "state": state,
                        "percentage": percentage,
                    },
                )
                return _response(200, {"items": updated})
            if method == "POST" and parts == ["deployment-config", "rollback"]:
                body = _body(event)
                item = TABLE.get_item(
                    Key=_item_key(tenant, "CONFIGURATION", body.get("deploymentId", ""))
                ).get("Item")
                if not item:
                    return _response(404, {"error": "deployment configuration not found"})
                item.update(
                    {
                        "rolloutState": "rollback",
                        "rolloutPercentage": 0,
                        "drifted": True,
                        "updatedAt": int(time.time()),
                    }
                )
                TABLE.put_item(Item=item)
                _audit(
                    tenant,
                    "deployment_configuration_rollback",
                    actor,
                    {"deployment_id": item["deploymentId"], "version": body.get("version")},
                )
                return _response(200, item)
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
                if not _operator_roles(event) and (
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
                if not _operator_roles(event) and (
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
                if action == "submit":
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
                organization_id = _policy_organization(tenant, body)
                content = body.get("content", "")
                if not isinstance(content, str) or not content or len(content) > 100000:
                    return _response(400, {"error": "valid bounded Skill content is required"})
                skill_id = body.get("skillId")
                digest = f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"
                item = _put(
                    tenant,
                    "SKILL",
                    skill_id,
                    {
                        "id": skill_id,
                        "organizationId": organization_id,
                        "name": body.get("name", skill_id),
                        "description": body.get("description", ""),
                        "version": body.get("version", "1.0.0"),
                        "content": content,
                        "digest": digest,
                        "enabled": body.get("enabled", True),
                        "createdAt": int(time.time()),
                        "author": actor,
                    },
                )
                _audit(tenant, "skill_created", actor, {"skill_id": skill_id, "digest": digest})
                return _response(201, item)
            if method == "POST" and parts == ["mcp-servers"]:
                body = _body(event)
                organization_id = _policy_organization(tenant, body)
                server_id = body.get("serverId")
                transport = body.get("transport")
                if (
                    not isinstance(server_id, str)
                    or not server_id
                    or transport not in {"stdio", "http"}
                ):
                    return _response(
                        400, {"error": "valid MCP serverId and transport are required"}
                    )
                if transport == "stdio" and not isinstance(body.get("command"), str):
                    return _response(400, {"error": "stdio MCP server command is required"})
                if transport == "http" and not isinstance(body.get("url"), str):
                    return _response(400, {"error": "HTTP MCP server URL is required"})
                item = _put(
                    tenant,
                    "MCP",
                    server_id,
                    {
                        "id": server_id,
                        "organizationId": organization_id,
                        "name": body.get("name", server_id),
                        "description": body.get("description", ""),
                        "version": body.get("version", "1.0.0"),
                        "transport": transport,
                        "command": body.get("command"),
                        "args": body.get("args", []),
                        "url": body.get("url"),
                        "environmentReferences": body.get("environmentReferences", []),
                        "enabled": body.get("enabled", True),
                        "createdAt": int(time.time()),
                        "author": actor,
                    },
                )
                _audit(tenant, "mcp_server_created", actor, {"server_id": server_id})
                return _response(201, item)
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
                try:
                    item = _create_item(
                        tenant,
                        "GROUP",
                        group_id,
                        {
                            "id": group_id,
                            "organizationId": policy.get("organization_id", ""),
                            "name": _bounded_text(body.get("name"), "name"),
                            "policyId": policy["id"],
                            "policyName": policy["name"],
                            "createdAt": int(time.time()),
                            "agent_keys": [],
                            "membership_revision": 1,
                            "membership_mode": "manual",
                        },
                    )
                except Exception as error:
                    if _is_conditional_conflict(error):
                        return _response(409, {"error": "group already exists"})
                    raise
                _audit(tenant, "group_created", actor, {"group_id": group_id})
                return _response(201, {**item, "membershipRevision": 1, "agents": []})
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
                return _response(
                    200,
                    {
                        "agentId": parts[2],
                        "deploymentId": parts[1],
                        "groupId": group["id"],
                        "policyBundle": _active_policy_bundle(tenant, policy),
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
