"""Minimal AWS control-plane adapter used by the hosted enterprise UI.

The Lambda is deliberately small: DynamoDB owns tenant-scoped desired state,
while S3 receives redacted lifecycle evidence. No request body is trusted for
tenant identity; the tenant is derived from the verified Cognito claims.
"""

import base64
import hashlib
import json
import math
import os
import re
import secrets
import time
import uuid
from decimal import Decimal
from pathlib import Path

import boto3
from boto3.dynamodb.conditions import Key

CONTROL_TABLE_NAME = os.environ["CONTROL_TABLE"]
TABLE = boto3.resource("dynamodb").Table(CONTROL_TABLE_NAME)
PRESENCE = boto3.resource("dynamodb").Table(os.environ["PRESENCE_TABLE"])
IDEMPOTENCY = boto3.resource("dynamodb").Table(os.environ["IDEMPOTENCY_TABLE"])
SCIM_TABLE_NAME = os.environ.get("SCIM_TABLE", "")
SCIM = boto3.resource("dynamodb").Table(SCIM_TABLE_NAME) if SCIM_TABLE_NAME else None
DYNAMODB = boto3.client("dynamodb")
S3 = boto3.client("s3")

# Tenant list reads are deliberately finite. Callers that require complete
# security state fail closed once either bound is reached; they never authorize
# from a silently truncated result or let one request drain an unbounded table.
_LIST_PAGE_ITEM_LIMIT = 250
_MAX_LIST_PAGES = 8
_MAX_LIST_ITEMS = 2_000
_DECISION_WINDOW_LIMIT = 250
_DECISION_TIMELINE_INDEX = "DecisionTimeline"
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

# Ownership is operational authority metadata, not a browser label. New
# identities must carry a reviewed accountable owner and all reviews expire on
# a fixed bounded cadence so abandoned agents cannot remain silently trusted.
_AGENT_CRITICALITIES = frozenset({"low", "medium", "high", "critical"})
_AGENT_OWNERSHIP_REVIEW_SECONDS = 90 * 24 * 60 * 60

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
    "security-operator": frozenset({"approval_decision", "incident_response"}),
    "policy-author": frozenset({"policy_write"}),
    "policy-approver": frozenset({"approval_decision", "policy_approval"}),
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
    if normalized.startswith("/enterprise/approvals/"):
        return "approval_decision"
    if normalized.startswith("/enterprise/identity/scim"):
        return "identity_admin"
    if normalized.startswith("/enterprise/identity/delegated-grants"):
        return "identity_admin"
    if re.fullmatch(
        r"/enterprise/policies/[^/]+/versions/[1-9][0-9]*/(decision|stage|activate)",
        normalized,
    ):
        return "policy_approval"
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
    if _fleet_emergency_stop_active(tenant) or agent.get("emergencyStop") is True:
        raise ManagedPackageConflict("emergency stop blocks managed package retrieval")
    agent_key = f"{deployment_id}:{agent_id}"
    groups = [
        group for group in _fleet(tenant)["groups"] if agent_key in group.get("agent_keys", [])
    ]
    if any(group.get("emergencyStop") is True for group in groups):
        raise ManagedPackageConflict("emergency stop blocks managed package retrieval")
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
    return migrated


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
    changed_sections = sorted(
        key
        for key in set(configuration) | set(base_configuration)
        if configuration.get(key) != base_configuration.get(key)
    )
    approved_by = (
        record.get("decided_by")
        if record.get("decision") == "approved"
        and record.get("state") in {"approved", "staged", "active"}
        else None
    )
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
        "changeSummary": {"changedSections": changed_sections},
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
    active_candidate = {
        **candidate,
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


def _set_fleet_emergency_stop(tenant, active, actor):
    """Persist a reversible fleet stop and return the authoritative state."""
    return _put(
        tenant,
        "CONTROL",
        "fleet-emergency-stop",
        {
            "id": "fleet-emergency-stop",
            "active": bool(active),
            "updatedAt": int(time.time()),
            "updatedBy": actor,
        },
    )


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


def _all_agents(tenant):
    agents = _list(tenant, "AGENT")
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


def _fleet(tenant):
    agents = _all_agents(tenant)
    groups = []
    for group in _list(tenant, "GROUP"):
        group["membershipRevision"] = _group_membership_revision(group)
        group["agents"] = [
            a for a in agents if f"{a['deployment_id']}:{a['id']}" in group.get("agent_keys", [])
        ]
        groups.append(group)
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
                    a.get("emergencyStop") for a in agents if a["deployment_id"] == d["id"]
                ),
                "status": "healthy",
            }
            for d in _list(tenant, "DEPLOYMENT")
        ],
        "slo": [],
        "alerts": [],
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
    fleet_stopped = _fleet_emergency_stop_active(tenant)
    agent_stopped = bool(agent and agent.get("emergencyStop", False))
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
            "passed": bool(agent and not fleet_stopped and not agent_stopped),
            "detail": "No emergency stop is active."
            if agent and not fleet_stopped and not agent_stopped
            else (
                "A fleet-wide emergency stop is active."
                if fleet_stopped
                else (
                    "An agent, group, or deployment emergency stop is active "
                    "or the agent is missing."
                )
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
            "issued_at": now,
            "expires_at": session_expires,
            "ttl": session_expires,
        }
    )
    # Exchanging a bootstrap proves possession of enrollment material, not
    # that the runtime process is alive. Only the authenticated agent
    # heartbeat route may transition presence to connected.
    agent.update({"status": "offline", "last_heartbeat": 0, "expires_at": 0})
    TABLE.put_item(Item=agent)
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
            "issued_at": now,
            "expires_at": refreshed_expires,
            "ttl": refreshed_expires,
        }
    )
    TABLE.delete_item(Key={"pk": _token_key("AGENT_SESSION", current_token), "sk": "SESSION"})
    return {"status": "connected", "accessToken": refreshed_token, "expiresAt": refreshed_expires}


def handler(event, context):
    """Route one API Gateway request through agent or operator trust boundaries."""
    try:
        method, path = _method_path(event)
        if method == "OPTIONS":
            return _response(204, {})
        if path in ("/agent/enroll", "/api/agent/enroll"):
            if method != "POST":
                return _response(405, {"error": "method not allowed"})
            return _response(201, _enroll_agent(event))
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
                    TABLE.put_item(
                        Item=item,
                        ConditionExpression=(
                            "lifecycle_state = :active AND lifecycle_revision = :revision"
                        ),
                        ExpressionAttributeValues={
                            ":active": "active",
                            ":revision": int(item["lifecycle_revision"]),
                        },
                    )
                except Exception as error:
                    if _is_conditional_conflict(error):
                        raise PermissionError(
                            "agent identity changed while heartbeat was processed"
                        ) from error
                    raise
                return _response(
                    200, {**item, **_renew_agent_session(tenant, session, _bearer(event))}
                )
            governed_agent = TABLE.get_item(
                Key=_item_key(tenant, "AGENT", agent_key), ConsistentRead=True
            ).get("Item")
            if not governed_agent:
                return _response(404, {"error": "agent not found"})
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
                if _fleet_emergency_stop_active(tenant):
                    return _response(
                        409,
                        {
                            "error": "fleet-wide emergency stop is active",
                            "emergencyStop": True,
                            "scope": "fleet",
                        },
                    )
                if agent.get("emergencyStop") is True:
                    return _response(
                        409,
                        {
                            "error": "agent emergency stop is active",
                            "emergencyStop": True,
                            "scope": "agent",
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
                        "agentId": agent_id,
                        "deploymentId": deployment_id,
                        "groupId": group["id"],
                        "policyId": policy["id"],
                        "version": policy["version"],
                        "configuration": _managed_policy_configuration(
                            tenant, policy["configuration"]
                        ),
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
                include_break_glass=not is_break_glass_governance,
                resource_scope=_mutation_resource_scope(tenant, event, path),
                include_delegated=not is_identity_governance,
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
                    "audit": "AUDIT",
                    "approvals": "APPROVAL",
                }[parts[0]]
                items = (
                    _fleet(tenant).get("mcpServers" if parts[0] == "mcp-servers" else parts[0], [])
                    if parts[0]
                    in {"groups", "agents", "health", "policies", "drift", "skills", "mcp-servers"}
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
                deployment_id = body.get("deploymentId")
                active = bool(body.get("active", True))
                agents = [
                    item
                    for item in _list(tenant, "AGENT")
                    if item.get("deployment_id") == deployment_id
                ]
                for item in agents:
                    item["emergencyStop"] = active
                    TABLE.put_item(Item=item)
                _audit(
                    tenant,
                    "deployment_emergency_stop",
                    actor,
                    {"deployment_id": deployment_id, "active": active, "agent_count": len(agents)},
                )
                return _response(
                    200,
                    {"deploymentId": deployment_id, "active": active, "agentCount": len(agents)},
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
                for key in group.get("agent_keys", []):
                    item = TABLE.get_item(Key=_item_key(tenant, "AGENT", key)).get("Item")
                    if item:
                        item["emergencyStop"] = active
                        TABLE.put_item(Item=item)
                _audit(
                    tenant, "group_emergency_stop", actor, {"group_id": parts[1], "active": active}
                )
                return _response(
                    200, {"id": parts[1], "active": active, "agents": group.get("agent_keys", [])}
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
                if _fleet_emergency_stop_active(tenant):
                    return _response(
                        409,
                        {
                            "error": "fleet-wide emergency stop is active",
                            "emergencyStop": True,
                            "scope": "fleet",
                        },
                    )
                if agent.get("emergencyStop") is True:
                    return _response(
                        409,
                        {
                            "error": "agent emergency stop is active",
                            "emergencyStop": True,
                            "scope": "agent",
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
                        "policyId": policy["id"],
                        "version": policy["version"],
                        "configuration": policy["configuration"],
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
                agent["emergencyStop"] = bool(_body(event).get("active", True))
                try:
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
                except Exception as error:
                    if _is_conditional_conflict(error):
                        raise PolicyConflict(
                            "agent lifecycle state changed concurrently"
                        ) from error
                    raise
                _audit(
                    tenant,
                    "agent_emergency_stop",
                    actor,
                    {
                        "deployment_id": parts[1],
                        "agent_id": parts[2],
                        "active": agent["emergencyStop"],
                    },
                )
                return _response(200, agent)
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
