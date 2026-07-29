"""Minimal AWS control-plane adapter used by the hosted enterprise UI.

The Lambda is deliberately small: DynamoDB owns tenant-scoped desired state,
while S3 receives redacted lifecycle evidence. No request body is trusted for
tenant identity; the tenant is derived from the verified Cognito claims.
"""

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

TABLE = boto3.resource("dynamodb").Table(os.environ["CONTROL_TABLE"])
PRESENCE = boto3.resource("dynamodb").Table(os.environ["PRESENCE_TABLE"])
IDEMPOTENCY = boto3.resource("dynamodb").Table(os.environ["IDEMPOTENCY_TABLE"])
SCIM_TABLE_NAME = os.environ.get("SCIM_TABLE", "")
SCIM = boto3.resource("dynamodb").Table(SCIM_TABLE_NAME) if SCIM_TABLE_NAME else None
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
    "auditor": frozenset(),
}


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
    agent = TABLE.get_item(
        Key=_item_key(session["tenant_id"], "AGENT", f"{parts[1]}:{parts[2]}"),
        ConsistentRead=True,
    ).get("Item")
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
    if normalized.startswith("/enterprise/policies"):
        return "policy_write"
    if normalized.startswith("/enterprise/skills") or normalized.startswith(
        "/enterprise/mcp-servers"
    ):
        return "policy_write"
    if normalized.startswith("/configuration"):
        return "runtime_admin"
    return "fleet_write"


def _operator_authorized(event, capability):
    """Authorize one explicit capability from canonical operator roles."""
    return any(
        "*" in _ROLE_CAPABILITIES[role] or capability in _ROLE_CAPABILITIES[role]
        for role in _operator_roles(event)
    )


def _mutation_authorized(event):
    """Retain the compatibility predicate while enforcing canonical roles.

    Cognito represents ``cognito:groups`` as an array in the JWT, while HTTP
    API authorizers expose claim values as strings. Depending on the gateway
    projection, that string may be one group, JSON array text, or bounded
    bracket/comma text. Normalize only exact group names; malformed values and
    lookalike substrings grant no authority.
    """
    return bool(_operator_roles(event))


def _scim_lifecycle(tenant):
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
    return {
        "status": "configured",
        "lifecycleEnforced": True,
        "users": {"total": len(users), "active": active, "disabled": len(users) - active},
        "groups": {"total": len(groups), "mapped": mapped, "unmapped": len(groups) - mapped},
        "groupMappings": mappings,
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
    scim = _scim_lifecycle(tenant)
    return {
        "provider": "microsoft_entra_id",
        "providerLabel": "Microsoft Entra ID",
        "protocol": "oidc",
        "status": "configured" if configured else "not_configured",
        "tenantHint": f"{entra_tenant[:8]}…" if configured else None,
        "tenantBinding": "server_owned",
        "roleSource": "cognito_managed_groups",
        "scimStatus": scim["status"],
        "scim": scim,
        "activeRoles": sorted(_operator_roles(event)),
        "roleMatrix": [
            {"role": role, "capabilities": sorted(capabilities)}
            for role, capabilities in _ROLE_CAPABILITIES.items()
        ],
    }


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
    except json.JSONDecodeError:
        raise ValueError("Malformed JSON")


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


def _key(kind, identifier):
    return {"pk": f"TENANT#{identifier}", "sk": f"{kind}#{identifier}"}


def _item_key(tenant, kind, identifier):
    return {"pk": f"TENANT#{tenant}", "sk": f"{kind}#{identifier}"}


def _configuration_hash(configuration):
    """Create a stable desired-state hash without storing configuration secrets."""
    encoded = json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


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
    key = f"tenant={tenant}/year={time.gmtime().tm_year}/month={time.gmtime().tm_mon:02d}/{int(time.time())}-{uuid.uuid4()}.json"
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
                    "content": "# Repository review\\nReview source changes and report findings.\\n",
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
    _put(
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
        },
    )
    _audit(tenant, "bootstrap_seeded", "system", {"deployment_id": "deployment-claude-local"})


def _all_agents(tenant):
    agents = _list(tenant, "AGENT")
    now = int(time.time())
    for agent in agents:
        if agent.get("expires_at", 0) < now and agent.get("status") != "offline":
            agent["status"] = "offline"
    return agents


def _fleet(tenant):
    agents = _all_agents(tenant)
    groups = []
    for group in _list(tenant, "GROUP"):
        group["agents"] = [
            a for a in agents if f"{a['deployment_id']}:{a['id']}" in group.get("agent_keys", [])
        ]
        groups.append(group)
    return {
        "organizations": _list(tenant, "ORG"),
        "projects": _list(tenant, "PROJECT"),
        "deployments": _list(tenant, "DEPLOYMENT"),
        "agents": agents,
        "sessions": [],
        "drift": [item for item in _list(tenant, "CONFIGURATION") if item.get("drifted")],
        "templates": _list(tenant, "TEMPLATE"),
        "policies": _list(tenant, "POLICY"),
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
            "activeSessionCount": len(agents),
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
    heartbeat_current = bool(
        agent
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
    return {
        "dashboard": {
            "generatedAt": now,
            "posture": "critical" if fleet_stopped else "healthy",
            "activeSessions": len(_all_agents(tenant)),
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
                for a in _all_agents(tenant)
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
    agent = TABLE.get_item(Key=_item_key(tenant, "AGENT", agent_key)).get("Item")
    if not agent:
        raise ValueError("agent must be registered before enrollment")
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
    if not agent or agent.get("project_root") != project_root:
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
                item.update(
                    {
                        "status": "connected",
                        "last_heartbeat": int(time.time()),
                        "expires_at": int(time.time()) + 300,
                    }
                )
                TABLE.put_item(Item=item)
                return _response(
                    200, {**item, **_renew_agent_session(tenant, session, _bearer(event))}
                )
            governed_agent = TABLE.get_item(
                Key=_item_key(tenant, "AGENT", agent_key), ConsistentRead=True
            ).get("Item")
            if not governed_agent:
                return _response(404, {"error": "agent not found"})
            _require_current_attestation(tenant, deployment_id, governed_agent)
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
                        UpdateExpression="SET #consumed = :true, #status = :consumed_status, consumed_at = :now",
                        ConditionExpression="attribute_exists(pk) AND #status = :approved_status AND #consumed = :false AND #expires_at > :now AND #agent_key = :agent AND #action_hash = :action_hash AND #tool_name = :tool_name AND #proposal_id = :proposal_id AND #task_id = :task_id AND #principal_id = :principal_id",
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
        actor = _claims(event).get("sub", "cognito-operator")
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            capability = _required_mutation_capability(path)
            if not _operator_authorized(event, capability):
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
            if method == "GET" and parts == ["compliance", "evidence"]:
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
            if method == "GET" and parts in (
                ["deployment-config"],
                ["deployment-config", "history"],
            ):
                return _response(200, {"items": _list(tenant, "CONFIGURATION"), "nextCursor": None})
            if method == "POST" and parts == ["templates"]:
                body = _body(event)
                template_id = body.get("templateId")
                configuration = body.get("configuration", {})
                if not isinstance(template_id, str) or not template_id:
                    raise ValueError("templateId is required")
                if not isinstance(configuration, dict):
                    raise ValueError("template configuration must be an object")
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
                method == "POST"
                and len(parts) == 3
                and parts[0] == "policies"
                and parts[2] == "versions"
            ):
                body = _body(event)
                policy = TABLE.get_item(Key=_item_key(tenant, "POLICY", parts[1])).get("Item")
                if not policy:
                    return _response(404, {"error": "policy not found"})
                policy.update(
                    {
                        "name": body["name"],
                        "configuration": body.get("configuration", {}),
                        "version": int(policy.get("version", 1)) + 1,
                        "updatedAt": int(time.time()),
                    }
                )
                TABLE.put_item(Item=policy)
                _audit(
                    tenant,
                    "policy_updated",
                    actor,
                    {"policy_id": parts[1], "version": policy["version"]},
                )
                return _response(200, policy)
            if method == "POST" and parts == ["skills"]:
                body = _body(event)
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
                        "organizationId": "org-demo",
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
                        "organizationId": "org-demo",
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
                body = _body(event)
                item = _put(
                    tenant,
                    "POLICY",
                    body["policyId"],
                    {
                        "id": body["policyId"],
                        "organization_id": "org-demo",
                        "name": body["name"],
                        "configuration": body.get("configuration", {}),
                        "version": 1,
                        "createdAt": int(time.time()),
                    },
                )
                _audit(tenant, "policy_created", actor, {"policy_id": body["policyId"]})
                return _response(201, item)
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
                        UpdateExpression="SET #status = :decision, decided_at = :now, decided_by = :actor, decision_reason = :reason, expires_at = :expires_at, #ttl = :ttl",
                        ConditionExpression="attribute_exists(pk) AND #status = :pending AND expires_at > :now",
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
                        },
                    )
                except Exception as error:
                    if _is_conditional_conflict(error):
                        return _response(409, {"error": "group already exists"})
                    raise
                _audit(tenant, "group_created", actor, {"group_id": group_id})
                return _response(201, {**item, "agents": []})
            if (
                method == "POST"
                and len(parts) == 3
                and parts[0] == "groups"
                and parts[2] == "policy"
            ):
                body = _body(event)
                group = TABLE.get_item(Key=_item_key(tenant, "GROUP", parts[1])).get("Item")
                policy = TABLE.get_item(
                    Key=_item_key(tenant, "POLICY", body.get("policyId", ""))
                ).get("Item")
                if not group or not policy:
                    return _response(404, {"error": "group or policy not found"})
                group.update({"policyId": policy["id"], "policyName": policy["name"]})
                TABLE.put_item(Item=group)
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
                and parts[2] == "agents"
            ):
                body = _body(event)
                group = TABLE.get_item(Key=_item_key(tenant, "GROUP", parts[1])).get("Item")
                key = f"{body['deploymentId']}:{body['agentId']}"
                if not group:
                    return _response(404, {"error": "group not found"})
                group["agent_keys"] = sorted(set(group.get("agent_keys", []) + [key]))
                TABLE.put_item(Item=group)
                _audit(
                    tenant,
                    "agent_added_to_group",
                    actor,
                    {"group_id": parts[1], "agent_id": body["agentId"]},
                )
                return _response(
                    200, next(g for g in _fleet(tenant)["groups"] if g["id"] == parts[1])
                )
            if (
                method == "DELETE"
                and len(parts) == 5
                and parts[0] == "groups"
                and parts[2] == "agents"
            ):
                group = TABLE.get_item(Key=_item_key(tenant, "GROUP", parts[1])).get("Item")
                key = f"{parts[3]}:{parts[4]}"
                if not group:
                    return _response(404, {"error": "group not found"})
                group["agent_keys"] = [item for item in group.get("agent_keys", []) if item != key]
                TABLE.put_item(Item=group)
                _audit(
                    tenant,
                    "agent_removed_from_group",
                    actor,
                    {"group_id": parts[1], "agent_id": parts[4]},
                )
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
                    existing_root = existing.get("project_root")
                    if existing_root:
                        if existing_root != project_root:
                            return _response(
                                409, {"error": "agent project scope is immutable after enrollment"}
                            )
                        return _response(200, existing)
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
                            return _response(200, current)
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
                    return _response(200, repaired)
                now = int(time.time())
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
                return _response(201, item)
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
                    Key=_item_key(tenant, "AGENT", f"{parts[1]}:{parts[2]}")
                ).get("Item")
                agent["emergencyStop"] = bool(_body(event).get("active", True))
                TABLE.put_item(Item=agent)
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
                return _response(200, _verify_agent(tenant, parts[1], parts[2]))
        return _response(404, {"error": "not found"})
    except ValueError as exc:
        return _response(400, {"error": str(exc)})
    except PermissionError as exc:
        return _response(403, {"error": str(exc)})
    except Exception as exc:
        print(json.dumps({"error": str(exc), "path": event.get("rawPath")}))
        return _response(500, {"error": "control plane unavailable"})
