"""Bind Microsoft Entra authentication to SCIM lifecycle and canonical roles.

The trigger identifies federation from Cognito's server-owned ``identities``
attribute. When SCIM is enabled, an Entra login fails closed unless the exact
OIDC object ID is active in the deployment-owned lifecycle table and belongs
to at least one group mapped to a canonical operator role.
"""

import hashlib
import json
import os
import uuid

_CANONICAL_ROLES = frozenset(
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


def _is_configured_entra_identity(attributes):
    """Return true only for an exact configured Cognito federation identity."""
    provider_name = os.environ.get("ENTRA_PROVIDER_NAME", "")
    raw_identities = attributes.get("identities", "") if isinstance(attributes, dict) else ""
    if not provider_name or not isinstance(raw_identities, str) or len(raw_identities) > 8192:
        return False
    try:
        identities = json.loads(raw_identities)
    except json.JSONDecodeError:
        return False
    return isinstance(identities, list) and any(
        isinstance(identity, dict)
        and identity.get("providerName") == provider_name
        and identity.get("providerType") == "OIDC"
        for identity in identities
    )


def _entra_object_id(attributes):
    """Return the OIDC-signed Entra object ID in canonical UUID form."""
    value = attributes.get("custom:entra_object_id") if isinstance(attributes, dict) else None
    if not isinstance(value, str) or len(value) > 64:
        raise PermissionError("Entra object identity is missing")
    try:
        return str(uuid.UUID(value))
    except ValueError as error:
        raise PermissionError("Entra object identity is malformed") from error


def _scim_roles(attributes):
    """Resolve active role mappings from exact tenant/user membership records."""
    table_name = os.environ.get("SCIM_TABLE", "")
    tenant = os.environ.get("SCIM_AAI_TENANT_ID", "")
    if not table_name or not tenant:
        raise PermissionError("SCIM lifecycle authority is unavailable")
    # AWS includes boto3 in the Lambda runtime. Import it only at the SCIM
    # boundary so OIDC-only deployments and minimal contract environments do
    # not acquire an unnecessary AWS dependency. A missing runtime library on
    # the SCIM path is an authority failure, never a reason to issue a token.
    try:
        import boto3
        from boto3.dynamodb.conditions import Key
    except ModuleNotFoundError as error:
        raise PermissionError("SCIM lifecycle authority is unavailable") from error
    table = boto3.resource("dynamodb").Table(table_name)
    user_id = _entra_object_id(attributes)
    user = table.get_item(
        Key={"pk": f"TENANT#{tenant}", "sk": f"USER#{user_id}"},
        ConsistentRead=True,
    ).get("Item")
    if not user or user.get("active") is not True:
        raise PermissionError("Entra operator is not actively provisioned")
    result = table.query(
        KeyConditionExpression=Key("pk").eq(f"TENANT#{tenant}#USER#{user_id}")
        & Key("sk").begins_with("GROUP#"),
        Limit=33,
        ConsistentRead=True,
    )
    memberships = result.get("Items", [])
    if result.get("LastEvaluatedKey") or len(memberships) > 32:
        raise PermissionError("Entra operator group membership exceeds the safe bound")
    roles = set()
    revisions = [f"user:{user.get('version', 0)}"]
    for membership in memberships:
        group_id = str(membership.get("sk", "")).removeprefix("GROUP#")
        if not group_id:
            continue
        group = table.get_item(
            Key={"pk": f"TENANT#{tenant}", "sk": f"GROUP#{group_id}"},
            ConsistentRead=True,
        ).get("Item")
        role = group.get("mapped_role") if group else None
        if group and group.get("active") is True and role in _CANONICAL_ROLES:
            roles.add(role)
            revisions.append(f"{group_id}:{group.get('version', 0)}:{role}")
    if not roles:
        raise PermissionError("Entra operator has no mapped product role")
    revision = hashlib.sha256("|".join(sorted(revisions)).encode()).hexdigest()
    return sorted(roles), revision


def handler(event, _context):
    """Enforce lifecycle state and annotate one Entra-issued operator session."""
    attributes = event.get("request", {}).get("userAttributes", {})
    if not _is_configured_entra_identity(attributes):
        return event
    tenant_id = os.environ.get("ENTRA_TENANT_ID", "")
    if not tenant_id:
        raise ValueError("configured Entra tenant identity is required")
    response = event.setdefault("response", {})
    overrides = response.setdefault("claimsAndScopeOverrideDetails", {})
    provenance = {
        "aai:identity_provider": "microsoft_entra_id",
        "aai:entra_tenant_id": tenant_id,
    }
    if os.environ.get("ENTRA_STRONG_AUTH_ENFORCED") == "true":
        # This assertion is deployment-owned: it is enabled only after the
        # exact Entra enterprise application is bound to an MFA-enforcing
        # Conditional Access policy and that policy passes live acceptance.
        # No mutable user attribute or browser value can create this claim.
        provenance["aai:strong_auth_enforced"] = "true"
    roles = None
    if os.environ.get("SCIM_ENABLED") == "true":
        roles, revision = _scim_roles(attributes)
        provenance.update(
            {
                "aai:scim_enforced": "true",
                "aai:scim_revision": revision,
            }
        )
    for token_name in ("idTokenGeneration", "accessTokenGeneration"):
        token = overrides.setdefault(token_name, {})
        claims = token.setdefault("claimsToAddOrOverride", {})
        claims.update(provenance)
    if roles is not None:
        # Cognito documents this V2 override as the authoritative replacement
        # for cognito:groups in both access and ID tokens.
        overrides["groupOverrideDetails"] = {"groupsToOverride": roles}
    return event
