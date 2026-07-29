"""Add non-authoritative Microsoft Entra provenance to Cognito tokens.

The trigger identifies a federated profile from Cognito's server-owned
``identities`` attribute. It never accepts provider or tenant identity from a
browser request. Application tenant and operator roles remain server-owned
control-plane entitlements and are resolved independently by the API.
"""

import json
import os


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


def handler(event, _context):
    """Annotate Entra-issued sessions for downstream server-side reconciliation."""
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
    for token_name in ("idTokenGeneration", "accessTokenGeneration"):
        token = overrides.setdefault(token_name, {})
        claims = token.setdefault("claimsToAddOrOverride", {})
        claims.update(provenance)
    return event
