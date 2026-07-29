#!/usr/bin/env python3
"""Run a bounded live Microsoft Entra SCIM lifecycle acceptance test.

The command discovers the deployed endpoint from CloudFormation and resolves
the dedicated SCIM bearer from AWS Secrets Manager.  It never accepts the
bearer on the command line, prints it, or persists it.  All test identities use
new synthetic UUIDs; lifecycle records are removed on exit while the
content-minimised audit trail is deliberately retained as acceptance evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any


class EntraScimAcceptanceError(RuntimeError):
    """Raised when deployed Entra SCIM behavior fails an acceptance invariant."""


@dataclass(frozen=True)
class ScimResponse:
    """One secret-free HTTP result returned by the live SCIM endpoint."""

    status: int
    body: Mapping[str, Any]


Requester = Callable[
    [str, str, str, str, Mapping[str, Any] | None, Mapping[str, str] | None], ScimResponse
]


def stack_outputs(cloudformation: Any, stack_name: str) -> dict[str, str]:
    """Return exact string outputs for one deployed CloudFormation stack."""
    stacks = cloudformation.describe_stacks(StackName=stack_name).get("Stacks", [])
    if len(stacks) != 1:
        raise EntraScimAcceptanceError("expected exactly one deployed control-plane stack")
    outputs = stacks[0].get("Outputs", [])
    return {
        str(item["OutputKey"]): str(item["OutputValue"])
        for item in outputs
        if isinstance(item, Mapping) and "OutputKey" in item and "OutputValue" in item
    }


def require_configured_endpoint(outputs: Mapping[str, str]) -> str:
    """Return the HTTPS SCIM endpoint or fail when Entra is not fully configured."""
    if outputs.get("MicrosoftEntraIdStatus") != "configured":
        raise EntraScimAcceptanceError("Microsoft Entra ID is not configured in this stack")
    if outputs.get("MicrosoftEntraScimStatus") != "configured":
        raise EntraScimAcceptanceError("Microsoft Entra SCIM is not configured in this stack")
    endpoint = outputs.get("MicrosoftEntraScimEndpoint", "").rstrip("/")
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
        raise EntraScimAcceptanceError("deployed SCIM endpoint is not a bounded HTTPS URL")
    return endpoint


def resolve_scim_token(secrets_manager: Any, secret_name: str) -> str:
    """Resolve the dedicated bearer without exposing it through process arguments."""
    if not secret_name or len(secret_name) > 512:
        raise EntraScimAcceptanceError("a bounded SCIM token secret name is required")
    try:
        value = secrets_manager.get_secret_value(SecretId=secret_name).get("SecretString", "")
    except Exception as error:
        raise EntraScimAcceptanceError(
            "SCIM bearer cannot be resolved from Secrets Manager"
        ) from error
    if not isinstance(value, str):
        raise EntraScimAcceptanceError("SCIM bearer secret must contain text")
    resolved: object
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        resolved = value
    else:
        if not isinstance(decoded, dict) or set(decoded) != {"token"}:
            raise EntraScimAcceptanceError("SCIM bearer JSON must contain only the token field")
        resolved = decoded.get("token")
    if not isinstance(resolved, str) or not 32 <= len(resolved) <= 512:
        raise EntraScimAcceptanceError("SCIM bearer is outside the required length bound")
    return resolved


def _synthetic_identifiers() -> tuple[str, str, str]:
    """Return exact new UUIDs for one isolated lifecycle run."""
    return str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())


def request_scim(
    endpoint: str,
    path: str,
    method: str,
    token: str,
    body: Mapping[str, Any] | None = None,
    query: Mapping[str, str] | None = None,
) -> ScimResponse:
    """Call one HTTPS SCIM route with a fixed timeout and no credential reflection."""
    base = endpoint.rstrip("/")
    if urllib.parse.urlparse(base).scheme != "https":
        raise EntraScimAcceptanceError("SCIM acceptance requires HTTPS")
    suffix = "/" + path.lstrip("/")
    url = base + suffix
    if query:
        url += "?" + urllib.parse.urlencode(query)
    headers = {
        "accept": "application/scim+json",
        "authorization": f"Bearer {token}",
        "content-type": "application/scim+json",
    }
    request = urllib.request.Request(  # noqa: S310 - HTTPS is enforced above
        url,
        data=None if body is None else json.dumps(body).encode("utf-8"),
        headers=headers,
        method=method,
    )
    try:
        import certifi

        context = ssl.create_default_context(cafile=certifi.where())
        with urllib.request.urlopen(  # noqa: S310 - bounded HTTPS request
            request, timeout=15, context=context
        ) as response:
            encoded = response.read(1_000_001)
            status = response.status
    except urllib.error.HTTPError as error:
        encoded = error.read(1_000_001)
        status = error.code
    except (OSError, TimeoutError) as error:
        raise EntraScimAcceptanceError("SCIM endpoint is unavailable") from error
    if len(encoded) > 1_000_000:
        raise EntraScimAcceptanceError("SCIM response exceeds the safe bound")
    if not encoded:
        return ScimResponse(status=status, body={})
    try:
        decoded = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EntraScimAcceptanceError("SCIM endpoint returned malformed JSON") from error
    if not isinstance(decoded, dict):
        raise EntraScimAcceptanceError("SCIM endpoint returned a non-object response")
    return ScimResponse(status=status, body=decoded)


def _require(response: ScimResponse, expected: int, operation: str) -> Mapping[str, Any]:
    """Require one exact status without including raw response content in errors."""
    if response.status != expected:
        raise EntraScimAcceptanceError(
            f"{operation} returned HTTP {response.status}; expected HTTP {expected}"
        )
    return response.body


def run_lifecycle(
    endpoint: str,
    token: str,
    *,
    requester: Requester = request_scim,
    identifiers: tuple[str, str, str] | None = None,
) -> tuple[str, str, str]:
    """Prove authenticated joiner, mover and leaver behavior against live SCIM."""
    user_id, first_group, second_group = identifiers or _synthetic_identifiers()
    invalid_token = "invalid-scim-acceptance-" + uuid.uuid4().hex
    if invalid_token == token:
        raise EntraScimAcceptanceError("synthetic invalid bearer unexpectedly matched the secret")
    _require(
        requester(endpoint, "ServiceProviderConfig", "GET", invalid_token, None, None),
        401,
        "invalid bearer check",
    )
    provider = _require(
        requester(endpoint, "ServiceProviderConfig", "GET", token, None, None),
        200,
        "service-provider discovery",
    )
    if (
        provider.get("patch", {}).get("supported") is not True
        or provider.get("bulk", {}).get("supported") is not False
    ):
        raise EntraScimAcceptanceError(
            "SCIM capability document is not the approved bounded profile"
        )

    user_schema = "urn:ietf:params:scim:schemas:core:2.0:User"
    group_schema = "urn:ietf:params:scim:schemas:core:2.0:Group"
    patch_schema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
    user = {
        "schemas": [user_schema],
        "externalId": user_id,
        "userName": f"aai-scim-{user_id}@example.invalid",
        "displayName": "AAI synthetic lifecycle operator",
        "active": True,
    }
    _require(requester(endpoint, "Users", "POST", token, user, None), 201, "joiner creation")
    _require(
        requester(endpoint, "Users", "POST", token, user, None),
        409,
        "duplicate joiner rejection",
    )
    for group_id, name in (
        (first_group, "AAI synthetic policy authors"),
        (second_group, "AAI synthetic policy approvers"),
    ):
        _require(
            requester(
                endpoint,
                "Groups",
                "POST",
                token,
                {"schemas": [group_schema], "externalId": group_id, "displayName": name},
                None,
            ),
            201,
            "group creation",
        )

    def membership(group_id: str, operation: Mapping[str, Any]) -> ScimResponse:
        return requester(
            endpoint,
            f"Groups/{group_id}",
            "PATCH",
            token,
            {"schemas": [patch_schema], "Operations": [operation]},
            None,
        )

    add = {"op": "add", "path": "members", "value": [{"value": user_id}]}
    remove = {"op": "remove", "path": f'members[value eq "{user_id}"]'}
    _require(membership(first_group, add), 200, "joiner membership")
    first = _require(
        requester(endpoint, f"Groups/{first_group}", "GET", token, None, None),
        200,
        "joiner membership verification",
    )
    if [item.get("value") for item in first.get("members", [])] != [user_id]:
        raise EntraScimAcceptanceError("joiner membership was not applied exactly")

    _require(membership(first_group, remove), 200, "mover old-membership removal")
    _require(membership(second_group, add), 200, "mover new-membership addition")
    old_group = _require(
        requester(endpoint, f"Groups/{first_group}", "GET", token, None, None),
        200,
        "mover old-membership verification",
    )
    new_group = _require(
        requester(endpoint, f"Groups/{second_group}", "GET", token, None, None),
        200,
        "mover new-membership verification",
    )
    if old_group.get("members") != [] or [
        item.get("value") for item in new_group.get("members", [])
    ] != [user_id]:
        raise EntraScimAcceptanceError("mover membership state is not exact")

    found = _require(
        requester(
            endpoint,
            "Users",
            "GET",
            token,
            None,
            {"filter": f'externalId eq "{user_id}"'},
        ),
        200,
        "joiner inventory lookup",
    )
    if found.get("totalResults") != 1:
        raise EntraScimAcceptanceError("synthetic operator inventory is ambiguous")

    _require(
        requester(endpoint, f"Users/{user_id}", "DELETE", token, None, None),
        204,
        "leaver deactivation",
    )
    disabled = _require(
        requester(endpoint, f"Users/{user_id}", "GET", token, None, None),
        200,
        "leaver verification",
    )
    if disabled.get("active") is not False:
        raise EntraScimAcceptanceError("leaver remained active")
    _require(membership(first_group, add), 400, "inactive leaver membership rejection")
    return user_id, first_group, second_group


def cleanup_synthetic_records(table: Any, tenant: str, identifiers: tuple[str, str, str]) -> None:
    """Remove only exact synthetic lifecycle state; retained audits remain immutable evidence."""
    user_id, first_group, second_group = identifiers
    keys = [
        {"pk": f"TENANT#{tenant}", "sk": f"USER#{user_id}"},
        {"pk": f"TENANT#{tenant}", "sk": f"GROUP#{first_group}"},
        {"pk": f"TENANT#{tenant}", "sk": f"GROUP#{second_group}"},
    ]
    for group_id in (first_group, second_group):
        keys.extend(
            (
                {"pk": f"TENANT#{tenant}#USER#{user_id}", "sk": f"GROUP#{group_id}"},
                {"pk": f"TENANT#{tenant}#GROUP#{group_id}", "sk": f"USER#{user_id}"},
            )
        )
    for key in keys:
        table.delete_item(Key=key)


def run_lifecycle_with_cleanup(
    endpoint: str,
    token: str,
    table: Any,
    tenant: str,
    *,
    requester: Requester = request_scim,
    identifiers: tuple[str, str, str] | None = None,
) -> tuple[str, str, str]:
    """Run acceptance and clean exact synthetic state on success or failure."""
    selected = identifiers or _synthetic_identifiers()
    try:
        run_lifecycle(endpoint, token, requester=requester, identifiers=selected)
    finally:
        cleanup_synthetic_records(table, tenant, selected)
    return selected


def main() -> int:
    """Run preflight plus live lifecycle acceptance and return a shell status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stack-name", default="AaiSecControlPlane")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region", default=None)
    parser.add_argument(
        "--scim-token-secret-name",
        default=os.environ.get("ENTRA_SCIM_TOKEN_SECRET_NAME", ""),
        help="Secrets Manager name; the bearer itself is never accepted on the command line",
    )
    parser.add_argument(
        "--aai-tenant-id",
        default=os.environ.get("ENTRA_AAI_TENANT_ID", ""),
        help="AAI tenant bound to the deployed Entra enterprise application",
    )
    arguments = parser.parse_args()

    import boto3

    session = boto3.Session(profile_name=arguments.profile, region_name=arguments.region)
    outputs = stack_outputs(session.client("cloudformation"), arguments.stack_name)
    try:
        endpoint = require_configured_endpoint(outputs)
    except EntraScimAcceptanceError as error:
        print(f"Entra SCIM acceptance NOT READY: {error}", file=sys.stderr)
        return 2
    if not arguments.aai_tenant_id or len(arguments.aai_tenant_id) > 128:
        print(
            "Entra SCIM acceptance NOT READY: a bounded --aai-tenant-id is required",
            file=sys.stderr,
        )
        return 2
    token = resolve_scim_token(session.client("secretsmanager"), arguments.scim_token_secret_name)
    table_name = outputs.get("ScimLifecycleTableName", "")
    if not table_name:
        raise EntraScimAcceptanceError("SCIM lifecycle table output is missing")
    table = session.resource("dynamodb").Table(table_name)
    run_lifecycle_with_cleanup(endpoint, token, table, arguments.aai_tenant_id)
    print(
        "Entra SCIM acceptance passed: bearer rejection, bounded discovery, joiner, "
        "duplicate rejection, mover, leaver, inactive-user denial, and exact state cleanup. "
        "Content-minimised lifecycle audit records were retained."
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except EntraScimAcceptanceError as error:
        print(f"Entra SCIM acceptance FAILED: {error}", file=sys.stderr)
        sys.exit(1)
