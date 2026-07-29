"""Tenant-bound SCIM 2.0 service provider for Microsoft Entra provisioning.

This Lambda is a separate authentication boundary from the operator API.
Microsoft Entra presents a bearer stored in Secrets Manager; neither a request
body nor an OIDC claim chooses the AAI tenant. User deactivation and group
membership are durable inputs to the Cognito pre-token authorization trigger.
"""

import hmac
import json
import os
import re
import time
import uuid
from urllib.parse import unquote

import boto3
from boto3.dynamodb.conditions import Key

TABLE = boto3.resource("dynamodb").Table(os.environ["SCIM_TABLE"])
DDB = boto3.client("dynamodb")
SECRETS = boto3.client("secretsmanager")

_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
_TENANT = os.environ["SCIM_AAI_TENANT_ID"]
_SECRET_NAME = os.environ["SCIM_TOKEN_SECRET_NAME"]
_MAX_PAGE = 200
_MAX_OPERATIONS = 20
_TOKEN_CACHE: tuple[float, str] | None = None


def _response(status: int, body: dict | None = None, *, location: str | None = None) -> dict:
    """Return one no-store SCIM response without reflecting request headers."""
    headers = {
        "content-type": "application/scim+json",
        "cache-control": "no-store",
    }
    if location:
        headers["location"] = location
    return {
        "statusCode": status,
        "headers": headers,
        "body": "" if body is None else json.dumps(body, separators=(",", ":")),
    }


def _error(status: int, detail: str, scim_type: str | None = None) -> dict:
    """Return a bounded SCIM error that contains no credential or raw payload."""
    body = {"schemas": [_ERROR_SCHEMA], "status": str(status), "detail": detail[:512]}
    if scim_type:
        body["scimType"] = scim_type
    return _response(status, body)


def _bearer(event: dict) -> str:
    headers = {str(key).lower(): value for key, value in (event.get("headers") or {}).items()}
    value = headers.get("authorization", "")
    if not isinstance(value, str) or not value.lower().startswith("bearer "):
        return ""
    token = value[7:].strip()
    return token if 32 <= len(token) <= 512 else ""


def _configured_token() -> str:
    """Resolve the SCIM bearer briefly so Secrets Manager rotation converges."""
    global _TOKEN_CACHE
    now = time.monotonic()
    if _TOKEN_CACHE and _TOKEN_CACHE[0] > now:
        return _TOKEN_CACHE[1]
    value = SECRETS.get_secret_value(SecretId=_SECRET_NAME).get("SecretString", "")
    if not isinstance(value, str):
        raise PermissionError("SCIM credential is unavailable")
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        decoded = None
    token = decoded.get("token") if isinstance(decoded, dict) else value
    if not isinstance(token, str) or not 32 <= len(token) <= 512:
        raise PermissionError("SCIM credential is unavailable")
    _TOKEN_CACHE = (now + 300, token)
    return token


def _authorize(event: dict) -> None:
    supplied = _bearer(event)
    if not supplied or not hmac.compare_digest(supplied, _configured_token()):
        raise PermissionError("SCIM bearer is invalid")


def _body(event: dict) -> dict:
    try:
        value = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError as error:
        raise ValueError("malformed JSON") from error
    if not isinstance(value, dict):
        raise ValueError("SCIM body must be an object")
    return value


def _resource_id(value: object, field: str = "externalId") -> str:
    """Require the immutable Entra object identifier used for OIDC binding."""
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError(f"{field} must be an Entra object UUID")
    try:
        return str(uuid.UUID(value))
    except ValueError as error:
        raise ValueError(f"{field} must be an Entra object UUID") from error


def _text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{field} must be a non-empty string up to {maximum} characters")
    return value.strip()


def _tenant_key(kind: str, identifier: str) -> dict[str, str]:
    return {"pk": f"TENANT#{_TENANT}", "sk": f"{kind}#{identifier}"}


def _membership_keys(group_id: str, user_id: str) -> tuple[dict[str, str], dict[str, str]]:
    return (
        {"pk": f"TENANT#{_TENANT}#USER#{user_id}", "sk": f"GROUP#{group_id}"},
        {"pk": f"TENANT#{_TENANT}#GROUP#{group_id}", "sk": f"USER#{user_id}"},
    )


def _get(kind: str, identifier: str) -> dict | None:
    return TABLE.get_item(Key=_tenant_key(kind, identifier), ConsistentRead=True).get("Item")


def _query_partition(pk: str, prefix: str, limit: int = _MAX_PAGE) -> list[dict]:
    result = TABLE.query(
        KeyConditionExpression=Key("pk").eq(pk) & Key("sk").begins_with(prefix),
        Limit=limit + 1,
        ConsistentRead=True,
    )
    items = result.get("Items", [])
    if result.get("LastEvaluatedKey") or len(items) > limit:
        raise RuntimeError("SCIM result exceeds the bounded service limit")
    return items


def _members(group_id: str) -> list[str]:
    return [
        str(item["sk"]).removeprefix("USER#")
        for item in _query_partition(f"TENANT#{_TENANT}#GROUP#{group_id}", "USER#")
    ]


def _user_view(item: dict) -> dict:
    return {
        "schemas": [_USER_SCHEMA],
        "id": item["id"],
        "externalId": item["external_id"],
        "userName": item["user_name"],
        "displayName": item.get("display_name", item["user_name"]),
        "active": bool(item.get("active", False)),
        "meta": {
            "resourceType": "User",
            "created": item["created_at"],
            "lastModified": item["updated_at"],
            "version": f'W/"{item["version"]}"',
            "location": f"/scim/v2/Users/{item['id']}",
        },
    }


def _group_view(item: dict) -> dict:
    return {
        "schemas": [_GROUP_SCHEMA],
        "id": item["id"],
        "externalId": item["external_id"],
        "displayName": item["display_name"],
        "members": [
            {"value": member, "$ref": f"/scim/v2/Users/{member}"} for member in _members(item["id"])
        ],
        "meta": {
            "resourceType": "Group",
            "created": item["created_at"],
            "lastModified": item["updated_at"],
            "version": f'W/"{item["version"]}"',
            "location": f"/scim/v2/Groups/{item['id']}",
        },
    }


def _audit(event_type: str, resource_kind: str, resource_id: str) -> None:
    """Retain content-minimised provisioning evidence in the lifecycle table."""
    now = int(time.time())
    TABLE.put_item(
        Item={
            "pk": f"TENANT#{_TENANT}#AUDIT",
            "sk": f"{now:012d}#{uuid.uuid4()}",
            "event_type": event_type,
            "resource_kind": resource_kind,
            "resource_id": resource_id,
            "created_at": now,
        }
    )


def _filter_items(items: list[dict], query: dict, kind: str) -> list[dict]:
    raw = query.get("filter")
    if not raw:
        return items
    match = re.fullmatch(
        r'(userName|displayName|externalId|id)\s+eq\s+"([^"\\]{1,256})"', unquote(str(raw))
    )
    if not match:
        raise ValueError("unsupported SCIM filter")
    field, expected = match.groups()
    key = {
        "userName": "user_name",
        "displayName": "display_name",
        "externalId": "external_id",
        "id": "id",
    }[field]
    if kind == "USER" and field == "displayName":
        return [item for item in items if item.get(key, item.get("user_name")) == expected]
    return [item for item in items if item.get(key) == expected]


def _list_resources(kind: str, query: dict) -> dict:
    count = min(max(int(query.get("count", 100)), 1), _MAX_PAGE)
    start = max(int(query.get("startIndex", 1)), 1)
    items = _query_partition(f"TENANT#{_TENANT}", f"{kind}#")
    items = _filter_items(items, query, kind)
    selected = items[start - 1 : start - 1 + count]
    view = _user_view if kind == "USER" else _group_view
    return {
        "schemas": [_LIST_SCHEMA],
        "totalResults": len(items),
        "startIndex": start,
        "itemsPerPage": len(selected),
        "Resources": [view(item) for item in selected],
    }


def _create_user(body: dict) -> dict:
    if _USER_SCHEMA not in body.get("schemas", []):
        raise ValueError("core User schema is required")
    external_id = _resource_id(body.get("externalId"))
    user_name = _text(body.get("userName"), "userName")
    active = body.get("active", True)
    if not isinstance(active, bool):
        raise ValueError("active must be boolean")
    now = int(time.time())
    item = _tenant_key("USER", external_id) | {
        "id": external_id,
        "external_id": external_id,
        "user_name": user_name,
        "display_name": _text(body.get("displayName", user_name), "displayName"),
        "active": active,
        "version": 1,
        "created_at": now,
        "updated_at": now,
    }
    TABLE.put_item(Item=item, ConditionExpression="attribute_not_exists(pk)")
    _audit("user_created", "user", external_id)
    return _user_view(item)


def _create_group(body: dict) -> dict:
    if _GROUP_SCHEMA not in body.get("schemas", []):
        raise ValueError("core Group schema is required")
    external_id = _resource_id(body.get("externalId"))
    now = int(time.time())
    item = _tenant_key("GROUP", external_id) | {
        "id": external_id,
        "external_id": external_id,
        "display_name": _text(body.get("displayName"), "displayName"),
        "active": True,
        "mapped_role": "",
        "version": 1,
        "created_at": now,
        "updated_at": now,
    }
    TABLE.put_item(Item=item, ConditionExpression="attribute_not_exists(pk)")
    _audit("group_created", "group", external_id)
    return _group_view(item)


def _replace_user(item: dict, operations: list[dict]) -> dict:
    normalized: list[dict] = []
    for operation in operations:
        if str(operation.get("op", "")).lower() != "replace":
            raise ValueError("Users support only replace PATCH operations")
        path = str(operation.get("path", ""))
        value = operation.get("value")
        if not path and isinstance(value, dict):
            for field in ("active", "userName", "displayName"):
                if field in value:
                    normalized.append({"op": "replace", "path": field, "value": value[field]})
            continue
        normalized.append(operation)

    for operation in normalized:
        path = str(operation.get("path", ""))
        value = operation.get("value")
        if path.lower() == "active":
            if not isinstance(value, bool):
                raise ValueError("active must be boolean")
            item["active"] = value
        elif path.lower() == "username":
            item["user_name"] = _text(value, "userName")
        elif path.lower() == "displayname":
            item["display_name"] = _text(value, "displayName")
        else:
            raise ValueError("unsupported User PATCH path")
    item["version"] = int(item.get("version", 0)) + 1
    item["updated_at"] = int(time.time())
    TABLE.put_item(Item=item)
    _audit("user_updated", "user", item["id"])
    return item


def _member_values(value: object) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= _MAX_OPERATIONS:
        raise ValueError("members must contain between 1 and 20 users")
    if any(not isinstance(entry, dict) for entry in value):
        raise ValueError("every member must be an object")
    return [_resource_id(entry.get("value"), "member value") for entry in value]


def _write_membership(group_id: str, user_id: str, *, add: bool) -> None:
    user = _get("USER", user_id)
    if not user or not user.get("active"):
        raise ValueError("group member must reference an active provisioned user")
    user_key, group_key = _membership_keys(group_id, user_id)
    if add:
        requests = [
            {
                "Put": {
                    "TableName": os.environ["SCIM_TABLE"],
                    "Item": {key: {"S": value} for key, value in item.items()},
                }
            }
            for item in (user_key | {"group_id": group_id}, group_key | {"user_id": user_id})
        ]
    else:
        requests = [
            {
                "Delete": {
                    "TableName": os.environ["SCIM_TABLE"],
                    "Key": {key: {"S": value} for key, value in item.items()},
                }
            }
            for item in (user_key, group_key)
        ]
    DDB.transact_write_items(TransactItems=requests)


def _patch_group(item: dict, operations: list[dict]) -> dict:
    for operation in operations:
        op = str(operation.get("op", "")).lower()
        path = str(operation.get("path", ""))
        value = operation.get("value")
        if op == "replace" and path.lower() == "displayname":
            item["display_name"] = _text(value, "displayName")
        elif op == "add" and path.lower() == "members":
            for user_id in _member_values(value):
                _write_membership(item["id"], user_id, add=True)
        elif op == "remove":
            match = re.fullmatch(r'members\[value eq "([0-9a-fA-F-]{36})"\]', path)
            ids = [_resource_id(match.group(1), "member value")] if match else _member_values(value)
            for user_id in ids:
                _write_membership(item["id"], user_id, add=False)
        else:
            raise ValueError("unsupported Group PATCH operation")
    item["version"] = int(item.get("version", 0)) + 1
    item["updated_at"] = int(time.time())
    TABLE.put_item(Item=item)
    _audit("group_updated", "group", item["id"])
    return item


def _service_provider_config() -> dict:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": _MAX_PAGE},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": True},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "Bearer token",
                "description": "Tenant-specific token stored in AWS Secrets Manager",
                "specUri": "https://www.rfc-editor.org/info/rfc6750",
                "primary": True,
            }
        ],
    }


def handler(event: dict, context: object) -> dict:
    """Authenticate Entra and execute one bounded SCIM lifecycle operation."""
    del context
    try:
        _authorize(event)
        method = event.get("requestContext", {}).get("http", {}).get("method", "GET").upper()
        raw_path = event.get("rawPath", "/")
        path = raw_path.split("/scim/v2", 1)[-1].rstrip("/") or "/"
        query = event.get("queryStringParameters") or {}
        if method == "GET" and path.lower() == "/serviceproviderconfig":
            return _response(200, _service_provider_config())
        if method == "GET" and path.lower() == "/resourcetypes":
            return _response(
                200,
                {
                    "schemas": [_LIST_SCHEMA],
                    "totalResults": 2,
                    "Resources": [
                        {
                            "id": "User",
                            "name": "User",
                            "endpoint": "/Users",
                            "schema": _USER_SCHEMA,
                        },
                        {
                            "id": "Group",
                            "name": "Group",
                            "endpoint": "/Groups",
                            "schema": _GROUP_SCHEMA,
                        },
                    ],
                },
            )
        if method == "GET" and path.lower() == "/schemas":
            return _response(
                200,
                {
                    "schemas": [_LIST_SCHEMA],
                    "totalResults": 2,
                    "Resources": [
                        {"id": _USER_SCHEMA, "name": "User"},
                        {"id": _GROUP_SCHEMA, "name": "Group"},
                    ],
                },
            )
        parts = [part for part in path.split("/") if part]
        if not parts or parts[0].lower() not in {"users", "groups"}:
            return _error(404, "SCIM resource not found")
        kind = "USER" if parts[0].lower() == "users" else "GROUP"
        if len(parts) == 1 and method == "GET":
            return _response(200, _list_resources(kind, query))
        if len(parts) == 1 and method == "POST":
            view = _create_user(_body(event)) if kind == "USER" else _create_group(_body(event))
            return _response(201, view, location=view["meta"]["location"])
        if len(parts) != 2:
            return _error(404, "SCIM resource not found")
        identifier = _resource_id(parts[1], "resource id")
        item = _get(kind, identifier)
        if not item:
            return _error(404, "SCIM resource not found")
        if method == "GET":
            return _response(200, _user_view(item) if kind == "USER" else _group_view(item))
        if method == "PATCH":
            body = _body(event)
            if _PATCH_SCHEMA not in body.get("schemas", []):
                raise ValueError("PatchOp schema is required")
            operations = body.get("Operations", body.get("operations"))
            if not isinstance(operations, list) or not 1 <= len(operations) <= _MAX_OPERATIONS:
                raise ValueError("PATCH requires between 1 and 20 operations")
            updated = (
                _replace_user(item, list(operations))
                if kind == "USER"
                else _patch_group(item, operations)
            )
            return _response(200, _user_view(updated) if kind == "USER" else _group_view(updated))
        if method == "DELETE":
            item["active"] = False
            item["version"] = int(item.get("version", 0)) + 1
            item["updated_at"] = int(time.time())
            TABLE.put_item(Item=item)
            _audit(f"{kind.lower()}_deactivated", kind.lower(), identifier)
            return _response(204)
        return _error(405, "method not allowed")
    except PermissionError:
        return _error(401, "SCIM authentication failed")
    except ValueError as error:
        return _error(400, str(error), "invalidValue")
    except Exception as error:
        if (
            getattr(error, "response", {}).get("Error", {}).get("Code")
            == "ConditionalCheckFailedException"
        ):
            return _error(409, "SCIM resource already exists", "uniqueness")
        return _error(500, "SCIM service failed closed")
