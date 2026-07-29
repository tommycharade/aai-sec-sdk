"""Adversarial contracts for the Microsoft Entra SCIM lifecycle boundary."""

import importlib.util
import json
import sys
import types
from pathlib import Path
from typing import Any, cast


class ConditionalFailure(Exception):
    """Minimal DynamoDB uniqueness failure."""

    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class Condition:
    """Small composable stand-in for boto3 key conditions."""

    def __init__(self, predicates: list[tuple[str, str, str]]) -> None:
        self.predicates = predicates

    def __and__(self, other: "Condition") -> "Condition":
        return Condition(self.predicates + other.predicates)


class Table:
    """In-memory table supporting the bounded SCIM access pattern."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}

    def get_item(self, *, Key: dict[str, str], **_: Any) -> dict[str, Any]:
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": dict(item)} if item else {}

    def put_item(self, *, Item: dict[str, Any], **kwargs: Any) -> None:
        key = (Item["pk"], Item["sk"])
        if kwargs.get("ConditionExpression") and key in self.items:
            raise ConditionalFailure()
        self.items[key] = dict(Item)

    def query(self, **kwargs: Any) -> dict[str, Any]:
        values = list(self.items.values())
        condition = kwargs.get("KeyConditionExpression")
        for field, operation, expected in condition.predicates if condition else []:
            if operation == "eq":
                values = [item for item in values if item.get(field) == expected]
            else:
                values = [item for item in values if str(item.get(field, "")).startswith(expected)]
        limit = kwargs.get("Limit", len(values))
        return {"Items": [dict(item) for item in values[:limit]]}


class DynamoClient:
    """Apply DynamoDB membership transactions atomically in the test model."""

    def __init__(self, table: Table) -> None:
        self.table = table

    def transact_write_items(self, *, TransactItems: list[dict[str, Any]]) -> None:
        staged = dict(self.table.items)
        for request in TransactItems:
            if "Put" in request:
                raw = request["Put"]["Item"]
                item = {key: value["S"] for key, value in raw.items()}
                staged[(item["pk"], item["sk"])] = item
            else:
                raw = request["Delete"]["Key"]
                key = {name: value["S"] for name, value in raw.items()}
                staged.pop((key["pk"], key["sk"]), None)
        self.table.items = staged


class SecretClient:
    """Return one synthetic bearer without exposing it in response payloads."""

    def __init__(self, token: str) -> None:
        self.token = token

    def get_secret_value(self, **_: Any) -> dict[str, str]:
        return {"SecretString": json.dumps({"token": self.token})}


def _load_scim(monkeypatch: Any) -> tuple[Any, Table, str]:
    table = Table()
    token = "synthetic-scim-bearer-value-1234567890"  # noqa: S105
    boto3 = types.ModuleType("boto3")
    boto3.resource = lambda *_args, **_kwargs: types.SimpleNamespace(  # type: ignore[attr-defined]
        Table=lambda _name: table
    )

    def client(name: str) -> object:
        return DynamoClient(table) if name == "dynamodb" else SecretClient(token)

    boto3.client = client  # type: ignore[attr-defined]
    dynamodb = types.ModuleType("boto3.dynamodb")
    conditions = types.ModuleType("boto3.dynamodb.conditions")
    conditions.Key = lambda name: types.SimpleNamespace(  # type: ignore[attr-defined]
        eq=lambda value: Condition([(name, "eq", value)]),
        begins_with=lambda value: Condition([(name, "begins_with", value)]),
    )
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "boto3.dynamodb", dynamodb)
    monkeypatch.setitem(sys.modules, "boto3.dynamodb.conditions", conditions)
    monkeypatch.setenv("SCIM_TABLE", "scim")
    monkeypatch.setenv("SCIM_AAI_TENANT_ID", "tenant-enterprise")
    monkeypatch.setenv("SCIM_TOKEN_SECRET_NAME", "synthetic/scim/token")
    path = Path(__file__).parents[1] / "infra/aws-control-plane/lambda/scim.py"
    spec = importlib.util.spec_from_file_location("aai_scim", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, table, token


def _event(
    path: str,
    method: str,
    token: str,
    body: dict[str, Any] | None = None,
    query: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "rawPath": path,
        "headers": {"authorization": f"Bearer {token}"},
        "body": json.dumps(body or {}),
        "queryStringParameters": query or {},
        "requestContext": {"http": {"method": method}},
    }


def _invoke(module: Any, event: dict[str, Any]) -> dict[str, Any]:
    return cast(dict[str, Any], module.handler(event, None))


def test_scim_bearer_fails_closed_without_reflection(monkeypatch: Any) -> None:
    """Missing, short and incorrect credentials cannot read lifecycle state."""
    module, _table, token = _load_scim(monkeypatch)
    for supplied in ("", "short", f"{token}-wrong"):
        response = _invoke(module, _event("/scim/v2/Users", "GET", supplied))
        assert response["statusCode"] == 401
        if supplied:
            assert supplied not in response["body"]


def test_scim_joiner_mover_leaver_lifecycle_is_tenant_bound(monkeypatch: Any) -> None:
    """Entra can provision, group, move and deactivate one synthetic operator."""
    module, table, token = _load_scim(monkeypatch)
    user_id = "11111111-2222-4333-8444-555555555555"
    group_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    user = _invoke(
        module,
        _event(
            "/scim/v2/Users",
            "POST",
            token,
            {
                "schemas": [module._USER_SCHEMA],
                "externalId": user_id,
                "userName": "synthetic.operator@example.invalid",
                "active": True,
            },
        ),
    )
    assert user["statusCode"] == 201
    assert token not in user["body"]
    duplicate = _invoke(module, _event("/scim/v2/Users", "POST", token, json.loads(user["body"])))
    assert duplicate["statusCode"] == 409

    group = _invoke(
        module,
        _event(
            "/scim/v2/Groups",
            "POST",
            token,
            {
                "schemas": [module._GROUP_SCHEMA],
                "externalId": group_id,
                "displayName": "AAI Policy Approvers",
            },
        ),
    )
    assert group["statusCode"] == 201
    added = _invoke(
        module,
        _event(
            f"/scim/v2/Groups/{group_id}",
            "PATCH",
            token,
            {
                "schemas": [module._PATCH_SCHEMA],
                "Operations": [{"op": "add", "path": "members", "value": [{"value": user_id}]}],
            },
        ),
    )
    assert added["statusCode"] == 200
    assert (f"TENANT#tenant-enterprise#USER#{user_id}", f"GROUP#{group_id}") in table.items

    removed = _invoke(
        module,
        _event(
            f"/scim/v2/Groups/{group_id}",
            "PATCH",
            token,
            {
                "schemas": [module._PATCH_SCHEMA],
                "Operations": [{"op": "remove", "path": f'members[value eq "{user_id}"]'}],
            },
        ),
    )
    assert removed["statusCode"] == 200
    assert (f"TENANT#tenant-enterprise#USER#{user_id}", f"GROUP#{group_id}") not in table.items

    disabled = _invoke(module, _event(f"/scim/v2/Users/{user_id}", "DELETE", token))
    assert disabled["statusCode"] == 204
    stored = table.items[("TENANT#tenant-enterprise", f"USER#{user_id}")]
    assert stored["active"] is False
    assert any(item.get("event_type") == "user_deactivated" for item in table.items.values())


def test_scim_rejects_unknown_members_and_unsupported_filters(monkeypatch: Any) -> None:
    """Malformed Entra operations cannot create dangling or unbounded authority."""
    module, _table, token = _load_scim(monkeypatch)
    group_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    _invoke(
        module,
        _event(
            "/scim/v2/Groups",
            "POST",
            token,
            {"schemas": [module._GROUP_SCHEMA], "externalId": group_id, "displayName": "Mapped"},
        ),
    )
    dangling = _invoke(
        module,
        _event(
            f"/scim/v2/Groups/{group_id}",
            "PATCH",
            token,
            {
                "schemas": [module._PATCH_SCHEMA],
                "Operations": [
                    {
                        "op": "add",
                        "path": "members",
                        "value": [{"value": "11111111-2222-4333-8444-555555555555"}],
                    }
                ],
            },
        ),
    )
    assert dangling["statusCode"] == 400
    malformed = _invoke(
        module,
        _event(
            f"/scim/v2/Groups/{group_id}",
            "PATCH",
            token,
            {
                "schemas": [module._PATCH_SCHEMA],
                "Operations": [{"op": "add", "path": "members", "value": ["not-an-object"]}],
            },
        ),
    )
    assert malformed["statusCode"] == 400
    unsupported = _invoke(
        module,
        _event(
            "/scim/v2/Users",
            "GET",
            token,
            query={"filter": 'userName co "operator"'},
        ),
    )
    assert unsupported["statusCode"] == 400
