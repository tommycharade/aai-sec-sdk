"""Contracts for the operator-facing live Entra SCIM acceptance command."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "test_aws_entra_scim.py"
    spec = importlib.util.spec_from_file_location("aai_test_aws_entra_scim", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _CloudFormation:
    def __init__(self, outputs: dict[str, str]) -> None:
        self.outputs = outputs

    def describe_stacks(self, **_: Any) -> dict[str, Any]:
        return {
            "Stacks": [
                {
                    "Outputs": [
                        {"OutputKey": key, "OutputValue": value}
                        for key, value in self.outputs.items()
                    ]
                }
            ]
        }


class _Secrets:
    def __init__(self, value: str) -> None:
        self.value = value

    def get_secret_value(self, **_: Any) -> dict[str, str]:
        return {"SecretString": self.value}


class _Table:
    def __init__(self) -> None:
        self.deleted: list[dict[str, str]] = []

    def delete_item(self, *, Key: dict[str, str]) -> None:  # noqa: N803 - boto3 contract
        self.deleted.append(Key)


def test_preflight_requires_complete_deployed_entra_configuration() -> None:
    module = _load()
    outputs = module.stack_outputs(
        _CloudFormation(
            {
                "MicrosoftEntraIdStatus": "not-configured",
                "MicrosoftEntraScimStatus": "not-configured",
            }
        ),
        "AaiSecControlPlane",
    )
    with pytest.raises(module.EntraScimAcceptanceError, match="Entra ID is not configured"):
        module.require_configured_endpoint(outputs)
    with pytest.raises(module.EntraScimAcceptanceError, match="HTTPS"):
        module.require_configured_endpoint(
            {
                "MicrosoftEntraIdStatus": "configured",
                "MicrosoftEntraScimStatus": "configured",
                "MicrosoftEntraScimEndpoint": "http://unsafe.example/scim/v2",
            }
        )


def test_secret_resolution_is_bounded_and_schema_strict() -> None:
    module = _load()
    token = "synthetic-scim-token-value-1234567890"  # noqa: S105
    assert module.resolve_scim_token(_Secrets(json.dumps({"token": token})), "synthetic") == token
    with pytest.raises(module.EntraScimAcceptanceError, match="only the token field"):
        module.resolve_scim_token(
            _Secrets(json.dumps({"token": token, "unexpected": "value"})), "synthetic"
        )
    with pytest.raises(module.EntraScimAcceptanceError, match="length bound"):
        module.resolve_scim_token(_Secrets("short"), "synthetic")


def test_lifecycle_proves_joiner_mover_leaver_and_cleans_exact_state() -> None:
    module = _load()
    user_id = "11111111-2222-4333-8444-555555555555"
    first_group = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    second_group = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
    users: dict[str, dict[str, Any]] = {}
    groups: dict[str, dict[str, Any]] = {}

    def requester(
        _endpoint: str,
        path: str,
        method: str,
        token: str,
        body: dict[str, Any] | None,
        query: dict[str, str] | None,
    ) -> Any:
        if token.startswith("invalid-scim-acceptance-"):
            return module.ScimResponse(401, {})
        if path == "ServiceProviderConfig":
            return module.ScimResponse(
                200, {"patch": {"supported": True}, "bulk": {"supported": False}}
            )
        if path == "Users" and method == "POST":
            assert body
            identifier = body["externalId"]
            if identifier in users:
                return module.ScimResponse(409, {})
            users[identifier] = dict(body)
            return module.ScimResponse(201, dict(body))
        if path == "Groups" and method == "POST":
            assert body
            groups[body["externalId"]] = {**body, "members": []}
            return module.ScimResponse(201, groups[body["externalId"]])
        if path == "Users" and method == "GET":
            assert query
            return module.ScimResponse(200, {"totalResults": 1})
        if path.startswith("Users/"):
            identifier = path.removeprefix("Users/")
            if method == "DELETE":
                users[identifier]["active"] = False
                return module.ScimResponse(204, {})
            return module.ScimResponse(200, users[identifier])
        if path.startswith("Groups/"):
            identifier = path.removeprefix("Groups/")
            if method == "GET":
                return module.ScimResponse(200, groups[identifier])
            assert body
            operation = body["Operations"][0]
            if operation["op"] == "add":
                member = operation["value"][0]["value"]
                if not users[member]["active"]:
                    return module.ScimResponse(400, {})
                groups[identifier]["members"] = [{"value": member}]
            else:
                groups[identifier]["members"] = []
            return module.ScimResponse(200, groups[identifier])
        raise AssertionError(f"unexpected request {method} {path}")

    table = _Table()
    identifiers = module.run_lifecycle_with_cleanup(
        "https://synthetic.example/scim/v2",
        "synthetic-scim-token-value-1234567890",
        table,
        "tenant-enterprise",
        requester=requester,
        identifiers=(user_id, first_group, second_group),
    )
    assert identifiers == (user_id, first_group, second_group)
    assert users[user_id]["active"] is False
    assert groups[first_group]["members"] == []
    assert groups[second_group]["members"] == [{"value": user_id}]

    assert len(table.deleted) == 7
    assert all(
        user_id in str(key) or first_group in str(key) or second_group in str(key)
        for key in table.deleted
    )


def test_lifecycle_cleanup_runs_after_partial_remote_failure() -> None:
    module = _load()
    table = _Table()
    identifiers = (
        "11111111-2222-4333-8444-555555555555",
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
    )
    calls = 0

    def requester(*_: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 1:
            return module.ScimResponse(401, {})
        raise module.EntraScimAcceptanceError("synthetic remote failure")

    with pytest.raises(module.EntraScimAcceptanceError, match="synthetic remote failure"):
        module.run_lifecycle_with_cleanup(
            "https://synthetic.example/scim/v2",
            "synthetic-scim-token-value-1234567890",
            table,
            "tenant-enterprise",
            requester=requester,
            identifiers=identifiers,
        )
    assert len(table.deleted) == 7
