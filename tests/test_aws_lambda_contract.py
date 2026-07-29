"""Contract tests for the deployed AWS control-plane Lambda boundary."""

import hashlib
import importlib.util
import json
import sys
import time
import types
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest


class ConditionalFailure(Exception):
    """Minimal boto-compatible conditional failure."""

    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class FakeTable:
    """DynamoDB table double covering the handler's conditional operations."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}

    def get_item(self, *, Key: dict[str, str], **_: Any) -> dict[str, Any]:
        item = self.items.get((Key["pk"], Key.get("sk", "")))
        return {} if item is None else {"Item": dict(item)}

    def put_item(self, *, Item: dict[str, Any], **kwargs: Any) -> None:
        key = (Item["pk"], Item.get("sk", ""))
        if kwargs.get("ConditionExpression") and key in self.items:
            raise ConditionalFailure()
        self.items[key] = dict(Item)

    def delete_item(self, *, Key: dict[str, str], **_: Any) -> None:
        key = (Key["pk"], Key.get("sk", ""))
        if key not in self.items:
            raise ConditionalFailure()
        del self.items[key]

    def update_item(
        self, *, Key: dict[str, str], ExpressionAttributeValues: dict[str, Any], **_: Any
    ) -> dict[str, Any]:
        key = (Key["pk"], Key.get("sk", ""))
        item = self.items.get(key)
        if item is None:
            raise ConditionalFailure()
        if ":project_root" in ExpressionAttributeValues:
            if item.get("project_root") not in (None, ""):
                raise ConditionalFailure()
            item["project_root"] = ExpressionAttributeValues[":project_root"]
            self.items[key] = item
            return {"Attributes": dict(item)}
        if ":pending" in ExpressionAttributeValues:
            if (
                item.get("status") != ExpressionAttributeValues[":pending"]
                or item.get("expires_at", 0) <= ExpressionAttributeValues[":now"]
            ):
                raise ConditionalFailure()
            item.update(
                {
                    "status": ExpressionAttributeValues[":decision"],
                    "decided_at": ExpressionAttributeValues[":now"],
                    "decided_by": ExpressionAttributeValues[":actor"],
                    "decision_reason": ExpressionAttributeValues[":reason"],
                    "expires_at": ExpressionAttributeValues[":expires_at"],
                    "ttl": ExpressionAttributeValues[":ttl"],
                }
            )
            self.items[key] = item
            return {"Attributes": dict(item)}
        if (
            item.get("status") != ExpressionAttributeValues[":approved_status"]
            or item.get("consumed") is not ExpressionAttributeValues[":false"]
        ):
            raise ConditionalFailure()
        for name in (
            "expires_at",
            "agent_key",
            "action_hash",
            "tool_name",
            "proposal_id",
            "task_id",
            "principal_id",
        ):
            expected = {
                "expires_at": ":now",
                "agent_key": ":agent",
                "action_hash": ":action_hash",
                "tool_name": ":tool_name",
                "proposal_id": ":proposal_id",
                "task_id": ":task_id",
                "principal_id": ":principal_id",
            }[name]
            if name == "expires_at":
                if item.get(name, 0) <= ExpressionAttributeValues[expected]:
                    raise ConditionalFailure()
            elif item.get(name) != ExpressionAttributeValues[expected]:
                raise ConditionalFailure()
        item["consumed"] = True
        item["status"] = ExpressionAttributeValues[":consumed_status"]
        item["consumed_at"] = ExpressionAttributeValues[":now"]
        self.items[key] = item
        return {"Attributes": dict(item)}

    def query(self, **kwargs: Any) -> dict[str, Any]:
        condition = kwargs.get("KeyConditionExpression")
        values = list(self.items.values())
        if isinstance(condition, FakeCondition):
            for field, operation, expected in condition.predicates:
                if operation == "eq":
                    values = [item for item in values if item.get(field) == expected]
                elif operation == "begins_with":
                    values = [
                        item
                        for item in values
                        if str(item.get(field, "")).startswith(str(expected))
                    ]
        return {"Items": [dict(item) for item in values]}


class FakeS3:
    """Capture audit writes without retaining sensitive test material."""

    def put_object(self, **_: Any) -> None:
        return None


class FakeCondition:
    """Composable placeholder for boto3 key expressions ignored by FakeTable."""

    def __init__(self, predicates: list[tuple[str, str, Any]]) -> None:
        self.predicates = predicates

    def __and__(self, other: Any) -> "FakeCondition":
        return FakeCondition(
            self.predicates + (other.predicates if isinstance(other, FakeCondition) else [])
        )


def _load_handler(monkeypatch: Any) -> Any:
    """Load the Lambda with dependency-free boto3 doubles."""
    table = FakeTable()
    boto3 = types.ModuleType("boto3")
    boto3.resource = (  # type: ignore[attr-defined]
        lambda *_args, **_kwargs: types.SimpleNamespace(Table=lambda _name: table)
    )
    boto3.client = lambda *_args, **_kwargs: FakeS3()  # type: ignore[attr-defined]
    dynamodb = types.ModuleType("boto3.dynamodb")
    conditions = types.ModuleType("boto3.dynamodb.conditions")
    conditions.Key = lambda name: types.SimpleNamespace(  # type: ignore[attr-defined]
        eq=lambda value: FakeCondition([(name, "eq", value)]),
        begins_with=lambda value: FakeCondition([(name, "begins_with", value)]),
    )
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "boto3.dynamodb", dynamodb)
    monkeypatch.setitem(sys.modules, "boto3.dynamodb.conditions", conditions)
    monkeypatch.setenv("CONTROL_TABLE", "control")
    monkeypatch.setenv("PRESENCE_TABLE", "presence")
    monkeypatch.setenv("IDEMPOTENCY_TABLE", "idempotency")
    monkeypatch.setenv("AUDIT_BUCKET", "audit")
    monkeypatch.setenv("ENTRA_PROVIDER_ENABLED", "false")
    monkeypatch.setenv("ENTRA_TENANT_ID", "")
    monkeypatch.setenv("ENTRA_AAI_TENANT_ID", "")
    monkeypatch.setenv("SCIM_ENABLED", "false")
    monkeypatch.setenv("SCIM_TABLE", "")
    monkeypatch.setenv("SPLUNK_STUB_ENABLED", "true")
    path = Path(__file__).parents[1] / "infra/aws-control-plane/lambda/handler.py"
    spec = importlib.util.spec_from_file_location("aai_lambda_handler", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, table


def _event(
    path: str,
    method: str,
    *,
    body: dict[str, Any] | None = None,
    claims: dict[str, Any] | None = None,
    token: str | None = None,
    project_root: str = "/synthetic/project",
) -> dict[str, Any]:
    headers = {"authorization": f"Bearer {token}"} if token else {}
    if token:
        headers["x-aai-project-root-digest"] = hashlib.sha256(project_root.encode()).hexdigest()
    return {
        "rawPath": path,
        "headers": headers,
        "body": json.dumps(body or {}),
        "requestContext": {
            "http": {"method": method},
            "authorizer": {"jwt": {"claims": claims or {}}},
        },
    }


def _invoke(module: Any, event: dict[str, Any]) -> dict[str, Any]:
    """Invoke the Lambda with the context value unused by this handler."""
    return cast(dict[str, Any], module.handler(event, None))


@pytest.mark.parametrize(
    ("claim", "expected"),
    [
        (["platform-admin"], True),
        ("platform-admin", True),
        ('["platform-admin","developers"]', True),
        ("[developers, security-operator]", True),
        ("developers,platform-admin", True),
        ("not-platform-admin", False),
        ('{"group":"platform-admin"}', False),
        (123, False),
        ("x" * 2049, False),
    ],
)
def test_cognito_operator_groups_normalize_gateway_strings_and_fail_closed(
    monkeypatch: Any,
    claim: object,
    expected: bool,
) -> None:
    """Only exact mutation roles survive API Gateway's string projection."""
    module, _table = _load_handler(monkeypatch)
    event = _event(
        "/enterprise/agents/bootstrap",
        "POST",
        claims={"cognito:groups": claim},
    )
    assert module._mutation_authorized(event) is expected


@pytest.mark.parametrize(
    ("role", "allowed", "denied"),
    [
        ("platform-admin", "runtime_admin", None),
        ("security-operator", "approval_decision", "policy_write"),
        ("policy-author", "policy_write", "approval_decision"),
        ("policy-approver", "policy_approval", "fleet_write"),
        ("fleet-operator", "fleet_write", "incident_response"),
        ("incident-responder", "incident_response", "policy_write"),
        ("auditor", None, "runtime_admin"),
    ],
)
def test_operator_roles_enforce_capabilities_without_authority_overlap(
    monkeypatch: Any,
    role: str,
    allowed: str | None,
    denied: str | None,
) -> None:
    """Canonical roles grant only their explicit server-owned capabilities."""
    module, _table = _load_handler(monkeypatch)
    event = _event("/enterprise/identity", "GET", claims={"cognito:groups": [role]})
    if allowed:
        assert module._operator_authorized(event, allowed)
    if denied:
        assert not module._operator_authorized(event, denied)


def test_entra_tenant_binding_requires_cognito_provenance_and_deployment_mapping(
    monkeypatch: Any,
) -> None:
    """A browser tenant value cannot replace the configured Entra-to-AAI binding."""
    module, table = _load_handler(monkeypatch)
    entra_tenant = "11111111-2222-4333-8444-555555555555"
    aai_tenant = "tenant-enterprise"
    monkeypatch.setenv("ENTRA_PROVIDER_ENABLED", "true")
    monkeypatch.setenv("ENTRA_TENANT_ID", entra_tenant)
    monkeypatch.setenv("ENTRA_AAI_TENANT_ID", aai_tenant)
    table.put_item(
        Item=module._item_key(aai_tenant, "TENANT", "root") | {"id": aai_tenant, "status": "active"}
    )
    claims = {
        "aai:identity_provider": "microsoft_entra_id",
        "aai:entra_tenant_id": entra_tenant,
        "sub": "entra-operator",
    }
    assert module._tenant(_event("/enterprise/tenant", "GET", claims=claims)) == aai_tenant
    with pytest.raises(PermissionError, match="tenant entitlement"):
        module._tenant(
            _event(
                "/enterprise/tenant",
                "GET",
                claims={**claims, "aai:entra_tenant_id": "attacker-tenant"},
            )
        )


def test_identity_and_splunk_stub_report_truthful_enterprise_posture(monkeypatch: Any) -> None:
    """The UI receives role provenance while a stub never claims SIEM delivery."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-enterprise"
    entra_tenant = "11111111-2222-4333-8444-555555555555"
    monkeypatch.setenv("ENTRA_PROVIDER_ENABLED", "true")
    monkeypatch.setenv("ENTRA_TENANT_ID", entra_tenant)
    monkeypatch.setenv("ENTRA_AAI_TENANT_ID", tenant)
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant, "status": "active"}
    )
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["auditor", "incident-responder"],
        "sub": "operator-a",
    }
    identity = _invoke(module, _event("/enterprise/identity", "GET", claims=claims))
    payload = json.loads(identity["body"])
    assert payload["status"] == "configured"
    assert payload["tenantHint"] == "11111111…"
    assert payload["tenantBinding"] == "server_owned"
    assert payload["activeRoles"] == ["auditor", "incident-responder"]
    assert "ENTRA_CLIENT_SECRET" not in json.dumps(payload)

    integrations = _invoke(module, _event("/enterprise/integrations", "GET", claims=claims))
    splunk = json.loads(integrations["body"])["splunk"]
    assert splunk["status"] == "stub"
    assert splunk["deliveryVerified"] is False


def test_entra_pre_token_trigger_uses_only_cognito_federation_identity(
    monkeypatch: Any,
) -> None:
    """Only the exact configured OIDC identity receives Entra provenance."""
    monkeypatch.setenv("ENTRA_PROVIDER_NAME", "MicrosoftEntraID")
    monkeypatch.setenv("ENTRA_TENANT_ID", "11111111-2222-4333-8444-555555555555")
    path = Path(__file__).parents[1] / "infra/aws-control-plane/lambda/pre_token.py"
    spec = importlib.util.spec_from_file_location("aai_pre_token", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    identity = json.dumps(
        [{"providerName": "MicrosoftEntraID", "providerType": "OIDC", "userId": "synthetic"}]
    )
    event = {"request": {"userAttributes": {"identities": identity}}, "response": {}}
    response = module.handler(event, None)
    overrides = response["response"]["claimsAndScopeOverrideDetails"]
    for token_name in ("idTokenGeneration", "accessTokenGeneration"):
        assert overrides[token_name]["claimsToAddOrOverride"] == {
            "aai:identity_provider": "microsoft_entra_id",
            "aai:entra_tenant_id": "11111111-2222-4333-8444-555555555555",
        }
    hostile = {
        "request": {
            "userAttributes": {
                "identities": json.dumps(
                    [{"providerName": "MicrosoftEntraID-lookalike", "providerType": "OIDC"}]
                )
            }
        },
        "response": {},
    }
    assert module.handler(hostile, None)["response"] == {}


def test_entra_pre_token_enforces_scim_lifecycle_and_mapped_roles(monkeypatch: Any) -> None:
    """Unprovisioned, deactivated and unmapped Entra operators fail before token issue."""
    _handler, table = _load_handler(monkeypatch)
    monkeypatch.setenv("ENTRA_PROVIDER_NAME", "MicrosoftEntraID")
    monkeypatch.setenv("ENTRA_TENANT_ID", "11111111-2222-4333-8444-555555555555")
    monkeypatch.setenv("SCIM_ENABLED", "true")
    monkeypatch.setenv("SCIM_TABLE", "scim")
    monkeypatch.setenv("SCIM_AAI_TENANT_ID", "tenant-enterprise")
    user_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    group_id = "99999999-8888-4777-8666-555555555555"
    identity = json.dumps(
        [{"providerName": "MicrosoftEntraID", "providerType": "OIDC", "userId": "pairwise"}]
    )
    event = {
        "request": {
            "userAttributes": {
                "identities": identity,
                "custom:entra_object_id": user_id,
            }
        },
        "response": {},
    }
    path = Path(__file__).parents[1] / "infra/aws-control-plane/lambda/pre_token.py"
    spec = importlib.util.spec_from_file_location("aai_scim_pre_token", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    with pytest.raises(PermissionError, match="not actively provisioned"):
        module.handler(event, None)
    table.put_item(
        Item={
            "pk": "TENANT#tenant-enterprise",
            "sk": f"USER#{user_id}",
            "active": True,
            "version": 1,
        }
    )
    with pytest.raises(PermissionError, match="no mapped product role"):
        module.handler(event, None)
    table.put_item(
        Item={
            "pk": f"TENANT#tenant-enterprise#USER#{user_id}",
            "sk": f"GROUP#{group_id}",
        }
    )
    table.put_item(
        Item={
            "pk": "TENANT#tenant-enterprise",
            "sk": f"GROUP#{group_id}",
            "active": True,
            "mapped_role": "policy-approver",
            "version": 2,
        }
    )
    result = module.handler(event, None)
    overrides = result["response"]["claimsAndScopeOverrideDetails"]
    assert overrides["groupOverrideDetails"] == {"groupsToOverride": ["policy-approver"]}
    assert (
        overrides["accessTokenGeneration"]["claimsToAddOrOverride"]["aai:scim_enforced"] == "true"
    )
    assert (
        len(overrides["accessTokenGeneration"]["claimsToAddOrOverride"]["aai:scim_revision"]) == 64
    )
    table.items[("TENANT#tenant-enterprise", f"USER#{user_id}")]["active"] = False
    with pytest.raises(PermissionError, match="not actively provisioned"):
        module.handler({**event, "response": {}}, None)


def test_scim_group_role_mapping_is_platform_admin_only_and_audited(monkeypatch: Any) -> None:
    """Only tenant administrators can map provisioned groups into product authority."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-enterprise"
    group_id = "99999999-8888-4777-8666-555555555555"
    monkeypatch.setenv("SCIM_ENABLED", "true")
    monkeypatch.setenv("ENTRA_AAI_TENANT_ID", tenant)
    module.SCIM = table
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item={
            "pk": f"TENANT#{tenant}",
            "sk": f"GROUP#{group_id}",
            "id": group_id,
            "display_name": "AAI Policy Approvers",
            "active": True,
            "mapped_role": "",
            "version": 1,
            "updated_at": 1,
        }
    )
    path = f"/enterprise/identity/scim/groups/{group_id}/role"
    denied = _invoke(
        module,
        _event(
            path,
            "PUT",
            body={"role": "policy-approver"},
            claims={"custom:tenant_id": tenant, "cognito:groups": ["fleet-operator"]},
        ),
    )
    assert denied["statusCode"] == 403
    assert json.loads(denied["body"])["requiredCapability"] == "identity_admin"
    applied = _invoke(
        module,
        _event(
            path,
            "PUT",
            body={"role": "policy-approver"},
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["platform-admin"],
                "sub": "admin-a",
            },
        ),
    )
    assert applied["statusCode"] == 200
    payload = json.loads(applied["body"])
    assert payload["scimStatus"] == "configured"
    assert payload["scim"]["groups"] == {"total": 1, "mapped": 1, "unmapped": 0}
    assert table.items[(f"TENANT#{tenant}", f"GROUP#{group_id}")]["mapped_role"] == (
        "policy-approver"
    )


def test_json_boundary_preserves_integral_policy_versions(monkeypatch: Any) -> None:
    """DynamoDB Decimal serialization must not make typed versions floats."""
    module, _table = _load_handler(monkeypatch)
    assert module._json({"version": Decimal("1"), "budget": Decimal("1.5")}) == {
        "version": 1,
        "budget": 1.5,
    }
    assert module._managed_policy_configuration("tenant-a", {"version": Decimal("2")}) == {
        "version": 2
    }


def test_trial_foundation_creation_is_tenant_scoped_and_agent_identity_is_derived(
    monkeypatch: Any,
) -> None:
    """A fresh trial can create real prerequisites without trusting browser ownership."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-trial-activation"
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root")
        | {"id": tenant, "status": "active", "trial": True}
    )
    table.put_item(
        Item=module._item_key(tenant, "ORG", "org-trial")
        | {"id": "org-trial", "name": "Trial workspace"}
    )
    table.put_item(
        Item=module._item_key(tenant, "POLICY", "policy-safe-default")
        | {
            "id": "policy-safe-default",
            "organization_id": "org-trial",
            "name": "Safe default policy",
            "configuration": {"policy": {"denyByDefault": True}},
            "version": 1,
        }
    )
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "trial-operator",
    }

    project = _invoke(
        module,
        _event(
            "/enterprise/projects",
            "POST",
            body={
                "organizationId": "org-trial",
                "projectId": "project-pilot",
                "name": "Platform pilot",
            },
            claims=claims,
        ),
    )
    assert project["statusCode"] == 201
    assert (
        _invoke(
            module,
            _event(
                "/enterprise/projects",
                "POST",
                body={
                    "organizationId": "org-trial",
                    "projectId": "project-pilot",
                    "name": "Replacement project",
                },
                claims=claims,
            ),
        )["statusCode"]
        == 409
    )
    malformed = _invoke(
        module,
        _event(
            "/enterprise/projects",
            "POST",
            body={
                "organizationId": "org-trial",
                "projectId": "../cross-tenant",
                "name": "Invalid",
            },
            claims=claims,
        ),
    )
    assert malformed["statusCode"] == 400

    deployment = _invoke(
        module,
        _event(
            "/enterprise/deployments",
            "POST",
            body={
                "organizationId": "org-trial",
                "projectId": "project-pilot",
                "deploymentId": "deployment-pilot",
                "name": "Claude pilot",
                "environment": "pilot",
                "region": "eu-west-2",
                "team": "Platform",
                "sdkVersion": "1.1.0",
            },
            claims=claims,
        ),
    )
    assert deployment["statusCode"] == 201
    wrong_organization = _invoke(
        module,
        _event(
            "/enterprise/deployments",
            "POST",
            body={
                "organizationId": "org-forged",
                "projectId": "project-pilot",
                "deploymentId": "deployment-forged",
                "name": "Forged",
                "environment": "prod",
                "region": "us-east-1",
            },
            claims=claims,
        ),
    )
    assert wrong_organization["statusCode"] == 400

    group = _invoke(
        module,
        _event(
            "/enterprise/groups",
            "POST",
            body={
                "groupId": "group-pilot",
                "name": "Pilot agents",
                "policyId": "policy-safe-default",
            },
            claims=claims,
        ),
    )
    assert group["statusCode"] == 201
    assert json.loads(group["body"])["organizationId"] == "org-trial"

    registered = _invoke(
        module,
        _event(
            "/enterprise/agents/register",
            "POST",
            body={
                "deploymentId": "deployment-pilot",
                "agentId": "claude-pilot",
                "host": "claude-code",
                "projectRoot": "/synthetic/pilot",
                "organizationId": "org-forged",
                "projectId": "project-forged",
                "environment": "prod",
                "region": "us-east-1",
            },
            claims=claims,
        ),
    )
    assert registered["statusCode"] == 201
    stored = table.items[(f"TENANT#{tenant}", "AGENT#deployment-pilot:claude-pilot")]
    assert stored["organization_id"] == "org-trial"
    assert stored["project_id"] == "project-pilot"
    assert stored["environment"] == "pilot"
    assert stored["region"] == "eu-west-2"
    assert stored["status"] == "offline"
    assert stored["last_heartbeat"] == 0
    immutable_scope = _invoke(
        module,
        _event(
            "/enterprise/agents/register",
            "POST",
            body={
                "deploymentId": "deployment-pilot",
                "agentId": "claude-pilot",
                "host": "claude-code",
                "projectRoot": "/synthetic/other",
            },
            claims=claims,
        ),
    )
    assert immutable_scope["statusCode"] == 409

    legacy = dict(stored)
    legacy["id"] = "legacy-agent"
    legacy["project_root"] = ""
    legacy.update(module._item_key(tenant, "AGENT", "deployment-pilot:legacy-agent"))
    table.put_item(Item=legacy)
    repaired_scope = _invoke(
        module,
        _event(
            "/enterprise/agents/register",
            "POST",
            body={
                "deploymentId": "deployment-pilot",
                "agentId": "legacy-agent",
                "host": "codex-cli",
                "projectRoot": "/synthetic/legacy",
            },
            claims=claims,
        ),
    )
    assert repaired_scope["statusCode"] == 200
    assert json.loads(repaired_scope["body"])["project_root"] == "/synthetic/legacy"

    raced = dict(stored)
    raced["id"] = "raced-agent"
    raced["project_root"] = ""
    raced_key = module._item_key(tenant, "AGENT", "deployment-pilot:raced-agent")
    raced.update(raced_key)
    table.put_item(Item=raced)
    original_update = table.update_item

    def racing_update(**kwargs: Any) -> dict[str, Any]:
        if ":project_root" in kwargs.get("ExpressionAttributeValues", {}):
            stored_race = table.items[(raced_key["pk"], raced_key["sk"])]
            stored_race["project_root"] = "/synthetic/winner"
            raise ConditionalFailure()
        return cast(dict[str, Any], original_update(**kwargs))

    monkeypatch.setattr(table, "update_item", racing_update)
    lost_repair = _invoke(
        module,
        _event(
            "/enterprise/agents/register",
            "POST",
            body={
                "deploymentId": "deployment-pilot",
                "agentId": "raced-agent",
                "host": "codex-cli",
                "projectRoot": "/synthetic/loser",
            },
            claims=claims,
        ),
    )
    assert lost_repair["statusCode"] == 409
    assert table.items[(raced_key["pk"], raced_key["sk"])]["project_root"] == "/synthetic/winner"
    monkeypatch.setattr(table, "update_item", original_update)
    assert (
        _invoke(
            module,
            _event(
                "/enterprise/agents/deployment-pilot/claude-pilot/verify",
                "GET",
                claims=claims,
            ),
        )["statusCode"]
        == 200
    )
    verification = json.loads(
        _invoke(
            module,
            _event(
                "/enterprise/agents/deployment-pilot/claude-pilot/verify",
                "GET",
                claims=claims,
            ),
        )["body"]
    )
    assert verification["verified"] is False
    assert verification["checks"]["heartbeat"]["passed"] is False

    missing_deployment = _invoke(
        module,
        _event(
            "/enterprise/agents/register",
            "POST",
            body={
                "deploymentId": "deployment-missing",
                "agentId": "agent-missing",
                "host": "codex-cli",
            },
            claims=claims,
        ),
    )
    assert missing_deployment["statusCode"] == 400
    missing_scope = _invoke(
        module,
        _event(
            "/enterprise/agents/register",
            "POST",
            body={
                "deploymentId": "deployment-pilot",
                "agentId": "agent-without-scope",
                "host": "codex-cli",
            },
            claims=claims,
        ),
    )
    assert missing_scope["statusCode"] == 400
    for unsafe_root in (
        "relative/project",
        "/",
        "/synthetic/project/",
        "/synthetic/../project",
        "/synthetic//project",
    ):
        invalid_scope = _invoke(
            module,
            _event(
                "/enterprise/agents/register",
                "POST",
                body={
                    "deploymentId": "deployment-pilot",
                    "agentId": "agent-invalid-scope",
                    "host": "codex-cli",
                    "projectRoot": unsafe_root,
                },
                claims=claims,
            ),
        )
        assert invalid_scope["statusCode"] == 400
        assert "canonical absolute project path" in json.loads(invalid_scope["body"])["error"]


def test_agent_enrollment_is_one_time_and_identity_bound(monkeypatch: Any) -> None:
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-a"
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant, "status": "active"}
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "tenant_id": tenant,
            "status": "offline",
            "project_root": "/synthetic/project",
        }
    )
    claims = {"custom:tenant_id": tenant, "cognito:groups": ["platform-admin"], "sub": "operator"}
    issued = _invoke(
        module,
        _event(
            "/enterprise/agents/bootstrap",
            "POST",
            body={"deploymentId": "dep-a", "agentId": "agent-a"},
            claims=claims,
        ),
    )
    assert issued["statusCode"] == 201
    bootstrap = json.loads(issued["body"])["bootstrapToken"]
    wrong_scope_enrollment = _invoke(
        module,
        _event(
            "/agent/enroll",
            "POST",
            body={"bootstrapToken": bootstrap, "projectRoot": "/synthetic/other"},
        ),
    )
    assert wrong_scope_enrollment["statusCode"] == 403
    enrolled = _invoke(
        module,
        _event(
            "/agent/enroll",
            "POST",
            body={
                "bootstrapToken": bootstrap,
                "projectRoot": "/synthetic/project",
                "host": "Claude Code",
            },
        ),
    )
    assert enrolled["statusCode"] == 201
    payload = json.loads(enrolled["body"])
    # Enrollment proves token possession only. Presence remains offline until
    # the enrolled runtime sends its authenticated heartbeat.
    assert table.items[(f"TENANT#{tenant}", "AGENT#dep-a:agent-a")]["status"] == "offline"
    replay = _invoke(module, _event("/agent/enroll", "POST", body={"bootstrapToken": bootstrap}))
    assert replay["statusCode"] == 403
    heartbeat = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/heartbeat",
            "POST",
            token=payload["accessToken"],
            body={
                "telemetry": {
                    "actionsTotal": 4,
                    "actionsAdmitted": 4,
                    "allowed": 3,
                    "denied": 1,
                    "approvalRequired": 0,
                    "executed": 3,
                    "failed": 0,
                    "timedOut": 0,
                    "cancelled": 0,
                    "resultRejected": 0,
                    "runtimeErrors": 0,
                    "costUnits": 4,
                    "averageLatencyMs": 7.25,
                    "maxLatencyMs": 12.0,
                }
            },
        ),
    )
    assert heartbeat["statusCode"] == 200
    wrong_scope_heartbeat = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/heartbeat",
            "POST",
            token=payload["accessToken"],
            project_root="/synthetic/other",
        ),
    )
    assert wrong_scope_heartbeat["statusCode"] == 403
    stored_agent = table.items[(f"TENANT#{tenant}", "AGENT#dep-a:agent-a")]
    assert stored_agent["status"] == "connected"
    assert stored_agent["telemetry"]["actionsTotal"] == 4
    bad_telemetry = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/heartbeat",
            "POST",
            token=payload["accessToken"],
            body={"telemetry": {"secret": 1}},
        ),
    )
    assert bad_telemetry["statusCode"] == 400
    # An agent stop must be enforced by the agent API before it returns an
    # effective policy; a UI/control-plane state change cannot be advisory.
    stopped = dict(table.items[(f"TENANT#{tenant}", "AGENT#dep-a:agent-a")])
    stopped["emergencyStop"] = True
    table.put_item(Item=stopped)
    stop_response = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/effective-policy",
            "GET",
            token=payload["accessToken"],
        ),
    )
    assert stop_response["statusCode"] == 409
    assert json.loads(stop_response["body"])["emergencyStop"] is True
    wrong_identity = _invoke(
        module, _event("/agent/dep-a/other-agent/heartbeat", "POST", token=payload["accessToken"])
    )
    assert wrong_identity["statusCode"] == 403


def test_agent_decisions_are_authenticated_content_minimised_and_dashboard_visible(
    monkeypatch: Any,
) -> None:
    """A host can prove outcomes without supplying tenant, policy or raw content."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-decision-proof"
    token = "synthetic-agent-session-token-1234"  # noqa: S105 - synthetic test credential
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant, "status": "active"}
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "host": "claude-code",
            "status": "connected",
            "project_root": "/synthetic/project",
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "POLICY", "policy-a")
        | {"id": "policy-a", "name": "Safe", "version": 7}
    )
    table.put_item(
        Item=module._item_key(tenant, "GROUP", "group-a")
        | {
            "id": "group-a",
            "policyId": "policy-a",
            "agent_keys": ["dep-a:agent-a"],
        }
    )
    table.put_item(
        Item={
            "pk": module._token_key("AGENT_SESSION", token),
            "sk": "SESSION",
            "tenant_id": tenant,
            "deployment_id": "dep-a",
            "agent_id": "agent-a",
            "project_root_hash": hashlib.sha256(b"/synthetic/project").hexdigest(),
            "expires_at": int(time.time()) + 600,
        }
    )
    body = {
        "decisionId": "a" * 64,
        "source": "claude_native",
        "toolName": "Bash",
        "decision": "approval_required",
        "resourceKind": "shell_command",
        "reasonCode": "approval_rule",
        "actionDigest": "d" * 64,
    }
    recorded = _invoke(
        module,
        _event("/agent/dep-a/agent-a/decisions", "POST", body=body, token=token),
    )
    assert recorded["statusCode"] == 202
    assert json.loads(recorded["body"]) == {
        "accepted": True,
        "duplicate": False,
        "decisionId": "a" * 64,
    }
    stored = table.items[(f"TENANT#{tenant}", f"DECISION#dep-a:agent-a:{'a' * 64}")]
    assert stored["policy_id"] == "policy-a"
    assert stored["policy_version"] == 7
    assert stored["reported_by_agent"] is True
    assert stored["action_digest"] == "d" * 64
    assert stored["timeline_pk"] == f"TENANT#{tenant}#DECISION"
    assert stored["timeline_sk"].endswith(f"#dep-a:agent-a:{'a' * 64}")
    assert "command" not in stored and "path" not in stored and "prompt" not in stored

    duplicate = _invoke(
        module,
        _event("/agent/dep-a/agent-a/decisions", "POST", body=body, token=token),
    )
    assert duplicate["statusCode"] == 202
    assert json.loads(duplicate["body"])["duplicate"] is True
    legacy_body = {key: value for key, value in body.items() if key != "actionDigest"}
    legacy_body["decisionId"] = "e" * 64
    legacy = _invoke(
        module,
        _event("/agent/dep-a/agent-a/decisions", "POST", body=legacy_body, token=token),
    )
    assert legacy["statusCode"] == 202
    del table.items[(f"TENANT#{tenant}", f"DECISION#dep-a:agent-a:{'e' * 64}")]
    invalid_digest = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/decisions",
            "POST",
            body={**body, "decisionId": "f" * 64, "actionDigest": "invalid"},
            token=token,
        ),
    )
    assert invalid_digest["statusCode"] == 400
    conflict = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/decisions",
            "POST",
            body={**body, "decision": "denied"},
            token=token,
        ),
    )
    assert conflict["statusCode"] == 409
    raw_content = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/decisions",
            "POST",
            body={**body, "decisionId": "b" * 64, "command": "secret command"},
            token=token,
        ),
    )
    assert raw_content["statusCode"] == 400
    wrong_agent = _invoke(
        module,
        _event("/agent/dep-a/other-agent/decisions", "POST", body=body, token=token),
    )
    assert wrong_agent["statusCode"] == 403
    table.put_item(
        Item=module._item_key(tenant, "GROUP", "group-conflict")
        | {
            "id": "group-conflict",
            "policyId": "policy-a",
            "agent_keys": ["dep-a:agent-a"],
        }
    )
    conflicting_assignment = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/decisions",
            "POST",
            body={**body, "decisionId": "c" * 64},
            token=token,
        ),
    )
    assert conflicting_assignment["statusCode"] == 403

    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "operator",
    }
    dashboard = _invoke(module, _event("/dashboard", "GET", claims=claims))
    snapshot = json.loads(dashboard["body"])
    assert snapshot["decisionsToday"] == 1
    assert snapshot["decisionCountsTruncated"] is False
    assert snapshot["deniedToday"] == 0
    assert snapshot["recentAudit"][0] == {
        "id": "a" * 64,
        "timestamp": snapshot["recentAudit"][0]["timestamp"],
        "agent": "agent-a",
        "tool": "Bash",
        "decision": "approval_required",
        "reason": "Interactive approval required",
        "resource": "Shell command",
        "source": "claude_native",
        "deploymentId": "dep-a",
        "policyId": "policy-a",
        "policyVersion": 7,
        "actionDigest": "d" * 64,
        "reportedByAgent": True,
    }


def test_agent_heartbeat_rotates_session_near_expiry(monkeypatch: Any) -> None:
    """A live agent receives a replacement bearer before session expiry."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-renewal"
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant, "status": "active"}
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "tenant_id": tenant,
            "status": "offline",
            "project_root": "/synthetic/project",
        }
    )
    claims = {"custom:tenant_id": tenant, "cognito:groups": ["platform-admin"], "sub": "operator"}
    issued = _invoke(
        module,
        _event(
            "/enterprise/agents/bootstrap",
            "POST",
            body={"deploymentId": "dep-a", "agentId": "agent-a"},
            claims=claims,
        ),
    )
    bootstrap = json.loads(issued["body"])["bootstrapToken"]
    enrolled = _invoke(
        module,
        _event(
            "/agent/enroll",
            "POST",
            body={"bootstrapToken": bootstrap, "projectRoot": "/synthetic/project"},
        ),
    )
    old_token = json.loads(enrolled["body"])["accessToken"]
    session_key = {"pk": module._token_key("AGENT_SESSION", old_token), "sk": "SESSION"}
    session = table.get_item(Key=session_key)["Item"]
    session["expires_at"] = int(time.time()) + 100
    session["ttl"] = session["expires_at"]
    table.put_item(Item=session)

    renewed = _invoke(module, _event("/agent/dep-a/agent-a/heartbeat", "POST", token=old_token))
    assert renewed["statusCode"] == 200
    renewed_payload = json.loads(renewed["body"])
    new_token = renewed_payload["accessToken"]
    assert new_token != old_token
    assert renewed_payload["expiresAt"] > session["expires_at"]

    old_replay = _invoke(module, _event("/agent/dep-a/agent-a/heartbeat", "POST", token=old_token))
    assert old_replay["statusCode"] == 403
    still_live = _invoke(module, _event("/agent/dep-a/agent-a/heartbeat", "POST", token=new_token))
    assert still_live["statusCode"] == 200


def test_agent_verification_requires_every_operational_prerequisite(monkeypatch: Any) -> None:
    """The AWS UI verification endpoint must not equate existence with readiness."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-verify"
    now = int(time.time())
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "status": "connected",
            "expires_at": now + 300,
            "emergencyStop": False,
            "host": "Claude Code",
            "project_root": "/synthetic/project",
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "POLICY", "policy-a") | {"id": "policy-a", "version": 1}
    )
    table.put_item(
        Item=module._item_key(tenant, "GROUP", "group-a")
        | {"id": "group-a", "policyId": "policy-a", "agent_keys": ["dep-a:agent-a"]}
    )
    group = table.get_item(Key=module._item_key(tenant, "GROUP", "group-a"))["Item"]
    groups = [group]
    monkeypatch.setattr(
        module,
        "_list",
        lambda _tenant, kind, **_kwargs: list(groups) if kind == "GROUP" else [],
    )
    claims = {"custom:tenant_id": tenant, "cognito:groups": ["platform-admin"], "sub": "operator"}

    verified = _invoke(
        module, _event("/enterprise/agents/dep-a/agent-a/verify", "GET", claims=claims)
    )
    payload = json.loads(verified["body"])
    assert payload["verified"] is True
    assert all(check["passed"] for check in payload["checks"].values())
    assert payload["host"] == "Claude Code"
    assert payload["groups"] == ["group-a"]
    assert payload["policyId"] == "policy-a"
    assert payload["policyVersion"] == 1

    group["agent_keys"] = []
    unassigned = _invoke(
        module, _event("/enterprise/agents/dep-a/agent-a/verify", "GET", claims=claims)
    )
    unassigned_payload = json.loads(unassigned["body"])
    assert unassigned_payload["verified"] is False
    assert unassigned_payload["policyId"] is None
    assert unassigned_payload["policyVersion"] is None
    assert unassigned_payload["checks"]["policyAssignment"]["passed"] is False

    agent = table.get_item(Key=module._item_key(tenant, "AGENT", "dep-a:agent-a"))["Item"]
    agent["status"] = "offline"
    agent["expires_at"] = now - 1
    table.put_item(Item=agent)
    offline = _invoke(
        module, _event("/enterprise/agents/dep-a/agent-a/verify", "GET", claims=claims)
    )
    offline_payload = json.loads(offline["body"])
    assert offline_payload["verified"] is False
    assert offline_payload["checks"]["heartbeat"]["passed"] is False
    assert offline_payload["checks"]["heartbeat"]["detail"] == ("Agent is offline or disconnected.")

    group["agent_keys"] = ["dep-a:agent-a"]
    duplicate_group = dict(group)
    duplicate_group["id"] = "group-duplicate"
    groups.append(duplicate_group)
    conflicting = json.loads(
        _invoke(
            module,
            _event("/enterprise/agents/dep-a/agent-a/verify", "GET", claims=claims),
        )["body"]
    )
    assert conflicting["checks"]["policyAssignment"] == {
        "passed": False,
        "detail": "Conflicting policy-group assignments must be resolved.",
    }
    agent_token = "synthetic-agent-session-conflict"  # noqa: S105 - synthetic test bearer
    table.put_item(
        Item={
            "pk": module._token_key("AGENT_SESSION", agent_token),
            "sk": "SESSION",
            "tenant_id": tenant,
            "deployment_id": "dep-a",
            "agent_id": "agent-a",
            "project_root_hash": hashlib.sha256(b"/synthetic/project").hexdigest(),
            "expires_at": now + 300,
        }
    )
    effective = _invoke(
        module,
        _event("/agent/dep-a/agent-a/effective-policy", "GET", token=agent_token),
    )
    assert effective["statusCode"] == 409
    assert json.loads(effective["body"])["error"] == (
        "agent has conflicting policy-group assignments"
    )

    missing = json.loads(
        _invoke(
            module,
            _event("/enterprise/agents/dep-a/missing/verify", "GET", claims=claims),
        )["body"]
    )
    assert missing["checks"]["registered"] == {
        "passed": False,
        "detail": "Agent is not registered to this deployment.",
    }
    assert missing["checks"]["heartbeat"] == {
        "passed": False,
        "detail": "Agent is not registered to this deployment.",
    }


def test_list_reads_every_dynamodb_page_before_policy_verification(monkeypatch: Any) -> None:
    module, _table = _load_handler(monkeypatch)
    calls: list[dict[str, Any]] = []

    def paginated_query(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        if "ExclusiveStartKey" not in kwargs:
            return {
                "Items": [{"id": "group-a"}],
                "LastEvaluatedKey": {"pk": "TENANT#tenant-a", "sk": "GROUP#group-a"},
            }
        return {"Items": [{"id": "group-b"}]}

    monkeypatch.setattr(module.TABLE, "query", paginated_query)

    assert module._list("tenant-a", "GROUP", consistent_read=True) == [
        {"id": "group-a"},
        {"id": "group-b"},
    ]
    assert calls[1]["ExclusiveStartKey"] == {
        "pk": "TENANT#tenant-a",
        "sk": "GROUP#group-a",
    }
    assert all(call["Limit"] == module._LIST_PAGE_ITEM_LIMIT for call in calls)
    assert all(call["ConsistentRead"] is True for call in calls)


def test_list_fails_closed_at_page_and_item_bounds(monkeypatch: Any) -> None:
    module, _table = _load_handler(monkeypatch)
    page_calls = 0

    def endless_query(**_kwargs: Any) -> dict[str, Any]:
        nonlocal page_calls
        page_calls += 1
        return {
            "Items": [{"id": f"group-{page_calls}"}],
            "LastEvaluatedKey": {"pk": "tenant", "sk": f"group-{page_calls}"},
        }

    monkeypatch.setattr(module.TABLE, "query", endless_query)
    monkeypatch.setattr(module, "_MAX_LIST_PAGES", 2)
    with pytest.raises(RuntimeError, match="bounded page limit"):
        module._list("tenant-a", "GROUP")
    assert page_calls == 2

    monkeypatch.setattr(
        module.TABLE,
        "query",
        lambda **_kwargs: {"Items": [{"id": "group-a"}, {"id": "group-b"}]},
    )
    monkeypatch.setattr(module, "_MAX_LIST_ITEMS", 1)
    with pytest.raises(RuntimeError, match="bounded item limit"):
        module._list("tenant-a", "GROUP")


def test_decision_window_is_recent_bounded_and_reports_truncation(monkeypatch: Any) -> None:
    module, _table = _load_handler(monkeypatch)
    calls: list[dict[str, Any]] = []

    def decision_query(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        if kwargs.get("IndexName") == module._DECISION_TIMELINE_INDEX:
            return {
                "Items": [
                    {"pk": "tenant", "sk": "DECISION#new", "observed_at": 3},
                    {"pk": "tenant", "sk": "DECISION#duplicate", "observed_at": 2},
                ],
                "LastEvaluatedKey": {"timeline_pk": "tenant", "timeline_sk": "2"},
            }
        return {
            "Items": [
                {"pk": "tenant", "sk": "DECISION#duplicate", "observed_at": 2},
                {"pk": "tenant", "sk": "DECISION#legacy", "observed_at": 1},
            ]
        }

    monkeypatch.setattr(module.TABLE, "query", decision_query)

    decisions, truncated = module._decision_window("tenant-a")

    assert [item["sk"] for item in decisions] == [
        "DECISION#new",
        "DECISION#duplicate",
        "DECISION#legacy",
    ]
    assert truncated is True
    assert calls[0]["IndexName"] == "DecisionTimeline"
    assert calls[0]["ScanIndexForward"] is False
    assert all(call["Limit"] == module._DECISION_WINDOW_LIMIT for call in calls)


def test_agent_verification_uses_one_clock_snapshot(monkeypatch: Any) -> None:
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-a"
    checked_at = 2_000
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "status": "connected",
            "expires_at": checked_at + 1,
        }
    )
    table.put_item(Item=module._item_key(tenant, "POLICY", "policy-a") | {"id": "policy-a"})
    group = {
        "id": "group-a",
        "policyId": "policy-a",
        "agent_keys": ["dep-a:agent-a"],
    }
    monkeypatch.setattr(
        module,
        "_list",
        lambda _tenant, kind, **_kwargs: [group] if kind == "GROUP" else [],
    )
    clock_reads = 0

    def advancing_clock() -> int:
        nonlocal clock_reads
        value = checked_at + clock_reads
        clock_reads += 1
        return value

    monkeypatch.setattr(module.time, "time", advancing_clock)

    result = module._verify_agent(tenant, "dep-a", "agent-a")

    assert result["checkedAt"] == checked_at
    assert result["checks"]["heartbeat"] == {
        "passed": True,
        "detail": "Heartbeat is current and the session is connected.",
    }
    assert clock_reads == 1


def test_fleet_emergency_stop_is_reversible_durable_and_enforced(monkeypatch: Any) -> None:
    """The top-level incident control must stop every enrolled agent boundary."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-fleet-stop"
    now = int(time.time())
    monkeypatch.setattr(
        module,
        "_list",
        lambda selected_tenant, kind, **_kwargs: [
            dict(item)
            for (pk, sk), item in table.items.items()
            if pk == f"TENANT#{selected_tenant}" and sk.startswith(f"{kind}#")
        ],
    )
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "status": "connected",
            "expires_at": now + 300,
            "emergencyStop": False,
            "host": "Claude Code",
            "project_root": "/synthetic/project",
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "POLICY", "policy-a")
        | {"id": "policy-a", "version": 1, "configuration": {"policy": {}}}
    )
    table.put_item(
        Item=module._item_key(tenant, "GROUP", "group-a")
        | {"id": "group-a", "policyId": "policy-a", "agent_keys": ["dep-a:agent-a"]}
    )
    session_value = "synthetic-agent-session"
    table.put_item(
        Item={
            "pk": module._token_key("AGENT_SESSION", session_value),
            "sk": "SESSION",
            "tenant_id": tenant,
            "deployment_id": "dep-a",
            "agent_id": "agent-a",
            "project_root_hash": hashlib.sha256(b"/synthetic/project").hexdigest(),
            "expires_at": now + 900,
        }
    )
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "operator-a",
    }
    audit_events: list[tuple[str, str, str, dict[str, Any]]] = []
    monkeypatch.setattr(
        module,
        "_audit",
        lambda audited_tenant, event, actor, evidence: audit_events.append(
            (audited_tenant, event, actor, evidence)
        ),
    )

    initial = _invoke(module, _event("/dashboard", "GET", claims=claims))
    assert json.loads(initial["body"])["emergencyStop"] is False
    unauthorized = _invoke(
        module,
        _event(
            "/emergency-stop",
            "POST",
            body={"active": True},
            claims={"custom:tenant_id": tenant, "sub": "viewer"},
        ),
    )
    assert unauthorized["statusCode"] == 403

    activated = _invoke(
        module,
        _event("/emergency-stop", "POST", body={"active": True}, claims=claims),
    )
    activated_payload = json.loads(activated["body"])
    assert activated_payload["emergencyStop"] is True
    assert activated_payload["posture"] == "critical"
    assert (
        table.get_item(Key=module._item_key(tenant, "CONTROL", "fleet-emergency-stop"))["Item"][
            "active"
        ]
        is True
    )
    denied = _invoke(
        module,
        _event("/agent/dep-a/agent-a/effective-policy", "GET", token=session_value),
    )
    denied_payload = json.loads(denied["body"])
    assert denied["statusCode"] == 409
    assert denied_payload == {
        "error": "fleet-wide emergency stop is active",
        "emergencyStop": True,
        "scope": "fleet",
    }
    verification = _invoke(
        module,
        _event("/enterprise/agents/dep-a/agent-a/verify", "GET", claims=claims),
    )
    verification_payload = json.loads(verification["body"])
    assert verification_payload["verified"] is False
    assert verification_payload["checks"]["emergencyStop"] == {
        "passed": False,
        "detail": "A fleet-wide emergency stop is active.",
    }
    narrower_stop = _invoke(
        module,
        _event(
            "/enterprise/agents/dep-a/agent-a/emergency-stop",
            "POST",
            body={"active": True},
            claims=claims,
        ),
    )
    assert narrower_stop["statusCode"] == 200

    cleared = _invoke(
        module,
        _event("/api/emergency-stop", "POST", body={"active": False}, claims=claims),
    )
    assert json.loads(cleared["body"])["emergencyStop"] is False
    still_denied = _invoke(
        module,
        _event("/agent/dep-a/agent-a/effective-policy", "GET", token=session_value),
    )
    assert still_denied["statusCode"] == 409
    assert json.loads(still_denied["body"])["scope"] == "agent"
    narrower_clear = _invoke(
        module,
        _event(
            "/enterprise/agents/dep-a/agent-a/emergency-stop",
            "POST",
            body={"active": False},
            claims=claims,
        ),
    )
    assert narrower_clear["statusCode"] == 200
    restored = _invoke(
        module,
        _event("/agent/dep-a/agent-a/effective-policy", "GET", token=session_value),
    )
    assert restored["statusCode"] == 200
    fleet_events = [event for event in audit_events if event[1] == "fleet_emergency_stop"]
    assert [event[3]["active"] for event in fleet_events] == [True, False]


def test_deployment_configuration_rollout_tracks_drift_and_activation(monkeypatch: Any) -> None:
    """The AWS control plane exposes the rollout states consumed by the UI."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-rollout"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    claims = {"custom:tenant_id": tenant, "cognito:groups": ["platform-admin"], "sub": "operator"}
    template = _invoke(
        module,
        _event(
            "/enterprise/templates",
            "POST",
            body={
                "templateId": "template-a",
                "name": "Safe",
                "configuration": {"runtime": {"maxActions": 5}},
            },
            claims=claims,
        ),
    )
    assert template["statusCode"] == 201
    staged = _invoke(
        module,
        _event(
            "/enterprise/deployment-config",
            "POST",
            body={"deploymentId": "deployment-a", "templateId": "template-a"},
            claims=claims,
        ),
    )
    assert staged["statusCode"] == 201
    assert json.loads(staged["body"])["drifted"] is True
    canary = _invoke(
        module,
        _event(
            "/enterprise/deployment-config/batch-rollout",
            "POST",
            body={"deploymentIds": ["deployment-a"], "state": "canary", "percentage": 10},
            claims=claims,
        ),
    )
    assert json.loads(canary["body"])["items"][0]["rolloutState"] == "canary"
    active = _invoke(
        module,
        _event(
            "/enterprise/deployment-config/batch-rollout",
            "POST",
            body={"deploymentIds": ["deployment-a"], "state": "active", "percentage": 100},
            claims=claims,
        ),
    )
    activated = json.loads(active["body"])["items"][0]
    assert activated["drifted"] is False
    assert activated["appliedHash"] == activated["desiredHash"]


def test_tenant_summary_exposes_only_safe_trial_metadata(monkeypatch: Any) -> None:
    """The operator tenant summary is scoped and excludes raw tenant fields."""
    module, table = _load_handler(monkeypatch)
    tenant = "trial-tenant"
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root")
        | {
            "id": tenant,
            "status": "active",
            "trial": True,
            "trial_expires_at": 1_800_000_000,
            "created_at": 1_700_000_000,
            "email": "must-not-be-returned@example.test",
        }
    )
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "operator",
    }
    response = _invoke(module, _event("/enterprise/tenant", "GET", claims=claims))
    assert response["statusCode"] == 200
    payload = json.loads(response["body"])
    assert payload == {
        "id": tenant,
        "status": "active",
        "trial": True,
        "trialExpiresAt": 1_800_000_000,
        "createdAt": 1_700_000_000,
    }
    assert "email" not in payload


def test_remote_approval_requires_exact_binding_and_is_single_use(monkeypatch: Any) -> None:
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-a"
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant, "status": "active"}
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "tenant_id": tenant,
            "status": "offline",
            "project_root": "/synthetic/project",
        }
    )
    claims = {"custom:tenant_id": tenant, "cognito:groups": ["platform-admin"], "sub": "operator"}
    issued = _invoke(
        module,
        _event(
            "/enterprise/agents/bootstrap",
            "POST",
            body={"deploymentId": "dep-a", "agentId": "agent-a"},
            claims=claims,
        ),
    )
    bootstrap = json.loads(issued["body"])["bootstrapToken"]
    enrolled = _invoke(
        module,
        _event(
            "/agent/enroll",
            "POST",
            body={"bootstrapToken": bootstrap, "projectRoot": "/synthetic/project"},
        ),
    )
    token = json.loads(enrolled["body"])["accessToken"]
    grant = {
        "approvalId": "approval-a",
        "agentKey": "dep-a:agent-a",
        "toolName": "write",
        "proposalId": "proposal-a",
        "taskId": "task-a",
        "principalId": "principal-a",
        "actionHash": "hash-a",
    }
    created = _invoke(module, _event("/enterprise/approvals", "POST", body=grant, claims=claims))
    assert created["statusCode"] == 201
    duplicate_grant = _invoke(
        module, _event("/enterprise/approvals", "POST", body=grant, claims=claims)
    )
    assert duplicate_grant["statusCode"] == 409
    consume = {
        "approval_id": "approval-a",
        "tool_name": "write",
        "proposal_id": "proposal-a",
        "task_id": "task-a",
        "principal_id": "principal-a",
        "action_hash": "hash-a",
    }
    accepted = _invoke(
        module, _event("/agent/dep-a/agent-a/approvals/consume", "POST", body=consume, token=token)
    )
    assert json.loads(accepted["body"])["approved"] is True
    replay = _invoke(
        module, _event("/agent/dep-a/agent-a/approvals/consume", "POST", body=consume, token=token)
    )
    assert json.loads(replay["body"])["approved"] is False
    wrong = dict(consume, action_hash="different")
    assert (
        json.loads(
            _invoke(
                module,
                _event("/agent/dep-a/agent-a/approvals/consume", "POST", body=wrong, token=token),
            )["body"]
        )["approved"]
        is False
    )


def test_operator_approval_queue_is_action_bound_audited_and_fail_closed(
    monkeypatch: Any,
) -> None:
    """An agent request must need one live operator decision before consumption."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-approval-queue"
    agent_key = "dep-a:agent-a"
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant, "status": "active"}
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", agent_key)
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "tenant_id": tenant,
            "host": "Claude Code",
            "status": "connected",
            "expires_at": int(time.time()) + 300,
            "project_root": "/synthetic/project",
        }
    )
    token = "synthetic-agent-session"  # noqa: S105 - synthetic test credential
    table.put_item(
        Item={
            "pk": module._token_key("AGENT_SESSION", token),
            "sk": "SESSION",
            "tenant_id": tenant,
            "deployment_id": "dep-a",
            "agent_id": "agent-a",
            "project_root_hash": hashlib.sha256(b"/synthetic/project").hexdigest(),
            "expires_at": int(time.time()) + 300,
        }
    )
    audit_events: list[tuple[str, str, dict[str, Any]]] = []
    monkeypatch.setattr(
        module,
        "_audit",
        lambda _tenant, event_type, actor, payload: audit_events.append(
            (event_type, actor, payload)
        ),
    )
    request = {
        "approval_id": "approval-pending-a",
        "tool_name": "publish_artifact",
        "proposal_id": "proposal-a",
        "task_id": "task-a",
        "principal_id": "principal-a",
        "action_hash": "a" * 64,
        "risk_class": "external_egress",
        "resource_ids": ["artifact:synthetic-report"],
        "review_ttl_seconds": 900,
        "grant_ttl_seconds": 120,
        # This value is deliberately ignored: agent identity is session-owned.
        "agent_key": "dep-forged:agent-forged",
    }
    created = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/approvals/request",
            "POST",
            body=request,
            token=token,
        ),
    )
    assert created["statusCode"] == 201
    created_body = json.loads(created["body"])
    assert created_body["status"] == "pending"
    assert created_body["agentKey"] == agent_key
    assert created_body["resourceIds"] == ["artifact:synthetic-report"]
    duplicate = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/approvals/request",
            "POST",
            body=request,
            token=token,
        ),
    )
    assert duplicate["statusCode"] == 409
    malformed = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/approvals/request",
            "POST",
            body=dict(request, approval_id="approval-malformed", risk_class="allow_all"),
            token=token,
        ),
    )
    assert malformed["statusCode"] == 400
    assert (
        f"TENANT#{tenant}",
        "APPROVAL#approval-malformed",
    ) not in table.items

    operator_claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "operator-a",
    }
    dashboard = _invoke(module, _event("/dashboard", "GET", claims=operator_claims))
    assert json.loads(dashboard["body"])["approvalQueue"] == 1
    listed = _invoke(module, _event("/enterprise/approvals", "GET", claims=operator_claims))
    assert json.loads(listed["body"])["items"][0]["status"] == "pending"

    unauthorised = _invoke(
        module,
        _event(
            "/enterprise/approvals/approval-pending-a/decision",
            "POST",
            body={"decision": "approved", "reason": "Validated release destination"},
            claims={"custom:tenant_id": tenant, "sub": "read-only-operator"},
        ),
    )
    assert unauthorised["statusCode"] == 403
    approved = _invoke(
        module,
        _event(
            "/enterprise/approvals/approval-pending-a/decision",
            "POST",
            body={"decision": "approved", "reason": "Validated release destination"},
            claims=operator_claims,
        ),
    )
    assert approved["statusCode"] == 200
    assert json.loads(approved["body"])["status"] == "approved"
    assert (
        json.loads(_invoke(module, _event("/dashboard", "GET", claims=operator_claims))["body"])[
            "approvalQueue"
        ]
        == 0
    )
    replayed_decision = _invoke(
        module,
        _event(
            "/enterprise/approvals/approval-pending-a/decision",
            "POST",
            body={"decision": "denied", "reason": "Too late"},
            claims=operator_claims,
        ),
    )
    assert replayed_decision["statusCode"] == 409

    consume = {
        "approval_id": request["approval_id"],
        "tool_name": request["tool_name"],
        "proposal_id": request["proposal_id"],
        "task_id": request["task_id"],
        "principal_id": request["principal_id"],
        "action_hash": request["action_hash"],
    }
    consumed = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/approvals/consume",
            "POST",
            body=consume,
            token=token,
        ),
    )
    assert json.loads(consumed["body"])["approved"] is True
    assert (
        json.loads(
            _invoke(
                module,
                _event(
                    "/agent/dep-a/agent-a/approvals/consume",
                    "POST",
                    body=consume,
                    token=token,
                ),
            )["body"]
        )["approved"]
        is False
    )
    assert [event[0] for event in audit_events].count("approval_requested") == 1
    assert [event[0] for event in audit_events].count("approval_decided") == 1
    assert (
        next(event[2]["decision"] for event in audit_events if event[0] == "approval_decided")
        == "approved"
    )
    assert [event[0] for event in audit_events].count("approval_consumed") == 1

    denied_request = dict(
        request,
        approval_id="approval-denied-a",
        proposal_id="proposal-denied-a",
        action_hash="b" * 64,
    )
    assert (
        _invoke(
            module,
            _event(
                "/agent/dep-a/agent-a/approvals/request",
                "POST",
                body=denied_request,
                token=token,
            ),
        )["statusCode"]
        == 201
    )
    denied = _invoke(
        module,
        _event(
            "/enterprise/approvals/approval-denied-a/decision",
            "POST",
            body={"decision": "denied", "reason": "Destination is not approved"},
            claims=operator_claims,
        ),
    )
    assert json.loads(denied["body"])["status"] == "denied"
    denied_consume = dict(
        consume,
        approval_id="approval-denied-a",
        proposal_id="proposal-denied-a",
        action_hash="b" * 64,
    )
    assert (
        json.loads(
            _invoke(
                module,
                _event(
                    "/agent/dep-a/agent-a/approvals/consume",
                    "POST",
                    body=denied_consume,
                    token=token,
                ),
            )["body"]
        )["approved"]
        is False
    )

    expired = dict(
        table.items[(f"TENANT#{tenant}", "APPROVAL#approval-denied-a")],
        id="approval-expired-a",
        sk="APPROVAL#approval-expired-a",
        status="pending",
        expires_at=int(time.time()) - 1,
    )
    table.put_item(Item=expired)
    assert (
        json.loads(_invoke(module, _event("/dashboard", "GET", claims=operator_claims))["body"])[
            "approvalQueue"
        ]
        == 0
    )


def test_unprovisioned_tenant_claim_fails_closed(monkeypatch: Any) -> None:
    """A signed claim cannot create an implicit tenant boundary."""
    module, _table = _load_handler(monkeypatch)
    response = _invoke(
        module,
        _event(
            "/enterprise/agents",
            "GET",
            claims={"custom:tenant_id": "tenant-not-provisioned", "sub": "operator"},
        ),
    )
    assert response["statusCode"] == 403


def test_cognito_subject_mapping_resolves_only_a_provisioned_trial(monkeypatch: Any) -> None:
    """Self-signup tenancy is server-mapped and remains fail-closed."""
    module, table = _load_handler(monkeypatch)
    table.put_item(Item={"pk": "USER#subject-a", "sk": "TENANT", "tenant_id": "trial-a"})
    table.put_item(Item=module._item_key("trial-a", "TENANT", "root") | {"id": "trial-a"})
    event = _event("/enterprise/agents", "GET", claims={"sub": "subject-a"})
    assert module._tenant(event) == "trial-a"
    assert (
        _invoke(module, _event("/enterprise/agents", "GET", claims={"sub": "unknown"}))[
            "statusCode"
        ]
        == 403
    )


def test_trial_provisioner_builds_restrictive_credential_free_records(monkeypatch: Any) -> None:
    """The signup defaults are isolated, bounded, and safe to publish."""
    # The pure policy builder must remain importable without AWS dependencies;
    # boto3 is required only when the deployed Lambda handler executes.
    monkeypatch.setitem(sys.modules, "boto3", None)
    path = Path(__file__).parents[1] / "infra/aws-control-plane/lambda/trial_onboarding.py"
    spec = importlib.util.spec_from_file_location("aai_trial_onboarding", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    records = module.build_trial_records("subject-a", "trial@example.test", now=100, trial_days=14)
    assert len(records) == 5
    assert records[0]["pk"] == "USER#subject-a"
    tenant = records[0]["tenant_id"]
    assert tenant.startswith("trial-") and len(tenant) == 38
    assert records[1]["pk"] == f"TENANT#{tenant}"
    policy = next(item for item in records if item["sk"] == "POLICY#policy-safe-default")
    assert policy["configuration"]["policy"]["denyByDefault"] is True
    assert policy["configuration"]["runtime"]["maxActions"] == 25
    assert policy["configuration"]["audit"]["captureToolContent"] is False
    assert policy["configuration"]["claudeCode"]["allowedCommandPatterns"] == [
        r"^pwd$",
        r"^ls$",
        r"^git[ \t]+status$",
        r"^git[ \t]+status[ \t]+--short$",
        r"^git[ \t]+diff[ \t]+--stat$",
        r"^git[ \t]+log[ \t]+--oneline$",
    ]
    assert all("credential" not in str(item).lower() for item in records)


def test_demo_seed_uses_the_same_narrow_native_read_commands(monkeypatch: Any) -> None:
    """Demo and trial tenants must start with one documented native-safe contract."""
    module, table = _load_handler(monkeypatch)

    module._seed("tenant-new")

    policy = table.items[("TENANT#tenant-new", "POLICY#policy-safe-default")]
    assert policy["configuration"]["claudeCode"]["allowedCommandPatterns"] == [
        r"^pwd$",
        r"^ls$",
        r"^git[ \t]+status$",
        r"^git[ \t]+status[ \t]+--short$",
        r"^git[ \t]+diff[ \t]+--stat$",
        r"^git[ \t]+log[ \t]+--oneline$",
    ]
