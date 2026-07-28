"""Contract tests for the deployed AWS control-plane Lambda boundary."""

import importlib.util
import json
import sys
import time
import types
from decimal import Decimal
from pathlib import Path
from typing import Any, cast


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
) -> dict[str, Any]:
    headers = {"authorization": f"Bearer {token}"} if token else {}
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


def test_agent_enrollment_is_one_time_and_identity_bound(monkeypatch: Any) -> None:
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-a"
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant, "status": "active"}
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {"id": "agent-a", "deployment_id": "dep-a", "tenant_id": tenant, "status": "offline"}
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
    enrolled = _invoke(
        module,
        _event("/agent/enroll", "POST", body={"bootstrapToken": bootstrap, "host": "Claude Code"}),
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
    assert "command" not in stored and "path" not in stored and "prompt" not in stored

    duplicate = _invoke(
        module,
        _event("/agent/dep-a/agent-a/decisions", "POST", body=body, token=token),
    )
    assert duplicate["statusCode"] == 202
    assert json.loads(duplicate["body"])["duplicate"] is True
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

    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "operator",
    }
    dashboard = _invoke(module, _event("/dashboard", "GET", claims=claims))
    snapshot = json.loads(dashboard["body"])
    assert snapshot["decisionsToday"] == 1
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
        | {"id": "agent-a", "deployment_id": "dep-a", "tenant_id": tenant, "status": "offline"}
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
    enrolled = _invoke(module, _event("/agent/enroll", "POST", body={"bootstrapToken": bootstrap}))
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
    monkeypatch.setattr(
        module,
        "_list",
        lambda _tenant, kind: [group] if kind == "GROUP" else [],
    )
    claims = {"custom:tenant_id": tenant, "cognito:groups": ["platform-admin"], "sub": "operator"}

    verified = _invoke(
        module, _event("/enterprise/agents/dep-a/agent-a/verify", "GET", claims=claims)
    )
    payload = json.loads(verified["body"])
    assert payload["verified"] is True
    assert all(check["passed"] for check in payload["checks"].values())

    group["agent_keys"] = []
    unassigned = _invoke(
        module, _event("/enterprise/agents/dep-a/agent-a/verify", "GET", claims=claims)
    )
    unassigned_payload = json.loads(unassigned["body"])
    assert unassigned_payload["verified"] is False
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


def test_fleet_emergency_stop_is_reversible_durable_and_enforced(monkeypatch: Any) -> None:
    """The top-level incident control must stop every enrolled agent boundary."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-fleet-stop"
    now = int(time.time())
    monkeypatch.setattr(
        module,
        "_list",
        lambda selected_tenant, kind: [
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
        | {"id": "agent-a", "deployment_id": "dep-a", "tenant_id": tenant, "status": "offline"}
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
    enrolled = _invoke(module, _event("/agent/enroll", "POST", body={"bootstrapToken": bootstrap}))
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
    assert all("credential" not in str(item).lower() for item in records)
