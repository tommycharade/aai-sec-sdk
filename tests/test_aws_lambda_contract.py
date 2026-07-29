"""Contract tests for the deployed AWS control-plane Lambda boundary."""

import base64
import hashlib
import importlib.util
import json
import re
import sys
import time
import types
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest

from agentic_security import (
    AgentHost,
    ManagedConfigurationCompiler,
    ManagedDeploymentPackage,
    ManagedExecutableRequirement,
    ManagedPlatform,
    ManagedPolicyIntent,
    NativeActionDecision,
    NativeActionRule,
)


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
        condition = kwargs.get("ConditionExpression")
        if condition:
            values = kwargs.get("ExpressionAttributeValues", {})
            if ":expected_revision" in values:
                if self.items.get(key, {}).get("revision") != values[":expected_revision"]:
                    raise ConditionalFailure()
            elif condition == "attribute_not_exists(pk)" and key in self.items:
                raise ConditionalFailure()
            elif condition == "#state = :expected":
                if self.items.get(key, {}).get("state") != values.get(":expected"):
                    raise ConditionalFailure()
            elif "ownership_revision" in condition:
                current = self.items.get(key, {})
                if current.get("lifecycle_state") != values.get(":active"):
                    raise ConditionalFailure()
                if "attribute_not_exists(ownership_revision)" in condition:
                    if "ownership_revision" in current:
                        raise ConditionalFailure()
                elif current.get("ownership_revision") != values.get(":ownership_revision"):
                    raise ConditionalFailure()
            elif "lifecycle_state = :active" in condition:
                current = self.items.get(key, {})
                if current.get("lifecycle_state") != values.get(":active") or current.get(
                    "lifecycle_revision"
                ) != values.get(":revision"):
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
        if ":active" in ExpressionAttributeValues and ":one" in ExpressionAttributeValues:
            if "lifecycle_state" in item or "lifecycle_revision" in item:
                raise ConditionalFailure()
            item["lifecycle_state"] = ExpressionAttributeValues[":active"]
            item["lifecycle_revision"] = ExpressionAttributeValues[":one"]
            self.items[key] = item
            return {"Attributes": dict(item)}
        if ":nonce" in ExpressionAttributeValues and ":expires" in ExpressionAttributeValues:
            if item.get("expires_at", 0) <= ExpressionAttributeValues[":now"]:
                raise ConditionalFailure()
            item["attestation_nonce"] = ExpressionAttributeValues[":nonce"]
            item["attestation_nonce_expires_at"] = ExpressionAttributeValues[":expires"]
            self.items[key] = item
            return {"Attributes": dict(item)}
        if ":nonce" in ExpressionAttributeValues and ":expires" not in ExpressionAttributeValues:
            if (
                item.get("attestation_nonce") != ExpressionAttributeValues[":nonce"]
                or item.get("attestation_nonce_expires_at", 0) <= ExpressionAttributeValues[":now"]
            ):
                raise ConditionalFailure()
            item.pop("attestation_nonce", None)
            item.pop("attestation_nonce_expires_at", None)
            self.items[key] = item
            return {"Attributes": dict(item)}
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


def _decode_ddb_value(value: dict[str, Any]) -> Any:
    """Decode the low-level DynamoDB shape used by transaction contract tests."""
    if "S" in value:
        return value["S"]
    if "N" in value:
        number = Decimal(value["N"])
        return int(number) if number == number.to_integral_value() else number
    if "BOOL" in value:
        return value["BOOL"]
    if "NULL" in value:
        return None
    if "L" in value:
        return [_decode_ddb_value(item) for item in value["L"]]
    if "M" in value:
        return {key: _decode_ddb_value(item) for key, item in value["M"].items()}
    raise AssertionError(f"unsupported DynamoDB value: {value}")


class FakeDynamoClient:
    """Atomic DynamoDB transaction double with exact policy preconditions."""

    def __init__(self, table: FakeTable) -> None:
        self.table = table
        self.before_transaction: Any = None

    def transact_write_items(self, *, TransactItems: list[dict[str, Any]]) -> None:
        if callable(self.before_transaction):
            callback, self.before_transaction = self.before_transaction, None
            callback()
        snapshot = {key: dict(item) for key, item in self.table.items.items()}
        try:
            for operation in TransactItems:
                put = operation["Put"]
                record = {key: _decode_ddb_value(value) for key, value in put["Item"].items()}
                key = (record["pk"], record.get("sk", ""))
                existing = self.table.items.get(key)
                condition = put["ConditionExpression"]
                names = put.get("ExpressionAttributeNames", {})
                values = {
                    key: _decode_ddb_value(value)
                    for key, value in put.get("ExpressionAttributeValues", {}).items()
                }
                if condition == "attribute_not_exists(pk)":
                    permitted = existing is None
                else:
                    permitted = existing is not None
                    current = existing or {}
                    for clause in condition.split(" AND "):
                        if clause.startswith("attribute_not_exists("):
                            field = clause.removeprefix("attribute_not_exists(").removesuffix(")")
                            permitted = permitted and field not in current
                            continue
                        if " <> " in clause:
                            field_name, expected_name = clause.split(" <> ")
                            comparison = "not_equal"
                        elif " > " in clause:
                            field_name, expected_name = clause.split(" > ")
                            comparison = "greater_than"
                        else:
                            field_name, expected_name = clause.split(" = ")
                            comparison = "equal"
                        field = names.get(field_name, field_name)
                        if comparison == "not_equal":
                            permitted = permitted and current.get(field) != values[expected_name]
                        elif comparison == "greater_than":
                            permitted = permitted and current.get(field, 0) > values[expected_name]
                        else:
                            permitted = permitted and current.get(field) == values[expected_name]
                if not permitted:
                    raise ConditionalFailure()
                self.table.items[key] = record
        except Exception as error:
            self.table.items = snapshot
            if isinstance(error, ConditionalFailure):
                error.response = {"Error": {"Code": "TransactionCanceledException"}}
            raise


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
    boto3.client = (  # type: ignore[attr-defined]
        lambda service, *_args, **_kwargs: (
            FakeDynamoClient(table) if service == "dynamodb" else FakeS3()
        )
    )
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
    monkeypatch.setenv("ENTRA_STRONG_AUTH_ENFORCED", "false")
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


def _ownership(**changes: Any) -> dict[str, Any]:
    """Return complete synthetic accountable ownership for registration tests."""
    return {
        "ownerId": "owner-platform",
        "ownerName": "Platform owner",
        "businessContact": "platform@example.invalid",
        "criticality": "high",
        **changes,
    }


def _ownership_record(now: int, **changes: Any) -> dict[str, Any]:
    """Return stored ownership fields whose review is currently valid."""
    return {
        "owner_id": "owner-platform",
        "owner_name": "Platform owner",
        "business_contact": "platform@example.invalid",
        "team": "Platform",
        "environment": "prod",
        "ownership_criticality": "high",
        "ownership_reviewed_at": now,
        "ownership_review_due_at": now + 90 * 24 * 60 * 60,
        "ownership_reviewed_by": "synthetic-reviewer",
        "ownership_revision": 1,
        **changes,
    }


def _discovery_snapshot(
    source_kind: str,
    observations: list[dict[str, Any]],
    *,
    now: int,
    complete: bool = True,
    expected_revision: int = 0,
) -> dict[str, Any]:
    """Return one current synthetic discovery source snapshot."""
    return {
        "sourceKind": source_kind,
        "generation": f"generation-{source_kind}-{expected_revision + 1}",
        "expectedRevision": expected_revision,
        "observedAt": now,
        "expiresAt": now + 300,
        "complete": complete,
        "observations": observations,
    }


def _runtime_manifest(host: str = "claude-code") -> dict[str, Any]:
    """Return one synthetic deployment-owned approved runtime manifest."""
    return {
        "schemaVersion": 1,
        "sdkVersion": "1.1.0",
        "sdkRevision": "a" * 40,
        "sourceOriginDigest": "b" * 64,
        "packageDigest": "c" * 64,
        "gatewayDigest": "d" * 64,
        "hookDigest": "e" * 64,
        "host": host,
    }


def _managed_package_fixture(
    *, policy_version: int = 1
) -> tuple[ManagedDeploymentPackage, dict[str, Any]]:
    """Build canonical package bytes and matching AWS desired-host metadata."""
    hook_path = "/opt/aai-security/hooks/native-policy"
    bundle = ManagedConfigurationCompiler().compile(
        ManagedPolicyIntent(
            "policy-safe",
            policy_version,
            action_rules=(NativeActionRule("Read", NativeActionDecision.ALLOW, "synthetic read"),),
        ),
        host=AgentHost.CLAUDE_CODE,
        host_version="2.1.220",
        platform=ManagedPlatform.LINUX,
        hook_command=hook_path,
    )
    package = ManagedDeploymentPackage.from_bundle(
        bundle,
        required_executables=(
            ManagedExecutableRequirement(hook_path, hashlib.sha256(b"synthetic hook").hexdigest()),
        ),
    )
    return package, {
        "host": package.host.value,
        "hostVersion": package.host_version,
        "platform": package.platform.value,
        "bundleHash": package.bundle_hash,
        "policyId": package.policy_id,
        "policyVersion": package.policy_version,
    }


def _set_runtime_manifests(monkeypatch: Any, manifests: list[dict[str, Any]]) -> None:
    """Install synthetic manifests with an exact release-approval binding."""
    raw = json.dumps(manifests)
    first = manifests[0]
    approval = {
        "schemaVersion": 1,
        "manifestBundleSha256": hashlib.sha256(raw.encode()).hexdigest(),
        "approvals": [
            {
                "hosts": [manifest["host"] for manifest in manifests],
                "releaseEvidenceSha256": "9" * 64,
                "releaseTag": "v1.1.0",
                "sdkRevision": first["sdkRevision"],
                "sdkVersion": first["sdkVersion"],
                "sourceOriginDigest": first["sourceOriginDigest"],
            }
        ],
    }
    monkeypatch.setenv("RUNTIME_ATTESTATION_MANIFESTS", raw)
    approval_raw = json.dumps(approval)
    monkeypatch.setenv(
        "RUNTIME_ATTESTATION_MANIFESTS_SHA256", hashlib.sha256(raw.encode()).hexdigest()
    )
    monkeypatch.setenv("RUNTIME_ATTESTATION_APPROVALS", approval_raw)
    monkeypatch.setenv(
        "RUNTIME_ATTESTATION_APPROVALS_SHA256",
        hashlib.sha256(approval_raw.encode()).hexdigest(),
    )


def _runtime_evidence(
    nonce: str,
    *,
    observed_at: int,
    host: str = "claude-code",
    configuration_digest: str = "f" * 64,
) -> dict[str, Any]:
    """Return synthetic content-minimised evidence for one challenge."""
    return {
        **_runtime_manifest(host),
        "configurationDigest": configuration_digest,
        "executableDigest": "1" * 64,
        "launchContextDigest": "2" * 64,
        "projectRootDigest": hashlib.sha256(b"/synthetic/project").hexdigest(),
        "observedAt": observed_at,
        "nonce": nonce,
    }


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
    assert payload["subject"] == "operator-a"
    assert payload["strongAuthentication"] == {
        "status": "not_configured",
        "maxAuthenticationAgeSeconds": 600,
    }
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
    monkeypatch.setenv("ENTRA_STRONG_AUTH_ENFORCED", "true")
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
            "aai:strong_auth_enforced": "true",
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
    with pytest.raises(PermissionError, match="no mapped or delegated product authority"):
        module.handler(event, None)
    delegated_key = ("TENANT#tenant-enterprise", "DELEGATED_GRANT#grant-a")
    table.put_item(
        Item={
            "pk": delegated_key[0],
            "sk": delegated_key[1],
            "id": "grant-a",
            "principal_id": user_id,
            "role": "fleet-operator",
            "status": "active",
            "expires_at": int(time.time()) + 300,
            "revision": 1,
        }
    )
    delegated = module.handler({**event, "response": {}}, None)
    delegated_overrides = delegated["response"]["claimsAndScopeOverrideDetails"]
    assert delegated_overrides["groupOverrideDetails"] == {"groupsToOverride": []}
    assert (
        delegated_overrides["accessTokenGeneration"]["claimsToAddOrOverride"]["aai:operator_id"]
        == user_id
    )
    assert (
        delegated_overrides["accessTokenGeneration"]["claimsToAddOrOverride"]["aai:delegated"]
        == "true"
    )
    del table.items[delegated_key]
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
    assert overrides["accessTokenGeneration"]["claimsToAddOrOverride"]["aai:operator_id"] == user_id
    assert overrides["accessTokenGeneration"]["claimsToAddOrOverride"]["aai:delegated"] == "false"
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


def test_delegated_admin_scope_is_live_narrow_and_revocable(monkeypatch: Any) -> None:
    """A delegated role authorizes only descendant resources and never identity control."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-delegated"
    for item in (
        module._item_key(tenant, "TENANT", "root") | {"id": tenant},
        module._item_key(tenant, "ORG", "org-a") | {"id": "org-a", "name": "A"},
        module._item_key(tenant, "ORG", "org-b") | {"id": "org-b", "name": "B"},
        module._item_key(tenant, "PROJECT", "project-a")
        | {"id": "project-a", "organization_id": "org-a", "name": "A project"},
        module._item_key(tenant, "PROJECT", "project-b")
        | {"id": "project-b", "organization_id": "org-b", "name": "B project"},
        module._item_key(tenant, "DEPLOYMENT", "existing-b")
        | {
            "id": "existing-b",
            "organization_id": "org-b",
            "project_id": "project-b",
            "name": "Existing B",
        },
    ):
        table.put_item(Item=item)
    admin_claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "admin-a",
    }
    created = _invoke(
        module,
        _event(
            "/enterprise/identity/delegated-grants",
            "POST",
            body={
                "principalId": "operator-a",
                "role": "fleet-operator",
                "scopeType": "organization",
                "scopeId": "org-a",
                "durationDays": 30,
                "reason": "Operate the synthetic A organization fleet",
            },
            claims=admin_claims,
        ),
    )
    assert created["statusCode"] == 201
    grant = json.loads(created["body"])
    assert grant["effectiveStatus"] == "active"
    assert grant["scopeId"] == "org-a"
    assert len([key for key in table.items if key[1].startswith("BREAK_GLASS_AUDIT#")]) == 1

    delegated_claims = {
        "custom:tenant_id": tenant,
        "sub": "operator-a",
        # This claim is informational only; the API resolves grant authority live.
        "aai:delegated": "true",
    }
    allowed = _invoke(
        module,
        _event(
            "/enterprise/deployments",
            "POST",
            body={
                "organizationId": "org-a",
                "projectId": "project-a",
                "deploymentId": "deployment-a",
                "name": "A deployment",
                "environment": "synthetic",
                "region": "test-1",
            },
            claims=delegated_claims,
        ),
    )
    assert allowed["statusCode"] == 201
    denied_sibling = _invoke(
        module,
        _event(
            "/enterprise/deployments",
            "POST",
            body={
                "organizationId": "org-b",
                "projectId": "project-b",
                "deploymentId": "deployment-b",
                "name": "B deployment",
                "environment": "synthetic",
                "region": "test-1",
            },
            claims=delegated_claims,
        ),
    )
    assert denied_sibling["statusCode"] == 403
    visible = _invoke(
        module,
        _event("/enterprise/deployments", "GET", claims=delegated_claims),
    )
    assert visible["statusCode"] == 200
    assert [item["id"] for item in json.loads(visible["body"])["items"]] == ["deployment-a"]
    denied_identity = _invoke(
        module,
        _event(
            "/enterprise/identity/delegated-grants",
            "POST",
            body={
                "principalId": "attacker",
                "role": "fleet-operator",
                "scopeType": "organization",
                "scopeId": "org-a",
                "durationDays": 30,
                "reason": "Attempt to widen delegated authority illegally",
            },
            claims=delegated_claims,
        ),
    )
    assert denied_identity["statusCode"] == 403
    forged = _invoke(
        module,
        _event(
            "/enterprise/projects",
            "POST",
            body={"organizationId": "org-a", "projectId": "forged", "name": "Forged"},
            claims={
                "custom:tenant_id": tenant,
                "sub": "attacker",
                "aai:delegated": "true",
            },
        ),
    )
    assert forged["statusCode"] == 403

    revoked = _invoke(
        module,
        _event(
            f"/enterprise/identity/delegated-grants/{grant['id']}/revoke",
            "POST",
            claims=admin_claims,
        ),
    )
    assert revoked["statusCode"] == 200
    assert json.loads(revoked["body"])["effectiveStatus"] == "revoked"
    denied_after_revoke = _invoke(
        module,
        _event(
            "/enterprise/projects",
            "POST",
            body={"organizationId": "org-a", "projectId": "after-revoke", "name": "Denied"},
            claims=delegated_claims,
        ),
    )
    assert denied_after_revoke["statusCode"] == 403
    assert len([key for key in table.items if key[1].startswith("BREAK_GLASS_AUDIT#")]) == 2


def test_delegated_admin_rejects_self_wildcard_expired_and_cross_tenant_grants(
    monkeypatch: Any,
) -> None:
    """Delegation cannot create wildcard, self, stale or cross-tenant authority."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-delegated-bounds"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(Item=module._item_key(tenant, "ORG", "org-a") | {"id": "org-a"})
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "admin-a",
    }
    for body in (
        {
            "principalId": "admin-a",
            "role": "fleet-operator",
            "scopeType": "organization",
            "scopeId": "org-a",
            "durationDays": 30,
            "reason": "Self delegation must always be rejected",
        },
        {
            "principalId": "operator-a",
            "role": "platform-admin",
            "scopeType": "organization",
            "scopeId": "org-a",
            "durationDays": 30,
            "reason": "Wildcard delegation must always be rejected",
        },
    ):
        response = _invoke(
            module,
            _event("/enterprise/identity/delegated-grants", "POST", body=body, claims=claims),
        )
        assert response["statusCode"] in {400, 403}
    table.put_item(
        Item={
            **module._item_key(tenant, "DELEGATED_GRANT", "expired"),
            "id": "expired",
            "principal_id": "operator-a",
            "role": "fleet-operator",
            "scope_type": "organization",
            "scope_id": "org-a",
            "status": "active",
            "expires_at": int(time.time()) - 1,
            "revision": 1,
        }
    )
    assert not module._operator_authorized(
        _event("/", "GET", claims={"custom:tenant_id": tenant, "sub": "operator-a"}),
        "fleet_write",
        tenant,
        resource_scope={"organization": "org-a"},
    )


def test_group_authority_edges_reject_cross_organization_policy_and_agent(
    monkeypatch: Any,
) -> None:
    """Group policy and membership changes must not bridge organization boundaries."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-group-organization-boundary"
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "admin-a",
    }
    for item in (
        module._item_key(tenant, "TENANT", "root") | {"id": tenant},
        module._item_key(tenant, "ORG", "org-a") | {"id": "org-a", "name": "A"},
        module._item_key(tenant, "ORG", "org-b") | {"id": "org-b", "name": "B"},
        module._item_key(tenant, "POLICY", "policy-a")
        | {
            "id": "policy-a",
            "organization_id": "org-a",
            "name": "Policy A",
            "configuration": {"tools": {"allowed": ["read_repository"]}},
            "version": 1,
            "governance_schema_version": 1,
        },
        module._item_key(tenant, "POLICY", "policy-b")
        | {
            "id": "policy-b",
            "organization_id": "org-b",
            "name": "Policy B",
            "configuration": {"tools": {"allowed": ["read_repository"]}},
            "version": 1,
            "governance_schema_version": 1,
        },
        module._item_key(tenant, "POLICY", "policy-missing-owner")
        | {
            "id": "policy-missing-owner",
            "name": "Missing owner",
            "configuration": {"tools": {"allowed": ["read_repository"]}},
            "version": 1,
            "governance_schema_version": 1,
        },
        module._item_key(tenant, "GROUP", "group-a")
        | {
            "id": "group-a",
            "organizationId": "org-a",
            "name": "Group A",
            "policyId": "policy-a",
            "policyName": "Policy A",
            "agent_keys": [],
        },
        module._item_key(tenant, "AGENT", "deployment-a:agent-a")
        | {
            "id": "agent-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "deployment_id": "deployment-a",
            "host": "claude-code",
            "status": "offline",
            "expires_at": 0,
        },
        module._item_key(tenant, "AGENT", "deployment-b:agent-b")
        | {
            "id": "agent-b",
            "organization_id": "org-b",
            "project_id": "project-b",
            "deployment_id": "deployment-b",
            "host": "claude-code",
            "status": "offline",
            "expires_at": 0,
        },
        module._item_key(tenant, "AGENT", "deployment-a:missing-owner")
        | {
            "id": "missing-owner",
            "deployment_id": "deployment-a",
            "host": "claude-code",
            "status": "offline",
            "expires_at": 0,
        },
    ):
        table.put_item(Item=item)

    cross_policy = _invoke(
        module,
        _event(
            "/enterprise/groups/group-a/policy",
            "POST",
            body={"policyId": "policy-b"},
            claims=claims,
        ),
    )
    assert cross_policy["statusCode"] == 409
    assert "same organization" in json.loads(cross_policy["body"])["error"]
    assert table.items[(f"TENANT#{tenant}", "GROUP#group-a")]["policyId"] == "policy-a"

    missing_policy_owner = _invoke(
        module,
        _event(
            "/enterprise/groups/group-a/policy",
            "POST",
            body={"policyId": "policy-missing-owner"},
            claims=claims,
        ),
    )
    assert missing_policy_owner["statusCode"] == 409

    missing_agent = _invoke(
        module,
        _event(
            "/enterprise/groups/group-a/agents",
            "POST",
            body={"deploymentId": "deployment-a", "agentId": "missing"},
            claims=claims,
        ),
    )
    assert missing_agent["statusCode"] == 404

    missing_agent_owner = _invoke(
        module,
        _event(
            "/enterprise/groups/group-a/agents",
            "POST",
            body={"deploymentId": "deployment-a", "agentId": "missing-owner"},
            claims=claims,
        ),
    )
    assert missing_agent_owner["statusCode"] == 409

    cross_agent = _invoke(
        module,
        _event(
            "/enterprise/groups/group-a/agents",
            "POST",
            body={"deploymentId": "deployment-b", "agentId": "agent-b"},
            claims=claims,
        ),
    )
    assert cross_agent["statusCode"] == 409
    assert "same organization" in json.loads(cross_agent["body"])["error"]
    assert table.items[(f"TENANT#{tenant}", "GROUP#group-a")]["agent_keys"] == []

    same_organization = _invoke(
        module,
        _event(
            "/enterprise/groups/group-a/agents",
            "POST",
            body={"deploymentId": "deployment-a", "agentId": "agent-a"},
            claims=claims,
        ),
    )
    assert same_organization["statusCode"] == 200
    assert table.items[(f"TENANT#{tenant}", "GROUP#group-a")]["agent_keys"] == [
        "deployment-a:agent-a"
    ]
    assert not module._operator_authorized(
        _event(
            "/",
            "GET",
            claims={"custom:tenant_id": "tenant-other", "sub": "operator-a"},
        ),
        "fleet_write",
        "tenant-other",
        resource_scope={"organization": "org-a"},
    )


def test_bulk_group_assignment_previews_applies_partial_results_and_replays(
    monkeypatch: Any,
) -> None:
    """Bulk assignment is bounded, partial, revisioned, durable and idempotent."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-bulk-membership"
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "fleet-operator-a",
    }
    now = int(time.time())
    records = [
        module._item_key(tenant, "TENANT", "root") | {"id": tenant},
        module._item_key(tenant, "GROUP", "target")
        | {
            "id": "target",
            "organizationId": "org-a",
            "name": "Target",
            "policyId": "policy-a",
            "policyName": "Policy A",
            "agent_keys": ["deployment-a:existing"],
            "membership_revision": 3,
        },
        module._item_key(tenant, "GROUP", "other")
        | {
            "id": "other",
            "organizationId": "org-a",
            "name": "Other",
            "policyId": "policy-a",
            "policyName": "Policy A",
            "agent_keys": ["deployment-a:assigned"],
            "membership_revision": 1,
        },
    ]
    for agent_id, organization_id, lifecycle_state in (
        ("eligible", "org-a", "active"),
        ("existing", "org-a", "active"),
        ("assigned", "org-a", "active"),
        ("inactive", "org-a", "revoked"),
        ("cross-org", "org-b", "active"),
    ):
        records.append(
            module._item_key(tenant, "AGENT", f"deployment-a:{agent_id}")
            | {
                "id": agent_id,
                "organization_id": organization_id,
                "project_id": "project-a",
                "deployment_id": "deployment-a",
                "host": "claude-code",
                "status": "offline",
                "expires_at": 0,
                "lifecycle_state": lifecycle_state,
                "lifecycle_revision": 1,
                "created_at": now,
            }
        )
    for record in records:
        table.put_item(Item=record)
    request = {
        "mode": "preview",
        "requestId": "batch-001",
        "expectedMembershipRevision": 3,
        "reason": "Assign the approved engineering pilot cohort.",
        "agents": [
            {"deploymentId": "deployment-a", "agentId": "eligible"},
            {"deploymentId": "deployment-a", "agentId": "existing"},
            {"deploymentId": "deployment-a", "agentId": "assigned"},
            {"deploymentId": "deployment-a", "agentId": "inactive"},
            {"deploymentId": "deployment-a", "agentId": "cross-org"},
            {"deploymentId": "deployment-a", "agentId": "missing"},
        ],
    }
    path = "/enterprise/groups/target/agents/bulk"

    preview = _invoke(module, _event(path, "POST", body=request, claims=claims))
    assert preview["statusCode"] == 200
    preview_body = json.loads(preview["body"])
    assert preview_body["counts"] == {
        "requested": 6,
        "ready": 1,
        "applied": 0,
        "unchanged": 1,
        "rejected": 4,
    }
    assert preview_body["canApply"] is True
    assert preview_body["partialFailure"] is True
    assert preview_body["membershipRevision"] == 3
    assert not [key for key in table.items if key[1].startswith("GROUP_MEMBERSHIP_AUDIT#")]
    assert not [key for key in table.items if key[1].startswith("GROUP_MEMBERSHIP_OPERATION#")]
    assert table.items[(f"TENANT#{tenant}", "GROUP#target")]["agent_keys"] == [
        "deployment-a:existing"
    ]

    applied = _invoke(
        module,
        _event(path, "POST", body={**request, "mode": "apply"}, claims=claims),
    )
    assert applied["statusCode"] == 207
    applied_body = json.loads(applied["body"])
    assert applied_body["counts"] == {
        "requested": 6,
        "ready": 0,
        "applied": 1,
        "unchanged": 1,
        "rejected": 4,
    }
    assert applied_body["resultingMembershipRevision"] == 4
    assert table.items[(f"TENANT#{tenant}", "GROUP#target")]["agent_keys"] == [
        "deployment-a:eligible",
        "deployment-a:existing",
    ]
    assert table.items[(f"TENANT#{tenant}", "GROUP#target")]["membership_revision"] == 4
    audit_keys = [key for key in table.items if key[1].startswith("GROUP_MEMBERSHIP_AUDIT#")]
    operation_keys = [
        key for key in table.items if key[1].startswith("GROUP_MEMBERSHIP_OPERATION#")
    ]
    assert len(audit_keys) == 1
    assert len(operation_keys) == 1
    audit = table.items[audit_keys[0]]
    assert audit["actor"] == "fleet-operator-a"
    assert audit["payload"]["applied_count"] == 1
    assert "agents" not in audit["payload"]

    replay = _invoke(
        module,
        _event(path, "POST", body={**request, "mode": "apply"}, claims=claims),
    )
    assert replay["statusCode"] == 207
    assert json.loads(replay["body"])["replayed"] is True
    assert table.items[(f"TENANT#{tenant}", "GROUP#target")]["membership_revision"] == 4
    assert len([key for key in table.items if key[1].startswith("GROUP_MEMBERSHIP_AUDIT#")]) == 1

    collision = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                **request,
                "mode": "apply",
                "reason": "A different valid operator reason for collision.",
            },
            claims=claims,
        ),
    )
    assert collision["statusCode"] == 409


def test_bulk_group_assignment_rejects_stale_malformed_and_concurrent_requests(
    monkeypatch: Any,
) -> None:
    """Stale previews, duplicate targets and transaction races change no authority."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-bulk-membership-race"
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "admin-a",
    }
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "GROUP", "target")
        | {
            "id": "target",
            "organizationId": "org-a",
            "name": "Target",
            "policyId": "policy-a",
            "policyName": "Policy A",
            "agent_keys": [],
            "membership_revision": 2,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "deployment-a:eligible")
        | {
            "id": "eligible",
            "organization_id": "org-a",
            "deployment_id": "deployment-a",
            "project_id": "project-a",
            "host": "codex-cli",
            "status": "offline",
            "expires_at": 0,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
        }
    )
    path = "/enterprise/groups/target/agents/bulk"
    base = {
        "mode": "preview",
        "requestId": "batch-race",
        "expectedMembershipRevision": 1,
        "reason": "Assign a bounded cohort after operator review.",
        "agents": [{"deploymentId": "deployment-a", "agentId": "eligible"}],
    }
    stale = _invoke(module, _event(path, "POST", body=base, claims=claims))
    assert stale["statusCode"] == 409

    duplicate = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                **base,
                "expectedMembershipRevision": 2,
                "agents": [
                    {"deploymentId": "deployment-a", "agentId": "eligible"},
                    {"deploymentId": "deployment-a", "agentId": "eligible"},
                ],
            },
            claims=claims,
        ),
    )
    assert duplicate["statusCode"] == 400

    request = {**base, "mode": "apply", "expectedMembershipRevision": 2}

    def change_group() -> None:
        current = table.items[(f"TENANT#{tenant}", "GROUP#target")]
        current["membership_revision"] = 3
        current["agent_keys"] = ["deployment-a:concurrent"]

    module.DYNAMODB.before_transaction = change_group
    raced = _invoke(module, _event(path, "POST", body=request, claims=claims))
    assert raced["statusCode"] == 409
    assert table.items[(f"TENANT#{tenant}", "GROUP#target")]["agent_keys"] == [
        "deployment-a:concurrent"
    ]
    assert not [key for key in table.items if key[1].startswith("GROUP_MEMBERSHIP_AUDIT#")]
    assert not [key for key in table.items if key[1].startswith("GROUP_MEMBERSHIP_OPERATION#")]

    oversized = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                **base,
                "expectedMembershipRevision": 3,
                "agents": [
                    {"deploymentId": "deployment-a", "agentId": f"agent-{index}"}
                    for index in range(101)
                ],
            },
            claims=claims,
        ),
    )
    assert oversized["statusCode"] == 400


def test_single_group_assignment_rejects_existing_policy_group_and_revisions_removal(
    monkeypatch: Any,
) -> None:
    """Legacy single routes preserve sole-group authority and revision membership writes."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-single-membership"
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "fleet-operator-a",
    }
    for record in (
        module._item_key(tenant, "TENANT", "root") | {"id": tenant},
        module._item_key(tenant, "GROUP", "target")
        | {
            "id": "target",
            "organizationId": "org-a",
            "name": "Target",
            "policyId": "policy-a",
            "policyName": "Policy A",
            "agent_keys": [],
            "membership_revision": 1,
        },
        module._item_key(tenant, "GROUP", "other")
        | {
            "id": "other",
            "organizationId": "org-a",
            "name": "Other",
            "policyId": "policy-a",
            "policyName": "Policy A",
            "agent_keys": ["deployment-a:assigned"],
            "membership_revision": 1,
        },
        module._item_key(tenant, "AGENT", "deployment-a:assigned")
        | {
            "id": "assigned",
            "organization_id": "org-a",
            "project_id": "project-a",
            "deployment_id": "deployment-a",
            "host": "claude-code",
            "status": "offline",
            "expires_at": 0,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
        },
        module._item_key(tenant, "AGENT", "deployment-a:eligible")
        | {
            "id": "eligible",
            "organization_id": "org-a",
            "project_id": "project-a",
            "deployment_id": "deployment-a",
            "host": "codex-cli",
            "status": "offline",
            "expires_at": 0,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
        },
    ):
        table.put_item(Item=record)
    add_path = "/enterprise/groups/target/agents"
    rejected = _invoke(
        module,
        _event(
            add_path,
            "POST",
            body={"deploymentId": "deployment-a", "agentId": "assigned"},
            claims=claims,
        ),
    )
    assert rejected["statusCode"] == 409
    added = _invoke(
        module,
        _event(
            add_path,
            "POST",
            body={"deploymentId": "deployment-a", "agentId": "eligible"},
            claims=claims,
        ),
    )
    assert added["statusCode"] == 200
    assert json.loads(added["body"])["membershipRevision"] == 2
    removed = _invoke(
        module,
        _event(
            "/enterprise/groups/target/agents/deployment-a/eligible",
            "DELETE",
            claims=claims,
        ),
    )
    assert removed["statusCode"] == 200
    assert json.loads(removed["body"])["membershipRevision"] == 3
    assert table.items[(f"TENANT#{tenant}", "GROUP#target")]["agent_keys"] == []


def test_dynamic_group_previews_conflicts_and_applies_deterministic_membership(
    monkeypatch: Any,
) -> None:
    """Dynamic rules use trusted inventory, fail on overlap and co-commit evidence."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-dynamic-groups"
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "fleet-operator-a",
    }
    now = int(time.time())
    for record in (
        module._item_key(tenant, "TENANT", "root") | {"id": tenant},
        module._item_key(tenant, "DEPLOYMENT", "dep-platform")
        | {
            "id": "dep-platform",
            "organization_id": "org-a",
            "project_id": "project-a",
            "team": "Platform",
            "environment": "prod",
            "region": "eu-west-2",
        },
        module._item_key(tenant, "DEPLOYMENT", "dep-data")
        | {
            "id": "dep-data",
            "organization_id": "org-a",
            "project_id": "project-b",
            "team": "Data",
            "environment": "prod",
            "region": "eu-west-2",
        },
        module._item_key(tenant, "GROUP", "target")
        | {
            "id": "target",
            "organizationId": "org-a",
            "name": "Platform production",
            "policyId": "policy-a",
            "policyName": "Policy A",
            "agent_keys": ["dep-data:remove", "dep-platform:unchanged"],
            "membership_revision": 2,
            "membership_mode": "manual",
        },
        module._item_key(tenant, "GROUP", "other")
        | {
            "id": "other",
            "organizationId": "org-a",
            "name": "Other",
            "policyId": "policy-a",
            "policyName": "Policy A",
            "agent_keys": ["dep-platform:conflict"],
            "membership_revision": 1,
        },
    ):
        table.put_item(Item=record)
    for deployment_id, agent_id in (
        ("dep-platform", "add"),
        ("dep-platform", "unchanged"),
        ("dep-platform", "conflict"),
        ("dep-data", "remove"),
    ):
        table.put_item(
            Item=module._item_key(tenant, "AGENT", f"{deployment_id}:{agent_id}")
            | {
                "id": agent_id,
                "organization_id": "org-a",
                "project_id": "project-a" if deployment_id == "dep-platform" else "project-b",
                "deployment_id": deployment_id,
                "host": "claude-code",
                "status": "offline",
                "expires_at": 0,
                "lifecycle_state": "active",
                "lifecycle_revision": 1,
                "owner_id": "owner-a",
                "owner_name": "Owner A",
                "business_contact": "owner@example.invalid",
                "ownership_criticality": "high",
                "ownership_reviewed_at": now,
                "ownership_review_due_at": now + 3600,
                "ownership_reviewed_by": "reviewer-a",
                "ownership_revision": 1,
            }
        )
    path = "/enterprise/groups/target/dynamic-membership"
    request = {
        "mode": "preview",
        "requestId": "dynamic-request-001",
        "expectedMembershipRevision": 2,
        "reason": "Keep production platform agents on the approved policy.",
        "rule": {
            "match": "all",
            "conditions": [
                {"field": "environment", "operator": "equals_any", "values": ["prod"]},
                {"field": "team", "operator": "equals_any", "values": ["Platform"]},
            ],
        },
    }

    preview = _invoke(module, _event(path, "POST", body=request, claims=claims))
    assert preview["statusCode"] == 200
    preview_body = json.loads(preview["body"])
    assert preview_body["counts"] == {
        "matched": 3,
        "additions": 1,
        "removals": 1,
        "unchanged": 1,
        "conflicts": 1,
    }
    assert preview_body["canApply"] is False
    assert preview_body["additions"] == [{"deploymentId": "dep-platform", "agentId": "add"}]
    assert preview_body["removals"] == [{"deploymentId": "dep-data", "agentId": "remove"}]
    assert preview_body["conflicts"][0]["groupIds"] == ["other"]
    assert table.items[(f"TENANT#{tenant}", "GROUP#target")]["membership_mode"] == "manual"
    assert not [key for key in table.items if key[1].startswith("DYNAMIC_GROUP_OPERATION#")]

    blocked = _invoke(
        module,
        _event(path, "POST", body={**request, "mode": "apply"}, claims=claims),
    )
    assert blocked["statusCode"] == 409
    assert table.items[(f"TENANT#{tenant}", "GROUP#target")]["membership_revision"] == 2

    table.items[(f"TENANT#{tenant}", "GROUP#other")]["agent_keys"] = []
    clear_request = {**request, "requestId": "dynamic-request-002"}
    clear_preview = _invoke(module, _event(path, "POST", body=clear_request, claims=claims))
    assert json.loads(clear_preview["body"])["canApply"] is True
    applied = _invoke(
        module,
        _event(path, "POST", body={**clear_request, "mode": "apply"}, claims=claims),
    )
    assert applied["statusCode"] == 200, applied
    applied_body = json.loads(applied["body"])
    assert applied_body["resultingMembershipRevision"] == 3
    stored = table.items[(f"TENANT#{tenant}", "GROUP#target")]
    assert stored["membership_mode"] == "dynamic"
    assert stored["agent_keys"] == [
        "dep-platform:add",
        "dep-platform:conflict",
        "dep-platform:unchanged",
    ]
    assert stored["dynamic_rule"]["conditions"][0]["field"] == "environment"
    assert len([key for key in table.items if key[1].startswith("DYNAMIC_GROUP_OPERATION#")]) == 1
    audits = [key for key in table.items if key[1].startswith("GROUP_MEMBERSHIP_AUDIT#")]
    assert len(audits) == 1
    audit = table.items[audits[0]]
    assert audit["event_type"] == "dynamic_group_membership_applied"
    assert audit["payload"]["addition_count"] == 2
    assert "agent_keys" not in audit["payload"]

    replay = _invoke(
        module,
        _event(path, "POST", body={**clear_request, "mode": "apply"}, claims=claims),
    )
    assert json.loads(replay["body"])["replayed"] is True
    collision = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                **clear_request,
                "mode": "apply",
                "reason": "A different valid dynamic rule reason for collision.",
            },
            claims=claims,
        ),
    )
    assert collision["statusCode"] == 409

    manual_add = _invoke(
        module,
        _event(
            "/enterprise/groups/target/agents",
            "POST",
            body={"deploymentId": "dep-data", "agentId": "remove"},
            claims=claims,
        ),
    )
    assert manual_add["statusCode"] == 409
    manual_remove = _invoke(
        module,
        _event(
            "/enterprise/groups/target/agents/dep-platform/add",
            "DELETE",
            claims=claims,
        ),
    )
    assert manual_remove["statusCode"] == 409

    # A trusted deployment attribute change deterministically removes authority
    # on the next reviewed reevaluation; the agent cannot supply this field.
    table.items[(f"TENANT#{tenant}", "DEPLOYMENT#dep-platform")]["team"] = "Data"
    reevaluate = {
        **clear_request,
        "requestId": "dynamic-request-003",
        "expectedMembershipRevision": 3,
        "reason": "Reevaluate membership after the trusted team inventory changed.",
    }
    reevaluation_preview = _invoke(module, _event(path, "POST", body=reevaluate, claims=claims))
    reevaluation_body = json.loads(reevaluation_preview["body"])
    assert reevaluation_body["counts"]["matched"] == 0
    assert reevaluation_body["counts"]["removals"] == 3
    assert reevaluation_body["canApply"] is True
    reevaluated = _invoke(
        module,
        _event(path, "POST", body={**reevaluate, "mode": "apply"}, claims=claims),
    )
    assert reevaluated["statusCode"] == 200
    assert table.items[(f"TENANT#{tenant}", "GROUP#target")]["agent_keys"] == []
    assert table.items[(f"TENANT#{tenant}", "GROUP#target")]["membership_revision"] == 4


def test_dynamic_group_rejects_untrusted_rules_stale_revisions_and_transaction_races(
    monkeypatch: Any,
) -> None:
    """Malformed selectors and concurrent inventory authority fail without writes."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-dynamic-groups-race"
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "admin-a",
    }
    for record in (
        module._item_key(tenant, "TENANT", "root") | {"id": tenant},
        module._item_key(tenant, "DEPLOYMENT", "dep-a")
        | {
            "id": "dep-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "team": "Platform",
            "environment": "prod",
            "region": "eu-west-2",
        },
        module._item_key(tenant, "GROUP", "target")
        | {
            "id": "target",
            "organizationId": "org-a",
            "name": "Target",
            "policyId": "policy-a",
            "policyName": "Policy A",
            "agent_keys": [],
            "membership_revision": 4,
        },
        module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "deployment_id": "dep-a",
            "host": "codex-cli",
            "status": "offline",
            "expires_at": 0,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
        },
    ):
        table.put_item(Item=record)
    path = "/enterprise/groups/target/dynamic-membership"
    base = {
        "mode": "preview",
        "requestId": "dynamic-race-001",
        "expectedMembershipRevision": 4,
        "reason": "Select the approved Codex production deployment cohort.",
        "rule": {
            "match": "all",
            "conditions": [{"field": "host", "operator": "equals_any", "values": ["codex-cli"]}],
        },
    }
    stale = _invoke(
        module,
        _event(path, "POST", body={**base, "expectedMembershipRevision": 3}, claims=claims),
    )
    assert stale["statusCode"] == 409
    unknown = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                **base,
                "rule": {
                    "match": "all",
                    "conditions": [
                        {"field": "browserRisk", "operator": "equals_any", "values": ["low"]}
                    ],
                },
            },
            claims=claims,
        ),
    )
    assert unknown["statusCode"] == 400
    duplicate_field = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                **base,
                "rule": {
                    "match": "all",
                    "conditions": [
                        {"field": "host", "operator": "equals_any", "values": ["codex-cli"]},
                        {"field": "host", "operator": "not_equals_any", "values": ["claude-code"]},
                    ],
                },
            },
            claims=claims,
        ),
    )
    assert duplicate_field["statusCode"] == 400

    def change_group() -> None:
        current = table.items[(f"TENANT#{tenant}", "GROUP#target")]
        current["membership_revision"] = 5
        current["agent_keys"] = ["dep-a:concurrent"]

    module.DYNAMODB.before_transaction = change_group
    raced = _invoke(
        module,
        _event(path, "POST", body={**base, "mode": "apply"}, claims=claims),
    )
    assert raced["statusCode"] == 409
    assert table.items[(f"TENANT#{tenant}", "GROUP#target")]["agent_keys"] == ["dep-a:concurrent"]
    assert not [key for key in table.items if key[1].startswith("DYNAMIC_GROUP_OPERATION#")]


def test_break_glass_requires_mfa_four_eyes_scope_and_immediate_revocation(
    monkeypatch: Any,
) -> None:
    """Emergency authority is exact, short-lived, independently approved and live."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-emergency"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    audit_events: list[str] = []
    monkeypatch.setattr(
        module,
        "_audit",
        lambda _tenant, event_type, _actor, _payload: audit_events.append(event_type),
    )
    now = int(time.time())
    requester = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["incident-responder"],
        "sub": "responder-a",
        "amr": ["mfa"],
        "auth_time": str(now),
    }
    request_path = "/enterprise/identity/break-glass/requests"
    no_mfa = _invoke(
        module,
        _event(
            request_path,
            "POST",
            body={
                "reason": "Restore the policy service during incident INC-42",
                "capabilities": ["policy_write"],
                "durationMinutes": 15,
            },
            claims={
                **{key: value for key, value in requester.items() if key != "amr"},
                "custom:entra_auth_methods": '["mfa"]',
            },
        ),
    )
    assert no_mfa["statusCode"] == 403

    created = _invoke(
        module,
        _event(
            request_path,
            "POST",
            body={
                "reason": "Restore the policy service during incident INC-42",
                "capabilities": ["policy_write"],
                "durationMinutes": 15,
                "subject": "attacker-selected-subject",
            },
            claims=requester,
        ),
    )
    assert created["statusCode"] == 201
    request = json.loads(created["body"])
    assert request["subject"] == "responder-a"
    assert request["effectiveStatus"] == "pending"
    request_id = request["id"]

    approver = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "admin-b",
        "aai:identity_provider": "microsoft_entra_id",
        "aai:strong_auth_enforced": "true",
        "auth_time": str(now),
    }
    approved = _invoke(
        module,
        _event(
            f"{request_path}/{request_id}/approve",
            "POST",
            claims=approver,
        ),
    )
    assert approved["statusCode"] == 200
    grant = json.loads(approved["body"])
    assert grant["effectiveStatus"] == "active"
    assert grant["approvedBy"] == "admin-b"
    assert grant["grantExpiresAt"] - grant["grantStartsAt"] == 15 * 60
    assert module._operator_authorized(_event("/", "GET", claims=requester), "policy_write", tenant)
    assert not module._operator_authorized(
        _event("/", "GET", claims=requester), "identity_admin", tenant
    )
    assert not module._operator_authorized(
        _event("/", "GET", claims={**requester, "custom:tenant_id": "tenant-other"}),
        "policy_write",
        "tenant-other",
    )
    grant_key = (f"TENANT#{tenant}", f"BREAK_GLASS#{request_id}")
    saved_expiry = table.items[grant_key]["grant_expires_at"]
    table.items[grant_key]["grant_expires_at"] = now - 1
    assert not module._operator_authorized(
        _event("/", "GET", claims=requester), "policy_write", tenant
    )
    table.items[grant_key]["grant_expires_at"] = saved_expiry

    replay = _invoke(
        module,
        _event(f"{request_path}/{request_id}/approve", "POST", claims=approver),
    )
    assert replay["statusCode"] == 409
    revoked = _invoke(
        module,
        _event(f"{request_path}/{request_id}/revoke", "POST", claims=approver),
    )
    assert revoked["statusCode"] == 200
    assert json.loads(revoked["body"])["effectiveStatus"] == "revoked"
    assert not module._operator_authorized(
        _event("/", "GET", claims=requester), "policy_write", tenant
    )
    assert audit_events == [
        "break_glass_requested",
        "break_glass_approved",
        "break_glass_revoked",
    ]


def test_break_glass_rejects_self_approval_wildcards_and_excessive_duration(
    monkeypatch: Any,
) -> None:
    """A privileged requester cannot create permanent or self-approved authority."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-emergency-bounds"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "admin-a",
        "amr": ["mfa"],
        "auth_time": str(int(time.time())),
    }
    path = "/enterprise/identity/break-glass/requests"
    stale = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                "reason": "Need policy authority during incident INC-98",
                "capabilities": ["policy_write"],
                "durationMinutes": 5,
            },
            claims={**claims, "auth_time": str(int(time.time()) - 601)},
        ),
    )
    assert stale["statusCode"] == 403
    assert "too old" in json.loads(stale["body"])["error"]
    for body in (
        {
            "reason": "Need unrestricted authority during an incident",
            "capabilities": ["*"],
            "durationMinutes": 15,
        },
        {
            "reason": "Need policy authority during an extended incident",
            "capabilities": ["policy_write"],
            "durationMinutes": 61,
        },
    ):
        response = _invoke(module, _event(path, "POST", body=body, claims=claims))
        assert response["statusCode"] == 400
    created = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                "reason": "Need policy authority during incident INC-99",
                "capabilities": ["policy_write"],
                "durationMinutes": 5,
            },
            claims=claims,
        ),
    )
    request_id = json.loads(created["body"])["id"]
    self_approval = _invoke(
        module,
        _event(f"{path}/{request_id}/approve", "POST", claims=claims),
    )
    assert self_approval["statusCode"] == 403
    assert "own request" in json.loads(self_approval["body"])["error"]
    table.items[(f"TENANT#{tenant}", f"BREAK_GLASS#{request_id}")]["request_expires_at"] = (
        int(time.time()) - 1
    )
    expired = _invoke(
        module,
        _event(
            f"{path}/{request_id}/approve",
            "POST",
            claims={**claims, "sub": "admin-b"},
        ),
    )
    assert expired["statusCode"] == 409
    denied_request = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                "reason": "Need runtime authority during incident INC-101",
                "capabilities": ["runtime_admin"],
                "durationMinutes": 5,
            },
            claims=claims,
        ),
    )
    denied_id = json.loads(denied_request["body"])["id"]
    denied = _invoke(
        module,
        _event(
            f"{path}/{denied_id}/deny",
            "POST",
            claims={**claims, "sub": "admin-b"},
        ),
    )
    denied_body = json.loads(denied["body"])
    assert denied["statusCode"] == 200
    assert denied_body["effectiveStatus"] == "denied"
    assert denied_body["decidedBy"] == "admin-b"
    assert denied_body["approvedBy"] is None


def test_break_glass_authority_cannot_govern_more_break_glass(monkeypatch: Any) -> None:
    """Emergency identity administration cannot bootstrap another emergency grant."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-emergency-chain"
    now = int(time.time())
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "BREAK_GLASS", "active-emergency-admin")
        | {
            "id": "active-emergency-admin",
            "subject": "emergency-admin",
            "capabilities": ["identity_admin"],
            "status": "approved",
            "grant_starts_at": now - 1,
            "grant_expires_at": now + 600,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "BREAK_GLASS", "pending-victim")
        | {
            "id": "pending-victim",
            "subject": "responder-b",
            "requested_by": "responder-b",
            "capabilities": ["policy_write"],
            "duration_seconds": 300,
            "reason": "Restore policy service during synthetic incident INC-100",
            "status": "pending",
            "requested_at": now,
            "request_expires_at": now + 600,
        }
    )
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": [],
        "sub": "emergency-admin",
        "amr": ["mfa"],
        "auth_time": str(now),
    }
    assert module._operator_authorized(_event("/", "GET", claims=claims), "identity_admin", tenant)
    response = _invoke(
        module,
        _event(
            "/enterprise/identity/break-glass/requests/pending-victim/approve",
            "POST",
            claims=claims,
        ),
    )
    assert response["statusCode"] == 403


def test_break_glass_authority_and_audit_commit_before_s3_replication(monkeypatch: Any) -> None:
    """A secondary audit outage cannot create an unaudited or ambiguous grant request."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-emergency-audit"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})

    def failed_replication(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("synthetic audit replication outage")

    monkeypatch.setattr(module, "_audit", failed_replication)
    response = _invoke(
        module,
        _event(
            "/enterprise/identity/break-glass/requests",
            "POST",
            body={
                "reason": "Restore fleet authority during synthetic incident INC-102",
                "capabilities": ["fleet_write"],
                "durationMinutes": 5,
            },
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["incident-responder"],
                "sub": "responder-a",
                "amr": ["mfa"],
                "auth_time": str(int(time.time())),
            },
        ),
    )
    assert response["statusCode"] == 201
    requests = [
        item for item in table.items.values() if str(item.get("sk", "")).startswith("BREAK_GLASS#")
    ]
    audits = [
        item
        for item in table.items.values()
        if str(item.get("sk", "")).startswith("BREAK_GLASS_AUDIT#")
    ]
    assert len(requests) == 1
    assert len(audits) == 1
    assert audits[0]["event_type"] == "break_glass_requested"
    assert len(audits[0]["payload_hash"]) == 64


def test_break_glass_concurrent_decision_cannot_diverge_from_audit(monkeypatch: Any) -> None:
    """A revision race commits neither the stale decision nor its audit event."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-emergency-race"
    now = int(time.time())
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    requester = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["incident-responder"],
        "sub": "responder-a",
        "amr": ["mfa"],
        "auth_time": str(now),
    }
    created = _invoke(
        module,
        _event(
            "/enterprise/identity/break-glass/requests",
            "POST",
            body={
                "reason": "Restore policy authority during synthetic incident INC-103",
                "capabilities": ["policy_write"],
                "durationMinutes": 5,
            },
            claims=requester,
        ),
    )
    request_id = json.loads(created["body"])["id"]
    request_key = (f"TENANT#{tenant}", f"BREAK_GLASS#{request_id}")

    def concurrent_change() -> None:
        table.items[request_key]["revision"] = 2

    module.DYNAMODB.before_transaction = concurrent_change
    response = _invoke(
        module,
        _event(
            f"/enterprise/identity/break-glass/requests/{request_id}/approve",
            "POST",
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["platform-admin"],
                "sub": "admin-b",
                "amr": ["mfa"],
                "auth_time": str(now),
            },
        ),
    )
    assert response["statusCode"] == 409
    assert table.items[request_key]["status"] == "pending"
    audit_types = [
        item.get("event_type")
        for item in table.items.values()
        if str(item.get("sk", "")).startswith("BREAK_GLASS_AUDIT#")
    ]
    assert audit_types == ["break_glass_requested"]


def test_access_certification_is_complete_bounded_and_auditor_only(monkeypatch: Any) -> None:
    """The export binds SCIM access, role mappings and emergency grants by digest."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-certification"
    monkeypatch.setenv("SCIM_ENABLED", "true")
    monkeypatch.setenv("ENTRA_AAI_TENANT_ID", tenant)
    module.SCIM = table
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    user_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    group_id = "99999999-8888-4777-8666-555555555555"
    table.put_item(
        Item={
            "pk": f"TENANT#{tenant}",
            "sk": f"USER#{user_id}",
            "id": user_id,
            "user_name": "synthetic.auditor@example.invalid",
            "display_name": "Synthetic Auditor",
            "active": True,
            "updated_at": 100,
        }
    )
    table.put_item(
        Item={
            "pk": f"TENANT#{tenant}",
            "sk": f"GROUP#{group_id}",
            "id": group_id,
            "display_name": "AAI Auditors",
            "active": True,
            "mapped_role": "auditor",
            "updated_at": 101,
        }
    )
    table.put_item(
        Item={
            "pk": f"TENANT#{tenant}#USER#{user_id}",
            "sk": f"GROUP#{group_id}",
        }
    )
    path = "/enterprise/identity/access-certification"
    denied = _invoke(
        module,
        _event(
            path,
            "GET",
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["fleet-operator"],
                "sub": "operator-a",
            },
        ),
    )
    assert denied["statusCode"] == 403
    exported = _invoke(
        module,
        _event(
            path,
            "GET",
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["auditor"],
                "sub": "auditor-a",
            },
        ),
    )
    assert exported["statusCode"] == 200
    payload = json.loads(exported["body"])
    assert payload["schemaVersion"] == 2
    assert payload["complete"] is True
    assert payload["delegatedGrants"] == []
    assert payload["operators"] == [
        {
            "subjectId": user_id,
            "userName": "synthetic.auditor@example.invalid",
            "displayName": "Synthetic Auditor",
            "active": True,
            "groupIds": [group_id],
            "roles": ["auditor"],
            "lastProvisionedAt": 100,
        }
    ]
    assert len(payload["contentHash"]) == 64
    artifact = {
        key: value for key, value in payload.items() if key not in {"generatedAt", "contentHash"}
    }
    assert (
        payload["contentHash"]
        == hashlib.sha256(
            json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
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


def test_aws_policy_governance_requires_independent_review_and_atomic_activation(
    monkeypatch: Any,
) -> None:
    """Hosted policy writes remain inactive until an independently approved promotion."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-policy-governance"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(Item=module._item_key(tenant, "ORG", "org-a") | {"id": "org-a", "name": "Alpha"})
    author_claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["policy-author"],
        "sub": "author-1",
    }
    reviewer_claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["policy-approver"],
        "sub": "reviewer-2",
    }
    admin_author_claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "author-1",
    }
    admin_claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "admin-3",
    }

    created = _invoke(
        module,
        _event(
            "/enterprise/policies",
            "POST",
            body={
                "policyId": "policy-governed",
                "name": "Governed",
                "configuration": {"tools": {"allowed": ["read_repository"]}},
            },
            claims=author_claims,
        ),
    )
    assert created["statusCode"] == 201
    created_body = json.loads(created["body"])
    assert created_body["version"] == 0
    assert created_body["activeVersion"] is None
    assert created_body["pendingVersion"] == 1
    assert created_body["configuration"] == {}

    inactive_group = _invoke(
        module,
        _event(
            "/enterprise/groups",
            "POST",
            body={
                "groupId": "group-too-early",
                "name": "Too early",
                "policyId": "policy-governed",
            },
            claims=admin_claims,
        ),
    )
    assert inactive_group["statusCode"] == 409

    submitted = _invoke(
        module,
        _event(
            "/enterprise/policies/policy-governed/versions/1/submit",
            "POST",
            claims=author_claims,
        ),
    )
    assert submitted["statusCode"] == 200
    denied_author_role = _invoke(
        module,
        _event(
            "/enterprise/policies/policy-governed/versions/1/decision",
            "POST",
            body={"decision": "approved", "reason": "Self approval"},
            claims=author_claims,
        ),
    )
    assert denied_author_role["statusCode"] == 403
    assert json.loads(denied_author_role["body"])["requiredCapability"] == "policy_approval"
    denied_self_approval = _invoke(
        module,
        _event(
            "/enterprise/policies/policy-governed/versions/1/decision",
            "POST",
            body={"decision": "approved", "reason": "Admin self approval"},
            claims=admin_author_claims,
        ),
    )
    assert denied_self_approval["statusCode"] == 403
    approved = _invoke(
        module,
        _event(
            "/enterprise/policies/policy-governed/versions/1/decision",
            "POST",
            body={"decision": "approved", "reason": "Independent review"},
            claims=reviewer_claims,
        ),
    )
    assert approved["statusCode"] == 200
    assert json.loads(approved["body"])["approvedBy"] == "reviewer-2"
    staged = _invoke(
        module,
        _event(
            "/enterprise/policies/policy-governed/versions/1/stage",
            "POST",
            claims=reviewer_claims,
        ),
    )
    assert staged["statusCode"] == 200
    activated = _invoke(
        module,
        _event(
            "/enterprise/policies/policy-governed/versions/1/activate",
            "POST",
            body={"expectedActiveVersion": 0},
            claims=reviewer_claims,
        ),
    )
    assert activated["statusCode"] == 200
    assert json.loads(activated["body"])["activeVersion"] == 1

    group = _invoke(
        module,
        _event(
            "/enterprise/groups",
            "POST",
            body={
                "groupId": "group-active",
                "name": "Active",
                "policyId": "policy-governed",
            },
            claims=admin_claims,
        ),
    )
    assert group["statusCode"] == 201

    draft_two = _invoke(
        module,
        _event(
            "/enterprise/policies/policy-governed/versions",
            "POST",
            body={
                "name": "Governed v2",
                "configuration": {"tools": {"allowed": ["read_repository", "run_tests"]}},
            },
            claims=author_claims,
        ),
    )
    assert draft_two["statusCode"] == 200
    assert json.loads(draft_two["body"])["state"] == "draft"
    policy_record = table.items[(f"TENANT#{tenant}", "POLICY#policy-governed")]
    assert policy_record["version"] == 1
    assert policy_record["configuration"] == {"tools": {"allowed": ["read_repository"]}}
    duplicate_pending = _invoke(
        module,
        _event(
            "/enterprise/policies/policy-governed/versions",
            "POST",
            body={"name": "Bypass", "configuration": {}},
            claims=author_claims,
        ),
    )
    assert duplicate_pending["statusCode"] == 409
    versions = _invoke(
        module,
        _event(
            "/enterprise/policies/policy-governed/versions",
            "GET",
            claims=reviewer_claims,
        ),
    )
    version_items = json.loads(versions["body"])["items"]
    assert [item["version"] for item in version_items] == [2, 1]
    assert version_items[0]["changeSummary"]["changedSections"] == ["tools"]

    assert (
        _invoke(
            module,
            _event(
                "/enterprise/policies/policy-governed/versions/2/submit",
                "POST",
                claims=author_claims,
            ),
        )["statusCode"]
        == 200
    )
    assert (
        _invoke(
            module,
            _event(
                "/enterprise/policies/policy-governed/versions/2/decision",
                "POST",
                body={"decision": "approved", "reason": "Independent v2 review"},
                claims=reviewer_claims,
            ),
        )["statusCode"]
        == 200
    )
    assert (
        _invoke(
            module,
            _event(
                "/enterprise/policies/policy-governed/versions/2/stage",
                "POST",
                claims=reviewer_claims,
            ),
        )["statusCode"]
        == 200
    )
    policy_key = (f"TENANT#{tenant}", "POLICY#policy-governed")

    def concurrent_activation() -> None:
        table.items[policy_key]["version"] = 9

    module.DYNAMODB.before_transaction = concurrent_activation
    conflicted_activation = _invoke(
        module,
        _event(
            "/enterprise/policies/policy-governed/versions/2/activate",
            "POST",
            body={"expectedActiveVersion": 1},
            claims=reviewer_claims,
        ),
    )
    assert conflicted_activation["statusCode"] == 409
    assert table.items[policy_key]["version"] == 9
    assert (
        table.items[
            (
                f"TENANT#{tenant}",
                "POLICY_VERSION#policy-governed:00000000000000000002",
            )
        ]["state"]
        == "staged"
    )
    assert (
        table.items[
            (
                f"TENANT#{tenant}",
                "POLICY_VERSION#policy-governed:00000000000000000001",
            )
        ]["state"]
        == "active"
    )

    secret_policy = _invoke(
        module,
        _event(
            "/enterprise/policies",
            "POST",
            body={
                "policyId": "policy-secret",
                "name": "Secret",
                "configuration": {"access_token": "synthetic-do-not-store"},
            },
            claims=author_claims,
        ),
    )
    assert secret_policy["statusCode"] == 400
    assert "must not contain secrets" in json.loads(secret_policy["body"])["error"]


def test_aws_policy_governance_migrates_existing_active_authority(monkeypatch: Any) -> None:
    """Legacy active policies gain an immutable ledger without interrupting coverage."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-policy-migration"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(Item=module._item_key(tenant, "ORG", "org-a") | {"id": "org-a", "name": "Alpha"})
    table.put_item(
        Item=module._item_key(tenant, "POLICY", "policy-legacy")
        | {
            "id": "policy-legacy",
            "organization_id": "org-a",
            "name": "Legacy",
            "configuration": {"runtime": {"maxActions": 12, "maxTokens": 5000}},
            "version": 3,
            "createdAt": 100,
            "author": "legacy-author",
        }
    )
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["auditor"],
        "sub": "auditor-1",
    }

    response = _invoke(
        module,
        _event("/enterprise/policies", "GET", claims=claims),
    )
    assert response["statusCode"] == 200
    policy = json.loads(response["body"])["items"][0]
    assert policy["activeVersion"] == 3
    assert policy["governanceState"] == "active"
    version = table.items[
        (
            f"TENANT#{tenant}",
            "POLICY_VERSION#policy-legacy:00000000000000000003",
        )
    ]
    assert version["state"] == "active"
    assert version["author"] == "legacy-author"
    assert (
        version["content_hash"]
        == hashlib.sha256(
            json.dumps(policy["configuration"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


def test_aws_policy_governance_deployment_grants_transaction_authority() -> None:
    """The Lambda role explicitly permits its same-table atomic activation write."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    assert 'table.grant(handler, "dynamodb:TransactWriteItems")' in stack


def test_aws_strong_authentication_assertion_is_server_owned() -> None:
    """Emergency MFA posture must not be derived from a mutable user attribute."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    assert "ENTRA_STRONG_AUTH_ENFORCED" in stack
    assert "CONTROL_TABLE: table.tableName" in stack
    assert "table.grantReadData(entraClaims)" in stack
    assert "entra_auth_methods" not in stack


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

    missing_ownership = _invoke(
        module,
        _event(
            "/enterprise/agents/register",
            "POST",
            body={
                "deploymentId": "deployment-pilot",
                "agentId": "unowned-agent",
                "host": "claude-code",
                "projectRoot": "/synthetic/unowned",
            },
            claims=claims,
        ),
    )
    assert missing_ownership["statusCode"] == 400
    assert "ownership must contain" in json.loads(missing_ownership["body"])["error"]

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
                "ownership": _ownership(),
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
    assert stored["team"] == "Platform"
    assert stored["owner_id"] == "owner-platform"
    assert stored["ownership_criticality"] == "high"
    assert json.loads(registered["body"])["ownership"]["status"] == "current"
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


def test_runtime_attestation_binds_heartbeat_and_quarantines_tampering(
    monkeypatch: Any,
) -> None:
    """Only fresh exact runtime evidence can establish and retain agent readiness."""
    module, table = _load_handler(monkeypatch)
    now = 1_900_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    _set_runtime_manifests(monkeypatch, [_runtime_manifest()])
    tenant = "tenant-attestation"
    token = "synthetic-attested-agent-session-123456"  # noqa: S105
    project_digest = hashlib.sha256(b"/synthetic/project").hexdigest()
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant, "status": "active"}
    )
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "dep-a")
        | {
            "id": "dep-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "sdk_version": "1.1.0",
        }
    )
    managed = {
        "host": "claude-code",
        "hostVersion": "2.1.211",
        "platform": "linux",
        "bundleHash": "d" * 64,
        "policyId": "policy-a",
        "policyVersion": 1,
    }
    table.put_item(
        Item=module._item_key(tenant, "CONFIGURATION", "dep-a")
        | {"desiredConfiguration": {"managedHost": managed}}
    )
    agent = module._item_key(tenant, "AGENT", "dep-a:agent-a") | {
        "id": "agent-a",
        "deployment_id": "dep-a",
        "host": "claude-code",
        "project_root": "/synthetic/project",
        "status": "offline",
        "expires_at": 0,
        "emergencyStop": False,
        **_ownership_record(now),
    }
    table.put_item(Item=agent)
    table.put_item(
        Item={
            "pk": module._token_key("AGENT_SESSION", token),
            "sk": "SESSION",
            "tenant_id": tenant,
            "deployment_id": "dep-a",
            "agent_id": "agent-a",
            "project_root_hash": project_digest,
            "issued_at": now,
            "expires_at": now + 900,
            "ttl": now + 900,
        }
    )
    policy = module._item_key(tenant, "POLICY", "policy-a") | {
        "id": "policy-a",
        "version": 1,
        "configuration": {"runtime": {"allowedTools": ["read_repository"]}},
    }
    group = module._item_key(tenant, "GROUP", "group-a") | {
        "id": "group-a",
        "policyId": "policy-a",
        "agent_keys": ["dep-a:agent-a"],
    }
    table.put_item(Item=policy)
    table.put_item(Item=group)

    challenge = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/attestation/challenge",
            "POST",
            token=token,
        ),
    )
    assert challenge["statusCode"] == 200
    nonce = json.loads(challenge["body"])["nonce"]
    heartbeat = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/heartbeat",
            "POST",
            token=token,
            body={
                "attestation": _runtime_evidence(nonce, observed_at=now),
                "managedConfiguration": {
                    **managed,
                    "source": "endpoint-managed-file",
                    "verifiedAt": now,
                    "expiresAt": now + 300,
                },
            },
        ),
    )
    assert heartbeat["statusCode"] == 200
    stored = table.items[(f"TENANT#{tenant}", "AGENT#dep-a:agent-a")]
    assert stored["status"] == "connected"
    assert stored["attestation_status"] == "compliant"
    assert stored["attestation_expires_at"] == now + 300
    assert stored["managed_configuration_report"]["bundleHash"] == "d" * 64
    assert "configurationDigest" not in stored

    claims = {"custom:tenant_id": tenant, "cognito:groups": ["auditor"], "sub": "auditor"}
    verified = json.loads(
        _invoke(
            module,
            _event("/enterprise/agents/dep-a/agent-a/verify", "GET", claims=claims),
        )["body"]
    )
    assert verified["verified"] is True
    assert verified["checks"]["runtimeAttestation"]["passed"] is True
    effective = _invoke(
        module,
        _event("/agent/dep-a/agent-a/effective-policy", "GET", token=token),
    )
    assert effective["statusCode"] == 200

    second_challenge = json.loads(
        _invoke(
            module,
            _event(
                "/agent/dep-a/agent-a/attestation/challenge",
                "POST",
                token=token,
            ),
        )["body"]
    )["nonce"]
    tampered = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/heartbeat",
            "POST",
            token=token,
            body={
                "attestation": _runtime_evidence(
                    second_challenge,
                    observed_at=now,
                    configuration_digest="9" * 64,
                )
            },
        ),
    )
    assert tampered["statusCode"] == 403
    assert "enrollment_baseline_mismatch" in json.loads(tampered["body"])["error"]
    quarantined = table.items[(f"TENANT#{tenant}", "AGENT#dep-a:agent-a")]
    assert quarantined["status"] == "quarantined"
    assert quarantined["attestation_reason_codes"] == ["enrollment_baseline_mismatch"]
    assert (
        module._token_key("AGENT_SESSION", token),
        "SESSION",
    ) not in table.items
    denied = _invoke(
        module,
        _event("/agent/dep-a/agent-a/effective-policy", "GET", token=token),
    )
    assert denied["statusCode"] == 403


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ({}, "evidence_schema_invalid"),
        ({"observedAt": 1_800_000_000}, "evidence_stale"),
        ({"nonce": "wrong-runtime-attestation-challenge-value"}, "challenge_invalid"),
        ({"packageDigest": "9" * 64}, "packageDigest_mismatch"),
    ],
)
def test_runtime_attestation_rejects_missing_stale_replayed_and_modified_evidence(
    monkeypatch: Any,
    mutation: dict[str, Any],
    reason: str,
) -> None:
    """Every bypass class revokes the session and emits a bounded reason code."""
    module, table = _load_handler(monkeypatch)
    now = 1_900_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    _set_runtime_manifests(monkeypatch, [_runtime_manifest()])
    tenant = "tenant-negative-attestation"
    token = "synthetic-negative-attestation-token-123456"  # noqa: S105
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "dep-a")
        | {"id": "dep-a", "sdk_version": "1.1.0"}
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "host": "claude-code",
            "project_root": "/synthetic/project",
            "status": "offline",
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
            "expires_at": now + 900,
        }
    )
    challenge = json.loads(
        _invoke(
            module,
            _event(
                "/agent/dep-a/agent-a/attestation/challenge",
                "POST",
                token=token,
            ),
        )["body"]
    )["nonce"]
    evidence = _runtime_evidence(challenge, observed_at=now)
    evidence.update(mutation)
    if mutation == {}:
        evidence = {}
    result = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/heartbeat",
            "POST",
            token=token,
            body={"attestation": evidence},
        ),
    )
    assert result["statusCode"] == 403
    assert reason in json.loads(result["body"])["error"]


def test_runtime_attestation_rejects_host_version_missing_from_configured_bundle(
    monkeypatch: Any,
) -> None:
    """A configured trust bundle cannot silently fall back for an unapproved release."""
    module, table = _load_handler(monkeypatch)
    now = 1_900_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    _set_runtime_manifests(monkeypatch, [_runtime_manifest()])
    tenant = "tenant-unapproved-version"
    token = "synthetic-unapproved-attestation-token-123456"  # noqa: S105
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "dep-a")
        | {"id": "dep-a", "sdk_version": "9.9.9"}
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "host": "claude-code",
            "project_root": "/synthetic/project",
            "status": "offline",
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
            "expires_at": now + 900,
        }
    )

    challenge = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/attestation/challenge",
            "POST",
            token=token,
        ),
    )
    assert json.loads(challenge["body"])["required"] is True
    heartbeat = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/heartbeat",
            "POST",
            token=token,
            body={"attestation": _runtime_evidence("unused", observed_at=now)},
        ),
    )
    assert heartbeat["statusCode"] == 403
    assert "approved_manifest_missing" in json.loads(heartbeat["body"])["error"]
    assert table.items[(f"TENANT#{tenant}", "AGENT#dep-a:agent-a")]["status"] == ("quarantined")


def test_runtime_manifest_approvals_fail_closed_for_unbound_release_evidence(
    monkeypatch: Any,
) -> None:
    """A manifest cannot become trusted without exact independently reviewed provenance."""
    module, _ = _load_handler(monkeypatch)
    manifests = [_runtime_manifest("claude-code"), _runtime_manifest("codex-cli")]
    raw = json.dumps(manifests)
    entry: dict[str, Any] = {
        "hosts": ["claude-code", "codex-cli"],
        "releaseEvidenceSha256": "9" * 64,
        "releaseTag": "v1.1.0",
        "sdkRevision": "a" * 40,
        "sdkVersion": "1.1.0",
        "sourceOriginDigest": "b" * 64,
    }
    base: dict[str, Any] = {
        "schemaVersion": 1,
        "manifestBundleSha256": hashlib.sha256(raw.encode()).hexdigest(),
        "approvals": [entry],
    }
    monkeypatch.setenv("RUNTIME_ATTESTATION_MANIFESTS", raw)
    monkeypatch.setenv(
        "RUNTIME_ATTESTATION_MANIFESTS_SHA256", hashlib.sha256(raw.encode()).hexdigest()
    )

    def set_approval(value: dict[str, Any]) -> None:
        """Bind each synthetic mutation so structural validation is reached."""
        encoded = json.dumps(value)
        monkeypatch.setenv("RUNTIME_ATTESTATION_APPROVALS", encoded)
        monkeypatch.setenv(
            "RUNTIME_ATTESTATION_APPROVALS_SHA256", hashlib.sha256(encoded.encode()).hexdigest()
        )

    set_approval(base)
    assert len(module._runtime_manifests()) == 2

    invalid = dict(base)
    invalid["manifestBundleSha256"] = "0" * 64
    set_approval(invalid)
    with pytest.raises(RuntimeError, match="does not bind the manifest bundle"):
        module._runtime_manifests()

    invalid = {**base, "approvals": [{**entry, "hosts": ["claude-code"]}]}
    set_approval(invalid)
    with pytest.raises(RuntimeError, match="do not cover"):
        module._runtime_manifests()

    invalid = {
        **base,
        "approvals": [{**entry, "sdkRevision": "c" * 40}],
    }
    set_approval(invalid)
    with pytest.raises(RuntimeError, match="revision does not match"):
        module._runtime_manifests()


def test_checked_in_empty_runtime_bundle_is_bound_but_not_configured(monkeypatch: Any) -> None:
    """Development remains honest: exact empty approval evidence is not compliance."""
    module, _ = _load_handler(monkeypatch)
    monkeypatch.delenv("RUNTIME_ATTESTATION_MANIFESTS", raising=False)
    monkeypatch.delenv("RUNTIME_ATTESTATION_APPROVALS", raising=False)

    assert module._runtime_manifests() == []


def test_runtime_manifest_environment_override_requires_pinned_digest(monkeypatch: Any) -> None:
    """An environment injection cannot bypass the CDK-pinned bundle identity."""
    module, _ = _load_handler(monkeypatch)
    monkeypatch.setenv("RUNTIME_ATTESTATION_MANIFESTS", "[]")
    monkeypatch.delenv("RUNTIME_ATTESTATION_MANIFESTS_SHA256", raising=False)

    with pytest.raises(RuntimeError, match="manifest environment integrity failed"):
        module._runtime_manifests()


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


def test_agent_revocation_immediately_denies_sessions_bootstrap_and_identity_reuse(
    monkeypatch: Any,
) -> None:
    """One durable transition invalidates every old capability at request time."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-agent-revoke"
    now = 1_900_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "operator-revoke",
    }
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant, "status": "active"}
    )
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "dep-a")
        | {
            "id": "dep-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "environment": "prod",
            "region": "eu-west-2",
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "deployment_id": "dep-a",
            "host": "claude-code",
            "project_root": "/synthetic/project",
            "environment": "prod",
            "region": "eu-west-2",
            "status": "connected",
            "last_heartbeat": now,
            "expires_at": now + 300,
            "emergencyStop": False,
            "lifecycle_state": "active",
            # boto3's resource layer returns DynamoDB numbers as Decimal.
            "lifecycle_revision": Decimal("1"),
        }
    )
    bootstrap_response = _invoke(
        module,
        _event(
            "/enterprise/agents/bootstrap",
            "POST",
            body={"deploymentId": "dep-a", "agentId": "agent-a"},
            claims=claims,
        ),
    )
    assert bootstrap_response["statusCode"] == 201
    bootstrap_token = json.loads(bootstrap_response["body"])["bootstrapToken"]
    session_token = "synthetic-session-before-revocation"  # noqa: S105
    table.put_item(
        Item={
            "pk": module._token_key("AGENT_SESSION", session_token),
            "sk": "SESSION",
            "tenant_id": tenant,
            "deployment_id": "dep-a",
            "agent_id": "agent-a",
            "project_root_hash": hashlib.sha256(b"/synthetic/project").hexdigest(),
            "expires_at": now + 900,
        }
    )
    # Prove that S3 is only a replica: the immutable transaction evidence must
    # still make the transition successful during an audit-bucket outage.
    monkeypatch.setattr(
        module, "_audit", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError())
    )
    revoked = _invoke(
        module,
        _event(
            "/enterprise/agents/dep-a/agent-a/revoke",
            "POST",
            body={
                "expectedLifecycleRevision": 1,
                "reason": "Device is no longer trusted after incident review.",
            },
            claims=claims,
        ),
    )
    assert revoked["statusCode"] == 200
    revoked_payload = json.loads(revoked["body"])
    assert revoked_payload["lifecycle_state"] == "revoked"
    assert revoked_payload["lifecycle_revision"] == 2
    assert revoked_payload["status"] == "offline"
    assert revoked_payload["emergencyStop"] is True
    assert "bootstrapToken" not in revoked_payload and "accessToken" not in revoked_payload
    assert len([key for key in table.items if key[1].startswith("AGENT_LIFECYCLE_AUDIT#")]) == 1

    denied_session = _invoke(
        module,
        _event("/agent/dep-a/agent-a/heartbeat", "POST", token=session_token),
    )
    assert denied_session["statusCode"] == 403
    denied_bootstrap = _invoke(
        module,
        _event(
            "/agent/enroll",
            "POST",
            body={
                "bootstrapToken": bootstrap_token,
                "projectRoot": "/synthetic/project",
            },
        ),
    )
    assert denied_bootstrap["statusCode"] == 403
    assert "revoked or offboarded" in json.loads(denied_bootstrap["body"])["error"]
    new_bootstrap = _invoke(
        module,
        _event(
            "/enterprise/agents/bootstrap",
            "POST",
            body={"deploymentId": "dep-a", "agentId": "agent-a"},
            claims=claims,
        ),
    )
    assert new_bootstrap["statusCode"] == 409
    reused = _invoke(
        module,
        _event(
            "/enterprise/agents/register",
            "POST",
            body={
                "deploymentId": "dep-a",
                "agentId": "agent-a",
                "host": "claude-code",
                "projectRoot": "/synthetic/project",
            },
            claims=claims,
        ),
    )
    assert reused["statusCode"] == 409
    stale_retry = _invoke(
        module,
        _event(
            "/enterprise/agents/dep-a/agent-a/revoke",
            "POST",
            body={
                "expectedLifecycleRevision": 1,
                "reason": "Device is no longer trusted after incident review.",
            },
            claims=claims,
        ),
    )
    assert stale_retry["statusCode"] == 409
    assert len([key for key in table.items if key[1].startswith("AGENT_LIFECYCLE_AUDIT#")]) == 1


def test_agent_ownership_review_is_cas_audited_and_expires(monkeypatch: Any) -> None:
    """Ownership review is server-derived, durable, concurrent-safe and time bounded."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-agent-ownership"
    now = 1_900_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "fleet-owner-reviewer",
    }
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant, "status": "active"}
    )
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "dep-a")
        | {
            "id": "dep-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "environment": "prod",
            "region": "eu-west-2",
            "team": "Payments platform",
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "deployment_id": "dep-a",
            "host": "claude-code",
            "project_root": "/synthetic/project",
            "environment": "prod",
            "region": "eu-west-2",
            "status": "offline",
            "last_heartbeat": 0,
            "expires_at": 0,
            "emergencyStop": False,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
        }
    )
    reviewed = _invoke(
        module,
        _event(
            "/enterprise/agents/dep-a/agent-a/ownership",
            "PUT",
            body={
                "expectedOwnershipRevision": 0,
                "ownership": _ownership(criticality="critical"),
                "reason": "Quarterly accountable ownership review was approved.",
            },
            claims=claims,
        ),
    )
    assert reviewed["statusCode"] == 200
    payload = json.loads(reviewed["body"])
    assert payload["ownership"] == {
        "status": "current",
        "revision": 1,
        "ownerId": "owner-platform",
        "ownerName": "Platform owner",
        "team": "Payments platform",
        "businessContact": "platform@example.invalid",
        "environment": "prod",
        "criticality": "critical",
        "reviewedAt": now,
        "reviewDueAt": now + module._AGENT_OWNERSHIP_REVIEW_SECONDS,
        "reviewedBy": "fleet-owner-reviewer",
        "reasonCodes": [],
    }
    assert len([key for key in table.items if key[1].startswith("AGENT_LIFECYCLE_AUDIT#")]) == 1
    stale_write = _invoke(
        module,
        _event(
            "/enterprise/agents/dep-a/agent-a/ownership",
            "PUT",
            body={
                "expectedOwnershipRevision": 0,
                "ownership": _ownership(),
                "reason": "A concurrent stale review must not overwrite authority.",
            },
            claims=claims,
        ),
    )
    assert stale_write["statusCode"] == 409
    monkeypatch.setattr(
        module.time,
        "time",
        lambda: now + module._AGENT_OWNERSHIP_REVIEW_SECONDS + 1,
    )
    verification = json.loads(
        _invoke(
            module,
            _event(
                "/enterprise/agents/dep-a/agent-a/verify",
                "GET",
                claims=claims,
            ),
        )["body"]
    )
    assert verification["verified"] is False
    assert verification["ownership"]["status"] == "stale"
    assert verification["checks"]["ownership"] == {
        "passed": False,
        "detail": "Agent ownership review is stale.",
    }


def test_agent_ownership_rejects_invalid_and_inactive_entra_owners(monkeypatch: Any) -> None:
    """Malformed contacts and disabled directory identities cannot own an agent."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-entra-owner"
    owner_id = "0d0f80b7-7890-4ed4-b2bf-cb7fb4e40c14"
    monkeypatch.setattr(module, "SCIM", table)
    monkeypatch.setenv("SCIM_ENABLED", "true")
    monkeypatch.setenv("ENTRA_AAI_TENANT_ID", tenant)
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant, "status": "active"}
    )
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "dep-a")
        | {
            "id": "dep-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "environment": "prod",
            "region": "eu-west-2",
            "team": "Platform",
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "deployment_id": "dep-a",
            "host": "codex-cli",
            "project_root": "/synthetic/project",
            "environment": "prod",
            "region": "eu-west-2",
            "status": "offline",
            "emergencyStop": False,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
        }
    )
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "owner-reviewer",
    }
    request = {
        "expectedOwnershipRevision": 0,
        "ownership": _ownership(ownerId=owner_id),
        "reason": "Directory-backed owner review for production service.",
    }
    inactive = _invoke(
        module,
        _event(
            "/enterprise/agents/dep-a/agent-a/ownership",
            "PUT",
            body=request,
            claims=claims,
        ),
    )
    assert inactive["statusCode"] == 400
    assert "actively provisioned" in json.loads(inactive["body"])["error"]
    table.put_item(
        Item={
            "pk": f"TENANT#{tenant}",
            "sk": f"USER#{owner_id}",
            "id": owner_id,
            "active": True,
        }
    )
    invalid_contact = {
        **request,
        "ownership": _ownership(ownerId=owner_id, businessContact="not-an-email"),
    }
    denied = _invoke(
        module,
        _event(
            "/enterprise/agents/dep-a/agent-a/ownership",
            "PUT",
            body=invalid_contact,
            claims=claims,
        ),
    )
    assert denied["statusCode"] == 400
    assert "valid email" in json.loads(denied["body"])["error"]


def test_concurrent_heartbeat_cannot_overwrite_agent_revocation(monkeypatch: Any) -> None:
    """A stale whole-record heartbeat write is lifecycle-revision guarded."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-agent-heartbeat-race"
    token = "synthetic-heartbeat-race-session"  # noqa: S105
    now = int(time.time())
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "host": "claude-code",
            "project_root": "/synthetic/project",
            "status": "offline",
            "expires_at": 0,
            "emergencyStop": False,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
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
            "expires_at": now + 900,
        }
    )
    original_put = table.put_item
    raced = False

    def revoke_before_heartbeat_put(*, Item: dict[str, Any], **kwargs: Any) -> None:
        nonlocal raced
        if kwargs.get("ConditionExpression") and Item.get("id") == "agent-a" and not raced:
            raced = True
            module._revoke_agent(
                tenant,
                "dep-a",
                "agent-a",
                {
                    "expectedLifecycleRevision": 1,
                    "reason": "Incident response revoked identity during heartbeat processing.",
                },
                "incident-operator",
            )
        original_put(Item=Item, **kwargs)

    monkeypatch.setattr(table, "put_item", revoke_before_heartbeat_put)
    heartbeat = _invoke(
        module,
        _event("/agent/dep-a/agent-a/heartbeat", "POST", token=token),
    )
    assert heartbeat["statusCode"] == 403
    stored = table.items[(f"TENANT#{tenant}", "AGENT#dep-a:agent-a")]
    assert stored["lifecycle_state"] == "revoked"
    assert stored["status"] == "offline"
    assert stored["lifecycle_revision"] == 2


def test_agent_replacement_is_atomic_inherits_groups_and_requires_new_enrollment(
    monkeypatch: Any,
) -> None:
    """Replacement never reuses identity or exposes a half-applied authority edge."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-agent-replace"
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "operator-replace",
    }
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "dep-a")
        | {
            "id": "dep-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "environment": "prod",
            "region": "eu-west-2",
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-old")
        | {
            "id": "agent-old",
            "organization_id": "org-a",
            "project_id": "project-a",
            "deployment_id": "dep-a",
            "host": "codex-cli",
            "project_root": "/synthetic/project",
            "environment": "prod",
            "region": "eu-west-2",
            "status": "connected",
            "last_heartbeat": 10,
            "expires_at": 20,
            "emergencyStop": False,
            "created_at": 1,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "GROUP", "group-a")
        | {
            "id": "group-a",
            "organizationId": "org-a",
            "policyId": "policy-a",
            "agent_keys": ["dep-a:agent-old"],
        }
    )
    old_session = "synthetic-old-replacement-session"  # noqa: S105
    table.put_item(
        Item={
            "pk": module._token_key("AGENT_SESSION", old_session),
            "sk": "SESSION",
            "tenant_id": tenant,
            "deployment_id": "dep-a",
            "agent_id": "agent-old",
            "project_root_hash": hashlib.sha256(b"/synthetic/project").hexdigest(),
            "expires_at": int(time.time()) + 900,
        }
    )
    replaced = _invoke(
        module,
        _event(
            "/enterprise/agents/dep-a/agent-old/replace",
            "POST",
            body={
                "expectedLifecycleRevision": 1,
                "replacementAgentId": "agent-new",
                "reason": "Managed workstation refresh requires a distinct identity.",
            },
            claims=claims,
        ),
    )
    assert replaced["statusCode"] == 201
    payload = json.loads(replaced["body"])
    assert payload["requiresBootstrap"] is True
    assert payload["predecessor"]["lifecycle_state"] == "revoked"
    assert payload["predecessor"]["replacement_agent_id"] == "agent-new"
    assert payload["replacement"]["lifecycle_state"] == "active"
    assert payload["replacement"]["lifecycle_revision"] == 1
    assert payload["replacement"]["successor_of"] == "agent-old"
    assert payload["replacement"]["status"] == "offline"
    assert table.items[(f"TENANT#{tenant}", "GROUP#group-a")]["agent_keys"] == [
        "dep-a:agent-new",
        "dep-a:agent-old",
    ]
    assert table.items[(f"TENANT#{tenant}", "GROUP#group-a")]["membership_revision"] == 2
    assert (
        _invoke(
            module,
            _event("/agent/dep-a/agent-old/heartbeat", "POST", token=old_session),
        )["statusCode"]
        == 403
    )

    bootstrap = _invoke(
        module,
        _event(
            "/enterprise/agents/bootstrap",
            "POST",
            body={"deploymentId": "dep-a", "agentId": "agent-new"},
            claims=claims,
        ),
    )
    assert bootstrap["statusCode"] == 201
    enrolled = _invoke(
        module,
        _event(
            "/agent/enroll",
            "POST",
            body={
                "bootstrapToken": json.loads(bootstrap["body"])["bootstrapToken"],
                "projectRoot": "/synthetic/project",
            },
        ),
    )
    assert enrolled["statusCode"] == 201
    assert json.loads(enrolled["body"])["agentId"] == "agent-new"


def test_agent_replacement_rolls_back_when_group_membership_changes_concurrently(
    monkeypatch: Any,
) -> None:
    """A stale group snapshot cannot produce partial replacement authority."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-agent-replace-race"
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "operator-replace",
    }
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-old")
        | {
            "id": "agent-old",
            "deployment_id": "dep-a",
            "host": "claude-code",
            "project_root": "/synthetic/project",
            "status": "offline",
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "GROUP", "group-a")
        | {"id": "group-a", "agent_keys": ["dep-a:agent-old"]}
    )

    def change_membership() -> None:
        group = table.items[(f"TENANT#{tenant}", "GROUP#group-a")]
        group["agent_keys"] = ["dep-a:agent-old", "dep-a:concurrent-agent"]

    module.DYNAMODB.before_transaction = change_membership
    response = _invoke(
        module,
        _event(
            "/enterprise/agents/dep-a/agent-old/replace",
            "POST",
            body={
                "expectedLifecycleRevision": 1,
                "replacementAgentId": "agent-new",
                "reason": "Managed workstation refresh requires a distinct identity.",
            },
            claims=claims,
        ),
    )
    assert response["statusCode"] == 409
    assert table.items[(f"TENANT#{tenant}", "AGENT#dep-a:agent-old")]["lifecycle_state"] == (
        "active"
    )
    assert (f"TENANT#{tenant}", "AGENT#dep-a:agent-new") not in table.items
    assert table.items[(f"TENANT#{tenant}", "GROUP#group-a")]["agent_keys"] == [
        "dep-a:agent-old",
        "dep-a:concurrent-agent",
    ]
    assert not [key for key in table.items if key[1].startswith("AGENT_LIFECYCLE_AUDIT#")]


def test_agent_offboarding_requires_revocation_and_retains_minimal_tombstone(
    monkeypatch: Any,
) -> None:
    """Deletion removes operational data but preserves immutable lifecycle evidence."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-agent-offboard"
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "operator-offboard",
    }
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "deployment_id": "dep-a",
            "host": "claude-code",
            "project_root": "/synthetic/private-project",
            "environment": "prod",
            "region": "eu-west-2",
            "status": "connected",
            "last_heartbeat": 100,
            "expires_at": 200,
            "emergencyStop": False,
            "created_at": 50,
            "telemetry": {"actionsTotal": 99},
            "managed_configuration_report": {"bundleHash": "sensitive-operational-state"},
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
        }
    )
    premature = _invoke(
        module,
        _event(
            "/enterprise/agents/dep-a/agent-a/offboard",
            "POST",
            body={
                "expectedLifecycleRevision": 1,
                "reason": "Repository ownership ended under the approved leaver process.",
            },
            claims=claims,
        ),
    )
    assert premature["statusCode"] == 409
    revoke = _invoke(
        module,
        _event(
            "/enterprise/agents/dep-a/agent-a/revoke",
            "POST",
            body={
                "expectedLifecycleRevision": 1,
                "reason": "Repository ownership ended under the approved leaver process.",
            },
            claims=claims,
        ),
    )
    assert revoke["statusCode"] == 200
    offboard = _invoke(
        module,
        _event(
            "/enterprise/agents/dep-a/agent-a/offboard",
            "POST",
            body={
                "expectedLifecycleRevision": 2,
                "reason": "Evidence retained after the approved offboarding review.",
            },
            claims=claims,
        ),
    )
    assert offboard["statusCode"] == 200
    tombstone = json.loads(offboard["body"])
    assert tombstone["lifecycle_state"] == "deleted"
    assert tombstone["lifecycle_revision"] == 3
    assert tombstone["project_root"] == ""
    assert (
        tombstone["project_root_hash"] == hashlib.sha256(b"/synthetic/private-project").hexdigest()
    )
    assert "telemetry" not in tombstone
    assert "managed_configuration_report" not in tombstone
    assert tombstone["created_at"] == 50
    assert tombstone["revoked_by"] == "operator-offboard"
    assert tombstone["deleted_by"] == "operator-offboard"
    assert len([key for key in table.items if key[1].startswith("AGENT_LIFECYCLE_AUDIT#")]) == 2
    verification = json.loads(
        _invoke(
            module,
            _event("/enterprise/agents/dep-a/agent-a/verify", "GET", claims=claims),
        )["body"]
    )
    assert verification["verified"] is False
    assert verification["checks"]["lifecycle"] == {
        "passed": False,
        "detail": "Agent identity is revoked, offboarded, or malformed.",
    }


def test_agent_verification_requires_every_operational_prerequisite(monkeypatch: Any) -> None:
    """The AWS UI verification endpoint must not equate existence with readiness."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-verify"
    now = int(time.time())
    _set_runtime_manifests(monkeypatch, [_runtime_manifest()])
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "dep-a")
        | {"id": "dep-a", "sdk_version": "1.1.0"}
    )
    managed = {
        "host": "claude-code",
        "hostVersion": "2.1.211",
        "platform": "linux",
        "bundleHash": "a" * 64,
        "policyId": "policy-a",
        "policyVersion": 1,
    }
    table.put_item(
        Item=module._item_key(tenant, "CONFIGURATION", "dep-a")
        | {"deploymentId": "dep-a", "desiredConfiguration": {"managedHost": managed}}
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "status": "connected",
            "expires_at": now + 300,
            "emergencyStop": False,
            "host": "claude-code",
            "project_root": "/synthetic/project",
            "attestation_status": "compliant",
            "attestation_observed_at": now,
            "attestation_expires_at": now + 300,
            "attestation_reason_codes": [],
            "managed_configuration_report": {
                **managed,
                "source": "endpoint-managed-file",
                "verifiedAt": now,
                "expiresAt": now + 300,
            },
            **_ownership_record(now),
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
    assert payload["host"] == "claude-code"
    assert payload["groups"] == ["group-a"]
    assert payload["policyId"] == "policy-a"
    assert payload["policyVersion"] == 1
    assert payload["managedConfiguration"]["status"] == "enforced"

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


def test_aws_managed_configuration_posture_rejects_drift_and_staleness(
    monkeypatch: Any,
) -> None:
    """The deployed projection derives posture instead of trusting a status field."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-managed"
    desired = {
        "host": "codex-cli",
        "hostVersion": "0.146.0",
        "platform": "linux",
        "bundleHash": "b" * 64,
        "policyId": "policy-safe",
        "policyVersion": 3,
    }
    agent: dict[str, object] = {
        "id": "codex-a",
        "deployment_id": "dep-a",
        "host": "codex-cli",
    }
    table.put_item(
        Item=module._item_key(tenant, "CONFIGURATION", "dep-a")
        | {"desiredConfiguration": {"managedHost": desired}}
    )
    assert module._managed_configuration_posture(tenant, agent, now=100)["status"] == "missing"
    with pytest.raises(PermissionError, match="not freshly enforced"):
        module._require_current_managed_configuration(tenant, agent)

    enforced_report: dict[str, object] = {
        **desired,
        "source": "codex-system",
        "verifiedAt": 90,
        "expiresAt": 200,
    }
    agent["managed_configuration_report"] = enforced_report
    assert module._managed_configuration_posture(tenant, agent, now=100)["status"] == "enforced"
    monkeypatch.setattr(module.time, "time", lambda: 100)
    module._require_current_managed_configuration(tenant, agent)
    agent["managed_configuration_report"] = {
        **enforced_report,
        "bundleHash": "c" * 64,
    }
    assert module._managed_configuration_posture(tenant, agent, now=100)["status"] == "conflict"
    agent["managed_configuration_report"] = {
        **desired,
        "source": "codex-system",
        "verifiedAt": 90,
        "expiresAt": 95,
    }
    assert module._managed_configuration_posture(tenant, agent, now=100)["status"] == "stale"

    with pytest.raises(ValueError, match="source"):
        module._managed_host(
            {
                **desired,
                "source": "project-file",
                "verifiedAt": 90,
                "expiresAt": 200,
            },
            report=True,
        )
    with pytest.raises(ValueError, match="SHA-256"):
        module._managed_host({**desired, "bundleHash": "not-a-digest"})

    dynamodb_report = module._managed_host(
        {
            **desired,
            "policyVersion": Decimal("3"),
            "source": "codex-system",
            "verifiedAt": Decimal("90"),
            "expiresAt": Decimal("200"),
        },
        report=True,
    )
    assert dynamodb_report["policyVersion"] == 3
    assert dynamodb_report["verifiedAt"] == 90
    with pytest.raises(ValueError, match="policyVersion"):
        module._managed_host({**desired, "policyVersion": Decimal("3.5")})


def test_aws_managed_package_validator_matches_canonical_sdk_contract(monkeypatch: Any) -> None:
    """The standalone Lambda adapter rejects altered and non-canonical package bytes."""
    module, _table = _load_handler(monkeypatch)
    package, desired = _managed_package_fixture()
    package_base64 = base64.b64encode(package.to_json()).decode()
    value, target, encoded = module._managed_package(package_base64, package.package_sha256)
    assert target == desired
    assert encoded == package.to_json()
    assert value["artifacts"][0]["sha256"] == package.artifacts[0].sha256

    with pytest.raises(ValueError, match="digest does not match"):
        module._managed_package(package_base64, "f" * 64)
    noncanonical = json.dumps(package.to_wire(), indent=2, sort_keys=True).encode()
    with pytest.raises(ValueError, match="not canonical"):
        module._managed_package(
            base64.b64encode(noncanonical).decode(), hashlib.sha256(noncanonical).hexdigest()
        )
    tampered = cast(dict[str, Any], package.to_wire())
    tampered["artifacts"][0]["content"] = "altered"
    tampered_bytes = json.dumps(tampered, separators=(",", ":"), sort_keys=True).encode()
    with pytest.raises(ValueError, match="artifact is invalid"):
        module._managed_package(
            base64.b64encode(tampered_bytes).decode(),
            hashlib.sha256(tampered_bytes).hexdigest(),
        )


def test_aws_managed_package_publication_and_drift_repair_route(monkeypatch: Any) -> None:
    """AWS publishes by CAS and lets only the exact attested agent repair drift."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-package"
    now = 1_900_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    _set_runtime_manifests(monkeypatch, [_runtime_manifest()])
    package, desired = _managed_package_fixture()
    project_root = "/synthetic/project"
    token = "synthetic-managed-package-agent-session"  # noqa: S105
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root")
        | {"id": tenant, "status": "active", "emergencyStop": False}
    )
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "dep-a")
        | {
            "id": "dep-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "sdk_version": "1.1.0",
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "CONFIGURATION", "dep-a")
        | {
            "deploymentId": "dep-a",
            "desiredConfiguration": {"managedHost": desired},
            "rolloutState": "active",
            "rolloutPercentage": 100,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "host": "claude-code",
            "project_root": project_root,
            "status": "connected",
            "expires_at": now + 300,
            "emergencyStop": False,
            "attestation_status": "compliant",
            "attestation_expires_at": now + 300,
        }
    )
    table.put_item(
        Item={
            "pk": module._token_key("AGENT_SESSION", token),
            "sk": "SESSION",
            "tenant_id": tenant,
            "deployment_id": "dep-a",
            "agent_id": "agent-a",
            "project_root_hash": hashlib.sha256(project_root.encode()).hexdigest(),
            "expires_at": now + 300,
        }
    )
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-admin-a",
    }
    body = {
        "expectedRevision": 0,
        "packageBase64": base64.b64encode(package.to_json()).decode(),
        "packageSha256": package.package_sha256,
    }
    published = _invoke(
        module,
        _event(
            "/enterprise/deployments/dep-a/managed-package",
            "PUT",
            claims=claims,
            body=body,
        ),
    )
    assert published["statusCode"] == 201
    assert json.loads(published["body"])["revision"] == 1
    replay = _invoke(
        module,
        _event(
            "/enterprise/deployments/dep-a/managed-package",
            "PUT",
            claims=claims,
            body=body,
        ),
    )
    assert replay["statusCode"] == 409

    metadata = json.loads(
        _invoke(
            module,
            _event(
                "/enterprise/deployments/dep-a/managed-package",
                "GET",
                claims={
                    "custom:tenant_id": tenant,
                    "cognito:groups": ["auditor"],
                    "sub": "auditor-a",
                },
            ),
        )["body"]
    )
    assert metadata["status"] == "current"
    assert "packageBase64" not in metadata

    # Missing managed evidence must not deadlock package repair while every
    # identity, project-scope and runtime-attestation check still holds.
    downloaded = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/managed-package",
            "GET",
            token=token,
            project_root=project_root,
        ),
    )
    payload = json.loads(downloaded["body"])
    assert downloaded["statusCode"] == 200
    assert payload["packageBase64"] == body["packageBase64"]
    assert payload["packageSha256"] == package.package_sha256
    assert payload["agentId"] == "agent-a"

    table.items[(f"TENANT#{tenant}", "CONFIGURATION#dep-a")]["rolloutState"] = "paused"
    paused = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/managed-package",
            "GET",
            token=token,
            project_root=project_root,
        ),
    )
    assert paused["statusCode"] == 409


def test_aws_managed_package_publication_requires_platform_admin(monkeypatch: Any) -> None:
    """Policy and fleet roles cannot independently publish endpoint authority."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-package-role"
    package, desired = _managed_package_fixture()
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(Item=module._item_key(tenant, "DEPLOYMENT", "dep-a") | {"id": "dep-a"})
    table.put_item(
        Item=module._item_key(tenant, "CONFIGURATION", "dep-a")
        | {"desiredConfiguration": {"managedHost": desired}}
    )
    denied = _invoke(
        module,
        _event(
            "/enterprise/deployments/dep-a/managed-package",
            "PUT",
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["policy-author"],
                "sub": "author-a",
            },
            body={
                "expectedRevision": 0,
                "packageBase64": base64.b64encode(package.to_json()).decode(),
                "packageSha256": package.package_sha256,
            },
        ),
    )
    assert denied["statusCode"] == 403
    assert json.loads(denied["body"])["requiredCapability"] == "managed_deployment"


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
    assert len(records) == 6
    assert records[0]["pk"] == "USER#subject-a"
    tenant = records[0]["tenant_id"]
    assert tenant.startswith("trial-") and len(tenant) == 38
    assert records[1]["pk"] == f"TENANT#{tenant}"
    policy = next(item for item in records if item["sk"] == "POLICY#policy-safe-default")
    policy_version = next(item for item in records if item["sk"].startswith("POLICY_VERSION#"))
    assert policy["activeVersion"] == 1
    assert policy_version["state"] == "active"
    assert (
        policy_version["content_hash"]
        == hashlib.sha256(
            json.dumps(policy["configuration"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
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


def test_discovery_reconciles_population_without_inflating_duplicate_coverage(
    monkeypatch: Any,
) -> None:
    """Fresh complete sources expose unmanaged, duplicate, orphan and leaver posture."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-discovery"
    now = int(time.time())
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-admin-a",
    }
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    for agent_id, project_root, owner_id in (
        ("managed-agent", "/synthetic/project", "user-active"),
        ("orphan-agent", "/orphan/project", "user-left"),
    ):
        table.put_item(
            Item={
                **module._item_key(tenant, "AGENT", f"deployment-a:{agent_id}"),
                "tenant_id": tenant,
                "id": agent_id,
                "organization_id": "org-a",
                "project_id": "project-a",
                "deployment_id": "deployment-a",
                "host": "claude-code",
                "project_root": project_root,
                "environment": "prod",
                "region": "eu-west-2",
                "status": "connected",
                "last_heartbeat": now,
                "expires_at": now + 300,
                "lifecycle_state": "active",
                "lifecycle_revision": 1,
                **_ownership_record(now, owner_id=owner_id),
            }
        )

    managed_digest = hashlib.sha256(b"/synthetic/project").hexdigest()
    unmanaged_digest = hashlib.sha256(b"/unmanaged/project").hexdigest()
    snapshots = {
        "entra": _discovery_snapshot(
            "identity",
            [
                {"kind": "identity", "id": "user-active", "active": True},
                {"kind": "identity", "id": "user-left", "active": False},
            ],
            now=now,
        ),
        "mdm": _discovery_snapshot(
            "endpoint",
            [
                {
                    "kind": "device",
                    "id": "device-a",
                    "managed": True,
                    "businessUnit": "Payments",
                    "userIds": ["user-active"],
                },
                {
                    "kind": "device",
                    "id": "device-b",
                    "managed": True,
                    "businessUnit": "Payments",
                    "userIds": ["user-active"],
                },
                {
                    "kind": "installation",
                    "id": "install-a",
                    "deviceId": "device-a",
                    "userId": "user-active",
                    "repositoryId": "repo-managed",
                    "host": "claude-code",
                    "projectRootDigest": managed_digest,
                    "binaryPresent": True,
                    "processActive": True,
                },
                {
                    "kind": "installation",
                    "id": "install-b",
                    "deviceId": "device-b",
                    "userId": "user-active",
                    "repositoryId": "repo-managed",
                    "host": "claude-code",
                    "projectRootDigest": managed_digest,
                    "binaryPresent": True,
                    "processActive": False,
                },
            ],
            now=now,
        ),
        "github": _discovery_snapshot(
            "source_control",
            [
                {
                    "kind": "repository",
                    "id": "repo-managed",
                    "projectRootDigest": managed_digest,
                    "expectedHosts": ["claude-code"],
                    "businessUnit": "Payments",
                },
                {
                    "kind": "repository",
                    "id": "repo-unmanaged",
                    "projectRootDigest": unmanaged_digest,
                    "expectedHosts": ["codex-cli"],
                    "businessUnit": "Risk",
                },
            ],
            now=now,
        ),
    }
    for source_id, snapshot in snapshots.items():
        created = _invoke(
            module,
            _event(
                f"/api/enterprise/discovery/sources/{source_id}/snapshots",
                "POST",
                body=snapshot,
                claims=claims,
            ),
        )
        assert created["statusCode"] == 201
        assert "observations" not in json.loads(created["body"])

    response = _invoke(
        module,
        _event("/api/enterprise/discovery", "GET", claims=claims),
    )
    assert response["statusCode"] == 200
    report = json.loads(response["body"])
    assert report["blindSpots"] == []
    assert report["summary"] == {
        "denominator": 2,
        "enrolled": 1,
        "healthy": 0,
        "compliant": 0,
        "unmanaged": 1,
        "duplicate": 1,
        "leaver": 1,
        "orphaned": 1,
        "coverageAvailable": True,
        "sourceComplete": True,
        "coveragePercent": 50.0,
        "healthyPercent": 0.0,
        "compliantPercent": 0.0,
    }
    managed = next(item for item in report["instances"] if item["host"] == "claude-code")
    assert managed["agentCount"] == 1
    assert managed["reasonCodes"] == ["duplicate_installation"]
    unmanaged = next(item for item in report["instances"] if item["host"] == "codex-cli")
    assert unmanaged["reasonCodes"] == ["installation_missing", "unmanaged"]
    orphan = next(item for item in report["agentFindings"] if item["agentId"] == "orphan-agent")
    assert orphan["reasonCodes"] == ["orphaned_enrollment", "inactive_owner_or_user"]
    assert [item["businessUnit"] for item in report["breakdowns"]["businessUnits"]] == [
        "Payments",
        "Risk",
    ]
    exported = _invoke(
        module,
        _event("/api/enterprise/discovery/export", "GET", claims=claims),
    )
    assert exported["statusCode"] == 200
    assert re.fullmatch(r"[0-9a-f]{64}", json.loads(exported["body"])["contentHash"])


def test_discovery_source_authority_revision_and_fail_closed_completeness(
    monkeypatch: Any,
) -> None:
    """Only platform authority publishes snapshots; incomplete evidence cannot orphan agents."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-discovery-boundary"
    now = int(time.time())
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item={
            **module._item_key(tenant, "AGENT", "deployment-a:agent-a"),
            "tenant_id": tenant,
            "id": "agent-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "deployment_id": "deployment-a",
            "host": "claude-code",
            "project_root": "/synthetic/project",
            "environment": "prod",
            "region": "eu-west-2",
            "status": "offline",
            "last_heartbeat": 0,
            "expires_at": 0,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
            **_ownership_record(now),
        }
    )
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-admin-a",
    }
    fleet_operator = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "fleet-operator-a",
    }
    path = "/api/enterprise/discovery/sources/entra/snapshots"
    identity = _discovery_snapshot("identity", [], now=now)
    denied = _invoke(module, _event(path, "POST", body=identity, claims=fleet_operator))
    assert denied["statusCode"] == 403
    assert json.loads(denied["body"])["requiredCapability"] == "discovery_write"
    assert (
        _invoke(module, _event(path, "POST", body=identity, claims=platform))["statusCode"] == 201
    )
    assert (
        _invoke(module, _event(path, "POST", body=identity, claims=platform))["statusCode"] == 409
    )

    for source_id, snapshot in (
        ("mdm", _discovery_snapshot("endpoint", [], now=now)),
        (
            "github",
            _discovery_snapshot("source_control", [], now=now, complete=False),
        ),
    ):
        assert (
            _invoke(
                module,
                _event(
                    f"/api/enterprise/discovery/sources/{source_id}/snapshots",
                    "POST",
                    body=snapshot,
                    claims=platform,
                ),
            )["statusCode"]
            == 201
        )
    report = json.loads(
        _invoke(
            module,
            _event("/api/enterprise/discovery", "GET", claims=platform),
        )["body"]
    )
    assert report["summary"]["coverageAvailable"] is False
    assert report["summary"]["sourceComplete"] is False
    assert report["summary"]["coveragePercent"] is None
    assert report["summary"]["orphaned"] == 0
    assert report["agentFindings"] == []
    assert report["blindSpots"] == [
        "empty_source:endpoint",
        "empty_source:identity",
        "non_current_source:source_control",
    ]
    assert {item["sourceKind"]: item["status"] for item in report["sources"]} == {
        "identity": "empty",
        "endpoint": "empty",
        "source_control": "incomplete",
    }

    malformed = _invoke(
        module,
        _event(
            "/api/enterprise/discovery/sources/bad/snapshots",
            "POST",
            body={**identity, "browserAuthority": True},
            claims=platform,
        ),
    )
    assert malformed["statusCode"] == 400

    monkeypatch.setattr(module.time, "time", lambda: now + 301)
    stale_report = json.loads(
        _invoke(
            module,
            _event("/api/enterprise/discovery", "GET", claims=platform),
        )["body"]
    )
    assert stale_report["summary"]["coverageAvailable"] is False
    assert stale_report["summary"]["coveragePercent"] is None
    assert stale_report["summary"]["orphaned"] == 0
    assert stale_report["agentFindings"] == []
    assert {item["status"] for item in stale_report["sources"]} == {
        "incomplete",
        "stale",
    }
    assert stale_report["blindSpots"] == [
        "non_current_source:endpoint",
        "non_current_source:identity",
        "non_current_source:source_control",
    ]
