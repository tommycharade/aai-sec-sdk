"""Contract tests for the deployed AWS control-plane Lambda boundary."""

import base64
import hashlib
import hmac
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
from scripts.verify_incident_case_export import verify_artifact

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


def _condition_parts(expression: str, separator: str) -> list[str]:
    """Split a synthetic DynamoDB condition only at its top-level operators."""
    parts: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(expression):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif depth == 0 and expression.startswith(separator, index):
            parts.append(expression[start:index].strip())
            start = index + len(separator)
    if parts:
        parts.append(expression[start:].strip())
    return parts


def _condition_permitted(
    condition: str,
    current: dict[str, Any],
    names: dict[str, str],
    values: dict[str, Any],
) -> bool:
    """Evaluate the bounded condition grammar emitted by the Lambda contract."""
    expression = condition.strip()
    while expression.startswith("(") and expression.endswith(")"):
        expression = expression[1:-1].strip()
    conjunction = _condition_parts(expression, " AND ")
    if conjunction:
        return all(_condition_permitted(item, current, names, values) for item in conjunction)
    disjunction = _condition_parts(expression, " OR ")
    if disjunction:
        return any(_condition_permitted(item, current, names, values) for item in disjunction)
    if expression.startswith("attribute_not_exists("):
        field = expression.removeprefix("attribute_not_exists(").removesuffix(")")
        return names.get(field, field) not in current
    if expression.startswith("attribute_exists("):
        field = expression.removeprefix("attribute_exists(").removesuffix(")")
        return names.get(field, field) in current
    for operator in (" <> ", " > ", " = "):
        if operator not in expression:
            continue
        field_name, expected_name = expression.split(operator, 1)
        actual = current.get(names.get(field_name, field_name))
        expected = values[expected_name]
        if operator == " <> ":
            return bool(actual != expected)
        if operator == " > ":
            return bool(actual is not None and actual > expected)
        return bool(actual == expected)
    raise AssertionError(f"unsupported DynamoDB condition: {condition}")


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
            elif not _condition_permitted(
                condition,
                self.items.get(key, {}),
                kwargs.get("ExpressionAttributeNames", {}),
                values,
            ):
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
        if ":partition" in ExpressionAttributeValues and ":tenant" in ExpressionAttributeValues:
            item["endpoint_detection_pk"] = ExpressionAttributeValues[":partition"]
            item["endpoint_detection_sk"] = ExpressionAttributeValues[":tenant"]
            self.items[key] = item
            return {"Attributes": dict(item)}
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
                if "ConditionCheck" in operation:
                    check = operation["ConditionCheck"]
                    key_shape = {
                        key: _decode_ddb_value(value) for key, value in check["Key"].items()
                    }
                    checked_item = self.table.items.get(
                        (key_shape["pk"], key_shape.get("sk", "")), {}
                    )
                    names = check.get("ExpressionAttributeNames", {})
                    values = {
                        key: _decode_ddb_value(value)
                        for key, value in check.get("ExpressionAttributeValues", {}).items()
                    }
                    if not _condition_permitted(
                        check["ConditionExpression"], checked_item, names, values
                    ):
                        raise ConditionalFailure()
                    continue
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
                permitted = _condition_permitted(condition, existing or {}, names, values)
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


class FakeSns:
    """Capture normalized alert notifications without external delivery."""

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    def publish(self, **value: Any) -> dict[str, str]:
        self.messages.append(dict(value))
        return {"MessageId": "synthetic-message"}


class FakeKms:
    """Capture exact digest signing calls without exposing private key material."""

    def __init__(self, key_id: str) -> None:
        self.key_id = key_id
        self.calls: list[dict[str, Any]] = []

    def sign(self, **value: Any) -> dict[str, Any]:
        self.calls.append(dict(value))
        return {
            "KeyId": self.key_id,
            "SigningAlgorithm": "ECDSA_SHA_256",
            "Signature": b"synthetic-ecdsa-signature",
        }

    def get_public_key(self, **value: Any) -> dict[str, Any]:
        self.calls.append(dict(value))
        return {
            "KeyId": self.key_id,
            "KeyUsage": "SIGN_VERIFY",
            "CustomerMasterKeySpec": "ECC_NIST_P256",
            "SigningAlgorithms": ["ECDSA_SHA_256"],
            "PublicKey": b"synthetic-p256-subject-public-key-info",
        }


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
    fake_sns = FakeSns()
    policy_key_id = "arn:aws:kms:eu-west-2:111111111111:key/12345678-1234-1234-1234-123456789abc"
    fake_kms = FakeKms(policy_key_id)
    boto3.client = (  # type: ignore[attr-defined]
        lambda service, *_args, **_kwargs: (
            FakeDynamoClient(table)
            if service == "dynamodb"
            else fake_kms
            if service == "kms"
            else fake_sns
            if service == "sns"
            else FakeS3()
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
    monkeypatch.setenv("POLICY_SIGNING_KEY_ARN", policy_key_id)
    monkeypatch.setenv("SECURITY_ALERTS_TOPIC_ARN", "arn:aws:sns:eu-west-2:111111111111:test")
    path = Path(__file__).parents[1] / "infra/aws-control-plane/lambda/handler.py"
    monkeypatch.syspath_prepend(str(path.parent))
    spec = importlib.util.spec_from_file_location("aai_lambda_handler", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    cast(Any, module)._fake_kms = fake_kms
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


def _bound_endpoint_alert(
    module: Any,
    table: FakeTable,
    tenant: str,
    *,
    now: int,
    alert_id: str = "endpoint-alert-a",
    agent_id: str = "agent-a",
    host: str = "claude-code",
) -> None:
    """Seed synthetic server-side facts for one unique current agent binding."""
    project_root = f"/synthetic/{agent_id}"
    project_digest = hashlib.sha256(project_root.encode()).hexdigest()
    table.put_item(
        Item=module._item_key(tenant, "AGENT", f"deployment-a:{agent_id}")
        | {
            "tenant_id": tenant,
            "id": agent_id,
            "deployment_id": "deployment-a",
            "host": host,
            "project_root": project_root,
            "status": "connected",
            "last_heartbeat": now,
            "expires_at": now + 300,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
            "session_revision": 1,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "DISCOVERY_SOURCE", "intune")
        | {
            "tenant_id": tenant,
            "sourceId": "intune",
            "sourceKind": "endpoint",
            "generation": "synthetic-current",
            "observedAt": now,
            "expiresAt": now + 300,
            "complete": True,
            "observations": [{"kind": "device", "id": "device-a", "managed": True}],
            "revision": 1,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "ENDPOINT_EVIDENCE", "device-a")
        | {
            "tenant_id": tenant,
            "id": "device-a",
            "observedAt": now,
            "revision": 1,
            "reportDigest": "a" * 64,
            "payload": {
                "installations": [
                    {
                        "id": "installation-a",
                        "host": host,
                        "projectRootDigest": project_digest,
                        "binaryPresent": True,
                        "processActive": False,
                    }
                ]
            },
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "ALERT", alert_id)
        | {
            "tenant_id": tenant,
            "id": alert_id,
            "source": "endpoint_evidence",
            "severity": "high",
            "type": "endpoint_runtime_stopped",
            "deviceId": "device-a",
            "message": "The protected agent runtime stopped reporting.",
            "reasonCode": "process_not_observed",
            "status": "open",
            "revision": 1,
            "occurrenceCount": 1,
            "firstObservedAt": now,
            "lastObservedAt": now,
        }
    )


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
    assert preview["statusCode"] == 200, preview
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
    assert submitted["statusCode"] == 200, submitted
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


def test_policy_semantic_diff_and_historical_simulation_are_bounded_and_honest(
    monkeypatch: Any,
) -> None:
    """A draft predicts only decisions supported by retained redacted evidence."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-policy-simulation"
    other_tenant = "tenant-policy-simulation-other"
    now = 2_130_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    for tenant_id in (tenant, other_tenant):
        table.put_item(Item=module._item_key(tenant_id, "TENANT", "root") | {"id": tenant_id})
    base_configuration = {
        "policy": {"allowedPrincipals": ["developer"], "denyByDefault": True},
        "tools": {"allowed": ["Read", "Write"], "denied": []},
        "approvals": {"requiredFor": [], "ttlSeconds": 120},
        "budgets": {"maxActions": 20},
        "audit": {"captureToolContent": False, "redactSensitiveData": True},
        "telemetry": {"captureToolContent": False, "redactSensitiveData": True},
        "claudeCode": {
            "allowedBuiltInTools": ["Bash", "Read", "Write"],
            "allowedMcpServers": ["github"],
        },
    }
    candidate_configuration = {
        **base_configuration,
        "tools": {"allowed": ["Read"], "denied": ["Write"]},
        "budgets": {"maxActions": 40},
        "audit": {"captureToolContent": True, "redactSensitiveData": True},
        "claudeCode": {
            "allowedBuiltInTools": ["Bash", "Read"],
            "allowedMcpServers": [],
        },
    }
    table.put_item(
        Item=module._item_key(tenant, "POLICY", "policy-a")
        | {
            "tenant_id": tenant,
            "id": "policy-a",
            "organization_id": "org-a",
            "name": "Policy A",
            "configuration": base_configuration,
            "version": 1,
            "activeVersion": 1,
            "latestVersion": 2,
            "governanceState": "draft",
            "pendingVersion": 2,
            "pendingAuthor": "author-a",
            "governance_schema_version": 1,
            "createdAt": now - 1_000,
            "author": "author-a",
        }
    )
    for version, state, configuration in (
        (1, "active", base_configuration),
        (2, "draft", candidate_configuration),
    ):
        table.put_item(
            Item=module._item_key(
                tenant,
                "POLICY_VERSION",
                module._policy_version_identifier("policy-a", version),
            )
            | {
                "tenant_id": tenant,
                "id": module._policy_version_identifier("policy-a", version),
                "policy_id": "policy-a",
                "organization_id": "org-a",
                "version": version,
                "base_version": max(0, version - 1),
                "name": f"Policy A v{version}",
                "configuration": configuration,
                "content_hash": module._configuration_hash(configuration),
                "state": state,
                "author": "author-a",
                "created_at": now - 500,
            }
        )
    table.put_item(
        Item=module._item_key(tenant, "GROUP", "group-a")
        | {"id": "group-a", "policyId": "policy-a", "agent_keys": ["deployment-a:agent-a"]}
    )
    decisions = (
        ("read", "claude_native", "Read", "project_file", "allowed", now - 10),
        ("write", "claude_native", "Write", "project_file", "allowed", now - 20),
        ("bash", "claude_native", "Bash", "shell_command", "allowed", now - 30),
        ("mcp", "mcp", "issues.create", "mcp_tool", "allowed", now - 40),
        ("old", "claude_native", "Write", "project_file", "allowed", now - 91 * 86_400),
    )
    for identity, source, tool, resource, decision, observed_at in decisions:
        table.put_item(
            Item=module._item_key(tenant, "DECISION", identity)
            | {
                "id": identity,
                "policy_id": "policy-a",
                "policy_version": 1,
                "source": source,
                "tool_name": tool,
                "resource_kind": resource,
                "decision": decision,
                "observed_at": observed_at,
                "timeline_pk": f"TENANT#{tenant}#DECISION",
                "timeline_sk": f"{observed_at:010d}#{identity}",
            }
        )
    author = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["policy-author"],
        "sub": "author-a",
    }
    approver = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["policy-approver"],
        "sub": "approver-b",
    }
    fleet = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "fleet-c",
    }
    version_response = _invoke(
        module,
        _event("/enterprise/policies/policy-a/versions/2", "GET", claims=approver),
    )
    assert version_response["statusCode"] == 200
    semantic = json.loads(version_response["body"])["changeSummary"]
    assert semantic["summary"]["authorityExpanded"] == 1
    assert semantic["summary"]["authorityRestricted"] >= 3
    assert semantic["summary"]["dataCaptureChanges"] == 1
    assert any(
        item["field"] == "claudeCode.allowedMcpServers" and item["effect"] == "authority_restricted"
        for item in semantic["changes"]
    )

    path = "/enterprise/policies/policy-a/versions/2/simulate"
    before_keys = set(table.items)
    first = _invoke(module, _event(path, "POST", body={"lookbackDays": 90}, claims=author))
    second = _invoke(module, _event(path, "POST", body={"lookbackDays": 90}, claims=approver))
    assert first["statusCode"] == second["statusCode"] == 200
    result = json.loads(first["body"])
    assert result["mutated"] is False
    assert result["scope"] == {
        "groupIds": ["group-a"],
        "agentKeys": ["deployment-a:agent-a"],
    }
    assert result["counts"] == {
        "historical": 4,
        "determined": 2,
        "indeterminate": 2,
        "changed": 1,
        "predictedAllowed": 1,
        "predictedDenied": 1,
        "predictedApprovalRequired": 0,
    }
    assert result["coveragePercent"] == 50.0
    assert result["transitions"] == {
        "allowed_to_allowed": 1,
        "allowed_to_denied": 1,
        "allowed_to_indeterminate": 2,
    }
    assert json.loads(second["body"])["simulationHash"] == result["simulationHash"]
    assert {
        item["reasonCode"]
        for item in result["items"]
        if item["predictedDecision"] == "indeterminate"
    } == {"mcp_server_identity_unavailable", "redacted_command_content"}
    assert set(table.items) == before_keys

    assert (
        _invoke(module, _event(path, "POST", body={"lookbackDays": 90}, claims=fleet))["statusCode"]
        == 403
    )
    assert (
        _invoke(module, _event(path, "POST", body={"lookbackDays": 91}, claims=author))[
            "statusCode"
        ]
        == 400
    )
    cross_tenant = _invoke(
        module,
        _event(
            path,
            "POST",
            body={"lookbackDays": 30},
            claims={
                "custom:tenant_id": other_tenant,
                "cognito:groups": ["policy-author"],
                "sub": "other-author",
            },
        ),
    )
    assert cross_tenant["statusCode"] == 404


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
    assert version["bundle_integrity"]["algorithm"] == "ECDSA_SHA_256"
    assert version["effective_configuration"] == policy["configuration"]
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


def test_policy_activation_signs_atomically_and_freezes_registry_resolution(
    monkeypatch: Any,
) -> None:
    """KMS failure changes nothing; success freezes exact MCP authority."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-signed-activation"
    policy_id = "policy-signed"
    policy = module._item_key(tenant, "POLICY", policy_id) | {
        "tenant_id": tenant,
        "id": policy_id,
        "name": "Signed policy",
        "configuration": {"tools": {"allowed": ["read_repository"]}},
        "version": 1,
        "activeVersion": 1,
        "latestVersion": 2,
        "governanceState": "staged",
        "pendingVersion": 2,
        "pendingAuthor": "author-a",
        "governance_schema_version": 1,
    }
    active = module._item_key(
        tenant, "POLICY_VERSION", module._policy_version_identifier(policy_id, 1)
    ) | {
        "tenant_id": tenant,
        "id": module._policy_version_identifier(policy_id, 1),
        "policy_id": policy_id,
        "version": 1,
        "base_version": 0,
        "name": "Signed policy",
        "configuration": policy["configuration"],
        "content_hash": module._configuration_hash(policy["configuration"]),
        "state": "active",
        "author": "author-a",
    }
    candidate_configuration = {
        "tools": {"allowed": ["read_repository"]},
        "claudeCode": {"allowedMcpServers": ["github"]},
    }
    candidate = module._item_key(
        tenant, "POLICY_VERSION", module._policy_version_identifier(policy_id, 2)
    ) | {
        "tenant_id": tenant,
        "id": module._policy_version_identifier(policy_id, 2),
        "policy_id": policy_id,
        "version": 2,
        "base_version": 1,
        "name": "Signed policy v2",
        "configuration": candidate_configuration,
        "content_hash": module._configuration_hash(candidate_configuration),
        "state": "staged",
        "author": "author-a",
        "decided_by": "reviewer-b",
    }
    mcp = module._item_key(tenant, "MCP", "github") | {
        "tenant_id": tenant,
        "id": "github",
        "name": "GitHub",
        "enabled": True,
        "transport": "stdio",
        "command": "github-mcp-server",
    }
    for item in (policy, active, candidate, mcp):
        table.put_item(Item=item)

    snapshot = {key: dict(value) for key, value in table.items.items()}
    original_sign = module.KMS.sign
    module.KMS.sign = lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("KMS unavailable"))
    with pytest.raises(RuntimeError, match="KMS unavailable"):
        module._activate_policy_version(
            tenant,
            policy_id,
            2,
            {"expectedActiveVersion": 1},
            "reviewer-b",
        )
    assert table.items == snapshot

    module.KMS.sign = original_sign
    module._activate_policy_version(
        tenant,
        policy_id,
        2,
        {"expectedActiveVersion": 1},
        "reviewer-b",
    )
    stored = table.items[(f"TENANT#{tenant}", "POLICY_VERSION#policy-signed:00000000000000000002")]
    assert stored["state"] == "active"
    assert stored["bundle_integrity"]["algorithm"] == "ECDSA_SHA_256"
    assert (
        stored["effective_configuration"]["claudeCode"]["managedMcpServers"][0]["command"]
        == "github-mcp-server"
    )
    call = module._fake_kms.calls[-1]
    assert call["MessageType"] == "DIGEST"
    assert call["SigningAlgorithm"] == "ECDSA_SHA_256"
    assert len(call["Message"]) == 32

    changed_mcp = dict(mcp)
    changed_mcp["command"] = "attacker-replacement"
    table.put_item(Item=changed_mcp)
    active_policy = table.items[(f"TENANT#{tenant}", "POLICY#policy-signed")]
    bundle = module._active_policy_bundle(tenant, active_policy)
    assert bundle["configuration"]["claudeCode"]["managedMcpServers"][0]["command"] == (
        "github-mcp-server"
    )


def test_policy_signing_key_is_asymmetric_retained_and_least_privileged() -> None:
    """Infrastructure exposes no signing private key and grants only required KMS calls."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    assert "keySpec: kms.KeySpec.ECC_NIST_P256" in stack
    assert "keyUsage: kms.KeyUsage.SIGN_VERIFY" in stack
    assert "removalPolicy: cdk.RemovalPolicy.RETAIN" in stack
    assert 'policySigningKey.grant(trialOnboarding, "kms:Sign")' in stack
    assert 'policySigningKey.grant(handler, "kms:Sign", "kms:GetPublicKey")' in stack
    assert "POLICY_SIGNING_KEY_ARN: policySigningKey.keyArn" in stack
    assert 'new cdk.CfnOutput(this, "PolicySigningKeyArn"' in stack


def test_operator_policy_trust_metadata_is_public_provenance_not_private_authority(
    monkeypatch: Any,
) -> None:
    """Operators can identify the signer while hosts still require pinned trust."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-policy-trust"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["auditor"],
        "sub": "auditor-a",
    }

    response = _invoke(module, _event("/enterprise/policy-trust", "GET", claims=claims))

    assert response["statusCode"] == 200
    value = json.loads(response["body"])
    assert value["algorithm"] == "ECDSA_SHA_256"
    assert value["trustSource"] == "administrator-installation-required"
    assert len(value["fingerprintSha256"]) == 64
    assert "private" not in json.dumps(value).lower()


def test_aws_managed_discovery_secret_tagging_is_least_privileged() -> None:
    """Connector creation may attach only the two required discovery tags."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    assert 'actions: ["secretsmanager:CreateSecret", "secretsmanager:TagResource"]' in stack
    assert '"aws:RequestTag/aai-sec:purpose": "discovery-connector"' in stack
    assert 'Null: { "aws:RequestTag/aai-sec:tenant-id": "false" }' in stack
    assert '"aws:TagKeys": ["aai-sec:tenant-id", "aai-sec:purpose"]' in stack
    assert 'actions: ["secretsmanager:DeleteSecret"]' in stack
    assert "discoverySecretKey.grantDecrypt(new kms.ViaServicePrincipal(" in stack
    assert "`secretsmanager.${this.region}.amazonaws.com`" in stack
    assert "discoverySecretKey.grantDecrypt(handler);" not in stack
    assert "arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME" in stack


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
    assert json.loads(stop_response["body"])["controlState"]["executionAllowed"] is False
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


def test_hosted_endpoint_evidence_is_tenant_bound_signed_and_server_derived(
    monkeypatch: Any,
) -> None:
    """A current MDM device can report once; tamper and stale state fail closed."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-endpoint-evidence"
    now = 2_000_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-admin-endpoint",
    }
    snapshot = _discovery_snapshot(
        "endpoint",
        [
            {
                "kind": "device",
                "id": "device-a",
                "managed": True,
                "businessUnit": "Platform",
                "userIds": [],
            }
        ],
        now=now,
    )
    assert (
        _invoke(
            module,
            _event(
                "/api/enterprise/discovery/sources/intune/snapshots",
                "POST",
                body=snapshot,
                claims=platform,
            ),
        )["statusCode"]
        == 201
    )
    credential_path = "/api/enterprise/endpoint-evidence/devices/device-a/credential"
    issued_response = _invoke(
        module, _event(credential_path, "POST", body={"expectedRevision": 0}, claims=platform)
    )
    assert issued_response["statusCode"] == 201
    issued = json.loads(issued_response["body"])
    assert len(issued["secret"]) >= 32
    assert issued["secret"] not in json.dumps(list(table.items.values()))
    payload = {
        "schemaVersion": 1,
        "observedAt": now,
        "device": {"id": "device-a", "managed": True, "businessUnit": "Platform"},
        "installations": [
            {
                "id": "installation-a",
                "deviceId": "device-a",
                "host": "claude-code",
                "projectRootDigest": "a" * 64,
                "binaryPresent": True,
                "processActive": True,
                "userId": "user-opaque-a",
                "repositoryId": "repository-opaque-a",
                "businessUnit": "Platform",
            }
        ],
    }
    signature = hmac.new(
        issued["secret"].encode(),
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
        hashlib.sha256,
    ).hexdigest()
    report = {"keyId": issued["keyId"], "payload": payload, "signature": signature}
    ingest_path = f"/api/endpoint-evidence/{tenant}/device-a"
    accepted = _invoke(module, _event(ingest_path, "POST", body=report, token=issued["secret"]))
    assert accepted["statusCode"] == 202
    duplicate = _invoke(module, _event(ingest_path, "POST", body=report, token=issued["secret"]))
    assert duplicate["statusCode"] == 202
    assert json.loads(duplicate["body"])["duplicate"] is True
    health = json.loads(
        _invoke(module, _event("/api/enterprise/endpoint-evidence", "GET", claims=platform))["body"]
    )
    assert health["summary"] == {"devices": 1, "healthy": 1, "attention": 0, "stale": 0}
    assert health["items"][0]["status"] == "healthy"
    assert "secret" not in json.dumps(health)
    assert "userId" not in json.dumps(health)
    tampered = json.loads(json.dumps(report))
    tampered["payload"]["installations"][0]["processActive"] = False
    assert (
        _invoke(module, _event(ingest_path, "POST", body=tampered, token=issued["secret"]))[
            "statusCode"
        ]
        == 403
    )
    replayed = json.loads(json.dumps(tampered))
    replayed["signature"] = hmac.new(
        issued["secret"].encode(),
        json.dumps(replayed["payload"], sort_keys=True, separators=(",", ":")).encode(),
        hashlib.sha256,
    ).hexdigest()
    assert (
        _invoke(module, _event(ingest_path, "POST", body=replayed, token=issued["secret"]))[
            "statusCode"
        ]
        == 409
    )
    security_alerts = json.loads(
        _invoke(module, _event("/api/enterprise/alerts", "GET", claims=platform))["body"]
    )["items"]
    assert {item["reasonCode"] for item in security_alerts} == {
        "signature_invalid",
        "report_replayed",
    }
    assert all(item["status"] == "open" for item in security_alerts)
    assert (
        _invoke(
            module,
            _event(
                "/api/endpoint-evidence/tenant-other/device-a",
                "POST",
                body=report,
                token=issued["secret"],
            ),
        )["statusCode"]
        == 403
    )
    rotated_response = _invoke(
        module, _event(credential_path, "POST", body={"expectedRevision": 1}, claims=platform)
    )
    assert rotated_response["statusCode"] == 201
    rotated = json.loads(rotated_response["body"])
    assert rotated["keyId"] != issued["keyId"]
    assert (
        _invoke(module, _event(ingest_path, "POST", body=report, token=issued["secret"]))[
            "statusCode"
        ]
        == 403
    )
    rotated_health = json.loads(
        _invoke(module, _event("/api/enterprise/endpoint-evidence", "GET", claims=platform))["body"]
    )
    assert rotated_health["items"][0]["reportStatus"] == "credential_rotated"
    assert "fresh_report_required_after_rotation" in rotated_health["items"][0]["reasonCodes"]
    revoked = _invoke(
        module,
        _event(
            credential_path,
            "DELETE",
            body={"expectedRevision": rotated["revision"]},
            claims=platform,
        ),
    )
    assert revoked["statusCode"] == 200
    assert json.loads(revoked["body"])["status"] == "revoked"
    rotated_report = {**report, "keyId": rotated["keyId"]}
    rotated_report["signature"] = hmac.new(
        rotated["secret"].encode(),
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
        hashlib.sha256,
    ).hexdigest()
    assert (
        _invoke(module, _event(ingest_path, "POST", body=rotated_report, token=rotated["secret"]))[
            "statusCode"
        ]
        == 403
    )
    monkeypatch.setattr(module.time, "time", lambda: now + 901)
    stale = json.loads(
        _invoke(module, _event("/api/enterprise/endpoint-evidence", "GET", claims=platform))["body"]
    )
    assert stale["items"][0]["status"] == "stale"
    assert stale["items"][0]["installations"] == []


def test_endpoint_credential_requires_current_managed_inventory(monkeypatch: Any) -> None:
    """Browser input cannot mint device authority outside current MDM inventory."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-endpoint-credential"
    now = int(time.time())
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-admin-endpoint",
    }
    path = "/api/enterprise/endpoint-evidence/devices/device-a/credential"
    assert (
        _invoke(module, _event(path, "POST", body={"expectedRevision": 0}, claims=claims))[
            "statusCode"
        ]
        == 404
    )
    snapshot = _discovery_snapshot(
        "endpoint", [{"kind": "device", "id": "device-a", "managed": False}], now=now
    )
    assert (
        _invoke(
            module,
            _event(
                "/api/enterprise/discovery/sources/intune/snapshots",
                "POST",
                body=snapshot,
                claims=claims,
            ),
        )["statusCode"]
        == 201
    )
    assert (
        _invoke(module, _event(path, "POST", body={"expectedRevision": 0}, claims=claims))[
            "statusCode"
        ]
        == 409
    )


def test_endpoint_alerts_are_deduplicated_delivered_acknowledged_and_resolved(
    monkeypatch: Any,
) -> None:
    """One health condition has durable lifecycle, delivery and audited ownership."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-endpoint-alerts"
    now = 2_100_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-endpoint-alerts",
    }
    responder = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["incident-responder"],
        "sub": "responder-endpoint-alerts",
    }
    snapshot = _discovery_snapshot(
        "endpoint", [{"kind": "device", "id": "device-a", "managed": True}], now=now
    )
    assert (
        _invoke(
            module,
            _event(
                "/api/enterprise/discovery/sources/intune/snapshots",
                "POST",
                body=snapshot,
                claims=platform,
            ),
        )["statusCode"]
        == 201
    )
    listed = _invoke(module, _event("/api/enterprise/alerts", "GET", claims=responder))
    assert listed["statusCode"] == 200
    alerts = json.loads(listed["body"])["items"]
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "endpoint_sensor_not_enrolled"
    assert alert["status"] == "open"
    assert alert["deliveryStatus"] == "delivered"
    assert alert["occurrenceCount"] == 1
    assert len(module.SNS.messages) == 1
    notification = json.dumps(module.SNS.messages[0])
    assert "device-a" in notification
    assert "secret" not in notification.lower()
    repeated = json.loads(
        _invoke(module, _event("/api/enterprise/alerts", "GET", claims=responder))["body"]
    )["items"]
    assert repeated[0]["revision"] == alert["revision"]
    assert repeated[0]["occurrenceCount"] == 1
    assert len(module.SNS.messages) == 1
    fleet_operator = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "fleet-endpoint-alerts",
    }
    path = f"/api/enterprise/alerts/{alert['id']}/acknowledge"
    denied = _invoke(
        module,
        _event(
            path,
            "POST",
            body={"expectedRevision": alert["revision"], "reason": "Synthetic response owned."},
            claims=fleet_operator,
        ),
    )
    assert denied["statusCode"] == 403
    secret_reason = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                "expectedRevision": alert["revision"],
                "reason": "Investigating with token=synthetic-sensitive-value",
            },
            claims=responder,
        ),
    )
    assert secret_reason["statusCode"] == 400
    assert "credential material" in json.loads(secret_reason["body"])["error"]
    acknowledged = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                "expectedRevision": alert["revision"],
                "reason": "Investigating missing enrollment with endpoint engineering.",
            },
            claims=responder,
        ),
    )
    assert acknowledged["statusCode"] == 200
    acknowledged_body = json.loads(acknowledged["body"])
    assert acknowledged_body["status"] == "acknowledged"
    assert acknowledged_body["acknowledgedBy"] == responder["sub"]
    stale_ack = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                "expectedRevision": alert["revision"],
                "reason": "Duplicate acknowledgement must fail closed safely.",
            },
            claims=responder,
        ),
    )
    assert stale_ack["statusCode"] == 409

    credential_path = "/api/enterprise/endpoint-evidence/devices/device-a/credential"
    issued_response = _invoke(
        module,
        _event(credential_path, "POST", body={"expectedRevision": 0}, claims=platform),
    )
    issued = json.loads(issued_response["body"])
    payload = {
        "schemaVersion": 1,
        "observedAt": now,
        "device": {"id": "device-a", "managed": True},
        "installations": [
            {
                "id": "installation-a",
                "deviceId": "device-a",
                "host": "claude-code",
                "projectRootDigest": "a" * 64,
                "binaryPresent": True,
                "processActive": True,
            }
        ],
    }
    report = {
        "keyId": issued["keyId"],
        "payload": payload,
        "signature": hmac.new(
            issued["secret"].encode(),
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).hexdigest(),
    }
    assert (
        _invoke(
            module,
            _event(
                f"/api/endpoint-evidence/{tenant}/device-a",
                "POST",
                body=report,
                token=issued["secret"],
            ),
        )["statusCode"]
        == 202
    )
    assert (
        _invoke(module, _event("/api/enterprise/endpoint-evidence", "GET", claims=responder))[
            "statusCode"
        ]
        == 200
    )
    resolved = json.loads(
        _invoke(module, _event("/api/enterprise/alerts", "GET", claims=responder))["body"]
    )["items"]
    assert resolved[0]["status"] == "resolved"
    assert resolved[0]["resolvedAt"] == now


def test_automatic_response_rule_is_governed_bounded_and_idempotent(
    monkeypatch: Any,
) -> None:
    """Only an independently approved rule may quarantine an exact agent binding."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-automatic-response"
    other_tenant = "tenant-automatic-response-other"
    now = 2_160_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(Item=module._item_key(other_tenant, "TENANT", "root") | {"id": other_tenant})
    _bound_endpoint_alert(module, table, tenant, now=now)
    author = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "rule-author",
    }
    approver = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "rule-approver",
    }
    fleet_only = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "fleet-only",
    }
    configuration = {
        "match": {
            "source": "endpoint_evidence",
            "reasonCodes": ["process_not_observed"],
            "severities": ["high"],
            "hosts": ["claude-code"],
        },
        "action": {"type": "quarantine_agent"},
        "safeguards": {"maxActionsPerHour": 1, "agentCooldownSeconds": 900},
        "priority": 100,
    }
    preview = _invoke(
        module,
        _event(
            "/api/enterprise/response-rules/preview",
            "POST",
            body={"configuration": configuration},
            claims=author,
        ),
    )
    assert preview["statusCode"] == 200, preview
    preview_body = json.loads(preview["body"])
    assert preview_body["mutated"] is False
    assert preview_body["matches"][0]["outcome"] == "would_contain"
    assert not [item for item in table.items.values() if item.get("case_id")]

    create_body = {
        "ruleId": "stop-dead-runtime",
        "name": "Stop dead protected runtimes",
        "description": "Quarantine the exact enrolled agent when its protected runtime stops.",
        "configuration": configuration,
    }
    denied = _invoke(
        module,
        _event(
            "/api/enterprise/response-rules",
            "POST",
            body=create_body,
            claims=fleet_only,
        ),
    )
    assert denied["statusCode"] == 403
    created = _invoke(
        module,
        _event(
            "/api/enterprise/response-rules",
            "POST",
            body=create_body,
            claims=author,
        ),
    )
    assert created["statusCode"] == 201
    assert json.loads(created["body"])["governanceState"] == "draft"
    submitted = _invoke(
        module,
        _event(
            "/api/enterprise/response-rules/stop-dead-runtime/versions/1/submit",
            "POST",
            claims=author,
        ),
    )
    assert submitted["statusCode"] == 200, submitted
    decision_path = "/api/enterprise/response-rules/stop-dead-runtime/versions/1/decision"
    self_approval = _invoke(
        module,
        _event(
            decision_path,
            "POST",
            body={
                "decision": "approved",
                "reason": "The author must not approve their own automatic authority.",
            },
            claims=author,
        ),
    )
    assert self_approval["statusCode"] == 403
    approved = _invoke(
        module,
        _event(
            decision_path,
            "POST",
            body={
                "decision": "approved",
                "reason": "The scope and containment safeguards are appropriate for production.",
            },
            claims=approver,
        ),
    )
    assert approved["statusCode"] == 200
    activated = _invoke(
        module,
        _event(
            "/api/enterprise/response-rules/stop-dead-runtime/versions/1/activate",
            "POST",
            body={"expectedActiveVersion": 0},
            claims=approver,
        ),
    )
    assert activated["statusCode"] == 200
    assert json.loads(activated["body"])["enabled"] is True

    outcomes = module._evaluate_response_rules(tenant, now=now)
    assert len(outcomes) == 1
    assert outcomes[0]["outcome"] == "contained"
    control = module._agent_control_state(
        tenant,
        table.items[(f"TENANT#{tenant}", "AGENT#deployment-a:agent-a")],
    )
    assert control["executionAllowed"] is False
    assert control["evidenceAllowed"] is True
    first_case_id = outcomes[0]["caseId"]
    assert first_case_id
    assert module._evaluate_response_rules(tenant, now=now) == outcomes
    assert len(module._list(tenant, "CASE")) == 1
    assert len(module._list(tenant, "RESPONSE_EXECUTION")) == 1

    # A distinct alert occurrence for the same exact agent is retained as
    # evidence but cannot exceed the approved hourly/cooldown authority.
    table.put_item(
        Item=module._item_key(tenant, "ALERT", "endpoint-alert-b")
        | {
            **table.items[(f"TENANT#{tenant}", "ALERT#endpoint-alert-a")],
            "pk": f"TENANT#{tenant}",
            "sk": "ALERT#endpoint-alert-b",
            "id": "endpoint-alert-b",
            "caseId": None,
            "revision": 1,
            "occurrenceCount": 1,
        }
    )
    outcomes = module._evaluate_response_rules(tenant, now=now + 1)
    assert {item["reasonCode"] for item in outcomes} >= {
        "approved_rule_matched",
        "hourly_limit",
    }
    assert len(module._list(tenant, "CASE")) == 1

    detail = _invoke(
        module,
        _event(
            "/api/enterprise/response-rules/stop-dead-runtime",
            "GET",
            claims=approver,
        ),
    )
    assert detail["statusCode"] == 200
    detail_body = json.loads(detail["body"])
    assert detail_body["activeVersion"] == 1
    assert detail_body["versions"][0]["contentHash"]
    assert len(detail_body["executions"]) == 2
    other_rules = json.loads(
        _invoke(
            module,
            _event(
                "/api/enterprise/response-rules",
                "GET",
                claims={
                    "custom:tenant_id": other_tenant,
                    "cognito:groups": ["security-operator"],
                    "sub": "other-operator",
                },
            ),
        )["body"]
    )
    assert other_rules["items"] == []


def test_endpoint_reads_cannot_trigger_automatic_response(monkeypatch: Any) -> None:
    """Only scheduled detection and event writes may invoke consequential rules."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-read-side-effect"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    evaluations: list[str] = []
    monkeypatch.setattr(
        module,
        "_evaluate_response_rules",
        lambda evaluated_tenant, **_kwargs: evaluations.append(evaluated_tenant),
    )

    module._reconcile_endpoint_alerts(tenant, {"items": []})
    assert evaluations == []
    module._reconcile_endpoint_alerts(
        tenant,
        {"items": []},
        automatic_response=True,
    )
    assert evaluations == [tenant]


def test_automatic_response_reservation_cannot_exceed_limit_under_race(
    monkeypatch: Any,
) -> None:
    """A concurrent trigger can consume capacity but cannot overrun it."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-response-reservation-race"
    now = 2_165_000_000
    rule = {
        "id": "bounded-rule",
        "active_version": 1,
        "configuration": {
            "match": {
                "source": "endpoint_evidence",
                "reasonCodes": ["process_not_observed"],
                "severities": ["high"],
                "hosts": ["claude-code"],
            },
            "action": {"type": "quarantine_agent"},
            "safeguards": {"maxActionsPerHour": 1, "agentCooldownSeconds": 900},
            "priority": 100,
        },
    }
    first = {"id": "alert-a", "occurrenceCount": 1}
    concurrent = {"id": "alert-b", "occurrenceCount": 1}
    binding = {"agentKey": "deployment-a:agent-a"}
    concurrent_result: list[str | None] = []
    module.DYNAMODB.before_transaction = lambda: concurrent_result.append(
        module._reserve_response_rule_action(
            tenant,
            rule,
            concurrent,
            binding,
            now,
        )
    )

    assert (
        module._reserve_response_rule_action(
            tenant,
            rule,
            first,
            binding,
            now,
        )
        == "hourly_limit"
    )
    assert concurrent_result == [None]
    assert len(module._list(tenant, "RESPONSE_LEASE")) == 1
    rate = table.get_item(Key=module._item_key(tenant, "RESPONSE_RATE", "bounded-rule"))["Item"]
    assert rate["action_times"] == [now]


def test_response_rule_version_rollback_and_disable_preserve_governance(
    monkeypatch: Any,
) -> None:
    """Rollback can select only an approved superseded version and disable fails stale."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-response-rule-rollback"
    now = 2_170_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    author = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "author-a",
    }
    approver = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "approver-b",
    }

    def configuration(maximum: int) -> dict[str, Any]:
        return {
            "match": {
                "source": "endpoint_evidence",
                "reasonCodes": ["process_not_observed"],
                "severities": ["high"],
                "hosts": ["claude-code", "codex"],
            },
            "action": {"type": "quarantine_agent"},
            "safeguards": {
                "maxActionsPerHour": maximum,
                "agentCooldownSeconds": 900,
            },
            "priority": 100,
        }

    create = _invoke(
        module,
        _event(
            "/api/enterprise/response-rules",
            "POST",
            body={
                "ruleId": "rollback-rule",
                "name": "Rollback rule",
                "description": "A governed synthetic rule used to prove safe rollback behavior.",
                "configuration": configuration(1),
            },
            claims=author,
        ),
    )
    assert create["statusCode"] == 201, create
    for version, expected in ((1, 0),):
        assert (
            _invoke(
                module,
                _event(
                    f"/api/enterprise/response-rules/rollback-rule/versions/{version}/submit",
                    "POST",
                    claims=author,
                ),
            )["statusCode"]
            == 200
        )
        assert (
            _invoke(
                module,
                _event(
                    f"/api/enterprise/response-rules/rollback-rule/versions/{version}/decision",
                    "POST",
                    body={
                        "decision": "approved",
                        "reason": "Independent review confirms bounded automatic authority.",
                    },
                    claims=approver,
                ),
            )["statusCode"]
            == 200
        )
        assert (
            _invoke(
                module,
                _event(
                    f"/api/enterprise/response-rules/rollback-rule/versions/{version}/activate",
                    "POST",
                    body={"expectedActiveVersion": expected},
                    claims=approver,
                ),
            )["statusCode"]
            == 200
        )
    draft_two = _invoke(
        module,
        _event(
            "/api/enterprise/response-rules/rollback-rule/versions",
            "POST",
            body={
                "name": "Rollback rule",
                "description": "A governed synthetic second version used to test rollback.",
                "configuration": configuration(2),
            },
            claims=author,
        ),
    )
    assert draft_two["statusCode"] == 201
    for operation, body, claims in (
        ("submit", None, author),
        (
            "decision",
            {
                "decision": "approved",
                "reason": "Independent review approves the changed hourly action limit.",
            },
            approver,
        ),
        ("activate", {"expectedActiveVersion": 1}, approver),
    ):
        result = _invoke(
            module,
            _event(
                f"/api/enterprise/response-rules/rollback-rule/versions/2/{operation}",
                "POST",
                body=body,
                claims=claims,
            ),
        )
        assert result["statusCode"] == 200
    rollback = _invoke(
        module,
        _event(
            "/api/enterprise/response-rules/rollback-rule/rollback",
            "POST",
            body={
                "expectedActiveVersion": 2,
                "targetVersion": 1,
                "reason": "Restore the previously approved safer hourly containment limit.",
            },
            claims=approver,
        ),
    )
    assert rollback["statusCode"] == 200
    assert json.loads(rollback["body"])["activeVersion"] == 1
    stale_disable = _invoke(
        module,
        _event(
            "/api/enterprise/response-rules/rollback-rule/disable",
            "POST",
            body={
                "expectedActiveVersion": 2,
                "reason": "A stale operator must not remove newer automatic authority.",
            },
            claims=approver,
        ),
    )
    assert stale_disable["statusCode"] == 409
    disabled = _invoke(
        module,
        _event(
            "/api/enterprise/response-rules/rollback-rule/disable",
            "POST",
            body={
                "expectedActiveVersion": 1,
                "reason": "Disable automatic authority while the response logic is reviewed.",
            },
            claims=approver,
        ),
    )
    assert disabled["statusCode"] == 200
    assert json.loads(disabled["body"])["enabled"] is False


def test_incident_case_binds_contains_and_revokes_only_authoritative_agent(
    monkeypatch: Any,
) -> None:
    """A case can act only through a unique, current server-derived endpoint binding."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-incident-response"
    now = 2_150_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    responder = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["incident-responder"],
        "sub": "responder-a",
    }
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-a",
    }
    project_root = "/synthetic/contained-project"
    project_digest = hashlib.sha256(project_root.encode()).hexdigest()
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "deployment-a:agent-a")
        | {
            "tenant_id": tenant,
            "id": "agent-a",
            "deployment_id": "deployment-a",
            "host": "claude-code",
            "project_root": project_root,
            "status": "connected",
            "last_heartbeat": now,
            "expires_at": now + 300,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
            "session_revision": 1,
        }
    )
    snapshot = _discovery_snapshot(
        "endpoint", [{"kind": "device", "id": "device-a", "managed": True}], now=now
    )
    assert (
        _invoke(
            module,
            _event(
                "/api/enterprise/discovery/sources/intune/snapshots",
                "POST",
                body=snapshot,
                claims=platform,
            ),
        )["statusCode"]
        == 201
    )
    credential_path = "/api/enterprise/endpoint-evidence/devices/device-a/credential"
    issued = json.loads(
        _invoke(
            module,
            _event(credential_path, "POST", body={"expectedRevision": 0}, claims=platform),
        )["body"]
    )
    evidence_payload = {
        "schemaVersion": 1,
        "observedAt": now,
        "device": {"id": "device-a", "managed": True},
        "installations": [
            {
                "id": "installation-a",
                "deviceId": "device-a",
                "host": "claude-code",
                "projectRootDigest": project_digest,
                "binaryPresent": True,
                "processActive": True,
            }
        ],
    }
    evidence = {
        "keyId": issued["keyId"],
        "payload": evidence_payload,
        "signature": hmac.new(
            issued["secret"].encode(),
            json.dumps(evidence_payload, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).hexdigest(),
    }
    assert (
        _invoke(
            module,
            _event(
                f"/api/endpoint-evidence/{tenant}/device-a",
                "POST",
                body=evidence,
                token=issued["secret"],
            ),
        )["statusCode"]
        == 202
    )
    alert_id = "endpoint-alert-a"
    table.put_item(
        Item=module._item_key(tenant, "ALERT", alert_id)
        | {
            "tenant_id": tenant,
            "id": alert_id,
            "source": "endpoint_evidence",
            "severity": "high",
            "type": "endpoint_runtime_stopped",
            "deviceId": "device-a",
            "message": "The protected agent runtime stopped reporting.",
            "reasonCode": "process_inactive",
            "status": "acknowledged",
            "revision": 1,
            "firstObservedAt": now,
            "lastObservedAt": now,
        }
    )
    denied_case = _invoke(
        module,
        _event(
            "/api/enterprise/cases",
            "POST",
            body={
                "alertId": alert_id,
                "expectedAlertRevision": 1,
                "reason": "Fleet-only authority must not open response cases.",
            },
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["fleet-operator"],
                "sub": "fleet-only",
            },
        ),
    )
    assert denied_case["statusCode"] == 403
    created = _invoke(
        module,
        _event(
            "/api/enterprise/cases",
            "POST",
            body={
                "alertId": alert_id,
                "expectedAlertRevision": 1,
                "reason": "Investigating the synthetic endpoint runtime condition.",
            },
            claims=responder,
        ),
    )
    assert created["statusCode"] == 201
    case = json.loads(created["body"])
    assert case["binding"]["agentKey"] == "deployment-a:agent-a"
    assert case["bindingCurrent"] is True
    assert case["evidence"]["rawContentIncluded"] is False
    assert (
        json.loads(
            _invoke(module, _event("/api/enterprise/alerts", "GET", claims=responder))["body"]
        )["items"][0]["caseId"]
        == case["id"]
    )
    bootstrap = json.loads(
        _invoke(
            module,
            _event(
                "/api/enterprise/agents/bootstrap",
                "POST",
                body={"deploymentId": "deployment-a", "agentId": "agent-a"},
                claims=platform,
            ),
        )["body"]
    )["bootstrapToken"]

    contained = _invoke(
        module,
        _event(
            f"/api/enterprise/cases/{case['id']}/contain",
            "POST",
            body={
                "expectedCaseRevision": 1,
                "expectedBindingDigest": case["binding"]["bindingDigest"],
                "reason": "Quarantine execution while preserving heartbeat evidence.",
            },
            claims=responder,
        ),
    )
    assert contained["statusCode"] == 200
    contained_case = json.loads(contained["body"])
    assert contained_case["status"] == "contained"
    control = module._agent_control_state(
        tenant, table.items[(f"TENANT#{tenant}", "AGENT#deployment-a:agent-a")]
    )
    assert control["executionAllowed"] is False
    assert control["evidenceAllowed"] is True
    assert control["quarantine"]["caseId"] == case["id"]

    session_token = "synthetic-agent-session-token-123456"  # noqa: S105
    table.put_item(
        Item={
            "pk": module._token_key("AGENT_SESSION", session_token),
            "sk": "SESSION",
            "tenant_id": tenant,
            "deployment_id": "deployment-a",
            "agent_id": "agent-a",
            "project_root_hash": project_digest,
            "session_revision": 1,
            "expires_at": now + 900,
        }
    )
    revoked = _invoke(
        module,
        _event(
            f"/api/enterprise/cases/{case['id']}/sessions/revoke",
            "POST",
            body={
                "expectedCaseRevision": 2,
                "reason": "Invalidate all current sessions during investigation.",
            },
            claims=responder,
        ),
    )
    assert revoked["statusCode"] == 200
    assert (
        _invoke(
            module,
            _event(
                "/agent/deployment-a/agent-a/heartbeat",
                "POST",
                token=session_token,
                project_root=project_root,
            ),
        )["statusCode"]
        == 403
    )
    detail = json.loads(
        _invoke(module, _event(f"/api/enterprise/cases/{case['id']}", "GET", claims=responder))[
            "body"
        ]
    )
    assert [event["eventType"] for event in detail["timeline"]] == [
        "case_created",
        "agent_quarantined",
        "agent_sessions_revoked",
    ]

    # Export correlation uses the case-captured agent binding and excludes
    # free-form approval narrative even when it exists in the source record.
    table.put_item(
        Item=module._item_key(tenant, "DECISION", "decision-a")
        | {
            "id": "decision-a",
            "deployment_id": "deployment-a",
            "agent_id": "agent-a",
            "observed_at": now - 10,
            "tool_name": "Bash",
            "decision": "denied",
            "reason_code": "policy_denied",
            "resource_kind": "command",
            "source": "claude_native_hook",
            "policy_id": "policy-a",
            "policy_version": 4,
            "action_digest": "b" * 64,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "APPROVAL", "approval-a")
        | {
            "id": "approval-a",
            "agent_key": "deployment-a:agent-a",
            "tool_name": "Bash",
            "proposal_id": "proposal-a",
            "task_id": "task-a",
            "principal_id": "synthetic-principal",
            "action_hash": "c" * 64,
            "risk_class": "consequential",
            "resource_ids": ["repository-a"],
            "status": "approved",
            # Real DynamoDB returns numeric attributes as Decimal even when
            # the application wrote integers. Keep this contract realistic so
            # export hashing cannot regress to non-JSON-safe content.
            "requested_at": Decimal(now - 10),
            "expires_at": Decimal(now + 600),
            "decided_at": Decimal(now - 5),
            "decided_by": "approver-a",
            "decision_reason": "Narrative intentionally excluded from portable evidence.",
        }
    )
    auditor = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["auditor"],
        "sub": "auditor-a",
    }
    exported = _invoke(
        module,
        _event(f"/api/enterprise/cases/{case['id']}/export", "GET", claims=auditor),
    )
    assert exported["statusCode"] == 200
    artifact = json.loads(exported["body"])
    verification = verify_artifact(artifact)
    assert verification == {
        "caseId": case["id"],
        "contentHash": artifact["integrity"]["contentHash"],
        "timelineEvents": 3,
        "decisions": 1,
        "approvals": 1,
    }
    assert artifact["content"]["decisions"][0]["id"] == "decision-a"
    assert "decisionReason" not in artifact["content"]["approvals"][0]
    assert artifact["content"]["completeness"]["approvalDecisionReasonsIncluded"] is False
    assert project_root not in exported["body"]
    assert "Narrative intentionally excluded" not in exported["body"]
    denied_export = _invoke(
        module,
        _event(
            f"/api/enterprise/cases/{case['id']}/export",
            "GET",
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["fleet-operator"],
                "sub": "fleet-only",
            },
        ),
    )
    assert denied_export["statusCode"] == 403

    other_tenant = "tenant-other-incident"
    table.put_item(Item=module._item_key(other_tenant, "TENANT", "root") | {"id": other_tenant})
    cross_tenant = _invoke(
        module,
        _event(
            f"/api/enterprise/cases/{case['id']}/export",
            "GET",
            claims={
                "custom:tenant_id": other_tenant,
                "cognito:groups": ["auditor"],
                "sub": "auditor-other",
            },
        ),
    )
    assert cross_tenant["statusCode"] == 404

    event_key = next(
        key
        for key, item in table.items.items()
        if item.get("case_id") == case["id"] and item.get("sequence") == 1
    )
    original_event = dict(table.items[event_key])
    table.items[event_key]["payload"] = {"reason": "Changed without updating the digest."}
    tampered = _invoke(
        module,
        _event(f"/api/enterprise/cases/{case['id']}/export", "GET", claims=auditor),
    )
    assert tampered["statusCode"] == 500
    table.items[event_key] = original_event

    original_case_record = module._case_record
    case_reads = 0

    def changed_case_record(case_tenant: str, case_id: str) -> dict[str, Any]:
        nonlocal case_reads
        case_reads += 1
        record = original_case_record(case_tenant, case_id)
        return {**record, "revision": int(record["revision"]) + 1} if case_reads > 1 else record

    monkeypatch.setattr(module, "_case_record", changed_case_record)
    with pytest.raises(module.PolicyConflict, match="changed during export"):
        module._case_export(tenant, case["id"], "auditor-a")
    monkeypatch.setattr(module, "_case_record", original_case_record)

    original_case_events = module._case_events
    bounded_events = [
        module._case_timeline_record(
            tenant,
            case["id"],
            "synthetic_event",
            "auditor-a",
            {"index": index},
            now=now - 1,
            sequence=index + 1,
        )
        for index in range(module._CASE_EXPORT_RECORD_LIMIT + 1)
    ]
    monkeypatch.setattr(module, "_case_events", lambda *_args: bounded_events)
    with pytest.raises(RuntimeError, match="timeline exceeds"):
        module._case_export(tenant, case["id"], "auditor-a")
    monkeypatch.setattr(module, "_case_events", original_case_events)

    monkeypatch.setattr(
        module,
        "_verify_agent",
        lambda *_args: {
            "verified": True,
            "checks": {
                "identity": {"passed": True},
                "heartbeat": {"passed": True},
                "emergencyStop": {"passed": False},
            },
            "controlState": {"activeStopScopes": []},
        },
    )
    released = _invoke(
        module,
        _event(
            f"/api/enterprise/cases/{case['id']}/release",
            "POST",
            body={
                "expectedCaseRevision": 3,
                "expectedContainmentRevision": 1,
                "reason": "Recovery evidence passed the server-side release gates.",
            },
            claims=responder,
        ),
    )
    assert released["statusCode"] == 200
    released_case = json.loads(released["body"])
    assert released_case["status"] == "investigating"
    assert released_case["containment"]["active"] is False
    assert (
        module._agent_control_state(
            tenant, table.items[(f"TENANT#{tenant}", "AGENT#deployment-a:agent-a")]
        )["executionAllowed"]
        is True
    )
    revoked_bootstrap = _invoke(
        module,
        _event(
            "/agent/enroll",
            "POST",
            body={"bootstrapToken": bootstrap, "projectRoot": project_root},
        ),
    )
    assert revoked_bootstrap["statusCode"] == 403
    assert "session authority has been revoked" in json.loads(revoked_bootstrap["body"])["error"]

    recontained = _invoke(
        module,
        _event(
            f"/api/enterprise/cases/{case['id']}/contain",
            "POST",
            body={
                "expectedCaseRevision": 4,
                "expectedBindingDigest": case["binding"]["bindingDigest"],
                "reason": "Reapply quarantine to test changed-correlation denial.",
            },
            claims=responder,
        ),
    )
    assert recontained["statusCode"] == 200
    assert json.loads(recontained["body"])["containment"]["revision"] == 3

    # A new matching agent makes the binding ambiguous. Subsequent authority
    # changes fail closed even though the browser still has the old case.
    duplicate = dict(table.items[(f"TENANT#{tenant}", "AGENT#deployment-a:agent-a")])
    duplicate.update(
        {"pk": f"TENANT#{tenant}", "sk": "AGENT#deployment-a:agent-b", "id": "agent-b"}
    )
    table.put_item(Item=duplicate)
    release = _invoke(
        module,
        _event(
            f"/api/enterprise/cases/{case['id']}/release",
            "POST",
            body={
                "expectedCaseRevision": 5,
                "expectedContainmentRevision": 3,
                "reason": "Attempt release after correlation became ambiguous.",
            },
            claims=responder,
        ),
    )
    assert release["statusCode"] == 409
    assert "binding" in json.loads(release["body"])["error"]


def test_endpoint_detection_schedule_materializes_stale_health(monkeypatch: Any) -> None:
    """The bounded scheduled path finds registered tenants without a browser poll."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-endpoint-schedule"
    now = 2_200_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-endpoint-schedule",
    }
    snapshot = _discovery_snapshot(
        "endpoint", [{"kind": "device", "id": "device-a", "managed": True}], now=now
    )
    assert (
        _invoke(
            module,
            _event(
                "/api/enterprise/discovery/sources/intune/snapshots",
                "POST",
                body=snapshot,
                claims=platform,
            ),
        )["statusCode"]
        == 201
    )
    registration = table.items[(f"TENANT#{tenant}", "TENANT#root")]
    assert registration["endpoint_detection_pk"].startswith("ENDPOINT_DETECTION#")
    monkeypatch.setattr(module.time, "time", lambda: now + 301)
    result = module.handler({"source": "aai.endpoint-detection", "schemaVersion": 1}, None)
    assert result == {"processedTenants": 1, "failedTenants": 0}
    alerts = [value for value in table.items.values() if value.get("source") == "endpoint_evidence"]
    assert {alert["reasonCode"] for alert in alerts} == {
        "credential_not_configured",
        "inventory_stale",
    }
    assert all(alert["deliveryStatus"] == "delivered" for alert in alerts)
    assert len(module.SNS.messages) == 2
    monkeypatch.setattr(
        module,
        "_endpoint_detection_cycle",
        lambda: (_ for _ in ()).throw(RuntimeError("synthetic scheduled failure")),
    )
    with pytest.raises(RuntimeError, match="synthetic scheduled failure"):
        module.handler({"source": "aai.endpoint-detection", "schemaVersion": 1}, None)


def test_endpoint_alert_delivery_failure_remains_pending_and_retries(monkeypatch: Any) -> None:
    """A provider outage cannot erase an alert or falsely mark it delivered."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-endpoint-delivery-retry"
    now = 2_300_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-endpoint-delivery",
    }
    snapshot = _discovery_snapshot(
        "endpoint", [{"kind": "device", "id": "device-a", "managed": True}], now=now
    )
    assert (
        _invoke(
            module,
            _event(
                "/api/enterprise/discovery/sources/intune/snapshots",
                "POST",
                body=snapshot,
                claims=claims,
            ),
        )["statusCode"]
        == 201
    )
    publisher = module.SNS.publish
    monkeypatch.setattr(
        module.SNS,
        "publish",
        lambda **_value: (_ for _ in ()).throw(OSError("synthetic provider outage")),
    )
    pending = json.loads(
        _invoke(module, _event("/api/enterprise/alerts", "GET", claims=claims))["body"]
    )["items"]
    assert pending[0]["deliveryStatus"] == "pending"
    monkeypatch.setattr(module.SNS, "publish", publisher)
    delivered = json.loads(
        _invoke(module, _event("/api/enterprise/alerts", "GET", claims=claims))["body"]
    )["items"]
    assert delivered[0]["deliveryStatus"] == "delivered"
    assert len(module.SNS.messages) == 1


def test_aws_endpoint_detection_is_scheduled_bounded_and_monitored() -> None:
    """Infrastructure must proactively reconcile health and surface exhaustion."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    assert 'indexName: "EndpointDetectionTenants"' in stack
    assert "schedule: events.Schedule.rate(cdk.Duration.minutes(5))" in stack
    assert 'source: "aai.endpoint-detection"' in stack
    assert "deadLetterQueue: endpointDetectionDlq" in stack
    assert '"EndpointDetectionDeadLetters"' in stack
    assert "securityAlerts.grantPublish(handler)" in stack
    assert "SECURITY_ALERTS_TOPIC_ARN: securityAlerts.topicArn" in stack


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
    assert denied_payload["error"] == "server-owned response control withholds agent execution"
    assert denied_payload["controlState"] == {
        "activeStopScopes": ["fleet"],
        "evidenceAllowed": True,
        "executionAllowed": False,
        "quarantine": None,
    }
    verification = _invoke(
        module,
        _event("/enterprise/agents/dep-a/agent-a/verify", "GET", claims=claims),
    )
    verification_payload = json.loads(verification["body"])
    assert verification_payload["verified"] is False
    assert verification_payload["checks"]["emergencyStop"] == {
        "passed": False,
        "detail": "A server-owned response control withholds execution authority.",
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
    assert json.loads(still_denied["body"])["controlState"]["activeStopScopes"] == ["agent"]
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


def test_response_stop_scopes_are_independent_and_follow_live_group_membership(
    monkeypatch: Any,
) -> None:
    """Clearing one response scope cannot erase another or exempt a new member."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-independent-response-controls"
    agent_a = module._item_key(tenant, "AGENT", "dep-a:agent-a") | {
        "tenant_id": tenant,
        "id": "agent-a",
        "deployment_id": "dep-a",
        "lifecycle_state": "active",
        "lifecycle_revision": 1,
    }
    agent_b = module._item_key(tenant, "AGENT", "dep-a:agent-b") | {
        **agent_a,
        "sk": "AGENT#dep-a:agent-b",
        "id": "agent-b",
    }
    group = module._item_key(tenant, "GROUP", "group-a") | {
        "id": "group-a",
        "agent_keys": ["dep-a:agent-a"],
    }
    for item in (agent_a, agent_b, group):
        table.put_item(Item=item)

    module._set_scope_emergency_stop(tenant, "deployment", "dep-a", True, "responder")
    module._set_scope_emergency_stop(tenant, "group", "group-a", True, "responder")
    assert module._agent_control_state(tenant, agent_a)["activeStopScopes"] == [
        "deployment",
        "group",
    ]

    module._set_scope_emergency_stop(tenant, "deployment", "dep-a", False, "responder")
    assert module._agent_control_state(tenant, agent_a)["activeStopScopes"] == ["group"]

    group["agent_keys"].append("dep-a:agent-b")
    table.put_item(Item=group)
    assert module._agent_control_state(tenant, agent_b)["activeStopScopes"] == ["group"]

    module._set_scope_emergency_stop(tenant, "group", "group-a", False, "responder")
    assert module._agent_control_state(tenant, agent_a)["executionAllowed"] is True
    assert module._agent_control_state(tenant, agent_b)["executionAllowed"] is True


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


def test_trial_handler_signs_before_any_tenant_record_is_written(monkeypatch: Any) -> None:
    """A signing outage cannot leave an unsigned or partially active trial tenant."""
    path = Path(__file__).parents[1] / "infra/aws-control-plane/lambda/trial_onboarding.py"
    monkeypatch.syspath_prepend(str(path.parent))
    key_id = "arn:aws:kms:eu-west-2:111111111111:key/12345678-1234-1234-1234-123456789abc"

    class Cognito:
        def admin_add_user_to_group(self, **_value: Any) -> None:
            return None

    def load_trial(table: FakeTable, kms: object, name: str) -> Any:
        boto3 = types.ModuleType("boto3")
        boto3.resource = (  # type: ignore[attr-defined]
            lambda *_args, **_kwargs: types.SimpleNamespace(Table=lambda _name: table)
        )
        boto3.client = (  # type: ignore[attr-defined]
            lambda service, *_args, **_kwargs: kms if service == "kms" else Cognito()
        )
        monkeypatch.setitem(sys.modules, "boto3", boto3)
        monkeypatch.setenv("CONTROL_TABLE", "control")
        monkeypatch.setenv("POLICY_SIGNING_KEY_ARN", key_id)
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    event = {
        "userPoolId": "eu-west-2_synthetic",
        "userName": "subject-a",
        "request": {"userAttributes": {"sub": "subject-a", "email": "trial@example.test"}},
    }
    failing_table = FakeTable()

    class FailingKms:
        def sign(self, **_value: Any) -> dict[str, Any]:
            raise RuntimeError("synthetic KMS outage")

    failing = load_trial(failing_table, FailingKms(), "aai_trial_failure")
    with pytest.raises(RuntimeError, match="synthetic KMS outage"):
        failing.handler(event, None)
    assert failing_table.items == {}

    successful_table = FakeTable()
    successful_kms = FakeKms(key_id)
    successful = load_trial(successful_table, successful_kms, "aai_trial_success")
    assert successful.handler(event, None) == event
    version = next(
        item for item in successful_table.items.values() if item["sk"].startswith("POLICY_VERSION#")
    )
    assert version["bundle_integrity"]["algorithm"] == "ECDSA_SHA_256"
    assert version["effective_content_hash"] == version["content_hash"]
    assert successful_kms.calls[0]["MessageType"] == "DIGEST"


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


def test_device_population_without_installations_suppresses_coverage(
    monkeypatch: Any,
) -> None:
    """Managed-device facts alone never become complete agent evidence."""
    module, table = _load_handler(monkeypatch)
    now = 1_785_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    tenant = "tenant-device-only"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-admin-a",
    }
    digest = hashlib.sha256(b"/synthetic/project").hexdigest()
    snapshots = {
        "entra": _discovery_snapshot(
            "identity",
            [{"kind": "identity", "id": "user-a", "active": True}],
            now=now,
        ),
        "intune": _discovery_snapshot(
            "endpoint",
            [
                {
                    "kind": "device",
                    "id": "device-a",
                    "managed": True,
                    "userIds": ["user-a"],
                }
            ],
            now=now,
        ),
        "github": _discovery_snapshot(
            "source_control",
            [
                {
                    "kind": "repository",
                    "id": "repo-a",
                    "projectRootDigest": digest,
                    "expectedHosts": ["claude-code"],
                }
            ],
            now=now,
        ),
    }
    for source_id, snapshot in snapshots.items():
        response = _invoke(
            module,
            _event(
                f"/api/enterprise/discovery/sources/{source_id}/snapshots",
                "POST",
                body=snapshot,
                claims=claims,
            ),
        )
        assert response["statusCode"] == 201

    report = json.loads(
        _invoke(module, _event("/api/enterprise/discovery", "GET", claims=claims))["body"]
    )
    assert report["summary"]["coverageAvailable"] is False
    assert report["summary"]["sourceComplete"] is False
    assert report["summary"]["coveragePercent"] is None
    assert report["summary"]["orphaned"] == 0
    assert report["blindSpots"] == ["missing_endpoint_installations"]


def test_discovery_connector_cannot_reinterpret_legacy_source_kind(
    monkeypatch: Any,
) -> None:
    """A snapshot-first source ID permanently establishes its evidence class."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-discovery-legacy-kind"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "DISCOVERY_SOURCE", "inventory-primary")
        | {
            "sourceId": "inventory-primary",
            "sourceKind": "identity",
            "generation": "legacy-generation",
            "revision": 1,
            "complete": True,
            "observedAt": 1,
            "expiresAt": 2,
            "observations": [],
            "contentHash": "a" * 64,
        }
    )
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-admin-a",
    }

    response = _invoke(
        module,
        _event(
            "/api/enterprise/discovery/sources/inventory-primary/connector-credential",
            "POST",
            body={"sourceKind": "endpoint", "expectedRevision": 0},
            claims=platform,
        ),
    )

    assert response["statusCode"] == 409
    assert "sourceKind is immutable" in response["body"]
    assert (
        table.get_item(
            Key=module._item_key(tenant, "DISCOVERY_CONNECTOR", "inventory-primary")
        ).get("Item")
        is None
    )


class FakeManagedDiscoverySecrets:
    """Capture managed collector secret metadata without retaining a live credential."""

    def __init__(self, provider_arn: str, key_arn: str, tenant: str) -> None:
        self.provider_arn = provider_arn
        self.key_arn = key_arn
        self.tenant = tenant
        self.described: list[str] = []
        self.created: list[dict[str, Any]] = []
        self.deleted: list[dict[str, Any]] = []

    def describe_secret(self, *, SecretId: str) -> dict[str, Any]:
        self.described.append(SecretId)
        return {
            "ARN": self.provider_arn,
            "KmsKeyId": self.key_arn,
            "Tags": [
                {"Key": "aai-sec:tenant-id", "Value": self.tenant},
                {"Key": "aai-sec:purpose", "Value": "discovery-provider"},
            ],
        }

    def create_secret(self, **kwargs: Any) -> dict[str, str]:
        self.created.append(dict(kwargs))
        return {
            "ARN": (f"arn:aws:secretsmanager:eu-west-2:111122223333:secret:{kwargs['Name']}-abc123")
        }

    def delete_secret(self, **kwargs: Any) -> None:
        self.deleted.append(dict(kwargs))


class FakeManagedDiscoveryScheduler:
    """Capture exact schedule creation and deletion calls."""

    def __init__(self) -> None:
        self.created: list[dict[str, Any]] = []
        self.deleted: list[dict[str, Any]] = []

    def create_schedule(self, **kwargs: Any) -> None:
        self.created.append(dict(kwargs))

    def delete_schedule(self, **kwargs: Any) -> None:
        self.deleted.append(dict(kwargs))


def _managed_discovery_doubles(
    monkeypatch: Any, module: Any, tenant: str, *, provider_name: str = "entra-primary"
) -> tuple[Any, Any, str]:
    """Configure deployment coordinates and return managed AWS adapter doubles."""
    key_arn = "arn:aws:kms:eu-west-2:111122223333:key/00000000-1111-4222-8333-444444444444"
    provider_arn = (
        "arn:aws:secretsmanager:eu-west-2:111122223333:secret:"
        f"aai-sec/discovery/providers/{tenant}/{provider_name}-abc123"
    )
    environment = {
        "DISCOVERY_COLLECTOR_ARN": "arn:aws:lambda:eu-west-2:111122223333:function:collector",
        "DISCOVERY_SCHEDULER_ROLE_ARN": "arn:aws:iam::111122223333:role/scheduler",
        "DISCOVERY_COLLECTOR_DLQ_ARN": "arn:aws:sqs:eu-west-2:111122223333:collector-dlq",
        "DISCOVERY_SECRET_KMS_KEY_ARN": key_arn,
        "DISCOVERY_PROVIDER_SECRET_PREFIX": "aai-sec/discovery/providers/",
        "DISCOVERY_CONNECTOR_SECRET_PREFIX": "aai-sec/discovery/connectors/",
        "AWS_REGION": "eu-west-2",
        "AWS_ACCOUNT_ID": "111122223333",
        "AWS_PARTITION": "aws",
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    secret_client = FakeManagedDiscoverySecrets(provider_arn, key_arn, tenant)
    scheduler = FakeManagedDiscoveryScheduler()
    monkeypatch.setattr(module, "_managed_discovery_clients", lambda: (secret_client, scheduler))
    return secret_client, scheduler, provider_arn


def test_managed_entra_discovery_create_directory_and_disable_are_fail_closed(
    monkeypatch: Any,
) -> None:
    """The managed lifecycle stores no plaintext and revokes before AWS cleanup."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-managed-discovery"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    secret_client, scheduler, provider_arn = _managed_discovery_doubles(monkeypatch, module, tenant)
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-admin-a",
    }
    capabilities = _invoke(
        module,
        _event(
            "/api/enterprise/discovery/managed-collector-capabilities",
            "GET",
            claims=claims,
        ),
    )
    assert capabilities["statusCode"] == 200
    capability_body = json.loads(capabilities["body"])
    assert capability_body["available"] is True
    assert capability_body["providerSecretNamePrefix"] == "aai-sec/discovery/providers/"
    assert capability_body["providers"] == ["entra", "github", "intune"]
    assert capability_body["providerConfigurations"]["github"] == {
        "sourceKind": "source_control",
        "secretSchema": ["token"],
        "configurationSchema": ["organization", "repositories"],
        "maximumRepositories": 500,
    }
    assert capability_body["providerConfigurations"]["intune"] == {
        "sourceKind": "endpoint",
        "secretSchema": ["tenantId", "clientId", "clientSecret"],
        "configurationSchema": ["userBusinessUnits"],
        "maximumUserBusinessUnits": 500,
        "installationEvidenceRequired": True,
    }

    path = "/api/enterprise/discovery/sources/entra-primary/managed-collector"
    created = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                "provider": "entra",
                "providerSecretArn": provider_arn,
                "intervalMinutes": 60,
                "expectedJobRevision": 0,
                "expectedCredentialRevision": 0,
            },
            claims=claims,
        ),
    )
    assert created["statusCode"] == 201
    assert json.loads(created["body"])["status"] == "scheduled"
    assert secret_client.described == [provider_arn]
    assert len(secret_client.created) == 1
    secret_value = json.loads(secret_client.created[0]["SecretString"])
    assert set(secret_value) == {"token"}
    assert secret_value["token"] not in json.dumps(list(table.items.values()))
    assert (
        len(
            [
                item
                for item in table.items.values()
                if str(item.get("sk", "")).startswith("DISCOVERY_AUDIT#")
            ]
        )
        == 1
    )
    assert len(scheduler.created) == 1
    schedule_input = json.loads(scheduler.created[0]["Target"]["Input"])
    assert schedule_input["tenantId"] == tenant
    assert schedule_input["sourceId"] == "entra-primary"
    assert schedule_input["configurationDigest"] == module._configuration_hash(
        {key: value for key, value in schedule_input.items() if key != "configurationDigest"}
    )

    directory = _invoke(
        module,
        _event("/api/enterprise/discovery/sources", "GET", claims=claims),
    )
    assert directory["statusCode"] == 200
    directory_body = json.loads(directory["body"])
    assert directory_body["items"][0]["managedCollector"] == {
        "provider": "entra",
        "sourceKind": "identity",
        "providerSummary": None,
        "status": "scheduled",
        "revision": 1,
        "intervalMinutes": 60,
        "lastAttemptAt": 0,
        "lastSuccessAt": 0,
        "lastErrorCode": None,
        "consecutiveFailures": 0,
        "cleanupRequired": False,
    }
    for forbidden in ("providerSecretArn", "connectorSecretArn", "scheduleName", "tokenHash"):
        assert forbidden not in directory["body"]

    disabled = _invoke(
        module,
        _event(
            path,
            "DELETE",
            body={"expectedJobRevision": 1, "expectedCredentialRevision": 1},
            claims=claims,
        ),
    )
    assert disabled["statusCode"] == 200
    assert json.loads(disabled["body"])["status"] == "disabled"
    assert (
        table.items[(f"TENANT#{tenant}", "DISCOVERY_CONNECTOR#entra-primary")]["status"]
        == "revoked"
    )
    assert (
        len(
            [
                item
                for item in table.items.values()
                if str(item.get("sk", "")).startswith("DISCOVERY_AUDIT#")
            ]
        )
        == 2
    )
    assert scheduler.deleted == [{"Name": scheduler.created[0]["Name"]}]
    assert secret_client.deleted[-1]["RecoveryWindowInDays"] == 7


def test_managed_github_discovery_binds_repository_mapping_and_redacts_directory(
    monkeypatch: Any,
) -> None:
    """GitHub setup stores a digest-bound map but exposes only safe summary metadata."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-managed-github"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    secret_client, scheduler, provider_arn = _managed_discovery_doubles(
        monkeypatch, module, tenant, provider_name="github-primary"
    )
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-admin-a",
    }
    provider_configuration = {
        "organization": "Example-Enterprise",
        "repositories": [
            {
                "fullName": "Example-Enterprise/.GitHub",
                "projectRootDigest": "a" * 64,
                "expectedHosts": ["codex-cli", "claude-code"],
                "businessUnit": "Platform",
            }
        ],
    }
    path = "/api/enterprise/discovery/sources/github-primary/managed-collector"

    created = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                "provider": "github",
                "providerSecretArn": provider_arn,
                "providerConfiguration": provider_configuration,
                "intervalMinutes": 60,
                "expectedJobRevision": 0,
                "expectedCredentialRevision": 0,
            },
            claims=claims,
        ),
    )

    assert created["statusCode"] == 201
    created_body = json.loads(created["body"])
    assert created_body == {
        "provider": "github",
        "sourceKind": "source_control",
        "providerSummary": {
            "organization": "example-enterprise",
            "repositoryCount": 1,
        },
        "status": "scheduled",
        "revision": 1,
        "intervalMinutes": 60,
        "lastAttemptAt": 0,
        "lastSuccessAt": 0,
        "lastErrorCode": None,
        "consecutiveFailures": 0,
        "cleanupRequired": False,
    }
    job = table.items[(f"TENANT#{tenant}", "DISCOVERY_JOB#github-primary")]
    assert job["sourceKind"] == "source_control"
    assert job["providerConfiguration"] == {
        "organization": "example-enterprise",
        "repositories": [
            {
                "fullName": "example-enterprise/.github",
                "projectRootDigest": "a" * 64,
                "expectedHosts": ["claude-code", "codex-cli"],
                "businessUnit": "Platform",
            }
        ],
    }
    schedule_input = json.loads(scheduler.created[0]["Target"]["Input"])
    assert schedule_input["provider"] == "github"
    assert schedule_input["providerConfigurationDigest"] == job["providerConfigurationDigest"]
    assert "providerConfiguration" not in schedule_input
    assert scheduler.created[0]["Description"] == "AAI Security managed github discovery"
    assert secret_client.described == [provider_arn]

    directory = _invoke(
        module,
        _event("/api/enterprise/discovery/sources", "GET", claims=claims),
    )
    assert directory["statusCode"] == 200
    directory_body = json.loads(directory["body"])
    assert directory_body["items"][0]["managedCollector"]["providerSummary"] == {
        "organization": "example-enterprise",
        "repositoryCount": 1,
    }
    for forbidden in (
        "providerSecretArn",
        "connectorSecretArn",
        "providerConfigurationDigest",
        "fullName",
        "projectRootDigest",
    ):
        assert forbidden not in directory["body"]


def test_managed_intune_discovery_binds_attribution_and_redacts_user_ids(
    monkeypatch: Any,
) -> None:
    """Intune setup exposes device-source posture without its user mapping."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-managed-intune"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    secret_client, scheduler, provider_arn = _managed_discovery_doubles(
        monkeypatch, module, tenant, provider_name="intune-primary"
    )
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-admin-a",
    }
    user_id = "33333333-3333-4333-8333-333333333333"
    path = "/api/enterprise/discovery/sources/intune-primary/managed-collector"
    created = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                "provider": "intune",
                "providerSecretArn": provider_arn,
                "providerConfiguration": {
                    "userBusinessUnits": [{"userId": user_id, "businessUnit": "Platform"}]
                },
                "intervalMinutes": 60,
                "expectedJobRevision": 0,
                "expectedCredentialRevision": 0,
            },
            claims=claims,
        ),
    )

    assert created["statusCode"] == 201
    body = json.loads(created["body"])
    assert body["provider"] == "intune"
    assert body["sourceKind"] == "endpoint"
    assert body["providerSummary"] == {
        "userBusinessUnitCount": 1,
        "installationEvidenceRequired": True,
    }
    job = table.items[(f"TENANT#{tenant}", "DISCOVERY_JOB#intune-primary")]
    assert job["providerConfiguration"] == {
        "userBusinessUnits": [{"userId": user_id, "businessUnit": "Platform"}]
    }
    schedule_input = json.loads(scheduler.created[0]["Target"]["Input"])
    assert schedule_input["provider"] == "intune"
    assert schedule_input["providerConfigurationDigest"] == job["providerConfigurationDigest"]
    assert "providerConfiguration" not in schedule_input
    assert secret_client.described == [provider_arn]

    directory = _invoke(
        module,
        _event("/api/enterprise/discovery/sources", "GET", claims=claims),
    )
    assert directory["statusCode"] == 200
    assert user_id not in directory["body"]
    assert "providerConfiguration" not in directory["body"]


@pytest.mark.parametrize(
    "provider_configuration",
    [
        {},
        {"userBusinessUnits": "not-a-list"},
        {"userBusinessUnits": [{"userId": "not-a-uuid", "businessUnit": "Platform"}]},
        {
            "userBusinessUnits": [
                {
                    "userId": "33333333-3333-4333-8333-333333333333",
                    "businessUnit": "Platform",
                },
                {
                    "userId": "33333333-3333-4333-8333-333333333333",
                    "businessUnit": "Risk",
                },
            ]
        },
    ],
)
def test_managed_intune_discovery_rejects_unsafe_mapping_before_aws(
    monkeypatch: Any, provider_configuration: dict[str, Any]
) -> None:
    """Malformed or ambiguous Intune attribution cannot provision resources."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-managed-intune-invalid"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    secret_client, scheduler, provider_arn = _managed_discovery_doubles(
        monkeypatch, module, tenant, provider_name="intune-primary"
    )
    response = _invoke(
        module,
        _event(
            "/api/enterprise/discovery/sources/intune-primary/managed-collector",
            "POST",
            body={
                "provider": "intune",
                "providerSecretArn": provider_arn,
                "providerConfiguration": provider_configuration,
                "intervalMinutes": 60,
                "expectedJobRevision": 0,
                "expectedCredentialRevision": 0,
            },
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["platform-admin"],
                "sub": "platform-admin-a",
            },
        ),
    )
    assert response["statusCode"] == 400
    assert secret_client.described == []
    assert scheduler.created == []


@pytest.mark.parametrize(
    "provider_configuration",
    [
        {"organization": "example-enterprise", "repositories": []},
        {
            "organization": "example-enterprise",
            "repositories": [
                {
                    "fullName": "another-enterprise/repository-a",
                    "projectRootDigest": "a" * 64,
                    "expectedHosts": ["claude-code"],
                }
            ],
        },
        {
            "organization": "example-enterprise",
            "repositories": [
                {
                    "fullName": "example-enterprise/repository-a",
                    "projectRootDigest": "not-a-digest",
                    "expectedHosts": ["claude-code"],
                }
            ],
        },
        {
            "organization": "example-enterprise",
            "repositories": [
                {
                    "fullName": "example-enterprise/repository-a",
                    "projectRootDigest": "a" * 64,
                    "expectedHosts": ["claude-code", "claude-code"],
                }
            ],
        },
        {
            "organization": "example-enterprise",
            "repositories": [
                {
                    "fullName": "example-enterprise/repository-a",
                    "projectRootDigest": "a" * 64,
                    "expectedHosts": ["claude-code"],
                },
                {
                    "fullName": "example-enterprise/repository-b",
                    "projectRootDigest": "a" * 64,
                    "expectedHosts": ["codex-cli"],
                },
            ],
        },
    ],
)
def test_managed_github_discovery_rejects_unsafe_mapping_before_aws(
    monkeypatch: Any, provider_configuration: dict[str, Any]
) -> None:
    """Malformed, cross-organization and ambiguous maps cannot provision resources."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-managed-github-invalid"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    secret_client, scheduler, provider_arn = _managed_discovery_doubles(
        monkeypatch, module, tenant, provider_name="github-primary"
    )
    response = _invoke(
        module,
        _event(
            "/api/enterprise/discovery/sources/github-primary/managed-collector",
            "POST",
            body={
                "provider": "github",
                "providerSecretArn": provider_arn,
                "providerConfiguration": provider_configuration,
                "intervalMinutes": 60,
                "expectedJobRevision": 0,
                "expectedCredentialRevision": 0,
            },
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["platform-admin"],
                "sub": "platform-admin-a",
            },
        ),
    )
    assert response["statusCode"] == 400
    assert secret_client.described == []
    assert scheduler.created == []


def test_managed_discovery_rejects_cross_tenant_secret_before_aws_lookup(
    monkeypatch: Any,
) -> None:
    """A browser cannot bind another tenant/account/region secret to a collector."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-managed-isolation"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    secret_client, scheduler, _provider_arn = _managed_discovery_doubles(
        monkeypatch, module, tenant
    )
    response = _invoke(
        module,
        _event(
            "/api/enterprise/discovery/sources/entra/managed-collector",
            "POST",
            body={
                "provider": "entra",
                "providerSecretArn": (
                    "arn:aws:secretsmanager:eu-west-2:111122223333:secret:"
                    "aai-sec/discovery/providers/another-tenant/entra-abc123"
                ),
                "intervalMinutes": 60,
                "expectedJobRevision": 0,
                "expectedCredentialRevision": 0,
            },
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["platform-admin"],
                "sub": "admin-a",
            },
        ),
    )
    assert response["statusCode"] == 400
    assert secret_client.described == []
    assert scheduler.created == []


def test_managed_discovery_transaction_conflict_cleans_external_resources(
    monkeypatch: Any,
) -> None:
    """A concurrent create leaves no schedule or usable secret behind."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-managed-race"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    secret_client, scheduler, provider_arn = _managed_discovery_doubles(monkeypatch, module, tenant)

    def concurrent_create() -> None:
        table.put_item(
            Item=module._item_key(tenant, "DISCOVERY_JOB", "entra")
            | {"sourceId": "entra", "sourceKind": "identity", "revision": 1}
        )

    module.DYNAMODB.before_transaction = concurrent_create
    response = _invoke(
        module,
        _event(
            "/api/enterprise/discovery/sources/entra/managed-collector",
            "POST",
            body={
                "provider": "entra",
                "providerSecretArn": provider_arn,
                "intervalMinutes": 15,
                "expectedJobRevision": 0,
                "expectedCredentialRevision": 0,
            },
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["platform-admin"],
                "sub": "admin-a",
            },
        ),
    )
    assert response["statusCode"] == 409
    assert len(scheduler.deleted) == 1
    assert secret_client.deleted[-1]["RecoveryWindowInDays"] == 7
    assert not any(key[1] == "DISCOVERY_CONNECTOR#entra" for key in table.items)


def test_discovery_connector_commits_complete_paginated_generation_atomically(
    monkeypatch: Any,
) -> None:
    """Partial, forged, replayed and concurrently stale connector uploads stay invisible."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-discovery-connector"
    now = int(time.time())
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-admin-a",
    }
    credential_path = "/api/enterprise/discovery/sources/github/connector-credential"
    issued = _invoke(
        module,
        _event(
            credential_path,
            "POST",
            body={"sourceKind": "source_control", "expectedRevision": 0},
            claims=platform,
        ),
    )
    assert issued["statusCode"] == 201
    credential = json.loads(issued["body"])
    token = credential["token"]
    stored = table.get_item(Key=module._item_key(tenant, "DISCOVERY_CONNECTOR", "github"))["Item"]
    assert token not in json.dumps(stored)
    assert stored["tokenHash"] == hashlib.sha256(token.encode()).hexdigest()
    directory_path = "/api/enterprise/discovery/sources"
    directory = _invoke(module, _event(directory_path, "GET", claims=platform))
    assert directory["statusCode"] == 200
    registered = json.loads(directory["body"])
    assert registered["nextCursor"] is None
    assert registered["items"][0] | {
        "credential": {
            **registered["items"][0]["credential"],
            "rotatedAt": 0,
        }
    } == {
        "sourceId": "github",
        "sourceKind": "source_control",
        "credential": {
            "status": "active",
            "revision": 1,
            "rotatedAt": 0,
            "revokedAt": None,
        },
        "snapshot": None,
        "managedCollector": None,
    }
    assert registered["items"][0]["credential"]["rotatedAt"] >= now
    assert token not in directory["body"]
    assert "tokenHash" not in directory["body"]
    assert (
        _invoke(
            module,
            _event(
                directory_path,
                "GET",
                claims={"custom:tenant_id": tenant, "sub": "unprivileged-a"},
            ),
        )["statusCode"]
        == 403
    )

    base = f"/api/discovery-ingest/{tenant}/github/generations"
    generation = {
        "generation": "github-page-set-1",
        "expectedRevision": 0,
        "observedAt": now,
        "expiresAt": now + 300,
        "pageCount": 2,
    }
    forged_credential = "synthetic-invalid-connector-credential"  # noqa: S105
    forged = _event(base, "POST", body=generation, token=forged_credential)
    assert _invoke(module, forged)["statusCode"] == 403
    assert _invoke(module, _event(base, "POST", body=generation, token=token))["statusCode"] == 201
    generation_key = (
        f"TENANT#{tenant}",
        "DISCOVERY_GENERATION#github:github-page-set-1",
    )
    # boto3 returns DynamoDB numbers as Decimal in the deployed Lambda.
    for field in ("expectedRevision", "observedAt", "expiresAt", "pageCount"):
        table.items[generation_key][field] = Decimal(table.items[generation_key][field])

    digest_a = hashlib.sha256(b"/synthetic/repository-a").hexdigest()
    digest_b = hashlib.sha256(b"/synthetic/repository-b").hexdigest()
    pages = [
        {
            "observations": [
                {
                    "kind": "repository",
                    "id": "repository-a",
                    "projectRootDigest": digest_a,
                    "expectedHosts": ["claude-code"],
                }
            ]
        },
        {
            "observations": [
                {
                    "kind": "repository",
                    "id": "repository-b",
                    "projectRootDigest": digest_b,
                    "expectedHosts": ["codex-cli"],
                }
            ]
        },
    ]
    page_hashes = []
    for page_number, body in enumerate(pages):
        response = _invoke(
            module,
            _event(
                f"{base}/github-page-set-1/pages/{page_number}",
                "PUT",
                body=body,
                token=token,
            ),
        )
        assert response["statusCode"] == 201
        page_hashes.append(json.loads(response["body"])["pageHash"])

    before_commit = json.loads(
        _invoke(module, _event("/api/enterprise/discovery", "GET", claims=platform))["body"]
    )
    assert before_commit["sources"] == []
    assert before_commit["summary"]["coverageAvailable"] is False

    bad_commit = _invoke(
        module,
        _event(
            f"{base}/github-page-set-1/commit",
            "POST",
            body={"pageHashes": [page_hashes[0], "0" * 64]},
            token=token,
        ),
    )
    assert bad_commit["statusCode"] == 400
    committed = _invoke(
        module,
        _event(
            f"{base}/github-page-set-1/commit",
            "POST",
            body={"pageHashes": page_hashes},
            token=token,
        ),
    )
    assert committed["statusCode"] == 200
    current = json.loads(
        _invoke(module, _event("/api/enterprise/discovery", "GET", claims=platform))["body"]
    )
    assert current["sources"][0]["status"] == "current"
    assert current["sources"][0]["observationCount"] == 2
    assert current["summary"]["denominator"] == 2
    assert current["summary"]["coverageAvailable"] is False
    current_directory = json.loads(
        _invoke(module, _event(directory_path, "GET", claims=platform))["body"]
    )
    assert current_directory["items"][0]["snapshot"] == {
        key: value
        for key, value in current["sources"][0].items()
        if key not in {"sourceId", "sourceKind"}
    }
    assert (
        _invoke(
            module,
            _event(
                f"{base}/github-page-set-1/commit",
                "POST",
                body={"pageHashes": page_hashes},
                token=token,
            ),
        )["statusCode"]
        == 404
    )

    stale_generation = {
        **generation,
        "generation": "github-stale-writer",
        "expectedRevision": 1,
        "pageCount": 1,
    }
    assert (
        _invoke(module, _event(base, "POST", body=stale_generation, token=token))["statusCode"]
        == 201
    )
    stale_page = _invoke(
        module,
        _event(
            f"{base}/github-stale-writer/pages/0",
            "PUT",
            body=pages[0],
            token=token,
        ),
    )
    stale_hash = json.loads(stale_page["body"])["pageHash"]
    legacy_snapshot = _discovery_snapshot(
        "source_control", pages[1]["observations"], now=now, expected_revision=1
    )
    assert (
        _invoke(
            module,
            _event(
                "/api/enterprise/discovery/sources/github/snapshots",
                "POST",
                body=legacy_snapshot,
                claims=platform,
            ),
        )["statusCode"]
        == 201
    )
    assert (
        _invoke(
            module,
            _event(
                f"{base}/github-stale-writer/commit",
                "POST",
                body={"pageHashes": [stale_hash]},
                token=token,
            ),
        )["statusCode"]
        == 409
    )

    duplicate_generation = {
        **generation,
        "generation": "github-cross-page-duplicate",
        "expectedRevision": 2,
    }
    assert (
        _invoke(module, _event(base, "POST", body=duplicate_generation, token=token))["statusCode"]
        == 201
    )
    duplicate_hashes = []
    for page_number in range(2):
        duplicate_page = _invoke(
            module,
            _event(
                f"{base}/github-cross-page-duplicate/pages/{page_number}",
                "PUT",
                body=pages[0],
                token=token,
            ),
        )
        duplicate_hashes.append(json.loads(duplicate_page["body"])["pageHash"])
    assert (
        _invoke(
            module,
            _event(
                f"{base}/github-cross-page-duplicate/commit",
                "POST",
                body={"pageHashes": duplicate_hashes},
                token=token,
            ),
        )["statusCode"]
        == 400
    )

    revoked = _invoke(module, _event(credential_path, "DELETE", claims=platform))
    assert revoked["statusCode"] == 200
    revoked_directory = json.loads(
        _invoke(module, _event(directory_path, "GET", claims=platform))["body"]
    )
    assert revoked_directory["items"][0]["credential"]["status"] == "revoked"
    assert revoked_directory["items"][0]["credential"]["revision"] == 2
    assert (
        _invoke(
            module,
            _event(
                base,
                "POST",
                body={**generation, "generation": "github-page-set-2", "expectedRevision": 2},
                token=token,
            ),
        )["statusCode"]
        == 403
    )
