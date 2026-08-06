"""Contract tests for the deployed AWS control-plane Lambda boundary."""

import base64
import copy
import hashlib
import hmac
import importlib.util
import json
import re
import sys
import threading
import time
import types
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
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
    PolicyTrustStore,
    TrustedPolicyKey,
)

_SYNTHETIC_P256_PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9AednGdWX5tOVVBzU4graM3pMoB7
1zN9CeMI3CdIylAEaD5uETFZniRiQmvKmYClaOEdOrDhpXqNTe7q+cLtCw==
-----END PUBLIC KEY-----
"""


class ConditionalFailure(Exception):
    """Minimal boto-compatible conditional failure."""

    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class ObjectLockConfigurationMissing(Exception):
    """Minimal boto-compatible legacy Object Lock absence response."""

    response = {"Error": {"Code": "NoSuchObjectLockConfiguration"}}


class ObjectLockAccessDenied(Exception):
    """Minimal boto-compatible Object Lock permission failure."""

    response = {"Error": {"Code": "AccessDenied"}}


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
                revision_field = "rolloutRevision" if "rolloutRevision" in condition else "revision"
                if self.items.get(key, {}).get(revision_field) != values[":expected_revision"]:
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
        if ":report_pk" in ExpressionAttributeValues:
            if (
                item.get("assurance_report_pk") != ExpressionAttributeValues[":report_pk"]
                or item.get("assurance_report_sk") != ExpressionAttributeValues[":report_sk"]
            ):
                raise ConditionalFailure()
            if ":candidate_revision" in ExpressionAttributeValues:
                if item.get("revision") != ExpressionAttributeValues[":candidate_revision"]:
                    raise ConditionalFailure()
            elif "revision" in item:
                raise ConditionalFailure()
            item.pop("assurance_report_pk", None)
            item.pop("assurance_report_sk", None)
            item["assurance_report_quarantined_at"] = ExpressionAttributeValues[":quarantined_at"]
            item["assurance_report_quarantine_reason"] = ExpressionAttributeValues[
                ":quarantine_reason"
            ]
            self.items[key] = item
            return {"Attributes": dict(item)}
        if ":partition" in ExpressionAttributeValues and ":tenant" in ExpressionAttributeValues:
            update_expression = str(_.get("UpdateExpression", ""))
            if "evidence_assurance_pk" in update_expression:
                item["evidence_assurance_pk"] = ExpressionAttributeValues[":partition"]
                item["evidence_assurance_sk"] = ExpressionAttributeValues[":tenant"]
            else:
                item["endpoint_detection_pk"] = ExpressionAttributeValues[":partition"]
                item["endpoint_detection_sk"] = ExpressionAttributeValues[":tenant"]
            self.items[key] = item
            return {"Attributes": dict(item)}
        if ":method" in ExpressionAttributeValues and ":route" in ExpressionAttributeValues:
            if (
                item.get("status") != ExpressionAttributeValues[":active"]
                or item.get("revision") != ExpressionAttributeValues[":revision"]
                or item.get("expires_at", 0) <= ExpressionAttributeValues[":now"]
            ):
                raise ConditionalFailure()
            item["last_used_at"] = ExpressionAttributeValues[":now"]
            item["last_used_method"] = ExpressionAttributeValues[":method"]
            item["last_used_route"] = ExpressionAttributeValues[":route"]
            item["use_count"] = int(item.get("use_count", 0)) + ExpressionAttributeValues[":one"]
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
        if ":pending" in ExpressionAttributeValues and ":queued" in ExpressionAttributeValues:
            if item.get("status") != ExpressionAttributeValues[":pending"]:
                raise ConditionalFailure()
            item["status"] = ExpressionAttributeValues[":queued"]
            item.pop("workflow_outbox_pk", None)
            item.pop("workflow_outbox_sk", None)
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
                elif operation == "lte":
                    values = [item for item in values if item.get(field, "") <= expected]
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
                if "Delete" in operation:
                    delete = operation["Delete"]
                    key_shape = {
                        key: _decode_ddb_value(value) for key, value in delete["Key"].items()
                    }
                    key = (key_shape["pk"], key_shape.get("sk", ""))
                    existing = self.table.items.get(key)
                    names = delete.get("ExpressionAttributeNames", {})
                    values = {
                        key: _decode_ddb_value(value)
                        for key, value in delete.get("ExpressionAttributeValues", {}).items()
                    }
                    if not _condition_permitted(
                        delete["ConditionExpression"], existing or {}, names, values
                    ):
                        raise ConditionalFailure()
                    del self.table.items[key]
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
    """Model bounded versioned Object Lock behavior with synthetic bytes only."""

    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], dict[str, Any]] = {}
        self.counter = 0
        self.get_requests: list[dict[str, Any]] = []

    def put_object(self, **value: Any) -> dict[str, str]:
        if value.get("IfNoneMatch") == "*" and any(
            key == value["Key"] for key, _version_id in self.objects
        ):
            error = ConditionalFailure()
            error.response = {"Error": {"Code": "PreconditionFailed"}}
            raise error
        self.counter += 1
        version_id = f"version-{self.counter}"
        body = value.get("Body", b"")
        assert isinstance(body, bytes)
        self.objects[(value["Key"], version_id)] = {
            "Body": body,
            "Metadata": dict(value.get("Metadata", {})),
            "Retention": {
                "Mode": value.get("ObjectLockMode", "COMPLIANCE"),
                "RetainUntilDate": value.get(
                    "ObjectLockRetainUntilDate", datetime.now(UTC) + timedelta(days=365)
                ),
            },
            "LegalHold": {"Status": "OFF"},
            "LastModified": datetime.now(UTC),
        }
        return {"VersionId": version_id}

    def list_object_versions(self, **value: Any) -> dict[str, Any]:
        prefix = value.get("Prefix", "")
        maximum = int(value.get("MaxKeys", 1_000))
        records = [
            {
                "Key": key,
                "VersionId": version_id,
                "Size": len(record["Body"]),
                "LastModified": record["LastModified"],
            }
            for (key, version_id), record in sorted(self.objects.items())
            if key.startswith(prefix)
        ]
        key_marker = value.get("KeyMarker")
        version_marker = value.get("VersionIdMarker")
        if key_marker is not None:
            records = [
                record
                for record in records
                if (record["Key"], record["VersionId"]) > (key_marker, version_marker or "")
            ]
        page = records[:maximum]
        return {
            "Versions": page,
            "DeleteMarkers": [],
            "IsTruncated": len(records) > maximum,
            "NextKeyMarker": page[-1]["Key"] if len(records) > maximum and page else None,
            "NextVersionIdMarker": (
                page[-1]["VersionId"] if len(records) > maximum and page else None
            ),
        }

    def head_object(self, **value: Any) -> dict[str, Any]:
        version_id = value.get("VersionId")
        if version_id is None:
            versions = [
                candidate_version for key, candidate_version in self.objects if key == value["Key"]
            ]
            version_id = max(versions, key=lambda item: int(item.removeprefix("version-")))
        record = self.objects[(value["Key"], version_id)]
        return {
            "Metadata": dict(record["Metadata"]),
            "ContentLength": len(record["Body"]),
            "VersionId": version_id,
        }

    def get_object(self, **value: Any) -> dict[str, bytes]:
        self.get_requests.append(dict(value))
        version_id = value.get("VersionId")
        if version_id is None:
            candidates = [
                (candidate_version, record)
                for (key, candidate_version), record in self.objects.items()
                if key == value["Key"]
            ]
            if not candidates:
                raise KeyError(value["Key"])
            _selected_version, selected = max(
                candidates, key=lambda item: int(item[0].removeprefix("version-"))
            )
            return {"Body": selected["Body"]}
        return {"Body": self.objects[(value["Key"], version_id)]["Body"]}

    def get_object_retention(self, **value: Any) -> dict[str, Any]:
        retention = self.objects[(value["Key"], value["VersionId"])].get("Retention")
        if retention is None:
            raise ObjectLockConfigurationMissing()
        return {"Retention": dict(retention)}

    def put_object_retention(self, **value: Any) -> None:
        record = self.objects[(value["Key"], value["VersionId"])]
        current = record["Retention"]["RetainUntilDate"]
        requested = value["Retention"]["RetainUntilDate"]
        if requested < current:
            raise ConditionalFailure()
        record["Retention"] = dict(value["Retention"])

    def get_object_legal_hold(self, **value: Any) -> dict[str, Any]:
        hold = self.objects[(value["Key"], value["VersionId"])].get("LegalHold")
        if hold is None:
            raise ObjectLockConfigurationMissing()
        return {"LegalHold": dict(hold)}

    def put_object_legal_hold(self, **value: Any) -> None:
        self.objects[(value["Key"], value["VersionId"])]["LegalHold"] = dict(value["LegalHold"])


class FakeSns:
    """Capture normalized alert notifications without external delivery."""

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []
        self.failures_remaining = 0

    def publish(self, **value: Any) -> dict[str, str]:
        if self.failures_remaining:
            self.failures_remaining -= 1
            raise RuntimeError("synthetic SNS outage")
        self.messages.append(dict(value))
        return {"MessageId": "synthetic-message"}


class FakeSqs:
    """Capture revision-bound FIFO evidence work without external delivery."""

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    def send_message(self, **value: Any) -> dict[str, str]:
        self.messages.append(dict(value))
        return {"MessageId": f"message-{len(self.messages)}"}

    def send_message_batch(self, **value: Any) -> dict[str, list[Any]]:
        for entry in value.get("Entries", []):
            self.messages.append(
                {"QueueUrl": value["QueueUrl"], "MessageBody": entry["MessageBody"]}
            )
        return {"Successful": list(value.get("Entries", [])), "Failed": []}


class FakeSecretsManager:
    """Retain exact synthetic secret versions without exposing them through views."""

    def __init__(self) -> None:
        self.secrets: dict[str, dict[str, Any]] = {}

    def create_secret(self, **value: Any) -> dict[str, str]:
        name = value["Name"]
        if name in self.secrets:
            raise ConditionalFailure()
        arn = f"arn:aws:secretsmanager:eu-west-2:111111111111:secret:{name}-synthetic"
        self.secrets[name] = {
            "arn": arn,
            "versions": {"version-1": value["SecretString"]},
            "deleted": False,
        }
        self.secrets[arn] = self.secrets[name]
        return {"ARN": arn, "Name": name, "VersionId": "version-1"}

    def put_secret_value(self, **value: Any) -> dict[str, str]:
        record = self.secrets[value["SecretId"]]
        version = f"version-{len(record['versions']) + 1}"
        record["versions"][version] = value["SecretString"]
        return {"ARN": record["arn"], "VersionId": version}

    def get_secret_value(self, **value: Any) -> dict[str, str]:
        record = self.secrets[value["SecretId"]]
        return {"SecretString": record["versions"][value["VersionId"]]}

    def delete_secret(self, **value: Any) -> dict[str, str]:
        self.secrets[value["SecretId"]]["deleted"] = True
        return {"ARN": self.secrets[value["SecretId"]]["arn"]}

    def describe_secret(self, **value: Any) -> dict[str, Any]:
        record = self.secrets[value["SecretId"]]
        if record.get("unavailable"):
            raise LookupError("synthetic secret unavailable")
        return dict(record["description"])


class FakeKms:
    """Capture exact digest signing calls without exposing private key material."""

    def __init__(self, key_id: str) -> None:
        self.key_id = key_id
        self.calls: list[dict[str, Any]] = []

    def sign(self, **value: Any) -> dict[str, Any]:
        self.calls.append(dict(value))
        return {
            "KeyId": value["KeyId"],
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

    def verify(self, **value: Any) -> dict[str, Any]:
        """Accept only the exact synthetic signature emitted by this KMS double."""
        self.calls.append(dict(value))
        return {
            "KeyId": value["KeyId"],
            "SigningAlgorithm": "ECDSA_SHA_256",
            "SignatureValid": value.get("Signature") == b"synthetic-ecdsa-signature",
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
    fake_sqs = FakeSqs()
    fake_s3 = FakeS3()
    fake_secrets = FakeSecretsManager()
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
            else fake_sqs
            if service == "sqs"
            else fake_secrets
            if service == "secretsmanager"
            else fake_s3
        )
    )
    dynamodb = types.ModuleType("boto3.dynamodb")
    conditions = types.ModuleType("boto3.dynamodb.conditions")
    conditions.Key = lambda name: types.SimpleNamespace(  # type: ignore[attr-defined]
        eq=lambda value: FakeCondition([(name, "eq", value)]),
        begins_with=lambda value: FakeCondition([(name, "begins_with", value)]),
        lte=lambda value: FakeCondition([(name, "lte", value)]),
    )
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "boto3.dynamodb", dynamodb)
    monkeypatch.setitem(sys.modules, "boto3.dynamodb.conditions", conditions)
    monkeypatch.setenv("CONTROL_TABLE", "control")
    monkeypatch.setenv("PRESENCE_TABLE", "presence")
    monkeypatch.setenv("IDEMPOTENCY_TABLE", "idempotency")
    monkeypatch.setenv("AUDIT_BUCKET", "audit")
    monkeypatch.setenv("EVIDENCE_REPORT_BUCKET", "evidence-reports")
    monkeypatch.setenv("INTEGRITY_BASELINE_BUCKET", "integrity-baselines")
    monkeypatch.setenv("DISCOVERY_PAGE_BUCKET", "discovery-pages")
    monkeypatch.setenv("EVIDENCE_QUEUE_URL", "https://sqs.example.invalid/evidence.fifo")
    monkeypatch.setenv(
        "ASSURANCE_REPORT_QUEUE_URL", "https://sqs.example.invalid/assurance-reports"
    )
    monkeypatch.setenv(
        "EVIDENCE_RETENTION_QUEUE_URL",
        "https://sqs.example.invalid/evidence-retention.fifo",
    )
    monkeypatch.setenv("ENTRA_PROVIDER_ENABLED", "false")
    monkeypatch.setenv("ENTRA_TENANT_ID", "")
    monkeypatch.setenv("ENTRA_AAI_TENANT_ID", "")
    monkeypatch.setenv("ENTRA_STRONG_AUTH_ENFORCED", "false")
    monkeypatch.setenv("SCIM_ENABLED", "false")
    monkeypatch.setenv("SCIM_TABLE", "")
    monkeypatch.setenv("SPLUNK_STUB_ENABLED", "true")
    monkeypatch.setenv("POLICY_SIGNING_KEY_ARN", policy_key_id)
    assurance_key_id = "arn:aws:kms:eu-west-1:111111111111:key/mrk-abcdefabcdefabcdefabcdefabcdefab"
    monkeypatch.setenv("ASSURANCE_REPORT_SIGNING_KEY_ARN", assurance_key_id)
    monkeypatch.setenv("ASSURANCE_REPORT_VERIFICATION_KEY_ARNS", json.dumps([assurance_key_id]))
    monkeypatch.setenv(
        "REGIONAL_POLICY_SIGNING_KEY_ARN",
        "arn:aws:kms:eu-west-2:111111111111:key/mrk-1234567890abcdef1234567890abcdef",
    )
    monkeypatch.setenv("RECOVERY_REGION", "eu-west-1")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    monkeypatch.setenv("SECURITY_ALERTS_TOPIC_ARN", "arn:aws:sns:eu-west-2:111111111111:test")
    monkeypatch.setenv("WEBHOOK_QUEUE_URL", "https://sqs.example.invalid/webhooks.fifo")
    monkeypatch.setenv("WEBHOOK_SECRET_PREFIX", "aai-sec/webhooks/")
    monkeypatch.setenv("WEBHOOK_SECRET_KMS_KEY_ARN", policy_key_id)
    monkeypatch.setenv("WORKFLOW_QUEUE_URL", "https://sqs.example.invalid/workflows.fifo")
    monkeypatch.setenv("WORKFLOW_SECRET_PREFIX", "aai-sec/workflows/")
    monkeypatch.setenv("AWS_ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("AWS_PARTITION", "aws")
    monkeypatch.setenv("ENDPOINT_DELIVERY_SECRET_PREFIX", "aai-sec/endpoint-delivery/")
    monkeypatch.setenv(
        "ENDPOINT_DELIVERY_SECRET_KMS_KEY_ARN",
        "arn:aws:kms:eu-west-1:111111111111:key/22222222-2222-4222-8222-222222222222",
    )
    path = Path(__file__).parents[1] / "infra/aws-control-plane/lambda/handler.py"
    monkeypatch.syspath_prepend(str(path.parent))
    spec = importlib.util.spec_from_file_location("aai_lambda_handler", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    cast(Any, module)._fake_kms = fake_kms
    cast(Any, module)._fake_s3 = fake_s3
    cast(Any, module)._fake_sns = fake_sns
    cast(Any, module)._fake_sqs = fake_sqs
    cast(Any, module)._fake_secrets = fake_secrets
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


def test_data_boundary_posture_and_operator_source_ip_fail_closed(monkeypatch: Any) -> None:
    """Only API Gateway's source address can cross a configured human boundary."""
    key_arn = "arn:aws:kms:eu-west-1:111111111111:key/11111111-1111-4111-8111-111111111111"
    monkeypatch.setenv("DATA_BOUNDARY_STATUS", "configured")
    monkeypatch.setenv("DATA_BOUNDARY_HOME_REGION", "eu-west-1")
    monkeypatch.setenv("DATA_BOUNDARY_APPROVED_REGIONS", json.dumps(["eu-west-1", "eu-west-2"]))
    monkeypatch.setenv("DATA_BOUNDARY_KEY_ARN", key_arn)
    monkeypatch.setenv("DATA_BOUNDARY_KEY_OWNERSHIP", "customer-managed")
    monkeypatch.setenv("DATA_BOUNDARY_OPERATOR_ACCESS_MODE", "ip-restricted")
    monkeypatch.setenv("DATA_BOUNDARY_OPERATOR_IPV4_CIDRS", json.dumps(["93.184.216.34/32"]))
    monkeypatch.setenv("DATA_BOUNDARY_CONDITIONAL_ACCESS_EVIDENCE_CONFIGURED", "true")
    monkeypatch.setenv("DATA_BOUNDARY_APPROVAL_EVIDENCE_CONFIGURED", "true")
    module, table = _load_handler(monkeypatch)
    table.put_item(
        Item=module._item_key("tenant-boundary", "TENANT", "root") | {"id": "tenant-boundary"}
    )
    claims = {
        "custom:tenant_id": "tenant-boundary",
        "cognito:groups": ["auditor"],
        "sub": "auditor-a",
    }

    missing = _event("/api/enterprise/data-boundary", "GET", claims=claims)
    missing["headers"]["x-forwarded-for"] = "93.184.216.34"
    denied = _invoke(module, missing)
    assert denied["statusCode"] == 403
    assert json.loads(denied["body"])["requiredBoundary"] == "ip-restricted"

    outside = _event("/api/enterprise/data-boundary", "GET", claims=claims)
    outside["requestContext"]["http"]["sourceIp"] = "8.8.8.8"
    assert _invoke(module, outside)["statusCode"] == 403

    allowed = _event("/api/enterprise/data-boundary", "GET", claims=claims)
    allowed["requestContext"]["http"]["sourceIp"] = "93.184.216.34"
    response = _invoke(module, allowed)
    assert response["statusCode"] == 200, response
    posture = json.loads(response["body"])
    assert posture["status"] == "configured"
    assert posture["encryption"] == {
        "ownership": "customer-managed",
        "keyFingerprint": "11111111",
        "scope": "retained-tenant-data-and-durable-queues",
        "rotationRequired": True,
    }
    assert posture["operatorAccess"]["allowedNetworkCount"] == 1
    assert "93.184.216.34" not in response["body"]
    assert key_arn not in response["body"]
    assert posture["operatorAccess"]["privateLinkConfigured"] is False


def test_data_boundary_runtime_rejects_incomplete_configured_authority(
    monkeypatch: Any,
) -> None:
    """A configured label cannot survive without its network and evidence boundary."""
    monkeypatch.setenv("DATA_BOUNDARY_STATUS", "configured")
    monkeypatch.setenv("DATA_BOUNDARY_HOME_REGION", "eu-west-1")
    monkeypatch.setenv("DATA_BOUNDARY_APPROVED_REGIONS", json.dumps(["eu-west-1"]))
    monkeypatch.setenv("DATA_BOUNDARY_KEY_OWNERSHIP", "customer-managed")
    monkeypatch.setenv("DATA_BOUNDARY_OPERATOR_ACCESS_MODE", "ip-restricted")
    monkeypatch.setenv("DATA_BOUNDARY_OPERATOR_IPV4_CIDRS", "[]")
    with pytest.raises(RuntimeError, match="incomplete"):
        _load_handler(monkeypatch)


def test_private_operator_boundary_requires_gateway_api_and_endpoint_context(
    monkeypatch: Any,
) -> None:
    """Public ingress and spoofed headers cannot impersonate PrivateLink context."""
    monkeypatch.setenv("DATA_BOUNDARY_STATUS", "configured")
    monkeypatch.setenv("DATA_BOUNDARY_HOME_REGION", "eu-west-1")
    monkeypatch.setenv("DATA_BOUNDARY_APPROVED_REGIONS", json.dumps(["eu-west-1"]))
    monkeypatch.setenv(
        "DATA_BOUNDARY_KEY_ARN",
        "arn:aws:kms:eu-west-1:111111111111:key/11111111-1111-4111-8111-111111111111",
    )
    monkeypatch.setenv("DATA_BOUNDARY_KEY_OWNERSHIP", "customer-managed")
    monkeypatch.setenv("DATA_BOUNDARY_OPERATOR_ACCESS_MODE", "private-link")
    monkeypatch.setenv("DATA_BOUNDARY_OPERATOR_IPV4_CIDRS", "[]")
    monkeypatch.setenv("DATA_BOUNDARY_OPERATOR_VPC_ENDPOINT_IDS", '["vpce-0123456789abcdef0"]')
    monkeypatch.setenv("DATA_BOUNDARY_PRIVATE_API_ID", "a1b2c3d4e5")
    monkeypatch.setenv("DATA_BOUNDARY_CONDITIONAL_ACCESS_EVIDENCE_CONFIGURED", "true")
    monkeypatch.setenv("DATA_BOUNDARY_APPROVAL_EVIDENCE_CONFIGURED", "true")
    module, table = _load_handler(monkeypatch)
    table.put_item(
        Item=module._item_key("tenant-private", "TENANT", "root") | {"id": "tenant-private"}
    )
    claims = {
        "custom:tenant_id": "tenant-private",
        "cognito:groups": ["auditor"],
        "sub": "auditor-a",
    }

    public = _event("/api/enterprise/data-boundary", "GET", claims=claims)
    public["headers"]["x-amzn-vpce-id"] = "vpce-0123456789abcdef0"
    denied = _invoke(module, public)
    assert denied["statusCode"] == 403
    assert json.loads(denied["body"])["requiredBoundary"] == "private-link"

    private_event: dict[str, Any] = {
        "path": "/api/enterprise/data-boundary",
        "httpMethod": "GET",
        "headers": {},
        "requestContext": {
            "apiId": "a1b2c3d4e5",
            "identity": {"vpceId": "vpce-0123456789abcdef0"},
            "authorizer": {"claims": claims},
        },
    }
    response = _invoke(module, private_event)
    assert response["statusCode"] == 200, response
    posture = json.loads(response["body"])
    assert posture["operatorAccess"]["privateLinkConfigured"] is True
    assert posture["operatorAccess"]["allowedVpcEndpointCount"] == 1
    assert "vpce-" not in response["body"]

    private_event["requestContext"]["apiId"] = "z9y8x7w6v5"
    assert _invoke(module, private_event)["statusCode"] == 403


def test_private_operator_infrastructure_binds_source_endpoint_and_cognito() -> None:
    """IaC preserves both the network and identity checks on private operator ingress."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    assert 'types: ["PRIVATE"]' in stack
    assert 'StringEquals: { "aws:SourceVpce": dataBoundaryOperatorVpcEndpointIds }' in stack
    assert 'authorizationType: "COGNITO_USER_POOLS"' in stack
    assert 'handler.addEnvironment("DATA_BOUNDARY_PRIVATE_API_ID", privateApi.ref)' in stack
    assert 'new cdk.CfnOutput(this, "PrivateOperatorApiUrl"' in stack


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


def _runtime_manifest(
    host: str = "claude-code",
    sdk_version: str = "1.1.0",
    sdk_revision: str = "a" * 40,
) -> dict[str, Any]:
    """Return one synthetic deployment-owned approved runtime manifest."""
    return {
        "schemaVersion": 1,
        "sdkVersion": sdk_version,
        "sdkRevision": sdk_revision,
        "sourceOriginDigest": "b" * 64,
        "packageDigest": "c" * 64,
        "gatewayDigest": "d" * 64,
        "hookDigest": "e" * 64,
        "host": host,
    }


def test_secure_webhook_lifecycle_is_tenant_scoped_rotatable_and_secret_free(
    monkeypatch: Any,
) -> None:
    """Platform admins get one-time secrets while all later views remain redacted."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-webhook"
    now = 1_800_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-webhook-admin",
    }
    created = _invoke(
        module,
        _event(
            "/api/enterprise/webhooks",
            "POST",
            claims=platform,
            body={
                "name": "SOC automation",
                "description": "Signed alerts for the enterprise response gateway",
                "endpoint": "https://hooks.example.test/aai/events",
                "eventTypes": [
                    "behavior.alert.opened",
                    "endpoint.alert.opened",
                    "webhook.test",
                ],
            },
        ),
    )
    assert created["statusCode"] == 201
    issued = json.loads(created["body"])
    destination = issued["destination"]
    secret = issued["signingSecret"]
    assert len(secret["secret"]) >= 32
    assert destination["activeKeyId"] == secret["keyId"]
    assert destination["revision"] == 1
    encoded_record = json.dumps(table.items[(f"TENANT#{tenant}", f"WEBHOOK#{destination['id']}")])
    assert secret["secret"] not in encoded_record

    module._queue_endpoint_alert_webhooks(
        tenant,
        {
            "id": "behavior-alert-a",
            "source": "behavior_analytics",
            "severity": "high",
            "type": "agent_new_mcp_server",
            "deviceId": "",
            "deploymentId": "dep-a",
            "agentId": "agent-a",
            "reasonCode": "new_mcp_server",
            "firstObservedAt": now,
            "lastObservedAt": now,
            "revision": 1,
        },
    )
    behavior_delivery = next(
        item
        for item in module._list(tenant, "WEBHOOK_DELIVERY")
        if item.get("event_type") == "behavior.alert.opened"
    )
    behavior_payload = json.loads(behavior_delivery["payload"])
    assert behavior_payload["data"]["agentId"] == "agent-a"
    assert behavior_payload["data"]["deploymentId"] == "dep-a"
    assert "behavior" not in behavior_payload["data"]

    listed = json.loads(
        _invoke(
            module,
            _event("/api/enterprise/webhooks", "GET", claims=platform),
        )["body"]
    )
    assert listed["items"] == [destination]
    assert "signingSecret" not in json.dumps(listed)
    assert "secret_arn" not in json.dumps(listed)

    rotated = _invoke(
        module,
        _event(
            f"/api/enterprise/webhooks/{destination['id']}/rotate",
            "POST",
            claims=platform,
            body={"expectedRevision": 1, "overlapSeconds": 3600},
        ),
    )
    assert rotated["statusCode"] == 201
    rotation = json.loads(rotated["body"])
    assert rotation["destination"]["revision"] == 2
    assert rotation["destination"]["previousKeyId"] == secret["keyId"]
    assert rotation["destination"]["previousKeyValidUntil"] == now + 3600
    assert rotation["signingSecret"]["keyId"] != secret["keyId"]
    assert rotation["signingSecret"]["secret"] != secret["secret"]

    recovery = json.loads(
        _invoke(
            module,
            _event(
                f"/api/enterprise/webhooks/{destination['id']}/rotate",
                "POST",
                claims=platform,
                body={"expectedRevision": 2, "overlapSeconds": 7200},
            ),
        )["body"]
    )
    assert recovery["destination"]["revision"] == 3
    assert recovery["destination"]["previousKeyId"] == secret["keyId"]
    assert recovery["destination"]["previousKeyValidUntil"] == now + 7200
    assert recovery["signingSecret"]["keyId"] != rotation["signingSecret"]["keyId"]

    stale = _invoke(
        module,
        _event(
            f"/api/enterprise/webhooks/{destination['id']}/rotate",
            "POST",
            claims=platform,
            body={"expectedRevision": 1, "overlapSeconds": 3600},
        ),
    )
    assert stale["statusCode"] == 409

    tested = _invoke(
        module,
        _event(
            f"/api/enterprise/webhooks/{destination['id']}/test",
            "POST",
            claims=platform,
            body={"expectedRevision": 3},
        ),
    )
    assert tested["statusCode"] == 202
    delivery = json.loads(tested["body"])
    assert delivery["eventType"] == "webhook.test"
    assert module._fake_sqs.messages[-1]["MessageDeduplicationId"] == delivery["id"]
    stored_delivery = table.items[(f"TENANT#{tenant}", f"WEBHOOK_DELIVERY#{delivery['id']}")]
    assert stored_delivery["status"] == "queued"
    assert "webhook_outbox_pk" not in stored_delivery
    assert "signingSecret" not in json.dumps(stored_delivery)

    table.put_item(
        Item=module._item_key(tenant, "WEBHOOK_HEALTH", destination["id"])
        | {
            "destination_id": destination["id"],
            "last_delivery_at": now + 1,
            "last_delivery_status": "delivered",
        }
    )
    posture = json.loads(
        _invoke(module, _event("/api/enterprise/webhooks", "GET", claims=platform))["body"]
    )["items"][0]
    assert posture["lastDeliveryAt"] == now + 1
    assert posture["lastDeliveryStatus"] == "delivered"

    retired = _invoke(
        module,
        _event(
            f"/api/enterprise/webhooks/{destination['id']}/retire",
            "POST",
            claims=platform,
            body={
                "expectedRevision": 3,
                "reason": "Synthetic receiver has been permanently decommissioned.",
            },
        ),
    )
    assert retired["statusCode"] == 200
    stored_destination = table.items[(f"TENANT#{tenant}", f"WEBHOOK#{destination['id']}")]
    assert stored_destination["secret_deletion_requested_at"] == now
    # Exact retry is recoverable and does not advance authority again.
    assert (
        _invoke(
            module,
            _event(
                f"/api/enterprise/webhooks/{destination['id']}/retire",
                "POST",
                claims=platform,
                body={
                    "expectedRevision": 3,
                    "reason": "Synthetic receiver has been permanently decommissioned.",
                },
            ),
        )["statusCode"]
        == 200
    )


def test_secure_webhooks_reject_unsafe_egress_roles_and_cross_tenant_reads(
    monkeypatch: Any,
) -> None:
    """Untrusted destinations and non-platform mutations fail before secret creation."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-webhook-deny"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    author = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["policy-author"],
        "sub": "policy-author-a",
    }
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-admin-a",
    }
    request: dict[str, Any] = {
        "name": "Unsafe",
        "description": "Synthetic rejected destination",
        "endpoint": "https://127.0.0.1/hook",
        "eventTypes": ["webhook.test"],
    }
    denied = _invoke(
        module,
        _event("/api/enterprise/webhooks", "POST", claims=author, body=request),
    )
    assert denied["statusCode"] == 403
    assert json.loads(denied["body"])["requiredCapability"] == "integration_admin"
    unsafe = _invoke(
        module,
        _event("/api/enterprise/webhooks", "POST", claims=platform, body=request),
    )
    assert unsafe["statusCode"] == 400
    assert module._fake_secrets.secrets == {}

    request["endpoint"] = "https://hooks.example.test/path?token=secret"
    assert (
        _invoke(
            module,
            _event("/api/enterprise/webhooks", "POST", claims=platform, body=request),
        )["statusCode"]
        == 400
    )
    request["endpoint"] = "https://hooks.example.test/path"
    created = json.loads(
        _invoke(
            module,
            _event("/api/enterprise/webhooks", "POST", claims=platform, body=request),
        )["body"]
    )
    table.put_item(
        Item=module._item_key("tenant-other-webhook", "TENANT", "root")
        | {"id": "tenant-other-webhook"}
    )
    other = {
        "custom:tenant_id": "tenant-other-webhook",
        "cognito:groups": ["platform-admin"],
        "sub": "other-platform-admin",
    }
    assert (
        _invoke(
            module,
            _event(
                f"/api/enterprise/webhooks/{created['destination']['id']}",
                "GET",
                claims=other,
            ),
        )["statusCode"]
        == 404
    )


def test_workflow_integration_lifecycle_is_verified_revision_bound_and_secret_free(
    monkeypatch: Any,
) -> None:
    """Only a verified exact revision can become active provider authority."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-workflow"
    now = 1_800_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "workflow-admin",
    }
    credential_reference = (
        "arn:aws:secretsmanager:eu-west-2:111111111111:"
        "secret:aai-sec/workflows/tenant-workflow/jira-primary-AbCdEf"
    )
    # The API must never read credential bytes while registering authority.
    monkeypatch.setattr(
        module._fake_secrets,
        "get_secret_value",
        lambda **_value: (_ for _ in ()).throw(
            AssertionError("API must not read workflow credentials")
        ),
    )
    created_response = _invoke(
        module,
        _event(
            "/api/enterprise/workflow-integrations",
            "POST",
            claims=platform,
            body={
                "name": "Primary Jira",
                "description": "Content-minimised enterprise incident workflow",
                "provider": "jira",
                "configuration": {
                    "baseUrl": "https://synthetic.atlassian.net",
                    "projectKey": "SEC",
                    "issueType": "Incident",
                },
                "credentialSecretArn": credential_reference,
                "eventTypes": ["case.opened", "case.contained", "case.resolved"],
            },
        ),
    )
    assert created_response["statusCode"] == 201
    connection = json.loads(created_response["body"])
    assert connection["status"] == "pending_verification"
    assert connection["credentialConfigured"] is True
    assert credential_reference not in json.dumps(connection)

    premature = _invoke(
        module,
        _event(
            f"/api/enterprise/workflow-integrations/{connection['id']}/activate",
            "POST",
            claims=platform,
            body={
                "expectedRevision": 1,
                "reason": "Enable the reviewed incident workflow for production use.",
            },
        ),
    )
    assert premature["statusCode"] == 409

    verification = _invoke(
        module,
        _event(
            f"/api/enterprise/workflow-integrations/{connection['id']}/verify",
            "POST",
            claims=platform,
            body={"expectedRevision": 1},
        ),
    )
    assert verification["statusCode"] == 202
    delivery = json.loads(verification["body"])
    assert delivery["verification"] is True
    assert module._fake_sqs.messages[-1]["QueueUrl"].endswith("workflows.fifo")
    assert set(json.loads(module._fake_sqs.messages[-1]["MessageBody"])) == {
        "tenantId",
        "deliveryId",
    }
    table.put_item(
        Item=module._item_key(tenant, "WORKFLOW_HEALTH", connection["id"])
        | {
            "tenant_id": tenant,
            "connection_id": connection["id"],
            "last_verification_at": now + 1,
            "last_verification_status": "delivered",
            "verified_revision": 1,
        }
    )
    activated = _invoke(
        module,
        _event(
            f"/api/enterprise/workflow-integrations/{connection['id']}/activate",
            "POST",
            claims=platform,
            body={
                "expectedRevision": 1,
                "reason": "Enable the reviewed incident workflow for production use.",
            },
        ),
    )
    assert activated["statusCode"] == 200
    active = json.loads(activated["body"])
    assert active["status"] == "active"
    assert active["revision"] == 2

    case = {
        "id": "case-a",
        "revision": 3,
        "status": "contained",
        "severity": "critical",
        "title": "Synthetic case",
        "alertSource": "behavior_analytics",
        "reasonCode": "new_mcp_server",
        "binding": {"host": "claude-code", "agentId": "agent-a"},
        "rawSensitiveContent": "must never leave the case boundary",
    }
    first = module._workflow_delivery_records(tenant, case, "case.contained", now=now + 2)
    second = module._workflow_delivery_records(tenant, case, "case.contained", now=now + 2)
    assert len(first) == 1
    assert first[0]["id"] == second[0]["id"]
    assert first[0]["connection_revision"] == 2
    assert "rawSensitiveContent" not in json.dumps(first[0]["payload"])
    assert first[0]["payload"]["case"]["reasonCode"] == "new_mcp_server"

    failed = {
        **first[0],
        "status": "failed",
        "attempt_count": 5,
        "failure_code": "provider_http_error",
    }
    table.put_item(Item=failed)
    retried_response = _invoke(
        module,
        _event(
            (
                f"/api/enterprise/workflow-integrations/{connection['id']}"
                f"/deliveries/{failed['id']}/retry"
            ),
            "POST",
            claims=platform,
            body={
                "expectedAttemptCount": 5,
                "reason": "The synthetic provider outage has been reviewed and resolved.",
            },
        ),
    )
    assert retried_response["statusCode"] == 202
    retried = json.loads(retried_response["body"])
    assert retried["id"] != failed["id"]
    stored_retry = table.items[(f"TENANT#{tenant}", f"WORKFLOW_DELIVERY#{retried['id']}")]
    assert stored_retry["status"] == "queued"
    assert stored_retry["retry_of"] == failed["id"]
    assert "workflow_outbox_pk" not in stored_retry
    assert json.loads(module._fake_sqs.messages[-1]["MessageBody"])["deliveryId"] == retried["id"]

    listed = _invoke(
        module,
        _event("/api/enterprise/workflow-integrations", "GET", claims=platform),
    )
    assert listed["statusCode"] == 200
    listed_body = json.loads(listed["body"])
    assert listed_body["items"][0]["lastVerificationStatus"] == "delivered"
    assert credential_reference not in json.dumps(listed_body)


def test_workflow_integrations_reject_roles_cross_tenant_secrets_and_unsafe_origins(
    monkeypatch: Any,
) -> None:
    """Registration is integration-admin-only and tenant/provider constrained."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-workflow-deny"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    author = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["policy-author"],
        "sub": "policy-author-a",
    }
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-admin-a",
    }
    request: dict[str, Any] = {
        "name": "Unsafe Jira",
        "description": "Synthetic rejected connection",
        "provider": "jira",
        "configuration": {
            "baseUrl": "https://evil.example.test",
            "projectKey": "SEC",
            "issueType": "Incident",
        },
        "credentialSecretArn": (
            "arn:aws:secretsmanager:eu-west-2:111111111111:"
            "secret:aai-sec/workflows/other-tenant/jira-AbCdEf"
        ),
        "eventTypes": ["case.opened"],
    }
    denied = _invoke(
        module,
        _event("/api/enterprise/workflow-integrations", "POST", claims=author, body=request),
    )
    assert denied["statusCode"] == 403
    assert json.loads(denied["body"])["requiredCapability"] == "integration_admin"
    assert (
        _invoke(
            module,
            _event(
                "/api/enterprise/workflow-integrations",
                "POST",
                claims=platform,
                body=request,
            ),
        )["statusCode"]
        == 400
    )
    request["configuration"]["baseUrl"] = "https://safe.atlassian.net"
    assert (
        _invoke(
            module,
            _event(
                "/api/enterprise/workflow-integrations",
                "POST",
                claims=platform,
                body=request,
            ),
        )["statusCode"]
        == 400
    )


def test_enterprise_assurance_reports_are_honest_hashed_and_read_only(
    monkeypatch: Any,
) -> None:
    """Purpose-specific reports must preserve gaps and never mutate evidence."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-assurance-report"
    now = 1_800_000_000
    table.put_item(
        Item={
            **module._item_key(tenant, "POLICY", "policy-a"),
            "tenant_id": tenant,
            "id": "policy-a",
            "version": 1,
        }
    )
    table.put_item(
        Item={
            **module._item_key(tenant, "GROUP", "group-a"),
            "tenant_id": tenant,
            "id": "group-a",
            "policyId": "policy-a",
            "agent_keys": [],
        }
    )
    table.put_item(
        Item={
            **module._item_key("tenant-other", "POLICY", "policy-private"),
            "tenant_id": "tenant-other",
            "id": "policy-private",
            "version": 99,
        }
    )
    before = copy.deepcopy(table.items)

    executive = module._assurance_report(tenant, "executive", now=now)
    auditor = module._assurance_report(tenant, "auditor", now=now)

    assert executive["profile"] == "executive"
    assert executive["posture"] == "evidence_incomplete"
    assert executive["sections"]["population"]["coverageAvailable"] is False
    assert "details" not in executive
    assert all("evidenceRoute" not in item for item in executive["trace"])
    assert auditor["details"]["policies"] == [{"policyId": "policy-a", "activeVersion": 1}]
    assert auditor["details"]["groups"] == [
        {
            "groupId": "group-a",
            "policyId": "policy-a",
            "membershipMode": "manual",
            "memberCount": 0,
        }
    ]
    assert all("evidenceRoute" in item for item in auditor["trace"])
    unsigned = {key: value for key, value in auditor.items() if key != "contentHash"}
    assert auditor["contentHash"] == module._canonical_sha256(unsigned)
    encoded = json.dumps(auditor, sort_keys=True)
    assert "project_root" not in encoded
    assert "business_contact" not in encoded
    assert "decision_reason" not in encoded
    assert "policy-private" not in encoded
    assert table.items == before
    table.items[(f"TENANT#{tenant}", "GROUP#group-a")]["agent_keys"] = ["deployment-a:agent-a"]
    changed = module._assurance_report(tenant, "auditor", now=now)
    assert changed["contentHash"] != auditor["contentHash"]


def test_enterprise_assurance_report_routes_enforce_profile_roles(monkeypatch: Any) -> None:
    """Only evidence readers receive identifier-bearing auditor trace data."""
    module, _ = _load_handler(monkeypatch)
    tenant = "tenant-assurance-route"
    author = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["policy-author"],
        "sub": "author-a",
    }
    auditor = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["auditor"],
        "sub": "auditor-a",
    }
    anonymous = {"custom:tenant_id": tenant, "sub": "anonymous-a"}
    table = module.TABLE
    table.put_item(
        Item={
            **module._item_key(tenant, "TENANT", "root"),
            "tenant_id": tenant,
            "id": tenant,
            "status": "active",
        }
    )

    assert (
        _invoke(
            module,
            _event("/api/enterprise/reports/executive", "GET", claims=author),
        )["statusCode"]
        == 200
    )
    denied = _invoke(
        module,
        _event("/api/enterprise/reports/auditor", "GET", claims=author),
    )
    assert denied["statusCode"] == 403
    assert "evidence-read" in json.loads(denied["body"])["error"]
    assert (
        _invoke(
            module,
            _event("/api/enterprise/reports/auditor", "GET", claims=auditor),
        )["statusCode"]
        == 200
    )
    assert (
        _invoke(
            module,
            _event("/api/enterprise/reports/executive", "GET", claims=anonymous),
        )["statusCode"]
        == 403
    )


def test_signed_assurance_snapshot_is_exact_version_bound_and_verifiable(
    monkeypatch: Any,
) -> None:
    """A retained snapshot must bind canonical report bytes to KMS and S3 versions."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-signed-assurance"
    table.put_item(
        Item={
            **module._item_key(tenant, "TENANT", "root"),
            "tenant_id": tenant,
            "id": tenant,
            "status": "active",
        }
    )
    snapshot = module._create_assurance_snapshot(
        tenant,
        "auditor",
        "auditor-a",
        source="operator",
        snapshot_id="operator-request-a",
        now=1_800_000_000,
        request_digest="a" * 64,
    )
    assert snapshot["profile"] == "auditor"
    assert snapshot["source"] == "operator"
    assert snapshot["objectVersionId"].startswith("version-")
    record = table.get_item(
        Key=module._assurance_item_key(tenant, "REPORT_SNAPSHOT", snapshot["id"]),
        ConsistentRead=True,
    )["Item"]
    assert "report" not in record
    assert "signature" in record
    document = module._assurance_snapshot_document(tenant, record)
    assert document["tenantId"] == tenant
    assert document["integrity"]["reportSha256"] == snapshot["contentSha256"]
    assert document["integrity"]["domain"] == "aai-sec-assurance-snapshot-v1"
    verified = module._verify_assurance_snapshot(tenant, snapshot["id"])
    assert verified["verified"] is True
    assert module._fake_kms.calls[-1]["MessageType"] == "DIGEST"
    assert module._fake_kms.calls[-1]["SigningAlgorithm"] == "ECDSA_SHA_256"

    # Simulate a crash after S3 accepted the object but before DynamoDB stored
    # its exact version. A retry adopts only the already signed valid object.
    del table.items[(f"ASSURANCE#{tenant}", f"REPORT_SNAPSHOT#{snapshot['id']}")]
    recovered = module._create_assurance_snapshot(
        tenant,
        "auditor",
        "auditor-a",
        source="operator",
        snapshot_id=snapshot["id"],
        now=1_800_000_100,
        request_digest="a" * 64,
    )
    assert recovered["contentSha256"] == snapshot["contentSha256"]
    record = table.get_item(
        Key=module._assurance_item_key(tenant, "REPORT_SNAPSHOT", snapshot["id"]),
        ConsistentRead=True,
    )["Item"]
    assert record["generated_at"] == 1_800_000_000

    # A later version at the same key can never replace the exact committed
    # version selected by DynamoDB metadata.
    module.S3.put_object(
        Bucket="evidence-reports",
        Key=record["object_key"],
        Body=b'{"tampered":true}',
    )
    assert module._assurance_snapshot_document(tenant, record) == document
    assert module._fake_s3.get_requests[-1]["VersionId"] == record["object_version_id"]
    with pytest.raises(LookupError):
        module._assurance_snapshot_record("tenant-other", snapshot["id"])


def test_assurance_report_schedule_is_revisioned_and_runs_idempotently(
    monkeypatch: Any,
) -> None:
    """Due tenant schedules create one deterministic snapshot and advance once."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-report-schedule"
    partition, sort_key = module._evidence_assurance_registration(tenant)
    table.put_item(
        Item={
            **module._item_key(tenant, "TENANT", "root"),
            "tenant_id": tenant,
            "id": tenant,
            "status": "active",
            "evidence_assurance_pk": partition,
            "evidence_assurance_sk": sort_key,
        }
    )
    now = 1_800_000_000
    schedule = module._set_assurance_report_schedule(
        tenant,
        {
            "expectedRevision": 0,
            "enabled": True,
            "profile": "executive",
            "cadence": "daily",
            "hourUtc": 8,
            "dayOfWeek": None,
            "rationale": "Create a daily executive assurance record.",
        },
        "platform-admin-a",
        now=now,
    )
    assert schedule["revision"] == 1
    with pytest.raises(module.PolicyConflict):
        module._set_assurance_report_schedule(
            tenant,
            {
                "expectedRevision": 0,
                "enabled": False,
                "profile": "executive",
                "cadence": "daily",
                "hourUtc": 8,
                "dayOfWeek": None,
                "rationale": "Attempt an update from stale browser state.",
            },
            "platform-admin-a",
            now=now,
        )
    schedule_record = table.items[(f"ASSURANCE#{tenant}", "REPORT_SCHEDULE#current")]
    schedule_record["next_run_at"] = now - 60
    due = now - 60
    report_partition, report_sort = module._assurance_report_index(tenant, due)
    schedule_record["assurance_report_pk"] = report_partition
    schedule_record["assurance_report_sk"] = report_sort
    monkeypatch.setattr(module.time, "time", lambda: now)
    shard = int(report_partition.rsplit("#", 1)[1])
    result = module._assurance_report_schedule_cycle(shard)
    assert result["queuedJobs"] == 1
    message = json.loads(module._fake_sqs.messages[-1]["MessageBody"])
    assert module._process_assurance_report_job(message)["status"] == "completed"
    stored = table.items[(f"ASSURANCE#{tenant}", "REPORT_SCHEDULE#current")]
    assert stored["last_snapshot_id"] == f"scheduled-{due}-executive"
    assert stored["next_run_at"] > now
    rerun = module._assurance_report_schedule_cycle(shard)
    assert rerun["queuedJobs"] == 0
    snapshots = [
        item for item in table.items.values() if item.get("sk", "").startswith("REPORT_SNAPSHOT#")
    ]
    assert len(snapshots) == 1


def test_assurance_snapshot_routes_separate_administration_and_auditor_read(
    monkeypatch: Any,
) -> None:
    """Schedule/generation require evidence admin while auditors may verify."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-report-route"
    table.put_item(
        Item={
            **module._item_key(tenant, "TENANT", "root"),
            "tenant_id": tenant,
            "id": tenant,
            "status": "active",
        }
    )
    admin = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "admin-a",
    }
    auditor = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["auditor"],
        "sub": "auditor-a",
    }
    created = _invoke(
        module,
        _event(
            "/api/enterprise/reports/snapshots",
            "POST",
            claims=admin,
            body={
                "requestId": "request-a",
                "profile": "auditor",
                "rationale": "Capture approved point-in-time audit posture.",
            },
        ),
    )
    assert created["statusCode"] == 201
    snapshot_id = json.loads(created["body"])["id"]
    denied = _invoke(
        module,
        _event(
            "/api/enterprise/reports/snapshots",
            "POST",
            claims=auditor,
            body={
                "requestId": "request-b",
                "profile": "auditor",
                "rationale": "Auditors cannot create retained report authority.",
            },
        ),
    )
    assert denied["statusCode"] == 403
    verified = _invoke(
        module,
        _event(
            f"/api/enterprise/reports/snapshots/{snapshot_id}/verify",
            "POST",
            claims=auditor,
        ),
    )
    assert verified["statusCode"] == 200
    assert json.loads(verified["body"])["verified"] is True


def test_assurance_snapshot_missing_exact_version_is_explicitly_unavailable(
    monkeypatch: Any,
) -> None:
    """A missing retained version never falls back to latest or becomes an opaque 500."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-report-unavailable"
    table.put_item(
        Item={**module._item_key(tenant, "TENANT", "root"), "tenant_id": tenant, "id": tenant}
    )
    admin = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "admin-a",
    }
    created = _invoke(
        module,
        _event(
            "/api/enterprise/reports/snapshots",
            "POST",
            claims=admin,
            body={
                "requestId": "missing-version",
                "profile": "executive",
                "rationale": "Retain an approved executive assurance record.",
            },
        ),
    )
    snapshot_id = json.loads(created["body"])["id"]
    record = table.items[(f"ASSURANCE#{tenant}", f"REPORT_SNAPSHOT#{snapshot_id}")]
    del module.S3.objects[(record["object_key"], record["object_version_id"])]

    for method, suffix in (("GET", ""), ("POST", "/verify")):
        response = _invoke(
            module,
            _event(
                f"/api/enterprise/reports/snapshots/{snapshot_id}{suffix}",
                method,
                claims=admin,
            ),
        )
        assert response["statusCode"] == 503
        assert json.loads(response["body"]) == {
            "error": "assurance snapshot is temporarily unavailable"
        }


def test_assurance_snapshot_worker_write_authority_is_prefix_bounded() -> None:
    """Primary and recovery workers can retain snapshots but cannot delete evidence."""
    root = Path(__file__).parents[1] / "infra" / "aws-control-plane" / "lib"
    primary = (root / "aws-control-plane-stack.ts").read_text(encoding="utf-8")
    recovery = (root / "passive-regional-cell-stack.ts").read_text(encoding="utf-8")

    assert 'actions: ["s3:PutObject", "s3:PutObjectRetention"]' in primary
    assert 'audit.arnForObjects("tenant=*/assurance-snapshots/*")' in primary
    assert 'audit.arnForObjects("tenant=*/year=*/month=*/idempotent-*")' in primary
    assert "audit.grantPut(assuranceReportWorker)" not in primary
    assert "audit.grantRead(assuranceReportWorker)" not in primary
    assert "table.grantReadData(assuranceReportWorker)" in primary
    assert "table.grantReadWriteData(assuranceReportWorker)" not in primary
    assert '"dynamodb:LeadingKeys": ["ASSURANCE#*"]' in primary
    assert (
        'assuranceReportSigningKey.grant(assuranceReportWorker, "kms:Sign", "kms:Verify")'
        in primary
    )
    assert 'policySigningKey.grant(assuranceReportWorker, "kms:Sign", "kms:Verify")' not in primary
    assert "evidenceReports.grantReadWrite(handler)" not in primary

    assert 'actions: ["s3:PutObject", "s3:PutObjectRetention"]' in recovery
    assert 'auditReplica.arnForObjects("tenant=*/assurance-snapshots/*")' in recovery
    assert 'auditReplica.arnForObjects("tenant=*/year=*/month=*/idempotent-*")' in recovery
    assert "auditReplica.grantPut(assuranceReportWorker)" not in recovery
    assert "auditReplica.grantRead(assuranceReportWorker)" not in recovery
    assert '"dynamodb:LeadingKeys": ["ASSURANCE#*"]' in recovery
    assert (
        'assuranceReportSigningReplica.grant(assuranceReportWorker, "kms:Sign", "kms:Verify")'
        in recovery
    )
    assert (
        'policySigningReplica.grant(assuranceReportWorker, "kms:Sign", "kms:Verify")'
        not in recovery
    )


def test_assurance_snapshot_signature_binds_identity_envelope(monkeypatch: Any) -> None:
    """Changing tenant, snapshot, profile, source or time invalidates KMS verification."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-envelope-binding"
    table.put_item(
        Item={**module._item_key(tenant, "TENANT", "root"), "tenant_id": tenant, "id": tenant}
    )
    snapshot = module._create_assurance_snapshot(
        tenant,
        "executive",
        "platform-admin-a",
        source="operator",
        snapshot_id="operator-envelope-a",
        now=1_800_000_000,
        request_digest="a" * 64,
    )
    record = table.items[(f"ASSURANCE#{tenant}", f"REPORT_SNAPSHOT#{snapshot['id']}")]
    original_envelope = record["envelope_sha256"]
    for field, replacement in (
        ("tenantId", "tenant-other"),
        ("snapshotId", "operator-envelope-b"),
        ("profile", "auditor"),
        ("source", "schedule"),
        ("generatedAt", 1_800_000_001),
        ("scheduleRevision", 9),
    ):
        document = copy.deepcopy(module._assurance_snapshot_document(tenant, record))
        document[field] = replacement
        payload = module._assurance_signature_payload(
            document["tenantId"],
            document["snapshotId"],
            document["profile"],
            document["source"],
            document["generatedAt"],
            document["integrity"]["reportSha256"],
            document["scheduleRevision"],
        )
        assert module._canonical_sha256(payload) != original_envelope

    module.KMS.verify = lambda **value: {
        "KeyId": value["KeyId"],
        "SigningAlgorithm": value["SigningAlgorithm"],
        "SignatureValid": value["Message"] == bytes.fromhex(original_envelope),
    }
    assert module._verify_assurance_snapshot(tenant, snapshot["id"])["verified"] is True
    record["envelope_sha256"] = "b" * 64
    with pytest.raises(RuntimeError, match="content verification"):
        module._verify_assurance_snapshot(tenant, snapshot["id"])


def test_assurance_report_reads_deny_roleless_and_request_reuse_is_bound(
    monkeypatch: Any,
) -> None:
    """Every retained-report read needs authority and request IDs bind all input."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-assurance-access"
    table.put_item(
        Item={**module._item_key(tenant, "TENANT", "root"), "tenant_id": tenant, "id": tenant}
    )
    admin = {"custom:tenant_id": tenant, "cognito:groups": ["platform-admin"], "sub": "admin-a"}
    roleless = {"custom:tenant_id": tenant, "sub": "roleless-a"}
    request = {
        "requestId": "bound-request",
        "profile": "executive",
        "rationale": "Capture an approved executive posture record.",
    }
    created = _invoke(
        module,
        _event("/api/enterprise/reports/snapshots", "POST", claims=admin, body=request),
    )
    snapshot_id = json.loads(created["body"])["id"]
    for path in (
        "/api/enterprise/reports/schedule",
        "/api/enterprise/reports/snapshots",
        f"/api/enterprise/reports/snapshots/{snapshot_id}",
    ):
        assert _invoke(module, _event(path, "GET", claims=roleless))["statusCode"] == 403
    assert (
        _invoke(
            module,
            _event(
                f"/api/enterprise/reports/snapshots/{snapshot_id}/verify",
                "POST",
                claims=roleless,
            ),
        )["statusCode"]
        == 403
    )
    changed = _invoke(
        module,
        _event(
            "/api/enterprise/reports/snapshots",
            "POST",
            claims=admin,
            body={
                **request,
                "rationale": "A different approved rationale must not reuse authority.",
            },
        ),
    )
    assert changed["statusCode"] == 409


def test_assurance_schedule_claim_blocks_concurrent_change_and_recovers(
    monkeypatch: Any,
) -> None:
    """A due occurrence is linearized before queueing and duplicate delivery is safe."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-assurance-race"
    table.put_item(
        Item={**module._item_key(tenant, "TENANT", "root"), "tenant_id": tenant, "id": tenant}
    )
    now = 1_800_000_000
    module._set_assurance_report_schedule(
        tenant,
        {
            "expectedRevision": 0,
            "enabled": True,
            "profile": "executive",
            "cadence": "daily",
            "hourUtc": 8,
            "dayOfWeek": None,
            "rationale": "Run an approved daily assurance capture.",
        },
        "admin-a",
        now=now,
    )
    schedule = table.items[(f"ASSURANCE#{tenant}", "REPORT_SCHEDULE#current")]
    due = now - 1
    schedule["next_run_at"] = due
    schedule["assurance_report_pk"], schedule["assurance_report_sk"] = (
        module._assurance_report_index(tenant, due)
    )
    monkeypatch.setattr(module.time, "time", lambda: now)
    shard = int(schedule["assurance_report_pk"].rsplit("#", 1)[1])
    module._assurance_report_schedule_cycle(shard)
    claimed = table.items[(f"ASSURANCE#{tenant}", "REPORT_SCHEDULE#current")]
    with pytest.raises(module.PolicyConflict, match="generation is already in progress"):
        module._set_assurance_report_schedule(
            tenant,
            {
                "expectedRevision": claimed["revision"],
                "enabled": False,
                "profile": "executive",
                "cadence": "daily",
                "hourUtc": 8,
                "dayOfWeek": None,
                "rationale": "Disable this schedule during a claimed occurrence.",
            },
            "admin-a",
            now=now,
        )
    module._assurance_report_schedule_cycle(shard)
    messages = [json.loads(item["MessageBody"]) for item in module._fake_sqs.messages]
    assert len(messages) == 1
    assert module._process_assurance_report_job(messages[-1])["status"] == "completed"
    assert module._process_assurance_report_job(messages[-1])["status"] == "stale_claim"
    assert (
        len(
            [
                item
                for item in table.items.values()
                if str(item.get("sk", "")).startswith("REPORT_SNAPSHOT#")
            ]
        )
        == 1
    )


def test_assurance_snapshot_stream_read_is_bounded(monkeypatch: Any) -> None:
    """Oversized streams are never fully consumed or parsed."""
    module, _ = _load_handler(monkeypatch)

    class OversizedBody:
        def __init__(self) -> None:
            self.requested: list[int] = []

        def read(self, size: int) -> bytes:
            self.requested.append(size)
            return b"x" * size

    body = OversizedBody()
    with pytest.raises(RuntimeError, match="exceeds"):
        module._evidence_body_bytes({"Body": body}, module._ASSURANCE_REPORT_MAX_BYTES)
    assert body.requested == [module._ASSURANCE_REPORT_MAX_BYTES + 1]


def test_assurance_mutations_never_commit_without_audit_evidence(monkeypatch: Any) -> None:
    """An audit outage leaves retryable objects but no successful control state."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-assurance-audit-gap"
    table.put_item(
        Item={**module._item_key(tenant, "TENANT", "root"), "tenant_id": tenant, "id": tenant}
    )
    original_put = module.S3.put_object
    failures = {"remaining": 1}

    def fail_audit_once(**value: Any) -> dict[str, str]:
        if "idempotent-" in value["Key"] and failures["remaining"]:
            failures["remaining"] -= 1
            raise RuntimeError("synthetic audit outage")
        return cast(dict[str, str], original_put(**value))

    module.S3.put_object = fail_audit_once
    with pytest.raises(RuntimeError, match="audit outage"):
        module._create_assurance_snapshot(
            tenant,
            "executive",
            "admin-a",
            source="operator",
            snapshot_id="operator-audit-gap",
            now=1_800_000_000,
            request_digest="a" * 64,
        )
    assert (f"ASSURANCE#{tenant}", "REPORT_SNAPSHOT#operator-audit-gap") not in table.items
    recovered = module._create_assurance_snapshot(
        tenant,
        "executive",
        "admin-a",
        source="operator",
        snapshot_id="operator-audit-gap",
        now=1_800_000_100,
        request_digest="a" * 64,
    )
    assert recovered["generatedAt"] == 1_800_000_000

    failures["remaining"] = 1
    with pytest.raises(RuntimeError, match="audit outage"):
        module._set_assurance_report_schedule(
            tenant,
            {
                "expectedRevision": 0,
                "enabled": True,
                "profile": "executive",
                "cadence": "daily",
                "hourUtc": 8,
                "dayOfWeek": None,
                "rationale": "Enable approved daily assurance records.",
            },
            "admin-a",
            now=1_800_000_000,
        )
    assert (f"ASSURANCE#{tenant}", "REPORT_SCHEDULE#current") not in table.items


def test_assurance_scheduler_isolates_corrupt_tenant_and_processes_next_page(
    monkeypatch: Any,
) -> None:
    """One malformed record and a 251st due tenant cannot starve valid schedules."""
    module, table = _load_handler(monkeypatch)
    now = 1_800_000_000
    shard = 0
    monkeypatch.setattr(
        module,
        "_assurance_report_index",
        lambda tenant, due_at: (
            f"ASSURANCE_REPORT#{shard:02d}",
            f"{int(due_at):012d}#{tenant}",
        ),
    )
    for index in range(252):
        tenant = f"tenant-page-{index:03d}"
        table.put_item(
            Item={
                **module._assurance_item_key(tenant, "REPORT_SCHEDULE", "current"),
                "tenant_id": tenant,
                "enabled": True,
                "profile": "executive",
                "cadence": "daily",
                "hour_utc": 8 if index != 0 else 99,
                "day_of_week": None,
                "revision": 1,
                "next_run_at": now - 1,
                "assurance_report_pk": f"ASSURANCE_REPORT#{shard:02d}",
                "assurance_report_sk": f"{now - 1:012d}#{tenant}",
            }
        )
    original_query = table.query

    def paged_query(**value: Any) -> dict[str, Any]:
        result = original_query(**value)
        if value.get("IndexName") != module._ASSURANCE_REPORT_INDEX:
            return cast(dict[str, Any], result)
        items = sorted(result["Items"], key=lambda item: item["assurance_report_sk"])
        limit = int(value["Limit"])
        return {
            "Items": items[:limit],
            **(
                {"LastEvaluatedKey": {"pk": items[limit - 1]["pk"], "sk": items[limit - 1]["sk"]}}
                if len(items) > limit
                else {}
            ),
        }

    table.query = paged_query
    monkeypatch.setattr(module.time, "time", lambda: now)
    first = module._assurance_report_schedule_cycle(shard)
    second = module._assurance_report_schedule_cycle(shard)
    assert first == {
        "shard": shard,
        "dueSchedules": 250,
        "queuedJobs": 249,
        "corruptSchedules": 1,
        "quarantineFailures": 0,
        "moreDueSchedules": True,
    }
    assert second["queuedJobs"] == 2
    assert second["moreDueSchedules"] is False
    assert len(module._fake_sqs.messages) == 251
    assert len(module._fake_sns.messages) == 1


def test_assurance_scheduler_quarantines_full_corrupt_page_before_valid_tenant(
    monkeypatch: Any,
) -> None:
    """A fully malformed first page cannot permanently starve the next tenant."""
    module, table = _load_handler(monkeypatch)
    now = 1_800_000_000
    shard = 0
    monkeypatch.setattr(
        module,
        "_assurance_report_index",
        lambda tenant, due_at: (
            f"ASSURANCE_REPORT#{shard:02d}",
            f"{int(due_at):012d}#{tenant}",
        ),
    )
    for index in range(251):
        tenant = f"tenant-corrupt-page-{index:03d}"
        table.put_item(
            Item={
                **module._assurance_item_key(tenant, "REPORT_SCHEDULE", "current"),
                "tenant_id": tenant,
                "enabled": True,
                "profile": "executive",
                "cadence": "daily",
                "hour_utc": 99 if index < 250 else 8,
                "day_of_week": None,
                "revision": 1,
                "next_run_at": now - 1,
                "assurance_report_pk": f"ASSURANCE_REPORT#{shard:02d}",
                "assurance_report_sk": f"{now - 1:012d}#{tenant}",
            }
        )
    original_query = table.query

    def paged_query(**value: Any) -> dict[str, Any]:
        result = cast(dict[str, Any], original_query(**value))
        if value.get("IndexName") != module._ASSURANCE_REPORT_INDEX:
            return result
        items = sorted(result["Items"], key=lambda item: item["assurance_report_sk"])
        limit = int(value["Limit"])
        return {
            "Items": items[:limit],
            **(
                {"LastEvaluatedKey": {"pk": items[limit - 1]["pk"], "sk": items[limit - 1]["sk"]}}
                if len(items) > limit
                else {}
            ),
        }

    table.query = paged_query
    monkeypatch.setattr(module.time, "time", lambda: now)
    first = module._assurance_report_schedule_cycle(shard)
    second = module._assurance_report_schedule_cycle(shard)
    assert first["corruptSchedules"] == 250
    assert first["quarantineFailures"] == 0
    assert first["queuedJobs"] == 0
    assert first["moreDueSchedules"] is True
    assert second["queuedJobs"] == 1
    assert second["moreDueSchedules"] is False
    quarantined = [
        item
        for item in table.items.values()
        if item.get("assurance_report_quarantine_reason") == "malformed_schedule_record"
    ]
    assert len(quarantined) == 250
    assert all("assurance_report_pk" not in item for item in quarantined)


def test_assurance_scheduler_quarantines_full_page_of_malformed_revisions(
    monkeypatch: Any,
) -> None:
    """String, boolean, missing and oversized revisions cannot starve page 251."""
    module, table = _load_handler(monkeypatch)
    now = 1_800_000_000
    monkeypatch.setattr(
        module,
        "_assurance_report_index",
        lambda tenant, due_at: ("ASSURANCE_REPORT#00", f"{int(due_at):012d}#{tenant}"),
    )
    revisions: tuple[Any, ...] = (
        "corrupt",
        True,
        None,
        module._ASSURANCE_REPORT_MAX_REVISION + 1,
    )
    for index in range(251):
        tenant = f"tenant-bad-revision-{index:03d}"
        item = {
            **module._assurance_item_key(tenant, "REPORT_SCHEDULE", "current"),
            "tenant_id": tenant,
            "enabled": True,
            "profile": "executive",
            "cadence": "daily",
            "hour_utc": 8,
            "day_of_week": None,
            "next_run_at": now - 1,
            "assurance_report_pk": "ASSURANCE_REPORT#00",
            "assurance_report_sk": f"{now - 1:012d}#{tenant}",
        }
        if index < 250:
            raw_revision = revisions[index % len(revisions)]
            if raw_revision is not None:
                item["revision"] = raw_revision
        else:
            item["revision"] = 1
        table.put_item(Item=item)
    original_query = table.query

    def paged_query(**value: Any) -> dict[str, Any]:
        result = cast(dict[str, Any], original_query(**value))
        if value.get("IndexName") != module._ASSURANCE_REPORT_INDEX:
            return result
        items = sorted(result["Items"], key=lambda item: item["assurance_report_sk"])
        limit = int(value["Limit"])
        return {
            "Items": items[:limit],
            **({"LastEvaluatedKey": {"pk": items[limit - 1]["pk"]}} if len(items) > limit else {}),
        }

    table.query = paged_query
    monkeypatch.setattr(module.time, "time", lambda: now)
    first = module._assurance_report_schedule_cycle(0)
    second = module._assurance_report_schedule_cycle(0)
    assert first["corruptSchedules"] == 250
    assert first["queuedJobs"] == 0
    assert second["queuedJobs"] == 1
    quarantined = [
        item
        for item in table.items.values()
        if item.get("assurance_report_quarantine_reason") == "malformed_schedule_record"
    ]
    assert len(quarantined) == 250
    assert all("assurance_report_pk" not in item for item in quarantined)


def test_assurance_scheduler_quarantine_cannot_overwrite_concurrent_repair(
    monkeypatch: Any,
) -> None:
    """A repaired schedule wins an exact race with stale-record quarantine."""
    module, table = _load_handler(monkeypatch)
    now = 1_800_000_000
    tenant = "tenant-concurrent-repair"
    monkeypatch.setattr(
        module,
        "_assurance_report_index",
        lambda indexed_tenant, due_at: (
            "ASSURANCE_REPORT#00",
            f"{int(due_at):012d}#{indexed_tenant}",
        ),
    )
    key = module._assurance_item_key(tenant, "REPORT_SCHEDULE", "current")
    table.put_item(
        Item={
            **key,
            "tenant_id": tenant,
            "enabled": True,
            "profile": "executive",
            "cadence": "daily",
            "hour_utc": 99,
            "day_of_week": None,
            "revision": 1,
            "next_run_at": now - 1,
            "assurance_report_pk": "ASSURANCE_REPORT#00",
            "assurance_report_sk": f"{now - 1:012d}#{tenant}",
        }
    )
    original_update = table.update_item
    repair_pending = True

    def repair_before_quarantine(**kwargs: Any) -> dict[str, Any]:
        nonlocal repair_pending
        if repair_pending and ":report_pk" in kwargs.get("ExpressionAttributeValues", {}):
            repair_pending = False
            table.items[(key["pk"], key["sk"])]["hour_utc"] = 8
            table.items[(key["pk"], key["sk"])]["revision"] = 2
        return cast(dict[str, Any], original_update(**kwargs))

    table.update_item = repair_before_quarantine
    monkeypatch.setattr(module.time, "time", lambda: now)
    first = module._assurance_report_schedule_cycle(0)
    repaired = table.items[(key["pk"], key["sk"])]
    assert first["corruptSchedules"] == 1
    assert first["quarantineFailures"] == 0
    assert repaired["revision"] == 2
    assert repaired["hour_utc"] == 8
    assert repaired["assurance_report_pk"] == "ASSURANCE_REPORT#00"
    assert "assurance_report_quarantine_reason" not in repaired

    second = module._assurance_report_schedule_cycle(0)
    assert second["queuedJobs"] == 1


def test_assurance_scheduler_transient_claim_failure_never_quarantines_valid_record(
    monkeypatch: Any,
) -> None:
    """Provider failure during a valid claim leaves the due schedule retryable."""
    module, table = _load_handler(monkeypatch)
    now = 1_800_000_000
    tenant = "tenant-transient-claim"
    monkeypatch.setattr(
        module,
        "_assurance_report_index",
        lambda indexed_tenant, due_at: (
            "ASSURANCE_REPORT#00",
            f"{int(due_at):012d}#{indexed_tenant}",
        ),
    )
    key = module._assurance_item_key(tenant, "REPORT_SCHEDULE", "current")
    table.put_item(
        Item={
            **key,
            "tenant_id": tenant,
            "enabled": True,
            "profile": "executive",
            "cadence": "daily",
            "hour_utc": 8,
            "day_of_week": None,
            "revision": 1,
            "next_run_at": now - 1,
            "assurance_report_pk": "ASSURANCE_REPORT#00",
            "assurance_report_sk": f"{now - 1:012d}#{tenant}",
        }
    )
    original_put = table.put_item

    def transient_claim_failure(**kwargs: Any) -> None:
        if kwargs.get("ConditionExpression") == (
            "revision = :revision AND next_run_at = :next_run_at"
        ):
            raise RuntimeError("synthetic DynamoDB throttling")
        original_put(**kwargs)

    table.put_item = transient_claim_failure
    monkeypatch.setattr(module.time, "time", lambda: now)
    with pytest.raises(RuntimeError, match="throttling"):
        module._assurance_report_schedule_cycle(0)
    retained = table.items[(key["pk"], key["sk"])]
    assert retained["assurance_report_pk"] == "ASSURANCE_REPORT#00"
    assert retained["revision"] == 1
    assert "assurance_report_quarantine_reason" not in retained
    view = module._assurance_report_schedule_view(retained)
    assert view["generationStatus"] == "idle"
    assert view["quarantinedAt"] is None


def test_assurance_schedule_view_exposes_quarantine_and_reviewed_repair(
    monkeypatch: Any,
) -> None:
    """Operators see quarantine and a revisioned schedule save clears it."""
    module, table = _load_handler(monkeypatch)
    now = 1_800_000_000
    tenant = "tenant-quarantine-view"
    key = module._assurance_item_key(tenant, "REPORT_SCHEDULE", "current")
    table.put_item(
        Item={
            **key,
            "tenant_id": tenant,
            "enabled": True,
            "profile": "executive",
            "cadence": "daily",
            "hour_utc": 99,
            "day_of_week": None,
            "revision": 1,
            "next_run_at": now - 1,
            "assurance_report_quarantined_at": now,
            "assurance_report_quarantine_reason": "malformed_schedule_record",
        }
    )
    view = module._assurance_report_schedule_view(table.items[(key["pk"], key["sk"])])
    assert view["generationStatus"] == "quarantined"
    assert view["quarantinedAt"] == now
    assert view["quarantineReason"] == "malformed_schedule_record"

    repaired = module._set_assurance_report_schedule(
        tenant,
        {
            "expectedRevision": 1,
            "enabled": True,
            "profile": "executive",
            "cadence": "daily",
            "hourUtc": 8,
            "dayOfWeek": None,
            "rationale": "Reviewed and repaired malformed reporting schedule.",
        },
        "admin-a",
        now=now + 60,
    )
    assert repaired["generationStatus"] == "idle"
    assert repaired["quarantinedAt"] is None
    assert repaired["quarantineReason"] is None


@pytest.mark.parametrize(
    ("has_revision", "raw_revision"),
    ((True, "corrupt"), (True, True), (False, None), (True, 2_147_483_648)),
)
def test_assurance_schedule_repairs_each_malformed_revision_shape(
    monkeypatch: Any, has_revision: bool, raw_revision: Any
) -> None:
    """Opaque revision zero binds and replaces the exact malformed record."""
    module, table = _load_handler(monkeypatch)
    now = 1_800_000_000
    tenant = f"tenant-repair-{str(raw_revision).lower()}-{has_revision}"
    key = module._assurance_item_key(tenant, "REPORT_SCHEDULE", "current")
    item = {
        **key,
        "tenant_id": tenant,
        "enabled": True,
        "profile": "executive",
        "cadence": "daily",
        "hour_utc": 8,
        "day_of_week": None,
        "next_run_at": now - 1,
        "assurance_report_quarantined_at": now,
        "assurance_report_quarantine_reason": "malformed_schedule_record",
    }
    if has_revision:
        item["revision"] = raw_revision
    table.put_item(Item=item)
    view = module._assurance_report_schedule_view(item)
    assert view["revision"] == 0
    assert view["generationStatus"] == "quarantined"
    repaired = module._set_assurance_report_schedule(
        tenant,
        {
            "expectedRevision": 0,
            "enabled": True,
            "profile": "executive",
            "cadence": "daily",
            "hourUtc": 8,
            "dayOfWeek": None,
            "rationale": "Reviewed and repaired malformed revision authority.",
        },
        "admin-a",
        now=now + 60,
    )
    assert repaired["revision"] == 1
    assert repaired["generationStatus"] == "idle"


def test_assurance_dispatch_partial_batch_retries_only_unaccepted_job(monkeypatch: Any) -> None:
    """Accepted jobs leave the due index while one rejected job remains retryable."""
    module, table = _load_handler(monkeypatch)
    now = 1_800_000_000
    shard = 0
    tenants = ("tenant-batch-a", "tenant-batch-b")
    monkeypatch.setattr(
        module,
        "_assurance_report_index",
        lambda tenant, due_at: (
            f"ASSURANCE_REPORT#{shard:02d}",
            f"{int(due_at):012d}#{tenant}",
        ),
    )
    for tenant in tenants:
        table.put_item(
            Item={
                **module._assurance_item_key(tenant, "REPORT_SCHEDULE", "current"),
                "tenant_id": tenant,
                "enabled": True,
                "profile": "executive",
                "cadence": "daily",
                "hour_utc": 8,
                "day_of_week": None,
                "revision": 1,
                "next_run_at": now - 1,
                "assurance_report_pk": f"ASSURANCE_REPORT#{shard:02d}",
                "assurance_report_sk": f"{now - 1:012d}#{tenant}",
            }
        )
    attempts = {"count": 0}
    original_send = module.SQS.send_message_batch

    def partial_send(**value: Any) -> dict[str, Any]:
        attempts["count"] += 1
        if attempts["count"] == 1:
            accepted, rejected = value["Entries"]
            module._fake_sqs.messages.append(
                {"QueueUrl": value["QueueUrl"], "MessageBody": accepted["MessageBody"]}
            )
            return {"Successful": [accepted], "Failed": [{"Id": rejected["Id"]}]}
        return cast(dict[str, Any], original_send(**value))

    monkeypatch.setattr(module.SQS, "send_message_batch", partial_send)
    monkeypatch.setattr(module.time, "time", lambda: now)
    with pytest.raises(RuntimeError, match="rejected"):
        module._assurance_report_schedule_cycle(shard)
    records = [item for item in table.items.values() if item.get("sk") == "REPORT_SCHEDULE#current"]
    assert sum("assurance_report_pk" in item for item in records) == 1


@pytest.mark.parametrize(
    "response",
    [
        {"Successful": [{"Id": "report-0"}]},
        {"Successful": [], "Failed": []},
        {"Successful": [{"Id": "report-0"}, {"Id": "report-0"}], "Failed": []},
        {"Successful": [], "Failed": [{"Id": "report-99"}]},
    ],
)
def test_assurance_dispatch_rejects_malformed_batch_response(
    monkeypatch: Any, response: dict[str, Any]
) -> None:
    """Unaccounted, duplicate, or unknown SQS result IDs fail closed."""
    module, _ = _load_handler(monkeypatch)
    monkeypatch.setattr(module.SQS, "send_message_batch", lambda **value: response)
    with pytest.raises(RuntimeError, match="malformed batch response"):
        module._dispatch_assurance_report_messages([{"tenantId": "tenant-a"}])


def test_assurance_history_page_reports_truncation_without_unbounded_read(
    monkeypatch: Any,
) -> None:
    """A bounded DynamoDB page remains usable while explicitly reporting more history."""
    module, table = _load_handler(monkeypatch)
    page = [
        {
            **module._assurance_item_key("tenant-a", "REPORT_SNAPSHOT", f"snapshot-{index}"),
            "id": f"snapshot-{index}",
        }
        for index in range(module._ASSURANCE_REPORT_HISTORY_LIMIT)
    ]
    observed: dict[str, Any] = {}

    def bounded_query(**value: Any) -> dict[str, Any]:
        observed.update(value)
        return {
            "Items": page,
            "LastEvaluatedKey": page[-1],
        }

    monkeypatch.setattr(table, "query", bounded_query)
    items, truncated = module._assurance_list_page(
        "tenant-a", "REPORT_SNAPSHOT", consistent_read=True
    )
    assert items == page
    assert truncated is True
    assert observed["Limit"] == module._ASSURANCE_REPORT_HISTORY_LIMIT + 1
    assert observed["ConsistentRead"] is True


def test_assurance_key_registry_fails_closed_on_ambiguous_or_foreign_authority(
    monkeypatch: Any,
) -> None:
    """Startup key configuration must be local, unique, complete, and dedicated."""
    module, _ = _load_handler(monkeypatch)
    signer = "arn:aws:kms:eu-west-1:111111111111:key/mrk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    historical = "arn:aws:kms:eu-west-1:111111111111:key/mrk-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    assert module._parse_assurance_key_registry(
        json.dumps([signer, historical]), "eu-west-1", signer, ()
    ) == (signer, historical)
    invalid = (
        ("{}", "eu-west-1", signer, ()),
        ("[]", "eu-west-1", signer, ()),
        (json.dumps([signer, signer]), "eu-west-1", signer, ()),
        (json.dumps([signer.replace("eu-west-1", "eu-west-2")]), "eu-west-1", signer, ()),
        (json.dumps([historical]), "eu-west-1", signer, ()),
        (json.dumps([signer]), "eu-west-1", signer, (signer,)),
    )
    for raw, region, signing_key, policy_keys in invalid:
        with pytest.raises(RuntimeError):
            module._parse_assurance_key_registry(raw, region, signing_key, policy_keys)


def test_assurance_verification_rejects_wrong_kms_response_and_accepts_historical_mrk(
    monkeypatch: Any,
) -> None:
    """Verification binds key/algorithm and resolves a retained MRK through its local replica."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-key-history"
    table.put_item(
        Item={**module._item_key(tenant, "TENANT", "root"), "tenant_id": tenant, "id": tenant}
    )
    snapshot = module._create_assurance_snapshot(
        tenant,
        "executive",
        "admin-a",
        source="operator",
        snapshot_id="operator-key-history",
        now=1_800_000_000,
        request_digest="a" * 64,
    )
    original_verify = module.KMS.verify
    wrong_key = "arn:aws:kms:eu-west-2:111111111111:key/mrk-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    module.KMS.verify = lambda **value: {
        "KeyId": wrong_key,
        "SigningAlgorithm": "ECDSA_SHA_256",
        "SignatureValid": True,
    }
    with pytest.raises(RuntimeError, match="verification failed"):
        module._verify_assurance_snapshot(tenant, snapshot["id"])
    module.KMS.verify = lambda **value: {
        "KeyId": value["KeyId"],
        "SigningAlgorithm": "RSASSA_PSS_SHA_256",
        "SignatureValid": True,
    }
    with pytest.raises(RuntimeError, match="verification failed"):
        module._verify_assurance_snapshot(tenant, snapshot["id"])
    module.KMS.verify = lambda **value: {
        "KeyId": value["KeyId"],
        "SigningAlgorithm": "ECDSA_SHA_256",
        "SignatureValid": False,
    }
    with pytest.raises(RuntimeError, match="verification failed"):
        module._verify_assurance_snapshot(tenant, snapshot["id"])
    module.KMS.verify = lambda **value: {}
    with pytest.raises(RuntimeError, match="verification failed"):
        module._verify_assurance_snapshot(tenant, snapshot["id"])
    original_document = module._assurance_snapshot_document
    with monkeypatch.context() as context:
        malformed = original_document(
            tenant, table.items[(f"ASSURANCE#{tenant}", f"REPORT_SNAPSHOT#{snapshot['id']}")]
        )
        malformed["integrity"]["signature"] = "not-valid-base64***"
        context.setattr(module, "_assurance_snapshot_document", lambda *_args: malformed)
        with pytest.raises(RuntimeError, match="signature is malformed"):
            module._verify_assurance_snapshot(tenant, snapshot["id"])

    old_identity = table.items[(f"ASSURANCE#{tenant}", f"REPORT_SNAPSHOT#{snapshot['id']}")][
        "signing_key_id"
    ]
    recovery_old_arn = f"arn:aws:kms:eu-west-1:111111111111:key/{old_identity}"
    new_arn = "arn:aws:kms:eu-west-1:111111111111:key/mrk-cccccccccccccccccccccccccccccccc"
    module.ASSURANCE_REPORT_SIGNING_KEY_ARN = new_arn
    module.ASSURANCE_REPORT_VERIFICATION_KEY_ARNS = (recovery_old_arn, new_arn)
    module.KMS.verify = original_verify
    assert module._verify_assurance_snapshot(tenant, snapshot["id"])["verified"] is True
    assert module._fake_kms.calls[-1]["KeyId"] == recovery_old_arn


def test_assurance_request_claim_rejects_concurrent_changed_first_use(monkeypatch: Any) -> None:
    """A durable pre-signing claim binds actor/profile/rationale before S3 can race."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-request-race"
    snapshot_id = "operator-shared-request"
    table.put_item(
        Item={
            **module._assurance_item_key(tenant, "REPORT_REQUEST", snapshot_id),
            "tenant_id": tenant,
            "snapshot_id": snapshot_id,
            "request_digest": "a" * 64,
            "created_at": 1_800_000_000,
        }
    )
    with pytest.raises(module.PolicyConflict, match="request identity"):
        module._create_assurance_snapshot(
            tenant,
            "executive",
            "other-admin",
            source="operator",
            snapshot_id=snapshot_id,
            now=1_800_000_000,
            request_digest="b" * 64,
        )


def test_assurance_request_claim_linearizes_real_overlapping_first_use(monkeypatch: Any) -> None:
    """Two overlapping changed requests produce one retained snapshot and one conflict."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-request-overlap"
    snapshot_id = "operator-overlap-request"
    table.put_item(
        Item={**module._item_key(tenant, "TENANT", "root"), "tenant_id": tenant, "id": tenant}
    )
    original_put = table.put_item
    barrier = threading.Barrier(2)

    def overlapping_put(*, Item: dict[str, Any], **kwargs: Any) -> None:
        if Item.get("sk") == f"REPORT_REQUEST#{snapshot_id}":
            barrier.wait(timeout=5)
        original_put(Item=Item, **kwargs)

    monkeypatch.setattr(table, "put_item", overlapping_put)

    def create(profile: str, digest: str) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            module._create_assurance_snapshot(
                tenant,
                profile,
                "admin-a",
                source="operator",
                snapshot_id=snapshot_id,
                now=1_800_000_000,
                request_digest=digest,
            ),
        )

    outcomes: list[object] = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(create, "executive", "a" * 64),
            executor.submit(create, "auditor", "b" * 64),
        ]
        for future in futures:
            try:
                outcomes.append(future.result(timeout=10))
            except Exception as error:  # noqa: PERF203 - preserve both concurrent outcomes.
                outcomes.append(error)
    assert sum(isinstance(value, dict) for value in outcomes) == 1
    assert sum(isinstance(value, module.PolicyConflict) for value in outcomes) == 1
    assert (
        len(
            [
                item
                for item in table.items.values()
                if item.get("sk") == f"REPORT_SNAPSHOT#{snapshot_id}"
            ]
        )
        == 1
    )


def test_discovery_object_pages_preserve_legacy_reads_and_fail_closed_on_loss(
    monkeypatch: Any,
) -> None:
    """Legacy pages remain readable while unavailable object evidence disappears."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-discovery-page-compatibility"
    generation = "identity-generation-a"
    observation = {"kind": "identity", "id": "synthetic-user-a", "active": True}
    normalized = [module._discovery_observation(observation, "identity")]
    page_hash = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    table.put_item(
        Item=module._item_key(
            tenant,
            "DISCOVERY_PAGE",
            f"identity-a:{generation}:00000",
        )
        | {
            "sourceId": "identity-a",
            "generation": generation,
            "pageNumber": 0,
            "pageHash": page_hash,
            "observations": normalized,
        }
    )
    source = {
        "sourceId": "identity-a",
        "sourceKind": "identity",
        "generation": generation,
        "pageCount": 1,
    }
    assert module._discovery_generation_observations(tenant, source) == normalized

    staged_generation = "identity-generation-b"
    table.put_item(
        Item=module._item_key(
            tenant,
            "DISCOVERY_GENERATION",
            f"identity-a:{staged_generation}",
        )
        | {
            "sourceId": "identity-a",
            "sourceKind": "identity",
            "generation": staged_generation,
            "pageCount": 1,
            "pageStorage": "s3_versioned_v1",
            "state": "uploading",
        }
    )
    module._put_discovery_generation_page(
        tenant,
        "identity-a",
        staged_generation,
        0,
        {"observations": [observation]},
    )
    object_source = {
        **source,
        "generation": staged_generation,
        "pageStorage": "s3_versioned_v1",
    }
    assert module._discovery_generation_observations(tenant, object_source) == normalized
    reads_before_oversized_metadata = len(module.S3.get_requests)
    assert (
        module._discovery_generation_observations(
            tenant,
            {**object_source, "pageCount": 21},
        )
        == []
    )
    assert len(module.S3.get_requests) == reads_before_oversized_metadata
    pointer = table.items[
        (
            f"TENANT#{tenant}",
            f"DISCOVERY_PAGE#identity-a:{staged_generation}:00000",
        )
    ]
    module.S3.put_object(
        Bucket="discovery-pages",
        Key=pointer["pageObjectKey"],
        Body=b'{"synthetic":"newer-untrusted-version"}',
    )
    assert module._discovery_generation_observations(tenant, object_source) == normalized
    object_digest = pointer.pop("pageObjectSha256")
    assert module._discovery_generation_observations(tenant, object_source) == []
    pointer["pageObjectSha256"] = object_digest
    del module.S3.objects[(pointer["pageObjectKey"], pointer["pageObjectVersionId"])]
    assert module._discovery_generation_observations(tenant, object_source) == []

    oversized_generation = "identity-generation-oversized"
    table.put_item(
        Item=module._item_key(
            tenant,
            "DISCOVERY_GENERATION",
            f"identity-a:{oversized_generation}",
        )
        | {
            "sourceId": "identity-a",
            "sourceKind": "identity",
            "generation": oversized_generation,
            "pageCount": 1,
            "pageStorage": "s3_versioned_v1",
            "state": "uploading",
        }
    )
    with pytest.raises(ValueError, match="1 to 1000"):
        module._put_discovery_generation_page(
            tenant,
            "identity-a",
            oversized_generation,
            0,
            {
                "observations": [
                    {"kind": "identity", "id": f"user-{index}", "active": True}
                    for index in range(1_001)
                ]
            },
        )


def test_discovery_object_pages_commit_the_twenty_thousand_record_envelope(
    monkeypatch: Any,
) -> None:
    """The documented maximum is accepted with fixed twenty-object fan-out."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-discovery-maximum"
    source_id = "identity-maximum"
    generation = "identity-maximum-generation"
    now = int(time.time())
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(
            tenant,
            "DISCOVERY_GENERATION",
            f"{source_id}:{generation}",
        )
        | {
            "tenant_id": tenant,
            "sourceId": source_id,
            "sourceKind": "identity",
            "generation": generation,
            "expectedRevision": 0,
            "observedAt": now,
            "expiresAt": now + 300,
            "pageCount": 20,
            "pageStorage": "s3_versioned_v1",
            "state": "uploading",
            "createdAt": now,
        }
    )
    page_hashes = []
    for page_number in range(20):
        result = module._put_discovery_generation_page(
            tenant,
            source_id,
            generation,
            page_number,
            {
                "observations": [
                    {
                        "kind": "identity",
                        "id": f"synthetic-user-{page_number:02d}-{index:04d}",
                        "active": True,
                    }
                    for index in range(1_000)
                ]
            },
        )
        page_hashes.append(result["pageHash"])

    committed = module._commit_discovery_generation(
        tenant,
        source_id,
        generation,
        {"pageHashes": page_hashes},
        "synthetic-scale-acceptance",
    )
    assert committed["observationCount"] == 20_000
    assert committed["pageCount"] == 20
    assert committed["pageStorage"] == "s3_versioned_v1"
    assert len(module._discovery_generation_observations(tenant, committed)) == 20_000
    page_records = [
        item
        for (pk, sk), item in table.items.items()
        if pk == f"TENANT#{tenant}" and sk.startswith(f"DISCOVERY_PAGE#{source_id}:")
    ]
    assert len(page_records) == 20
    assert all("observations" not in item for item in page_records)


def test_service_identity_lifecycle_is_one_time_scoped_and_evidenced(monkeypatch: Any) -> None:
    """Machine credentials rotate/revoke live and never appear in later reads."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-service-identity"
    now = 1_800_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-service-admin",
    }
    path = "/api/enterprise/identity/service-identities"
    created_response = _invoke(
        module,
        _event(
            path,
            "POST",
            claims=platform,
            body={
                "serviceIdentityId": "ci-policy-reader",
                "name": "CI policy reader",
                "description": "Reads governed inventory for synthetic CI.",
                "purpose": "Verify desired policy inventory before deployment.",
                "capabilities": ["inventory_read"],
                "expiresInDays": 30,
            },
        ),
    )
    assert created_response["statusCode"] == 201
    created = json.loads(created_response["body"])
    token = created["credential"]["accessToken"]
    assert token.startswith("aai_si_ci-policy-reader.")
    assert created["revision"] == 1

    listed = json.loads(_invoke(module, _event(path, "GET", claims=platform))["body"])["items"]
    assert listed[0]["credentialFingerprint"] == created["credentialFingerprint"]
    assert "credential" not in listed[0]
    assert token not in json.dumps(listed)

    machine_path = "/machine/v1/enterprise/policies"
    used = _invoke(module, _event(machine_path, "GET", token=token))
    assert used["statusCode"] == 200
    assert json.loads(used["body"])["items"] == []
    listed_after_use = json.loads(_invoke(module, _event(path, "GET", claims=platform))["body"])[
        "items"
    ][0]
    assert listed_after_use["useCount"] == 1
    assert listed_after_use["lastUsedRoute"] == "/enterprise/policies"
    usage = json.loads(
        _invoke(
            module,
            _event(f"{path}/ci-policy-reader/usage", "GET", claims=platform),
        )["body"]
    )
    assert usage["truncated"] is False
    assert usage["items"][0]["capability"] == "inventory_read"
    assert usage["items"][0]["credentialRevision"] == 1

    rotated_response = _invoke(
        module,
        _event(
            f"{path}/ci-policy-reader/rotate",
            "POST",
            claims=platform,
            body={"expectedRevision": 1, "expiresInDays": 14},
        ),
    )
    assert rotated_response["statusCode"] == 201
    rotated = json.loads(rotated_response["body"])
    replacement = rotated["credential"]["accessToken"]
    assert replacement != token
    assert rotated["revision"] == 2
    assert _invoke(module, _event(machine_path, "GET", token=token))["statusCode"] == 403
    assert _invoke(module, _event(machine_path, "GET", token=replacement))["statusCode"] == 200

    revoked = _invoke(
        module,
        _event(
            f"{path}/ci-policy-reader/revoke",
            "POST",
            claims=platform,
            body={"expectedRevision": 2, "reason": "Synthetic CI job retired."},
        ),
    )
    assert revoked["statusCode"] == 200
    assert json.loads(revoked["body"])["status"] == "revoked"
    assert _invoke(module, _event(machine_path, "GET", token=replacement))["statusCode"] == 403
    retained = b"\n".join(item["Body"] for item in module.S3.objects.values()).decode()
    assert token not in retained
    assert replacement not in retained
    assert "service_identity_request_admitted" in retained


def test_service_identity_denies_escalation_forgery_expiry_and_cross_tenant_access(
    monkeypatch: Any,
) -> None:
    """A bearer cannot widen scope, cross tenants, or survive its server expiry."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-service-scope"
    other = "tenant-service-other"
    now = 1_800_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    for tenant_id in (tenant, other):
        table.put_item(Item=module._item_key(tenant_id, "TENANT", "root") | {"id": tenant_id})
    table.put_item(
        Item=module._item_key(other, "POLICY", "other-private")
        | {"id": "other-private", "tenant_id": other, "version": 1}
    )
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-service-scope",
    }
    path = "/api/enterprise/identity/service-identities"
    unsupported = _invoke(
        module,
        _event(
            path,
            "POST",
            claims=platform,
            body={
                "serviceIdentityId": "forged-admin",
                "name": "Forged admin",
                "description": "Synthetic negative case.",
                "purpose": "Prove excluded capabilities fail closed.",
                "capabilities": ["identity_admin"],
                "expiresInDays": 1,
            },
        ),
    )
    assert unsupported["statusCode"] == 400
    created = json.loads(
        _invoke(
            module,
            _event(
                path,
                "POST",
                claims=platform,
                body={
                    "serviceIdentityId": "bounded-reader",
                    "name": "Bounded reader",
                    "description": "Synthetic tenant-bound reader.",
                    "purpose": "Read only the bound tenant inventory.",
                    "capabilities": ["inventory_read"],
                    "expiresInDays": 1,
                },
            ),
        )["body"]
    )
    token = created["credential"]["accessToken"]
    policies = json.loads(
        _invoke(
            module,
            _event("/machine/v1/enterprise/policies", "GET", token=token),
        )["body"]
    )["items"]
    assert "other-private" not in json.dumps(policies)
    assert (
        _invoke(
            module,
            _event("/machine/v1/enterprise/groups", "POST", token=token, body={}),
        )["statusCode"]
        == 403
    )
    assert (
        _invoke(
            module,
            _event(
                "/machine/v1/enterprise/policies/policy-a/versions/1/activate",
                "POST",
                token=token,
                body={},
            ),
        )["statusCode"]
        == 403
    )
    assert (
        _invoke(
            module,
            _event("/machine/v1/enterprise/policies", "GET", token="forged-" + "token"),
        )["statusCode"]
        == 403
    )
    monkeypatch.setattr(module.time, "time", lambda: now + 86401)
    assert (
        _invoke(
            module,
            _event("/machine/v1/enterprise/policies", "GET", token=token),
        )["statusCode"]
        == 403
    )


def test_service_identity_management_requires_platform_authority(monkeypatch: Any) -> None:
    """Human policy, fleet and delegated roles cannot mint machine authority."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-service-role"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    body = {
        "serviceIdentityId": "denied-service",
        "name": "Denied service",
        "description": "Synthetic negative case.",
        "purpose": "Prove human least privilege.",
        "capabilities": ["inventory_read"],
        "expiresInDays": 7,
    }
    for role in ("policy-author", "fleet-operator", "auditor"):
        response = _invoke(
            module,
            _event(
                "/api/enterprise/identity/service-identities",
                "POST",
                claims={
                    "custom:tenant_id": tenant,
                    "cognito:groups": [role],
                    "sub": f"synthetic-{role}",
                },
                body=body,
            ),
        )
        assert response["statusCode"] == 403
        assert json.loads(response["body"])["requiredCapability"] == "identity_admin"

    created = _invoke(
        module,
        _event(
            "/api/enterprise/identity/service-identities",
            "POST",
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["platform-admin"],
                "sub": "synthetic-platform-admin",
            },
            body=body,
        ),
    )
    assert created["statusCode"] == 201
    listed = _invoke(
        module,
        _event(
            "/api/enterprise/identity/service-identities",
            "GET",
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["auditor"],
                "sub": "synthetic-auditor",
            },
        ),
    )
    assert listed["statusCode"] == 200
    assert json.loads(listed["body"])["items"][0]["id"] == "denied-service"
    assert "accessToken" not in listed["body"]
    assert "credential_key" not in listed["body"]


def test_machine_api_allowlist_covers_each_scope_and_excludes_human_governance(
    monkeypatch: Any,
) -> None:
    """The versioned allowlist is complete for advertised scopes and deny-first elsewhere."""
    module, _table = _load_handler(monkeypatch)
    assert module._machine_route_capability("GET", "/api/enterprise/agents") == "inventory_read"
    assert (
        module._machine_route_capability("GET", "/api/enterprise/runtime-releases")
        == "inventory_read"
    )
    assert (
        module._machine_route_capability("GET", "/api/enterprise/version-compliance")
        == "inventory_read"
    )
    assert (
        module._machine_route_capability("GET", "/api/enterprise/reports/auditor")
        == "evidence_read"
    )
    assert (
        module._machine_route_capability("POST", "/api/enterprise/policies/policy-a/versions")
        == "policy_draft_write"
    )
    assert (
        module._machine_route_capability(
            "POST", "/api/enterprise/policies/policy-a/versions/1/simulate"
        )
        == "policy_simulation"
    )
    assert (
        module._machine_route_capability("POST", "/api/enterprise/groups/group-a/agents/bulk")
        == "fleet_write"
    )
    assert (
        module._machine_route_capability("POST", "/api/enterprise/deployment-config")
        == "runtime_write"
    )
    assert (
        module._machine_route_capability("POST", "/api/enterprise/runtime-rollouts")
        == "runtime_write"
    )
    assert (
        module._machine_route_capability(
            "POST", "/api/enterprise/runtime-rollouts/deployment-a/rollback"
        )
        == "runtime_write"
    )
    for method, path in (
        ("POST", "/api/enterprise/policies/policy-a/versions/1/activate"),
        ("POST", "/api/enterprise/approvals/approval-a/decision"),
        ("POST", "/api/enterprise/identity/service-identities"),
        ("POST", "/api/enterprise/emergency-stop"),
        ("GET", "/api/enterprise/identity"),
    ):
        assert module._machine_route_capability(method, path) is None

    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    machine_route = stack.index('path: "/machine/{proxy+}"')
    jwt_route = stack.index('path: "/{proxy+}", methods: [apigwv2.HttpMethod.ANY]', machine_route)
    assert machine_route < jwt_route


def test_machine_declarative_resources_reconcile_with_revision_guards(
    monkeypatch: Any,
) -> None:
    """Terraform-facing writes must detect drift and retain retired evidence."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-terraform"
    now = 1_800_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "ORG", "org-platform")
        | {"id": "org-platform", "name": "Platform"}
    )
    table.put_item(
        Item=module._item_key(tenant, "POLICY", "policy-active")
        | {
            "id": "policy-active",
            "tenant_id": tenant,
            "organization_id": "org-platform",
            "name": "Active policy",
            "configuration": {},
            "version": 1,
            "activeVersion": 1,
            "latestVersion": 1,
            "governanceState": "active",
            "governance_schema_version": 1,
            "author": "synthetic-author",
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "POLICY_VERSION", "policy-active:1")
        | {
            "id": "policy-active:1",
            "tenant_id": tenant,
            "policy_id": "policy-active",
            "organization_id": "org-platform",
            "version": 1,
            "base_version": 0,
            "name": "Active policy",
            "configuration": {},
            "local_configuration": {},
            "component_refs": [],
            "graph_digest": "a" * 64,
            "composition_explanation": [],
            "content_hash": "b" * 64,
            "state": "active",
            "author": "synthetic-author",
            "created_at": now,
        }
    )
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "synthetic-platform-admin",
    }
    credential = json.loads(
        _invoke(
            module,
            _event(
                "/api/enterprise/identity/service-identities",
                "POST",
                claims=platform,
                body={
                    "serviceIdentityId": "terraform",
                    "name": "Terraform",
                    "description": "Synthetic declarative management.",
                    "purpose": "Exercise deterministic configuration reconciliation.",
                    "capabilities": [
                        "inventory_read",
                        "policy_draft_write",
                        "fleet_write",
                    ],
                    "expiresInDays": 7,
                },
            ),
        )["body"]
    )["credential"]["accessToken"]

    assert (
        _invoke(
            module,
            _event("/machine/v1/enterprise/tenant", "GET", token=credential),
        )["statusCode"]
        == 200
    )
    skill_body = {
        "skillId": "secure-review",
        "organizationId": "org-platform",
        "name": "Secure review",
        "description": "Synthetic safe review guidance.",
        "version": "1.0.0",
        "content": "# Secure review\nDo not expose synthetic secrets.\n",
        "enabled": True,
    }
    created = _invoke(
        module,
        _event("/machine/v1/enterprise/skills", "POST", token=credential, body=skill_body),
    )
    assert created["statusCode"] == 201
    assert json.loads(created["body"])["revision"] == 1
    assert (
        _invoke(
            module,
            _event("/machine/v1/enterprise/skills", "POST", token=credential, body=skill_body),
        )["statusCode"]
        == 409
    )
    updated = _invoke(
        module,
        _event(
            "/machine/v1/enterprise/skills/secure-review",
            "PUT",
            token=credential,
            body={
                **skill_body,
                "content": "# Secure review\nDeny unsafe changes.\n",
                "expectedRevision": 1,
            },
        ),
    )
    assert updated["statusCode"] == 200
    assert json.loads(updated["body"])["revision"] == 2
    stale = _invoke(
        module,
        _event(
            "/machine/v1/enterprise/skills/secure-review",
            "PUT",
            token=credential,
            body={**skill_body, "expectedRevision": 1},
        ),
    )
    assert stale["statusCode"] == 409
    retired = _invoke(
        module,
        _event(
            "/machine/v1/enterprise/skills/secure-review",
            "DELETE",
            token=credential,
            body={"expectedRevision": 2},
        ),
    )
    assert retired["statusCode"] == 200
    assert json.loads(retired["body"])["status"] == "retired"

    table.put_item(
        Item=module._item_key(tenant, "SKILL", "legacy-review")
        | {
            "id": "legacy-review",
            "tenant_id": tenant,
            "organizationId": "org-platform",
            "name": "Legacy review",
            "description": "Synthetic legacy record.",
            "version": "1.0.0",
            "content": "# Legacy\n",
            "enabled": True,
        }
    )
    migrated = _invoke(
        module,
        _event(
            "/machine/v1/enterprise/skills/legacy-review",
            "PUT",
            token=credential,
            body={
                **skill_body,
                "skillId": "legacy-review",
                "name": "Legacy review",
                "expectedRevision": 1,
            },
        ),
    )
    assert migrated["statusCode"] == 200
    assert json.loads(migrated["body"])["revision"] == 2

    insecure_mcp = {
        "serverId": "github",
        "organizationId": "org-platform",
        "name": "GitHub",
        "description": "Synthetic MCP registration.",
        "version": "1.0.0",
        "transport": "http",
        "url": "http://mcp.example.invalid",
        "environmentReferences": ["GITHUB_MCP_TOKEN"],
        "enabled": True,
    }
    for unsafe_url in (
        "http://mcp.example.invalid",
        "https://synthetic-token@mcp.example.invalid",
        "https://mcp.example.invalid?token=synthetic",
        "https://mcp.example.invalid#fragment",
        "https://[malformed",
    ):
        assert (
            _invoke(
                module,
                _event(
                    "/machine/v1/enterprise/mcp-servers",
                    "POST",
                    token=credential,
                    body={**insecure_mcp, "url": unsafe_url},
                ),
            )["statusCode"]
            == 400
        )
    mcp_created = _invoke(
        module,
        _event(
            "/machine/v1/enterprise/mcp-servers",
            "POST",
            token=credential,
            body={**insecure_mcp, "url": "https://mcp.example.invalid/github"},
        ),
    )
    assert mcp_created["statusCode"] == 201
    assert json.loads(mcp_created["body"])["revision"] == 1

    def race_mcp_update() -> None:
        current = table.items[(f"TENANT#{tenant}", "MCP#github")]
        current["revision"] = 2
        current["url"] = "https://mcp.example.invalid/raced"

    module.DYNAMODB.before_transaction = race_mcp_update
    with pytest.raises(module.PolicyConflict, match="declarative configuration changed"):
        module._replace_managed_registration(
            tenant,
            "MCP",
            "github",
            {
                **insecure_mcp,
                "url": "https://mcp.example.invalid/intended",
                "expectedRevision": 1,
            },
            "service:terraform",
        )
    assert table.items[(f"TENANT#{tenant}", "MCP#github")]["url"].endswith("/raced")
    mcp_retired = _invoke(
        module,
        _event(
            "/machine/v1/enterprise/mcp-servers/github",
            "DELETE",
            token=credential,
            body={"expectedRevision": 2},
        ),
    )
    assert mcp_retired["statusCode"] == 200
    assert json.loads(mcp_retired["body"])["status"] == "retired"

    group_body = {
        "groupId": "group-platform",
        "name": "Platform",
        "policyId": "policy-active",
    }
    group = _invoke(
        module,
        _event("/machine/v1/enterprise/groups", "POST", token=credential, body=group_body),
    )
    assert group["statusCode"] == 201
    changed = _invoke(
        module,
        _event(
            "/machine/v1/enterprise/groups/group-platform",
            "PUT",
            token=credential,
            body={
                "name": "Platform engineering",
                "policyId": "policy-active",
                "expectedConfigurationRevision": 1,
            },
        ),
    )
    assert changed["statusCode"] == 200
    assert json.loads(changed["body"])["configurationRevision"] == 2
    table.items[(f"TENANT#{tenant}", "GROUP#group-platform")]["agent_keys"] = [
        "deployment-a:agent-a"
    ]
    blocked_delete = _invoke(
        module,
        _event(
            "/machine/v1/enterprise/groups/group-platform",
            "DELETE",
            token=credential,
            body={"expectedConfigurationRevision": 2},
        ),
    )
    assert blocked_delete["statusCode"] == 409
    table.items[(f"TENANT#{tenant}", "GROUP#group-platform")]["agent_keys"] = []
    deleted = _invoke(
        module,
        _event(
            "/machine/v1/enterprise/groups/group-platform",
            "DELETE",
            token=credential,
            body={"expectedConfigurationRevision": 2},
        ),
    )
    assert deleted["statusCode"] == 200
    assert json.loads(deleted["body"])["deleted"] is True

    def unavailable_replica(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("synthetic Object Lock replica unavailable")

    monkeypatch.setattr(module, "_audit", unavailable_replica)
    durable_without_replica = module._create_managed_registration(
        tenant,
        "SKILL",
        "replica-outage",
        {
            **skill_body,
            "skillId": "replica-outage",
            "name": "Replica outage",
        },
        "service:terraform",
    )
    assert durable_without_replica["revision"] == 1
    configuration_events = {
        item["event_type"]
        for item in table.items.values()
        if item.get("sk", "").startswith("CONFIGURATION_AUDIT#")
    }
    assert {
        "skill_created",
        "skill_updated",
        "skill_retired",
        "mcp_server_created",
        "mcp_server_retired",
        "group_created",
        "group_configuration_updated",
        "group_deleted",
    } <= configuration_events


def test_machine_declarative_routes_reject_unsafe_mcp_and_governance_escalation(
    monkeypatch: Any,
) -> None:
    """The automation surface must reject insecure endpoints and human transitions."""
    module, _table = _load_handler(monkeypatch)
    assert (
        module._machine_route_capability("PUT", "/api/enterprise/skills/skill-a")
        == "policy_draft_write"
    )
    assert (
        module._machine_route_capability("DELETE", "/api/enterprise/mcp-servers/server-a")
        == "policy_draft_write"
    )
    assert (
        module._machine_route_capability("PUT", "/api/enterprise/groups/group-a") == "fleet_write"
    )
    assert (
        module._machine_route_capability("DELETE", "/api/enterprise/groups/group-a")
        == "fleet_write"
    )
    assert (
        module._machine_route_capability(
            "POST", "/api/enterprise/policies/policy-a/versions/1/decision"
        )
        is None
    )
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    machine_route = stack.index('path: "/machine/{proxy+}"')
    machine_statement = stack[machine_route : stack.index(";", machine_route)]
    assert "authorizer" not in machine_statement
    assert "MachineApiIntegration" in machine_statement


def test_evidence_assurance_retention_legal_hold_and_export(monkeypatch: Any) -> None:
    """Exercise the complete tenant records-management journey with immutable versions."""
    module, _table = _load_handler(monkeypatch)
    tenant = "tenant-demo"
    security = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "security-a",
    }
    auditor = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["auditor"],
        "sub": "auditor-a",
    }

    initial = _invoke(module, _event("/api/enterprise/evidence", "GET", claims=auditor))
    assert initial["statusCode"] == 200
    initial_body = json.loads(initial["body"])
    assert initial_body["status"] == "verified"
    assert initial_body["policy"]["retentionDays"] == 365
    assert initial_body["recordCount"] > 0

    updated = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/retention",
            "PUT",
            claims=security,
            body={
                "expectedRevision": 0,
                "retentionDays": 730,
                "rationale": "Customer records schedule requires two years.",
            },
        ),
    )
    assert updated["statusCode"] == 200
    assert json.loads(updated["body"])["revision"] == 1
    assert all(
        record["Retention"]["RetainUntilDate"] > datetime.now(UTC) + timedelta(days=729)
        for record in module._fake_s3.objects.values()
    )

    current = json.loads(
        _invoke(module, _event("/api/enterprise/evidence", "GET", claims=auditor))["body"]
    )
    target = current["records"][0]
    held = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/legal-hold",
            "POST",
            claims=security,
            body={
                "key": target["key"],
                "versionId": target["versionId"],
                "active": True,
                "rationale": "Synthetic investigation preservation.",
            },
        ),
    )
    assert held["statusCode"] == 200
    after_hold = json.loads(
        _invoke(module, _event("/api/enterprise/evidence", "GET", claims=auditor))["body"]
    )
    assert after_hold["legalHoldCount"] == 1

    exported = _invoke(module, _event("/api/enterprise/evidence/export", "GET", claims=auditor))
    assert exported["statusCode"] == 200
    artifact = json.loads(exported["body"])
    digest = artifact.pop("contentSha256")
    assert (
        digest
        == hashlib.sha256(
            json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    assert artifact["recordCount"] == len(artifact["records"])


def test_evidence_governance_fails_closed_on_bypass_and_tamper(monkeypatch: Any) -> None:
    """Deny weak roles, retention reduction, stale writes, cross-tenant holds and altered bytes."""
    module, _table = _load_handler(monkeypatch)
    tenant = "tenant-demo"
    security = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "security-a",
    }
    fleet = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "fleet-a",
    }
    denied_read = _invoke(module, _event("/api/enterprise/evidence", "GET", claims=fleet))
    assert denied_read["statusCode"] == 403
    denied_write = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/retention",
            "PUT",
            claims=fleet,
            body={"expectedRevision": 0, "retentionDays": 730, "rationale": "No authority."},
        ),
    )
    assert denied_write["statusCode"] == 403

    accepted = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/retention",
            "PUT",
            claims=security,
            body={
                "expectedRevision": 0,
                "retentionDays": 730,
                "rationale": "Approved customer retention schedule.",
            },
        ),
    )
    assert accepted["statusCode"] == 200, accepted
    stale = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/retention",
            "PUT",
            claims=security,
            body={
                "expectedRevision": 0,
                "retentionDays": 900,
                "rationale": "Intentionally stale retention update.",
            },
        ),
    )
    assert stale["statusCode"] == 409
    reduction = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/retention",
            "PUT",
            claims=security,
            body={
                "expectedRevision": 1,
                "retentionDays": 365,
                "rationale": "Attempt to shorten immutable retention.",
            },
        ),
    )
    assert reduction["statusCode"] == 400
    cross_tenant = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/legal-hold",
            "POST",
            claims=security,
            body={
                "key": "tenant=other/year=2026/record.json",
                "versionId": "version-1",
                "active": True,
                "rationale": "Cross-tenant attempt.",
            },
        ),
    )
    assert cross_tenant["statusCode"] == 403

    object_record = next(iter(module._fake_s3.objects.values()))
    object_record["Body"] += b"tampered"
    assurance = _invoke(module, _event("/api/enterprise/evidence", "GET", claims=security))
    assert assurance["statusCode"] == 200
    assert json.loads(assurance["body"])["status"] == "at_risk"
    failed_export = _invoke(
        module, _event("/api/enterprise/evidence/export", "GET", claims=security)
    )
    assert failed_export["statusCode"] == 500


def test_evidence_assurance_reports_legacy_object_lock_gaps_without_failing(
    monkeypatch: Any,
) -> None:
    """Treat absent legacy lock state as at risk while preserving assurance access."""
    module, _table = _load_handler(monkeypatch)
    tenant = "tenant-demo"
    module._audit(tenant, "legacy_record", "synthetic", {"source": "pre-migration"})
    legacy = next(iter(module._fake_s3.objects.values()))
    legacy.pop("Retention")
    legacy.pop("LegalHold")

    response = _invoke(
        module,
        _event(
            "/api/enterprise/evidence",
            "GET",
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["auditor"],
                "sub": "auditor-a",
            },
        ),
    )

    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["status"] == "at_risk"
    assert body["verifiedCount"] == body["recordCount"] - 1
    legacy_record = next(record for record in body["records"] if not record["retainUntil"])
    assert legacy_record["retentionMode"] is None
    assert legacy_record["legalHold"] is False

    def deny_legal_hold(**_value: Any) -> dict[str, Any]:
        raise ObjectLockAccessDenied()

    monkeypatch.setattr(module._fake_s3, "get_object_legal_hold", deny_legal_hold)
    denied = _invoke(
        module,
        _event(
            "/api/enterprise/evidence",
            "GET",
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["auditor"],
                "sub": "auditor-a",
            },
        ),
    )
    assert denied["statusCode"] == 500


def test_evidence_inventory_never_presents_a_bounded_sample_as_complete(monkeypatch: Any) -> None:
    """Refuse synchronous export and retention mutation above the explicit pilot bound."""
    module, _table = _load_handler(monkeypatch)
    tenant = "tenant-demo"
    security = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "security-a",
    }
    for index in range(module._EVIDENCE_RECORD_LIMIT + 1):
        module._audit(tenant, "synthetic_bound_probe", "test", {"index": index})

    assurance = _invoke(module, _event("/api/enterprise/evidence", "GET", claims=security))
    assert assurance["statusCode"] == 200
    body = json.loads(assurance["body"])
    assert body["status"] == "incomplete"
    assert body["complete"] is False
    assert body["recordCount"] == module._EVIDENCE_RECORD_LIMIT + 1
    assert body["verifiedCount"] == 0
    assert body["records"] == []
    export = _invoke(module, _event("/api/enterprise/evidence/export", "GET", claims=security))
    assert export["statusCode"] == 409
    update = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/retention",
            "PUT",
            claims=security,
            body={
                "expectedRevision": 0,
                "retentionDays": 730,
                "rationale": "Approved two-year synthetic records schedule.",
            },
        ),
    )
    assert update["statusCode"] == 409


def test_async_retention_extends_every_version_above_the_synchronous_bound(
    monkeypatch: Any,
) -> None:
    """Apply an increase-only policy before a complete revision-bound backfill."""
    module, _table = _load_handler(monkeypatch)
    tenant = "tenant-demo"
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "security-retention",
    }
    for index in range(module._EVIDENCE_RECORD_LIMIT + 5):
        module._audit(tenant, "retention_bound_probe", "test", {"index": index})
    for (key, _version), record in module._fake_s3.objects.items():
        if key.startswith(f"tenant={tenant}/"):
            record["LastModified"] = datetime.now(UTC) - timedelta(seconds=10)
    monkeypatch.setattr(module, "_EVIDENCE_RETENTION_CUTOVER_SECONDS", 0)

    started = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/retention-jobs",
            "POST",
            claims=claims,
            body={
                "requestId": "mass-retention-a",
                "expectedRevision": 0,
                "retentionDays": 730,
                "rationale": "Approved two-year synthetic enterprise records schedule.",
            },
        ),
    )
    assert started["statusCode"] == 202
    job = json.loads(started["body"])
    assert job["status"] == "settling"
    posture = json.loads(
        _invoke(module, _event("/api/enterprise/evidence", "GET", claims=claims))["body"]
    )
    assert posture["complete"] is False
    assert posture["policy"]["retentionDays"] == 730
    assert posture["policy"]["applicationStatus"] == "applying"
    assert posture["latestRetentionJob"]["id"] == job["id"]

    # A write after policy cutover receives the longer future-record policy
    # immediately, before the existing-version backfill completes.
    module._audit(tenant, "post_cutover_probe", "test", {"synthetic": True})
    newest = max(module._fake_s3.objects.values(), key=lambda item: item["LastModified"])
    assert newest["Retention"]["RetainUntilDate"] > datetime.now(UTC) + timedelta(days=729)

    scheduled = module._evidence_retention_schedule_cycle()
    assert scheduled["dispatchedJobs"] == 1
    processed = 0
    while module._fake_sqs.messages:
        message = module._fake_sqs.messages.pop(0)
        assert message["QueueUrl"].endswith("evidence-retention.fifo")
        result = module.process_retention_queue_event(
            {
                "Records": [
                    {
                        "eventSource": "aws:sqs",
                        "body": message["MessageBody"],
                        "attributes": {"ApproximateReceiveCount": "1"},
                    }
                ]
            }
        )
        processed += 1
        assert result["status"] in {"queued", "completed"}
        assert processed < 100

    completed = json.loads(
        _invoke(
            module,
            _event(
                f"/api/enterprise/evidence/retention-jobs/{job['id']}",
                "GET",
                claims=claims,
            ),
        )["body"]
    )
    assert completed["status"] == "completed"
    assert completed["recordCount"] > module._EVIDENCE_RECORD_LIMIT
    assert completed["recordCount"] == (
        completed["extendedCount"] + completed["alreadyCompliantCount"]
    )
    assert completed["pageCount"] > 25
    applied = module._evidence_policy(tenant)
    assert applied["applicationStatus"] == "applied"
    assert applied["affectedRecordCount"] == completed["recordCount"]
    target = datetime.fromtimestamp(completed["retainUntil"], UTC)
    assert all(
        record["Retention"]["Mode"] == "COMPLIANCE"
        and record["Retention"]["RetainUntilDate"] >= target
        for record in module._fake_s3.objects.values()
        if record["LastModified"] <= datetime.fromtimestamp(completed["cutoverAt"], UTC)
    )


def test_async_retention_upgrades_a_legacy_applied_policy(monkeypatch: Any) -> None:
    """An older policy record without application fields must remain upgradeable."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-demo"
    table.put_item(
        Item={
            **module._item_key(tenant, "EVIDENCE_POLICY", "retention"),
            "tenant_id": tenant,
            "retention_days": 365,
            "revision": 4,
            "updated_at": 1,
            "updated_by": "legacy-operator",
            "rationale_hash": "0" * 64,
        }
    )
    response = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/retention-jobs",
            "POST",
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["security-operator"],
                "sub": "security-retention",
            },
            body={
                "requestId": "legacy-policy-upgrade",
                "expectedRevision": 4,
                "retentionDays": 730,
                "rationale": "Approved synthetic legacy-policy migration exercise.",
            },
        ),
    )
    assert response["statusCode"] == 202
    policy = module._evidence_policy(tenant)
    assert policy["revision"] == 5
    assert policy["retentionDays"] == 730
    assert policy["applicationStatus"] == "applying"


def test_async_retention_denies_bypass_and_keeps_the_increased_policy_on_failure(
    monkeypatch: Any,
) -> None:
    """Deny weak/stale/concurrent input and never roll future retention backward."""
    module, _table = _load_handler(monkeypatch)
    tenant = "tenant-demo"
    security = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "security-retention",
    }
    fleet = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "fleet-retention",
    }
    body = {
        "requestId": "retention-failure-a",
        "expectedRevision": 0,
        "retentionDays": 730,
        "rationale": "Approved synthetic retention failure exercise reference.",
    }
    denied = _invoke(
        module,
        _event("/api/enterprise/evidence/retention-jobs", "POST", claims=fleet, body=body),
    )
    assert denied["statusCode"] == 403
    monkeypatch.setattr(module, "_EVIDENCE_RETENTION_CUTOVER_SECONDS", 0)
    module._audit(tenant, "retention_failure_probe", "test", {"synthetic": True})
    for record in module._fake_s3.objects.values():
        record["LastModified"] = datetime.now(UTC) - timedelta(seconds=10)
    started = _invoke(
        module,
        _event("/api/enterprise/evidence/retention-jobs", "POST", claims=security, body=body),
    )
    assert started["statusCode"] == 202
    job_id = json.loads(started["body"])["id"]
    replay = _invoke(
        module,
        _event("/api/enterprise/evidence/retention-jobs", "POST", claims=security, body=body),
    )
    assert replay["statusCode"] == 202
    assert json.loads(replay["body"])["id"] == job_id
    concurrent = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/retention-jobs",
            "POST",
            claims=security,
            body={**body, "requestId": "concurrent", "expectedRevision": 1, "retentionDays": 900},
        ),
    )
    assert concurrent["statusCode"] == 409
    stale = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/retention-jobs",
            "POST",
            claims=security,
            body={**body, "requestId": "stale", "retentionDays": 900},
        ),
    )
    assert stale["statusCode"] == 409

    module._evidence_retention_schedule_cycle()
    message = module._fake_sqs.messages.pop(0)

    def deny_retention(**_value: Any) -> None:
        raise ObjectLockAccessDenied()

    put_retention = module.S3.put_object_retention
    monkeypatch.setattr(module.S3, "put_object_retention", deny_retention)
    failed = module.process_retention_queue_event(
        {
            "Records": [
                {
                    "eventSource": "aws:sqs",
                    "body": message["MessageBody"],
                    "attributes": {"ApproximateReceiveCount": "3"},
                }
            ]
        }
    )
    assert failed["status"] == "failed"
    assert failed["failureReason"] == "retention_provider_access_denied"
    assert failed["alertDelivered"] is True
    policy = module._evidence_policy(tenant)
    assert policy["retentionDays"] == 730
    assert policy["applicationStatus"] == "failed"
    assert policy["failureReason"] == "retention_provider_access_denied"
    monkeypatch.setattr(module.S3, "put_object_retention", put_retention)
    retry = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/retention-jobs",
            "POST",
            claims=security,
            body={
                **body,
                "requestId": "retention-failure-reconcile",
                "expectedRevision": 1,
            },
        ),
    )
    assert retry["statusCode"] == 202
    retried_policy = module._evidence_policy(tenant)
    assert retried_policy["retentionDays"] == 730
    assert retried_policy["revision"] == 2
    assert retried_policy["applicationStatus"] == "applying"
    cross_tenant = _invoke(
        module,
        _event(
            f"/api/enterprise/evidence/retention-jobs/{job_id}",
            "GET",
            claims={
                "custom:tenant_id": "tenant-other",
                "cognito:groups": ["security-operator"],
                "sub": "other-security",
            },
        ),
    )
    assert cross_tenant["statusCode"] == 403


def test_async_retention_repairs_a_committed_page_when_next_dispatch_fails(
    monkeypatch: Any,
) -> None:
    """Retrying the old message repairs the durable outbox gap without reapplying a page."""
    module, _table = _load_handler(monkeypatch)
    tenant = "tenant-demo"
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "security-retention",
    }
    for index in range(15):
        module._audit(tenant, "retention_dispatch_probe", "test", {"index": index})
    for record in module._fake_s3.objects.values():
        record["LastModified"] = datetime.now(UTC) - timedelta(seconds=10)
    monkeypatch.setattr(module, "_EVIDENCE_RETENTION_CUTOVER_SECONDS", 0)
    started = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/retention-jobs",
            "POST",
            claims=claims,
            body={
                "requestId": "dispatch-recovery-a",
                "expectedRevision": 0,
                "retentionDays": 730,
                "rationale": "Approved synthetic queue dispatch recovery exercise.",
            },
        ),
    )
    job_id = json.loads(started["body"])["id"]
    module._evidence_retention_schedule_cycle()
    message = module._fake_sqs.messages.pop(0)
    sender = module.SQS.send_message
    monkeypatch.setattr(
        module.SQS,
        "send_message",
        lambda **_value: (_ for _ in ()).throw(OSError("synthetic queue outage")),
    )
    with pytest.raises(OSError, match="synthetic queue outage"):
        module.process_retention_queue_event(
            {
                "Records": [
                    {
                        "eventSource": "aws:sqs",
                        "body": message["MessageBody"],
                        "attributes": {"ApproximateReceiveCount": "1"},
                    }
                ]
            }
        )
    committed = module._retention_job_record(tenant, job_id)
    assert committed["status"] == "queued"
    assert committed["page_count"] == 1
    monkeypatch.setattr(module.SQS, "send_message", sender)
    recovered = module.process_retention_queue_event(
        {
            "Records": [
                {
                    "eventSource": "aws:sqs",
                    "body": message["MessageBody"],
                    "attributes": {"ApproximateReceiveCount": "2"},
                }
            ]
        }
    )
    assert recovered == {"status": "queue_recovered"}
    assert len(module._fake_sqs.messages) == 1
    assert module._retention_job_record(tenant, job_id)["page_count"] == 1


def test_aws_async_retention_is_isolated_bounded_and_monitored() -> None:
    """Infrastructure must isolate irreversible retention work and its recovery path."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    assert 'handler: "retention_worker.handler"' in stack
    assert "EVIDENCE_RETENTION_QUEUE_URL: evidenceRetentionWorkerQueue.queueUrl" in stack
    assert 'source: "aai.evidence-retention"' in stack
    assert "schedule: events.Schedule.rate(cdk.Duration.minutes(1))" in stack
    assert "recursiveLoop: lambda.RecursiveLoop.ALLOW" in stack
    assert "reservedConcurrentExecutions: 5" in stack
    assert "EvidenceRetentionWorkerDeadLetters" in stack
    assert "EvidenceRetentionScheduleDeadLetters" in stack


def test_async_assurance_repairs_a_committed_page_when_next_dispatch_fails(
    monkeypatch: Any,
) -> None:
    """The read-only assurance worker must repair its committed-page outbox edge."""
    module, _table = _load_handler(monkeypatch)
    tenant = "tenant-demo"
    for index in range(15):
        module._audit(tenant, "assurance_dispatch_probe", "test", {"index": index})
    started = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/jobs",
            "POST",
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["security-operator"],
                "sub": "security-assurance",
            },
            body={
                "requestId": "assurance-dispatch-recovery",
                "rationale": "Approved synthetic assurance dispatch recovery exercise.",
            },
        ),
    )
    job_id = json.loads(started["body"])["id"]
    message = module._fake_sqs.messages.pop(0)
    sender = module.SQS.send_message
    monkeypatch.setattr(
        module.SQS,
        "send_message",
        lambda **_value: (_ for _ in ()).throw(OSError("synthetic assurance queue outage")),
    )
    with pytest.raises(OSError, match="synthetic assurance queue outage"):
        module.process_evidence_queue_event(
            {
                "Records": [
                    {
                        "eventSource": "aws:sqs",
                        "body": message["MessageBody"],
                        "attributes": {"ApproximateReceiveCount": "1"},
                    }
                ]
            }
        )
    committed = module._evidence_job_record(tenant, job_id)
    assert committed["status"] == "queued"
    assert committed["page_count"] == 1
    monkeypatch.setattr(module.SQS, "send_message", sender)
    recovered = module.process_evidence_queue_event(
        {
            "Records": [
                {
                    "eventSource": "aws:sqs",
                    "body": message["MessageBody"],
                    "attributes": {"ApproximateReceiveCount": "2"},
                }
            ]
        }
    )
    assert recovered == {"status": "queue_recovered"}
    assert len(module._fake_sqs.messages) == 1
    assert module._evidence_job_record(tenant, job_id)["page_count"] == 1


def test_regional_recovery_rebuilds_queues_only_from_revision_bound_jobs(
    monkeypatch: Any,
) -> None:
    """A recovery Region plans in standby and dispatches only after activation."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-recovery"
    now = int(time.time())
    table.items[(f"TENANT#{tenant}", "TENANT#root")] = {
        "pk": f"TENANT#{tenant}",
        "sk": "TENANT#root",
        "evidence_assurance_pk": "EVIDENCE_ASSURANCE#00",
        "evidence_assurance_sk": tenant,
    }
    evidence_key = module._item_key(tenant, "EVIDENCE_JOB", "assurance-a")
    table.items[(evidence_key["pk"], evidence_key["sk"])] = {
        **evidence_key,
        "tenant_id": tenant,
        "id": "assurance-a",
        "status": "queued",
        "revision": 4,
        "updated_at": now,
    }
    retention_key = module._item_key(tenant, "EVIDENCE_RETENTION_JOB", "retention-a")
    table.items[(retention_key["pk"], retention_key["sk"])] = {
        **retention_key,
        "tenant_id": tenant,
        "id": "retention-a",
        "status": "settling",
        "revision": 7,
        "policy_revision": 2,
        "cutover_at": now - 1,
        "updated_at": now,
    }
    policy_key = module._item_key(tenant, "EVIDENCE_POLICY", "retention")
    table.items[(policy_key["pk"], policy_key["sk"])] = {
        **policy_key,
        "tenant_id": tenant,
        "id": "retention",
        "revision": 2,
        "application_status": "applying",
        "application_job_id": "retention-a",
    }
    event = {
        "source": "aai.regional-transition-jobs",
        "schemaVersion": 2,
        "mode": "check",
        "activationEvidenceRef": "change/INC-1234",
        "direction": "failover",
        "targetRegion": "eu-west-1",
        "transitionId": "12345678-1234-4234-8234-123456789abc",
        "authoritySha256": "a" * 64,
    }
    monkeypatch.setenv("REGIONAL_CELL_ROLE", "recovery")
    checked = module.handler(event, None)
    assert checked["plannedActions"] == 2
    assert checked["dispatchedJobs"] == 0
    assert checked["queueSource"] == "authoritative-dynamodb-job-records"
    assert module._fake_sqs.messages == []

    with pytest.raises(PermissionError, match="does not match this cell"):
        module.handler({**event, "direction": "failback"}, None)
    with pytest.raises(PermissionError, match="does not match this cell"):
        module.handler({**event, "authoritySha256": "not-a-digest"}, None)
    assert module._fake_sqs.messages == []

    event["mode"] = "apply"
    with pytest.raises(PermissionError, match="not activated"):
        module.handler(event, None)
    monkeypatch.setenv("REGIONAL_JOB_RECONCILIATION_ENABLED", "true")
    applied = module.handler(event, None)
    assert applied["plannedActions"] == 2
    assert applied["dispatchedJobs"] == 2
    assert {message["MessageDeduplicationId"] for message in module._fake_sqs.messages} == {
        "assurance-a:4",
        "retention:retention-a:7",
    }


def test_regional_recovery_fails_closed_on_ambiguous_job_authority(monkeypatch: Any) -> None:
    """Recovery never chooses a live job winner from timestamps."""
    module, table = _load_handler(monkeypatch)
    clean_tenant = "tenant-clean"
    table.items[(f"TENANT#{clean_tenant}", "TENANT#root")] = {
        "pk": f"TENANT#{clean_tenant}",
        "sk": "TENANT#root",
        "evidence_assurance_pk": "EVIDENCE_ASSURANCE#00",
        "evidence_assurance_sk": clean_tenant,
    }
    clean_key = module._item_key(clean_tenant, "EVIDENCE_JOB", "clean-job")
    table.items[(clean_key["pk"], clean_key["sk"])] = {
        **clean_key,
        "tenant_id": clean_tenant,
        "id": "clean-job",
        "status": "queued",
        "revision": 3,
        "updated_at": int(time.time()),
    }
    tenant = "tenant-conflict"
    table.items[(f"TENANT#{tenant}", "TENANT#root")] = {
        "pk": f"TENANT#{tenant}",
        "sk": "TENANT#root",
        "evidence_assurance_pk": "EVIDENCE_ASSURANCE#00",
        "evidence_assurance_sk": tenant,
    }
    for identifier in ("job-a", "job-b"):
        key = module._item_key(tenant, "EVIDENCE_JOB", identifier)
        table.items[(key["pk"], key["sk"])] = {
            **key,
            "tenant_id": tenant,
            "id": identifier,
            "status": "queued",
            "revision": 1,
            "updated_at": int(time.time()),
        }
    monkeypatch.setenv("REGIONAL_CELL_ROLE", "recovery")
    monkeypatch.setenv("REGIONAL_JOB_RECONCILIATION_ENABLED", "true")
    with pytest.raises(RuntimeError, match="authority contains conflicts"):
        module.handler(
            {
                "source": "aai.regional-transition-jobs",
                "schemaVersion": 2,
                "mode": "apply",
                "activationEvidenceRef": "change/INC-5678",
                "direction": "failover",
                "targetRegion": "eu-west-1",
                "transitionId": "12345678-1234-4234-8234-123456789abc",
                "authoritySha256": "b" * 64,
            },
            None,
        )
    assert module._fake_sqs.messages == []


def test_async_evidence_job_completes_all_pages_and_binds_export(monkeypatch: Any) -> None:
    """Scan beyond the synchronous bound and verify every derived export page."""
    module, _table = _load_handler(monkeypatch)
    tenant = "tenant-demo"
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "security-a",
    }
    for index in range(23):
        module._audit(tenant, "async_evidence_probe", "test", {"index": index})
    for (key, _version), record in module._fake_s3.objects.items():
        if key.startswith(f"tenant={tenant}/"):
            record["LastModified"] = datetime.now(UTC) - timedelta(seconds=10)

    started = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/jobs",
            "POST",
            claims=claims,
            body={
                "requestId": "async-export-a",
                "rationale": "Run complete synthetic tenant assurance and export.",
            },
        ),
    )
    assert started["statusCode"] == 202
    job_id = json.loads(started["body"])["id"]
    processed = 0
    while module._fake_sqs.messages:
        message = module._fake_sqs.messages.pop(0)
        result = module.process_evidence_queue_event(
            {
                "Records": [
                    {
                        "eventSource": "aws:sqs",
                        "body": message["MessageBody"],
                        "attributes": {"ApproximateReceiveCount": "1"},
                    }
                ]
            }
        )
        processed += 1
        assert result["status"] in {"queued", "completed"}
        assert processed < 20

    response = _invoke(
        module,
        _event(f"/api/enterprise/evidence/jobs/{job_id}", "GET", claims=claims),
    )
    assert response["statusCode"] == 200
    job = json.loads(response["body"])
    assert job["status"] == "completed"
    assert job["recordCount"] == 23
    assert job["verifiedCount"] == 23
    assert job["atRiskCount"] == 0
    assert job["pageCount"] >= 3

    chain = module._EVIDENCE_INITIAL_CHAIN_HASH
    exported_records = []
    for page_number in range(1, job["pageCount"] + 1):
        page_response = _invoke(
            module,
            _event(
                f"/api/enterprise/evidence/jobs/{job_id}/pages/{page_number}",
                "GET",
                claims=claims,
            ),
        )
        assert page_response["statusCode"] == 200
        page = json.loads(page_response["body"])
        page_hash = page.pop("contentSha256")
        assert (
            page_hash
            == hashlib.sha256(
                json.dumps(page, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )
        chain = hashlib.sha256(f"{chain}:{page_hash}".encode()).hexdigest()
        exported_records.extend(page["records"])
    assert len(exported_records) == 23
    assert chain == job["chainSha256"]
    index = job["exportIndex"]
    index_hash = index.pop("contentSha256")
    assert (
        index_hash
        == hashlib.sha256(
            json.dumps(index, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    assert index_hash == job["contentSha256"]

    assurance = json.loads(
        _invoke(module, _event("/api/enterprise/evidence", "GET", claims=claims))["body"]
    )
    assert assurance["latestAsyncJob"]["id"] == job_id
    assert assurance["monitor"]["status"] == "healthy"


def test_async_evidence_job_denies_bypass_tamper_and_terminal_provider_failure(
    monkeypatch: Any,
) -> None:
    """Deny weak roles/cross-tenant reads and expose no unverifiable derived page."""
    module, _table = _load_handler(monkeypatch)
    tenant = "tenant-demo"
    security = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "security-a",
    }
    fleet = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "fleet-a",
    }
    denied = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/jobs",
            "POST",
            claims=fleet,
            body={"requestId": "denied", "rationale": "Unauthorized synthetic request."},
        ),
    )
    assert denied["statusCode"] == 403

    module._audit(tenant, "async_tamper_probe", "test", {"synthetic": True})
    for (key, _version), record in module._fake_s3.objects.items():
        if key.startswith(f"tenant={tenant}/"):
            record["LastModified"] = datetime.now(UTC) - timedelta(seconds=10)
    started = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/jobs",
            "POST",
            claims=security,
            body={
                "requestId": "tamper-a",
                "rationale": "Verify synthetic derived-page tamper detection.",
            },
        ),
    )
    job_id = json.loads(started["body"])["id"]
    while module._fake_sqs.messages:
        message = module._fake_sqs.messages.pop(0)
        module.process_evidence_queue_event(
            {
                "Records": [
                    {
                        "eventSource": "aws:sqs",
                        "body": message["MessageBody"],
                        "attributes": {"ApproximateReceiveCount": "1"},
                    }
                ]
            }
        )
    page_key = module._evidence_report_page_key(tenant, job_id, 1)
    page_versions = [
        record for (key, _version), record in module._fake_s3.objects.items() if key == page_key
    ]
    page_versions[-1]["Body"] += b"tampered"
    tampered = _invoke(
        module,
        _event(f"/api/enterprise/evidence/jobs/{job_id}/pages/1", "GET", claims=security),
    )
    assert tampered["statusCode"] == 500
    cross_tenant = _invoke(
        module,
        _event(
            f"/api/enterprise/evidence/jobs/{job_id}",
            "GET",
            claims={
                "custom:tenant_id": "tenant-other",
                "cognito:groups": ["security-operator"],
                "sub": "security-other",
            },
        ),
    )
    assert cross_tenant["statusCode"] == 403

    failed_start = _invoke(
        module,
        _event(
            "/api/enterprise/evidence/jobs",
            "POST",
            claims=security,
            body={
                "requestId": "provider-failure-a",
                "rationale": "Prove terminal provider failures remain visible.",
            },
        ),
    )
    assert json.loads(failed_start["body"])["status"] == "queued"
    failed_message = module._fake_sqs.messages.pop(0)

    def deny_inventory(**_value: Any) -> dict[str, Any]:
        raise ObjectLockAccessDenied()

    monkeypatch.setattr(module._fake_s3, "list_object_versions", deny_inventory)
    failure = module.process_evidence_queue_event(
        {
            "Records": [
                {
                    "eventSource": "aws:sqs",
                    "body": failed_message["MessageBody"],
                    "attributes": {"ApproximateReceiveCount": "3"},
                }
            ]
        }
    )
    assert failure["status"] == "failed"
    assert failure["failureReason"] == "evidence_provider_access_denied"
    monitor = module._evidence_monitor_view(module._evidence_monitor_record(tenant))
    assert monitor["status"] == "critical"
    assert monitor["alertDelivered"] is True


def test_scheduled_evidence_assurance_starts_once_and_rejects_forged_events(
    monkeypatch: Any,
) -> None:
    """Use the tenant index once per due window and validate internal event shape."""
    module, _table = _load_handler(monkeypatch)
    module._seed("tenant-demo")

    first = module.handler({"source": "aai.evidence-assurance", "schemaVersion": 1}, None)
    assert first == {"processedTenants": 1, "startedJobs": 1, "activeJobs": 0}
    second = module.handler({"source": "aai.evidence-assurance", "schemaVersion": 1}, None)
    assert second == {"processedTenants": 1, "startedJobs": 0, "activeJobs": 1}
    assert len(module._fake_sqs.messages) == 1
    with pytest.raises(ValueError, match="schedule event is invalid"):
        module.handler(
            {
                "source": "aai.evidence-assurance",
                "schemaVersion": 1,
                "tenantId": "tenant-forged",
            },
            None,
        )


def test_evidence_monitor_retries_pending_delivery_and_preserves_receipt(
    monkeypatch: Any,
) -> None:
    """An unchanged gap retries failed delivery and retains its acknowledgement."""
    module, _table = _load_handler(monkeypatch)
    tenant = "tenant-demo"
    module._seed(tenant)
    failed_job = {"id": "job-failed", "status": "failed", "failure_reason": "test_failure"}
    module._fake_sns.failures_remaining = 1

    pending = module._reconcile_evidence_monitor(tenant, failed_job)
    assert pending["delivery_status"] == "pending"
    delivered = module._reconcile_evidence_monitor(tenant, failed_job)
    assert delivered["delivery_status"] == "delivered"
    assert len(module._fake_sns.messages) == 1
    receipt = delivered["delivered_at"]

    unchanged = module._reconcile_evidence_monitor(tenant, failed_job)
    assert unchanged["delivery_status"] == "delivered"
    assert unchanged["delivered_at"] == receipt
    assert len(module._fake_sns.messages) == 1

    declining_tenant = "tenant-declining"
    module._put(
        declining_tenant,
        "TENANT",
        "root",
        {"id": declining_tenant, "status": "active"},
    )
    declining = module._reconcile_evidence_monitor(
        declining_tenant,
        {
            "id": "job-declining",
            "status": "completed",
            "record_count": 2,
            "baseline_record_count": Decimal("3"),
            "at_risk_count": 0,
            "delete_marker_count": 0,
        },
    )
    assert declining["status"] == "attention"
    assert declining["reason_codes"] == ["retained_record_count_decreased"]


def test_evidence_policy_rejects_non_integral_stored_authority(monkeypatch: Any) -> None:
    """Malformed DynamoDB numeric authority cannot be truncated into a valid policy."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-demo"
    module._seed(tenant)
    table.put_item(
        Item={
            **module._item_key(tenant, "EVIDENCE_POLICY", "retention"),
            "tenant_id": tenant,
            "retention_days": Decimal("365.5"),
            "revision": Decimal("1.1"),
        }
    )
    response = _invoke(
        module,
        _event(
            "/api/enterprise/evidence",
            "GET",
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": ["auditor"],
                "sub": "auditor-a",
            },
        ),
    )
    assert response["statusCode"] == 500


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
    *,
    policy_version: int = 1,
    with_trust: bool = False,
    host: AgentHost = AgentHost.CLAUDE_CODE,
) -> tuple[ManagedDeploymentPackage, dict[str, Any]]:
    """Build canonical package bytes and matching AWS desired-host metadata."""
    hook_path = "/opt/aai-security/hooks/native-policy"
    bundle = ManagedConfigurationCompiler().compile(
        ManagedPolicyIntent(
            "policy-safe",
            policy_version,
            action_rules=(NativeActionRule("Read", NativeActionDecision.ALLOW, "synthetic read"),),
        ),
        host=host,
        host_version="0.146.0" if host is AgentHost.CODEX_CLI else "2.1.220",
        platform=ManagedPlatform.LINUX,
        hook_command=hook_path,
    )
    trust_store = (
        PolicyTrustStore(
            tuple(
                TrustedPolicyKey(key_id, _SYNTHETIC_P256_PUBLIC_PEM)
                for key_id in (
                    "arn:aws:kms:eu-west-2:111111111111:key/12345678-1234-1234-1234-123456789abc",
                    "arn:aws:kms:eu-west-2:111111111111:key/mrk-1234567890abcdef1234567890abcdef",
                    "arn:aws:kms:eu-west-1:111111111111:key/mrk-1234567890abcdef1234567890abcdef",
                )
            )
        )
        if with_trust
        else None
    )
    package = ManagedDeploymentPackage.from_bundle(
        bundle,
        required_executables=(
            ManagedExecutableRequirement(hook_path, hashlib.sha256(b"synthetic hook").hexdigest()),
        ),
        policy_trust_store=trust_store,
    )
    desired = {
        "host": package.host.value,
        "hostVersion": package.host_version,
        "platform": package.platform.value,
        "bundleHash": package.bundle_hash,
        "policyId": package.policy_id,
        "policyVersion": package.policy_version,
    }
    if package.policy_trust_bundle_sha256 is not None:
        desired["policyTrustBundleSha256"] = package.policy_trust_bundle_sha256
    return package, desired


def _set_runtime_manifests(monkeypatch: Any, manifests: list[dict[str, Any]]) -> None:
    """Install synthetic manifests with an exact release-approval binding."""
    raw = json.dumps(manifests)
    approval = {
        "schemaVersion": 1,
        "manifestBundleSha256": hashlib.sha256(raw.encode()).hexdigest(),
        "approvals": [],
    }
    if manifests:
        approval["approvals"] = [
            {
                "hosts": [manifest["host"]],
                "releaseEvidenceSha256": "9" * 64,
                "releaseTag": f"v{manifest['sdkVersion']}",
                "sdkRevision": manifest["sdkRevision"],
                "sdkVersion": manifest["sdkVersion"],
                "sourceOriginDigest": manifest["sourceOriginDigest"],
            }
            for manifest in manifests
        ]
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


def _native_missing_evidence(now: int) -> dict[str, Any]:
    """Return synthetic closed Codex process evidence for AWS contracts."""
    return {
        "host": "codex-cli",
        "hostVersion": "0.146.0",
        "platform": "linux",
        "bundleHash": "d" * 64,
        "state": "missing",
        "reason": "administrator-requirements-missing",
        "expectedDigest": "a" * 64,
        "observedDigest": "b" * 64,
        "approvalPolicy": "on-request",
        "sandboxMode": "workspace-write",
        "defaultPermissions": None,
        "webSearchMode": None,
        "managedMcpServerNames": [],
        "unexpectedMcpServerCount": 1,
        "preToolHookSha256": ["c" * 64],
        "requirements": None,
        "securityOrigins": {"approval_policy": "user"},
        "mismatches": [],
        "unverifiedControls": [],
        "allowedActions": [],
        "deniedActions": ["Read"],
        "approvalRequiredActions": [],
        "verifiedAt": now,
        "expiresAt": now + 60,
    }


def _native_enforced_evidence(now: int, bundle_hash: str) -> dict[str, Any]:
    """Return synthetic positive Codex evidence with no unresolved controls."""
    return {
        **_native_missing_evidence(now),
        "bundleHash": bundle_hash,
        "state": "enforced",
        "reason": "effective-controls-match",
        "defaultPermissions": ":workspace",
        "webSearchMode": "cached",
        "unexpectedMcpServerCount": 0,
        "requirements": {
            "allowedApprovalPolicies": ["on-request"],
            "defaultPermissions": ":workspace",
            "allowedPermissionProfiles": {":workspace": True},
            "allowedSandboxModes": [],
            "allowedWebSearchModes": ["cached"],
            "allowManagedHooksOnly": True,
            "featureRequirements": {"hooks": True},
            "network": {
                "enabled": None,
                "managedAllowedDomainsOnly": None,
                "domains": {},
            },
        },
        "securityOrigins": {"approval_policy": "system"},
        "allowedActions": ["Read"],
        "deniedActions": ["Bash(rm *)"],
    }


def test_native_effective_controls_are_content_minimised_and_freshness_derived(
    monkeypatch: Any,
) -> None:
    """AWS storage rejects extensions and derives stale state on every read."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-native-controls"
    now = 1_900_000_000
    evidence = _native_missing_evidence(now)
    desired = {
        "host": "codex-cli",
        "hostVersion": "0.146.0",
        "platform": "linux",
        "bundleHash": evidence["bundleHash"],
        "policyId": "policy-safe",
        "policyVersion": 1,
    }
    table.put_item(
        Item=module._item_key(tenant, "CONFIGURATION", "dep-a")
        | {"desiredConfiguration": {"managedHost": desired}}
    )
    agent = {
        "id": "codex-a",
        "deployment_id": "dep-a",
        "host": "codex-cli",
        "native_effective_controls_report": module._native_effective_controls(evidence),
    }

    normalized = module._native_effective_controls(evidence)
    assert normalized == evidence
    posture = module._native_effective_control_posture(tenant, agent, now=now)
    assert posture == {
        "status": "missing",
        "desired": {
            "bundleHash": evidence["bundleHash"],
            "hostVersion": "0.146.0",
            "platform": "linux",
        },
        "observed": evidence,
    }
    assert module._agent_control_state(tenant, agent)["authorityBlockers"] == [
        "native_effective_controls"
    ]
    table.put_item(Item=module._item_key(tenant, "AGENT", "dep-a:codex-a") | agent)
    table.put_item(
        Item=module._item_key(tenant, "POLICY", "policy-safe") | {"id": "policy-safe", "version": 1}
    )
    table.put_item(
        Item=module._item_key(tenant, "GROUP", "group-safe")
        | {
            "id": "group-safe",
            "policyId": "policy-safe",
            "agent_keys": ["dep-a:codex-a"],
        }
    )
    verification = module._verify_agent(tenant, "dep-a", "codex-a")
    assert verification["checks"]["nativeEffectiveControls"]["passed"] is False
    assert verification["checks"]["emergencyStop"]["passed"] is True
    assert (
        module._native_effective_control_posture(tenant, agent, now=now + 61)["status"] == "stale"
    )
    forged = _native_enforced_evidence(now, "e" * 64)
    agent["native_effective_controls_report"] = module._native_effective_controls(forged)
    assert module._native_effective_control_posture(tenant, agent, now=now)["status"] == "conflict"
    assert module._agent_control_state(tenant, agent)["executionAllowed"] is False
    agent["native_effective_controls_report"] = module._native_effective_controls(
        _native_enforced_evidence(now, evidence["bundleHash"])
    )
    monkeypatch.setattr(module.time, "time", lambda: now)
    assert module._agent_control_state(tenant, agent)["executionAllowed"] is True
    module._require_current_native_effective_controls(tenant, agent)
    hostile = dict(evidence, rawConfig={"Authorization": "Bearer synthetic-secret"})
    with pytest.raises(ValueError, match="invalid schema") as caught:
        module._native_effective_controls(hostile)
    assert "synthetic-secret" not in str(caught.value)
    with pytest.raises(ValueError, match="digest is invalid"):
        module._native_effective_controls({**evidence, "bundleHash": "not-a-digest"})


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


def test_cloud_credential_broker_authority_is_machine_attested_and_live_revocable(
    monkeypatch: Any,
) -> None:
    """Provider scope is inert until a machine adapter proves it and remains revocable."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-cloud-broker"
    other_tenant = "tenant-cloud-other"
    now = 1_800_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    for tenant_id in (tenant, other_tenant):
        table.put_item(Item=module._item_key(tenant_id, "TENANT", "root") | {"id": tenant_id})
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-cloud-admin",
    }
    broker_request = {
        "brokerId": "azure-production-read",
        "name": "Azure production metadata",
        "provider": "azure_workload_identity",
        "principal": ("11111111-2222-4333-8444-555555555555/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
        "audience": "https://vault.example.test",
        "allowedTools": ["read_secret_metadata"],
        "resourceIds": ["vault:synthetic"],
        "maxTtlSeconds": 300,
    }
    created_response = _invoke(
        module,
        _event(
            "/api/enterprise/credential-brokers",
            "POST",
            claims=platform,
            body=broker_request,
        ),
    )
    assert created_response["statusCode"] == 201
    created = json.loads(created_response["body"])
    assert created["verificationStatus"] == "unverified"
    assert created["executionAllowed"] is False
    assert not {
        "clientSecret",
        "accessToken",
        "subjectToken",
        "credential",
        "credentialKey",
    } & set(created)

    integrations = json.loads(
        _invoke(module, _event("/api/enterprise/integrations", "GET", claims=platform))["body"]
    )
    assert integrations["credentialBrokers"] == [created]
    other_integrations = json.loads(
        _invoke(
            module,
            _event(
                "/api/enterprise/integrations",
                "GET",
                claims={
                    "custom:tenant_id": other_tenant,
                    "cognito:groups": ["platform-admin"],
                    "sub": "other-cloud-admin",
                },
            ),
        )["body"]
    )
    assert other_integrations["credentialBrokers"] == []

    service_identity = json.loads(
        _invoke(
            module,
            _event(
                "/api/enterprise/identity/service-identities",
                "POST",
                claims=platform,
                body={
                    "serviceIdentityId": "azure-broker-adapter",
                    "name": "Azure broker adapter",
                    "description": "Attests exact synthetic cloud scope for the runtime.",
                    "purpose": "Bind cloud provider evidence to server-owned broker authority.",
                    "capabilities": ["credential_broker_runtime"],
                    "expiresInDays": 30,
                },
            ),
        )["body"]
    )
    token = service_identity["credential"]["accessToken"]
    evidence = {
        "schemaVersion": 1,
        "expectedRevision": created["revision"],
        "provider": created["provider"],
        "principal": created["principal"],
        "audience": created["audience"],
        "allowedTools": created["allowedTools"],
        "resourceIds": created["resourceIds"],
        "maxTtlSeconds": created["maxTtlSeconds"],
        "configurationHash": created["configurationHash"],
        "observedAt": now,
        "expiresAt": now + 900,
        "checks": {
            "identityBound": True,
            "scopeBound": True,
            "ttlBound": True,
            "revocationReady": True,
        },
        "evidenceDigest": "a" * 64,
    }
    human_forgery = _invoke(
        module,
        _event(
            "/api/enterprise/credential-brokers/azure-production-read/evidence",
            "POST",
            claims=platform,
            body=evidence,
        ),
    )
    assert human_forgery["statusCode"] == 403

    for invalid_evidence in (
        {**evidence, "observedAt": now + 1},
        {**evidence, "allowedTools": [1]},
    ):
        assert (
            _invoke(
                module,
                _event(
                    "/machine/v1/enterprise/credential-brokers/azure-production-read/evidence",
                    "POST",
                    token=token,
                    body=invalid_evidence,
                ),
            )["statusCode"]
            == 400
        )

    verified_response = _invoke(
        module,
        _event(
            "/machine/v1/enterprise/credential-brokers/azure-production-read/evidence",
            "POST",
            token=token,
            body=evidence,
        ),
    )
    assert verified_response["statusCode"] == 200
    verified = json.loads(verified_response["body"])
    assert verified["verificationStatus"] == "verified"
    assert verified["executionAllowed"] is True
    authority_path = "/machine/v1/enterprise/credential-brokers/azure-production-read/authority"
    authority = json.loads(_invoke(module, _event(authority_path, "GET", token=token))["body"])
    assert authority == {
        "brokerId": "azure-production-read",
        "executionAllowed": True,
        "verificationStatus": "verified",
        "revision": 1,
        "revocationEpoch": 1,
        "configurationHash": created["configurationHash"],
    }

    monkeypatch.setattr(module.time, "time", lambda: now + 901)
    stale = json.loads(_invoke(module, _event(authority_path, "GET", token=token))["body"])
    assert stale["verificationStatus"] == "stale"
    assert stale["executionAllowed"] is False

    evidence["observedAt"] = now + 901
    evidence["expiresAt"] = now + 1801
    assert (
        _invoke(
            module,
            _event(
                "/machine/v1/enterprise/credential-brokers/azure-production-read/evidence",
                "POST",
                token=token,
                body=evidence,
            ),
        )["statusCode"]
        == 200
    )
    revoked_response = _invoke(
        module,
        _event(
            "/api/enterprise/credential-brokers/azure-production-read/revoke",
            "POST",
            claims=platform,
            body={"expectedRevision": 1, "reason": "Synthetic incident containment."},
        ),
    )
    assert revoked_response["statusCode"] == 200
    revoked = json.loads(revoked_response["body"])
    assert revoked["status"] == "revoked"
    assert revoked["revocationEpoch"] == 2
    assert revoked["executionAllowed"] is False
    after_revoke = json.loads(_invoke(module, _event(authority_path, "GET", token=token))["body"])
    assert after_revoke["verificationStatus"] == "revoked"
    assert after_revoke["executionAllowed"] is False


@pytest.mark.parametrize(
    "override",
    [
        {"provider": "unsupported"},
        {"principal": "client-secret-value"},
        {"audience": "http://unsafe.example.test"},
        {"allowedTools": ["read", "read"]},
        {"resourceIds": []},
        {"maxTtlSeconds": 3601},
        {
            "provider": "aws_sts",
            "principal": "arn:aws:iam::123456789012:role/aai-sec-scoped-tool",
            "audience": "sts.amazonaws.com",
            "maxTtlSeconds": 300,
        },
        {"clientSecret": "synthetic-value"},  # noqa: S106 - rejected test input
    ],
)
def test_cloud_credential_broker_registration_rejects_unsafe_authority(
    monkeypatch: Any, override: dict[str, Any]
) -> None:
    """Malformed, duplicated, or unbounded scope never enters tenant state."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-cloud-invalid"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-cloud-admin",
    }
    request = {
        "brokerId": "azure-invalid",
        "name": "Invalid synthetic broker",
        "provider": "azure_workload_identity",
        "principal": ("11111111-2222-4333-8444-555555555555/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
        "audience": "https://vault.example.test",
        "allowedTools": ["read"],
        "resourceIds": ["vault:synthetic"],
        "maxTtlSeconds": 300,
        **override,
    }
    response = _invoke(
        module,
        _event(
            "/api/enterprise/credential-brokers",
            "POST",
            claims=platform,
            body=request,
        ),
    )
    assert response["statusCode"] == 400
    assert module._list(tenant, "CREDENTIAL_BROKER", consistent_read=True) == []


def test_isolation_profile_authority_is_machine_evidenced_and_live_revocable(
    monkeypatch: Any,
) -> None:
    """A registered profile stays blocked until exact runtime evidence is current."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-isolation-authority"
    other_tenant = "tenant-isolation-other"
    now = 1_800_100_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    for tenant_id in (tenant, other_tenant):
        table.put_item(Item=module._item_key(tenant_id, "TENANT", "root") | {"id": tenant_id})
    table.put_item(
        Item=module._item_key(tenant, "ORG", "org-isolation")
        | {"id": "org-isolation", "name": "Isolation org"}
    )
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-isolation-admin",
    }
    constraints = {
        "filesystemReadOnly": True,
        "networkMode": "none",
        "allowedNetworkDestinations": [],
        "processNamespace": True,
        "maxMemoryMib": 256,
        "maxPids": 64,
        "cpuLimitMillicores": 1000,
        "maxDurationSeconds": 30,
        "credentialMode": "none",
        "noNewPrivileges": True,
        "capabilitiesDropped": True,
    }
    request = {
        "profileId": "docker-hostile-code",
        "name": "Docker hostile code",
        "provider": "docker_engine",
        "boundary": "container",
        "workloadRef": "sha256:" + "a" * 64,
        "allowedTools": ["compile_untrusted"],
        "constraints": constraints,
    }
    created_response = _invoke(
        module,
        _event("/api/enterprise/isolation-profiles", "POST", claims=platform, body=request),
    )
    assert created_response["statusCode"] == 201
    created = json.loads(created_response["body"])
    assert created["verificationStatus"] == "unverified"
    assert created["executionAllowed"] is False
    assert "signature" not in created and "credential" not in created

    policy_response = _invoke(
        module,
        _event(
            "/api/enterprise/policies",
            "POST",
            claims=platform,
            body={
                "policyId": "policy-attested-code",
                "organizationId": "org-isolation",
                "name": "Attested code execution",
                "configuration": {
                    "tools": {"allowed": ["compile_untrusted"]},
                    "isolation": {
                        "verifier": "deployment_attested",
                        "requiredForHighRisk": True,
                        "mode": "required",
                        "acceptedProfiles": [created["id"]],
                    },
                },
            },
        ),
    )
    assert policy_response["statusCode"] == 201, policy_response["body"]
    unavailable_policy = _invoke(
        module,
        _event(
            "/api/enterprise/policies",
            "POST",
            claims=platform,
            body={
                "policyId": "policy-unknown-isolation",
                "organizationId": "org-isolation",
                "name": "Unknown isolation",
                "configuration": {"isolation": {"acceptedProfiles": ["profile-does-not-exist"]}},
            },
        ),
    )
    assert unavailable_policy["statusCode"] == 400

    integrations = json.loads(
        _invoke(module, _event("/api/enterprise/integrations", "GET", claims=platform))["body"]
    )
    assert integrations["isolationProfiles"] == [created]
    other = {
        "custom:tenant_id": other_tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "other-admin",
    }
    assert (
        json.loads(
            _invoke(module, _event("/api/enterprise/integrations", "GET", claims=other))["body"]
        )["isolationProfiles"]
        == []
    )

    service_identity = json.loads(
        _invoke(
            module,
            _event(
                "/api/enterprise/identity/service-identities",
                "POST",
                claims=platform,
                body={
                    "serviceIdentityId": "isolation-runtime",
                    "name": "Isolation runtime",
                    "description": "Reports exact synthetic sandbox evidence.",
                    "purpose": "Bind runtime evidence to reviewed isolation profiles.",
                    "capabilities": ["isolation_runtime"],
                    "expiresInDays": 30,
                },
            ),
        )["body"]
    )
    token = service_identity["credential"]["accessToken"]
    evidence = {
        "schemaVersion": 1,
        "expectedRevision": created["revision"],
        "provider": created["provider"],
        "boundary": created["boundary"],
        "workloadRef": created["workloadRef"],
        "allowedTools": created["allowedTools"],
        "constraints": created["constraints"],
        "configurationHash": created["configurationHash"],
        "observedAt": now,
        "expiresAt": now + 900,
        "checks": {
            "boundaryCreated": True,
            "workloadDigestVerified": True,
            "filesystemEnforced": True,
            "networkEnforced": True,
            "processEnforced": True,
            "resourcesEnforced": True,
            "credentialIsolationEnforced": True,
            "escapeProbePassed": True,
        },
        "evidenceDigest": "b" * 64,
    }
    assert (
        _invoke(
            module,
            _event(
                "/api/enterprise/isolation-profiles/docker-hostile-code/evidence",
                "POST",
                claims=platform,
                body=evidence,
            ),
        )["statusCode"]
        == 403
    )
    for invalid in (
        {**evidence, "observedAt": now + 1},
        {**evidence, "constraints": {**constraints, "maxPids": 65}},
        {**evidence, "checks": {**evidence["checks"], "escapeProbePassed": False}},
    ):
        assert (
            _invoke(
                module,
                _event(
                    "/machine/v1/enterprise/isolation-profiles/docker-hostile-code/evidence",
                    "POST",
                    token=token,
                    body=invalid,
                ),
            )["statusCode"]
            == 400
        )

    verified = json.loads(
        _invoke(
            module,
            _event(
                "/machine/v1/enterprise/isolation-profiles/docker-hostile-code/evidence",
                "POST",
                token=token,
                body=evidence,
            ),
        )["body"]
    )
    assert verified["executionAllowed"] is True
    authority_path = "/machine/v1/enterprise/isolation-profiles/docker-hostile-code/authority"
    authority = json.loads(_invoke(module, _event(authority_path, "GET", token=token))["body"])
    assert authority == {
        "profileId": "docker-hostile-code",
        "executionAllowed": True,
        "verificationStatus": "verified",
        "revision": 1,
        "revocationEpoch": 1,
        "configurationHash": created["configurationHash"],
    }

    monkeypatch.setattr(module.time, "time", lambda: now + 901)
    stale = json.loads(_invoke(module, _event(authority_path, "GET", token=token))["body"])
    assert stale["executionAllowed"] is False
    assert stale["verificationStatus"] == "stale"
    revoked = json.loads(
        _invoke(
            module,
            _event(
                "/api/enterprise/isolation-profiles/docker-hostile-code/revoke",
                "POST",
                claims=platform,
                body={"expectedRevision": 1, "reason": "Synthetic escape review."},
            ),
        )["body"]
    )
    assert revoked["status"] == "revoked"
    assert revoked["revocationEpoch"] == 2
    assert revoked["executionAllowed"] is False


@pytest.mark.parametrize(
    "override",
    [
        {"provider": "unsupported"},
        {"boundary": "microvm"},
        {"workloadRef": "worker:latest"},
        {"allowedTools": ["compile", "compile"]},
        {"constraints": {"filesystemReadOnly": True}},
        {"constraints": {"networkMode": "none", "allowedNetworkDestinations": ["*"]}},
        {"secret": "synthetic-value"},  # noqa: S106 - rejected test input
    ],
)
def test_isolation_profile_registration_rejects_unsafe_authority(
    monkeypatch: Any, override: dict[str, Any]
) -> None:
    """Mutable, weaker, wildcard, secret-bearing, or malformed profiles never persist."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-isolation-invalid"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-isolation-admin",
    }
    constraints = {
        "filesystemReadOnly": True,
        "networkMode": "none",
        "allowedNetworkDestinations": [],
        "processNamespace": True,
        "maxMemoryMib": 256,
        "maxPids": 64,
        "cpuLimitMillicores": 1000,
        "maxDurationSeconds": 30,
        "credentialMode": "none",
        "noNewPrivileges": True,
        "capabilitiesDropped": True,
    }
    request = {
        "profileId": "invalid-profile",
        "name": "Invalid profile",
        "provider": "docker_engine",
        "boundary": "container",
        "workloadRef": "sha256:" + "a" * 64,
        "allowedTools": ["compile"],
        "constraints": constraints,
        **override,
    }
    response = _invoke(
        module,
        _event("/api/enterprise/isolation-profiles", "POST", claims=platform, body=request),
    )
    assert response["statusCode"] == 400
    assert module._list(tenant, "ISOLATION_PROFILE", consistent_read=True) == []


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
    assert module._delegated_scope_lineage(tenant, "tenant", tenant) == {"tenant": tenant}
    assert module._delegated_scope_lineage(tenant, "project", "project-a") == {
        "tenant": tenant,
        "organization": "org-a",
        "project": "project-a",
    }
    with pytest.raises(LookupError, match="tenant scope"):
        module._delegated_scope_lineage(tenant, "tenant", "another-tenant")
    spaced_environment_scope = module._mutation_resource_scope(
        tenant,
        _event(
            "/enterprise/deployments",
            "POST",
            body={"projectId": "project-a", "environment": "Development EU"},
        ),
        "/enterprise/deployments",
    )
    assert spaced_environment_scope == {
        "tenant": tenant,
        "organization": "org-a",
        "project": "project-a",
        "environment": "Development EU",
    }
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


def test_custom_role_requires_independent_approval_and_binds_environment_scope(
    monkeypatch: Any,
) -> None:
    """Custom authority is immutable, independently approved and exactly scoped."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-custom-role"
    for item in (
        module._item_key(tenant, "TENANT", "root") | {"id": tenant},
        module._item_key(tenant, "ORG", "org-a") | {"id": "org-a", "name": "A"},
        module._item_key(tenant, "PROJECT", "project-a")
        | {"id": "project-a", "organization_id": "org-a", "name": "A project"},
        module._item_key(tenant, "DEPLOYMENT", "dev-existing")
        | {
            "id": "dev-existing",
            "organization_id": "org-a",
            "project_id": "project-a",
            "environment": "development",
            "name": "Development",
        },
        module._item_key(tenant, "DEPLOYMENT", "prod-existing")
        | {
            "id": "prod-existing",
            "organization_id": "org-a",
            "project_id": "project-a",
            "environment": "production",
            "name": "Production",
        },
    ):
        table.put_item(Item=item)
    admin_a = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "admin-a",
    }
    admin_b = {**admin_a, "sub": "admin-b"}
    role_path = "/enterprise/identity/custom-roles"
    created = _invoke(
        module,
        _event(
            role_path,
            "POST",
            body={
                "customRoleId": "development-fleet-operator",
                "name": "Development fleet operator",
                "description": "Operate development deployments without production authority.",
                "capabilities": ["fleet_write", "inventory_read"],
                "reason": "Delegate bounded development fleet operations to the platform team",
            },
            claims=admin_a,
        ),
    )
    assert created["statusCode"] == 201
    draft = json.loads(created["body"])
    assert draft["status"] == "draft"
    assert draft["revision"] == 1
    assert len(draft["authorityDigest"]) == 64

    before_approval = _invoke(
        module,
        _event(
            "/enterprise/identity/delegated-grants",
            "POST",
            body={
                "principalId": "operator-a",
                "roleType": "custom",
                "role": draft["id"],
                "scopeType": "environment",
                "scopeId": "development",
                "durationDays": 30,
                "reason": "Operate only the development environment for this tenant",
            },
            claims=admin_a,
        ),
    )
    assert before_approval["statusCode"] == 400
    self_decision = _invoke(
        module,
        _event(
            f"{role_path}/{draft['id']}/decision",
            "POST",
            body={
                "expectedRevision": 1,
                "decision": "approve",
                "reason": "Approve the bounded development operations role after review",
            },
            claims=admin_a,
        ),
    )
    assert self_decision["statusCode"] == 403
    approved = _invoke(
        module,
        _event(
            f"{role_path}/{draft['id']}/decision",
            "POST",
            body={
                "expectedRevision": 1,
                "decision": "approve",
                "reason": "Approve the bounded development operations role after review",
            },
            claims=admin_b,
        ),
    )
    role = json.loads(approved["body"])
    assert approved["statusCode"] == 200
    assert role["status"] == "active"
    assert role["revision"] == 2
    assert role["decidedBy"] == "admin-b"
    identity = _invoke(module, _event("/enterprise/identity", "GET", claims=admin_a))
    identity_payload = json.loads(identity["body"])
    delegated_posture = identity_payload["delegatedAdministration"]
    assert delegated_posture["customRoles"] == [role]
    assert "identity_admin" not in delegated_posture["customRoleCapabilities"]
    assert delegated_posture["scopeCatalog"]["tenants"] == [{"id": tenant, "name": tenant}]
    assert delegated_posture["scopeCatalog"]["environments"] == [
        {"id": "development", "name": "development"},
        {"id": "production", "name": "production"},
    ]
    certification = _invoke(
        module,
        _event("/enterprise/identity/access-certification", "GET", claims=admin_a),
    )
    certification_payload = json.loads(certification["body"])
    assert certification_payload["schemaVersion"] == 3
    assert certification_payload["customRoles"] == [role]

    granted = _invoke(
        module,
        _event(
            "/enterprise/identity/delegated-grants",
            "POST",
            body={
                "principalId": "operator-a",
                "roleType": "custom",
                "role": role["id"],
                "scopeType": "environment",
                "scopeId": "development",
                "durationDays": 30,
                "reason": "Operate only the development environment for this tenant",
            },
            claims=admin_a,
        ),
    )
    assert granted["statusCode"] == 201
    grant = json.loads(granted["body"])
    assert grant["roleType"] == "custom"
    assert grant["roleRevision"] == role["revision"]
    assert grant["roleDigest"] == role["authorityDigest"]
    assert grant["roleLabel"] == role["name"]

    delegated = {"custom:tenant_id": tenant, "sub": "operator-a", "cognito:groups": []}
    visible = _invoke(module, _event("/enterprise/deployments", "GET", claims=delegated))
    assert visible["statusCode"] == 200
    assert [item["id"] for item in json.loads(visible["body"])["items"]] == ["dev-existing"]
    allowed = _invoke(
        module,
        _event(
            "/enterprise/deployments",
            "POST",
            body={
                "organizationId": "org-a",
                "projectId": "project-a",
                "deploymentId": "dev-new",
                "name": "New development deployment",
                "environment": "development",
                "region": "test-1",
            },
            claims=delegated,
        ),
    )
    assert allowed["statusCode"] == 201
    denied = _invoke(
        module,
        _event(
            "/enterprise/deployments",
            "POST",
            body={
                "organizationId": "org-a",
                "projectId": "project-a",
                "deploymentId": "prod-new",
                "name": "New production deployment",
                "environment": "production",
                "region": "test-1",
            },
            claims=delegated,
        ),
    )
    assert denied["statusCode"] == 403


def test_custom_role_retirement_tamper_and_claims_fail_closed(monkeypatch: Any) -> None:
    """Retired, forged or tampered custom roles never retain delegated authority."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-custom-role-fail-closed"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(Item=module._item_key(tenant, "ORG", "org-a") | {"id": "org-a"})
    admin_a = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "admin-a",
    }
    admin_b = {**admin_a, "sub": "admin-b"}
    role_path = "/enterprise/identity/custom-roles"
    created = _invoke(
        module,
        _event(
            role_path,
            "POST",
            body={
                "customRoleId": "bounded-policy-author",
                "name": "Bounded policy author",
                "description": "Author policy only inside an assigned business unit.",
                "capabilities": ["policy_write", "policy_simulation"],
                "reason": "Delegate policy authoring without platform administration rights",
            },
            claims=admin_a,
        ),
    )
    draft = json.loads(created["body"])
    approved = _invoke(
        module,
        _event(
            f"{role_path}/{draft['id']}/decision",
            "POST",
            body={
                "expectedRevision": 1,
                "decision": "approve",
                "reason": "Approve this least privilege policy authoring role after review",
            },
            claims=admin_b,
        ),
    )
    role = json.loads(approved["body"])
    granted = _invoke(
        module,
        _event(
            "/enterprise/identity/delegated-grants",
            "POST",
            body={
                "principalId": "author-a",
                "roleType": "custom",
                "role": role["id"],
                "scopeType": "organization",
                "scopeId": "org-a",
                "durationDays": 30,
                "reason": "Author policy only for the assigned synthetic business unit",
            },
            claims=admin_a,
        ),
    )
    assert granted["statusCode"] == 201
    author_event = _event(
        "/",
        "GET",
        claims={"custom:tenant_id": tenant, "sub": "author-a", "cognito:groups": []},
    )
    scope = {"tenant": tenant, "organization": "org-a"}
    assert module._operator_authorized(author_event, "policy_write", tenant, resource_scope=scope)
    assert not module._operator_authorized(
        author_event, "identity_admin", tenant, resource_scope=scope
    )
    assert not module._operator_authorized(
        _event(
            "/",
            "GET",
            claims={
                "custom:tenant_id": tenant,
                "sub": "forged",
                "cognito:groups": [role["id"]],
            },
        ),
        "policy_write",
        tenant,
        resource_scope=scope,
    )

    grant = json.loads(granted["body"])
    grant_key = (f"TENANT#{tenant}", f"DELEGATED_GRANT#{grant['id']}")
    table.items[grant_key]["role_digest"] = "f" * 64
    assert not module._operator_authorized(
        author_event, "policy_write", tenant, resource_scope=scope
    )
    table.items[grant_key]["role_digest"] = role["authorityDigest"]
    table.items[grant_key]["role_revision"] = 99
    assert not module._operator_authorized(
        author_event, "policy_write", tenant, resource_scope=scope
    )
    table.items[grant_key]["role_revision"] = role["revision"]
    assert module._operator_authorized(author_event, "policy_write", tenant, resource_scope=scope)

    role_key = (f"TENANT#{tenant}", f"CUSTOM_ROLE#{role['id']}")
    original_digest = table.items[role_key]["authority_digest"]
    table.items[role_key]["authority_digest"] = "0" * 64
    assert not module._operator_authorized(
        author_event, "policy_write", tenant, resource_scope=scope
    )
    table.items[role_key]["authority_digest"] = original_digest
    table.items[role_key]["capabilities"] = ["*"]
    assert not module._operator_authorized(
        author_event, "policy_write", tenant, resource_scope=scope
    )
    table.items[role_key]["capabilities"] = ["policy_simulation", "policy_write"]
    assert module._operator_authorized(author_event, "policy_write", tenant, resource_scope=scope)

    retired = _invoke(
        module,
        _event(
            f"{role_path}/{role['id']}/retire",
            "POST",
            body={
                "expectedRevision": 2,
                "reason": "Retire the role because the delegated operating model has ended",
            },
            claims=admin_a,
        ),
    )
    assert retired["statusCode"] == 200
    assert json.loads(retired["body"])["status"] == "retired"
    assert not module._operator_authorized(
        author_event, "policy_write", tenant, resource_scope=scope
    )

    wildcard = _invoke(
        module,
        _event(
            role_path,
            "POST",
            body={
                "customRoleId": "unsafe-role",
                "name": "Unsafe role",
                "description": "This role must never be persisted.",
                "capabilities": ["*"],
                "reason": "Attempt to create unrestricted custom authority for testing",
            },
            claims=admin_a,
        ),
    )
    assert wildcard["statusCode"] == 400
    assert (f"TENANT#{tenant}", "CUSTOM_ROLE#unsafe-role") not in table.items
    credential_reason = _invoke(
        module,
        _event(
            role_path,
            "POST",
            body={
                "customRoleId": "secret-role",
                "name": "Secret role",
                "description": "This role must never be persisted.",
                "capabilities": ["inventory_read"],
                "reason": "password=synthetic-secret-value must never enter audit evidence",
            },
            claims=admin_a,
        ),
    )
    assert credential_reason["statusCode"] == 400
    assert (f"TENANT#{tenant}", "CUSTOM_ROLE#secret-role") not in table.items


def test_custom_role_concurrent_decision_commits_no_false_audit(monkeypatch: Any) -> None:
    """A stale role decision cannot diverge from its durable governance evidence."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-custom-role-race"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    admin_a = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "admin-a",
    }
    path = "/enterprise/identity/custom-roles"
    created = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                "customRoleId": "raced-reviewer",
                "name": "Raced reviewer",
                "description": "Synthetic optimistic concurrency evidence.",
                "capabilities": ["evidence_read"],
                "reason": "Prove concurrent role decisions cannot create false audit evidence",
            },
            claims=admin_a,
        ),
    )
    role = json.loads(created["body"])
    role_key = (f"TENANT#{tenant}", f"CUSTOM_ROLE#{role['id']}")

    def concurrent_change() -> None:
        table.items[role_key]["revision"] = 9

    module.DYNAMODB.before_transaction = concurrent_change
    decision = _invoke(
        module,
        _event(
            f"{path}/{role['id']}/decision",
            "POST",
            body={
                "expectedRevision": 1,
                "decision": "approve",
                "reason": "Approve only if the exact reviewed role revision remains current",
            },
            claims={**admin_a, "sub": "admin-b"},
        ),
    )
    assert decision["statusCode"] == 409
    assert table.items[role_key]["status"] == "draft"
    audit_types = [
        item.get("event_type")
        for item in table.items.values()
        if str(item.get("sk", "")).startswith("BREAK_GLASS_AUDIT#")
    ]
    assert audit_types == ["custom_role_created"]


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


def test_dynamic_group_derives_endpoint_posture_and_risk_from_server_evidence(
    monkeypatch: Any,
) -> None:
    """Posture and risk selectors use retained evidence, never browser scores."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-dynamic-posture"
    now = int(time.time())
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "fleet-operator-a",
    }
    deployment = module._item_key(tenant, "DEPLOYMENT", "dep-a") | {
        "id": "dep-a",
        "organization_id": "org-a",
        "project_id": "project-a",
        "team": "Platform",
        "environment": "prod",
        "region": "eu-west-2",
    }
    group = module._item_key(tenant, "GROUP", "target") | {
        "id": "target",
        "organizationId": "org-a",
        "name": "At-risk endpoints",
        "policyId": "policy-restrictive",
        "policyName": "Restrictive policy",
        "agent_keys": [],
        "membership_revision": 1,
        "membership_mode": "manual",
    }
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(Item=deployment)
    table.put_item(Item=group)
    health_status = {"device-a": "healthy", "device-b": "attention"}
    for agent_id, project_root, device_id in (
        ("agent-a", "/synthetic/project-a", "device-a"),
        ("agent-b", "/synthetic/project-b", "device-b"),
    ):
        table.put_item(
            Item=module._item_key(tenant, "AGENT", f"dep-a:{agent_id}")
            | {
                "id": agent_id,
                "organization_id": "org-a",
                "project_id": "project-a",
                "deployment_id": "dep-a",
                "project_root": project_root,
                "host": "claude-code",
                "lifecycle_state": "active",
                "lifecycle_revision": 1,
            }
        )
        table.put_item(
            Item=module._item_key(tenant, "ENDPOINT_EVIDENCE", device_id)
            | {
                "deviceId": device_id,
                "payload": {
                    "installations": [
                        {
                            "projectRootDigest": hashlib.sha256(project_root.encode()).hexdigest(),
                            "host": "claude-code",
                        }
                    ]
                },
            }
        )
    table.put_item(
        Item=module._item_key(tenant, "ALERT", "alert-device-b")
        | {
            "id": "alert-device-b",
            "deviceId": "device-b",
            "severity": "critical",
            "status": "open",
        }
    )

    def endpoint_health(_tenant: str, *, now: int | None = None) -> dict[str, Any]:
        del _tenant, now
        return {
            "items": [
                {"deviceId": device_id, "status": status}
                for device_id, status in health_status.items()
            ]
        }

    monkeypatch.setattr(module, "_endpoint_evidence_health", endpoint_health)
    path = "/enterprise/groups/target/dynamic-membership"
    request = {
        "mode": "preview",
        "requestId": "dynamic-posture-001",
        "expectedMembershipRevision": 1,
        "reason": "Move critical endpoint risk onto the restrictive policy.",
        "rule": {
            "match": "all",
            "conditions": [
                {
                    "field": "endpointPosture",
                    "operator": "equals_any",
                    "values": ["attention"],
                },
                {
                    "field": "riskLevel",
                    "operator": "equals_any",
                    "values": ["critical"],
                },
            ],
        },
    }
    preview = _invoke(module, _event(path, "POST", body=request, claims=claims))
    assert preview["statusCode"] == 200
    preview_body = json.loads(preview["body"])
    assert preview_body["additions"] == [{"deploymentId": "dep-a", "agentId": "agent-b"}]
    assert preview_body["evaluation"]["sources"] == ["alert-ledger", "endpoint-evidence"]
    assert re.fullmatch(r"[0-9a-f]{64}", preview_body["evaluation"]["contextDigest"])
    assert "project-a" not in json.dumps(preview_body["evaluation"])

    applied = _invoke(
        module,
        _event(path, "POST", body={**request, "mode": "apply"}, claims=claims),
    )
    assert applied["statusCode"] == 200
    stored = table.items[(f"TENANT#{tenant}", "GROUP#target")]
    assert stored["agent_keys"] == ["dep-a:agent-b"]
    assert stored["dynamic_context_digest"] == preview_body["evaluation"]["contextDigest"]
    audit = next(
        item for key, item in table.items.items() if key[1].startswith("GROUP_MEMBERSHIP_AUDIT#")
    )
    assert audit["payload"]["context_digest"] == stored["dynamic_context_digest"]
    assert "riskLevelByAgent" not in audit["payload"]

    health_status["device-b"] = "stale"
    table.items[(f"TENANT#{tenant}", "ALERT#alert-device-b")]["status"] = "resolved"
    status = module._reconcile_dynamic_group(tenant, stored, now=now + 300)
    assert status["counts"]["removals"] == 1
    assert table.items[(f"TENANT#{tenant}", "GROUP#target")]["agent_keys"] == []


def test_dynamic_group_posture_missing_ambiguous_and_malformed_evidence_fails_closed(
    monkeypatch: Any,
) -> None:
    """Ambiguous targets never match and malformed risk cannot reduce protection."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-dynamic-posture-deny"
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "admin-a",
    }
    project_root = "/synthetic/ambiguous"
    target_digest = hashlib.sha256(project_root.encode()).hexdigest()
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
            "agent_keys": [],
            "membership_revision": 1,
        },
        module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "organization_id": "org-a",
            "deployment_id": "dep-a",
            "project_root": project_root,
            "host": "claude-code",
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
        },
    ):
        table.put_item(Item=record)
    for device_id in ("device-a", "device-b"):
        table.put_item(
            Item=module._item_key(tenant, "ENDPOINT_EVIDENCE", device_id)
            | {
                "deviceId": device_id,
                "payload": {
                    "installations": [{"projectRootDigest": target_digest, "host": "claude-code"}]
                },
            }
        )
    monkeypatch.setattr(
        module,
        "_endpoint_evidence_health",
        lambda _tenant, now=None: {
            "items": [
                {"deviceId": "device-a", "status": "healthy"},
                {"deviceId": "device-b", "status": "healthy"},
            ]
        },
    )
    path = "/enterprise/groups/target/dynamic-membership"
    base = {
        "mode": "preview",
        "requestId": "dynamic-posture-deny-001",
        "expectedMembershipRevision": 1,
        "reason": "Prove ambiguous endpoint evidence cannot select policy authority.",
        "rule": {
            "match": "all",
            "conditions": [
                {
                    "field": "endpointPosture",
                    "operator": "not_equals_any",
                    "values": ["attention"],
                }
            ],
        },
    }
    ambiguous = _invoke(module, _event(path, "POST", body=base, claims=claims))
    assert ambiguous["statusCode"] == 200
    assert json.loads(ambiguous["body"])["counts"]["matched"] == 0

    unsupported = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                **base,
                "requestId": "dynamic-posture-deny-002",
                "rule": {
                    "match": "all",
                    "conditions": [
                        {
                            "field": "endpointPosture",
                            "operator": "equals_any",
                            "values": ["browser-says-healthy"],
                        }
                    ],
                },
            },
            claims=claims,
        ),
    )
    assert unsupported["statusCode"] == 400

    table.put_item(
        Item=module._item_key(tenant, "ALERT", "malformed")
        | {"id": "malformed", "agentKey": "dep-a:agent-a", "severity": "safe", "status": "open"}
    )
    malformed = _invoke(
        module,
        _event(
            path,
            "POST",
            body={
                **base,
                "requestId": "dynamic-posture-deny-003",
                "rule": {
                    "match": "all",
                    "conditions": [
                        {"field": "riskLevel", "operator": "equals_any", "values": ["none"]}
                    ],
                },
            },
            claims=claims,
        ),
    )
    assert malformed["statusCode"] == 409
    assert table.items[(f"TENANT#{tenant}", "GROUP#target")]["agent_keys"] == []


def test_dynamic_group_schedule_reuses_one_trusted_context_per_tenant(
    monkeypatch: Any,
) -> None:
    """Many rules cannot multiply endpoint and alert reads within one cycle."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-dynamic-cache"
    registration = module._item_key(tenant, "TENANT", "root") | {
        "id": tenant,
        "endpoint_detection_pk": "ENDPOINT_DETECTION#00",
        "endpoint_detection_sk": tenant,
    }
    query_calls = 0

    def query(**_kwargs: Any) -> dict[str, Any]:
        nonlocal query_calls
        query_calls += 1
        return {"Items": [registration] if query_calls == 1 else []}

    table.query = query
    rule = {
        "match": "all",
        "conditions": [{"field": "riskLevel", "operator": "equals_any", "values": ["high"]}],
    }
    groups = [
        {
            "id": group_id,
            "membership_mode": "dynamic",
            "dynamic_rule": rule,
            "dynamic_rule_hash": hashlib.sha256(
                json.dumps(rule, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }
        for group_id in ("group-a", "group-b")
    ]
    monkeypatch.setattr(
        module,
        "_list",
        lambda _tenant, kind, consistent_read=False: groups if kind == "GROUP" else [],
    )
    context_calls = 0
    context = {
        "evaluatedAt": 1,
        "sources": ["alert-ledger"],
        "endpointPostureByTarget": {},
        "riskLevelByAgent": {},
        "riskLevelByTarget": {},
        "contextDigest": "a" * 64,
    }

    def security_context(_tenant: str, _fields: Any, *, now: int | None = None) -> dict[str, Any]:
        nonlocal context_calls
        del now
        context_calls += 1
        return context

    observed_contexts = []

    def reconcile_with_context(
        _tenant: str,
        _group: dict[str, Any],
        *,
        now: int | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        del now
        observed_contexts.append(context)
        return {"outcome": "healthy"}

    monkeypatch.setattr(module, "_dynamic_group_security_context", security_context)
    monkeypatch.setattr(module, "_reconcile_dynamic_group", reconcile_with_context)
    result = module._dynamic_group_reconciliation_cycle()
    assert result == {"processedTenants": 1, "processedGroups": 2, "failedGroups": 0}
    assert context_calls == 1
    assert observed_contexts == [context, context]


def test_scheduled_dynamic_group_reconciliation_changes_authority_and_surfaces_overlap(
    monkeypatch: Any,
) -> None:
    """The service schedule changes only approved rules and fails closed on overlap."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-dynamic-schedule"
    rule = {
        "match": "all",
        "conditions": [{"field": "team", "operator": "equals_any", "values": ["Platform"]}],
    }
    canonical = json.dumps(rule, sort_keys=True, separators=(",", ":"))
    rule_hash = hashlib.sha256(canonical.encode()).hexdigest()
    records = [
        module._item_key(tenant, "TENANT", "root")
        | {
            "id": tenant,
            "endpoint_detection_pk": "ENDPOINT_DETECTION#00",
            "endpoint_detection_sk": tenant,
        },
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
            "agent_keys": ["dep-a:agent-old"],
            "membership_revision": 2,
            "membership_mode": "dynamic",
            "dynamic_rule": rule,
            "dynamic_rule_hash": rule_hash,
        },
    ]
    for agent_id in ("agent-old", "agent-new"):
        records.append(
            module._item_key(tenant, "AGENT", f"dep-a:{agent_id}")
            | {
                "id": agent_id,
                "organization_id": "org-a",
                "project_id": "project-a",
                "deployment_id": "dep-a",
                "host": "claude-code",
                "status": "offline",
                "expires_at": 0,
                "lifecycle_state": "active",
                "lifecycle_revision": 1,
            }
        )
    for record in records:
        table.put_item(Item=record)

    result = module.handler(
        {"source": "aai.dynamic-group-reconciliation", "schemaVersion": 1}, None
    )
    assert result == {"processedTenants": 1, "processedGroups": 1, "failedGroups": 0}
    group = table.items[(f"TENANT#{tenant}", "GROUP#target")]
    assert group["agent_keys"] == ["dep-a:agent-new", "dep-a:agent-old"]
    assert group["membership_revision"] == 3
    status = module._dynamic_reconciliation_status(tenant, "target")
    assert status["outcome"] == "healthy"
    assert status["changed"] is True
    assert status["counts"] == {
        "matched": 2,
        "additions": 1,
        "removals": 0,
        "unchanged": 1,
    }
    assert len([key for key in table.items if key[1].startswith("GROUP_MEMBERSHIP_AUDIT#")]) == 1

    module.handler({"source": "aai.dynamic-group-reconciliation", "schemaVersion": 1}, None)
    assert module._dynamic_reconciliation_status(tenant, "target")["changed"] is False
    assert len([key for key in table.items if key[1].startswith("GROUP_MEMBERSHIP_AUDIT#")]) == 1

    table.put_item(
        Item=module._item_key(tenant, "GROUP", "conflicting")
        | {
            "id": "conflicting",
            "organizationId": "org-a",
            "name": "Conflicting",
            "policyId": "policy-b",
            "policyName": "Policy B",
            "agent_keys": ["dep-a:agent-new"],
            "membership_revision": 1,
        }
    )
    with pytest.raises(RuntimeError, match="dynamic group reconciliations failed"):
        module.handler({"source": "aai.dynamic-group-reconciliation", "schemaVersion": 1}, None)
    assert table.items[(f"TENANT#{tenant}", "GROUP#target")]["membership_revision"] == 3
    failed = module._dynamic_reconciliation_status(tenant, "target")
    assert failed["outcome"] == "failed"
    assert failed["errorCode"] == "policy_group_overlap"
    assert failed["lastSuccessAt"] is not None
    assert len([key for key in table.items if key[1].startswith("GROUP_MEMBERSHIP_AUDIT#")]) == 2

    with pytest.raises(ValueError, match="schedule event is invalid"):
        module.handler(
            {
                "source": "aai.dynamic-group-reconciliation",
                "schemaVersion": 1,
                "tenant": tenant,
            },
            None,
        )

    table.items[(f"TENANT#{tenant}", "GROUP#conflicting")]["agent_keys"] = []
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-third")
        | {
            "id": "agent-third",
            "organization_id": "org-a",
            "project_id": "project-a",
            "deployment_id": "dep-a",
            "host": "claude-code",
            "status": "offline",
            "expires_at": 0,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
        }
    )

    def concurrent_membership_change() -> None:
        current = table.items[(f"TENANT#{tenant}", "GROUP#target")]
        current["membership_revision"] = 4
        current["agent_keys"] = ["dep-a:agent-new", "dep-a:agent-old", "dep-a:concurrent"]

    module.DYNAMODB.before_transaction = concurrent_membership_change
    with pytest.raises(RuntimeError, match="dynamic group reconciliations failed"):
        module.handler({"source": "aai.dynamic-group-reconciliation", "schemaVersion": 1}, None)
    raced_group = table.items[(f"TENANT#{tenant}", "GROUP#target")]
    assert raced_group["membership_revision"] == 4
    assert "dep-a:concurrent" in raced_group["agent_keys"]
    raced_status = module._dynamic_reconciliation_status(tenant, "target")
    assert raced_status["outcome"] == "failed"
    assert raced_status["errorCode"] == "policy_state_conflict"
    assert raced_status["membershipRevision"] == 4


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
    assert payload["schemaVersion"] == 3
    assert payload["complete"] is True
    assert payload["delegatedGrants"] == []
    assert payload["customRoles"] == []
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


def test_time_limited_policy_exception_is_independently_signed_and_expires(
    monkeypatch: Any,
) -> None:
    """One exact agent receives reviewed derived authority only until server expiry."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-policy-exception"
    clock = [2_200_000_000]
    monkeypatch.setattr(module.time, "time", lambda: clock[0])
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    base = {
        "policy": {"allowedPrincipals": ["developer"], "denyByDefault": True},
        "tools": {"allowed": ["Read"], "denied": ["Write"]},
        "approvals": {"requiredFor": ["Bash"], "ttlSeconds": 120},
        "budgets": {"maxActions": 10},
        "audit": {"captureToolContent": False, "redactSensitiveData": True},
        "telemetry": {"captureToolContent": False, "redactSensitiveData": True},
        "claudeCode": {
            "allowedBuiltInTools": ["Read"],
            "allowedSkills": [],
            "allowedMcpServers": [],
        },
    }
    candidate = {
        **base,
        "tools": {"allowed": ["Read", "Write"], "denied": []},
        "budgets": {"maxActions": 20},
        "claudeCode": {
            "allowedBuiltInTools": ["Read", "Write"],
            "allowedSkills": [],
            "allowedMcpServers": [],
        },
    }
    base_bundle = module._sign_policy_bundle(tenant, "policy-a", 1, base, clock[0] - 100)
    version = {
        **module._item_key(
            tenant, "POLICY_VERSION", module._policy_version_identifier("policy-a", 1)
        ),
        "tenant_id": tenant,
        "id": module._policy_version_identifier("policy-a", 1),
        "policy_id": "policy-a",
        "organization_id": "org-a",
        "version": 1,
        "base_version": 0,
        "name": "Safe base",
        "configuration": base,
        "content_hash": module._configuration_hash(base),
        **module._bundle_record_fields(base_bundle),
        "state": "active",
        "author": "bootstrap",
        "created_at": clock[0] - 100,
        "activated_by": "bootstrap",
        "activated_at": clock[0] - 100,
    }
    table.put_item(Item=version)
    table.put_item(
        Item=module._item_key(tenant, "POLICY", "policy-a")
        | {
            "tenant_id": tenant,
            "id": "policy-a",
            "organization_id": "org-a",
            "name": "Safe base",
            "configuration": base,
            "version": 1,
            "activeVersion": 1,
            "latestVersion": 1,
            "governanceState": "active",
            "governance_schema_version": 1,
            "createdAt": clock[0] - 100,
            "author": "bootstrap",
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "tenant_id": tenant,
            "id": "agent-a",
            "deployment_id": "dep-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "host": "claude-code",
            "status": "connected",
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
            "session_revision": 1,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "GROUP", "group-a")
        | {
            "tenant_id": tenant,
            "id": "group-a",
            "organization_id": "org-a",
            "policyId": "policy-a",
            "agent_keys": ["dep-a:agent-a"],
        }
    )
    author = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["policy-author"],
        "sub": "exception-author",
    }
    approver = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["policy-approver"],
        "sub": "exception-approver",
    }
    create_body = {
        "exceptionId": "temporary-write-access",
        "deploymentId": "dep-a",
        "agentId": "agent-a",
        "owner": "Platform engineering",
        "purpose": "Complete a bounded synthetic migration during the approved window.",
        "expiresAt": clock[0] + 1_800,
        "configuration": candidate,
    }
    created = _invoke(
        module,
        _event("/api/enterprise/policy-exceptions", "POST", body=create_body, claims=author),
    )
    assert created["statusCode"] == 201, created
    created_body = json.loads(created["body"])
    assert created_body["state"] == "draft"
    assert created_body["changeSummary"]["summary"]["authorityExpanded"] >= 2
    duplicate = _invoke(
        module,
        _event(
            "/api/enterprise/policy-exceptions",
            "POST",
            body={**create_body, "exceptionId": "overlapping-access"},
            claims=author,
        ),
    )
    assert duplicate["statusCode"] == 409
    path = "/api/enterprise/policy-exceptions/temporary-write-access"
    assert _invoke(module, _event(f"{path}/submit", "POST", claims=author))["statusCode"] == 200
    self_approval = _invoke(
        module,
        _event(
            f"{path}/decision",
            "POST",
            body={"decision": "approved", "reason": "Self approval must fail closed."},
            claims=author,
        ),
    )
    assert self_approval["statusCode"] == 403
    approved = _invoke(
        module,
        _event(
            f"{path}/decision",
            "POST",
            body={
                "decision": "approved",
                "reason": "Scope, authority change and bounded lifetime are acceptable.",
            },
            claims=approver,
        ),
    )
    assert approved["statusCode"] == 200
    activated = _invoke(module, _event(f"{path}/activate", "POST", body={}, claims=approver))
    assert activated["statusCode"] == 200, activated
    assert json.loads(activated["body"])["state"] == "active"
    assert module._fake_kms.calls[-1]["SigningAlgorithm"] == "ECDSA_SHA_256"

    effective_path = "/api/enterprise/agents/dep-a/agent-a/effective-policy"
    effective = _invoke(module, _event(effective_path, "GET", claims=approver))
    assert effective["statusCode"] == 200, effective
    effective_body = json.loads(effective["body"])
    assert effective_body["effectiveSource"] == "temporary_exception"
    assert effective_body["exception"]["id"] == "temporary-write-access"
    assert effective_body["policyBundle"]["policyId"].startswith("exception:")
    assert effective_body["policyBundle"]["configuration"]["tools"]["allowed"] == [
        "Read",
        "Write",
    ]

    expiry_events: list[str] = []
    monkeypatch.setattr(
        module,
        "_audit",
        lambda _tenant, event_type, _actor, _payload: expiry_events.append(event_type),
    )
    clock[0] += 1_801
    restored = _invoke(module, _event(effective_path, "GET", claims=approver))
    assert restored["statusCode"] == 200, restored
    restored_body = json.loads(restored["body"])
    assert restored_body["effectiveSource"] == "active_policy"
    assert restored_body["exception"] is None
    assert restored_body["policyBundle"]["policyId"] == "policy-a"
    listed = json.loads(
        _invoke(
            module,
            _event("/api/enterprise/policy-exceptions", "GET", claims=approver),
        )["body"]
    )["items"]
    assert listed[0]["state"] == "expired"
    assert listed[0]["effective"] is False
    assert expiry_events == ["policy_exception_expired"]


def test_policy_exception_invalidates_on_base_change_and_rejects_unsafe_input(
    monkeypatch: Any,
) -> None:
    """Secrets, stale bindings, wrong roles and transition replay never grant authority."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-policy-exception-denial"
    now = 2_210_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    base = {"policy": {"denyByDefault": True}, "tools": {"allowed": ["Read"]}}
    bundle = module._sign_policy_bundle(tenant, "policy-a", 1, base, now - 10)
    table.put_item(
        Item=module._item_key(tenant, "POLICY", "policy-a")
        | {
            "id": "policy-a",
            "organization_id": "org-a",
            "name": "Policy A",
            "configuration": base,
            "version": 1,
            "governance_schema_version": 1,
        }
    )
    table.put_item(
        Item=module._item_key(
            tenant, "POLICY_VERSION", module._policy_version_identifier("policy-a", 1)
        )
        | {
            "id": module._policy_version_identifier("policy-a", 1),
            "policy_id": "policy-a",
            "organization_id": "org-a",
            "version": 1,
            "base_version": 0,
            "name": "Policy A",
            "configuration": base,
            "content_hash": module._configuration_hash(base),
            **module._bundle_record_fields(bundle),
            "state": "active",
            "author": "bootstrap",
            "created_at": now - 10,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "GROUP", "group-a")
        | {"id": "group-a", "policyId": "policy-a", "agent_keys": ["dep-a:agent-a"]}
    )
    author = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["policy-author"],
        "sub": "author-a",
    }
    fleet = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "fleet-a",
    }
    request = {
        "exceptionId": "exception-a",
        "deploymentId": "dep-a",
        "agentId": "agent-a",
        "owner": "Synthetic owner",
        "purpose": "Exercise stale authority handling without production data.",
        "expiresAt": now + 1_800,
        "configuration": {
            "policy": {"denyByDefault": True},
            "tools": {"allowed": ["Read", "Write"]},
        },
    }
    assert (
        _invoke(
            module,
            _event("/api/enterprise/policy-exceptions", "POST", body=request, claims=fleet),
        )["statusCode"]
        == 403
    )
    unsafe = _invoke(
        module,
        _event(
            "/api/enterprise/policy-exceptions",
            "POST",
            body={**request, "configuration": {"token": "synthetic-secret"}},
            claims=author,
        ),
    )
    assert unsafe["statusCode"] == 400
    assert "must not contain secrets" in json.loads(unsafe["body"])["error"]
    weakened = _invoke(
        module,
        _event(
            "/api/enterprise/policy-exceptions",
            "POST",
            body={
                **request,
                "configuration": {
                    **base,
                    "tools": {"allowed": ["Read", "Write"]},
                    "isolation": {"requiredForHighRisk": False, "mode": "optional"},
                },
            },
            claims=author,
        ),
    )
    assert weakened["statusCode"] == 400
    assert "may change only temporary tool" in json.loads(weakened["body"])["error"]
    created = _invoke(
        module,
        _event("/api/enterprise/policy-exceptions", "POST", body=request, claims=author),
    )
    assert created["statusCode"] == 201
    policy = table.items[(f"TENANT#{tenant}", "POLICY#policy-a")]
    policy["version"] = 2
    table.put_item(Item=policy)
    listed = json.loads(
        _invoke(
            module,
            _event("/api/enterprise/policy-exceptions", "GET", claims=author),
        )["body"]
    )["items"]
    assert listed[0]["state"] == "invalidated"
    replay = _invoke(
        module,
        _event(
            "/api/enterprise/policy-exceptions/exception-a/submit",
            "POST",
            claims=author,
        ),
    )
    assert replay["statusCode"] == 409

    # Corrupt lifecycle evidence must fail closed. It must never be interpreted
    # as a terminal record that permits replacement of the per-agent slot.
    policy["version"] = 1
    table.put_item(Item=policy)
    corrupt_key = (f"TENANT#{tenant}", "POLICY_EXCEPTION#exception-a")
    table.items[corrupt_key]["state"] = "unknown-corrupt-state"
    corrupt_list = _invoke(
        module,
        _event("/api/enterprise/policy-exceptions", "GET", claims=author),
    )
    assert corrupt_list["statusCode"] == 500
    replacement = _invoke(
        module,
        _event(
            "/api/enterprise/policy-exceptions",
            "POST",
            body={**request, "exceptionId": "exception-b"},
            claims=author,
        ),
    )
    assert replacement["statusCode"] == 500
    assert (
        table.items[(f"TENANT#{tenant}", "POLICY_EXCEPTION_SLOT#dep-a:agent-a")]["exception_id"]
        == "exception-a"
    )
    assert (f"TENANT#{tenant}", "POLICY_EXCEPTION#exception-b") not in table.items


def test_native_control_analysis_is_returned_and_blocks_aws_authority(
    monkeypatch: Any,
) -> None:
    """AWS review views explain conflicts and the authority gate rejects them."""
    module, _table = _load_handler(monkeypatch)
    secret_pattern = r"^deploy --token synthetic-never-return$"  # noqa: S105
    configuration = {
        "tools": {"builtIn": ["Read"]},
        "claudeCode": {
            "enabled": True,
            "allowedBuiltInTools": ["Read", "Bash"],
            "allowedCommandPatterns": [secret_pattern],
            "deniedCommandPatterns": [secret_pattern],
        },
        "managedHost": {"host": "codex-cli"},
    }
    record = {
        "policy_id": "policy-conflict",
        "organization_id": "org-a",
        "version": 1,
        "base_version": 0,
        "name": "Conflict",
        "configuration": configuration,
        "content_hash": module._configuration_hash(configuration),
        "state": "approved",
        "author": "author-a",
        "created_at": 2_100_000_000,
    }

    view = module._policy_version_view("tenant-a", record, [record])

    assert view["nativeControlAnalysis"]["status"] == "blocked"
    assert view["nativeControlAnalysis"]["evaluatedHosts"] == ["codex-cli"]
    assert secret_pattern not in str(view["nativeControlAnalysis"])
    with pytest.raises(module.PolicyConflict, match="native-control conflicts"):
        module._assert_native_control_compatibility(configuration)


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


def test_aws_policy_components_are_signed_exact_and_restrictive(monkeypatch: Any) -> None:
    """AWS composition accepts only signed governed versions and never widens authority."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-policy-components"
    organization_id = "org-a"
    policy_id = "policy-baseline"
    configuration = {
        "policy": {"denyByDefault": True},
        "tools": {"allowed": ["read_repository", "run_tests"]},
        "budgets": {"maxActions": 100},
    }
    composition = module.compose_policy((), configuration).to_dict()
    bundle = module._sign_policy_bundle(tenant, policy_id, 1, configuration, 2_210_000_000)
    component = module._item_key(
        tenant,
        "POLICY_VERSION",
        module._policy_version_identifier(policy_id, 1),
    ) | {
        "tenant_id": tenant,
        "id": module._policy_version_identifier(policy_id, 1),
        "policy_id": policy_id,
        "organization_id": organization_id,
        "version": 1,
        "base_version": 0,
        "name": "Baseline",
        "configuration": configuration,
        "local_configuration": configuration,
        "component_refs": [],
        "graph_digest": composition["graphDigest"],
        "composition_explanation": composition["explanation"],
        "content_hash": module._configuration_hash(configuration),
        **module._bundle_record_fields(bundle),
        "state": "active",
        "author": "author-a",
        "decision": "approved",
        "decided_by": "reviewer-b",
        "created_at": 2_210_000_000,
    }
    table.put_item(Item=component)
    reference = {
        "policyId": policy_id,
        "version": 1,
        "contentHash": component["content_hash"],
    }

    result = module._compose_governed_policy(
        tenant,
        organization_id,
        "policy-workload",
        {
            "localConfiguration": {
                "tools": {"allowed": ["read_repository", "write_repository"]},
                "budgets": {"maxActions": 25},
            },
            "componentRefs": [reference],
        },
    )
    assert result["configuration"] == {
        "policy": {"denyByDefault": True},
        "tools": {"allowed": ["read_repository"]},
        "budgets": {"maxActions": 25},
    }
    assert result["component_refs"] == [reference]
    assert len(result["graph_digest"]) == 64

    with pytest.raises(module.PolicyConflict, match="content hash"):
        module._compose_governed_policy(
            tenant,
            organization_id,
            "policy-workload",
            {
                "localConfiguration": {},
                "componentRefs": [{**reference, "contentHash": "0" * 64}],
            },
        )
    table.put_item(Item={**component, "bundle_integrity": None})
    with pytest.raises(RuntimeError, match="signed effective authority"):
        module._compose_governed_policy(
            tenant,
            organization_id,
            "policy-workload",
            {"localConfiguration": {}, "componentRefs": [reference]},
        )
    forged_integrity = {
        **component["bundle_integrity"],
        "signature": base64.b64encode(b"forged-signature").decode("ascii"),
    }
    table.put_item(Item={**component, "bundle_integrity": forged_integrity})
    with pytest.raises(RuntimeError, match="signature verification failed"):
        module._compose_governed_policy(
            tenant,
            organization_id,
            "policy-workload",
            {"localConfiguration": {}, "componentRefs": [reference]},
        )


def test_aws_policy_composition_preview_route_is_effective_and_side_effect_free(
    monkeypatch: Any,
) -> None:
    """Hosted UI preview returns server-composed authority without creating a draft."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-policy-preview"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(Item=module._item_key(tenant, "ORG", "org-a") | {"id": "org-a"})
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["policy-author"],
        "sub": "author-a",
    }
    response = _invoke(
        module,
        _event(
            "/enterprise/policies/composition/preview",
            "POST",
            body={
                "organizationId": "org-a",
                "policyId": "policy-candidate",
                "localConfiguration": {"policy": {"denyByDefault": True}},
                "componentRefs": [],
            },
            claims=claims,
        ),
    )
    assert response["statusCode"] == 200
    result = json.loads(response["body"])
    assert result["configuration"] == {"policy": {"denyByDefault": True}}
    assert len(result["graphDigest"]) == 64
    assert not any(item.get("id") == "policy-candidate" for item in table.items.values())


def _verified_policy_source(module: Any, content: bytes) -> Any:
    """Build complete synthetic provider evidence for hosted import contracts."""
    return module.VerifiedPolicySource(
        provider="github",
        repository="github.com/example/security-policy",
        commit_sha="b" * 40,
        blob_sha="c" * 40,
        path="policies/engineering.json",
        content=content,
        pull_request="github.com/example/security-policy/pull/42",
        reviewed_by=("github:reviewer-b",),
        signer_identity="github:author-a",
        retrieved_at=2_210_000_000,
    )


def test_aws_policy_git_import_export_is_draft_only_idempotent_and_signed(
    monkeypatch: Any,
) -> None:
    """Hosted GitOps creates no authority and exports exact KMS-bound provenance."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-policy-gitops"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(Item=module._item_key(tenant, "ORG", "org-a") | {"id": "org-a"})
    source = json.dumps(
        {
            "schemaVersion": 1,
            "policyId": "policy-from-git",
            "organizationId": "org-a",
            "name": "Reviewed Git policy",
            "componentRefs": [],
            "localConfiguration": {
                "policy": {"denyByDefault": True},
                "tools": {"allowed": ["read_repository"], "denied": ["shell"]},
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    monkeypatch.setattr(
        module,
        "_invoke_policy_source_verifier",
        lambda _request: _verified_policy_source(module, source),
    )
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["policy-author"],
        "sub": "author-a",
    }
    request = {
        "importId": "import-42",
        "repository": "github.com/example/security-policy",
        "commitSha": "b" * 40,
        "path": "policies/engineering.json",
    }
    response = _invoke(
        module,
        _event("/enterprise/policies/imports", "POST", body=request, claims=claims),
    )
    assert response["statusCode"] == 201
    imported = json.loads(response["body"])
    assert imported["draft"] == {
        "policyId": "policy-from-git",
        "version": 1,
        "state": "draft",
    }
    policy = table.items[(f"TENANT#{tenant}", "POLICY#policy-from-git")]
    version = table.items[
        (f"TENANT#{tenant}", "POLICY_VERSION#policy-from-git:00000000000000000001")
    ]
    assert policy["version"] == 0 and policy["activeVersion"] is None
    assert version["state"] == "draft" and version["source_provenance"] == imported["provenance"]
    assert not any(item[1].startswith("GROUP#") for item in table.items)

    replay = _invoke(
        module,
        _event("/enterprise/policies/imports", "POST", body=request, claims=claims),
    )
    assert replay["statusCode"] == 201 and json.loads(replay["body"]) == imported
    fetched = _invoke(
        module,
        _event("/enterprise/policies/imports/import-42", "GET", claims=claims),
    )
    assert fetched["statusCode"] == 200 and json.loads(fetched["body"]) == imported

    exported_response = _invoke(
        module,
        _event(
            "/enterprise/policies/policy-from-git/versions/1/export",
            "POST",
            claims=claims,
        ),
    )
    assert exported_response["statusCode"] == 200
    exported = json.loads(exported_response["body"])
    assert json.loads(exported["canonicalDocument"]) == exported["document"]
    assert (
        exported["sourceSha256"]
        == hashlib.sha256(exported["canonicalDocument"].encode()).hexdigest()
    )
    assert exported["provenance"]["integrity"]["keyId"] == module.POLICY_SIGNING_KEY_ARN


def test_aws_policy_git_import_rolls_back_every_record_on_race(
    monkeypatch: Any,
) -> None:
    """A concurrent idempotency claim leaves no policy shell or orphan version."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-policy-import-race"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(Item=module._item_key(tenant, "ORG", "org-a") | {"id": "org-a"})
    source = (
        b'{"schemaVersion":1,"policyId":"policy-race","organizationId":"org-a",'
        b'"name":"Race","componentRefs":[],"localConfiguration":{}}'
    )
    monkeypatch.setattr(
        module,
        "_invoke_policy_source_verifier",
        lambda _request: _verified_policy_source(module, source),
    )

    def claim_import() -> None:
        table.put_item(
            Item=module._item_key(tenant, "POLICY_IMPORT", "import-race") | {"id": "import-race"}
        )

    module.DYNAMODB.before_transaction = claim_import
    with pytest.raises(module.PolicyConflict):
        module._import_policy_source(
            tenant,
            {
                "importId": "import-race",
                "repository": "github.com/example/security-policy",
                "commitSha": "b" * 40,
                "path": "policies/engineering.json",
            },
            "author-a",
        )
    assert (f"TENANT#{tenant}", "POLICY#policy-race") not in table.items
    assert not any("POLICY_VERSION#policy-race" in key[1] for key in table.items)


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
        "budgets": {"maxActions": 25},
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
    # DynamoDB's resource API returns every persisted number as Decimal. The
    # signed bundle must normalize that storage representation before applying
    # the provider-neutral canonical JSON contract.
    stored["effective_configuration"]["budgets"]["maxActions"] = Decimal("25")
    active_policy = table.items[(f"TENANT#{tenant}", "POLICY#policy-signed")]
    bundle = module._active_policy_bundle(tenant, active_policy)
    assert bundle["configuration"]["budgets"]["maxActions"] == 25
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
    assert 'policySigningKey.grant(handler, "kms:Sign", "kms:Verify", "kms:GetPublicKey")' in stack
    assert "POLICY_SIGNING_KEY_ARN: policySigningKey.keyArn" in stack
    assert "REGIONAL_POLICY_SIGNING_KEY_ARN: regionalPolicySigningKey.keyArn" in stack
    assert 'RECOVERY_REGION: process.env.AUDIT_REPLICA_REGION ?? "eu-west-1"' in stack
    assert 'new cdk.CfnOutput(this, "PolicySigningKeyArn"' in stack
    assert 'new cdk.CfnOutput(this, "RegionalFaultTargetExecutionRoleArn"' in stack
    assert "value: handler.role!.roleArn" in stack


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
    runtime_manifest = _runtime_manifest()
    _set_runtime_manifests(monkeypatch, [runtime_manifest])
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
    assert effective["statusCode"] == 200, effective

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


def test_runtime_release_catalog_exposes_only_approved_content_minimised_metadata(
    monkeypatch: Any,
) -> None:
    """Operators can inspect exact release authority without executable bytes or secrets."""
    module, _table = _load_handler(monkeypatch)
    manifests = [_runtime_manifest("claude-code"), _runtime_manifest("codex-cli")]
    _set_runtime_manifests(monkeypatch, manifests)

    catalog = module._runtime_release_catalog()

    assert catalog["status"] == "configured"
    assert [release["id"] for release in catalog["releases"]] == [
        "claude-code:1.1.0",
        "codex-cli:1.1.0",
    ]
    assert catalog["releases"][0] == {
        "id": "claude-code:1.1.0",
        "host": "claude-code",
        "sdkVersion": "1.1.0",
        "sdkRevision": "a" * 40,
        "releaseTag": "v1.1.0",
        "manifestSha256": hashlib.sha256(
            json.dumps(manifests[0], separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest(),
        "releaseEvidenceSha256": "9" * 64,
        "packageSha256": "c" * 64,
        "gatewaySha256": "d" * 64,
        "hookSha256": "e" * 64,
    }
    encoded = json.dumps(catalog)
    assert "sourceOriginDigest" not in encoded
    assert "privateKey" not in encoded
    assert "packageBase64" not in encoded


def test_current_attestation_requires_the_exact_complete_release_manifest(
    monkeypatch: Any,
) -> None:
    """A stale compliant flag cannot authorize after release authority changes."""
    module, table = _load_handler(monkeypatch)
    now = 1_900_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    manifest = _runtime_manifest()
    _set_runtime_manifests(monkeypatch, [manifest])
    tenant = "tenant-release-binding"
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "dep-a")
        | {"id": "dep-a", "sdk_version": "1.1.0"}
    )
    agent = {
        "host": "claude-code",
        "attestation_status": "compliant",
        "attestation_expires_at": now + 300,
        "attestation_sdk_version": "1.1.0",
        "attestation_sdk_revision": "a" * 40,
        "attestation_manifest_sha256": "0" * 64,
    }

    with pytest.raises(PermissionError, match="current approved release"):
        module._require_current_attestation(tenant, "dep-a", agent)

    agent["attestation_manifest_sha256"] = module._runtime_manifest_digest(manifest)
    module._require_current_attestation(tenant, "dep-a", agent)


def test_version_compliance_is_tenant_scoped_and_derived_from_fresh_attestation(
    monkeypatch: Any,
) -> None:
    """Only live exact approved evidence counts as fleet version compliance."""
    module, table = _load_handler(monkeypatch)
    now = 1_900_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    _set_runtime_manifests(monkeypatch, [_runtime_manifest("claude-code")])
    tenant = "tenant-version-compliance"
    other_tenant = "tenant-version-other"
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "dep-approved")
        | {"id": "dep-approved", "name": "Approved", "sdk_version": "1.1.0"}
    )
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "dep-unapproved")
        | {"id": "dep-unapproved", "name": "Unapproved", "sdk_version": "9.9.9"}
    )

    def put_agent(
        agent_id: str,
        deployment_id: str,
        *,
        status: str = "connected",
        attestation_status: str = "compliant",
        observed_version: str | None = "1.1.0",
        observed_revision: str = "a" * 40,
        manifest_digest: str | None = None,
        expires_at: int = now + 300,
    ) -> None:
        item = module._item_key(tenant, "AGENT", f"{deployment_id}:{agent_id}") | {
            "id": agent_id,
            "deployment_id": deployment_id,
            "host": "claude-code",
            "status": status,
            "expires_at": now + 300,
            "lifecycle_state": "active",
            "attestation_status": attestation_status,
            "attestation_expires_at": expires_at,
            "attestation_sdk_revision": observed_revision,
            "attestation_manifest_sha256": manifest_digest
            or module._runtime_manifest_digest(_runtime_manifest()),
            "attestation_reason_codes": [],
        }
        if observed_version is not None:
            item["attestation_sdk_version"] = observed_version
        table.put_item(Item=item)

    put_agent("agent-current", "dep-approved")
    put_agent("agent-expired", "dep-approved", expires_at=now)
    put_agent("agent-mismatch", "dep-approved", observed_version="1.0.1")
    put_agent("agent-artifact", "dep-approved", manifest_digest="0" * 64)
    put_agent("agent-missing", "dep-approved", attestation_status="pending", observed_version=None)
    put_agent(
        "agent-quarantined",
        "dep-approved",
        status="quarantined",
        attestation_status="quarantined",
    )
    put_agent("agent-unapproved", "dep-unapproved", observed_version="9.9.9")
    for lifecycle_state in ("revoked", "deleted", "corrupt"):
        table.put_item(
            Item=module._item_key(tenant, "AGENT", f"dep-approved:agent-{lifecycle_state}")
            | {
                "id": f"agent-{lifecycle_state}",
                "deployment_id": "dep-approved",
                "host": "claude-code",
                "status": "connected",
                "lifecycle_state": lifecycle_state,
                "attestation_status": "compliant",
            }
        )
    table.put_item(
        Item=module._item_key(other_tenant, "AGENT", "dep-other:agent-secret")
        | {
            "id": "agent-secret",
            "deployment_id": "dep-other",
            "host": "claude-code",
            "status": "connected",
            "lifecycle_state": "active",
        }
    )

    report = module._version_compliance(tenant, now=now)

    assert report["totalAgents"] == 7
    assert report["compliantAgents"] == 1
    assert report["attentionAgents"] == 6
    assert report["scope"] == "fleet"
    assert report["hasMore"] is False
    assert report["nextToken"] is None
    assert {row["agentId"]: row["status"] for row in report["agents"]} == {
        "agent-current": "compliant",
        "agent-artifact": "artifact_mismatch",
        "agent-expired": "evidence_expired",
        "agent-mismatch": "version_mismatch",
        "agent-missing": "evidence_missing",
        "agent-quarantined": "quarantined",
        "agent-unapproved": "desired_release_unapproved",
    }
    assert "agent-secret" not in json.dumps(report)
    assert "agent-revoked" not in json.dumps(report)
    assert "agent-deleted" not in json.dumps(report)
    assert "agent-corrupt" not in json.dumps(report)
    assert report["deployments"] == [
        {
            "deploymentId": "dep-approved",
            "name": "Approved",
            "desiredSdkVersion": "1.1.0",
            "currentReleaseId": "claude-code:1.1.0",
            "targetReleaseId": None,
            "runtimeRolloutState": None,
            "runtimeRolloutPercentage": 0,
            "targetApproved": True,
            "agentCount": 6,
            "compliantAgents": 1,
            "attentionAgents": 5,
            "status": "attention",
        },
        {
            "deploymentId": "dep-unapproved",
            "name": "Unapproved",
            "desiredSdkVersion": "9.9.9",
            "currentReleaseId": "claude-code:9.9.9",
            "targetReleaseId": None,
            "runtimeRolloutState": None,
            "runtimeRolloutPercentage": 0,
            "targetApproved": False,
            "agentCount": 1,
            "compliantAgents": 0,
            "attentionAgents": 1,
            "status": "attention",
        },
    ]


def test_runtime_release_routes_require_explicit_read_authority(monkeypatch: Any) -> None:
    """A tenant identifier alone cannot disclose release or fleet compliance posture."""
    module, table = _load_handler(monkeypatch)
    _set_runtime_manifests(monkeypatch, [_runtime_manifest()])
    tenant = "tenant-release-route"
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant, "status": "active"}
    )
    unprivileged = {"custom:tenant_id": tenant, "sub": "unprivileged-user"}
    policy_only_roles = ("policy-author", "policy-approver")
    for path in (
        "/api/enterprise/runtime-releases",
        "/api/enterprise/runtime-rollouts",
        "/api/enterprise/version-compliance",
    ):
        denied = _invoke(module, _event(path, "GET", claims=unprivileged))
        assert denied["statusCode"] == 403
        for role in policy_only_roles:
            policy_only = _invoke(
                module,
                _event(
                    path,
                    "GET",
                    claims={
                        "custom:tenant_id": tenant,
                        "cognito:groups": [role],
                        "sub": f"synthetic-{role}",
                    },
                ),
            )
            assert policy_only["statusCode"] == 403
        for role in ("platform-admin", "security-operator", "fleet-operator", "auditor"):
            allowed = _invoke(
                module,
                _event(
                    path,
                    "GET",
                    claims={
                        "custom:tenant_id": tenant,
                        "cognito:groups": [role],
                        "sub": f"synthetic-{role}",
                    },
                ),
            )
            assert allowed["statusCode"] == 200
    invalid_page = _event(
        "/api/enterprise/version-compliance",
        "GET",
        claims={
            "custom:tenant_id": tenant,
            "cognito:groups": ["auditor"],
            "sub": "synthetic-auditor",
        },
    )
    invalid_page["queryStringParameters"] = {"limit": "0"}
    assert _invoke(module, invalid_page)["statusCode"] == 400


def test_version_compliance_quarantine_outranks_empty_release_authority(
    monkeypatch: Any,
) -> None:
    """Containment remains the primary operator signal when releases are absent."""
    module, table = _load_handler(monkeypatch)
    _set_runtime_manifests(monkeypatch, [])
    tenant = "tenant-empty-release"
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "dep-a")
        | {"id": "dep-a", "sdk_version": "1.1.0"}
    )
    for agent_id, status in (("agent-contained", "quarantined"), ("agent-open", "connected")):
        table.put_item(
            Item=module._item_key(tenant, "AGENT", f"dep-a:{agent_id}")
            | {
                "id": agent_id,
                "deployment_id": "dep-a",
                "host": "claude-code",
                "status": status,
                "lifecycle_state": "active",
                "attestation_status": status,
            }
        )

    report = module._version_compliance(tenant)

    assert report["releaseStatus"] == "not_configured"
    assert {row["agentId"]: row["status"] for row in report["agents"]} == {
        "agent-contained": "quarantined",
        "agent-open": "release_not_configured",
    }


def test_version_compliance_is_bounded_and_cursor_paginated(monkeypatch: Any) -> None:
    """Large fleets advance by tenant-bound pages instead of failing at 2,000 rows."""
    module, table = _load_handler(monkeypatch)
    _set_runtime_manifests(monkeypatch, [_runtime_manifest()])
    tenant = "tenant-version-pages"
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "dep-a")
        | {"id": "dep-a", "sdk_version": "1.1.0"}
    )
    manifest_digest = module._runtime_manifest_digest(_runtime_manifest())
    lifecycle_records = (
        ("00-revoked", "revoked"),
        ("01-deleted", "deleted"),
        ("02-corrupt", "corrupt"),
        ("10-active", "active"),
        ("11-active", "active"),
    )
    for agent_id, lifecycle_state in lifecycle_records:
        table.put_item(
            Item=module._item_key(tenant, "AGENT", f"dep-a:{agent_id}")
            | {
                "id": agent_id,
                "deployment_id": "dep-a",
                "host": "claude-code",
                "status": "connected",
                "lifecycle_state": lifecycle_state,
                "attestation_status": "compliant",
                "attestation_expires_at": 2_000_000_000,
                "attestation_sdk_version": "1.1.0",
                "attestation_sdk_revision": "a" * 40,
                "attestation_manifest_sha256": manifest_digest,
            }
        )
    original_query = table.query

    def paged_query(**kwargs: Any) -> dict[str, Any]:
        result = original_query(**kwargs)
        condition = kwargs.get("KeyConditionExpression")
        is_agent_query = isinstance(condition, FakeCondition) and any(
            operation == "begins_with" and expected == "AGENT#"
            for _field, operation, expected in condition.predicates
        )
        if not is_agent_query:
            return cast(dict[str, Any], result)
        items = sorted(result["Items"], key=lambda item: item["sk"])
        start = kwargs.get("ExclusiveStartKey")
        if start:
            items = [item for item in items if item["sk"] > start["sk"]]
        limit = kwargs["Limit"]
        page = items[:limit]
        response: dict[str, Any] = {"Items": page}
        if len(items) > limit:
            response["LastEvaluatedKey"] = {"pk": page[-1]["pk"], "sk": page[-1]["sk"]}
        return response

    monkeypatch.setattr(table, "query", paged_query)

    first = module._version_compliance(tenant, now=1_900_000_000, page_limit=3)
    second = module._version_compliance(
        tenant,
        now=1_900_000_000,
        page_limit=3,
        page_token=first["nextToken"],
    )

    assert first["scope"] == "page"
    assert first["hasMore"] is True
    assert first["totalAgents"] == 0
    assert second["scope"] == "page"
    assert second["hasMore"] is False
    assert second["totalAgents"] == 2
    assert {row["agentId"] for row in first["agents"] + second["agents"]} == {
        "10-active",
        "11-active",
    }
    assert second["deployments"][0]["status"] == "page_compliant"
    with pytest.raises(ValueError, match="outside the authorized tenant"):
        module._tenant_page_cursor("another-tenant", "AGENT", first["nextToken"])


def test_runtime_release_machine_routes_require_exact_inventory_scope(
    monkeypatch: Any,
) -> None:
    """Machine posture reads require a live inventory credential, not any service token."""
    module, table = _load_handler(monkeypatch)
    now = 1_900_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    _set_runtime_manifests(monkeypatch, [_runtime_manifest()])
    tenant = "tenant-release-machine"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-release-machine",
    }
    path = "/api/enterprise/identity/service-identities"

    def create_token(identity: str, capability: str) -> str:
        response = _invoke(
            module,
            _event(
                path,
                "POST",
                claims=platform,
                body={
                    "serviceIdentityId": identity,
                    "name": identity,
                    "description": "Synthetic release posture contract.",
                    "purpose": "Prove exact machine route authorization.",
                    "capabilities": [capability],
                    "expiresInDays": 1,
                },
            ),
        )
        assert response["statusCode"] == 201
        return cast(str, json.loads(response["body"])["credential"]["accessToken"])

    inventory_token = create_token("release-reader", "inventory_read")
    draft_token = create_token("release-drafter", "policy_draft_write")
    fleet_token = create_token("release-fleet-writer", "fleet_write")
    runtime_token = create_token("release-runtime-writer", "runtime_write")
    for suffix in ("runtime-releases", "runtime-rollouts", "version-compliance"):
        route = f"/machine/v1/enterprise/{suffix}"
        assert _invoke(module, _event(route, "GET", token=inventory_token))["statusCode"] == 200
        assert _invoke(module, _event(route, "GET", token=draft_token))["statusCode"] == 403
    delivery_route = _event(
        "/machine/v1/enterprise/endpoint-delivery", "GET", token=inventory_token
    )
    delivery_route["queryStringParameters"] = {"deploymentId": "missing-deployment"}
    assert _invoke(module, delivery_route)["statusCode"] == 404
    denied_delivery = _event("/machine/v1/enterprise/endpoint-delivery", "GET", token=draft_token)
    denied_delivery["queryStringParameters"] = {"deploymentId": "missing-deployment"}
    assert _invoke(module, denied_delivery)["statusCode"] == 403
    mutation = {
        "deploymentId": "missing-deployment",
        "expectedRevision": 0,
        "targetReleaseId": "claude-code:1.1.0",
        "targetState": "canary",
        "percentage": 10,
        "healthCriteria": {
            "maxUnavailablePercent": 10,
            "maxDriftPercent": 10,
            "minSampleSize": 1,
            "gracePeriodSeconds": 300,
        },
        "reason": "Synthetic exact machine runtime-write authorization contract.",
    }
    machine_route = "/machine/v1/enterprise/runtime-rollouts"
    assert (
        _invoke(module, _event(machine_route, "POST", body=mutation, token=runtime_token))[
            "statusCode"
        ]
        == 404
    )
    for denied_token in (inventory_token, draft_token, fleet_token):
        assert (
            _invoke(module, _event(machine_route, "POST", body=mutation, token=denied_token))[
                "statusCode"
            ]
            == 403
        )


def test_endpoint_delivery_readiness_requires_signed_platform_and_exact_package(
    monkeypatch: Any,
) -> None:
    """The control plane never guesses platform or exposes a package locator."""
    module, table = _load_handler(monkeypatch)
    now = 1_900_040_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    manifest = _runtime_manifest("claude-code", "1.1.0", "a" * 40)
    _set_runtime_manifests(monkeypatch, [manifest])
    tenant = "tenant-delivery-readiness"
    deployment_id = "deployment-delivery"
    agent_id = "agent-delivery"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", deployment_id)
        | {"id": deployment_id, "sdk_version": "1.1.0"}
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", f"{deployment_id}:{agent_id}")
        | {
            "id": agent_id,
            "deployment_id": deployment_id,
            "host": "claude-code",
            "project_root": "/synthetic/delivery",
            "status": "connected",
            "expires_at": now + 300,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
            "session_revision": 1,
        }
    )
    monkeypatch.setattr(
        module,
        "_authoritative_endpoint_devices",
        lambda *_args, **_kwargs: {"device-a": {"id": "device-a", "managed": True}},
    )
    binding = {
        "status": "bound",
        "reasonCode": "unique_current_match",
        "deviceId": "device-a",
        "agentKey": f"{deployment_id}:{agent_id}",
        "installationIds": ["installation-a"],
        "operatingSystem": None,
        "architecture": None,
        "bindingDigest": "b" * 64,
        "evidenceObservedAt": now - 10,
    }
    monkeypatch.setattr(module, "_endpoint_agent_binding", lambda *_args, **_kwargs: dict(binding))
    empty_catalog = {
        "schemaVersion": 1,
        "status": "not_configured",
        "packageBundleSha256": "c" * 64,
        "approvalBundleSha256": "d" * 64,
        "packages": [],
    }
    monkeypatch.setattr(module, "_delivery_package_catalog", lambda _catalog: empty_catalog)

    blocked = module._endpoint_delivery_readiness(tenant, deployment_id, now=now)

    assert blocked["readyAgents"] == 0
    assert blocked["blockedAgents"] == 1
    assert blocked["items"][0]["reasonCode"] == "platform_evidence_missing"
    assert blocked["items"][0]["packageId"] is None

    release_id = "claude-code:1.1.0"
    public_package = {
        "id": f"delivery:{'e' * 64}",
        "releaseId": release_id,
        "host": "claude-code",
        "operatingSystem": "darwin",
        "architecture": "arm64",
        "packageFormat": "pkg",
        "manifestSha256": "e" * 64,
        "objectSha256": "f" * 64,
        "storageIdentitySha256": "1" * 64,
        "providerPackageIdentitySha256": "2" * 64,
        "packageSignatureEvidenceSha256": "3" * 64,
        "releaseEvidenceSha256": "4" * 64,
        "approvedAt": "2026-08-05",
        "approverEvidenceSha256": "5" * 64,
    }
    configured_catalog = {**empty_catalog, "status": "configured", "packages": [public_package]}
    monkeypatch.setattr(
        module,
        "_endpoint_agent_binding",
        lambda *_args, **_kwargs: {
            **binding,
            "operatingSystem": "darwin",
            "architecture": "arm64",
        },
    )
    monkeypatch.setattr(module, "_delivery_package_catalog", lambda _catalog: configured_catalog)

    ready = module._endpoint_delivery_readiness(tenant, deployment_id, now=now)

    assert ready["readyAgents"] == 1
    assert ready["blockedAgents"] == 0
    assert ready["items"][0]["status"] == "ready"
    assert ready["items"][0]["packageId"] == public_package["id"]
    serialized = json.dumps(ready).lower()
    assert "bucketarn" not in serialized
    assert "objectkey" not in serialized
    assert "objectversionid" not in serialized

    route = _event(
        "/api/enterprise/endpoint-delivery",
        "GET",
        claims={
            "custom:tenant_id": tenant,
            "cognito:groups": ["fleet-operator"],
            "sub": "fleet-delivery-reader",
        },
    )
    route["queryStringParameters"] = {"deploymentId": deployment_id}
    response = _invoke(module, route)
    assert response["statusCode"] == 200, response
    assert json.loads(response["body"])["items"][0]["status"] == "ready"
    denied = _event(
        "/api/enterprise/endpoint-delivery",
        "GET",
        claims={
            "custom:tenant_id": tenant,
            "cognito:groups": ["policy-author"],
            "sub": "policy-only-reader",
        },
    )
    denied["queryStringParameters"] = {"deploymentId": deployment_id}
    assert _invoke(module, denied)["statusCode"] == 403

    table.put_item(
        Item=module._item_key(tenant, "AGENT", "other-deployment:agent-duplicate")
        | {
            "id": "agent-duplicate",
            "deployment_id": "other-deployment",
            "host": "claude-code",
            "project_root": "/synthetic/delivery",
            "status": "connected",
            "expires_at": now + 300,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
            "session_revision": 1,
        }
    )

    def ambiguous_binding(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        candidates = kwargs["agent_candidates"]
        root_digest = hashlib.sha256(b"/synthetic/delivery").hexdigest()
        assert len(candidates[("claude-code", root_digest)]) == 2
        return {
            **binding,
            "status": "ambiguous",
            "reasonCode": "agent_match_not_unique",
            "agentKey": None,
            "operatingSystem": "darwin",
            "architecture": "arm64",
        }

    monkeypatch.setattr(module, "_endpoint_agent_binding", ambiguous_binding)
    ambiguous = module._endpoint_delivery_readiness(tenant, deployment_id, now=now)
    assert ambiguous["items"][0]["status"] == "blocked"
    assert ambiguous["items"][0]["reasonCode"] == "endpoint_binding_missing"


def test_endpoint_discovery_requires_canonical_directory_registration_identity(
    monkeypatch: Any,
) -> None:
    """Provider target identity is canonical MDM authority, not arbitrary text."""
    module, _table = _load_handler(monkeypatch)
    valid = module._discovery_observation(
        {
            "kind": "device",
            "id": "device-a",
            "managed": True,
            "directoryDeviceRegistrationId": ("22222222-2222-4222-8222-222222222222"),
        },
        "endpoint",
    )
    assert valid["directoryDeviceRegistrationId"] == ("22222222-2222-4222-8222-222222222222")
    for invalid in ("not-a-uuid", "22222222-2222-4222-8222-22222222222A"):
        with pytest.raises(ValueError, match="canonical UUID"):
            module._discovery_observation(
                {
                    "kind": "device",
                    "id": "device-a",
                    "managed": True,
                    "directoryDeviceRegistrationId": invalid,
                },
                "endpoint",
            )


def test_runtime_remediation_is_machine_scoped_revision_bound_and_attestation_verified(
    monkeypatch: Any,
) -> None:
    """An MDM worker can report delivery, but only fresh exact attestation proves success."""
    module, table = _load_handler(monkeypatch)
    now = 1_900_050_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    current_manifest = _runtime_manifest("claude-code", "1.1.0", "a" * 40)
    target_manifest = _runtime_manifest("claude-code", "1.2.0", "f" * 40)
    _set_runtime_manifests(monkeypatch, [current_manifest, target_manifest])
    tenant = "tenant-runtime-remediation"
    deployment_id = "deployment-remediation"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", deployment_id)
        | {
            "id": deployment_id,
            "organization_id": "organization-remediation",
            "project_id": "project-remediation",
            "sdk_version": "1.1.0",
        }
    )
    current_digest = module._runtime_manifest_digest(current_manifest)
    target_digest = module._runtime_manifest_digest(target_manifest)
    for index in range(20):
        agent_id = f"agent-{index:02d}"
        table.put_item(
            Item=module._item_key(tenant, "AGENT", f"{deployment_id}:{agent_id}")
            | {
                "id": agent_id,
                "deployment_id": deployment_id,
                "host": "claude-code",
                "status": "connected",
                "expires_at": now + 3_600,
                "lifecycle_state": "active",
                "lifecycle_revision": 1,
                "session_revision": 1,
                "attestation_status": "compliant",
                "attestation_observed_at": now - 30,
                "attestation_expires_at": now + 300,
                "attestation_sdk_version": "1.1.0",
                "attestation_sdk_revision": "a" * 40,
                "attestation_manifest_sha256": current_digest,
            }
        )
    fleet_operator = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "fleet-remediation-operator",
    }
    rollout = _invoke(
        module,
        _event(
            "/api/enterprise/runtime-rollouts",
            "POST",
            claims=fleet_operator,
            body={
                "deploymentId": deployment_id,
                "expectedRevision": 0,
                "targetReleaseId": "claude-code:1.2.0",
                "targetState": "canary",
                "percentage": 25,
                "healthCriteria": {
                    "maxUnavailablePercent": 10,
                    "maxDriftPercent": 10,
                    "minSampleSize": 1,
                    "gracePeriodSeconds": 300,
                },
                "reason": "Deliver an approved release through the bounded endpoint channel.",
            },
        ),
    )
    assert rollout["statusCode"] == 201, rollout
    queue_event = _event("/api/enterprise/runtime-remediations", "GET", claims=fleet_operator)
    queue_event["queryStringParameters"] = {
        "deploymentId": deployment_id,
        "limit": "2",
    }
    queue_response = _invoke(module, queue_event)
    assert queue_response["statusCode"] == 200, queue_response
    queue = json.loads(queue_response["body"])
    assert queue["totalItems"] > 2
    assert queue["hasMore"] is True
    assert queue["nextToken"]
    assert queue["statusCounts"]["pending"] == queue["totalItems"]
    assert queue["channelStatusCounts"]["not_started"] == queue["totalItems"]
    assert queue["runtimeVerificationCounts"]["not_verified"] == queue["totalItems"]
    instruction = queue["items"][0]
    assert instruction["status"] == "pending"
    assert instruction["taskRevision"] == 0
    serialized = json.dumps(instruction).lower()
    assert all(
        value not in serialized for value in ("https://", "command", "projectroot", "base64")
    )

    next_event = _event("/api/enterprise/runtime-remediations", "GET", claims=fleet_operator)
    next_event["queryStringParameters"] = {
        "deploymentId": deployment_id,
        "limit": "2",
        "nextToken": queue["nextToken"],
    }
    next_page = json.loads(_invoke(module, next_event)["body"])
    assert {item["agentId"] for item in queue["items"]}.isdisjoint(
        {item["agentId"] for item in next_page["items"]}
    )
    cross_deployment = _event("/api/enterprise/runtime-remediations", "GET", claims=fleet_operator)
    cross_deployment["queryStringParameters"] = {
        "deploymentId": "another-deployment",
        "nextToken": queue["nextToken"],
    }
    assert _invoke(module, cross_deployment)["statusCode"] in {400, 404}

    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-remediation-admin",
    }

    def service_token(identity: str, capabilities: list[str]) -> str:
        response = _invoke(
            module,
            _event(
                "/api/enterprise/identity/service-identities",
                "POST",
                claims=platform,
                body={
                    "serviceIdentityId": identity,
                    "name": identity,
                    "description": "Synthetic endpoint-management channel.",
                    "purpose": "Prove exact runtime remediation authority.",
                    "capabilities": capabilities,
                    "expiresInDays": 1,
                },
            ),
        )
        assert response["statusCode"] == 201, response
        return cast(str, json.loads(response["body"])["credential"]["accessToken"])

    worker_token = service_token(
        "runtime-remediation-worker", ["inventory_read", "runtime_remediation"]
    )
    runtime_token = service_token("runtime-rollout-writer", ["runtime_write"])
    claim_path = (
        f"/machine/v1/enterprise/runtime-remediations/{deployment_id}/"
        f"{instruction['agentId']}/claim"
    )
    claim_body = {
        "instructionId": instruction["instructionId"],
        "expectedTaskRevision": 0,
        "requestId": "claim-runtime-remediation-001",
    }
    rollout_key = module._item_key(tenant, "RUNTIME_ROLLOUT", deployment_id)
    agent_key_shape = module._item_key(tenant, "AGENT", f"{deployment_id}:{instruction['agentId']}")
    original_rollout = dict(table.items[(rollout_key["pk"], rollout_key["sk"])])
    original_agent = dict(table.items[(agent_key_shape["pk"], agent_key_shape["sk"])])

    def race_rollout() -> None:
        table.items[(rollout_key["pk"], rollout_key["sk"])].update(
            {"revision": original_rollout["revision"] + 1, "state": "paused"}
        )

    module.DYNAMODB.before_transaction = race_rollout
    with pytest.raises(module.PolicyConflict, match="revision changed"):
        module._claim_runtime_remediation(
            tenant, deployment_id, instruction["agentId"], claim_body, "service:worker"
        )
    assert module._runtime_remediation_task(tenant, deployment_id, instruction["agentId"]) is None
    table.items[(rollout_key["pk"], rollout_key["sk"])] = dict(original_rollout)

    def race_quarantine() -> None:
        table.items[(agent_key_shape["pk"], agent_key_shape["sk"])].update(
            {"status": "quarantined", "attestation_status": "quarantined"}
        )

    module.DYNAMODB.before_transaction = race_quarantine
    with pytest.raises(module.PolicyConflict, match="revision changed"):
        module._claim_runtime_remediation(
            tenant,
            deployment_id,
            instruction["agentId"],
            {**claim_body, "requestId": "claim-runtime-remediation-race-agent"},
            "service:worker",
        )
    assert module._runtime_remediation_task(tenant, deployment_id, instruction["agentId"]) is None
    table.items[(agent_key_shape["pk"], agent_key_shape["sk"])] = dict(original_agent)
    assert (
        _invoke(
            module,
            _event(
                claim_path,
                "POST",
                body=claim_body,
                token="synthetic-agent-session-token-123456",  # noqa: S106 - synthetic fixture.
            ),
        )["statusCode"]
        == 403
    )
    assert (
        _invoke(module, _event(claim_path, "POST", body=claim_body, token=runtime_token))[
            "statusCode"
        ]
        == 403
    )
    human_claim = _invoke(
        module,
        _event(
            claim_path.replace("/machine/v1", "/api"),
            "POST",
            body=claim_body,
            claims=platform,
        ),
    )
    assert human_claim["statusCode"] == 403
    claimed_response = _invoke(
        module, _event(claim_path, "POST", body=claim_body, token=worker_token)
    )
    assert claimed_response["statusCode"] == 200, claimed_response
    claimed = json.loads(claimed_response["body"])
    assert claimed["status"] == "in_progress"
    assert claimed["channelStatus"] == "in_progress"
    assert claimed["runtimeVerification"] == "not_verified"
    assert claimed["taskRevision"] == 1
    assert claimed["attempts"] == 1
    duplicate_claim_response = _invoke(
        module, _event(claim_path, "POST", body=claim_body, token=worker_token)
    )
    assert duplicate_claim_response["statusCode"] == 200, duplicate_claim_response
    duplicate_claim = json.loads(duplicate_claim_response["body"])
    assert duplicate_claim["taskRevision"] == 1
    conflicting_claim = _invoke(
        module,
        _event(
            claim_path,
            "POST",
            body={
                **claim_body,
                "requestId": "claim-runtime-remediation-002",
                "expectedTaskRevision": 1,
            },
            token=worker_token,
        ),
    )
    assert conflicting_claim["statusCode"] == 409

    worker_actor = module._runtime_remediation_task(tenant, deployment_id, instruction["agentId"])[
        "claimedBy"
    ]
    module.DYNAMODB.before_transaction = race_rollout
    with pytest.raises(module.PolicyConflict, match="revision changed"):
        module._report_runtime_remediation(
            tenant,
            deployment_id,
            instruction["agentId"],
            {
                "instructionId": instruction["instructionId"],
                "expectedTaskRevision": 1,
                "requestId": "report-runtime-remediation-race",
                "outcome": "installed",
                "reasonCode": None,
            },
            worker_actor,
        )
    table.items[(rollout_key["pk"], rollout_key["sk"])] = dict(original_rollout)
    assert (
        module._runtime_remediation_task(tenant, deployment_id, instruction["agentId"])["status"]
        == "claimed"
    )

    report_path = claim_path.removesuffix("claim") + "report"
    invalid_report = _invoke(
        module,
        _event(
            report_path,
            "POST",
            body={
                "instructionId": instruction["instructionId"],
                "expectedTaskRevision": 1,
                "requestId": "report-runtime-remediation-invalid",
                "outcome": "failed",
                "reasonCode": "raw_shell_error",
            },
            token=worker_token,
        ),
    )
    assert invalid_report["statusCode"] == 400
    installed_body = {
        "instructionId": instruction["instructionId"],
        "expectedTaskRevision": 1,
        "requestId": "report-runtime-remediation-001",
        "outcome": "installed",
        "reasonCode": None,
    }
    installed_response = _invoke(
        module, _event(report_path, "POST", body=installed_body, token=worker_token)
    )
    assert installed_response["statusCode"] == 200, installed_response
    installed = json.loads(installed_response["body"])
    assert installed["status"] == "awaiting_attestation"
    assert installed["channelStatus"] == "installed_reported"
    assert installed["runtimeVerification"] == "not_verified"
    assert installed["taskRevision"] == 2
    rollout_record = module._runtime_rollout_record(tenant, deployment_id)
    assert (
        module._runtime_rollout_convergence(tenant, rollout_record, now=now)["canaryConverged"]
        is False
    )

    agent_key = (f"TENANT#{tenant}", f"AGENT#{deployment_id}:{instruction['agentId']}")
    table.items[agent_key].update(
        {
            "attestation_sdk_version": "1.2.0",
            "attestation_sdk_revision": "f" * 40,
            "attestation_manifest_sha256": target_digest,
        }
    )
    stale_observation = module._runtime_remediations(tenant, deployment_id, now=now)
    stale_item = next(
        item for item in stale_observation["items"] if item["agentId"] == instruction["agentId"]
    )
    assert stale_item["runtimeVerification"] == "not_verified"
    table.items[agent_key]["attestation_observed_at"] = now
    verified = module._runtime_remediations(tenant, deployment_id, now=now)
    verified_item = next(
        item for item in verified["items"] if item["agentId"] == instruction["agentId"]
    )
    assert verified_item["status"] == "verified"
    assert verified_item["channelStatus"] == "installed_reported"
    assert verified_item["runtimeVerification"] == "verified"
    assert verified["channelStatusCounts"]["installed_reported"] >= 1
    assert verified["runtimeVerificationCounts"]["verified"] >= 1
    assert verified_item["taskRevision"] == 2
    assert any(
        item.get("event_type") == "runtime_remediation_install_reported"
        and item["payload"]["instruction_id"] == instruction["instructionId"]
        and re.fullmatch(r"[0-9a-f]{64}", item["payload"]["task_sha256"])
        for item in table.items.values()
    )


def test_runtime_remediation_malformed_state_and_stale_instruction_fail_closed(
    monkeypatch: Any,
) -> None:
    """Persisted task corruption and rollout changes cannot be reported as success."""
    module, table = _load_handler(monkeypatch)
    now = 1_900_060_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    manifests = [
        _runtime_manifest("codex-cli", "1.1.0", "a" * 40),
        _runtime_manifest("codex-cli", "1.2.0", "f" * 40),
    ]
    _set_runtime_manifests(monkeypatch, manifests)
    tenant = "tenant-runtime-remediation-closed"
    deployment_id = "deployment-remediation-closed"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", deployment_id)
        | {"id": deployment_id, "sdk_version": "1.1.0"}
    )
    agent_id = next(
        f"agent-{index}"
        for index in range(1_000)
        if module._rollout_agent_selected(tenant, f"{deployment_id}:agent-{index}", 25)
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", f"{deployment_id}:{agent_id}")
        | {
            "id": agent_id,
            "deployment_id": deployment_id,
            "host": "codex-cli",
            "status": "connected",
            "expires_at": now + 300,
            "lifecycle_state": "active",
            "attestation_status": "compliant",
            "attestation_expires_at": now + 300,
            "attestation_sdk_version": "1.1.0",
            "attestation_sdk_revision": "a" * 40,
            "attestation_manifest_sha256": module._runtime_manifest_digest(manifests[0]),
        }
    )
    catalog = module._runtime_release_catalog()
    releases = module._runtime_release_map(catalog)
    module._put_runtime_rollout(
        tenant,
        None,
        {
            "schemaVersion": 1,
            "deploymentId": deployment_id,
            "host": "codex-cli",
            "state": "canary",
            "currentReleaseId": "codex-cli:1.1.0",
            "currentReleaseBinding": module._runtime_release_binding(
                catalog, releases["codex-cli:1.1.0"]
            ),
            "targetReleaseId": "codex-cli:1.2.0",
            "targetReleaseBinding": module._runtime_release_binding(
                catalog, releases["codex-cli:1.2.0"]
            ),
            "percentage": 25,
            "healthCriteria": {
                "maxUnavailablePercent": 10,
                "maxDriftPercent": 10,
                "minSampleSize": 1,
                "gracePeriodSeconds": 300,
            },
            "reason": "Exercise malformed endpoint remediation evidence.",
            "startedAt": now,
            "startedBy": "operator-a",
            "pausedAt": None,
            "pauseReason": None,
            "selectedMemberDigests": [],
        },
        "runtime_release_rollout_started",
        "operator-a",
        "Exercise malformed endpoint remediation evidence.",
    )
    instruction = module._runtime_remediations(tenant, deployment_id, now=now)["items"][0]
    claimed = module._claim_runtime_remediation(
        tenant,
        deployment_id,
        agent_id,
        {
            "instructionId": instruction["instructionId"],
            "expectedTaskRevision": 0,
            "requestId": "claim-before-authority-change",
        },
        "service:worker",
    )
    assert claimed["status"] == "in_progress"
    task_key = module._item_key(tenant, "RUNTIME_REMEDIATION", f"{deployment_id}:{agent_id}")
    task_snapshot = dict(table.items[(task_key["pk"], task_key["sk"])])
    table.items[(task_key["pk"], task_key["sk"])]["releaseId"] = "codex-cli:9.9.9"
    with pytest.raises(RuntimeError, match="contradicts its live instruction"):
        module._runtime_remediations(tenant, deployment_id, now=now)
    table.items[(task_key["pk"], task_key["sk"])] = task_snapshot
    rollout = module._runtime_rollout_record(tenant, deployment_id)
    module._pause_runtime_rollout(
        tenant,
        deployment_id,
        {
            "expectedRevision": rollout["revision"],
            "reason": "Freeze dispatch while endpoint evidence is investigated.",
        },
        "operator-a",
    )
    with pytest.raises(module.PolicyConflict, match="instruction changed"):
        module._report_runtime_remediation(
            tenant,
            deployment_id,
            agent_id,
            {
                "instructionId": instruction["instructionId"],
                "expectedTaskRevision": claimed["taskRevision"],
                "requestId": "report-after-authority-change",
                "outcome": "installed",
                "reasonCode": None,
            },
            "service:worker",
        )
    table.put_item(
        Item=module._item_key(tenant, "RUNTIME_REMEDIATION", f"{deployment_id}:{agent_id}")
        | {
            "tenant_id": tenant,
            "schemaVersion": 1,
            "deploymentId": deployment_id,
            "agentId": agent_id,
            "instructionId": instruction["instructionId"],
            "rolloutRevision": 1,
            "releaseId": instruction["releaseId"],
            "revision": 1,
            "attempts": 1,
            "status": "installed",
            "claimRequestId": "claim-corrupt",
            "claimedAt": now,
            "leaseExpiresAt": now + 900,
            "claimedBy": "service:worker",
            "reportRequestId": "report-corrupt",
            "reportedAt": now,
            "outcome": "installed",
            "reasonCode": "installation_failed",
            "updatedAt": now,
        }
    )
    with pytest.raises(RuntimeError, match="successful runtime remediation"):
        module._runtime_remediations(tenant, deployment_id, now=now)


def test_runtime_release_rollout_admits_only_current_and_selected_target_versions(
    monkeypatch: Any,
) -> None:
    """A deterministic canary may move from one exact approved release to another."""
    module, table = _load_handler(monkeypatch)
    now = 1_900_100_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    current_manifest = _runtime_manifest("claude-code", "1.1.0", "a" * 40)
    target_manifest = _runtime_manifest("claude-code", "1.2.0", "f" * 40)
    _set_runtime_manifests(monkeypatch, [current_manifest, target_manifest])
    tenant = "tenant-runtime-canary"
    deployment_id = "dep-runtime"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", deployment_id)
        | {"id": deployment_id, "name": "Runtime canary", "sdk_version": "1.1.0"}
    )
    agent_ids = [f"agent-{index}" for index in range(12)]
    current_digest = module._runtime_manifest_digest(current_manifest)
    target_digest = module._runtime_manifest_digest(target_manifest)
    for agent_id in agent_ids:
        table.put_item(
            Item=module._item_key(tenant, "AGENT", f"{deployment_id}:{agent_id}")
            | {
                "id": agent_id,
                "deployment_id": deployment_id,
                "host": "claude-code",
                "status": "connected",
                "expires_at": now + 3_600,
                "lifecycle_state": "active",
                "attestation_status": "compliant",
                "attestation_expires_at": now + 300,
                "attestation_sdk_version": "1.1.0",
                "attestation_sdk_revision": "a" * 40,
                "attestation_manifest_sha256": current_digest,
            }
        )
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "runtime-operator",
    }
    request = {
        "deploymentId": deployment_id,
        "expectedRevision": 0,
        "targetReleaseId": "claude-code:1.2.0",
        "targetState": "canary",
        "percentage": 25,
        "healthCriteria": {
            "maxUnavailablePercent": 10,
            "maxDriftPercent": 10,
            "minSampleSize": 1,
            "gracePeriodSeconds": 300,
        },
        "reason": "Move the approved SDK release through a deterministic production canary.",
    }
    started = _invoke(
        module,
        _event("/enterprise/runtime-rollouts", "POST", body=request, claims=claims),
    )
    assert started["statusCode"] == 201, started
    canary = json.loads(started["body"])
    assert canary["state"] == "canary"
    assert canary["revision"] == 1
    assert 0 < canary["convergence"]["selectedAgents"] < len(agent_ids)

    def ddb_resource_shape(value: Any) -> Any:
        if isinstance(value, bool) or value is None or isinstance(value, str):
            return value
        if isinstance(value, int):
            return Decimal(value)
        if isinstance(value, list):
            return [ddb_resource_shape(item) for item in value]
        if isinstance(value, dict):
            return {key: ddb_resource_shape(item) for key, item in value.items()}
        return value

    rollout_key = (f"TENANT#{tenant}", f"RUNTIME_ROLLOUT#{deployment_id}")
    table.items[rollout_key] = ddb_resource_shape(table.items[rollout_key])
    assert isinstance(table.items[rollout_key]["revision"], Decimal)
    assert isinstance(
        table.items[rollout_key]["targetReleaseBinding"]["attestationManifest"]["schemaVersion"],
        Decimal,
    )
    assert (
        module._runtime_manifest(
            tenant,
            deployment_id,
            "claude-code",
            agent=table.items[(f"TENANT#{tenant}", f"AGENT#{deployment_id}:{agent_ids[0]}")],
        )
        is not None
    )
    assert (
        _invoke(module, _event("/enterprise/runtime-rollouts", "GET", claims=claims))["statusCode"]
        == 200
    )
    selected = {
        agent_id
        for agent_id in agent_ids
        if module._rollout_agent_selected(
            tenant, f"{deployment_id}:{agent_id}", canary["percentage"]
        )
    }
    stored_open = table.items[(f"TENANT#{tenant}", f"RUNTIME_ROLLOUT#{deployment_id}")]
    target_id = stored_open["targetReleaseId"]
    target_binding = stored_open["targetReleaseBinding"]
    stored_open["targetReleaseId"] = None
    stored_open["targetReleaseBinding"] = None
    unselected_agent = table.items[
        (
            f"TENANT#{tenant}",
            f"AGENT#{deployment_id}:{next(agent for agent in agent_ids if agent not in selected)}",
        )
    ]
    with pytest.raises(RuntimeError, match="release binding is malformed"):
        module._require_current_attestation(tenant, deployment_id, unselected_agent)
    stored_open["targetReleaseId"] = target_id
    stored_open["targetReleaseBinding"] = target_binding
    paused_response = _invoke(
        module,
        _event(
            f"/enterprise/runtime-rollouts/{deployment_id}/pause",
            "POST",
            body={
                "expectedRevision": canary["revision"],
                "reason": "Freeze the exact canary cohort while evidence is investigated.",
            },
            claims=claims,
        ),
    )
    assert paused_response["statusCode"] == 200
    paused = json.loads(paused_response["body"])
    newcomer_id = next(
        f"new-agent-{index}"
        for index in range(1_000)
        if module._rollout_agent_selected(
            tenant, f"{deployment_id}:new-agent-{index}", canary["percentage"]
        )
    )
    newcomer = module._item_key(tenant, "AGENT", f"{deployment_id}:{newcomer_id}") | {
        "id": newcomer_id,
        "deployment_id": deployment_id,
        "host": "claude-code",
        "status": "connected",
        "expires_at": now + 3_600,
        "lifecycle_state": "active",
        "attestation_status": "compliant",
        "attestation_expires_at": now + 300,
        "attestation_sdk_version": "1.1.0",
        "attestation_sdk_revision": "a" * 40,
        "attestation_manifest_sha256": current_digest,
    }
    table.put_item(Item=newcomer)
    assert (
        module._runtime_manifest(tenant, deployment_id, "claude-code", agent=newcomer)["sdkVersion"]
        == "1.1.0"
    )
    replacement_target = _runtime_manifest("claude-code", "1.2.0", "e" * 40)
    _set_runtime_manifests(monkeypatch, [current_manifest, replacement_target])
    original_selected = table.items[
        (f"TENANT#{tenant}", f"AGENT#{deployment_id}:{next(iter(selected))}")
    ]
    assert (
        module._runtime_manifest(tenant, deployment_id, "claude-code", agent=original_selected)[
            "sdkRevision"
        ]
        == "f" * 40
    )
    _set_runtime_manifests(monkeypatch, [])
    assert (
        module._runtime_manifest(tenant, deployment_id, "claude-code", agent=original_selected)[
            "sdkRevision"
        ]
        == "f" * 40
    )
    with pytest.raises(PermissionError, match="current approved release"):
        module._require_current_attestation(tenant, deployment_id, original_selected)
    _set_runtime_manifests(monkeypatch, [current_manifest, replacement_target])
    resumed_response = _invoke(
        module,
        _event(
            "/enterprise/runtime-rollouts",
            "POST",
            body={**request, "expectedRevision": paused["revision"]},
            claims=claims,
        ),
    )
    assert resumed_response["statusCode"] == 201
    canary = json.loads(resumed_response["body"])
    agent_ids.append(newcomer_id)
    selected.add(newcomer_id)
    for agent_id in agent_ids:
        agent = table.items[(f"TENANT#{tenant}", f"AGENT#{deployment_id}:{agent_id}")]
        manifest = module._runtime_manifest(tenant, deployment_id, "claude-code", agent=agent)
        assert manifest["sdkVersion"] == ("1.2.0" if agent_id in selected else "1.1.0")
        if agent_id in selected:
            with pytest.raises(PermissionError, match="current approved release"):
                module._require_current_attestation(tenant, deployment_id, agent)
            agent.update(
                {
                    "attestation_sdk_version": "1.2.0",
                    "attestation_sdk_revision": "f" * 40,
                    "attestation_manifest_sha256": target_digest,
                    "attestation_observed_at": now,
                }
            )
        else:
            module._require_current_attestation(tenant, deployment_id, agent)
    canary_read = json.loads(
        _invoke(module, _event("/enterprise/runtime-rollouts", "GET", claims=claims))["body"]
    )["items"][0]
    assert canary_read["convergence"]["canaryConverged"] is True
    expanded = _invoke(
        module,
        _event(
            "/enterprise/runtime-rollouts",
            "POST",
            body={
                **request,
                "expectedRevision": canary_read["revision"],
                "targetState": "active",
                "percentage": 100,
            },
            claims=claims,
        ),
    )
    assert expanded["statusCode"] == 201, expanded
    assert json.loads(expanded["body"])["state"] == "active"
    for agent_id in agent_ids:
        agent = table.items[(f"TENANT#{tenant}", f"AGENT#{deployment_id}:{agent_id}")]
        agent.update(
            {
                "attestation_sdk_version": "1.2.0",
                "attestation_sdk_revision": "f" * 40,
                "attestation_manifest_sha256": target_digest,
                "attestation_observed_at": now,
            }
        )
    completed = json.loads(
        _invoke(module, _event("/enterprise/runtime-rollouts", "GET", claims=claims))["body"]
    )["items"][0]
    assert completed["state"] == "converged"
    assert completed["currentReleaseId"] == "claude-code:1.2.0"
    assert completed["convergence"]["fullConverged"] is True
    compliance = module._version_compliance(tenant, now=now)
    assert compliance["compliantAgents"] == len(agent_ids)
    assert compliance["deployments"][0]["currentReleaseId"] == "claude-code:1.2.0"
    assert compliance["deployments"][0]["runtimeRolloutState"] == "converged"
    stored_rollout = table.items[(f"TENANT#{tenant}", f"RUNTIME_ROLLOUT#{deployment_id}")]
    authority_document = {
        key: module._json(value)
        for key, value in stored_rollout.items()
        if key not in {"pk", "sk", "tenant_id"}
    }
    authority_sha256 = hashlib.sha256(
        json.dumps(authority_document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    convergence_audit = next(
        item
        for item in table.items.values()
        if item.get("event_type") == "runtime_release_rollout_converged"
    )
    assert convergence_audit["payload"]["authority_sha256"] == authority_sha256
    assert convergence_audit["payload"]["state"] == "converged"
    assert convergence_audit["payload"]["health_criteria"] == request["healthCriteria"]
    stored_rollout["state"] = "browser_claimed_healthy"
    with pytest.raises(RuntimeError, match="state is invalid"):
        module._runtime_manifest(
            tenant,
            deployment_id,
            "claude-code",
            agent=table.items[(f"TENANT#{tenant}", f"AGENT#{deployment_id}:{agent_ids[0]}")],
        )
    stored_rollout["state"] = "converged"
    stored_rollout.pop("currentReleaseBinding")
    with pytest.raises(RuntimeError, match="record has an invalid schema"):
        module._runtime_manifest(
            tenant,
            deployment_id,
            "claude-code",
            agent=table.items[(f"TENANT#{tenant}", f"AGENT#{deployment_id}:{agent_ids[0]}")],
        )


def test_runtime_release_rollout_rejects_switches_and_supports_measured_rollback(
    monkeypatch: Any,
) -> None:
    """Target switching, premature expansion and stale writes fail closed."""
    module, table = _load_handler(monkeypatch)
    now = 1_900_200_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    manifests = [
        _runtime_manifest("codex-cli", "1.1.0", "a" * 40),
        _runtime_manifest("codex-cli", "1.2.0", "f" * 40),
        _runtime_manifest("codex-cli", "1.3.0", "e" * 40),
    ]
    _set_runtime_manifests(monkeypatch, manifests)
    tenant = "tenant-runtime-rollback"
    deployment_id = "dep-codex"
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", deployment_id)
        | {
            "id": deployment_id,
            "organization_id": "org-runtime",
            "project_id": "project-runtime",
            "sdk_version": "1.1.0",
        }
    )
    current_digest = module._runtime_manifest_digest(manifests[0])
    for index in range(8):
        agent_id = f"agent-{index}"
        table.put_item(
            Item=module._item_key(tenant, "AGENT", f"{deployment_id}:{agent_id}")
            | {
                "id": agent_id,
                "deployment_id": deployment_id,
                "host": "codex-cli",
                "status": "connected",
                "expires_at": now + 3_600,
                "lifecycle_state": "active",
                "attestation_status": "compliant",
                "attestation_expires_at": now + 300,
                "attestation_sdk_version": "1.1.0",
                "attestation_sdk_revision": "a" * 40,
                "attestation_manifest_sha256": current_digest,
            }
        )
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["fleet-operator"],
        "sub": "runtime-operator",
    }
    base = {
        "deploymentId": deployment_id,
        "expectedRevision": 0,
        "targetReleaseId": "codex-cli:1.2.0",
        "targetState": "canary",
        "percentage": 25,
        "healthCriteria": {
            "maxUnavailablePercent": 10,
            "maxDriftPercent": 10,
            "minSampleSize": 100,
            "gracePeriodSeconds": 300,
        },
        "reason": "Validate the approved Codex runtime release on a bounded canary ring.",
    }
    for denied_role in (
        "security-operator",
        "policy-author",
        "policy-approver",
        "incident-responder",
        "auditor",
    ):
        denied_role_response = _invoke(
            module,
            _event(
                "/enterprise/runtime-rollouts",
                "POST",
                body=base,
                claims={
                    "custom:tenant_id": tenant,
                    "cognito:groups": [denied_role],
                    "sub": f"denied-{denied_role}",
                },
            ),
        )
        assert denied_role_response["statusCode"] == 403
    cross_tenant = _invoke(
        module,
        _event(
            "/enterprise/runtime-rollouts",
            "POST",
            body=base,
            claims={
                "custom:tenant_id": "tenant-runtime-other",
                "cognito:groups": ["fleet-operator"],
                "sub": "other-tenant-operator",
            },
        ),
    )
    assert cross_tenant["statusCode"] == 403
    assert module._runtime_rollout_record("tenant-runtime-other", deployment_id) is None
    table.put_item(
        Item=module._item_key(tenant, "DELEGATED_GRANT", "other-deployment-only")
        | {
            "id": "other-deployment-only",
            "principal_id": "delegated-runtime-operator",
            "role": "fleet-operator",
            "scope_type": "deployment",
            "scope_id": "other-deployment",
            "status": "active",
            "expires_at": now + 300,
            "revision": 1,
        }
    )
    delegated_denied = _invoke(
        module,
        _event(
            "/enterprise/runtime-rollouts",
            "POST",
            body=base,
            claims={
                "custom:tenant_id": tenant,
                "sub": "delegated-runtime-operator",
                "aai:delegated": "true",
            },
        ),
    )
    assert delegated_denied["statusCode"] == 403
    undersized_broad = _invoke(
        module,
        _event(
            "/enterprise/runtime-rollouts",
            "POST",
            body={**base, "targetState": "active", "percentage": 25},
            claims=claims,
        ),
    )
    assert undersized_broad["statusCode"] == 400
    started = _invoke(
        module, _event("/enterprise/runtime-rollouts", "POST", body=base, claims=claims)
    )
    assert started["statusCode"] == 201
    canary = json.loads(started["body"])
    for changed in (
        {"targetState": "active", "percentage": 100},
        {"targetReleaseId": "codex-cli:1.3.0"},
    ):
        denied = _invoke(
            module,
            _event(
                "/enterprise/runtime-rollouts",
                "POST",
                body={**base, "expectedRevision": canary["revision"], **changed},
                claims=claims,
            ),
        )
        assert denied["statusCode"] == 409
    target_digest = module._runtime_manifest_digest(manifests[1])
    selected_agents = []
    for index in range(8):
        agent = table.items[(f"TENANT#{tenant}", f"AGENT#{deployment_id}:agent-{index}")]
        if module._rollout_agent_selected(
            tenant, f"{deployment_id}:{agent['id']}", canary["percentage"]
        ):
            selected_agents.append(agent)
            agent.update(
                {
                    "attestation_sdk_version": "1.2.0",
                    "attestation_sdk_revision": "f" * 40,
                    "attestation_manifest_sha256": target_digest,
                    "attestation_observed_at": now,
                }
            )
    insufficient = module._runtime_rollout_convergence(
        tenant, module._runtime_rollout_record(tenant, deployment_id), now=now
    )
    assert selected_agents
    assert insufficient["compliantAgents"] == insufficient["selectedAgents"]
    assert insufficient["canaryConverged"] is False
    assert "minimum_sample_not_met" in insufficient["blockers"]
    sample_bypass = _invoke(
        module,
        _event(
            "/enterprise/runtime-rollouts",
            "POST",
            body={
                **base,
                "expectedRevision": canary["revision"],
                "targetState": "active",
                "percentage": 100,
            },
            claims=claims,
        ),
    )
    assert sample_bypass["statusCode"] == 409
    stale = _invoke(
        module,
        _event(
            f"/enterprise/runtime-rollouts/{deployment_id}/pause",
            "POST",
            body={
                "expectedRevision": 0,
                "reason": "Pause the canary while release evidence is investigated.",
            },
            claims=claims,
        ),
    )
    assert stale["statusCode"] == 409
    rollback = _invoke(
        module,
        _event(
            f"/enterprise/runtime-rollouts/{deployment_id}/rollback",
            "POST",
            body={
                "expectedRevision": canary["revision"],
                "reason": "Return selected endpoints to the retained approved Codex release.",
            },
            claims=claims,
        ),
    )
    assert rollback["statusCode"] == 200, rollback
    rolling_back = json.loads(rollback["body"])
    assert rolling_back["state"] == "rolling_back"
    for agent in selected_agents:
        agent.update(
            {
                "attestation_sdk_version": "1.1.0",
                "attestation_sdk_revision": "a" * 40,
                "attestation_manifest_sha256": current_digest,
            }
        )
    rolled_back = json.loads(
        _invoke(module, _event("/enterprise/runtime-rollouts", "GET", claims=claims))["body"]
    )["items"][0]
    assert rolled_back["state"] == "rolled_back"
    assert rolled_back["targetReleaseId"] is None
    assert rolled_back["percentage"] == 0


def test_runtime_rollout_authority_and_primary_audit_commit_atomically(
    monkeypatch: Any,
) -> None:
    """S3 replication may fail, but authority never exists without primary evidence."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-runtime-audit"
    deployment_id = "deployment-runtime-audit"
    manifests = [
        _runtime_manifest("claude-code", "1.1.0", "a" * 40),
        _runtime_manifest("claude-code", "1.2.0", "f" * 40),
    ]
    _set_runtime_manifests(monkeypatch, manifests)
    catalog = module._runtime_release_catalog()
    releases = module._runtime_release_map(catalog)
    updated = {
        "schemaVersion": 1,
        "deploymentId": deployment_id,
        "host": "claude-code",
        "state": "canary",
        "currentReleaseId": "claude-code:1.1.0",
        "currentReleaseBinding": module._runtime_release_binding(
            catalog, releases["claude-code:1.1.0"]
        ),
        "targetReleaseId": "claude-code:1.2.0",
        "targetReleaseBinding": module._runtime_release_binding(
            catalog, releases["claude-code:1.2.0"]
        ),
        "percentage": 10,
        "healthCriteria": {
            "maxUnavailablePercent": 10,
            "maxDriftPercent": 10,
            "minSampleSize": 1,
            "gracePeriodSeconds": 300,
        },
        "reason": "Run an approved bounded runtime release canary.",
        "startedAt": 1_900_000_000,
        "startedBy": "operator-a",
        "pausedAt": None,
        "pauseReason": None,
        "selectedMemberDigests": [],
    }

    def deny_replication(**_value: Any) -> dict[str, str]:
        raise RuntimeError("synthetic audit replica outage")

    monkeypatch.setattr(module.S3, "put_object", deny_replication)
    stored = module._put_runtime_rollout(
        tenant,
        None,
        updated,
        "runtime_release_rollout_started",
        "operator-a",
        updated["reason"],
    )
    assert stored["revision"] == 1
    primary = [
        item
        for item in table.items.values()
        if str(item.get("sk", "")).startswith("CONFIGURATION_AUDIT#")
        and item.get("event_type") == "runtime_release_rollout_started"
    ]
    assert len(primary) == 1
    assert primary[0]["payload"]["runtime_rollout_revision"] == 1

    second_tenant = "tenant-runtime-audit-conflict"
    module.DYNAMODB.before_transaction = lambda: table.put_item(
        Item={
            **module._item_key(second_tenant, "RUNTIME_ROLLOUT", deployment_id),
            **updated,
            "tenant_id": second_tenant,
            "revision": 1,
        }
    )
    with pytest.raises(module.PolicyConflict, match="revision changed"):
        module._put_runtime_rollout(
            second_tenant,
            None,
            updated,
            "runtime_release_rollout_started",
            "operator-a",
            updated["reason"],
        )
    assert not any(
        item.get("tenant_id") == second_tenant
        and str(item.get("sk", "")).startswith("CONFIGURATION_AUDIT#")
        for item in table.items.values()
    )


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
    assert stored["behavior_pk"] == f"TENANT#{tenant}#AGENT#dep-a:agent-a"
    assert stored["behavior_sk"].endswith(f"#decision#dep-a:agent-a:{'a' * 64}")
    assert stored["behavior_kind"] == "decision"
    migration = table.items[
        (
            f"TENANT#{tenant}",
            f"BEHAVIOR_MIGRATION#{module._BEHAVIOR_AGENT_INDEX_MIGRATION_ID}",
        )
    ]
    assert migration["schema_version"] == 1
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
    mcp_body = {
        **body,
        "decisionId": "9" * 64,
        "source": "mcp",
        "toolName": "mcp__github__list_issues",
        "resourceKind": "mcp_tool",
        "mcpServerId": "github",
    }
    mcp_recorded = _invoke(
        module,
        _event("/agent/dep-a/agent-a/decisions", "POST", body=mcp_body, token=token),
    )
    assert mcp_recorded["statusCode"] == 202
    mcp_stored_key = (f"TENANT#{tenant}", f"DECISION#dep-a:agent-a:{'9' * 64}")
    assert table.items[mcp_stored_key]["mcp_server_id"] == "github"
    assert module._decision_view(table.items[mcp_stored_key])["mcpServerId"] == "github"
    unrelated_mcp_identity = _invoke(
        module,
        _event(
            "/agent/dep-a/agent-a/decisions",
            "POST",
            body={**body, "decisionId": "8" * 64, "mcpServerId": "github"},
            token=token,
        ),
    )
    assert unrelated_mcp_identity["statusCode"] == 400
    # Keep the original dashboard assertion focused on one retained decision.
    del table.items[mcp_stored_key]
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
        "schemaVersion": 2,
        "observedAt": now,
        "device": {
            "id": "device-a",
            "managed": True,
            "businessUnit": "Platform",
            "operatingSystem": "darwin",
            "architecture": "arm64",
        },
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
    retained = table.items[(f"TENANT#{tenant}", "ENDPOINT_EVIDENCE#device-a")]
    assert retained["payload"]["schemaVersion"] == 2
    assert retained["payload"]["device"]["operatingSystem"] == "darwin"
    assert retained["payload"]["device"]["architecture"] == "arm64"
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


def test_alert_suppression_is_exact_expiring_audited_and_non_destructive(
    monkeypatch: Any,
) -> None:
    """Suppression retains evidence, cannot hide another target and revokes cleanly."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-alert-suppression"
    now = int(time.time())
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["incident-responder"],
        "sub": "suppression-owner",
    }
    match = {
        "sources": ["endpoint_evidence"],
        "severities": ["high", "critical"],
        "reasonCodes": ["signature_invalid"],
        "deploymentIds": [],
        "agentIds": [],
        "deviceIds": ["device-a"],
        "responseRuleIds": [],
    }
    created = _invoke(
        module,
        _event(
            "/api/enterprise/alert-suppressions",
            "POST",
            body={
                "id": "planned-device-maintenance",
                "name": "Planned endpoint maintenance",
                "reason": "Approved maintenance for the exact synthetic endpoint only.",
                "expiresAt": now + 3_600,
                "match": match,
            },
            claims=claims,
        ),
    )
    assert created["statusCode"] == 201, created
    suppression = json.loads(created["body"])
    assert suppression["status"] == "active"
    listed = _invoke(
        module,
        _event("/api/enterprise/alert-suppressions", "GET", claims=claims),
    )
    assert listed["statusCode"] == 200, listed
    assert json.loads(listed["body"])["items"] == [suppression]

    suppressed = module._open_endpoint_alert(tenant, "device-a", "signature_invalid", now=now + 1)
    assert suppressed["status"] == "suppressed"
    assert suppressed["deliveryStatus"] == "suppressed"
    assert suppressed["suppressionId"] == suppression["id"]
    assert suppressed["deduplicationKey"] == suppressed["id"]
    assert module._list(tenant, "RESPONSE_EXECUTION") == []

    unrelated = module._open_endpoint_alert(tenant, "device-b", "signature_invalid", now=now + 1)
    assert unrelated["status"] == "open"
    assert unrelated.get("suppressionId") is None

    revoked = _invoke(
        module,
        _event(
            f"/api/enterprise/alert-suppressions/{suppression['id']}/revoke",
            "POST",
            body={
                "expectedRevision": suppression["revision"],
                "reason": "Maintenance ended and alert delivery must resume immediately.",
            },
            claims=claims,
        ),
    )
    assert revoked["statusCode"] == 200, revoked
    reopened = module._open_endpoint_alert(
        tenant, "device-a", "signature_invalid", now=now + 2, reopen_acknowledged=True
    )
    assert reopened["status"] == "open"
    assert reopened["revision"] == 2
    assert reopened["occurrenceCount"] == 2
    assert table.items[(f"TENANT#{tenant}", f"ALERT#{suppressed['id']}")]["status"] == "open"
    audit_types = {
        json.loads(record["Body"])["event_type"] for record in module._fake_s3.objects.values()
    }
    assert {
        "alert_suppression_created",
        "endpoint_alert_suppressed",
        "alert_suppression_revoked",
        "endpoint_alert_reopened",
    } <= audit_types


def test_behavior_alert_windows_share_deduplication_identity_when_suppressed(
    monkeypatch: Any,
) -> None:
    """Repeated behavior windows group stably while retaining each evidence record."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-behavior-suppression"
    now = int(time.time())
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["incident-responder"],
        "sub": "suppression-owner",
    }
    created = _invoke(
        module,
        _event(
            "/api/enterprise/alert-suppressions",
            "POST",
            body={
                "id": "known-mcp-rollout",
                "name": "Known MCP rollout",
                "reason": "Approved rollout of one exact behavior detection rule.",
                "expiresAt": now + 3_600,
                "match": {
                    "sources": ["behavior_analytics"],
                    "severities": ["high"],
                    "reasonCodes": ["new_mcp_server"],
                    "deploymentIds": ["dep-a"],
                    "agentIds": ["agent-a"],
                    "deviceIds": [],
                    "responseRuleIds": ["detect-new-mcp"],
                },
            },
            claims=claims,
        ),
    )
    assert created["statusCode"] == 201, created
    configuration = {
        "match": {
            "source": "agent_activity",
            "signalTypes": ["new_mcp_server"],
            "hosts": ["claude-code"],
            "severity": "high",
        },
        "action": {"type": "create_alert"},
        "baseline": {
            "lookbackDays": 7,
            "currentWindowMinutes": 15,
            "minimumBaselineEvents": 5,
            "minimumCurrentEvents": 2,
            "sensitivityMultiplier": 3.0,
        },
        "priority": 100,
    }
    rule = {
        "id": "detect-new-mcp",
        "active_version": 1,
        "configuration": configuration,
        "content_hash": module._configuration_hash(configuration),
    }
    agent = {"id": "agent-a", "deployment_id": "dep-a", "host": "claude-code"}
    metric = {
        "signalType": "new_mcp_server",
        "baselineCount": 5,
        "currentCount": 2,
        "threshold": 2,
        "expectedCurrentCount": 0.0,
        "dimension": "github",
        "dimensionHash": hashlib.sha256(b"github").hexdigest(),
        "evidenceDigest": hashlib.sha256(b"synthetic-evidence").hexdigest(),
    }
    first = module._open_behavior_alert(tenant, rule, agent, metric, now=now + 1)
    second = module._open_behavior_alert(tenant, rule, agent, metric, now=now + 901)
    assert first["id"] != second["id"]
    assert first["deduplicationKey"] == second["deduplicationKey"]
    assert first["status"] == second["status"] == "suppressed"
    assert len(module._list(tenant, "ALERT")) == 2
    executions = module._list(tenant, "RESPONSE_EXECUTION")
    assert {item["outcome"] for item in executions} == {"suppressed"}
    assert {item["reason_code"] for item in executions} == {"active_suppression"}


@pytest.mark.parametrize("attack", ["broad", "overlong", "wildcard", "unauthorized"])
def test_alert_suppression_bypasses_fail_closed(monkeypatch: Any, attack: str) -> None:
    """Browser input cannot create broad, permanent, wildcard or unauthorized silence."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-suppression-bypass"
    now = int(time.time())
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    match = {
        "sources": ["behavior_analytics"],
        "severities": ["high"],
        "reasonCodes": ["new_mcp_server"],
        "deploymentIds": [],
        "agentIds": [],
        "deviceIds": [],
        "responseRuleIds": ["detect-new-mcp"],
    }
    if attack == "broad":
        match["reasonCodes"] = []
        match["responseRuleIds"] = []
    elif attack == "wildcard":
        match["responseRuleIds"] = ["*"]
    response = _invoke(
        module,
        _event(
            "/api/enterprise/alert-suppressions",
            "POST",
            body={
                "id": f"reject-{attack}",
                "name": "Rejected suppression",
                "reason": "Synthetic bypass attempt must fail closed at the API boundary.",
                "expiresAt": now + (8 * 24 * 60 * 60) if attack == "overlong" else now + 3_600,
                "match": match,
            },
            claims={
                "custom:tenant_id": tenant,
                "cognito:groups": [
                    "policy-author" if attack == "unauthorized" else "incident-responder"
                ],
                "sub": "synthetic-attacker",
            },
        ),
    )
    assert response["statusCode"] in {400, 403}
    assert module._list(tenant, "ALERT_SUPPRESSION") == []


def test_tampered_stored_suppression_restores_alerting(monkeypatch: Any) -> None:
    """Corrupt persistence must fail open for detection rather than hide an alert."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-tampered-suppression"
    now = int(time.time())
    table.put_item(
        Item=module._item_key(tenant, "ALERT_SUPPRESSION", "tampered")
        | {
            "id": "tampered",
            "status": "active",
            "expires_at": now + 3_600,
            "match": {
                "sources": ["endpoint_evidence"],
                "severities": ["high"],
                "reasonCodes": [],
                "deploymentIds": [],
                "agentIds": [],
                "deviceIds": [],
                "responseRuleIds": [],
            },
            "content_hash": "0" * 64,
        }
    )
    alert = module._open_endpoint_alert(tenant, "device-a", "signature_invalid", now=now + 1)
    assert alert["status"] == "open"
    assert alert.get("suppressionId") is None


def test_behavior_rule_is_explainable_alert_only_and_case_bound(monkeypatch: Any) -> None:
    """Agent observations may create governed alerts but never automatic authority."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-behavior-rule"
    now = 2_165_500_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    agent_key = "deployment-a:agent-a"
    table.put_item(
        Item=module._item_key(tenant, "AGENT", agent_key)
        | {
            "id": "agent-a",
            "deployment_id": "deployment-a",
            "host": "claude-code",
            "project_root": "/synthetic/behavior-project",
            "status": "connected",
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
            "session_revision": 1,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "POLICY", "policy-a")
        | {"id": "policy-a", "name": "Safe", "version": 3}
    )
    table.put_item(
        Item=module._item_key(tenant, "GROUP", "group-a")
        | {"id": "group-a", "policyId": "policy-a", "agent_keys": [agent_key]}
    )

    def decision(
        identifier: str,
        observed_at: int,
        *,
        tool: str,
        source: str,
        mcp: str | None = None,
    ) -> None:
        record: dict[str, Any] = {
            **module._item_key(tenant, "DECISION", f"{agent_key}:{identifier}"),
            "id": identifier,
            "deployment_id": "deployment-a",
            "agent_id": "agent-a",
            "host": "claude-code",
            "tool_name": tool,
            "source": source,
            "decision": "allowed",
            "resource_kind": "mcp_tool" if mcp or source == "mcp" else "project_file",
            "reason_code": "explicit_allow",
            "observed_at": observed_at,
            "timeline_pk": f"TENANT#{tenant}#DECISION",
            "timeline_sk": f"{observed_at:010d}#{agent_key}:{identifier}",
        }
        if mcp:
            record["mcp_server_id"] = mcp
        table.put_item(Item=record)

    for index in range(5):
        decision(f"history-{index}", now - 86_400 + index, tool="Read", source="claude_native")
    decision(
        "current-a",
        now - 60,
        tool="mcp__github__list_issues",
        source="claude_native",
        mcp="github",
    )
    decision(
        "current-b",
        now,
        tool="mcp__github__get_issue",
        source="claude_native",
        mcp="github",
    )

    configuration = {
        "match": {
            "source": "agent_activity",
            "signalTypes": ["new_mcp_server"],
            "hosts": ["claude-code"],
            "severity": "high",
        },
        "action": {"type": "create_alert"},
        "baseline": {
            "lookbackDays": 7,
            "currentWindowMinutes": 15,
            "minimumBaselineEvents": 5,
            "minimumCurrentEvents": 2,
            "sensitivityMultiplier": 3.0,
        },
        "priority": 100,
    }
    author = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "behavior-author",
    }
    approver = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "behavior-approver",
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
    assert preview_body["count"] == 1
    assert (
        preview_body["matches"][0]
        | {
            "agentKey": agent_key,
            "outcome": "would_alert",
            "baselineComplete": True,
            "baselineCount": 5,
            "currentCount": 2,
            "threshold": 2,
            "dimension": "github",
        }
        == preview_body["matches"][0]
    )
    assert module._list(tenant, "ALERT") == []

    created = _invoke(
        module,
        _event(
            "/api/enterprise/response-rules",
            "POST",
            body={
                "ruleId": "detect-new-mcp",
                "name": "Detect newly observed MCP servers",
                "description": "Alert when an enrolled agent reports a new MCP server identity.",
                "configuration": configuration,
            },
            claims=author,
        ),
    )
    assert created["statusCode"] == 201, created
    assert (
        _invoke(
            module,
            _event(
                "/api/enterprise/response-rules/detect-new-mcp/versions/1/submit",
                "POST",
                claims=author,
            ),
        )["statusCode"]
        == 200
    )
    decision_path = "/api/enterprise/response-rules/detect-new-mcp/versions/1/decision"
    assert (
        _invoke(
            module,
            _event(
                decision_path,
                "POST",
                body={
                    "decision": "approved",
                    "reason": "Self approval must remain unavailable for behavior detections.",
                },
                claims=author,
            ),
        )["statusCode"]
        == 403
    )
    assert (
        _invoke(
            module,
            _event(
                decision_path,
                "POST",
                body={
                    "decision": "approved",
                    "reason": "The alert-only scope and explainable threshold are appropriate.",
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
                "/api/enterprise/response-rules/detect-new-mcp/versions/1/activate",
                "POST",
                body={"expectedActiveVersion": 0},
                claims=approver,
            ),
        )["statusCode"]
        == 200
    )

    changed_boundary = _invoke(
        module,
        _event(
            "/api/enterprise/response-rules/detect-new-mcp/versions",
            "POST",
            body={
                "name": "Illegitimate containment upgrade",
                "description": ("A later version must not change the permanent evidence boundary."),
                "configuration": {
                    "match": {
                        "source": "endpoint_evidence",
                        "reasonCodes": ["signature_invalid"],
                        "severities": ["critical"],
                        "hosts": ["claude-code"],
                    },
                    "action": {"type": "quarantine_agent"},
                    "safeguards": {
                        "maxActionsPerHour": 1,
                        "agentCooldownSeconds": 3600,
                    },
                    "priority": 1,
                },
            },
            claims=approver,
        ),
    )
    assert changed_boundary["statusCode"] == 400
    assert "evidence boundary cannot change" in json.loads(changed_boundary["body"])["error"]

    alerts = module._evaluate_behavior_rules_for_agent(tenant, agent_key, now=now)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["source"] == "behavior_analytics"
    assert alert["reasonCode"] == "new_mcp_server"
    assert alert["behavior"]["dimension"] == "github"
    assert alert["behavior"]["reportedByAgent"] is True
    assert alert["behavior"]["threshold"] == 2
    assert module._list(tenant, "CONTAINMENT") == []
    repeated = module._evaluate_behavior_rules_for_agent(tenant, agent_key, now=now)
    assert repeated[0]["id"] == alert["id"]
    assert len(module._list(tenant, "ALERT")) == 1
    assert len(module._list(tenant, "RESPONSE_EXECUTION")) == 1
    assert module._list(tenant, "RESPONSE_EXECUTION")[0]["outcome"] == "alerted"

    case = module._create_case(
        tenant,
        {
            "alertId": alert["id"],
            "expectedAlertRevision": module._list(tenant, "ALERT")[0]["revision"],
            "reason": "Investigate the newly observed MCP identity before containment.",
        },
        "incident-responder",
    )
    assert case["alertSource"] == "behavior_analytics"
    assert case["binding"]["status"] == "bound"
    assert case["binding"]["agentKey"] == agent_key
    export = module._case_export(tenant, case["id"], "incident-responder")
    assert export["content"]["case"]["alertSource"] == "behavior_analytics"
    assert (
        export["content"]["evidence"]["behaviorEvidenceDigest"]
        == alert["behavior"]["evidenceDigest"]
    )
    retained_alert = module._list(tenant, "ALERT")[0]
    acknowledged = module._acknowledge_endpoint_alert(
        tenant,
        alert["id"],
        {
            "expectedRevision": retained_alert["revision"],
            "reason": "A responder owns investigation of the newly observed MCP identity.",
        },
        "incident-responder",
    )
    assert acknowledged["source"] == "behavior_analytics"
    assert acknowledged["status"] == "acknowledged"
    assert (
        module._case_view(
            tenant,
            module._list(tenant, "CASE")[0],
            detailed=True,
        )["bindingCurrent"]
        is True
    )
    contained = module._contain_case(
        tenant,
        case["id"],
        {
            "expectedCaseRevision": case["revision"],
            "expectedBindingDigest": case["binding"]["bindingDigest"],
            "reason": "Quarantine the exact enrolled agent during the MCP investigation.",
        },
        "incident-responder",
    )
    assert contained["status"] == "contained"
    assert (
        module._agent_control_state(
            tenant, table.items[(f"TENANT#{tenant}", f"AGENT#{agent_key}")]
        )["executionAllowed"]
        is False
    )


def test_behavior_baseline_fails_closed_and_rejects_authority_widening(
    monkeypatch: Any,
) -> None:
    """Incomplete history cannot alert and agent activity cannot auto-quarantine."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-behavior-incomplete"
    now = 2_166_000_000
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "host": "codex",
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
            "session_revision": 1,
        }
    )
    configuration: dict[str, Any] = {
        "match": {
            "source": "agent_activity",
            "signalTypes": ["denied_action_spike"],
            "hosts": ["codex"],
            "severity": "critical",
        },
        "action": {"type": "create_alert"},
        "baseline": {
            "lookbackDays": 7,
            "currentWindowMinutes": 15,
            "minimumBaselineEvents": 20,
            "minimumCurrentEvents": 3,
            "sensitivityMultiplier": 2.0,
        },
        "priority": 1,
    }
    normalized = module._response_rule_configuration(configuration)
    metrics = module._behavior_rule_metrics(tenant, normalized, "dep-a:agent-a", now=now)
    assert metrics == [
        {
            "signalType": "denied_action_spike",
            "outcome": "baseline_insufficient",
            "baselineComplete": True,
            "baselineCount": 0,
            "minimumBaselineEvents": 20,
            "currentCount": 0,
            "threshold": None,
            "expectedCurrentCount": None,
            "dimension": None,
            "dimensionHash": None,
            "evidenceDigest": module._configuration_hash([]),
        }
    ]
    truncated = module._behavior_signal_metrics(
        normalized,
        "denied_action_spike",
        "dep-a:agent-a",
        [],
        [],
        now=now,
        history_truncated=True,
    )
    assert truncated[0]["outcome"] == "baseline_insufficient"
    assert truncated[0]["baselineComplete"] is False

    spike_decisions: list[dict[str, Any]] = [
        {
            "id": f"historical-{index}",
            "deployment_id": "dep-a",
            "agent_id": "agent-a",
            "decision": "denied" if index == 0 else "allowed",
            "observed_at": now - 86_400 + index,
        }
        for index in range(20)
    ] + [
        {
            "id": f"current-{index}",
            "deployment_id": "dep-a",
            "agent_id": "agent-a",
            "decision": "denied",
            "observed_at": now - index,
        }
        for index in range(3)
    ]
    spike = module._behavior_signal_metrics(
        normalized,
        "denied_action_spike",
        "dep-a:agent-a",
        spike_decisions,
        [],
        now=now,
    )
    assert spike[0]["outcome"] == "would_alert"
    assert spike[0]["currentCount"] == 3
    assert spike[0]["threshold"] == 3
    for signal, reason_code in (
        ("outside_project_spike", "outside_project"),
        ("configuration_error_spike", "invalid_configuration"),
    ):
        scoped_configuration = copy.deepcopy(configuration)
        scoped_configuration["match"]["signalTypes"] = [signal]
        scoped = module._behavior_signal_metrics(
            module._response_rule_configuration(scoped_configuration),
            signal,
            "dep-a:agent-a",
            [
                {
                    **item,
                    "reason_code": reason_code if item["id"].startswith("current") else None,
                }
                for item in spike_decisions
            ],
            [],
            now=now,
        )
        assert scoped[0]["outcome"] == "would_alert"
        assert scoped[0]["currentCount"] == 3
    with pytest.raises(ValueError, match="create_alert"):
        module._response_rule_configuration(
            {**configuration, "action": {"type": "quarantine_agent"}}
        )
    with pytest.raises(ValueError, match="sensitivityMultiplier"):
        invalid_configuration: dict[str, Any] = copy.deepcopy(configuration)
        invalid_configuration["baseline"]["sensitivityMultiplier"] = float("nan")
        module._response_rule_configuration(invalid_configuration)


def test_behavior_baselines_are_exact_agent_partitioned_paginated_and_redacted(
    monkeypatch: Any,
) -> None:
    """A noisy agent cannot truncate another agent's baseline or leak action content."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-agent-baselines"
    other_tenant = "tenant-other"
    now = 2_166_500_000
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    for agent_id in ("target", "noisy"):
        table.put_item(
            Item=module._item_key(tenant, "AGENT", f"dep-a:{agent_id}")
            | {
                "id": agent_id,
                "deployment_id": "dep-a",
                "host": "claude-code",
                "lifecycle_state": "active",
            }
        )
    table.put_item(
        Item=module._item_key(other_tenant, "AGENT", "dep-x:foreign")
        | {
            "id": "foreign",
            "deployment_id": "dep-x",
            "host": "codex",
            "lifecycle_state": "active",
        }
    )
    table.put_item(
        Item=module._item_key(
            tenant, "BEHAVIOR_MIGRATION", module._BEHAVIOR_AGENT_INDEX_MIGRATION_ID
        )
        | {
            "id": module._BEHAVIOR_AGENT_INDEX_MIGRATION_ID,
            "started_at": now - module._BEHAVIOR_AGENT_INDEX_MIGRATION_SECONDS - 1,
            "schema_version": 1,
        }
    )
    configuration = module._response_rule_configuration(
        {
            "match": {
                "source": "agent_activity",
                "signalTypes": ["decision_volume_spike"],
                "hosts": ["claude-code"],
                "severity": "high",
            },
            "action": {"type": "create_alert"},
            "baseline": {
                "lookbackDays": 7,
                "currentWindowMinutes": 15,
                "minimumBaselineEvents": 5,
                "minimumCurrentEvents": 3,
                "sensitivityMultiplier": 3.0,
            },
            "priority": 100,
        }
    )
    content_hash = module._configuration_hash(configuration)
    table.put_item(
        Item=module._item_key(tenant, "RESPONSE_RULE", "volume-rule")
        | {
            "id": "volume-rule",
            "name": "Decision volume",
            "configuration": configuration,
            "content_hash": content_hash,
            "active_version": 1,
            "enabled": True,
        }
    )
    table.put_item(
        Item=module._item_key(
            tenant,
            "RESPONSE_RULE_VERSION",
            module._response_rule_version_identifier("volume-rule", 1),
        )
        | {
            "id": module._response_rule_version_identifier("volume-rule", 1),
            "rule_id": "volume-rule",
            "version": 1,
            "state": "active",
            "content_hash": content_hash,
            "configuration": configuration,
        }
    )

    def indexed_decision(agent_id: str, index: int) -> None:
        observed_at = now - 86_400 + index
        record_id = f"{agent_id}-{index:04d}"
        agent_key = f"dep-a:{agent_id}"
        table.put_item(
            Item=module._item_key(tenant, "DECISION", record_id)
            | {
                "id": record_id,
                "deployment_id": "dep-a",
                "agent_id": agent_id,
                "tool_name": "sensitive-tool-name",
                "decision": "allowed",
                "observed_at": observed_at,
                "behavior_pk": f"TENANT#{tenant}#AGENT#{agent_key}",
                "behavior_sk": f"{observed_at:010d}#decision#{record_id}",
                "behavior_kind": "decision",
            }
        )

    for index in range(5):
        indexed_decision("target", index)
    for index in range(module._BEHAVIOR_HISTORY_LIMIT + 1):
        indexed_decision("noisy", index)

    page = module._behavior_baseline_page(tenant, now=now, page_limit=50)
    by_agent = {item["agentId"]: item for item in page["items"]}
    assert page["scope"] == "fleet"
    assert page["hasMore"] is False
    assert page["readConsistency"] == "eventually_consistent_index"
    assert page["summary"] == {
        "agents": 2,
        "ready": 1,
        "warming": 0,
        "incomplete": 1,
        "not_configured": 0,
    }
    assert by_agent["target"]["status"] == "ready"
    assert by_agent["target"]["historyTruncated"] is False
    assert by_agent["target"]["signals"][0]["baselineCount"] == 5
    assert by_agent["noisy"]["status"] == "incomplete"
    assert by_agent["noisy"]["historyTruncated"] is True
    assert page["contentBoundary"] == {
        "rawPromptsIncluded": False,
        "toolArgumentsIncluded": False,
        "toolResultsIncluded": False,
        "credentialsIncluded": False,
        "projectPathsIncluded": False,
    }
    assert "sensitive-tool-name" not in json.dumps(page)
    assert "foreign" not in json.dumps(page)

    # A just-written observation may not be visible through the eventually
    # consistent GSI yet. The evaluator receives that server-owned item
    # directly and must merge it without accepting a mismatched partition.
    current = {
        **module._item_key(tenant, "DECISION", "current-target"),
        "id": "current-target",
        "deployment_id": "dep-a",
        "agent_id": "target",
        "decision": "denied",
        "observed_at": now,
        "behavior_pk": f"TENANT#{tenant}#AGENT#dep-a:target",
        "behavior_sk": f"{now:010d}#decision#current-target",
        "behavior_kind": "decision",
    }
    immediate = module._behavior_agent_history(
        tenant, "dep-a:target", now=now, current_observation=current
    )
    assert immediate["eventCount"] == 6
    assert immediate["currentObservationMerged"] is True
    mismatched = module._behavior_agent_history(
        tenant,
        "dep-a:target",
        now=now,
        current_observation={**current, "behavior_pk": "TENANT#foreign#AGENT#dep-a:target"},
    )
    assert mismatched["eventCount"] == 5
    assert mismatched["currentObservationMerged"] is False

    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "operator-a",
    }
    route = _event("/api/enterprise/behavior-baselines", "GET", claims=claims)
    route["queryStringParameters"] = {"limit": "50"}
    response = _invoke(module, route)
    assert response["statusCode"] == 200
    unauthorized = _invoke(
        module,
        _event(
            "/api/enterprise/behavior-baselines",
            "GET",
            claims={"custom:tenant_id": tenant, "sub": "no-role"},
        ),
    )
    assert unauthorized["statusCode"] == 403


def test_behavior_agent_timeline_is_declared_in_aws_iac() -> None:
    """The scalable exact-agent read boundary is part of the deployed table schema."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text()
    assert 'indexName: "BehaviorAgentTimeline"' in stack
    assert 'partitionKey: { name: "behavior_pk"' in stack
    assert 'sortKey: { name: "behavior_sk"' in stack


def test_repository_and_configuration_integrity_rules_are_exact_and_explainable(
    monkeypatch: Any,
) -> None:
    """Complete repository and host baselines create retained alert-only findings."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-integrity-detection"
    now = 2_167_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    agent_key = "deployment-a:agent-a"
    project_root = "/synthetic/project"
    project_digest = hashlib.sha256(project_root.encode()).hexdigest()
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "POLICY", "policy-a")
        | {"id": "policy-a", "version": 4, "configuration": {}}
    )
    table.put_item(
        Item=module._item_key(tenant, "GROUP", "group-a")
        | {"id": "group-a", "policyId": "policy-a", "agent_keys": [agent_key]}
    )
    desired = {
        "host": "codex-cli",
        "hostVersion": "1.2.3",
        "platform": "macos",
        "bundleHash": "a" * 64,
        "policyId": "policy-a",
        "policyVersion": 4,
    }
    observed = {
        **desired,
        "bundleHash": "b" * 64,
        "source": "codex-system",
        "verifiedAt": now - 30,
        "expiresAt": now + 300,
    }
    table.put_item(
        Item=module._item_key(tenant, "CONFIGURATION", "deployment-a")
        | {
            "deploymentId": "deployment-a",
            "desiredConfiguration": {"managedHost": desired},
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "AGENT", agent_key)
        | {
            "id": "agent-a",
            "deployment_id": "deployment-a",
            "host": "codex-cli",
            "project_root": project_root,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
            "session_revision": 1,
            "managed_configuration_report": observed,
            "attestation_status": "quarantined",
            "attestation_reason_codes": ["enrollment_baseline_mismatch"],
            "attestation_baseline_digest": "c" * 64,
            "attestation_observed_at": now - 10,
        }
    )

    def put_generation(
        generation: str,
        expected_revision: int,
        root_digest: str,
    ) -> str:
        observations = [
            {
                "kind": "repository",
                "id": "repository-a",
                "projectRootDigest": root_digest,
                "expectedHosts": ["codex-cli"],
            }
        ]
        page_hash = hashlib.sha256(
            json.dumps(observations, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        content_hash = hashlib.sha256(
            json.dumps(
                {
                    "sourceId": "github-a",
                    "sourceKind": "source_control",
                    "generation": generation,
                    "observedAt": now - 60 + expected_revision,
                    "expiresAt": now + 3_600,
                    "pageHashes": [page_hash],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        table.put_item(
            Item=module._item_key(tenant, "DISCOVERY_PAGE", f"github-a:{generation}:00000")
            | {
                "sourceId": "github-a",
                "generation": generation,
                "pageNumber": 0,
                "pageHash": page_hash,
                "observations": observations,
            }
        )
        table.put_item(
            Item=module._item_key(tenant, "DISCOVERY_GENERATION", f"github-a:{generation}")
            | {
                "sourceId": "github-a",
                "sourceKind": "source_control",
                "generation": generation,
                "expectedRevision": expected_revision,
                "observedAt": now - 60 + expected_revision,
                "expiresAt": now + 3_600,
                "pageCount": 1,
                "state": "committed",
                "contentHash": content_hash,
            }
        )
        return content_hash

    put_generation("baseline", 0, project_digest)
    current_hash = put_generation("current", 1, "d" * 64)
    table.put_item(
        Item=module._item_key(tenant, "DISCOVERY_SOURCE", "github-a")
        | {
            "sourceId": "github-a",
            "sourceKind": "source_control",
            "generation": "current",
            "revision": 2,
            "complete": True,
            "observedAt": now - 59,
            "expiresAt": now + 3_600,
            "pageCount": 1,
            "contentHash": current_hash,
        }
    )
    configuration: dict[str, Any] = {
        "match": {
            "source": "integrity_evidence",
            "signalTypes": [
                "repository_mapping_changed",
                "managed_configuration_drift",
                "runtime_attestation_drift",
            ],
            "hosts": ["codex"],
            "severity": "critical",
        },
        "action": {"type": "create_alert"},
        "priority": 20,
    }
    normalized = module._response_rule_configuration(configuration)
    content_hash = module._configuration_hash(normalized)
    table.put_item(
        Item=module._item_key(tenant, "RESPONSE_RULE", "integrity-a")
        | {
            "id": "integrity-a",
            "active_version": 1,
            "enabled": True,
            "configuration": normalized,
            "content_hash": content_hash,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "RESPONSE_RULE_VERSION", "integrity-a:v00000001")
        | {
            "id": "integrity-a:v00000001",
            "rule_id": "integrity-a",
            "version": 1,
            "state": "active",
            "configuration": normalized,
            "content_hash": content_hash,
        }
    )
    responder = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["incident-responder"],
        "sub": "incident-responder",
    }
    suppression = _invoke(
        module,
        _event(
            "/api/enterprise/alert-suppressions",
            "POST",
            body={
                "id": "known-managed-rollout",
                "name": "Known managed configuration rollout",
                "reason": (
                    "Approved exact rollout while retained integrity evidence remains visible."
                ),
                "expiresAt": now + 3_600,
                "match": {
                    "sources": ["integrity_evidence"],
                    "severities": ["critical"],
                    "reasonCodes": ["managed_configuration_drift"],
                    "deploymentIds": ["deployment-a"],
                    "agentIds": ["agent-a"],
                    "deviceIds": [],
                    "responseRuleIds": ["integrity-a"],
                },
            },
            claims=responder,
        ),
    )
    assert suppression["statusCode"] == 201, suppression

    preview = module._response_rule_preview(tenant, normalized)
    assert preview["mutated"] is False
    assert preview["count"] == 3
    assert preview["baselineInsufficient"] == 0
    assert {item["reasonCode"] for item in preview["matches"]} == {
        "repository_mapping_changed",
        "managed_configuration_drift",
        "runtime_attestation_drift",
    }
    alerts = module._evaluate_integrity_rules(tenant, now=now)
    assert len(alerts) == 3
    assert {item["source"] for item in alerts} == {"integrity_evidence"}
    assert all(item["integrity"]["reportedByAgent"] is False for item in alerts)
    by_reason = {item["reasonCode"]: item for item in alerts}
    assert by_reason["managed_configuration_drift"]["status"] == "suppressed"
    assert by_reason["repository_mapping_changed"]["status"] == "open"
    assert by_reason["runtime_attestation_drift"]["status"] == "open"
    assert module._list(tenant, "CONTAINMENT") == []
    repeated = module._evaluate_integrity_rules(tenant, now=now)
    assert {item["id"] for item in repeated} == {item["id"] for item in alerts}
    assert len(module._list(tenant, "ALERT")) == 3

    repository_alert = by_reason["repository_mapping_changed"]
    case = module._create_case(
        tenant,
        {
            "alertId": repository_alert["id"],
            "expectedAlertRevision": repository_alert["revision"],
            "reason": "Investigate the exact repository mapping change before containment.",
        },
        "incident-responder",
    )
    assert case["alertSource"] == "integrity_evidence"
    assert case["binding"]["status"] == "bound"
    assert case["binding"]["host"] == "codex-cli"
    detail = module._case_view(
        tenant,
        module._case_record(tenant, case["id"]),
        detailed=True,
    )
    assert detail["evidence"]["endpointReportDigest"] is None
    assert (
        detail["evidence"]["integrityEvidenceDigest"]
        == repository_alert["integrity"]["evidenceDigest"]
    )
    exported = module._case_export(tenant, case["id"], "incident-responder")
    assert (
        exported["content"]["evidence"]["integrityEvidenceDigest"]
        == repository_alert["integrity"]["evidenceDigest"]
    )

    unchanged_hash = put_generation("current", 1, project_digest)
    source = table.get_item(
        Key=module._item_key(tenant, "DISCOVERY_SOURCE", "github-a"),
        ConsistentRead=True,
    )["Item"]
    table.put_item(Item={**source, "contentHash": unchanged_hash})
    repository_metrics = module._repository_integrity_metrics(
        tenant,
        table.get_item(
            Key=module._item_key(tenant, "AGENT", agent_key),
            ConsistentRead=True,
        )["Item"],
        now=now,
    )
    assert not any(item["outcome"] == "would_alert" for item in repository_metrics)


def test_integrity_baseline_tamper_and_rule_widening_fail_closed(monkeypatch: Any) -> None:
    """Malformed history cannot alert and integrity rules cannot gain containment."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-integrity-fail-closed"
    now = 2_168_000_000
    agent = {
        "id": "agent-a",
        "deployment_id": "deployment-a",
        "host": "codex-cli",
        "project_root": "/synthetic/project",
        "lifecycle_state": "active",
        "lifecycle_revision": 1,
        "session_revision": 1,
    }
    table.put_item(Item=module._item_key(tenant, "AGENT", "deployment-a:agent-a") | agent)
    table.put_item(
        Item=module._item_key(tenant, "DISCOVERY_PAGE", "github-a:baseline:00000")
        | {
            "sourceId": "github-a",
            "generation": "baseline",
            "pageNumber": 0,
            "pageHash": "0" * 64,
            "observations": [],
        }
    )
    for generation, expected_revision in (("baseline", 0), ("current", 1)):
        table.put_item(
            Item=module._item_key(
                tenant,
                "DISCOVERY_GENERATION",
                f"github-a:{generation}",
            )
            | {
                "sourceId": "github-a",
                "sourceKind": "source_control",
                "generation": generation,
                "expectedRevision": expected_revision,
                "observedAt": now - 10,
                "expiresAt": now + 300,
                "pageCount": 1,
                "state": "committed",
                "contentHash": "1" * 64,
            }
        )
    table.put_item(
        Item=module._item_key(tenant, "DISCOVERY_SOURCE", "github-a")
        | {
            "sourceId": "github-a",
            "sourceKind": "source_control",
            "generation": "current",
            "revision": 2,
            "complete": True,
            "observedAt": now - 10,
            "expiresAt": now + 300,
            "pageCount": 1,
            "contentHash": "1" * 64,
        }
    )
    baseline_key = module._item_key(tenant, "DISCOVERY_GENERATION", "github-a:baseline")
    incomplete_reference = table.get_item(Key=baseline_key, ConsistentRead=True)["Item"]
    table.put_item(Item={**incomplete_reference, "baselineObjectKey": "tenant=x/incomplete"})
    with pytest.raises(ValueError, match="reference is incomplete"):
        module._verified_repository_generation(tenant, "github-a", "baseline")
    table.put_item(
        Item={
            **incomplete_reference,
            "baselineObjectKey": (
                "tenant=another/source=github-a/generation=baseline/repository-baseline.json"
            ),
            "baselineObjectVersionId": "version-cross-tenant",
            "baselineObjectSha256": "a" * 64,
        }
    )
    with pytest.raises(ValueError, match="crosses its committed scope"):
        module._verified_repository_generation(tenant, "github-a", "baseline")
    table.put_item(
        Item={
            **incomplete_reference,
            "baselineObjectKey": module._integrity_baseline_object_key(
                tenant, "github-a", "baseline"
            ),
            "baselineObjectVersionId": "version-missing",
            "baselineObjectSha256": "a" * 64,
        }
    )
    with pytest.raises(ValueError, match="object is unavailable"):
        module._verified_repository_generation(tenant, "github-a", "baseline")
    configuration: dict[str, Any] = {
        "match": {
            "source": "integrity_evidence",
            "signalTypes": ["repository_mapping_changed"],
            "hosts": ["codex"],
            "severity": "high",
        },
        "action": {"type": "create_alert"},
        "priority": 1,
    }
    normalized = module._response_rule_configuration(configuration)
    content_hash = module._configuration_hash(normalized)
    table.put_item(
        Item=module._item_key(tenant, "RESPONSE_RULE", "integrity-fail-closed")
        | {
            "id": "integrity-fail-closed",
            "active_version": 1,
            "enabled": True,
            "configuration": normalized,
            "content_hash": content_hash,
        }
    )
    table.put_item(
        Item=module._item_key(
            tenant,
            "RESPONSE_RULE_VERSION",
            "integrity-fail-closed:v00000001",
        )
        | {
            "id": "integrity-fail-closed:v00000001",
            "rule_id": "integrity-fail-closed",
            "version": 1,
            "state": "active",
            "configuration": normalized,
            "content_hash": content_hash,
        }
    )
    metrics = module._integrity_rule_metrics(tenant, normalized, agent, now=now)
    assert metrics[0]["outcome"] == "baseline_insufficient"
    assert metrics[0]["baselineComplete"] is False
    assert metrics[0]["reasonCodes"] == ["repository_baseline_integrity_failed"]
    assert module._evaluate_integrity_rules(tenant, now=now) == []
    assert module._list(tenant, "ALERT") == []
    health = table.get_item(
        Key=module._item_key(tenant, "INTEGRITY_HEALTH", "current"),
        ConsistentRead=True,
    )["Item"]
    assert health["status"] == "degraded"
    malformed_attestation = {
        **agent,
        "attestation_status": "quarantined",
        "attestation_reason_codes": "configurationDigest_invalid",
        "attestation_baseline_digest": "not-a-digest",
        "attestation_observed_at": "invalid",
    }
    attestation_configuration: dict[str, Any] = {
        "match": {
            "source": "integrity_evidence",
            "signalTypes": ["runtime_attestation_drift"],
            "hosts": ["codex"],
            "severity": "high",
        },
        "action": {"type": "create_alert"},
        "priority": 1,
    }
    attestation_metrics = module._integrity_rule_metrics(
        tenant,
        module._response_rule_configuration(attestation_configuration),
        malformed_attestation,
        now=now,
    )
    assert attestation_metrics[0]["outcome"] == "baseline_insufficient"
    assert attestation_metrics[0]["reasonCodes"] == ["runtime_attestation_invalid"]
    with pytest.raises(ValueError, match="create_alert"):
        module._response_rule_configuration(
            {**configuration, "action": {"type": "quarantine_agent"}}
        )
    duplicate = copy.deepcopy(configuration)
    duplicate["match"]["signalTypes"] = [
        "repository_mapping_changed",
        "repository_mapping_changed",
    ]
    with pytest.raises(ValueError, match="signalTypes"):
        module._response_rule_configuration(duplicate)


def test_codex_cli_matches_the_public_codex_detection_scope(monkeypatch: Any) -> None:
    """Canonical Codex CLI identities must not be missed by public rule scope."""
    module, _table = _load_handler(monkeypatch)
    assert module._response_rule_host_identity("codex-cli") == "codex"
    assert module._response_rule_matches(
        {
            "match": {
                "source": "endpoint_evidence",
                "reasonCodes": ["process_not_observed"],
                "severities": ["high"],
                "hosts": ["codex"],
            }
        },
        {
            "source": "endpoint_evidence",
            "reasonCode": "process_not_observed",
            "severity": "high",
        },
        {"host": "codex-cli"},
    )


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
        "endpoint",
        [
            {
                "kind": "device",
                "id": "device-a",
                "managed": True,
                "directoryDeviceRegistrationId": ("22222222-2222-4222-8222-222222222222"),
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
    issued = json.loads(
        _invoke(
            module,
            _event(credential_path, "POST", body={"expectedRevision": 0}, claims=platform),
        )["body"]
    )
    evidence_payload = {
        "schemaVersion": 2,
        "observedAt": now,
        "device": {
            "id": "device-a",
            "managed": True,
            "operatingSystem": "darwin",
            "architecture": "arm64",
        },
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
    live_binding = module._endpoint_agent_binding(tenant, "device-a", now=now)
    assert live_binding["operatingSystem"] == "darwin"
    assert live_binding["architecture"] == "arm64"
    assert live_binding["directoryDeviceRegistrationId"] == ("22222222-2222-4222-8222-222222222222")
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
        Item=module._item_key(tenant, "DECISION", "decision-mcp")
        | {
            "id": "decision-mcp",
            "deployment_id": "deployment-a",
            "agent_id": "agent-a",
            "observed_at": now - 8,
            "tool_name": "create_issue",
            "decision": "approval_required",
            "reason_code": "approval_rule",
            "resource_kind": "mcp_tool",
            "source": "mcp",
            "mcp_server_id": "github",
            "policy_id": "policy-a",
            "policy_version": 4,
            "action_digest": "d" * 64,
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
    correlated = json.loads(
        _invoke(
            module,
            _event(f"/api/enterprise/cases/{case['id']}", "GET", claims=responder),
        )["body"]
    )["investigationTimeline"]
    assert correlated["complete"] is True
    assert correlated["incompleteReasons"] == []
    assert correlated["omittedEvents"] == 0
    assert correlated["rawContentIncluded"] is False
    assert correlated["credentialsIncluded"] is False
    assert correlated["freeFormNarrativeIncluded"] is False
    assert correlated["categoryCounts"]["policy"] == 2
    assert correlated["categoryCounts"]["tool"] == 4
    assert correlated["categoryCounts"]["mcp"] == 1
    assert correlated["categoryCounts"]["approval"] == 2
    assert correlated["categoryCounts"]["isolation"] == 1
    assert [item["occurredAt"] for item in correlated["items"]] == sorted(
        item["occurredAt"] for item in correlated["items"]
    )
    correlated_by_id = {item["id"]: item for item in correlated["items"]}
    assert correlated_by_id["decision:decision-a"]["source"]["provenance"] == (
        "authenticated_agent_report"
    )
    assert correlated_by_id["decision:decision-a"]["references"] == {
        "actionDigest": "b" * 64,
        "agentKey": "deployment-a:agent-a",
        "mcpServerId": None,
        "policyId": "policy-a",
        "policyVersion": 4,
        "toolName": "Bash",
    }
    assert correlated_by_id["decision:decision-mcp"]["references"]["mcpServerId"] == "github"
    assert correlated_by_id["approval:approval-a:approved"]["actor"] == "approver-a"
    assert "Narrative intentionally excluded" not in json.dumps(correlated)
    assert project_root not in json.dumps(correlated)
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
        "decisions": 2,
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


def test_investigation_timeline_marks_every_incomplete_source(monkeypatch: Any) -> None:
    """The operator view never presents bounded partial evidence as complete."""
    module, _table = _load_handler(monkeypatch)
    now = 2_200_000_000
    case = {
        "id": "case-a",
        "createdAt": now - 30,
        "binding": {
            "agentKey": "deployment-a:agent-a",
            "policyId": "policy-a",
            "policyVersion": 7,
            "bindingDigest": "a" * 64,
        },
    }
    alert = {
        "id": "alert-a",
        "source": "endpoint_evidence",
        "severity": "high",
        "reasonCode": "runtime_attestation_missing",
        "status": "open",
        "firstObservedAt": now - 60,
    }
    case_events = [
        {
            "id": f"event-{index:03d}",
            "eventType": "historical_case_event",
            "actor": "responder-a",
            "occurredAt": now - 20 + index,
            "payload": {"reason": "Narrative must not enter the normalized view."},
            "payloadHash": f"{index:064x}"[-64:],
        }
        for index in range(module._CASE_INVESTIGATION_RECORD_LIMIT + 1)
    ]

    result = module._case_investigation_timeline(
        case,
        alert,
        case_events,
        [],
        [],
        decision_window_truncated=True,
        now=now + module._CASE_INVESTIGATION_RECORD_LIMIT,
    )

    assert result["complete"] is False
    assert result["incompleteReasons"] == [
        "tenant_decision_window_truncated",
        "investigation_record_limit_exceeded",
    ]
    assert result["omittedEvents"] == 3
    assert len(result["items"]) == module._CASE_INVESTIGATION_RECORD_LIMIT
    assert "Narrative must not enter" not in json.dumps(result)
    assert result["items"] == sorted(
        result["items"],
        key=lambda item: (item["occurredAt"], item["eventType"], item["id"]),
    )
    malformed_decision = {
        "id": "decision-corrupt",
        "deployment_id": "deployment-a",
        "agent_id": "agent-a",
        "observed_at": now,
        "tool_name": "Bash",
        "decision": "allowed_without_policy",
    }
    with pytest.raises(RuntimeError, match="decision evidence is malformed"):
        module._case_investigation_timeline(
            case,
            alert,
            [],
            [malformed_decision],
            [],
            decision_window_truncated=False,
            now=now,
        )


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


def test_incident_credential_revocation_is_agent_scoped_live_and_recoverable(
    monkeypatch: Any,
) -> None:
    """Case authority blocks every broker for one bound agent and no sibling."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-incident-credentials"
    now = 2_175_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    responder = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["incident-responder"],
        "sub": "responder-credentials",
    }
    platform = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "platform-credentials",
    }
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    for agent_id in ("agent-a", "agent-b"):
        table.put_item(
            Item=module._item_key(tenant, "AGENT", f"deployment-a:{agent_id}")
            | {
                "tenant_id": tenant,
                "id": agent_id,
                "deployment_id": "deployment-a",
                "host": "claude-code",
                "project_root": f"/synthetic/{agent_id}",
                "status": "connected",
                "expires_at": now + 300,
                "lifecycle_state": "active",
                "lifecycle_revision": 1,
            }
        )
    broker_fields = {
        "tenant_id": tenant,
        "name": "Synthetic workload broker",
        "provider": "azure_workload_identity",
        "principal": "11111111-2222-4333-8444-555555555555/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "audience": "https://vault.example.test",
        "allowed_tools": ["read_metadata"],
        "resource_ids": ["vault:synthetic"],
        "max_ttl_seconds": 300,
        "status": "active",
        "revision": 1,
        "revocation_epoch": 1,
        "evidence_revision": 1,
        "evidence_observed_at": now,
        "evidence_expires_at": now + 600,
        "evidence_digest": "b" * 64,
    }
    for broker_id in ("broker-a", "broker-b"):
        table.put_item(
            Item=module._item_key(tenant, "CREDENTIAL_BROKER", broker_id)
            | {**broker_fields, "id": broker_id, "name": f"Broker {broker_id}"}
        )
    binding = {
        "status": "bound",
        "agentKey": "deployment-a:agent-a",
        "deploymentId": "deployment-a",
        "agentId": "agent-a",
        "agentLifecycleRevision": 1,
        "bindingDigest": "a" * 64,
        "groupIds": ["group-a"],
        "policyId": "policy-a",
        "policyVersion": 1,
    }
    case_id = "case-credential-a"
    alert_id = "alert-credential-a"
    table.put_item(
        Item=module._item_key(tenant, "ALERT", alert_id)
        | {
            "id": alert_id,
            "source": "endpoint_evidence",
            "reasonCode": "process_inactive",
            "status": "acknowledged",
            "revision": 1,
            "severity": "high",
            "deviceId": "device-a",
            "message": "Synthetic runtime integrity alert.",
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "CASE", case_id)
        | {
            "tenant_id": tenant,
            "id": case_id,
            "alertId": alert_id,
            "title": "Synthetic credential incident",
            "severity": "high",
            "reasonCode": "process_inactive",
            "deviceId": "device-a",
            "alertSource": "endpoint_evidence",
            "ownerId": "responder-credentials",
            "status": "open",
            "revision": 1,
            "createdAt": now,
            "updatedAt": now,
            "binding": binding,
            "containment": None,
        }
    )

    def current_binding(_tenant: str, case: dict[str, Any]) -> dict[str, Any]:
        assert _tenant == tenant
        return dict(case["binding"])

    monkeypatch.setattr(module, "_case_current_binding", current_binding)
    revoked_response = _invoke(
        module,
        _event(
            f"/api/enterprise/cases/{case_id}/credentials/revoke",
            "POST",
            body={
                "expectedCaseRevision": 1,
                "expectedBindingDigest": binding["bindingDigest"],
                "reason": "Revoke brokered authority while the endpoint is investigated.",
            },
            claims=responder,
        ),
    )
    assert revoked_response["statusCode"] == 200
    revoked_case = json.loads(revoked_response["body"])
    assert revoked_case["status"] == "investigating"
    assert revoked_case["credentialRevocation"] == {
        "active": True,
        "agentKey": "deployment-a:agent-a",
        "revision": 1,
        "brokerCount": 2,
        "brokerIds": ["broker-a", "broker-b"],
        "activatedAt": now,
        "activatedBy": "responder-credentials",
    }
    control = table.items[(f"TENANT#{tenant}", "CREDENTIAL_CONTROL#deployment-a:agent-a")]
    assert control["active"] is True
    assert {item["brokerId"] for item in control["brokerSnapshots"]} == {
        "broker-a",
        "broker-b",
    }
    serialized_case = json.dumps(revoked_case).lower()
    assert "secret" not in serialized_case
    assert "token" not in serialized_case
    assert "synthetic-provider-token" not in serialized_case

    authority_request = {
        "schemaVersion": 1,
        "deploymentId": "deployment-a",
        "agentId": "agent-a",
        "principalId": "user:alice",
        "taskId": "task:synthetic",
        "toolName": "read_metadata",
        "resourceIds": ["vault:synthetic"],
        "credentialId": None,
    }
    human_check = _invoke(
        module,
        _event(
            "/api/enterprise/credential-brokers/broker-a/authority/check",
            "POST",
            body=authority_request,
            claims=platform,
        ),
    )
    assert human_check["statusCode"] == 403
    service_identity = json.loads(
        _invoke(
            module,
            _event(
                "/api/enterprise/identity/service-identities",
                "POST",
                body={
                    "serviceIdentityId": "incident-broker-runtime",
                    "name": "Incident-aware broker runtime",
                    "description": "Checks exact agent credential authority before provider use.",
                    "purpose": (
                        "Withhold brokered authority during a server-owned incident response."
                    ),
                    "capabilities": ["credential_broker_runtime"],
                    "expiresInDays": 7,
                },
                claims=platform,
            ),
        )["body"]
    )
    machine_token = service_identity["credential"]["accessToken"]
    machine_check = _invoke(
        module,
        _event(
            "/machine/v1/enterprise/credential-brokers/broker-a/authority/check",
            "POST",
            body=authority_request,
            token=machine_token,
        ),
    )
    assert machine_check["statusCode"] == 200
    assert json.loads(machine_check["body"])["reasonCode"] == "incident_case_revoked"
    machine_mutation = _invoke(
        module,
        _event(
            f"/machine/v1/enterprise/cases/{case_id}/credentials/restore",
            "POST",
            body={},
            token=machine_token,
        ),
    )
    assert machine_mutation["statusCode"] == 403
    exact_denial = module._credential_authority_check(
        tenant, "broker-a", authority_request, "service:broker-runtime"
    )
    assert exact_denial["executionAllowed"] is False
    assert exact_denial["state"] == "revoked"
    assert exact_denial["reasonCode"] == "incident_case_revoked"
    assert exact_denial["caseId"] == case_id
    sibling_allow = module._credential_authority_check(
        tenant,
        "broker-a",
        {**authority_request, "agentId": "agent-b"},
        "service:broker-runtime",
    )
    assert sibling_allow["executionAllowed"] is True
    assert sibling_allow["reasonCode"] == "no_active_incident_control"
    wrong_scope = module._credential_authority_check(
        tenant,
        "broker-a",
        {**authority_request, "agentId": "agent-b", "resourceIds": ["vault:other"]},
        "service:broker-runtime",
    )
    assert wrong_scope["executionAllowed"] is False
    assert wrong_scope["reasonCode"] == "broker_scope_mismatch"

    # A broker registered during the incident is also denied; the server-owned
    # agent control cannot be bypassed by selecting a broker omitted from the
    # original evidence snapshot.
    table.put_item(
        Item=module._item_key(tenant, "CREDENTIAL_BROKER", "broker-new")
        | {**broker_fields, "id": "broker-new", "name": "Broker new"}
    )
    assert (
        module._credential_authority_check(
            tenant, "broker-new", authority_request, "service:broker-runtime"
        )["reasonCode"]
        == "incident_case_revoked"
    )

    blocked_transition = _invoke(
        module,
        _event(
            f"/api/enterprise/cases/{case_id}/resolve",
            "POST",
            body={
                "expectedCaseRevision": 2,
                "reason": "Do not resolve while credential authority remains revoked.",
            },
            claims=responder,
        ),
    )
    assert blocked_transition["statusCode"] == 409
    assert "credential authority" in json.loads(blocked_transition["body"])["error"]
    monkeypatch.setattr(
        module,
        "_verify_agent",
        lambda *_args: {
            "verified": True,
            "checks": {
                "identity": {"passed": True},
                "heartbeat": {"passed": True},
                "emergencyStop": {"passed": True},
            },
            "controlState": {"activeStopScopes": []},
        },
    )
    table.items[(f"TENANT#{tenant}", f"ALERT#{alert_id}")]["status"] = "resolved"
    restored_response = _invoke(
        module,
        _event(
            f"/api/enterprise/cases/{case_id}/credentials/restore",
            "POST",
            body={
                "expectedCaseRevision": 2,
                "expectedCredentialControlRevision": 1,
                "reason": "Fresh server evidence proves the endpoint is ready for broker access.",
            },
            claims=responder,
        ),
    )
    assert restored_response["statusCode"] == 200, restored_response
    restored_case = json.loads(restored_response["body"])
    assert restored_case["credentialRevocation"]["active"] is False
    assert restored_case["credentialRevocation"]["revision"] == 2
    assert (
        module._credential_authority_check(
            tenant, "broker-a", authority_request, "service:broker-runtime"
        )["executionAllowed"]
        is True
    )
    assert [event["eventType"] for event in restored_case["timeline"]] == [
        "agent_credentials_revoked",
        "agent_credential_authority_restored",
    ]

    stale_restore = _invoke(
        module,
        _event(
            f"/api/enterprise/cases/{case_id}/credentials/restore",
            "POST",
            body={
                "expectedCaseRevision": 2,
                "expectedCredentialControlRevision": 1,
                "reason": "A replay cannot restore or alter current credential authority.",
            },
            claims=responder,
        ),
    )
    assert stale_restore["statusCode"] == 409

    other_tenant = "tenant-credential-other"
    table.put_item(Item=module._item_key(other_tenant, "TENANT", "root") | {"id": other_tenant})
    with pytest.raises(LookupError, match="broker not found"):
        module._credential_authority_check(
            other_tenant, "broker-a", authority_request, "service:other"
        )


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


def _endpoint_delivery_secret(module: Any, tenant: str) -> str:
    """Register one synthetic tenant-tagged Intune credential reference."""
    arn = (
        "arn:aws:secretsmanager:eu-west-1:111111111111:secret:"
        f"aai-sec/endpoint-delivery/{tenant}/intune-synthetic"
    )
    module._fake_secrets.secrets[arn] = {
        "description": {
            "ARN": arn,
            "KmsKeyId": module._ENDPOINT_DELIVERY_SECRET_KMS_KEY_ARN,
            "Tags": [
                {"Key": "aai-sec:tenant-id", "Value": tenant},
                {
                    "Key": "aai-sec:purpose",
                    "Value": "endpoint-delivery-provider",
                },
            ],
        }
    }
    return arn


def test_intune_provider_configuration_requires_independent_approval_and_hides_secret(
    monkeypatch: Any,
) -> None:
    """Intune delivery authority is immutable, two-person and locator-free."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-intune-provider"
    author = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "provider-author",
    }
    approver = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "provider-approver",
    }
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "kratos") | {"id": "kratos", "name": "Kratos"}
    )
    secret_arn = _endpoint_delivery_secret(module, tenant)
    draft_response = _invoke(
        module,
        _event(
            "/api/enterprise/endpoint-delivery/providers/intune/drafts",
            "POST",
            body={
                "providerTenantId": "11111111-1111-4111-8111-111111111111",
                "providerSecretArn": secret_arn,
                "deploymentIds": ["kratos"],
                "permissionEvidenceSha256": "a" * 64,
                "reason": "Enable reviewed Intune delivery for the Kratos deployment.",
            },
            claims=author,
        ),
    )
    assert draft_response["statusCode"] == 201, draft_response
    draft = json.loads(draft_response["body"])
    assert draft["state"] == "draft"
    assert draft["credentialConfigured"] is True
    assert secret_arn not in draft_response["body"]

    submitted = _invoke(
        module,
        _event(
            "/api/enterprise/endpoint-delivery/providers/intune/versions/1/submit",
            "POST",
            body={"expectedContentHash": draft["contentHash"]},
            claims=author,
        ),
    )
    assert submitted["statusCode"] == 200, submitted
    table.put_item(
        Item=module._item_key(tenant, "DELEGATED_GRANT", "provider-review")
        | {
            "id": "provider-review",
            "principal_id": "delegated-reviewer",
            "role": "security-operator",
            "scope_type": "deployment",
            "scope_id": "kratos",
            "status": "active",
            "expires_at": int(time.time()) + 300,
        }
    )
    delegated_review = _invoke(
        module,
        _event(
            "/api/enterprise/endpoint-delivery/providers/intune/versions/1/decision",
            "POST",
            body={
                "decision": "approved",
                "reason": "The delegated operator cannot approve provider-wide authority.",
            },
            claims={
                "custom:tenant_id": tenant,
                "aai:operator_id": "delegated-reviewer",
                "sub": "delegated-reviewer",
            },
        ),
    )
    assert delegated_review["statusCode"] == 403
    self_review = _invoke(
        module,
        _event(
            "/api/enterprise/endpoint-delivery/providers/intune/versions/1/decision",
            "POST",
            body={
                "decision": "approved",
                "reason": "The least-privilege Graph permissions were independently verified.",
            },
            claims=author,
        ),
    )
    assert self_review["statusCode"] == 403
    approved = _invoke(
        module,
        _event(
            "/api/enterprise/endpoint-delivery/providers/intune/versions/1/decision",
            "POST",
            body={
                "decision": "approved",
                "reason": "The least-privilege Graph permissions were independently verified.",
            },
            claims=approver,
        ),
    )
    assert approved["statusCode"] == 200, approved
    activated = _invoke(
        module,
        _event(
            "/api/enterprise/endpoint-delivery/providers/intune/versions/1/activate",
            "POST",
            body={"expectedActiveVersion": 0},
            claims=approver,
        ),
    )
    assert activated["statusCode"] == 200, activated
    posture = json.loads(activated["body"])
    assert posture["activeVersion"] == 1
    assert posture["pendingVersion"] is None
    assert posture["versions"][0]["approvedBy"] == "provider-approver"
    assert secret_arn not in activated["body"]


def test_intune_provider_activation_revalidates_secret_and_fails_closed(
    monkeypatch: Any,
) -> None:
    """Retagging a reviewed credential prevents it becoming delivery authority."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-intune-retag"
    author = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "provider-author",
    }
    approver = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["security-operator"],
        "sub": "provider-approver",
    }
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(Item=module._item_key(tenant, "DEPLOYMENT", "kratos") | {"id": "kratos"})
    secret_arn = _endpoint_delivery_secret(module, tenant)
    draft = json.loads(
        _invoke(
            module,
            _event(
                "/api/enterprise/endpoint-delivery/providers/intune/drafts",
                "POST",
                body={
                    "providerTenantId": "11111111-1111-4111-8111-111111111111",
                    "providerSecretArn": secret_arn,
                    "deploymentIds": ["kratos"],
                    "permissionEvidenceSha256": "b" * 64,
                    "reason": "Enable reviewed Intune delivery for the Kratos deployment.",
                },
                claims=author,
            ),
        )["body"]
    )
    assert (
        _invoke(
            module,
            _event(
                "/api/enterprise/endpoint-delivery/providers/intune/versions/1/submit",
                "POST",
                body={"expectedContentHash": draft["contentHash"]},
                claims=author,
            ),
        )["statusCode"]
        == 200
    )
    assert (
        _invoke(
            module,
            _event(
                "/api/enterprise/endpoint-delivery/providers/intune/versions/1/decision",
                "POST",
                body={
                    "decision": "approved",
                    "reason": "The least-privilege Graph permissions were independently verified.",
                },
                claims=approver,
            ),
        )["statusCode"]
        == 200
    )
    module._fake_secrets.secrets[secret_arn]["description"]["Tags"] = [
        {"Key": "aai-sec:tenant-id", "Value": "another-tenant"},
        {"Key": "aai-sec:purpose", "Value": "endpoint-delivery-provider"},
    ]
    denied = _invoke(
        module,
        _event(
            "/api/enterprise/endpoint-delivery/providers/intune/versions/1/activate",
            "POST",
            body={"expectedActiveVersion": 0},
            claims=approver,
        ),
    )
    assert denied["statusCode"] == 400
    root = table.items[(f"TENANT#{tenant}", "ENDPOINT_PROVIDER#intune")]
    assert root["active_version"] == 0
    assert (
        table.items[(f"TENANT#{tenant}", "ENDPOINT_PROVIDER_VERSION#intune:1")]["state"]
        == "approved"
    )


def test_intune_provider_infrastructure_separates_api_and_worker_authority() -> None:
    """Only a disabled-by-default isolated worker can decrypt delivery credentials."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    assert 'new kms.Key(\n      this,\n      "EndpointDeliveryCredentialKey"' in stack
    assert "ENDPOINT_DELIVERY_SECRET_PREFIX: endpointDeliverySecretPrefix" in stack
    assert "ENDPOINT_DELIVERY_SECRET_KMS_KEY_ARN: endpointDeliveryCredentialKey.keyArn" in stack
    segment_start = stack.index("The API verifies secret identity, KMS provenance")
    segment = stack[segment_start : stack.index("policySigningKey.grant", segment_start)]
    assert 'actions: ["secretsmanager:DescribeSecret"]' in segment
    assert '"secretsmanager:GetSecretValue"' not in segment
    assert "endpointDeliveryCredentialKey.grantDecrypt(handler)" not in stack
    assert 'indexName: "EndpointDeliveryOutbox"' in stack
    assert '"EndpointDeliveryWorker"' in stack
    assert "endpointDeliveryCredentialKey.grantDecrypt(endpointDeliveryWorker)" in stack
    assert "endpointDeliveryWorkerQueue.grantSendMessages(endpointDeliveryWorker)" in stack
    assert "ENDPOINT_DELIVERY_QUEUE_URL: endpointDeliveryWorkerQueue.queueUrl" in stack
    assert "recursiveLoop: lambda.RecursiveLoop.ALLOW" in stack
    assert "enabled: endpointDeliveryDispatchEnabled" in stack
    assert 'ENDPOINT_DELIVERY_DISPATCH_ENABLED?.trim() ?? "false"' in stack
    assert (
        "enabled endpoint delivery requires ENDPOINT_DELIVERY_ENABLEMENT_EVIDENCE_SHA256" in stack
    )
    assert 'handler: "intune_delivery_worker.handler"' in stack
    assert "batchSize: 1" in stack


def test_intune_delivery_outbox_is_idempotent_and_authority_bound(monkeypatch: Any) -> None:
    """Reconciliation freezes exact live authority without dispatching Graph writes."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-intune-outbox"
    secret_arn = _endpoint_delivery_secret(module, tenant)
    provider_configuration = {
        "schemaVersion": 1,
        "provider": "intune",
        "providerTenantId": "11111111-1111-4111-8111-111111111111",
        "providerSecretArn": secret_arn,
        "deploymentIds": ["kratos"],
        "permissionEvidenceSha256": "c" * 64,
        "reason": "Approved endpoint delivery configuration for synthetic testing.",
    }
    provider_hash = module._configuration_hash(provider_configuration)
    table.put_item(
        Item=module._item_key(tenant, "ENDPOINT_PROVIDER", "intune")
        | {
            "id": "intune",
            "provider": "intune",
            "active_version": 1,
            "latest_version": 1,
            "pending_version": None,
            "governance_state": "active",
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "ENDPOINT_PROVIDER_VERSION", "intune:1")
        | {
            "id": "intune:1",
            "provider": "intune",
            "version": 1,
            "state": "active",
            "configuration": provider_configuration,
            "content_hash": provider_hash,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "kratos")
        | {"id": "kratos", "sdk_version": "1.0.1"}
    )
    rollout = {
        **module._item_key(tenant, "RUNTIME_ROLLOUT", "kratos"),
        "tenant_id": tenant,
        "deploymentId": "kratos",
        "revision": 7,
        "state": "active",
    }
    table.put_item(Item=rollout)
    for index in range(42):
        agent_id = f"claude-{index:03d}"
        table.put_item(
            Item=module._item_key(tenant, "AGENT", f"kratos:{agent_id}")
            | {
                "id": agent_id,
                "deployment_id": "kratos",
                "host": "claude-code",
                "lifecycle_state": "active",
                "lifecycle_revision": 3,
            }
        )
        table.put_item(
            Item=module._item_key(tenant, "ENDPOINT_EVIDENCE", f"device-{index:03d}")
            | {"revision": 5, "reportDigest": f"{index + 1:064x}"}
        )
    monkeypatch.setattr(module, "_validated_runtime_rollout", lambda value, _tenant: value)
    monkeypatch.setattr(module, "_runtime_rollout_agent_selected", lambda *_value: True)
    monkeypatch.setattr(
        module,
        "_runtime_agent_attests_release",
        lambda agent, *_args, **_kwargs: agent.get("id") == "claude-000",
    )
    monkeypatch.setattr(
        module,
        "_endpoint_delivery_readiness",
        lambda _tenant, _deployment: {
            "packageAuthority": {
                "packages": [
                    {
                        "id": "package-a",
                        "manifestSha256": "e" * 64,
                        "objectSha256": "f" * 64,
                        "providerPackageIdentitySha256": "1" * 64,
                    }
                ]
            },
            "items": [
                {
                    "readyForDispatch": True,
                    "directoryDeviceRegistrationId": (f"00000000-0000-4000-8000-{index + 1:012d}"),
                    "deviceId": f"device-{index:03d}",
                    "agentKey": f"kratos:claude-{index:03d}",
                    "agentId": f"claude-{index:03d}",
                    "host": "claude-code",
                    "releaseId": "claude-code:1.0.1",
                    "packageId": "package-a",
                    "bindingDigest": f"{index + 100:064x}",
                }
                for index in range(42)
            ],
        },
    )
    assert module._create_endpoint_delivery_commands(tenant, rollout) == 1
    assert module._create_endpoint_delivery_commands(tenant, rollout) == 0
    commands = [
        item
        for item in table.items.values()
        if item.get("sk", "").startswith("ENDPOINT_DELIVERY_COMMAND#")
    ]
    assert len(commands) == 1
    command = commands[0]
    targets = [
        item
        for item in table.items.values()
        if item.get("sk", "").startswith("ENDPOINT_DELIVERY_TARGET#")
    ]
    assert len(targets) == 41
    assert command["status"] == "pending"
    assert command["instruction"]["providerVersion"] == 1
    assert command["instruction"]["rolloutRevision"] == 7
    assert command["instruction"]["targetCount"] == 41
    assert len(command["instruction"]["pages"]) == 2
    assert all(target["instruction"]["agentLifecycleRevision"] == 3 for target in targets)
    assert command["delivery_outbox_pk"] == f"ENDPOINT_DELIVERY_OUTBOX#{tenant}"
    assert secret_arn not in json.dumps(command)
    assert secret_arn not in json.dumps(targets)
    view = module._endpoint_delivery_commands(tenant, "kratos")
    assert view["dispatchEnabled"] is False
    assert view["items"][0]["dispatchEnabled"] is False
    assert view["items"][0]["attemptCount"] == 0
    assert view["items"][0]["failureCode"] is None
    assert view["items"][0]["providerEvidence"] is None
    assert view["items"][0]["continuationStage"] == "not_started"
    assert view["items"][0]["completedTargets"] == 0


def test_endpoint_delivery_command_view_is_content_minimised_and_fails_closed(
    monkeypatch: Any,
) -> None:
    """Operators receive fixed evidence, while malformed worker state is denied."""
    module, _table = _load_handler(monkeypatch)
    provider_evidence: dict[str, Any] = {
        "groupReferenceSha256": "c" * 64,
        "appReferenceSha256": "d" * 64,
        "assignmentReferenceSha256": "e" * 64,
        "targetCount": 3,
    }
    record: dict[str, Any] = {
        "id": "a" * 64,
        "provider": "intune",
        "deployment_id": "deployment-1",
        "host": "claude-code",
        "release_id": "release-1",
        "package_id": "package-1",
        "provider_version": 1,
        "rollout_revision": 2,
        "target_count": 3,
        "cohort_digest": "b" * 64,
        "status": "assigned_reported",
        "attempt_count": 2,
        "failure_code": None,
        "provider_evidence": provider_evidence,
        "instruction_digest": "f" * 64,
        "created_at": 1_800_000_000,
        "updated_at": 1_800_000_010,
    }

    view = module._endpoint_delivery_command_view(record)

    assert view["attemptCount"] == 2
    assert view["providerEvidence"] == record["provider_evidence"]
    assert view["continuationRevision"] == 0
    assert view["continuationStage"] == "not_started"
    assert view["completedTargets"] == 0
    assert "groupId" not in json.dumps(view)
    with pytest.raises(RuntimeError, match="provider evidence is invalid"):
        module._endpoint_delivery_command_view(
            {**record, "provider_evidence": {**provider_evidence, "groupId": "raw"}}
        )
    with pytest.raises(RuntimeError, match="failure code is invalid"):
        module._endpoint_delivery_command_view({**record, "failure_code": "raw URL"})
    with pytest.raises(RuntimeError, match="continuation state is invalid"):
        module._endpoint_delivery_command_view({**record, "continuation_completed_targets": 4})


def test_intune_delivery_dispatch_is_gated_and_latest_authority_bound(
    monkeypatch: Any,
) -> None:
    """Only an evidenced cutover may send an opaque latest command to FIFO."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-intune-dispatch"
    command_id = "a" * 64
    digest = "b" * 64
    cohort = "c" * 64
    command = {
        "pk": f"TENANT#{tenant}",
        "sk": f"ENDPOINT_DELIVERY_COMMAND#{command_id}",
        "tenant_id": tenant,
        "id": command_id,
        "status": "pending",
        "instruction_digest": digest,
        "cohort_digest": cohort,
        "instruction": {"deploymentId": "deployment-1", "packageId": "package-1"},
        "delivery_outbox_pk": f"ENDPOINT_DELIVERY_OUTBOX#{tenant}",
        "delivery_outbox_sk": f"1#{command_id}",
    }
    table.items[(command["pk"], command["sk"])] = dict(command)
    authority = {
        "pk": f"TENANT#{tenant}",
        "sk": "ENDPOINT_DELIVERY_AUTHORITY#deployment-1:package-1",
        "command_id": command_id,
        "instruction_digest": digest,
        "cohort_digest": cohort,
    }
    table.items[(authority["pk"], authority["sk"])] = authority

    assert module._dispatch_endpoint_delivery_command(command) is False
    assert module._fake_sqs.messages == []

    module._ENDPOINT_DELIVERY_DISPATCH_ENABLED = True
    module._ENDPOINT_DELIVERY_QUEUE_URL = "https://sqs.example.invalid/intune.fifo"
    module._ENDPOINT_DELIVERY_ENABLEMENT_EVIDENCE_SHA256 = "d" * 64
    assert module._dispatch_endpoint_delivery_command(command) is True
    assert json.loads(module._fake_sqs.messages[0]["MessageBody"]) == {
        "tenantId": tenant,
        "commandId": command_id,
        "continuationRevision": 0,
    }
    assert module._fake_sqs.messages[0]["MessageDeduplicationId"] == f"{command_id}:0"
    stored = table.items[(command["pk"], command["sk"])]
    assert stored["status"] == "queued"
    assert "delivery_outbox_pk" not in stored


def test_intune_delivery_dispatch_rejects_superseded_command(monkeypatch: Any) -> None:
    """A stale immutable command never reaches the provider queue."""
    module, table = _load_handler(monkeypatch)
    module._ENDPOINT_DELIVERY_DISPATCH_ENABLED = True
    module._ENDPOINT_DELIVERY_QUEUE_URL = "https://sqs.example.invalid/intune.fifo"
    module._ENDPOINT_DELIVERY_ENABLEMENT_EVIDENCE_SHA256 = "d" * 64
    tenant = "tenant-intune-stale"
    command = {
        "tenant_id": tenant,
        "id": "a" * 64,
        "status": "pending",
        "instruction_digest": "b" * 64,
        "cohort_digest": "c" * 64,
        "instruction": {"deploymentId": "deployment-1", "packageId": "package-1"},
    }
    table.items[(f"TENANT#{tenant}", "ENDPOINT_DELIVERY_AUTHORITY#deployment-1:package-1")] = {
        "command_id": "e" * 64,
        "instruction_digest": "f" * 64,
        "cohort_digest": "0" * 64,
    }
    assert module._dispatch_endpoint_delivery_command(command) is False
    assert module._fake_sqs.messages == []


def test_intune_delivery_outbox_rejects_concurrent_provider_change(monkeypatch: Any) -> None:
    """A provider cutover during command creation cannot leave stale work queued."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-intune-outbox-race"
    secret_arn = _endpoint_delivery_secret(module, tenant)
    configuration = {
        "providerSecretArn": secret_arn,
        "deploymentIds": ["kratos"],
    }
    table.put_item(
        Item=module._item_key(tenant, "ENDPOINT_PROVIDER", "intune")
        | {
            "active_version": 1,
            "governance_state": "active",
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "ENDPOINT_PROVIDER_VERSION", "intune:1")
        | {
            "provider": "intune",
            "version": 1,
            "state": "active",
            "configuration": configuration,
            "content_hash": "a" * 64,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "kratos")
        | {"id": "kratos", "sdk_version": "1.0.1"}
    )
    rollout = module._item_key(tenant, "RUNTIME_ROLLOUT", "kratos") | {
        "tenant_id": tenant,
        "deploymentId": "kratos",
        "revision": 1,
        "state": "active",
    }
    table.put_item(Item=rollout)
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "kratos:claude-a")
        | {
            "id": "claude-a",
            "deployment_id": "kratos",
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "ENDPOINT_EVIDENCE", "device-a")
        | {"revision": 1, "reportDigest": "b" * 64}
    )
    monkeypatch.setattr(module, "_validated_runtime_rollout", lambda value, _tenant: value)
    monkeypatch.setattr(module, "_runtime_rollout_agent_selected", lambda *_value: True)
    monkeypatch.setattr(
        module,
        "_endpoint_delivery_readiness",
        lambda *_value: {
            "packageAuthority": {
                "packages": [
                    {
                        "id": "package-a",
                        "manifestSha256": "c" * 64,
                        "objectSha256": "d" * 64,
                        "providerPackageIdentitySha256": "e" * 64,
                    }
                ]
            },
            "items": [
                {
                    "readyForDispatch": True,
                    "directoryDeviceRegistrationId": ("22222222-2222-4222-8222-222222222222"),
                    "deviceId": "device-a",
                    "agentKey": "kratos:claude-a",
                    "agentId": "claude-a",
                    "host": "claude-code",
                    "releaseId": "claude-code:1.0.1",
                    "packageId": "package-a",
                    "bindingDigest": "f" * 64,
                }
            ],
        },
    )

    def cut_over_provider() -> None:
        table.items[(f"TENANT#{tenant}", "ENDPOINT_PROVIDER#intune")]["active_version"] = 2

    module.DYNAMODB.before_transaction = cut_over_provider
    with pytest.raises(module.PolicyConflict):
        module._create_endpoint_delivery_commands(tenant, rollout)
    assert not [
        item
        for item in table.items.values()
        if item.get("sk", "").startswith(
            ("ENDPOINT_DELIVERY_COMMAND#", "ENDPOINT_DELIVERY_TARGET#")
        )
    ]


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


def test_aws_integrity_baselines_are_private_versioned_and_handler_scoped() -> None:
    """Fleet baselines must use exact-version private storage, not public state."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    start = stack.index('new s3.Bucket(this, "IntegrityBaselineBucket"')
    end = stack.index("});", start)
    bucket = stack[start:end]
    assert "versioned: true" in bucket
    assert "s3.BucketEncryption.KMS" in bucket
    assert "encryptionKey: dataProtectionKey" in bucket
    assert "s3.BlockPublicAccess.BLOCK_ALL" in bucket
    assert "enforceSSL: true" in bucket
    assert "cdk.RemovalPolicy.RETAIN" in bucket
    assert '"s3:GetObjectVersion"' in stack
    assert '"s3:PutObject"' in stack
    assert 'integrityBaselines.arnForObjects("tenant=*")' in stack
    assert "integrityBaselines.grantReadWrite(handler)" not in stack
    assert "INTEGRITY_BASELINE_BUCKET: integrityBaselines.bucketName" in stack
    assert 'CfnOutput(this, "IntegrityBaselineBucketName"' in stack


def test_aws_data_stores_and_queues_share_one_isolated_data_key_boundary() -> None:
    """Retained tenant stores and durable transports cannot use weak defaults."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    assert stack.count("encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED") == 4
    assert stack.count("encryptionKey: dataProtectionKey") >= 8
    assert "sqs.QueueEncryption.SQS_MANAGED" not in stack
    assert "sqs.QueueEncryption.KMS_MANAGED" not in stack
    assert stack.count("encryptionMasterKey: dataProtectionKey") >= 20
    assert "masterKey: dataProtectionKey" in stack
    assert 'new cdk.CfnOutput(this, "DataBoundaryStatus"' in stack
    assert 'new cdk.CfnOutput(this, "DataBoundaryKeyOwnership"' in stack


def test_aws_discovery_pages_are_private_versioned_and_handler_scoped() -> None:
    """Fleet inventory payloads require retained exact-version private storage."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    start = stack.index('new s3.Bucket(this, "DiscoveryPageBucket"')
    end = stack.index("});", start)
    bucket = stack[start:end]
    assert "versioned: true" in bucket
    assert "s3.BucketEncryption.KMS" in bucket
    assert "encryptionKey: dataProtectionKey" in bucket
    assert "s3.BlockPublicAccess.BLOCK_ALL" in bucket
    assert "enforceSSL: true" in bucket
    assert "cdk.RemovalPolicy.RETAIN" in bucket
    assert 'discoveryPages.arnForObjects("tenant=*")' in stack
    assert "discoveryPages.grantReadWrite(handler)" not in stack
    assert "DISCOVERY_PAGE_BUCKET: discoveryPages.bucketName" in stack
    assert 'CfnOutput(this, "DiscoveryPageBucketName"' in stack


def test_aws_dynamic_groups_have_a_monitored_internal_reconciliation_schedule() -> None:
    """Approved dynamic rules must converge without relying on a browser session."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    passive = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/passive-regional-cell-stack.ts"
    ).read_text(encoding="utf-8")
    for source in (stack, passive):
        assert '"DynamicGroupReconciliationSchedule"' in source
        assert 'source: "aai.dynamic-group-reconciliation"' in source
        assert "events.Schedule.rate(cdk.Duration.minutes(5))" in source
    assert "deadLetterQueue: dynamicGroupReconciliationDlq" in stack
    assert '"DynamicGroupReconciliationDeadLetters"' in stack
    assert "new cloudwatchActions.SnsAction(securityAlerts)" in stack


def test_aws_evidence_worker_declares_its_bounded_recursive_queue_workflow() -> None:
    """Lambda recursion protection must not truncate intentional paginated work."""
    stack = (
        Path(__file__).parents[1] / "infra/aws-control-plane/lib/aws-control-plane-stack.ts"
    ).read_text(encoding="utf-8")
    assert "recursiveLoop: lambda.RecursiveLoop.ALLOW" in stack
    assert "reservedConcurrentExecutions: 5" in stack
    assert "deadLetterQueue: { queue: evidenceWorkerDlq, maxReceiveCount: 3 }" in stack


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
    runtime_manifest = _runtime_manifest()
    _set_runtime_manifests(monkeypatch, [runtime_manifest])
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
            "attestation_sdk_version": runtime_manifest["sdkVersion"],
            "attestation_sdk_revision": runtime_manifest["sdkRevision"],
            "attestation_manifest_sha256": module._runtime_manifest_digest(runtime_manifest),
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


def test_aws_managed_configuration_requires_exact_policy_trust_convergence(
    monkeypatch: Any,
) -> None:
    """Missing or altered endpoint trust evidence cannot become enforced."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-trust-convergence"
    desired = {
        "host": "claude-code",
        "hostVersion": "2.1.220",
        "platform": "macos",
        "bundleHash": "b" * 64,
        "policyId": "policy-safe",
        "policyVersion": 4,
        "policyTrustBundleSha256": "a" * 64,
    }
    table.put_item(
        Item=module._item_key(tenant, "CONFIGURATION", "dep-a")
        | {"desiredConfiguration": {"managedHost": desired}}
    )
    agent: dict[str, Any] = {
        "deployment_id": "dep-a",
        "host": "claude-code",
        "managed_configuration_report": {
            **{key: value for key, value in desired.items() if key != "policyTrustBundleSha256"},
            "source": "mdm",
            "verifiedAt": 90,
            "expiresAt": 200,
        },
    }
    assert module._managed_configuration_posture(tenant, agent, now=100)["status"] == "conflict"
    agent["managed_configuration_report"] = {
        **desired,
        "source": "mdm",
        "verifiedAt": 90,
        "expiresAt": 200,
    }
    assert module._managed_configuration_posture(tenant, agent, now=100)["status"] == "enforced"
    agent["managed_configuration_report"]["policyTrustBundleSha256"] = "f" * 64
    assert module._managed_configuration_posture(tenant, agent, now=100)["status"] == "conflict"


def test_aws_policy_trust_cutover_readiness_requires_every_live_authority(
    monkeypatch: Any,
) -> None:
    """Cutover posture is true only for exact package, rollout and heartbeat trust."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-cutover"
    now = 1_900_000_000
    package, desired = _managed_package_fixture(with_trust=True)
    table.put_item(
        Item=module._item_key(tenant, "CONFIGURATION", "dep-a")
        | {
            "deploymentId": "dep-a",
            "desiredConfiguration": {"managedHost": desired},
            "rolloutState": "converged",
            "rolloutPercentage": 100,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "MANAGED_PACKAGE", "dep-a")
        | {
            "deploymentId": "dep-a",
            "revision": 1,
            "packageSha256": package.package_sha256,
            "bundleHash": package.bundle_hash,
            "host": package.host.value,
            "hostVersion": package.host_version,
            "platform": package.platform.value,
            "policyId": package.policy_id,
            "policyVersion": package.policy_version,
            "policyTrustBundleSha256": package.policy_trust_bundle_sha256,
            "publishedAt": now - 10,
            "publishedBy": "platform-admin",
        }
    )
    report = {
        **desired,
        "source": "mdm",
        "verifiedAt": now - 10,
        "expiresAt": now + 200,
    }
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "host": "claude-code",
            "lifecycle_state": "active",
            "managed_configuration_report": report,
        }
    )
    posture = module._policy_trust_convergence(tenant, now=now)
    assert posture["readyForSignerCutover"] is True
    assert posture["enforcedAgentCount"] == 1
    assert len(posture["requiredTrustKeyArns"]) == 3
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant, "status": "active"}
    )
    monkeypatch.setattr(module.time, "time", lambda: now)
    claims = {
        "sub": "platform-admin-a",
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
    }
    route = _invoke(
        module,
        _event("/enterprise/resilience/policy-trust", "GET", claims=claims),
    )
    assert route["statusCode"] == 200
    assert json.loads(route["body"])["readyForSignerCutover"] is True
    denied = _invoke(
        module,
        _event(
            "/enterprise/resilience/policy-trust",
            "GET",
            claims={"sub": "unknown", "custom:tenant_id": tenant},
        ),
    )
    assert denied["statusCode"] == 403
    agent_key = module._item_key(tenant, "AGENT", "dep-a:agent-a")
    table.items[(agent_key["pk"], agent_key["sk"])]["managed_configuration_report"][
        "policyTrustBundleSha256"
    ] = "f" * 64
    assert module._policy_trust_convergence(tenant, now=now)["readyForSignerCutover"] is False


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


def test_aws_managed_package_v2_requires_exact_deployment_owned_trust(monkeypatch: Any) -> None:
    """A package publisher cannot choose an unrelated signer trust root."""
    module, _table = _load_handler(monkeypatch)
    package, desired = _managed_package_fixture(with_trust=True)
    value, target, _encoded = module._managed_package(
        base64.b64encode(package.to_json()).decode(), package.package_sha256
    )
    assert value["schemaVersion"] == 2
    assert target == desired
    forged = cast(dict[str, Any], json.loads(package.to_json()))
    forged["policyTrust"]["content"] = forged["policyTrust"]["content"].replace(
        "12345678-1234-1234-1234-123456789abc",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
    )
    forged["policyTrust"]["sha256"] = hashlib.sha256(
        forged["policyTrust"]["content"].encode()
    ).hexdigest()
    forged_bytes = json.dumps(forged, separators=(",", ":"), sort_keys=True).encode()
    with pytest.raises(ValueError, match="deployment-owned"):
        module._managed_package(
            base64.b64encode(forged_bytes).decode(),
            hashlib.sha256(forged_bytes).hexdigest(),
        )


@pytest.mark.parametrize("host", [AgentHost.CLAUDE_CODE, AgentHost.CODEX_CLI])
def test_aws_managed_package_publication_and_drift_repair_route(
    monkeypatch: Any, host: AgentHost
) -> None:
    """AWS publishes by CAS and lets only the exact attested agent repair drift."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-package"
    now = 1_900_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    runtime_manifest = _runtime_manifest(host.value)
    _set_runtime_manifests(monkeypatch, [runtime_manifest])
    package, desired = _managed_package_fixture(host=host)
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
            "host": host.value,
            "project_root": project_root,
            "status": "connected",
            "expires_at": now + 300,
            "emergencyStop": False,
            "attestation_status": "compliant",
            "attestation_expires_at": now + 300,
            "attestation_sdk_version": runtime_manifest["sdkVersion"],
            "attestation_sdk_revision": runtime_manifest["sdkRevision"],
            "attestation_manifest_sha256": module._runtime_manifest_digest(runtime_manifest),
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
        "authorityBlockers": ["emergency_stop"],
        "evidenceAllowed": True,
        "executionAllowed": False,
        "nativeEffectiveControls": {
            "desired": None,
            "required": False,
            "status": "not_applicable",
        },
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
    """Only exact endpoint evidence can converge a ring and anchor rollback."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-rollout"
    clock = [2_230_000_000]
    monkeypatch.setattr(module.time, "time", lambda: clock[0])
    package_v1, desired_v1 = _managed_package_fixture(policy_version=1)
    package_v2, desired_v2 = _managed_package_fixture(policy_version=2)
    table.put_item(
        Item=module._item_key(tenant, "TENANT", "root")
        | {
            "id": tenant,
            "endpoint_detection_pk": "ENDPOINT_DETECTION#00",
            "endpoint_detection_sk": tenant,
        }
    )
    table.put_item(
        Item=module._item_key(tenant, "DEPLOYMENT", "deployment-a")
        | {
            "id": "deployment-a",
            "organization_id": "org-a",
            "project_id": "project-a",
            "sdk_version": "1.1.0",
        }
    )
    agent_ids = [f"agent-{index:02d}" for index in range(20)]
    for agent_id in agent_ids:
        table.put_item(
            Item=module._item_key(tenant, "AGENT", f"deployment-a:{agent_id}")
            | {
                "id": agent_id,
                "deployment_id": "deployment-a",
                "host": "claude-code",
                "status": "connected",
                "expires_at": clock[0] + 3_600,
                "lifecycle_state": "active",
                "lifecycle_revision": 1,
            }
        )
    claims = {"custom:tenant_id": tenant, "cognito:groups": ["platform-admin"], "sub": "operator"}

    def create_template(template_id: str, desired: dict[str, Any]) -> None:
        response = _invoke(
            module,
            _event(
                "/enterprise/templates",
                "POST",
                body={
                    "templateId": template_id,
                    "name": template_id,
                    "configuration": {"managedHost": desired},
                },
                claims=claims,
            ),
        )
        assert response["statusCode"] == 201, response

    def publish(package: ManagedDeploymentPackage, expected_revision: int) -> None:
        response = _invoke(
            module,
            _event(
                "/enterprise/deployments/deployment-a/managed-package",
                "PUT",
                body={
                    "expectedRevision": expected_revision,
                    "packageBase64": base64.b64encode(package.to_json()).decode(),
                    "packageSha256": package.package_sha256,
                },
                claims=claims,
            ),
        )
        assert response["statusCode"] == 201, response

    def configuration() -> dict[str, Any]:
        response = _invoke(
            module,
            _event("/enterprise/deployment-config", "GET", claims=claims),
        )
        assert response["statusCode"] == 200, response
        return cast(dict[str, Any], json.loads(response["body"])["items"][0])

    def rollout_request(
        revision: int,
        *,
        target: str,
        percentage: int,
        ring: str,
        schedule: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "deploymentIds": ["deployment-a"],
            "expectedRevisions": {"deployment-a": revision},
            "targetState": target,
            "percentage": percentage,
            "channel": "stable",
            "ring": ring,
            "reason": "Exercise a bounded synthetic managed configuration rollout.",
            "healthCriteria": {
                "maxUnavailablePercent": 10,
                "maxDriftPercent": 10,
                "minSampleSize": 1,
                "gracePeriodSeconds": 300,
            },
            "schedule": schedule,
        }

    create_template("template-a", desired_v1)
    staged = _invoke(
        module,
        _event(
            "/enterprise/deployment-config",
            "POST",
            body={"deploymentId": "deployment-a", "templateId": "template-a"},
            claims=claims,
        ),
    )
    assert staged["statusCode"] == 201, staged
    staged_body = json.loads(staged["body"])
    assert staged_body["drifted"] is True
    assert staged_body["appliedHash"] is None
    assert staged_body["rolloutRevision"] == 1
    publish(package_v1, 0)

    legacy_claim = _invoke(
        module,
        _event(
            "/enterprise/deployment-config/batch-rollout",
            "POST",
            body={"deploymentIds": ["deployment-a"], "state": "active", "percentage": 100},
            claims=claims,
        ),
    )
    assert legacy_claim["statusCode"] == 400
    canary = _invoke(
        module,
        _event(
            "/enterprise/deployment-config/batch-rollout",
            "POST",
            body=rollout_request(
                staged_body["rolloutRevision"],
                target="canary",
                percentage=25,
                ring="canary",
            ),
            claims=claims,
        ),
    )
    assert canary["statusCode"] == 200, canary
    canary_body = json.loads(canary["body"])["items"][0]
    assert canary_body["rolloutState"] == "canary"
    assert canary_body["rolloutPackageRevision"] == 1
    assert canary_body["convergence"]["selectedAgents"] > 0
    assert canary_body["convergence"]["selectedAgents"] < len(agent_ids)
    assert canary_body["appliedHash"] is None

    stale = _invoke(
        module,
        _event(
            "/enterprise/deployment-config/batch-rollout",
            "POST",
            body=rollout_request(
                staged_body["rolloutRevision"],
                target="active",
                percentage=100,
                ring="broad",
            ),
            claims=claims,
        ),
    )
    assert stale["statusCode"] == 409
    active = _invoke(
        module,
        _event(
            "/enterprise/deployment-config/batch-rollout",
            "POST",
            body=rollout_request(
                canary_body["rolloutRevision"],
                target="active",
                percentage=100,
                ring="broad",
            ),
            claims=claims,
        ),
    )
    activated = json.loads(active["body"])["items"][0]
    assert active["statusCode"] == 200, active
    assert activated["rolloutState"] == "active"
    assert activated["drifted"] is True
    assert activated["appliedHash"] is None

    for agent_id in agent_ids:
        table.items[(f"TENANT#{tenant}", f"AGENT#deployment-a:{agent_id}")][
            "managed_configuration_report"
        ] = {
            **desired_v1,
            "source": "endpoint-managed-file",
            "verifiedAt": clock[0],
            "expiresAt": clock[0] + 3_600,
        }
    converged = configuration()
    assert converged["rolloutState"] == "converged", converged
    assert converged["drifted"] is False
    assert converged["appliedHash"] == converged["desiredHash"]
    assert converged["lastKnownGoodVersion"] == 1
    assert converged["lastKnownGoodPackageRevision"] == 1
    assert converged["convergence"]["fullConverged"] is True

    create_template("template-b", desired_v2)
    second_stage = _invoke(
        module,
        _event(
            "/enterprise/deployment-config",
            "POST",
            body={"deploymentId": "deployment-a", "templateId": "template-b"},
            claims=claims,
        ),
    )
    assert second_stage["statusCode"] == 201, second_stage
    second_body = json.loads(second_stage["body"])
    assert second_body["version"] == 2
    assert second_body["lastKnownGoodVersion"] == 1
    publish(package_v2, 1)
    second_active = _invoke(
        module,
        _event(
            "/enterprise/deployment-config/batch-rollout",
            "POST",
            body=rollout_request(
                second_body["rolloutRevision"],
                target="active",
                percentage=100,
                ring="broad",
            ),
            claims=claims,
        ),
    )
    assert second_active["statusCode"] == 200, second_active
    clock[0] += 301
    events: list[str] = []
    monkeypatch.setattr(
        module,
        "_audit",
        lambda _tenant, event_type, _actor, _payload: events.append(event_type),
    )
    scheduled = module.handler({"source": "aai.rollout-reconciliation", "schemaVersion": 1}, None)
    assert scheduled["processedRollouts"] == 1
    auto_paused = configuration()
    assert auto_paused["rolloutState"] == "paused"
    assert "drift threshold" in auto_paused["pauseReason"]
    assert events == ["deployment_rollout_auto_paused"]

    rolled_back = _invoke(
        module,
        _event(
            "/enterprise/deployment-config/rollback",
            "POST",
            body={
                "deploymentId": "deployment-a",
                "targetVersion": 1,
                "expectedRevision": auto_paused["rolloutRevision"],
                "reason": "Restore the exact last known-good managed configuration.",
            },
            claims=claims,
        ),
    )
    assert rolled_back["statusCode"] == 200, rolled_back
    rollback_body = json.loads(rolled_back["body"])
    assert rollback_body["version"] == 3
    # Existing fresh endpoint evidence already matches the retained known-good
    # version, so the server may reconcile the rollback in the same request.
    assert rollback_body["rolloutState"] == "converged"
    assert rollback_body["desiredHash"] == converged["desiredHash"]
    assert rollback_body["rolloutPackageRevision"] == 1
    package_payload = module._agent_managed_package(
        tenant,
        "deployment-a",
        agent_ids[0],
        table.items[(f"TENANT#{tenant}", f"AGENT#deployment-a:{agent_ids[0]}")],
    )
    assert package_payload["revision"] == 1
    restored = configuration()
    assert restored["rolloutState"] == "converged"
    assert restored["version"] == 3
    assert restored["convergence"]["fullConverged"] is True


def test_managed_rollout_schedule_and_unsafe_transitions_fail_closed(monkeypatch: Any) -> None:
    """Malformed windows, canary expansion and browser convergence claims are denied."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-rollout-denial"
    now = 2_240_000_000
    monkeypatch.setattr(module.time, "time", lambda: now)
    package, desired = _managed_package_fixture()
    table.put_item(Item=module._item_key(tenant, "TENANT", "root") | {"id": tenant})
    table.put_item(Item=module._item_key(tenant, "DEPLOYMENT", "dep-a") | {"id": "dep-a"})
    table.put_item(
        Item=module._item_key(tenant, "AGENT", "dep-a:agent-a")
        | {
            "id": "agent-a",
            "deployment_id": "dep-a",
            "host": "claude-code",
            "status": "connected",
            "expires_at": now + 3_600,
            "lifecycle_state": "active",
            "lifecycle_revision": 1,
        }
    )
    claims = {
        "custom:tenant_id": tenant,
        "cognito:groups": ["platform-admin"],
        "sub": "admin-a",
    }
    assert (
        _invoke(
            module,
            _event(
                "/enterprise/templates",
                "POST",
                body={
                    "templateId": "template-a",
                    "name": "Template A",
                    "configuration": {"managedHost": desired},
                },
                claims=claims,
            ),
        )["statusCode"]
        == 201
    )
    staged = json.loads(
        _invoke(
            module,
            _event(
                "/enterprise/deployment-config",
                "POST",
                body={"deploymentId": "dep-a", "templateId": "template-a"},
                claims=claims,
            ),
        )["body"]
    )
    publish = _invoke(
        module,
        _event(
            "/enterprise/deployments/dep-a/managed-package",
            "PUT",
            body={
                "expectedRevision": 0,
                "packageBase64": base64.b64encode(package.to_json()).decode(),
                "packageSha256": package.package_sha256,
            },
            claims=claims,
        ),
    )
    assert publish["statusCode"] == 201
    base = {
        "deploymentIds": ["dep-a"],
        "expectedRevisions": {"dep-a": staged["rolloutRevision"]},
        "targetState": "canary",
        "percentage": 10,
        "channel": "stable",
        "ring": "canary",
        "reason": "Schedule a bounded synthetic canary during its maintenance window.",
        "healthCriteria": {
            "maxUnavailablePercent": 10,
            "maxDriftPercent": 10,
            "minSampleSize": 1,
            "gracePeriodSeconds": 300,
        },
        "schedule": {
            "notBefore": now + 600,
            "deadline": now + 3_600,
            "timeZone": "Europe/London",
        },
    }
    rollout_schedule = cast(dict[str, Any], base["schedule"])
    invalid_zone = _invoke(
        module,
        _event(
            "/enterprise/deployment-config/batch-rollout",
            "POST",
            body={**base, "schedule": {**rollout_schedule, "timeZone": "Not/AZone"}},
            claims=claims,
        ),
    )
    assert invalid_zone["statusCode"] == 400
    oversized_canary = _invoke(
        module,
        _event(
            "/enterprise/deployment-config/batch-rollout",
            "POST",
            body={**base, "percentage": 50},
            claims=claims,
        ),
    )
    assert oversized_canary["statusCode"] == 400
    forged = _invoke(
        module,
        _event(
            "/enterprise/deployment-config/batch-rollout",
            "POST",
            body={**base, "appliedHash": staged["desiredHash"]},
            claims=claims,
        ),
    )
    assert forged["statusCode"] == 400
    scheduled = _invoke(
        module,
        _event(
            "/enterprise/deployment-config/batch-rollout",
            "POST",
            body=base,
            claims=claims,
        ),
    )
    assert scheduled["statusCode"] == 200, scheduled
    scheduled_body = json.loads(scheduled["body"])["items"][0]
    assert scheduled_body["rolloutState"] == "scheduled"
    assert scheduled_body["appliedHash"] is None
    decreasing = _invoke(
        module,
        _event(
            "/enterprise/deployment-config/batch-rollout",
            "POST",
            body={
                **base,
                "expectedRevisions": {"dep-a": scheduled_body["rolloutRevision"]},
                "percentage": 5,
            },
            claims=claims,
        ),
    )
    assert decreasing["statusCode"] == 409


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
    retained_request = table.items[(f"TENANT#{tenant}", "APPROVAL#approval-pending-a")]
    assert retained_request["behavior_pk"] == f"TENANT#{tenant}#AGENT#{agent_key}"
    assert retained_request["behavior_kind"] == "approval"
    assert retained_request["behavior_sk"].endswith("#approval#approval-pending-a")
    assert retained_request["ttl"] == (
        retained_request["requested_at"] + module._BEHAVIOR_OBSERVATION_RETENTION_SECONDS
    )
    assert retained_request["expires_at"] < retained_request["ttl"]
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
    approved_record = table.items[(f"TENANT#{tenant}", "APPROVAL#approval-pending-a")]
    assert approved_record["ttl"] == (
        approved_record["requested_at"] + module._BEHAVIOR_OBSERVATION_RETENTION_SECONDS
    )
    assert approved_record["expires_at"] < approved_record["ttl"]
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


def test_demo_seed_migrates_legacy_organization_into_the_schedule_index(
    monkeypatch: Any,
) -> None:
    """A legacy provisioned demo tenant must not strand asynchronous jobs."""
    module, table = _load_handler(monkeypatch)
    tenant = "tenant-demo"
    module._put(
        tenant,
        "ORG",
        "org-demo",
        {"id": "org-demo", "name": "Example enterprise", "created_at": 1},
    )
    monkeypatch.setattr(module, "_EVIDENCE_RETENTION_CUTOVER_SECONDS", 0)
    job = module._create_retention_job(
        tenant,
        {
            "requestId": "legacy-schedule-recovery",
            "expectedRevision": 0,
            "retentionDays": 730,
            "rationale": "Approved synthetic legacy schedule recovery exercise.",
        },
        "security-operator",
    )

    module._seed(tenant)
    module._seed(tenant)

    root = table.items[(f"TENANT#{tenant}", "TENANT#root")]
    expected_partition, expected_sort_key = module._evidence_assurance_registration(tenant)
    assert root["status"] == "active"
    assert root["evidence_assurance_pk"] == expected_partition
    assert root["evidence_assurance_sk"] == expected_sort_key
    scheduled = module._evidence_retention_schedule_cycle()
    assert scheduled == {"processedTenants": 1, "dispatchedJobs": 1, "activeJobs": 0}
    message = json.loads(module._fake_sqs.messages[-1]["MessageBody"])
    assert message == {
        "schemaVersion": 1,
        "tenantId": tenant,
        "jobId": job["id"],
        "expectedRevision": 1,
    }


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

    first_page_key = (
        f"TENANT#{tenant}",
        "DISCOVERY_PAGE#github:github-page-set-1:00000",
    )
    first_page_record = table.items[first_page_key]
    assert first_page_record["pageStorage"] == "s3_versioned_v1"
    assert "observations" not in first_page_record
    assert first_page_record["pageObjectKey"].startswith(
        f"tenant={hashlib.sha256(tenant.encode()).hexdigest()}/"
    )
    first_page_object = module.S3.objects[
        (first_page_record["pageObjectKey"], first_page_record["pageObjectVersionId"])
    ]
    assert (
        hashlib.sha256(first_page_object["Body"]).hexdigest()
        == first_page_record["pageObjectSha256"]
    )

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
    original_page_body = first_page_object["Body"]
    first_page_object["Body"] = original_page_body + b" "
    tampered_commit = _invoke(
        module,
        _event(
            f"{base}/github-page-set-1/commit",
            "POST",
            body={"pageHashes": page_hashes},
            token=token,
        ),
    )
    assert tampered_commit["statusCode"] == 400
    first_page_object["Body"] = original_page_body
    original_page_key = first_page_record["pageObjectKey"]
    first_page_record["pageObjectKey"] = original_page_key.replace(
        hashlib.sha256(tenant.encode()).hexdigest(),
        hashlib.sha256(b"other-tenant").hexdigest(),
    )
    cross_tenant_commit = _invoke(
        module,
        _event(
            f"{base}/github-page-set-1/commit",
            "POST",
            body={"pageHashes": page_hashes},
            token=token,
        ),
    )
    assert cross_tenant_commit["statusCode"] == 400
    first_page_record["pageObjectKey"] = original_page_key
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
    committed_record = table.items[generation_key]
    assert committed_record["baselineObjectKey"].startswith("tenant=")
    assert committed_record["baselineObjectVersionId"].startswith("version-")
    assert re.fullmatch(r"[0-9a-f]{64}", committed_record["baselineObjectSha256"])
    object_key = committed_record["baselineObjectKey"]
    object_version = committed_record["baselineObjectVersionId"]
    stored_baseline = module.S3.objects[(object_key, object_version)]
    assert b"/synthetic/repository" not in stored_baseline["Body"]
    _record, repositories = module._verified_repository_generation(
        tenant, "github", "github-page-set-1"
    )
    assert sorted(repositories) == ["repository-a", "repository-b"]
    before_cached_reads = len(module.S3.get_requests)
    cache: dict[tuple[str, str, str], Any] = {}
    module._verified_repository_generation(tenant, "github", "github-page-set-1", cache=cache)
    module._verified_repository_generation(tenant, "github", "github-page-set-1", cache=cache)
    assert len(module.S3.get_requests) == before_cached_reads + 1
    original_body = stored_baseline["Body"]
    stored_baseline["Body"] = original_body + b" "
    with pytest.raises(ValueError, match="object digest"):
        module._verified_repository_generation(tenant, "github", "github-page-set-1")
    stored_baseline["Body"] = original_body
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
