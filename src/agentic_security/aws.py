"""AWS reference adapters for production control-plane deployments.

The core SDK intentionally has no cloud dependency.  This module keeps the
AWS implementation behind an optional adapter boundary so an application can
use DynamoDB for atomic, multi-process idempotency without changing the
provider-neutral runtime contracts.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from .credentials import ScopedCredential
from .idempotency import (
    IdempotencyClaim,
    IdempotencyClaimStatus,
    IdempotencyGCReport,
    IdempotencyRecord,
    IdempotencyState,
)
from .types import (
    ExecutionResult,
    ExecutionStatus,
    ReconciliationState,
    SideEffectState,
    TimeoutPhase,
)


def _iso(value: datetime) -> str:
    """Serialize an aware timestamp in a lexically sortable format."""
    return value.astimezone(UTC).isoformat()


def _parse_timestamp(value: str) -> datetime:
    """Parse a timestamp emitted by :func:`_iso`."""
    return datetime.fromisoformat(value).astimezone(UTC)


def _safe_result(value: Any) -> Any:
    """Accept only JSON-compatible terminal results before persistence."""
    if isinstance(value, ExecutionResult):
        return {
            "__agentic_security_type__": "ExecutionResult",
            "status": value.status.value,
            "tool_name": value.tool_name,
            "request_id": value.request_id,
            "reason": value.reason,
            "output": _safe_result(value.output),
            "approval_id": value.approval_id,
            "audit_recorded": value.audit_recorded,
            "idempotency_recorded": value.idempotency_recorded,
            "reconciliation_state": (
                None if value.reconciliation_state is None else value.reconciliation_state.value
            ),
            "timeout_phase": None if value.timeout_phase is None else value.timeout_phase.value,
            "handler_started": value.handler_started,
            "side_effect_state": value.side_effect_state.value,
        }
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _restore_result(value: Any) -> Any:
    """Rehydrate the runtime's typed terminal result after a JSON round trip."""
    if (
        not isinstance(value, Mapping)
        or value.get("__agentic_security_type__") != "ExecutionResult"
    ):
        return value
    return ExecutionResult(
        status=ExecutionStatus(str(value["status"])),
        tool_name=str(value["tool_name"]),
        request_id=str(value["request_id"]),
        reason=value.get("reason"),
        output=_restore_result(value.get("output")),
        approval_id=value.get("approval_id"),
        audit_recorded=bool(value.get("audit_recorded", True)),
        idempotency_recorded=bool(value.get("idempotency_recorded", True)),
        reconciliation_state=(
            None
            if value.get("reconciliation_state") is None
            else ReconciliationState(str(value["reconciliation_state"]))
        ),
        timeout_phase=(
            None
            if value.get("timeout_phase") is None
            else TimeoutPhase(str(value["timeout_phase"]))
        ),
        handler_started=bool(value.get("handler_started", False)),
        side_effect_state=SideEffectState(str(value.get("side_effect_state", "not_started"))),
    )


class DynamoDbIdempotencyStore:
    """Atomic, restart-safe idempotency store backed by a DynamoDB table.

    The supplied table must have a string partition key named ``pk`` and a
    TTL attribute named ``ttl`` configured by the deployment.  Claim uses a
    conditional put, while terminal updates are conditional on the existing
    operation identity.  A conditional failure is always reconciled by a
    read; a caller never treats an unknown write outcome as a new claim.

    ``table`` is injected rather than imported from boto3 so the SDK remains
    dependency-free and deployments can provide a configured resource client.
    """

    def __init__(self, table: Any, *, now: Any | None = None) -> None:
        """Create an adapter around a boto3 Table-compatible object."""
        self._table = table
        self._now = now or (lambda: datetime.now(UTC))

    @staticmethod
    def _item(record: IdempotencyRecord) -> dict[str, Any]:
        """Convert a typed record into a bounded DynamoDB item."""
        item: dict[str, Any] = {
            "pk": record.operation_key,
            "action_fingerprint": record.action_fingerprint,
            "tenant": record.tenant,
            "principal_id": record.principal_id,
            "tool_name": record.tool_name,
            "resource_ids": list(record.resource_ids),
            "state": record.state.value,
            "result": _safe_result(record.result),
            "created_at": _iso(record.created_at),
        }
        if record.expires_at is not None:
            item["expires_at"] = _iso(record.expires_at)
            # DynamoDB TTL is epoch seconds.  It is only a storage hint; the
            # adapter still evaluates expiry itself before accepting claims.
            item["ttl"] = int(record.expires_at.timestamp())
        return item

    @staticmethod
    def _record(item: Mapping[str, Any]) -> IdempotencyRecord:
        """Convert a DynamoDB item into the public record type."""
        expires = item.get("expires_at")
        return IdempotencyRecord(
            operation_key=str(item["pk"]),
            action_fingerprint=str(item["action_fingerprint"]),
            tenant=str(item["tenant"]),
            principal_id=str(item["principal_id"]),
            tool_name=str(item["tool_name"]),
            resource_ids=tuple(str(value) for value in item.get("resource_ids", [])),
            state=IdempotencyState(str(item["state"])),
            result=_restore_result(item.get("result")),
            created_at=_parse_timestamp(str(item["created_at"])),
            expires_at=None if expires is None else _parse_timestamp(str(expires)),
        )

    @staticmethod
    def _conditional_failure(error: Exception) -> bool:
        """Recognize boto conditional failures without importing boto3."""
        response = getattr(error, "response", None)
        return isinstance(response, Mapping) and response.get("Error", {}).get("Code") == (
            "ConditionalCheckFailedException"
        )

    def _get(self, operation_key: str) -> IdempotencyRecord | None:
        """Read one record, returning ``None`` only for a missing item."""
        response = self._table.get_item(Key={"pk": operation_key}, ConsistentRead=True)
        item = response.get("Item")
        return None if item is None else self._record(item)

    def claim(self, record: IdempotencyRecord) -> IdempotencyClaim:
        """Atomically claim a key and reconcile races or prior outcomes."""
        if not record.operation_key.strip():
            raise ValueError("operation key is required")
        item = self._item(record)
        try:
            self._table.put_item(Item=item, ConditionExpression="attribute_not_exists(pk)")
            return IdempotencyClaim(IdempotencyClaimStatus.CLAIMED, record)
        except Exception as error:
            if not self._conditional_failure(error):
                raise
        existing = self._get(record.operation_key)
        if existing is None:
            # The conditional write may have raced with a deletion.  Do not
            # guess whether the first write committed; retry through claim.
            return self.claim(record)
        if (
            existing.expires_at is not None
            and existing.expires_at <= self._now()
            and existing.state is IdempotencyState.COMPLETED
        ):
            try:
                self._table.put_item(
                    Item=item,
                    ConditionExpression="#state = :completed AND #expires_at <= :now",
                    ExpressionAttributeNames={"#state": "state", "#expires_at": "expires_at"},
                    ExpressionAttributeValues={
                        ":completed": IdempotencyState.COMPLETED.value,
                        ":now": _iso(self._now()),
                    },
                )
                return IdempotencyClaim(IdempotencyClaimStatus.CLAIMED, record)
            except Exception as error:
                if not self._conditional_failure(error):
                    raise
                existing = self._get(record.operation_key) or existing
                if existing.state is IdempotencyState.COMPLETED and (
                    existing.expires_at is None or existing.expires_at <= self._now()
                ):
                    return IdempotencyClaim(IdempotencyClaimStatus.EXPIRED, existing)
        identity = (
            existing.action_fingerprint,
            existing.tenant,
            existing.principal_id,
            existing.tool_name,
            existing.resource_ids,
        )
        requested = (
            record.action_fingerprint,
            record.tenant,
            record.principal_id,
            record.tool_name,
            record.resource_ids,
        )
        status = (
            IdempotencyClaimStatus.CONFLICT
            if identity != requested
            else IdempotencyClaimStatus.EXISTING
        )
        return IdempotencyClaim(status, existing)

    def lookup(self, operation_key: str) -> IdempotencyRecord | None:
        """Read an operation consistently without creating state."""
        record = self._get(operation_key)
        if (
            record is not None
            and record.state is IdempotencyState.COMPLETED
            and record.expires_at is not None
            and record.expires_at <= self._now()
        ):
            return None
        return record

    def _update(
        self, operation_key: str, state: IdempotencyState, result: Any
    ) -> IdempotencyRecord:
        """Conditionally persist a terminal state and return the new record."""
        current = self._get(operation_key)
        if current is None:
            raise KeyError("operation key was not claimed")
        updated = IdempotencyRecord(
            operation_key=current.operation_key,
            action_fingerprint=current.action_fingerprint,
            tenant=current.tenant,
            principal_id=current.principal_id,
            tool_name=current.tool_name,
            resource_ids=current.resource_ids,
            state=state,
            result=_safe_result(result),
            created_at=current.created_at,
            expires_at=current.expires_at,
        )
        self._table.put_item(
            Item=self._item(updated),
            ConditionExpression="attribute_exists(pk) AND #fingerprint = :fingerprint",
            ExpressionAttributeNames={"#fingerprint": "action_fingerprint"},
            ExpressionAttributeValues={":fingerprint": current.action_fingerprint},
        )
        return updated

    def complete(self, operation_key: str, result: Any) -> IdempotencyRecord:
        """Persist a successful terminal result."""
        return self._update(operation_key, IdempotencyState.COMPLETED, result)

    def mark_uncertain(self, operation_key: str, result: Any) -> IdempotencyRecord:
        """Persist an outcome that requires reconciliation before retry."""
        return self._update(operation_key, IdempotencyState.UNCERTAIN, result)

    def gc(self, now: datetime | None = None) -> IdempotencyGCReport:
        """Remove only expired completed records; retain uncertain records."""
        at = now or self._now()
        response = self._table.scan(ConsistentRead=True)
        records = tuple(self._record(item) for item in response.get("Items", []))
        removed = 0
        retained = 0
        for record in records:
            if (
                record.state is IdempotencyState.COMPLETED
                and record.expires_at is not None
                and record.expires_at <= at
            ):
                self._table.delete_item(
                    Key={"pk": record.operation_key},
                    ConditionExpression="#state = :completed AND #expires_at <= :now",
                    ExpressionAttributeNames={"#state": "state", "#expires_at": "expires_at"},
                    ExpressionAttributeValues={
                        ":completed": IdempotencyState.COMPLETED.value,
                        ":now": _iso(at),
                    },
                )
                removed += 1
            else:
                retained += 1
        return IdempotencyGCReport(len(records), removed, retained, at)


@dataclass(frozen=True, slots=True)
class AwsScopePolicy:
    """Typed IAM session policy bound to one live tool and resource set.

    The deployment supplies the policy builder.  The model cannot supply or
    widen this object: :class:`AwsStsCredentialBroker` compares its typed
    binding with the runtime request before calling STS.  The base IAM role
    remains an independent deployment control and must be no broader than the
    provider permissions the application intends to grant.
    """

    tool_name: str
    resources: tuple[str, ...]
    document: Mapping[str, Any]

    def __post_init__(self) -> None:
        """Reject empty or non-JSON IAM policy documents."""
        if not self.tool_name.strip() or any(not resource.strip() for resource in self.resources):
            raise ValueError("AWS scope policy identity and resources are required")
        if not isinstance(self.document, Mapping):
            raise ValueError("AWS scope policy document must be a mapping")
        if self.document.get("Version") != "2012-10-17" or not isinstance(
            self.document.get("Statement"), list
        ):
            raise ValueError("AWS scope policy must contain a Version and Statement list")
        json.dumps(self.document, sort_keys=True, separators=(",", ":"))


class AwsStsCredentialBroker:
    """Mint short-lived AWS session credentials under an exact IAM scope.

    ``sts_client`` is a boto3 STS-compatible object injected by the
    deployment.  STS intersects the inline session policy with the trusted
    role policy; it never expands the role.  The returned credential stores
    serialized temporary material behind :meth:`ScopedCredential.with_secret`
    and never exposes it as a public attribute.
    """

    def __init__(self, sts_client: Any, role_arn: str, policy_builder: Any) -> None:
        """Create a broker with an explicit role and trusted policy builder."""
        if not role_arn.startswith("arn:"):
            raise ValueError("AWS role ARN is required")
        self._sts = sts_client
        self._role_arn = role_arn
        self._policy_builder = policy_builder

    def mint(
        self, context: Any, tool: Any, resources: tuple[Any, ...], ttl_seconds: int
    ) -> ScopedCredential:
        """Assume the role only after the policy binding matches the request."""
        if ttl_seconds <= 0:
            raise ValueError("credential TTL must be positive")
        resource_ids = tuple(str(getattr(resource, "id", resource)) for resource in resources)
        scope = self._policy_builder(tool.name, resource_ids)
        if (
            not isinstance(scope, AwsScopePolicy)
            or scope.tool_name != tool.name
            or scope.resources != resource_ids
        ):
            raise ValueError("AWS policy builder returned an invalid scope binding")
        duration = min(max(ttl_seconds, 900), 3600)
        session_name = "aai-" + sha256(f"{context.task_id}:{tool.name}".encode()).hexdigest()[:24]
        response = self._sts.assume_role(
            RoleArn=self._role_arn,
            RoleSessionName=session_name,
            DurationSeconds=duration,
            Policy=json.dumps(scope.document, sort_keys=True, separators=(",", ":")),
        )
        credentials = response.get("Credentials", {})
        required = ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration")
        if any(not credentials.get(field) for field in required):
            raise ValueError("STS returned incomplete temporary credentials")
        expires_at = credentials["Expiration"]
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if not isinstance(expires_at, datetime) or expires_at.tzinfo is None:
            raise ValueError("STS returned an invalid credential expiry")
        value = json.dumps(
            {
                "access_key_id": credentials["AccessKeyId"],
                "secret_access_key": credentials["SecretAccessKey"],
                "session_token": credentials["SessionToken"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        issued_at = datetime.now(UTC)

        def provider(serialized: str = value) -> str:
            return serialized

        return ScopedCredential(
            credential_id=f"aws:{context.task_id}:{session_name}",
            tool_name=tool.name,
            resources=resources,
            issued_at=issued_at,
            expires_at=min(issued_at + timedelta(seconds=ttl_seconds), expires_at),
            _secret_provider=provider,
        )


__all__ = ["AwsScopePolicy", "AwsStsCredentialBroker", "DynamoDbIdempotencyStore"]
