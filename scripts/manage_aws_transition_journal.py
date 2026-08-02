#!/usr/bin/env python3
"""Manage a single-writer AWS regional-transition witness journal.

The journal lives in a third AWS Region and is deliberately not a Global
Table. Strongly consistent reads plus conditional DynamoDB transactions provide
the compare-and-swap boundary that replicated last-writer-wins state cannot.
This module never changes compute, identity, signing, jobs, or routing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from scripts import verify_aws_regional_activation as activation


class TransitionJournalError(RuntimeError):
    """Report malformed, stale, concurrent, or unavailable journal authority."""


_AUTHORITY_KEY = {"pk": {"S": "AUTHORITY"}, "sk": {"S": "CURRENT"}}
_STABLE_FIELDS = {
    "pk",
    "sk",
    "schemaVersion",
    "generation",
    "activeRegion",
    "phase",
    "revision",
    "updatedAt",
    "lastCompletedTransitionId",
}
_ACTIVE_FIELDS = _STABLE_FIELDS | {
    "activeTransitionId",
    "direction",
    "sourceRegion",
    "targetRegion",
    "authoritySha256",
    "evidenceSha256",
    "approvalSha256",
    "expiresAt",
}
_PHASES = {
    "STABLE",
    "FENCING_SOURCE",
    "SOURCE_FENCED",
    "ACTIVATING_TARGET",
    "TARGET_ACTIVE_NOT_ROUTED",
    "RECONCILING_TARGET_JOBS",
    "TARGET_JOBS_RECONCILED_NOT_ROUTED",
}
_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


@dataclass(frozen=True)
class JournalState:
    """Validated current transition authority read from the witness Region."""

    generation: int
    active_region: str
    phase: str
    revision: int
    updated_at: int
    last_completed_transition_id: str
    active_transition_id: str | None = None
    direction: str | None = None
    source_region: str | None = None
    target_region: str | None = None
    authority_sha256: str | None = None
    evidence_sha256: str | None = None
    approval_sha256: str | None = None
    expires_at: int | None = None

    def evidence(self) -> dict[str, Any]:
        """Return a content-minimised operator view without approval references."""
        return {
            "activeRegion": self.active_region,
            "activeTransitionId": self.active_transition_id,
            "generation": self.generation,
            "phase": self.phase,
            "revision": self.revision,
            "updatedAt": self.updated_at,
        }


def approval_sha256(manifest: activation.ActivationManifest) -> str:
    """Bind the exact two-person approval set without storing evidence content."""
    return manifest.approval_sha256()


def _decode_attribute(value: object) -> Any:
    """Decode the small exact DynamoDB attribute subset used by the journal."""
    if not isinstance(value, dict) or len(value) != 1:
        raise TransitionJournalError("journal attribute is malformed")
    kind, payload = next(iter(value.items()))
    if kind == "S" and isinstance(payload, str):
        return payload
    if kind == "N" and isinstance(payload, str):
        try:
            number = Decimal(payload)
        except InvalidOperation as error:
            raise TransitionJournalError("journal number is malformed") from error
        if number != number.to_integral_value():
            raise TransitionJournalError("journal number must be integral")
        return int(number)
    raise TransitionJournalError("journal attribute type is unsupported")


def _decode_item(item: object) -> dict[str, Any]:
    """Decode one bounded journal item and reject duplicate semantic fields."""
    if not isinstance(item, dict) or not 1 <= len(item) <= 32:
        raise TransitionJournalError("journal item is missing or oversized")
    return {str(key): _decode_attribute(value) for key, value in item.items()}


def _bounded_integer(value: object, label: str, *, maximum: int = 2**63 - 1) -> int:
    """Return a non-negative bounded integer without accepting booleans."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise TransitionJournalError(f"journal {label} is malformed")
    return value


def _parse_state(item: object) -> JournalState:
    """Validate exact stable or in-progress journal state."""
    value = _decode_item(item)
    phase = value.get("phase")
    fields = _STABLE_FIELDS if phase == "STABLE" else _ACTIVE_FIELDS
    if set(value) != fields or value.get("pk") != "AUTHORITY" or value.get("sk") != "CURRENT":
        raise TransitionJournalError("journal authority fields are malformed")
    if value.get("schemaVersion") != 1 or phase not in _PHASES:
        raise TransitionJournalError("journal schema or phase is unsupported")
    active_region = value.get("activeRegion")
    if not isinstance(active_region, str) or not _REGION.fullmatch(active_region):
        raise TransitionJournalError("journal active Region is malformed")
    generation = _bounded_integer(value.get("generation"), "generation")
    revision = _bounded_integer(value.get("revision"), "revision")
    updated_at = _bounded_integer(value.get("updatedAt"), "updatedAt", maximum=4_102_444_800)
    last = value.get("lastCompletedTransitionId")
    if not isinstance(last, str) or (last and not _UUID.fullmatch(last)):
        raise TransitionJournalError("journal completed transition identity is malformed")
    if phase == "STABLE":
        return JournalState(generation, active_region, phase, revision, updated_at, last)
    transition = value.get("activeTransitionId")
    direction = value.get("direction")
    source = value.get("sourceRegion")
    target = value.get("targetRegion")
    authority_digest = value.get("authoritySha256")
    evidence_digest = value.get("evidenceSha256")
    approval_digest = value.get("approvalSha256")
    expires = _bounded_integer(value.get("expiresAt"), "expiresAt", maximum=4_102_444_800)
    if (
        not isinstance(transition, str)
        or not _UUID.fullmatch(transition)
        or direction not in {"failover", "failback"}
        or not isinstance(source, str)
        or not _REGION.fullmatch(source)
        or not isinstance(target, str)
        or not _REGION.fullmatch(target)
        or source == target
        or not isinstance(authority_digest, str)
        or not _SHA256.fullmatch(authority_digest)
        or not isinstance(evidence_digest, str)
        or not _SHA256.fullmatch(evidence_digest)
        or not isinstance(approval_digest, str)
        or not _SHA256.fullmatch(approval_digest)
    ):
        raise TransitionJournalError("active journal authority is malformed")
    return JournalState(
        generation,
        active_region,
        phase,
        revision,
        updated_at,
        last,
        transition,
        direction,
        source,
        target,
        authority_digest,
        evidence_digest,
        approval_digest,
        expires,
    )


def verify_table_posture(
    client: Any,
    manifest: activation.ActivationManifest,
) -> dict[str, Any]:
    """Require one protected, encrypted, single-Region witness table with PITR."""
    manifest.require_journal_authority()
    try:
        response = client.describe_table(TableName=manifest.journal_table_name)
        backups = client.describe_continuous_backups(TableName=manifest.journal_table_name)
    except Exception as error:
        raise TransitionJournalError("transition witness table is unavailable") from error
    table = response.get("Table")
    if not isinstance(table, dict):
        raise TransitionJournalError("transition witness table description is malformed")
    arn = table.get("TableArn")
    expected_keys = [
        {"AttributeName": "pk", "KeyType": "HASH"},
        {"AttributeName": "sk", "KeyType": "RANGE"},
    ]
    if (
        table.get("TableName") != manifest.journal_table_name
        or table.get("TableStatus") != "ACTIVE"
        or table.get("DeletionProtectionEnabled") is not True
        or table.get("BillingModeSummary", {}).get("BillingMode") != "PAY_PER_REQUEST"
        or table.get("KeySchema") != expected_keys
        or table.get("SSEDescription", {}).get("Status") != "ENABLED"
        or table.get("Replicas") not in (None, [])
        or not isinstance(arn, str)
        or f":dynamodb:{manifest.coordination_region}:" not in arn
    ):
        raise TransitionJournalError("transition witness table posture is unsafe")
    point_in_time = backups.get("ContinuousBackupsDescription", {}).get(
        "PointInTimeRecoveryDescription", {}
    )
    if point_in_time.get("PointInTimeRecoveryStatus") != "ENABLED":
        raise TransitionJournalError("transition witness point-in-time recovery is disabled")
    return {
        "coordinationRegion": manifest.coordination_region,
        "journalTableArn": arn,
        "status": "verified-single-writer-witness",
    }


def read_state(client: Any, manifest: activation.ActivationManifest) -> JournalState:
    """Read current authority strongly consistently from the witness Region."""
    manifest.require_journal_authority()
    try:
        response = client.get_item(
            TableName=manifest.journal_table_name,
            Key=_AUTHORITY_KEY,
            ConsistentRead=True,
        )
    except Exception as error:
        raise TransitionJournalError("transition journal authority is unavailable") from error
    state = _parse_state(response.get("Item"))
    if state.active_region not in {manifest.primary_region, manifest.recovery_region}:
        raise TransitionJournalError("journal active Region is outside reviewed authority")
    return state


def initialize_state(
    client: Any, manifest: activation.ActivationManifest, *, now: int
) -> dict[str, Any]:
    """Create generation-zero primary authority exactly once with two approvals."""
    manifest.require_journal_authority()
    if (
        manifest.direction != "failover"
        or manifest.source_region != manifest.primary_region
        or manifest.expected_routing_generation != 0
        or now >= manifest.expires_at
    ):
        raise TransitionJournalError(
            "journal initialization requires live generation-zero failover authority"
        )
    authority = {
        **_AUTHORITY_KEY,
        "schemaVersion": {"N": "1"},
        "generation": {"N": "0"},
        "activeRegion": {"S": manifest.primary_region},
        "phase": {"S": "STABLE"},
        "revision": {"N": "0"},
        "updatedAt": {"N": str(now)},
        "lastCompletedTransitionId": {"S": ""},
    }
    event = _event_item(manifest, phase="JOURNAL_INITIALIZED", revision=0, now=now)
    _transact(
        client,
        [
            {
                "Put": {
                    "TableName": manifest.journal_table_name,
                    "Item": authority,
                    "ConditionExpression": "attribute_not_exists(pk) AND attribute_not_exists(sk)",
                }
            },
            {
                "Put": {
                    "TableName": manifest.journal_table_name,
                    "Item": event,
                    "ConditionExpression": "attribute_not_exists(pk) AND attribute_not_exists(sk)",
                }
            },
        ],
    )
    state = read_state(client, manifest)
    if (
        state.phase != "STABLE"
        or state.generation != 0
        or state.active_region != manifest.primary_region
    ):
        raise TransitionJournalError("initialized journal authority did not converge")
    return {"claim": "initialized", "journal": state.evidence()}


def _value_map(manifest: activation.ActivationManifest, now: int) -> dict[str, Any]:
    """Return exact low-level DynamoDB values for one transition authority."""
    return {
        ":approval": {"S": approval_sha256(manifest)},
        ":authority": {"S": manifest.authority_sha256()},
        ":direction": {"S": manifest.direction},
        ":evidence": {"S": manifest.evidence.sha256},
        ":expires": {"N": str(manifest.expires_at)},
        ":generation": {"N": str(manifest.expected_routing_generation)},
        ":now": {"N": str(now)},
        ":one": {"N": "1"},
        ":source": {"S": manifest.source_region},
        ":target": {"S": manifest.target_region},
        ":transition": {"S": manifest.transition_id},
    }


def _event_item(
    manifest: activation.ActivationManifest,
    *,
    phase: str,
    revision: int,
    now: int,
    step_evidence_sha256: str | None = None,
) -> dict[str, Any]:
    """Build one append-only content-addressed transition event."""
    if step_evidence_sha256 is not None and not _SHA256.fullmatch(step_evidence_sha256):
        raise TransitionJournalError("step evidence SHA-256 is malformed")
    event = {
        "pk": {"S": f"TRANSITION#{manifest.transition_id}"},
        "sk": {"S": f"EVENT#{revision:010d}#{phase}"},
        "schemaVersion": {"N": "1"},
        "phase": {"S": phase},
        "revision": {"N": str(revision)},
        "occurredAt": {"N": str(now)},
        "direction": {"S": manifest.direction},
        "sourceRegion": {"S": manifest.source_region},
        "targetRegion": {"S": manifest.target_region},
        "authoritySha256": {"S": manifest.authority_sha256()},
        "evidenceSha256": {"S": manifest.evidence.sha256},
        "approvalSha256": {"S": approval_sha256(manifest)},
    }
    if step_evidence_sha256 is not None:
        event["stepEvidenceSha256"] = {"S": step_evidence_sha256}
    return event


def _verify_completed_step_evidence(
    client: Any,
    manifest: activation.ActivationManifest,
    *,
    phase: str,
    revision: int,
    expected_sha256: str,
) -> None:
    """Bind an idempotent retry to the exact evidence recorded at completion."""
    try:
        response = client.get_item(
            TableName=manifest.journal_table_name,
            Key={
                "pk": {"S": f"TRANSITION#{manifest.transition_id}"},
                "sk": {"S": f"EVENT#{revision:010d}#{phase}"},
            },
            ConsistentRead=True,
        )
    except Exception as error:
        raise TransitionJournalError("completed transition evidence is unavailable") from error
    event = _decode_item(response.get("Item"))
    if (
        set(event)
        != {
            "pk",
            "sk",
            "schemaVersion",
            "phase",
            "revision",
            "occurredAt",
            "direction",
            "sourceRegion",
            "targetRegion",
            "authoritySha256",
            "evidenceSha256",
            "approvalSha256",
            "stepEvidenceSha256",
        }
        or event.get("pk") != f"TRANSITION#{manifest.transition_id}"
        or event.get("sk") != f"EVENT#{revision:010d}#{phase}"
        or event.get("schemaVersion") != 1
        or event.get("phase") != phase
        or event.get("revision") != revision
        or event.get("direction") != manifest.direction
        or event.get("sourceRegion") != manifest.source_region
        or event.get("targetRegion") != manifest.target_region
        or event.get("authoritySha256") != manifest.authority_sha256()
        or event.get("evidenceSha256") != manifest.evidence.sha256
        or event.get("approvalSha256") != approval_sha256(manifest)
        or event.get("stepEvidenceSha256") != expected_sha256
    ):
        raise TransitionJournalError("completed transition evidence differs from retry")


def _transact(client: Any, items: list[dict[str, Any]]) -> None:
    """Commit one journal CAS and normalize provider concurrency failures."""
    try:
        client.transact_write_items(TransactItems=items)
    except Exception as error:
        code = getattr(error, "response", {}).get("Error", {}).get("Code")
        if code in {"ConditionalCheckFailedException", "TransactionCanceledException"}:
            raise TransitionJournalError("transition journal changed concurrently") from error
        raise TransitionJournalError("transition journal write failed") from error


def _same_authority(
    state: JournalState, manifest: activation.ActivationManifest, *, now: int
) -> bool:
    """Return whether an in-progress state belongs to this still-live authority."""
    return (
        state.active_transition_id == manifest.transition_id
        and state.direction == manifest.direction
        and state.source_region == manifest.source_region
        and state.target_region == manifest.target_region
        and state.authority_sha256 == manifest.authority_sha256()
        and state.evidence_sha256 == manifest.evidence.sha256
        and state.approval_sha256 == approval_sha256(manifest)
        and state.expires_at == manifest.expires_at
        and now < manifest.expires_at
    )


def claim_source_fence(
    client: Any, manifest: activation.ActivationManifest, *, now: int
) -> dict[str, Any]:
    """CAS stable authority into FENCING_SOURCE or resume the exact same claim."""
    manifest.require_journal_authority()
    state = read_state(client, manifest)
    if state.phase in _PHASES - {"STABLE"}:
        if not _same_authority(state, manifest, now=now):
            raise TransitionJournalError("another transition already owns the journal")
        if state.phase not in {"FENCING_SOURCE", "SOURCE_FENCED"}:
            raise TransitionJournalError("source-fence step is already past its retry boundary")
        return {"claim": "resumed", "journal": state.evidence()}
    if (
        now >= manifest.expires_at
        or state.generation != manifest.expected_routing_generation
        or state.active_region != manifest.source_region
    ):
        raise TransitionJournalError("stale generation or source Region cannot claim transition")
    values = _value_map(manifest, now)
    values.update(
        {
            ":stable": {"S": "STABLE"},
            ":next": {"S": "FENCING_SOURCE"},
            ":revision": {"N": str(state.revision)},
        }
    )
    update = {
        "TableName": manifest.journal_table_name,
        "Key": _AUTHORITY_KEY,
        "UpdateExpression": (
            "SET #phase=:next, revision=revision+:one, updatedAt=:now, "
            "activeTransitionId=:transition, direction=:direction, sourceRegion=:source, "
            "targetRegion=:target, authoritySha256=:authority, evidenceSha256=:evidence, "
            "approvalSha256=:approval, expiresAt=:expires"
        ),
        "ConditionExpression": (
            "#phase=:stable AND revision=:revision AND generation=:generation AND "
            "activeRegion=:source AND attribute_not_exists(activeTransitionId)"
        ),
        "ExpressionAttributeNames": {"#phase": "phase"},
        "ExpressionAttributeValues": values,
    }
    event = _event_item(manifest, phase="FENCING_SOURCE", revision=state.revision + 1, now=now)
    _transact(
        client,
        [
            {"Update": update},
            {
                "Put": {
                    "TableName": manifest.journal_table_name,
                    "Item": event,
                    "ConditionExpression": "attribute_not_exists(pk) AND attribute_not_exists(sk)",
                }
            },
        ],
    )
    claimed = read_state(client, manifest)
    if claimed.phase != "FENCING_SOURCE" or not _same_authority(claimed, manifest, now=now):
        raise TransitionJournalError("source-fence claim did not converge")
    return {"claim": "created", "journal": claimed.evidence()}


def advance_phase(
    client: Any,
    manifest: activation.ActivationManifest,
    *,
    expected_phase: str,
    next_phase: str,
    now: int,
    step_evidence_sha256: str | None = None,
) -> dict[str, Any]:
    """Advance one exact transition phase with revision and authority CAS."""
    allowed = {
        ("FENCING_SOURCE", "SOURCE_FENCED"),
        ("SOURCE_FENCED", "ACTIVATING_TARGET"),
        ("ACTIVATING_TARGET", "TARGET_ACTIVE_NOT_ROUTED"),
        ("TARGET_ACTIVE_NOT_ROUTED", "RECONCILING_TARGET_JOBS"),
        ("RECONCILING_TARGET_JOBS", "TARGET_JOBS_RECONCILED_NOT_ROUTED"),
    }
    if (expected_phase, next_phase) not in allowed:
        raise TransitionJournalError("journal phase transition is unsupported")
    if step_evidence_sha256 is not None and not _SHA256.fullmatch(step_evidence_sha256):
        raise TransitionJournalError("step evidence SHA-256 is malformed")
    state = read_state(client, manifest)
    if not _same_authority(state, manifest, now=now):
        raise TransitionJournalError("journal authority differs or has expired")
    if state.phase == next_phase:
        if step_evidence_sha256 is not None:
            _verify_completed_step_evidence(
                client,
                manifest,
                phase=next_phase,
                revision=state.revision,
                expected_sha256=step_evidence_sha256,
            )
        return {"claim": "already-completed", "journal": state.evidence()}
    if state.phase != expected_phase:
        raise TransitionJournalError("journal phase is stale or out of order")
    values = _value_map(manifest, now)
    values.update(
        {
            ":expected": {"S": expected_phase},
            ":next": {"S": next_phase},
            ":revision": {"N": str(state.revision)},
        }
    )
    update = {
        "TableName": manifest.journal_table_name,
        "Key": _AUTHORITY_KEY,
        "UpdateExpression": "SET #phase=:next, revision=revision+:one, updatedAt=:now",
        "ConditionExpression": (
            "#phase=:expected AND revision=:revision AND generation=:generation AND "
            "activeTransitionId=:transition AND authoritySha256=:authority AND "
            "evidenceSha256=:evidence AND approvalSha256=:approval AND expiresAt=:expires"
        ),
        "ExpressionAttributeNames": {"#phase": "phase"},
        "ExpressionAttributeValues": values,
    }
    event = _event_item(
        manifest,
        phase=next_phase,
        revision=state.revision + 1,
        now=now,
        step_evidence_sha256=step_evidence_sha256,
    )
    _transact(
        client,
        [
            {"Update": update},
            {
                "Put": {
                    "TableName": manifest.journal_table_name,
                    "Item": event,
                    "ConditionExpression": "attribute_not_exists(pk) AND attribute_not_exists(sk)",
                }
            },
        ],
    )
    advanced = read_state(client, manifest)
    if advanced.phase != next_phase or not _same_authority(advanced, manifest, now=now):
        raise TransitionJournalError("journal phase did not converge")
    result = {"claim": "advanced", "journal": advanced.evidence()}
    if step_evidence_sha256 is not None:
        result["stepEvidenceSha256"] = step_evidence_sha256
    return result
