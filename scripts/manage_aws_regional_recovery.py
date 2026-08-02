"""Prepare and verify the durable storage boundary for AWS regional recovery.

This tool intentionally stops short of activating a recovery API. It converts
the four authoritative DynamoDB stores into two-Region Global Tables, proves
bounded replication with synthetic canaries, and persists the reviewed RTO/RPO
manifest only after verification succeeds. It never changes traffic routing,
identity-provider state, active policy signing authority, or audit retention.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4


class RecoveryConfigurationError(RuntimeError):
    """Report recovery input or provider state that cannot prove safe posture."""


Runner = Callable[..., subprocess.CompletedProcess[str]]
Sleeper = Callable[[float], None]
Clock = Callable[[], float]

_MANIFEST_FIELDS = {
    "schemaVersion",
    "stackName",
    "primaryRegion",
    "recoveryRegion",
    "targetFleetSize",
    "rtoMinutes",
    "rpoSeconds",
    "recoveryMode",
    "approvalEvidenceRef",
}
_OUTPUT_TABLES = {
    "control": "ControlTableName",
    "presence": "PresenceTableName",
    "idempotency": "IdempotencyTableName",
    "scim": "ScimLifecycleTableName",
}
_SORT_KEY_TABLES = frozenset({"control", "presence", "scim"})
_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_STACK = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")
_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/+-]{0,127}$")
_EVIDENCE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,511}$")
_TABLE_NAME = re.compile(r"^[A-Za-z0-9_.-]{3,255}$")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON fields before they can create ambiguous authority."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryConfigurationError(f"duplicate recovery field: {key}")
        result[key] = value
    return result


def _bounded_integer(value: object, field: str, minimum: int, maximum: int) -> int:
    """Return one non-boolean bounded integer."""
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RecoveryConfigurationError(f"{field} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class RegionalRecoveryManifest:
    """Reviewed, secret-free authority for one active-passive recovery pair."""

    stack_name: str
    primary_region: str
    recovery_region: str
    target_fleet_size: int
    rto_minutes: int
    rpo_seconds: int
    approval_evidence_ref: str

    @classmethod
    def parse(cls, payload: str) -> RegionalRecoveryManifest:
        """Parse the exact schema-v1 fail-closed active-passive contract."""
        if len(payload.encode("utf-8")) > 16_384:
            raise RecoveryConfigurationError("recovery manifest exceeds 16 KiB")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise RecoveryConfigurationError("recovery manifest is not valid JSON") from error
        if not isinstance(value, dict) or set(value) != _MANIFEST_FIELDS:
            raise RecoveryConfigurationError("recovery manifest fields do not match schema 1")
        if value["schemaVersion"] != 1:
            raise RecoveryConfigurationError("schemaVersion must be 1")
        if value["recoveryMode"] != "fail-closed-active-passive":
            raise RecoveryConfigurationError("recoveryMode must be fail-closed-active-passive")
        stack_name = value["stackName"]
        primary_region = value["primaryRegion"]
        recovery_region = value["recoveryRegion"]
        evidence_ref = value["approvalEvidenceRef"]
        if not isinstance(stack_name, str) or not _STACK.fullmatch(stack_name):
            raise RecoveryConfigurationError("stackName is invalid")
        if (
            not isinstance(primary_region, str)
            or not _REGION.fullmatch(primary_region)
            or not isinstance(recovery_region, str)
            or not _REGION.fullmatch(recovery_region)
            or primary_region == recovery_region
        ):
            raise RecoveryConfigurationError("primary and recovery Regions must be distinct")
        if not isinstance(evidence_ref, str) or not _EVIDENCE_REF.fullmatch(evidence_ref):
            raise RecoveryConfigurationError("approvalEvidenceRef must be a non-secret reference")
        return cls(
            stack_name=stack_name,
            primary_region=primary_region,
            recovery_region=recovery_region,
            target_fleet_size=_bounded_integer(
                value["targetFleetSize"], "targetFleetSize", 100, 1_000_000
            ),
            rto_minutes=_bounded_integer(value["rtoMinutes"], "rtoMinutes", 5, 240),
            rpo_seconds=_bounded_integer(value["rpoSeconds"], "rpoSeconds", 1, 900),
            approval_evidence_ref=evidence_ref,
        )

    def canonical_json(self) -> str:
        """Return deterministic bytes suitable for encrypted Parameter Store."""
        return json.dumps(
            {
                "approvalEvidenceRef": self.approval_evidence_ref,
                "primaryRegion": self.primary_region,
                "recoveryMode": "fail-closed-active-passive",
                "recoveryRegion": self.recovery_region,
                "rpoSeconds": self.rpo_seconds,
                "rtoMinutes": self.rto_minutes,
                "schemaVersion": 1,
                "stackName": self.stack_name,
                "targetFleetSize": self.target_fleet_size,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def parameter_name(stack_name: str) -> str:
    """Return the stack-specific encrypted regional-recovery authority path."""
    if not _STACK.fullmatch(stack_name):
        raise RecoveryConfigurationError("stackName is invalid")
    return f"/aai-sec/{stack_name}/regional-recovery"


def _aws(
    arguments: Sequence[str],
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run one fixed AWS CLI request and decode its bounded JSON response."""
    if not _PROFILE.fullmatch(profile) or not _REGION.fullmatch(region):
        raise RecoveryConfigurationError("AWS profile or Region is malformed")
    result = runner(
        ["aws", *arguments, "--profile", profile, "--region", region, "--output", "json"],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        message = (
            result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "AWS CLI failed"
        )
        raise RecoveryConfigurationError(message[-500:])
    if len(result.stdout.encode("utf-8")) > 2_097_152:
        raise RecoveryConfigurationError("AWS response exceeds 2 MiB")
    try:
        value = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as error:
        raise RecoveryConfigurationError("AWS returned malformed JSON") from error
    if not isinstance(value, dict):
        raise RecoveryConfigurationError("AWS returned an unexpected response")
    return value


def stack_outputs(
    manifest: RegionalRecoveryManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, str]:
    """Load the exact primary resource identities required for replication."""
    response = _aws(
        ["cloudformation", "describe-stacks", "--stack-name", manifest.stack_name],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )
    stacks = response.get("Stacks")
    if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], dict):
        raise RecoveryConfigurationError("expected exactly one primary stack")
    raw_outputs = stacks[0].get("Outputs")
    if not isinstance(raw_outputs, list) or len(raw_outputs) > 100:
        raise RecoveryConfigurationError("primary stack outputs are malformed")
    outputs: dict[str, str] = {}
    for item in raw_outputs:
        if not isinstance(item, dict):
            raise RecoveryConfigurationError("primary stack output is malformed")
        key, value = item.get("OutputKey"), item.get("OutputValue")
        if not isinstance(key, str) or not isinstance(value, str) or key in outputs:
            raise RecoveryConfigurationError("primary stack output identity is ambiguous")
        outputs[key] = value
    required = {
        *_OUTPUT_TABLES.values(),
        "AuditBucketName",
        "AuditReplicaBucketArn",
        "AuditReplicaRegion",
        "RegionalPolicySigningKeyArn",
        "PolicySigningKeyArn",
    }
    if not required.issubset(outputs):
        missing = ", ".join(sorted(required - outputs.keys()))
        raise RecoveryConfigurationError(f"primary stack is missing recovery outputs: {missing}")
    if outputs["AuditReplicaRegion"] != manifest.recovery_region:
        raise RecoveryConfigurationError("audit replica Region does not match recovery authority")
    for output in _OUTPUT_TABLES.values():
        if not _TABLE_NAME.fullmatch(outputs[output]):
            raise RecoveryConfigurationError("stack returned an invalid DynamoDB table name")
    return outputs


def recovery_stack_outputs(
    manifest: RegionalRecoveryManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, str]:
    """Return exact passive-cell outputs without treating absence as readiness."""
    response = _aws(
        [
            "cloudformation",
            "describe-stacks",
            "--stack-name",
            "AaiSecRegionalRecovery",
        ],
        profile=profile,
        region=manifest.recovery_region,
        runner=runner,
    )
    stacks = response.get("Stacks")
    if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], dict):
        raise RecoveryConfigurationError("expected exactly one passive recovery stack")
    outputs = stacks[0].get("Outputs")
    if not isinstance(outputs, list) or len(outputs) > 20:
        raise RecoveryConfigurationError("passive recovery outputs are malformed")
    result: dict[str, str] = {}
    for item in outputs:
        if not isinstance(item, dict):
            raise RecoveryConfigurationError("passive recovery output is malformed")
        key, value = item.get("OutputKey"), item.get("OutputValue")
        if not isinstance(key, str) or not isinstance(value, str) or key in result:
            raise RecoveryConfigurationError("passive recovery output identity is ambiguous")
        result[key] = value
    if result.get("RegionalPolicySigningReplicaStatus") != "staged-not-active":
        raise RecoveryConfigurationError("passive signing replica is not explicitly staged")
    if not isinstance(result.get("RegionalPolicySigningReplicaKeyArn"), str):
        raise RecoveryConfigurationError("passive signing replica ARN is missing")
    return result


def deploy_signing_replica(
    primary_key_arn: str,
    manifest: RegionalRecoveryManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> None:
    """Deploy only the retained passive KMS replica from reviewed authority."""
    match = re.fullmatch(
        r"arn:(aws|aws-us-gov|aws-cn):kms:[a-z]{2}(?:-gov)?-[a-z]+-\d:(\d{12}):key/(mrk-[0-9a-f]{32})",
        primary_key_arn,
    )
    if match is None:
        raise RecoveryConfigurationError("primary regional signing key ARN is malformed")
    environment = os.environ.copy()
    # Ambient recovery values are never deployment authority.
    for field in (
        "REGIONAL_POLICY_SIGNING_KEY_ARN",
        "RECOVERY_REGION",
        "PRIMARY_REGION",
        "CDK_DEFAULT_ACCOUNT",
        "CDK_DEFAULT_REGION",
    ):
        environment.pop(field, None)
    environment.update(
        {
            "AWS_PROFILE": profile,
            "AWS_REGION": manifest.recovery_region,
            "CDK_DEFAULT_ACCOUNT": match.group(2),
            "CDK_DEFAULT_REGION": manifest.recovery_region,
            "REGIONAL_POLICY_SIGNING_KEY_ARN": primary_key_arn,
            "RECOVERY_REGION": manifest.recovery_region,
            "PRIMARY_REGION": manifest.primary_region,
        }
    )
    infrastructure = Path(__file__).resolve().parents[1] / "infra" / "aws-control-plane"
    commands = (
        ["npm", "run", "build"],
        [
            "npx",
            "cdk",
            "--app",
            "npx ts-node --prefer-ts-exts bin/regional-recovery.ts",
            "deploy",
            "AaiSecRegionalRecovery",
            "--require-approval",
            "never",
        ],
    )
    for command in commands:
        result = runner(command, cwd=infrastructure, env=environment, check=False)
        if result.returncode != 0:
            raise RecoveryConfigurationError(
                f"recovery trust deployment failed: {' '.join(command)}"
            )


def verify_signing_replica(
    primary_key_arn: str,
    replica_key_arn: str,
    manifest: RegionalRecoveryManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, str]:
    """Prove the staged keys share material while neither changes signer authority."""
    primary_response = _aws(
        ["kms", "describe-key", "--key-id", primary_key_arn],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )
    replica_response = _aws(
        ["kms", "describe-key", "--key-id", replica_key_arn],
        profile=profile,
        region=manifest.recovery_region,
        runner=runner,
    )
    primary = primary_response.get("KeyMetadata")
    replica = replica_response.get("KeyMetadata")
    primary_configuration = (
        primary.get("MultiRegionConfiguration") if isinstance(primary, dict) else None
    )
    replica_configuration = (
        replica.get("MultiRegionConfiguration") if isinstance(replica, dict) else None
    )
    primary_id = primary.get("KeyId") if isinstance(primary, dict) else None
    replica_id = replica.get("KeyId") if isinstance(replica, dict) else None
    related = (
        primary_configuration.get("ReplicaKeys")
        if isinstance(primary_configuration, dict)
        else None
    )
    replica_primary = (
        replica_configuration.get("PrimaryKey") if isinstance(replica_configuration, dict) else None
    )
    if (
        not isinstance(primary, dict)
        or not isinstance(replica, dict)
        or primary.get("Arn") != primary_key_arn
        or replica.get("Arn") != replica_key_arn
        or primary_id != replica_id
        or not isinstance(primary_id, str)
        or not primary_id.startswith("mrk-")
        or primary.get("KeySpec") != "ECC_NIST_P256"
        or replica.get("KeySpec") != "ECC_NIST_P256"
        or primary.get("KeyUsage") != "SIGN_VERIFY"
        or replica.get("KeyUsage") != "SIGN_VERIFY"
        or primary.get("KeyState") != "Enabled"
        or replica.get("KeyState") != "Enabled"
        or not isinstance(primary_configuration, dict)
        or primary_configuration.get("MultiRegionKeyType") != "PRIMARY"
        or not isinstance(replica_configuration, dict)
        or replica_configuration.get("MultiRegionKeyType") != "REPLICA"
        or not isinstance(replica_primary, dict)
        or replica_primary.get("Arn") != primary_key_arn
        or not isinstance(related, list)
        or not any(
            isinstance(item, dict) and item.get("Arn") == replica_key_arn for item in related
        )
    ):
        raise RecoveryConfigurationError("regional policy-signing key pair is inconsistent")
    return {
        "keyId": primary_id,
        "primaryKeyArn": primary_key_arn,
        "replicaKeyArn": replica_key_arn,
        "status": "STAGED_NOT_ACTIVE",
    }


def _table_description(
    table_name: str,
    *,
    profile: str,
    region: str,
    runner: Runner,
) -> dict[str, Any]:
    """Return one validated DynamoDB table description."""
    value = _aws(
        ["dynamodb", "describe-table", "--table-name", table_name],
        profile=profile,
        region=region,
        runner=runner,
    ).get("Table")
    if not isinstance(value, dict) or value.get("TableName") != table_name:
        raise RecoveryConfigurationError(f"DynamoDB did not return table {table_name}")
    return value


def _pitr_enabled(
    table_name: str,
    *,
    profile: str,
    region: str,
    runner: Runner,
) -> bool:
    """Return whether continuous point-in-time recovery is enabled."""
    value = _aws(
        ["dynamodb", "describe-continuous-backups", "--table-name", table_name],
        profile=profile,
        region=region,
        runner=runner,
    )
    description = value.get("ContinuousBackupsDescription")
    pitr = (
        description.get("PointInTimeRecoveryDescription") if isinstance(description, dict) else None
    )
    return isinstance(pitr, dict) and pitr.get("PointInTimeRecoveryStatus") == "ENABLED"


def verify_table_posture(
    role: str,
    table_name: str,
    manifest: RegionalRecoveryManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, str]:
    """Prove one table is protected and has an active recovery replica."""
    primary = _table_description(
        table_name, profile=profile, region=manifest.primary_region, runner=runner
    )
    stream = primary.get("StreamSpecification")
    if (
        primary.get("TableStatus") != "ACTIVE"
        or primary.get("DeletionProtectionEnabled") is not True
        or not isinstance(stream, dict)
        or stream.get("StreamEnabled") is not True
        or stream.get("StreamViewType") != "NEW_AND_OLD_IMAGES"
        or not _pitr_enabled(
            table_name, profile=profile, region=manifest.primary_region, runner=runner
        )
    ):
        raise RecoveryConfigurationError(f"primary {role} table is not recovery-ready")
    replicas = primary.get("Replicas")
    recovery_replica = (
        next(
            (
                replica
                for replica in replicas
                if isinstance(replica, dict)
                and replica.get("RegionName") == manifest.recovery_region
            ),
            None,
        )
        if isinstance(replicas, list)
        else None
    )
    if not isinstance(recovery_replica, dict) or recovery_replica.get("ReplicaStatus") != "ACTIVE":
        raise RecoveryConfigurationError(f"{role} recovery replica is not ACTIVE")
    recovery = _table_description(
        table_name, profile=profile, region=manifest.recovery_region, runner=runner
    )
    if (
        recovery.get("TableStatus") != "ACTIVE"
        or recovery.get("DeletionProtectionEnabled") is not True
        or recovery.get("KeySchema") != primary.get("KeySchema")
        or not _pitr_enabled(
            table_name, profile=profile, region=manifest.recovery_region, runner=runner
        )
    ):
        raise RecoveryConfigurationError(f"recovery {role} table posture differs from primary")
    return {"role": role, "tableName": table_name, "replicaStatus": "ACTIVE"}


def prepare_table_replica(
    role: str,
    table_name: str,
    manifest: RegionalRecoveryManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
    sleeper: Sleeper = time.sleep,
    clock: Clock = time.monotonic,
) -> None:
    """Create one replica if absent and wait within the approved RTO."""
    primary = _table_description(
        table_name, profile=profile, region=manifest.primary_region, runner=runner
    )
    stream = primary.get("StreamSpecification")
    if (
        primary.get("DeletionProtectionEnabled") is not True
        or not isinstance(stream, dict)
        or stream.get("StreamViewType") != "NEW_AND_OLD_IMAGES"
        or not _pitr_enabled(
            table_name, profile=profile, region=manifest.primary_region, runner=runner
        )
    ):
        raise RecoveryConfigurationError(f"primary {role} table prerequisites are incomplete")
    replicas = primary.get("Replicas")
    existing = (
        next(
            (
                replica
                for replica in replicas
                if isinstance(replica, dict)
                and replica.get("RegionName") == manifest.recovery_region
            ),
            None,
        )
        if isinstance(replicas, list)
        else None
    )
    if existing is None:
        _aws(
            [
                "dynamodb",
                "update-table",
                "--table-name",
                table_name,
                "--replica-updates",
                json.dumps([{"Create": {"RegionName": manifest.recovery_region}}]),
            ],
            profile=profile,
            region=manifest.primary_region,
            runner=runner,
            timeout=120,
        )
    deadline = clock() + manifest.rto_minutes * 60
    while True:
        current = _table_description(
            table_name, profile=profile, region=manifest.primary_region, runner=runner
        )
        replicas = current.get("Replicas")
        replica = (
            next(
                (
                    candidate
                    for candidate in replicas
                    if isinstance(candidate, dict)
                    and candidate.get("RegionName") == manifest.recovery_region
                ),
                None,
            )
            if isinstance(replicas, list)
            else None
        )
        status = replica.get("ReplicaStatus") if isinstance(replica, dict) else None
        if status == "ACTIVE":
            break
        if status in {"CREATION_FAILED", "INACCESSIBLE_ENCRYPTION_CREDENTIALS", "REGION_DISABLED"}:
            raise RecoveryConfigurationError(f"{role} replica entered terminal state {status}")
        if clock() >= deadline:
            raise RecoveryConfigurationError(f"{role} replica exceeded the approved RTO")
        sleeper(15)
    recovery = _table_description(
        table_name, profile=profile, region=manifest.recovery_region, runner=runner
    )
    if recovery.get("DeletionProtectionEnabled") is not True:
        _aws(
            [
                "dynamodb",
                "update-table",
                "--table-name",
                table_name,
                "--deletion-protection-enabled",
            ],
            profile=profile,
            region=manifest.recovery_region,
            runner=runner,
        )
    if not _pitr_enabled(
        table_name, profile=profile, region=manifest.recovery_region, runner=runner
    ):
        _aws(
            [
                "dynamodb",
                "update-continuous-backups",
                "--table-name",
                table_name,
                "--point-in-time-recovery-specification",
                "PointInTimeRecoveryEnabled=true",
            ],
            profile=profile,
            region=manifest.recovery_region,
            runner=runner,
        )
    # Replica status can become ACTIVE before regional PITR/deletion updates
    # finish and before the source table returns from UPDATING. Do not let the
    # next table or final verifier race that provider convergence window.
    while True:
        primary = _table_description(
            table_name, profile=profile, region=manifest.primary_region, runner=runner
        )
        recovery = _table_description(
            table_name, profile=profile, region=manifest.recovery_region, runner=runner
        )
        if (
            primary.get("TableStatus") == "ACTIVE"
            and primary.get("DeletionProtectionEnabled") is True
            and recovery.get("TableStatus") == "ACTIVE"
            and recovery.get("DeletionProtectionEnabled") is True
            and _pitr_enabled(
                table_name,
                profile=profile,
                region=manifest.primary_region,
                runner=runner,
            )
            and _pitr_enabled(
                table_name,
                profile=profile,
                region=manifest.recovery_region,
                runner=runner,
            )
        ):
            return
        if clock() >= deadline:
            raise RecoveryConfigurationError(f"{role} protection convergence exceeded RTO")
        sleeper(5)


def replication_canary(
    role: str,
    table_name: str,
    manifest: RegionalRecoveryManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
    sleeper: Sleeper = time.sleep,
    clock: Clock = time.monotonic,
) -> dict[str, Any]:
    """Measure create and delete replication without granting application authority."""
    canary_id = str(uuid4())
    partition = f"DR_CANARY#{canary_id}"
    digest = hashlib.sha256(f"{role}\0{table_name}\0{canary_id}".encode()).hexdigest()
    item: dict[str, dict[str, str]] = {
        "pk": {"S": partition},
        "kind": {"S": "regional-recovery-canary"},
        "digest": {"S": digest},
        "ttl": {"N": str(int(time.time()) + 3600)},
    }
    key: dict[str, dict[str, str]] = {"pk": {"S": partition}}
    if role in _SORT_KEY_TABLES:
        item["sk"] = {"S": "CANARY"}
        key["sk"] = {"S": "CANARY"}
    started = clock()
    _aws(
        [
            "dynamodb",
            "put-item",
            "--table-name",
            table_name,
            "--item",
            json.dumps(item, sort_keys=True, separators=(",", ":")),
            "--condition-expression",
            "attribute_not_exists(pk)",
        ],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )
    deadline = started + manifest.rpo_seconds
    while True:
        response = _aws(
            [
                "dynamodb",
                "get-item",
                "--table-name",
                table_name,
                "--key",
                json.dumps(key, sort_keys=True, separators=(",", ":")),
                "--consistent-read",
            ],
            profile=profile,
            region=manifest.recovery_region,
            runner=runner,
        )
        if response.get("Item") == item:
            break
        if clock() >= deadline:
            raise RecoveryConfigurationError(f"{role} create replication exceeded RPO")
        sleeper(1)
    create_seconds = round(clock() - started, 3)
    _aws(
        [
            "dynamodb",
            "delete-item",
            "--table-name",
            table_name,
            "--key",
            json.dumps(key, sort_keys=True, separators=(",", ":")),
            "--condition-expression",
            "digest = :digest",
            "--expression-attribute-values",
            json.dumps({":digest": {"S": digest}}, separators=(",", ":")),
        ],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )
    delete_started = clock()
    delete_deadline = delete_started + manifest.rpo_seconds
    while True:
        response = _aws(
            [
                "dynamodb",
                "get-item",
                "--table-name",
                table_name,
                "--key",
                json.dumps(key, sort_keys=True, separators=(",", ":")),
                "--consistent-read",
            ],
            profile=profile,
            region=manifest.recovery_region,
            runner=runner,
        )
        if "Item" not in response:
            break
        if clock() >= delete_deadline:
            raise RecoveryConfigurationError(f"{role} delete replication exceeded RPO")
        sleeper(1)
    return {
        "role": role,
        "tableName": table_name,
        "createReplicationSeconds": create_seconds,
        "deleteReplicationSeconds": round(clock() - delete_started, 3),
        "contentDigest": digest,
    }


def verify_staged_signing_key(
    key_arn: str,
    manifest: RegionalRecoveryManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, str]:
    """Require a staged asymmetric multi-Region key without activating it."""
    response = _aws(
        ["kms", "describe-key", "--key-id", key_arn],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )
    metadata = response.get("KeyMetadata")
    multi_region = metadata.get("MultiRegionConfiguration") if isinstance(metadata, dict) else None
    if (
        not isinstance(metadata, dict)
        or metadata.get("Arn") != key_arn
        or metadata.get("MultiRegion") is not True
        or metadata.get("KeySpec") != "ECC_NIST_P256"
        or metadata.get("KeyUsage") != "SIGN_VERIFY"
        or metadata.get("KeyState") != "Enabled"
        or not isinstance(multi_region, dict)
        or multi_region.get("MultiRegionKeyType") != "PRIMARY"
    ):
        raise RecoveryConfigurationError("staged regional policy signing key is invalid")
    return {"keyArn": key_arn, "status": "STAGED_NOT_ACTIVE"}


def persist_manifest(
    manifest: RegionalRecoveryManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> None:
    """Persist reviewed authority only after every storage check succeeds."""
    _aws(
        [
            "ssm",
            "put-parameter",
            "--name",
            parameter_name(manifest.stack_name),
            "--type",
            "SecureString",
            "--overwrite",
            "--value",
            manifest.canonical_json(),
            "--description",
            "AAI Security regional recovery targets and approval reference",
        ],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )


def load_persisted_manifest(
    manifest: RegionalRecoveryManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> RegionalRecoveryManifest:
    """Load and verify the exact reviewed authority before later trust phases."""
    response = _aws(
        [
            "ssm",
            "get-parameter",
            "--name",
            parameter_name(manifest.stack_name),
            "--with-decryption",
        ],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )
    parameter = response.get("Parameter")
    payload = parameter.get("Value") if isinstance(parameter, dict) else None
    if not isinstance(payload, str):
        raise RecoveryConfigurationError("persisted regional recovery authority is missing")
    persisted = RegionalRecoveryManifest.parse(payload)
    if persisted.canonical_json() != manifest.canonical_json():
        raise RecoveryConfigurationError(
            "operator config differs from persisted regional recovery authority"
        )
    return persisted


def _parser() -> argparse.ArgumentParser:
    """Build the deliberately narrow operator command surface."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("check", "prepare-storage", "check-trust", "prepare-trust"),
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--profile", default="p1")
    parser.add_argument("--confirm-storage-replication", action="store_true")
    parser.add_argument("--confirm-trust-replication", action="store_true")
    parser.add_argument("--evidence-out", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Check posture or prepare and verify the non-routing storage foundation."""
    arguments = _parser().parse_args(argv)
    try:
        manifest = RegionalRecoveryManifest.parse(arguments.config.read_text(encoding="utf-8"))
        outputs = stack_outputs(manifest, profile=arguments.profile)
        tables = {role: outputs[key] for role, key in _OUTPUT_TABLES.items()}
        if arguments.command == "prepare-storage":
            if not arguments.confirm_storage_replication:
                raise RecoveryConfigurationError(
                    "--confirm-storage-replication is required before adding replicas"
                )
            for role, table_name in tables.items():
                prepare_table_replica(role, table_name, manifest, profile=arguments.profile)
        posture = [
            verify_table_posture(role, table_name, manifest, profile=arguments.profile)
            for role, table_name in tables.items()
        ]
        signing = verify_staged_signing_key(
            outputs["RegionalPolicySigningKeyArn"], manifest, profile=arguments.profile
        )
        signing_replica: dict[str, str] | None = None
        if arguments.command == "prepare-trust":
            if not arguments.confirm_trust_replication:
                raise RecoveryConfigurationError(
                    "--confirm-trust-replication is required before replicating signing trust"
                )
            load_persisted_manifest(manifest, profile=arguments.profile)
            deploy_signing_replica(
                outputs["RegionalPolicySigningKeyArn"],
                manifest,
                profile=arguments.profile,
            )
        if arguments.command in {"check-trust", "prepare-trust"}:
            passive_outputs = recovery_stack_outputs(manifest, profile=arguments.profile)
            signing_replica = verify_signing_replica(
                outputs["RegionalPolicySigningKeyArn"],
                passive_outputs["RegionalPolicySigningReplicaKeyArn"],
                manifest,
                profile=arguments.profile,
            )
            if outputs["PolicySigningKeyArn"] == outputs["RegionalPolicySigningKeyArn"]:
                raise RecoveryConfigurationError("staged key was activated before trust rollout")
        canaries: list[dict[str, Any]] = []
        if arguments.command == "prepare-storage":
            canaries = [
                replication_canary(role, table_name, manifest, profile=arguments.profile)
                for role, table_name in tables.items()
            ]
            persist_manifest(manifest, profile=arguments.profile)
        evidence = {
            "schemaVersion": 1,
            "mode": (
                "storage-and-trust-foundation"
                if arguments.command in {"check-trust", "prepare-trust"}
                else "storage-foundation-only"
            ),
            "trafficActivated": False,
            "identityReplicated": False,
            "activeSigningKeyChanged": False,
            "primaryRegion": manifest.primary_region,
            "recoveryRegion": manifest.recovery_region,
            "targetFleetSize": manifest.target_fleet_size,
            "rtoMinutes": manifest.rto_minutes,
            "rpoSeconds": manifest.rpo_seconds,
            "tables": posture,
            "canaries": canaries,
            "stagedSigningKey": signing,
            "stagedSigningReplica": signing_replica,
        }
        encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n"
        if arguments.evidence_out is not None:
            arguments.evidence_out.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        return 0
    except (OSError, RecoveryConfigurationError) as error:
        print(f"Regional recovery check failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
