#!/usr/bin/env python3
"""Verify live AWS activation prerequisites and emit a read-only transition plan.

The command deliberately has no activation mode. It binds reviewed manifests to
persisted AWS authority, reads one exact Object-Locked evidence version, repeats
the live identity, passive-cell, audit-continuity, origin-fencing and DNS checks,
and emits the ordered manual transition plan only when every check passes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts import deploy_aws_evidence_continuity as continuity  # noqa: E402
from scripts import deploy_aws_passive_cell as passive  # noqa: E402
from scripts import manage_aws_regional_recovery as recovery  # noqa: E402
from scripts import verify_aws_regional_activation as activation  # noqa: E402


class RegionalActivationPreflightError(RuntimeError):
    """Raised when live provider state cannot prove a safe manual transition."""


Runner = Callable[..., subprocess.CompletedProcess[str]]
S3Factory = Callable[[str], Any]
_API_URL = re.compile(r"^https://([a-z0-9]+)\.execute-api\.([a-z0-9-]+)\.amazonaws\.com/?$")


def _aws(
    arguments: Sequence[str],
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Call the existing bounded AWS boundary and normalize its error type."""
    try:
        return recovery._aws(arguments, profile=profile, region=region, runner=runner)
    except recovery.RecoveryConfigurationError as error:
        raise RegionalActivationPreflightError(str(error)) from error


def verify_authority_alignment(
    manifest: activation.ActivationManifest,
    regional: recovery.RegionalRecoveryManifest,
    evidence_continuity: continuity.EvidenceContinuityManifest,
    passive_cell: passive.PassiveCellManifest,
) -> None:
    """Reject any disagreement across independently reviewed authority files."""
    expected = (
        regional.primary_region,
        regional.recovery_region,
        regional.target_fleet_size,
        regional.rto_minutes,
        regional.rpo_seconds,
    )
    actual = (
        manifest.primary_region,
        manifest.recovery_region,
        manifest.target_fleet_size,
        manifest.rto_minutes,
        manifest.rpo_seconds,
    )
    if actual != expected:
        raise RegionalActivationPreflightError(
            "activation and persisted regional-recovery targets disagree"
        )
    if (
        evidence_continuity.primary_stack_name != regional.stack_name
        or evidence_continuity.primary_region != regional.primary_region
        or evidence_continuity.recovery_region != regional.recovery_region
        or passive_cell.primary_region != regional.primary_region
        or passive_cell.recovery_region != regional.recovery_region
    ):
        raise RegionalActivationPreflightError(
            "activation, continuity and passive-cell authority disagree"
        )


def read_retained_evidence(
    manifest: activation.ActivationManifest,
    *,
    expected_bucket_arn: str,
    s3_client: Any,
    now: datetime | None = None,
) -> bytes:
    """Read and verify one exact retained S3 object version without mutation."""
    if manifest.evidence.bucket_arn != expected_bucket_arn:
        raise RegionalActivationPreflightError(
            "activation evidence bucket differs from persisted audit authority"
        )
    bucket = expected_bucket_arn.removeprefix("arn:aws:s3:::")
    if not bucket or bucket == expected_bucket_arn:
        raise RegionalActivationPreflightError("persisted audit bucket ARN is malformed")
    try:
        response = s3_client.get_object(
            Bucket=bucket,
            Key=manifest.evidence.key,
            VersionId=manifest.evidence.version_id,
        )
    except Exception as error:  # provider exceptions vary by botocore version
        raise RegionalActivationPreflightError(
            "exact retained activation evidence version is unavailable"
        ) from error
    body = response.get("Body")
    if not hasattr(body, "read"):
        raise RegionalActivationPreflightError("activation evidence body is unavailable")
    try:
        payload = body.read(1_048_577)
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    if not isinstance(payload, bytes) or len(payload) > 1_048_576:
        raise RegionalActivationPreflightError("activation evidence exceeds 1 MiB")
    digest = hashlib.sha256(payload).hexdigest()
    metadata = response.get("Metadata")
    retained_until = response.get("ObjectLockRetainUntilDate")
    current = datetime.now(UTC) if now is None else now
    if current.tzinfo is None:
        raise RegionalActivationPreflightError("preflight clock must be timezone-aware")
    if (
        response.get("VersionId") != manifest.evidence.version_id
        or digest != manifest.evidence.sha256
        or not isinstance(metadata, dict)
        or metadata.get("content-sha256") != digest
        or response.get("ObjectLockMode") != "COMPLIANCE"
        or not isinstance(retained_until, datetime)
        or retained_until.tzinfo is None
        or retained_until <= current
        or retained_until.timestamp() <= manifest.expires_at
    ):
        raise RegionalActivationPreflightError(
            "activation evidence version is not content-bound under live COMPLIANCE retention"
        )
    return payload


def verify_passive_stack(
    manifest: passive.PassiveCellManifest,
    *,
    profile: str,
    expected_status: str = "staged-not-serving",
    runner: Runner = subprocess.run,
) -> str:
    """Require one stable recovery stack in the exact reviewed lifecycle state."""
    if expected_status not in {"staged-not-serving", "active-not-routed"}:
        raise RegionalActivationPreflightError("expected recovery-cell status is unsupported")
    response = _aws(
        ["cloudformation", "describe-stacks", "--stack-name", manifest.stack_name],
        profile=profile,
        region=manifest.recovery_region,
        runner=runner,
    )
    stacks = response.get("Stacks")
    if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], dict):
        raise RegionalActivationPreflightError("passive-cell stack is not deployed")
    stack = stacks[0]
    if stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
        raise RegionalActivationPreflightError("passive-cell stack is not stable")
    try:
        status = passive._stack_output(response, "PassiveCellStatus")
        api_id = passive._stack_output(response, "PassiveControlPlaneApiId")
    except passive.PassiveCellDeploymentError as error:
        raise RegionalActivationPreflightError(str(error)) from error
    if status != expected_status:
        raise RegionalActivationPreflightError(f"recovery-cell stack is not {expected_status}")
    return api_id


def verify_api_origin_fencing(
    *,
    primary_api_url: str,
    passive_api_id: str,
    primary_region: str,
    recovery_region: str,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, str]:
    """Require both raw execute-api origins to reject direct public requests."""
    match = _API_URL.fullmatch(primary_api_url)
    if not match or match.group(2) != primary_region:
        raise RegionalActivationPreflightError("primary API output is malformed")
    primary_api_id = match.group(1)
    for label, api_id, region in (
        ("source", primary_api_id, primary_region),
        ("target", passive_api_id, recovery_region),
    ):
        response = _aws(
            ["apigatewayv2", "get-api", "--api-id", api_id],
            profile=profile,
            region=region,
            runner=runner,
        )
        if response.get("ApiId") != api_id or response.get("DisableExecuteApiEndpoint") is not True:
            raise RegionalActivationPreflightError(
                f"{label} direct execute-api origin is not disabled"
            )
    return {"sourceApiId": primary_api_id, "targetApiId": passive_api_id}


def verify_stable_dns_records(
    manifest: activation.ActivationManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> None:
    """Require exact stable API and UI names to exist in the reviewed hosted zone."""
    response = _aws(
        [
            "route53",
            "list-resource-record-sets",
            "--hosted-zone-id",
            manifest.hosted_zone_id,
        ],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )
    records = response.get("ResourceRecordSets")
    if not isinstance(records, list) or len(records) > 10_000:
        raise RegionalActivationPreflightError("stable DNS records are unavailable")
    names = {
        item.get("Name", "").rstrip(".")
        for item in records
        if isinstance(item, dict) and item.get("Type") in {"A", "AAAA", "CNAME"}
    }
    required = {manifest.stable_api_domain, manifest.stable_ui_domain}
    if not required.issubset(names):
        raise RegionalActivationPreflightError("stable API or UI DNS record is missing")


def provider_preflight(
    manifest: activation.ActivationManifest,
    regional: recovery.RegionalRecoveryManifest,
    evidence_continuity: continuity.EvidenceContinuityManifest,
    passive_cell: passive.PassiveCellManifest,
    *,
    profile: str,
    s3_factory: S3Factory,
    runner: Runner = subprocess.run,
    now_epoch: int | None = None,
    expected_cell_status: str = "staged-not-serving",
) -> dict[str, Any]:
    """Repeat live provider checks and return a non-mutating transition plan."""
    verify_authority_alignment(manifest, regional, evidence_continuity, passive_cell)
    try:
        recovery.load_persisted_manifest(regional, profile=profile, runner=runner)
    except recovery.RecoveryConfigurationError as error:
        raise RegionalActivationPreflightError(
            f"persisted regional-recovery authority unavailable: {error}"
        ) from error
    try:
        continuity.require_persisted_manifest(evidence_continuity, profile=profile, runner=runner)
    except continuity.EvidenceContinuityDeploymentError as error:
        raise RegionalActivationPreflightError(
            f"persisted evidence-continuity authority unavailable: {error}"
        ) from error
    try:
        passive.require_persisted_manifest(passive_cell, profile=profile, runner=runner)
    except passive.PassiveCellDeploymentError as error:
        raise RegionalActivationPreflightError(
            f"persisted passive-cell authority unavailable: {error}"
        ) from error
    try:
        resources = continuity.discover(
            evidence_continuity, regional, profile=profile, runner=runner
        )
        identity = passive.verify_recovery_identity(
            passive_cell,
            primary_stack_name=regional.stack_name,
            profile=profile,
            runner=runner,
        )
        primary_outputs = recovery.stack_outputs(regional, profile=profile, runner=runner)
    except (
        recovery.RecoveryConfigurationError,
        continuity.EvidenceContinuityDeploymentError,
        passive.PassiveCellDeploymentError,
    ) as error:
        raise RegionalActivationPreflightError(str(error)) from error
    api_id = verify_passive_stack(
        passive_cell,
        profile=profile,
        expected_status=expected_cell_status,
        runner=runner,
    )
    origins = verify_api_origin_fencing(
        primary_api_url=primary_outputs.get("ApiUrl", ""),
        passive_api_id=api_id,
        primary_region=regional.primary_region,
        recovery_region=regional.recovery_region,
        profile=profile,
        runner=runner,
    )
    verify_stable_dns_records(manifest, profile=profile, runner=runner)
    try:
        audit = {
            "primaryToRecovery": continuity.verify_live_direction(
                source_bucket=resources["primaryBucket"],
                source_region=regional.primary_region,
                destination_arn=resources["recoveryBucketArn"],
                rule_id="replicate-audit-to-recovery-region",
                profile=profile,
                runner=runner,
            ),
            "recoveryToPrimary": continuity.verify_live_direction(
                source_bucket=resources["recoveryBucket"],
                source_region=regional.recovery_region,
                destination_arn=resources["primaryBucketArn"],
                rule_id="replicate-recovery-audit-to-primary-region",
                profile=profile,
                runner=runner,
            ),
        }
    except continuity.EvidenceContinuityDeploymentError as error:
        raise RegionalActivationPreflightError(str(error)) from error
    current_epoch = int(time.time()) if now_epoch is None else now_epoch
    payload = read_retained_evidence(
        manifest,
        expected_bucket_arn=resources["primaryBucketArn"],
        s3_client=s3_factory(regional.primary_region),
        now=datetime.fromtimestamp(current_epoch, tz=UTC),
    )
    try:
        claims = json.loads(payload, object_pairs_hook=activation._strict_object)
        if not isinstance(claims, dict) or not isinstance(claims.get("identity"), dict):
            raise RegionalActivationPreflightError(
                "retained activation evidence identity is malformed"
            )
        if claims["identity"].get("recoveryPoolId") != passive_cell.user_pool_id:
            raise RegionalActivationPreflightError(
                "retained identity evidence names a different recovery user pool"
            )
        verified = activation.verify_bundle(manifest, payload, now=current_epoch)
        plan = activation.transition_plan(manifest, verified)
    except (json.JSONDecodeError, activation.RegionalActivationVerificationError) as error:
        raise RegionalActivationPreflightError(str(error)) from error
    return {
        "activationExecuted": False,
        "auditContinuity": audit,
        "identity": identity,
        "originFencing": origins,
        "plan": plan,
        "status": "provider-state-verified-ready-for-manual-transition",
        "verified": verified,
    }


def _parser() -> argparse.ArgumentParser:
    """Build the read-only operator command surface."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--regional-recovery-config", type=Path, required=True)
    parser.add_argument("--evidence-continuity-config", type=Path, required=True)
    parser.add_argument("--passive-cell-config", type=Path, required=True)
    parser.add_argument("--profile", default="p1")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run a read-only AWS preflight and print the plan or first blocker."""
    arguments = _parser().parse_args(argv)
    try:
        manifest = activation.ActivationManifest.parse(
            arguments.manifest.read_text(encoding="utf-8")
        )
        regional = recovery.RegionalRecoveryManifest.parse(
            arguments.regional_recovery_config.read_text(encoding="utf-8")
        )
        evidence_continuity = continuity.EvidenceContinuityManifest.parse(
            arguments.evidence_continuity_config.read_text(encoding="utf-8")
        )
        passive_cell = passive.PassiveCellManifest.parse(
            arguments.passive_cell_config.read_text(encoding="utf-8")
        )
        import boto3

        session = boto3.Session(profile_name=arguments.profile)
        result = provider_preflight(
            manifest,
            regional,
            evidence_continuity,
            passive_cell,
            profile=arguments.profile,
            s3_factory=lambda region: session.client("s3", region_name=region),
        )
        print(json.dumps(result, sort_keys=True))
    except (
        OSError,
        UnicodeError,
        activation.RegionalActivationVerificationError,
        recovery.RecoveryConfigurationError,
        continuity.EvidenceContinuityDeploymentError,
        passive.PassiveCellDeploymentError,
        RegionalActivationPreflightError,
    ) as error:
        print(f"Regional activation preflight failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
