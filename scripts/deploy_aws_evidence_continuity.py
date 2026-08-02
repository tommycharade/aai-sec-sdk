#!/usr/bin/env python3
"""Guard, deploy and exercise bidirectional immutable AWS audit continuity.

The guard derives bucket and account identity from persisted recovery authority
and AWS, strips ambient CDK authority, verifies both synthesized templates and
deploys those exact assemblies without re-synthesis. It cannot activate the
passive API, workers, routing or policy signing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts import deploy_aws_control_plane as control_deploy  # noqa: E402
from scripts import manage_aws_regional_recovery as recovery  # noqa: E402
from scripts import test_aws_bidirectional_audit_continuity as canary  # noqa: E402
from scripts import verify_aws_evidence_continuity as verifier  # noqa: E402


class EvidenceContinuityDeploymentError(RuntimeError):
    """Report authority or provider state that cannot prove a safe deployment."""


Runner = Callable[..., subprocess.CompletedProcess[str]]
_FIELDS = {
    "schemaVersion",
    "primaryStackName",
    "recoveryStackName",
    "primaryRegion",
    "recoveryRegion",
    "approvalEvidenceRef",
    "activationPermitted",
}
_STACK = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")
_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_EVIDENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{7,511}$")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON fields before they become deployment authority."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceContinuityDeploymentError(f"duplicate continuity field: {key}")
        result[key] = value
    return result


@dataclass(frozen=True)
class EvidenceContinuityManifest:
    """Secret-free reviewed authority for replication-only stack updates."""

    primary_stack_name: str
    recovery_stack_name: str
    primary_region: str
    recovery_region: str
    approval_evidence_ref: str

    @classmethod
    def parse(cls, payload: str) -> EvidenceContinuityManifest:
        """Parse the exact schema-v1 non-activation contract."""
        if len(payload.encode()) > 16_384:
            raise EvidenceContinuityDeploymentError("continuity manifest exceeds 16 KiB")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except json.JSONDecodeError as error:
            raise EvidenceContinuityDeploymentError("continuity manifest is not JSON") from error
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise EvidenceContinuityDeploymentError(
                "continuity manifest fields do not match schema 1"
            )
        if value["schemaVersion"] != 1 or value["activationPermitted"] is not False:
            raise EvidenceContinuityDeploymentError("manifest must explicitly prohibit activation")
        primary_stack, replica_stack = value["primaryStackName"], value["recoveryStackName"]
        primary_region, replica_region = value["primaryRegion"], value["recoveryRegion"]
        evidence = value["approvalEvidenceRef"]
        if primary_stack != "AaiSecControlPlane" or replica_stack != "AaiSecAuditReplica":
            raise EvidenceContinuityDeploymentError("manifest names an unreviewed stack")
        if not _STACK.fullmatch(primary_stack) or not _STACK.fullmatch(replica_stack):
            raise EvidenceContinuityDeploymentError("stack name is malformed")
        if (
            not isinstance(primary_region, str)
            or not _REGION.fullmatch(primary_region)
            or not isinstance(replica_region, str)
            or not _REGION.fullmatch(replica_region)
            or primary_region == replica_region
        ):
            raise EvidenceContinuityDeploymentError("primary and recovery Regions must differ")
        if not isinstance(evidence, str) or not _EVIDENCE.fullmatch(evidence):
            raise EvidenceContinuityDeploymentError("approvalEvidenceRef is malformed")
        return cls(primary_stack, replica_stack, primary_region, replica_region, evidence)

    def canonical_json(self) -> str:
        """Return stable bytes for encrypted Parameter Store authority."""
        return json.dumps(
            {
                "activationPermitted": False,
                "approvalEvidenceRef": self.approval_evidence_ref,
                "primaryRegion": self.primary_region,
                "primaryStackName": self.primary_stack_name,
                "recoveryRegion": self.recovery_region,
                "recoveryStackName": self.recovery_stack_name,
                "schemaVersion": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def parameter_name(stack_name: str) -> str:
    """Return the stack-scoped encrypted continuity authority path."""
    if not _STACK.fullmatch(stack_name):
        raise EvidenceContinuityDeploymentError("primaryStackName is malformed")
    return f"/aai-sec/{stack_name}/evidence-continuity"


def _aws(
    arguments: Sequence[str], *, profile: str, region: str, runner: Runner = subprocess.run
) -> dict[str, Any]:
    """Call the bounded shared AWS CLI boundary and normalize its errors."""
    try:
        return recovery._aws(arguments, profile=profile, region=region, runner=runner)
    except recovery.RecoveryConfigurationError as error:
        raise EvidenceContinuityDeploymentError(str(error)) from error


def persist_manifest(
    manifest: EvidenceContinuityManifest, *, profile: str, runner: Runner = subprocess.run
) -> None:
    """Persist reviewed replication-only authority before stack mutation."""
    _aws(
        [
            "ssm",
            "put-parameter",
            "--name",
            parameter_name(manifest.primary_stack_name),
            "--type",
            "SecureString",
            "--overwrite",
            "--value",
            manifest.canonical_json(),
            "--description",
            "AAI Security bidirectional immutable evidence continuity authority",
        ],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )


def require_persisted_manifest(
    manifest: EvidenceContinuityManifest, *, profile: str, runner: Runner = subprocess.run
) -> None:
    """Require exact persisted authority for deployment and retained canaries."""
    response = _aws(
        [
            "ssm",
            "get-parameter",
            "--name",
            parameter_name(manifest.primary_stack_name),
            "--with-decryption",
        ],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )
    parameter = response.get("Parameter")
    payload = parameter.get("Value") if isinstance(parameter, dict) else None
    if not isinstance(payload, str):
        raise EvidenceContinuityDeploymentError("persisted continuity authority is missing")
    persisted = EvidenceContinuityManifest.parse(payload)
    if persisted.canonical_json() != manifest.canonical_json():
        raise EvidenceContinuityDeploymentError("persisted continuity authority differs")


def _output(response: dict[str, Any], name: str) -> str:
    """Return one exact CloudFormation output without accepting duplicates."""
    stacks = response.get("Stacks")
    if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], dict):
        raise EvidenceContinuityDeploymentError("expected exactly one recovery stack")
    outputs = stacks[0].get("Outputs")
    if not isinstance(outputs, list) or len(outputs) > 100:
        raise EvidenceContinuityDeploymentError("recovery stack outputs are malformed")
    matches = [
        item.get("OutputValue")
        for item in outputs
        if isinstance(item, dict) and item.get("OutputKey") == name
    ]
    if len(matches) != 1 or not isinstance(matches[0], str):
        raise EvidenceContinuityDeploymentError(f"recovery output is missing: {name}")
    return matches[0]


def discover(
    manifest: EvidenceContinuityManifest,
    regional_manifest: recovery.RegionalRecoveryManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, str]:
    """Derive exact account and buckets from persisted authority and provider state."""
    if (
        regional_manifest.stack_name != manifest.primary_stack_name
        or regional_manifest.primary_region != manifest.primary_region
        or regional_manifest.recovery_region != manifest.recovery_region
    ):
        raise EvidenceContinuityDeploymentError("continuity and regional manifests disagree")
    try:
        recovery.load_persisted_manifest(regional_manifest, profile=profile, runner=runner)
        primary_outputs = recovery.stack_outputs(regional_manifest, profile=profile, runner=runner)
    except recovery.RecoveryConfigurationError as error:
        raise EvidenceContinuityDeploymentError(str(error)) from error
    caller = _aws(
        ["sts", "get-caller-identity"],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )
    account = caller.get("Account")
    if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account):
        raise EvidenceContinuityDeploymentError("AWS account identity is malformed")
    replica_response = _aws(
        ["cloudformation", "describe-stacks", "--stack-name", manifest.recovery_stack_name],
        profile=profile,
        region=manifest.recovery_region,
        runner=runner,
    )
    replica_arn = _output(replica_response, "AuditReplicaBucketArn")
    if replica_arn != primary_outputs["AuditReplicaBucketArn"]:
        raise EvidenceContinuityDeploymentError("primary and recovery replica identities differ")
    primary_bucket = primary_outputs["AuditBucketName"]
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", primary_bucket):
        raise EvidenceContinuityDeploymentError("primary audit bucket name is malformed")
    primary_arn = f"arn:aws:s3:::{primary_bucket}"
    if not replica_arn.startswith("arn:aws:s3:::") or "/" in replica_arn.removeprefix(
        "arn:aws:s3:::"
    ):
        raise EvidenceContinuityDeploymentError("recovery audit bucket ARN is malformed")
    return {
        "account": account,
        "primaryBucket": primary_bucket,
        "primaryBucketArn": primary_arn,
        "recoveryBucket": replica_arn.removeprefix("arn:aws:s3:::"),
        "recoveryBucketArn": replica_arn,
    }


def _base_environment() -> dict[str, str]:
    """Copy non-authority process state while stripping every relevant override."""
    environment = os.environ.copy()
    for name in (
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "CDK_DEFAULT_ACCOUNT",
        "CDK_DEFAULT_REGION",
        "AUDIT_REPLICA_BUCKET_ARN",
        "AUDIT_REPLICA_REGION",
        "PRIMARY_AUDIT_BUCKET_ARN",
        "PRIMARY_AUDIT_REGION",
        *control_deploy._ENTRA_ENVIRONMENT_FIELDS,
    ):
        environment.pop(name, None)
    return environment


def deployment_environments(
    manifest: EvidenceContinuityManifest,
    resources: dict[str, str],
    *,
    profile: str,
    entra: control_deploy.EntraDeploymentManifest | None,
    audit: control_deploy.AuditRecoveryManifest,
) -> tuple[dict[str, str], dict[str, str]]:
    """Build exact primary and recovery synthesis environments."""
    base = _base_environment()
    primary = {
        **base,
        "AWS_PROFILE": profile,
        "AWS_REGION": manifest.primary_region,
        "AWS_DEFAULT_REGION": manifest.primary_region,
        "CDK_DEFAULT_ACCOUNT": resources["account"],
        "CDK_DEFAULT_REGION": manifest.primary_region,
        **audit.deployment_environment(),
    }
    if entra is not None:
        primary.update(entra.deployment_environment())
    replica = {
        **base,
        "AWS_PROFILE": profile,
        "AWS_REGION": manifest.recovery_region,
        "AWS_DEFAULT_REGION": manifest.recovery_region,
        "CDK_DEFAULT_ACCOUNT": resources["account"],
        "CDK_DEFAULT_REGION": manifest.recovery_region,
        "AUDIT_REPLICA_REGION": manifest.recovery_region,
        "PRIMARY_AUDIT_REGION": manifest.primary_region,
        "PRIMARY_AUDIT_BUCKET_ARN": resources["primaryBucketArn"],
    }
    return primary, replica


def _synthesize(
    command: list[str],
    stack_name: str,
    environment: dict[str, str],
    output_directory: Path,
    *,
    runner: Runner,
) -> tuple[Path, str]:
    """Synthesize one bounded assembly and return its exact template digest."""
    infrastructure = _ROOT / "infra" / "aws-control-plane"
    result = runner(
        [*command, "synth", stack_name, "--output", str(output_directory), "--quiet"],
        cwd=infrastructure,
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if result.returncode != 0:
        raise EvidenceContinuityDeploymentError(f"{stack_name} synthesis failed")
    template_path = output_directory / f"{stack_name}.template.json"
    try:
        template_bytes = template_path.read_bytes()
    except OSError as error:
        raise EvidenceContinuityDeploymentError("synthesized template is missing") from error
    if len(template_bytes) > 5_000_000:
        raise EvidenceContinuityDeploymentError("synthesized template exceeds 5 MB")
    return template_path, hashlib.sha256(template_bytes).hexdigest()


def _verify_template(path: Path, destination: str, rule_id: str) -> dict[str, str | int]:
    """Independently verify one synthesized replication direction."""
    try:
        template = json.loads(path.read_text(encoding="utf-8"))
        return verifier.verify(
            template, destination_bucket_arn=destination, expected_rule_id=rule_id
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise EvidenceContinuityDeploymentError(
            "continuity template verification failed"
        ) from error


def _deploy_assembly(
    stack_name: str,
    assembly: Path,
    template_path: Path,
    digest: str,
    environment: dict[str, str],
    *,
    runner: Runner,
) -> None:
    """Deploy the exact verified CDK assembly without re-synthesis."""
    if hashlib.sha256(template_path.read_bytes()).hexdigest() != digest:
        raise EvidenceContinuityDeploymentError("verified template changed before deployment")
    result = runner(
        [
            "npx",
            "cdk",
            "--app",
            str(assembly),
            "deploy",
            stack_name,
            "--require-approval",
            "never",
        ],
        cwd=_ROOT / "infra" / "aws-control-plane",
        env=environment,
        timeout=900,
        check=False,
    )
    if result.returncode != 0:
        raise EvidenceContinuityDeploymentError(f"{stack_name} deployment failed")


def verify_live_direction(
    *,
    source_bucket: str,
    source_region: str,
    destination_arn: str,
    rule_id: str,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, str]:
    """Prove exact live versioning, Object Lock and replication configuration."""
    versioning = _aws(
        ["s3api", "get-bucket-versioning", "--bucket", source_bucket],
        profile=profile,
        region=source_region,
        runner=runner,
    )
    lock = _aws(
        ["s3api", "get-object-lock-configuration", "--bucket", source_bucket],
        profile=profile,
        region=source_region,
        runner=runner,
    ).get("ObjectLockConfiguration", {})
    replication = _aws(
        ["s3api", "get-bucket-replication", "--bucket", source_bucket],
        profile=profile,
        region=source_region,
        runner=runner,
    ).get("ReplicationConfiguration", {})
    rules = replication.get("Rules") if isinstance(replication, dict) else None
    retention = lock.get("Rule", {}).get("DefaultRetention", {}) if isinstance(lock, dict) else {}
    if (
        versioning.get("Status") != "Enabled"
        or lock.get("ObjectLockEnabled") != "Enabled"
        or retention.get("Mode") != "COMPLIANCE"
        or int(retention.get("Days", 0)) < 365
        or not isinstance(rules, list)
        or len(rules) != 1
    ):
        raise EvidenceContinuityDeploymentError("live source immutability posture is incomplete")
    rule = rules[0]
    if (
        rule.get("ID") != rule_id
        or rule.get("Status") != "Enabled"
        or rule.get("Priority") != 1
        or rule.get("Filter") != {"Prefix": ""}
        or rule.get("DeleteMarkerReplication") != {"Status": "Disabled"}
        or rule.get("SourceSelectionCriteria", {}).get("ReplicaModifications")
        != {"Status": "Enabled"}
        or rule.get("Destination", {}).get("Bucket") != destination_arn
    ):
        raise EvidenceContinuityDeploymentError("live replication rule differs from authority")
    return {"ruleId": rule_id, "status": "verified-live-immutable-replication"}


def _parser() -> argparse.ArgumentParser:
    """Build the deliberately narrow operator command surface."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "prepare", "deploy", "canary"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--regional-recovery-config", type=Path, required=True)
    parser.add_argument("--profile", default="p1")
    parser.add_argument("--confirm-authority", action="store_true")
    parser.add_argument("--confirm-replication-deployment", action="store_true")
    parser.add_argument("--confirm-retained-canary", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Check, persist, deploy or exercise continuity without activating traffic."""
    arguments = _parser().parse_args(argv)
    try:
        manifest = EvidenceContinuityManifest.parse(arguments.config.read_text(encoding="utf-8"))
        regional = recovery.RegionalRecoveryManifest.parse(
            arguments.regional_recovery_config.read_text(encoding="utf-8")
        )
        resources = discover(manifest, regional, profile=arguments.profile)
        audit = control_deploy.load_persisted_recovery_manifest(
            manifest.primary_stack_name,
            profile=arguments.profile,
            region=manifest.primary_region,
        )
        if audit is None or (
            audit.replica_bucket_arn != resources["recoveryBucketArn"]
            or audit.replica_region != manifest.recovery_region
        ):
            raise EvidenceContinuityDeploymentError("persisted audit recovery authority differs")
        entra = control_deploy.load_persisted_manifest(
            manifest.primary_stack_name,
            profile=arguments.profile,
            region=manifest.primary_region,
        )
        primary_env, replica_env = deployment_environments(
            manifest, resources, profile=arguments.profile, entra=entra, audit=audit
        )
        if arguments.command in {"deploy", "canary"}:
            require_persisted_manifest(manifest, profile=arguments.profile)
        with tempfile.TemporaryDirectory(prefix="aai-evidence-continuity-") as temporary:
            root = Path(temporary)
            infrastructure = _ROOT / "infra" / "aws-control-plane"
            build = subprocess.run(
                ["npm", "run", "build"],  # noqa: S607 - fixed package-manager command
                cwd=infrastructure,
                check=False,
                timeout=300,
            )
            if build.returncode != 0:
                raise EvidenceContinuityDeploymentError("infrastructure build failed")
            replica_path, replica_digest = _synthesize(
                ["npx", "cdk", "--app", "npx ts-node --prefer-ts-exts bin/audit-replica.ts"],
                manifest.recovery_stack_name,
                replica_env,
                root / "recovery",
                runner=subprocess.run,
            )
            primary_path, primary_digest = _synthesize(
                ["npx", "cdk", "--app", "npx ts-node --prefer-ts-exts bin/aws-control-plane.ts"],
                manifest.primary_stack_name,
                primary_env,
                root / "primary",
                runner=subprocess.run,
            )
            replica_evidence = _verify_template(
                replica_path,
                resources["primaryBucketArn"],
                "replicate-recovery-audit-to-primary-region",
            )
            primary_evidence = _verify_template(
                primary_path,
                resources["recoveryBucketArn"],
                "replicate-audit-to-recovery-region",
            )
            if arguments.command == "prepare":
                if not arguments.confirm_authority:
                    raise EvidenceContinuityDeploymentError("--confirm-authority is required")
                persist_manifest(manifest, profile=arguments.profile)
            if arguments.command == "deploy":
                if not arguments.confirm_replication_deployment:
                    raise EvidenceContinuityDeploymentError(
                        "--confirm-replication-deployment is required"
                    )
                _deploy_assembly(
                    manifest.recovery_stack_name,
                    root / "recovery",
                    replica_path,
                    replica_digest,
                    replica_env,
                    runner=subprocess.run,
                )
                _deploy_assembly(
                    manifest.primary_stack_name,
                    root / "primary",
                    primary_path,
                    primary_digest,
                    primary_env,
                    runner=subprocess.run,
                )

        live = None
        if arguments.command in {"deploy", "canary"}:
            live = {
                "primaryToRecovery": verify_live_direction(
                    source_bucket=resources["primaryBucket"],
                    source_region=manifest.primary_region,
                    destination_arn=resources["recoveryBucketArn"],
                    rule_id="replicate-audit-to-recovery-region",
                    profile=arguments.profile,
                ),
                "recoveryToPrimary": verify_live_direction(
                    source_bucket=resources["recoveryBucket"],
                    source_region=manifest.recovery_region,
                    destination_arn=resources["primaryBucketArn"],
                    rule_id="replicate-recovery-audit-to-primary-region",
                    profile=arguments.profile,
                ),
            }
        canary_evidence = None
        if arguments.command == "canary":
            if not arguments.confirm_retained_canary:
                raise EvidenceContinuityDeploymentError("--confirm-retained-canary is required")
            import boto3

            primary_client = boto3.Session(
                profile_name=arguments.profile, region_name=manifest.primary_region
            ).client("s3")
            recovery_client = boto3.Session(
                profile_name=arguments.profile, region_name=manifest.recovery_region
            ).client("s3")
            canary_evidence = {
                "primaryToRecovery": canary.exercise_direction(
                    primary_client,
                    recovery_client,
                    source_bucket=resources["primaryBucket"],
                    destination_bucket=resources["recoveryBucket"],
                    direction="primary-to-recovery",
                    timeout_seconds=300,
                ),
                "recoveryToPrimary": canary.exercise_direction(
                    recovery_client,
                    primary_client,
                    source_bucket=resources["recoveryBucket"],
                    destination_bucket=resources["primaryBucket"],
                    direction="recovery-to-primary",
                    timeout_seconds=300,
                ),
            }
        print(
            json.dumps(
                {
                    "activationPermitted": False,
                    "canary": canary_evidence,
                    "command": arguments.command,
                    "live": live,
                    "primaryTemplate": {**primary_evidence, "templateSha256": primary_digest},
                    "recoveryTemplate": {**replica_evidence, "templateSha256": replica_digest},
                    "status": "evidence-continuity-guard-passed",
                },
                sort_keys=True,
            )
        )
        return 0
    except (
        OSError,
        UnicodeError,
        subprocess.TimeoutExpired,
        control_deploy.DeploymentConfigurationError,
        recovery.RecoveryConfigurationError,
        RuntimeError,
    ) as error:
        print(f"Evidence-continuity guard failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
