#!/usr/bin/env python3
"""Fence the source or deploy a verified active-but-not-routed recovery cell.

Every command repeats the live regional-activation preflight. Mutating commands
require a separate operator confirmation, and this module intentionally has no
DNS, CloudFront, Route 53, Global Accelerator, or traffic-routing operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts import deploy_aws_control_plane as control_plane  # noqa: E402
from scripts import deploy_aws_evidence_continuity as continuity  # noqa: E402
from scripts import deploy_aws_passive_cell as passive  # noqa: E402
from scripts import manage_aws_regional_recovery as recovery  # noqa: E402
from scripts import plan_aws_regional_activation as preflight  # noqa: E402
from scripts import verify_active_regional_cell as active_verifier  # noqa: E402
from scripts import verify_aws_regional_activation as activation  # noqa: E402


class ActiveCellDeploymentError(RuntimeError):
    """Report state that cannot prove a safe, bounded transition step."""


Runner = Callable[..., subprocess.CompletedProcess[str]]
_RESOURCE_LIMITS = {
    "AWS::Lambda::Function": 50,
    "AWS::Lambda::EventSourceMapping": 20,
    "AWS::Events::Rule": 50,
}
_STACK_STABLE = {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
_ACCOUNT = re.compile(r"^\d{12}$")


@dataclass(frozen=True)
class SourceResources:
    """Exact provider-discovered source resources covered by one fence step."""

    functions: tuple[str, ...]
    event_source_mappings: tuple[str, ...]
    event_rules: tuple[str, ...]

    def canonical_json(self) -> str:
        """Return a deterministic representation used to bind fence evidence."""
        return json.dumps(
            {
                "eventRules": list(self.event_rules),
                "eventSourceMappings": list(self.event_source_mappings),
                "functions": list(self.functions),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def sha256(self) -> str:
        """Return the digest of the exact source resource set."""
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()


def _aws(
    arguments: Sequence[str],
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Use the bounded AWS command boundary and normalize provider failures."""
    try:
        return recovery._aws(arguments, profile=profile, region=region, runner=runner)
    except recovery.RecoveryConfigurationError as error:
        raise ActiveCellDeploymentError(str(error)) from error


def discover_source_resources(
    regional: recovery.RegionalRecoveryManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> SourceResources:
    """Discover a stable source stack and its complete bounded fence surface."""
    stack = _aws(
        ["cloudformation", "describe-stacks", "--stack-name", regional.stack_name],
        profile=profile,
        region=regional.primary_region,
        runner=runner,
    ).get("Stacks")
    if (
        not isinstance(stack, list)
        or len(stack) != 1
        or not isinstance(stack[0], dict)
        or stack[0].get("StackStatus") not in _STACK_STABLE
    ):
        raise ActiveCellDeploymentError("source stack is not stable")

    found: dict[str, list[str]] = {kind: [] for kind in _RESOURCE_LIMITS}
    token: str | None = None
    pages = 0
    while True:
        command = [
            "cloudformation",
            "list-stack-resources",
            "--stack-name",
            regional.stack_name,
        ]
        if token is not None:
            command.extend(["--next-token", token])
        response = _aws(
            command,
            profile=profile,
            region=regional.primary_region,
            runner=runner,
        )
        pages += 1
        if pages > 10:
            raise ActiveCellDeploymentError("source resource discovery exceeded 10 pages")
        summaries = response.get("StackResourceSummaries")
        if not isinstance(summaries, list) or len(summaries) > 100:
            raise ActiveCellDeploymentError("source stack resources are malformed")
        for item in summaries:
            if not isinstance(item, dict):
                raise ActiveCellDeploymentError("source stack resource is malformed")
            kind = item.get("ResourceType")
            if kind not in found:
                continue
            physical_id = item.get("PhysicalResourceId")
            if not isinstance(physical_id, str) or not 1 <= len(physical_id) <= 512:
                raise ActiveCellDeploymentError("source fence resource identity is malformed")
            found[kind].append(physical_id)
            if len(found[kind]) > _RESOURCE_LIMITS[kind]:
                raise ActiveCellDeploymentError(f"source fence exceeds the {kind} resource bound")
        next_token = response.get("NextToken")
        if next_token is None:
            break
        if not isinstance(next_token, str) or not next_token or next_token == token:
            raise ActiveCellDeploymentError("source resource pagination is malformed")
        token = next_token

    if not found["AWS::Lambda::Function"]:
        raise ActiveCellDeploymentError("source stack has no Lambda functions to fence")
    if any(len(values) != len(set(values)) for values in found.values()):
        raise ActiveCellDeploymentError("source fence resource identities are duplicated")
    return SourceResources(
        tuple(sorted(found["AWS::Lambda::Function"])),
        tuple(sorted(found["AWS::Lambda::EventSourceMapping"])),
        tuple(sorted(found["AWS::Events::Rule"])),
    )


def verify_source_fence(
    resources: SourceResources,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Independently prove every discovered source execution path is disabled."""
    for rule in resources.event_rules:
        state = _aws(
            ["events", "describe-rule", "--name", rule],
            profile=profile,
            region=region,
            runner=runner,
        ).get("State")
        if state != "DISABLED":
            raise ActiveCellDeploymentError(f"source EventBridge rule is not disabled: {rule}")
    for mapping in resources.event_source_mappings:
        response = _aws(
            ["lambda", "get-event-source-mapping", "--uuid", mapping],
            profile=profile,
            region=region,
            runner=runner,
        )
        if response.get("UUID") != mapping or response.get("State") != "Disabled":
            raise ActiveCellDeploymentError(
                f"source Lambda event-source mapping is not disabled: {mapping}"
            )
    for function in resources.functions:
        concurrency = _aws(
            ["lambda", "get-function-concurrency", "--function-name", function],
            profile=profile,
            region=region,
            runner=runner,
        ).get("ReservedConcurrentExecutions")
        if concurrency != 0:
            raise ActiveCellDeploymentError(f"source Lambda is not concurrency-fenced: {function}")
    return {
        "eventRuleCount": len(resources.event_rules),
        "eventSourceMappingCount": len(resources.event_source_mappings),
        "functionCount": len(resources.functions),
        "resourceSetSha256": resources.sha256(),
        "status": "source-fence-verified",
    }


def fence_source(
    resources: SourceResources,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Disable schedules and event sources before hard-throttling source Lambdas."""
    failures: list[str] = []
    operations = [
        (["events", "disable-rule", "--name", name], f"rule:{name}")
        for name in resources.event_rules
    ]
    operations.extend(
        (
            ["lambda", "update-event-source-mapping", "--uuid", uuid, "--enabled", "false"],
            f"mapping:{uuid}",
        )
        for uuid in resources.event_source_mappings
    )
    operations.extend(
        (
            [
                "lambda",
                "put-function-concurrency",
                "--function-name",
                name,
                "--reserved-concurrent-executions",
                "0",
            ],
            f"function:{name}",
        )
        for name in resources.functions
    )
    for command, label in operations:
        try:
            _aws(command, profile=profile, region=region, runner=runner)
        except ActiveCellDeploymentError:
            failures.append(label)
    if failures:
        # Continue through the bounded set, but never claim a partial fence succeeded.
        raise ActiveCellDeploymentError("source fence mutation failed for: " + ", ".join(failures))
    return verify_source_fence(resources, profile=profile, region=region, runner=runner)


def active_environment(
    manifest: activation.ActivationManifest,
    regional: recovery.RegionalRecoveryManifest,
    passive_cell: passive.PassiveCellManifest,
    verified: dict[str, Any],
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, str]:
    """Derive active CDK inputs only from persisted and provider-verified authority."""
    outputs = recovery.stack_outputs(regional, profile=profile, runner=runner)
    trust = recovery.recovery_stack_outputs(regional, profile=profile, runner=runner)
    account = _aws(
        ["sts", "get-caller-identity"],
        profile=profile,
        region=regional.recovery_region,
        runner=runner,
    ).get("Account")
    if not isinstance(account, str) or not _ACCOUNT.fullmatch(account):
        raise ActiveCellDeploymentError("AWS account identity is malformed")
    entra = control_plane.load_persisted_manifest(
        regional.stack_name,
        profile=profile,
        region=regional.primary_region,
        runner=runner,
    )
    if entra is None:
        raise ActiveCellDeploymentError("persisted Microsoft Entra authority is unavailable")
    key_arn = trust.get("RegionalPolicySigningReplicaKeyArn")
    if verified.get("entraTenantId") != entra.entra_tenant_id:
        raise ActiveCellDeploymentError("retained Entra tenant differs from persisted authority")
    if verified.get("targetSigningKeyArn") != key_arn:
        raise ActiveCellDeploymentError("retained signing key differs from provider authority")
    environment = passive._deployment_environment(passive_cell, regional, outputs, trust, account)
    environment.update(
        {
            "AWS_DEFAULT_REGION": regional.recovery_region,
            "AWS_PROFILE": profile,
            "AWS_REGION": regional.recovery_region,
            "ENTRA_AAI_TENANT_ID": entra.aai_tenant_id,
            "ENTRA_STRONG_AUTH_ENFORCED": "true",
            "ENTRA_TENANT_ID": entra.entra_tenant_id,
            "RECOVERY_ACTIVATION_EVIDENCE_SHA256": manifest.evidence.sha256,
            "RECOVERY_CELL_MODE": "active",
        }
    )
    return environment


def prepare_active_template(
    passive_cell: passive.PassiveCellManifest,
    environment: dict[str, str],
    *,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Synthesize and independently verify one active-but-not-routed assembly."""
    infrastructure = _ROOT / "infra" / "aws-control-plane"
    try:
        result = runner(
            ["npm", "run", "synth:passive", "--", "--quiet"],
            cwd=infrastructure,
            env=environment,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ActiveCellDeploymentError("active-cell synthesis could not run") from error
    if result.returncode != 0:
        raise ActiveCellDeploymentError("active-cell synthesis failed")
    path = infrastructure / "cdk.out" / f"{passive_cell.stack_name}.template.json"
    try:
        payload = path.read_bytes()
        if len(payload) > 5_000_000:
            raise ActiveCellDeploymentError("active-cell template exceeds 5 MB")
        evidence = active_verifier.verify(
            json.loads(payload),
            activation_evidence_sha256=environment["RECOVERY_ACTIVATION_EVIDENCE_SHA256"],
            signing_key_arn=environment["RECOVERY_POLICY_SIGNING_KEY_ARN"],
            entra_tenant_id=environment["ENTRA_TENANT_ID"],
            aai_tenant_id=environment["ENTRA_AAI_TENANT_ID"],
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ActiveCellDeploymentError("synthesized active cell failed verification") from error
    evidence["templateSha256"] = hashlib.sha256(payload).hexdigest()
    return evidence


def deploy_active_template(
    stack_name: str,
    environment: dict[str, str],
    expected_sha256: str,
    *,
    runner: Runner = subprocess.run,
) -> None:
    """Deploy the exact verified assembly without resynthesis or traffic routing."""
    infrastructure = _ROOT / "infra" / "aws-control-plane"
    path = infrastructure / "cdk.out" / f"{stack_name}.template.json"
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise ActiveCellDeploymentError("verified active-cell template is missing") from error
    if digest != expected_sha256:
        raise ActiveCellDeploymentError("active-cell template changed after verification")
    try:
        result = runner(
            [
                "npx",
                "cdk",
                "--app",
                "cdk.out",
                "deploy",
                stack_name,
                "--require-approval",
                "never",
            ],
            cwd=infrastructure,
            env=environment,
            timeout=900,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ActiveCellDeploymentError("active-cell deployment could not run") from error
    if result.returncode != 0:
        raise ActiveCellDeploymentError("active-cell CloudFormation deployment failed")


def _parser() -> argparse.ArgumentParser:
    """Build a three-step command surface with no routing capability."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "fence-source", "activate-target"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--regional-recovery-config", type=Path, required=True)
    parser.add_argument("--evidence-continuity-config", type=Path, required=True)
    parser.add_argument("--passive-cell-config", type=Path, required=True)
    parser.add_argument("--profile", default="p1")
    parser.add_argument("--confirm-source-fence", action="store_true")
    parser.add_argument("--confirm-target-activation", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Repeat preflight, then execute no more than one explicitly confirmed step."""
    arguments = _parser().parse_args(argv)
    try:
        manifest = activation.ActivationManifest.parse(
            arguments.manifest.read_text(encoding="utf-8")
        )
        regional = recovery.RegionalRecoveryManifest.parse(
            arguments.regional_recovery_config.read_text(encoding="utf-8")
        )
        evidence = continuity.EvidenceContinuityManifest.parse(
            arguments.evidence_continuity_config.read_text(encoding="utf-8")
        )
        passive_cell = passive.PassiveCellManifest.parse(
            arguments.passive_cell_config.read_text(encoding="utf-8")
        )
        import boto3

        session = boto3.Session(profile_name=arguments.profile)
        checked = preflight.provider_preflight(
            manifest,
            regional,
            evidence,
            passive_cell,
            profile=arguments.profile,
            s3_factory=lambda region: session.client("s3", region_name=region),
        )
        resources = discover_source_resources(regional, profile=arguments.profile)
        result: dict[str, Any] = {
            "activationExecuted": False,
            "command": arguments.command,
            "preflightStatus": checked["status"],
            "sourceResourceSetSha256": resources.sha256(),
            "trafficRouted": False,
        }
        if arguments.command == "fence-source":
            if not arguments.confirm_source_fence:
                raise ActiveCellDeploymentError("--confirm-source-fence is required")
            result["sourceFence"] = fence_source(
                resources,
                profile=arguments.profile,
                region=regional.primary_region,
            )
        else:
            environment = active_environment(
                manifest,
                regional,
                passive_cell,
                checked["verified"],
                profile=arguments.profile,
            )
            template = prepare_active_template(passive_cell, environment)
            result["template"] = template
            if arguments.command == "activate-target":
                if not arguments.confirm_target_activation:
                    raise ActiveCellDeploymentError("--confirm-target-activation is required")
                result["sourceFence"] = verify_source_fence(
                    resources,
                    profile=arguments.profile,
                    region=regional.primary_region,
                )
                deploy_active_template(
                    passive_cell.stack_name,
                    environment,
                    template["templateSha256"],
                )
                result["activationExecuted"] = True
                result["status"] = "target-active-not-routed"
            else:
                result["status"] = "verified-ready-for-separate-transition-steps"
        print(json.dumps(result, sort_keys=True))
    except (
        OSError,
        UnicodeError,
        activation.RegionalActivationVerificationError,
        recovery.RecoveryConfigurationError,
        continuity.EvidenceContinuityDeploymentError,
        passive.PassiveCellDeploymentError,
        control_plane.DeploymentConfigurationError,
        preflight.RegionalActivationPreflightError,
        ActiveCellDeploymentError,
    ) as error:
        print(f"Active-cell transition guard failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
