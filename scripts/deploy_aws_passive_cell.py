"""Prepare and deploy only the non-serving AWS regional recovery cell.

The guard derives replicated resource identities from provider state, requires
real recovery-region Cognito and Microsoft Entra configuration, and verifies
the synthesized CloudFormation before deployment. It cannot activate traffic,
compute concurrency, event sources, data writes, audit writes or policy signing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from scripts import manage_aws_regional_recovery as recovery  # noqa: E402
from scripts import verify_passive_regional_cell as template_verifier  # noqa: E402


class PassiveCellDeploymentError(RuntimeError):
    """Report configuration or provider state that cannot prove safe staging."""


Runner = Callable[..., subprocess.CompletedProcess[str]]
_FIELDS = {
    "schemaVersion",
    "passiveStackName",
    "primaryRegion",
    "recoveryRegion",
    "recoveryUserPoolId",
    "recoveryUserPoolClientId",
    "approvalEvidenceRef",
    "identityAcceptanceEvidenceRef",
    "activationPermitted",
}
_STACK = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")
_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_POOL_CLIENT = re.compile(r"^[a-z0-9]{10,128}$")
_EVIDENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,511}$")
_ENTRA_ISSUER = re.compile(
    r"^https://login\.microsoftonline\.com/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/v2\.0$",
    re.IGNORECASE,
)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON fields before they create ambiguous authority."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PassiveCellDeploymentError(f"duplicate passive-cell field: {key}")
        result[key] = value
    return result


@dataclass(frozen=True)
class PassiveCellManifest:
    """Secret-free reviewed authority for one non-serving cell deployment."""

    stack_name: str
    primary_region: str
    recovery_region: str
    user_pool_id: str
    user_pool_client_id: str
    approval_evidence_ref: str
    identity_evidence_ref: str

    @classmethod
    def parse(cls, payload: str) -> PassiveCellManifest:
        """Parse the exact schema-v1 non-activation deployment contract."""
        if len(payload.encode("utf-8")) > 16_384:
            raise PassiveCellDeploymentError("passive-cell manifest exceeds 16 KiB")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise PassiveCellDeploymentError("passive-cell manifest is not valid JSON") from error
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise PassiveCellDeploymentError("passive-cell manifest fields do not match schema 1")
        if value["schemaVersion"] != 1 or value["activationPermitted"] is not False:
            raise PassiveCellDeploymentError("manifest must explicitly prohibit activation")
        stack = value["passiveStackName"]
        primary = value["primaryRegion"]
        secondary = value["recoveryRegion"]
        pool = value["recoveryUserPoolId"]
        client = value["recoveryUserPoolClientId"]
        approval = value["approvalEvidenceRef"]
        identity = value["identityAcceptanceEvidenceRef"]
        if stack != "AaiSecPassiveRegionalCell":
            raise PassiveCellDeploymentError(
                "passiveStackName must identify the reviewed passive stack"
            )
        if (
            not isinstance(primary, str)
            or not _REGION.fullmatch(primary)
            or not isinstance(secondary, str)
            or not _REGION.fullmatch(secondary)
            or primary == secondary
        ):
            raise PassiveCellDeploymentError("primary and recovery Regions must be distinct")
        if not isinstance(pool, str) or not pool.startswith(f"{secondary}_"):
            raise PassiveCellDeploymentError("recovery user pool belongs to the wrong Region")
        if not isinstance(client, str) or not _POOL_CLIENT.fullmatch(client):
            raise PassiveCellDeploymentError("recovery user-pool client ID is invalid")
        if not isinstance(approval, str) or not _EVIDENCE.fullmatch(approval):
            raise PassiveCellDeploymentError("approvalEvidenceRef is invalid")
        if not isinstance(identity, str) or not _EVIDENCE.fullmatch(identity):
            raise PassiveCellDeploymentError("identityAcceptanceEvidenceRef is invalid")
        return cls(stack, primary, secondary, pool, client, approval, identity)

    def canonical_json(self) -> str:
        """Return deterministic bytes for encrypted Parameter Store persistence."""
        return json.dumps(
            {
                "activationPermitted": False,
                "approvalEvidenceRef": self.approval_evidence_ref,
                "identityAcceptanceEvidenceRef": self.identity_evidence_ref,
                "passiveStackName": self.stack_name,
                "primaryRegion": self.primary_region,
                "recoveryRegion": self.recovery_region,
                "recoveryUserPoolClientId": self.user_pool_client_id,
                "recoveryUserPoolId": self.user_pool_id,
                "schemaVersion": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def parameter_name(stack_name: str) -> str:
    """Return the stack-specific encrypted deployment-authority path."""
    if not _STACK.fullmatch(stack_name):
        raise PassiveCellDeploymentError("passiveStackName is invalid")
    return f"/aai-sec/{stack_name}/passive-cell"


def _aws(
    arguments: Sequence[str],
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Use the regional-recovery AWS boundary and normalize its errors."""
    try:
        return recovery._aws(arguments, profile=profile, region=region, runner=runner)
    except recovery.RecoveryConfigurationError as error:
        raise PassiveCellDeploymentError(str(error)) from error


def _stack_output(response: dict[str, Any], name: str) -> str:
    """Return one exact CloudFormation output without accepting duplicates."""
    stacks = response.get("Stacks")
    if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], dict):
        raise PassiveCellDeploymentError("expected exactly one CloudFormation stack")
    outputs = stacks[0].get("Outputs")
    if not isinstance(outputs, list) or len(outputs) > 100:
        raise PassiveCellDeploymentError("CloudFormation outputs are malformed")
    matches = [
        item.get("OutputValue")
        for item in outputs
        if isinstance(item, dict) and item.get("OutputKey") == name
    ]
    if len(matches) != 1 or not isinstance(matches[0], str):
        raise PassiveCellDeploymentError(f"required stack output is missing: {name}")
    return matches[0]


def _pool_security_profile(pool: dict[str, Any]) -> str:
    """Return the comparable fail-closed configuration of one Cognito pool."""

    def canonical(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: canonical(item) for key, item in sorted(value.items())}
        if isinstance(value, list):
            items = [canonical(item) for item in value]
            return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, default=str))
        return value

    fields = {
        name: canonical(pool.get(name))
        for name in (
            "AccountRecoverySetting",
            "AutoVerifiedAttributes",
            "MfaConfiguration",
            "Policies",
            "SchemaAttributes",
            "UsernameAttributes",
            "UsernameConfiguration",
            "UserAttributeUpdateSettings",
        )
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)


def verify_recovery_identity(
    manifest: PassiveCellManifest,
    *,
    primary_stack_name: str,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, str]:
    """Prove recovery Cognito, Entra federation and primary SCIM are configured."""
    primary = _aws(
        ["cloudformation", "describe-stacks", "--stack-name", primary_stack_name],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )
    if _stack_output(primary, "MicrosoftEntraIdStatus") != "configured":
        raise PassiveCellDeploymentError("primary Microsoft Entra federation is not configured")
    if _stack_output(primary, "MicrosoftEntraScimStatus") != "configured":
        raise PassiveCellDeploymentError("primary Microsoft Entra SCIM is not configured")
    primary_pool_id = _stack_output(primary, "UserPoolId")
    if primary_pool_id == manifest.user_pool_id:
        raise PassiveCellDeploymentError("primary and recovery user pools must be distinct")

    primary_pool_response = _aws(
        ["cognito-idp", "describe-user-pool", "--user-pool-id", primary_pool_id],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )
    primary_pool = primary_pool_response.get("UserPool")
    if not isinstance(primary_pool, dict) or primary_pool.get("Id") != primary_pool_id:
        raise PassiveCellDeploymentError("primary user pool identity is malformed")

    pool_response = _aws(
        ["cognito-idp", "describe-user-pool", "--user-pool-id", manifest.user_pool_id],
        profile=profile,
        region=manifest.recovery_region,
        runner=runner,
    )
    pool = pool_response.get("UserPool")
    if (
        not isinstance(pool, dict)
        or pool.get("Id") != manifest.user_pool_id
        or pool.get("DeletionProtection") != "ACTIVE"
        or pool.get("MfaConfiguration") not in {"ON", "OPTIONAL"}
    ):
        raise PassiveCellDeploymentError("recovery user pool is not protected with MFA")
    if primary_pool.get("DeletionProtection") != "ACTIVE" or _pool_security_profile(
        primary_pool
    ) != _pool_security_profile(pool):
        raise PassiveCellDeploymentError(
            "primary and recovery user-pool security configuration differs"
        )

    client_response = _aws(
        [
            "cognito-idp",
            "describe-user-pool-client",
            "--user-pool-id",
            manifest.user_pool_id,
            "--client-id",
            manifest.user_pool_client_id,
        ],
        profile=profile,
        region=manifest.recovery_region,
        runner=runner,
    )
    client = client_response.get("UserPoolClient")
    providers = client.get("SupportedIdentityProviders") if isinstance(client, dict) else None
    if (
        not isinstance(client, dict)
        or client.get("ClientId") != manifest.user_pool_client_id
        or not isinstance(providers, list)
        or "MicrosoftEntraID" not in providers
    ):
        raise PassiveCellDeploymentError("recovery app client is not bound to Microsoft Entra")

    primary_provider_response = _aws(
        [
            "cognito-idp",
            "describe-identity-provider",
            "--user-pool-id",
            primary_pool_id,
            "--provider-name",
            "MicrosoftEntraID",
        ],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )
    primary_provider = primary_provider_response.get("IdentityProvider")
    primary_details = (
        primary_provider.get("ProviderDetails") if isinstance(primary_provider, dict) else None
    )
    primary_issuer = (
        primary_details.get("oidc_issuer") if isinstance(primary_details, dict) else None
    )
    provider_response = _aws(
        [
            "cognito-idp",
            "describe-identity-provider",
            "--user-pool-id",
            manifest.user_pool_id,
            "--provider-name",
            "MicrosoftEntraID",
        ],
        profile=profile,
        region=manifest.recovery_region,
        runner=runner,
    )
    provider = provider_response.get("IdentityProvider")
    details = provider.get("ProviderDetails") if isinstance(provider, dict) else None
    issuer = details.get("oidc_issuer") if isinstance(details, dict) else None
    if (
        not isinstance(provider, dict)
        or provider.get("ProviderType") != "OIDC"
        or not isinstance(issuer, str)
        or not _ENTRA_ISSUER.fullmatch(issuer)
        or issuer != primary_issuer
    ):
        raise PassiveCellDeploymentError(
            "recovery Microsoft Entra issuer is not the primary tenant-specific issuer"
        )
    return {
        "userPoolId": manifest.user_pool_id,
        "userPoolClientId": manifest.user_pool_client_id,
        "identityProvider": "MicrosoftEntraID",
        "status": "configured-not-activated",
    }


def persist_manifest(
    manifest: PassiveCellManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> None:
    """Persist the reviewed secret-free staging authority as a SecureString."""
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
            "AAI Security non-serving passive-cell deployment authority",
        ],
        profile=profile,
        region=manifest.primary_region,
        runner=runner,
    )


def require_persisted_manifest(
    manifest: PassiveCellManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> None:
    """Fail when deployment input differs from persisted reviewed authority."""
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
        raise PassiveCellDeploymentError("persisted passive-cell authority is missing")
    persisted = PassiveCellManifest.parse(payload)
    if persisted.canonical_json() != manifest.canonical_json():
        raise PassiveCellDeploymentError("manifest differs from persisted deployment authority")


def _deployment_environment(
    manifest: PassiveCellManifest,
    regional_manifest: recovery.RegionalRecoveryManifest,
    outputs: dict[str, str],
    trust_outputs: dict[str, str],
    account_id: str,
) -> dict[str, str]:
    """Build an exact environment without trusting ambient authority fields."""
    environment = os.environ.copy()
    for name in (
        "RECOVERY_AWS_ACCOUNT_ID",
        "RECOVERY_REGION",
        "PRIMARY_REGION",
        "RECOVERY_CONTROL_TABLE",
        "RECOVERY_PRESENCE_TABLE",
        "RECOVERY_IDEMPOTENCY_TABLE",
        "RECOVERY_SCIM_TABLE",
        "RECOVERY_AUDIT_BUCKET",
        "RECOVERY_POLICY_SIGNING_KEY_ARN",
        "RECOVERY_ASSURANCE_REPORT_SIGNING_KEY_ARN",
        "RECOVERY_ASSURANCE_REPORT_HISTORICAL_VERIFICATION_KEY_ARNS",
        "RECOVERY_USER_POOL_ID",
        "RECOVERY_USER_POOL_CLIENT_ID",
        "RECOVERY_CELL_MODE",
        "RECOVERY_ACTIVATION_EVIDENCE_SHA256",
        "ENTRA_TENANT_ID",
        "ENTRA_AAI_TENANT_ID",
        "ENTRA_STRONG_AUTH_ENFORCED",
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "CDK_DEFAULT_ACCOUNT",
        "CDK_DEFAULT_REGION",
    ):
        environment.pop(name, None)
    audit_arn = outputs["AuditReplicaBucketArn"]
    if not audit_arn.startswith("arn:aws:s3:::"):
        raise PassiveCellDeploymentError("audit replica bucket ARN is malformed")
    environment.update(
        {
            "RECOVERY_AWS_ACCOUNT_ID": account_id,
            "RECOVERY_REGION": manifest.recovery_region,
            "PRIMARY_REGION": manifest.primary_region,
            "RECOVERY_CONTROL_TABLE": outputs["ControlTableName"],
            "RECOVERY_PRESENCE_TABLE": outputs["PresenceTableName"],
            "RECOVERY_IDEMPOTENCY_TABLE": outputs["IdempotencyTableName"],
            "RECOVERY_SCIM_TABLE": outputs["ScimLifecycleTableName"],
            "RECOVERY_AUDIT_BUCKET": audit_arn.removeprefix("arn:aws:s3:::"),
            "RECOVERY_POLICY_SIGNING_KEY_ARN": trust_outputs["RegionalPolicySigningReplicaKeyArn"],
            "RECOVERY_ASSURANCE_REPORT_SIGNING_KEY_ARN": trust_outputs[
                "AssuranceReportSigningReplicaKeyArn"
            ],
            "RECOVERY_ASSURANCE_REPORT_HISTORICAL_VERIFICATION_KEY_ARNS": trust_outputs[
                "AssuranceReportHistoricalVerificationReplicaKeyArns"
            ],
            "RECOVERY_USER_POOL_ID": manifest.user_pool_id,
            "RECOVERY_USER_POOL_CLIENT_ID": manifest.user_pool_client_id,
            "RECOVERY_CELL_MODE": "standby",
        }
    )
    if (
        regional_manifest.primary_region != manifest.primary_region
        or regional_manifest.recovery_region != manifest.recovery_region
    ):
        raise PassiveCellDeploymentError("identity and regional-recovery manifests disagree")
    return environment


def prepare_synth(
    manifest: PassiveCellManifest,
    regional_manifest: recovery.RegionalRecoveryManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Verify provider state, synthesize and inspect the non-serving template."""
    try:
        recovery.load_persisted_manifest(regional_manifest, profile=profile, runner=runner)
        outputs = recovery.stack_outputs(regional_manifest, profile=profile, runner=runner)
        trust_outputs = recovery.recovery_stack_outputs(
            regional_manifest, profile=profile, runner=runner
        )
        for role, output in recovery._OUTPUT_TABLES.items():
            recovery.verify_table_posture(
                role, outputs[output], regional_manifest, profile=profile, runner=runner
            )
        recovery.verify_signing_replica(
            outputs["RegionalPolicySigningKeyArn"],
            trust_outputs["RegionalPolicySigningReplicaKeyArn"],
            regional_manifest,
            profile=profile,
            runner=runner,
        )
        recovery.verify_signing_replica(
            outputs["AssuranceReportSigningKeyArn"],
            trust_outputs["AssuranceReportSigningReplicaKeyArn"],
            regional_manifest,
            profile=profile,
            runner=runner,
        )
        primary_history = recovery._key_arn_list(
            outputs["AssuranceReportHistoricalVerificationKeyArns"],
            "primary historical assurance key registry",
        )
        recovery_history = recovery._key_arn_list(
            trust_outputs["AssuranceReportHistoricalVerificationReplicaKeyArns"],
            "recovery historical assurance key registry",
        )
        if len(primary_history) != len(recovery_history):
            raise PassiveCellDeploymentError("historical assurance replica count differs")
        for primary_key, replica_key in zip(primary_history, recovery_history, strict=True):
            recovery.verify_signing_replica(
                primary_key,
                replica_key,
                regional_manifest,
                profile=profile,
                runner=runner,
            )
    except recovery.RecoveryConfigurationError as error:
        raise PassiveCellDeploymentError(str(error)) from error
    identity = verify_recovery_identity(
        manifest,
        primary_stack_name=regional_manifest.stack_name,
        profile=profile,
        runner=runner,
    )
    caller = _aws(
        ["sts", "get-caller-identity"],
        profile=profile,
        region=manifest.recovery_region,
        runner=runner,
    )
    account = caller.get("Account")
    if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account):
        raise PassiveCellDeploymentError("AWS account identity is malformed")
    environment = _deployment_environment(
        manifest, regional_manifest, outputs, trust_outputs, account
    )
    environment.update(
        {
            "AWS_PROFILE": profile,
            "AWS_REGION": manifest.recovery_region,
            "AWS_DEFAULT_REGION": manifest.recovery_region,
        }
    )
    infrastructure = Path(__file__).resolve().parents[1] / "infra" / "aws-control-plane"
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
        raise PassiveCellDeploymentError("passive-cell synthesis could not run") from error
    if result.returncode != 0:
        raise PassiveCellDeploymentError("passive-cell synthesis failed")
    template_path = infrastructure / "cdk.out" / f"{manifest.stack_name}.template.json"
    try:
        template_bytes = template_path.read_bytes()
        if len(template_bytes) > 5_000_000:
            raise PassiveCellDeploymentError("synthesized passive cell exceeds 5 MB")
        template = json.loads(template_bytes)
        template_evidence = template_verifier.verify(template)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise PassiveCellDeploymentError("synthesized passive cell failed verification") from error
    template_evidence["templateSha256"] = hashlib.sha256(template_bytes).hexdigest()
    return {"identity": identity, "template": template_evidence, "environment": environment}


def deploy(
    manifest: PassiveCellManifest,
    environment: dict[str, str],
    expected_template_sha256: str,
    *,
    runner: Runner = subprocess.run,
) -> None:
    """Deploy the exact verified assembly without adding activation authority."""
    infrastructure = Path(__file__).resolve().parents[1] / "infra" / "aws-control-plane"
    template_path = infrastructure / "cdk.out" / f"{manifest.stack_name}.template.json"
    try:
        current_digest = hashlib.sha256(template_path.read_bytes()).hexdigest()
    except OSError as error:
        raise PassiveCellDeploymentError("verified passive-cell template is missing") from error
    if current_digest != expected_template_sha256:
        raise PassiveCellDeploymentError("passive-cell template changed after verification")
    try:
        result = runner(
            [
                "npx",
                "cdk",
                "--app",
                "cdk.out",
                "deploy",
                manifest.stack_name,
                "--require-approval",
                "never",
            ],
            cwd=infrastructure,
            env=environment,
            timeout=900,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PassiveCellDeploymentError("passive-cell deployment could not run") from error
    if result.returncode != 0:
        raise PassiveCellDeploymentError("passive-cell CloudFormation deployment failed")


def _parser() -> argparse.ArgumentParser:
    """Build the deliberately narrow operator command surface."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "prepare", "deploy"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--regional-recovery-config", type=Path, required=True)
    parser.add_argument("--profile", default="p1")
    parser.add_argument("--confirm-identity-foundation", action="store_true")
    parser.add_argument("--confirm-non-serving-deployment", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Check, persist or deploy only after every independent guard passes."""
    arguments = _parser().parse_args(argv)
    try:
        manifest = PassiveCellManifest.parse(arguments.config.read_text(encoding="utf-8"))
        regional_manifest = recovery.RegionalRecoveryManifest.parse(
            arguments.regional_recovery_config.read_text(encoding="utf-8")
        )
        if arguments.command == "deploy":
            if not arguments.confirm_non_serving_deployment:
                raise PassiveCellDeploymentError("--confirm-non-serving-deployment is required")
            require_persisted_manifest(manifest, profile=arguments.profile)
        evidence = prepare_synth(manifest, regional_manifest, profile=arguments.profile)
        if arguments.command == "prepare":
            if not arguments.confirm_identity_foundation:
                raise PassiveCellDeploymentError("--confirm-identity-foundation is required")
            persist_manifest(manifest, profile=arguments.profile)
        elif arguments.command == "deploy":
            deploy(
                manifest,
                evidence["environment"],
                evidence["template"]["templateSha256"],
            )
        safe_evidence = {
            "command": arguments.command,
            "identity": evidence["identity"],
            "stackName": manifest.stack_name,
            "status": "staged-not-serving",
            "template": evidence["template"],
        }
        print(json.dumps(safe_evidence, sort_keys=True))
    except (
        OSError,
        UnicodeError,
        recovery.RecoveryConfigurationError,
        PassiveCellDeploymentError,
    ) as error:
        print(f"Passive-cell guard failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
