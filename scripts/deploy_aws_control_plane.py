"""Safely configure and deploy the AWS control plane with persistent Entra identity.

The deployment manifest contains identifiers and secret *names*, never secret
values. It is stored as an encrypted SSM parameter so a later routine deploy
cannot accidentally remove a configured identity provider merely because one
operator shell omitted ephemeral environment variables.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID


class DeploymentConfigurationError(ValueError):
    """Raised when identity deployment input cannot prove a safe configuration."""


Runner = Callable[..., subprocess.CompletedProcess[str]]
UrlOpener = Callable[..., Any]
_MANIFEST_FIELDS = {
    "schemaVersion",
    "entraTenantId",
    "entraClientId",
    "entraClientSecretName",
    "aaiTenantId",
    "entraScimTokenSecretName",
    "strongAuthenticationEnforced",
    "conditionalAccessEvidenceRef",
}
_AWS_SECRET_NAME = re.compile(r"^[A-Za-z0-9/_+=.@-]{1,512}$")
_AAI_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_EVIDENCE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,511}$")
_AWS_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/+-]{0,127}$")
_AWS_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_ENTRA_ENVIRONMENT_FIELDS = (
    "ENTRA_TENANT_ID",
    "ENTRA_CLIENT_ID",
    "ENTRA_CLIENT_SECRET_NAME",
    "ENTRA_AAI_TENANT_ID",
    "ENTRA_SCIM_TOKEN_SECRET_NAME",
    "ENTRA_STRONG_AUTH_ENFORCED",
)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys before they can create ambiguous authority."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeploymentConfigurationError(f"duplicate manifest field: {key}")
        result[key] = value
    return result


def _uuid(value: object, field: str) -> str:
    """Return one canonical UUID or reject aliases and tenant-independent values."""
    if not isinstance(value, str):
        raise DeploymentConfigurationError(f"{field} must be a UUID string")
    try:
        canonical = str(UUID(value))
    except ValueError as error:
        raise DeploymentConfigurationError(f"{field} must be a canonical UUID") from error
    if value.lower() != canonical:
        raise DeploymentConfigurationError(f"{field} must use canonical UUID spelling")
    return canonical


def _bounded_string(value: object, field: str, *, maximum: int = 256) -> str:
    """Validate one non-empty, trimmed manifest string."""
    if not isinstance(value, str) or value != value.strip() or not 1 <= len(value) <= maximum:
        raise DeploymentConfigurationError(f"{field} must be a bounded non-empty string")
    return value


@dataclass(frozen=True)
class EntraDeploymentManifest:
    """Typed, secret-free identity configuration persisted for repeatable deployment."""

    entra_tenant_id: str
    entra_client_id: str
    entra_client_secret_name: str
    aai_tenant_id: str
    entra_scim_token_secret_name: str
    conditional_access_evidence_ref: str

    @classmethod
    def parse(cls, payload: str) -> EntraDeploymentManifest:
        """Parse a strict schema-v1 manifest and require the enterprise-safe posture."""
        if len(payload.encode("utf-8")) > 16_384:
            raise DeploymentConfigurationError("manifest exceeds the 16 KiB bound")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise DeploymentConfigurationError("manifest is not valid JSON") from error
        if not isinstance(value, dict) or set(value) != _MANIFEST_FIELDS:
            raise DeploymentConfigurationError(
                "manifest fields do not exactly match schema version 1"
            )
        if value["schemaVersion"] != 1:
            raise DeploymentConfigurationError("manifest schemaVersion must be 1")
        if value["strongAuthenticationEnforced"] is not True:
            raise DeploymentConfigurationError(
                "strongAuthenticationEnforced must be true for an enterprise deployment"
            )
        client_secret = _bounded_string(value["entraClientSecretName"], "entraClientSecretName")
        scim_secret = _bounded_string(value["entraScimTokenSecretName"], "entraScimTokenSecretName")
        if not _AWS_SECRET_NAME.fullmatch(client_secret) or not _AWS_SECRET_NAME.fullmatch(
            scim_secret
        ):
            raise DeploymentConfigurationError(
                "Secrets Manager names contain unsupported characters"
            )
        if client_secret == scim_secret:
            raise DeploymentConfigurationError("OIDC and SCIM must use separate secrets")
        aai_tenant = _bounded_string(value["aaiTenantId"], "aaiTenantId", maximum=128)
        if not _AAI_TENANT.fullmatch(aai_tenant):
            raise DeploymentConfigurationError("aaiTenantId has an unsupported format")
        evidence_reference = _bounded_string(
            value["conditionalAccessEvidenceRef"],
            "conditionalAccessEvidenceRef",
            maximum=512,
        )
        if not _EVIDENCE_REFERENCE.fullmatch(evidence_reference):
            raise DeploymentConfigurationError(
                "conditionalAccessEvidenceRef must be an opaque non-secret reference"
            )
        return cls(
            entra_tenant_id=_uuid(value["entraTenantId"], "entraTenantId"),
            entra_client_id=_uuid(value["entraClientId"], "entraClientId"),
            entra_client_secret_name=client_secret,
            aai_tenant_id=aai_tenant,
            entra_scim_token_secret_name=scim_secret,
            conditional_access_evidence_ref=evidence_reference,
        )

    def canonical_json(self) -> str:
        """Return the stable secret-free representation stored in Parameter Store."""
        return json.dumps(
            {
                "aaiTenantId": self.aai_tenant_id,
                "conditionalAccessEvidenceRef": self.conditional_access_evidence_ref,
                "entraClientId": self.entra_client_id,
                "entraClientSecretName": self.entra_client_secret_name,
                "entraScimTokenSecretName": self.entra_scim_token_secret_name,
                "entraTenantId": self.entra_tenant_id,
                "schemaVersion": 1,
                "strongAuthenticationEnforced": True,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def deployment_environment(self) -> dict[str, str]:
        """Return only non-secret CDK environment values and secret references."""
        return {
            "ENTRA_TENANT_ID": self.entra_tenant_id,
            "ENTRA_CLIENT_ID": self.entra_client_id,
            "ENTRA_CLIENT_SECRET_NAME": self.entra_client_secret_name,
            "ENTRA_AAI_TENANT_ID": self.aai_tenant_id,
            "ENTRA_SCIM_TOKEN_SECRET_NAME": self.entra_scim_token_secret_name,
            "ENTRA_STRONG_AUTH_ENFORCED": "true",
        }


def _aws(
    arguments: Sequence[str],
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Run one fixed AWS CLI operation and decode its bounded JSON response."""
    if not _AWS_PROFILE.fullmatch(profile) or not _AWS_REGION.fullmatch(region):
        raise DeploymentConfigurationError("AWS profile or region is malformed")
    command = ["aws", *arguments, "--profile", profile, "--region", region, "--output", "json"]
    result = runner(command, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        message = (
            result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "AWS CLI failed"
        )
        raise DeploymentConfigurationError(message[:500])
    if len(result.stdout.encode("utf-8")) > 1_048_576:
        raise DeploymentConfigurationError("AWS CLI response exceeds the 1 MiB bound")
    try:
        value = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as error:
        raise DeploymentConfigurationError("AWS CLI returned malformed JSON") from error
    if not isinstance(value, dict):
        raise DeploymentConfigurationError("AWS CLI returned an unexpected response")
    return value


def parameter_name(stack_name: str) -> str:
    """Return the stack-specific encrypted identity configuration path."""
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}", stack_name):
        raise DeploymentConfigurationError("stack name is invalid")
    return f"/aai-sec/{stack_name}/entra-deployment"


def stack_outputs(
    stack_name: str,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
    allow_missing: bool = False,
) -> dict[str, str]:
    """Return bounded stack outputs without exposing resource secrets."""
    try:
        response = _aws(
            ["cloudformation", "describe-stacks", "--stack-name", stack_name],
            profile=profile,
            region=region,
            runner=runner,
        )
    except DeploymentConfigurationError as error:
        if allow_missing and "does not exist" in str(error):
            return {}
        raise
    stacks = response.get("Stacks")
    if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], dict):
        raise DeploymentConfigurationError("expected exactly one deployed control-plane stack")
    outputs = stacks[0].get("Outputs", [])
    if not isinstance(outputs, list) or len(outputs) > 100:
        raise DeploymentConfigurationError("stack outputs are malformed or oversized")
    result: dict[str, str] = {}
    for item in outputs:
        if not isinstance(item, dict):
            raise DeploymentConfigurationError("stack output is malformed")
        key, value = item.get("OutputKey"), item.get("OutputValue")
        if not isinstance(key, str) or not isinstance(value, str) or key in result:
            raise DeploymentConfigurationError("stack output identity is ambiguous")
        result[key] = value
    return result


def load_persisted_manifest(
    stack_name: str, *, profile: str, region: str, runner: Runner = subprocess.run
) -> EntraDeploymentManifest | None:
    """Load the encrypted deployment manifest, returning None only when absent."""
    name = parameter_name(stack_name)
    command = [
        "aws",
        "ssm",
        "get-parameter",
        "--name",
        name,
        "--with-decryption",
        "--profile",
        profile,
        "--region",
        region,
        "--output",
        "json",
    ]
    result = runner(command, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        error = result.stderr
        if "ParameterNotFound" in error:
            return None
        raise DeploymentConfigurationError((error.strip() or "SSM lookup failed")[-500:])
    try:
        response = json.loads(result.stdout)
        payload = response["Parameter"]["Value"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise DeploymentConfigurationError("persisted Entra manifest is malformed") from error
    if not isinstance(payload, str):
        raise DeploymentConfigurationError("persisted Entra manifest is not text")
    return EntraDeploymentManifest.parse(payload)


def _secret_value(name: str, *, profile: str, region: str, runner: Runner = subprocess.run) -> str:
    """Read a secret only into memory for shape validation and never print it."""
    response = _aws(
        ["secretsmanager", "get-secret-value", "--secret-id", name],
        profile=profile,
        region=region,
        runner=runner,
    )
    value = response.get("SecretString")
    if not isinstance(value, str):
        raise DeploymentConfigurationError(f"secret {name} must contain SecretString text")
    return value


def _scim_token(secret: str) -> str:
    """Accept a plain bearer or the runbook's exact one-field JSON representation."""
    token = secret
    if secret.startswith("{"):
        try:
            value = json.loads(secret, object_pairs_hook=_strict_object)
        except json.JSONDecodeError as error:
            raise DeploymentConfigurationError("SCIM secret contains malformed JSON") from error
        if (
            not isinstance(value, dict)
            or set(value) != {"token"}
            or not isinstance(value["token"], str)
        ):
            raise DeploymentConfigurationError("SCIM JSON secret must contain only token")
        token = value["token"]
    if (
        not 32 <= len(token) <= 512
        or token != token.strip()
        or any(ord(character) < 33 or ord(character) > 126 for character in token)
    ):
        raise DeploymentConfigurationError(
            "SCIM bearer must be 32-512 visible non-whitespace ASCII characters"
        )
    return token


def verify_oidc_metadata(tenant_id: str, *, opener: UrlOpener = urllib.request.urlopen) -> None:
    """Verify bounded tenant-specific Microsoft OIDC discovery before deployment."""
    expected_issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    url = f"{expected_issuer}/.well-known/openid-configuration"
    # Both scheme and host are fixed above; tenant_id is a canonical UUID.
    request = urllib.request.Request(  # noqa: S310 - exact HTTPS Microsoft authority
        url, headers={"Accept": "application/json"}
    )
    try:
        with opener(request, timeout=5) as response:
            resolved_url = response.geturl()
            payload = response.read(65_537)
    except (OSError, urllib.error.URLError) as error:
        raise DeploymentConfigurationError("tenant-specific Entra OIDC discovery failed") from error
    if len(payload) > 65_536:
        raise DeploymentConfigurationError("Entra OIDC discovery response exceeds 64 KiB")
    if resolved_url != url:
        raise DeploymentConfigurationError("Entra OIDC discovery redirect is not allowed")
    try:
        metadata = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise DeploymentConfigurationError(
            "Entra OIDC discovery returned malformed JSON"
        ) from error
    if not isinstance(metadata, dict) or metadata.get("issuer") != expected_issuer:
        raise DeploymentConfigurationError("Entra OIDC issuer does not match the configured tenant")
    required = {
        "authorization_endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
        "token_endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        "jwks_uri": f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
    }
    if any(metadata.get(key) != value for key, value in required.items()):
        raise DeploymentConfigurationError("Entra OIDC metadata endpoints are not tenant-bound")


def preflight(
    manifest: EntraDeploymentManifest,
    stack_name: str,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
    opener: UrlOpener = urllib.request.urlopen,
) -> dict[str, str]:
    """Verify secrets, tenant existence and OIDC provenance without changing AWS."""
    outputs = stack_outputs(stack_name, profile=profile, region=region, runner=runner)
    control_table = outputs.get("ControlTableName")
    if not control_table:
        raise DeploymentConfigurationError("ControlTableName stack output is missing")
    oidc_secret = _secret_value(
        manifest.entra_client_secret_name, profile=profile, region=region, runner=runner
    )
    if (
        not 1 <= len(oidc_secret) <= 4096
        or oidc_secret != oidc_secret.strip()
        or oidc_secret.startswith(("{", "["))
        or any(ord(character) < 33 or ord(character) > 126 for character in oidc_secret)
    ):
        raise DeploymentConfigurationError("OIDC client secret has an invalid shape")
    _scim_token(
        _secret_value(
            manifest.entra_scim_token_secret_name,
            profile=profile,
            region=region,
            runner=runner,
        )
    )
    tenant = _aws(
        [
            "dynamodb",
            "get-item",
            "--table-name",
            control_table,
            "--key",
            json.dumps(
                {
                    "pk": {"S": f"TENANT#{manifest.aai_tenant_id}"},
                    "sk": {"S": "TENANT#root"},
                },
                separators=(",", ":"),
            ),
            "--consistent-read",
        ],
        profile=profile,
        region=region,
        runner=runner,
    )
    if not isinstance(tenant.get("Item"), dict):
        raise DeploymentConfigurationError("bound AAI tenant does not exist")
    verify_oidc_metadata(manifest.entra_tenant_id, opener=opener)
    return outputs


def persist_manifest(
    manifest: EntraDeploymentManifest,
    stack_name: str,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> None:
    """Persist only the reviewed non-secret manifest as an encrypted parameter."""
    _aws(
        [
            "ssm",
            "put-parameter",
            "--name",
            parameter_name(stack_name),
            "--type",
            "SecureString",
            "--overwrite",
            "--value",
            manifest.canonical_json(),
            "--description",
            "Persistent AAI Security Microsoft Entra deployment references",
        ],
        profile=profile,
        region=region,
        runner=runner,
    )


def deploy(
    stack_name: str,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> EntraDeploymentManifest | None:
    """Deploy with persisted identity configuration or refuse destructive omission."""
    manifest = load_persisted_manifest(stack_name, profile=profile, region=region, runner=runner)
    outputs = stack_outputs(
        stack_name,
        profile=profile,
        region=region,
        runner=runner,
        allow_missing=True,
    )
    if manifest is None and outputs.get("MicrosoftEntraIdStatus") == "configured":
        raise DeploymentConfigurationError(
            "stack has Entra configured but its persistent deployment manifest is missing"
        )
    environment = os.environ.copy()
    # Ambient shell state is not deployment authority. Remove every legacy
    # identity field before optionally loading the persisted reviewed manifest.
    for field in _ENTRA_ENVIRONMENT_FIELDS:
        environment.pop(field, None)
    environment.update({"AWS_PROFILE": profile, "AWS_REGION": region})
    if manifest is not None:
        preflight(
            manifest,
            stack_name,
            profile=profile,
            region=region,
            runner=runner,
        )
        environment.update(manifest.deployment_environment())
    root = Path(__file__).resolve().parents[1]
    infrastructure = root / "infra" / "aws-control-plane"
    for command in (
        ["npm", "run", "build"],
        ["npx", "cdk", "deploy", stack_name, "--require-approval", "never"],
    ):
        result = runner(command, cwd=infrastructure, env=environment, check=False)
        if result.returncode != 0:
            raise DeploymentConfigurationError(f"deployment command failed: {' '.join(command)}")
    post = stack_outputs(stack_name, profile=profile, region=region, runner=runner)
    if manifest is not None and (
        post.get("MicrosoftEntraIdStatus") != "configured"
        or post.get("MicrosoftEntraScimStatus") != "configured"
        or not post.get("MicrosoftEntraScimEndpoint", "").startswith("https://")
    ):
        raise DeploymentConfigurationError("deployed Entra/SCIM posture is incomplete")
    return manifest


def _parser() -> argparse.ArgumentParser:
    """Build the intentionally small deployment command surface."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "configure", "deploy", "status"))
    parser.add_argument("--config", type=Path)
    parser.add_argument("--profile", default=os.environ.get("AWS_PROFILE", "p1"))
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "eu-west-2"))
    parser.add_argument("--stack-name", default="AaiSecControlPlane")
    parser.add_argument(
        "--confirm-conditional-access",
        action="store_true",
        help="Confirm the evidence reference points to an MFA-enforcing Conditional Access review",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Validate, persist, deploy or inspect the enterprise identity configuration."""
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command in {"check", "configure"}:
            if arguments.config is None:
                raise DeploymentConfigurationError("--config is required")
            payload = arguments.config.read_text(encoding="utf-8")
            candidate_manifest = EntraDeploymentManifest.parse(payload)
            preflight(
                candidate_manifest,
                arguments.stack_name,
                profile=arguments.profile,
                region=arguments.region,
            )
            if arguments.command == "configure":
                if not arguments.confirm_conditional_access:
                    raise DeploymentConfigurationError(
                        "--confirm-conditional-access is required before persistence"
                    )
                persist_manifest(
                    candidate_manifest,
                    arguments.stack_name,
                    profile=arguments.profile,
                    region=arguments.region,
                )
            print(
                f"Entra deployment {arguments.command} passed for stack "
                f"{arguments.stack_name}; no secret values were emitted."
            )
        elif arguments.command == "deploy":
            active_manifest = deploy(
                arguments.stack_name, profile=arguments.profile, region=arguments.region
            )
            state = "configured" if active_manifest else "not configured"
            print(f"AWS control-plane deployment completed; Entra is {state}.")
        else:
            deployed_manifest = load_persisted_manifest(
                arguments.stack_name, profile=arguments.profile, region=arguments.region
            )
            outputs = stack_outputs(
                arguments.stack_name, profile=arguments.profile, region=arguments.region
            )
            print(
                json.dumps(
                    {
                        "manifest": "configured" if deployed_manifest else "not-configured",
                        "oidc": outputs.get("MicrosoftEntraIdStatus", "unknown"),
                        "scim": outputs.get("MicrosoftEntraScimStatus", "unknown"),
                        "strongAuthentication": (
                            "declared-reviewed" if deployed_manifest else "not-configured"
                        ),
                    },
                    sort_keys=True,
                )
            )
    except (DeploymentConfigurationError, OSError) as error:
        print(f"Entra deployment FAILED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
