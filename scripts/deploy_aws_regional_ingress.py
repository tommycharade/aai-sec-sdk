#!/usr/bin/env python3
"""Prepare and deploy verified Regional custom domains without changing DNS.

The guard derives API, bucket, account, and certificate state from AWS; persists
the reviewed secret-free authority; verifies the synthesized template; and can
deploy only that exact CDK assembly. It has no Route 53 or traffic operation.
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
from urllib.parse import urlsplit

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts import manage_aws_regional_recovery as recovery  # noqa: E402
from scripts import verify_regional_ingress_stack as verifier  # noqa: E402


class RegionalIngressDeploymentError(RuntimeError):
    """Report authority or provider state that cannot prove safe ingress."""


Runner = Callable[..., subprocess.CompletedProcess[str]]
_FIELDS = {
    "activationPermitted",
    "approvalEvidenceRef",
    "canaryApiDomain",
    "canaryUiDomain",
    "cellRole",
    "certificateArn",
    "cognitoOrigin",
    "region",
    "schemaVersion",
    "sourceStackName",
    "stableApiDomain",
    "stableUiDomain",
    "stackName",
}
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_STACK = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")
_EVIDENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{7,511}$")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegionalIngressDeploymentError(f"duplicate ingress field: {key}")
        result[key] = value
    return result


def _origin(value: object) -> str:
    if not isinstance(value, str):
        raise RegionalIngressDeploymentError("cognitoOrigin must be an HTTPS origin")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.hostname != parsed.hostname.lower()
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.geturl() != value
    ):
        raise RegionalIngressDeploymentError("cognitoOrigin must be one exact HTTPS origin")
    return value


@dataclass(frozen=True)
class RegionalIngressManifest:
    """Reviewed non-routing authority for one Region's stable/canary ingress."""

    stack_name: str
    source_stack_name: str
    cell_role: str
    region: str
    certificate_arn: str
    cognito_origin: str
    stable_api_domain: str
    stable_ui_domain: str
    canary_api_domain: str
    canary_ui_domain: str
    approval_evidence_ref: str

    @classmethod
    def parse(cls, payload: str) -> RegionalIngressManifest:
        """Parse exact schema-v1 authority that explicitly prohibits routing."""
        if len(payload.encode()) > 16_384:
            raise RegionalIngressDeploymentError("ingress manifest exceeds 16 KiB")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except json.JSONDecodeError as error:
            raise RegionalIngressDeploymentError("ingress manifest is not JSON") from error
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise RegionalIngressDeploymentError("ingress manifest fields do not match schema 1")
        if value["schemaVersion"] != 1 or value["activationPermitted"] is not False:
            raise RegionalIngressDeploymentError("ingress manifest must prohibit activation")
        role = value["cellRole"]
        expected_stack = {
            "primary": "AaiSecPrimaryRegionalIngress",
            "recovery": "AaiSecRecoveryRegionalIngress",
        }.get(role)
        if value["stackName"] != expected_stack:
            raise RegionalIngressDeploymentError("stackName does not match the cell role")
        if not isinstance(value["sourceStackName"], str) or not _STACK.fullmatch(
            value["sourceStackName"]
        ):
            raise RegionalIngressDeploymentError("sourceStackName is invalid")
        region = value["region"]
        if not isinstance(region, str) or not _REGION.fullmatch(region):
            raise RegionalIngressDeploymentError("ingress Region is invalid")
        certificate = value["certificateArn"]
        if not isinstance(certificate, str) or not re.fullmatch(
            rf"arn:(?:aws|aws-us-gov|aws-cn):acm:{region}:\d{{12}}:certificate/[0-9a-f-]{{36}}",
            certificate,
            re.IGNORECASE,
        ):
            raise RegionalIngressDeploymentError("certificate ARN is invalid or cross-Region")
        domains = [
            value[name]
            for name in ("stableApiDomain", "stableUiDomain", "canaryApiDomain", "canaryUiDomain")
        ]
        if (
            any(not isinstance(item, str) or not _DOMAIN.fullmatch(item) for item in domains)
            or len(set(domains)) != 4
        ):
            raise RegionalIngressDeploymentError(
                "ingress domains must be four exact distinct names"
            )
        stable_api, stable_ui, canary_api, canary_ui = (str(item) for item in domains)
        evidence = value["approvalEvidenceRef"]
        if not isinstance(evidence, str) or not _EVIDENCE.fullmatch(evidence):
            raise RegionalIngressDeploymentError("approvalEvidenceRef is invalid")
        return cls(
            value["stackName"],
            value["sourceStackName"],
            role,
            region,
            certificate,
            _origin(value["cognitoOrigin"]),
            stable_api,
            stable_ui,
            canary_api,
            canary_ui,
            evidence,
        )

    def canonical_json(self) -> str:
        """Return deterministic bytes for encrypted authority persistence."""
        return json.dumps(
            {
                "activationPermitted": False,
                "approvalEvidenceRef": self.approval_evidence_ref,
                "canaryApiDomain": self.canary_api_domain,
                "canaryUiDomain": self.canary_ui_domain,
                "cellRole": self.cell_role,
                "certificateArn": self.certificate_arn,
                "cognitoOrigin": self.cognito_origin,
                "region": self.region,
                "schemaVersion": 1,
                "sourceStackName": self.source_stack_name,
                "stableApiDomain": self.stable_api_domain,
                "stableUiDomain": self.stable_ui_domain,
                "stackName": self.stack_name,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def _aws(
    arguments: Sequence[str],
    *,
    manifest: RegionalIngressManifest,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Call only the bounded AWS read/persistence operations used by this guard."""
    try:
        return recovery._aws(arguments, profile=profile, region=manifest.region, runner=runner)
    except recovery.RecoveryConfigurationError as error:
        raise RegionalIngressDeploymentError(str(error)) from error


def _stack_outputs(
    manifest: RegionalIngressManifest, *, profile: str, runner: Runner
) -> dict[str, str]:
    response = _aws(
        ["cloudformation", "describe-stacks", "--stack-name", manifest.source_stack_name],
        manifest=manifest,
        profile=profile,
        runner=runner,
    )
    stacks = response.get("Stacks")
    if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], dict):
        raise RegionalIngressDeploymentError("source stack identity is ambiguous")
    if stacks[0].get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
        raise RegionalIngressDeploymentError("source stack is not in a stable deployed state")
    raw = stacks[0].get("Outputs")
    if not isinstance(raw, list) or len(raw) > 100:
        raise RegionalIngressDeploymentError("source stack outputs are malformed")
    outputs: dict[str, str] = {}
    for item in raw:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("OutputKey"), str)
            or not isinstance(item.get("OutputValue"), str)
        ):
            raise RegionalIngressDeploymentError("source stack output is malformed")
        if item["OutputKey"] in outputs:
            raise RegionalIngressDeploymentError("source stack output is duplicated")
        outputs[item["OutputKey"]] = item["OutputValue"]
    return outputs


def provider_identities(
    manifest: RegionalIngressManifest, *, profile: str, runner: Runner = subprocess.run
) -> tuple[str, str, str]:
    """Derive account, API ID, and UI bucket and validate the exact ACM certificate."""
    account = _aws(
        ["sts", "get-caller-identity"], manifest=manifest, profile=profile, runner=runner
    ).get("Account")
    if (
        not isinstance(account, str)
        or not re.fullmatch(r"\d{12}", account)
        or f":{account}:certificate/" not in manifest.certificate_arn
    ):
        raise RegionalIngressDeploymentError("certificate and caller account identities differ")
    outputs = _stack_outputs(manifest, profile=profile, runner=runner)
    if manifest.cell_role == "primary":
        endpoint = outputs.get("ApiUrl", "")
        parsed = urlsplit(endpoint)
        match = re.fullmatch(
            r"([a-z0-9]{8,64})\.execute-api\.[a-z0-9-]+\.amazonaws\.com", parsed.hostname or ""
        )
        if (
            parsed.scheme != "https"
            or not match
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise RegionalIngressDeploymentError("primary API output is malformed")
        api_id = match.group(1)
        bucket = outputs.get("UiBucketName")
    else:
        api_id = outputs.get("PassiveControlPlaneApiId")
        bucket = outputs.get("PassiveUiOriginBucketName")
    if not isinstance(api_id, str) or not re.fullmatch(r"[a-z0-9]{8,64}", api_id):
        raise RegionalIngressDeploymentError("provider-derived control API ID is invalid")
    if not isinstance(bucket, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        raise RegionalIngressDeploymentError("provider-derived UI bucket is invalid")
    api = _aws(
        ["apigatewayv2", "get-api", "--api-id", api_id],
        manifest=manifest,
        profile=profile,
        runner=runner,
    )
    if (
        api.get("ApiId") != api_id
        or api.get("ProtocolType") != "HTTP"
        or api.get("DisableExecuteApiEndpoint") is not True
    ):
        raise RegionalIngressDeploymentError("control API raw execute-api endpoint is not closed")
    certificate = _aws(
        ["acm", "describe-certificate", "--certificate-arn", manifest.certificate_arn],
        manifest=manifest,
        profile=profile,
        runner=runner,
    ).get("Certificate")
    if not isinstance(certificate, dict):
        raise RegionalIngressDeploymentError("ACM certificate evidence is unavailable")
    sans = certificate.get("SubjectAlternativeNames")
    validations = certificate.get("DomainValidationOptions")
    expected = {
        manifest.stable_api_domain,
        manifest.stable_ui_domain,
        manifest.canary_api_domain,
        manifest.canary_ui_domain,
    }
    if (
        certificate.get("CertificateArn") != manifest.certificate_arn
        or certificate.get("Status") != "ISSUED"
        or not isinstance(sans, list)
        or set(sans) != expected
        or len(sans) != 4
        or not isinstance(validations, list)
        or len(validations) != 4
        or any(
            not isinstance(item, dict) or item.get("ValidationStatus") != "SUCCESS"
            for item in validations
        )
        or certificate.get("KeyAlgorithm") not in {"RSA_2048", "EC_prime256v1"}
        or "sha1" in str(certificate.get("SignatureAlgorithm", "")).lower()
    ):
        raise RegionalIngressDeploymentError(
            "ACM certificate is not exact, issued, and fully validated"
        )
    return account, api_id, bucket


def parameter_name(manifest: RegionalIngressManifest) -> str:
    return f"/aai-sec/{manifest.stack_name}/regional-ingress"


def persist_manifest(
    manifest: RegionalIngressManifest, *, profile: str, runner: Runner = subprocess.run
) -> None:
    _aws(
        [
            "ssm",
            "put-parameter",
            "--name",
            parameter_name(manifest),
            "--type",
            "SecureString",
            "--value",
            manifest.canonical_json(),
            "--overwrite",
        ],
        manifest=manifest,
        profile=profile,
        runner=runner,
    )


def require_persisted_manifest(
    manifest: RegionalIngressManifest, *, profile: str, runner: Runner = subprocess.run
) -> None:
    value = _aws(
        ["ssm", "get-parameter", "--name", parameter_name(manifest), "--with-decryption"],
        manifest=manifest,
        profile=profile,
        runner=runner,
    )
    parameter = value.get("Parameter")
    payload = parameter.get("Value") if isinstance(parameter, dict) else None
    if (
        not isinstance(payload, str)
        or RegionalIngressManifest.parse(payload).canonical_json() != manifest.canonical_json()
    ):
        raise RegionalIngressDeploymentError("ingress manifest differs from persisted authority")


def deployment_environment(
    manifest: RegionalIngressManifest, *, profile: str, account: str, api_id: str, bucket: str
) -> dict[str, str]:
    """Build exact CDK inputs after deleting ambient ingress authority."""
    environment = os.environ.copy()
    names = {
        "AWS_DEFAULT_REGION": manifest.region,
        "AWS_PROFILE": profile,
        "AWS_REGION": manifest.region,
        "CDK_DEFAULT_ACCOUNT": account,
        "CDK_DEFAULT_REGION": manifest.region,
        "REGIONAL_INGRESS_AWS_ACCOUNT_ID": account,
        "REGIONAL_INGRESS_CANARY_API_DOMAIN": manifest.canary_api_domain,
        "REGIONAL_INGRESS_CANARY_UI_DOMAIN": manifest.canary_ui_domain,
        "REGIONAL_INGRESS_CELL_ROLE": manifest.cell_role,
        "REGIONAL_INGRESS_CERTIFICATE_ARN": manifest.certificate_arn,
        "REGIONAL_INGRESS_COGNITO_ORIGIN": manifest.cognito_origin,
        "REGIONAL_INGRESS_CONTROL_API_ID": api_id,
        "REGIONAL_INGRESS_REGION": manifest.region,
        "REGIONAL_INGRESS_STABLE_API_DOMAIN": manifest.stable_api_domain,
        "REGIONAL_INGRESS_STABLE_UI_DOMAIN": manifest.stable_ui_domain,
        "REGIONAL_INGRESS_STACK_NAME": manifest.stack_name,
        "REGIONAL_INGRESS_UI_BUCKET": bucket,
    }
    for name in set(names) | {key for key in environment if key.startswith("REGIONAL_INGRESS_")}:
        environment.pop(name, None)
    environment.update(names)
    return environment


def prepare(
    manifest: RegionalIngressManifest, *, profile: str, runner: Runner = subprocess.run
) -> dict[str, Any]:
    """Discover provider identities, synthesize, and independently verify ingress."""
    account, api_id, bucket = provider_identities(manifest, profile=profile, runner=runner)
    environment = deployment_environment(
        manifest, profile=profile, account=account, api_id=api_id, bucket=bucket
    )
    infrastructure = _ROOT / "infra/aws-control-plane"
    try:
        result = runner(
            ["npm", "run", "synth:ingress", "--", "--quiet"],
            cwd=infrastructure,
            env=environment,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RegionalIngressDeploymentError("regional ingress synthesis could not run") from error
    if result.returncode != 0:
        raise RegionalIngressDeploymentError("regional ingress synthesis failed")
    path = infrastructure / "cdk.out" / f"{manifest.stack_name}.template.json"
    try:
        payload = path.read_bytes()
        evidence = verifier.verify(
            json.loads(payload),
            cell_role=manifest.cell_role,
            control_api_id=api_id,
            ui_bucket=bucket,
            certificate_arn=manifest.certificate_arn,
            cognito_origin=manifest.cognito_origin,
            stable_api_domain=manifest.stable_api_domain,
            stable_ui_domain=manifest.stable_ui_domain,
            canary_api_domain=manifest.canary_api_domain,
            canary_ui_domain=manifest.canary_ui_domain,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise RegionalIngressDeploymentError(
            "synthesized regional ingress failed verification"
        ) from error
    evidence["templateSha256"] = hashlib.sha256(payload).hexdigest()
    return {"environment": environment, "template": evidence}


def deploy(
    manifest: RegionalIngressManifest,
    environment: dict[str, str],
    expected_sha256: str,
    *,
    runner: Runner = subprocess.run,
) -> None:
    """Deploy the exact verified custom-domain assembly without routing it."""
    infrastructure = _ROOT / "infra/aws-control-plane"
    path = infrastructure / "cdk.out" / f"{manifest.stack_name}.template.json"
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise RegionalIngressDeploymentError("verified ingress template is missing") from error
    if digest != expected_sha256:
        raise RegionalIngressDeploymentError("ingress template changed after verification")
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
        raise RegionalIngressDeploymentError("regional ingress deployment could not run") from error
    if result.returncode != 0:
        raise RegionalIngressDeploymentError("regional ingress deployment failed")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "prepare", "deploy"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--profile", default="p1")
    parser.add_argument("--confirm-persist-authority", action="store_true")
    parser.add_argument("--confirm-unrouted-deployment", action="store_true")
    args = parser.parse_args(argv)
    try:
        manifest = RegionalIngressManifest.parse(args.config.read_text(encoding="utf-8"))
        if args.command == "deploy":
            if not args.confirm_unrouted_deployment:
                raise RegionalIngressDeploymentError("--confirm-unrouted-deployment is required")
            require_persisted_manifest(manifest, profile=args.profile)
        evidence = prepare(manifest, profile=args.profile)
        if args.command == "prepare":
            if not args.confirm_persist_authority:
                raise RegionalIngressDeploymentError("--confirm-persist-authority is required")
            persist_manifest(manifest, profile=args.profile)
        elif args.command == "deploy":
            deploy(manifest, evidence["environment"], evidence["template"]["templateSha256"])
        print(
            json.dumps(
                {
                    "command": args.command,
                    "stackName": manifest.stack_name,
                    "status": "custom-domains-unrouted",
                    "template": evidence["template"],
                },
                sort_keys=True,
            )
        )
    except (
        OSError,
        UnicodeError,
        RegionalIngressDeploymentError,
        recovery.RecoveryConfigurationError,
    ) as error:
        print(f"Regional ingress guard failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
