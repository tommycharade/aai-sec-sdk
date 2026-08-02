#!/usr/bin/env python3
"""Prepare and deploy only the uninitialized regional-transition witness.

The guard persists secret-free deployment authority, derives the AWS account
from STS, strips ambient CDK authority, independently verifies the synthesized
template, and deploys that exact assembly. It cannot initialize journal state
or change any regional runtime or route.
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

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts import manage_aws_regional_recovery as recovery  # noqa: E402
from scripts import verify_transition_journal_stack as verifier  # noqa: E402


class TransitionJournalDeploymentError(RuntimeError):
    """Report authority or provider state that cannot prove safe deployment."""


Runner = Callable[..., subprocess.CompletedProcess[str]]
_FIELDS = {
    "schemaVersion",
    "stackName",
    "tableName",
    "coordinationRegion",
    "primaryRegion",
    "recoveryRegion",
    "approvalEvidenceRef",
    "activationPermitted",
}
_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_TABLE = re.compile(r"^[A-Za-z0-9_.-]{3,255}$")
_EVIDENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{7,511}$")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate deployment fields before authority is ambiguous."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TransitionJournalDeploymentError(f"duplicate witness field: {key}")
        result[key] = value
    return result


@dataclass(frozen=True)
class TransitionJournalDeploymentManifest:
    """Reviewed secret-free authority for an uninitialized witness stack."""

    stack_name: str
    table_name: str
    coordination_region: str
    primary_region: str
    recovery_region: str
    approval_evidence_ref: str

    @classmethod
    def parse(cls, payload: str) -> TransitionJournalDeploymentManifest:
        """Parse an exact non-activation witness deployment manifest."""
        if len(payload.encode()) > 16_384:
            raise TransitionJournalDeploymentError("witness manifest exceeds 16 KiB")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except json.JSONDecodeError as error:
            raise TransitionJournalDeploymentError("witness manifest is not JSON") from error
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise TransitionJournalDeploymentError("witness manifest fields do not match schema 1")
        if value["schemaVersion"] != 1 or value["activationPermitted"] is not False:
            raise TransitionJournalDeploymentError("witness deployment must prohibit activation")
        if value["stackName"] != "AaiSecRegionalTransitionJournal":
            raise TransitionJournalDeploymentError("stackName must identify the reviewed witness")
        table = value["tableName"]
        if not isinstance(table, str) or not _TABLE.fullmatch(table):
            raise TransitionJournalDeploymentError("witness tableName is invalid")
        regions = (
            value["coordinationRegion"],
            value["primaryRegion"],
            value["recoveryRegion"],
        )
        if any(not isinstance(region, str) or not _REGION.fullmatch(region) for region in regions):
            raise TransitionJournalDeploymentError("witness deployment Region is invalid")
        if len(set(regions)) != 3:
            raise TransitionJournalDeploymentError("witness and runtime Regions must be distinct")
        evidence = value["approvalEvidenceRef"]
        if not isinstance(evidence, str) or not _EVIDENCE.fullmatch(evidence):
            raise TransitionJournalDeploymentError("approvalEvidenceRef is invalid")
        return cls(value["stackName"], table, *regions, evidence)

    def canonical_json(self) -> str:
        """Return stable bytes for encrypted Parameter Store persistence."""
        return json.dumps(
            {
                "activationPermitted": False,
                "approvalEvidenceRef": self.approval_evidence_ref,
                "coordinationRegion": self.coordination_region,
                "primaryRegion": self.primary_region,
                "recoveryRegion": self.recovery_region,
                "schemaVersion": 1,
                "stackName": self.stack_name,
                "tableName": self.table_name,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def parameter_name(manifest: TransitionJournalDeploymentManifest) -> str:
    """Return the fixed encrypted deployment-authority parameter path."""
    return f"/aai-sec/{manifest.stack_name}/deployment"


def _aws(
    arguments: Sequence[str],
    *,
    manifest: TransitionJournalDeploymentManifest,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Call the bounded AWS CLI wrapper in the witness Region."""
    try:
        return recovery._aws(
            arguments,
            profile=profile,
            region=manifest.coordination_region,
            runner=runner,
        )
    except recovery.RecoveryConfigurationError as error:
        raise TransitionJournalDeploymentError(str(error)) from error


def persist_manifest(
    manifest: TransitionJournalDeploymentManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> None:
    """Persist exact witness deployment authority as encrypted, non-secret state."""
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
    manifest: TransitionJournalDeploymentManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> None:
    """Require byte-equivalent persisted deployment authority before deployment."""
    response = _aws(
        [
            "ssm",
            "get-parameter",
            "--name",
            parameter_name(manifest),
            "--with-decryption",
        ],
        manifest=manifest,
        profile=profile,
        runner=runner,
    )
    parameter = response.get("Parameter")
    payload = parameter.get("Value") if isinstance(parameter, dict) else None
    if not isinstance(payload, str):
        raise TransitionJournalDeploymentError("persisted witness authority is unavailable")
    persisted = TransitionJournalDeploymentManifest.parse(payload)
    if persisted.canonical_json() != manifest.canonical_json():
        raise TransitionJournalDeploymentError("witness manifest differs from persisted authority")


def deployment_environment(
    manifest: TransitionJournalDeploymentManifest,
    *,
    profile: str,
    account_id: str,
) -> dict[str, str]:
    """Build exact CDK inputs while discarding ambient witness authority."""
    if not re.fullmatch(r"\d{12}", account_id):
        raise TransitionJournalDeploymentError("AWS account identity is malformed")
    environment = os.environ.copy()
    for name in (
        "CDK_DEFAULT_ACCOUNT",
        "CDK_DEFAULT_REGION",
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "TRANSITION_COORDINATION_REGION",
        "TRANSITION_JOURNAL_TABLE_NAME",
        "PRIMARY_REGION",
        "RECOVERY_REGION",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "AWS_DEFAULT_REGION": manifest.coordination_region,
            "AWS_PROFILE": profile,
            "AWS_REGION": manifest.coordination_region,
            "CDK_DEFAULT_ACCOUNT": account_id,
            "CDK_DEFAULT_REGION": manifest.coordination_region,
            "PRIMARY_REGION": manifest.primary_region,
            "RECOVERY_REGION": manifest.recovery_region,
            "TRANSITION_COORDINATION_REGION": manifest.coordination_region,
            "TRANSITION_JOURNAL_TABLE_NAME": manifest.table_name,
        }
    )
    return environment


def prepare_synth(
    manifest: TransitionJournalDeploymentManifest,
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Derive account identity, synthesize, and verify an uninitialized witness."""
    account = _aws(
        ["sts", "get-caller-identity"],
        manifest=manifest,
        profile=profile,
        runner=runner,
    ).get("Account")
    if not isinstance(account, str):
        raise TransitionJournalDeploymentError("AWS account identity is missing")
    environment = deployment_environment(manifest, profile=profile, account_id=account)
    infrastructure = _ROOT / "infra" / "aws-control-plane"
    try:
        result = runner(
            ["npm", "run", "synth:journal", "--", "--quiet"],
            cwd=infrastructure,
            env=environment,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TransitionJournalDeploymentError("witness synthesis could not run") from error
    if result.returncode != 0:
        raise TransitionJournalDeploymentError("witness synthesis failed")
    path = infrastructure / "cdk.out" / f"{manifest.stack_name}.template.json"
    try:
        payload = path.read_bytes()
        if len(payload) > 2_000_000:
            raise TransitionJournalDeploymentError("witness template exceeds 2 MB")
        evidence = verifier.verify(json.loads(payload), expected_table_name=manifest.table_name)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise TransitionJournalDeploymentError("synthesized witness failed verification") from error
    evidence["templateSha256"] = hashlib.sha256(payload).hexdigest()
    return {"environment": environment, "template": evidence}


def deploy(
    manifest: TransitionJournalDeploymentManifest,
    environment: dict[str, str],
    expected_sha256: str,
    *,
    runner: Runner = subprocess.run,
) -> None:
    """Deploy the exact verified, uninitialized witness CDK assembly."""
    infrastructure = _ROOT / "infra" / "aws-control-plane"
    path = infrastructure / "cdk.out" / f"{manifest.stack_name}.template.json"
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise TransitionJournalDeploymentError("verified witness template is missing") from error
    if digest != expected_sha256:
        raise TransitionJournalDeploymentError("witness template changed after verification")
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
        raise TransitionJournalDeploymentError("witness deployment could not run") from error
    if result.returncode != 0:
        raise TransitionJournalDeploymentError("witness CloudFormation deployment failed")


def _parser() -> argparse.ArgumentParser:
    """Build a deployment-only command surface with no journal initialization."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "prepare", "deploy"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--profile", default="p1")
    parser.add_argument("--confirm-persist-authority", action="store_true")
    parser.add_argument("--confirm-uninitialized-deployment", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Check, persist, or deploy only after all independent guards pass."""
    arguments = _parser().parse_args(argv)
    try:
        manifest = TransitionJournalDeploymentManifest.parse(
            arguments.config.read_text(encoding="utf-8")
        )
        if arguments.command == "deploy":
            if not arguments.confirm_uninitialized_deployment:
                raise TransitionJournalDeploymentError(
                    "--confirm-uninitialized-deployment is required"
                )
            require_persisted_manifest(manifest, profile=arguments.profile)
        evidence = prepare_synth(manifest, profile=arguments.profile)
        if arguments.command == "prepare":
            if not arguments.confirm_persist_authority:
                raise TransitionJournalDeploymentError("--confirm-persist-authority is required")
            persist_manifest(manifest, profile=arguments.profile)
        elif arguments.command == "deploy":
            deploy(
                manifest,
                evidence["environment"],
                evidence["template"]["templateSha256"],
            )
        print(
            json.dumps(
                {
                    "command": arguments.command,
                    "stackName": manifest.stack_name,
                    "status": "uninitialized-single-writer-witness",
                    "template": evidence["template"],
                },
                sort_keys=True,
            )
        )
    except (
        OSError,
        UnicodeError,
        recovery.RecoveryConfigurationError,
        TransitionJournalDeploymentError,
    ) as error:
        print(f"Transition witness guard failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
