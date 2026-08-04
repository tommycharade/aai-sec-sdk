"""Stage, promote and verify the retained assurance-report KMS signer.

The workflow is intentionally two phase. ``prepare`` checkpoints a new primary
MRK immediately, creates its recovery-Region replica, verifies a pre-rotation
signature and updates only passive trust. ``promote`` persists reviewed
current/history authority, deploys the primary, then redeploys the non-serving
passive cell. Every provider boundary has a durable resumable phase; old keys
are never disabled or scheduled for deletion.
"""

from __future__ import annotations

import argparse
import base64
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

from scripts import deploy_aws_control_plane as control  # noqa: E402
from scripts import manage_aws_regional_recovery as recovery  # noqa: E402


class AssuranceSignerRotationError(RuntimeError):
    """Report a rotation state or provider result that cannot prove safe cutover."""


Runner = Callable[..., subprocess.CompletedProcess[str]]
_MRK_ARN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):kms:([a-z]{2}(?:-gov)?-[a-z]+-\d):(\d{12}):key/(mrk-[0-9a-f]{32})$"
)
_EVIDENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,511}$")
_STATE_FIELDS = {
    "schemaVersion",
    "phase",
    "stackName",
    "primaryRegion",
    "recoveryRegion",
    "oldCurrentSignerArn",
    "oldCurrentReplicaArn",
    "oldHistoricalSignerArns",
    "oldHistoricalReplicaArns",
    "newCurrentSignerArn",
    "newCurrentReplicaArn",
    "approvalEvidenceRef",
}
_PHASES = (
    "primary_key_staged",
    "prepared",
    "authority_persisted",
    "primary_promoted",
    "passive_converged",
    "verified",
)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON state fields."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AssuranceSignerRotationError(f"duplicate rotation field: {key}")
        result[key] = value
    return result


def _arn(value: object, field: str, *, region: str | None = None) -> str:
    """Return one exact MRK ARN in the expected Region."""
    match = _MRK_ARN.fullmatch(value) if isinstance(value, str) else None
    if match is None or (region is not None and match.group(2) != region):
        raise AssuranceSignerRotationError(f"{field} is not an exact MRK ARN")
    assert isinstance(value, str)  # Narrowed by the regular-expression match.
    return value


def _arn_list(value: object, field: str, *, region: str) -> tuple[str, ...]:
    """Return a bounded, unique MRK registry."""
    if not isinstance(value, list) or len(value) > 8 or len(set(value)) != len(value):
        raise AssuranceSignerRotationError(f"{field} is invalid")
    return tuple(_arn(item, field, region=region) for item in value)


@dataclass(frozen=True)
class RotationState:
    """Secret-free evidence binding one staged signer cutover."""

    phase: str
    stack_name: str
    primary_region: str
    recovery_region: str
    old_current_signer_arn: str
    old_current_replica_arn: str
    old_historical_signer_arns: tuple[str, ...]
    old_historical_replica_arns: tuple[str, ...]
    new_current_signer_arn: str
    new_current_replica_arn: str | None
    approval_evidence_ref: str

    @classmethod
    def parse(cls, payload: str) -> RotationState:
        """Parse closed schema-v1 state and bind every primary/replica identity."""
        if len(payload.encode()) > 32_768:
            raise AssuranceSignerRotationError("rotation state exceeds 32 KiB")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise AssuranceSignerRotationError("rotation state is malformed") from error
        if not isinstance(value, dict) or set(value) != _STATE_FIELDS:
            raise AssuranceSignerRotationError("rotation state schema is invalid")
        if value.get("schemaVersion") != 1 or value.get("phase") not in _PHASES:
            raise AssuranceSignerRotationError("rotation state phase is invalid")
        primary_region = value.get("primaryRegion")
        recovery_region = value.get("recoveryRegion")
        if (
            not isinstance(primary_region, str)
            or not isinstance(recovery_region, str)
            or primary_region == recovery_region
        ):
            raise AssuranceSignerRotationError("rotation Regions are invalid")
        old_primary = _arn(value.get("oldCurrentSignerArn"), "old current", region=primary_region)
        old_replica = _arn(value.get("oldCurrentReplicaArn"), "old replica", region=recovery_region)
        new_primary = _arn(value.get("newCurrentSignerArn"), "new current", region=primary_region)
        new_replica_value = value.get("newCurrentReplicaArn")
        if value["phase"] == "primary_key_staged" and new_replica_value is None:
            new_replica = None
        else:
            new_replica = _arn(new_replica_value, "new replica", region=recovery_region)
        old_history = _arn_list(
            value.get("oldHistoricalSignerArns"), "old history", region=primary_region
        )
        old_replica_history = _arn_list(
            value.get("oldHistoricalReplicaArns"),
            "old replica history",
            region=recovery_region,
        )
        if len(old_history) != len(old_replica_history):
            raise AssuranceSignerRotationError("historical replica coverage differs")
        pairs = [
            (old_primary, old_replica),
            *zip(old_history, old_replica_history, strict=True),
        ]
        if new_replica is not None:
            pairs.append((new_primary, new_replica))
        for primary_arn, replica_arn in pairs:
            primary_match = _MRK_ARN.fullmatch(primary_arn)
            replica_match = _MRK_ARN.fullmatch(replica_arn)
            if (
                not primary_match
                or not replica_match
                or (
                    primary_match.group(1) != replica_match.group(1)
                    or primary_match.group(3) != replica_match.group(3)
                    or primary_match.group(4) != replica_match.group(4)
                )
            ):
                raise AssuranceSignerRotationError("primary/replica key identity differs")
        evidence = value.get("approvalEvidenceRef")
        stack_name = value.get("stackName")
        if not isinstance(evidence, str) or not _EVIDENCE.fullmatch(evidence):
            raise AssuranceSignerRotationError("approval evidence reference is invalid")
        if not isinstance(stack_name, str) or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9-]{0,127}", stack_name
        ):
            raise AssuranceSignerRotationError("stack name is invalid")
        return cls(
            value["phase"],
            stack_name,
            primary_region,
            recovery_region,
            old_primary,
            old_replica,
            old_history,
            old_replica_history,
            new_primary,
            new_replica,
            evidence,
        )

    def canonical_json(self) -> str:
        """Return deterministic state without credentials or report content."""
        return json.dumps(
            {
                "approvalEvidenceRef": self.approval_evidence_ref,
                "newCurrentReplicaArn": self.new_current_replica_arn,
                "newCurrentSignerArn": self.new_current_signer_arn,
                "oldCurrentReplicaArn": self.old_current_replica_arn,
                "oldCurrentSignerArn": self.old_current_signer_arn,
                "oldHistoricalReplicaArns": list(self.old_historical_replica_arns),
                "oldHistoricalSignerArns": list(self.old_historical_signer_arns),
                "phase": self.phase,
                "primaryRegion": self.primary_region,
                "recoveryRegion": self.recovery_region,
                "schemaVersion": 1,
                "stackName": self.stack_name,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def _aws(arguments: Sequence[str], *, profile: str, region: str, runner: Runner) -> dict[str, Any]:
    """Run one bounded AWS CLI operation."""
    command = ["aws", *arguments, "--profile", profile, "--region", region, "--output", "json"]
    result = runner(command, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode != 0:
        raise AssuranceSignerRotationError((result.stderr.strip() or "AWS CLI failed")[-500:])
    if len(result.stdout.encode()) > 1_048_576:
        raise AssuranceSignerRotationError("AWS response exceeds 1 MiB")
    try:
        value = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as error:
        raise AssuranceSignerRotationError("AWS returned malformed JSON") from error
    if not isinstance(value, dict):
        raise AssuranceSignerRotationError("AWS returned an invalid response")
    return value


def _persist_state(state_path: Path, state: RotationState) -> RotationState:
    """Atomically replace the local secret-free phase checkpoint."""
    state_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = state_path.with_name(f".{state_path.name}.tmp")
    temporary.write_text(state.canonical_json() + "\n", encoding="utf-8")
    temporary.replace(state_path)
    return state


def _phase(state: RotationState, phase: str, state_path: Path) -> RotationState:
    """Persist one monotonic workflow phase before the next side effect."""
    current = _PHASES.index(state.phase)
    target = _PHASES.index(phase)
    if target < current or target > current + 1:
        raise AssuranceSignerRotationError("rotation phase transition is invalid")
    return _persist_state(
        state_path,
        RotationState(**{**state.__dict__, "phase": phase}),
    )


def _existing_replica_arn(
    primary_arn: str,
    recovery_region: str,
    *,
    profile: str,
    primary_region: str,
    runner: Runner,
) -> str | None:
    """Resolve a previously created replica after an interrupted preparation."""
    response = _aws(
        ["kms", "describe-key", "--key-id", primary_arn],
        profile=profile,
        region=primary_region,
        runner=runner,
    )
    configuration = response.get("KeyMetadata", {}).get("MultiRegionConfiguration", {})
    replicas = configuration.get("ReplicaKeys", []) if isinstance(configuration, dict) else []
    if not isinstance(replicas, list):
        raise AssuranceSignerRotationError("KMS replica registry is malformed")
    matches = [
        item.get("Arn")
        for item in replicas
        if isinstance(item, dict) and item.get("Region") == recovery_region
    ]
    if len(matches) > 1:
        raise AssuranceSignerRotationError("KMS replica registry is ambiguous")
    return _arn(matches[0], "existing replica", region=recovery_region) if matches else None


def prepare(
    manifest: recovery.RegionalRecoveryManifest,
    state_path: Path,
    evidence_ref: str,
    *,
    profile: str,
    fixture_path: Path,
    runner: Runner = subprocess.run,
) -> RotationState:
    """Stage or resume passive trust without changing active signing authority."""
    if not _EVIDENCE.fullmatch(evidence_ref):
        raise AssuranceSignerRotationError("approval evidence reference is invalid")
    outputs = recovery.stack_outputs(manifest, profile=profile, runner=runner)
    passive = recovery.recovery_stack_outputs(manifest, profile=profile, runner=runner)
    existing = (
        RotationState.parse(state_path.read_text(encoding="utf-8")) if state_path.exists() else None
    )
    old_current = _arn(
        outputs["AssuranceReportSigningKeyArn"], "old current", region=manifest.primary_region
    )
    live_replica = _arn(
        passive["AssuranceReportSigningReplicaKeyArn"],
        "live replica",
        region=manifest.recovery_region,
    )
    old_history = tuple(
        recovery._key_arn_list(
            outputs["AssuranceReportHistoricalVerificationKeyArns"], "old history"
        )
    )
    live_replica_history = tuple(
        recovery._key_arn_list(
            passive["AssuranceReportHistoricalVerificationReplicaKeyArns"],
            "live replica history",
        )
    )
    if existing is not None:
        state = existing
        pre_stage = (
            live_replica == state.old_current_replica_arn
            and live_replica_history == state.old_historical_replica_arns
        )
        staged = (
            state.new_current_replica_arn is not None
            and live_replica == state.new_current_replica_arn
            and live_replica_history
            == (state.old_current_replica_arn, *state.old_historical_replica_arns)
        )
        if (
            state.phase not in {"primary_key_staged", "prepared"}
            or state.stack_name != manifest.stack_name
            or state.primary_region != manifest.primary_region
            or state.recovery_region != manifest.recovery_region
            or state.approval_evidence_ref != evidence_ref
            or state.old_current_signer_arn != old_current
            or state.old_historical_signer_arns != old_history
            or not (pre_stage or staged)
        ):
            raise AssuranceSignerRotationError("existing rotation state does not match live trust")
        if state.phase == "prepared":
            return state
        old_replica = state.old_current_replica_arn
        old_replica_history = state.old_historical_replica_arns
        new_current = state.new_current_signer_arn
    else:
        old_replica = live_replica
        old_replica_history = live_replica_history
        created = _aws(
            [
                "kms",
                "create-key",
                "--multi-region",
                "--key-usage",
                "SIGN_VERIFY",
                "--key-spec",
                "ECC_NIST_P256",
                "--description",
                "AAI Security staged assurance report signer",
                "--tags",
                "TagKey=aai-sec:purpose,TagValue=assurance-report-signing",
                "TagKey=aai-sec:active-authority,TagValue=false",
            ],
            profile=profile,
            region=manifest.primary_region,
            runner=runner,
        )
        new_current = _arn(
            created.get("KeyMetadata", {}).get("Arn"),
            "new current",
            region=manifest.primary_region,
        )
        state = _persist_state(
            state_path,
            RotationState(
                "primary_key_staged",
                manifest.stack_name,
                manifest.primary_region,
                manifest.recovery_region,
                old_current,
                old_replica,
                old_history,
                old_replica_history,
                new_current,
                None,
                evidence_ref,
            ),
        )
    new_replica = _existing_replica_arn(
        new_current,
        manifest.recovery_region,
        profile=profile,
        primary_region=manifest.primary_region,
        runner=runner,
    )
    if new_replica is None:
        replicated = _aws(
            [
                "kms",
                "replicate-key",
                "--key-id",
                new_current,
                "--replica-region",
                manifest.recovery_region,
                "--description",
                "AAI Security staged assurance report recovery replica",
                "--tags",
                "TagKey=aai-sec:purpose,TagValue=assurance-report-signing-replica",
                "TagKey=aai-sec:active-authority,TagValue=false",
            ],
            profile=profile,
            region=manifest.primary_region,
            runner=runner,
        )
        new_replica = _arn(
            replicated.get("ReplicaKeyMetadata", {}).get("Arn"),
            "new replica",
            region=manifest.recovery_region,
        )
    state = _persist_state(
        state_path,
        RotationState(**{**state.__dict__, "new_current_replica_arn": new_replica}),
    )
    new_history = (old_current, *old_history)
    new_replica_history = (old_replica, *old_replica_history)
    recovery.deploy_signing_replica(
        outputs["RegionalPolicySigningKeyArn"],
        new_current,
        json.dumps(new_history, separators=(",", ":")),
        manifest,
        profile=profile,
        configured_assurance_replica_key_arn=new_replica,
        configured_historical_assurance_replica_key_arns=json.dumps(
            new_replica_history, separators=(",", ":")
        ),
        runner=runner,
    )
    recovery.verify_signing_replica(
        new_current, new_replica, manifest, profile=profile, runner=runner
    )
    verify_old_snapshot_fixture(state, fixture_path, profile=profile, runner=runner)
    return _phase(state, "prepared", state_path)


def promote(
    state: RotationState,
    state_path: Path,
    *,
    profile: str,
    passive_config: Path,
    recovery_config: Path,
    runner: Runner = subprocess.run,
) -> RotationState:
    """Resume current-authority promotion from every durable phase boundary."""
    if state.phase not in {
        "prepared",
        "authority_persisted",
        "primary_promoted",
        "passive_converged",
    }:
        raise AssuranceSignerRotationError("rotation state cannot be promoted")
    if state.new_current_replica_arn is None:
        raise AssuranceSignerRotationError("recovery replica is not staged")
    manifest = control.AssuranceSignerDeploymentManifest(
        state.new_current_signer_arn,
        (state.old_current_signer_arn, *state.old_historical_signer_arns),
        state.recovery_region,
        state.approval_evidence_ref,
    )
    outputs = control.stack_outputs(
        state.stack_name, profile=profile, region=state.primary_region, runner=runner
    )
    live_signer = outputs.get("AssuranceReportSigningKeyArn")
    if state.phase == "prepared":
        if live_signer != state.old_current_signer_arn:
            raise AssuranceSignerRotationError("active signer changed after preparation")
        control.persist_assurance_signer_manifest(
            manifest,
            state.stack_name,
            profile=profile,
            region=state.primary_region,
            runner=runner,
        )
        state = _phase(state, "authority_persisted", state_path)
    persisted = control.load_persisted_assurance_signer_manifest(
        state.stack_name, profile=profile, region=state.primary_region, runner=runner
    )
    if persisted != manifest:
        raise AssuranceSignerRotationError("persisted signer authority differs from rotation")
    if state.phase == "authority_persisted":
        if live_signer == state.old_current_signer_arn:
            control.deploy(
                state.stack_name,
                profile=profile,
                region=state.primary_region,
                runner=runner,
                allow_assurance_signer_transition=True,
            )
        elif live_signer != state.new_current_signer_arn:
            raise AssuranceSignerRotationError("live signer is outside rotation authority")
        post = control.stack_outputs(
            state.stack_name, profile=profile, region=state.primary_region, runner=runner
        )
        if post.get("AssuranceReportSigningKeyArn") != state.new_current_signer_arn:
            raise AssuranceSignerRotationError("primary signer promotion did not converge")
        state = _phase(state, "primary_promoted", state_path)
    if state.phase == "primary_promoted":
        result = runner(
            [
                sys.executable,
                str(Path(__file__).with_name("deploy_aws_passive_cell.py")),
                "deploy",
                "--config",
                str(passive_config),
                "--regional-recovery-config",
                str(recovery_config),
                "--profile",
                profile,
            ],
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )
        if result.returncode != 0:
            raise AssuranceSignerRotationError(
                (result.stderr.strip() or "passive deploy failed")[-500:]
            )
        state = _phase(state, "passive_converged", state_path)
    return state


def verify_old_snapshot_fixture(
    state: RotationState, fixture_path: Path, *, profile: str, runner: Runner = subprocess.run
) -> None:
    """Verify one pre-rotation signature through old primary and recovery replicas."""
    try:
        payload = fixture_path.read_bytes()
        if len(payload) > 16_384:
            raise ValueError
        fixture = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
        if not isinstance(fixture, dict) or set(fixture) != {"messageBase64", "signatureBase64"}:
            raise ValueError
        message = base64.b64decode(fixture["messageBase64"], validate=True)
        signature = base64.b64decode(fixture["signatureBase64"], validate=True)
        if len(message) != 32 or not 1 <= len(signature) <= 1_024:
            raise ValueError
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        raise AssuranceSignerRotationError("verification fixture is invalid") from error
    for key_arn, region in (
        (state.old_current_signer_arn, state.primary_region),
        (state.old_current_replica_arn, state.recovery_region),
    ):
        response = _aws(
            [
                "kms",
                "verify",
                "--key-id",
                key_arn,
                "--message",
                f"{fixture['messageBase64']}",
                "--message-type",
                "DIGEST",
                "--signature",
                f"{fixture['signatureBase64']}",
                "--signing-algorithm",
                "ECDSA_SHA_256",
            ],
            profile=profile,
            region=region,
            runner=runner,
        )
        if (
            response.get("SignatureValid") is not True
            or response.get("KeyId") != key_arn
            or response.get("SigningAlgorithm") != "ECDSA_SHA_256"
        ):
            raise AssuranceSignerRotationError("pre-rotation signature verification failed")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "promote", "verify"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--regional-recovery-config", type=Path, required=True)
    parser.add_argument("--passive-config", type=Path)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--approval-evidence-ref")
    parser.add_argument("--profile", default="p1")
    parser.add_argument("--confirm-two-phase-cutover", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Execute one explicit phase and emit no signature or report content."""
    arguments = _parser().parse_args(argv)
    try:
        manifest = recovery.RegionalRecoveryManifest.parse(
            arguments.regional_recovery_config.read_text(encoding="utf-8")
        )
        if arguments.command == "prepare":
            if (
                not arguments.confirm_two_phase_cutover
                or not arguments.approval_evidence_ref
                or arguments.fixture is None
            ):
                raise AssuranceSignerRotationError(
                    "prepare requires confirmation, evidence and fixture"
                )
            state = prepare(
                manifest,
                arguments.state,
                arguments.approval_evidence_ref,
                profile=arguments.profile,
                fixture_path=arguments.fixture,
            )
        else:
            state = RotationState.parse(arguments.state.read_text(encoding="utf-8"))
            if arguments.command == "promote":
                if not arguments.confirm_two_phase_cutover or arguments.passive_config is None:
                    raise AssuranceSignerRotationError(
                        "promote requires confirmation and passive config"
                    )
                state = promote(
                    state,
                    arguments.state,
                    profile=arguments.profile,
                    passive_config=arguments.passive_config,
                    recovery_config=arguments.regional_recovery_config,
                )
            else:
                if (
                    state.phase not in {"passive_converged", "verified"}
                    or arguments.fixture is None
                ):
                    raise AssuranceSignerRotationError(
                        "verify requires converged state and fixture"
                    )
                verify_old_snapshot_fixture(state, arguments.fixture, profile=arguments.profile)
                if state.phase != "verified":
                    state = _phase(state, "verified", arguments.state)
        print(json.dumps({"phase": state.phase, "state": str(arguments.state)}, sort_keys=True))
    except (
        OSError,
        control.DeploymentConfigurationError,
        recovery.RecoveryConfigurationError,
        AssuranceSignerRotationError,
    ) as error:
        print(f"Assurance signer rotation failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
