"""Two-phase assurance signer rotation contracts."""

from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from scripts import deploy_aws_control_plane as control
from scripts import manage_aws_regional_recovery as recovery
from scripts import rotate_aws_assurance_signer as rotation

_ACCOUNT = "123456789012"
_OLD_ID = "mrk-" + "1" * 32
_NEW_ID = "mrk-" + "2" * 32
_OLDER_ID = "mrk-" + "3" * 32
_POLICY_ID = "mrk-" + "4" * 32


def _arn(region: str, identity: str) -> str:
    return f"arn:aws:kms:{region}:{_ACCOUNT}:key/{identity}"


def _manifest() -> recovery.RegionalRecoveryManifest:
    return recovery.RegionalRecoveryManifest(
        stack_name="AaiSecControlPlane",
        primary_region="eu-west-2",
        recovery_region="eu-west-1",
        target_fleet_size=100,
        rto_minutes=60,
        rpo_seconds=300,
        approval_evidence_ref="change/DR-123",
    )


def test_prepare_stages_new_replica_and_retains_old_current_as_history(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Phase one changes passive trust while primary authority remains old."""
    manifest = _manifest()
    old_current = _arn(manifest.primary_region, _OLD_ID)
    old_replica = _arn(manifest.recovery_region, _OLD_ID)
    older = _arn(manifest.primary_region, _OLDER_ID)
    older_replica = _arn(manifest.recovery_region, _OLDER_ID)
    new_current = _arn(manifest.primary_region, _NEW_ID)
    new_replica = _arn(manifest.recovery_region, _NEW_ID)
    monkeypatch.setattr(
        recovery,
        "stack_outputs",
        lambda *_args, **_kwargs: {
            "AssuranceReportSigningKeyArn": old_current,
            "AssuranceReportHistoricalVerificationKeyArns": json.dumps([older]),
            "RegionalPolicySigningKeyArn": _arn(manifest.primary_region, _POLICY_ID),
        },
    )
    monkeypatch.setattr(
        recovery,
        "recovery_stack_outputs",
        lambda *_args, **_kwargs: {
            "AssuranceReportSigningReplicaKeyArn": old_replica,
            "AssuranceReportHistoricalVerificationReplicaKeyArns": json.dumps([older_replica]),
        },
    )
    responses = iter(
        [
            {"KeyMetadata": {"Arn": new_current}},
            {"KeyMetadata": {"MultiRegionConfiguration": {"ReplicaKeys": []}}},
            {"ReplicaKeyMetadata": {"Arn": new_replica}},
        ]
    )
    monkeypatch.setattr(rotation, "_aws", lambda *_args, **_kwargs: next(responses))
    deployed: dict[str, Any] = {}

    def deploy_replica(*args: Any, **kwargs: Any) -> None:
        deployed["args"] = args
        deployed["kwargs"] = kwargs

    monkeypatch.setattr(recovery, "deploy_signing_replica", deploy_replica)
    monkeypatch.setattr(recovery, "verify_signing_replica", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(rotation, "verify_old_snapshot_fixture", lambda *_args, **_kwargs: None)
    state_path = tmp_path / "rotation.json"
    state = rotation.prepare(
        manifest,
        state_path,
        "change/ASSURANCE-42",
        profile="p1",
        fixture_path=tmp_path / "fixture.json",
    )

    assert state.phase == "prepared"
    assert state.new_current_signer_arn == new_current
    assert state.old_current_signer_arn == old_current
    assert json.loads(deployed["args"][2]) == [old_current, older]
    assert json.loads(deployed["kwargs"]["configured_historical_assurance_replica_key_arns"]) == [
        old_replica,
        older_replica,
    ]
    assert deployed["kwargs"]["configured_assurance_replica_key_arn"] == new_replica
    assert rotation.RotationState.parse(state_path.read_text()) == state


def test_prepare_resumes_from_immediate_primary_key_checkpoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A crash after key creation reuses the checkpoint instead of orphaning authority."""
    manifest = _manifest()
    old_current = _arn(manifest.primary_region, _OLD_ID)
    old_replica = _arn(manifest.recovery_region, _OLD_ID)
    new_current = _arn(manifest.primary_region, _NEW_ID)
    new_replica = _arn(manifest.recovery_region, _NEW_ID)
    monkeypatch.setattr(
        recovery,
        "stack_outputs",
        lambda *_a, **_k: {
            "AssuranceReportSigningKeyArn": old_current,
            "AssuranceReportHistoricalVerificationKeyArns": "[]",
            "RegionalPolicySigningKeyArn": _arn(manifest.primary_region, _POLICY_ID),
        },
    )
    monkeypatch.setattr(
        recovery,
        "recovery_stack_outputs",
        lambda *_a, **_k: {
            "AssuranceReportSigningReplicaKeyArn": old_replica,
            "AssuranceReportHistoricalVerificationReplicaKeyArns": "[]",
        },
    )
    creates = 0

    def create(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal creates
        creates += 1
        return {"KeyMetadata": {"Arn": new_current}}

    monkeypatch.setattr(rotation, "_aws", create)
    monkeypatch.setattr(
        rotation,
        "_existing_replica_arn",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("synthetic crash")),
    )
    state_path = tmp_path / "rotation.json"
    with pytest.raises(RuntimeError, match="synthetic crash"):
        rotation.prepare(
            manifest,
            state_path,
            "change/ASSURANCE-42",
            profile="p1",
            fixture_path=tmp_path / "fixture.json",
        )
    checkpoint = rotation.RotationState.parse(state_path.read_text())
    assert checkpoint.phase == "primary_key_staged"
    assert checkpoint.new_current_signer_arn == new_current
    assert checkpoint.new_current_replica_arn is None

    monkeypatch.setattr(rotation, "_existing_replica_arn", lambda *_a, **_k: new_replica)
    monkeypatch.setattr(recovery, "deploy_signing_replica", lambda *_a, **_k: None)
    monkeypatch.setattr(recovery, "verify_signing_replica", lambda *_a, **_k: {})
    monkeypatch.setattr(rotation, "verify_old_snapshot_fixture", lambda *_a, **_k: None)
    resumed = rotation.prepare(
        manifest,
        state_path,
        "change/ASSURANCE-42",
        profile="p1",
        fixture_path=tmp_path / "fixture.json",
    )
    assert resumed.phase == "prepared"
    assert resumed.new_current_replica_arn == new_replica
    assert creates == 1


def test_prepare_resumes_after_passive_trust_converged_before_phase_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Already-staged recovery outputs are accepted only when exact state matches."""
    manifest = _manifest()
    old_current = _arn(manifest.primary_region, _OLD_ID)
    old_replica = _arn(manifest.recovery_region, _OLD_ID)
    new_current = _arn(manifest.primary_region, _NEW_ID)
    new_replica = _arn(manifest.recovery_region, _NEW_ID)
    state_path = tmp_path / "rotation.json"
    rotation._persist_state(
        state_path,
        rotation.RotationState(
            "primary_key_staged",
            manifest.stack_name,
            manifest.primary_region,
            manifest.recovery_region,
            old_current,
            old_replica,
            (),
            (),
            new_current,
            new_replica,
            "change/ASSURANCE-42",
        ),
    )
    monkeypatch.setattr(
        recovery,
        "stack_outputs",
        lambda *_a, **_k: {
            "AssuranceReportSigningKeyArn": old_current,
            "AssuranceReportHistoricalVerificationKeyArns": "[]",
            "RegionalPolicySigningKeyArn": _arn(manifest.primary_region, _POLICY_ID),
        },
    )
    monkeypatch.setattr(
        recovery,
        "recovery_stack_outputs",
        lambda *_a, **_k: {
            "AssuranceReportSigningReplicaKeyArn": new_replica,
            "AssuranceReportHistoricalVerificationReplicaKeyArns": json.dumps([old_replica]),
        },
    )
    monkeypatch.setattr(rotation, "_existing_replica_arn", lambda *_a, **_k: new_replica)
    monkeypatch.setattr(recovery, "deploy_signing_replica", lambda *_a, **_k: None)
    monkeypatch.setattr(recovery, "verify_signing_replica", lambda *_a, **_k: {})
    monkeypatch.setattr(rotation, "verify_old_snapshot_fixture", lambda *_a, **_k: None)
    state = rotation.prepare(
        manifest,
        state_path,
        "change/ASSURANCE-42",
        profile="p1",
        fixture_path=tmp_path / "fixture.json",
    )
    assert state.phase == "prepared"


def test_promote_persists_authority_deploys_both_cells_and_preserves_history(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Phase two makes new current and old verify-only through persistent authority."""
    manifest = _manifest()
    state = rotation.RotationState(
        "prepared",
        manifest.stack_name,
        manifest.primary_region,
        manifest.recovery_region,
        _arn(manifest.primary_region, _OLD_ID),
        _arn(manifest.recovery_region, _OLD_ID),
        (_arn(manifest.primary_region, _OLDER_ID),),
        (_arn(manifest.recovery_region, _OLDER_ID),),
        _arn(manifest.primary_region, _NEW_ID),
        _arn(manifest.recovery_region, _NEW_ID),
        "change/ASSURANCE-42",
    )
    outputs = iter(
        [
            {"AssuranceReportSigningKeyArn": state.old_current_signer_arn},
            {"AssuranceReportSigningKeyArn": state.new_current_signer_arn},
        ]
    )
    monkeypatch.setattr(control, "stack_outputs", lambda *_a, **_k: next(outputs))
    persisted: list[control.AssuranceSignerDeploymentManifest] = []
    monkeypatch.setattr(
        control,
        "persist_assurance_signer_manifest",
        lambda value, *_a, **_k: persisted.append(value),
    )
    monkeypatch.setattr(
        control,
        "load_persisted_assurance_signer_manifest",
        lambda *_a, **_k: persisted[0],
    )
    deployed: list[str] = []
    monkeypatch.setattr(
        control,
        "deploy",
        lambda stack_name, **_kwargs: deployed.append(stack_name),
    )

    def runner(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert "deploy_aws_passive_cell.py" in command[1]
        return subprocess.CompletedProcess(command, 0, "{}", "")

    promoted = rotation.promote(
        state,
        tmp_path / "rotation.json",
        profile="p1",
        passive_config=tmp_path / "passive.json",
        recovery_config=tmp_path / "recovery.json",
        runner=runner,
    )
    assert promoted.phase == "passive_converged"
    assert deployed == [manifest.stack_name]
    assert persisted[0].current_signer_arn == state.new_current_signer_arn
    assert persisted[0].historical_verification_key_arns == (
        state.old_current_signer_arn,
        *state.old_historical_signer_arns,
    )


def test_promotion_resumes_after_each_partial_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Persistence, primary and passive crashes resume from durable checkpoints."""
    manifest = _manifest()
    state_path = tmp_path / "rotation.json"
    state = rotation.RotationState(
        "prepared",
        manifest.stack_name,
        manifest.primary_region,
        manifest.recovery_region,
        _arn(manifest.primary_region, _OLD_ID),
        _arn(manifest.recovery_region, _OLD_ID),
        (),
        (),
        _arn(manifest.primary_region, _NEW_ID),
        _arn(manifest.recovery_region, _NEW_ID),
        "change/ASSURANCE-42",
    )
    rotation._persist_state(state_path, state)
    live = {"signer": state.old_current_signer_arn}
    persisted: list[control.AssuranceSignerDeploymentManifest] = []
    monkeypatch.setattr(
        control,
        "stack_outputs",
        lambda *_a, **_k: {"AssuranceReportSigningKeyArn": live["signer"]},
    )
    monkeypatch.setattr(
        control,
        "persist_assurance_signer_manifest",
        lambda value, *_a, **_k: persisted.append(value),
    )
    monkeypatch.setattr(
        control,
        "load_persisted_assurance_signer_manifest",
        lambda *_a, **_k: persisted[0],
    )
    deploy_attempt = 0

    def deploy(*_args: Any, **_kwargs: Any) -> None:
        nonlocal deploy_attempt
        deploy_attempt += 1
        if deploy_attempt == 1:
            raise RuntimeError("crash before primary deploy")
        live["signer"] = state.new_current_signer_arn
        raise RuntimeError("crash after primary deploy")

    monkeypatch.setattr(control, "deploy", deploy)

    with pytest.raises(RuntimeError, match="before primary"):
        rotation.promote(
            state,
            state_path,
            profile="p1",
            passive_config=tmp_path / "passive.json",
            recovery_config=tmp_path / "recovery.json",
        )
    assert rotation.RotationState.parse(state_path.read_text()).phase == "authority_persisted"

    with pytest.raises(RuntimeError, match="after primary"):
        rotation.promote(
            rotation.RotationState.parse(state_path.read_text()),
            state_path,
            profile="p1",
            passive_config=tmp_path / "passive.json",
            recovery_config=tmp_path / "recovery.json",
        )
    assert rotation.RotationState.parse(state_path.read_text()).phase == "authority_persisted"

    passive_attempt = 0

    def passive_runner(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal passive_attempt
        passive_attempt += 1
        return subprocess.CompletedProcess(
            command,
            2 if passive_attempt == 1 else 0,
            "{}",
            "synthetic passive failure" if passive_attempt == 1 else "",
        )

    with pytest.raises(rotation.AssuranceSignerRotationError, match="passive failure"):
        rotation.promote(
            rotation.RotationState.parse(state_path.read_text()),
            state_path,
            profile="p1",
            passive_config=tmp_path / "passive.json",
            recovery_config=tmp_path / "recovery.json",
            runner=passive_runner,
        )
    assert rotation.RotationState.parse(state_path.read_text()).phase == "primary_promoted"

    converged = rotation.promote(
        rotation.RotationState.parse(state_path.read_text()),
        state_path,
        profile="p1",
        passive_config=tmp_path / "passive.json",
        recovery_config=tmp_path / "recovery.json",
        runner=passive_runner,
    )
    assert converged.phase == "passive_converged"
    assert len(persisted) == 1


def test_pre_rotation_signature_verifies_in_primary_and_recovery(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Completion evidence validates old snapshots through both retained MRKs."""
    manifest = _manifest()
    state = rotation.RotationState(
        "passive_converged",
        manifest.stack_name,
        manifest.primary_region,
        manifest.recovery_region,
        _arn(manifest.primary_region, _OLD_ID),
        _arn(manifest.recovery_region, _OLD_ID),
        (),
        (),
        _arn(manifest.primary_region, _NEW_ID),
        _arn(manifest.recovery_region, _NEW_ID),
        "change/ASSURANCE-42",
    )
    fixture = tmp_path / "fixture.json"
    fixture.write_text(
        json.dumps(
            {
                "messageBase64": base64.b64encode(b"a" * 32).decode(),
                "signatureBase64": base64.b64encode(b"synthetic-signature").decode(),
            }
        )
    )
    calls: list[tuple[str, str]] = []

    def fake_aws(arguments: list[str], *, region: str, **_kwargs: Any) -> dict[str, Any]:
        calls.append((arguments[3], region))
        return {
            "SignatureValid": True,
            "KeyId": arguments[3],
            "SigningAlgorithm": "ECDSA_SHA_256",
        }

    monkeypatch.setattr(rotation, "_aws", fake_aws)
    rotation.verify_old_snapshot_fixture(state, fixture, profile="p1")
    assert calls == [
        (state.old_current_signer_arn, state.primary_region),
        (state.old_current_replica_arn, state.recovery_region),
    ]


def test_rotation_verification_rejects_false_signature_and_malformed_fixture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Rotation evidence fails closed for provider denial and malformed base64."""
    manifest = _manifest()
    state = rotation.RotationState(
        "passive_converged",
        manifest.stack_name,
        manifest.primary_region,
        manifest.recovery_region,
        _arn(manifest.primary_region, _OLD_ID),
        _arn(manifest.recovery_region, _OLD_ID),
        (),
        (),
        _arn(manifest.primary_region, _NEW_ID),
        _arn(manifest.recovery_region, _NEW_ID),
        "change/ASSURANCE-42",
    )
    fixture = tmp_path / "fixture.json"
    fixture.write_text(
        json.dumps(
            {
                "messageBase64": base64.b64encode(b"a" * 32).decode(),
                "signatureBase64": base64.b64encode(b"signature").decode(),
            }
        )
    )
    monkeypatch.setattr(rotation, "_aws", lambda *_a, **_k: {"SignatureValid": False})
    with pytest.raises(rotation.AssuranceSignerRotationError, match="verification failed"):
        rotation.verify_old_snapshot_fixture(state, fixture, profile="p1")
    fixture.write_text(json.dumps({"messageBase64": "%%%", "signatureBase64": "%%%"}))
    with pytest.raises(rotation.AssuranceSignerRotationError, match="fixture is invalid"):
        rotation.verify_old_snapshot_fixture(state, fixture, profile="p1")


@pytest.mark.parametrize(
    "response",
    (
        {
            "SignatureValid": True,
            "KeyId": "arn:aws:kms:eu-west-2:123456789012:key/mrk-" + "9" * 32,
            "SigningAlgorithm": "ECDSA_SHA_256",
        },
        {
            "SignatureValid": True,
            "KeyId": _arn("eu-west-2", _OLD_ID),
            "SigningAlgorithm": "RSASSA_PSS_SHA_256",
        },
    ),
)
def test_rotation_verification_binds_returned_key_and_algorithm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, response: dict[str, Any]
) -> None:
    """A provider cannot attest a different key or algorithm."""
    manifest = _manifest()
    state = rotation.RotationState(
        "passive_converged",
        manifest.stack_name,
        manifest.primary_region,
        manifest.recovery_region,
        _arn(manifest.primary_region, _OLD_ID),
        _arn(manifest.recovery_region, _OLD_ID),
        (),
        (),
        _arn(manifest.primary_region, _NEW_ID),
        _arn(manifest.recovery_region, _NEW_ID),
        "change/ASSURANCE-42",
    )
    fixture = tmp_path / "fixture.json"
    fixture.write_text(
        json.dumps(
            {
                "messageBase64": base64.b64encode(b"a" * 32).decode(),
                "signatureBase64": base64.b64encode(b"signature").decode(),
            }
        )
    )
    monkeypatch.setattr(rotation, "_aws", lambda *_a, **_k: response)
    with pytest.raises(rotation.AssuranceSignerRotationError, match="verification failed"):
        rotation.verify_old_snapshot_fixture(state, fixture, profile="p1")


@pytest.mark.parametrize(("message", "signature"), ((b"a" * 31, b"sig"), (b"a" * 32, b"s" * 1_025)))
def test_rotation_fixture_enforces_digest_and_signature_bounds(
    tmp_path: Path, message: bytes, signature: bytes
) -> None:
    """Only one SHA-256 digest and a bounded signature enter KMS verification."""
    manifest = _manifest()
    state = rotation.RotationState(
        "passive_converged",
        manifest.stack_name,
        manifest.primary_region,
        manifest.recovery_region,
        _arn(manifest.primary_region, _OLD_ID),
        _arn(manifest.recovery_region, _OLD_ID),
        (),
        (),
        _arn(manifest.primary_region, _NEW_ID),
        _arn(manifest.recovery_region, _NEW_ID),
        "change/ASSURANCE-42",
    )
    fixture = tmp_path / "fixture.json"
    fixture.write_text(
        json.dumps(
            {
                "messageBase64": base64.b64encode(message).decode(),
                "signatureBase64": base64.b64encode(signature).decode(),
            }
        )
    )
    with pytest.raises(rotation.AssuranceSignerRotationError, match="fixture is invalid"):
        rotation.verify_old_snapshot_fixture(state, fixture, profile="p1")


def test_rotation_fixture_rejects_complete_file_over_sixteen_kib(tmp_path: Path) -> None:
    """The parser rejects an oversized fixture before Base64 or KMS work."""
    manifest = _manifest()
    state = rotation.RotationState(
        "passive_converged",
        manifest.stack_name,
        manifest.primary_region,
        manifest.recovery_region,
        _arn(manifest.primary_region, _OLD_ID),
        _arn(manifest.recovery_region, _OLD_ID),
        (),
        (),
        _arn(manifest.primary_region, _NEW_ID),
        _arn(manifest.recovery_region, _NEW_ID),
        "change/ASSURANCE-42",
    )
    fixture = tmp_path / "fixture.json"
    fixture.write_text(
        json.dumps(
            {
                "messageBase64": base64.b64encode(b"a" * 32).decode(),
                "signatureBase64": base64.b64encode(b"s" * 12_300).decode(),
            }
        )
    )
    assert fixture.stat().st_size > 16_384
    with pytest.raises(rotation.AssuranceSignerRotationError, match="fixture is invalid"):
        rotation.verify_old_snapshot_fixture(state, fixture, profile="p1")


def test_signer_manifest_rejects_current_history_overlap() -> None:
    """Persistent deployment authority cannot grant one key both roles."""
    current = _arn("eu-west-2", _NEW_ID)
    with pytest.raises(control.DeploymentConfigurationError):
        control.AssuranceSignerDeploymentManifest.parse(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "currentSignerArn": current,
                    "historicalVerificationKeyArns": [current],
                    "recoveryRegion": "eu-west-1",
                    "approvalEvidenceRef": "change/ASSURANCE-42",
                }
            )
        )
