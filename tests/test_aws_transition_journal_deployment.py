"""Adversarial contracts for the transition-witness deployment guard."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "deploy_aws_transition_journal.py"
    spec = importlib.util.spec_from_file_location("aai_deploy_transition_journal", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _value(**updates: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schemaVersion": 1,
        "stackName": "AaiSecRegionalTransitionJournal",
        "tableName": "AaiSecRegionalTransitionJournal",
        "coordinationRegion": "eu-central-1",
        "primaryRegion": "eu-west-2",
        "recoveryRegion": "eu-west-1",
        "approvalEvidenceRef": "change/WITNESS-123",
        "activationPermitted": False,
    }
    result.update(updates)
    return result


def _completed(value: dict[str, Any] | None = None, *, error: str = "") -> Any:
    return subprocess.CompletedProcess([], 1 if error else 0, json.dumps(value or {}), error)


def test_manifest_is_exact_canonical_distinct_and_non_activating() -> None:
    module = _load()
    manifest = module.TransitionJournalDeploymentManifest.parse(json.dumps(_value()))
    assert json.loads(manifest.canonical_json()) == _value()
    assert module.parameter_name(manifest) == (
        "/aai-sec/AaiSecRegionalTransitionJournal/deployment"
    )
    with pytest.raises(module.TransitionJournalDeploymentError, match="duplicate"):
        module.TransitionJournalDeploymentManifest.parse('{"schemaVersion":1,"schemaVersion":1}')
    with pytest.raises(module.TransitionJournalDeploymentError, match="prohibit activation"):
        module.TransitionJournalDeploymentManifest.parse(
            json.dumps(_value(activationPermitted=True))
        )
    with pytest.raises(module.TransitionJournalDeploymentError, match="must be distinct"):
        module.TransitionJournalDeploymentManifest.parse(
            json.dumps(_value(coordinationRegion="eu-west-2"))
        )


def test_environment_strips_ambient_authority(monkeypatch: Any) -> None:
    module = _load()
    manifest = module.TransitionJournalDeploymentManifest.parse(json.dumps(_value()))
    monkeypatch.setenv("TRANSITION_COORDINATION_REGION", "attacker-region")
    monkeypatch.setenv("TRANSITION_JOURNAL_TABLE_NAME", "AttackerTable")
    monkeypatch.setenv("PRIMARY_REGION", "attacker-primary")
    monkeypatch.setenv("CDK_DEFAULT_ACCOUNT", "999999999999")
    environment = module.deployment_environment(
        manifest, profile="synthetic", account_id="111111111111"
    )
    assert environment["TRANSITION_COORDINATION_REGION"] == "eu-central-1"
    assert environment["TRANSITION_JOURNAL_TABLE_NAME"] == manifest.table_name
    assert environment["PRIMARY_REGION"] == "eu-west-2"
    assert environment["CDK_DEFAULT_ACCOUNT"] == "111111111111"


def test_persisted_deployment_authority_must_match_exactly() -> None:
    module = _load()
    manifest = module.TransitionJournalDeploymentManifest.parse(json.dumps(_value()))
    stored = manifest.canonical_json()
    calls: list[list[str]] = []

    def runner(command: list[str], **_: Any) -> Any:
        calls.append(command)
        if "get-parameter" in command:
            return _completed({"Parameter": {"Value": stored}})
        return _completed()

    module.persist_manifest(manifest, profile="synthetic", runner=runner)
    module.require_persisted_manifest(manifest, profile="synthetic", runner=runner)
    assert any("SecureString" in command for command in calls)
    stored = module.TransitionJournalDeploymentManifest.parse(
        json.dumps(_value(approvalEvidenceRef="change/DIFFERENT-123"))
    ).canonical_json()
    with pytest.raises(module.TransitionJournalDeploymentError, match="differs"):
        module.require_persisted_manifest(manifest, profile="synthetic", runner=runner)


def test_deploy_uses_only_exact_verified_uninitialized_assembly(monkeypatch: Any) -> None:
    module = _load()
    manifest = module.TransitionJournalDeploymentManifest.parse(json.dumps(_value()))
    payload = b'{"verified":true}'
    monkeypatch.setattr(module.Path, "read_bytes", lambda *_args, **_kw: payload)
    calls: list[list[str]] = []

    def runner(command: list[str], **_: Any) -> Any:
        calls.append(command)
        return _completed()

    module.deploy(
        manifest,
        {"TRANSITION_COORDINATION_REGION": "eu-central-1"},
        hashlib.sha256(payload).hexdigest(),
        runner=runner,
    )
    assert "cdk.out" in calls[0]
    assert "deploy" in calls[0]
    assert "ts-node" not in calls[0]
    assert not any(term in calls[0] for term in ("route53", "lambda", "initialize"))
    with pytest.raises(module.TransitionJournalDeploymentError, match="changed after verification"):
        module.deploy(manifest, {}, "0" * 64, runner=runner)


def test_deployment_guard_has_no_initialization_or_routing_authority() -> None:
    source = (Path(__file__).parents[1] / "scripts" / "deploy_aws_transition_journal.py").read_text(
        encoding="utf-8"
    )
    assert 'choices=("check", "prepare", "deploy")' in source
    assert "initialize_state" not in source
    assert "route53" not in source.lower()
    assert '"activationPermitted": False' in source
