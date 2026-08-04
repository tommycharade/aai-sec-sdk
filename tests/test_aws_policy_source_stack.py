"""Synthesized least-privilege contracts for hosted policy GitHub verification."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).parents[1]
INFRA = ROOT / "infra/aws-control-plane"


def synth(**updates: str) -> dict[str, Any]:
    """Synthesize the stack with explicit synthetic GitHub deployment inputs."""
    if not (INFRA / "node_modules/aws-cdk-lib").is_dir():
        pytest.skip("pinned CDK dependencies are absent; the policy-source-iac job owns synthesis")
    environment = {
        **os.environ,
        "POLICY_GITHUB_SECRET_NAME": "aai-sec/policy/github",
        "POLICY_GITHUB_ALLOWED_REPOSITORIES": "github.com/example/security-policy",
        **updates,
    }
    result = subprocess.run(
        ["npx", "cdk", "synth", "--json"],  # noqa: S607 - repository-locked CLI
        cwd=INFRA,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return cast(dict[str, Any], json.loads(result.stdout))


def test_policy_source_worker_is_isolated_and_handler_invocation_is_exact() -> None:
    """Only the worker reads GitHub credentials; only the handler may invoke it."""
    template = synth()
    resources = template["Resources"]
    workers = [
        value
        for value in resources.values()
        if value.get("Type") == "AWS::Lambda::Function"
        and value["Properties"].get("Handler") == "policy_source_verifier.handler"
    ]
    assert len(workers) == 1
    environment = workers[0]["Properties"]["Environment"]["Variables"]
    assert environment["POLICY_GITHUB_ALLOWED_REPOSITORIES"] == (
        "github.com/example/security-policy"
    )
    worker_policy = next(
        value
        for key, value in resources.items()
        if key.startswith("PolicySourceVerifierServiceRoleDefaultPolicy")
    )
    worker_statements = worker_policy["Properties"]["PolicyDocument"]["Statement"]
    worker_actions = {
        action
        for statement in worker_statements
        for action in (
            statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
        )
    }
    assert "secretsmanager:GetSecretValue" in worker_actions
    assert not any(
        action.startswith(("dynamodb:", "kms:Sign", "lambda:InvokeFunction"))
        for action in worker_actions
    )
    handler_policy = next(
        value
        for key, value in resources.items()
        if key.startswith("ControlPlaneHandlerServiceRoleDefaultPolicy")
    )
    invoke = next(
        statement
        for statement in handler_policy["Properties"]["PolicyDocument"]["Statement"]
        if statement["Action"] == "lambda:InvokeFunction"
    )
    assert "PolicySourceVerifier" in json.dumps(invoke["Resource"])


def test_policy_source_stack_rejects_partial_or_malformed_configuration() -> None:
    """A secret without an allow-list and a mutable repository selector fail synthesis."""
    for updates in (
        {"POLICY_GITHUB_ALLOWED_REPOSITORIES": ""},
        {"POLICY_GITHUB_ALLOWED_REPOSITORIES": "github.com/example/*"},
    ):
        environment = {
            **os.environ,
            "POLICY_GITHUB_SECRET_NAME": "aai-sec/policy/github",
            **updates,
        }
        result = subprocess.run(
            ["npx", "cdk", "synth", "--json"],  # noqa: S607 - repository-locked CLI
            cwd=INFRA,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode != 0
