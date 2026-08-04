"""Parity contracts for the generated standalone AWS composition runtime."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

from agentic_security.policy_composition import (
    PolicyComponent,
    PolicyCompositionError,
    compose_policy,
)
from agentic_security.policy_sources import PolicySourceDocument

ROOT = Path(__file__).parents[1]


def load_module(path: Path, name: str) -> ModuleType:
    """Load one repository module without changing global import paths."""
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def test_generated_lambda_runtime_is_current() -> None:
    """The deployable Lambda copy cannot drift from the canonical SDK source."""
    generator = load_module(
        ROOT / "scripts/generate_aws_policy_composition.py",
        "aws_policy_composition_generator",
    )
    target = ROOT / "infra/aws-control-plane/lambda/policy_composition.py"
    assert target.read_text(encoding="utf-8") == generator.rendered()


def test_generated_policy_source_runtimes_are_current_and_semantically_equal() -> None:
    """AWS source verification cannot drift from the canonical SDK contracts."""
    generator = load_module(
        ROOT / "scripts/generate_aws_policy_sources.py",
        "aws_policy_source_generator",
    )
    for source, target in generator.SOURCES.items():
        assert target.read_text(encoding="utf-8") == generator.rendered(source)
    runtime = load_module(
        ROOT / "infra/aws-control-plane/lambda/policy_sources.py",
        "policy_sources",
    )
    source = (
        b'{"schemaVersion":1,"policyId":"policy-a","organizationId":"org-a",'
        b'"name":"A","componentRefs":[],"localConfiguration":'
        b'{"policy":{"denyByDefault":true}}}'
    )
    assert (
        runtime.PolicySourceDocument.from_bytes(source).wire()
        == PolicySourceDocument.from_bytes(source).wire()
    )
    github = load_module(
        ROOT / "infra/aws-control-plane/lambda/github_policy_source.py",
        "aws_github_policy_source",
    )
    assert github.GitHubPolicySourceVerifier.__name__ == "GitHubPolicySourceVerifier"


def test_generated_lambda_runtime_matches_restrictive_sdk_semantics() -> None:
    """AWS and SDK produce identical authority, explanation and graph evidence."""
    runtime = load_module(
        ROOT / "infra/aws-control-plane/lambda/policy_composition.py",
        "aws_policy_composition_runtime",
    )
    digest = hashlib.sha256(b"baseline").hexdigest()
    graph_digest = hashlib.sha256(b"baseline-graph").hexdigest()
    configuration = {
        "policy": {"denyByDefault": True},
        "tools": {"allowed": ["Read", "Write"], "denied": ["Shell"]},
        "approvals": {"requiredFor": ["external"], "ttlSeconds": 600},
        "budgets": {"maxActions": 20},
        "audit": {"redactSensitiveData": True, "captureToolContent": True},
    }
    local = {
        "policy": {"denyByDefault": True},
        "tools": {"allowed": ["Read", "Edit"], "denied": ["Delete"]},
        "approvals": {"requiredFor": ["high-risk"], "ttlSeconds": 300},
        "budgets": {"maxActions": 10},
        "audit": {"redactSensitiveData": True, "captureToolContent": False},
    }
    sdk = compose_policy(
        [PolicyComponent("baseline", 1, digest, configuration, graph_digest)],
        local,
    ).to_dict()
    aws = runtime.compose_policy(
        [runtime.PolicyComponent("baseline", 1, digest, configuration, graph_digest)],
        local,
    ).to_dict()
    assert aws == sdk


@pytest.mark.parametrize(
    "configuration",
    [
        {"policy": {"denyByDefault": False}},
        {"telemetry": {"enabled": "yes"}},
        {"tools": {"allowed": ["Read", "Read"]}},
    ],
)
def test_generated_lambda_runtime_fails_closed_like_sdk(
    configuration: dict[str, object],
) -> None:
    """Unsafe standalone inputs raise the same public failure family."""
    runtime = load_module(
        ROOT / "infra/aws-control-plane/lambda/policy_composition.py",
        "aws_policy_composition_runtime_denial",
    )
    with pytest.raises(PolicyCompositionError):
        compose_policy([], configuration)
    with pytest.raises(runtime.PolicyCompositionError):
        runtime.compose_policy([], configuration)
