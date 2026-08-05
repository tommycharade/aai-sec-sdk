"""Adversarial tests for deterministic restrictive policy composition."""

from __future__ import annotations

import copy
import hashlib
from typing import Any

import pytest

from agentic_security.policy_composition import (
    PolicyComponent,
    PolicyCompositionError,
    compose_policy,
)


def component(
    policy_id: str, configuration: dict[str, object], *, version: int = 1
) -> PolicyComponent:
    """Return one synthetic exact component identity."""
    digest = hashlib.sha256(f"{policy_id}:{version}".encode()).hexdigest()
    return PolicyComponent(policy_id, version, digest, configuration)


def test_restrictive_rules_create_one_explainable_effective_policy() -> None:
    baseline = component(
        "baseline",
        {
            "policy": {"denyByDefault": True, "allowedPrincipals": ["alice", "bob"]},
            "tools": {"allowed": ["Read", "Write"], "denied": ["Shell"]},
            "approvals": {"ttlSeconds": 600, "requiredFor": ["high-risk"]},
            "budgets": {"maxActions": 30},
            "isolation": {
                "requiredForHighRisk": False,
                "acceptedProfiles": ["docker-reviewed", "microvm-reviewed"],
            },
            "audit": {"redactSensitiveData": True, "captureToolContent": True},
            "runtime": {"policyProvider": "local_allow_list"},
        },
    )
    result = compose_policy(
        [baseline],
        {
            "policy": {"denyByDefault": True, "allowedPrincipals": ["alice"]},
            "tools": {"allowed": ["Read", "Edit"], "denied": ["Delete"]},
            "approvals": {"ttlSeconds": 300, "requiredFor": ["external"]},
            "budgets": {"maxActions": 10},
            "isolation": {
                "requiredForHighRisk": True,
                "acceptedProfiles": ["docker-reviewed", "wasm-reviewed"],
            },
            "audit": {"redactSensitiveData": True, "captureToolContent": False},
            "runtime": {"policyProvider": "local_allow_list"},
        },
    )
    assert result.configuration == {
        "approvals": {"requiredFor": ["external", "high-risk"], "ttlSeconds": 300},
        "audit": {"captureToolContent": False, "redactSensitiveData": True},
        "budgets": {"maxActions": 10},
        "isolation": {
            "acceptedProfiles": ["docker-reviewed"],
            "requiredForHighRisk": True,
        },
        "policy": {"allowedPrincipals": ["alice"], "denyByDefault": True},
        "runtime": {"policyProvider": "local_allow_list"},
        "tools": {"allowed": ["Read"], "denied": ["Delete", "Shell"]},
    }
    allowed = next(step for step in result.explanation if step.field == "tools.allowed")
    assert allowed.rule == "allow_intersection"
    assert allowed.sources == (baseline.identity, "local")
    assert allowed.removed == ("Edit", "Write")
    assert len(result.graph_digest) == 64
    assert result.to_dict()["configuration"] == result.configuration


def test_component_order_cannot_change_effective_authority() -> None:
    first = component("alpha", {"tools": {"allowed": ["Read", "Write"]}})
    second = component("bravo", {"tools": {"allowed": ["Read", "Edit"]}})
    left = compose_policy([first, second], {})
    right = compose_policy([second, first], {})
    assert left.configuration == right.configuration == {"tools": {"allowed": ["Read"]}}
    # Order remains content-bound for review; silently reordering reviewed
    # sources creates a different graph digest even when authority is equal.
    assert left.graph_digest != right.graph_digest


def test_empty_allow_intersection_is_valid_fail_closed_authority() -> None:
    result = compose_policy(
        [component("alpha", {"claudeCode": {"allowedBuiltInTools": ["Read"]}})],
        {"claudeCode": {"allowedBuiltInTools": ["Write"]}},
    )
    assert result.configuration["claudeCode"]["allowedBuiltInTools"] == []


@pytest.mark.parametrize(
    "configuration",
    [
        {"policy": {"denyByDefault": False}},
        {"audit": {"redactSensitiveData": False}},
        {"runtime": {"redactSensitiveData": False}},
    ],
)
def test_immutable_safeguards_cannot_be_disabled(
    configuration: dict[str, object],
) -> None:
    with pytest.raises(PolicyCompositionError, match="immutable safeguard"):
        compose_policy([], configuration)


@pytest.mark.parametrize(
    ("left", "right", "message"),
    [
        (
            {"runtime": {"policyProvider": "opa"}},
            {"runtime": {"policyProvider": "cedar"}},
            "conflicting exact",
        ),
        ({"legacy": {"mode": "one"}}, {"legacy": {"mode": "two"}}, "conflicting exact"),
        ({"legacy": {"first": 1}}, {"legacy": {"second": 2}}, "conflicting exact"),
        ({"budgets": {"maxActions": True}}, {"budgets": {"maxActions": 2}}, "limits"),
        ({"tools": {"allowed": ["Read", "Read"]}}, {}, "duplicate-free"),
    ],
)
def test_conflicts_and_ambiguous_values_fail_closed(
    left: dict[str, object], right: dict[str, object], message: str
) -> None:
    with pytest.raises(PolicyCompositionError, match=message):
        compose_policy([component("alpha", left)], right)


def test_component_identity_and_count_are_bounded() -> None:
    duplicate = component("alpha", {})
    with pytest.raises(PolicyCompositionError, match="unique"):
        compose_policy([duplicate, duplicate], {})
    with pytest.raises(PolicyCompositionError, match="at most eight"):
        compose_policy(
            [component(chr(97 + index), {}, version=index + 1) for index in range(9)], {}
        )
    with pytest.raises(PolicyCompositionError, match="content hash"):
        PolicyComponent("alpha", 1, "not-a-hash", {})


def test_component_and_json_shape_validation_cover_every_public_boundary() -> None:
    """Malformed identities, graphs, scalar types and oversized JSON are rejected."""
    digest = "0" * 64
    with pytest.raises(PolicyCompositionError, match="policy ID"):
        PolicyComponent("", 1, digest, {})
    with pytest.raises(PolicyCompositionError, match="positive integer"):
        PolicyComponent("alpha", True, digest, {})
    with pytest.raises(PolicyCompositionError, match="graph digest"):
        PolicyComponent("alpha", 1, digest, {}, graph_digest="invalid")
    with pytest.raises(PolicyCompositionError, match="must be an object"):
        PolicyComponent("alpha", 1, digest, [])  # type: ignore[arg-type]
    with pytest.raises(PolicyCompositionError, match="object key"):
        compose_policy([], {"": 1})
    with pytest.raises(PolicyCompositionError, match="list exceeds"):
        compose_policy([], {"legacy": [0] * 10_001})
    assert compose_policy([], {"legacy": 1.5}).configuration == {"legacy": 1.5}
    with pytest.raises(PolicyCompositionError, match="must contain booleans"):
        compose_policy(
            [component("alpha", {"telemetry": {"enabled": True}})],
            {"telemetry": {"enabled": "yes"}},
        )
    with pytest.raises(PolicyCompositionError, match="must contain booleans"):
        compose_policy([], {"telemetry": {"enabled": "yes"}})
    with pytest.raises(PolicyCompositionError, match="source must be an object"):
        compose_policy([], [])  # type: ignore[arg-type]
    with pytest.raises(PolicyCompositionError, match="path is ambiguous"):
        compose_policy([], {"legacy": 1, "legacy.child": 2})
    with pytest.raises(PolicyCompositionError, match="exceeds 1 MiB"):
        compose_policy([], {"legacy": "x" * 1_048_576})


def test_results_are_defensive_and_deterministic() -> None:
    local: dict[str, object] = {
        "tools": {"allowed": ["Write", "Read"]},
        "policy": {"denyByDefault": True},
    }
    original = copy.deepcopy(local)
    first = compose_policy([], local)
    local["tools"] = {"allowed": ["Delete"]}
    second = compose_policy([], original)
    assert first.to_dict() == second.to_dict()
    assert first.configuration["tools"]["allowed"] == ["Read", "Write"]
    with pytest.raises(TypeError):
        first.configuration["tools"]["allowed"] = ("Delete",)
    component_source: dict[str, Any] = {"tools": {"allowed": ["Read"]}}
    frozen = component("frozen", component_source)
    component_source["tools"]["allowed"] = ["Delete"]
    assert compose_policy([frozen], {}).configuration["tools"]["allowed"] == ("Read",)


def test_empty_typed_sections_are_no_opinions() -> None:
    result = compose_policy(
        [component("baseline", {"policy": {}})],
        {"policy": {"denyByDefault": True}},
    )
    assert result.configuration == {"policy": {"denyByDefault": True}}


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        object(),
        {
            "nested": {
                "too": {"deep": {"for": {"the": {"bounded": {"policy": {"input": {"x": 1}}}}}}}
            }
        },
    ],
)
def test_non_json_or_unbounded_values_are_rejected(value: object) -> None:
    with pytest.raises(PolicyCompositionError):
        compose_policy([], {"legacy": {"value": value}})
