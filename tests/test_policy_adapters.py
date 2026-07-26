from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from agentic_security import (
    ActionProposal,
    CedarPolicyEngine,
    ExecutionContext,
    GuardedRuntime,
    InMemoryAuditSink,
    OpaPolicyEngine,
    PolicyRequest,
    Principal,
    Resource,
    ToolDefinition,
    ToolRegistry,
)
from agentic_security.policies import PolicyDecision


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("allow", PolicyDecision.ALLOW),
        ("Allowed", PolicyDecision.ALLOW),
        ("permit", PolicyDecision.ALLOW),
        ("permitted", PolicyDecision.ALLOW),
        ("deny", PolicyDecision.DENY),
        ("Denied", PolicyDecision.DENY),
        ("forbid", PolicyDecision.DENY),
        ("approval_required", PolicyDecision.APPROVAL_REQUIRED),
        ("approval", PolicyDecision.APPROVAL_REQUIRED),
        ("approval-required", PolicyDecision.APPROVAL_REQUIRED),
    ],
)
def test_policy_adapters_map_all_explicit_decision_spellings(
    value: str, expected: PolicyDecision
) -> None:
    result = CedarPolicyEngine(lambda _: {"decision": value}).decide(
        context(), tool(), {"record_id": "record:1"}, ()
    )
    assert result.decision is expected


def context() -> ExecutionContext:
    return ExecutionContext(
        "agent:policy-test",
        Principal("user:alice", tenant="tenant:a"),
        "task:policy-test",
        "test external policy",
        tenant="tenant:a",
    )


def tool() -> ToolDefinition:
    return ToolDefinition(
        "read_record",
        lambda _context, arguments: {"record": arguments["record_id"]},
        lambda arguments: dict(arguments),
        description="Read one synthetic record.",
        resources=lambda arguments: (Resource(arguments["record_id"], "record", "tenant:a"),),
    )


def test_policy_request_contains_live_identity_arguments_and_resources() -> None:
    request = PolicyRequest.from_action(
        context(), tool(), {"record_id": "record:1"}, (Resource("record:1", "record", "tenant:a"),)
    )

    value = request.to_dict()

    assert value["principal_id"] == "user:alice"
    assert value["tool_name"] == "read_record"
    assert value["arguments"] == {"record_id": "record:1"}
    assert value["resources"] == [{"id": "record:1", "kind": "record", "tenant": "tenant:a"}]


def test_opa_adapter_maps_allow_result() -> None:
    calls: list[Mapping[str, Any]] = []

    def evaluate(payload: Mapping[str, Any]) -> Mapping[str, Any]:
        calls.append(payload)
        return {"result": {"allow": True}}

    engine = OpaPolicyEngine(evaluate)
    result = engine.decide(context(), tool(), {"record_id": "record:1"}, ())

    assert result.decision is PolicyDecision.ALLOW
    assert calls[0]["input"]["principal_id"] == "user:alice"


def test_cedar_adapter_maps_explicit_deny_result() -> None:
    engine = CedarPolicyEngine(lambda _: {"decision": "Deny", "reason": "closed period"})

    result = engine.decide(context(), tool(), {"record_id": "record:1"}, ())

    assert result.decision is PolicyDecision.DENY
    assert result.reason == "closed period"


def test_external_policy_metadata_is_preserved() -> None:
    engine = CedarPolicyEngine(
        lambda _: {
            "decision": "Allow",
            "policy_version": "policy-42",
            "provenance": "cedar-production",
        }
    )

    result = engine.decide(context(), tool(), {"record_id": "record:1"}, ())

    assert result.policy_version == "policy-42"
    assert result.provenance == "cedar-production"


@pytest.mark.parametrize(
    ("response", "reason", "version", "provenance"),
    [
        (
            {"decision": "Allow", "allow": False},
            "Cedar policy allowed this action",
            None,
            None,
        ),
        (
            {"allow": False},
            "Cedar policy allowed this action",
            None,
            None,
        ),
        (
            {
                "decision": "Allow",
                "reason": "approved",
                "version": "legacy-version",
                "source": "legacy-source",
            },
            "approved",
            "legacy-version",
            "legacy-source",
        ),
    ],
)
def test_policy_adapter_preserves_precedence_and_metadata_fallbacks(
    response: dict[str, Any], reason: str, version: str | None, provenance: str | None
) -> None:
    """Explicit decisions win and legacy metadata remains observable."""
    result = CedarPolicyEngine(lambda _: response).decide(context(), tool(), {}, ())
    assert result.reason == reason
    assert result.policy_version == version
    assert result.provenance == provenance


def test_policy_adapter_rejects_non_string_metadata_and_reasons() -> None:
    """Malformed provider metadata cannot become policy evidence."""
    result = CedarPolicyEngine(
        lambda _: {
            "decision": "Allow",
            "reason": 42,
            "policy_version": object(),
            "provenance": [],
        }
    ).decide(context(), tool(), {}, ())
    assert result.reason == "Cedar policy allowed this action"
    assert result.policy_version is None
    assert result.provenance is None


def test_external_policy_errors_fail_closed() -> None:
    engine = OpaPolicyEngine(lambda _: {"result": {"decision": "maybe"}})
    result = engine.decide(context(), tool(), {"record_id": "record:1"}, ())
    assert result.decision is PolicyDecision.DENY

    failing = CedarPolicyEngine(lambda _: (_ for _ in ()).throw(RuntimeError("offline")))
    result = failing.decide(context(), tool(), {"record_id": "record:1"}, ())
    assert result.decision is PolicyDecision.DENY


def test_opa_adapter_is_used_by_runtime_before_handler() -> None:
    called = []
    registered = ToolDefinition(
        "read_record",
        lambda _context, arguments: called.append(arguments),
        lambda arguments: dict(arguments),
        description="Read one synthetic record.",
    )
    registry = ToolRegistry()
    registry.register(registered)
    runtime = GuardedRuntime(
        context(),
        registry,
        OpaPolicyEngine(lambda _: {"result": {"allow": False, "reason": "denied by OPA"}}),
        InMemoryAuditSink(),
    )

    result = runtime.execute(ActionProposal("read_record", {"record_id": "record:1"}, "proposal:1"))

    assert result.status == "denied"
    assert called == []
