from __future__ import annotations

from collections.abc import Mapping
from typing import Any

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
