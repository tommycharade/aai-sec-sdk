# API reference and design

The public API uses typed objects and structured outcomes. A minimal integration
with the current SDK looks like this:

The package ships a `py.typed` marker so downstream type checkers can use its
public annotations.

```python
from agentic_security import (
    ActionProposal,
    ExecutionContext,
    GuardedRuntime,
    InMemoryAuditSink,
    Principal,
    RiskLevel,
    ToolDefinition,
    ToolRegistry,
)
from agentic_security.policies import AllowListPolicy

context = ExecutionContext(
    agent_id="agent:example",
    principal=Principal("user:alice", tenant="tenant:example"),
    task_id="task:example",
    purpose="read one synthetic record",
    tenant="tenant:example",
)
registry = ToolRegistry()
registry.register(ToolDefinition(
    name="read_record",
    handler=lambda ctx, args: {"record_id": args["record_id"]},
    validator=lambda args: {"record_id": args["record_id"]},
    risk=RiskLevel.LOW,
    description="Read one synthetic record.",
))
runtime = GuardedRuntime(
    context, registry, AllowListPolicy({"read_record"}), InMemoryAuditSink()
)
result = runtime.execute(
    ActionProposal("read_record", {"record_id": "record_001"}, "proposal:1")
)
assert result.status == "executed"
```

Expected outcomes use `ExecutionStatus.EXECUTED`, `DENIED`,
`APPROVAL_REQUIRED`, `FAILED`, `EXECUTED_UNRECORDED`,
`EXECUTED_RESULT_REJECTED`, `TIMED_OUT`, or `CANCELLED`; callers must not
blindly retry `TIMED_OUT` or `EXECUTED_UNRECORDED` because side-effect or audit
state may be uncertain. Policy decisions use `PolicyDecision`. The
generated reference below is built from public docstrings and is checked in CI.
The example is synthetic and does not connect to a model or external service.

## Public runtime API

::: agentic_security.GuardedRuntime

::: agentic_security.types.ExecutionContext

::: agentic_security.types.Principal

::: agentic_security.types.Resource

::: agentic_security.types.ActionProposal

::: agentic_security.types.ExecutionResult

::: agentic_security.types.ExecutionStatus

::: agentic_security.types.CancellationToken

::: agentic_security.RuntimeConfig

## Tools

::: agentic_security.tools.ToolDefinition

`ToolDefinition` applies result redaction and a serialized size limit before a
handler result crosses the runtime boundary. Use `output_validator` for an
application-specific result schema or normalization step.

::: agentic_security.tools.ToolRegistry

::: agentic_security.tools.OutputValidator

::: agentic_security.tools.ReconciliationHandler

## Policies

::: agentic_security.policies.PolicyEngine

::: agentic_security.policies.AllowListPolicy

::: agentic_security.policies.PolicyDecision

::: agentic_security.policies.PolicyResult

::: agentic_security.policy_adapters.PolicyRequest

::: agentic_security.policy_adapters.OpaPolicyEngine

::: agentic_security.policy_adapters.CedarPolicyEngine

`PolicyResult` may carry an external policy version and provenance label. The
runtime preserves both in execution audit evidence so operators can identify
which policy decision point authorized an action.

## Approvals and audit

Approvals must be bound to the hash of the validated arguments and extracted
resources. An approval for one proposal or argument set cannot authorize a
modified action.

::: agentic_security.approvals.ApprovalProvider

::: agentic_security.approvals.ApprovalGrant

::: agentic_security.approvals.action_hash

::: agentic_security.approvals.InMemoryApprovalProvider

::: agentic_security.audit.InMemoryAuditSink

## Credential brokering

::: agentic_security.credentials.CredentialBroker

::: agentic_security.credentials.CredentialMetadata

::: agentic_security.credentials.ScopedCredential

::: agentic_security.credentials.InMemoryCredentialBroker

::: agentic_security.credentials.TokenCredentialBroker

## Deployment adapters

The package includes explicit adapters for common deployment infrastructure.
`JsonHttpClient` requires HTTPS (except explicitly enabled localhost tests),
uses a bounded timeout, and never invents authentication or retry behavior.
`HttpOpaPolicyEngine`, `HttpCedarPolicyEngine`, and `HttpApprovalProvider` use
that transport. `JsonlAuditSink` provides fsync-backed append-only audit
storage, while `SubprocessToolHandler` provides a no-shell JSON process
boundary with timeout and output limits. A subprocess is not a complete OS
sandbox; production deployments should add container or platform isolation.

::: agentic_security.http.JsonHttpClient

::: agentic_security.adapters.HttpOpaPolicyEngine

::: agentic_security.adapters.HttpCedarPolicyEngine

::: agentic_security.adapters.HttpApprovalProvider

::: agentic_security.adapters.JsonlAuditSink

::: agentic_security.adapters.SubprocessToolHandler

## Telemetry

::: agentic_security.telemetry.CompositeAuditSink

::: agentic_security.telemetry.OpenTelemetryAuditSink
