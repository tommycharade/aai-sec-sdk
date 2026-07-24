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
`EXECUTED_RESULT_REJECTED`, `TIMED_OUT`, or `CANCELLED`; the legacy
`RECONCILED` enum value is retained for compatibility but is not emitted by the
current runtime. Callers must not blindly retry `TIMED_OUT` or
`EXECUTED_UNRECORDED` because side-effect or audit state may be uncertain.
`ExecutionResult.reconciliation_state` independently
reports `STILL_RUNNING`, `CONFIRMED_COMPLETE`, `CONFIRMED_ABSENT`, `UNKNOWN`, or
`FAILED`. A live timed-out worker always keeps the primary status `TIMED_OUT`.
Policy decisions use `PolicyDecision`. The
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

::: agentic_security.types.ReconciliationResult

::: agentic_security.types.ReconciliationState

::: agentic_security.RuntimeConfig

`RuntimeConfig.execution_timeout_seconds` is a caller-wait deadline. Python
cannot forcibly terminate an arbitrary running thread, so non-cooperative
workers remain tracked and count against `max_timed_out_workers` until they
return. Use `GuardedRuntime.health()` for operational alerts. Configure a
custom `redactor` for domain-specific secret or PII rules.

## Tools

::: agentic_security.tools.ToolDefinition

`ToolDefinition` applies result redaction and a serialized size limit before a
handler result crosses the runtime boundary. Use `output_validator` for an
application-specific result schema or normalization step.
High-impact and external-egress tools must be idempotent or provide a typed
reconciliation callback. A handler timeout remains uncertain while the worker
can still commit. `requires_isolation=True` requires a handler-provided
attestation and configured verifier; a boolean `isolated` marker is not
security evidence. The included subprocess adapter is only a process boundary.

For tools with `idempotency_required=True`, every proposal must include a
caller-supplied stable `operation_key` representing the business side effect,
not a generated proposal ID. Configure `RuntimeConfig.idempotency_store`;
`InMemoryIdempotencyStore` is process-local development/test storage, not
durable production storage. If terminal persistence fails after a handler has
run, the runtime returns `EXECUTED_UNRECORDED` and leaves the operation unsafe
to retry until the store is repaired or the side effect is reconciled.

::: agentic_security.tools.ToolRegistry

::: agentic_security.tools.OutputValidator

::: agentic_security.tools.ReconciliationHandler

::: agentic_security.idempotency.IdempotencyStore

::: agentic_security.idempotency.InMemoryIdempotencyStore

::: agentic_security.isolation.IsolationAttestation

::: agentic_security.isolation.IsolationVerifier

::: agentic_security.isolation.CallbackIsolationVerifier

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

::: agentic_security.audit.AuditExporter

::: agentic_security.audit.ReplicatedAuditSink

::: agentic_security.audit.InMemoryAuditExporter

::: agentic_security.audit.Redactor

## Credential brokering

::: agentic_security.credentials.CredentialBroker

::: agentic_security.credentials.CredentialMetadata

::: agentic_security.credentials.ScopedCredential

::: agentic_security.credentials.InMemoryCredentialBroker

::: agentic_security.credentials.TokenCredentialBroker

::: agentic_security.credentials.ProviderToken

Credential callbacks must return `ProviderToken`, not a bare string. The
provider attests the effective tool/resource scope and expiry; the SDK checks
that attestation against the live action. `ScopedCredential.with_secret()`
accepts a non-returning operation, preventing accidental secret return through
the handler result. In-process handlers remain trusted code; use process or
container isolation for hostile code.

## Deployment adapters

The package includes explicit adapters for common deployment infrastructure.
`JsonHttpClient` requires HTTPS (except explicitly enabled localhost tests),
uses a bounded timeout, and never invents authentication or retry behavior.
`HttpOpaPolicyEngine`, `HttpCedarPolicyEngine`, and `HttpApprovalProvider` use
that transport. `JsonlAuditSink` provides fsync-backed append-only audit
storage, a multi-process lock, a size fail-closed limit, and verification. It
is local evidence, not a forensic/WORM service: production deployments should
replicate to access-controlled encrypted remote storage. `SubprocessToolHandler`
provides a no-shell JSON process boundary with timeout and streaming output
limits enforced while the child process is being read; input writes are also
deadline-bounded. A
subprocess is not a complete OS sandbox; production deployments should add
container or platform isolation.

::: agentic_security.http.JsonHttpClient

::: agentic_security.adapters.HttpOpaPolicyEngine

::: agentic_security.adapters.HttpCedarPolicyEngine

::: agentic_security.adapters.HttpApprovalProvider

::: agentic_security.adapters.HttpAuditExporter

::: agentic_security.adapters.JsonlAuditSink

::: agentic_security.adapters.SubprocessToolHandler

## Telemetry

::: agentic_security.telemetry.CompositeAuditSink

::: agentic_security.telemetry.OpenTelemetryAuditSink
