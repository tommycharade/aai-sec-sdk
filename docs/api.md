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
`ExecutionResult.idempotency_recorded` independently reports whether a
terminal idempotency result was durably persisted. For uncertain timeout,
cancellation, or handler-failure outcomes, `False` is a release-blocking
operational signal and the side effect must be reconciled before retrying.
`ExecutionResult.reconciliation_state` independently
reports `STILL_RUNNING`, `CONFIRMED_COMPLETE`, `CONFIRMED_ABSENT`, `UNKNOWN`, or
`FAILED`. A live timed-out worker always keeps the primary status `TIMED_OUT`.
`ExecutionResult.timeout_phase` identifies `POLICY`, `APPROVAL`, `CREDENTIAL`,
`AUDIT`, `HANDLER`, or `RECONCILIATION`. `handler_started` and
`side_effect_state` distinguish pre-handler denials from actions whose effect
is uncertain; policy, approval, and credential timeouts never invoke the
handler.
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

## Typed security components

## Enterprise fleet control plane

::: agentic_security.enterprise_control_plane.FleetIdentity

::: agentic_security.enterprise_control_plane.EnterpriseFleetStore

::: agentic_security.enterprise_control_plane.EnterpriseFleetApplication

## Native agent host hooks

::: agentic_security.claude_code

::: agentic_security.codex_cli

## Managed host policy compilation

The compiler produces deployment artifacts but does not write privileged host
paths. Effective authority remains fail-closed until independently observed
endpoint evidence matches the complete desired bundle.

::: agentic_security.managed_configuration.ManagedConfigurationCompiler

::: agentic_security.managed_configuration.ManagedPolicyIntent

::: agentic_security.managed_configuration.NativeActionRule

::: agentic_security.managed_configuration.ManagedCommandRule

::: agentic_security.managed_configuration.ManagedMcpServer

::: agentic_security.managed_configuration.ManagedConfigurationBundle

::: agentic_security.managed_configuration.ObservedManagedConfiguration

::: agentic_security.managed_configuration.EffectiveAuthority

::: agentic_security.managed_configuration.reconcile_effective_authority

Applications normally continue to use `GuardedRuntime`; these contracts are
provided for integrations and contract tests. Do not construct a permit from
model output or bypass the runtime lifecycle.

::: agentic_security.ActionFacts

::: agentic_security.AuthorizationEvidence

::: agentic_security.ExecutionPermit

Permits are issued only by `PreExecutionAuthorizer`. The lifecycle authenticates
the permit's object identity against an internal issuer registry; constructing a
same-shaped object or copying fields cannot authorize a handler call.
Validated argument mappings and sequences inside `ActionFacts` and
`ExecutionPermit` are recursively frozen. The lifecycle passes handlers a
defensive ordinary-container copy, so a handler can transform its local input
without mutating the authorization snapshot.

::: agentic_security.PreExecutionAuthorizer

::: agentic_security.ExecutionLifecycle

::: agentic_security.TerminalRecorder

::: agentic_security.BoundedOperationTracker

::: agentic_security.BoundedOperationExecutor

::: agentic_security.ActionBudgetLease

`TerminalRecorder` owns the idempotency state transition around a consequential
action. Callers must claim before invoking `record`; the configured store
enforces atomic claim/replay/conflict/expiry semantics. `lookup` rejects a
different action under the same operation key, `claim` returns existing or
expired evidence without permitting unsafe replay, `record` returns `False`
when terminal persistence fails, and `gc` returns the store's observable
garbage-collection report.
`replay_completed` is the single completed-result replay API; malformed
terminal records and identity collisions fail closed, while in-progress and
uncertain records remain non-replayable.

`RuntimeConfig.execution_timeout_seconds` is a caller-wait deadline for policy,
approval, credential, audit, handler, and reconciliation operations. Python
cannot forcibly terminate an arbitrary running thread, so non-cooperative
workers remain tracked and count against `max_timed_out_workers` until they
return. Use `GuardedRuntime.health()` for operational alerts. Configure a
custom `redactor` for domain-specific secret or PII rules.

`GuardedRuntime.telemetry()` returns the bounded, content-free aggregate
execution counters used by the agent heartbeat. It reports action outcomes,
admission and cost units, and aggregate latency; it never includes tool names,
arguments, resources, principals, credentials, or handler output. Deployments
may send this snapshot to the enterprise control plane for fleet performance
views. It is an operational metric snapshot, not a replacement for the
redacted audit stream.

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
`RuntimeConfig.idempotency_ttl_seconds` defaults to one day. Expired completed
records may be reclaimed; expired in-progress or uncertain records remain
retained and return `EXPIRED` until explicitly reconciled. Call `store.gc()`
and retain its `IdempotencyGCReport`; GC never silently deletes active or
uncertain records.

::: agentic_security.tools.ToolRegistry

::: agentic_security.tools.OutputValidator

::: agentic_security.tools.ReconciliationHandler

::: agentic_security.idempotency.IdempotencyStore

::: agentic_security.idempotency.InMemoryIdempotencyStore

::: agentic_security.idempotency.IdempotencyGCReport

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

::: agentic_security.approvals.ApprovalConsumption

::: agentic_security.approvals.ApprovalOutcome

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

## UI control plane adapter

The optional management UI talks to an authenticated control-plane adapter.
The reference implementation below validates complete configuration
replacements, applies persisted controls to a live authority before serving,
persists them atomically, records requested/activated changes, and exposes a
persisted emergency stop. Bind it to an application-owned authority and an
authoritative audit sink before enabling mutation. It does not create
application identity or replace the deployment's policy, approval, credential,
audit, or isolation services.

::: agentic_security.ControlPlaneStore

::: agentic_security.ControlPlaneApplication

::: agentic_security.ControlPlaneAuthority

::: agentic_security.CallbackControlPlaneAuthority

::: agentic_security.OperatorAuthenticator

::: agentic_security.OperatorIdentity

::: agentic_security.StaticBearerAuthenticator

::: agentic_security.ControlPlaneDependencyError

::: agentic_security.InMemoryControlPlaneAuthority

::: agentic_security.AgentPresence

::: agentic_security.AgentPresenceStore

::: agentic_security.AgentSessionCredential

::: agentic_security.AgentSessionStore

::: agentic_security.AgentSessionStoreError

`AgentSessionStore` is the reference same-user credential cache for native hook
and MCP processes. It derives an opaque filename from the control-plane URL,
deployment and agent identity, writes atomically outside the project with
directory mode `0700` and file mode `0600`, and rejects symlinks, foreign
ownership, broad permissions, malformed content and expired credentials. The
cache transfers a bearer; it does not validate or authorize it. The control
plane remains authoritative on every request. The reference implementation is
POSIX-only and refuses construction when numeric ownership and private file
modes cannot be verified; Windows deployments require an ACL-aware credential
store adapter. Reads use a no-follow descriptor, revalidate its metadata, and
are bounded to 4096 bytes before decoding.

::: agentic_security.ControlPlaneAgentClient

`ControlPlaneAgentClient.report_decision` is available only for an enrolled AWS
agent session. It submits a SHA-256 event digest plus fixed, content-minimised
decision metadata; it never submits tool arguments, prompts, commands, paths,
outputs, credentials, principals, or caller-selected policy identity. The
server derives ownership and current policy metadata from the authenticated
session. A report is operational evidence and grants no authority.

::: agentic_security.ControlPlaneDecisionExporter

`ControlPlaneDecisionExporter` is an `AuditExporter` for host and SDK decision
events. It maps structured local outcomes into the closed control-plane
vocabulary, discards free-form action content, and ignores lifecycle events
that are not decisions. Use it as the required replica in
`ReplicatedAuditSink` when the management plane must acknowledge evidence
before a consequential action proceeds:

```python
from agentic_security import (
    ControlPlaneAgentClient,
    ControlPlaneDecisionExporter,
    JsonlAuditSink,
    ReplicatedAuditSink,
)

client = ControlPlaneAgentClient(
    "https://control-plane.example",
    "synthetic-short-lived-agent-session",
    agent_id="claude-example",
    deployment_id="deployment-example",
    aws_agent_session=True,
)
audit = ReplicatedAuditSink(
    JsonlAuditSink(".claude/security-audit.jsonl"),
    ControlPlaneDecisionExporter(client, source="claude_native"),
)
```

The example token and identities are synthetic. Supply the real short-lived
session through a deployment secret boundary rather than source code.

::: agentic_security.ControlPlaneConfigurationError

::: agentic_security.validate_configuration

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
storage, a multi-process lock, a size fail-closed limit, verification, and a
bounded tail reserved for fail-closed replication compensation. Individual
ordinary records are capped at half that reserve. It
is local evidence, not a forensic/WORM service: production deployments should
replicate to access-controlled encrypted remote storage. On restart, the local
sink verifies the complete existing chain before appending; corruption is a
fail-closed error that must be preserved and investigated. `SubprocessToolHandler`
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
