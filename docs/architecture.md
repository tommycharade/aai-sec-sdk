# Architecture

The core runtime should remain small and provider-neutral:

```text
model/provider -> adapter -> security runtime -> tool adapter -> system
                                  |
             context / policy / approvals / budgets / audit / kill switch
```

The execution pipeline is ordered deliberately:

```text
proposal -> normalize -> schema/business validation -> policy -> approval
         -> budget/idempotency -> credential mint -> scoped execution -> result handling -> audit
```

No side effect or privileged credential mint may happen before applicable checks pass. A credential broker receives only the application-owned context, validated live resources, and registered tool definition; the resulting short-lived credential is attached to the handler context and is never copied into proposals or audit payloads. Provider integrations, policy engines, credential brokers, sandboxes, telemetry backends, and approval systems belong behind adapters.

## Explicit security components

The runtime boundary is decomposed into immutable, typed components:

- `ActionFacts` is the host-derived snapshot of the proposal, validated
  arguments, resources, registered tool, and action fingerprint.
- `PreExecutionAuthorizer` is the centralized final decision point. It accepts
  provider evidence and issues an `ExecutionPermit` only when policy,
  approval, identity, tenant/resource, credential, isolation, and delegation
  checks all pass.
- `ExecutionPermit` is an immutable capability bound to those exact facts and
  the host-owned handler context. A proposal or model result is not a permit.
- `ExecutionLifecycle` performs the final emergency-stop check and is the only
  runtime path that invokes a handler. Its invocation remains bounded and
  cooperatively cancellable, with late-worker accounting preserved.
- `BoundedOperationExecutor` and `BoundedOperationTracker` own bounded worker
  admission, phase timeout classification, and late-worker lifecycle counters.
  `ActionBudgetLease` owns atomic one-shot action-budget release. The runtime
  remains the ordering façade and supplies provider operations to these
  components.
- `TerminalRecorder` owns final idempotency persistence and audit outcome
  handling; a side effect is never reported as safely complete when terminal
  persistence fails.
- `ActionPreparation` owns argument/resource validation, host identity checks,
  and nonce-bound isolation verification before policy evaluation.
- `PolicyPreparation` owns normalization of tool-declared approval requirements;
  provider results cannot weaken a registered tool contract.
- `CredentialPreparation` owns the final exact tool/resource scope check on
  broker-issued credentials before a credential enters handler context.

These components are provider-neutral. The runtime remains an orchestration
façade and owns bounded provider calls because timeout, worker capacity,
ordering, and stop state are part of the host security boundary. Adapters
supply policy, approval, credential, isolation, audit, and idempotency
infrastructure.

## Current runtime scope

The current stable release provides the framework-neutral core: explicit tool
registration, deterministic argument validation, deny-by-default local policy,
mandatory tenant/resource checks, scoped in-memory approvals for development and tests,
budgets, emergency stop, idempotency, and redaction-aware hash-chain audit
events. The `CredentialBroker` contract, synthetic broker, and
`TokenCredentialBroker` provide development and deployment integration
surfaces. `JsonlAuditSink`, bounded HTTP OPA/Cedar/approval adapters, and a
no-shell subprocess process boundary are included as explicit adapters.

The current runtime provides a bounded caller wait and cooperative cancellation
for handlers that observe the context token; it cannot forcibly terminate a
thread blocked in external code. A timed-out non-cooperative handler keeps its
reserved concurrency slot until its worker exits, preventing timeout retries
from bypassing the configured concurrency boundary. It provides configurable
rate, active fan-out, cost-unit, and delegation budgets, but not full
OS/container sandboxing. Durable JSONL audit and
bounded HTTP policy/approval adapters are provided, but deployments must still
configure authenticated endpoints and operational storage controls.
Side-effect safety is adapter-based: `IdempotencyStore` is the durable claim
boundary and `IsolationVerifier` is the platform evidence boundary. The core
ships process-local references for tests and development; deployments must
provide transactional durable storage and real sandbox/attestation evidence
for consequential or hostile workloads.
When an evaluator returns `policy_version`/`version` or
`provenance`/`source`, those values are retained in execution audit evidence.

The first telemetry adapter is `OpenTelemetryAuditSink`. It wraps an
authoritative audit sink and emits one span per redacted security event.
OpenTelemetry is optional; applications install `opentelemetry-api` and pass
their configured tracer to the adapter.

Durable audit is an explicit two-stage boundary. `JsonlAuditSink` provides
local fsync, locking, size limits, and chain verification. `ReplicatedAuditSink`
requires an `AuditExporter` acknowledgement and raises on remote failure, so
the runtime cannot report a normally recorded consequential action when the
configured replica is unavailable. WORM storage, retention, signing, and
access control remain deployment responsibilities.

The policy adapter layer provides `OpaPolicyEngine` and `CedarPolicyEngine`.
They accept injected evaluators, serialize the same live identity/argument/
resource request, and map only explicit external decisions. Transport errors,
malformed responses, and unknown decisions are denied.
