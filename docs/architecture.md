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

## Current runtime scope

The current pre-release provides the framework-neutral core: explicit tool
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
When an evaluator returns `policy_version`/`version` or
`provenance`/`source`, those values are retained in execution audit evidence.

The first telemetry adapter is `OpenTelemetryAuditSink`. It wraps an
authoritative audit sink and emits one span per redacted security event.
OpenTelemetry is optional; applications install `opentelemetry-api` and pass
their configured tracer to the adapter.

The policy adapter layer provides `OpaPolicyEngine` and `CedarPolicyEngine`.
They accept injected evaluators, serialize the same live identity/argument/
resource request, and map only explicit external decisions. Transport errors,
malformed responses, and unknown decisions are denied.
