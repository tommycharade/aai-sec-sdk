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

The first runtime release provides the framework-neutral core: explicit tool
registration, deterministic argument validation, deny-by-default local policy,
tenant/resource checks, scoped in-memory approvals for development and tests,
budgets, emergency stop, idempotency, and redaction-aware hash-chain audit
events. The `CredentialBroker` contract and synthetic `InMemoryCredentialBroker`
provide the first credential integration surface. Production deployments should
implement that contract with an audience- and resource-bound provider; external
policy engines, sandboxes, OpenTelemetry exporters, and MCP gateways remain
separate adapters without weakening the core execution invariant.

The first telemetry adapter is `OpenTelemetryAuditSink`. It wraps an
authoritative audit sink and emits one span per redacted security event.
OpenTelemetry is optional; applications install `opentelemetry-api` and pass
their configured tracer to the adapter.

The policy adapter layer provides `OpaPolicyEngine` and `CedarPolicyEngine`.
They accept injected evaluators, serialize the same live identity/argument/
resource request, and map only explicit external decisions. Transport errors,
malformed responses, and unknown decisions are denied.
