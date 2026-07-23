# Security model

## Trust boundary

Model output is untrusted input. Tool names, arguments, retrieved text, memory, tool results, and inter-agent messages are also untrusted. The SDK’s security boundary sits between a proposed action and the side effect that would execute it.

## Required decision inputs

An authorization decision should include, at minimum:

- authenticated agent identity;
- end-user or delegated principal;
- task and purpose;
- tool and validated arguments;
- target resource and destination;
- tenant and environment;
- current policy and manifest versions;
- approval, budget, idempotency, and kill-switch state.

## Guarantees and non-guarantees

The SDK aims to guarantee that unknown or unauthorized actions do not execute
when all handlers are routed through the runtime and the application supplies
trusted identity, policy, and resource extraction. Security decisions are
observable through the configured audit sink. The default audit sink is an
in-memory development chain, not durable forensic storage.

The SDK does not guarantee that every prompt injection is detected, that
business authorization can be inferred automatically, that an in-flight
handler can be cancelled by `stop()`, or that infrastructure such as IAM,
network controls, timeouts, and sandboxes is unnecessary.

Handlers may return arbitrary application values; the core does not impose an
output schema, output-size limit, or result-content policy. Applications must
validate and redact tool results before returning them to a model or exporting
them to another system.

## Credential-brokering threat model

Credential minting is a privileged operation. The runtime therefore invokes a
`CredentialBroker` only after argument validation, resource extraction, live
policy evaluation, approval consumption, and budget admission. The broker must
derive scope from the application-owned `ExecutionContext`, registered tool,
and validated resources; it must not trust proposal fields for identity,
tenant, or authorization.

Credentials are short-lived and attached only to the handler context. They are
not included in `ActionProposal`, `ExecutionResult`, or audit payloads. A
missing broker, broker exception, expired credential, or scope mismatch fails
closed and the handler is not called. Production implementations should use
audience-bound provider tokens and avoid returning reusable raw secrets.
