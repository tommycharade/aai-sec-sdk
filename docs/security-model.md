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
business authorization can be inferred automatically, or that a non-cooperative
handler can be forcibly cancelled by `stop()`. Runtime operation waits are
bounded, but deployment infrastructure must still provide its own IAM,
network policy, durable audit controls, and OS/container sandboxing.

Handlers may return arbitrary application values, but the runtime applies the
optional tool output normalizer, redacts supported sensitive fields, and
enforces the configured serialized output-size limit before returning a result.
Applications remain responsible for semantic output schemas and for handling
untrusted tool content before sending it to a model.

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
audience-bound provider tokens and avoid returning reusable raw secrets. The
included `TokenCredentialBroker` wraps an authenticated token-service callback;
the callback remains responsible for provider-side scope enforcement.

## Timeout and retry semantics

The runtime timeout bounds policy evaluation, credential minting, audit
persistence, and handler invocation. A timeout in policy or credential minting
denies without running the handler. A handler timeout returns `TIMED_OUT` and
the runtime retains the concurrency slot until the worker exits. The side
effect remains uncertain, so callers must reconcile before retrying. High-impact
and external-egress tools must be idempotent or declare an explicit
`reconciliation` contract at registration time.

## Deployment adapters and process boundaries

`JsonlAuditSink`, HTTP OPA/Cedar and approval adapters, and
`SubprocessToolHandler` are concrete integration surfaces. The HTTP client
requires HTTPS, explicit headers, and bounded transport waits. The subprocess
adapter never invokes a shell and passes only a JSON context/argument payload;
it is a process boundary, not a complete sandbox. Deployments handling hostile
code must place that worker in an OS/container sandbox with a restricted
filesystem, network, identity, and resource policy.
