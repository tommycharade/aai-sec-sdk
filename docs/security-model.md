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

For consequential deployments, wrap the local sink in `ReplicatedAuditSink`
with a required `AuditExporter`. The exporter must acknowledge only after
durable remote acceptance; export failure raises and the runtime fails closed.
`JsonlAuditSink` remains a local recovery/evidence adapter, not WORM or
tamper-proof forensic storage. Follow the [operational runbooks](runbooks.md)
for outages, corruption, rotation, and evidence preservation.

Handlers may return arbitrary application values, but the runtime applies the
optional tool output normalizer, performs key and common-token content
redaction, and
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
the callback must return a `ProviderToken` scope attestation; the SDK rejects a
bare string and mismatched tool/resource scope. The provider remains
responsible for proving that the attested scope is enforced by its IAM system.
An in-process callback cannot prevent a deliberately malicious trusted handler
from copying a secret; process/container isolation is required for hostile code.

## Timeout and retry semantics

The runtime timeout bounds policy evaluation, approval consumption, credential
minting, audit persistence, handler invocation, and reconciliation. A timeout
in policy, approval, or credential minting denies without running the handler.
A handler timeout returns `TIMED_OUT` and
the runtime retains the concurrency slot until the worker exits. The side
effect remains uncertain, so callers must reconcile before retrying. A
reconciliation callback is evidence only while the original worker may still
commit; it cannot make the immediate result final. High-impact and
external-egress tools must be idempotent or declare a reconciliation
callback. `ExecutionResult.reconciliation_state` is separate evidence: a
callback cannot claim `CONFIRMED_COMPLETE` or `CONFIRMED_ABSENT` while the
original worker remains capable of committing, and the runtime reports
`STILL_RUNNING` instead. Callers must reconcile before retrying an uncertain
operation.

Every bounded phase reports its timeout phase through
`ExecutionResult.timeout_phase`: policy, approval, credential, audit, handler,
or reconciliation. Policy, approval, and credential timeouts have
`handler_started=False` and `side_effect_state=NOT_STARTED`. Handler and
reconciliation timeouts have `handler_started=True` and
`side_effect_state=UNCERTAIN`; callers must not retry them without
reconciliation. Audit timeout after a handler runs reports `AUDIT` while the
side effect remains `EXECUTED`, because the uncertainty is in evidence rather
than execution.

## Idempotency and restart safety

Idempotent tools require a stable caller-supplied `ActionProposal.operation_key`.
The key is atomically bound to the exact action fingerprint, tenant, principal,
tool, and resource IDs. A changed action under an existing key is denied. An
`IdempotencyStore` implementation must provide atomic claims and persist
completed/uncertain states; `InMemoryIdempotencyStore` is only a process-local
reference implementation. Without a configured store, the runtime fails
closed. If terminal persistence fails after execution, the runtime returns
`EXECUTED_UNRECORDED` rather than claiming a durable success. The SDK does not
claim restart or multi-process safety for local memory.
TTL applies to completed records. GC may remove expired completed records only;
expired `IN_PROGRESS` and `UNCERTAIN` records are retained and surfaced as
`EXPIRED` so expiry cannot become an unsafe replay path. GC returns an
`IdempotencyGCReport` for metrics and audit evidence.

## Isolation attestation

`requires_isolation=True` does not accept a handler boolean or trust a Python
attribute. The handler must provide a nonce-bound `IsolationAttestation`, and a
configured trusted `IsolationVerifier` must validate its issuer, workload,
profile, expiry, action binding, and capabilities. The verifier is the adapter
boundary for containers, microVMs, WASM runtimes, or platform attestation.
`SubprocessToolHandler` intentionally makes no isolation claim: it is a
no-shell process boundary and must be deployed inside a real sandbox when
handling hostile code.

## Production readiness checklist

- Use authenticated policy, approval, and IAM endpoints over HTTPS.
- Require `ProviderToken` attestations and test provider-side scope contracts.
- Treat in-process handlers as trusted; require `requires_isolation=True` for
  hostile or model-generated code and deploy a real container/microVM/WASM
  sandbox around the subprocess adapter.
- Export local audit events to encrypted, access-controlled WORM/SIEM storage.
- Alert on `GuardedRuntime.health()["timed_out_workers"]` before retrying
  uncertain actions.
- Monitor the per-operation timeout counters in `GuardedRuntime.health()`;
  policy, credential, audit, reconciliation, and handler workers all retain
  lifecycle accounting until they exit.
- Configure rate, fan-out, cost, delegation, and action budgets per task.
- Run the release verification, SBOM, provenance, and compatibility checks
  described in `releasing.md` before depending on a published version.

## Deployment adapters and process boundaries

`JsonlAuditSink`, HTTP OPA/Cedar and approval adapters, and
`SubprocessToolHandler` are concrete integration surfaces. The HTTP client
requires HTTPS, explicit headers, and bounded transport waits. The subprocess
adapter never invokes a shell and passes only a JSON context/argument payload;
it is a process boundary, not a complete sandbox. Deployments handling hostile
code must place that worker in an OS/container sandbox with a restricted
filesystem, network, identity, and resource policy.
