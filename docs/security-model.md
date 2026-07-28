# Security model

## Trust boundary

Model output is untrusted input. Tool names, arguments, retrieved text, memory, tool results, and inter-agent messages are also untrusted. The SDK’s security boundary sits between a proposed action and the side effect that would execute it.

The boundary is represented explicitly by `ActionFacts` ->
`PreExecutionAuthorizer` -> `ExecutionPermit` -> `ExecutionLifecycle`. Facts
are immutable host-derived values, including recursively frozen validated
argument containers; the authorizer is the centralized final decision point,
and lifecycle is the permit-gated handler invocation path. Handlers receive a
defensive copy rather than the authorization snapshot.
Permit issuer identity is kept in an internal registry rather than permit
fields, so `object.__new__` objects and copied fields cannot authorize a
handler call. This protects the SDK boundary from accidental forgery; code
with authority to modify the running Python interpreter remains trusted.

Bounded provider and handler waits are admitted through
`BoundedOperationTracker`. A timeout retains its worker slot until completion;
`BoundedOperationExecutor` emits the typed timeout phase, while
`ActionBudgetLease` prevents timeout and worker-exit callbacks from releasing
the same action budget twice.
The runtime does not expose a public operation that invokes a registered
handler from a proposal without a permit. This is an in-process architectural
guarantee, not a sandbox claim: trusted application code can still call its
own handler directly outside the SDK.

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

## Claude presence and control-plane threat model

The optional Claude/MCP presence bridge is a separate authenticated boundary.
An MCP process registers with a short-lived agent credential, and the control
plane binds the submitted agent identifier to the authenticated token subject.
Project root and host metadata are bounded input; they never grant policy,
principal, credential, or tool authority. Heartbeat session identifiers are
opaque bearer values and are returned only to the registering process, never
to the operator dashboard.

Host onboarding treats shell history and host configuration as persistence
boundaries. The UI never embeds an exchanged bearer in its generated command:
the operator copies the session separately and pastes it into a hidden shell
prompt. Claude inherits that value without writing it to `.mcp.json`; Codex's
project-scoped installer stores only `env_vars = ["AAI_SEC_AGENT_TOKEN"]` and
non-secret routing metadata. The installer rejects symlinked, invalid, or
ambiguously owned TOML rather than following or overwriting it. A copied token
can still be exposed through the operator's clipboard or compromised shell, so
sessions remain short-lived, deployment/agent-bound, rotated by heartbeat and
revocable by the control plane.

The registry expires missing heartbeats, records registration, heartbeat, and
disconnect transitions through the configured audit sink, and the example MCP
gateway stops its guarded runtime when heartbeat delivery fails. The control
plane does not infer that a process is safe merely because it is connected:
operator authentication, runtime policy, tool registration, approvals, IAM,
audit durability, and isolation remain independent requirements. The client
uses HTTPS outside explicitly permitted localhost development URLs and bounds
responses; deployments must still provide TLS termination, token rotation,
network policy, and monitoring.

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
`TerminalRecorder` owns lookup, identity collision checks, claim, terminal
state persistence, and observable GC at the runtime boundary. Recording is
valid only after the caller has claimed the key; missing-claim or transition
errors remain fail closed.
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
handling hostile code. `DockerSandboxToolHandler` is the concrete container
option; it fixes `--network=none`, read-only root, dropped capabilities,
non-root UID, no-new-privileges, PID/memory bounds, and a restricted temporary
filesystem. Pin the image by digest and retain host/daemon hardening and
the adapter rejects mutable image tags before execution; retain host/daemon
hardening and escape-test evidence. It is not a microVM and is not sufficient for a threat
model that includes a malicious Docker daemon or host kernel.

## Production readiness checklist

- Use authenticated policy, approval, and IAM endpoints over HTTPS.
- Require `ProviderToken` attestations and test provider-side scope contracts.
- Treat in-process handlers as trusted; require `requires_isolation=True` for
  hostile or model-generated code and use `DockerSandboxToolHandler` or a
  separately managed microVM/WASM adapter.
- Export local audit events to encrypted, access-controlled WORM/SIEM storage.
- Alert on `GuardedRuntime.health()["timed_out_workers"]` before retrying
  uncertain actions.
- Monitor the per-operation timeout counters in `GuardedRuntime.health()`;
  policy, credential, audit, reconciliation, and handler workers all retain
  lifecycle accounting until they exit.
- Configure rate, fan-out, cost, delegation, and action budgets per task.
- Run the release verification, SBOM, provenance, and compatibility checks
  described in `releasing.md` before depending on a published version.
- Treat mutation evidence as commit- and scope-bound assurance: the checked
  evidence must name the exact tool, score, commit, and complete 11-file security
  scope. It is not portable evidence for another source revision.

## Deployment adapters and process boundaries

`JsonlAuditSink`, HTTP OPA/Cedar and approval adapters, and
`SubprocessToolHandler`/`DockerSandboxToolHandler` are concrete integration
surfaces. The HTTP client
requires HTTPS, explicit headers, and bounded transport waits. The subprocess
adapters never invoke a shell and pass only a JSON context/argument payload.
The Docker adapter adds a real container boundary but deployments handling
hostile code must still retain image provenance, daemon/host hardening, and
filesystem, network, identity, resource, and escape-denial evidence.
## Enterprise fleet trust boundaries

The enterprise fleet layer adds organization, project, and deployment scope
to the existing runtime boundary. The browser is an untrusted operator client;
the authenticated API and injected authorizer decide whether an operation is
permitted. Fleet persistence stores metadata, configuration references, and
content hashes, never bearer tokens or credentials. Agent sessions are opaque,
short-lived, scoped to one deployment and agent, and excluded from inventory
responses. Every lifecycle and rollout mutation is auditable. Provider-backed
authentication, policy, IAM, approval, audit retention, isolation, and runtime
activation remain explicit adapters and are not simulated by the UI.
Fleet collection reads use bounded continuation cursors. Cursors carry no
identity, role, or credential material and are treated as untrusted offsets;
tenant and project authorization is re-evaluated on every page, and malformed,
repeated, or excessive pagination fails closed rather than returning an
unbounded response.
