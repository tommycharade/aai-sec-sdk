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

## Operator identity and authorization

The hosted control plane treats operator authentication, tenant entitlement
and role authority as separate facts. Cognito verifies the token. A native
trial user resolves tenant through an immutable claim or server-owned subject
mapping. A Microsoft Entra ID user receives provider provenance from a Cognito
pre-token trigger only after that trigger identifies the configured federated
profile. The API then compares the Entra tenant to deployment configuration
and selects a provisioned AAI tenant; request JSON and browser state never
select tenant authority.

Entra authentication does not directly grant an AAI role. With SCIM enabled,
a separate tenant-bound endpoint provisions users, groups and memberships by
immutable Entra object UUID. A platform administrator maps exact active groups
to canonical roles. The Cognito pre-token trigger resolves the live user,
memberships and mappings and replaces the token's groups; unprovisioned,
inactive, unmapped, malformed and oversized lifecycle state fails closed.
Canonical roles translate into explicit capabilities for runtime
administration, policy authoring, policy approval, fleet operation, identity
administration, action approval and incident response. Read-only auditors
receive no mutation capability, and only platform administrators can change
directory-to-role mappings.

Access and ID tokens expire after five minutes, bounding mover and leaver
convergence when refresh reruns lifecycle checks. This is not immediate global
revocation. Live Entra acceptance, break-glass access, access certification
and delegated administration remain open in the
[P0/P1 implementation status](p0-p1-implementation-status.md). A configured
identity provider or synthetic contract test is not production joiner, mover
and leaver evidence.

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

Native host hooks are policy enforcement points, not deployment integrity
controls. Claude and Codex project hook files can be changed or disabled by a
user who controls the project. Codex additionally requires explicit trust for
non-managed project hooks. Enterprise Codex deployments should distribute the
reviewed hook outside the repository, pin hooks on in managed
`requirements.toml`, and optionally reject non-managed hooks. The control plane
must treat a missing hook, stale evidence or configuration drift as unhealthy;
an MCP heartbeat alone does not prove native-tool coverage.
Current-CLI acceptance also demonstrated that `--ignore-user-config` bypasses
the project hook layer. Enterprise launch policy must prohibit unmanaged
profiles and flags, independently verify the managed requirement, and alert on
missing native evidence; the SDK does not claim authority over an unmanaged
Codex process started by a user who controls the host.

Codex `PreToolUse` does not currently support an approval-producing `ask`
decision: attempting it fails the hook and continues the tool call. The SDK
therefore records the local policy result as approval-required but emits a host
deny. Exact approval and subsequent execution occur only through
`GuardedRuntime` and the governed MCP workflow.
Allowed Codex native calls use successful exit with no output. This avoids the
host's fail-open error path for a bare `permissionDecision: "allow"`, which is
valid only when accompanied by `updatedInput` for a rewrite. Denials alone emit
the hook-specific permission decision.

Native command allow rules use complete-string matching; deny and approval
rules search the whole string for a matching component. This ordering and
matching asymmetry prevents a safe prefix from authorizing an appended shell
operation. Codex patch confinement validates every declared source and move
destination before returning allow and rejects `.codex`, `.claude`, `.git`,
and `.mcp.json` security-state targets. Claude native writes enforce the same
protected paths. Protecting `.git` prevents an agent from changing repository
configuration or hooks that a later Git command could execute. Invalid central regex configuration takes
the same explicit deny path as a missing policy rather than crashing the hook.
Patch operation authority is also explicit: `Write` grants Add, `Edit` grants
Update and Delete, and Move requires both capabilities; path confinement alone
never expands an operation grant.
Native command allow decisions bind the live event working directory to the
approved project root. Codex also binds every tool-level working-directory
override. Missing, malformed, escaping, or symlink-resolved external
directories deny explicitly; deny and approval patterns remain global.
Native decision evidence may include only a SHA-256 digest derived from the
native tool name plus already-redacted action and working-directory digests.
Claude Bash correlation uses the exact command and Claude Read correlation uses
the resolved file path; optional descriptions, offsets, and limits cannot
substitute a different action or prevent a legitimate proof. The complete
untrusted tool input remains independently hashed in local audit evidence. The
control plane exposes only the scoped digest for exact action correlation,
without retaining command text, arguments, paths, prompts, or outputs; the same
action in a different project produces different evidence.
The shared policy validator limits each command-pattern class to 100 entries,
each pattern to 256 characters, rejects lookarounds, inline flags,
backreferences and quantified groups, and caps evaluated command text at 8,192
characters. Wildcard repetition and ambiguous overlapping repetition are also
rejected, including repeats separated by an atom that the earlier repeat could
consume. The enterprise write API and each hook repeat this validation so a
legacy stored policy cannot bypass a newer control. Native allow decisions
also reject newlines, command substitution, shell lists, pipelines,
redirections and subshell syntax independently of regex configuration; shipped
allow patterns use `[ \\t]` rather than newline-inclusive `\s`. Control syntax
is rejected even when quoted inside a nested shell or `eval` argument. Shell
and `eval` entry points themselves—including `sh -c id`, `bash -c ...`, and
wrapper-launched shells—plus `source` and `.` file execution—are never eligible
for native allow because their visible argv introduces a second command-parsing
boundary. Parameter expansion is also ineligible: forms such as `$SHELL -c id`
can replace the authorized executable after evaluation. Pattern
count limits are validated over each complete decision class before activation,
not one expression at a time. Audit initialization is also inside the
fail-closed boundary: directory, permission, and corrupt-chain errors produce a
deny-only hook response because a process crash is not an authoritative
decision on either host. A final setup boundary catches unexpected adapter
exceptions and emits the same denial.
The exported Codex `handle()` API converts malformed host payloads into the
same explicit denial as the stdio adapter; integrations cannot turn validation
exceptions into a non-authoritative hook failure.
Central Claude and Codex policy activation also requires the server-owned `emergencyStop` field
to be exactly `false`; absence, null, strings, numbers, and active state deny.
Codex patch proposals are bounded to 256 KiB and 256 declared source/move
targets before path resolution, keeping attacker-controlled hook work finite.
Relative patch targets resolve from the hook event's live working directory,
which must itself remain inside the approved project root. This matches the
host's write semantics and prevents an outside or protected subdirectory from
changing where an apparently safe relative header lands. Claude and Codex
conservatively case-fold the first relative path component before checking
`.claude`, `.codex`, `.git`, and `.mcp.json`, preventing case-insensitive hosts
from mapping a differently cased spelling onto protected authority state.
Command patterns also reject Python-only named Unicode escapes such as
`\N{SEMICOLON}` so browser and SDK validation cannot interpret one policy
differently at the shell boundary.
The reference Codex hook caps its per-project local audit chain at 1 MB because
each short-lived process verifies that chain before appending. Reaching the cap
fails closed and requires operator export/rotation; AWS-enrolled agents still
require synchronous central replication for every decision.
The checked-in offline fallback permits only exact `pwd`/`ls` and narrowly
enumerated read-only `git status`, `git diff --stat`, and `git log --oneline`
forms. It does not admit arbitrary Git flag tails or test runners: Git output
flags can overwrite authority files, and project tests execute repository code.
AWS demo and trial safe-default policies use the same exact command forms, so
first enrollment behaves consistently across Claude Code and Codex CLI.
Operator verification is bound to the live host identity and the sole assigned
effective policy ID/version. The console must compare that tuple before offering
activation commands; an inventory heartbeat or group name alone is insufficient
proof that the host has reconciled the policy being displayed. The AWS agent
policy route independently rejects zero or multiple group memberships before
returning authority. Project root is required at registration and immutable
after enrollment; a legacy empty record may be repaired once before enrollment
resumes. That repair is a conditional DynamoDB update, so concurrent operators
cannot make the scope last-writer-wins; the first non-empty root becomes
authoritative and a conflicting request receives HTTP 409.
Onboarding pins native-hook and MCP imports to the explicitly selected SDK
checkout; an absent or different globally installed package cannot silently
remove or replace the enforcement implementation.

Required remote audit replication uses a provisional local event. If export
fails, the host denies and the primary sink appends a linked
`*_effective_decision` event with `replication_status=failed`; its
`supersedes_event_hash` identifies the provisional event. This prevents local
operators from mistaking a pre-export allow for the host's effective outcome.
The bounded JSONL adapter reserves up to 64 KiB, but never more than half its
configured file limit, outside ordinary-write capacity for that compensation
path. A normal append can therefore report “full” before
the physical file limit is reached; emergency use remains size checked, fsynced,
locked, redacted, and hash chained. Ordinary event records are also bounded to
half the reserve, leaving room for the larger superseding fields.

## Claude presence and control-plane threat model

The optional Claude/MCP presence bridge is a separate authenticated boundary.
An MCP process registers with a short-lived agent credential, and the control
plane binds the submitted agent identifier to the authenticated token subject.
Project root and host metadata are bounded input; they never grant policy,
principal, credential, or tool authority. The registered immutable project
root is nevertheless part of the agent identity boundary: bootstrap exchange,
the issued session, the host cache key, and every authenticated agent request
must all present the same canonical-root digest. The control plane rechecks the
live registered root before accepting a request. This prevents a bearer or
cache entry copied from one checkout from silently controlling another; it is
not device attestation and does not protect against an attacker who controls
the same OS account and can steal both the credential and root. Heartbeat
session identifiers are opaque bearer values and are returned only to the
registering process, never to the operator dashboard.

Host onboarding treats shell history and host configuration as persistence
boundaries. The UI never embeds an exchanged bearer in its generated command:
the operator copies the session separately and pastes it into a hidden shell
prompt. Neither Claude nor Codex writes it to project configuration. Instead,
the installer places it in an SDK-owned host credential cache scoped by the
control-plane URL, deployment, agent and canonical project root. The cache is outside the repository,
written atomically in a `0700` directory with a `0600` file, and rejects
symlinks, foreign ownership, broad permissions, malformed records and expired
values. A copied or cached token can still be exposed through the clipboard,
compromised shell, backup, or another process running as the same OS user; the
reference cache is not an OS keychain. Sessions therefore remain short-lived,
deployment/agent-bound, rotated by heartbeat and revocable by the control
plane. The reference cache supports POSIX hosts only and fails closed where
numeric ownership plus `0700`/`0600` modes cannot be verified, including
Windows. Windows and higher-assurance deployments must replace it with an
ACL-aware OS/device credential broker while preserving the same rotation
contract. Cache records are opened without following symlinks, revalidated
from the open descriptor, and read with a strict 4096-byte allocation bound
before decoding or parsing.

Local `JsonlAuditSink` paths use the same no-follow principle for the audit
directory, event file and inter-process lock. Each child is opened relative to
an already verified directory descriptor and `fstat` confirms a regular file
before content is trusted. Replacing any component with a symlink therefore
fails closed instead of redirecting security evidence to another target.

The registry expires missing heartbeats, records registration, heartbeat, and
disconnect transitions through the configured audit sink, and the example MCP
gateway stops its guarded runtime when heartbeat delivery fails. The control
plane does not infer that a process is safe merely because it is connected:
operator authentication, runtime policy, tool registration, approvals, IAM,
audit durability, and isolation remain independent requirements. The client
uses HTTPS outside explicitly permitted localhost development URLs and bounds
responses; deployments must still provide TLS termination, token rotation,
network policy, and monitoring.

Host decision reports are a separate evidence boundary. A valid agent session
authenticates which enrolled process sent a report, but does not make the report
authoritative. The control plane accepts only a fixed decision vocabulary and a
SHA-256 event digest; it rejects prompts, commands, paths, arguments, results,
credentials, principals, free-form reasons, and caller-supplied policy claims.
Tenant, deployment, agent, policy version, and observation time are derived
server-side. Reports can populate operator views and durable evidence, but can
never authorize execution, satisfy an approval, change policy, or override an
emergency stop. A compromised enrolled process can still submit false evidence,
so forensic assurance must correlate this stream with deployment-owned WORM
audit, identity, and infrastructure logs.

Native hook audit events persist deterministic digests of tool input and the
working directory, not raw commands, arguments or paths. This content-minimised
default reduces local secret and source disclosure while still supporting
event correlation. A digest is not anonymization and may be susceptible to
guessing for low-entropy values, so local JSONL permissions, retention and
replication remain security controls.

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
filesystem. Pin production images by registry digest. Local evidence runs may
use Docker's immutable `sha256:...` content-addressed image ID; mutable names
and tags are rejected. Retain host/daemon hardening and escape-test evidence.
It is not a microVM and is not sufficient for a threat model that includes a
malicious Docker daemon or host kernel.

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
  evidence must name the exact tool, score, commit, and complete declared
  security scope. It is not portable evidence for another source revision.

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
short-lived, scoped to one deployment, agent and canonical project root, and
excluded from inventory responses. Every lifecycle and rollout mutation is auditable. Provider-backed
authentication, policy, IAM, approval, audit retention, isolation, and runtime
activation remain explicit adapters and are not simulated by the UI.
Central approval requests cross two distinct trust boundaries. The agent
session authenticates the deployment and agent, but request metadata is still
untrusted and grants no authority. The operator API authenticates and
authorizes the human decision, then conditionally turns one live pending record
into an exact-action grant. The browser cannot choose tenant or agent identity,
approve without a mutation role, replace an existing approval ID, extend the
bounded grant TTL, or make a denied/expired request consumable. Tool arguments,
results, prompts, and credentials are deliberately excluded from the queue;
deployments that need richer business context must provide it through a
separate authenticated domain-authorization system rather than weakening the
SDK action binding.
First-run project and deployment registration is also an authority boundary.
The browser may propose bounded names and stable identifiers, but the API
requires each parent organization/project to exist in the authenticated tenant.
Agent registration requires an existing deployment and copies ownership,
environment, and region from that server-owned record rather than request JSON.
Neither agent registration nor bootstrap exchange is accepted as liveness:
presence remains offline until the deployment-bound session sends a successful
heartbeat. Duplicate project, deployment, group, and agent identifiers are
rejected rather than overwriting an existing authority record.

AWS operator mutation roles come from the verified Cognito
`cognito:groups` claim. API Gateway projects JWT claim values as strings, so
the Lambda normalizes a bounded single value, JSON-array string, or
bracket/comma projection into exact group names. Only `platform-admin` and
`security-operator` authorize mutations. Malformed values, oversized claims,
objects, and lookalike substrings fail closed; the browser cannot supply or
override this claim.
Fleet collection reads use bounded continuation cursors. Cursors carry no
identity, role, or credential material and are treated as untrusted offsets;
tenant and project authorization is re-evaluated on every page, and malformed,
repeated, or excessive pagination fails closed rather than returning an
unbounded response.
