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

Cloud credential authority is also host-owned. Provider principal, audience,
scope policy, token-exchange client and revocation evidence cannot come from
model output. Azure, GCP and AWS grants are exact-scope and short-lived; a
failed or unavailable live revocation check prevents mint or subsequent
secret use. The capability limits exposure inside the SDK but does not revoke
provider work already in flight. See [Cloud credential
authority](cloud-credential-authority-design.md).

Production isolation authority is likewise host-owned. Policy accepts exact
reviewed profile digests and boundary kinds; evidence binds the live principal,
tenant, agent, task, purpose, tool, resources and nonce. Missing, stale,
overlong, unsigned, mismatched or revoked evidence denies before handler
execution. The permit and audit event retain immutable profile/workload
identity without retaining signatures. This verifies authority evidence, not
the security of an unassessed host or sandbox implementation. See [Production
isolation authority](production-isolation-authority-design.md).

Bounded provider and handler waits are admitted through
`BoundedOperationTracker`. A timeout retains its worker slot until completion;
`BoundedOperationExecutor` emits the typed timeout phase, while
`ActionBudgetLease` prevents timeout and worker-exit callbacks from releasing
the same action budget twice.
The runtime does not expose a public operation that invokes a registered
handler from a proposal without a permit. This is an in-process architectural
guarantee, not a sandbox claim: trusted application code can still call its
own handler directly outside the SDK.

Runtime-release transitions are server-owned authority between two immutable
release bindings. Each binding includes the exact closed attestation manifest,
source revision, artifact identities and manifest/approval bundle identities.
Pause and rollback snapshot only SHA-256 digests of the selected active agent
identities, preventing population churn from silently expanding authority.
Missing or malformed rollout state never falls back to deployment metadata.
Persisted rollout authority is evaluated before the development-only empty
catalog path, so catalog removal cannot disable attestation. A single closed,
state-specific validator gates admission, convergence, mutation,
reconciliation and projection.
Every transition transaction also commits primary audit evidence binding the
complete resulting authority-document hash and exact health criteria.

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
revocation.

Entra deployment authority is persistent rather than shell-local. A strict,
secret-free schema binds one canonical Entra tenant and client, separate OIDC
and SCIM secret resource names, one existing AAI tenant and an opaque
Conditional Access evidence reference. The supported deployment command stores
that schema in encrypted AWS Parameter Store and reloads it for every CDK
deployment. If the stack reports federation configured but the manifest is
missing, deployment fails closed instead of removing the identity provider.
Preflight verifies exact tenant-specific Microsoft OIDC metadata and bounded
secret shape without printing secret values. This protects deployment
continuity; it does not independently prove the customer's Conditional Access
policy or prevent an AWS administrator from bypassing the supported command.

Break-glass authority is not represented by a role claim. A strongly
authenticated incident responder requests exact capabilities for their own
signed subject, and a different strongly authenticated identity administrator
must approve the request within 15 minutes. Both token authentication times
must be no older than 10 minutes. The grant starts only after approval, has a
hard 60-minute maximum, and is resolved from consistent server-owned state on
every mutation. Wildcards, caller-selected subjects, self-approval, replay,
extension, stale grants and lookup failures grant no authority. Revocation and
expiry therefore take effect without waiting for the five-minute Cognito token
boundary. Request, decision, revocation and export events are independently
audited. Emergency capabilities cannot request or decide another emergency
grant; those lifecycle controls require normal directory-derived authority.

The auditor-only access-certification API exports a bounded complete view of
SCIM operators, memberships, group-to-role mappings, canonical capabilities
break-glass history and delegated grants with a stable SHA-256 content digest.
It refuses a
partial oversized inventory and marks an export incomplete when SCIM is not
configured. The digest is integrity evidence, not a signature, human review,
or compliance certification. Live Entra and multi-business-unit delegated
administration acceptance remain open in the
[P0/P1 implementation status](p0-p1-implementation-status.md). A configured
identity provider or synthetic contract test is not production joiner, mover
and leaver evidence.

Delegated administration is server-owned authority rather than a browser or
token role claim. A normal tenant identity administrator may assign one
non-admin canonical role to another exact signed principal for an existing
organization, project or deployment and a maximum of 366 days. The API
resolves resource lineage from tenant-owned records, checks the live grant on
every scoped mutation and filters delegated-only inventory reads. Organization
scope contains projects and deployments; project scope contains deployments;
deployment scope is exact. A missing target, unknown route, failed lookup,
expired grant, revoked grant, forged informational claim or sibling resource
denies authority. Batch operations require every target to be covered.

Delegation cannot create `platform-admin`, identity administration, emergency
grant governance or another delegation. Self-delegation is denied. Create and
revoke transitions atomically commit the authority record and immutable audit
item. When SCIM is configured, the target must be an actively provisioned
Entra object. The pre-token trigger permits a delegated-only operator to sign
in but does not copy the delegated role into tenant-wide Cognito groups; the
API remains the live resource-authorization boundary. Tenant-wide directory
roles still take precedence, so removing an operator's broader Entra group is
a separate prerequisite when converting that operator to scoped access.

### Non-human control-plane authority

Automation never reuses a human Cognito or Entra token. The separate
`/machine/v1` route accepts only a service bearer whose SHA-256 lookup resolves
to a live tenant-owned identity. The server rechecks status, expiry, revision,
current credential binding and the exact route capability before every
admission. Tenant and capability are server-owned; neither bearer content nor
request JSON selects them. A private handler marker prevents caller-shaped JWT
claims from entering this authority path.

Machine capabilities are an explicit, versioned allowlist independent of human
routes. They permit bounded inventory/evidence reads, draft/simulation work,
fleet changes and measured runtime rollout operations. They can never grant
identity administration, policy approval or activation, human approval
decisions, break glass, emergency/incident response or managed-package
publication. Delegated grants and emergency grants are not considered for a
machine request. Unknown routes and unavailable authority state fail closed.

Bearers are returned once and are not persisted in plaintext. Rotation and
revocation compare the expected revision and atomically invalidate the current
credential pointer. Every admitted request records content-minimised usage and
immutable audit evidence before normal routing. This is bearer security, not
workload attestation or mTLS; the deployment still owns secret-manager delivery,
network restriction and leak response. See
[Scoped service identities and machine API](service-identities-design.md).
The Terraform provider is constrained to that route allow-list. Optimistic
resource revisions prevent last-writer-wins authority, group deletion requires
empty membership, and evidence-bearing policy and integration objects are
retained or retired rather than silently erased. See [Terraform provider and
declarative management](terraform-provider-design.md).

Group membership and policy assignment are authority edges, not presentation
metadata. The API consistently reloads the group, agent and policy records and
requires exact non-empty server-owned organization equality before changing
either edge. A caller with legitimate control of one organization therefore
cannot attach an enrolled agent or policy from a sibling organization by
guessing its identifier. Missing legacy ownership and nonexistent agents fail
closed rather than creating a dangling or cross-boundary reference.

Bulk membership assignment preserves that boundary at fleet scale. Requests
are limited to 100 unique targets, carry an exact expected membership revision,
and are evaluated from strongly consistent group and agent records. Preview is
read-only and grants no reservation or authority. Apply repeats validation and
uses one DynamoDB transaction to compare-and-swap the membership set, persist
an actor-bound idempotency result, and create immutable content-minimised audit
evidence. A concurrent membership change rolls back the entire transaction.
Per-agent business rejection may produce an explicit partial result, but no
rejected target is mutated. Reusing a request ID with different actor, group,
revision, reason, or target set fails closed. The API also rejects adding an
active agent already present in another group so a browser cannot create the
ambiguous multi-group authority that runtime verification denies.

Policy/native compatibility reports are advisory data until the server uses
them as a lifecycle gate. The browser cannot submit or acknowledge a report to
gain authority. Both staging and activation recompute static conflicts from the
authoritative immutable policy. Exact duplicate command expressions are
compared internally but never returned; findings contain only fixed text,
field names and host identity. Static analysis cannot prove regex languages do
not overlap and cannot prove a host applied its configuration, so post-
activation native-control evidence and convergence remain mandatory.

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

The hosted AWS adapter adds tenant-governed S3 Object Lock evidence. The bucket
enforces a 365-day COMPLIANCE floor independently of DynamoDB. A tenant policy
may extend that floor to ten years but cannot shorten it through the control
plane. Exact-version legal hold is tenant-prefix checked, and the operator's
rationale is hashed rather than persisted as narrative. New records carry a
creation-time SHA-256 metadata binding; assurance re-reads the immutable bytes
and reports any mismatch as `at_risk`. Bounded export refuses truncation.
Tenant-wide work uses a revision-bound FIFO message, a fixed server cutoff and
a separate derived-report bucket. The final index binds every canonical page
through an ordered SHA-256 chain and is committed to retained audit evidence;
the browser independently recalculates the same bindings. Scheduled scans
persist changed gap states and publish non-healthy transitions to the durable
alert channel. This software assurance does not replace live cross-region
recovery proof; the deployed 603-version exercise is recorded in the
[cross-region acceptance](cross-region-audit-recovery-acceptance-2026-08-01.md).
See [Durable evidence governance](durable-evidence-governance-design.md).

Cross-region recovery configuration is persistent deployment authority. The
deployer strips ambient replica variables, reloads one reviewed Parameter Store
manifest and refuses to update a previously replicated stack if that authority
is missing. The destination must independently prove versioning and a 365-day
COMPLIANCE floor. Historical gaps use a bounded S3 Batch Replication role, and
acceptance independently compares every source and replica version's identity,
bytes, digest metadata and retention. This proves evidence recoverability, not
regional API failover or a contractual RTO/RPO. See the
[audit-recovery deployment guard](audit-recovery-deployment-guard-design.md).

Regional control-plane recovery is a larger authority boundary than audit
replication. The active-passive design requires replicated control, presence,
idempotency and SCIM state; overlapping policy-signing trust; replicated
identity; Region-local queue reconciliation; bidirectional immutable audit; and
one advertised active endpoint. DynamoDB eventual replication is not treated
as a distributed lock, and a provisioned passive API is not permitted to serve
traffic before a controlled activation. Disconnected agents do not infer an
outage bypass from cached policy because revocation, emergency-stop, approval
and session state may have changed. See the
[regional recovery design](regional-control-plane-recovery-design.md).

The passive compute cell applies that principle below DNS: its API default
origin is disabled, Lambdas have zero reserved concurrency, schedules and queue
mappings are disabled, and roles cannot mutate Global Tables, write immutable
audit evidence, send work or sign policy. A discovered API ID or direct Lambda
invoke permission therefore cannot create a second active authority. Enabling
any of those controls is an independently reviewed recovery operation; see the
[passive regional cell design](passive-regional-cell-design.md).

Passive-cell deployment authority is persistent and provider-derived. A strict
secret-free manifest can only name the reviewed non-serving stack and must keep
`activationPermitted` false. The deployment guard reloads the previously
persisted regional-recovery authority, derives table/audit/key/account
identities from AWS, compares primary and recovery Cognito security posture,
requires the same tenant-specific Microsoft Entra issuer, strips ambient CDK
authority and independently verifies synthesized CloudFormation. Deployment
therefore cannot substitute a synthetic identity, unrelated pool, attacker
table or alternate stack. The verified template SHA-256 is checked again and
the exact CDK assembly is deployed without re-synthesis. Population continuity
is not inferred from matching pool configuration; it requires separately
retained live identity evidence.

Regional activation authority is a short-lived, exact-version contract rather
than an operator toggle. The read-only preflight binds one canonical transition
and direction to persisted recovery authority, the primary immutable audit
bucket and one COMPLIANCE-locked S3 version. It repeats passive-stack, recovery
identity, bidirectional replication, direct-origin fencing and stable-DNS
checks before emitting an ordered plan. Load acceptance is computed over a
unique fleet, while dependency and consistency probes reject bypass, duplicate
effects and authority widening. The preflight has no activation operation. The
guarded executor repeats it before each command, can fence source execution or
deploy an independently verified active-but-not-routed target as separate
confirmed steps, and has no traffic-routing operation. See the
[regional activation design](regional-activation-and-exercise-design.md) and
[guarded transition executor](regional-transition-executor-design.md).

Transition ownership is not stored in the replicated control Global Table.
One protected DynamoDB witness in a third Region provides strongly consistent
reads and transactional compare-and-swap over generation, phase, revision,
transition UUID, retained evidence and two-person approval digests. In-progress
phases are committed before source or target mutation, so exact retries resume
while competing, stale, expired or substituted authority fails closed. See the
[regional transition journal](regional-transition-journal-design.md).

Post-activation target readiness is also journal governed. The executor
re-verifies source fencing and the exact live recovery Lambda, queue-mapping,
schedule, signer, evidence and Entra authority before invoking the internal job
reconciler. Runtime output is treated as untrusted data and completion requires
a bounded zero-action check plus an append-only evidence digest. Traffic stays
on the source. The implemented non-routing ingress creates same-name Regional
API Gateway custom domains, exact stable/canary mappings and a read-only
private-bucket UI proxy. Its deployment guard derives provider identities,
validates exact ACM names and deploys only an independently verified assembly;
it contains no DNS resource. A separate routing executor performs one
transactional Route 53 API/UI/marker batch only after fresh source-fence,
target-runtime, zero-action reconciliation, canary-authentication and exact DNS
state proofs. Because Route 53 has no conditional generation token, the witness
plus exclusive IAM/SCP DNS authority remains necessary. Failed-cutover rollback
requires schema-v4 authority bound to both processed runtime templates. The
failed target is independently fenced before exact source restoration; source
canaries pass before one inverse Route 53 batch writes generation + 2; stable
smoke then seals an immutable `ROLLED_BACK` event. DNS-only rollback, changed
template state and failback without exact primary runtime/job reconciliation
remain denied. Planned failback uses a distinct primary adapter: its internal
job event binds direction, target Region, transition UUID and authority digest,
and only an IAM-scoped dedicated transition role may invoke the exact target
handler. The event fields are defence in depth, not caller authentication:
Lambda invocation authority must remain limited to that exact role and handler,
while Route 53 mutation is limited to the exact stable hosted zone. See
[Regional target readiness and stable ingress](regional-target-readiness-and-stable-ingress-design.md).

Regional load evidence uses pre-enrolled synthetic sessions loaded from an
exact transition-bound Secrets Manager object in the target Region and routing
account. The adapter calls only the target canary's normal agent heartbeat,
effective-policy and content-free decision routes, disables redirects, bounds
responses/timeouts, stops after prerequisite failure and never emits tokens.
The generic harness computes aggregate acceptance. Dependency and consistency
methods fail until a separately authorized target-cell-only fault controller is
implemented; load success cannot self-certify them. See the
[AWS Regional exercise provider](aws-regional-exercise-provider-design.md).
Fault authority is separately bound to one dependency, exact target runtime
template, direction/cell role, routing generation, two approvers and a maximum
five-minute fault. The read-only planner requires a durable compensation
workflow and independent cleanup watchdog before any IAM mutation can be
introduced. See the
[Regional dependency fault controller](regional-fault-controller-design.md).
Each Regional cell exports only its real control-handler execution role as
deployment-owned controller input. Independent template verification rejects a
literal ARN, a missing role, a worker role or a role not bound to the expected
cell handler. The operator and model never select this identity.
The controller requires a durable per-target lock and independently armed
Scheduler cleanup before it can attach a UUID-named inline deny. Dependency
actions and resources are code/deployment-owned; unknown dependencies and
Cognito's out-of-role authentication path fail before IAM mutation. Cleanup is
authorized by the exact retained lock digest rather than a still-live approval,
so expiry cannot strand the deny. Completion transactionally releases the lock
and retains content-free evidence.
Acquisition transactionally checks that the fault UUID has no retained evidence
before writing its target lock, preventing replay after completion. Only a lost
response in the initial `LOCKED` state is retryable; an advanced duplicate
workflow is rejected. Before attach, a complete live inline-policy inventory
also rejects an out-of-band or stranded Regional deny. Production deployment
must still make this controller the exclusive writer of the reserved inline
policy namespace because IAM does not offer a compare-and-swap attach API.
The private Standard Step Functions topology now encodes the complete normal
order, bounded provider retries, immediate exception cleanup and independent
Scheduler fallback. It has no API/UI or `StartExecution` grant and excludes
execution data from error logs. Its first task uses read-only AWS APIs to bind
the live witness, both processed templates, all stack-owned execution paths and
the stable Route 53 records to the reviewed authority. Several inventory APIs
require wildcard resource scope, so code and IaC verification constrain the
exact action set while runtime checks bind account, Regions, stack names,
digests and hosted zone. Later phases directly invoke the exact target handler
role and accept only real AWS access denial or successful recovery evidence.
Cognito fails before mutation because its authentication boundary is outside
that role. A
14-day encrypted DLQ and five security-topic alarms make workflow and watchdog
delivery failure observable. The workflow role's sole wildcard resource is the
exact CloudWatch Logs delivery control-plane action set required because those
APIs do not support resource-level permissions; an independent verifier rejects
any wildcard action, content read or broader resource use.

Bidirectional evidence continuity is independently constrained in each S3
direction. Both Object Lock buckets enable replica-modification sync while
excluding delete markers, and synthesized CloudFormation is rejected unless
its destination and least-privilege replication actions match the reviewed
contract. Recovery queues are never copied: a bounded internal reconciler
derives exact revision-bound work from the control Global Table, fails on
ambiguous jobs and cannot apply while the cell is in standby. See
[Evidence continuity and recovery-job reconciliation](evidence-continuity-and-job-reconciliation-design.md).

Regional signer migration additionally binds the old/new/replica public trust
set into a schema-v2 managed endpoint package while keeping its expected digest
as separate server-owned desired state. Root installation is all-or-rollback;
heartbeats remeasure native configuration and trust; and cutover readiness is
derived only from every active endpoint. Readiness never changes KMS or signing
authority. See [policy trust convergence](policy-trust-convergence-design.md).

Mass-retention extension is a separate irreversible boundary. The API
atomically binds a longer future-write policy to an idempotent job, waits longer
than any evidence-writing Lambda can run and then extends every pre-cutover S3
version through a dedicated bounded worker. Queue content grants no authority;
the worker reloads tenant, job, policy revision and application binding before
mutation. Provider or dispatch failure never restores the shorter policy and is
surfaced as a failed application with durable-alert posture. See
[Asynchronous tenant retention](asynchronous-retention-design.md).

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

Hosted agent identity lifecycle is forward-only and server-owned. Presence can
move between connected and offline, but authority can move only from active to
revoked to deleted. Every agent-authenticated request strongly reads the agent
record after resolving the hashed session token. Unknown, malformed, revoked
or deleted lifecycle state denies before policy, telemetry, approval or
execution-adjacent behavior. Bootstrap exchange performs the same check before
consuming enrollment material, and registration cannot reuse a retained ID.
Heartbeat and emergency-stop writes compare the current lifecycle revision so
a stale concurrent write cannot overwrite revocation.

Lifecycle transitions and immutable content-minimised evidence are committed
in one DynamoDB transaction. Replacement also conditionally updates inherited
group membership and creates a distinct offline successor; any concurrent
membership or lifecycle change rolls back the whole operation. Historical
group references are evidence, not authority, because only an active identity
can enroll, join a group or use an agent route. Offboarding hashes and removes
the project path and discards operational telemetry while retaining lineage,
actors, reasons, timestamps and replacement relationships. This does not
detect a departed employee or archived repository by itself; those external
signals and the offboarding SLO remain a P1 integration requirement.

When a deployment-owned approved runtime manifest is configured, every
heartbeat consumes a one-time control-plane challenge and carries fresh,
content-minimised hashes for the SDK package, gateway, native hook, project
configuration, executable, launch context, source revision and project scope.
Invariant hashes must match the approved manifest; project-specific hashes are
bound on first compliant enrollment. Missing, stale, replayed or changed
evidence quarantines the agent, revokes its session and blocks policy,
decision, and approval routes. Symbolic links, oversized files, unsafe Git
metadata and measurement races fail closed on the host.

An empty approved-manifest bundle is an explicit `not_configured` state, not a
successful attestation. It preserves development compatibility but fails the
operator verification check and must not be accepted for production rollout.
Non-empty manifests require a separate provenance record that binds the exact
bundle bytes to the release tag, revision, repository identity, host set and
verified release-evidence checksum. The generator refuses a dirty checkout and
executes only fixed, non-shell `git`, release-verifier and `gh attestation`
argument vectors. Repository-local Git configuration and the authenticated
GitHub CLI are therefore deployment-workstation trust boundaries; generation
must run on a controlled release host. CDK and Lambda independently reject a
missing, stale, malformed, ambiguous or incomplete approval record.
Software measurement cannot defeat an administrator/root attacker able to
replace the attestor or process memory. Hardware-backed endpoint/workload
identity and endpoint management remain outside this SDK boundary and are
required for a stronger device-integrity claim. See
[Runtime attestation design](runtime-attestation-design.md).

Managed-host evidence is an independent boundary. A deployment-owned callback
opens the compiled Claude or Codex files without following symlinks and checks
regular-file type, root ownership, restrictive modes, bounded exact bytes and
host/source identity before each authenticated heartbeat. The callback cannot
grant authority: the server compares its fixed evidence schema with
server-owned desired state and derives the posture. If a deployment has an
assigned managed bundle, missing, stale or conflicting evidence blocks
effective policy, decision and approval routes. A project file, healthy
heartbeat, or desired bundle cannot satisfy this gate.

This remains software evidence from the enrolled process. It does not prove
that Claude Code or Codex loaded the measured source and cannot resist a root
attacker replacing process memory. Endpoint management, approved launch
controls, live allowed/denied/approval/MCP probes and hardware-backed identity
remain required for enterprise acceptance.

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

### Real-host acceptance boundary

The Claude Code acceptance harness is evidence collection, never execution
authority. It measures the resolved local executable and admits a run only for
an exact version, OS, architecture and SHA-256 tuple in the code-reviewed,
default-deny matrix. It uses project-only settings, strict MCP configuration,
an explicit tool set and a disposable synthetic root. Unsupported or changed
binaries, malformed streams, duplicate/missing terminal results, output/time
bounds, invalid onboarding and unavailable authentication all fail closed.

Prompts, tool arguments, hook payloads, model results, stderr, credentials and
paths are untrusted and exist only in bounded temporary process storage or
memory. The persisted report contains fixed result codes and digests. Denial
uses a disposable marker to prove no side effect; approval uses a synthetic
Git executable to prove it was not invoked. The runner never uses a shell and
terminates the complete process group on timeout.

Exact measurement is software evidence from a trusted operator host, not
hardware attestation. It cannot prevent an administrator changing process
memory or the executable during a run, and the Claude process is not a
sandbox. The localhost MCP scenario proves only the checked-in reference
integration; it cannot satisfy central policy, MDM, credential, isolation,
durable-audit, resilience or fleet-scale acceptance. See [Real Claude Code
acceptance harness](real-claude-code-acceptance-harness.md).

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

Infrastructure synthesis is a build-time trust boundary, not a hosted product
API. AWS CDK runs only against reviewed repository configuration and is not
packaged into SDK, UI or Lambda runtime artifacts. Temporary dependency risk in
that toolchain still requires an owner, fixed expiry, preserved scanner
visibility and an automated upstream-remediation signal; it cannot be used to
waive runtime findings or permit untrusted synthesis input. The active
exception, controls and closure criteria are recorded in [Temporary risk
acceptance: AWS CDK bundled
brace-expansion](risk-acceptance-cdk-brace-expansion-2026-07-29.md).

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
Production UI assets therefore resolve an HTTP-only client and are inspected to
exclude deterministic enrollment and bootstrap capabilities. This asset
boundary reduces accidental demo deployment; it is not a security sandbox,
proof that a CDN object is current, or protection against a compromised build
pipeline. Optional workspace loading failures are contained in the browser and
expose a reload path, but every resulting API operation still requires
independent server authorization.
Managed rollout requests are also untrusted proposals. The API derives
eligible active endpoints from server inventory, selects canaries from a
stable tenant/agent hash, binds an immutable desired configuration and managed
package revision, and rejects stale optimistic revisions, malformed schedules,
percentage reduction and incompatible hosts. The browser cannot submit an
applied hash, endpoint health, convergence, selected membership or
last-known-good target. A scheduled reconciler may only start a due rollout,
remove rollout authority by pausing, or record convergence from fresh exact
endpoint evidence. Rollback can reference only the retained known-good
configuration/package pair and creates a new immutable version; it never
rewrites history.
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
Agent registration requires an existing deployment and copies organization,
project, team, environment, and region from that server-owned record rather
than request JSON. A new identity must also name an accountable owner, monitored
business contact and typed criticality. Entra-enabled tenants validate the
owner against live SCIM state. The server, not the browser, derives whether the
90-day review is current, stale or missing. Ownership renewal compares the
expected ownership revision and active lifecycle state in the same transaction
that writes durable evidence; a stale writer cannot silently transfer
accountability. Missing or expired ownership prevents positive verification.
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

## Managed host configuration boundary

Central policy intent, generated artifacts, installed files, and configuration
loaded by a running host are distinct security states. The compiler is not an
installer and desired state is not enforcement evidence. A host has effective
managed authority only after short-lived endpoint evidence binds the same host
to the exact bundle digest. Missing, stale, future-dated, wrong-host, and
mismatched evidence withholds every intended allow.

Generated artifacts contain no credentials and use only absolute managed hook
commands. Relative paths and shell-composed commands are rejected before
serialization. MCP identities use HTTPS or absolute local executables and do
not carry environment values. Endpoint management must independently protect
the files, executable, launch profile, OS identity, and credential sources.

Managed deployment packages are untrusted until a deployment-owned expected
package digest, desired bundle digest, host and platform all match. Canonical
schema validation rejects duplicate keys, unknown fields, incomplete file
sets, traversal and content substitution. The package carries only executable
paths and digests, never executable bytes; the endpoint installer verifies the
already-installed administrator-owned hook before any configuration write.
Delivering both package and expected digest through one unauthenticated channel
does not provide integrity and is explicitly outside the guarantee.

The optional POSIX installer is a separate privileged deployment boundary, not
a model or runtime capability. It validates every source and target before the
first write, stages restrictive regular files on the target filesystem and
rolls back all earlier replacements if a later artifact fails. Windows fails
closed pending ACL verification. Installation proves protected bytes on disk,
not that a host process loaded them; heartbeat measurement and live action
probes remain independent requirements.

Codex process-loaded configuration is inspected only through its documented
app-server protocol. The endpoint pins the exact executable digest, invokes it
without a shell, bounds every response and projects raw configuration into a
fixed content-minimised schema before comparison or export. Raw responses may
contain credentials, paths, commands and URLs, so they are never logged,
persisted or included in errors. Missing administrator requirements, protocol
uncertainty and projected drift fail closed. MCP names are inventory only;
identity/runtime status is not claimed because querying it can initialize an
external server. Claude Code has no equivalent supported machine-readable API
and remains explicitly unverified at this boundary. See
[Codex effective-control evidence](codex-effective-controls-design.md).

For Codex, the server binds every process observation to the current desired
bundle hash, host version and platform before accepting the endpoint-reconciled
state. A forged positive state for another bundle is a conflict. Missing,
future-dated, expired, conflicting and partially observable evidence adds the
fixed `native_effective_controls` authority blocker and denies governed policy
and decision routes. The authenticated managed-package route remains available
only as a repair path and continues to enforce exact agent identity, rollout,
runtime attestation, emergency stop and quarantine. This exception supplies
configuration bytes; it never grants action authority.

Host limitations remain visible as coverage rather than being silently
promoted to enforcement. Claude command/path behavior routed through the AAI
hook is labelled SDK-enforced; Codex experimental network controls require a
pinned canary; native Windows Codex deny-read does not constrain reads made by
shell subprocesses. A policy expression requested with multiple outcomes
resolves deny-first and remains a conflict requiring audited operator repair.

Approved runtime release metadata is a separate deployment-owned boundary. The
operator API projects only manifests whose exact bundle digest, host/version
identity and independently verified provenance coverage have passed the same
fail-closed startup validation used by runtime attestation. Neither a browser
nor an enrolled endpoint can register a release, supply its approval evidence
or choose the compliance result. Tenant-wide reads require explicit human
`inventory_read` authority or the exact machine `inventory_read` scope;
policy-only and approval-only roles are denied.

Version compliance is calculated from tenant-scoped deployment targets and
fresh active-agent attestation. Missing release authority, an unapproved target,
missing or expired evidence, quarantine and version mismatch remain explicit
non-compliant states, with quarantine taking precedence over release setup.
The server also requires the exact approved SDK revision
and complete manifest digest, so a stale compliant flag cannot survive a
package/gateway/hook manifest change. Bounded tenant-bound cursor pages replace
an all-or-nothing fleet-size ceiling, and an incomplete page is never complete
fleet posture. An empty page is not counted as compliant. The projection
contains artifact digests but no executable bytes, source origin,
paths, commands, prompts or credentials. It is inventory evidence, not an MDM
delivery or managed-upgrade claim. See
[Approved runtime releases and version compliance](runtime-release-compliance-design.md).

Runtime upgrades are separate revision-bound authority. A deployment may admit
only its retained approved current release and one approved same-host target.
The server deterministically selects canary members from tenant, deployment and
agent identity; neither the browser nor endpoint supplies membership. New
transitions are limited to 1–25 percent. Broad selection must exceed 25 percent
and requires every selected canary to provide fresh exact version, revision and
manifest attestation. Target switching, percentage decreases and stale
revisions fail closed. Runtime authority and content-minimised primary audit
evidence commit in one DynamoDB transaction. See
[Measured runtime-release rollouts](runtime-release-rollout-design.md).

Endpoint remediation coordination is a still narrower observation boundary.
The server derives an executable-free instruction only for the exact live
rollout member and hashes the complete release/rollout binding. Browsers,
ordinary agent sessions and broad runtime machine credentials cannot claim or
report it. A dedicated `runtime_remediation` machine credential can lease one
instruction and submit only `installed` or a fixed redacted failure code; it
cannot author a rollout, select members, receive executable material or mark a
runtime verified. A rollout revision change invalidates the instruction.
Fresh exact challenge-bound attestation remains the only completion signal.
Every claim/report transaction conditions on the exact rollout and active agent
state together with the task and audit write. SDK clients recompute canonical
instruction digests, reject changed mutation authority and refuse redirects so
the scoped service bearer cannot cross origins.
Hosted provider dispatch, privileged installation and provider credentials are
outside this contract and require IAM-authenticated adapters, immutable
delivery packages and current managed-device binding. See
[Runtime remediation coordination](runtime-remediation-coordination-design.md).

## Dynamic group authority boundary

Dynamic membership changes which policy can authorize an agent, so neither the
browser nor an enrolled runtime supplies match attributes or a computed member
list. The control plane supports a closed conjunction over stable inventory
fields, strongly reloads agents, deployments and all groups, and derives the
desired set itself. Unknown fields, duplicate conditions, missing lineage,
inactive or cross-organization agents, oversized rules and candidate sets fail
closed.

Preview is non-mutating. Apply repeats evaluation, rejects overlap with another
policy group and compares the exact group membership revision in the same
transaction that stores the canonical rule, materialized membership,
idempotency result and primary audit evidence. A concurrent writer therefore
cannot substitute a different authority set. Dynamic groups reject manual add,
remove and batch routes, preventing those older paths from bypassing the rule.
Audit evidence contains only rule hashes and change counts; full membership,
prompts, tool arguments and credentials are excluded.

Scheduled convergence is a separate internal service boundary. EventBridge
supplies only a fixed source and schema version; tenant, group, rule, candidate
inventory and actor are resolved by the control plane. The reconciler accepts
only a previously operator-applied canonical rule, verifies its hash, repeats
strong inventory and overlap checks and compares the exact membership revision
when authority changes. It cannot author a rule or consume browser-selected
members. A malformed rule, overlap, incomplete lineage, bound exhaustion or
concurrent change preserves the last-known membership, stores a fixed-code
failure status and fails the invocation for bounded retry and monitored DLQ
delivery. Status records contain counts and health timestamps, never member
lists. See [Dynamic policy groups](dynamic-groups-design.md).

## Population discovery boundary

Discovery inputs are deployment-owned observations, never authorization. They
may lower posture and identify unmanaged, duplicate, leaver, or orphaned state,
but cannot enroll, revoke, quarantine, assign policy, or approve execution. The
server correlates them with its own tenant-scoped enrollment inventory.

Only complete, unexpired snapshots from identity, endpoint, and source-control
sources establish a defensible denominator. Missing, incomplete, stale, or
empty required evidence suppresses percentages and orphan conclusions. Raw
project paths, credentials, prompts, commands, and tool content are excluded;
project scope uses SHA-256 digests. Publication is revision-bound, bounded, and
audited by source metadata and hash rather than observation content. See
[Agent population discovery](agent-discovery-design.md).

Large snapshots use immutable bounded pages and an atomic generation commit.
Uncommitted pages are never included in reconciliation. A connector bearer is
stored only as a digest and bound to one tenant/source/class; it cannot enter
operator or agent routes. Rotation and revocation are live server-owned state
checked on every ingestion call. This prevents browser identity, URL fields,
partial uploads, stale writers, or connector output from becoming authority.
Application bearer theft remains a deployment risk, so production deployments
must deliver it through a secret manager, rotate it, restrict connector egress,
and may add cloud workload identity at the API gateway.

New pages are stored in a private, versioned S3 bucket under a server-derived
tenant-hash prefix. DynamoDB binds the exact object version and SHA-256 digest;
commit and reconciliation independently verify object size, digest, closed
schema, tenant/source/generation/page scope, normalized observations and page
hash. Missing, altered, oversized or cross-tenant object references lower
assurance and cannot establish coverage. Fixed 20-page fan-out supports at most
20,000 observations. See [Object-backed discovery
ingestion](object-backed-discovery-ingestion-design.md).

The operator source directory is a separate read model, not a credential
store. It strongly reads source and connector records, emits only lifecycle and
freshness metadata, and excludes both the stored digest and observation
content. A source ID's semantic class becomes immutable when either a legacy
snapshot or connector registration establishes it, preventing later credential
issuance from reinterpreting trusted source data. The UI holds a newly issued
plaintext credential only until the operator acknowledges the one-time panel;
it does not place it in fleet state or browser storage.

AWS-managed discovery adds three separate authorities: a tenant-tagged provider
secret, a source-scoped ingestion bearer, and a scheduler invocation role. The
browser supplies only the provider secret ARN, a closed cadence and, for GitHub,
a bounded typed organization/repository mapping. It never submits either secret
value, a schedule expression, target ARN, URL, raw project path or tenant. The
control plane validates same-account, same-region, KMS key, tenant namespace and
exact purpose tags without reading provider secret bytes. It writes the
generated ingestion bearer directly to a separately tagged KMS secret and
retains only its digest in DynamoDB.

The scheduled event is canonical and digest-bound to the live job revision,
provider, provider configuration and both secret ARNs. The collector strongly
reads that job before secret or network access, accepts only the Entra token and
users endpoint, the exact Intune managed-devices endpoint, or the fixed GitHub
organization-repositories endpoint plus the deployment API origin, and bounds
time, response bytes, pages and observations.
Redirects or continuation links outside the provider's exact host/path/query
contract fail closed. GitHub additionally requires every visible active
repository to match one deployment-owned project/host mapping and every mapping
to be visible; it publishes numeric repository IDs but not names. Failed,
partial, empty or mapping-incomplete collection never advances current evidence.
Disable atomically marks the job disabled and revokes ingestion before
best-effort schedule/secret cleanup; a stale schedule therefore cannot publish
even if AWS cleanup is delayed. Client-credential theft, malicious AWS
administrators, provider tenant compromise and the absence of hardware-backed
workload identity remain deployment risks. A GitHub token that cannot see an
unmapped repository cannot expose that blind spot; production acceptance must
independently prove all-repository access, and a centrally installed GitHub App
is the preferred future credential model. See
[AWS-managed discovery connectors](scheduled-discovery-connectors-design.md).

Reviewed policy imports use a separate GitHub App authority. A dedicated broker
alone reads the RSA private key and exchanges a short-lived App JWT for an
installation token narrowed to the exact configured repositories and read-only
Contents, Metadata and Pull requests. The verifier may invoke the broker but
cannot read its key; the control-plane handler may invoke the verifier but not
the broker. Malformed keys, broader returned permissions, implausible expiry,
redirects or invocation failure deny import before provider content is read.

Intune is authoritative only for its managed-device population. The collector
does not infer binary presence, process activity or project roots from device
enrollment, and it excludes device names, serial numbers, email addresses and
hardware properties. It retains only the canonical Entra device registration
ID required for future delivery targeting. That value is not treated as the
directory object ID: a dedicated worker must resolve it by the documented
alternate key and reproduce the exact registration ID online before group
membership mutation. Endpoint reports cannot submit or override it.
Reconciliation suppresses all percentages and orphan
conclusions until current endpoint evidence contains normalized installation
observations as well as devices. This avoids upgrading a read-only management
record into evidence Microsoft Graph cannot provide.

Endpoint installation and process evidence therefore uses a separate
administrator-run sensor. Its manifest names exact local files, executable
paths and project roots, but output replaces project roots with SHA-256 and
excludes paths, arguments, environment and user-facing content. A fixed
process adapter is the only dynamic operating-system lookup. Process
enumeration binds exact executable and configured project working-directory
paths, never invokes a shell, and aborts on access-denied sentinel values or
other incomplete visibility. POSIX collection verifies a root-owned,
non-symlink manifest without broad write permission before reading
configuration. Windows remains fail-closed until an ACL adapter can prove the
owner SID and effective write boundary.

Binary measurement rejects symlinks and measures an already-open regular inode,
including optional byte digest and before/after metadata, so path replacement
cannot become affirmative evidence. Each report is canonical HMAC-SHA-256
signed by a per-device software credential. The fleet assembler binds that key
to one authoritative MDM device, rejects stale, revoked, duplicate, changed or
unknown reports, and creates one complete fleet input for atomic publication.
The HMAC is source authentication, not hardware attestation; MDM administrators,
endpoint root compromise and stolen device secrets remain deployment risks.
See [Endpoint evidence publisher](endpoint-evidence-publisher-design.md).

Hosted Intune delivery is a separate privileged boundary. Intune app
deployment is group-assignment based, so the control plane derives an exact
rollout cohort rather than treating a managed-device ID as a command target.
An isolated, disabled-by-default worker now uses a dedicated role and
tenant-tagged delivery secret, exact package-app digest binding, transactional
FIFO outbox, online rollout/endpoint reauthorization and bounded
unknown-outcome reconciliation. It reports only provider assignment; fresh
independent runtime attestation remains the sole installation proof. The
read-only discovery credential cannot be silently widened. See
[Microsoft Intune managed delivery](intune-managed-delivery-design.md).
The [hosted endpoint evidence channel](hosted-endpoint-evidence.md) stores only
credential digests, binds reports to current MDM devices, rejects altered,
stale, replayed and cross-tenant evidence, and derives health server-side.
Endpoint detections are also server-derived. A device cannot choose severity,
alert state, acknowledgement or containment. Scheduled reconciliation uses a
deployment-owned sharded tenant index. Notification failure leaves a durable
pending alert for retry; it never converts the health condition into success.

Incident response does not upgrade endpoint observation into authority. Case
creation records a server-derived correlation, but containment re-derives it
from current authoritative inventory and signed evidence. Zero matches,
multiple matches, stale evidence, a changed binding digest, inactive lifecycle
authority or concurrent case state all deny the action. The browser never
submits an agent identity.

Quarantine, fleet stop, deployment stop, group stop and agent stop are
independent server records. Clearing one scope cannot erase another, and a new
group member inherits the live group stop. Quarantine withholds execution
authority while retaining the heartbeat/attestation channel so responders do
not destroy their own evidence. Session revocation is a separate monotonically
increasing authority revision; a bearer or bootstrap issued under an earlier
revision fails closed. Release requires a current binding and independently
derived recovery evidence. This is SDK/control-plane containment, not an MDM,
EDR, operating-system process kill or network-isolation claim.

Automatic response does not let a detection choose authority. A rule uses a
closed typed language, an immutable content hash and two-subject approval. The
scheduled detector re-derives the unique current endpoint-to-agent binding for
every alert occurrence, then applies rule-level hourly limits and a fleet-wide
per-agent cooldown before creating a rule-owned case. Unknown rules, malformed
versions, stale evidence, ambiguous bindings, prior case ownership and
concurrent state fail closed. GET requests cannot invoke this consequential
evaluation. Disabling removes future automatic authority immediately; rollback
can select only an independently approved superseded version. Response records
contain hashes and identifiers, not tool content or credentials. See
[Approved automatic response rules](automatic-response-rules-design.md).

Agent behavior detection has a deliberately weaker authority boundary.
Decision and approval reports are authenticated, content-minimised
observations; they can create an explainable alert but can never invoke an
automatic quarantine rule. The server derives tenant, agent, host, policy and
receipt time, bounds the retained history, refuses truncated or insufficient
baselines and records count/threshold/digest evidence without raw activity.
Behavior history is partitioned by exact tenant and enrolled agent, so one
noisy identity cannot truncate another identity's baseline. During the 30-day
sparse-index migration window, bounded legacy history is merged and any
truncation is explicit. DynamoDB secondary-index reads are eventually
consistent; the evaluator merges the current server-owned observation
synchronously, while the read-only fleet posture honestly declares that it may
briefly lag.
New tool and MCP identities remain untrusted dimensions. If a responder later
opens a case, every consequential action revalidates the current enrolled-agent
lifecycle, deployment, sole group, active policy and project-root digest. This
prevents browser or agent output from selecting authority while preserving a
manual response path. See [Explainable agent behavior
detection](behavior-detection-design.md).

Repository and configuration anomaly detection uses a separate alert-only
integrity boundary. The control plane independently re-hashes complete,
consecutive source-control inventory generations and compares only the exact
repository scope that previously contained an enrolled agent. It also compares
server-owned desired managed configuration with server-derived posture and
accepts only fixed runtime-attestation mismatch reasons that have already
quarantined the session. Agent or model output cannot choose tenant, host,
project scope, expected state, severity or response target. Missing, stale,
incomplete, non-consecutive or malformed authority produces no finding and
degrades detector health; it is never interpreted as a clean comparison.
Alerts retain identifiers and digests, not filesystem paths, repository URLs,
configuration bytes or credentials. A case may initiate manual SDK quarantine
only after the current enrolled-agent binding is revalidated. See [Repository
and configuration anomaly detection](repository-configuration-anomaly-design.md).

New source-control generations also bind detector input to a private,
server-derived S3 object key, exact version ID and SHA-256 digest committed in
the control table. A detector verifies the object size, digest, closed schema,
page hashes and generation hash before comparison. Partial references,
overwrites, malformed bytes and unavailable storage fail closed; they cannot be
interpreted as a clean baseline. An invocation-local tenant/source/generation
cache avoids repeating the same verified read for every agent and never crosses
an invocation or creates authority. See [Fleet integrity baseline
storage](fleet-integrity-baseline-storage-design.md).

Alert suppression is incident-response authority, not presentation state. The
server requires an exact identity selector, derives operator and time, limits
duration to seven days, retains the matched alert, withholds outbound delivery,
and prevents a suppressed endpoint alert from entering automatic containment.
Expiry or revocation restores routing for later observations without rewriting
earlier evidence. See [Governed alert suppression and
deduplication](alert-suppression-design.md).

Policy simulation is not execution and does not grant authority. The control
plane evaluates only a pending immutable version against a bounded tenant- and
policy-scoped window of redacted decision evidence. It reports missing command
content and MCP server identity as indeterminate instead of reconstructing or
guessing them. The result hash binds the candidate and exact sample, but does
not prove unseen behavior, endpoint convergence or policy safety. Semantic
diffs highlight expansions, restrictions and data-capture changes without
turning reviewer judgement into an automated allow decision. See
[Policy change assurance](policy-change-assurance-design.md).

Enterprise assurance reports are read-only projections, not new authority.
The server derives tenant and canonical operator role from authentication,
strongly reads bounded tenant records and preserves unavailable coverage when
population evidence is incomplete. The executive profile omits entity
identifiers; the auditor profile requires evidence-read authority and exposes
only bounded identifiers and routes to existing least-privilege evidence APIs.
Neither profile includes raw project paths, command content, credentials or
free-form narratives. Section and report hashes detect alteration of a retained
snapshot but are not signatures, trusted timestamps, compliance certificates
or substitutes for Object Lock evidence assurance. See
[Enterprise assurance reports](enterprise-assurance-reports-design.md).

Case export is a separate read authority available only to canonical evidence
roles. The server, never the browser, assembles a complete bounded snapshot,
rechecks case and source-alert revisions, removes raw content, credentials and
free-form approval narrative, and writes the canonical content digest to the
Object-Lock audit sink before returning the artifact. The browser verifies the
SHA-256 digest before download; `scripts/verify_incident_case_export.py`
repeats content, count, timeline and audit-receipt checks offline. The digest
detects modification but is not a KMS signature or a claim of legal
admissibility.

## Signed central policy threat model

An authenticated control-plane response is transport, not runtime policy
authority. A compromised database, proxy, browser, project repository or model
could otherwise replace policy bytes, replay another tenant's policy, or alter
a registered Skill or MCP server after review.

Reusable policy composition cannot delegate this authority to a mutable parent.
Each component edge binds one same-tenant, independently approved active or
retired policy version by ID, version, effective-content hash and component
graph digest. Code-owned merge rules intersect allow-lists, union denials and
approval requirements, minimize limits, preserve required safeguards and reject
ambiguous exact fields. The control plane stores local intent separately from
the effective configuration, reproduces both the effective hash and complete
graph digest before staging and activation, and bounds graph depth and size.
Missing, pending, cross-tenant, self-referential, stale or corrupt components
therefore deny promotion. See [Policy composition and GitOps](policy-composition-and-gitops-design.md).

Git repositories remain untrusted transport even when their branch is
protected. Policy import accepts only a server-retrieved exact repository,
full commit object ID and path. The deployment-owned verifier independently
checks the immutable blob, verified commit signer, one merged pull request and
the latest independent approval before parsing a closed bounded JSON schema.
The browser cannot supply content, review evidence, signer identity or provider
credentials. An accepted source creates only a draft in one atomic transaction;
it has no approval, activation, assignment or endpoint authority. Provider
failure, rewritten coordinates, duplicate keys, malformed content, cross-tenant
identity, unresolved components and changed idempotency input leave no partial
policy. Exports bind canonical source and graph digests to a separately signed
control-plane provenance envelope. A source-control administrator or compromised
reviewer can still approve malicious intent, so independent control-plane review
and endpoint verification remain mandatory.

In AWS, the GitHub credential and provider egress are isolated in a dedicated
Lambda with no DynamoDB or KMS signing permission. The policy-writing Lambda
cannot read the credential and may invoke only that exact worker. It treats the
worker response as untrusted, reconstructs typed evidence and compares source
and evidence digests before one conditional transaction writes the policy
shell, draft and provenance. This limits a verifier compromise from directly
activating or signing authority; it does not make a compromised GitHub account,
reviewer or worker trustworthy, so independent product approval remains a
separate mandatory boundary.

AWS activation resolves the exact effective configuration and signs a
canonical tenant, policy ID, version, content hash and configuration payload
with a non-exportable P-256 KMS key. The active version, resolved configuration
and signing evidence commit in the same DynamoDB transaction. Existing active
versions are signed without changing their stored authority; KMS failure or
inconsistent content blocks migration and retrieval. Trial provisioning signs
before writing any tenant record.

Claude Code and Codex receive public verification keys only through an
administrator-owned trust bundle. The SDK rejects missing trust, unsafe file
ownership/mode, symlinks, unknown keys or algorithms, malformed envelopes,
invalid signatures, altered hashes/content/identity/version and cross-tenant
replay before returning effective policy. The operator UI may show signer
fingerprints, but browser-returned key bytes never become trust automatically.
Key rotation requires an explicit old/new overlap rollout. A process that can
replace the administrator trust bundle remains able to choose a signer, so
endpoint file protection and managed deployment are part of the control.

Temporary exceptions never rewrite or masquerade as an immutable active
policy version. The AWS control plane binds one exception to an exact enrolled
agent, sole group, policy ID, base version and base content hash, requires a
different authenticated subject to approve it, and signs a distinct derived
policy identity with KMS at activation. Only tool, Claude resource/command and
maximum-action fields may differ; identity, credentials, isolation, approval
provider, capture, telemetry and redaction remain inherited and are rechecked
by the API. Server-clock expiry, revocation, agent lifecycle change, group
reassignment or base-policy change restores the ordinary signed bundle.
Corrupt derived signing evidence fails the refresh closed rather than falling
back silently. See [Time-limited policy exceptions](time-limited-policy-exceptions-design.md).

## Outbound webhook threat model

Webhook destinations are untrusted network peers. An authenticated browser may
request a configuration change but never supplies an event payload, signing
key, tenant identity or delivery message. Platform-administrator authority,
strict public HTTPS validation and optimistic revision checks are repeated at
the control-plane boundary. Signing keys are generated server-side, encrypted
under a dedicated KMS key, selected by exact Secrets Manager version and shown
to the browser only once.

The API persists a content-minimised tenant-scoped outbox record before sending
only its identity to a FIFO queue. A dedicated worker reloads the live endpoint,
payload and exact key versions on every attempt. It resolves DNS immediately
before a no-redirect request and rejects any non-global address, but
deployment-owned egress filtering is still required against the residual DNS
rebinding interval. The worker has no policy-signing, Cognito or broad secret
authority.

Signatures bind timestamp, stable delivery ID and exact raw body with
HMAC-SHA256. Timestamp validation limits delay; a receiver-owned durable atomic
claim on the delivery ID prevents replay and duplicate processing. Signature
validation without that claim is insufficient. Rotation uses a bounded dual
signature interval so the receiver can move keys without an unsigned gap.
Terminal status is written to Object Lock without response content or key
material. At-least-once transport means receiver idempotency remains mandatory.
See [Secure webhooks](secure-webhooks-design.md).

## Incident workflow provider threat model

ServiceNow, Jira Cloud and PagerDuty are untrusted workflow peers. They may be
unavailable, malicious, slow, return oversized or malformed content, redirect
requests, resolve through private addresses, commit a write without returning
success, or contain duplicate external objects. Their state never grants SDK
policy, identity, approval, containment, recovery or case-transition
authority.

The browser and API handle only closed non-secret provider configuration and a
structurally parsed tenant-scoped Secrets Manager ARN. Only the isolated
workflow worker has `GetSecretValue` and KMS decrypt authority for
`aai-sec/workflows/*`. Queue messages contain only tenant and delivery IDs.
Before each attempt, the worker strongly reloads delivery and connection
authority, requires an unchanged revision and allowed status, revalidates the
secret namespace, validates provider-specific credential JSON, resolves the
provider hostname and rejects redirects/private results.

The worker sends only fixed content-minimised case fields, uses five-second
timeouts and a 16 KiB response bound, and never persists response bodies or
credential values. ServiceNow correlation IDs, Jira labels and PagerDuty dedup
keys reconcile ambiguous retries. More than one match fails closed. Terminal
evidence is written to Object Lock before mutable health posture; bounded FIFO
retries, repair scheduling, DLQs and alarms make failure visible. An operator
retry requires integration-admin authority, an unchanged active connection
and retained rationale, and creates a linked new identity.

Provider field mappings, customer IAM scope, egress controls, credential
rotation/revocation and outage behavior still require live acceptance. See
[Governed incident workflow
integrations](incident-workflow-integrations-design.md).

## Signed assurance snapshot threat model

The browser may request a profile, schedule and rationale, but it cannot supply
report facts, tenant identity, signing evidence, object coordinates or schedule
execution authority. Live roles are checked for every request. Auditor content,
schedule metadata and history require `evidence_read`; generation and schedule
changes require `evidence_admin`.

AWS KMS signs a SHA-256 digest of a domain-separated canonical envelope, not
only the report body. The envelope binds tenant, snapshot, profile, source,
generated/signed time, schedule revision and canonical report digest. Copying a
valid signature across tenants or changing any envelope field therefore fails
verification. KMS key identity, algorithm and `SignatureValid` are all checked.
The report signer is a dedicated retained multi-Region key, distinct from
executable-policy authority. The worker receives no policy-key ARN or grant. A
validated local-Region registry maps stable MRK identities to current and
historical replicas; malformed, duplicate, foreign, missing or overlapping
authority fails closed.
Historical replicas receive verify-only IAM and are part of the exact
deployment-verification input; only the current assurance key can sign.

Snapshot bytes and a deterministic audit event are retained under S3 Object
Lock before DynamoDB metadata commits. Exact object version and digest are
rechecked on every read, with a one-megabyte pre-parse bound. Missing, altered,
oversized, cross-tenant or malformed evidence fails closed. Request IDs bind
profile, actor and rationale digest in a conditional claim written before
signing; concurrent changed first use is a conflict.

Scheduled work is claimed by an optimistic schedule revision before it enters
a dedicated SQS queue. The worker reloads the exact claim; duplicate, stale or
changed claims cannot select authority. A dispatcher never builds reports, one
failed tenant cannot block valid schedules, and fixed sharding, queue retries,
reserved concurrency and DLQ alarms bound fleet-wide work. Standby recovery
compute has no concurrency or active schedule/signing authority. See
[Enterprise assurance reports](enterprise-assurance-reports-design.md).

Mutable report state uses `ASSURANCE#{tenant}`, separate from policy, identity
and agent records. Worker IAM permits only conditional `PutItem` against that
leading key, dedicated assurance-key sign/verify and two exact audit S3
prefixes. Bounded due pages let later tenants progress; only acknowledged SQS
batch IDs leave the due index, while malformed provider responses fail closed.
Malformed schedules are conditionally quarantined out of the due GSI, so even
a complete corrupt page cannot indefinitely hide a later valid tenant. The
quarantine update binds the exact observed index and revision. Conditional
conflicts preserve concurrent repair, while DynamoDB throttling and service
failures fail the shard and leave valid records indexed; infrastructure
failure is never treated as evidence of malformed tenant state.

## Incident credential authority

Brokered credentials remain subordinate to a case-owned exact-agent control.
The incident responder identifies a case, not an agent or broker list; the
server re-derives the current binding and enforces the control across current
and future brokers. Only a `credential_broker_runtime` machine identity may
read the decision, while only authenticated incident response may create or
restore it. Missing, malformed, stale, cross-tenant or unavailable checks deny
mint and use. Credential values never enter case, audit or UI state. See
[Incident-driven credential revocation](incident-credential-revocation-design.md).

## Investigation correlation boundary

The hosted incident detail route correlates case, alert, policy-binding,
decision and approval evidence by authenticated tenant and the exact agent
binding captured by the case. The browser cannot select correlation keys or
claim completeness. Every source is projected into a fixed, credential-free
schema with explicit provenance before ordering. Agent decision evidence stays
an authenticated observation and cannot become policy or operator authority.
Bounded-source and record-limit omissions are visible fail-safe states, not
healthy investigations. See
[Unified investigation timeline](unified-investigation-timeline-design.md).

## Enterprise data-boundary authority

Encryption keys, approved retained-data Regions and operator source networks
are deployment authority. Browser state, token claims, model output and
ambient shell variables cannot select them. A strict manifest is verified,
persisted in encrypted Parameter Store and reloaded for deployment; once a
stack reports a configured boundary, loss of that manifest blocks deployment.

Configured operator requests trust only API Gateway context and fail closed
before tenant lookup. IP mode checks the source address. Private mode combines
an exact `aws:SourceVpce` API resource policy, Cognito authorization and an
independent Lambda check of the private API and endpoint IDs. The public API
continues to serve separately authenticated machine and agent routes but cannot
be used as a human fallback. Customer-key scope also excludes
CloudWatch logs, static UI assets, dedicated signing keys and provider secrets;
those remain separate boundaries and must never be described as covered by the
tenant data key. See [Enterprise data boundary](enterprise-data-boundary-design.md).

## Managed endpoint delivery authority

Physical software delivery is a separate privileged boundary from runtime
release approval. Delivery packages are deployment-owned closed manifests with
exact release, platform, architecture, S3 object version and digest bindings;
a separate approval bundle must cover them exactly. Lambda and CDK validate
the same authority. Operator responses omit object locators, executable bytes,
commands, signing material and provider credentials.

The browser cannot bind an endpoint. Readiness is derived inside the tenant
from current complete MDM discovery, a fresh signed endpoint report, exact host
and project-root digest correlation, and active server-owned agent lifecycle.
Anything other than one device, one installation and one agent blocks
readiness. Schema-v1 sensor evidence has no signed platform identity and is
therefore health evidence only; schema v2 signs normalized OS/architecture
measured by the administrator process.

This preflight is not dispatch authority. The existing runtime-remediation
service bearer receives no package locator and cannot install software. Intune
configuration now requires an immutable two-subject approval lifecycle. The
API validates tenant/KMS/purpose-bound Secrets Manager metadata at draft and
activation time but has no secret-read or decrypt permission. The rollout
reconciler can transactionally create idempotent dormant commands bound to
exact live provider, rollout, deployment, agent, signed endpoint evidence and
package state, with primary audit evidence in the same commit.

Hosted Intune delivery remains deployment-disabled by default. The isolated
worker and encrypted FIFO/DLQ are present, but the event source and repair
schedule are disabled unless deployment owners set the exact enablement flag
and a reviewed SHA-256 evidence identity together. The API still has no Graph
credential/decrypt authority. On each bounded command the worker reconstructs
fresh endpoint binding, resolves Entra device alternate keys online, verifies
pre-provisioned group/app metadata, reauthorizes before mutation, converges
exact dedicated-group membership, preserves unrelated assignments and writes
content-minimised Object Lock evidence. Commands above 40 targets fail before
credential access until continuation authority is implemented. Live customer
acceptance and independent post-install attestation remain mandatory. See
[Managed endpoint delivery authority](managed-endpoint-delivery-authority-design.md).

## Real Codex host acceptance boundary

The acceptance runner treats the installed Codex executable and every event it
emits as untrusted input. Only an exact version, operating system, architecture
and SHA-256 tuple is admitted. Streams, time, output size, record count, report
fields and local audit size are bounded; malformed, incomplete, changed or
oversized evidence fails closed. Tool prompts, arguments, output, paths and
credentials are never persisted.

Codex normalizes MCP server ID `agentic-security` to hook namespace
`mcp__agentic_security__`. The native hook permits only the literal and this
exact normalized prefix; near-prefix identities deny. Namespace matching is
not process identity: production use also requires administrator-owned MCP
configuration and fresh app-server evidence. Headless approval is enabled only
for the explicitly allow-listed synthetic MCP tool, after which both the
native hook and SDK gateway still authorize independently. See [Real Codex CLI
acceptance](real-codex-cli-acceptance-harness.md).
