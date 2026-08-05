# Enterprise P0 and P1 implementation status

This page is the live delivery ledger for the
[enterprise rollout requirements](enterprise-rollout-p0-p1-requirements.md).
It records implementation and evidence separately so a configuration field,
mock, heartbeat or local test cannot be mistaken for enterprise acceptance.

## Status meanings

- **Implemented:** production-shaped implementation and required local contract
  evidence exist. Deployment acceptance may still be outstanding.
- **Partial:** a meaningful control exists, but the requirement's acceptance
  evidence is incomplete.
- **Not started:** no implementation satisfies the requirement.
- **Stub:** interface and honest product workflow exist, but no production
  integration or delivery claim exists.

## P0 ledger

| ID | Requirement | Status | Current evidence | Next acceptance work |
| --- | --- | --- | --- | --- |
| P0-01 | Enterprise-enforced Claude configuration | Partial | Typed endpoint-managed settings and exclusive MCP compilation; canonical digest-bound package; root installer preflight/rollback; tenant-scoped control-plane publication and attested agent retrieval; desired/observed source, version, digest and freshness posture | Connect the authenticated package channel to MDM, run real root-owned install/deletion/weakening acceptance and prove approved launch profiles |
| P0-02 | Codex managed requirements | Partial | Typed system `requirements.toml` compilation for profiles, hooks, restrictive command rules, MCP identity, deny-read and network controls; canonical package, POSIX installer transaction and authenticated distribution; exact-binary real-host evidence confirms the local process reports administrator requirements missing instead of inheriting project authority | Connect the package channel to MDM, deploy requirements to a real managed Codex host, enforce the launcher and rerun exit-0 malformed/upgrade/bypass acceptance |
| P0-03 | Native-control reconciliation | Partial | Deterministic deny-first reconciliation and protected-file measurement; release-pinned bounded app-server evidence; real Codex 0.147.0-alpha.1.2 acceptance proves command allow/deny, approval routing, patch confinement, symlink-escape denial, guarded MCP execution and a complete content-free audit chain while preserving the managed-requirements blocker | Obtain exit-0 acceptance under installed administrator requirements, complete rules/deny-read observability and obtain equivalent authenticated Claude evidence or retain explicit manual evidence |
| P0-04 | Complete agent discovery | Partial | Source-scoped revocable connector credentials; redacted operator source directory; UI-first registration, rotation/revocation and separate credential/evidence posture; private exact-version S3 pages with digest-bound atomic commit and a 20,000-record bound; fail-closed complete-source denominator; unmanaged, duplicate, leaver and orphan reconciliation; Entra/endpoint/GitHub reference collectors; AWS-managed Entra, Intune and GitHub scheduling; administrator-run exact binary/process sensor; hosted per-device credential lifecycle, HMAC ingestion, replay/tamper denial and server-derived freshness UI; Intune device evidence alone cannot satisfy installation evidence; adversarial contracts for forged credentials, replay, altered hashes, cross-tenant object pointers, unsafe files, stale/revoked/cross-device reports, incompleteness and expiry | Package and deploy the sensor through a real customer MDM, complete successful real Entra, Intune and GitHub collections, independently prove provider/device credential scope, prove at least 95% real pilot discovery coverage, and load-test the customer's target above the 20,000-record synchronous envelope if required |
| P0-05 | Runtime attestation | Partial | Typed Claude/Codex measurement, release-bound clean-checkout manifest generator, exact manifest/provenance validation, nonce-bound heartbeat, baseline drift detection, quarantine/session revocation, fleet/group posture UI and adversarial contracts | Publish and pin the next independently verified release manifests, then complete live modified-package/hook/config/process and hardware-backed identity acceptance |
| P0-06 | Entra SSO, SCIM and granular RBAC | Partial | Tenant-specific Entra OIDC; tenant-bound SCIM lifecycle and canonical-role mapping; five-minute token reconciliation; expiring organization/project/deployment role delegation with live revocation and scoped reads; cross-organization group authority-edge denial; recent-MFA, four-eyes, maximum-60-minute break glass; schema-v2 digest-bound access export; persistent secret-free deployment manifest with tenant-specific OIDC/secret/AAI-tenant preflight and missing-manifest removal guard; adversarial contracts, deployed synthetic scope acceptance and focused Identity & Access workspaces for setup, directory roles, delegation, emergency access and reviews | Supply and configure the pilot tenant; prove real OIDC and SCIM joiner/mover/leaver; run deployed two-person MFA, delegated multi-business-unit and certification exercises |
| P0-07 | SIEM/SOAR | Stub | Splunk status contract and honest UI state with `deliveryVerified: false` | HEC delivery, authentication, schema, retry, dead letter, monitoring and replay |
| P0-08 | Durable evidence | Complete | S3 Object Lock; increase-only 365–3,650-day tenant retention; exact-version legal hold; revision-bound mass retention; fixed-cutoff asynchronous assurance/export with independent browser verification; scheduled gaps and durable alerts; live assurance acceptance across 532 records/54 pages; live mass-retention acceptance across 536 pre-cutover versions at 730 days; persisted fail-closed cross-region authority; live S3 Batch Replication and independent recovery verification of all 603 versions with exact identity/order, SHA-256 bytes, metadata, COMPLIANCE retention parity and replica provenance | Repeat the documented exercise in the first customer environment and retain its customer-owned evidence; regional API failover/RTO/RPO remain P0-11 |
| P0-09 | Production credential broker | Partial | Provider-neutral Azure/GCP workload brokers; scoped AWS STS; exact principal/audience/tool/resource/scope/TTL binding; live revocation checks; secret-free tenant-isolated hosted registration; machine-only fresh evidence; server-owned revocation epoch; case-owned exact-agent revocation across current and future brokers; recovery-gated restoration; typed operator workspace and adversarial contracts | Supply reviewed real AWS/Azure/GCP roles and accounts; deploy token-exchange/revocation adapters; prove least privilege, expiry, outage, callback discipline and incident revocation latency against each provider; independently review role policy and retained evidence |
| P0-10 | Production isolation | Partial | Exact reviewed profiles, structured action-bound production verification, live revocation, attested Docker launch contract, central lifecycle/evidence APIs, policy selection and enterprise UI | Selected customer boundary/host deployment, live hostile-code acceptance and independent assessment |
| P0-11 | HA/DR | Partial | Durable AWS stores; complete live bidirectional immutable audit replication; active-passive regional design; persisted 1,000-agent/30-minute-RTO/60-second-RPO authority; protected Global Tables and RPO canaries; multi-Region signing trust; managed-endpoint trust migration; guarded passive and active-not-routed runtimes; third-Region transactional witness; schema-v4 generation, ingress, exact-runtime, dedicated-role and two-Entra-approver authority; exact Regional stable/canary API and private-UI ingress; fresh source-fence/target-runtime/zero-job proof; authenticated canary/stable smoke; transactional Route 53 API/UI/generation-marker cutover; failed-target fencing; exact template-bound source reactivation; generation+2 inverse routing; retry-safe `ROLLED_BACK` sealing; exact primary target restoration/runtime proof; direction/Region/transition-bound target job reconciliation; symmetric planned failback; exact-version COMPLIANCE evidence retention/read-back guard; transition-bound real target heartbeat/policy/decision load adapter; read-only two-person dependency-fault authority; independently verified deployment-owned target-handler role outputs; single-writer fault lock, Scheduler watchdog/DLQ, code-owned IAM boundaries, expiry-safe cleanup handlers and private 18-state compensated Step Functions topology; exact live journal/template/runtime/routing preconditions; target-handler audit/DynamoDB/KMS/queue denial and recovery probes; adversarial IaC CI and runbooks | Deploy/initialize the witness, cells, exact custom domains and fault controller; establish exclusive DNS, fault-workflow and exact-handler invocation authority; provision the synthetic fleet; execute and retain real 1,000-agent load, dependency, backup/key recovery and failover/rollback/failback evidence; Cognito fault injection remains unsupported |
| P0-12 | Assurance package | Partial | Apache-2.0 project, SBOM/release provenance and security policy | Independent penetration test, vulnerability SLA and customer legal/compliance pack |

P0-08 is complete for the deployed evidence boundary. The remaining partial P0
rows still prevent enterprise-wide rollout.

## Current delivery slice — managed host authority

The managed-host compiler converts typed policy intent into deterministic
Claude Code or Codex administrator-owned artifacts. It rejects unsupported
client versions, relative or shell-composed hooks, insecure MCP identities and
unbounded policy input. The resulting bundle digest binds the complete intent,
target host/version/platform and every artifact digest.

The fleet heartbeat accepts only a fixed, content-minimised managed evidence
schema. The control plane derives `enforced`, `missing`, `stale`, `conflict` or
`not_configured` by comparing it with server-owned desired state; an agent
cannot submit the status. Agent verification now requires exact fresh managed
configuration in addition to registration, heartbeat, policy assignment,
runtime attestation and no emergency stop.

This does not close P0-01 through P0-03. The SDK does not write privileged
system paths, Claude server-managed configuration cannot express per-group
settings, and a bearer-authenticated host measurement is not hardware-backed
device attestation. Live MDM deployment, approved-launch enforcement and
execution-matching acceptance remain required.

The enrolled-agent client now closes the protocol gap between measurement and
fleet posture. A deployment-owned callback reopens protected files without
following symlinks, verifies root ownership, restrictive modes, exact bounded
bytes and host/source identity, and sends typed evidence on every heartbeat.
When a managed bundle is assigned, missing, stale or conflicting evidence
blocks governed agent routes instead of merely lowering a dashboard score.
This is still software evidence and does not replace the outstanding live host
execution and MDM acceptance.

Codex now has an additional process-loaded evidence path. A deployment-pinned
executable is launched without a shell, queried through the supported
app-server protocol, and reduced in memory to a credential-free projection.
The endpoint and AWS control planes validate the exact schema and derive
freshness on read; the agent detail UI presents approval, sandbox, managed hook
and MCP inventory evidence without exposing raw configuration. Local Kratos
acceptance truthfully returns `missing` because no administrator requirements
are installed. MCP runtime status, command-rule matching and deny-read matching
remain explicit unverified controls, so this row stays Partial and those states
withhold every intended allow.

That evidence is now an execution boundary rather than dashboard-only posture.
It carries the inspected managed bundle hash, and both control planes rebind it
to current server desired state, host version, platform and server-clock
freshness. A forged `enforced` report for another bundle becomes `conflict`.
The AWS heartbeat returns a fixed `native_effective_controls` blocker, the
enrolled client fails closed, and governed policy/decision routes repeat the
check. The exact attested managed-package route remains available for recovery.
This materially advances P0-03 but does not close it because MCP runtime,
command-rule and deny-read execution matching plus Claude's equivalent evidence
remain outstanding.

The package distribution slice now gives a platform administrator an
optimistic-concurrency publication route and gives the exact enrolled agent an
authenticated retrieval route. Every publication is reparsed from canonical
bytes and must exactly match current server-owned desired state. Downloads are
rollout-, attestation- and emergency-stop-gated, and remain possible while
managed configuration is missing so an endpoint can repair itself. Operator
reads expose metadata only. This closes control-plane distribution, not MDM
installation or live host-load acceptance.

Schema-v2 packages now bind the canonical policy-signing trust store as a
separate administrator-owned artifact. Publication and retrieval require its
out-of-band digest, the privileged installer stages and verifies the complete
native-configuration-plus-trust transaction before deleting backups, and each
heartbeat reopens the files without following symlinks and requires root
ownership, restrictive modes and exact bytes. The deployed control plane
derives a tenant-wide cutover posture only when one trust digest is current in
every package, rollout and fresh endpoint report. The
[2026-08-02 live acceptance](policy-trust-convergence-acceptance-2026-08-02.md)
proved the safe empty-fleet state and unchanged active signer. Physical endpoint
installation and convergence are deliberately not claimed.

The real Claude Code compatibility gap now has a repeatable, bounded host
harness and an exact default-deny version matrix. It invokes only a disposable
synthetic project and records content-free allow, deny, approval, project-scope
and guarded-MCP observations. Thirteen focused contract/adversarial tests cover
exact digest admission, changed binaries, malformed and oversized host output,
authentication blocking, no-side-effect scenarios, report minimisation and the
documented CLI path. The 2026-08-05 installed-host run accepted the measured
Claude Code 2.1.220 macOS arm64 executable and verified onboarding, then
correctly returned `blocked` when the local OAuth session was unavailable. The
real model/tool observations therefore remain open until an authenticated
rerun exits zero; see [Real Claude Code acceptance
harness](real-claude-code-acceptance-harness.md) and [current
evidence](real-claude-code-acceptance-evidence-2026-08-05.md).

The real Codex CLI compatibility slice now has an exact default-deny version
matrix and repeatable disposable-project harness. The 2026-08-05 installed-host
run produced 10 passes and zero failures across process protocol,
authentication, native command and patch controls, project-scope denial,
guarded MCP execution and hash-chained audit. It exited `4` because
administrator requirements are absent. This resolves the earlier local MCP and
live-execution uncertainty but does not close P0-02 or P0-03: enterprise
acceptance requires MDM-owned policy and an exit-0 rerun. See [Real Codex CLI
acceptance evidence](real-codex-cli-acceptance-evidence-2026-08-05.md).

## P1 ledger

| Workstream | Status | Implemented foundation | Major remaining work |
| --- | --- | --- | --- |
| Fleet lifecycle | Partial | Enrollment, groups, revision-bound bulk assignment, trusted dynamic-group preview/apply and monitored five-minute deterministic reevaluation, health, immutable desired/package rollout binding, deterministic canary rings, time-zone maintenance windows, server-derived endpoint convergence, automatic health/deadline pause, exact known-good rollback, drift, emergency stop, irreversible revoke, atomic replacement, evidence-retaining offboarding, accountable ownership, server-clock-expiring exact-agent policy exceptions, source-reconciled orphan/leaver detection, AWS-managed Entra/Intune/GitHub discovery connectors, signed endpoint installation/process collection, per-device credential lifecycle, server-derived evidence health, deployment-owned approved runtime-release catalog, tenant-scoped version-compliance reporting, revision-bound dual-version runtime canary selection/admission with measured pause and rollback, and an executable-free least-privilege endpoint remediation coordination queue whose channel reports cannot replace attestation | Publish real release manifests; add immutable platform delivery packages, bijective device binding and IAM-authenticated Intune/Jamf dispatch; connect physical MDM distribution; complete real-provider population coverage and response automation |
| Policy governance | Partial | Typed editor, immutable version ledger, readable active-versus-pending authority, independent review with rationale, semantic authority diff, bounded redacted historical simulation, restrictive composition, reviewed exact-commit GitHub import, immutable provenance UI, draft-only writes, KMS-signed canonical export, unattended repository- and permission-scoped GitHub App token minting, signed bundles, temporary agent exceptions, canary/scheduling, evidence-only convergence and known-good rollback | Complete live Git-provider acceptance and physical-endpoint rollout-SLO acceptance |
| Security operations | Partial | Approvals, audit timeline, independent scoped emergency stops, scheduled server-derived endpoint detections, independently reviewed alert-only tool/MCP/denial/approval/decision-volume/outside-project/configuration-error behavior rules with exact-agent bounded history, explicit migration/completeness gates, explainable thresholds and paginated fleet readiness, independently re-hashed repository mapping and managed-configuration/runtime-attestation integrity rules with explicit blind spots and no automatic containment, private exact-version S3 integrity baselines and discovery pages with digest binding, stable evidence-preserving deduplication groups, exact maximum-seven-day suppressions with audited expiry/revocation, audited acknowledgement, durable SNS/SQS and signed-webhook delivery, revisioned cases, source-specific server-revalidated agent binding, evidence-preserving agent quarantine, independently approved endpoint-response rules with preview, action limits, cooldown, idempotent evidence, disable and rollback, session revocation, exact-agent brokered-credential revocation with machine-only live checks and recovery-gated restoration, a typed provenance-labelled identity/policy/tool/MCP/approval/credential/isolation/evidence/operator investigation timeline with explicit completeness, recovery-gated release, integrity-verifiable content-minimised case export, and governed ServiceNow/Jira/PagerDuty lifecycle delivery with exact-revision verification, provider reconciliation, isolated credentials, controlled retries and operator UI | Real-provider incident-revocation and workflow acceptance, customer-specific capacity/load proof for exact-agent behavior history and the wider control plane, and MDM/EDR isolation |
| Reporting and administration | Partial | Seven-workspace operator navigation with contextual destinations and preserved deep links; fleet posture, health, SLO and compliance summaries; fail-closed population coverage; deployment-owned approved SDK/gateway/hook catalog and server-derived per-agent/deployment version compliance; purpose-specific executive and evidence-reader assurance reports; operator and daily/weekly scheduled snapshots with domain-separated KMS signatures, exact replicated Object Lock versions, audit-before-state evidence, revision-bound SQS workers, recovery-cell parity and in-product verification/download; scoped expiring service identities; versioned Terraform provider; tenant-managed signed webhooks with durable delivery and replay-verification helper; persistent customer-managed data-key, approved retained-data Region and exact PrivateLink VPC-endpoint authority with a read-only posture UI | Customer-validated framework mappings, external report delivery, real-workload machine-API and Terraform acceptance, provider Registry release/signing, live customer webhook interruption/replay acceptance, live CMK/deletion/residency acceptance, and customer VPN/Direct Connect, DNS, endpoint-policy and security-group acceptance for private access |

### P1-ADM-08 implementation evidence

The hosted control plane now separates human Cognito/Entra access from a
versioned `/machine/v1` bearer boundary. A platform administrator can create a
tenant-owned service identity with one or more of eight exact capabilities and a
1–90-day expiry. The plaintext credential is returned once; subsequent reads
expose only a fingerprint. Every request reloads digest-keyed credential and
strongly consistent identity state, then checks expiry, status, credential
revision, current pointer and an independently maintained route allowlist.
Machine context cannot inherit human, delegated or break-glass authority.

Rotation atomically invalidates the old bearer and revocation immediately
removes future authority. Admitted requests create content-minimised retained
usage and immutable audit evidence. Contracts prove issue/list secrecy,
admission, rotation, revocation, expiry, forgery denial, cross-tenant isolation,
unsupported capability denial and exclusion of policy activation and other
human governance. The private UI provides typed least-privilege creation,
one-time secret handling, posture and per-identity evidence.

This completes the implementation foundation of P1-ADM-08. Enterprise
acceptance remains open until an approved real workload stores the bearer in an
enterprise secret manager and exercises deployed use, rotation and revocation;
see [Scoped service identities and machine API](service-identities-design.md)
and [Inputs needed from the product owner](needed-from-from.md).

### P1-ADM-09 implementation evidence

The Go Terraform provider under `terraform-provider-aai-sec/` uses only the
versioned service-identity boundary. It provides a tenant data source and
schema-declared resources for governed policy drafts, groups, Skills and MCP
registrations; policy JSON remains server-schema-validated.
Refresh/import read exact tenant-scoped IDs; mutable resources send optimistic
revisions; stale changes return conflict instead of overwriting authority.
Group configuration and membership revisions are independent, occupied groups
cannot be deleted, and Skill/MCP destruction retires rather than erases.
Policy destruction retains the immutable ledger, and no provider route can
submit, approve, stage or activate policy. Each desired-state mutation and its
content-minimised primary audit record commit atomically; Object Lock export is
a replica of that already durable evidence.

Go unit tests cover endpoint and token validation, versioned routing, bounded
errors, exact-ID lookup and provider inventory. AWS Lambda contracts cover
create/update/retire/delete behavior, legacy revision migration, stale writes,
occupied-group deletion and machine-governance denial. `make check` compiles,
vets and tests the provider and formats its HCL example. Registry publication,
release signing and a deployed real-workload Terraform apply remain external
acceptance work; see [Terraform provider and declarative
management](terraform-provider-design.md).

### P1-ADM-10 implementation evidence

The hosted control plane now creates tenant-scoped public-HTTPS webhook
destinations under platform-administrator authority. A 256-bit HMAC key is
generated server-side, encrypted with a dedicated rotating KMS key, selected by
exact Secrets Manager version and returned only at creation or rotation. A
bounded one-hour to seven-day overlap causes the isolated worker to send both
current and previous signatures without exposing either secret to the queue,
database views or ordinary browser reads.

Events enter a persistent DynamoDB outbox before their tenant/delivery identity
is submitted to a FIFO queue. The worker reloads live authority, rejects
redirects and private DNS answers, bounds timeout and response bytes, retries
five times, uses a DLQ and writes content-minimised terminal evidence to Object
Lock. A separate health projection cannot overwrite destination configuration.
The public `verify_webhook` helper validates exact bytes, timestamp and key ID,
uses constant-time comparison and fails closed when its caller-provided atomic
replay store is unavailable. The typed UI manages destinations, one-time
secrets, verification events, delivery posture, rotation and lifecycle without
claiming a queued event was delivered.

Unit, adversarial, Lambda/worker contract and CDK synthesis evidence cover
tamper, expiry, replay, dual-key overlap, role and tenant isolation, unsafe
egress, exact-version secret authority, durable queueing, terminal audit and
posture repair without redelivery. This completes the implementation foundation
of P1-ADM-10. A real customer receiver, durable receiver replay store, egress
policy and interruption/rotation/DLQ replay exercise remain acceptance work.
P0-07 remains a Splunk stub. See [Secure webhooks](secure-webhooks-design.md).

### P1-ADM-11 and P1-ADM-12 implementation evidence

The AWS deployment now accepts one strict reviewed manifest for a same-account,
same-Region rotating customer KMS data key, approved retained-data Regions and
public IPv4 operator networks. It persists that authority in encrypted
Parameter Store, removes ambient overrides, re-verifies it before every deploy
and blocks deployment if a previously configured authority disappears. The key
encrypts retained tenant DynamoDB tables, tenant-data/evidence S3 buckets,
durable queues and security notifications. A read-only UI and API expose only
redacted posture, deletion classes and limitations.

Configured human routes fail closed on missing or outside API Gateway context
before tenant lookup and ignore forwarding headers. Schema-v2 private mode now
deploys a Cognito-authorized private REST API restricted to exact reviewed
execute-api VPC endpoint IDs, while preserving a separate public machine/agent
channel. The software foundation for P1-ADM-12 is implemented. Live customer
VPN/Direct Connect, routing, DNS, endpoint-policy, security-group and
allow/deny acceptance evidence remains open, as do customer key-policy,
deletion and residency exercises. CloudWatch logs,
global identity/edge processing, static assets, signing keys and provider
secrets are explicitly outside the customer data-key claim. See [Enterprise
data boundary](enterprise-data-boundary-design.md).

### P1-FLT-01 acceptance evidence

**Bulk enrollment and assignment is complete for the requirement's “select
many” path.** The hosted group detail UI selects up to 100 active unassigned
agents, requires an operator rationale, shows progress, previews live typed
outcomes, applies eligible assignments, and retains partial failures per agent.
The AWS route `POST /api/enterprise/groups/{group}/agents/bulk` repeats live
validation, compares the exact membership revision, rejects multi-group
authority, and atomically stores the membership change, idempotency result and
immutable audit summary. Contract tests prove preview has no side effect,
partial HTTP 207 behavior, replay, request-ID collision denial, stale revision
denial, transaction rollback, duplicate/oversized rejection, sole-group
enforcement, and revisioned removal. UI tests prove preview precedes apply and
that the same request ID is reused. CSV/file import is a future convenience,
not required because P1-FLT-01 explicitly accepts either import **or** selection.

### P1-FLT-02 acceptance evidence

The bounded dynamic-group slice evaluates only strongly read server inventory,
previews without writes, blocks policy-group overlap, and atomically stores
materialized membership, canonical rule, optimistic revision, idempotency
result and primary audit evidence. Contract tests cover trusted-attribute
changes, deterministic removal, unsupported fields, stale revisions, overlap,
manual-route bypass and transaction races. UI tests prove typed authoring,
preview-before-apply and exact request-ID reuse. A monitored five-minute
service schedule now reevaluates only previously approved rules, atomically
materializes changed authority and exposes durable health without member-list
content. Contract tests prove automatic addition, no-change idempotence,
last-known-authority preservation on overlap, fixed failure evidence and
rejection of caller-shaped schedule events. Endpoint posture attributes remain
outstanding and are not claimed.

### P1-SOC-09 implementation evidence

The hosted control plane now has closed-schema ServiceNow, Jira Cloud and
PagerDuty connections under `integration_admin` authority. The API stores a
structurally validated tenant-scoped Secrets Manager ARN but cannot read its
value. A dedicated KMS-decrypting worker strongly reloads exact live authority,
revalidates public provider DNS and no-redirect HTTPS, bounds responses and
handles provider credentials only in memory.

Case-open, contain, resolve and close transactions atomically create
deterministic content-minimised outbox records for active subscriptions. FIFO
delivery, scheduled repair, five-attempt DLQs/alarms, ServiceNow correlation,
Jira labels and PagerDuty dedup keys cover retries and ambiguous provider
commits. More than one external match fails closed. Terminal evidence reaches
Object Lock before mutable health. An explicit retry requires a retained reason,
terminal attempt count and unchanged active connection, and creates a linked
identity that performs provider reconciliation again.

The enterprise UI provides a table-first provider workspace, typed registration,
help for every setting, secret-ARN-only handling, synthetic verification,
exact-revision activation, pause/resume/retire, delivery evidence and governed
retry. Synthetic API, worker, SSRF, credential-isolation, provider contract,
infrastructure and UI tests are retained. P1-SOC-09 remains Partial until a
customer-owned provider completes least-privilege, create/update/resolve,
response-loss, duplicate, outage, retry, rotation and revocation acceptance.
See [Governed incident workflow
integrations](incident-workflow-integrations-design.md) and [Inputs needed from
the product owner](needed-from-from.md).

### P1-FLT-08, P1-POL-05 and P1-POL-06 implementation evidence

The AWS control plane now treats rollout state as server-derived operational
evidence rather than an operator presentation flag. Every desired assignment
creates an immutable configuration version. Starting a rollout requires the
exact optimistic revision, desired managed-host target, current immutable
package revision, active compatible agents, bounded channel/ring/percentage,
health thresholds, rationale and optional IANA-zone maintenance window.
Canaries are deterministic from tenant and agent identity and are capped at
25%; percentages may expand but cannot decrease outside rollback.

The five-minute reconciler computes availability, drift and convergence from
fresh authenticated agent reports. Browser requests cannot submit applied
hashes, endpoint membership, health or known-good state. A threshold breach or
deadline automatically pauses authority. Only a 100% rollout with fresh exact
evidence from every active endpoint becomes `converged` and records a
last-known-good configuration/package pair. Rollback creates a new immutable
version from that exact retained pair and measures convergence again. Contract
tests prove forged convergence denial, stale revision rejection, schedule and
canary bounds, automatic pause, immutable package selection and rollback.

This implements the control-plane portions of P1-FLT-08, P1-POL-05 and
P1-POL-06. The requirement remains short of enterprise acceptance until a real
MDM-delivered Claude/Codex fleet demonstrates the rollout SLO. P1-FLT-06 also
remains partial: configuration packages are pinned, but SDK, gateway and hook
upgrade channels still need independently approved release manifests and
physical endpoint distribution.

### P1-FLT-09 and P1-POL-10 implementation evidence

The AWS authority boundary permits one open temporary exception per exact
enrolled agent. Creation derives the sole group and current active policy from
server-owned state, retains owner, purpose and expiry, and permits only the
focused tool, Claude resource/command and maximum-action fields exposed by the
typed UI. `draft -> review -> approved -> active` is compare-and-swap governed
and self-approval is denied. Activation signs a distinct derived policy bundle
with KMS. Effective-policy retrieval rechecks agent lifecycle, assignment,
base version/content hash and server-clock expiry; expiry, revocation or stale
scope restores the normal signed policy and records lifecycle evidence.
Contracts cover overlap, role denial, secrets, immutable-field weakening,
transition replay, signing and expiry. The 2026-08-01 AWS acceptance exercised
independent approval, KMS-signed activation, exact-agent delivery and
server-clock restoration against the deployed stack; see
[time-limited policy exception acceptance](time-limited-policy-exception-acceptance-2026-08-01.md).
Endpoint convergence and configured runtime attestation remain separate pilot
requirements and are not claimed by this evidence.

## Current delivery slice — Entra identity and trust

The active implementation establishes the provider-neutral identity boundary
with Microsoft Entra ID as the first adapter:

1. CDK rejects partial Entra configuration and non-tenant-specific issuer IDs.
2. The OIDC client secret resolves from Secrets Manager and is never returned
   to the UI or Lambda environment.
3. A Cognito V2 pre-token trigger adds provider provenance only for the exact
   configured OIDC identity.
4. The API independently binds that directory to one provisioned AAI tenant.
5. Mutating routes require an explicit capability from one of seven canonical
   roles; malformed and lookalike roles fail closed.
6. A separate bearer-protected SCIM endpoint provisions tenant-bound users,
   groups and memberships using immutable Entra object UUIDs.
7. Only a platform administrator maps exact active groups to canonical roles;
   token issuance reconciles live lifecycle state and fails closed.
8. Access and ID tokens expire after five minutes, bounding mover/leaver
   convergence when refresh repeats the lifecycle lookup.
9. The UI reports lifecycle counts, sync posture and role mappings while
   preserving honest degraded and not-configured states. The UI separates the
   overview, Entra setup, directory roles, delegated access, emergency access
   and certification journeys; Splunk remains a non-delivering stub outside
   identity readiness.
10. Emergency access is self-targeted, exact-capability, conditional,
    recent-MFA, four-eyes and bounded to 60 minutes; the server rechecks it on
    every mutation and revocation takes effect immediately.
11. Auditors can export a digest-bound complete SCIM, role and emergency-access
   artifact; oversized partial inventories fail and unconfigured SCIM is
   explicitly incomplete.
12. Tenant identity administrators can assign an expiring non-admin role to an
    active Entra object for one organization, project or deployment. The API
    resolves lineage and live grant state per mutation, filters delegated-only
    reads, denies self/platform-admin/identity delegation, and includes the
    complete ledger in access-certification schema version 2.

The live acceptance command now discovers deployed posture, reads its bearer
only from Secrets Manager, and exercises synthetic joiner, mover and leaver
state with exact cleanup. The 2026-07-29 AWS preflight returned `NOT READY`
because the pilot stack has no Entra tenant configuration; this is correct
fail-closed evidence, not an acceptance pass. P0-06 still requires a configured
pilot tenant and real Entra OIDC sign-in, role transition and token-revocation
exercise, a deployed two-person Entra MFA break-glass and access-review
exercise, and a multi-business-unit delegated-scope exercise.

### P1-POL-11 implementation evidence

The provider-neutral and AWS policy ledgers now return a deterministic,
configuration-digest-bound `nativeControlAnalysis` for every immutable version.
It identifies exact command expressions assigned conflicting decisions, native
built-in or file-tool authority outside the SDK boundary, stricter native
settings that make SDK permissions inoperative, and configured native controls
that are disabled. Findings contain fixed explanations and field names only;
the expression or policy value is never returned.

Both staging and activation recompute this analysis from stored candidate
content and reject any blocker. The enterprise UI displays blockers, warnings,
affected host and remediation, treats a missing report as unavailable, and
disables staging/activation unless the server reports zero blockers. Unit,
adversarial, AWS parity, Lambda-contract and UI journey tests cover the gate.
A clear static report does not prove deployment: Claude/Codex endpoint
convergence remains a separate rollout acceptance requirement.

## Current AWS acceptance — 2026-07-29

The governed policy lifecycle and hosted UI are merged and deployed. The live
safe-default policy migrated to an immutable active version-2 ledger entry
without changing active authority. Public unauthenticated policy and identity
requests fail with HTTP 401.

The deployed delegated-administration boundary passed a synthetic live
organization-scope exercise: create, allowed descendant mutation, sibling
denial, filtered read, delegated identity-governance denial, forged-claim
denial, immediate revocation, post-revocation denial and schema-v2 access
certification all produced the expected HTTP status. Exact synthetic DynamoDB
and S3 audit records were removed after the exercise. This proves deployed
software enforcement, not real Entra lifecycle or multi-business-unit
governance acceptance.

The managed Claude Code and Codex registrations on Kratos are not currently
verified: both heartbeats are expired, runtime manifests are not configured,
and exact managed configuration is not freshly proven. Entra OIDC and SCIM are
also not configured. These are explicit rollout blockers, not dashboard-only
warnings. See [AWS pilot acceptance evidence](aws-pilot-acceptance-2026-07-29.md)
for the exact pass/fail record and release sequence.
