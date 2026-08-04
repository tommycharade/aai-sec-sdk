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
| P0-02 | Codex managed requirements | Partial | Typed system `requirements.toml` compilation for profiles, hooks, restrictive command rules, MCP identity, deny-read and network controls; canonical package, POSIX installer transaction and authenticated distribution | Connect the package channel to MDM, deploy to a real managed Codex host, enforce the launcher and run malformed/upgrade/bypass acceptance |
| P0-03 | Native-control reconciliation | Partial | Deterministic deny-first reconciliation, protected-file measurement on every enrolled heartbeat, exact desired/evidence checks, governed-route denial and conflict/missing/stale UI | Bind complete host-native effective settings (not only protected-file measurement) and prove displayed authority against live Claude/Codex execution |
| P0-04 | Complete agent discovery | Partial | Source-scoped revocable connector credentials; redacted operator source directory; UI-first registration, rotation/revocation and separate credential/evidence posture; immutable paginated generations with atomic commit and a 2,000-record bound; fail-closed complete-source denominator; unmanaged, duplicate, leaver and orphan reconciliation; Entra/endpoint/GitHub reference collectors; AWS-managed Entra, Intune and GitHub scheduling; administrator-run exact binary/process sensor; hosted per-device credential lifecycle, HMAC ingestion, replay/tamper denial and server-derived freshness UI; Intune device evidence alone cannot satisfy installation evidence; adversarial contracts for forged credentials, replay, altered hashes, unsafe files, stale/revoked/cross-device reports, incompleteness and expiry | Package and deploy the sensor through a real customer MDM, move very large pages to dedicated object storage, complete successful real Entra, Intune and GitHub collections, independently prove provider/device credential scope, and prove at least 95% real pilot discovery coverage |
| P0-05 | Runtime attestation | Partial | Typed Claude/Codex measurement, release-bound clean-checkout manifest generator, exact manifest/provenance validation, nonce-bound heartbeat, baseline drift detection, quarantine/session revocation, fleet/group posture UI and adversarial contracts | Publish and pin the next independently verified release manifests, then complete live modified-package/hook/config/process and hardware-backed identity acceptance |
| P0-06 | Entra SSO, SCIM and granular RBAC | Partial | Tenant-specific Entra OIDC; tenant-bound SCIM lifecycle and canonical-role mapping; five-minute token reconciliation; expiring organization/project/deployment role delegation with live revocation and scoped reads; cross-organization group authority-edge denial; recent-MFA, four-eyes, maximum-60-minute break glass; schema-v2 digest-bound access export; persistent secret-free deployment manifest with tenant-specific OIDC/secret/AAI-tenant preflight and missing-manifest removal guard; adversarial contracts, deployed synthetic scope acceptance and focused Identity & Access workspaces for setup, directory roles, delegation, emergency access and reviews | Supply and configure the pilot tenant; prove real OIDC and SCIM joiner/mover/leaver; run deployed two-person MFA, delegated multi-business-unit and certification exercises |
| P0-07 | SIEM/SOAR | Stub | Splunk status contract and honest UI state with `deliveryVerified: false` | HEC delivery, authentication, schema, retry, dead letter, monitoring and replay |
| P0-08 | Durable evidence | Complete | S3 Object Lock; increase-only 365–3,650-day tenant retention; exact-version legal hold; revision-bound mass retention; fixed-cutoff asynchronous assurance/export with independent browser verification; scheduled gaps and durable alerts; live assurance acceptance across 532 records/54 pages; live mass-retention acceptance across 536 pre-cutover versions at 730 days; persisted fail-closed cross-region authority; live S3 Batch Replication and independent recovery verification of all 603 versions with exact identity/order, SHA-256 bytes, metadata, COMPLIANCE retention parity and replica provenance | Repeat the documented exercise in the first customer environment and retain its customer-owned evidence; regional API failover/RTO/RPO remain P0-11 |
| P0-09 | Production credential broker | Partial | Typed broker contracts and AWS scoped STS reference | Real AWS/Azure/GCP production role inventory and revocation evidence |
| P0-10 | Production isolation | Partial | Typed attestation contract and Docker probe | Supported production sandbox adapter and independent hostile-code assessment |
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

## P1 ledger

| Workstream | Status | Implemented foundation | Major remaining work |
| --- | --- | --- | --- |
| Fleet lifecycle | Partial | Enrollment, groups, revision-bound bulk assignment, trusted dynamic-group preview/apply and monitored five-minute deterministic reevaluation, health, immutable desired/package rollout binding, deterministic canary rings, time-zone maintenance windows, server-derived endpoint convergence, automatic health/deadline pause, exact known-good rollback, drift, emergency stop, irreversible revoke, atomic replacement, evidence-retaining offboarding, accountable ownership, server-clock-expiring exact-agent policy exceptions, source-reconciled orphan/leaver detection, AWS-managed Entra/Intune/GitHub discovery connectors, signed endpoint installation/process collection, per-device credential lifecycle and server-derived evidence health | Real release manifests for managed SDK/gateway/hook upgrades, physical MDM distribution, real-provider population coverage and response automation |
| Policy governance | Partial | Typed editor, immutable version ledger, readable active-versus-pending authority, independent review with rationale, semantic authority diff, bounded redacted historical simulation, restrictive composition, reviewed exact-commit GitHub import, immutable provenance UI, draft-only writes, KMS-signed canonical export, unattended repository- and permission-scoped GitHub App token minting, signed bundles, temporary agent exceptions, canary/scheduling, evidence-only convergence and known-good rollback | Complete live Git-provider acceptance and physical-endpoint rollout-SLO acceptance |
| Security operations | Partial | Approvals, audit timeline, independent scoped emergency stops, scheduled server-derived endpoint detections, deduplicated alert lifecycle, audited acknowledgement, durable SNS/SQS delivery, revisioned cases, authoritative endpoint-to-agent binding, evidence-preserving agent quarantine, independently approved versioned endpoint-response rules with preview, action limits, cooldown, idempotent evidence, disable and rollback, session revocation, recovery-gated release and integrity-verifiable content-minimised case export | Broader tool/MCP/repository/configuration anomaly rules, credential-broker response, maintenance windows, baselines, MDM/EDR isolation and external workflow integrations |
| Reporting and administration | Partial | Fleet posture, health, SLO and compliance summaries; fail-closed population coverage; content-hashed export; purpose-specific executive and evidence-reader assurance reports with explicit blind spots, non-guarantees and content-addressed traceability; scoped expiring service identities with one-time credentials, exact machine-route capabilities, rotation, revocation and usage evidence; versioned Terraform provider for tenant inspection, governed drafts, groups, Skills and MCP servers with import and revision-guarded drift handling; tenant-managed signed webhooks with one-time HMAC keys, dual-key rotation, durable outbox/DLQ delivery, replay-verification helper and secret-free posture | Customer-validated framework mappings and signed/scheduled report distribution, real-workload machine-API and Terraform acceptance, provider Registry release/signing, live customer webhook interruption/replay acceptance, CMK/residency and private access |

### P1-ADM-08 implementation evidence

The hosted control plane now separates human Cognito/Entra access from a
versioned `/machine/v1` bearer boundary. A platform administrator can create a
tenant-owned service identity with one or more of six exact capabilities and a
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
