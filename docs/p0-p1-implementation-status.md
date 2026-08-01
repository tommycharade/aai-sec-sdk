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
| P0-04 | Complete agent discovery | Partial | Source-scoped revocable connector credentials; redacted operator source directory; UI-first registration, one-time secret handling, rotation/revocation and separate credential/evidence posture; immutable paginated generations with atomic commit and 2,000-record bound; legacy revision-bound snapshots; fail-closed complete-source denominator; unmanaged, duplicate, leaver and orphan reconciliation; redacted hash-bound export; Entra/endpoint/GitHub reference collectors; AWS-managed Entra, Intune and GitHub scheduling with KMS/Secrets Manager isolation, fixed provider endpoints, bounded collection, typed digest-bound mappings, fixed failure codes and live lifecycle acceptance; separate administrator-run endpoint sensor with exact binary/process measurement, path-free per-device HMAC reports and authoritative MDM fleet assembly; Intune managed-device evidence alone cannot satisfy the endpoint installation requirement; adversarial contracts for forged credentials, replay, partial pages, altered hashes, malformed input, unsafe files, stale/revoked/cross-device endpoint reports, incompleteness and expiry | Package and deploy the sensor through a real customer MDM, expose per-device report freshness in the UI, move very large pages to dedicated object storage, complete successful real Entra, Intune and GitHub collections, independently prove provider/device credential scope, and prove at least 95% real pilot discovery coverage |
| P0-05 | Runtime attestation | Partial | Typed Claude/Codex measurement, release-bound clean-checkout manifest generator, exact manifest/provenance validation, nonce-bound heartbeat, baseline drift detection, quarantine/session revocation, fleet/group posture UI and adversarial contracts | Publish and pin the next independently verified release manifests, then complete live modified-package/hook/config/process and hardware-backed identity acceptance |
| P0-06 | Entra SSO, SCIM and granular RBAC | Partial | Tenant-specific Entra OIDC; tenant-bound SCIM lifecycle and canonical-role mapping; five-minute token reconciliation; expiring organization/project/deployment role delegation with live revocation and scoped reads; cross-organization group authority-edge denial; recent-MFA, four-eyes, maximum-60-minute break glass; schema-v2 digest-bound access export; adversarial contracts, deployed synthetic scope acceptance and Identity & Trust UI | Configure the pilot tenant; prove real OIDC and SCIM joiner/mover/leaver; run deployed two-person MFA, delegated multi-business-unit and certification exercises |
| P0-07 | SIEM/SOAR | Stub | Splunk status contract and honest UI state with `deliveryVerified: false` | HEC delivery, authentication, schema, retry, dead letter, monitoring and replay |
| P0-08 | Durable evidence | Partial | S3 Object Lock, retention and cross-region pilot evidence | Tenant retention, legal hold, complete export and evidence-loss recovery SLO |
| P0-09 | Production credential broker | Partial | Typed broker contracts and AWS scoped STS reference | Real AWS/Azure/GCP production role inventory and revocation evidence |
| P0-10 | Production isolation | Partial | Typed attestation contract and Docker probe | Supported production sandbox adapter and independent hostile-code assessment |
| P0-11 | HA/DR | Partial | Durable AWS stores, audit replication and recovery checks | Approved RTO/RPO, regional control-plane recovery and rehearsed runbooks |
| P0-12 | Assurance package | Partial | Apache-2.0 project, SBOM/release provenance and security policy | Independent penetration test, vulnerability SLA and customer legal/compliance pack |

No P0 row is complete for enterprise-wide rollout yet.

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

## P1 ledger

| Workstream | Status | Implemented foundation | Major remaining work |
| --- | --- | --- | --- |
| Fleet lifecycle | Partial | Enrollment, groups, revision-bound bulk assignment, trusted dynamic-group preview/apply and deterministic reevaluation, health, rollouts, rollback, drift, emergency stop, irreversible revoke, atomic replacement, evidence-retaining offboarding, accountable ownership, source-reconciled orphan/leaver detection, AWS-managed Entra/Intune/GitHub discovery connectors, and signed endpoint installation/process collection | Bulk enrollment import, scheduled dynamic reevaluation, managed upgrades, exception expiry, MDM sensor packaging/rollout, per-device evidence health, real-provider population coverage and response automation |
| Policy governance | Partial | Typed editor, immutable version ledger, readable active-versus-pending authority, independent review with rationale, self-approval denial, staging, atomic activation, assignment impact and rollback | Historical simulation, richer semantic diff, signed bundles, scheduling, inheritance, expiring exceptions and measured endpoint convergence |
| Security operations | Partial | Alerts, approvals, audit timeline and emergency stops | Cases, quarantine, automatic containment, credential revocation, detections, anomaly controls and workflow integrations |
| Reporting and administration | Partial | Fleet posture, health, SLO and compliance summaries plus fail-closed population coverage and content-hashed export | Executive/auditor report packs, connector service identities, Terraform, CMK/residency and private access |

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
preview-before-apply and exact request-ID reuse. Scheduled service-driven
reevaluation and endpoint posture attributes remain outstanding and are not
claimed.

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
   preserving honest degraded and not-configured states. Splunk remains a
   non-delivering stub.
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
