# Enterprise rollout P0 and P1 requirements

| Field | Value |
| --- | --- |
| Status | Proposed |
| Scope | Enterprise-wide management of Claude Code and Codex CLI |
| Audience | Product, architecture, engineering, QA, security operations, compliance |
| Decision owner | Product owner and enterprise security owner |
| Last updated | 2026-07-29 |

This document converts the CISO product review into implementable and
testable requirements. It is the release gate for describing the product as
an enterprise-wide control for Claude Code and Codex CLI.

## Priority definitions

- **P0 — enterprise rollout blocker:** must be implemented and evidenced before
  an enterprise-wide production purchase or mandatory rollout. A limited,
  low-risk pilot may proceed only under the restrictions in
  [enterprise operations readiness](enterprise-operations-readiness.md).
- **P1 — enterprise scale requirement:** needed to operate the product safely
  and efficiently at scale after the P0 foundations exist. A P1 may become a
  P0 for a particular customer because of regulation, fleet size or operating
  model.

## Current baseline

The requirements below build on capabilities already present in the reference
implementation:

- a Cognito-authenticated, tenant-scoped AWS control plane and web UI;
- typed policies, groups, agent enrollment and effective-policy retrieval;
- authenticated heartbeats, fleet health, staged rollouts, drift reporting and
  emergency stops;
- exact-action, expiring, single-use approvals and redaction-safe audit events;
- local Claude Code and Codex hook/MCP onboarding and synthetic acceptance
  evidence;
- fail-closed SDK controls for policy, budgets, credentials, isolation,
  idempotency and telemetry adapters.

This baseline proves a controlled pilot. It does **not** prove that every
enterprise agent installation is discovered, tamper-resistant or governed by
an independently verified production enforcement boundary.

## P0 enterprise rollout blockers

### P0-01 — Enterprise-enforced Claude Code configuration

**Risk.** Project-owned `.claude` files can be changed or removed by a user or
process with repository access. They are useful for onboarding and pilots but
are not an immutable enterprise control.

**Required outcome.** Distribute and enforce the approved hook, MCP gateway,
launch settings and policy routing through Claude server-managed settings,
device management, or another enterprise-owned configuration channel. The
control plane must distinguish centrally managed configuration from local
project configuration and report the effective source.

**Acceptance evidence.**

- A real managed Claude Code device receives the configuration without a
  repository commit.
- Local deletion or weakening is rejected, restored or reported as non-compliant
  within five minutes.
- Tests prove that project files and launch flags cannot bypass the managed
  hook and gateway.
- The UI shows configuration source, version, hash and last verification time.

**Owner/dependencies.** Endpoint engineering; Claude enterprise administration;
runtime integration team.

### P0-02 — Codex managed-requirements integration

**Risk.** A user can start an unmanaged Codex process or alter project-local
configuration, bypassing policy enforced only by onboarding files.

**Required outcome.** Generate and distribute enterprise-managed Codex
requirements, managed hooks and approved launch profiles. Where supported,
cloud-managed or device-managed `requirements.toml` must constrain sandbox,
network, MCP, identity and command-rule configuration.

**Acceptance evidence.**

- A real managed Codex installation receives the required configuration.
- An unmanaged launch, conflicting local configuration and weakening command-line
  flag are denied or reported as non-compliant.
- The UI shows the effective managed requirements and their provenance.
- Contract and adversarial tests cover upgrades and malformed requirements.

**Owner/dependencies.** Endpoint engineering; Codex administration; runtime
integration team.

### P0-03 — Native-control reconciliation

**Risk.** The AAI policy alone does not express every host-native control. An
operator could believe an action is denied while a weaker Claude or Codex
setting remains effective, or vice versa.

**Required outcome.** Reconcile the AAI policy with Claude managed permissions
and Codex sandbox, network, identity, rule and requirement settings. Present a
single effective-authority view without treating the UI as the enforcement
boundary. Conflicts must fail closed or require an explicit, audited resolution.

**Acceptance evidence.**

- A deterministic reconciliation engine produces allowed, denied and
  approval-required actions with provenance for each contributing control.
- Conflict, missing-source and stale-source tests fail closed.
- The policy and agent views show the combined effective authority and explain
  each conflict.
- Live Claude and Codex tests prove the displayed result matches execution.

**Owner/dependencies.** Security architecture; policy team; P0-01 and P0-02.

### P0-04 — Complete agent discovery

**Risk.** Enrollment inventory shows known agents, not every authorized or
running Claude/Codex instance. Shadow installations can remain outside policy
and monitoring.

**Required outcome.** Reconcile authorized users, managed devices, repositories,
installed binaries, active processes and enrolled agents. Flag unmanaged,
duplicate, stale and orphaned instances with a clear coverage denominator.

**Acceptance evidence.**

- Discovery covers at least 95% of the agreed pilot population and documents
  the remaining blind spots.
- Known unmanaged and duplicate test installations appear in the UI within the
  discovery SLO.
- Reconciliation is tenant-scoped, privacy-reviewed and tested for stale data.
- Coverage reports can be exported by business unit, repository and device.

**Owner/dependencies.** Endpoint platform; identity; source-control platform;
security operations.

### P0-05 — Runtime attestation and tamper detection

**Risk.** A heartbeat proves that something possessing a credential called the
control plane; it does not prove the approved binary, hook, configuration or
gateway is running untampered.

**Required outcome.** Verify signed package identity, executable provenance,
hook/configuration hashes, SDK version and expected process/launch context.
Continuously calculate posture and revoke or quarantine an agent that cannot
prove the required state.

**Acceptance evidence.**

- Signed release and provenance verification are bound to enrollment and
  heartbeat evidence.
- Modified binary, hook, configuration and process identity tests become
  non-compliant within five minutes.
- Attestation freshness and reason codes are visible and auditable.
- A failed or expired attestation cannot receive effective policy or execute a
  consequential governed action.

**Owner/dependencies.** Supply-chain security; endpoint engineering; agent
runtime team.

### P0-06 — Enterprise SSO, SCIM and granular RBAC

**Risk.** Basic authentication and broad operator groups do not provide the
identity lifecycle, delegation or separation of duties expected in a large
enterprise.

**Required outcome.** Support enterprise SAML/OIDC federation, SCIM lifecycle,
IdP group mapping, least-privilege roles and separation between policy author,
approver, fleet operator, incident responder, auditor and tenant administrator.

**Acceptance evidence.**

- Joiner, mover and leaver tests provision, change and revoke access through
  SCIM within the agreed SLO.
- A role-permission matrix is enforced by API and UI, including cross-tenant
  denial and four-eyes restrictions.
- Break-glass access is time-bound, strongly authenticated and independently
  audited.
- Quarterly access-certification evidence can be exported.

**Owner/dependencies.** Identity platform; control-plane team; compliance.

### P0-07 — SIEM and SOAR integration

**Risk.** Product-local alerts and evidence do not enter the enterprise's
monitored incident workflow; delivery failure may go unnoticed.

**Required outcome.** Export normalized, redacted events to supported SIEM/SOAR
destinations such as Splunk, Microsoft Sentinel or Google Chronicle. Provide
signed webhooks, bounded retries, dead-letter handling, delivery health and
replay.

**Acceptance evidence.**

- Synthetic allow, deny, approval, tamper, drift and emergency-stop events are
  searchable in the customer's destination with tenant and agent correlation.
- Delivery interruption raises an alert, retains events and successfully
  replays them without duplication.
- Schema versioning, redaction and destination authentication have contract
  and adversarial tests.
- A SOC runbook assigns alert ownership and response SLOs.

**Sequencing note.** SIEM implementation is parked for the current product
iteration by product decision. It remains a P0 exit criterion for an
enterprise-wide rollout and must not be represented as complete.

**Owner/dependencies.** Security operations; telemetry team; customer SIEM
platform.

### P0-08 — Durable evidence guarantees

**Risk.** In-process or ordinarily mutable evidence cannot support incident,
legal or regulatory investigation when records are lost, altered or retained
for the wrong period.

**Required outcome.** Provide immutable/WORM retention, configurable tenant
retention, legal hold, integrity verification, complete export, evidence-loss
alerts and tested recovery.

**Acceptance evidence.**

- Attempts to overwrite or delete retained evidence fail and generate an
  auditable result.
- Legal hold and tenant retention policies are exercised against synthetic
  records.
- Cross-region recovery proves record count, ordering, hashes and retention.
- Delivery gaps are detected within the monitoring SLO and can be replayed.

**Owner/dependencies.** Cloud platform; records management; compliance.

### P0-09 — Production credential broker

**Risk.** A configured credential requirement is not proof that a real tool
received only the identity and permissions intended for one approved action.

**Required outcome.** Integrate supported AWS, Azure and GCP workload-identity
or secret-broker paths. Credentials must be short-lived, principal/resource
scoped, issued only after authorization, revocable and absent from model output,
project files and normal telemetry.

**Acceptance evidence.**

- Real provider tests prove allowed access and deny sibling tenant, agent,
  resource and expired-session access.
- Credential issuance, use, expiry and revocation are correlated without
  recording the credential value.
- Denial, broker outage and partial issuance cause no tool side effect.
- Incident response can revoke active authority within its SLO.

**Owner/dependencies.** Cloud IAM; credential platform; runtime team.

### P0-10 — Production isolation integration

**Risk.** Declaring an isolation requirement does not prove that untrusted code
ran inside the expected boundary or that the boundary resisted escape.

**Required outcome.** Support attested container, microVM, endpoint sandbox or
equivalent adapters with explicit filesystem, network, process, resource and
credential constraints. Match isolation strength to workload risk.

**Acceptance evidence.**

- A live adapter verifies the boundary before execution and records its
  immutable identity and configuration.
- Escape, forbidden network, filesystem, process and resource-exhaustion tests
  are denied or contained.
- Missing, stale or weaker-than-policy isolation fails closed.
- Independent assessment covers the production boundary and its host
  assumptions.

**Owner/dependencies.** Platform security; endpoint/container platform;
runtime team.

### P0-11 — High availability and disaster recovery

**Risk.** A control-plane outage can either stop all engineering work or tempt
operators to bypass controls. Evidence and approvals may be lost or become
inconsistent during failure.

**Required outcome.** Define and meet RTO/RPO, use multi-region operation or a
proven regional recovery design, test backups, and document fail-closed outage
and controlled recovery runbooks.

**Acceptance evidence.**

- Load, dependency-failure and regional-recovery tests meet approved SLOs and
  target fleet size.
- Policy, identity, approval, idempotency and audit consistency survive
  failover without authority widening or replay.
- Backup restoration and key recovery are tested on a schedule.
- Operators rehearse fail-closed outage, emergency access and return-to-service
  procedures.

**Owner/dependencies.** SRE; cloud platform; security architecture.

### P0-12 — Security assurance and enterprise trust package

**Risk.** Buyers cannot approve a critical security control without independent
assurance, vulnerability-management commitments and contractual data handling
evidence.

**Required outcome.** Provide an independent penetration test, remediation
evidence, SBOM and signed provenance, vulnerability disclosure and SLA,
security architecture/threat model, DPA/subprocessor information and a credible
SOC 2 Type II and ISO 27001 roadmap.

**Acceptance evidence.**

- No unresolved critical or high finding remains from an independent test.
- Every release publishes verifiable provenance, checksums and an SBOM.
- Vulnerability intake, severity, notification and remediation SLAs are tested.
- The customer assurance pack has an owner, review date and approved statements
  of guarantees and non-guarantees.

**Owner/dependencies.** Security assurance; legal/privacy; release engineering.

## P1 enterprise scale requirements

### Fleet lifecycle

| ID | Requirement | Required outcome and acceptance evidence |
| --- | --- | --- |
| P1-FLT-01 | Bulk enrollment and assignment | Import or select many agents and assign them to a group/policy with preview, bounded batches, progress, partial-failure handling and an audit record. |
| P1-FLT-02 | Dynamic groups | Build groups from trusted attributes such as business unit, repository, device posture and risk; preview membership and test deterministic reevaluation. |
| P1-FLT-03 | Full agent lifecycle | Replace, revoke and delete agents while retaining required evidence; prevent a revoked identity from reusing its prior session. |
| P1-FLT-04 | Ownership metadata | Require accountable owner, team, business contact, environment and criticality; report missing or stale ownership. |
| P1-FLT-05 | Expiring enrollment | Enrollment links/secrets are single-use, scoped and time-bound; expiry and replay fail closed. |
| P1-FLT-06 | Managed upgrades | Roll out pinned SDK, gateway and hook versions by channel/ring with compatibility checks and automatic pause. |
| P1-FLT-07 | Drift remediation | Preview and automatically remediate approved drift classes; dangerous or ambiguous changes require approval. |
| P1-FLT-08 | Maintenance windows and rings | Schedule rollout windows and canary rings by time zone and business criticality with tested pause/rollback. |
| P1-FLT-09 | Exception expiry | Every temporary exception has owner, justification and expiry; expiry automatically restores the prior secure state. |
| P1-FLT-10 | Orphan/offboarding handling | Detect archived repositories, departed employees and ownerless agents; revoke sessions and authority within the offboarding SLO. |

### Policy governance

| ID | Requirement | Required outcome and acceptance evidence |
| --- | --- | --- |
| P1-POL-01 | Governed lifecycle | Enforce draft, review, approval, staging and activation states; activated versions are immutable. |
| P1-POL-02 | Four-eyes approval | Prevent an author from solely approving a protected policy or exception; enforce in both API and UI. |
| P1-POL-03 | Historical simulation | Evaluate a draft against redacted historical actions without executing them and report predicted changes. |
| P1-POL-04 | Semantic change view | Show newly allowed, denied and approval-required actions plus changed limits, credentials, isolation and capture behavior. |
| P1-POL-05 | Canary and scheduling | Activate by selected agents or percentage, schedule expansion and automatically pause on health/security thresholds. |
| P1-POL-06 | Deterministic rollback | Restore the prior known-good version and prove affected agents converge within the rollout SLO. |
| P1-POL-07 | Policy as code | Import/export schema-validated policy through Git with review status, signatures and control-plane provenance. |
| P1-POL-08 | Signed bundles | Sign policy artifacts and reject altered, unsigned or untrusted versions at the runtime boundary. |
| P1-POL-09 | Reuse and inheritance | Support versioned policy components with deterministic composition and an understandable effective-policy explanation. |
| P1-POL-10 | Time-limited exceptions | Scope exceptions to owner, purpose, agent/resource and expiry; include review and automatic reversion. |
| P1-POL-11 | Native-control conflicts | Detect and explain conflicts between AAI policy and Claude/Codex controls before activation. |

### Security operations

| ID | Requirement | Required outcome and acceptance evidence |
| --- | --- | --- |
| P1-SOC-01 | Incident cases | Create a case from an alert with agents, policies, actions, approvals, evidence, owner, status and timeline. |
| P1-SOC-02 | Automatic containment | Permit approved detection rules to stop or restrict a bounded scope with safeguards, evidence and rollback. |
| P1-SOC-03 | Quarantine | Separate investigative quarantine from emergency stop and policy denial; display the exact resulting authority. |
| P1-SOC-04 | Credential revocation | Revoke relevant active sessions and brokered authority from an incident without requiring a policy edit. |
| P1-SOC-05 | Investigation timeline | Correlate identity, policy, tool, MCP, approval, credential, isolation, evidence and operator events in one ordered view. |
| P1-SOC-06 | Detection rules | Detect unusual tool, MCP server, repository, approval, configuration and execution behavior with versioned rules. |
| P1-SOC-07 | Baseline and anomaly signals | Establish explainable baselines with tunable sensitivity and no autonomous authority widening. |
| P1-SOC-08 | Suppression and deduplication | Group repeated alerts by stable identity/action facts; every suppression is scoped, expiring and auditable. |
| P1-SOC-09 | Workflow integrations | Integrate with ServiceNow, Jira and PagerDuty using scoped credentials, idempotency and monitored delivery. |
| P1-SOC-10 | Audit-ready case export | Export a complete, integrity-verifiable case without raw credentials or unapproved sensitive content. |

### Reporting and administration

| ID | Requirement | Required outcome and acceptance evidence |
| --- | --- | --- |
| P1-ADM-01 | Coverage reporting | Report discovered, enrolled, healthy, compliant and unmanaged coverage by business unit, repository, environment and risk. |
| P1-ADM-02 | Version compliance | Report the percentage on approved SDK/hook/gateway versions and identify blocked or stale upgrades. |
| P1-ADM-03 | Exception and effectiveness reports | Report active/expiring exceptions, approval volume/latency, most-denied actions, stale agents, drift and mean time to detect/contain. |
| P1-ADM-04 | Evidence delivery reporting | Show retention, delivery latency, loss, dead-letter and replay status for every configured sink. |
| P1-ADM-05 | Executive and auditor views | Provide purpose-specific summaries with traceability to immutable detailed evidence and no misleading compliance claim. |
| P1-ADM-06 | Delegated administration | Support custom roles and administrative scopes bounded by tenant, business unit, project and environment. |
| P1-ADM-07 | Access governance | Provide IdP group mapping, break-glass workflow and periodic access certification. |
| P1-ADM-08 | Machine access | Issue scoped, expiring service identities/API credentials with rotation, revocation and usage evidence. |
| P1-ADM-09 | Automation surface | Provide a versioned management API and Terraform provider for repeatable tenant, group, policy and integration configuration. |
| P1-ADM-10 | Secure webhooks | Sign webhooks, rotate keys without interruption and protect against replay. |
| P1-ADM-11 | Enterprise data controls | Support customer-managed keys, approved data residency, documented deletion and tenant-isolation tests. |
| P1-ADM-12 | Private access | Support PrivateLink or equivalent private connectivity, IP restrictions and conditional-access integration where required. |

## Delivery sequence

1. **Wave 1 — authority and coverage:** P0-01 through P0-06 establish managed
   enforcement, effective authority, discovery, attestation and operator
   identity.
2. **Wave 2 — operational control:** P0-07 through P0-10 establish enterprise
   event delivery, durable evidence, scoped credentials and verified isolation.
3. **Wave 3 — resilience and assurance:** P0-11 and P0-12 prove recovery and
   provide independent assurance.
4. **Scale-out:** deliver P1 fleet and policy capabilities first, followed by
   security-operations workflows and advanced administration/reporting.

Dependencies do not permit a later wave to weaken an earlier control. Work may
run in parallel when its acceptance evidence remains independently testable.

## Enterprise rollout acceptance gate

Before enterprise-wide approval, retained evidence must prove all of the
following in the target environment:

1. At least 95% of target Claude Code and Codex installations are discovered.
2. Every enrolled agent resolves to one unambiguous effective policy.
3. Unmanaged or tampered agents are detected within five minutes.
4. Project files and launch flags cannot bypass enterprise-managed controls.
5. A fleet-wide emergency stop reaches healthy agents within the approved SLO.
6. A canary policy rollout and deterministic rollback complete successfully.
7. Approval replay, expiry, identity mismatch and argument mutation are blocked.
8. SIEM delivery failure is detected and retained events are replayed without
   duplication.
9. Credential scope and isolation posture are verified at execution time, not
   merely present in configuration.
10. Offboarding revokes sessions and authority within the approved SLO.
11. Load and disaster-recovery tests meet the target fleet size, RTO and RPO.
12. An independent penetration test has no unresolved critical or high finding.

An unmet gate must be shown as an explicit exception with owner, affected scope,
compensating controls and expiry. It cannot be hidden by a healthy heartbeat or
a successful local synthetic test.

## Definition of done for each requirement

A requirement is complete only when all applicable evidence exists:

- implementation at the real authority or deployment boundary;
- deterministic positive, negative, bypass and failure-mode tests;
- a live Claude Code and/or Codex acceptance test where the control applies;
- tenant-isolation, authentication and authorization tests for control-plane
  behavior;
- threat-model, public documentation, operator runbook and rollback update;
- redaction-safe telemetry and immutable audit evidence;
- performance, recovery and delivery SLO evidence where relevant;
- `make check` and the authenticated AWS acceptance suite passing; and
- named product, engineering, QA and security acceptance owners.

Configuration fields or UI controls alone do not satisfy this definition.

## Immutable security principles

- The model never supplies or overrides identity, policy, credentials,
  approvals or attestation.
- Unknown tools, malformed configuration, missing authority, conflicting policy
  and stale security state fail closed.
- Every consequential action is authorized with its live arguments, resource,
  principal, purpose and current policy.
- The UI cannot disable immutable SDK safeguards such as approval binding,
  replay protection, tenant isolation or pre-export redaction.
- Host-native Claude and Codex controls remain visible contributors to effective
  authority; they are never assumed equivalent to SDK runtime enforcement.

## Product decision

The product may be presented as suitable for a controlled, low-risk enterprise
pilot when the pilot acceptance plan is met. It must not be marketed or approved
as a comprehensive enterprise-wide management and enforcement control until all
P0 requirements and the enterprise rollout acceptance gate have retained,
reviewed evidence.
