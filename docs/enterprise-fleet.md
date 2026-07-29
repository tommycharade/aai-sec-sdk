# Enterprise fleet control plane

The enterprise fleet layer manages many independently deployed SDK control
planes and many Claude Code projects without moving execution authority into
the browser. It is a provider-neutral inventory and governance boundary:
authentication, runtime authority, policy engines, approval services, IAM,
and durable audit retention remain deployment-owned adapters.

## Scope model

Every resource belongs to one organization:

```text
organization
└── project
    └── deployment (team / environment / region)
        └── Claude Code agents and sessions
```

An authenticated identity carries an organization and optional project scope.
The API checks that scope on every read, registration, configuration, and
rollout operation. The UI never receives bearer tokens, agent heartbeat
sessions, credentials, or raw secrets.

Deployments carry team, environment, and region dimensions so operators can
filter and compare the same SDK policy across platform groups and geographic
rollouts. The team field is inventory metadata, not an authorization grant;
authorization remains organization/project/RBAC based.

For enterprise IAM, provide a `CallbackFleetAuthenticator` backed by the
organization's OIDC/JWT or service-mesh verifier. The callback must validate
signature, issuer, audience, expiry, and claims before returning a normalized
`FleetIdentity`; the SDK does not guess those rules or accept roles from the
browser. Authorization is a separate callback and fails closed on exceptions.

Credential governance uses `FleetSecretReference` and
`CallbackFleetSecretResolver`. Templates may contain broker endpoint and
opaque reference metadata, but never credential material. A deployment-owned
secret manager resolves a reference only for a bounded purpose; resolution
failures are errors rather than empty or synthetic credentials.

## Inventory API

The reference WSGI application exposes these authenticated endpoints:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/enterprise/organizations` | Tenant inventory |
| `GET /api/enterprise/projects` | Project inventory |
| `GET /api/enterprise/deployments` | SDK deployment inventory |
| `GET /api/enterprise/agents` | Claude and other agent presence |
| `GET /api/enterprise/agents/{deployment}/{agent}/effective-policy` | Authenticated policy resolved from the agent's group assignment |
| `GET /api/enterprise/agents/{deployment}/{agent}/verify` | Redacted enrollment-readiness checks for operations |
| `GET /api/enterprise/sessions` | Active/expired session inventory without session tokens |
| `GET /api/enterprise/capabilities` | Persistence adapter and HA capability metadata |
| `GET /api/enterprise/drift` | Desired/applied configuration drift |
| `GET /api/enterprise/templates` | Tenant-scoped configuration templates |
| `GET /api/enterprise/policies` | Tenant-scoped configuration policies |
| `GET /api/enterprise/groups` | Agent groups with selected policy and enrolled agents |
| `GET /api/enterprise/deployment-config` | Current desired/applied configuration state |
| `GET /api/enterprise/deployment-config/history` | Bounded prior configuration versions |
| `GET /api/enterprise/health` | Deployment health and rollout indicators |
| `GET /api/enterprise/slo` | Sample-based availability and SLO status in the bounded window |
| `GET /api/enterprise/compliance/evidence` | Redacted tenant-scoped evidence bundle for review/export |
| `GET /api/enterprise/audit` | Bounded redaction-safe lifecycle evidence index for investigations |
| `GET /api/enterprise/approvals` | Tenant-scoped pending and historical exact-action approval requests |
| `GET /api/enterprise/alerts` | Derived fleet alerts |
| `POST /api/enterprise/projects` | Create a tenant-scoped project under an existing organization |
| `POST /api/enterprise/deployments` | Create a deployment whose ownership is derived from its existing project |
| `POST /api/enterprise/agents/register` | Register an authenticated agent |
| `POST /api/enterprise/agents/{deployment}/{agent}/revoke` | Irreversibly revoke one identity using its expected lifecycle revision |
| `POST /api/enterprise/agents/{deployment}/{agent}/replace` | Atomically revoke a predecessor, create a new offline successor and inherit group assignment |
| `POST /api/enterprise/agents/{deployment}/{agent}/offboard` | Remove operational data from a revoked identity while retaining a lifecycle tombstone |
| `PUT /api/enterprise/agents/{deployment}/{agent}/ownership` | Review accountable ownership using its expected ownership revision |
| `POST /api/enterprise/agents/{deployment}/{agent}/heartbeat` | Refresh presence and optionally publish bounded aggregate SDK telemetry plus managed-host evidence |
| `POST /api/enterprise/agents/{deployment}/{agent}/disconnect` | Mark offline |
| `POST /api/agent/{deployment}/{agent}/decisions` | Record one authenticated, content-minimised host decision as operational evidence |
| `POST /api/agent/{deployment}/{agent}/approvals/request` | Submit a bounded approval request using the authenticated agent session |
| `POST /api/agent/{deployment}/{agent}/approvals/consume` | Atomically consume one approved exact-action grant |
| `POST /api/enterprise/templates` | Create a configuration template |
| `POST /api/enterprise/policies` | Create an inactive policy and version-one draft |
| `POST /api/enterprise/policies/{policy}/versions` | Create the next draft without changing active authority |
| `GET /api/enterprise/policies/{policy}/versions` | List the immutable policy version ledger and review metadata |
| `GET /api/enterprise/policies/{policy}/versions/{version}` | Read one exact immutable policy version |
| `POST /api/enterprise/policies/{policy}/versions/{version}/submit` | Freeze a draft and submit it for independent review |
| `POST /api/enterprise/policies/{policy}/versions/{version}/decision` | Approve or reject with a rationale; authors cannot self-approve |
| `POST /api/enterprise/policies/{policy}/versions/{version}/stage` | Stage an independently approved version against its active base |
| `POST /api/enterprise/policies/{policy}/versions/{version}/activate` | Atomically activate using `expectedActiveVersion` |
| `POST /api/enterprise/groups` | Create a group and bind it to a policy |
| `POST /api/enterprise/groups/{group}/policy` | Change a group's immutable policy assignment and audit the change |
| `POST /api/enterprise/groups/{group}/agents` | Enroll an existing agent in a group |
| `POST /api/enterprise/groups/{group}/agents/bulk` | Preview or apply one revision-bound batch of up to 100 assignments |
| `POST /api/enterprise/groups/{group}/dynamic-membership` | Preview or apply a deterministic rule over trusted inventory |
| `DELETE /api/enterprise/groups/{group}/agents/{deployment}/{agent}` | Remove an agent from a group |
| `POST /api/enterprise/templates/validate` | Validate safe configuration without persisting it |
| `POST /api/enterprise/deployment-config` | Assign desired configuration |
| `POST /api/enterprise/deployment-config/rollout` | Stage, canary, pause, activate, or rollback |
| `POST /api/enterprise/deployment-config/batch-rollout` | Apply one rollout command to up to 200 deployments |
| `POST /api/enterprise/deployment-config/rollback` | Restore a known prior version as a new staged version |
| `POST /api/enterprise/deployment-config/applied` | Record an applied configuration hash |
| `POST /api/emergency-stop` | Activate or clear the durable tenant-wide stop used by every enrolled agent |
| `POST /api/enterprise/emergency-stop` | Stop or clear one deployment through its authority |
| `POST /api/enterprise/groups/{group}/emergency-stop` | Stop or clear all agents in one group |
| `POST /api/enterprise/agents/{deployment}/{agent}/emergency-stop` | Stop or clear one enrolled agent |
| `POST /api/enterprise/alerts/{alertId}/ack` | Acknowledge an alert without deleting evidence |
| `POST /api/enterprise/alerts/dispatch` | Deliver unacknowledged alerts through an alert adapter |
| `POST /api/enterprise/slo/sample` | Record one redaction-safe health sample for an authorized deployment |
| `POST /api/enterprise/approvals` | Create a direct operator grant for compatibility and automation |
| `POST /api/enterprise/approvals/{approvalId}/decision` | Approve or deny one live pending request with an operator rationale |

The tenant-wide emergency stop accepts `{"active": true}` or
`{"active": false}` from a `security-operator` or `platform-admin`. It is
stored independently from deployment, group, and agent stops. Effective-policy
requests fail closed with HTTP 409 while it is active, including requests from
agents enrolled after activation. Clearing the fleet stop does not clear a
narrower stop. Every transition records the operator identity, resulting state,
and affected-agent count in the redacted audit trail.

Agent verification returns `host`, the exact sole `group`, and the consistently
read `policyId`/`policyVersion` alongside liveness and stop checks. Missing or
conflicting policy state returns null policy identity and cannot verify. A UI
must compare this complete tuple with its selected activation scope.

### Bulk group assignment

Group membership is a policy-authority edge. The bulk endpoint therefore does
not accept a browser-computed result or perform a loop of independent
single-agent writes. It accepts a closed-schema request containing:

- `mode`: `preview` or `apply`;
- a collision-resistant `requestId` reused between preview and apply;
- the exact positive `expectedMembershipRevision` shown by the group;
- one to 100 unique deployment/agent identifiers; and
- an operator reason of at least 20 characters.

Preview strongly reloads the group, every proposed agent, and the bounded group
inventory. It makes no write and returns one typed outcome per agent:
`ready`, `unchanged`, or `rejected`, with fixed reason codes. Missing,
inactive, cross-organization, malformed, or already-assigned agents are never
silently skipped. An active agent already in another group is rejected because
runtime verification requires one unambiguous policy group.

Apply repeats the live evaluation. A changed membership revision returns HTTP
409 and commits nothing. Eligible agents are committed together with a new
membership revision, an actor- and request-bound idempotency result, and one
content-minimised immutable DynamoDB audit summary. A batch containing both
eligible and rejected agents returns HTTP 207: eligible assignments commit;
rejected agents remain unchanged and retain explicit outcomes. Replaying the
same request ID and exact semantic request returns the stored result without a
second authority or audit change; reuse with different content is rejected.
S3 receives a best-effort secondary copy after the primary transaction.

### Dynamic group membership

Dynamic groups materialize a bounded rule over strongly read, server-owned
agent and deployment attributes. The operator uses a typed editor, supplies an
auditable reason and previews additions, removals, unchanged agents and policy
group overlaps before apply. Overlap, stale revision, malformed lineage,
unsupported fields and transaction races fail closed without a partial update.

After apply, the group stores its canonical rule, rule hash, evaluation actor
and time. Manual single-agent and bulk membership routes reject changes to a
dynamic group; future changes use another preview and rule reevaluation. See
[Dynamic policy groups](dynamic-groups-design.md) for the complete contract and
security invariants.

The UI follows a three-step **Select → Preview → Apply** journey. It lists only
currently active, unassigned agents from the browser snapshot, requires a
rationale, displays server-authoritative counts and per-agent outcomes, and
shows the resulting revision as the completion receipt. The server remains
authoritative when browser inventory becomes stale.

### Agent identity lifecycle

Presence and identity lifecycle are deliberately separate. `connected` and
`offline` are reversible presence states. `active → revoked → deleted` is a
server-owned, forward-only authority transition. Legacy records are migrated
once to explicit lifecycle revision 1 using a conditional update; malformed or
partially migrated lifecycle state fails closed.

Revoke, replace and offboard requests require an exact
`expectedLifecycleRevision` and an operator reason of at least 20 characters.
The hosted adapter uses one DynamoDB transaction to compare-and-swap the agent
record and create immutable `AGENT_LIFECYCLE_AUDIT` evidence. Replacement also
creates a distinct successor and updates every inherited group membership in
that transaction. A changed lifecycle revision, occupied successor ID, changed
group membership or oversized replacement fan-out rolls back the entire
operation.

Revocation does not enumerate bearer records. Instead, every agent route and
bootstrap exchange strongly reads the live agent record and requires
`lifecycle_state=active`. This immediately denies old sessions and unused
bootstrap tokens even if their TTL has not expired. Heartbeat writes and
operator emergency-stop changes compare the same lifecycle revision so a
concurrent stale write cannot reactivate or overwrite revocation.

Replacement keeps the predecessor in its historical groups and adds the new
offline identity to the same groups. The predecessor cannot exercise policy
authority because its lifecycle is revoked; retaining the relationship makes
assignment evidence reviewable. The successor must receive and consume fresh
enrollment material. Offboarding is permitted only after revocation and stores
a tombstone: tenant lineage, host, lifecycle actors/reasons, timestamps,
replacement relationship and a project-root digest remain, while the local
path, telemetry and managed-host observations are removed. Agent IDs are never
reusable.

### Accountable agent ownership

New agent registration requires an `ownership` object containing a stable
`ownerId`, human-readable `ownerName`, monitored `businessContact` mailbox and
one of `low`, `medium`, `high` or `critical`. The API does not accept team or
environment from that object: it copies both from the existing tenant-owned
deployment so a browser cannot rewrite business lineage. When Microsoft Entra
SCIM is configured for the tenant, `ownerId` must be an active provisioned
Entra object UUID.

Ownership reviews are valid for 90 days. The server returns `current`, `stale`
or `missing` plus review timestamps and reason codes; it never accepts the
status from a client. Missing, malformed or expired ownership prevents the
agent verification endpoint from returning `verified=true`. Legacy identities
remain visible as missing until a fleet operator completes a review.

`PUT /enterprise/agents/{deployment}/{agent}/ownership` requires the exact
`expectedOwnershipRevision`, a complete replacement ownership object and a
reason of at least 20 characters. Revision zero is valid only for an agent that
has never had ownership metadata. The control plane compares lifecycle and
ownership state in one DynamoDB transaction and writes immutable, content-
minimised evidence in that same transaction. The S3 audit copy is secondary.
Replacement identities inherit the predecessor's current ownership review;
offboarding retains owner ID, team, criticality, review timing and a hash of the
business contact while removing the contact value and local project path.

### Central action approvals

An enrolled agent submits a held action through its deployment/agent-bound
session. The server derives `agentKey` from that session and accepts only the
bounded tool, proposal, task, principal, action hash, risk class, and resource
identifiers needed for review. It does not accept tool arguments, outputs,
credentials, prompts, or a caller-selected agent identity. Descriptive request
metadata remains untrusted evidence; an operator must verify it against the
authenticated agent, policy, task, and intended resource.

Only `security-operator` and `platform-admin` identities may decide a request.
The decision requires a non-empty rationale and uses a conditional state
transition, so two operators cannot both decide the same pending request. A
denial is never consumable. An approval becomes a short-lived grant bound to
the exact tenant, agent, tool, proposal, task, principal, and action hash. It
can be consumed once by that same enrolled agent. Expiry, replay, mismatched
bindings, missing state, or a concurrent decision returns no authority.

The dashboard count is derived from live, unexpired `pending` records. The UI
shows pending work and decision history on a dedicated **Approvals** page;
the audit trail remains read-only evidence. `approval_requested` and
`approval_decided` lifecycle events contain bounded identifiers and hashes,
not action content.

Inventory and fleet collection endpoints accept `limit=1..200` and an opaque
numeric continuation `cursor`; responses contain `nextCursor` until the
collection is exhausted. The UI follows those cursors automatically, so a
tenant with more than one page of deployments or Claude instances is not
silently truncated. Cursors carry no identity or authority and are valid only
as continuation tokens for the same authenticated read.

Agent registration returns one opaque, expiring session. It is accepted only
for the authenticated deployment/agent scope. Session inventory exposes only
agent/deployment scope, timestamps, and active/expired status; the opaque
session token is never returned. Expired heartbeats are marked offline and
lifecycle events are written to the configured audit sink.

An authenticated heartbeat may include a `telemetry` object containing only
bounded numeric aggregates: action totals, admitted cost units, allowed,
denied, approval-required, executed, failed, timed-out and cancelled counts,
plus average and maximum guarded-action latency in milliseconds. Unknown,
negative, non-finite, oversized, or secret-like fields are rejected. The
control plane stores the latest snapshot with the agent metadata and exposes
only that fixed projection to operators; it never stores tool arguments,
resources, outputs, or credentials as telemetry.

The same heartbeat may include `managedConfiguration`. Its closed schema binds
`host`, `hostVersion`, `platform`, `bundleHash`, `policyId`, `policyVersion`,
`source`, `verifiedAt` and `expiresAt`. The server compares those fields with
the deployment template's `managedHost` desired state and derives posture; the
agent cannot report `status`. A missing desired bundle is `not_configured`, a
missing report is `missing`, expired or future-dated evidence is `stale`, and
any identity or digest difference is `conflict`. Only an exact fresh match is
`enforced`.

Agent verification requires `enforced` managed posture. This evidence remains
content-minimised and credential-free. It proves what the approved runtime
reported, not hardware-backed device identity; endpoint ownership, file
permissions and approved launch controls remain deployment responsibilities.

### Host decision evidence

An enrolled Claude hook or SDK runtime may report an observed decision through
`POST /api/agent/{deployment}/{agent}/decisions`. The request accepts exactly
six fields: a SHA-256 event digest, a fixed source, a bounded tool name, one of
`allowed`, `denied`, or `approval_required`, a fixed resource kind, and a fixed
reason code. Prompts, commands, paths, arguments, outputs, principals,
credentials, free-form reasons, and caller-selected policy metadata are
rejected.

The authenticated session binds the report to one deployment and agent. The
server uses a strongly consistent group read and requires exactly one current
group before resolving policy. It derives tenant, deployment, agent, policy
version, and observation time rather than trusting those values from the host.
Identical reports are idempotent; reuse of a digest with different metadata is
rejected. A reverse-chronological DynamoDB index supplies a bounded dashboard
window, and the response marks totals as truncated when older rows exist.
Decision records carry a 30-day TTL (physical deletion follows DynamoDB's
asynchronous TTL process), while the durable audit adapter receives the same
content-free event under its separate retention policy.

This stream is evidence, not authority. An enrolled process can report what it
observed, but its report cannot permit an action, change a policy, approve a
request, or prove that an unobserved side effect did not occur. Operators use
it to verify activation and investigate outcomes; authorization remains at the
host execution boundary.

Policies are immutable, tenant-scoped configuration records in this reference
implementation. A group selects one policy, and membership changes affect only
group assignment; they do not create, rotate, or revoke the agent's session.
Every policy, group, enrollment, and removal is authorized against the live
operator identity and recorded as redacted fleet audit evidence. Runtime
enforcement still occurs in each deployment's SDK authority.

An enrolled runtime can resolve its policy before serving tools through the
effective-policy endpoint. The lookup is scoped to the authenticated agent and
fails closed when no group is assigned or when multiple groups select different
policies. The response is configuration data, not an executable decision; the
deployment adapter must map it to typed SDK policy objects and cannot weaken
immutable SDK safeguards.

## Configuration governance

The UI template editor provides typed controls for deny-by-default policy,
approvals, tool allow-lists, budgets, credentials, high-risk isolation, audit,
and telemetry. It generates reviewable JSON while retaining an advanced editor
for provider-specific fields; backend validation remains authoritative.

Templates can inherit from one parent template. Inheritance is bounded and
cycle-checked; child values override parent values. A deployment assignment
creates a desired configuration hash and starts in `staged` state. Operators
can move it through `canary`, `active`, `paused`, or `rollback` with an
explicit percentage. A deployment is drifted when its applied hash is absent
or differs from the desired hash.

Templates may use typed governance sections: `policy`, `approvals`, `tools`,
`budgets`, `credentials`, `isolation`, `audit`, `telemetry`, `runtime`, and
`claudeCode`. Each recognized section is a closed schema, so misspelled fields
fail validation before persistence. Provider endpoints and broker references
are metadata only; credentials and bearer material are never accepted. Legacy
extension sections remain supported for migration, but typed sections are the
recommended enterprise contract.

Persistence is an explicit adapter boundary. The bundled
`SQLiteFleetPersistenceAdapter` enables WAL and bounded lock waits for local
development, but advertises `highAvailability: false`. Deployments can require
HA at startup with `require_high_availability=True`; the reference adapter is
then rejected before serving traffic. A PostgreSQL or managed-database adapter
must implement `FleetPersistenceAdapter`, migrations, transactions, locking,
backup/restore, and tenant-safe concurrency before being used in production.
The optional PostgreSQL implementation is available with
`pip install 'agentic-security-sdk[postgres]'`; pass its deployment-managed DSN
as the `path` argument. Connection failure aborts startup and the DSN is never
returned by the API.

The management UI provides tenant-scoped template creation, parent selection,
deployment filtering, template assignment, canary rollout, rollback to the
latest known history version, and emergency stop. Invalid JSON remains in the
editor for correction; the control plane performs the authoritative secret and
shape validation before persistence.

Rollout and emergency operations are not database-only claims. A deployment
can be bound to a `FleetDeploymentAuthority` adapter. Active/canary rollout,
rollback, and stop/clear operations invoke the live authority first; an
adapter failure leaves the operation unsuccessful and the database does not
claim activation. On application startup, persisted active rollout and
emergency-stop state is reconciled into every bound authority before the WSGI
application serves requests; a reconciliation failure aborts startup.

The fleet store rejects secret-like configuration keys and stores only JSON
configuration and hashes. It does not provision OPA/Cedar, IAM, approvals,
credentials, sandboxes, or telemetry backends; those remain explicit adapters.

The compliance evidence endpoint is intentionally a summary, not a raw audit
export. It includes deployment identity, configuration hashes and versions,
rollout state, health/SLO posture, active-session counts, audit event types and
counts, and explicit redaction assertions. It excludes configuration values,
credential material, session tokens, and raw audit payloads. Use the deployment's
immutable audit service for forensic event export.
Health is intentionally split into current state and explicit SLO samples.
Schedulers or telemetry adapters call the sample endpoint at a controlled
frequency; the read-only SLO endpoint computes availability over the bounded
configured window and reports `meeting`, `breach`, or `no_data`. Samples contain
only status and counts, never credentials, sessions, or configuration values.

Alerts are derived from current authoritative state. Incident commanders can
acknowledge them, while a provider-neutral `FleetAlertSink` can deliver
redacted alert records to an enterprise notification or incident system. The
included `WebhookFleetAlertSink` is a bounded HTTPS implementation suitable
for an enterprise webhook gateway; endpoint material must be injected from a
secret manager and is never persisted by the fleet store.
Delivery failures are reported as failures and do not clear, hide, or mutate
the underlying alert condition.

## Managed package distribution

A platform administrator can publish one exact canonical Claude Code or Codex
package for a deployment with `PUT
/api/enterprise/deployments/{deploymentId}/managed-package`. Publication uses
an expected revision, validates the SHA-256 and canonical SDK schema, and
requires the package target to match current server-owned desired state.
Operator `GET` on the same route returns metadata only.

An enrolled endpoint retrieves package bytes through `GET
/agent/{deploymentId}/{agentId}/managed-package`. The route is tenant-,
project-, agent-, attestation-, rollout- and emergency-stop-bound. It remains
available when managed configuration is missing or conflicting so a managed
endpoint can repair itself. The SDK client verifies the response and package
again before returning a typed object. Publication or download is never
reported as installation or enforcement evidence; a subsequent protected-file
measurement and live host acceptance remain necessary. See
[Managed package distribution](managed-package-distribution-design.md).

## Reference setup

The local UI example multiplexes the original runtime API with the enterprise
API. Start it with a UI token and open [the management UI](ui.md):

```bash
AAI_SEC_UI_TOKEN=synthetic-enterprise-ui-token-1234 \
AAI_SEC_AGENT_TOKEN=synthetic-enterprise-agent-token-1234 \
AAI_SEC_UI_PORT=8001 \
AAI_SEC_UI_ORIGIN=http://localhost:5174 \
python3 examples/ui_control_plane.py
```

For production, replace static bearer authentication with an enterprise IdP
through `CallbackFleetAuthenticator`, use a durable multi-process database
adapter, put the API behind TLS, and
connect each deployment to an authoritative runtime and immutable audit
service. The SQLite/reference implementation is suitable for development and
contract testing, not an enterprise production HA deployment.

## Smoke-test evidence

With the reference server on port `8001` and the UI on port `5174`, set
`VITE_USE_MOCKS=false`, `VITE_API_BASE_URL=http://localhost:8001/api`, and a
synthetic `VITE_API_TOKEN`. Open the UI, select **Enterprise fleet**, verify
the seeded `Safe default` template and `Local development` deployment, filter
by `platform`, and exercise template assignment, canary, rollback, and stop
with synthetic data. Confirm the resulting notice, health state, and alert;
then clear the stop only through an authorized API call. Do not use production
tokens in Vite variables or screenshots.

::: agentic_security.enterprise_control_plane
    options:
      members:
        - FleetIdentity
        - FleetIdentityVerifier
        - CallbackFleetAuthenticator
        - FleetSecretReference
        - FleetSecretResolver
        - CallbackFleetSecretResolver
        - EnterpriseFleetStore
        - EnterpriseFleetApplication
        - FleetAuthenticator
        - FleetDeploymentAuthority
        - FleetAlertSink
        - WebhookFleetAlertSink
        - validate_fleet_configuration
        - FleetPage
        - FleetAuthorizationError
        - FleetConfigurationError
        - FleetNotFoundError
        - StaticFleetAuthenticator
      show_source: false

## Population coverage

Enrollment is not a complete inventory. The AWS pilot adds a separate
**Coverage** workspace backed by current identity, endpoint, and source-control
snapshots. It shows whether the expected-population denominator is defensible,
which Claude Code or Codex targets are unmanaged or duplicated, and which active
enrollments belong to leavers or no longer map to an expected target.

Coverage is unavailable—not zero or 100%—when a required source is missing,
incomplete, stale, or establishes no denominator. The operator can inspect
source freshness, review business-unit posture, move to connection or agent
lifecycle workflows, and export a redacted content-hashed report. The report is
detection evidence; it does not automatically grant policy or contain an agent.
See [Agent population discovery](agent-discovery-design.md).
