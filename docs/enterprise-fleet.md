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
| `POST /api/enterprise/agents/{deployment}/{agent}/heartbeat` | Refresh presence and optionally publish bounded aggregate SDK telemetry |
| `POST /api/enterprise/agents/{deployment}/{agent}/disconnect` | Mark offline |
| `POST /api/agent/{deployment}/{agent}/decisions` | Record one authenticated, content-minimised host decision as operational evidence |
| `POST /api/agent/{deployment}/{agent}/approvals/request` | Submit a bounded approval request using the authenticated agent session |
| `POST /api/agent/{deployment}/{agent}/approvals/consume` | Atomically consume one approved exact-action grant |
| `POST /api/enterprise/templates` | Create a configuration template |
| `POST /api/enterprise/policies` | Create a configuration policy |
| `POST /api/enterprise/groups` | Create a group and bind it to a policy |
| `POST /api/enterprise/groups/{group}/policy` | Change a group's immutable policy assignment and audit the change |
| `POST /api/enterprise/groups/{group}/agents` | Enroll an existing agent in a group |
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
