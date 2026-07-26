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

## Inventory API

The reference WSGI application exposes these authenticated endpoints:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/enterprise/organizations` | Tenant inventory |
| `GET /api/enterprise/projects` | Project inventory |
| `GET /api/enterprise/deployments` | SDK deployment inventory |
| `GET /api/enterprise/agents` | Claude and other agent presence |
| `GET /api/enterprise/sessions` | Active/expired session inventory without session tokens |
| `GET /api/enterprise/drift` | Desired/applied configuration drift |
| `GET /api/enterprise/templates` | Tenant-scoped configuration templates |
| `GET /api/enterprise/deployment-config` | Current desired/applied configuration state |
| `GET /api/enterprise/deployment-config/history` | Bounded prior configuration versions |
| `GET /api/enterprise/health` | Deployment health and rollout indicators |
| `GET /api/enterprise/slo` | Sample-based availability and SLO status in the bounded window |
| `GET /api/enterprise/compliance/evidence` | Redacted tenant-scoped evidence bundle for review/export |
| `GET /api/enterprise/alerts` | Derived fleet alerts |
| `POST /api/enterprise/agents/register` | Register an authenticated agent |
| `POST /api/enterprise/agents/{deployment}/{agent}/heartbeat` | Refresh presence |
| `POST /api/enterprise/agents/{deployment}/{agent}/disconnect` | Mark offline |
| `POST /api/enterprise/templates` | Create a configuration template |
| `POST /api/enterprise/templates/validate` | Validate safe configuration without persisting it |
| `POST /api/enterprise/deployment-config` | Assign desired configuration |
| `POST /api/enterprise/deployment-config/rollout` | Stage, canary, pause, activate, or rollback |
| `POST /api/enterprise/deployment-config/batch-rollout` | Apply one rollout command to up to 200 deployments |
| `POST /api/enterprise/deployment-config/rollback` | Restore a known prior version as a new staged version |
| `POST /api/enterprise/deployment-config/applied` | Record an applied configuration hash |
| `POST /api/enterprise/emergency-stop` | Stop or clear one deployment through its authority |
| `POST /api/enterprise/alerts/{alertId}/ack` | Acknowledge an alert without deleting evidence |
| `POST /api/enterprise/alerts/dispatch` | Deliver unacknowledged alerts through an alert adapter |
| `POST /api/enterprise/slo/sample` | Record one redaction-safe health sample for an authorized deployment |

Agent registration returns one opaque, expiring session. It is accepted only
for the authenticated deployment/agent scope. Session inventory exposes only
agent/deployment scope, timestamps, and active/expired status; the opaque
session token is never returned. Expired heartbeats are marked offline and
lifecycle events are written to the configured audit sink.

## Configuration governance

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
AAI_SEC_UI_TOKEN=synthetic-local-token-1234 \
AAI_SEC_AGENT_TOKEN=synthetic-agent-token-1234 \
python3 examples/ui_control_plane.py
```

For production, replace static bearer authentication with an enterprise IdP
through `CallbackFleetAuthenticator`, use a durable multi-process database
adapter, put the API behind TLS, and
connect each deployment to an authoritative runtime and immutable audit
service. The SQLite/reference implementation is suitable for development and
contract testing, not an enterprise production HA deployment.

## Smoke-test evidence

With the reference server on port `8001` and the UI on port `5175`, set
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
