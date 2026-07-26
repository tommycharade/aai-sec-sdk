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
    └── deployment
        └── Claude Code agents and sessions
```

An authenticated identity carries an organization and optional project scope.
The API checks that scope on every read, registration, configuration, and
rollout operation. The UI never receives bearer tokens, agent heartbeat
sessions, credentials, or raw secrets.

## Inventory API

The reference WSGI application exposes these authenticated endpoints:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/enterprise/organizations` | Tenant inventory |
| `GET /api/enterprise/projects` | Project inventory |
| `GET /api/enterprise/deployments` | SDK deployment inventory |
| `GET /api/enterprise/agents` | Claude and other agent presence |
| `GET /api/enterprise/drift` | Desired/applied configuration drift |
| `POST /api/enterprise/agents/register` | Register an authenticated agent |
| `POST /api/enterprise/agents/{deployment}/{agent}/heartbeat` | Refresh presence |
| `POST /api/enterprise/agents/{deployment}/{agent}/disconnect` | Mark offline |
| `POST /api/enterprise/templates` | Create a configuration template |
| `POST /api/enterprise/deployment-config` | Assign desired configuration |
| `POST /api/enterprise/deployment-config/rollout` | Stage, canary, pause, activate, or rollback |
| `POST /api/enterprise/deployment-config/applied` | Record an applied configuration hash |

Agent registration returns one opaque, expiring session. It is accepted only
for the authenticated deployment/agent scope and is never included in fleet
inventory responses. Expired heartbeats are marked offline and lifecycle
events are written to the configured audit sink.

## Configuration governance

Templates can inherit from one parent template. Inheritance is bounded and
cycle-checked; child values override parent values. A deployment assignment
creates a desired configuration hash and starts in `staged` state. Operators
can move it through `canary`, `active`, `paused`, or `rollback` with an
explicit percentage. A deployment is drifted when its applied hash is absent
or differs from the desired hash.

Rollout and emergency operations are not database-only claims. A deployment
can be bound to a `FleetDeploymentAuthority` adapter. Active/canary rollout,
rollback, and stop/clear operations invoke the live authority first; an
adapter failure leaves the operation unsuccessful and the database does not
claim activation.

The fleet store rejects secret-like configuration keys and stores only JSON
configuration and hashes. It does not provision OPA/Cedar, IAM, approvals,
credentials, sandboxes, or telemetry backends; those remain explicit adapters.

## Reference setup

The local UI example multiplexes the original runtime API with the enterprise
API. Start it with a UI token and open [the management UI](ui.md):

```bash
AAI_SEC_UI_TOKEN=synthetic-local-token-1234 \
AAI_SEC_AGENT_TOKEN=synthetic-agent-token-1234 \
python3 examples/ui_control_plane.py
```

For production, replace static bearer authentication with an enterprise IdP,
use a durable multi-process database adapter, put the API behind TLS, and
connect each deployment to an authoritative runtime and immutable audit
service. The SQLite/reference implementation is suitable for development and
contract testing, not an enterprise production HA deployment.

::: agentic_security.enterprise_control_plane
    options:
      members:
        - FleetIdentity
        - EnterpriseFleetStore
        - EnterpriseFleetApplication
        - FleetAuthenticator
        - FleetDeploymentAuthority
        - FleetPage
        - FleetAuthorizationError
        - FleetConfigurationError
        - FleetNotFoundError
        - StaticFleetAuthenticator
      show_source: false
