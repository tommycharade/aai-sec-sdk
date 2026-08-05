# Wider enterprise UI

The wider enterprise UI manages deployments of the SDK, integrations,
providers, groups, agents, operational health and configuration lifecycle. It
does not replace the Policy editor. Policies define authority; the enterprise
UI determines where and to whom those policies are deployed.

See [Enterprise integration design](enterprise-integration-design.md) for the
host contracts and [Enterprise user journeys](enterprise-user-journeys.md) for
the central team's operating workflows.

## Enterprise navigation

The recommended navigation is:

- Dashboard
- Assurance
- Coverage
- Groups
- Agents
- Approvals
- Incidents
- Audit trail
- Policies
- Skills and MCP
- Connect agents
- Identity and access
- Deployments
- SDK runtime
- Webhooks
- Incident workflows

The **Identity and access** page must not be one continuous administration
form. Its overview shows verified identity foundations and one next-best
action. Separate workspaces cover **Entra setup**, **Directory & roles**,
**Delegated access**, **Emergency access**, and **Access reviews**. This keeps
rare emergency and certification work out of the routine federation journey.
The parked Splunk stub belongs to integration posture, not identity readiness,
and must not appear as a failed identity control.

The **Webhooks** administration page is a focused destination workflow, not a
generic integration form. It lists endpoint, event coverage, delivery posture,
key posture and lifecycle state; opens recent content-free delivery evidence;
and gives platform administrators typed create, test, rotate, pause, resume and
retire actions. Signing secrets appear in a blocking one-time reveal. Every
event and security-sensitive setting has contextual help. Non-platform roles
receive the same secret-free posture without mutation controls. The page does
not describe a queued test as verified delivery and does not present webhooks
as completed SIEM integration.

The **Incident workflows** administration page is separate from generic
Webhooks and the Incidents investigation workspace. Its table shows provider,
subscribed lifecycle, verification, latest delivery/external reference and
status. Detail presents human-readable provider configuration, exact revision,
credential-reference posture and content-minimised delivery evidence.

The typed creation flow supports ServiceNow, Jira Cloud and PagerDuty. Every
setting has contextual mouse and keyboard help. The browser accepts a
tenant-scoped Secrets Manager ARN but never credential bytes. A connection
must progress through register, synthetic verification and exact-revision
activation. Platform administrators can then verify again, pause, resume,
retire or explicitly retry a terminal failure with retained rationale.
Read-only operators see posture and evidence but no mutation controls.
Provider state is workflow output, never agent or policy authority.

## Enterprise-managed features

| Feature | What the wider UI should provide |
| --- | --- |
| GuardedRuntime | Deployment configuration, runtime version and health. |
| OPA/Cedar provider | Provider selection, endpoint, authentication reference and health. |
| HTTP approvals | Approval-service endpoint, authentication reference and health. |
| Emergency stop | Global, group and deployment stop controls with explicit confirmation and audit. |
| Idempotency store | Adapter, storage location, TTL, garbage-collection status and health. |
| Credential broker | Broker selection, endpoint, enablement and health. |
| Token credential broker | Token-service/provider configuration and scope evidence. |
| Credential TTL and revocation | Rotation, revocation and broker operational status. |
| Isolation verifier | Verifier selection, endpoint and health. |
| Deployment-attested isolation | Attestation provider, deployment evidence and verification status. |
| Audit sinks | Memory, JSONL, replicated and OpenTelemetry destinations. |
| Audit path and endpoint | Storage location, endpoint, retention and delivery status. |
| Telemetry | Exporter enablement and destination. |
| Audit replication | Delivery failures, retries and evidence-loss alerts. |
| MCP gateway | Gateway command, server name, deployment status and version. |
| MCP HTTP application | Host, port, authentication and bounded request/response settings. |
| MCP session store | Session expiry, revocation and storage health. |
| Claude Code integration | Project onboarding, MCP registration and PreToolUse hook setup. |
| OpenCode profile | Guided MCP configuration and connection verification. |
| OpenHands profile | Guided self-hosted MCP configuration and connection verification. |
| Cline profile | Guided MCP configuration and connection verification. |
| Gemini CLI profile | Guided extension/MCP configuration and connection verification. |
| GitHub Copilot profile | Guided CLI/cloud-agent MCP configuration and connection verification. |
| Codex CLI profile | Guided MCP configuration and connection verification. |
| Custom host integration | Integration status and documentation; implementation remains developer-owned. |
| Agent registration | Register, replace, revoke and inspect enrolled agents. |
| Agent heartbeat | Heartbeat interval, expiry threshold and health view. |
| Disconnect detection | Offline state, expiry status and operator alerts. |
| Project metadata | Host, project root, identity, last heartbeat and expiry. |
| Lifecycle auditing | Registration, replacement, expiry and disconnect history. |
| Configuration persistence | Save validated configuration and show activation state. |
| Configuration history | Compare versions, approve rollback and restore a prior version. |
| Live runtime activation | Stage, activate and verify configuration changes. |
| Configuration validation | Show validation results before activation. |
| UI authentication | Operators, roles, bearer tokens and enterprise SSO integration. |
| Microsoft Entra onboarding | A non-secret, task-focused setup workspace with redirect URI, server-owned tenant binding, downloadable manifest, guarded deployment commands and explicit live-acceptance gate. |
| Directory authority | SCIM lifecycle, exact group-to-role mappings, canonical capabilities and degraded/not-configured states. |
| Delegated administration | Expiring organization/project/deployment grants, live scope, rationale, revocation and retained history. |
| Emergency access | Recent-MFA, four-eyes, exact-capability, maximum-60-minute break-glass workflow. |
| Access certification | Complete-or-explicitly-incomplete digest-bound operator, role, delegation and emergency evidence export. |
| CORS/origin restriction | Allowed browser origins and deployment environment. |
| Agent groups | Create groups, select a policy, use manual batch assignment or trusted dynamic rules, inspect outcomes and manage agents. |
| Claude onboarding script | Display or generate the exact onboarding command for a project. |
| Configuration backups | Show backup status and provide controlled restore operations. |
| Executive and auditor assurance | Present server-derived, content-hashed posture summaries with explicit blind spots; restrict entity-level evidence lineage to evidence readers and export the exact viewed snapshot. |

The **Connect agents → Cloud credentials** workspace implements the credential
rows above as a typed, secret-free workflow. It distinguishes registration
from verified execution authority, shows exact scope and evidence expiry, and
requires an accountable human revocation. Only a machine identity scoped to
`credential_broker_runtime` can submit provider evidence. Local reference
registrations remain visibly blocked because SQLite cannot verify a cloud
identity.

The adjacent **Isolation profiles** workspace implements production-boundary
desired state and posture. Operators select a platform, immutable workload,
exact protected tools, network mode, credential mode and resource ceilings;
read-only filesystem, process namespace, no-new-privileges and dropped
capabilities remain immutable. Only `isolation_runtime` machine authority can
submit short-lived exact-configuration evidence. The policy editor selects
registered profile IDs and labels profiles as verified or blocked.

## Assurance workspace

**Assurance** is the reporting surface for leadership and assessors. It is not
a second dashboard and it must not manufacture compliance conclusions. The
executive profile presents bounded tenant posture, population, runtime,
policy, exception, operations and evidence summaries without entity details.
The auditor profile adds only the least-privilege policy, group, discovery and
source-evidence references required to trace those summaries.

Both profiles are derived by the control plane from strongly read tenant
records and expose the same report time, section hashes and canonical content
hash. The UI makes incomplete evidence prominent, states the report's explicit
non-guarantees and downloads the exact server response. It never converts
missing coverage into zero, accepts client-authored posture, or treats a
download as proof of immutable retention. Auditor detail requires the
`evidence_read` capability.

## Group and policy relationship

A group is the deployment-management boundary. Each group selects one policy
version and contains zero or more enrolled agents. The UI should show the
effective relationship clearly:

```text
Policy -> Group -> Agent deployments -> Agent projects
```

Changing group membership must not silently mutate an active session. The
runtime must re-evaluate live actions using the currently active authority,
and policy changes should expose rollout state and affected agents.

The group detail journey uses a typed bulk assignment dialog rather than a
single-agent selector. Operators search or select active unassigned agents,
enter an auditable rationale, and request a server-authoritative preview. The
preview shows ready, unchanged and rejected outcomes before **Apply** is
enabled. Apply is bound to the displayed membership revision and request ID;
stale revisions require a new preview. Partial success remains visible per
agent and never appears as an all-success toast. The completion view shows the
new revision and the exact applied/unchanged/rejected counts.

Operators can instead select **Automate membership**. A typed rule builder
offers only trusted inventory fields and exact include/exclude values. It
explains every field with contextual help, requires a business reason, and
shows matched, added, removed, unchanged and overlapping agents before apply.
Overlap blocks apply. Once enabled, the group is labelled **Dynamic**, manual
assignment/removal controls disappear, and **Review rule** opens the current
human-readable rule for deterministic reevaluation.

## Operational safeguards

### Evidence workspace

**Evidence** replaces a decision-only audit page with an assurance-first
records-management journey. The page verifies the live immutable inventory
before displaying a positive state, clearly distinguishes incomplete and
at-risk posture, and exposes:

- integrity-verified versus total retained versions;
- increase-only tenant retention;
- exact-version legal hold with hashed rationale;
- delete-marker visibility;
- complete digest-bound manifest export; and
- tenant-wide asynchronous assurance progress and scheduled monitor posture;
- impact-reviewed mass-retention extension and durable application progress;
- redacted runtime and lifecycle decision evidence.

The browser cannot submit tenant identity, integrity status or completeness.
It cannot shorten retention or bypass the 365-day COMPLIANCE floor. A failed or
truncated assurance request remains visibly failed closed.

Retention editing is review-first. Before save, the operator sees current and
target periods, the complete count or explicit lower bound, affected future
writes, synchronous versus background handling and the irreversible cost/legal
impact. An explicit cannot-shorten acknowledgement is required. Large
inventories continue independently of the browser and show examined/extended
counts, pages, failure reason and alert-delivery posture. A failed application
states that the longer future policy remains active and offers reconciliation,
never rollback.

When the synchronous inventory is incomplete, the page offers **Run full
assurance** rather than a misleading sample. The operator supplies a change or
case rationale; tenant, cutoff and status remain server-owned. The completed
view downloads every page, recalculates each canonical page hash and ordered
chain, then verifies the final export-index digest before constructing the JSON
download. Scheduled state distinguishes `healthy`, `attention`, `critical` and
alert-delivery `pending`; job failures are never collapsed into an empty state.

Enterprise actions should require role-based authorization, use explicit
confirmation for emergency operations, produce audit events, and expose
health/error state rather than silently accepting configuration. Secrets should
be stored as references to an enterprise secret/IAM system, never displayed or
persisted in browser state.

Identity setup may copy or download non-secret deployment values, but the
browser never accepts an OIDC client secret, SCIM bearer, tenant authority or
role claim. Configuration status is not acceptance evidence: the UI continues
to distinguish deployed federation from completed OIDC, joiner/mover/leaver,
role-denial and two-person MFA exercises.

### Data boundaries

Administration includes one focused read-only **Data boundaries** page. It
shows encryption ownership and a redacted key fingerprint, primary and
approved retained-data Regions, operator-network mode and count, Conditional
Access evidence presence, deletion behavior by data class, and separate
deployment-approval versus live-acceptance status. Every concept has
keyboard-accessible contextual help.

The page states `PrivateLink not configured` while only source-IP restriction
exists. When private ingress is deployed it shows the approved endpoint count,
explains that the operator API is private while machine/agent connectivity is a
separate channel, and keeps live customer acceptance visibly pending.
It offers no KMS, Region or network editor: those controls remain reviewed
deployment authority and cannot be weakened by a browser session.
