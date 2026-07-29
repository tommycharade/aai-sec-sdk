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
- Policies
- Groups
- Agents
- Deployments
- Integrations
- Approvals
- Audit and evidence
- Credentials
- Isolation
- Configuration history
- Emergency controls
- Settings

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
| CORS/origin restriction | Allowed browser origins and deployment environment. |
| Agent groups | Create groups, select a policy, preview/apply up to 100 assignments, inspect partial outcomes and remove agents. |
| Claude onboarding script | Display or generate the exact onboarding command for a project. |
| Configuration backups | Show backup status and provide controlled restore operations. |

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

## Operational safeguards

Enterprise actions should require role-based authorization, use explicit
confirmation for emergency operations, produce audit events, and expose
health/error state rather than silently accepting configuration. Secrets should
be stored as references to an enterprise secret/IAM system, never displayed or
persisted in browser state.
