# Enterprise integration design

This document defines how a central security team onboards and governs agent
hosts. It is an integration contract for the enterprise UI, onboarding
workflow and control plane. It does not treat host configuration as proof of
runtime authority: the SDK runtime and deployment infrastructure remain the
enforcement boundary.

## Shared integration contract

### Operator identity contract

Operator identity is provider-neutral at the control-plane boundary. The first
adapter federates a tenant-specific Microsoft Entra ID application into
Cognito using authorization-code OIDC. Cognito remains the API token issuer;
the API independently resolves tenant entitlement and canonical role
capabilities. Upstream Entra claims, browser input and model output cannot
select an AAI tenant or widen a role.

The role vocabulary separates platform administration, security operations,
policy authoring, policy approval, fleet operation, incident response and
audit. Provider adapters map enterprise directory lifecycle into those roles;
the core authorization layer consumes only the canonical role/capability
contract. The Entra adapter now accepts tenant-bound SCIM user, group and
membership lifecycle and lets a platform administrator map exact directory
groups to canonical roles. Token issuance reconciles that live state every
five minutes and fails closed for inactive, unprovisioned or roleless users.
Live Entra acceptance, break-glass access, certification and delegated
administration remain required before enterprise-wide rollout.

SIEM adapters use the same honest-capability rule. The initial Splunk surface
is a schema and workflow stub and must report `deliveryVerified: false`; it
cannot satisfy the enterprise SIEM gate until authenticated delivery, retry,
dead-letter, monitoring and replay have live evidence.

Every supported host follows the same lifecycle:

```text
discover host -> generate scoped installer -> install SDK adapter
              -> register deployment/agent -> assign group policy
              -> verify heartbeat and synthetic decision -> monitor and respond
```

The installer must:

- use a project or workspace scope unless an operator explicitly selects a
  user/organization scope;
- preserve existing host configuration and create timestamped backups;
- install a pinned SDK version or reference an approved package source;
- write no bearer tokens or credentials into repository files;
- create a short-lived enrollment credential or require one from the operator;
- show exactly what files, commands and processes will change;
- return a verification command and an enrollment status link;
- be safe to rerun and fail closed when existing configuration is malformed.

The control plane stores host type, project/workspace, deployment, agent
identity, SDK version, last heartbeat, group, policy version and health. The
host never supplies its own authority, policy decision or principal in model
output.

### Operator approval journey

When policy returns `APPROVAL_REQUIRED`, the enrolled host may submit the
runtime-issued approval ID and exact action binding to the agent approval
endpoint. The control plane derives agent identity from the short-lived session
and queues only content-minimised metadata. The agent remains blocked while the
request is pending.

The central operator opens **Approvals**, verifies the authenticated host,
principal, task, risk class, bounded resource identifiers, and action
fingerprint, then records an approval or denial rationale. Approval grants
authority only to that exact action for a short TTL and one consumption. A
timeout, denial, expiry, replay, changed argument fingerprint, or control-plane
failure keeps execution blocked. The audit page presents the resulting
evidence but is not itself an approval control.

After enrollment, a deployment may fetch its effective policy with the
authenticated `GET /api/enterprise/agents/{deploymentId}/{agentId}/effective-policy`
endpoint. The endpoint fails closed when the agent has no policy group or when
multiple assigned groups resolve to different policies. The response contains
configuration data only; the deployment must translate it into typed SDK
objects and keep immutable SDK safeguards in force.

## Claude Code

### Enforcement surfaces

Claude Code needs two coordinated surfaces:

1. A project-scoped `PreToolUse` hook for native tools such as Bash, Read,
   Edit, Write, Glob and Grep.
2. An authenticated MCP gateway for SDK-owned application tools that need
   `GuardedRuntime`, approvals, credentials, idempotency and reconciliation.

### UI onboarding flow

The UI should ask for:

- project root;
- target deployment;
- agent display name;
- desired group;
- SDK version/channel;
- whether to generate or execute the installer locally.

It should then generate a copyable command using
`scripts/onboard_claude.py`, show the files that will be changed, and expose a
verification checklist:

- hook configured in `.claude/settings.json`;
- project policy present in `.claude/aai-sec-config.json`;
- MCP server present in `.mcp.json`;
- Claude process started from the expected project root;
- `/mcp` reports the gateway;
- heartbeat is visible in the enterprise UI;
- synthetic read, approval-required and denied checks pass.

The enterprise hook command carries only non-secret routing metadata. The
short-lived enrollment token is inherited from the host process and is never
written to project files. The hook resolves the effective policy for each
native-tool event, so a group policy change does not wait for a local policy
file refresh.

### Trust boundaries

The hook can govern native host tools but cannot prove sandbox isolation,
credential scope, durable audit replication or runtime budgets. Those controls
must be verified through the MCP/runtime and deployment checks.

The reference MCP gateway registers first, retrieves this effective policy and
starts only when it receives a valid tool allow-list. Losing the control-plane
heartbeat stops the reference runtime; production adapters should apply the
same fail-closed lifecycle with their deployment-specific shutdown mechanism.
AWS agent sessions are deliberately short-lived. When an authenticated
heartbeat is within five minutes of expiry, the control plane atomically issues
a replacement bearer and invalidates the previous one. The gateway adopts the
replacement and atomically writes it to the identity-scoped, user-private host
cache. Claude's separate native-hook processes read that current cache rather
than retaining the original inherited bearer. A healthy process can therefore
run indefinitely without writing a secret into project configuration. A missed
heartbeat, failed renewal, unsafe cache, revoked session or emergency stop
still fails closed.

## Codex CLI

### Enforcement surface

Codex CLI uses an authenticated MCP server plus a `PreToolUse` hook. The hook
intercepts supported native `Bash`, `apply_patch`, MCP and local function tools;
the server routes SDK-owned tools through the same `GuardedRuntime`. Set
`AAI_SEC_AGENT_HOST=codex-cli` so audit events and MCP initialization identify
the client as Codex rather than relying on model-supplied metadata.

The shared agent client carries that host value into the authenticated
registration request; Codex presence is not recorded as Claude Code by
default. `scripts/onboard_codex.py` writes a project-scoped required MCP entry
and native hook with non-secret routing metadata only. The short-lived value is accepted during
onboarding and then rotated through the SDK-owned host credential cache; it is
not forwarded through Codex project configuration.

The integration does not invent a Codex-specific policy language. It maps the
shared native-tool policy onto canonical Codex events and translates MCP tool
calls into the existing typed `ActionProposal`, preserving authenticated agent
identity at the process boundary. Approval-rule matches are audited but denied
at the native hook because Codex does not currently support an approval-producing
`PreToolUse` result. Approval-bound operations must use the governed MCP path.

### UI onboarding flow

The UI generates:

- a project-scoped installer command for the selected scope;
- the gateway command and SDK checkout reference;
- the deployment and agent enrollment parameters;
- a verification command using `codex mcp get`;
- a synthetic MCP read and denied-action check.

The UI must clearly distinguish Codex's user-local MCP configuration from
enterprise enrollment. Central team management requires deployment enrollment
and an authenticated agent identity; a user-local MCP entry is not sufficient
evidence that the enterprise deployment is governed.

The enrollment action consumes the one-time bootstrap secret before producing
the short-lived session token used by the MCP process. Bootstrap and session
credentials must never be committed to the repository or stored in the Codex
configuration as long-lived secrets.
The gateway renews the AWS session during its regular heartbeat loop and
publishes the latest bearer to the SDK-owned, user-private host cache.
Operators should treat a process that cannot heartbeat as unenrolled, even if
its user-local MCP entry and cached credential remain.

### Trust boundaries

Codex MCP registration only starts the gateway. It does not itself authorize a
tool or establish a principal. The gateway requires authenticated process
context and fails closed when the control plane or runtime authority is absent.
Project hook trust is user-controlled and therefore suitable for pilots, not
immutable enterprise enforcement. Production rollout distributes the hook with
device management and pins managed hooks in `requirements.toml`.

## GitHub Copilot Agent

### Enforcement surface

GitHub Copilot Agent should use the supported MCP integration and, where the
deployment supports it, host hooks for native command/tool interception. The
enterprise UI must treat GitHub organization/repository identity and the SDK
agent identity as separate facts and bind them during enrollment. The shared
gateway uses `AAI_SEC_AGENT_HOST=github-copilot` for the host profile while the
repository/organization MCP configuration remains the Copilot-owned setup
surface.

### UI onboarding flow

The UI should ask for:

- GitHub organization;
- repository or workspace;
- Copilot agent environment;
- deployment region/environment;
- group and policy;
- GitHub App/OIDC or approved enrollment mechanism.

It should generate a repository-safe configuration patch or GitHub-managed
setup instruction, never a long-lived secret. Verification should show:

- MCP server registered in the target Copilot environment;
- repository identity bound to the enrolled deployment;
- a successful synthetic allowed call;
- a denied or approval-required call;
- audit evidence linked to the repository and agent.

### Trust boundaries

GitHub repository permissions are not a substitute for SDK policy. A repository
may be allowed to use the gateway while individual tools, resources and
principals remain denied by the selected policy.

## Host capability matrix

| Capability | Claude Code | Codex CLI | GitHub Copilot Agent |
| --- | --- | --- | --- |
| Native host hook | `PreToolUse` | `PreToolUse`; native approval becomes deny + MCP route | Host/version dependent; verify deployment support |
| MCP gateway | Required for SDK-owned tools | Required | Required |
| Project/repository scope | `.claude/` and project MCP config | Project MCP scope | Repository/organization-managed config |
| Central enrollment | MCP heartbeat plus deployment ID | MCP heartbeat plus deployment ID | MCP heartbeat plus repository/organization binding |
| Policy enforcement | Hook plus runtime | Hook plus runtime gateway | Runtime gateway plus supported host controls |
| Verification | `/mcp` and synthetic hook checks | `/hooks`, MCP get and native/MCP synthetic calls | MCP/agent configuration and synthetic calls |
| Main UI risk | Hook config mistaken for full runtime security | User-local MCP mistaken for enterprise enrollment | GitHub permission mistaken for SDK authorization |

## Rollout and response

Integration rollout is staged per group:

1. Generate configuration and show a diff.
2. Apply to one canary deployment.
3. Verify heartbeat, policy version and synthetic checks.
4. Expand by percentage or deployment selection.
5. Pause automatically on failed health or verification checks.
6. Provide rollback to the previous known-good version.

Emergency stop is a separate control from policy editing. It should stop a
deployment or group immediately, show the affected agents and preserve audit
evidence. Clearing the stop requires explicit operator confirmation and a
post-stop verification check.
