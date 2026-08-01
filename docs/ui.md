# AAI Security UI

`aai-sec-ui/` is the separate React/TypeScript management console for the
SDK. It is intended to help an operator connect Claude Code to the SDK and
manage the SDK's restrictive runtime controls.

## Claude Code integration

For a step-by-step onboarding procedure, see the [Claude Code onboarding
guide](claude-code.md). The short version is: configure the hook in
`.claude/settings.json`, register the MCP gateway with `claude mcp add`, start
Claude from the project root, verify `/mcp`, and run the synthetic denial and
approval checks.

The UI configures both boundaries required for a complete Claude Code setup:

- a `PreToolUse` hook for Claude's built-in tools such as `Bash`, `Read`,
  `Edit`, and `Write`; and
- an MCP gateway command for tools whose execution, credentials, idempotency,
  approvals, or reconciliation must be owned by the SDK.

The hook and MCP entries are complementary. An MCP server cannot govern
Claude's native tools, and a hook does not provide the SDK's full execution
runtime for application side effects.

The global search control is also an entity-aware command palette: press
**⌘K** on macOS or **Ctrl+K** on other platforms to open it, then search for an
agent, group, policy, deployment, or destination such as Integrations. Results
show the relevant host, policy, environment, or group context and are bounded
to keep the palette fast for large fleets. This is intended as the fastest route
for operators who manage several workspaces or return to a known task.

The **Integrations** page provides guided activation for Claude Code and Codex
CLI, plus an explicitly admin-managed GitHub Copilot Agent profile. Select a
host to see its enrolled count, enforcement surfaces, deployment/group scope
and verification contract. Claude Code and Codex use a short-lived enrollment
session; the operator chooses the deployment, agent identity, project root and
policy group, prepares enrollment, copies the session separately, and runs a
secret-free generated command. That command prompts for the session without
putting it in shell history. The result is backed by the
control plane rather than inferred from a copied file: it checks registration,
heartbeat, policy assignment and emergency-stop state. Host configuration is
project/repository-scoped by default; a local config file is not treated as
enterprise enrollment until the authenticated agent heartbeat and policy
assignment are verified. Claude writes routing metadata to
`.claude/settings.json` and `.mcp.json`; Codex uses
`scripts/onboard_codex.py` to write a project-scoped `.codex/config.toml`.
Both installers preserve unrelated project configuration and transfer the
one-time shell value into an identity-scoped, user-private rotating cache and
then clear it;
neither host inherits it after onboarding. Project configuration contains only
the control-plane URL, deployment, agent identity, and `aws` session mode. The
gateway rotates the cache and each short-lived native hook process reads the
current value. After successful verification the UI offers **View agent**,
taking the operator directly to the live agent inspector.

The Copilot profile does not generate a misleading ready-to-paste bearer
configuration. Guided activation remains unavailable until the deployment has
a credential broker that can renew short-lived sessions across cloud-agent
restarts; use the documented deployment adapter for controlled pilots.

## Managed controls

The console keeps the operator's mental model explicit:

- **Enterprise fleet** is the home for groups, policies, agent membership,
  connected Claude agents, and health. Select a group to inspect its policy,
  healthy/attention counts, monitored agents, and membership actions.
- **Deployments & rollout** is the home for organizations, projects, SDK
  deployment registration, templates, canaries, rollback, drift, availability
  SLOs, alerts, and redacted session inventory. Group controls are intentionally
  not duplicated there. The page opens on a deployment-first command view that
  derives readiness from enrolled-agent health, desired configuration, drift,
  unacknowledged alerts, and emergency-stop state. Its attention queue points
  to the first deployment requiring action, while each inventory row presents
  coverage, desired configuration, rollout progress and health before exposing
  destructive controls in a secondary menu. **Rollouts & health** contains SLO,
  drift, alerts and session evidence. It opens with a derived operational
  posture, a prioritized intervention queue, and a deployment health matrix;
  agent/session inventories and the redacted compliance projection remain
  available under **Evidence & diagnostics** without competing with live
  blockers. **Templates & setup** contains configuration templates and
  deployment/project registration. These modes keep the frequent deployment
  decision separate from infrequent setup and diagnostic work.
- **Skills & MCP** is the reviewed resource catalog. It shows each resource's
  version, transport or content identity, enabled state, and current policy
  reach including the number of affected agents. Search narrows the catalog
  without hiding the registration controls; selecting a resource in a policy
  remains the explicit deployment gate.

Both surfaces are backed by the authenticated `/api/enterprise/*` contracts
described in [Enterprise fleet](enterprise-fleet.md). Fleet collections are
cursor-paginated by the API and the browser follows continuation pages
automatically for larger tenants. Session tokens and credential material are
never displayed.

Mutating group controls and policy saves show an explicit pending state and
disable competing actions until the control-plane request completes. Success
and failure remain visible through the console status banners; a disabled
control is not treated as evidence that an operation succeeded.

Agent verification messages are derived from the same boolean condition they
describe. Missing registration, offline status, expired heartbeat, conflicting
group assignment, missing policy and emergency-stop states each return a fixed,
non-sensitive explanation; a failed check never carries healthy-state copy.
Activation additionally requires the returned host, sole group, effective
policy ID, and policy version to match the UI selection exactly. Changing any
part of that tuple invalidates prior verification.
Strongly consistent tenant list reads paginate to obtain complete
policy-assignment state, but fixed page and item limits prevent unbounded
Lambda work. Exceeding either limit fails the request closed instead of
authorizing from a partial list. Operational decision history uses a separate
reverse-chronological, bounded index; the API marks counts as truncated when
the visible window is a lower bound.

On narrow screens, dense fleet tables preserve their complete column set inside
a horizontally scrollable region and display an explicit swipe hint. This
keeps policy, heartbeat, health, and action columns available without shrinking
critical text below an operable size.

The top bar reports control-plane freshness from successful reads: **Syncing**
appears during initial load, **Live** after a successful dashboard or fleet
read, and **Stale** when a later poll fails while the last known snapshot is
retained. The overview's update label is derived from the snapshot timestamp;
it does not claim that data is current when the API has not reported it. A
healthy-looking snapshot must therefore be read together with its freshness
state.

The authenticated top bar keeps **Connect agent** available from every page.
Overview also surfaces one contextual next action: give unassigned agents a
policy, investigate stale health, or review held high-risk actions. This keeps
the first useful action visible after onboarding instead of requiring the
operator to infer which page to open next.

### Approvals, audit, and response boundary

The **Approvals** page is the live operator queue for high-risk actions held at
the execution boundary. It shows only the authenticated agent identity,
runtime-owned action fingerprint, tool, principal, task, risk class, and bounded
resource identifiers. Tool arguments, outputs, prompts, credentials, and
sensitive content are not copied into the queue. Operators approve once or deny
with a required rationale. The control plane conditionally records that
decision; an approval remains exact-action bound, short-lived, single-use, and
unavailable after expiry, replay, a binding mismatch, or a concurrent decision.

The **Audit trail** remains read-only evidence. It presents decision counts and
supports searching by agent, tool, resource, or reason plus filtering by
allowed, approval-required, or denied decisions. Operators must decide from the
live Approvals record, not infer authority from an audit event. Both pages show
redacted metadata, while lifecycle evidence records the request and operator
decision without action content.

The **Incidents** workspace separates operator-owned cases from **Response
rules**. Rules begin in a fleet inventory with status, host scope, active
version, action limit, cooldown and update metadata. Opening one shows active
authority separately from pending governance and lists content-minimised match
outcomes. The editor is typed: exact endpoint reasons, severity, Claude
Code/Codex scope, fixed SDK quarantine, hourly limit, per-agent cooldown and
priority. Every control has a keyboard-focusable help marker. A read-only impact
preview is required before draft creation in the browser, while the API repeats
all schema and authority validation.

Draft creation never activates a rule. The workflow visibly requires submit,
independent approval and version-bound activation. Authors cannot approve their
own versions; disabling removes future automatic authority immediately; and
rollback offers only independently approved superseded versions. The UI states
that quarantine restricts SDK execution authority while preserving heartbeat
and attestation—it does not claim device, network or process isolation. See
[Approved automatic response rules](automatic-response-rules-design.md).

Trial tenants also receive a server-derived status banner showing the remaining
trial time and safe-default readiness. Before the first enrollment it links
directly to onboarding; once an agent is enrolled it reports the enrolled-agent
count and links to the agent directory instead. The browser never calculates
entitlement or accepts trial metadata from user input; it renders the bounded summary returned by
`GET /api/enterprise/tenant`.

Template creation includes typed governance controls for deny-by-default policy,
approval provider, tool allow-list, action budget, credential broker mode,
high-risk isolation, audit provider, and telemetry. “Apply to template JSON”
generates the corresponding configuration sections for review. The advanced JSON
editor remains available for provider-specific fields, but submission is still
validated by the backend and does not make the browser an authority boundary.

The UI's Runtime settings page maps to the SDK's explicit configuration
surfaces:

- local, OPA, or Cedar policy provider;
- in-memory or HTTP approvals;
- memory, JSONL, replicated, or OpenTelemetry audit adapter;
- action, concurrency, fan-out, cost, delegation, rate, and timeout budgets;
- idempotency and approval TTLs;
- credential and high-risk isolation requirements; and
- sensitive-data redaction and optional content capture.

Primary console destinations are hash-addressable (for example, `#fleet` or
`#policy`) so an operator can bookmark or share a working view without losing
the current workspace context. Entity searches preserve the selected object in
the hash too, such as `#agents/agent/<deployment-id>%3A<agent-id>`; reloading
that link opens the same inspector or filtered deployment view. Browser
back/forward navigation follows those destination changes. The trial and
activation banner intentionally appears on Overview only; operational pages
keep their vertical space for the task being performed.

Executable tool handlers, argument validators, resource extractors, and
credential implementations remain application-owned code. The UI manages
allow-lists and runtime controls for registered tools; it deliberately does
not create dynamic function lookups or accept executable policy from model
output.

The browser submits a complete typed configuration to an authenticated
control-plane API. It must not connect directly to the Python runtime or be
treated as an authority boundary. The API must authenticate the operator,
authorize configuration changes, validate restrictive limits, redact data,
audit writes, activate changes through a live runtime authority, and expose
bounded rollback history. On startup the adapter must reconcile persisted
configuration and emergency-stop state into the live authority before serving
requests; a failed reconciliation must prevent the service from starting.

The policy editor distinguishes an unsaved draft from an applied policy. New
policies show their actual draft name and identifier, while edits show the
current version and the next-version operation. Its rollout-impact panel
reports only the groups and deduplicated agents currently assigned to that
policy; workspace-wide decision counts are not presented as policy-specific
metrics when the API cannot attribute them. Dashboard decision cards likewise
show the source-backed decision total, denied total, and pending approvals
instead of an inferred or hard-coded allow percentage.

Claude presence is separate from configuration: the MCP process must be
started with `AAI_SEC_CONTROL_PLANE_URL` and an agent token, then it registers
and heartbeats through the authenticated agent endpoints. The dashboard shows
only those live registrations; writing `.mcp.json` alone does not create a
presence record.

## Hosted trial onboarding

The hosted **Start free trial** flow opens Cognito's signup endpoint directly,
so a new visitor does not have to find the signup link from the sign-in page.
The visitor signs up and confirms their email; the Cognito post-confirmation trigger then
creates a new isolated trial tenant, a restrictive starter policy and template,
and a server-owned user-to-tenant mapping. The user is added to the operator
group only for coarse RBAC. Every API request still resolves the tenant from
the verified Cognito subject mapping, so a browser cannot choose or change its
tenant by editing a request body. Trial defaults deny unknown tools, bound
runtime actions, require approval for `git push`, redact sensitive data and do
not capture tool content.

The first authenticated fleet request tolerates the short gap between Cognito
confirmation and post-confirmation tenant provisioning. The browser retries
only the expected missing-entitlement response, then shows a provisioning
message if the server still needs time; other authorization failures remain
fail-closed and are surfaced as errors.

The trial CTA is a real onboarding path only in the hosted deployment. Local
development can use mock mode; it must not be treated as evidence of Cognito,
tenant provisioning, or production authorization.

## Local development

```bash
cd aai-sec-ui
cp .env.example .env
npm install
npm run dev
```

Mock mode is enabled by default. To exercise HTTP mode against the dependency-
free reference adapter, run this from the SDK repository in another terminal:

```bash
AAI_SEC_UI_TOKEN=synthetic-enterprise-ui-token-1234 \
AAI_SEC_AGENT_TOKEN=synthetic-enterprise-agent-token-1234 \
AAI_SEC_UI_PORT=8001 \
  python examples/ui_control_plane.py
```

Set `VITE_USE_MOCKS=false`, `VITE_API_BASE_URL=http://localhost:8001/api`, and
the same `VITE_API_TOKEN` in the UI `.env`. Restart Vite after changing
`VITE_*` values; they are read at startup.

To run the local UI against the deployed AWS control plane, use the checked-in
production configuration and the AWS development mode instead of plain
`npm run dev`:

```bash
cd aai-sec-ui
npm run dev:aws -- --port 5174
```

This loads `.env.production`, including the Cognito domain, client ID, and API
URL. The UI automatically uses the current localhost origin as the Cognito
callback during local development; the hosted deployment uses its CloudFront
callback URL. If a Vite process is already using port 5174, stop it first
and restart it with this command; changing environment variables does not
update an already-running Vite process. The browser should then be opened at
`http://localhost:5174/`, and the Cognito callback is registered for that URL.
The adapter persists validated configuration and exposes the emergency stop,
but it is localhost-only and does not by itself construct an application
runtime. Production deployments must add authenticated operator identity,
authorization, durable audit, and runtime reconciliation. Never bundle a
durable administrator bearer token in a production `VITE_*` variable because
Vite embeds those values in browser assets; use a short-lived authenticated
operator session instead.

For a production browser deployment, prefer the explicit BFF/session mode:

```dotenv
VITE_USE_MOCKS=false
VITE_API_BASE_URL=/api
VITE_API_AUTH_MODE=cookie
```

The hosting layer must establish a short-lived, HttpOnly, Secure, SameSite
operator session and translate it to the authenticated control-plane request.
The UI sends `credentials: include` and does not send or embed a bearer token
in this mode. The BFF remains responsible for CSRF protection, OIDC claims,
RBAC, TLS, rate limits, and session revocation.

On **Policy**, create a tenant-scoped configuration policy using the UI-first
typed editor. It is organized into identity and scope, tool permissions,
Claude native-tool controls, command rules, approvals, resource limits,
credentials, isolation, data capture/redaction, and review/versioning. The
effective-policy preview shows allowed, denied and approval-required actions,
limits, requirements and affected groups/agents before saving. Expert users can
open advanced JSON, but it is schema-validated and cannot bypass immutable SDK
safeguards. On **Enterprise fleet**, the posture strip first shows total groups,
enrolled agents, healthy heartbeats, and unassigned agents. Create an agent
group, select its policy, inspect enrolled Claude Code or Codex agents, and use
**Assign agents** to open the controlled bulk workflow. Select up to 100
unassigned agents, provide a rationale, review live ready/unchanged/rejected
outcomes, and apply only from that preview. The completion receipt shows the
new membership revision and partial-failure counts. Use **Remove from group**
for an individual removal. Group membership is control-plane metadata; the
deployment runtime remains the authority that enforces the selected policy.
The **Agents** page is the cross-enterprise operations directory: it provides
health metrics, search across agent/deployment/project/group/policy identity,
a healthy/attention filter, heartbeat freshness, and a focused inspector for
verification and emergency-stop actions. It shows each enrolled host's central group/policy
coverage, including an explicit fail-closed warning for conflicting group
assignments or no assigned policy. The fleet opens on a clean groups index: the
operator selects **View group** to enter a focused detail view with health
metrics, policy assignment, membership changes and emergency-stop controls,
then uses **Back to groups** to return to the index. Group creation is kept
behind a single **Create group** action so the primary monitoring workflow is
not competing with setup forms.

Group detail includes the deployment availability SLO returned by the control
plane when samples exist, plus aggregate SDK telemetry when enrolled runtimes
report it: action totals, allow/deny/approval outcomes, cost units, and
average/max guarded-action latency. The **Agents** inspector shows the same
bounded metrics for one host and clearly labels heartbeat-only agents as not
reporting performance data. CPU, token-use, raw tool content, and tool names
are not part of this contract and are never represented as guessed values.

If a live fleet request fails, the fleet-dependent screens show an explicit
recovery state with the error context, access guidance, and a **Retry
connection** action. The UI never replaces missing enterprise state with demo
fixtures, so operators can distinguish an unavailable control plane from an
empty fleet.

Fleet loading uses a page-shaped skeleton rather than an empty screen while a
retry or initial sync is in progress. Selecting a group also updates the URL
to `#fleet/group/{group-id}`, so operators can bookmark, share, and refresh a
focused group view without losing context.

Every configurable field has a question-mark help control. Hover over or focus
the icon to see the setting's purpose, security effect and any important
operational constraint. The same help pattern is used across Policy, Runtime
settings, Integrations, templates and fleet registration forms.

Host onboarding never invents a deployment boundary. In a live workspace with
no registered deployment, the enrollment action is disabled and the operator
is directed to **Deployments & rollout** first. The local deployment fallback
is reserved for simulation mode.

The first-run host flow ends at central enrollment and verification. Claude
Code hook fields, generated `settings.json`, and native-tool rules are grouped
under **Advanced Claude Code settings** so they remain available without
competing with the primary connection path.

The **Coverage** page is the population-assurance workspace. It keeps expected
population discovery separate from enrolled-agent operations. The page first
states whether coverage can be calculated, then shows the explicit denominator,
source freshness, unmanaged/duplicate/leaver/orphan findings, expected-instance
details, and business-unit breakdown. If any required source is absent,
incomplete, or stale, percentages are suppressed and the blind spots are shown.
Operators can export content-hashed evidence or move directly to Connect agents
and Agents for response.

**Coverage → Inventory sources → Connect inventory** provides UI-first managed
Entra, Intune and GitHub setup. Intune registration shows the exact read-only
Graph permission, accepts only optional opaque user-to-business-unit mappings,
and states that device enrollment cannot substitute for installation evidence.
GitHub registration uses typed organization,
repository, project-root digest, expected-host and business-unit fields, with
field-level help and schema-checked JSON import for larger fleets. The UI sends
only a Secrets Manager ARN and the bounded non-secret map; it never accepts or
stores a provider token. Source rows distinguish provider schedule health,
credential state and current evidence and show only a redacted organization and
repository count for GitHub.
