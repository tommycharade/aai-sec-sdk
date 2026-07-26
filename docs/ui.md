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

## Managed controls

The Enterprise Fleet page provides the first fleet-management surface for
organizations, projects, SDK deployments, connected Claude agents, and
configuration drift. It supports tenant-scoped deployment filtering across
team, environment, region, and ID; safe template creation with one-level
parent inheritance; assignment and staged configuration; canary rollout;
history rollback; deployment registration; current health and sample-based
availability SLO inspection; alert acknowledgement/delivery; and deployment
emergency stop/recovery. Operators can request redaction-safe samples, while
production schedulers should call the same API at a controlled frequency. It
also allows an authorized operator to register projects within the
authenticated organization; organization roots remain enterprise identity
provisioning objects.
is backed by the authenticated `/api/enterprise/*` contracts described in
[Enterprise fleet](enterprise-fleet.md). Inventory is tenant-scoped; it does
not expose heartbeat sessions or secrets.

The UI's Runtime settings page maps to the SDK's explicit configuration
surfaces:

- local, OPA, or Cedar policy provider;
- in-memory or HTTP approvals;
- memory, JSONL, replicated, or OpenTelemetry audit adapter;
- action, concurrency, fan-out, cost, delegation, rate, and timeout budgets;
- idempotency and approval TTLs;
- credential and high-risk isolation requirements; and
- sensitive-data redaction and optional content capture.

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

Claude presence is separate from configuration: the MCP process must be
started with `AAI_SEC_CONTROL_PLANE_URL` and an agent token, then it registers
and heartbeats through the authenticated agent endpoints. The dashboard shows
only those live registrations; writing `.mcp.json` alone does not create a
presence record.

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
AAI_SEC_UI_TOKEN=synthetic-local-token-1234 \
AAI_SEC_AGENT_TOKEN=synthetic-agent-token-1234 \
  python examples/ui_control_plane.py
```

Set `VITE_USE_MOCKS=false` and the same `VITE_API_TOKEN` in the UI `.env`.
The adapter persists validated configuration and exposes the emergency stop,
but it is localhost-only and does not by itself construct an application
runtime. Production deployments must add authenticated operator identity,
authorization, durable audit, and runtime reconciliation. Never bundle a
durable administrator bearer token in a production `VITE_*` variable because
Vite embeds those values in browser assets; use a short-lived authenticated
operator session instead.
