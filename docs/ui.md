# AAI Security UI

`aai-sec-ui/` is the separate React/TypeScript management console for the
SDK. It is intended to help an operator connect Claude Code to the SDK and
manage the SDK's restrictive runtime controls.

## Claude Code integration

The UI configures both boundaries required for a complete Claude Code setup:

- a `PreToolUse` hook for Claude's built-in tools such as `Bash`, `Read`,
  `Edit`, and `Write`; and
- an MCP gateway command for tools whose execution, credentials, idempotency,
  approvals, or reconciliation must be owned by the SDK.

The hook and MCP entries are complementary. An MCP server cannot govern
Claude's native tools, and a hook does not provide the SDK's full execution
runtime for application side effects.

## Managed controls

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
and audit writes.

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
  python examples/ui_control_plane.py
```

Set `VITE_USE_MOCKS=false` and the same `VITE_API_TOKEN` in the UI `.env`.
The adapter persists validated configuration and exposes the emergency stop,
but it is localhost-only and does not by itself construct an application
runtime. Production deployments must add authenticated operator identity,
authorization, durable audit, and runtime reconciliation.
