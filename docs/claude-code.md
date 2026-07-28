# Claude Code: complete working example

This example uses both Claude Code integration points:

```text
Claude native tools ── PreToolUse hook ──> deterministic project policy/audit

Application tools ─── MCP server ────────> GuardedRuntime, approvals, credentials,
                                           idempotency, and audit
```

The hook does not execute actions. It returns Claude Code's native `allow`,
`ask`, or `deny` decision before Claude executes a built-in tool. Use MCP when
the SDK must own the operation and provide credentials, idempotency, timeout,
reconciliation, or result validation.

## Claude Code onboarding checklist

Use this sequence when onboarding a new project:

1. Install the SDK and confirm the project root you want Claude Code to work
   in.
2. Configure the project-scoped `PreToolUse` hook in
   `.claude/settings.json`.
3. Register the SDK-owned MCP gateway with `claude mcp add`.
4. Start Claude Code from the same project root and confirm `/mcp` shows the
   gateway.
5. Run the synthetic verification commands below and inspect the audit file.
6. Replace the synthetic identity, policy, approval, audit, credential, and
   isolation adapters before enabling consequential work.

### One-command setup

From the project you want Claude Code to use, run:

```bash
SDK_ROOT="${AAI_SEC_SDK_ROOT:-$HOME/.aai-sec-sdk}"
if [ ! -f "$SDK_ROOT/scripts/onboard_claude.py" ]; then
  git clone https://github.com/tommycharade/aai-sec-sdk.git "$SDK_ROOT"
fi
python3 "$SDK_ROOT/scripts/onboard_claude.py" \
  --project-root "$PWD" --sdk-root "$SDK_ROOT" \
  --control-plane-url http://localhost:8000/api
```

Review the repository and command before running it in a regulated
environment. Set `AAI_SEC_SDK_ROOT` when the SDK is already checked out at a
different path. The script writes only project-scoped files and creates
timestamped backups before changing existing configuration.

The script creates or updates `.claude/settings.json` and `.mcp.json`, keeps
existing entries, and creates timestamped backups before modifying either
file. It also installs `.claude/aai-sec-config.json`, the checked-in safe
default policy used by the example hook. Preview the changes first with
`--dry-run`. It does not invoke Claude or silently replace an existing
configuration or policy.

The default policy is intentionally narrow: `Read`, `Glob`, and `Grep` are the
only explicitly allowed native tools; read-only/status/test commands are
allowed; publishing, commits, pushes, and deployments require approval; and
destructive shell commands are denied. Edit the project policy only after
reviewing the security impact and adding tests.

For the local reference control plane, export the synthetic agent token before
starting Claude:

```bash
export AAI_SEC_AGENT_TOKEN=synthetic-agent-token-1234
claude
```

The MCP process then registers the project as `claude-code-local`, sends
heartbeats, and stops its guarded runtime if the control plane becomes
unavailable. The gateway also reports content-free runtime aggregates on each
heartbeat—action outcomes, cost units, and guarded-action latency—so the UI
can show performance without receiving tool arguments or outputs. The UI shows
the connected project under **Agents**; heartbeat expiry changes it to
`offline` and records an audited lifecycle event.

For an enterprise deployment, onboard the project with a deployment scope:

First, have an authenticated platform operator create a one-time bootstrap
token for the registered deployment. The AWS hosted control plane exposes this
as `POST /enterprise/agents/bootstrap`; the response contains the token once
and it must not be stored in the project. Then run onboarding with that token:

```bash
python3 /path/to/aai-sec-sdk/scripts/onboard_claude.py \
  --project-root "$PWD" \
  --enterprise-control-plane-url https://<api-id>.execute-api.eu-west-2.amazonaws.com \
  --deployment-id deployment-prod-eu \
  --agent-id claude-platform-prod \
  --bootstrap-token "<one-time-token>"
# The script prints this export after a successful exchange.
export AAI_SEC_AGENT_TOKEN="<short-lived-session-token>"
claude
```

The script consumes the bootstrap token at `/agent/enroll`, writes only
non-secret routing metadata to Claude's files, and prints the short-lived
session token for the current shell. The token is deployment/agent-bound and
expires; repeat enrollment with a newly issued bootstrap token when it expires.

The real-device acceptance run for Claude Code 2.1.220 is recorded in
[real Claude Code acceptance evidence](real-claude-code-acceptance-evidence-2026-07-27.md).

The deployment ID determines which organization/project fleet receives the
agent registration. The enterprise UI can then show the project alongside
other deployments, report heartbeat health and drift, and apply staged
configuration rollouts. Do not put the agent token in `.mcp.json`; inherit it
from the process environment or a secret manager.

Enterprise onboarding also embeds only the control-plane URL, deployment ID
and agent ID in the hook command. When `AAI_SEC_AGENT_TOKEN` is inherited by
Claude Code, the native-tool hook resolves the same authenticated effective
group policy as the MCP gateway before each event. Missing credentials,
unassigned or conflicting groups, malformed policy, or control-plane failure
deny the native action. This keeps central policy enforcement consistent for
Claude's built-in tools and SDK-owned MCP tools.

The hook configuration and MCP configuration are separate Claude Code host
boundaries. Put the `hooks` object in `.claude/settings.json`; put the
`mcpServers` object in `.mcp.json` or register it with `claude mcp add`. Do not
merge them into one file unless the Claude Code version you are using explicitly
documents that format.

If you are using the optional management UI, open **Integrations → Claude Code**
to configure the project root, hook command, MCP command, tool allow-lists, and
command approval rules. Save the configuration, download the generated host
configuration, then apply the two objects to their respective Claude Code
files. The UI control plane must be authenticated and connected to a live
runtime authority; its localhost reference adapter is for development only.

## 1. Install the SDK

From the project you want Claude Code to work on:

```bash
python3 -m pip install agentic-security-sdk
mkdir -p .claude
cp /path/to/aai-sec-sdk/examples/.claude/settings.json .claude/settings.json
```

The copied settings file runs
`examples/claude_code_hook.py` for `Bash`, `Read`, `Edit`, `Write`, `Glob`, and
`Grep`. If the example is outside the project, change the command to an
absolute path:

```json
{
  "type": "command",
  "command": "python3 /absolute/path/to/claude_code_hook.py",
  "timeout": 10
}
```

Claude Code reads project hook configuration from `.claude/settings.json`.
Review the current [Claude Code hook documentation](https://code.claude.com/docs/en/hooks)
when upgrading Claude Code because hook fields are host-owned configuration.

## 2. Start Claude Code

Run Claude Code from the project root:

```bash
claude
```

Try these synthetic checks:

```text
Ask Claude to run: git status
Ask Claude to run: git push origin main
Ask Claude to run: rm -rf /tmp/example
Ask Claude to read: /etc/hosts
```

Expected behavior:

| Request | Hook result |
| --- | --- |
| `git status` | Allowed |
| `git push` | Ask for interactive approval |
| `rm -rf` | Denied |
| Read outside project | Denied |

The hook writes a redaction-aware audit chain to
`.claude/security-audit.jsonl`. This example uses synthetic local identity and
rules. Replace them with the authenticated identity and policy boundary used
by your organization before production use.

## 2a. Run the local policy coverage harness

After onboarding a deployed project, run the SDK's non-destructive policy
harness from the project root:

```bash
python3 /absolute/path/to/aai-sec-sdk/scripts/test_claude_policy.py \
  --project-root "$PWD" \
  --sdk-root /absolute/path/to/aai-sec-sdk \
  --report .claude/policy-test-report.json \
  --allow-untested
```

The harness temporarily applies a synthetic policy, sends synthetic
`PreToolUse` events to the configured hook, checks allow/deny/approval/path,
malformed-input and audit behaviour, then restores the previous project policy.
It never invokes Claude or executes a proposed command. Omit
`--allow-untested` when the run must prove complete coverage; the command then
exits non-zero until runtime-only controls have a GuardedRuntime/MCP test.

To create and verify the matching enterprise policy and group, provide the
local control-plane URL and operator token. To verify live membership, also
provide the deployment and agent identifiers:

```bash
AAI_SEC_UI_TOKEN="synthetic-enterprise-ui-token-1234" \
python3 /absolute/path/to/aai-sec-sdk/scripts/test_claude_policy.py \
  --project-root "$PWD" \
  --control-plane-url http://localhost:8001/api \
  --deployment-id deployment-local \
  --agent-id claude-code-local \
  --report .claude/policy-test-report.json
```

The JSON report lists every check as `passed`, `failed` or `not_tested`. Native
Claude hook coverage includes tool allow-lists, command rules, path boundaries,
unknown tools, malformed input and audit output. Budgets, credentials,
isolation, durable audit sinks, telemetry and idempotency are explicitly
reported as runtime controls requiring MCP/GuardedRuntime or deployment tests;
they are not falsely treated as enforced by a Claude hook.

## 3. Add SDK-owned application tools through MCP

The MCP example is a separate process that exposes an explicit registered
`lookup_record` tool through `GuardedRuntime`:

```bash
claude mcp add --transport stdio --scope project \
  agentic-security -- \
  python3 /absolute/path/to/aai-sec-sdk/examples/mcp_gateway.py
```

Check the connection:

```bash
claude mcp list
claude mcp get agentic-security
```

Inside Claude Code, `/mcp` should show the server and its tools. Ask Claude
to call `lookup_record` with `record_001`. The proposal is validated and
authorized by the SDK before the synthetic handler runs. An unknown tool or
invalid record identifier is denied.

Claude Code stores project-scoped MCP configuration in `.mcp.json`. The
project file should be reviewed like source code because it controls which
external processes Claude can start. [Claude Code MCP configuration](https://code.claude.com/docs/en/mcp)
describes project, user, and local scopes.

## 5. Choosing hook versus MCP

## 4. Managed Skills and MCP servers

The enterprise UI can register reviewed Skills and MCP servers. A policy may
select their IDs under `claudeCode.allowedSkills` and
`claudeCode.allowedMcpServers`. The authenticated effective-policy response
resolves those IDs into `managedSkills` and `managedMcpServers` definitions.

The deployment-owned reconciliation helper can then apply that manifest to a
project:

```bash
python3 /path/to/aai-sec-sdk/scripts/reconcile_claude_resources.py \
  --project-root "$PWD" \
  --effective-policy .claude/effective-policy.json
```

It writes selected Skills to `.claude/skills/` and selected MCP entries to
`.mcp.json`, preserving unrelated entries and removing only resources from its
own managed manifest. It validates Skill digests and rejects insecure HTTP
MCP URLs. Secret values are supplied by the deployment environment, never by
the UI or policy JSON. This is configuration provisioning, not sandboxing;
the SDK gateway and host isolation controls remain necessary.

Use the hook for host-native operations where Claude Code remains the executor:

- Bash commands;
- file reads and writes;
- project search;
- Git commands;
- other Claude-native tools matched by `PreToolUse`.

Use MCP and `GuardedRuntime` for operations where the SDK must remain the
executor and authority boundary:

- external API calls;
- payments or destructive business actions;
- scoped credentials;
- durable idempotency;
- approval workflows;
- reconciliation after uncertain outcomes;
- domain-specific resource authorization.

Do not treat the hook example as a sandbox. Claude Code or another process may
still have access to the host outside the matched tools. For hostile or
regulated workloads, combine the hook and MCP gateway with OS/container
isolation, restricted credentials, and network egress controls.

## 6. Customize the policy

The hook API is extensible through ordered rules:

```python
from agentic_security import (
    ClaudeCodeHook,
    ClaudeHookDecision,
    command_rule,
    exact_tool_rule,
)

hook = ClaudeCodeHook(
    rules=[
        command_rule(
            (r"git\s+push",),
            decision=ClaudeHookDecision.ASK,
            reason="publishing requires approval",
        ),
        exact_tool_rule({"Read", "Glob", "Grep"}),
    ]
)
```

Rules are evaluated in order and the default decision is deny. A rule
exception also denies. Add tests for every new command or path rule and run
`make check` before distributing the hook configuration.

::: agentic_security.claude_code
    options:
      members:
        - ClaudeCodeHook
        - ClaudeHookDecision
        - ClaudeHookResult
        - ClaudeToolEvent
        - command_rule
        - exact_tool_rule
        - path_within_rule
      show_source: false
