# Agent integrations

The SDK can be connected to agent hosts through the Model Context Protocol
(MCP). The integration layer is deliberately separate from the security
runtime: the host creates the authenticated `ExecutionContext`, registers the
explicit tool allow-list, and supplies policy, approval, credential, audit,
and isolation dependencies. The agent can request a tool, but it cannot
choose those security inputs.

## Supported host profiles

The package includes profiles for:

| Host | Profile | Primary connection |
| --- | --- | --- |
| OpenCode | `opencode` | MCP gateway |
| OpenHands self-hosted | `openhands` | MCP gateway |
| Claude Code | `claude-code` | MCP gateway and SDK `PreToolUse` adapter |
| Cline | `cline` | MCP gateway |
| Gemini CLI | `gemini-cli` | MCP gateway through an extension |
| GitHub Copilot CLI/cloud agent | `github-copilot` | MCP gateway |
| Codex CLI | `codex-cli` | MCP server configured with `codex mcp` |

These profiles are integration labels, not identities or permissions. See
[`AgentHost`][agentic_security.integrations.AgentHost] and
[`HOST_PROFILES`][agentic_security.integrations.HOST_PROFILES].

## Create one gateway

Install the SDK and create the runtime in the application that owns the
identity and tools. The same gateway code works for every supported host:

```python
from agentic_security import AgentHost, GuardedRuntime, integration_for

# Build this from your application's authenticated request context.
runtime: GuardedRuntime = build_runtime_for_current_task()

integration = integration_for(AgentHost.CLAUDE_CODE, runtime)
integration.serve_stdio()
```

See the complete synthetic bootstrap in
[`examples/mcp_gateway.py`](https://github.com/tommycharade/aai-sec-sdk/blob/main/examples/mcp_gateway.py). It can be copied into
an application and the host profile changed without changing the security
runtime.

Equivalent named factories are available when an application wants an
explicit host dependency: `opencode_integration`, `openhands_integration`,
`claude_code_integration`, `cline_integration`, `gemini_cli_integration`,
`github_copilot_integration`, and `codex_cli_integration`.

The gateway implements the MCP `initialize`, `ping`, `tools/list`, and
`tools/call` methods. A call becomes an `ActionProposal` and is passed to
`GuardedRuntime.execute`; a tool is never invoked directly by the integration.
Unknown tools, malformed arguments, policy denials, missing approval, and
runtime failures remain fail-closed.

Add an optional JSON Schema to each `ToolDefinition` so the host can render a
useful tool contract. The runtime validator remains authoritative; the schema
is a discovery and user-experience contract, not a replacement for validation:

```python
ToolDefinition(
    name="read_record",
    handler=read_record,
    validator=validate_read_record,
    description="Read one synthetic record.",
    input_schema={
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
        "additionalProperties": False,
    },
)
```

For an HTTP MCP deployment, use the authenticated HTTP server framework of
your choice and pass each decoded JSON-RPC object to
[`McpGateway.handle`][agentic_security.integrations.McpGateway.handle]. Do not
put credentials or principals in the MCP request. Resolve them at the host
boundary when constructing the runtime.

The SDK also includes a framework-neutral WSGI application for a small
deployment or as a reference boundary:

```python
from agentic_security import AgentHost, McpHttpApplication, RuntimeSessionStore

sessions = RuntimeSessionStore()
# `session_token` was issued by your authenticated application boundary.
sessions.register(session_token, runtime, ttl_seconds=900)
application = McpHttpApplication(sessions, AgentHost.CLAUDE_CODE)
```

Put this application behind TLS and a production WSGI server. The SDK checks
POST, bearer authentication, session expiry/revocation, content length, JSON
shape, and response size; it does not invent IAM identities or terminate TLS.

## Host configuration

Each host should be configured to start the application entry point that
creates the runtime. A typical local MCP configuration is conceptually:

```json
{
  "mcpServers": {
    "agentic-security": {
      "command": "python3",
      "args": ["-m", "my_app.security_gateway"]
    }
  }
}
```

The exact filename and setting differ by host. Use the host's current MCP
configuration documentation for the final location:

- [OpenCode tools and MCP](https://opencode.ai/docs/tools)
- [OpenHands SDK and tools](https://docs.openhands.dev/sdk/index)
- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Cline hooks](https://docs.cline.bot/customization/hooks)
- [Gemini CLI extensions](https://google-gemini.github.io/gemini-cli/docs/extensions/)
- [GitHub Copilot hooks and MCP](https://docs.github.com/en/copilot/concepts/agents/hooks)
- [Codex CLI MCP](https://github.com/openai/codex/blob/main/codex-rs/README.md)

## Live Claude presence

The optional control-plane integration can show a Claude Code project as a
live agent. The MCP entry must provide the control-plane URL and inherit an
agent token from the launching environment:

```bash
export AAI_SEC_AGENT_TOKEN="short-lived-agent-token"
export AAI_SEC_CONTROL_PLANE_URL="https://control.example.test/api"
claude
```

The gateway registers its authenticated agent identity and project root,
sends bounded heartbeats, and marks itself offline on orderly shutdown or
heartbeat expiry. The control plane never accepts a principal from MCP JSON;
the authenticated token identity must match the registration identity. The
UI shows only live presence records and never displays the heartbeat bearer.

## Native actions and complete coverage

An MCP gateway governs only tools exposed through the gateway. It does not
automatically govern a host's built-in shell, filesystem, editor, Git, or
browser actions. For complete coverage, combine the gateway with the host's
pre-tool hook/plugin surface or run the entire agent in a sandbox whose
network, filesystem, process, and credential access are restricted.

This distinction is especially important for Cursor, Junie, and Aider-style
workflows where MCP may be available but does not necessarily replace every
built-in operation. Do not describe an MCP-only deployment as a complete
security boundary unless all consequential actions are routed through it.

## Extending to another host

The host-neutral contract is intentionally small:

1. Create the application-owned `ExecutionContext`.
2. Register `ToolDefinition` objects in a `ToolRegistry`.
3. Construct `GuardedRuntime` with explicit policy and operational controls.
4. Translate the host's tool-call event into an `ActionProposal`.
5. Call `runtime.execute(proposal)`.
6. Translate the typed `ExecutionResult` back to the host's response format.

Add a profile to `AgentHost` and `HOST_PROFILES` only when the host has a
stable, tested integration surface. Host adapters must never accept identity,
policy decisions, approvals, credentials, or isolation evidence from the
agent payload.

## Testing an integration

Every adapter should include:

- a `tools/list` contract test;
- an allowed call that proves the registered handler executes;
- an unknown-tool and malformed-argument test;
- a policy/approval denial test proving the handler has no side effect;
- an identity-injection test proving model fields cannot replace context;
- transport-size and malformed-JSON tests;
- a host smoke test using the host's own MCP or hook runner where available.

Run the repository gate with `make check` before publishing an integration.

::: agentic_security.integrations
    options:
      members:
        - AgentHost
        - HostProfile
        - HOST_PROFILES
        - McpGateway
        - McpHttpApplication
        - RuntimeSession
        - RuntimeSessionStore
        - HostIntegration
        - integration_for
        - opencode_integration
        - openhands_integration
        - claude_code_integration
        - cline_integration
        - gemini_cli_integration
        - github_copilot_integration
        - codex_cli_integration
        - IntegrationProtocolError
      show_source: false
