# Managed host configuration

Project files are useful for evaluation, but they are not an enterprise
enforcement boundary. A user or process with repository access can remove
them, and an alternate launch can avoid them. The managed-configuration API
compiles one typed policy intent into administrator-owned Claude Code or Codex
configuration and keeps desired state separate from observed state.

## Security contract

`ManagedConfigurationCompiler.compile` is a pure operation. It returns:

- deterministic files and SHA-256 digests;
- the target host, version, operating system, policy ID, and policy version;
- allowed, denied, and approval-required action summaries;
- capability-level coverage identifying native versus SDK enforcement; and
- a bundle digest binding the complete intent and every artifact.

It does **not** install privileged files or prove that a host loaded them.
Endpoint management, MDM, or a separately authenticated host service must
deploy the artifacts atomically and protect them from modification.

The optional [managed endpoint deployment](managed-endpoint-deployment-design.md)
package binds those artifacts to exact administrator-installed executables and
provides preflight, restrictive atomic replacement and complete rollback. The
package is authoritative only when its expected digest, bundle, host and
platform arrive through authenticated endpoint management.

`reconcile_effective_authority` accepts endpoint-owned evidence only. Missing,
expired, future-dated, wrong-host, or mismatched evidence produces no effective
allows. Duplicate action expressions resolve in this order:

```text
deny > approval required > allow
```

Conflicts remain visible for operator resolution even though execution fails
closed.

## Claude Code output

For Claude Code 2.1.191 or later, the compiler emits:

- endpoint-managed `managed-settings.json` with managed-only permission rules,
  bypass mode disabled, fail-closed remote refresh, and a managed `PreToolUse`
  hook; and
- exclusive `managed-mcp.json` containing only reviewed, credential-free MCP
  definitions.

Documented paths are:

| Platform | Managed settings directory |
| --- | --- |
| macOS | `/Library/Application Support/ClaudeCode/` |
| Linux/WSL | `/etc/claude-code/` |
| Windows | `C:\Program Files\ClaudeCode\` |

Claude server-managed settings currently apply uniformly to the organization,
not per AAI group, and cannot distribute `managed-mcp.json`. Use endpoint
management when per-device/group assignment or exclusive MCP deployment is
required. The control plane must display the effective source because
server-managed and endpoint-managed sources occupy the same highest tier but
do not merge. See the [Claude managed-settings precedence and fail-closed
behavior](https://code.claude.com/docs/en/server-managed-settings) and
[managed MCP deployment](https://code.claude.com/docs/en/managed-mcp).

## Codex output

For Codex 0.138.0 or later, the compiler emits system `requirements.toml` with:

- allowed approval and permission profiles;
- a conservative managed default profile;
- hooks pinned on and unmanaged hooks excluded;
- a managed `PreToolUse` hook at an absolute deployment-owned path;
- restrictive command rules;
- MCP server name-and-identity allowlists;
- filesystem deny-read requirements;
- browser, computer-use, and plugin controls; and
- an experimental managed network-domain allowlist when domains are supplied.

The requirements file belongs at `/etc/codex/requirements.toml` on Unix or
`%ProgramData%\OpenAI\Codex\requirements.toml` on Windows. Codex enforces the
requirements but does not distribute hook executables. Endpoint management
must install the referenced hook and verify its digest. See the [Codex managed
configuration reference](https://learn.chatgpt.com/docs/enterprise/managed-configuration).

The Codex network requirement is explicitly experimental. Roll it out to a
version- and OS-pinned canary before broad use. On native Windows, managed
deny-read does not cover shell subprocess reads; use OS isolation and an
approved launch profile as additional boundaries.

## Example

```python
from agentic_security import (
    AgentHost,
    ControlPlaneAgentClient,
    ManagedConfigurationCompiler,
    ManagedConfigurationSource,
    ManagedMcpServer,
    ManagedPlatform,
    ManagedPolicyIntent,
    NativeActionDecision,
    NativeActionRule,
    ObservedManagedConfiguration,
    measure_managed_configuration,
    reconcile_effective_authority,
)

intent = ManagedPolicyIntent(
    policy_id="engineering-safe",
    policy_version=4,
    action_rules=(
        NativeActionRule("Read", NativeActionDecision.ALLOW, "repository reads"),
        NativeActionRule("Bash(rm *)", NativeActionDecision.DENY, "destructive command"),
    ),
    mcp_servers=(
        ManagedMcpServer("github", url="https://api.githubcopilot.com/mcp/"),
    ),
)
bundle = ManagedConfigurationCompiler().compile(
    intent,
    host=AgentHost.CLAUDE_CODE,
    host_version="2.1.211",
    platform=ManagedPlatform.MACOS,
    hook_command="/opt/aai-security/hooks/claude-policy",
)

# Deployment writes the files with administrator ownership, then the endpoint
# reports what the running host actually loaded. Desired state is not enough.
observed = ObservedManagedConfiguration(
    host=AgentHost.CLAUDE_CODE,
    bundle_hash=bundle.bundle_hash,
    source=ManagedConfigurationSource.ENDPOINT_MANAGED_FILE,
    verified_at=100.0,
    expires_at=400.0,
)
authority = reconcile_effective_authority(bundle, observed, now=120.0)
assert authority.allowed_actions == ("Read",)
```

For an enrolled AWS agent, report only freshly measured protected files:

```python
import time

client = ControlPlaneAgentClient(
    "https://control-plane.example",
    "synthetic-short-lived-agent-session",
    agent_id="claude-example",
    project_root="/workspace/example",
    deployment_id="deployment-example",
    aws_agent_session=True,
    managed_configuration_provider=lambda: measure_managed_configuration(
        bundle,
        source=ManagedConfigurationSource.MDM,
        now=time.time(),
    ),
)
client.heartbeat("synthetic-short-lived-agent-session")
```

Policy-signing rotation uses a schema-v2 managed package and
`measure_managed_deployment_package` instead of measuring only the native
bundle. That verifier additionally requires the exact root-owned trust file and
adds `policyTrustBundleSha256` to heartbeat evidence. See
[managed policy-signing trust convergence](policy-trust-convergence-design.md).

The verifier is read-only and supports root-owned macOS/Linux managed files.
It opens files without following symlinks, verifies regular-file type, root
ownership, restrictive write permissions, a one-megabyte bound and exact
reviewed bytes. Windows requires an ACL-aware deployment adapter and therefore
fails closed in this provider-neutral verifier. File equality still does not
prove that the host process loaded the file; the live action tests below remain
mandatory.

Never put credentials in an MCP definition. Use per-user OAuth, environment
expansion, a credential helper, or the SDK credential broker. The generated
MCP identity does not inspect arbitrary environment variables, so deployment
policy must constrain those separately.

## Deployment verification

For each managed endpoint:

1. install every generated artifact and hook using an administrator-owned
   channel;
2. protect file ownership and permissions;
3. restart the host and inspect its effective managed source;
4. calculate the bundle hash from the exact installed bytes;
5. send short-lived, authenticated evidence to the control plane;
6. test an allowed action, a denied action, an approval-required action, and an
   unapproved MCP server; and
7. delete or weaken a local project file and prove effective authority does not
   change.

The SDK supplies compilation, protected-file measurement, authenticated
heartbeat ingestion and desired-versus-observed reconciliation. It does not
write privileged files or control host launch. The separate operator CLI can
perform an explicit root installation after deployment-owned digest and hook
verification; it is not invoked by the SDK or agent. When a managed bundle is
assigned, the control plane blocks effective-policy and other governed agent
routes until exact fresh evidence arrives. The UI must continue to label the
deployment blocked until live action probes additionally prove that the host
loaded and enforced the managed source.
