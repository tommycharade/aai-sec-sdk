# Real Codex CLI acceptance evidence — 2026-08-05

**Result:** 10 passed, 0 failed, 1 deployment blocker

**Installed host:** Codex CLI `0.147.0-alpha.1.2`, macOS arm64 from the ChatGPT application

**Scope:** disposable synthetic Git project and content-free evidence

## Observed result

| Check | Result | Fixed observation |
| --- | --- | --- |
| Exact binary attestation | Pass | `accepted` |
| App-server protocol | Pass | bounded content-free process observation |
| Administrator-managed requirements | Blocked | `missing` |
| Codex authentication | Pass | `available` |
| Allowed command | Pass | allowed and executed |
| Destructive command | Pass | denied without side effect |
| Approval-required command | Pass | governed route, no side effect |
| In-project patch | Pass | confined patch executed |
| Symlink escape patch | Pass | denied without outside-project side effect |
| Guarded MCP lookup | Pass | connected local guarded execution |
| Local audit chain | Pass | complete valid decision chain |

The runner exited `4`, not `0`, because this device has no administrator-owned
Codex requirements file. That is a real P0 deployment-authority blocker. The
SDK does not silently create privileged machine policy from a project checkout.

The measured executable was `275653216` bytes with SHA-256
`9f6748b4ab10ffc92c28b9ccedae89e61a302bbc011df7d276ee38f55906e481`.
The report was mode `0600`; inspection found no home-directory path, prompt
marker, synthetic record ID, bearer material or token text.

## MCP integration defect found and resolved

The real host exposed `agentic-security` to the hook as
`mcp__agentic_security__lookup_record`. The shipped hook previously permitted
only the unnormalized hyphenated namespace, so it denied the real gateway. The
hook now supports both exact forms and adversarial tests deny near-prefix
lookalikes.

Headless `codex exec` also cancels MCP calls that need interactive approval.
The harness now configures server-level approval for only the explicitly
enabled synthetic lookup tool. The native hook and `GuardedRuntime` still make
independent allow decisions, and the successful run retained the six-event
`allow`, `deny`, `ask`, `allow`, `deny`, `allow` audit chain.

## Remaining work

Install the compiled `requirements.toml` through the approved administrator or
MDM channel, then rerun the exact command in the [acceptance harness](real-codex-cli-acceptance-harness.md).
An enterprise acceptance run must exit `0`. Malformed/upgrade/bypass tests,
approved-launch enforcement and physical endpoint ownership evidence remain
deployment-owned P0 work.
