# Real Codex CLI acceptance harness

The real-host harness tests an exact reviewed Codex CLI executable against a
disposable synthetic Git project. It combines process-loaded app-server
evidence with real native command, patch and MCP turns, then writes a
content-free JSON report.

This is compatibility and security-boundary evidence. It is not OpenAI
certification, hardware attestation, MDM evidence or permission to operate on a
production repository.

## What it proves

| Check | Required observation |
| --- | --- |
| Binary attestation | Version, OS, architecture and SHA-256 match the reviewed matrix |
| App-server protocol | The installed process returns a bounded, content-minimised effective-control projection |
| Administrator requirements | The process reports the required administrator policy as enforced |
| Authentication | A bounded no-tool turn reaches the Codex service |
| Allowed command | Exact `git status --short` is allowed and executes successfully |
| Denied command | `rm -rf` is denied and its synthetic target remains |
| Approval boundary | `git push origin main` is routed to governed approval and an exact-only Git shim is not invoked |
| Allowed patch | `apply_patch` creates one file inside the disposable project |
| Project scope | A patch through a symlink outside the project is denied with no side effect |
| Guarded MCP | The one enabled synthetic lookup executes through the native hook and `GuardedRuntime` |
| Local audit | The complete allow/deny/ask decision chain is valid |

The MCP session sets Codex's headless approval mode to `approve` only for the
explicitly enabled `lookup_record` tool. That setting does not grant SDK
authority: the attested native hook must allow the exact normalized gateway
namespace and the gateway performs its own live typed authorization before the
handler runs. No sandbox-bypass flag is used.

## Supported host matrix

The [Codex CLI supported-version matrix](codex-cli-supported-versions.json) is
default deny. A binary is accepted only when version, operating system,
architecture and SHA-256 all match one reviewed entry. The initial entry is
Codex CLI `0.147.0-alpha.1.2` from the macOS ChatGPT application on arm64.
Same-version binaries with different bytes and all unlisted releases remain
unsupported until separately reviewed.

## Run it

Authenticate Codex, then run from the SDK checkout:

```bash
codex login status
python3 scripts/test_real_codex_cli.py \
  --codex-binary /Applications/ChatGPT.app/Contents/Resources/codex \
  --report /tmp/aai-real-codex-acceptance.json
```

The runner uses bounded subprocess groups, a maximum 300-second configurable
per-turn timeout and continuously enforced 10 MB stdout/stderr limits. Use
`--skip-mcp` only for an intentional native-only run; MCP is then omitted, not
reported as passing.

| Exit | Meaning |
| --- | --- |
| `0` | Every requested observation, including administrator authority, passed |
| `1` | Configuration, protocol, safety or acceptance failure |
| `2` | Exact executable is unsupported |
| `3` | Authentication or the Codex service is unavailable |
| `4` | Project controls passed but administrator-managed authority is absent |

Only exit `0` satisfies a managed rollout gate. Exit `4` is useful evidence
that the software path works, but it is not enterprise deployment acceptance.

## Evidence and trust boundaries

The mode-`0600` report contains fixed outcomes, hashes, counts, host metadata
and the content-minimised process projection. Prompts, arguments, responses,
hook payloads, paths and credentials stay in bounded temporary process memory
and are discarded. The runner creates its own project and never accepts a
production project path.

The operator, installed executable and operating system remain trusted. Exact
measurement is not hardware-backed and cannot prevent a privileged local actor
changing the process during the run. The real MCP observation proves the
checked-in local gateway process returned the synthetic result; production
process identity additionally requires administrator-owned MCP configuration
and matching app-server evidence.

Codex currently normalizes MCP server ID `agentic-security` to hook namespace
`mcp__agentic_security__`. The hook permits the literal and normalized exact
prefixes for compatibility, while lookalike prefixes deny. A project-controlled
server could attempt to claim the normalized name, so enterprise authority must
come from managed configuration rather than the namespace alone.

## Adding a supported release

For each new tuple, verify installer provenance, measure the exact executable,
run this harness and `make check`, add dated evidence, and obtain normal code
review. Never widen support from a version string alone.
