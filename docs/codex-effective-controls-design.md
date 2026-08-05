# Codex effective-control evidence

## Outcome

An endpoint can ask the running Codex app-server which configuration and
administrator requirements it actually resolved, compare a deliberately small
projection with the centrally compiled bundle, and report a short-lived result.
The control plane binds that result to the current server-owned managed bundle
and uses it as a Codex execution-authority prerequisite. The observation is
still evidence about the queried process at one instant: it is not an
installation claim, hardware attestation, or proof that an arbitrary later
action ran under unchanged settings.

This closes the gap between “the expected file exists” and “Codex loaded the
expected restrictions” for controls exposed by Codex's supported app-server
API. Controls not exposed with enough detail remain explicitly unverified.

The real-host acceptance harness now composes this process observation with
real `codex exec` turns. The 2026-08-05 run proved native command, patch, scope,
approval-routing and local guarded-MCP behavior, while the same process probe
truthfully reported `administrator-requirements-missing`. This is stronger than
synthetic protocol evidence but still cannot convert project configuration
into administrator authority. See [real Codex CLI acceptance](real-codex-cli-acceptance-harness.md).

## Trust boundaries and threat model

The endpoint probe crosses three boundaries:

1. The control plane supplies a reviewed `ManagedConfigurationBundle` and the
   expected SHA-256 of the Codex executable from approved release metadata.
2. The endpoint launches that exact executable directly, without a shell, and
   performs the documented app-server initialization and read-only configuration
   requests.
3. App-server output is untrusted and may contain credentials, project paths,
   commands, URLs, prompts, or attacker-controlled text.

The probe therefore:

- requires an absolute regular executable, rejects group/world-writable bytes,
  and verifies its complete SHA-256 at construction and immediately before
  every launch;
- requires an existing absolute project directory;
- uses an argument vector and never invokes a shell;
- has bounded time, response count, line size, and total output size;
- discards stderr and never includes app-server response bodies or errors in
  exceptions, logs, evidence, or telemetry;
- correlates exact request identifiers and rejects duplicate, missing,
  malformed, oversized, or error responses;
- constructs evidence only from an allowlisted projection; and
- includes the exact managed `bundleHash` inspected by the probe; and
- withholds every governed route that can return or consume execution authority
  when evidence is missing, stale, malformed, incomplete, or inconsistent with
  the current server-owned bundle.

The app-server process inherits the endpoint environment because it must resolve
the same user and managed configuration as Codex. That environment is trusted
deployment input and is never copied into evidence. A compromised endpoint,
administrator, Codex executable, or OS can forge local observations; device
attestation and endpoint integrity remain separate deployment controls.

## Content-minimised evidence

The safe result contains only:

- host and version;
- platform family;
- the SHA-256 identity of the managed bundle supplied to the probe;
- effective approval, sandbox, default-permission, and web-search modes;
- configured MCP server **names only**;
- SHA-256 digests and counts of loaded `PreToolUse` command hooks;
- administrator requirement booleans, enum allowlists, named permission-profile
  decisions, feature decisions, and network domain decisions;
- source categories for a fixed set of security settings, never source paths;
- expected and observed canonical projection digests;
- state, fixed reason codes, fixed control-gap identifiers, and a short expiry.

Raw JSON, origin keys, source file paths, command strings, MCP URLs/arguments,
headers, environment variables, and free-form host errors are never returned.

## Reconciliation

The expected projection is derived from the Codex `requirements.toml` artifact
inside the compiled bundle. Reconciliation is deny-first:

- missing administrator requirements produce `missing`;
- a mismatch in a projected requirement, active approval/sandbox/default mode,
  or required managed hook produces `conflict`;
- a successful match produces `enforced` only when every requested control can
  be proven by the supported API;
- requested MCP identity, command-rule, deny-read, or network details that the
  installed app-server version does not expose remain
  `deployment_required`, with fixed gap identifiers and no effective allows.

Configured MCP names are inventory, not proof that identity matching succeeded
or that a server connected. The probe does not call `mcpServerStatus/list`
because doing so can initialize external servers and cause network/process side
effects. Live MCP acceptance remains a separate, explicitly authorized test.

## Server-owned execution authority

The endpoint cannot grant itself authority by submitting `state=enforced`.
Every read derives posture again from strongly read server state:

1. load the current deployment `managedHost` target;
2. validate the exact closed evidence schema;
3. compare `bundleHash`, `hostVersion`, and `platform` with that target;
4. apply the server clock to `verifiedAt` and `expiresAt`; and
5. accept the endpoint's reconciled state only after the identity and freshness
   checks pass.

| State | Server interpretation | Execution authority |
| --- | --- | --- |
| `enforced` | Exact current target, fresh evidence, and no unresolved probe control | Available if all other gates pass |
| `missing` | No current target or no valid process evidence | Blocked |
| `conflict` | Bundle, host version, platform, or process projection differs | Blocked |
| `stale` | Evidence is future-dated or expired | Blocked |
| `deployment_required` | The supported API cannot prove every requested control | Blocked |

The heartbeat response exposes a server-owned `controlState` with
`executionAllowed`, fixed `authorityBlockers`, and a content-free
`nativeEffectiveControls` projection. The enrolled client treats a missing or
false `executionAllowed` as a dependency failure. Governed policy and decision
routes independently repeat the native-control check; the UI is never the
enforcement boundary.

The authenticated `managed-package` route deliberately remains available when
native evidence alone is blocking execution. This is the recovery channel for
installing the exact assigned package. Runtime attestation, rollout selection,
tenant/agent identity, emergency stop, and incident quarantine still apply, so
the repair exception cannot obtain another deployment's package or override
response controls.

## Claude Code limitation

Claude Code documents interactive `/status`, `/permissions`, `/hooks`, and
`/mcp` diagnostics but no supported machine-readable effective-configuration
interface equivalent to Codex app-server. The SDK must report this capability as
unavailable and continue to rely on protected-file measurement plus live action
acceptance. It must not scrape terminal output or claim process-loaded evidence.

## Verification

Tests use a synthetic app-server executable and synthetic values. They cover a
matching projection, absent requirements, drift, stale evidence, wrong binaries,
malformed/oversized/duplicate/error responses, timeouts, secret-bearing fields,
cleanup, bundle substitution, a forged `enforced` state, server-clock expiry,
governed-route denial, and repair-package availability. A live Kratos check is
expected to report `missing` until an
administrator installs the compiled `/etc/codex/requirements.toml`; that is a
truthful negative acceptance, not a test failure.
