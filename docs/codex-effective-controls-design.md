# Codex effective-control evidence

## Outcome

An endpoint can ask the running Codex app-server which configuration and
administrator requirements it actually resolved, compare a deliberately small
projection with the centrally compiled bundle, and report a short-lived result.
The result is evidence about the queried process at one instant. It is not an
installation claim, a binary provenance claim, or proof that a later action was
executed under the same settings.

This closes the gap between “the expected file exists” and “Codex loaded the
expected restrictions” for controls exposed by Codex's supported app-server
API. Controls not exposed with enough detail remain explicitly unverified.

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
- withholds every intended allow when evidence is missing, stale, malformed,
  incomplete, or inconsistent with the compiled bundle.

The app-server process inherits the endpoint environment because it must resolve
the same user and managed configuration as Codex. That environment is trusted
deployment input and is never copied into evidence. A compromised endpoint,
administrator, Codex executable, or OS can forge local observations; device
attestation and endpoint integrity remain separate deployment controls.

## Content-minimised evidence

The safe result contains only:

- host and version;
- platform family;
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
and cleanup. A live Kratos check is expected to report `missing` until an
administrator installs the compiled `/etc/codex/requirements.toml`; that is a
truthful negative acceptance, not a test failure.
