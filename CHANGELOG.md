# Changelog

- Added fail-closed Codex CLI native-tool enforcement using the documented
  `PreToolUse` hook. Project onboarding now installs a required SDK MCP gateway
  and a secret-free native hook; Bash, `apply_patch`, MCP and unknown-tool
  behavior are adversarially tested; native decisions export content-minimised
  `codex_native` evidence. Because Codex does not currently support an
  approval-producing hook result, approval-rule matches are audited and denied
  with an explicit governed-MCP route. Documentation distinguishes pilot
  project trust from enterprise-managed `requirements.toml` deployment.
  Current-CLI acceptance also records that `--ignore-user-config` bypasses the
  project hook layer; enterprise launch controls must prohibit that flag and
  verify the managed hook requirement independently.
  Allowed Codex calls now use the documented zero-output success contract;
  bare allow responses no longer create a host-reported, fail-open hook error.
- Minimized Claude and Codex native-hook persistence so raw commands,
  arguments, file paths and working directories are replaced by stable digests
  before local JSONL or remote replication.
- Bound enterprise bootstrap exchange, cached credentials, bearer sessions and
  every authenticated agent request to the registered immutable project root.
  A credential copied from another checkout or an agent whose registered scope
  changed now fails closed; legacy unscoped cache records are invalidated.
- Hardened native shell-entry detection across POSIX and Windows command forms:
  entry-point names are case-insensitive and executable suffixes such as
  `.exe`, `.cmd`, `.com`, and `.bat` cannot disguise `sh`, `bash`, or another
  prohibited command interpreter.
- Hardened `JsonlAuditSink` against path substitution. Its directory, audit
  file and lock file are opened descriptor-relative without following
  symlinks, and opened objects are verified as regular files before reading,
  locking, appending or validating the chain.
- Hardened native command and patch matching: allow regexes must cover the
  complete shell command, deny/approval regexes search every component, Codex
  move destinations receive the same root-confinement check as source paths,
  and malformed central allow patterns fail closed before hook construction.
  Claude native writes and Codex patches now deny all targets under `.claude`,
  `.codex`, and `.git`, plus `.mcp.json`, so agents cannot rewrite their own
  policy, hook, MCP, repository execution configuration, or local evidence
  state.
  Native allow rules now also reject newlines, command substitution, shell
  lists, pipelines, redirections and subshell syntax even if a custom regex
  would match them; shipped whitespace rules use spaces/tabs rather than `\s`.
  Codex patch authorization now grants Add, Update, Delete, and Move separately:
  `Write` permits Add, `Edit` permits Update/Delete, and Move requires both.
  Allowed Claude commands now require the live event working directory to
  resolve inside the approved project root. Codex applies the same check to
  both event and tool-level working-directory scopes.
  Native decision evidence now carries a content-minimised action digest so
  activation proof can bind each result to the exact prompted check and its
  working-directory scope. Claude evidence projects the authority-bearing Bash
  command or resolved Read path, so optional presentation fields cannot create
  false positives or make the guided proof unreliable. Codex exact-name rules
  now reject Bash, patch and process tools that require argument-aware
  authorization instead.
  Native command allow paths reject parameter-expanded executables such as
  `$SHELL -c`, and the AWS effective-policy route rejects ambiguous group
  membership before returning any policy. New agents require a project root;
  legacy empty scope can be repaired once and then becomes immutable through a
  conditional write. Patch-relative paths now resolve from the live Codex hook
  working directory, preventing outside-root and protected-subdirectory scope
  confusion. Claude and Codex native writes reject case variants of every
  protected authority path, including on case-insensitive macOS filesystems.
  Bounded JSONL audit reserves capacity for the linked effective
  denial so a failed required replica cannot leave local evidence ending in a
  provisional allow, while small explicit file limits retain at least half of
  their capacity for normal events. Provider-neutral effective-policy lookup
  now rejects multiple group memberships even when they reference one policy,
  matching verification and AWS fail-closed semantics. Python-only named
  Unicode regex escapes are rejected to keep browser and SDK policy semantics
  identical at the command boundary.
- Unified command-pattern validation across the enterprise API, legacy local
  policy files, Claude and Codex hook startup, and the core matchers. Patterns
  are count/length bounded and reject backreferences, lookarounds and
  quantified groups, wildcard repetition, and ambiguous overlapping repetition
  associated with catastrophic backtracking, even when overlapping repeats are
  separated by consumable characters; oversized command input denies
  before matching. Existing patterns that use `.*` must migrate to a bounded
  character class around a mandatory delimiter, such as `curl[^|]+\\|`.
  Audit-directory, permission and
  corrupt-chain startup failures now emit an explicit host denial instead of
  crashing a hook that the host could otherwise treat as non-authoritative.
  A final setup boundary converts unexpected provider/filesystem adapter
  exceptions into the same explicit denial for both Claude and Codex.
  Source-checkout onboarding now pins hook and MCP imports to the adjacent SDK,
  preventing a missing global installation from disabling host enforcement.
  Oversized regex repeat bounds are normalized into closed policy validation.
  Quoted shell-control syntax in nested shell/eval arguments is no longer
  eligible for native allow. Shell/eval command entry points are rejected even
  when their nested command contains no punctuation; `source`/`.` file
  execution is rejected as the same hidden parsing boundary. Malformed direct
  Codex hook API payloads now return a structured denial. UI policy writes enforce whole-list pattern
  limits, and failed required audit replication records a linked local
  effective-denial event that supersedes the provisional decision.
  The local coverage target now reports two-decimal precision and propagates a
  failed threshold instead of allowing rounding or later checks to mask it.
  Mutation evidence now includes the native Claude/Codex hooks and shared
  command-pattern validator as a separately thresholded security component.
  Central Claude and Codex policy now require an explicitly false emergency-stop state;
  patch text/target processing and per-invocation local audit-chain scans are
  bounded before untrusted work. A full local chain fails closed for explicit
  export/rotation instead of approaching the host timeout or dropping evidence.
  The shipped offline fallback no longer admits arbitrary Git option tails or
  project test runners; only narrowly enumerated, non-writing inspection forms
  are eligible for native allow, preventing output flags from overwriting hook,
  policy, MCP, or audit state.
  Agent verification responses now include the consistently read effective
  policy ID/version, allowing consoles to bind activation to the exact host,
  deployment, agent, group, and policy revision rather than stale inventory.
  The local Claude policy harness now binds hook subprocess imports to the
  selected SDK checkout, preventing an ambient editable install from replacing
  the implementation under test.
- Made hosted agent verification details truth-preserving: missing, offline,
  expired, healthy, and conflicting-policy states now return distinct fixed
  messages, and multiple policy-group assignments fail the UI's exactly-one
  policy check instead of being treated as valid. Tenant list pagination is
  strongly consistent for policy assignment, complete within fixed page and
  item limits, and fails closed at either bound. Operational decisions now use
  a TTL-backed, bounded reverse-chronological index so high-volume history
  cannot permanently take the dashboard offline or masquerade as exact totals.
- Added an identity-scoped host session cache so Claude native hooks, Codex and
  the MCP gateway share heartbeat-rotated AWS agent bearers beyond the original
  15-minute session. The reference cache is outside project configuration,
  atomic, user-only, bounded and fail-closed for symlinks, unsafe permissions,
  foreign ownership, malformed content and expiry. Repeat enterprise
  onboarding now preserves fail-closed AWS mode, direct-checkout scripts load
  their adjacent SDK source, Codex secures the session before changing project
  TOML, record reads are allocation-bounded, and unsupported non-POSIX storage
  fails closed pending an ACL-aware credential adapter.
- Fixed AWS operator mutation RBAC for the string-shaped `cognito:groups`
  claims emitted by API Gateway. Bounded single, JSON-array, and
  bracket/comma projections now normalize to exact role names, while malformed,
  oversized, and lookalike claims continue to fail closed.
- Added authenticated, content-minimised host decision evidence for enrolled
  Claude hooks and SDK/MCP runtimes. The AWS control plane now derives policy
  and identity metadata server-side, idempotently indexes allowed, denied, and
  approval-required outcomes, and supplies source-backed dashboard totals while
  rejecting prompts, commands, paths, arguments, outputs, credentials, and
  caller-selected policy claims.
- Added a guided first-governed-action proof to Claude Code onboarding. After
  liveness and policy verification, operators can run one safe allowed read,
  one approval-bound command, and one blocked destructive command and see the
  three actual host outcomes appear for the enrolled agent. Codex native
  shell/file evidence is explicitly identified as unavailable rather than
  represented by fixture data.
- Fixed fresh-trial activation by implementing tenant-safe project and
  deployment registration, deriving agent ownership from the selected
  deployment, rejecting identity replacement, and requiring a real runtime
  heartbeat before an enrolled agent is reported connected. The enterprise UI
  now prepares the project, deployment, safe-policy group, and desired template
  as one guided pilot foundation before showing Claude Code or Codex setup.
- Added a first-class enterprise approval queue instead of routing held actions
  to a read-only audit page. Enrolled agents can submit bounded, exact-action
  requests; authorized operators can approve or deny them with a recorded
  rationale; and approved grants remain agent/tool/proposal/task/principal/hash
  bound, short-lived, single-use, fail-closed on expiry or replay, and auditable.
- Added a real reversible tenant-wide emergency stop to the AWS control plane.
  The dashboard now reports the durable state, every agent effective-policy
  request fails closed while it is active, newly enrolled agents are covered,
  narrower stop scopes are preserved, and activation/clear transitions are
  operator-authorized and audited.
- Rebuilt Integrations as a three-stage connection journey for Claude Code and
  Codex CLI: define scope, install secret-free project configuration, and prove
  the live heartbeat/policy binding. Added a hardened project-scoped Codex
  installer, stopped serializing the agent bearer through `codex mcp add`, and
  made the Copilot profile explicitly admin-managed until a restart-safe
  credential broker is available.
- Rebuilt Rollouts & health around operator intervention: a source-derived
  posture, prioritized blocker queue and deployment health matrix now precede
  diagnostics, while agent/session inventories and compliance evidence use
  progressive disclosure. Corrected the UI drift contract to the camel-case
  deployment configuration fields returned by both supported control planes.
- Reworked Deployments & rollout into a live operator command view. Fleet
  readiness and the next-action queue are now derived from agent health,
  configuration assignment, drift, alerts and emergency-stop state; the
  deployment inventory shows coverage and rollout status at a glance and moves
  rollback and emergency stop into a deliberate secondary action menu.
- Added bounded agent performance telemetry end to end. The runtime reports
  content-free action outcomes, cost units, and latency aggregates through
  authenticated heartbeats; the enterprise control plane validates and stores
  only the fixed projection; and the UI now surfaces reporting coverage and
  per-agent/group performance without inventing values.
- Removed misleading dashboard and policy-editor metrics: decision cards now
  show source-backed totals, the policy editor shows draft/applied state and
  real assignment impact, and freshness labels use the control-plane timestamp
  rather than implying that every snapshot was just checked.
- Reduced onboarding friction by placing advanced Claude Code hook, generated
  settings, and native-tool controls behind an explicit expandable section;
  central enrollment and verification are now the first-run focus.
- Surfaced real deployment availability SLO data in group detail and made the
  absence of performance telemetry explicit instead of implying coverage that
  the agent contract does not provide.
- Made live host onboarding fail clearly when no registered deployment is
  available; the UI no longer presents a synthetic `deployment-local` boundary
  outside simulation mode.
- Added page-shaped fleet loading states and durable group deep links so a
  retry never renders an empty screen and group context survives refreshes and
  handoffs.
- Added an explicit fleet recovery state with retry and access guidance when
  live enterprise fleet data cannot be loaded; missing control-plane data is no
  longer presented as an empty screen or silently replaced with fixtures.
- Refined the Enterprise fleet landing surface with a posture strip for groups,
  enrolled agents, current health, and unassigned coverage before the group
  table.
- Added a contextual Overview next-action panel for uncovered agents, stale
  health, and held high-risk actions, plus a persistent Connect agent action in
  the authenticated top bar to reduce onboarding friction.
- Improved the Audit trail with decision summaries, search and decision filters,
  explicit empty states, and a clear redacted-evidence boundary. The UI no longer
  implies that the approval count is itself an actionable approval workflow.
- Tightened AWS enrollment verification so the UI reports an agent as ready
  only when its heartbeat is current, its policy group resolves to a real
  policy, and no emergency stop is active; record existence alone no longer
  produces a false "connected" state.
- Made the overview, trial banner, notifications and fleet fixtures agree on
  the same enrolled-agent source of truth; the trial action now changes from
  **Connect an agent** to **Manage agents** after enrollment.
- Made host onboarding a verifiable activation flow: Claude Code now has the
  same central deployment/group enrollment path as Codex CLI, generated
  commands use the selected agent identity, and the UI can verify live
  registration, heartbeat, policy assignment, and emergency-stop state.
- Added a direct **View agent** handoff after successful verification, plus
  explicit copied feedback for generated onboarding commands, so operators can
  move immediately from setup to the agent's live health and policy view.
- Reworked the Skills & MCP page into an operational catalog with search,
  enabled counts, policy reach, and affected-agent impact beside every
  registered resource.

All notable changes to this project will be documented here.

The project follows Semantic Versioning after `1.0.0`. Before `1.0.0`, public APIs may change while the design is validated, but breaking changes will still be called out explicitly.

## 1.0.1 - 2026-07-26

This corrective release makes the published evidence bundle independently
verifiable. Mutation evidence is included before checksum generation, release
CI publishes and then downloads the exact GitHub Release bundle for clean
verification, and provenance is produced only from pushed version tags.

The runtime now exposes failed idempotency persistence on timeout, cancellation,
and handler-failure outcomes. Validated arguments are recursively immutable in
authorization facts and handlers receive defensive copies. Deployment evidence
requirements for consequential workloads are documented explicitly.

## 1.0.0 - 2026-07-26

The first stable Apache-2.0 release. The SDK provides a typed, fail-closed
execution boundary for agentic tool calls, with explicit host-owned identity,
policy, approval, credential, isolation, budget, idempotency, timeout, and
audit controls. Production deployments must still provide durable adapters,
real sandboxing where required, authenticated IAM/policy services, and domain
authorization.

## Unreleased

- Fixed the release gates for core-only environments: optional AWS/PostgreSQL
  imports now type-check without forcing provider dependencies, mutation tests
  include the AWS Lambda contract fixture, and local Docker isolation evidence
  uses Docker's immutable content-addressed image ID. Trial policy construction
  also keeps the AWS provider import behind the deployed Lambda boundary, and
  public SDK CI no longer assumes the separate private UI checkout is present.

- Added a keyboard-accessible global command palette: press **⌘K** on macOS or
  **Ctrl+K** on other platforms to jump between the console's primary surfaces.
- Made the command palette entity-aware so operators can find enrolled agents,
  policy groups, policies, and deployments with their operational context.
- Made entity results deep-linkable: reopening an agent, group, or policy URL
  restores its detail view instead of dropping the operator at a generic list.
- Added pending-state feedback to policy saves and group membership, policy,
  and emergency-stop actions to prevent ambiguous double submissions.
- Added responsive scroll guidance for dense fleet, agent, and deployment
  tables so narrow screens do not make operational columns appear missing.
- Added a truthful control-plane freshness indicator with Live, Syncing, and
  Stale states; transient poll failures retain the last known snapshot instead
  of silently presenting an empty fleet.
- Made primary console destinations bookmarkable and browser-history aware,
  removed the repeated trial banner from operational pages, and simplified the
  agent directory to one explicit inspection action per row.
- Clarified the enterprise console information architecture: group and agent
  management now lives under **Enterprise fleet**, while deployment operations
  live under **Deployments & rollout** without duplicated group controls.
- Added a tenant-scoped trial summary and activation banner so new workspaces
  can see their remaining trial time and reach first-agent onboarding directly.
- Made first-run signup resilient to the Cognito/post-confirmation provisioning
  race: the console retries only the expected entitlement gap and explains
  workspace setup instead of exposing a raw infrastructure 403.
- Sharpened the public landing-page promise around the first user outcome:
  secure Claude Code before production, then expand the same controls to other
  coding agents.
- Fixed Codex CLI presence registration to preserve `codex-cli` as the
  authenticated host identity instead of hard-coding Claude Code, and made the
  UI command explicit about its short-lived enrollment session requirement.
- Corrected the generated Codex command to the installed `codex mcp add`
  syntax and documented its current user-scoped configuration boundary.
- Completed the enrollment handoff so the UI exchanges the one-time bootstrap
  secret for the short-lived agent session that the gateway actually accepts.
- Added bounded AWS agent-session renewal: live Claude Code and Codex gateways
  rotate their bearer in memory before expiry, while the previous bearer is
  immediately rejected and missed heartbeats remain fail-closed.
- Refined the enterprise fleet journey so operators land on a clean groups
  index, open a focused group detail view for health and membership actions,
  and access group creation only when needed.
- Rebuilt the Agents page as a searchable operations directory with health
  metrics, policy coverage, heartbeat freshness, filtering and an agent
  inspector for verification and emergency-stop actions.
- Split **Deployments & rollout** into deployment-first, **Rollouts & health**,
  and **Templates & setup** modes so common rollout actions are not buried
  beneath configuration and diagnostic forms.
- Fixed enterprise Claude Code onboarding to generate executable `env
  NAME=VALUE` hook commands, preserved integer policy versions across the AWS
  DynamoDB JSON boundary, and added an initial AWS agent heartbeat before the
  MCP gateway serves tools. Added real Claude Code acceptance evidence for
  native hook decisions, central MCP policy enforcement, heartbeat and
  emergency-stop recovery.
- Added AWS control-plane template assignment, rollout state, drift tracking,
  rollback and deployment/group emergency-stop routes used by the enterprise
  UI, with live canary-to-active acceptance evidence.
- Added AWS deployment adapters for DynamoDB-backed idempotency, typed STS
  session policies, restrictive Docker execution, and a live control-plane
  smoke test covering multi-process claims, emergency-stop enforcement, WORM
  audit retention, and SNS/SQS alert delivery.
- Added an encrypted SQS security-alert queue with a dead-letter queue to the
  AWS control-plane reference stack.
- Added the 1.1 integration foundation: bounded WSGI MCP transport,
  application-authenticated expiring runtime sessions, bounded response
  serialization, and deployment bootstrap guidance for all supported hosts.
- Added atomic live policy replacement for long-running runtimes and central
  enterprise stop enforcement at deployment, group, and agent scope.
- Added authenticated agent enrollment verification with explicit readiness
  checks and a redaction-safe enterprise audit evidence index.
- Added audited group-policy reassignment and corresponding enterprise UI
  controls; policy records remain immutable and take effect on runtime refresh.

## 1.1.0 - 2026-07-26

- Added a Claude Code `PreToolUse` hook adapter with deterministic ordered
  rules, deny-by-default behavior, native allow/ask/deny responses, path and
  command matchers, and redaction-aware audit output.
- Added a complete Claude Code project example covering `.claude/settings.json`,
  native tool protection, MCP registration, verification commands, and the
  boundary between hook-governed host actions and SDK-owned MCP actions.
- Added an extensible MCP integration layer with host profiles and a
  dependency-free stdio gateway for OpenCode, OpenHands self-hosted, Claude
  Code, Cline, Gemini CLI, GitHub Copilot CLI/cloud agent, and Codex CLI.
- Added bounded HTTP/WSGI transport with bearer-session authentication,
  runtime session expiry/revocation, request/response size limits, and
  fail-closed malformed input handling.
- Added JSON Schema discovery to `ToolDefinition` and integration contract,
  adversarial transport, session, and model-identity tests.
- Added integration documentation and generated README navigation.

- Hardened execution permits against `object.__new__` and copied-field forgery
  by authenticating issued object identity at the lifecycle boundary.
- Extracted bounded worker admission/timeout accounting and atomic action-budget
  leases into explicit security components while preserving runtime ordering.

- Added immutable `ActionFacts` and `ExecutionPermit` boundary types,
  centralized `PreExecutionAuthorizer`, and permit-gated
  `ExecutionLifecycle` handler invocation while preserving `GuardedRuntime`.
- Added an explicit `TerminalRecorder` for idempotency lookup, atomic claim,
  replay/conflict/expiry handling, terminal persistence, and GC. Permit
  issuance is authorizer-owned and lifecycle rejects cross-authority or forged
  permits.
- Expanded mutation scope to all security-relevant runtime controls and
  adapters with aggregate, per-component, critical-mutant, raw-evidence, and
  negative-control enforcement.
- Made action-budget lease release atomic and single-use across concurrent
  timeout, reconciliation, audit, and worker-exit callbacks; duplicate
  releases are rejected without counter underflow, with adversarial stress
  coverage and operational guidance.
- Routed approval consumption through the same bounded worker, timeout,
  capacity, and emergency-stop lifecycle as other external security
  dependencies; added an approval stop-race regression test.
- Added typed `ApprovalConsumption` outcomes with explicit `UNKNOWN` handling,
  action-bound audit evidence, and operational guidance for stop-after-consume
  approval races.

- Added typed phase-specific timeout outcomes for policy, approval, credential,
  audit, handler, and reconciliation work, including handler-started and
  side-effect-state fields.
- Removed the runtime-wide handler-completion registry; handler completion
  evidence is now scoped to the timeout signal and lifecycle stress-tested.
- Enforced idempotency TTLs with injectable clocks and observable GC. Expired
  completed records may be reclaimed, while expired in-progress or uncertain
  records remain retained and fail closed with `EXPIRED`.

- Mutation enforcement now runs a bounded mutmut pass and enforces the 80%
  killed-mutant threshold; configuration-only checks do not claim a score.
- Aligned the documented mutation source scope with the complete package
  actually configured for mutation, preventing an understated assurance claim.
- Fixed release checksum generation so `SHA256SUMS` cannot include a stale
  prior copy of itself and invalidate otherwise correct evidence.
- Mutation result parsing now shares the hard deadline, so a hung results
  command cannot bypass the bounded-run failure.
- PEP 517 build inputs are exact-pinned and audited separately, and release CI
  generates SBOMs from each installed wheel/source artifact with provenance
  attestations for those subjects.
- CI now runs the bounded mutation gate itself and uploads machine-readable
  mutation evidence; release CI independently verifies checksums, SBOM
  bindings, source commit/tag, and cryptographic provenance subjects.
- Hardened `JsonlAuditSink` restart and append recovery to verify the complete
  existing hash chain before extending it; corrupted local evidence now fails
  closed instead of being silently extended.
- Added the SEC-006 durable audit exporter and fail-closed replication
  contract, SEC-007 operational runbooks, and SEC-008–SEC-010 assurance gates,
  bounded corpus tests, mutation baseline, and adapter contracts.
- Added explicit reconciliation states that never finalize a side effect while
  a timed-out worker may still commit.
- Added typed, verifier-backed isolation attestations; the legacy
  `isolated=True` marker is no longer accepted as evidence.
- Added stable caller operation keys and the `IdempotencyStore` protocol with a
  process-local development implementation. Missing stores and key collisions
  fail closed; durable restart/multi-process behavior remains an adapter
  responsibility.
- Unified lifecycle accounting for policy, credential, audit, reconciliation,
  and handler workers, including per-operation health counters.
- Allowed `Budget(max_delegation_depth=0)` to explicitly prohibit delegation.
- Added adversarial SEC-001–SEC-005 acceptance tests and documented the
  production boundaries around durable storage and real sandboxing.
- Fixed pre-admission audit timeout accounting so denied actions cannot release
  an action budget they never acquired, and report terminal idempotency-store
  failures as `EXECUTED_UNRECORDED` instead of apparent success.

- Added provider-scope-attested credentials with non-returning secret use,
  strict content-aware redaction, runtime-independent tenant/approval/isolation
  invariants, automatic reconciliation outcomes, and tracked timed-out-worker
  health limits.
- Added action rate, fan-out, cost, and delegation budgets; fail-closed audit
  size limits with multi-process locking and chain verification; and release
  artifact/SBOM/checksum automation.
- Added adversarial tests for custom policy bypasses, credential scope and
  exfiltration attempts, timeout lifecycle, audit corruption/full conditions,
  isolation requirements, and budget overruns.
- Fixed credential capability identity collisions, re-checked the host kill
  switch immediately before credential minting and handler invocation, and
  enforced subprocess output limits during streaming reads rather than after
  unbounded buffering.
- Fixed concurrent JSONL audit writers to refresh the hash chain under the
  interprocess lock, bounded subprocess stdin writes by the execution timeout,
  and made timed-out-worker capacity admission atomic.
- Kept reconciliation results explicitly uncertain while a timed-out worker is
  still live, and made worker-capacity rejection fail closed without leaking
  action budget or concurrency slots.
- Hardened action authorization by binding approvals to exact validated action
  hashes, scoping idempotency keys to the tool and action, rejecting malformed
  proposals safely, requiring complete tenant metadata, and enforcing approval
  for external-egress tools.
- Added strict policy-result validation, explicit audit-failure outcomes,
  bounded handler waits with cooperative cancellation, private credential
  material callbacks, redacted/size-limited tool results, and policy
  version/provenance evidence in execution audit events.
- Ensured timed-out non-cooperative handlers retain their concurrency slot
  until the worker exits, preventing timeout retries from overlapping side
  effects beyond the configured concurrency limit.
- Redacted audit payloads before they reach custom sinks, made tenant metadata
  mandatory, bounded policy/credential/audit operations, required idempotency
  or reconciliation for high-impact actions, and added concrete HTTPS policy,
  approval, durable-audit, token-broker, and subprocess process-boundary
  adapters.
- Reject non-finite timeout configuration so the bounded-wait guarantee cannot
  be disabled with `NaN` or infinity.
- Removed provider callbacks from the handler-visible credential object graph;
  credential material is now held in an internal weak capability registry.
- Made `make check` include package and dependency-security validation and
  enabled protected-main-branch review and status-check enforcement.
- Improved audit redaction for common credential fields and prevented the
  development broker’s metadata inspection API from exposing secrets.
- Corrected API and getting-started documentation to match the current runtime
  and documented current limitations around cancellation, timeouts, and policy
  server integrations.
- Enabled repository Discussions, private vulnerability reporting, GitHub Pages,
  Dependabot configuration, and immutable GitHub Actions references.
- Protected the `main` branch with required code-owner review, quality and
  documentation checks, linear history, and force-push/deletion protection.
- Clarified that the SDK source is fully Apache-2.0 licensed and may be used
  commercially without separate permission; branding and endorsement remain
  subject to the trademark policy.
- Added the first guarded execution runtime with typed tools, deny-by-default policy, scoped approvals, budgets, idempotency, kill switch, and redaction-aware audit events.
- Added open-source licensing, documentation publishing, examples, and repository quality gates.
- Added a complete synthetic support-operations application demonstrating policy,
  tenant isolation, approval, scoped credentials, idempotent replay, emergency
  stop, and audit verification.
