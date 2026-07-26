# Changelog

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
