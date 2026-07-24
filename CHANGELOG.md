# Changelog

All notable changes to this project will be documented here.

The project follows Semantic Versioning after `1.0.0`. Before `1.0.0`, public APIs may change while the design is validated, but breaking changes will still be called out explicitly.

## Unreleased

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
