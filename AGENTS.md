# Project guardrails

These rules apply to every change in this repository. They are deliberately short enough to use during implementation and specific enough to test in review and CI.

## Before changing code

1. Read `docs/guardrails.md` and the relevant design record.
2. Identify the security boundary being changed: proposal, policy, identity, approval, execution, data flow, telemetry, or control plane.
3. Add or update the threat model and public API documentation when the change affects behavior, authority, data handling, or configuration.

## Non-negotiable engineering rules

- The host, never the model, decides whether a tool executes.
- Unknown tools, malformed arguments, missing identity, missing policy, expired approvals, and unsafe defaults fail closed.
- Every consequential action is authorized with its live arguments, resource, principal, purpose, and current policy—not only at session start.
- Credentials, principals, approval state, and policy decisions are never accepted from model output.
- Public APIs must use explicit typed objects and structured results; avoid ambiguous booleans and hidden global state.
- Open-source code must be fully explained: public symbols require docstrings, and security-sensitive logic requires comments describing the invariant and trust boundary.
- Security-sensitive defaults are restrictive: explicit tool allow-lists, bounded steps/time/cost, scoped credentials, and observable decisions.
- Sensitive data is redacted before persistence or telemetry export. Tests must use synthetic data.
- Documentation is code: update the source documentation, regenerate the README, and build the documentation site for documentation changes.
- Integrations with IAM, policy engines, sandboxes, providers, and telemetry systems use adapters; the core must remain provider-neutral.
- No dynamic function lookup, shell execution, network egress, or broad credential access may be introduced without a threat-model entry and dedicated tests.
- Demonstration-only unsafe code must never be present in production paths.

## Required evidence for a change

Every change must include the appropriate combination of:

- unit tests for deterministic behavior;
- adversarial tests for bypasses and fail-closed behavior;
- an integration/contract test for changed adapters;
- documentation and a small usage example for public API changes;
- a threat-model/control update for security-boundary changes;
- a release-note entry for user-visible behavior or breaking changes.

The quality gate is `make check`. A change is not complete until it passes locally and in CI.
