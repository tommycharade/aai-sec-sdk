# Testing and assurance

`make check` is the required local and CI quality gate. It runs formatting,
linting, strict typing, unit and adversarial tests, 90% branch coverage,
guardrail checks, a strict documentation build, package validation, dependency
audits, and mutation-baseline validation.

## Deterministic property/fuzz coverage

`tests/test_assurance.py` runs a finite checked-in corpus from
`tests/corpus/malformed_inputs.json`. It exercises proposal construction,
action fingerprints, nested redaction, policy response mapping, and audit
acknowledgement behavior. The corpus is capped at 32 cases and has no random
seed, network call, sleep, or unbounded loop, so CI remains reproducible.
Expand the corpus with a regression case whenever malformed input reaches a
new boundary.

## Mutation testing

`mutation-baseline.json` records the security branches and the bounded command.
`make mutation` runs the actual tool in a pinned development environment and
fails unless the declared threshold is met. Run it when changing
authorization, approval, credential, idempotency, timeout, isolation, budget,
or audit code. Require at least 80% killed mutants in the listed security
branches. CI validates the runner and baseline on every pull request; release
automation or a security-sensitive change should run `make mutation`. No
mutation score is claimed without the runner's parsed result file.

## Adapter contracts

The local contract suite uses synthetic fakes for OPA, Cedar, approval, IAM,
idempotency, remote audit, and isolation boundaries. These tests verify request
shape, binding, malformed-response handling, and fail-closed behavior. They do
not certify an external deployment. Provider integrations should add
ephemeral-service tests for authentication, timeouts, stale versions, replay,
and service-unavailable responses.
