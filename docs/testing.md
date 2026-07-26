# Testing and assurance

`make check` is the required local and CI quality gate. It runs formatting,
linting, strict typing, unit and adversarial tests, 90% branch coverage,
guardrail checks, a strict documentation build, package validation, dependency
audits, mutation-baseline validation, and the nested React UI typecheck,
contract tests, and production build. The browser smoke path for the live
reference server is documented in the enterprise fleet runbook and is used
before release evidence is accepted.

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
`critical-mutants.json` is the schema-3 companion manifest of stable invariant
IDs, exact module/class/method symbols, executable test IDs, and static source
contracts. The runner emits a commit-bound symbol-to-mutant mapping with the
source span, AST-node fingerprint, and mutation class reconstructed by the
verifier; numeric mutmut IDs are evidence identifiers and are never used as a
substitute for the reviewed symbol contract. Symbols listed
under `static_contracts` have no generated mutation operator and require the
listed adversarial tests instead. Diagnostic strings, event names, mapping
keys, enum/state labels, operation names, timeout phases, and policy or
approval metadata are not automatically exempt: any exclusion requires an
explicit mutation-site rationale and executable contract evidence.
The declared mutation source scope includes the runtime boundary, typed
components, approvals, budgets, credentials, idempotency, isolation, policy,
audit/redaction, and provider adapters. It is checked exactly against
`pyproject.toml`:

- `src/agentic_security/components.py`
- `src/agentic_security/runtime.py`
- `src/agentic_security/approvals.py`
- `src/agentic_security/budgets.py`
- `src/agentic_security/credentials.py`
- `src/agentic_security/idempotency.py`
- `src/agentic_security/isolation.py`
- `src/agentic_security/policies.py`
- `src/agentic_security/policy_adapters.py`
- `src/agentic_security/audit.py`
- `src/agentic_security/adapters.py`

`make mutation` runs the actual tool in a pinned development environment and
fails unless the overall threshold is met. It also requires at least 75% killed
mutants in every declared component and 100% of the exact critical-symbol
mapping. Any unmatched critical symbol, timeout, suspicious, skipped, or
not-checked result fails
closed. Surviving non-critical mutants count against the aggregate and
component thresholds but are not execution gaps; critical-symbol mutants must
all be killed. Run it when changing authorization, approval, credential, idempotency,
timeout, isolation, budget, or audit code. CI runs the same `make mutation` command on pull requests and
releases, uploads `.mutmut-cache/evidence.json` and `results.txt`, and fails
on stale/missing/truncated/timeout/unparseable evidence or evidence generated
for another commit. The evidence records the exact score, commit, tool,
command, and source scope. No mutation score is claimed without the runner's
parsed result file. One deliberately timing-heavy
worker stress test is excluded from mutmut's baseline selection because
mutation process overhead makes it nondeterministic; it remains mandatory in
the normal unit/adversarial suite and is not excluded from `make check`.
No source file is excluded because its mutants are difficult to kill. Only
objectively non-security tooling may be outside the scope, and each such
boundary requires contract tests. The runner records raw results with a
commit header, per-component scores, critical-mutant results, and negative
control outcomes. High-impact adoption must retain that raw evidence with the
reviewed commit.

`scripts/verify_mutation_evidence.py` independently rechecks the uploaded
evidence against the current commit, `pyproject.toml`, the baseline threshold,
and the results-file hash. It fails closed for missing, stale, cross-commit,
scope-mismatched, malformed, or tampered evidence.

## Adapter contracts

The local contract suite uses synthetic fakes for OPA, Cedar, approval, IAM,
idempotency, remote audit, and isolation boundaries. These tests verify request
shape, binding, malformed-response handling, and fail-closed behavior. They do
not certify an external deployment. Provider integrations should add
ephemeral-service tests for authentication, timeouts, stale versions, replay,
and service-unavailable responses.
