# Testing and assurance

`make check` is the required local and CI quality gate. It runs formatting,
linting, strict typing, unit and adversarial tests, 90% branch coverage,
guardrail checks, a strict documentation build, package validation, dependency
audits, and mutation-baseline validation. When the separate private
`aai-sec-ui` checkout is present beside the SDK sources, the same command also
runs its React typecheck, contract tests, and production build. A clean public
SDK checkout reports that the private UI is absent and completes the SDK gate;
the UI repository enforces its own mandatory `npm run check` workflow.
`tests/test_enterprise_e2e.py` starts the
actual reference WSGI server on an ephemeral localhost port and exercises
authenticated HTTP registration, template assignment, rollout, and compliance
evidence. The browser smoke path for the live
reference server is documented in the enterprise fleet runbook and is used
before release evidence is accepted.

The optional live PostgreSQL path is exercised by the `postgres-integration`
GitHub Actions job. Locally, install `.[postgres]`, set
`AAI_SEC_POSTGRES_DSN`, and run:

```bash
python -m pytest -q tests/test_enterprise_postgres_integration.py
```

Without a DSN the test skips; the CI service job always supplies one.

Runtime-manifest assurance is split across three boundaries:

- `tests/test_runtime_attestation.py` covers content-minimised measurement,
  linked worktrees, packed refs, symlink/race bounds and changed artifacts;
- `tests/test_runtime_manifest_generator.py` covers clean-checkout enforcement,
  release identity, deterministic Claude/Codex manifests, GitHub provenance
  invocation and safe output handling; and
- `tests/test_aws_lambda_contract.py` proves exact manifest/provenance binding,
  challenge freshness, mismatch quarantine, session revocation and governed
  route denial.

`npm run build && npm run synth` in `infra/aws-control-plane` additionally
proves that CDK accepts the checked-in empty development pair and will reject a
stale pair before deployment. Live modified-host acceptance remains required
before P0-05 is complete.

`scripts/test_aws_control_plane.py` now stages an isolated synthetic deployment
with a managed-host bundle and proves that missing and conflicting evidence
block governed agent routes before an exact fresh report restores access. The
report used by this control-plane smoke is synthetic and proves the deployed
API protocol only; it is not evidence that a real Claude Code process loaded a
managed file. Retain separate device evidence from the privileged-file
measurement and live host action probes in
[Managed host configuration](managed-host-configuration.md).

`tests/test_managed_deployment.py` validates canonical package parsing,
out-of-band digest binding, exact host file sets, artifact/executable digests,
duplicate-key denial, cross-target denial and path confinement.
`tests/test_managed_endpoint_installer.py` runs the privileged transaction
against an isolated synthetic endpoint image. It proves no-write preflight,
administrator checks, exact restrictive files, hook tamper denial, symlink
denial and reverse-order restoration after an injected second-file failure.
Real root-owned host loading and MDM acceptance remain separate evidence; see
[Managed endpoint deployment](managed-endpoint-deployment-design.md).

`scripts/test_aws_entra_scim.py` is the live Microsoft Entra provisioning
acceptance command. It discovers Entra and SCIM status from the selected
CloudFormation stack, resolves the dedicated bearer directly from Secrets
Manager, and tests invalid authentication, bounded capability discovery,
joiner, duplicate, mover, leaver and inactive-user denial. It returns `2`
without reading a secret or writing lifecycle state when the stack is not
configured. Exact synthetic state is removed on success or failure while the
content-minimised lifecycle audit is retained. Unit contracts live in
`tests/test_aws_entra_scim_script.py`; the Lambda's adversarial protocol
contracts remain in `tests/test_aws_scim_contract.py`. This does not replace a
real Entra OIDC login and token-revocation exercise.

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
