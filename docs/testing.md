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

The `regional-fault-controller-iac` job synthesizes the coordination-Region
Step Functions, Lambda and Scheduler stack from synthetic exact resource maps.
`scripts/verify_regional_fault_controller_stack.py` independently rejects
public execution grants, precondition bypass, reordered or uncompensated
mutations, unbounded retries, broad IAM, execution-data logging, weakened
watchdog DLQ posture and a falsely ready probe status. Provider-shaped tests
prove complete short-lived authority, exact witness state, processed-template
binding, complete bounded runtime inventory, source fencing, target state,
source-only routing, real access-denial evidence and recovery. Cognito and
unrecognized provider failures fail closed. These are infrastructure and
protocol contracts; they are not live AWS dependency-failure evidence.

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

`tests/test_endpoint_evidence_publisher.py` covers the production-shaped
endpoint discovery handoff. It proves administrator-only collection, exact
binary/process measurement, path and secret minimisation, symlink and binary
tamper behavior, per-device signature binding, stale/revoked/cross-device and
duplicate-report rejection, unknown-field denial, exact MDM metadata matching,
and compatibility with the existing endpoint normalizer. Real MDM rollout and
95% pilot report freshness remain deployment acceptance; see
[Endpoint evidence publisher](endpoint-evidence-publisher-design.md).
`scripts/test_endpoint_evidence.py` is the isolated root/admin acceptance
command. With the `endpoint` extra installed, it measures the live Python
process and executable, proves that temporary paths and the synthetic secret do
not enter the signed report, assembles against an authoritative synthetic
device inventory, passes the existing endpoint normalizer, and rejects a
changed signed report.

`tests/test_endpoint_evidence_transport.py` and the hosted endpoint contracts
in `tests/test_aws_lambda_contract.py` prove HTTPS-only secret-safe transport,
MDM-bound issuance, HMAC verification, idempotent retry, cross-tenant denial,
tamper denial and server-derived stale posture. They are software/API evidence;
real MDM rollout remains separate acceptance. The hosted contracts also cover
scheduled tenant discovery, bounded failure propagation to EventBridge,
root-cause alert deduplication, signature/replay event alerts, normalized SNS
delivery, incident-response RBAC, optimistic acknowledgement,
credential-shaped rationale rejection and automatic health-alert resolution.
The Splunk status remains a non-delivering stub and is not accepted as SIEM
evidence.

The hosted behavior-detection contracts in
`tests/test_aws_lambda_contract.py` prove strict alert-only schema, independent
review, MCP identity minimisation, normalized spike thresholds,
insufficient/truncated-history denial, deterministic alert identity,
idempotence, no automatic containment, acknowledgement, revalidated case
binding, manual case-owned quarantine and integrity-verified export. SDK
contracts in `tests/test_ui_control_plane.py` prove that only a bounded MCP
server identifier is exported and that unrelated evidence cannot smuggle that
field. The private UI suite proves the typed trust-boundary editor and the
human-readable incident explanation. These are synthetic control-plane
contracts; they do not prove complete telemetry from a compromised host or
production SIEM delivery.

Repository/configuration anomaly contracts prove complete consecutive
generation re-hashing, exact enrolled repository scope, managed desired versus
observed comparison, fixed attestation reasons, canonical Codex host matching,
deterministic alert identity, exact suppression, no automatic containment,
server-revalidated case binding and integrity-bound export. Missing or
malformed authority produces `baseline_insufficient`, no alert and degraded
evaluator health. Activity contracts also cover outside-project and fail-closed
configuration-error spikes. The private UI suite proves typed integrity-rule
authoring, contextual help, preview-before-save, alert-only copy, exact
suppression selection and human-readable case evidence. These synthetic
contracts do not prove the correctness of a customer's source-control,
endpoint or attestation connector.

Alert-suppression contracts additionally prove exact target matching,
seven-day maximum expiry, broad/wildcard/unauthorized denial, retained
suppressed evidence, no delivery or automatic containment, optimistic
revocation, endpoint reopening and stable behavior grouping across evaluation
windows. See [Governed alert suppression and
deduplication](alert-suppression-design.md).

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

Managed package distribution contracts cover canonical publication and exact
typed client verification, tenant/deployment/agent separation, stale revision
conflicts, desired-state changes, inactive rollouts, emergency stops, missing
managed-configuration repair, altered response digests and metadata mismatch.
The standalone AWS Lambda validator is checked against real SDK-generated
packages. These are protocol tests, not evidence that MDM installed the package
or that a live Claude Code or Codex process loaded it.

Incident-response contracts cover deterministic case creation, exact
endpoint-to-agent correlation, content-minimised timelines, quarantine,
session-revision revocation, independent emergency-stop scopes and guarded
release. Positive tests prove evidence-preserving containment and successful
release after recovery checks. Adversarial tests prove missing or ambiguous
bindings, changed correlation, stale revisions, missing execution authority
and denied authority cannot become execution. The enrolled AWS client treats a
missing or false `controlState.executionAllowed` as a dependency failure after
submitting heartbeat evidence.

Case-export contracts additionally prove canonical evidence-role enforcement,
exact captured-binding correlation, strong bounded reads, no raw project paths
or approval narrative, deterministic package hashes and immutable-audit
receipt binding. The offline verifier accepts an unchanged synthetic artifact
and rejects changed outer content, invalid per-event hashes, unsafe capture
flags and rehashed free-form approval text. UI tests prove cryptographic
verification happens before the browser creates a download.

The local contract suite uses synthetic fakes for OPA, Cedar, approval, IAM,
idempotency, remote audit, and isolation boundaries. These tests verify request
shape, binding, malformed-response handling, and fail-closed behavior. They do
not certify an external deployment. Provider integrations should add
ephemeral-service tests for authentication, timeouts, stale versions, replay,
and service-unavailable responses.
