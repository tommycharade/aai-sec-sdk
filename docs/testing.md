# Testing and assurance

Runtime-release rollout contracts prove deterministic dual-version selection,
immutable manifest and approval-bundle bindings, exact target attestation,
minimum-sample and canary-before-broad sequencing, threshold pause, frozen
pause/rollback membership under population churn, target-attested measured
rollback, malformed-authority refusal, tenant/delegated-scope and RBAC denial,
empty-catalog bypass denial, state-specific field-removal denial,
recursive DynamoDB `Decimal` normalization for stored authority and nested
manifest hashing, stale-revision denial and an atomic complete-authority audit hash. UI contracts
prove closed-schema response validation, independent release-endpoint failure,
bounded integer health inputs, accessible modal focus behavior, explicit resume,
pause and rollback journeys, contradictory-convergence and malformed-catalog
denial, non-dismissible pending mutations, completed-transition reset, and
accepted-mutation/failed-refresh recovery that prevents an unsafe retry.
Physical MDM installation remains a separate
live-acceptance gate; see
[Measured runtime-release rollouts](runtime-release-rollout-design.md).

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

The gate also validates the machine-readable customer assurance pack. Its
closed schema requires a technical owner, HTTPS private-reporting route,
approved and next-review dates no more than 120 days apart, every required
document, bounded vulnerability response targets, evidence for any completed
penetration/certification claim, and evidence-linked guarantees. Adversarial
tests reject expiry, SLA weakening, unsupported certification, missing
documents and unreviewed fields. This proves the published pack remains current
and internally consistent; it does not prove a real incident met its SLA or an
external assessor approved the product.

Tagged-release CI also builds a deterministic archive of the pack. The release
verifier rejects extra, missing, traversing or hash-mismatched archive files.

`scripts/test_real_claude_code.py` is the separate live-host compatibility
gate. It exact-matches the installed Claude Code version, platform,
architecture and executable digest against a default-deny reviewed matrix,
onboards only a disposable synthetic project, and exercises real native
allow/deny/approval/scope behavior plus the localhost guarded MCP tool. Its
JSON evidence contains no prompts, tool arguments, results, credentials or
paths. Authentication/service unavailability is `blocked`, never a pass. The
script can incur bounded Claude model cost and is not part of `make check` or
CI; see [Real Claude Code acceptance
harness](real-claude-code-acceptance-harness.md).

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

Cloud-credential contracts cover Azure, GCP and AWS exact scope, wrong-tool and
wrong-resource denial, policy-widening denial, bounded TTL, malformed provider
identity, revocation, checker failure and secret-free projections. Hosted
control-plane tests additionally prove human/machine authority separation,
tenant isolation, evidence expiry, exact configuration binding and revocation
epoch advancement. These deterministic tests are not live cloud-role
acceptance; run the checklist in [Cloud credential
authority](cloud-credential-authority-design.md) for each production provider.
The contracts also reject provider tokens whose underlying lifetime exceeds
the requested SDK lifetime and reject AWS STS registrations below the
provider's fifteen-minute minimum.

Isolation-authority tests cover immutable profile hashing, malformed and
unbounded constraints, exact action/profile/workload binding, future/stale/
overlong/expired evidence, signature failure, revocation, dependency outage,
permit evidence and content-minimised audit. Docker contract tests prove that
the attested profile matches fixed filesystem, network, PID, CPU, memory,
credential, privilege and timeout controls. Hosted tests prove tenant
isolation, human/machine evidence separation, exact evidence checks, expiry,
policy reference validation and live revocation. These tests do not replace a
production hostile-code assessment; use [Production isolation
authority](production-isolation-authority-design.md).

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

Runtime-remediation coordination is covered at two boundaries:

- `tests/test_aws_lambda_contract.py` proves deployment-scoped pagination,
  exact instruction/revision binding, machine-only claim/report authority,
  canonical digest recomputation, active-lease and idempotency behavior,
  concurrent rollout/quarantine cancellation, stale rollout invalidation, malformed
  task denial, atomic primary audit, independent channel/verification totals
  and the rule that an install report remains unverified until fresh exact
  attestation; and
- `tests/test_ui_control_plane.py` proves the typed
  `RuntimeRemediationClient`, closed response schemas, contradictory count and
  eligibility rejection, expired verification denial, GET/POST redirect bearer
  containment, bounded fixed failure codes and content-free network requests.

These are coordination and evidence contracts, not live Intune/Jamf dispatch
or physical endpoint acceptance.

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

`tests/test_codex_effective_controls.py` exercises a synthetic app-server over
the real JSONL subprocess boundary. It proves matching and deny-first behavior,
binary pinning, bounded time and output, duplicate/malformed/error handling, and
that secret-bearing configuration fields and server errors never enter the
evidence projection.

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
protected key-file ownership/mode enforcement, atomic mode-`0600` report
replacement, and compatibility with the existing endpoint normalizer.
`tests/test_macos_endpoint_sensor_package.py` proves digest binding,
secret-free package contents, fixed shell-free launchd arguments, explicit
signed/unsigned posture, protected output handling and fail-closed macOS tool
execution. On macOS, `scripts/test_macos_endpoint_sensor_package.py` assembles
and inspects a disposable package with the real `pkgbuild` and `pkgutil` tools;
it does not claim MDM deployment or production code signing. Real MDM rollout
and 95% pilot report freshness remain deployment acceptance; see
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

Incident credential-authority contracts prove exact case-bound agent scope,
current and future broker denial, unaffected sibling agents, cross-tenant
isolation, human/machine capability separation, stale-revision denial,
resolution blocking and recovery only after server verification and source
alert recovery. SDK unit tests prove fail-closed checks before mint, after mint
and before each credential callback, including checker outage and malformed
responses. These remain synthetic software contracts; production acceptance
requires real provider roles and measured revocation behavior.

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

## Assurance-report rotation and scheduling

AWS contract tests run a complete synthetic signer cutover: candidate staging,
exact primary/recovery MRK pairing, persistent promotion, old-current history,
passive convergence and pre-rotation signature verification in both Regions.
Synthesized IAM contracts separately prove historical keys are verify-only.
Failure injection interrupts after key creation, SSM persistence, primary
deployment and passive deployment and proves the next invocation resumes from
the durable phase. Negative fixtures cover malformed base64 and false KMS
verification, wrong key identity, wrong algorithm, non-32-byte digests and
oversized signatures. Deployment preflight tests reject removed, reordered,
substituted and truncated historical signer registries before CDK runs.
Scheduler adversarial tests distinguish deterministic malformed records from
transient DynamoDB claim failures, prove revision-bound concurrent repair and
advance beyond fully corrupt 250-record pages containing malformed string,
boolean, missing and oversized revisions.

## Vulnerability-management rehearsal

`scripts/verify_vulnerability_management.py` treats the checked governance
policy and exercise record as untrusted input. It rejects unknown fields,
non-UTC or unordered timestamps, stale review authority, weakened higher-
severity deadlines, unbounded exceptions and every individual critical SLA
miss. `make check` runs the verifier through the repository guardrail target.

The checked exercise is explicitly synthetic. Its success proves the policy
shape, deadline calculations and evidence contract; it is not evidence that a
live response team met those times. Production acceptance must retain a real
exercise or incident record and independently review its timestamps.

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

Codex native-authority contracts bind evidence to current server desired state,
not merely the endpoint's state label. Positive tests require exact bundle,
host version, platform, freshness and an `enforced` projection. Adversarial
tests submit an otherwise valid `enforced` observation for another bundle and
prove the server derives `conflict`, emits the fixed
`native_effective_controls` blocker and denies governed routes. Expiry and
missing desired state also fail closed. A paired repair test proves the exact
attested agent can still retrieve its current canonical managed package while
native authority is blocked; emergency stop and quarantine do not receive that
exception.

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

## Data-boundary contracts

Deployment tests preserve schema-v1 IP manifests and reject duplicate or
unknown schema-v2 fields, mixed CIDR/VPC-endpoint authority, malformed endpoint
IDs, private or non-canonical source networks, wrong-account or wrong-Region
keys, disabled keys and keys without rotation. PrivateLink preflight tests
reject missing endpoints and wrong account, service, type, state or private-DNS
posture. They prove ambient environment values cannot
replace persisted authority and a configured stack cannot deploy after that
authority is lost. CDK synthesis tests bind customer-key encryption to retained
DynamoDB, S3, SQS and SNS resources.

Lambda adversarial tests deny missing and outside source context, ignore
spoofed forwarding/VPC-endpoint headers, admit only exact private API and
endpoint context or an approved IP address, enforce tenant roles and prove no
full key ARN, CIDR or endpoint ID enters the response. CDK synthesis proves the
private REST endpoint association, `aws:SourceVpce` resource policy, Cognito
authorizer and private output contract. UI tests verify the
page remains read-only and distinguishes IP restriction, PrivateLink and live
acceptance. Browser checks cover desktop, narrow layouts and keyboard-accessible
context help. These tests are software evidence, not a completed customer KMS,
deletion or private-connectivity acceptance exercise.

## Console navigation contracts

The UI suite asserts that the primary sidebar contains exactly the seven
Product Owner-approved workspaces. Route-level tests prove contextual controls
remain reachable, workspace selection exposes `aria-current`, contextual tabs
expose one `aria-selected` destination with roving keyboard focus, and old
hash routes retain their exact destination while selecting the correct parent
workspace. The primary authenticated shell also runs `axe-core` in CI; focused
tests prove the first-focus skip path, named landmarks, route-aware document
title, modal focus entry/containment/restoration and atomic status copy.
Desktop and 390-pixel browser checks must show no document-level horizontal
overflow, sub-44-pixel compact operator controls or browser console errors.
Manual browser review covers visual hierarchy and contrast because JSDOM
cannot calculate rendered color contrast. These checks prove information
architecture and interaction quality; they do not prove that an operator has
the server-side role required to mutate a protected resource or replace a
screen-reader and 200% zoom acceptance exercise.

The UI production gate additionally resolves the HTTP-only client, builds the
actual customer assets, rejects simulation enrollment/bootstrap markers, and
enforces explicit raw/gzip budgets. Negative tests prove contaminated and
oversized fixture bundles fail. Route tests open the lazy detection-rule
workspace; a focused error-boundary test proves an optional chunk failure keeps
a recovery action visible instead of blanking the console. The size gate is a
regression alarm, not field performance evidence; representative real-user
monitoring remains deployment-owned.

## Real Codex CLI host acceptance

`scripts/test_real_codex_cli.py` admits only an exact executable from the
default-deny support matrix and operates exclusively in a disposable synthetic
Git project. It verifies process-loaded controls, native command and patch
decisions, scope confinement, guarded MCP execution and the content-free local
audit chain. `tests/test_real_codex_cli_acceptance.py` covers changed-binary
rejection, matrix bounds, malformed streams, failed MCP status, report
minimisation and the distinction between passing project controls and missing
administrator authority. See the [harness contract](real-codex-cli-acceptance-harness.md)
and [current evidence](real-codex-cli-acceptance-evidence-2026-08-05.md).
