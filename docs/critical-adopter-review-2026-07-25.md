# Fresh Critical Adopter Review

**Reviewed commit:** source snapshot bound to `498fbd6` evidence
**Review date:** 2026-07-26
**Working tree:** uncommitted implementation snapshot; final release still requires a clean commit

## Evidence reviewed

- Targeted runtime security tests were added for denial identity/reasons,
  approval binding, and policy provenance.
- `make check` passed.
- GitHub CI passed on Python 3.11, 3.12, and 3.13.
- Historical figures below are retained as review history only. The current
  declared scope is the complete 11-file security scope; current mutation
  evidence is recorded separately and is not accepted until all thresholds
  pass.
- Mutation evidence was commit-bound and independently verified.
- The fresh bounded run records 1,974/2,372 killed mutants (83.22%), all
  component thresholds pass, and all 205 exact critical-symbol mutants are
  killed. The verifier independently reconstructs source spans and AST-node
  fingerprints and accepts the evidence.

## Recommendation

**Conditional go for low-risk and trusted-handler workloads.**

**No-go for high-impact production actions and hostile-code execution.**

## P1 findings and status

### Architecture and expanded mutation assurance resolved in the current snapshot

The current workstream implements a coherent vertical slice: immutable
`ActionFacts` and `ExecutionPermit`, centralized `PreExecutionAuthorizer`,
and permit-gated `ExecutionLifecycle` handler invocation. `GuardedRuntime`
remains the compatibility entry point, and targeted component/runtime tests
pass.

The runtime now delegates deterministic validation/isolation, policy
normalization, approval gating, and credential scope checks to explicit phase
components. The full declared source scope passes the aggregate, component,
and exact critical-symbol gates with no timeout, skipped, suspicious, or
unchecked execution gaps. Surviving non-critical mutants remain visible in
the aggregate score and are not silently excluded.

The previous failed runs remain below as historical diagnostics only. The
current evidence is the only accepted mutation record and is bound to its
source snapshot and results hash.

The permit boundary is now hardened against same-shaped objects fabricated via
`object.__new__` and copied-field reflection: lifecycle authorization uses a
module-owned issuer registry keyed by permit identity. This is an in-process
boundary, not a defense against code that already controls the Python
interpreter.

### Action-budget release is resolved by `103bf6d`

`103bf6d` makes `_release_action_budget_once()` atomic with the existing
per-action lock and protects `BudgetState.release()` from underflow. Multiple
timeout callbacks can no longer release the same lease twice.

Evidence includes `test_action_budget_release_callbacks_are_atomic_under_concurrency`
and `test_budget_release_rejects_concurrent_duplicate_releases_without_underflow`
in `tests/test_product_owner_backlog.py`, plus the full `make check` run.

### Mutation assurance scope and central runtime resolved in the current snapshot

The mutation scope is now configured as the complete security-relevant
11-file scope: runtime/components, approvals, budgets, credentials,
idempotency, isolation, policies/policy adapters, audit, and adapters. The
central runtime, typed components, approval, policy, budget, idempotency,
credential, isolation, audit, and adapter modules are all in the declared
scope. No source exclusions or clean-worktree claims are made while this
workstream is in progress.

The critical invariant manifest is `critical-mutants.json`; it now uses exact
module/class/method symbols and records a commit-bound symbol-to-mutant
mapping. Symbols without generated mutation operators are listed as static
contracts with executable adversarial-test references. The source-level P1 is
closed for this snapshot: the complete scope and exact critical mapping pass.
Runtime mutation assurance remains a production-readiness requirement for every
future change and does not replace deployment-level evidence.

## P2 issues

### `make check` does not run the actual mutation gate (documented)

`make check` runs `mutation-check`, which validates the bounded contract and
normal quality gates. The actual mutmut execution is intentionally a separate
bounded command, `make mutation`, because it is materially more expensive. CI
and release workflows run `make mutation`; local developers must run it
explicitly when mutation evidence is required.

### Durable production adapters remain deployment responsibilities

The core now provides strong contracts for typed approval outcomes, stable
idempotency keys, expiry and safe garbage collection, phase-specific timeout
outcomes, nonce-bound isolation attestations, and replicated audit
acknowledgement.

Production deployments still need to supply:

- durable multi-process idempotency;
- immutable/WORM audit storage;
- cryptographically meaningful isolation verification;
- actual container, microVM, or WASM sandboxing;
- provider-side IAM scope enforcement.

These limitations are accurately documented in
[`docs/production-readiness.md`](production-readiness.md) and
[`docs/security-model.md`](security-model.md).

### Release evidence is credible but not yet demonstrated by a published release

The release workflow includes artifact-specific SBOMs, checksums, release
metadata, clean-checkout verification, provenance attestation, and provenance
verification.

No tagged production release or independently inspectable release-evidence
bundle was available in this review. The process is credible, but the
operational release track record is not yet proven.

## Findings resolved since earlier reviews

- Timeout-phase ambiguity.
- Approval unknown-outcome handling.
- Approval/stop race checks.
- Idempotency expiry and garbage-collection semantics.
- Completion-registry retention.
- Mutation evidence staleness and cross-commit reuse.
- Release checksum and SBOM binding.
- Clean-checkout release verification.
- Provenance verification workflow.

## Workload decision

| Workload | Decision |
| --- | --- |
| Read-only, low-risk tools | Go with authenticated policy and audit |
| Trusted internal handlers | Conditional go |
| Credentialed state changes | Conditional go after durable adapter testing |
| Payments, deletion, messaging, account mutation | No-go |
| Hostile or model-generated code | No-go without a real sandbox and verifier |
| Regulated workloads | No-go pending deployment evidence |

## Apache-2.0 and commercial assessment

The Apache-2.0 core remains credible:

- commercial use is permitted;
- `LICENSE` and `NOTICE` are packaged;
- trademark restrictions are separate;
- paid features are not required for fail-closed behavior.

A managed edition could be valuable to enterprise platform and security teams,
particularly for:

- hosted policy and approval control;
- transactional idempotency;
- immutable audit and SIEM integration;
- managed IAM and attestation;
- hardened sandbox execution;
- fleet emergency stop and health dashboards;
- compliance evidence;
- support SLAs and maintained provider adapters.

The runtime, contracts, tests, documentation, security fixes, and local
reference implementations should remain open source.

## Final decision

**Conditional pilot approval.**

Before high-impact production adoption:

1. Extend mutation testing to runtime authorization, timeout, budget,
   approval, and idempotency paths before high-impact production adoption;
   the current bounded gate intentionally does not claim that coverage.

The project is now a credible open-source security-runtime framework, but not
yet a fully evidenced production security platform.
