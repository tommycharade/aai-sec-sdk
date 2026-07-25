# Fresh Critical Adopter Review

**Reviewed commit:** final commit-bound mutation evidence  
**Review date:** 2026-07-25  
**Working tree:** clean at the verification point

## Evidence reviewed

- 113 tests passed.
- 90.52% coverage.
- `make check` passed.
- GitHub CI passed on Python 3.11, 3.12, and 3.13.
- Actual bounded mutation run passed: 180/218 mutants killed, 82.57% on the
  declared three-file scope.
- Mutation evidence was commit-bound and independently verified.

## Recommendation

**Conditional go for low-risk and trusted-handler workloads.**

**No-go for high-impact production actions and hostile-code execution.**

## P1 findings and status

### Action-budget release is not thread-safe

`_release_action_budget_once()` in `src/agentic_security/runtime.py` uses an
unsynchronized check/set sequence. Multiple timeout callbacks can invoke it
concurrently, particularly when both a handler and reconciliation operation
time out.

`BudgetState.release()` in `src/agentic_security/budgets.py` decrements
counters without underflow protection. A double release could make the
active/concurrency count negative and allow more concurrent work than
configured.

The existing test calls the method sequentially in
`tests/test_product_owner_backlog.py`.
This requires a lock or atomic lease and a concurrent stress test.

### Mutation assurance scope corrected; central runtime remains open

The mutation score passes, but the configured bounded mutation scope includes
only:

- `credentials.py`;
- `isolation.py`;
- `audit.py`.

The central `src/agentic_security/runtime.py` implementation and the
approval/policy/budget/idempotency/type modules are outside the actual mutmut
scope. A bounded experiment widening the scope to runtime plus the existing
three modules completed but scored only 862/1310 (65.8%), so it correctly
failed the 80% gate. The project now explicitly makes no mutation-coverage
claim for the runtime boundary.

The passing score is valid only for the three listed modules. It does not
establish mutation assurance for the central execution boundary or the
action-budget race above. This finding is resolved as a claims-correction,
not as evidence that the runtime is mutation-tested; runtime mutation
assurance remains a production-readiness requirement for high-impact use.

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

1. Make action-budget release atomic and prove it under concurrent
   timeout/reconciliation callbacks.
2. Extend mutation testing to runtime authorization, timeout, budget,
   approval, and idempotency paths before high-impact production adoption;
   the current bounded gate intentionally does not claim that coverage.

The project is now a credible open-source security-runtime framework, but not
yet a fully evidenced production security platform.
