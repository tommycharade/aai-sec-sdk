# Fresh Critical Adopter Review

**Reviewed commit:** `a528b22c566ef62a1f92bafd295cd24902d281ff`
**Review date:** 2026-07-26
**Working tree:** clean

## Current verdict

The project has improved materially. The current commit passes the normal quality
gate and the complete mutation gate.

I would use it for low-risk pilot workloads and trusted internal handlers.

I would not yet approve it for high-impact production actions because the
published `v1.0.0` release has supply-chain verification problems, and uncertain
idempotency persistence failures remain inconsistently surfaced.

## Evidence verified

- `196` tests passed.
- Coverage: `90.93%`.
- `make check`: passed.
- `make mutation`: passed.
  - `1,973 / 2,374` mutants killed.
  - `83.11%`, against an 80% requirement.
  - All component thresholds passed.
  - `205 / 205` critical mutants killed.
  - Mutation evidence independently verified locally.
- Working tree was clean.
- GitHub release `v1.0.0` exists with SBOM, checksums, provenance, and mutation
  evidence assets.

## Resolved since the previous review

- Mutation score below threshold.
- Mutation evidence header mismatch.
- Missing critical-mutant manifest mapping.
- Missing mutation evidence upload in the release workflow.
- Permit authority bypass through same-shaped objects.
- Increased unit and integration coverage.

## Remaining P1 issues

### P1 — Published release evidence cannot be independently verified

I downloaded the published `v1.0.0` release and ran:

```text
python3 scripts/verify_release_evidence.py ...
```

It failed with:

```text
ValueError: checksum manifest is stale, truncated, or contains unexpected files
```

The release contains `evidence.json` and `results.txt`, but `SHA256SUMS` does
not include them. The verifier requires every file other than `SHA256SUMS` to
appear in the checksum manifest.

Relevant source:

- [`scripts/verify_release_evidence.py`](https://github.com/tommycharade/aai-sec-sdk/blob/main/scripts/verify_release_evidence.py)

This makes the publicly advertised release evidence bundle inconsistent.

### P1 — Published provenance is bound to `main`, not the release tag

Provenance verification failed for both `v1.0.0` and `refs/tags/v1.0.0`:

```text
expected SourceRepositoryRef to be v1.0.0, got refs/heads/main
```

The release was produced by a successful manual workflow run from `main`, while
`RELEASE-METADATA.json` claims the release commit and tag. The workflow permits
manual source/tag combinations:

- [.github/workflows/release-artifacts.yml](https://github.com/tommycharade/aai-sec-sdk/blob/main/.github/workflows/release-artifacts.yml)

The packaged source appears equivalent, but provenance does not prove that the
artifact was built from the claimed release tag. This is a supply-chain release
blocker.

### P1 — Uncertain idempotency persistence failures remain hidden

The timeout and general exception paths ignore the return value of
`_store_terminal()`:

- [`src/agentic_security/runtime.py`](https://github.com/tommycharade/aai-sec-sdk/blob/main/src/agentic_security/runtime.py)

Successful execution and rejected-result paths correctly convert persistence
failure into `EXECUTED_UNRECORDED`, but timeout and handler-failure paths do not.
The runtime may therefore return an uncertain result without clearly indicating
that its terminal state was not durably recorded.

## Remaining P2 issues

### P2 — Documentation reports incorrect mutation figures and timeout

The actual current result is `1,973 / 2,374 = 83.11%`, but documentation states
`1,974 / 2,372 = 83.22%`:

- [docs/critical-adopter-review-2026-07-25.md](critical-adopter-review-2026-07-25.md)
- [docs/production-readiness.md](production-readiness.md)

The mutation baseline allows 600 seconds, while release documentation still says
120 seconds:

- [`mutation-baseline.json`](https://github.com/tommycharade/aai-sec-sdk/blob/main/mutation-baseline.json)
- [docs/releasing.md](releasing.md)

This undermines evidence credibility.

### P2 — CI does not verify the exact published bundle

The release workflow verifies the build job's `dist/` directory, but the
published release later contained additional evidence assets that were not
included in the checksum manifest.

The process needs a post-publication or exact release-bundle verification step
that checks what adopters actually download.

### P2 — “Immutable” component claims are shallow

`ActionFacts` and `ExecutionPermit` are frozen dataclasses, but validated
arguments are typed as `Any` and may contain mutable nested structures:

- [`src/agentic_security/components.py`](https://github.com/tommycharade/aai-sec-sdk/blob/main/src/agentic_security/components.py)

The documentation should either deep-freeze/normalize arguments or qualify the
immutability claim.

### P2 — Durable deployment evidence remains absent

Adopters still need to provide and validate:

- multi-process durable idempotency;
- WORM or immutable audit storage;
- provider-side IAM enforcement;
- genuine container, microVM, or WASM isolation;
- sandbox escape testing;
- real remote policy and approval integrations.

These limitations are documented in
[docs/production-readiness.md](production-readiness.md).

## Workload recommendation

| Workload | Decision |
| --- | --- |
| Read-only, low-risk tools | Go |
| Trusted internal handlers | Conditional go |
| Credentialed state changes | Conditional, after durable adapter tests |
| Payments, deletion, messaging, account mutation | No-go |
| Hostile or model-generated code | No-go without real sandboxing |
| Regulated workloads | No-go pending deployment evidence and release verification |

## Commercial assessment

A commercial edition could be valuable to enterprise platform and security teams.
Potential paid capabilities include:

- managed transactional idempotency;
- immutable audit and SIEM integration;
- hosted approval and policy control;
- managed IAM and credential brokering;
- hardened sandbox execution;
- fleet-wide emergency stop and health monitoring;
- compliance evidence and support SLAs.

The Apache-2.0 runtime, contracts, tests, documentation, and local reference
implementations should remain open source.

## Final recommendation

**Conditional go for pilots; no-go for consequential production use until:**

1. The published release bundle passes independent checksum verification.
2. Provenance is bound to the actual release tag.
3. Timeout and exception paths surface failed idempotency persistence.
4. Documentation is synchronized with actual evidence.
5. At least one release is independently reproducible and verifiable by an
   external adopter.

## Resolution follow-up

The follow-up implementation addresses the actionable P1/P2 findings as
follows:

1. Release mutation evidence is copied into `dist/` before `SHA256SUMS` is
   generated, so the checksum manifest covers every published evidence file.
2. The release workflow is tag-only, publishes the exact checked bundle, and
   downloads that GitHub Release bundle for post-publication verification.
   Attestation verification uses the full tag ref rather than the default
   branch.
3. Timeout, cancellation, and exception paths now expose whether terminal
   idempotency recording succeeded through `ExecutionResult.idempotency_recorded`.
   A persistence failure is surfaced as an uncertain outcome instead of being
   silently discarded.
4. Mutation figures and timings are now release-evidence-driven, with the
   documented 600-second baseline aligned to the repository configuration.
5. `ActionFacts` recursively freezes supported argument structures, and
   handlers receive a defensive thawed copy. The API and security-model docs
   describe this boundary precisely.
6. Deployment-owned evidence requirements are explicit in
   [deployment-evidence.md](deployment-evidence.md), including durable
   idempotency, WORM audit, provider IAM, real isolation, escape testing, and
   remote policy/approval integration tests.

The corrected implementation is intended for a new patch release. The
historical findings above remain unchanged so that the review record is
auditable; release verification evidence for the corrected tag should be
attached to the release and linked from the release notes.
