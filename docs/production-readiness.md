# Production readiness

This page is the adoption decision guide for the current `0.x` SDK. It is
explicit about what the open-source runtime enforces locally and what must be
supplied and verified by a deployment.

## Current recommendation

The SDK is suitable for controlled production use with trusted handlers and
low-risk or read-only actions when the deployment supplies authenticated policy,
approval, IAM, audit, idempotency, and isolation infrastructure.

It is not, by itself, a sufficient security boundary for payments, destructive
operations, hostile or model-generated code, or regulated workloads.

The SDK is a security-runtime framework. It is not an LLM safety oracle, IAM
replacement, sandbox, compliance certification, business authorization system,
or guarantee that an external side effect can be cancelled after a timeout.

## Capability and responsibility matrix

| Control | SDK provides | Deployment must provide |
| --- | --- | --- |
| Tool authorization | Typed runtime boundary, deny-by-default checks, policy and approval contracts | Authenticated policy and approval services, domain authorization |
| Identity and tenancy | Application-owned context, principal/resource consistency checks | Authentication, principal lifecycle, tenant policy |
| Credentials | Scoped credential contracts, provider-token attestation checks, secret-use boundary | IAM enforcement, token service, rotation, revocation, provider-side scope proof |
| Idempotency | Stable operation keys, collision checks, atomic store protocol, safe in-memory reference | Transactional multi-process store, retention, recovery, domain reconciliation |
| Timeouts | Phase-specific outcomes, bounded waits, lifecycle accounting, health signals | Cooperative cancellation or isolated workers, dependency capacity and alerting |
| Isolation | Typed nonce-bound attestation contract and verifier interface | Real container, microVM, WASM, or equivalent sandbox and trusted verifier |
| Audit | Redaction, hash-chain verification, fsync/local sink, remote exporter contract | Immutable/WORM retention, access control, replication, legal hold, monitoring |
| Supply chain | Checksums, artifact SBOMs, provenance verification workflow | Promotion policy, independent verification, registry controls, release approval |

## Required controls by workload

### Low-risk read-only actions

At minimum:

- explicit tool allow-list;
- authenticated principal and tenant context;
- argument and resource validation;
- bounded steps, time, concurrency, rate, fan-out, and cost;
- redacted audit sink;
- tested denial and timeout handling.

### Credentialed or state-changing actions

Add:

- a transactional `IdempotencyStore`;
- stable caller-supplied `operation_key` values;
- action-bound approvals for high-impact operations;
- provider-side IAM scope verification;
- remote immutable audit export;
- reconciliation procedures for every uncertain outcome;
- operational alerts for worker saturation and dependency outages.

### Hostile or model-generated code

Add all of the above plus:

- `requires_isolation=True`;
- a trusted, nonce-bound `IsolationVerifier`;
- a real OS/container/microVM/WASM sandbox;
- restricted filesystem, network, identity, and resource policy;
- no direct credential exposure to the worker;
- adversarial sandbox escape and downgrade tests.

The included `SubprocessToolHandler` is only a no-shell process boundary. A
Python callable or `isolated=True` attribute is not isolation evidence.

## Release evidence

Before adopting a release, run:

```bash
make check
make mutation
make package-check
make security-check
```

Expected evidence includes passing tests and coverage, a successful bounded
mutation run whose evidence names the exact 3-file scope, score, commit, and
tool, clean wheel and source builds, legal metadata, dependency audits,
artifact-matched checksums and complete per-artifact SBOMs, verified
provenance, and a clean reviewed release commit/tag. The artifact build and
independent clean verification are separate release steps.

`make check` validates the mutation contract and normal quality gates. The
actual mutation score is established only by a successful `make mutation` run.
A mutation score is assurance evidence, not a security certification; the
score must never be copied between commits or scopes.

## Failure and retry rules

Do not blindly retry a result with `timeout_phase=HANDLER` or
`RECONCILIATION`, `side_effect_state=UNCERTAIN`, reconciliation state
`STILL_RUNNING`/`UNKNOWN`/`FAILED`, `EXECUTED_UNRECORDED`, idempotency state
`IN_PROGRESS`/`UNCERTAIN`/`EXPIRED`, audit replication failure, or missing,
expired, or unverifiable isolation or credential attestation.

Use the stable operation key and the domain reconciliation system to determine
whether the side effect completed. See [Operational runbooks](runbooks.md).

## Adoption evidence checklist

Before production approval, retain:

- threat model and data-flow review;
- policy, approval, and IAM contract tests;
- durable idempotency restart and concurrency tests;
- isolation attestation and sandbox escape tests;
- remote audit replication and corruption-recovery tests;
- worker saturation and emergency-stop tabletop evidence;
- release checksums, SBOM, and provenance verification output;
- incident contacts, escalation rules, retention requirements, and rollback plan.

Passing repository checks does not replace these deployment acceptance artifacts.

## Commercial edition boundary

The Apache-2.0 core should remain open and usable. Commercial value belongs in
operational assurance and managed infrastructure: hosted policy and approval,
durable idempotency, immutable audit and SIEM integrations, managed IAM and
attestation, hardened sandbox execution, fleet-wide emergency stop and health
dashboards, compliance evidence, support SLAs, and maintained enterprise
adapters.

Paid functionality must not be required for the core’s fail-closed behavior,
public contracts, security fixes, or documentation.
