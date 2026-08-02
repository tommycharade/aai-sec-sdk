# Regional activation and recovery-exercise guard

## Decision

Regional failover and failback are manual, independently approved transitions.
No health check, model, browser state or shell environment may activate a cell.
The supported preflight is `scripts/plan_aws_regional_activation.py`; it is
read-only and has no activation command. It emits a nine-step plan only after
reviewed authority, retained evidence and current AWS provider state agree.

The preflight is intentionally separate from a future transition executor. An
executor must repeat every provider check immediately before each conditional
change. A plan is evidence that activation was ready at one instant, not a
capability, lease or permission to skip a later check.

## Authority and evidence

One schema-v1 activation manifest authorizes exactly one transition UUID and
direction. It fixes the primary, recovery, source and target Regions; stable
API/UI domains; hosted zone; target fleet; RTO/RPO; approval reference; and one
exact S3 evidence object version. The authority:

- expires within one hour;
- requires `activationPermitted: true` and `automaticActivation: false`;
- maps failover only from primary to recovery and failback only in reverse;
- rejects unknown, missing and duplicate JSON fields; and
- binds the evidence bucket ARN, key, version ID and SHA-256.

The evidence object must be in the primary immutable audit bucket derived from
persisted CloudFormation/recovery authority. The preflight requests the exact
version ID, hashes no more than 1 MiB, compares the `content-sha256` metadata,
and requires live `COMPLIANCE` retention beyond both the current time and
manifest expiry. A mutable latest version, copied local file or browser claim
is not accepted.

## Required provider-state checks

Before returning a plan, the preflight independently requires:

1. byte-equivalent persisted regional, evidence-continuity and passive-cell
   manifests;
2. matching Region, fleet, RTO and RPO authority across all manifests;
3. a stable deployed passive stack whose provider output is
   `staged-not-serving`;
4. protected primary/recovery Cognito pools, tenant-specific Microsoft Entra
   federation, configured SCIM and the exact recovery pool in retained
   evidence;
5. both live S3 replication rules and COMPLIANCE Object Lock posture;
6. disabled raw `execute-api` endpoints in both Regions;
7. both reviewed stable DNS names in the exact Route 53 hosted zone; and
8. the complete retained activation bundle.

The activation bundle must prove all four Global Tables are active, protected
and inside RPO; 100% managed-endpoint signer trust; signing/verification;
bidirectional immutable audit; zero job conflicts; source routing; fleet load;
dependency failures; policy/identity/approval/idempotency/audit consistency;
backup/key recovery; two independent approvers; break-glass rehearsal; source
fencing; and failback readiness.

## Measured recovery exercise

`scripts/run_regional_recovery_exercise.py` owns measurement and aggregation.
A provider adapter may execute one synthetic probe, but cannot provide an
aggregate pass assertion. The harness:

- measures every unique synthetic agent with 1–128 workers and a maximum
  100,000-agent fleet;
- computes deterministic nearest-rank p99 heartbeat, policy-read and
  decision-write latency itself;
- requires p99 heartbeat/policy read at or below 1 second, p99 decision write
  at or below 2 seconds and an error rate at or below 1%;
- sequentially injects audit, Cognito, DynamoDB, KMS and queue failures and
  requires detected failure, denied execution, no bypass and safe recovery;
- exercises approval, audit, identity, idempotency and policy consistency; and
- refuses replay, more than one side effect or any authority widening.

The generic harness is not itself a live AWS adapter. Its typed adapter
boundary exists so the eventual AWS driver can use synthetic tenant identities
and bounded fault controls without placing credentials or customer data in the
evidence schema. Until that adapter runs during a rehearsed activation and its
output is retained, load/dependency/consistency acceptance remains incomplete.

## Ordered transition

The verifier emits this order and no alternate ordering:

1. freeze the change window with two independent approvers;
2. fence source compute;
3. verify the source is non-serving and direct origins are closed;
4. activate only the target runtime authority;
5. reconcile Region-local jobs from exact DynamoDB revisions;
6. run target smoke and consistency checks;
7. compare-and-swap stable routing;
8. verify operator and target-fleet convergence; and
9. seal immutable transition evidence in both Regions.

Failback uses the same order with source and target reversed. DNS never moves
before source fencing, target smoke and exact job reconciliation.

## Threats and controls

| Threat | Control | Failure posture |
| --- | --- | --- |
| Stale approval is replayed | Canonical UUID, one-hour expiry and exact direction | Manifest rejected |
| Evidence is replaced | Exact S3 version, body SHA-256 and digest metadata | Preflight rejected |
| Retention is weakened | Live COMPLIANCE mode and retention beyond authority expiry | Preflight rejected |
| Alternate bucket is supplied | Bucket ARN derived from persisted primary audit authority | Preflight rejected |
| Two cells serve simultaneously | Source fence precedes target authority and DNS | No transition plan/execution |
| Raw API bypasses stable routing | Both execute-api defaults must be disabled | Preflight rejected |
| Load adapter self-certifies | Harness computes population, p99 and error rate | Exercise rejected |
| Dependency outage creates bypass | Five named fault probes require denied execution | Exercise rejected |
| Approval/idempotency replays effects | Side-effect count is bounded to one with no widening | Exercise rejected |
| Malformed measurements exploit Python coercion | Explicit non-boolean numeric bounds | Evidence rejected |

## Operator usage

Create four reviewed files outside the repository: the time-bounded activation
manifest, regional recovery manifest, evidence-continuity manifest and real
passive-cell manifest. Do not use the synthetic example identity.

```bash
python3 scripts/plan_aws_regional_activation.py \
  --manifest /absolute/path/to/activation-manifest.json \
  --regional-recovery-config /absolute/path/to/regional-recovery.json \
  --evidence-continuity-config /absolute/path/to/evidence-continuity.json \
  --passive-cell-config /absolute/path/to/passive-cell.json \
  --profile p1
```

Exit code `2` identifies the first fail-closed blocker. Exit code `0` prints
`activationExecuted: false`, the repeated provider evidence and the ordered
plan. It never changes Lambda concurrency, IAM, event mappings, schedules,
custom domains or Route 53 records.

## Current non-guarantees

This tranche does not deploy identity, activate the passive cell, implement
the conditional transition executor or prove live RTO/RPO. The current AWS
environment still requires Microsoft Entra/SCIM, recovery Cognito, real managed
endpoint trust convergence, stable domains, direct-origin closure and the live
recovery exercise. P0-11 therefore remains **Partial**.
