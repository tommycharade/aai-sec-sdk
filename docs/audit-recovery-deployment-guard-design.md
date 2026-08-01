# Persistent audit-recovery deployment guard

## Decision

Cross-region audit recovery is deployment authority, not ambient shell state.
The primary control-plane deployer loads one reviewed, secret-free recovery
manifest from encrypted Parameter Store and removes any ambient
`AUDIT_REPLICA_*` values before synthesis. Once the stack reports a replica,
losing that manifest blocks deployment instead of silently removing the S3
replication rule.

The manifest binds one exact destination bucket ARN, a distinct AWS Region and
an opaque recovery-review reference. Configuration succeeds only when AWS
proves that the destination is versioned and defaults to at least 365 days of
COMPLIANCE Object Lock. A post-deployment check requires the exact destination,
region and historical Batch Replication role outputs.

## Historical repair

Live S3 replication protects versions written after a rule is active; it does
not repair older versions. `scripts/backfill_aws_audit_replication.py` creates a
bounded S3 Batch Replication job for exact versions with `NONE`, `FAILED` or
`COMPLETED` replication status at a fixed cutoff. `COMPLETED` versions are
intentionally reprocessed: their bytes may exist while destination retention or
metadata is stale after a later source-side change. The script:

- counts source versions and refuses more than the reviewed safety bound;
- asks S3 to generate the version-aware manifest in the source Region;
- uses a dedicated least-privilege Batch Operations role;
- writes a provider completion report outside the immutable audit namespace;
- fails on timeout, terminal provider failure or any failed task.

The role can initiate replication for source audit objects and write only under
the recovery-report prefix. The existing S3 replication role remains the
principal authorized to read immutable source versions and create replicas.
Replication metrics enable object-level failed/not-tracked events, which enter
the existing durable security-alert SNS/SQS channel with provider failure
reasons. CloudWatch replication metrics are best-effort and published in the
destination Region, so they are not treated as the sole failure signal.
The rule uses the explicit V2 schema required by metrics: priority 1, an empty
prefix that covers every evidence object, and disabled delete-marker replication
because delete markers are not retained evidence records.

## Independent acceptance

`scripts/verify_aws_audit_recovery.py` does not trust the Batch Operations
completion count. It independently enumerates both versioned buckets and
requires exact key/version identity and canonical ordering, SHA-256 equality,
preserved content-digest metadata, COMPLIANCE mode, destination retention no
shorter than source retention and `REPLICA` provenance. Verification is bounded
and emits a canonical manifest digest suitable for retained acceptance evidence.

Delete markers are not evidence records and are excluded from the retained
version proof. Production audit writers never delete records; unexpected delete
markers should be investigated separately.

## Failure and recovery

- Missing or malformed persisted authority: deployment stops before synthesis.
- Same-region or weakly retained destination: configuration and deployment stop.
- Historical job failure: live replication remains enabled; inspect the
  completion report, correct the failure and rerun the idempotent repair.
- Verification mismatch: do not declare recovery ready. Preserve both provider
  reports and verifier output, then investigate the exact object/version.

This control proves immutable audit data recoverability. It does not by itself
provide a second regional API, an approved RTO/RPO or automated control-plane
failover.
