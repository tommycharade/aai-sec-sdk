# Cross-region audit recovery acceptance — 2026-08-01

## Outcome

**Accepted for the deployed P0-08 evidence boundary.** The live AWS exercise
recovered and independently verified all 603 immutable audit object versions
from the primary `eu-west-2` bucket in the `eu-west-1` recovery bucket. Exact
key/version identity, canonical ordering, bytes, digest metadata, COMPLIANCE
mode, retain-until parity and S3 replica provenance all passed.

This proves recoverability of the audit evidence set. It does not prove a
regional control-plane failover, an approved RTO/RPO or customer-operated DR;
those remain under P0-11.

## Deployed boundary

| Item | Live value |
| --- | --- |
| AWS account/profile | `396510133537` / `p1` |
| Primary stack | `AaiSecControlPlane`, `UPDATE_COMPLETE` |
| Primary Region | `eu-west-2` |
| Recovery Region | `eu-west-1` |
| Source bucket | `aaiseccontrolplane-auditbucketb01e0ae8-wgrcz2izyuj2` |
| Replica bucket | `aaisecauditreplica-auditreplicabucketd9f6ff2a-smxacsrsl53i` |
| Recovery manifest | `/aai-sec/AaiSecControlPlane/audit-recovery`, encrypted `SecureString`, version 1 |
| Recovery feature merge | `f1deeb034069f47b2648f70e44f867feb1b6c562` |
| Replication-schema fix | `ff9ffd95a81a50889838ad282bd36ee514a0cf5e` |
| Retention-parity fix | `89639a262ba10a7d3a0a0ea5258c29c2421e2487` |

The deployed rule uses priority 1, an empty-prefix all-object filter,
delete-marker replication disabled and replication metrics enabled. S3
`OperationFailedReplication` and `OperationNotTracked` events target the
durable security-alert SNS/SQS path. The exact source bucket, replica ARN,
replica Region and dedicated Batch Operations role are CloudFormation outputs.

## Test sequence and evidence

### 1. Fail-closed deployment authority

The recovery manifest was validated against live AWS before persistence. The
destination proved versioning `Enabled`, Object Lock `Enabled` and a default
365-day `COMPLIANCE` period. The deployment helper removed ambient replica
variables and loaded the persisted manifest. A later deploy without that
manifest is contract-tested to stop before synthesis when the stack already
reports replication.

### 2. Live-write smoke test

The repeatable smoke command wrote
`replication-smoke/fd3079ecb89b45d89765b350ccb75c90.json` to the source. The
destination received the same version ID
`7QrM8GiH4nS9ihjiqOByXcm2GL.lXnvB`, synthetic metadata, COMPLIANCE lock and
`ReplicationStatus=REPLICA` within the 180-second bound. The source reported
`COMPLETED`.

### 3. Historical absence repair

Before repair the source held 602 versions and the recovery bucket held 37.
After the smoke write, the fixed-cutoff Batch Replication job
`21b603ab-0956-4eed-bce0-b8eeb6b902a8` selected exact `NONE`/`FAILED` versions:

- cutoff: `2026-08-01T22:21:32.074127+00:00`;
- source versions at cutoff: 603;
- tasks: 565 total, 565 succeeded, 0 failed;
- active execution: 84 seconds;
- all-task report prefix:
  `replication-reports/bce80119-e553-4360-ac1b-ae63be1f94e8`.

### 4. Independent verifier found retention drift

The provider's successful task count was not accepted as recovery proof. The
independent verifier found that 37 older replicas had matching bytes and
version IDs but retained their original 365-day lock after source retention was
extended to 730 days. Exact example:

| Version | Source retain-until | Replica retain-until before repair |
| --- | --- | --- |
| `Io9CPXTxq5jVwdMEF5vIF1PCtUtmMqs4` | `2028-07-31T21:13:36Z` | `2027-07-27T12:38:41.636Z` |

Acceptance failed at this point. The repair tool was changed to include
`COMPLETED` versions, because a provider completion status proves a prior copy,
not current retention or metadata parity. The regression is documented and
tested in merge `89639a2`.

### 5. Retention-parity repair

Job `d313817c-7d1c-48bd-8b6f-61ff71032df1` ran from the exact merged repair:

- cutoff: `2026-08-01T22:34:29.291000+00:00`;
- filter statuses: `COMPLETED`, `FAILED`, `NONE`;
- tasks: 603 total, 603 succeeded, 0 failed;
- active execution: 84 seconds;
- all-task report prefix:
  `replication-reports/50cfad73-73f4-4f8c-b505-84a1c60cd84a`.

The known stale version then matched exactly: both source and replica retained
COMPLIANCE mode through `2028-07-31T21:13:36Z`.

### 6. Complete independent verification

`scripts/verify_aws_audit_recovery.py` independently listed and fetched every
exact version from both buckets. It did not trust either Batch Operations
report. Final result:

```json
{
  "canonicalManifestSha256": "d4acc0a8c32b073c2ce0e264028913fae544da24f50d720ff822a3e96a6591aa",
  "replicaRegion": "eu-west-1",
  "sourceRegion": "eu-west-2",
  "verifiedVersions": 603
}
```

The source and replica each contained exactly 603 object versions. Every pair
had the same key and version ID, SHA-256 body digest and `content-sha256`
metadata value (including matching absence for legacy synthetic records), and
the replica was COMPLIANCE-locked through at least the source retain-until date
with `ReplicationStatus=REPLICA`.

The source had five historical delete markers and the replica had zero. This is
intentional: delete markers are not retained evidence records, production audit
writers do not delete evidence, and the V2 rule explicitly excludes them. The
603-version proof therefore covers the complete evidence object set rather than
claiming delete-marker parity.

## Operational observations

- The shared security-alert queue remained at three visible, zero in-flight and
  zero delayed messages across the successful parity job; existing messages
  were not received or deleted because that would alter their delivery state.
- The unauthenticated API continued to return HTTP 401 after rollback and after
  the successful deployment.
- The first metrics-enabled deployment failed safely because the rule used the
  S3 V1 schema. CloudFormation reached `UPDATE_ROLLBACK_COMPLETE`; no audit
  versions were changed or deleted. The V2 schema fix passed all CI gates and
  deployed from merge `ff9ffd9` before any batch repair ran.
- Microsoft Entra ID/SCIM and runtime attestation remain `not-configured` in
  this development stack. They are separate rollout gates and are not implied
  by this evidence-recovery acceptance.

## Re-run commands

```bash
python3 scripts/test_aws_audit_replication.py \
  --source-bucket <source> --source-region eu-west-2 \
  --replica-bucket <replica> --replica-region eu-west-1 --profile p1

python3 scripts/backfill_aws_audit_replication.py \
  --source-bucket <source> --report-bucket <report-bucket> \
  --role-arn <batch-role-arn> --region eu-west-2 --profile p1

python3 scripts/verify_aws_audit_recovery.py \
  --source-bucket <source> --source-region eu-west-2 \
  --replica-bucket <replica> --replica-region eu-west-1 --profile p1
```

Do not declare recovery accepted from object count, a smoke write or a green
provider job alone. The independent full-version verifier is the acceptance
boundary.
