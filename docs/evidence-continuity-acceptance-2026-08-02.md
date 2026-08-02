# Evidence continuity acceptance — 2026-08-02

## Result

P0-11 phase 5 evidence continuity passed in AWS account `396510133537` between
the primary `eu-west-2` and recovery `eu-west-1` Regions at
`2026-08-02T05:16:07Z`. This acceptance covers bidirectional immutable audit
replication and read-only recovery-job planning. It does not activate the
passive API, workers, schedules, routing, identity replica or signing key.

## Deployment evidence

The provider-state guard loaded the persisted regional and audit-recovery
authorities, derived both bucket identities from CloudFormation, stripped
ambient deployment variables and synthesized both stacks. The independent
template verifier passed before either update:

| Direction | Rule | Verified template SHA-256 |
| --- | --- | --- |
| Primary to recovery | `replicate-audit-to-recovery-region` | `b90365d0b15301ff46e41e3540beeff8fb184650a25c8f417fe955dabddf4f40` |
| Recovery to primary | `replicate-recovery-audit-to-primary-region` | `4c3bf65f68046e957fca48367af6cdb69ead79338b82f0f9b16c9acb8b4a2c36` |

The exact verified CDK assemblies were deployed without re-synthesis. Recovery
was updated first, followed by primary. Post-deployment provider reads passed
for both source buckets and proved:

- versioning enabled;
- 365-day COMPLIANCE Object Lock defaults;
- one exact enabled V2 rule per direction;
- replica-modification sync enabled;
- delete-marker replication disabled; and
- the exact opposite retained bucket ARN as destination.

The persisted phase authority explicitly has `activationPermitted:false` and
is stored at `/aai-sec/AaiSecControlPlane/evidence-continuity`.

## Retained two-direction canary

The guard wrote one synthetic COMPLIANCE-locked object in each Region. Both
objects remain retained. For each direction the test required the exact version
ID, bytes, SHA-256 metadata, COMPLIANCE mode, unshortened retention and
`REPLICA` provenance in the opposite Region. It then extended retention and
added a unique proof tag on the replica and waited for both modifications to
return to the origin.

| Direction | Retained key | Version ID | Content SHA-256 |
| --- | --- | --- | --- |
| Primary to recovery | `continuity-canary/primary-to-recovery/5d1ba51dcb6b4e0ab20492bd3bfca679.json` | `XJL3b1X0t5ewHbGc2pBCL0mT2459yTmm` | `5a929d29fb36ed1f5769ee28427bef69b5007a9861973859ad43d0becd355f04` |
| Recovery to primary | `continuity-canary/recovery-to-primary/5425e01ff9624322a9dee592ef021e69.json` | `XEBSCu6VLFTCpvvBFodMAMCd71s_06uH` | `791900555a14a6003274ca76e6fb3351dd05380da0eb4a769fd3397bc1e71da3` |

No object or delete marker was removed or created by cleanup.

## Recovery-job evidence

The deployed primary handler received the exact internal event in `check` mode.
It read the authoritative control Global Table and returned:

```json
{
  "deferredJobs": 0,
  "dispatchedJobs": 0,
  "failedStaleJobs": 0,
  "mode": "check",
  "plannedActions": 0,
  "processedTenants": 1,
  "queueSource": "authoritative-dynamodb-job-records"
}
```

The approval reference was represented only by SHA-256
`f9fa6013889c1d53c785dda7e49f9a051886ac5a7bc33fe94d10ccbcb601fbfd`.
No SQS message was read, copied or dispatched. The deployed environment keeps
`RECOVERY_JOB_RECONCILIATION_ENABLED=false`; `apply` also requires
`PASSIVE_CELL_MODE=active`, so phase 5 did not create recovery execution
authority.

## Remaining P0-11 work

This result closes the phase-5 evidence-continuity prerequisite, not regional
failover. Cognito/Entra recovery identity, the passive-cell deployment, signer
cutover, endpoint routing, 1,000-agent load and the approved failover/failback
exercise remain required before P0-11 can be complete.
