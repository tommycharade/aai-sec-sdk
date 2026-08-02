# Regional recovery storage and trust acceptance — 2026-08-02

## Result

The AWS storage and staged signing-trust foundations passed against the live
pilot account on 2026-08-02. This closes phases 1 and the infrastructure portion
of phase 2 in the [regional recovery design](regional-control-plane-recovery-design.md).
It does **not** make P0-11 complete and does not authorize regional traffic.

The reviewed authority targets 1,000 agents, a 30-minute RTO and a 60-second
DynamoDB RPO, with `eu-west-2` primary and `eu-west-1` recovery. It is stored as
SecureString parameter `/aai-sec/AaiSecControlPlane/regional-recovery`, version
1, only after the storage checks succeeded.

## Live storage evidence

The primary stack ended `UPDATE_COMPLETE`. The control, presence, idempotency
and SCIM lifecycle tables were all independently observed `ACTIVE` in both
Regions with point-in-time recovery and deletion protection enabled. Exact
synthetic content was created in the primary, observed in recovery, conditionally
deleted and then observed absent in recovery:

| Store | Create replication | Delete replication | Content digest prefix |
| --- | ---: | ---: | --- |
| Control | 1.404 s | 0.736 s | `d13efeef084c` |
| Presence | 3.162 s | 2.543 s | `747b8ea3bf14` |
| Idempotency | 1.416 s | 2.483 s | `692b3cf853ad` |
| SCIM lifecycle | 3.185 s | 2.508 s | `44ca31a2f7ec` |

Every measurement was below the 60-second RPO. The first preparation attempt
correctly withheld both canaries and persisted authority when one provider-side
table update had not converged. The operator tool was tightened to wait for
active, protected, PITR-enabled posture in both Regions; the repeated exercise
then passed. Existing replicas were retained throughout.

## Live signing-trust evidence

Recovery stack `AaiSecRegionalRecovery` ended `CREATE_COMPLETE`. The staged
P-256 `SIGN_VERIFY` keys have the same multi-Region key ID:

- primary: `arn:aws:kms:eu-west-2:396510133537:key/mrk-be901b9e4d604c039103a052869d3227`;
- replica: `arn:aws:kms:eu-west-1:396510133537:key/mrk-be901b9e4d604c039103a052869d3227`.

AWS reported the intended `PRIMARY`/`REPLICA` relationship and both keys
enabled. The deployed single-Region signer remains active, so no policy signing
authority changed. A mode-`0600` overlap bundle was generated with the existing
signer plus both multi-Region identities. The primary and replica public keys
had the same SHA-256 fingerprint; the existing signer remained distinct.

The enrolled local Kratos Claude Code configuration uses hosted AWS session
policy retrieval and does not currently reference an administrator-owned local
trust-bundle path. Therefore this exercise does not claim endpoint trust
convergence. Signer cutover remains prohibited until the managed host package
publishes the overlap and every governed endpoint reports its exact digest.

## Negative and boundary evidence

- Unauthenticated access to the active API returned HTTP 401 after deployment.
- Recovery evidence explicitly reports `trafficActivated: false`,
  `identityReplicated: false` and `activeSigningKeyChanged: false`.
- The recovery stack contains only the retained KMS replica; it has no API,
  Cognito pool, worker, UI or routing resource.
- Tooling rejects malformed/duplicate manifests, divergent persisted authority,
  unsafe table posture, content mismatch, RPO timeout, unrelated KMS material,
  malformed KMS relationships and premature signer activation.

## Remaining P0-11 gates

P0-11 remains **Partial**. The following evidence is still required:

1. publish the overlap through managed endpoint configuration and prove fleet
   convergence before activating the multi-Region signer;
2. configure and exercise Cognito multi-Region replication with the pilot Entra
   tenant and Conditional Access;
3. deploy the passive API, workers, alerts and UI without opening a direct-origin
   bypass;
4. prove bidirectional immutable audit writes and authoritative queue/job
   reconciliation;
5. meet the target with 1,000 simulated agents under load and dependency loss;
6. rehearse backup restore, emergency access, key recovery, failover and
   failback within the approved RTO/RPO.
