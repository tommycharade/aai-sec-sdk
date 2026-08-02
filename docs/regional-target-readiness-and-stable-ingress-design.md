# Regional target readiness and stable ingress

## Outcome

The guarded transition now has an implemented pre-routing target-readiness
step. Stable ingress remains a reviewed design until customer-owned domains,
certificates and change authority exist. These boundaries are separate on
purpose: live compute and reconstructed jobs do not imply that traffic may
move, and the presence of DNS records does not imply that the target is safe.

## Implemented target-readiness step

`reconcile-target` is available only after the journal reaches
`TARGET_ACTIVE_NOT_ROUTED`. It repeats the complete provider preflight but now
requires the deployed recovery stack to report exactly `active-not-routed`.
It then:

1. transactionally claims `RECONCILING_TARGET_JOBS` in the third-Region
   witness;
2. independently re-verifies the complete source fence;
3. discovers exactly one handler, two workers, two queue mappings and four
   schedules from stable CloudFormation state;
4. reads each live Lambda configuration and requires the reviewed concurrency,
   handler, memory, timeout, architecture, code digest, revision, Python
   runtime, activation-evidence digest, recovery signer and Entra authority;
5. requires both mappings and all schedules to be enabled;
6. invokes the exact target handler in read-only `check` mode;
7. invokes `apply`, which rebuilds Region-local queue work only from strongly
   read DynamoDB job and policy revisions;
8. polls with a bounded ten-minute window until no dispatch/fail action
   remains; fresh running jobs may remain explicitly deferred; and
9. re-reads the target and rejects any code/config revision change during the
   step; and
10. records `TARGET_JOBS_RECONCILED_NOT_ROUTED` with a SHA-256 over the source
   fence, live target posture, initial check, apply result and final check.

The Lambda response is untrusted. Duplicate JSON keys, unknown fields,
booleans-as-counts, oversized counts, a changed evidence digest, a different
queue source, inconsistent dispatch totals, Lambda errors and oversized output
all fail closed. If the process or provider fails after dispatch, the journal
remains in progress. The same authority may retry; FIFO deduplication and
revision-conditioned workers prevent repeated committed effects. A completed
retry must match the exact evidence digest already appended to the journal.

This is a runtime and job-reconciliation smoke, not a public-ingress smoke. The
raw `execute-api` endpoints remain disabled and traffic remains on the source.
A future route command must repeat a zero-action reconciliation check
immediately before claiming routing; it cannot rely indefinitely on this
earlier result.

## Stable ingress decision

The target design uses Regional API Gateway custom domains in both Regions.
AWS documents that Regional APIs deployed in multiple Regions may use the same
custom domain name. Each Region requires its own same-Region ACM certificate.
Route 53 aliases can then select the active Regional endpoint.

The two stable names are implemented consistently:

- `stableApiDomain` maps to the Region's existing authenticated control-plane
  API stage;
- `stableUiDomain` maps to a small Regional REST API that reads only the exact
  private UI bucket through an API Gateway-to-S3 service integration;
- both Regional APIs disable their default `execute-api` endpoint;
- TLS 1.2 is mandatory and certificates, API mappings, S3 role scope and
  hosted-zone identity are independently verified; and
- separate Region-specific canary names reach each regional API/UI endpoint
  before stable traffic moves.

The UI proxy is deliberately serverless. It trades some CDN performance for a
single routing primitive that can move the UI and API together. A later CDN may
sit in front only if it preserves atomic regional authority and does not
reintroduce a globally unique alternate-domain conflict.

AWS references:

- [API Gateway Regional endpoint types](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-endpoint-types.html)
- [Regional custom-domain setup](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-regional-api-custom-domain-create.html)
- [API Gateway S3 proxy integration](https://docs.aws.amazon.com/apigateway/latest/developerguide/integrating-api-with-aws-services-s3.html)
- [Route 53 transactional change batches](https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html)

## Routing compare-and-swap

Route 53 change batches are transactional—all records in a valid batch change
or none do—but Route 53 does not expose a conditional generation token. The
single-writer witness therefore remains the CAS authority. The planned route
step is:

```text
TARGET_JOBS_RECONCILED_NOT_ROUTED
  -> VERIFYING_TARGET_INGRESS
  -> TARGET_INGRESS_VERIFIED_NOT_ROUTED
  -> ROUTING_TARGET
  -> VERIFYING_STABLE_ROUTE
  -> STABLE (generation + 1, activeRegion = target)
```

Before `ROUTING_TARGET`, the executor will repeat source fencing, target live
posture, zero-action job reconciliation, canary authentication, policy read,
signed decision write and immutable audit verification. It will strongly read
the witness generation and exact current Route 53 API, UI and generation-marker
records. One Route 53 change batch will delete the byte-equivalent source
aliases and marker and create the exact target aliases and next marker. It will
wait for the returned change ID to become `INSYNC`, then independently read
Route 53 and probe both stable names before committing the new journal
generation.

An out-of-band DNS administrator could still race the provider between the
exact read and Route 53 mutation. Production acceptance therefore also
requires a dedicated transition role, removal of ordinary Route 53 write
authority, an organization SCP or equivalent permission boundary, CloudTrail
alerting and AWS Config drift detection. Without that control, the adapter can
detect divergence but cannot truthfully claim provider-level CAS.

## Failed cutover and failback

If Route 53 rejects the change batch, no DNS record changes and the journal
remains `ROUTING_TARGET`. If Route 53 accepts the batch but stable probes fail,
the executor must not mark the target stable. A separately recorded rollback
phase applies the exact inverse transactional batch, waits for `INSYNC`, proves
source routing and leaves the failed transition sealed for investigation.

Failback is not implemented by swapping labels in the failover code. The
primary runtime needs the same active-template verifier, target job
reconciliation, regional ingress and canary contracts first. Only then may the
same state machine run with source and target reversed.

## Current blockers and non-guarantees

Implementation of stable ingress and routing still requires:

- approved stable and regional-canary names in one Route 53 hosted zone;
- primary and recovery ACM certificate ARNs covering those names;
- deployment of the recovery Cognito/Entra configuration and regional cell;
- customer approval for the dedicated routing role and organization-level DNS
  write restriction; and
- a scheduled two-person recovery exercise.

No Route 53, certificate, custom-domain, UI proxy or live AWS transition was
created by the target-readiness tranche. P0-11 remains **Partial**.
