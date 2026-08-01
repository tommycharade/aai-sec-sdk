# Asynchronous mass-retention acceptance — 2026-08-01

## Outcome

The deployed `p1` AWS control plane increased the synthetic demo tenant from
the 365-day S3 Object Lock floor to 730 days across a source inventory above the
250-version synchronous boundary. The longer policy protected future writes
before backfill. The scheduled FIFO worker then completed every page, and an
independent verifier queried the retention state of every exact pre-cutover S3
version.

This is acceptance of source-region asynchronous mass retention. It is not
cross-region recovery acceptance and does not claim that Microsoft Entra ID or
runtime attestation is configured.

## Deployed environment

- Region: `eu-west-2`
- Control-plane revision: `b093b1ca758122b8608c43240753a56f60ce636b`
- UI revision: `3163fee22ece37d8c42a2aee17cc6fba1b1d9451`
- UI: `https://d2ir54klde64bd.cloudfront.net`
- API: `https://lwg33pxwk8.execute-api.eu-west-2.amazonaws.com`
- Tenant: synthetic `tenant-demo`
- Job: `2f3b271e-a3bb-5676-85db-e04335eefbe7`
- Cutover: `2026-08-01T21:14:41Z`
- Fixed minimum retain-until: `2028-07-31T21:13:36Z`

## Application proof

The create transaction returned `settling`, policy revision 1 and a change from
365 to 730 days. DynamoDB immediately reported `application_status=applying`.
The retained `evidence_retention_extension_started` event was written after
that transaction and already carried S3 Object Lock `COMPLIANCE` retention to
`2028-07-31T21:13:36Z`. This independently proves that future writes used the
longer period before existing-version processing started.

EventBridge discovered the tenant through the sharded schedule index and the
dedicated worker completed with:

- status: `completed`;
- job revision: 55;
- pages: 54;
- versions examined: 536;
- versions extended: 535;
- versions already compliant at the target: 1;
- delete markers: 0; and
- failure reason: none.

The exact policy revision then changed atomically to `applied` with
`affected_record_count=536`. The read-only auditor route returned the same
terminal state and counts.

## Independent S3 verification

A separate bounded verifier listed source-bucket versions itself, filtered them
against the fixed server cutover and called `GetObjectRetention` for every exact
key/version pair. It did not trust the job's counters or policy posture.

- Pre-cutover versions listed: 536
- Exact versions inspected: 536
- `COMPLIANCE` mode: 536 of 536
- Retain-until at or beyond the fixed target: 536 of 536
- Minimum observed retain-until: `2028-07-31T21:13:36Z`
- Maximum observed retain-until: `2028-07-31T21:13:36Z`
- Provider failures: 0

The retained `evidence_retention_extension_completed` event reported the same
536/535 counts. Its stored SHA-256 metadata matched the immutable bytes and its
own Object Lock state was `COMPLIANCE` through
`2028-07-31T21:31:30Z`.

## Operational proof

- Worker source queue: 0 visible, 0 in flight
- Worker DLQ: 0 visible, 0 in flight
- Schedule DLQ: 0 visible, 0 in flight
- Worker error alarm: `OK`
- Worker DLQ alarm: `OK`
- Schedule DLQ alarm: `OK`
- Worker timeout: 60 seconds
- Worker reserved concurrency: 5
- Worker recursive-loop configuration: `Allow`
- EventBridge schedule: enabled at one-minute rate
- Unauthenticated API Gateway request: HTTP 401
- Hosted UI assets: merged production JS and CSS revisions served after a
  completed CloudFront invalidation

## Acceptance finding and correction

The first scheduled attempt exposed a legacy-data migration defect. The demo
tenant had a provisioned organization from an older release but no tenant-root
schedule-index record, so EventBridge correctly discovered zero tenants. The
job remained `settling`; no pre-cutover version was partially changed and the
longer 730-day future-write policy stayed active.

PR 96 added an idempotent migration from that existing provisioned organization
to the tenant root and sharded evidence index. A regression test creates the
retention job before migration, runs migration twice and proves that the exact
job revision is dispatched once afterward. Independent CI passed, the fix was
merged as the deployed control-plane revision above, and the real EventBridge
rule then dispatched and completed the original job without manual queue
injection.

## Authentication caveat and remaining work

Positive-path API calls were direct Lambda invocations with synthetic,
tenant-bound operator claims. This proves the deployed handler, DynamoDB, S3,
SQS, EventBridge and audit contracts without retaining a real user token in the
test shell. API Gateway independently rejected an unauthenticated request with
HTTP 401. Browser-authenticated positive-path acceptance remains appropriate
after Microsoft Entra ID is configured; the stack currently reports Entra and
runtime attestation as `not-configured`.

P0-08 still requires a fresh cross-region recovery exercise that compares
source and replica counts, deterministic order, content hashes and retention
state. This evidence does not close or weaken that requirement.

## Quality evidence

- Feature PR 95: all GitHub checks passed, including Python 3.11/3.12/3.13,
  documentation, Docker isolation, PostgreSQL integration and the 8m57s bounded
  mutation-security gate.
- Migration PR 96: the same independent suite passed, including the 8m34s
  mutation-security gate.
- Final local SDK gate: 890 passed, 1 intentionally skipped, 90.26% coverage,
  strict documentation/package/dependency/mutation-baseline checks passed.
- UI gate: typecheck, 139 tests and production build passed; desktop and
  390×844 operator journeys were visually verified with no console errors.
