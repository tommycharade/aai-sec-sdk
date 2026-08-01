# Asynchronous evidence assurance acceptance — 2026-08-01

## Outcome

The deployed `p1` AWS control plane completed a tenant-wide point-in-time
assurance/export above the 250-version synchronous boundary. Independent
verification of every API-returned page reproduced both the ordered chain hash
and final index hash. The scheduled-monitor contract surfaced legacy evidence
as attention-required, delivered a durable alert and retained the completion
and monitor events under S3 Object Lock COMPLIANCE mode.

This is acceptance of asynchronous assurance and export, not acceptance of
asynchronous mass-retention mutation or cross-region disaster recovery. Those
two P0-08 items remain open.

## Deployed environment

- Region: `eu-west-2`
- UI: `https://d2ir54klde64bd.cloudfront.net`
- API: `https://lwg33pxwk8.execute-api.eu-west-2.amazonaws.com`
- Job: `a4196faa-62a9-5c5c-8d60-a82c486814aa`
- Snapshot result: 532 records in 54 pages
- Current-standard verified: 2
- At risk: 530 legacy records
- Delete markers: 0
- Queue after completion: 0 visible, 0 in flight

The synchronous summary intentionally remained `incomplete` at its 251-record
lower bound and linked to the completed asynchronous result. It did not present
the partial synchronous count as complete.

## Integrity proof

An independent verifier called all 54 authenticated page contracts, removed
each claimed digest, canonicalized the remaining JSON and recomputed SHA-256.
It then rebuilt the ordered rolling chain from the documented all-zero initial
digest and canonicalized the export index independently.

- Recomputed chain SHA-256:
  `89ff085f1c86b5602dc61738101fc9cb826b45fc274bbe9b34f66cc52a81958c`
- Recomputed index SHA-256:
  `c3b151ab557b61b493b680a92ab6410ebb8fdf16b989a41ae911fbe78ca5e9ad`
- API job, export index and independent values matched exactly.
- Page identity, page order, record totals and assurance totals matched.

The completion audit event contained the same final content hash and was
retained in Object Lock `COMPLIANCE` mode until
`2027-08-01T20:09:38Z`. The monitor transition event was retained to the same
date.

## Monitoring and fail-closed proof

- Monitor status: `attention`
- Reason: `integrity_or_retention_gap`
- Durable alert delivery: `true`
- Worker DLQ: empty
- Schedule DLQ: empty
- Worker error, worker DLQ and schedule DLQ alarms: `OK`
- An unauthenticated API Gateway request returned HTTP 401.

The 530 at-risk results are expected for historical objects created before the
current content-binding/Object-Lock metadata contract. Reporting them as at
risk is the correct fail-closed result; this run does not relabel legacy data as
verified.

## Acceptance finding and correction

The first deployed run stopped after exactly 16 successful pages because AWS
Lambda recursive-loop protection interpreted the intentional
Lambda-to-FIFO-to-Lambda continuation as accidental recursion. There were no
worker errors or throttles. Infrastructure now explicitly sets the dedicated
worker to `RecursiveLoop: Allow` and limits reserved concurrency to five while
retaining these compensating controls:

- exact tenant/job/revision binding on every message;
- conditional revision writes and FIFO deduplication;
- 100,000-page hard limit;
- three page attempts followed by terminal failure;
- dedicated DLQ and CloudWatch alarms.

After deployment, AWS reported `RecursiveLoop: Allow`; the same stalled job
resumed at page 17 and completed at page 54 with an empty queue. A source and
CDK-synthesis regression test protects the declaration.

## Test scope caveat

The authenticated positive-path calls were direct Lambda invocations carrying
synthetic, tenant-bound operator claims. This proves the deployed handler,
worker, DynamoDB, S3, SQS, SNS and response contracts without storing a real
user token in the test shell. API Gateway authentication was separately tested
for the unauthenticated negative path (HTTP 401). A browser-authenticated
positive-path acceptance remains appropriate once Microsoft Entra ID is
configured; this environment currently reports Entra as `not-configured`.

## Local quality evidence

- `make check`: 883 passed, 1 intentionally skipped
- Focused infrastructure/evidence contracts: 7 passed
- TypeScript build: passed
- CDK synthesis: emitted `RecursiveLoop: Allow` and
  `ReservedConcurrentExecutions: 5`
- UI suite from the feature delivery: 137 tests passed, typecheck passed and
  production build passed

