# Asynchronous tenant retention

## Purpose

This design closes the P0-08 mass-retention gap above the 250-version
synchronous boundary. It extends the tenant's S3 Object Lock COMPLIANCE period
across every existing audit-object version while immediately protecting future
writes. It is deliberately increase-only: neither failure, retry nor operator
input can shorten retention.

## Threat and authority boundary

The browser proposes a longer period, request ID and records-management
rationale. The authenticated tenant and operator capability come from the
server-owned identity context. Only `evidence_admin` can start a job;
`evidence_read` can inspect progress. SQS fields are lookup keys, never
authority. The worker reloads the exact tenant, job, policy revision and
application binding from DynamoDB before every S3 mutation.

S3 Object Lock COMPLIANCE mode is the irreversible enforcement boundary.
DynamoDB coordinates desired policy and durable progress but cannot reduce the
bucket's 365-day floor or an existing later retain-until date.

## Cutover model

Starting a job atomically commits two records:

1. the longer tenant policy with `applicationStatus=applying`; and
2. an idempotent revision-bound retention job.

Every subsequent audit write therefore receives the longer period immediately.
The job waits 65 seconds before listing versions. This is longer than the
maximum evidence-writing Lambda timeout, so a request that read the old policy
before cutover must finish or be terminated before the scan starts. The fixed
cutover timestamp then bounds the complete inventory: post-cutover objects
already use the new policy; every version at or before cutover is inspected and
extended when necessary.

The transition is safe in only one direction. If queueing, S3, DynamoDB or
alert delivery fails, the longer future-record policy remains active. The UI
shows `failed`, retains the sanitized reason and offers reconciliation at the
same or a longer period. It never offers rollback.

## Durable workflow

- EventBridge checks provisioned tenants every minute using the existing
  sharded evidence-assurance tenant index.
- A dedicated encrypted FIFO queue and Lambda isolate irreversible retention
  work from read-only assurance/export.
- One message handles at most ten listed versions or delete markers.
- Messages bind tenant, job and optimistic revision; FIFO deduplication binds
  each next revision.
- A committed-page/failed-send edge is repaired when the previous message is
  retried: it dispatches the already-recorded next revision without repeating
  the page. The schedule also recovers queued work after the FIFO deduplication
  window and stale running work after 30 minutes.
- A job is bounded to 100,000 pages, three attempts per message, reserved
  concurrency five and a four-day source-queue lifetime.
- Exhausted failures update both job and policy application posture atomically,
  publish a critical durable alert and remain visible if delivery is pending.
- Completion atomically marks the job complete and the exact policy revision
  applied before writing a retained completion event.

## Operator API

| Route | Capability | Behavior |
| --- | --- | --- |
| `POST /api/enterprise/evidence/retention-jobs` | `evidence_admin` | Idempotently start an increase-only tenant backfill from exact policy revision |
| `GET /api/enterprise/evidence/retention-jobs` | `evidence_read` | List the 50 newest jobs |
| `GET /api/enterprise/evidence/retention-jobs/{jobId}` | `evidence_read` | Read exact server-owned progress and terminal alert posture |

The create schema is closed and accepts only `requestId`, `expectedRevision`,
`retentionDays` and `rationale`. Retention is an integer from 365 through 3,650
days. Reusing a request ID with different content, stale revision, concurrent
application, reduction, malformed value or weak role fails closed.

## UI journey

1. The operator chooses a longer period and enters an approved schedule/change
   reference.
2. **Review extension** opens an impact summary showing current and target
   periods, known or lower-bound version count, immediate future-write effect,
   synchronous versus background treatment and irreversibility.
3. The operator explicitly acknowledges that the period cannot be shortened.
4. Small complete inventories use the synchronous fast path. Incomplete large
   inventories start the durable job automatically; the operator does not need
   to choose an implementation mode.
5. The retention card shows `settling`, `queued`, `running`, `completed` or
   `failed`, versions examined, versions extended, pages and durable-alert
   delivery. Closing the page does not stop work.
6. A failed job explains that the longer future policy remains active and a
   retry reconciles existing versions without rollback.

## Guarantees and non-guarantees

The workflow guarantees increase-only application to every source-region audit
version at or before the server cutover when it reports `completed`. It does
not claim that replica-region retention has been recovered or compared; the
separate live cross-region count/order/hash/retention exercise remains open.
It also does not interpret a longer period as legal advice or records-schedule
approval.

## Verification

Contracts cover more than 250 versions, immediate future-write policy,
complete pagination, exact counts, idempotency, stale/concurrent/weak-role and
cross-tenant denial, terminal provider failure, retained longer policy,
critical alert delivery, queue-send recovery and dedicated infrastructure
bounds. UI tests cover human-readable impact review, explicit acknowledgement,
correct synchronous/async routing and progress types. Live acceptance must
extend a deployed tenant above 250 versions, independently inspect every
pre-cutover retain-until date, prove post-cutover writes use the new period and
confirm empty DLQs and healthy alarms.
