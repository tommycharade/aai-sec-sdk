# Durable evidence governance

This design advances P0-08 by turning the AWS Object Lock foundation into a
tenant-visible records-management control. It covers tenant retention,
exact-version legal hold, live integrity assurance, asynchronous tenant-wide
export, mass-retention extension and scheduled evidence-gap monitoring. It does
**not** claim that
cross-region recovery has passed for a customer environment.

## Threat and trust boundary

The browser, operator-entered object identity and audit payload are untrusted.
The API derives the tenant from the verified operator token and permits evidence
reads only to security operators, auditors and platform administrators. Evidence
mutations require `evidence_admin`; fleet and policy roles cannot acquire it by
supplying request content.

S3 Object Lock in `COMPLIANCE` mode is the enforcement boundary. DynamoDB stores
the tenant policy and optimistic revision, but cannot shorten the bucket's
365-day default. The Lambda receives only exact-version S3 permissions needed to
read retention/legal-hold state and extend retention or change legal hold.
Asynchronous work is authorized by an SQS event-source mapping, not by fields in
the queue body. The worker reloads the server-owned tenant job and requires its
exact optimistic revision before every state transition.

## Invariants

- Tenant retention is 365–3,650 days and can only increase through this API.
- The synchronous fast path extends existing versions before storing the new
  future-record policy. The asynchronous path first makes the longer policy
  authoritative for new writes, waits beyond the maximum evidence-writer
  lifetime, then extends every pre-cutover version. Failure may retain data
  longer, never for less time.
- Every new audit object explicitly carries COMPLIANCE retention plus a SHA-256
  content binding in S3 metadata.
- Legal hold addresses an exact key and version under `tenant=<token tenant>/`.
  Cross-tenant keys fail before an S3 mutation.
- Rationale text is never written to evidence; only its SHA-256 digest is kept.
- Assurance hashes the retained bytes again and compares the result with the
  creation-time binding. A mismatch is `at_risk`, not healthy.
- An exact S3 `NoSuchObjectLockConfiguration` response on a legacy version is
  represented as missing retention or legal hold and therefore `at_risk`.
  Access-denied, service and malformed-response failures remain fatal.
- The synchronous inventory is complete only at 250 versions or fewer. A larger
  tenant receives `incomplete`, and retention update/export fails closed rather
  than returning a partial artifact. The bounded listing supplies only an
  observed lower-bound count; the API performs no per-object verification or
  presents any sampled records when tenant-wide completeness is unavailable.
- Export verifies every bounded version, orders records deterministically and
  binds the complete manifest with a canonical SHA-256 digest. The browser
  independently verifies that digest before download.
- Tenant-wide jobs fix a server-time snapshot cutoff, traverse S3 object
  versions in pages, and exclude later writes by S3 `LastModified`. Each page is
  canonically hashed; an ordered rolling hash binds every page into a final
  index. A substituted, reordered or omitted page fails client verification.
- Derived report pages live in a separate private, encrypted, versioned bucket
  for 30 days. They are convenience artifacts, not the source record. The final
  index hash is written to retained Object-Lock audit evidence.
- Scheduled scans run every 15 minutes, permit only one active job per tenant,
  regard a successful result as fresh for six hours, and fail jobs with no
  progress for 30 minutes. Empty evidence, a decrease from the previous
  completed record count, at-risk versions and delete markers are explicit gap
  reasons. A changed non-healthy state is delivered to the
  durable security-alert SNS/SQS channel; a delivery failure remains visible as
  pending and is never represented as healthy.

## Operator API

| Route | Authority | Result |
| --- | --- | --- |
| `GET /api/enterprise/evidence` | `evidence_read` | Live policy, integrity, retention, legal-hold and completeness posture |
| `PUT /api/enterprise/evidence/retention` | `evidence_admin` | Optimistic, increase-only retention update applied to existing and future records |
| `POST /api/enterprise/evidence/retention-jobs` | `evidence_admin` | Idempotently start a revision-bound mass-retention extension |
| `GET /api/enterprise/evidence/retention-jobs` | `evidence_read` | List the 50 newest mass-retention jobs and progress |
| `GET /api/enterprise/evidence/retention-jobs/{jobId}` | `evidence_read` | Read one exact tenant-bound retention job and alert posture |
| `POST /api/enterprise/evidence/legal-hold` | `evidence_admin` | Legal-hold change for one exact tenant object version |
| `GET /api/enterprise/evidence/export` | `evidence_read` | Complete integrity-bound manifest, or a fail-closed conflict/error |
| `POST /api/enterprise/evidence/jobs` | `evidence_admin` | Idempotently start a tenant-wide point-in-time assurance/export job |
| `GET /api/enterprise/evidence/jobs` | `evidence_read` | List the 50 newest tenant jobs and progress states |
| `GET /api/enterprise/evidence/jobs/{jobId}` | `evidence_read` | Read one exact tenant-bound job and its completed export index |
| `GET /api/enterprise/evidence/jobs/{jobId}/pages/{page}` | `evidence_read` | Read one completed page after server-side schema and digest verification |

The hosted **Evidence** workspace leads with assurance instead of a raw audit
table. It shows verified versions, retention, legal holds and delete markers;
then offers increase-only retention, exact-version preservation, verified export
and the existing redacted decision timeline.

## Failure behavior and limitations

An unavailable S3 version, malformed tenant policy, mismatched content hash,
truncated inventory, stale policy revision or unauthorized role never produces a
positive assurance result. Audit writes also resolve the live tenant retention
policy before persisting the object.

The 250-version synchronous path remains the fast path. Above that boundary the
UI must use the asynchronous assurance/export job; it must never treat the
bounded synchronous count as complete. A single job is bounded to 100,000 pages
(at most 1,000,000 listed versions or delete markers), fails closed on malformed
pagination or provider errors, retries a page at most three times and then
records a sanitized terminal reason. Increase-only retention above 250 versions
uses the dedicated asynchronous retention workflow. It makes the longer
future-write policy authoritative before scanning, waits 65 seconds to drain
writers that may have read the old policy and then extends every version at or
before that cutover. A failed job leaves the longer future policy active and
visible; retry reconciles existing versions without rollback. See
[Asynchronous tenant retention](asynchronous-retention-design.md). Cross-region
count/order/hash/retention recovery remains open.

The evidence worker is an intentional Lambda-to-FIFO-to-Lambda continuation
workflow. Its Lambda recursive-loop setting is therefore explicitly `Allow`;
without this declaration AWS terminates valid exports after approximately 16
pages. This does not make the loop unbounded: every message is bound to the
tenant, job and optimistic revision; FIFO deduplication prevents duplicate next
steps; a job stops at 100,000 pages; reserved concurrency is five; each page has
three attempts; and worker errors, queue exhaustion and dead letters are
alarmed. Changing that declaration or any of those compensating controls
requires a threat-model and infrastructure-contract review.

## Verification

Contract tests cover multi-page completion, mass retention above the synchronous
bound, idempotent creation, cross-tenant
denial, page substitution, malformed worker events, stale revisions, retry and
terminal provider failure, deduplicated scheduling and alert delivery, plus the
synchronous weak-role, retention, legal-hold and byte-tampering cases. CDK
synthesis proves the separate worker, FIFO/DLQ, report store, schedule/DLQ,
alarms and least-privilege permissions are deployable. UI tests and browser
exercises cover progress, verified download and failed states without
representing fixture data as live.
