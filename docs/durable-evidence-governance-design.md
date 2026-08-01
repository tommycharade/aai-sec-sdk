# Durable evidence governance

This design advances P0-08 by turning the AWS Object Lock foundation into a
tenant-visible records-management control. It covers tenant retention,
exact-version legal hold, live integrity assurance and complete bounded export.
It does **not** claim that cross-region recovery or evidence-loss monitoring has
passed for a customer environment.

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

## Invariants

- Tenant retention is 365–3,650 days and can only increase through this API.
- Existing versions are extended before the new future-record policy is stored.
  A concurrent failure may retain data longer, never for less time.
- Every new audit object explicitly carries COMPLIANCE retention plus a SHA-256
  content binding in S3 metadata.
- Legal hold addresses an exact key and version under `tenant=<token tenant>/`.
  Cross-tenant keys fail before an S3 mutation.
- Rationale text is never written to evidence; only its SHA-256 digest is kept.
- Assurance hashes the retained bytes again and compares the result with the
  creation-time binding. A mismatch is `at_risk`, not healthy.
- The synchronous inventory is complete only at 250 versions or fewer. A larger
  tenant receives `incomplete`, and retention update/export fails closed rather
  than returning a partial artifact.
- Export verifies every bounded version, orders records deterministically and
  binds the complete manifest with a canonical SHA-256 digest. The browser
  independently verifies that digest before download.

## Operator API

| Route | Authority | Result |
| --- | --- | --- |
| `GET /api/enterprise/evidence` | `evidence_read` | Live policy, integrity, retention, legal-hold and completeness posture |
| `PUT /api/enterprise/evidence/retention` | `evidence_admin` | Optimistic, increase-only retention update applied to existing and future records |
| `POST /api/enterprise/evidence/legal-hold` | `evidence_admin` | Legal-hold change for one exact tenant object version |
| `GET /api/enterprise/evidence/export` | `evidence_read` | Complete integrity-bound manifest, or a fail-closed conflict/error |

The hosted **Evidence** workspace leads with assurance instead of a raw audit
table. It shows verified versions, retention, legal holds and delete markers;
then offers increase-only retention, exact-version preservation, verified export
and the existing redacted decision timeline.

## Failure behavior and limitations

An unavailable S3 version, malformed tenant policy, mismatched content hash,
truncated inventory, stale policy revision or unauthorized role never produces a
positive assurance result. Audit writes also resolve the live tenant retention
policy before persisting the object.

The 250-version synchronous path is intentionally a pilot boundary, not the
long-term export architecture. Production-scale tenants need asynchronous S3
Inventory/Batch Operations, a monitored assurance schedule, explicit evidence-
gap alerts and replay, and a new live cross-region recovery exercise proving
count, ordering, hashes and retention. Those items remain open in the P0 ledger.

## Verification

Contract tests cover the complete positive journey plus weak-role access,
retention reduction, stale revision, cross-tenant legal hold and post-write byte
tampering. CDK synthesis proves the least-privilege S3 permissions are
deployable. UI tests and desktop/mobile browser exercises cover assurance,
retention and legal-hold journeys without representing fixture data as live.
