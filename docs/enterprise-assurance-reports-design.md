# Enterprise assurance reports

This design defines the production-shaped implementation of P1-ADM-05. It
gives executives and auditors purpose-specific views of the same bounded,
tenant-owned evidence without presenting an operational dashboard as a
compliance certificate.

## Security boundary

Agent reports, discovery snapshots, policy metadata, alerts and browser input
are untrusted observations. They cannot grant authority or prove compliance.
The report API derives tenant and role from authenticated context, strongly
reads server-owned records and never accepts report facts from the caller.

The control plane therefore:

- exposes only two fixed report profiles: `executive` and `auditor`;
- requires a canonical tenant role for executive content and `evidence_read`
  for auditor content, schedule metadata and retained history;
- derives every count from bounded tenant reads and fails instead of silently
  truncating a population;
- returns unavailable percentages when discovery evidence is incomplete;
- excludes project paths, user names, command content, credentials and raw tool
  arguments;
- labels observation gaps and non-guarantees next to the affected metric;
- includes section hashes and existing evidence endpoints so an auditor can
  trace a summary to detailed, independently retained evidence; and
- performs no policy decision, approval, containment or agent action.

A live report has a canonical content hash. An operator can additionally create
or schedule a **signed snapshot**. The snapshot binds report content plus its
tenant, snapshot, profile, source, schedule revision and timestamps to a
domain-separated AWS KMS ECDSA P-256 signature. This proves control-plane
origin and alteration detection; it is not a timestamp-authority statement,
compliance certification or independent attestation.

## Report profiles

### Executive posture

The executive view is aggregate-only. It shows known-population coverage,
healthy and compliant installation posture, policy governance, active
exceptions, open security work, evidence readiness and the most important
blind spots. It does not expose agent, device, policy, group or operator
identifiers.

### Auditor readiness

The auditor view contains the same aggregate posture plus bounded breakdowns,
policy and group references, exception/approval lifecycle counts and evidence
trace references. It still excludes raw sensitive content. Detailed immutable
records remain behind their existing least-privilege APIs.

## API and authorization contract

```text
GET /api/enterprise/reports/executive
GET /api/enterprise/reports/auditor
GET|PUT /api/enterprise/reports/schedule
GET|POST /api/enterprise/reports/snapshots
GET /api/enterprise/reports/snapshots/{snapshotId}
POST /api/enterprise/reports/snapshots/{snapshotId}/verify
```

Schedule and history reads require `evidence_read`. Creating a snapshot or
changing a schedule requires `evidence_admin`. An executive snapshot download
requires a canonical tenant role; auditor snapshots require `evidence_read`.
Service identities remain constrained by their separately versioned route
capability.

Live report responses contain a fixed profile, generation time, posture,
bounded summaries, explicit blind spots/non-guarantees and content-addressed
section traces. Auditor responses add bounded business-unit/repository
breakdowns and least-privilege evidence routes.

## Scheduled signed snapshots

A tenant may select a daily or weekly UTC schedule and either report profile.
Schedule changes use optimistic revisions and retain only a SHA-256 digest of
the operator rationale. A due-time GSI partitions enabled schedules into
sixteen fixed shards. Sixteen EventBridge rules invoke bounded dispatchers
every fifteen minutes. A dispatcher claims an occurrence before enqueueing it
and never builds reports itself. Schedule, request-claim and snapshot metadata
use a separate `ASSURANCE#{tenant}` partition. The worker's only DynamoDB write
grant is confined to that leading key and cannot mutate policy, identity,
enrollment or agent authority.

The claim contains the exact tenant, due time, profile, snapshot identity and
schedule revision. A dedicated standard SQS queue invokes a 60-second worker
with reserved concurrency and a monitored DLQ. The worker reloads the exact
claim before deriving any report. Duplicate delivery returns the same retained
snapshot. A crash after S3 but before DynamoDB adopts only an already valid,
KMS-verified object; a crash after metadata but before schedule completion is
also safe to retry.

While a fresh occurrence is claimed, schedule changes fail with a revision
conflict. This defines whether generation or the operator change happened
first; an old profile can never be generated after a successful schedule
change. Claims older than fifteen minutes may be replaced, exceeding the
worker timeout and bounded retry window.

One corrupt schedule is conditionally removed from the due index, marked with
a content-minimised quarantine reason and reported to the durable
security-alert topic without blocking valid tenants. A concurrent repair wins
over quarantine. Deterministic record validation is separate from the
DynamoDB claim operation: throttling or another provider failure fails the
shard and leaves a valid schedule indexed for retry; only malformed stored
content can trigger quarantine. The schedule API and UI expose quarantine,
timestamp and reason, and a reviewed revisioned save is the repair path. Each
cycle processes one bounded page of at most 250 due records. Successfully queued records leave the
due index, exposing the next page on the following cycle; the 251st and later
tenants therefore make progress even when the entire preceding page is
malformed. The dispatcher has a 60-second bound. A partial SQS result removes
only acknowledged records. Missing, duplicate or unknown result IDs fail
closed and leave claims safe for idempotent retry.

Malformed string, boolean, missing and oversized revisions are bound using
their exact observed DynamoDB value or absence. The API projects opaque
revision zero for reviewed repair and the replacement condition still binds
the malformed value, so neither coercion nor a concurrent update can win.

## Retention, integrity and recovery

Snapshots use the tenant-prefixed audit bucket rather than the short-lived
derived-report bucket. The store has versioning, a 365-day S3 Object Lock
COMPLIANCE floor, tenant-configured longer retention where applicable, private
access and cross-Region replication. DynamoDB stores the exact object version
and digest. Every download and verification re-reads that version, limits the
body to 1,000,000 bytes before parsing, validates a closed schema and recomputes
all hashes. Amazon S3 replication retains source version IDs; while that exact
version is unavailable because replication is pending or impaired, the API
returns `503` and never substitutes the current version of the key.

The signed payload domain is `aai-sec-assurance-snapshot-v1` and contains:

- schema version, tenant ID and snapshot ID;
- executive or auditor profile and operator or schedule source;
- generated/signed timestamp and claimed schedule revision; and
- SHA-256 of the canonical report.

Operator creation first commits a conditional request claim binding actor,
profile and rationale digest before signing or S3 writes. Snapshot creation
then retains immutable bytes and an idempotent Object Lock audit record before
committing metadata. Concurrent changed first use is therefore rejected, and
an audit outage cannot leave successful state without evidence. Retries
validate exact existing bytes and do not assume ECDSA signatures are
deterministic.

Reports use a dedicated retained multi-Region KMS signing key, never the
executable-policy signer. The report worker receives only `kms:Sign` and
`kms:Verify` for that key, and its environment contains no policy-signing key
ARN. Snapshot metadata stores the Region-stable `mrk-…` identity. Each cell
owns a validated local-Region verification registry containing the current key
and retained historical report keys. Rotation adds the new local replica while
retaining old entries. No key or replica may be removed until every snapshot
it signed has exceeded its longest configured retention.

Primary deployments accept up to eight reviewed historical local key ARNs in
`ASSURANCE_REPORT_HISTORICAL_VERIFICATION_KEY_ARNS`. The recovery deployment
creates retained replicas for the matching primary keys and passes their
resolved local ARNs through
`RECOVERY_ASSURANCE_REPORT_HISTORICAL_VERIFICATION_KEY_ARNS`. Active-cell
verification requires the exact ordered registry and verify-only IAM grants;
historical keys cannot sign new snapshots.

The activated recovery cell has the same queue, worker, schedules and dedicated
assurance-key replica against the replicated audit namespace. Historical
verification uses recovery-Region replica ARNs for the same MRK identities. In
standby, all four Lambdas have zero concurrency, all 21 schedule rules and
three event-source mappings are disabled, and no active signing grant exists.
Deployment verification checks the exact worker role, partition-bound write,
S3 prefixes, dedicated key, mappings and schedule count before routing changes.

## Operator journey

1. Open **Assurance** and choose Executive or Auditor.
2. Read posture, blind spots and non-guarantees before interpreting metrics.
3. Enter an approved review rationale and create a signed snapshot, or enable a
   daily/weekly UTC schedule.
4. Open retained history and verify the exact S3 version and KMS signature.
5. Download the signed JSON document only after successful verification.
6. Use the evidence-assurance export—not this summary—as the detailed immutable
   evidence package for an audit.

If the UI reports a snapshot as temporarily unavailable, check source
replication status, destination `REPLICA` status and the report worker/DLQ
alarms. Never recreate a retained snapshot under the same identity or download
an unversioned object as a workaround.

## Distribution boundary

The UI provides secure tenant-authenticated history, verification and download.
It does not send reports by email or to a SIEM. Splunk remains an explicit
non-production stub. Compliance-framework mapping and independent attestation
still require a reviewed controls catalogue and customer assurance process.

## Acceptance evidence

Contract tests cover authorization, tenant isolation, pre-signing request
claims, identity-envelope tampering, wrong KMS key/algorithm responses,
historical-key recovery verification, exact-version reads, crash recovery,
duplicate delivery, concurrent schedule changes, corrupt-record isolation,
251-plus due schedules, a fully corrupt 250-record page, partial/malformed SQS
batches, real overlapping request claims, corrupt KMS responses and bounded
history truncation. Synthesized-template verification covers the due-time GSI,
queue/DLQ, worker concurrency, Object Lock reuse, dedicated MRK, exact worker
IAM, current-plus-historical replica deployment, verify-only historical grants,
recovery parity and disabled standby authority. UI tests cover failed or absent
verification/download prevention, evidence-role gating, contextual help and
responsive layouts.
