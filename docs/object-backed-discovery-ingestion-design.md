# Object-backed discovery ingestion

## Outcome

Enterprise discovery generations accept up to 20 immutable pages of 1,000
normalized observations: 20,000 observations per source generation. Page
payloads live in a dedicated private, versioned S3 bucket instead of DynamoDB.
The control table contains only the page identity, count, canonical hash and
exact object key, version and SHA-256 digest.

The fixed 20-page fan-out is intentional. This change increases useful fleet
capacity by ten times without turning an operator request into an unbounded S3
scan. It is an initial enterprise operating envelope, not a claim of unlimited
scale. Endpoint inventory normally emits both a device and an installation
observation, so one generation can describe at most 10,000 fully represented
devices. Estates above this envelope require a partitioned asynchronous
reconciler and measured capacity evidence.

## Trust boundary and invariants

- The connector credential remains bound to one tenant, source ID and source
  kind. Request content never chooses a bucket or object prefix.
- The service hashes the authenticated tenant ID and derives every object key
  from that digest plus validated source, generation and page identifiers.
- Pages contain only schema-normalized discovery observations. Credentials,
  connector tokens, prompts, tool arguments, outputs and raw project roots are
  rejected before storage.
- S3 Block Public Access, TLS-only access, server-side encryption, versioning
  and stack-retained storage are mandatory deployment controls.
- Each upload uses create-only object semantics. A retry may reuse a prior
  object only when its bytes have the same SHA-256 digest; a collision with
  different bytes fails closed.
- DynamoDB records the exact S3 version and object digest. Commit and later
  reconciliation fetch that exact version, apply a 2 MB page bound, verify the
  digest before JSON parsing, enforce a closed schema, normalize every
  observation again and independently recompute the page hash.
- A missing, malformed, oversized, altered, partial or cross-tenant reference
  cannot become current authority. During reporting, unavailable committed
  evidence lowers discovery assurance and produces an unavailable coverage
  result rather than trusting metadata alone.
- Commit still rejects missing pages, caller-supplied hash mismatches and
  duplicate identities across pages before atomically advancing the source
  revision.

## Storage and compatibility

New generation declarations require `DISCOVERY_PAGE_BUCKET`; there is no silent
DynamoDB fallback. Pages written before this format remain readable from their
legacy immutable DynamoDB records. Source-control commits continue to create a
separate compact exact-version integrity baseline for anomaly detection, so
detectors do not repeatedly load all discovery pages.

The reference publisher defaults to 1,000 observations per page and rejects
more than 20,000 observations locally before sending inventory. The AWS-managed
collector uses the same ingestion page size and observation bound. Provider
APIs may retain narrower provider-specific mapping or pagination constraints;
the UI and documentation must not imply that object storage removes those
provider limits.

## Operations, retention and cost

The discovery-page bucket is retained if the stack is removed. Operators must
include it in backup, access review, data-residency, deletion and recovery
procedures. Object versions referenced by retained committed generations must
not be expired by a generic lifecycle rule. A future retention controller may
remove unreferenced failed-upload objects only after proving that no live or
retained generation points to them.

At the maximum generation size, one commit performs 20 exact-version S3 reads
and processes at most 20,000 normalized observations. Coverage reads have the
same object-read bound. Production rollout must measure latency and memory with
the customer's observation shapes; the current 15-second, 512 MB control-plane
Lambda remains the hard synchronous envelope.

## Acceptance evidence

- positive contract coverage for object upload, exact-version read, commit and
  legacy DynamoDB compatibility;
- adversarial rejection of altered bytes, malformed or partial references,
  cross-tenant keys, stale revisions, duplicate identities and oversized
  generations;
- publisher and managed-collector tests for 1,000-record pages and the 20,000
  observation ceiling;
- infrastructure assertions for private access, TLS, encryption, versioning,
  retention and least-privilege object actions; and
- deployed evidence binding an exact object version and digest to a committed
  generation before the capability is called operationally complete.
