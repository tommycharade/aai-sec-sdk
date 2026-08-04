# Fleet integrity baseline storage

## Outcome

Repository integrity detection stores each newly committed source-control
baseline in a dedicated private, versioned S3 bucket. The control table retains
the exact object key, version and SHA-256 digest. A detector therefore reads
immutable evidence by version instead of treating a mutable object name as
authority.

This tranche removes repeated page reads from the per-agent detector path and
keeps repository observations out of alert, case and telemetry payloads. The
existing bounded discovery upload remains the ingestion limit: at most 20 pages
of 100 normalized observations (2,000 observations) per source generation.
Larger discovery ingestion remains a separate scaling requirement and is not
claimed as complete here.

## Trust boundary

- Cognito claims provide tenant identity; request bodies never choose an S3
  prefix.
- The service derives the object key from the SHA-256 digest of the tenant ID
  plus validated source and generation identifiers.
- Only normalized source-control observations are stored. Repository contents,
  credentials, connector tokens and raw project roots are excluded.
- S3 Block Public Access, TLS-only access, server-side encryption and versioning
  are mandatory infrastructure controls.
- A commit fails if storage is unavailable or S3 does not return an immutable
  version ID. DynamoDB authority is never advanced first.
- The exact object version and digest are included in the same committed
  generation metadata used by the detector.
- Reads use the exact version, enforce a 16 MB bound, verify SHA-256 before JSON
  parsing, require the closed schema and independently re-hash every page and
  the generation content hash.
- Missing, partial, malformed, oversized or tampered references fail closed as
  an integrity baseline blind spot. They do not create execution authority or
  automatic containment.

## Compatibility

Generations created before this storage format remain readable from their
immutable DynamoDB pages and receive the same independent re-hashing. New
source-control generations require the baseline bucket; there is no silent
fallback that could make a production deployment appear protected while the
storage plane is absent.

Agent host identity is also exact. New enrollment accepts only `claude-code`
or `codex-cli`. Historical records containing free-text display labels are not
inferred as trusted hosts and must be re-enrolled under a canonical identity.

## Performance model

One invocation-local cache is shared by all integrity rules and matching agents.
Each exact source generation is fetched and verified once per evaluation or
preview, rather than once per agent. The cache never crosses Lambda invocations
or tenants and contains no authority beyond already verified evidence.

## Operations and recovery

The baseline bucket is retained if the stack is removed. Operators should
include it in backup, access-review, cost and recovery exercises. Object
versions are referenced by live DynamoDB generations; lifecycle rules must not
expire versions until a future retention controller proves that no retained
generation references them.

## Required evidence

- unit and contract tests for exact-version storage and successful re-read;
- tampered object bytes and partial-reference rejection;
- legacy DynamoDB generation compatibility;
- infrastructure assertions for private access, encryption, TLS, versioning,
  retention and least-privilege handler access;
- a deployed source-control generation proving the S3/DynamoDB binding before
  this item can be called operationally complete.

