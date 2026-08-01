# Audit-ready incident case export

This design implements P1-SOC-10 from the
[enterprise rollout requirements](enterprise-rollout-p0-p1-requirements.md).
It turns one retained incident case into a bounded, content-minimised JSON
package that an auditor can verify without access to the control plane.

## Customer outcome

An incident responder, security operator, auditor or platform administrator
can download one case package from the Incidents workspace. The package
contains the case and alert state, the server-derived endpoint-to-agent
binding, response history, correlated redacted decisions, approvals and
evidence digests. It never contains project paths, endpoint payloads, prompts,
tool arguments, tool results, credentials or credential-shaped configuration.

The console verifies the package hash before offering the download and shows
the digest and evidence counts. A repository-supplied offline verifier repeats
the same check and validates every timeline payload hash.

## Trust boundaries

- The authenticated tenant claim selects the tenant. A case identifier never
  selects a tenant.
- Only canonical incident-responder, security-operator, auditor and
  platform-administrator roles may export a case.
- The browser does not assemble evidence, choose an agent or claim
  completeness. The control plane reads strongly consistent tenant records.
- Correlation uses the binding captured by the case. Live binding posture is
  included separately so a changed endpoint relationship remains visible.
- The export is content-minimised before hashing and before immutable audit
  persistence.
- Export generation fails if a bounded source is incomplete, if the case
  changes during assembly or if immutable audit persistence fails.

## Versioned artifact

The response has four top-level fields:

- `schemaVersion`: currently `1`;
- `content`: the complete bounded evidence package;
- `integrity`: SHA-256 over UTF-8 `AAI canonical JSON v1` encoding of
  `content` (recursive lexicographic object-key ordering, compact separators,
  Unicode preserved);
- `auditReceipt`: the content-minimised receipt returned after the export hash
  is written to the Object-Lock-protected audit sink.

The content declares its correlation window, counts, bounds and capture
boundary. Decisions and approvals are correlated to the exact captured agent
from 24 hours before the source alert's first observation through a cutoff one
second before export generation. The one-second boundary prevents a record
created concurrently in the export second from being silently treated as part
of a complete snapshot. Timeline events are revision-bound case events and are
not restricted by that decision/approval window.

## Completeness and limits

The package contains at most 500 timeline events, 500 decisions and 500
approvals. Those are refusal bounds, not truncation rules. Exceeding a bound,
an oversized tenant partition, a changed case revision or a changed source
alert revision causes export generation to fail. A successful artifact always
sets `complete: true`, `decisionsTruncated: false`,
`rawContentIncluded: false` and `credentialsIncluded: false`.
The package also sets `approvalDecisionReasonsIncluded: false`; approval
bindings and outcomes remain present, but optional free-form decision
narrative is never made portable.

## Integrity and non-guarantees

The content hash and per-event payload hashes detect accidental or malicious
modification after download. The immutable audit receipt lets an authorized
investigator compare the exported digest with the retained control-plane
record. The package is not a digital signature and does not independently
prove who operated AWS; deployments requiring portable third-party
authenticity should add a KMS signing adapter without weakening this hash and
WORM baseline.

The export does not prove device isolation, process termination, credential
broker revocation, SIEM delivery or legal admissibility. Those remain separate
deployment controls and evidence sources.

## Verification

Control-plane contracts must prove role denial, tenant isolation, no raw
content or credentials, exact binding correlation, deterministic content
hashes, per-event payload hashes, refusal rather than truncation and
concurrent-revision denial. UI tests must prove hash verification precedes
download and a mismatched package is never saved. The offline verifier must
accept an unchanged package and reject changed content or timeline payloads.
