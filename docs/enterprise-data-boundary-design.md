# Enterprise data boundary

| Field | Value |
| --- | --- |
| Status | Production-shaped implementation foundation |
| Requirements | P1-ADM-11, P1-ADM-12 |
| Authority owner | AWS deployment owner |
| First provider | AWS, with Microsoft Entra Conditional Access evidence |

## Customer problem

An enterprise buyer must be able to establish where control-plane data is
stored, who controls encryption, how each data class is deleted, and which
networks may reach human administration routes. A tenant setting in the
browser cannot establish any of those guarantees. They are infrastructure and
identity boundaries and must survive an omitted shell variable or a compromised
operator session.

## Decision

The AWS deployment accepts one strict, secret-free data-boundary manifest. The
supported deployment command validates it, verifies the referenced KMS key,
stores it in encrypted Parameter Store and reloads it for every deployment.
Once a deployed stack reports a configured boundary, a missing manifest blocks
future deployment instead of silently reverting to weaker defaults.

Schema version 1 binds:

- the exact home Region and a finite approved data-Region set;
- one same-account, same-Region customer-managed symmetric KMS key;
- an `ip-restricted` human administration mode and one to 32 public IPv4 CIDRs;
- opaque encryption-key-policy, data-residency, deletion-process,
  Conditional Access and deployment-approval evidence references.

The customer-managed key encrypts the retained DynamoDB tables, tenant-data S3
buckets, SNS security alerts and durable SQS queues. Dedicated signing and
provider-secret keys remain separate because combining executable-signing,
credential and data-encryption authority would widen blast radius. The static
UI bucket contains published application assets rather than tenant records and
remains separately encrypted.

CloudWatch log storage remains AWS-service encrypted and Regional rather than
using the customer data key. Production paths must therefore keep logs
content-minimised and free of tenant payloads, credentials and policy bodies.
An enterprise requiring CMK control over operational logs must add explicit
log groups and retention to its deployment before acceptance.

The Lambda receives only the secret-free posture and CIDR allow-list. Every
human request is checked against API Gateway's trusted
`requestContext.http.sourceIp` before tenant lookup, seeding or authorization.
Missing, malformed, private or out-of-range source evidence is denied when the
boundary is configured. Machine, SCIM, enrollment, endpoint-evidence,
discovery-ingestion and agent routes retain their own authentication boundaries
and are not accidentally denied by an operator VPN list.

## API and UI

`GET /enterprise/data-boundary` requires a canonical tenant operator role and
returns a fixed, secret-free deployment posture:

- configuration and encryption ownership;
- key fingerprint, never the full key ARN;
- home and approved data Regions;
- administrative access mode and allowed-network count, never CIDR values;
- Conditional Access evidence-reference presence;
- the retention/deletion behavior for operational state, short-lived
  capability records, immutable evidence, provider credentials and static
  assets; and
- explicit gaps and live-acceptance requirements.

The enterprise UI renders this as a focused read-only **Data boundaries** page.
It does not pretend a browser toggle can rotate a KMS key, move residency or
change a network perimeter.

## Trust boundaries and failure behavior

- Browser JSON, token claims and model output cannot select a key, Region or
  CIDR.
- Ambient deployment variables are erased and replaced only from the persisted
  manifest.
- The KMS preflight requires an enabled, customer-owned, symmetric
  encrypt/decrypt key with rotation enabled in the exact deployment account and
  Region.
- Approved Regions must include the home Region and configured immutable-audit
  replica Region. Unknown or duplicate Regions fail synthesis.
- Human network restriction uses only API Gateway source context; forwarding
  headers are ignored.
- Key-policy evidence is not key-policy enforcement. The customer still owns
  a reviewed key policy and must prove deployment, runtime, recovery and
  revocation behavior.
- IP restriction is not PrivateLink. A later private-ingress cell may replace
  the public endpoint, but the UI must continue to label this version
  `ip-restricted`, never `private`.
- CloudFront edge caching and Cognito/Entra authentication are global/provider
  services. The approved data-Region claim covers retained application data,
  not every transient provider processing location.
- The configured key scope does not include CloudWatch logs, the static UI
  bucket, provider secret material or signing keys. Each has a separate trust
  and encryption boundary.

## Deletion contract

Deletion is described by data class rather than one misleading button:

- operational DynamoDB state is retained with stack deletion protection and
  requires a separately approved tenant-offboarding workflow;
- TTL records expire as configured, but expiry is asynchronous and is not a
  deletion-time guarantee;
- immutable evidence remains under COMPLIANCE Object Lock and legal hold until
  its retention authority permits deletion;
- provider credentials are deleted or disabled through Secrets Manager and
  provider-owned revocation, outside the browser;
- static application assets contain no tenant records and can be replaced by a
  normal UI deployment.

The first customer must approve a deletion runbook and retain a synthetic
offboarding exercise. This implementation does not claim that such an exercise
has occurred.

## Verification

Required automated evidence includes strict manifest parsing, duplicate-field
denial, unsafe CIDR denial, wrong-account/Region key denial, disabled or
non-rotating key denial, persisted-manifest omission protection, CDK encryption
and output assertions, operator source-IP allow/deny/missing-context tests,
tenant-role denial, secret-free posture contracts and UI accessibility plus
responsive browser verification.
