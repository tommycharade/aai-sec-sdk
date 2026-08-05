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

Schema version 1 remains supported for existing IP-restricted deployments.
Schema version 2 binds the same encryption and residency authority and chooses
exactly one operator transport:

- the exact home Region and a finite approved data-Region set;
- one same-account, same-Region customer-managed symmetric KMS key;
- `ip-restricted` with one to 32 public IPv4 CIDRs; or
- `private-link` with one to eight same-account, available execute-api
  interface VPC endpoint IDs and no CIDR fallback;
- opaque encryption-key-policy, data-residency, deletion-process,
  Conditional Access and deployment-approval evidence references; and, for
  schema version 2, a private-access review evidence reference.

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

For `private-link`, CDK creates a private REST API associated with only the
reviewed VPC endpoints. Its resource policy permits `execute-api:Invoke` only
when `aws:SourceVpce` exactly matches that set, and every operator method still
uses the Cognito user-pool authorizer. Lambda independently checks the private
API ID and API Gateway's `$context.identity.vpceId` before tenant lookup. The
public HTTP API remains the separately authenticated machine/agent channel;
its human catch-all fails closed while private mode is active.

For `ip-restricted`, Lambda checks API Gateway's trusted
`requestContext.http.sourceIp`. Missing, malformed or out-of-range context is
denied. Machine, SCIM, enrollment, endpoint-evidence,
discovery-ingestion and agent routes retain their own authentication boundaries
and are not accidentally denied by an operator VPN list.

## API and UI

`GET /enterprise/data-boundary` requires a canonical tenant operator role and
returns a fixed, secret-free deployment posture:

- configuration and encryption ownership;
- key fingerprint, never the full key ARN;
- home and approved data Regions;
- administrative access mode and allowed network or VPC-endpoint count, never
  CIDR or VPC endpoint values;
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
  headers are ignored. Private mode requires the exact deployed REST API ID
  and `$context.identity.vpceId` as defense in depth.
- Key-policy evidence is not key-policy enforcement. The customer still owns
  a reviewed key policy and must prove deployment, runtime, recovery and
  revocation behavior.
- PrivateLink applies to the operator API, not the public machine/agent API or
  static CloudFront assets. Operators need private connectivity (VPN or Direct
  Connect), DNS resolution and endpoint security-group access to reach it.
- The deployment preflight proves endpoint identity, account, Region, service,
  type, availability and private DNS. It does not prove customer routing,
  endpoint policy, security groups or on-premises DNS; those require live
  acceptance.
- Private operator ingress is currently created for the primary control-plane
  stack. Regional operator failover remains unavailable until reviewed private
  endpoints and equivalent private REST APIs exist in each target Region; a
  passive cell fails closed rather than reverting to public operator access.
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

Required automated evidence includes strict schema-v1 migration and schema-v2
parsing, mutually exclusive CIDR/VPC-endpoint authority, duplicate-field and
unsafe-network denial, wrong endpoint service/account/state/private-DNS denial,
wrong-account/Region key denial, persisted-manifest omission protection, CDK
encryption and private-resource-policy assertions, source-IP and private-context
adversarial tests, tenant-role denial, secret-free posture contracts and UI
accessibility plus responsive browser verification.

AWS documents that private API Gateway endpoints are available only for REST
APIs, use execute-api interface VPC endpoints, and can be restricted by
`aws:SourceVpce`: [private REST APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-private-apis.html),
[create a private API](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-private-api-create.html),
and [resource-policy examples](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-resource-policies-examples.html).
