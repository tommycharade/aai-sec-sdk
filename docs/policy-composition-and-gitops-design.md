# Policy composition and GitOps

This design covers P1-POL-07 and P1-POL-09. It adds reusable, version-bound
policy components and a Git import/export workflow without allowing Git, a
browser, or a mutable parent policy to become runtime authority.

## Decision

An independently approved policy version is the reusable component. A draft
may reference up to eight exact versions from other policies in the same
organization. Each reference binds the component policy ID, version and
content SHA-256. References never mean “latest” or “active”, so a later change
to a component cannot silently alter an already reviewed child.

A policy version stores three distinct objects:

- `localConfiguration`: fields authored specifically for this policy;
- `componentRefs`: ordered, exact immutable component identities; and
- `configuration`: the fully composed effective policy evaluated by the
  existing review, simulation, signing and runtime paths.

The effective configuration and a bounded field-level explanation are
computed by the control plane before the draft is stored. The browser may
preview the same operation for usability, but server output is authoritative.
Activation continues to copy only the effective configuration into the active
policy snapshot. Existing policies migrate as versions with empty component
references and a local configuration equal to their current configuration.

## Why policy versions are components

Creating a second component lifecycle would duplicate draft, independent
approval, immutable versioning, signing and audit behavior. Reusing governed
policy versions means a component has already crossed those boundaries. A
component may be referenced only while its version is `active` or `retired`,
has an independent approver and has an exact content hash. `draft`, `review`,
`approved`, `staged`, rejected or missing versions fail closed. Providers that
support signed bundles, including AWS, additionally require valid stored
integrity evidence. The SQLite reference provider is not presented as signed
or highly available production authority.

The AWS Lambda uses a checked-in standalone runtime generated mechanically from
the canonical SDK composition module. CI verifies source freshness and semantic
parity. This keeps the deployable Lambda self-contained without creating a
second editable set of merge rules.

Retired versions remain valid immutable inputs for an existing or new draft;
retirement removes active fleet assignment, not retained reviewed evidence.
Deletion of referenced policy versions is prohibited.

## Deterministic restrictive composition

Composition starts with no opinion. Components are applied in their declared
order, followed by local policy intent. Ordering is retained for explanation,
but it cannot be used to overwrite a conflict or widen earlier authority.

| Field class | Composition rule | Examples |
| --- | --- | --- |
| Allow-list | Set intersection after the first opinion | tools, principals, built-ins, Skills, MCP servers, command allow patterns, credential scopes |
| Deny-list | Set union | denied tools and denied command patterns |
| Approval requirement | Set union; minimum TTL | required tools/risk classes/commands and approval expiry |
| Maximum budget or lifetime | Numeric minimum | actions, concurrency, fan-out, cost, rate, delegation, timeout and credential/idempotency TTL |
| Required safeguard | Boolean OR | deny-by-default, high-risk isolation, credentials when a component requires them, redaction |
| Optional capture or egress | Boolean AND after the first opinion | tool-content capture and telemetry enablement |
| Provider or deployment reference | Exact equality | policy, approval, audit, broker, isolation and telemetry provider references |
| Closed enum | Exact equality unless a field-specific restrictive order exists | credential/isolation modes and managed-host identity |
| Unknown legacy field | Exact equality | migration extensions cannot gain undocumented merge semantics |

Lists are canonicalized as unique, sorted JSON values. Duplicate values,
booleans masquerading as numbers, non-finite numbers, unknown typed fields,
unsafe command patterns and secrets are rejected by the normal policy schema
before composition. An empty allow-list is valid and means no authority.

A differing provider, host identity, bundle digest, or unknown legacy value is
a conflict, not “last writer wins”. The operator must resolve it explicitly in
the source components before review. Components cannot set
`denyByDefault: false`, disable mandatory redaction or weaken immutable SDK
safeguards.

## Graph and tenant constraints

References are resolved by strongly consistent reads. The control plane:

- rejects self-reference and cross-organization references;
- rejects repeated references and changed content hashes;
- traverses the complete component graph with a maximum depth of four and a
  maximum of 32 unique versions;
- rejects cycles, missing links and ambiguous duplicate policy identities;
- stores a separate graph digest binding local intent, ordered exact references
  (including each component graph digest), and the effective result; and
- repeats graph validation at staging and activation so a corrupted provider
  record cannot be promoted.

`contentHash` remains the effective-configuration SHA-256 for compatibility
with runtime drift and signed-bundle verification. `graphDigest` proves how
that result was derived. Lifecycle transitions reproduce and compare both.
Because every edge names an immutable version, composition is reproducible
without consulting mutable active-policy pointers.

## Effective-policy explanation

Every draft and version detail returns `composition` with:

- the graph digest and ordered component identities;
- each effective field, merge rule and winning/restricting sources;
- removed allow-list values and added deny/approval values;
- the local policy contribution;
- conflicts, if preview is requested before draft creation; and
- explicit `no-op` contributions where a component added no authority change.

The UI leads with the effective result. It shows reusable components as a
stack, lets an operator expand “why is this value effective?”, and keeps local
intent visually separate from inherited restrictions. JSON remains an expert
view. The UI never describes a component update as applied to a child whose
exact reference did not change.

## Git source contract

Git is a reviewed source and transport, not an authorization system. A
deployment-owned `PolicySourceVerifier` adapter retrieves one exact commit and
path from an allow-listed repository and returns server-observed facts:

- provider and canonical repository identity;
- full commit SHA and immutable blob SHA;
- path and content digest;
- branch-protection/review result and reviewed pull-request reference;
- signer identity and signature-verification result; and
- retrieval time and provider evidence digest.

The first provider adapter targets GitHub. Its installation credential is a
deployment-owned secret reference with read-only Contents, Metadata and Pull
Requests access. The browser supplies no token, review status, signer result or
policy content. Provider calls use bounded timeouts and pagination and fail
closed on rate limits, partial review data, changed commits, redirects or an
unavailable verifier.

The canonical schema-v1 policy source document contains exactly:

```json
{
  "schemaVersion": 1,
  "policyId": "policy-engineering",
  "organizationId": "org-example",
  "name": "Engineering agents",
  "componentRefs": [
    {
      "policyId": "policy-enterprise-baseline",
      "version": 4,
      "contentHash": "<64 lowercase hex characters>"
    }
  ],
  "localConfiguration": {}
}
```

Unknown fields, duplicate JSON keys, YAML aliases/tags, non-UTF-8 content and
documents over 1 MiB are rejected. JSON is canonical. YAML may be accepted as
an authoring format only through a safe parser and is normalized to the same
canonical JSON before hashing; the initial implementation may ship JSON first
rather than introducing an unsafe parser.

## Import and export lifecycle

Export returns canonical source bytes plus a control-plane provenance envelope
that binds tenant, policy/version/content hash, component graph digest,
exporting subject/time and signing key. The envelope is signed by the existing
policy-signing adapter. It contains no credentials or provider token.

Import accepts an idempotency identity plus repository, full commit SHA and
path. The server retrieves
and verifies the document, checks tenant/policy scope, resolves components and
creates a normal draft. It records immutable Git and control-plane provenance
on that draft. Import never submits, approves, stages, activates or assigns a
policy. A second authenticated subject still performs approval in the normal
control-plane lifecycle.

Re-importing the same provider evidence and canonical content is idempotent.
The same request identity with different content, a rewritten commit, changed
review state, missing signature or another tenant is rejected and audited.

## API surface

```text
POST /api/enterprise/policies/composition/preview
POST /api/enterprise/policies/{policyId}/versions/{version}/export
POST /api/enterprise/policies/imports
GET  /api/enterprise/policies/imports/{importId}
```

The reference implementation is available through `EnterpriseFleetStore`.
Inject a deployment-owned `PolicySourceVerifier` and `PolicyExportSigner` when
constructing the store. If either adapter is absent, its operation fails
closed. `GitHubPolicySourceVerifier` supplies the GitHub evidence contract but
deliberately receives the credential callback and bounded HTTP transport from
the deployment; it neither discovers ambient credentials nor performs work in
its constructor.

```python
from agentic_security import EnterpriseFleetStore, GitHubPolicySourceVerifier

verifier = GitHubPolicySourceVerifier(
    token_provider=resolve_read_only_github_app_token,  # deployment-owned
    transport=bounded_no_redirect_transport,
    now=clock,
)
store = EnterpriseFleetStore(
    "fleet.sqlite",
    policy_source_verifier=verifier,
    policy_export_signer=kms_policy_export_signer,
)
```

The names in this abbreviated integration example are application adapters,
not SDK globals. Production deployments should use PostgreSQL and a KMS/HSM
signer; SQLite remains the local reference persistence adapter.

The AWS-hosted implementation keeps provider access in a dedicated verifier
Lambda. That worker can read one configured Secrets Manager secret and call
only the fixed GitHub API origin; it has no DynamoDB, fleet mutation or KMS
signing permission. The control-plane Lambda can invoke only that exact worker,
reconstructs `VerifiedPolicySource` from its bounded response and compares the
request and evidence digests before writing anything. Policy shell, immutable
draft and import record commit in one DynamoDB transaction. KMS signs export
provenance in the control plane. Missing configuration, verifier errors,
malformed evidence and transaction races fail without a partial policy.

Normal create/update requests gain `componentRefs` and
`localConfiguration`. Legacy `configuration` remains accepted only when
`componentRefs` is absent; it maps to local configuration. Sending both forms
is ambiguous and fails closed.

## Threats and controls

| Threat | Control | Failure posture |
| --- | --- | --- |
| Mutable parent silently widens children | Exact policy version and content hash | Existing child is unchanged |
| Component order hides an overwrite | Restrictive field-specific algebra; conflicts reject | Draft is not created |
| Cross-tenant component reference | Authenticated organization plus consistent component read | Request denied |
| Cycle or graph bomb | Depth, unique-node and reference-count bounds | Composition denied |
| Browser forges Git approval | Server-owned source-verifier adapter | Import denied |
| Git content changes after review | Exact commit, blob and content digests | Import denied |
| Imported file activates authority | Import creates only an ordinary draft | No fleet change |
| Unknown field gains merge behavior | Closed typed schema or exact-equality legacy rule | Conflict/rejection |
| Explanation differs from runtime | Effective configuration stored once and used by review/sign/runtime | Promotion denied on digest mismatch |

## Required evidence

Unit and adversarial tests must prove every merge operator, deterministic
canonicalization, changed-order behavior, empty intersections, provider
conflicts, graph bounds, cycles, stale hashes, cross-tenant denial and legacy
migration. Control-plane and AWS contracts must prove immutable references,
strongly consistent reads, activation revalidation, audit/provenance retention,
idempotent import and no side effect on preview/provider failure. UI tests must
prove effective-first explanation, local-versus-inherited clarity, conflict
resolution, no silent activation and accessible keyboard/screen-reader flows.

Live acceptance requires an organization-owned GitHub repository with branch
protection, two independent identities, a read-only GitHub App installation
and retained export/import/approval/activation evidence. Synthetic provider
tests do not satisfy that deployment acceptance.
