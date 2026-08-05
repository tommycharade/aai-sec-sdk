# Managed endpoint delivery authority

## Decision

The first hosted endpoint-management integration is Microsoft Intune. The
control plane will add the two missing authorities that must exist before any
provider worker can dispatch privileged installation work:

1. an immutable, platform-specific delivery-package catalog bound to an
   independently approved runtime release; and
2. a current bijective binding between one managed device, one observed
   installation and one active enrolled agent.

This tranche does **not** call Microsoft Graph, upload executable bytes, store
Intune credentials or claim that an endpoint installed anything. It adds a
read-only preflight beside the existing runtime-remediation queue so an
operator can distinguish “release intent exists” from “release intent also has
an exact approved delivery object and an unambiguous target identity.” The
existing claim/report queue is unchanged and cannot retrieve package locators.
Fresh challenge-bound runtime attestation remains the only proof of
installation and the only signal that can complete a rollout.

## Customer outcome

Before a canary starts, a platform engineer can answer four separate questions:

| Question | Authority | Required state |
| --- | --- | --- |
| Is the runtime approved? | Deployment-owned runtime release catalog | Exact host/version manifest and provenance are approved. |
| Are immutable bytes deliverable? | Delivery-package catalog | Exact release, platform, architecture, S3 object version and SHA-256 are approved. |
| Is the endpoint target unambiguous? | Current Intune/device discovery plus signed endpoint evidence | Exactly one managed device, installation and active enrolled agent correlate. |
| Is the runtime actually running? | Challenge-bound runtime attestation | Fresh evidence matches the exact target release. |

The UI must never collapse these into one green “installed” state.

## Trust boundaries

### Delivery package authority

Delivery manifests are deployment-owned inputs, not browser-authored records.
The deployment pipeline validates a closed bundle and a separate approval
bundle before CDK synthesis. Lambda independently revalidates the bundled
bytes and their deployment-provided SHA-256 values before serving metadata.

Each entry binds:

- one exact approved runtime `releaseId`;
- host, operating system and architecture;
- package format;
- exact S3 bucket ARN, object key, immutable object version and object SHA-256;
- provider package identity digest, never a provider credential or raw secret;
- release-evidence and package-signature evidence SHA-256 values; and
- a stable package ID derived from the canonical manifest.

The operator API exposes only content-minimised identities and digests. It does
not return the bucket, object key, executable bytes, signing material, provider
credential or installation command. A later Intune worker receives the object
locator only through its dedicated IAM role and server-side job record.

The initial checked-in catalog is empty. Empty is `not_configured`, never
healthy. A partially approved, duplicate, stale, malformed, cross-release or
digest-mismatched bundle fails closed.

Signed endpoint evidence currently identifies operating system and
architecture, but not Linux distribution or package manager. The authority
therefore permits exactly one package format for each
`releaseId`/operating-system/architecture tuple. Registering both DEB and RPM
for the same tuple fails closed instead of selecting by bundle order. Supporting
both safely requires a future signed distribution/package-manager field in the
endpoint evidence and binding contract.

### Endpoint binding authority

The browser cannot choose a device, installation or agent mapping. For each
active enrolled agent, the server derives a binding from:

- a complete, current endpoint discovery source containing a managed device;
- a fresh signed device report;
- one installation with the exact host and project-root digest;
- one active enrolled agent whose server-stored project root hashes to that
  digest; and
- current lifecycle/session authority.

The binding is `ready` only when cardinality is exactly `1:1:1`. Zero or more
than one device, installation or enrolled-agent match is an explicit blocker.
The canonical `bindingDigest` is resolved inside the authenticated tenant and covers deployment, agent, device,
installation, host, evidence revision/digest and lifecycle revision. It
contains no raw project path.

Every consequential provider mutation must recompute the binding from live
strong reads and compare the exact digest. A stored or browser-supplied
“ready” flag is never authority.

### Remediation authority

The existing executable-free instruction remains rollout-derived. A future
hosted provider dispatch must additionally require:

- one exact delivery package for the selected approved release and endpoint
  platform/architecture; and
- one current `ready` endpoint binding.

The separate operator preflight exposes fixed package and binding posture, but the
existing service-bearer client still cannot receive an S3 locator or dispatch
provider work. This avoids turning a broad machine credential into software
distribution authority.

## Closed delivery manifest

The canonical bundle is `delivery-packages.json`:

```json
[
  {
    "schemaVersion": 1,
    "releaseId": "claude-code:1.1.0",
    "host": "claude-code",
    "operatingSystem": "darwin",
    "architecture": "arm64",
    "packageFormat": "pkg",
    "bucketArn": "arn:aws:s3:::synthetic-release-bucket",
    "objectKey": "releases/v1.1.0/aai-sec.pkg",
    "objectVersionId": "synthetic-version-1",
    "objectSha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "providerPackageIdentitySha256": "1111111111111111111111111111111111111111111111111111111111111111",
    "packageSignatureEvidenceSha256": "2222222222222222222222222222222222222222222222222222222222222222",
    "releaseEvidenceSha256": "3333333333333333333333333333333333333333333333333333333333333333"
  }
]
```

The example is schema illustration only and is never deployed as trusted
authority. Real object versions and evidence are generated from the approved
release pipeline outside source control.

`delivery-packages.approvals.json` binds the exact bundle SHA-256, every
canonical package ID, approver evidence digest and review timestamp. Approval
must cover the bundle exactly; surplus and missing entries are rejected.

## API projection

Human reads require a tenant role with `inventory_read`; the versioned machine
API requires an exact `inventory_read` service identity:

```text
GET /api/enterprise/endpoint-delivery?deploymentId=...
GET /machine/v1/enterprise/endpoint-delivery?deploymentId=...
```

The bounded response contains:

- catalog status and bundle/approval digests;
- content-minimised compatible package entries;
- one row per active deployment agent with package and binding status;
- fixed reason codes consumed by the UI as one safe next action; and
- a complete bounded deployment projection of at most the active fleet limit.

Runtime attestation remains visible in the adjacent version-compliance and
remediation surfaces; it is not collapsed into delivery readiness.

No browser route creates, edits or approves package authority or reports
provider outcomes.

## UI placement

Do not add another primary navigation destination. Extend **Rollouts → Runtime
releases** with one delivery-readiness section:

1. **Release approved** — exact runtime release authority.
2. **Package ready** — immutable platform delivery package.
3. **Target bound** — unique current device/install/agent binding.
4. **Runtime verified** — exact fresh attestation.

Each deployment row offers **Delivery readiness**. Opening it shows ready and
blocked counts, endpoint rows, fixed blocker explanations, evidence freshness
and package identity. Advanced package-bundle digests are collapsed behind
**Package authority evidence**.

Every metric and state has keyboard-focusable contextual help. Empty,
unavailable, stale, forbidden and partial-page states explain one safe next
action. The UI never offers an “Install” button until the separately reviewed
Intune worker exists.

## Intune worker sequence

The next tranche may add hosted dispatch only after this authority is deployed:

1. a dedicated Lambda role authenticates to Microsoft Graph using a
   tenant-tagged Secrets Manager reference;
2. a transactional outbox freezes the exact rollout instruction, package and
   binding digests before provider submission;
3. provider idempotency and reconciliation handle timeout/unknown outcomes;
4. online reauthorization repeats rollout, package and binding checks
   immediately before dispatch;
5. provider success is recorded as `installed_reported`, never `verified`; and
6. a later endpoint attestation independently proves the target release.

The worker must not accept executable bytes, commands, device IDs or package
IDs from the browser or model.

## Threats and controls

| Threat | Control |
| --- | --- |
| Browser registers unreviewed executable | No package mutation API; deployment-owned closed bundles only. |
| Mutable S3 key changes after approval | Exact S3 object version and object SHA-256 are required. |
| Package is approved for another release | Exact release ID plus release-evidence digest must match the runtime catalog. |
| Device ID is manually mapped to a privileged agent | Server derives correlation from current trusted discovery and signed endpoint evidence. |
| Duplicate installation is silently selected | Any cardinality other than `1:1:1` blocks eligibility. |
| Old clean evidence survives device or agent change | Binding digest covers evidence and lifecycle revisions and is recomputed online. |
| MDM channel success widens runtime authority | Channel observation remains separate; only attestation completes rollout. |
| Service bearer becomes software-distribution credential | Existing remediation bearer receives no locator, command, executable or provider credential. |
| Oversized fleet is presented as a complete preflight | Existing bounded tenant inventory and deployment population limits fail the read rather than truncating silently. |

## Verification

Automated evidence in this tranche:

- closed bundle and approval validation in CDK and Lambda;
- unknown fields, duplicate platform identity, traversal-shaped object keys,
  mutable/missing object versions, release mismatch and approval drift denial;
- exact ready binding and explicit missing-platform blocker projection;
- tenant-role and exact machine `inventory_read` route isolation;
- content minimisation and credential/path/command absence;
- UI loading, unavailable, ready and blocked states;
- keyboard, automated accessibility and 390-pixel narrow-browser acceptance; and
- full SDK and UI quality gates.

The remaining provider tranche must prove stale, unmanaged, revoked,
cross-deployment and duplicate binding denial again at dispatch time, package
and binding reauthorization, outbox/idempotency behavior, permission-denied
provider states, and causal post-dispatch evidence. Live completion still
requires a real Intune tenant, dedicated provider role, managed pilot devices,
immutable uploaded packages and upgrade/rollback acceptance. The software must
continue to label those as outstanding.
