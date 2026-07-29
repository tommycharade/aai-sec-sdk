# AWS pilot acceptance evidence — 2026-07-29

This record captures the post-deployment acceptance state of the hosted pilot.
It deliberately separates a deployed control-plane result from endpoint
enforcement. A policy being active in AWS does not prove that Claude Code or
Codex has loaded and enforced it.

## Environment and immutable references

| Item | Observed value |
| --- | --- |
| AWS account and region | `396510133537`, `eu-west-2` |
| CloudFormation stack | `AaiSecControlPlane` — `UPDATE_COMPLETE` |
| Hosted UI | `https://d2ir54klde64bd.cloudfront.net` |
| API | `https://lwg33pxwk8.execute-api.eu-west-2.amazonaws.com` |
| SDK deployed merge | `6bead88002e436071b5a6dd3d66c13c38a212f92` |
| UI deployed merge | `9311a52f53914e70f2bb82f905f791701658d2c1` |
| Deployed UI JavaScript | `assets/index-BgcTctCD.js` |

The deployed CloudFront index referenced the exact JavaScript and CSS build
assets, both assets returned HTTP 200, and the deployment invalidation reached
`Completed`. Unauthenticated requests to `/enterprise/policies` and
`/enterprise/identity` returned HTTP 401 through API Gateway. This proves the
public authorizer rejects missing credentials; it does not replace a signed-in
role and cross-tenant acceptance exercise.

## Delegated administration

The merged delegated-administration Lambda was deployed and exercised through
AWS IAM invocation with one unique synthetic tenant. The exercise used two
organizations and server-owned project/deployment records, then asserted:

| Assertion | Result |
| --- | --- |
| Platform administrator creates a seven-day organization-scoped fleet grant | HTTP 201 |
| Delegated operator creates a deployment below the assigned organization | HTTP 201 |
| The same operator targets a sibling organization | HTTP 403 |
| Deployment inventory returns only the in-scope deployment | HTTP 200, exact one-item result |
| Delegated operator attempts to delegate identity authority | HTTP 403 |
| An attacker supplies a forged informational delegation claim | HTTP 403 |
| Platform administrator revokes the live grant | HTTP 200, `revoked` |
| Revoked operator retries without refreshing its token | HTTP 403 |
| Access certification contains the governed grant | HTTP 200, schema version 2 |

Cleanup then queried the exact tenant partition and audit prefix and observed
zero remaining DynamoDB records and zero remaining S3 objects. This proves the
deployed software boundary, including live revocation. It does not substitute
for the outstanding real Entra/SCIM and independent multi-business-unit
exercise.

## Agent identity lifecycle

The deployed control-plane harness created one unique synthetic deployment and
agent, enrolled it, established a live session and assigned the safe policy
group. It then exercised the merged lifecycle boundary against API Gateway,
Lambda and DynamoDB:

| Assertion | Result |
| --- | --- |
| Issue an unused predecessor bootstrap token | HTTP 201 |
| Atomically replace the active identity | HTTP 201; predecessor `revoked`, successor `active` |
| Reuse the predecessor session after replacement | HTTP 403 |
| Consume the predecessor's unused bootstrap token | HTTP 403 |
| Issue fresh bootstrap material for the successor | HTTP 201 |
| Enrol the successor with fresh material | HTTP 201 |
| Offboard the revoked predecessor | HTTP 200; lifecycle `deleted` |
| Remove the predecessor's local project path | Empty path with retained SHA-256 digest |

The same run also passed project-scope binding, managed-configuration
missing/conflict enforcement, approval replay denial, emergency-stop recovery,
multi-process idempotency, WORM audit retention and SNS/SQS alert delivery.
Exact synthetic agent, session, bootstrap, membership, deployment, template,
configuration, approval and idempotency records were removed afterward;
content-minimised immutable lifecycle audit records remain as intended.

Runtime attestation was the sole failed positive-verification check and the
deployed API explicitly returned `not_configured`. The harness continued only
under its named pilot flag and printed that this did not prove release
provenance or full agent verification. This is a lifecycle acceptance pass, not
a P0-05 attestation pass.

## Governed policy ledger

The deployed Lambda was invoked through AWS IAM with a synthetic,
tenant-scoped administrator subject to read the immutable version ledger for
`policy-safe-default`. The route safely migrated the legacy active snapshot to
one ledger entry. The observed response was:

| Assertion | Result |
| --- | --- |
| Lambda and route response | HTTP 200, no function error |
| Active policy version | `2` |
| Ledger state | `active` |
| Content hash | `a02ed182917ddb40a99792be3935faf2857619e18fef171723340a9795feb17d` |
| Active authority changed | No; configuration and version remained unchanged |
| Migration attribution | `legacy-migration` |

The migrated configuration remains deny-by-default, permits only bounded read
tools and exact safe command patterns, requires approval for `git push`, denies
`rm -rf`, limits the runtime to 25 actions, and keeps tool-content capture off
with sensitive-data redaction on. The contract and adversarial suites separately
prove draft, independent review, staging, stale-base conflict and atomic
activation. This live read proves the deployed adapter can persist and return
the immutable ledger; it does not claim that a new live policy was promoted or
that an endpoint converged.

## Managed endpoint verification

The deployed verification route was exercised for the registered Claude Code
and Codex instances on the Kratos project. Both returned HTTP 200 with a
negative `verified` result. The negative result is the correct fail-closed
outcome:

| Verification check | Claude Code | Codex CLI |
| --- | --- | --- |
| Registered | Pass | Pass |
| Exactly one valid policy group | Pass | Pass |
| Emergency stop clear | Pass | Pass |
| Current heartbeat | **Fail — expired** | **Fail — expired** |
| Approved runtime attestation | **Fail — no approved manifest** | **Fail — no approved manifest** |
| Fresh exact managed configuration | **Fail — not proven** | **Fail — not proven** |
| Overall verified | **Fail** | **Fail** |

The local binaries observed during acceptance were Claude Code `2.1.220` and
Codex CLI `0.146.0-alpha.3.1`. Project configuration exists for both hosts, but
project-owned files are not enterprise-managed evidence. The public SDK release
is still `v1.0.1`, while the merged source declares `1.1.0`; therefore no
`v1.1.0` release artifact or tag-bound provenance exists from which a truthful
runtime approval manifest can be generated.

## Identity and integrations

- Microsoft Entra ID OIDC and SCIM remain `not-configured` in the deployed
  stack. Source contracts fail closed and cover joiner, mover and leaver state,
  but P0-06 has no live tenant acceptance evidence yet.
- Splunk is intentionally a truthful stub. The UI and API report
  `deliveryVerified: false`; no HEC delivery is claimed.
- Runtime attestation manifests remain `not-configured`. Empty, digest-bound
  manifest files preserve fail-closed behavior until independently verified
  release inputs exist.

## Release decision

The hosted product is suitable for continued low-risk pilot work. It is not
ready for an enterprise-wide mandatory rollout because the live endpoint gate
is negative and Entra is not configured. The next evidence sequence is:

1. publish and independently verify `v1.1.0` release artifacts and provenance;
2. generate exact Claude Code and Codex runtime manifests from that release;
3. deploy the manifests and an exact managed-host package;
4. re-enrol or renew both Kratos agents and sustain fresh heartbeats;
5. prove allowed, denied and approval-required execution against the displayed
   effective authority, including tamper and stale-configuration rejection; and
6. configure a pilot Entra tenant and run OIDC plus SCIM joiner, mover and
   leaver acceptance.

Publishing a tag and approving runtime manifests are release-authority actions.
They must use reviewed release evidence and must never be replaced by synthetic
hashes simply to make the dashboard green.
