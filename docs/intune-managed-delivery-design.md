# Microsoft Intune managed delivery design

## Decision

Microsoft Intune is the first hosted endpoint-delivery provider, but it is not
modelled as a per-device command runner. Microsoft Graph deploys mobile apps
through assignments whose target is a group. The v1.0
[`mobileAppAssignment`](https://learn.microsoft.com/en-us/graph/api/resources/intune-apps-mobileappassignment?view=graph-rest-1.0)
contract describes a group assignment, and the
[`groupAssignmentTarget`](https://learn.microsoft.com/en-us/graph/api/resources/intune-shared-groupassignmenttarget?view=graph-rest-1.0)
contains a group ID. There is no generic Graph action that means “install this
app now on this managed-device ID.”

The control plane therefore uses a provider-neutral delivery outbox and an
Intune adapter that converges an exact server-owned rollout cohort through a
dedicated static Entra device group and an exact Intune app assignment. It must
not pretend that accepting a Graph mutation means the package installed.
Provider convergence is `assigned_reported`; only fresh challenge-bound runtime
attestation is `verified`.

This design is intentionally staged. The control plane retains target identity,
independently governed Intune configuration and a transactional outbox. An
isolated worker, FIFO queue, DLQ and repair schedule are implemented but
deployment-disabled by default. Real Graph writes require an explicit
deployment flag plus a separately reviewed enablement-evidence SHA-256; live
customer acceptance remains open.

## Provider constraint and identity chain

Intune discovery supplies a managed-device `id` and `azureADDeviceId`. The
latter is the Entra device registration ID, not necessarily the directory
object ID accepted by group-membership APIs. Microsoft Graph supports resolving
a device by the alternate `deviceId` key through
[`GET /devices(deviceId='{deviceId}')`](https://learn.microsoft.com/en-us/graph/api/device-get?view=graph-rest-1.0).
The adapter must perform that exact online lookup and require the response's
`deviceId` to match before using its returned directory-object `id`.

The complete target chain is:

```text
tenant + rollout revision + selected agent
  -> current managed-device discovery ID
  -> signed installation-to-agent binding
  -> Intune directory device registration ID
  -> online exact Entra directory-object lookup
  -> dedicated rollout cohort group
  -> exact approved Intune mobile-app identity
  -> required group assignment
  -> provider reconciliation
  -> independent runtime attestation
```

The browser, model, agent, MCP server and ordinary machine bearer cannot supply
or override any identity in this chain.

## Authority model

### 1. Runtime intent

The revisioned rollout remains the only authority for host, target release,
selected cohort, pause and rollback. A changed rollout revision invalidates
every undispatched or leased job from the previous revision.

### 2. Package authority

The deployment-owned delivery manifest binds the approved runtime release,
platform, architecture, immutable object and a digest of the provider app
identity. The raw Intune mobile-app ID is read only by the dedicated worker from
a tenant-tagged Secrets Manager record and must hash to the approved digest.

### 3. Endpoint identity

Current complete Intune discovery is authoritative for the managed-device ID
and directory device registration ID. Signed endpoint evidence is authoritative
only for local platform, installation and project-root correlation. A unique
tenant-wide `1:1:1` device/install/agent binding is mandatory.

### 4. Provider target

Each active rollout revision has one dedicated assigned-membership Entra
security group. The worker owns only groups carrying the exact AAI authority
marker and tenant/deployment/rollout digests. It must never mutate a
customer-owned general-purpose group.

### 5. Worker identity

Only an SQS event-source mapping invokes the dedicated worker role. SQS contains
an opaque outbox key, never a credential, device ID, package locator or Graph
request body. The worker strongly reloads the job and all live authority before
retrieving its tenant-tagged secret.

## Transactional outbox

The control-plane reconciler derives eligible work automatically; there is no
browser **Install** action. One DynamoDB transaction stores:

- the exact rollout revision and canonical instruction digest;
- package ID, manifest digest and private locator digest;
- endpoint binding digest and evidence revision;
- provider kind and provider-configuration revision;
- desired cohort digest and member count;
- idempotency key and bounded state-machine revision;
- an unqueued outbox index entry; and
- content-minimised primary audit evidence.

Only the opaque job key is sent to the FIFO queue. Failure to enqueue leaves the
outbox index intact for a bounded scheduled dispatcher. Acceptance by SQS
removes only the pending index attributes; it does not alter provider status.

### Implemented worker phase

The five-minute rollout reconciler first materializes each
server-selected target only when all of these exact records still match in one
DynamoDB transaction:

- active Intune provider pointer and independently approved immutable version;
- live rollout revision/state and deployment SDK version;
- active agent lifecycle revision;
- signed endpoint evidence revision and digest; and
- deployment-owned package/app-identity digests.

Targets are then sealed into immutable pages of at most 40 entries. A final
transaction checks those exact page digests and creates one complete command
per package/cohort, content-minimised primary audit evidence and an
`EndpointDeliveryOutbox` index entry. This ensures the future group-assignment
worker cannot mistake one device write for complete desired membership.
Reconciliation is idempotent by exact tenant-bound target, page, cohort and
instruction digests. The operator view states
`dispatchEnabled` from deployment-owned state and omits the secret ARN,
directory registration ID, package locator and complete instruction. When
enabled, the dispatcher sends only tenant and opaque command identity and
removes outbox attributes only after FIFO acceptance. The worker is isolated
from API authority, validates tenant/KMS/purpose-bound secret metadata before
decrypting, and reauthorizes current provider, rollout, agent, discovery,
signed endpoint and latest-command authority before every mutation.

One invocation processes at most one 40-target page. Commands of up to 500
targets advance through revision-bound encrypted FIFO continuations. Each
invocation reloads complete authority; the final stage prunes at most 40 stale
dedicated-group members and creates the required assignment only after exact
group reproduction. See the implemented
[bounded continuation authority](intune-continuation-authority-design.md).

## Governed provider configuration

Intune configuration uses an immutable `draft -> review -> approved -> active`
ledger. A platform administrator authors and submits a version. A different
subject with `provider_approval` authority must approve or reject it; the author
cannot self-approve even if they also hold platform-administrator authority.
Activation compares the expected active version and atomically retires its
predecessor.

The closed draft schema contains the canonical Microsoft tenant UUID, explicit
deployment IDs, permission-evidence SHA-256, rationale and a Secrets Manager
ARN. The API validates exact tenant namespace, dedicated KMS key and exact tag
set at both draft and activation boundaries using only `DescribeSecret`. The
handler has neither `GetSecretValue` nor decrypt authority. API projections
replace the ARN with a one-way reference digest.

## Dispatch-time online reauthorization

Immediately before every Graph mutation, the worker strongly and independently
rechecks:

1. tenant and provider configuration are active and exact-revision matched;
2. rollout state/revision/release and deterministic cohort are unchanged;
3. every target agent is active, non-quarantined and still selected;
4. current complete Intune discovery and fresh signed endpoint evidence still
   produce the exact binding digest;
5. the package and separate approval bundles still validate and match the
   frozen package digest;
6. the secret is tenant-tagged, KMS-protected and exact-purpose scoped;
7. the raw provider app ID hashes to the approved package identity; and
8. the online Entra device lookup returns exactly one matching registration ID.

Any mismatch marks the job `blocked` with a fixed reason before Graph write.
The worker never accepts a replacement ID from a provider error or browser.

## Intune convergence state machine

```text
not_configured
  -> ready                 reviewed secret, app and owned-group authority
  -> queued                exact outbox transaction committed
  -> resolving_targets     online Entra device resolution
  -> converging_members    exact cohort membership reconciliation
  -> converging_assignment exact required-app assignment reconciliation
  -> assigned_reported     provider reads reproduce desired state
  -> verified              fresh exact runtime attestation only

any open state
  -> blocked               authority changed or target became ambiguous
  -> retryable             bounded provider timeout/throttle/unknown outcome
  -> failed                fixed terminal provider/configuration reason
```

Graph timeout is an unknown outcome, not failure. The next attempt reads group
membership and app assignments before deciding whether a write is still
needed. Request IDs and canonical desired-state digests make retries
idempotent. Raw provider bodies and exception text are never persisted.

## Rollback and stale assignment safety

Rollback creates new desired state for the retained known-good app; it does not
reuse a stale target job. The adapter must reconcile both positive and negative
authority:

- add the exact selected cohort to the current owned group;
- remove members no longer selected from that owned group;
- create or retain only the exact desired app assignment owned by AAI;
- remove superseded AAI-owned assignments only after their identities are
  independently reproduced; and
- never delete or replace unrelated customer assignments.

Because provider propagation is eventually consistent, rollout verification
remains blocked until endpoint attestation proves the intended release. A
provider group or assignment report cannot become known-good state.

## Credentials and permissions

Discovery and delivery use separate applications or credentials. The existing
read-only discovery secret cannot be widened silently. Delivery uses the
tenant namespace `aai-sec/endpoint-delivery/<tenant>/...`, a dedicated KMS key
and the exact tag set:

```text
aai-sec:tenant-id=<tenant>
aai-sec:purpose=endpoint-delivery-provider
```

The eventual Intune app requires only the reviewed application permissions
needed to read devices, manage membership of AAI-owned groups and manage the
exact Intune app assignments. Microsoft documents
`DeviceManagementApps.ReadWrite.All` for the v1.0
[`assign` action](https://learn.microsoft.com/en-us/graph/api/intune-apps-mobileapp-assign?view=graph-rest-1.0)
and group membership through
[`POST /groups/{id}/members/$ref`](https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0).
The pilot must record the final least-privilege permission set and prove that
the role cannot mutate unowned groups or apps.

The secret value uses a closed schema. `providerPackageIdentitySha256` is the
SHA-256 of the canonical lowercase `mobileAppId`; relabelling another app is
rejected. `mobileAppEvidenceSha256` hashes exactly `id`, `displayName`,
`publisher`, `createdDateTime` and `lastModifiedDateTime`. Group evidence hashes
exactly `id`, `displayName`, `description`, `securityEnabled` and `mailEnabled`.
The worker reproduces both metadata projections online before mutation.

```json
{
  "schemaVersion": 1,
  "clientId": "11111111-1111-4111-8111-111111111111",
  "clientSecret": "stored-only-in-secrets-manager",
  "resources": [
    {
      "deploymentId": "synthetic-pilot",
      "providerPackageIdentitySha256": "b454f82c5857ebabf342b7258e5cf7def78b7cd975814119462973de9a38df10",
      "mobileAppId": "22222222-2222-4222-8222-222222222222",
      "mobileAppEvidenceSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "groupId": "33333333-3333-4333-8333-333333333333",
      "groupEvidenceSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }
  ]
}
```

The example is synthetic; its metadata evidence values are not deployable.

## UI placement

No new primary navigation item is added.

- **Integrations** will configure the Intune delivery connection, secret ARN,
  package identities and owned-group posture. Secret values are never entered.
- **Rollouts → Runtime releases → Delivery readiness** adds provider-target and
  assignment posture after package and binding readiness.
- **Fleet → Coverage** explains missing Intune registration identity or stale
  discovery.
- **Audit** shows content-minimised configuration, queue, assignment and
  reconciliation evidence.

The UI may offer **Enable hosted delivery** only after a dry-run reproduces all
authority and an independent approver accepts the exact configuration revision.
It never offers a free-form device ID, app ID, Graph URL or request-body field.

## Secure defaults and non-goals

- Hosted dispatch, its event source and repair schedule are disabled by default.
- Enabling requires both `ENDPOINT_DELIVERY_DISPATCH_ENABLED=true` and a
  lowercase SHA-256 `ENDPOINT_DELIVERY_ENABLEMENT_EVIDENCE_SHA256`; incomplete
  or contradictory CDK input fails synthesis.
- The checked-in package and provider catalogs are empty and not healthy.
- Unknown Graph fields, redirects, origins, IDs, pagination links and response
  codes fail closed.
- The worker has explicit timeouts, bounded retries, reserved concurrency and a
  DLQ.
- The worker cannot upload arbitrary packages, execute scripts, run shell
  commands, change policy, clear quarantine or mark a runtime verified.
- This design does not claim support for Jamf, Kandji or arbitrary MDM APIs.
- This design does not claim live Intune compatibility until customer-owned
  acceptance exits successfully.

## Required verification

Automated evidence must cover malformed and duplicate target identity,
cross-tenant secret/group/app references, stale rollout and binding replay,
package-app digest mismatch, unmanaged/quarantined targets, queue duplication,
concurrent lease, timeout-unknown reconciliation, redirect/origin rejection,
foreign assignment preservation, rollback, fixed redaction and the strict
separation of `assigned_reported` from `verified`.

Live acceptance must use a non-production Intune tenant and managed Claude Code
and Codex devices. It must exercise install, expansion, pause, rollback,
provider timeout, throttling, credential rotation/revocation, duplicate target,
member drift and post-install attestation before hosted delivery is described
as available.
