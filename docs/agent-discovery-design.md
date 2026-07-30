# Agent population discovery

## Purpose

Enterprise coverage must answer a different question from enrollment: **where
should Claude Code or Codex exist, and which of those instances are actually
governed?** Counting only enrolled agents creates a circular denominator and can
report 100% while unknown installations remain unmanaged.

The discovery boundary accepts complete, time-bounded snapshots from three
deployment-owned inventory classes, correlates them with server-owned agent
enrollment, and exposes the result in the **Coverage** workspace.

## Trust and authority model

Discovery is observational and can only lower assurance. A source snapshot can
create a finding, but it cannot enroll, revoke, quarantine, assign policy, or
approve an action. Those authorities remain in their existing control-plane
boundaries.

Platform administrators create or rotate a connector credential through the
`discovery_write` capability. The plaintext secret is returned once; the
control plane stores only its SHA-256 digest and binds it to exactly one tenant,
source identifier and source class. Connector credentials cannot call operator
or agent routes and can be revoked immediately. The browser never supplies
trusted inventory.

Required source classes are:

| Source | Establishes | Minimum observations |
|---|---|---|
| Identity | Current people and leavers | `identity` records with an active state |
| Endpoint | Devices and observed agent installations | `device` and `installation` records |
| Source control | Repositories where an agent host is expected | `repository` records |

Every snapshot has a generation, optimistic-concurrency revision, observation
time, expiry, completeness flag, and canonical content hash. A snapshot is
current only when it is complete and unexpired. Raw project paths are rejected;
connectors submit their SHA-256 digest. Credentials, prompts, tool arguments,
outputs, and source tokens are never accepted.

## Coverage semantics

The expected denominator is the unique set of `(projectRootDigest, host)`
targets declared by current source-control records or observed by current
endpoint records. Enrollment is correlated by hashing the server-owned project
root and matching the host.

Coverage, health, and compliance percentages are returned only when all three
required source classes have a current complete snapshot and the denominator is
non-zero. Otherwise those percentages are `null`, `coverageAvailable` is false,
and `blindSpots` identifies missing or non-current sources. Incomplete or stale
evidence never produces orphan conclusions.

The reconciler reports:

- expected but unenrolled instances (`unmanaged`);
- duplicate agent enrollments or endpoint installations;
- missing binaries, unobserved processes, and unmanaged devices;
- active agents whose owner or observed user is inactive (`leaver`); and
- active enrollments that have no expected population target (`orphaned`).

Findings are deterministic observations, not automatic containment. Operators
must verify the source and use the existing agent lifecycle controls to respond.

## API contract

The legacy small-pilot endpoint
`POST /api/enterprise/discovery/sources/{sourceId}/snapshots` accepts exactly:

```json
{
  "sourceKind": "source_control",
  "generation": "github-enterprise-2026-07-29T21:00Z",
  "expectedRevision": 0,
  "observedAt": 1785362400,
  "expiresAt": 1785362700,
  "complete": true,
  "observations": [
    {
      "kind": "repository",
      "id": "repo-platform",
      "projectRootDigest": "<64 lowercase hexadecimal characters>",
      "expectedHosts": ["claude-code", "codex-cli"],
      "businessUnit": "Platform"
    }
  ]
}
```

The endpoint rejects unknown fields, duplicate observations, unknown kinds,
expired or overlong validity windows, invalid digests, more than 100
observations, and stale revisions. The response excludes observations. Audit
evidence records only source metadata, count, revision, and hash.

Production-shaped ingestion uses a source-scoped credential and three phases:

1. `POST /discovery-ingest/{tenantId}/{sourceId}/generations` declares a
   generation, its expected source revision, observation/expiry times and a
   page count from 1 to 20.
2. `PUT /discovery-ingest/{tenantId}/{sourceId}/generations/{generation}/pages/{pageNumber}`
   uploads one immutable page containing 1 to 100 normalized observations. The
   response returns the canonical page hash.
3. `POST /discovery-ingest/{tenantId}/{sourceId}/generations/{generation}/commit`
   supplies the ordered hash of every declared page. The control plane strongly
   reads and validates every page, rejects cross-page duplicate identities, and
   atomically advances both the source revision and generation state.

Until commit succeeds, a generation has no effect on coverage. Missing pages,
hash mismatches, duplicate observations, credential revocation, replay, or a
concurrent source revision all fail closed. A committed generation supports up
to 2,000 observations while retaining bounded Lambda and DynamoDB work.

The deployed API Gateway deliberately exposes this connector-authenticated path
without the operator `/api` prefix. Supplying `/api/discovery-ingest/...` enters
the Cognito-protected operator route and is rejected. The reference publisher
constructs the correct path from the API Gateway origin.

Credential lifecycle is operator-owned:

- `GET /api/enterprise/discovery/sources` lists the union of registered
  credentials and committed snapshots for tenant operators. It returns only
  source identity, credential lifecycle metadata, and redacted snapshot
  freshness metadata; token digests, plaintext credentials, observations, and
  raw provider data are excluded;
- `POST /api/enterprise/discovery/sources/{sourceId}/connector-credential`
  creates or rotates a source credential using `sourceKind` and
  `expectedRevision`;
- `DELETE /api/enterprise/discovery/sources/{sourceId}/connector-credential`
  revokes it immediately.

`GET /api/enterprise/discovery` returns the current reconciliation report.
`GET /api/enterprise/discovery/export` returns the same redacted report with a
canonical `contentHash` for evidence handling.

## Deployment constraints and next acceptance work

The legacy snapshot route remains for small pilots and compatibility. Connector
generations remove its 100-record ceiling and are suitable for a bounded pilot;
very large estates should move immutable pages to dedicated object storage and
retain the same atomic current-generation pointer. The application bearer is a
revocable service credential, not hardware-backed workload identity. Production
acceptance should add secret-manager delivery/rotation, optional cloud workload
identity at the gateway, scheduled connector operation, and proof that at least
95% of the agreed pilot population is represented. The fail-closed freshness,
completeness and commit semantics must not change.

## Operator journey

1. A platform administrator opens **Coverage → Inventory sources**, registers
   a stable source ID and saves the one-time publisher credential in the
   approved secret manager. Registration does not create evidence or authority.
2. A deployment-owned scheduled job uses the appropriate reference collector
   and the source-scoped publisher to commit a complete generation.
3. The operator verifies that credential state is **Active** and independently
   verifies that evidence state is **Current**. Either state can fail without
   being cosmetically upgraded by the other.
4. The operator opens **Coverage posture** and first checks source confidence.
5. If coverage is available, the operator reviews the denominator, unmanaged
   targets, duplicates, leavers, orphans, and business-unit breakdown.
6. The operator connects a missing agent or opens the Agents workspace for
   lifecycle response.
7. The operator exports the content-hashed report as assessment evidence.

Rotation requires the current credential revision and invalidates the previous
secret immediately. Revocation denies all subsequent ingestion while retaining
the last committed snapshot until its declared expiry; the console states this
impact before applying either change. The one-time credential exists only in
the issuance response and transient browser component state. Closing the
credential panel removes it from the rendered UI, and reloading cannot recover
it.

## Reference collector workflow

The repository includes provider-minimising reference collectors and an atomic
publisher. They are separate so an operator can review normalized inventory
before sending it. Provider and connector secrets are environment-only and are
never command arguments or output.

```bash
# Entra identity inventory. The Graph token needs only the deployment-approved
# user read scope; the output retains opaque ID, active state and department.
AZURE_GRAPH_TOKEN='<from-secret-manager>' \
  python scripts/collect_discovery_inventory.py entra > /tmp/entra-inventory.json

# Endpoint inventory uses an exact deployment-owned JSON export schema.
python scripts/collect_discovery_inventory.py endpoint \
  --input /path/to/synthetic-or-managed-endpoint-export.json \
  > /tmp/endpoint-inventory.json

# GitHub requires a reviewed map from repository full name to a SHA-256 project
# root digest and expected Claude/Codex hosts; raw paths are never accepted.
GITHUB_TOKEN='<from-secret-manager>' \
  python scripts/collect_discovery_inventory.py github \
  --organization example-enterprise \
  --mapping /path/to/repository-discovery-map.json \
  > /tmp/github-inventory.json

# Use the API Gateway origin printed by the AWS stack, not the UI URL or /api.
AAI_DISCOVERY_CONNECTOR_TOKEN='<one-time-returned-source-secret>' \
  python scripts/publish_discovery_generation.py \
  --api-url https://example.execute-api.eu-west-2.amazonaws.com \
  --tenant-id tenant-synthetic \
  --source-id github-enterprise \
  --input /tmp/github-inventory.json \
  --generation github-2026-07-29T23-00Z \
  --expected-revision 0
```

Temporary inventory files remain deployment-owned sensitive operational data;
store them in an access-controlled temporary location and remove them under the
deployment retention policy. For scheduled operation, run collection and
publication in one isolated job with a secret-manager injection and no shell
history substitution.

## Security acceptance criteria

- Missing, incomplete, empty-denominator, or expired required sources never
  produce a percentage or orphan conclusion.
- Duplicate installations never inflate the enrolled numerator.
- A non-platform operator cannot publish source authority.
- Revision replay and malformed or over-broad input fail closed.
- Connector credentials are source-scoped, digest-only at rest, returned once,
  revocable, and rejected on every mismatched route.
- The operator source directory never returns credential material, token
  digests, raw observations, or provider payloads, and is denied without a
  tenant operator role.
- Partial generations, missing pages, altered hashes, duplicate cross-page
  identities and concurrent source revisions never change the active source.
- Raw paths and observation contents do not appear in publication audit events.
- UI tests render complete coverage and unavailable coverage as distinct states.
