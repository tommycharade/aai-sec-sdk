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

The initial AWS pilot permits only a `platform-admin` to publish snapshots via
the `discovery_write` capability. Production connectors should exchange that
operator path for workload identities scoped to one tenant and one source. The
browser never supplies trusted inventory.

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

`GET /api/enterprise/discovery` returns the current reconciliation report.
`GET /api/enterprise/discovery/export` returns the same redacted report with a
canonical `contentHash` for evidence handling.

## Pilot constraints and production path

The serverless pilot stores one bounded snapshot per source in the tenant
control table, with a maximum of 100 observations. This is suitable for contract
validation and a small pilot, not a large enterprise inventory. Production
adapters should upload signed, paginated source generations to dedicated
storage, atomically mark a generation complete, and publish only the normalized
current view to the reconciler. The fail-closed freshness and completeness
semantics must not change.

## Operator journey

1. Deployment-owned connectors collect identity, endpoint, and repository
   inventory and publish complete snapshots.
2. The operator opens **Coverage** and first checks source confidence.
3. If coverage is available, the operator reviews the denominator, unmanaged
   targets, duplicates, leavers, orphans, and business-unit breakdown.
4. The operator connects a missing agent or opens the Agents workspace for
   lifecycle response.
5. The operator exports the content-hashed report as assessment evidence.

## Security acceptance criteria

- Missing, incomplete, empty-denominator, or expired required sources never
  produce a percentage or orphan conclusion.
- Duplicate installations never inflate the enrolled numerator.
- A non-platform operator cannot publish source authority.
- Revision replay and malformed or over-broad input fail closed.
- Raw paths and observation contents do not appear in publication audit events.
- UI tests render complete coverage and unavailable coverage as distinct states.
