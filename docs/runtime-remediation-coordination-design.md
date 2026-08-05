# Runtime remediation coordination

## Purpose

A runtime rollout answers **which approved release an endpoint is allowed and
expected to run**. It does not answer whether an external endpoint-management
channel accepted work, whether an installer reported success, or whether the
runtime subsequently proved the exact release.

This design adds a least-privilege coordination contract for P1-FLT-06 and
P1-FLT-07. A customer-hosted Intune, Jamf or equivalent adapter can read exact
server-selected work, lease it and report one bounded outcome. The contract
does not dispatch provider work, distribute executable files or elevate the
Claude Code/Codex process. Fresh exact runtime attestation remains the only
verification signal.

## Three independent truths

| Truth | Authority | What it proves |
| --- | --- | --- |
| Release authorized | Runtime-rollout record | The exact current/target release pair and deterministic cohort are approved. |
| Channel observed | Remediation task | A scoped external worker leased the instruction and reported `installed` or a fixed failure code. |
| Runtime verified | Challenge-bound runtime attestation | The endpoint currently measures the expected SDK version, revision and complete artifact manifest. |

An `installed` report is deliberately displayed as **Awaiting attestation**.
It cannot complete a rollout, satisfy version compliance or grant execution.

## Trust boundaries

- The browser can read remediation posture but cannot claim or report work.
- An ordinary agent session, MCP server, hook, model or model-callable tool has
  no remediation route.
- A machine credential requires the separate `runtime_remediation` capability.
  Its exact versioned allow-list contains only claim/report routes. Internally
  this maps to `endpoint_remediation_observe`, not broad fleet or rollout
  authority.
- The worker receives no URL, path, command, script, provider package ID,
  executable bytes or credential. It receives immutable release identities and
  SHA-256 digests only.
- Provider credentials and root/administrator installation remain outside this
  contract. A hosted provider adapter must use a dedicated IAM role and
  tenant-tagged Secrets Manager authority; it must not reuse this bearer as a
  privileged installation credential.
- A report is an untrusted operational observation. Runtime attestation is
  independently challenge-bound and server-evaluated.

## Instruction contract

The control plane derives an instruction only for an active agent selected by
an open `canary`, `active`, `paused` or `rolling_back` transition. The canonical
instruction binds:

- deployment and agent identity;
- host, rollout state and exact rollout revision;
- release ID, tag, SDK version and source revision;
- complete manifest and release-evidence digests; and
- SDK package, MCP gateway and native-hook digests.

`instructionId` is SHA-256 over that complete canonical document. A pause,
resume, expansion or rollback changes the rollout revision and therefore
invalidates an earlier instruction before claim or report. The live server
selection is re-evaluated on every mutation. Both the Python SDK and browser
client independently recompute the canonical digest, and mutation responses
must preserve every immutable instruction field.

## Independent task and verification state

The wire contract does not compress provider observation and runtime proof into
one fact. Every item and every full-queue aggregate carries both:

- `channelStatus`: `not_started`, `in_progress`, `installed_reported` or
  `failed`; and
- `runtimeVerification`: `not_verified`, `verified` or `blocked`.

`channelStatusCounts` and `runtimeVerificationCounts` must each sum to the
complete deployment queue. A verified runtime may still retain an
`installed_reported` or `failed` channel observation; that history does not
create or invalidate proof. `verified` additionally requires an attestation
observation no later than the page measurement and an evidence expiry later
than it. Clients reject contradictory or expired verification.

The combined workflow status remains a convenience for claim/retry filtering:

```text
pending
  -> in_progress             exact 15-minute lease
  -> awaiting_attestation    worker reported installed
  -> verified                fresh exact attestation only

pending/in_progress
  -> failed                  fixed content-free reason
  -> pending                 bounded retry after lease expiry or operator repair

any open state
  -> blocked                 quarantine or changed authority
```

The persisted task uses optimistic revisions, at most five attempts and exact
request IDs for idempotent claim/report retries. A second worker cannot steal a
live lease. Claims and reports commit atomically with transactional conditions
on the exact rollout revision/state/release binding and current active,
non-quarantined agent state. A concurrent pause, rollback, lifecycle change or
quarantine cancels the complete task/audit transaction. The content-minimised
audit hashes agent identity and canonical resulting-task semantics and contains
no raw provider response, path, command, prompt, credential or executable
content. Channel success is named `install_reported`, never `installed`.

Allowed failure codes are:

- `channel_timeout`;
- `digest_mismatch`;
- `host_unsupported`;
- `installation_failed`;
- `package_unavailable`;
- `preflight_failed`;
- `privilege_unavailable`; and
- `restart_failed`.

Raw exceptions and provider payloads are rejected.

Continuation pages are bound to one deployment cursor. The operator UI also
requires rollout revision, rollout state, full-queue totals and both independent
count sets to remain unchanged before appending a page, and rejects duplicate
agent or instruction identities. If authority changes, the operator restarts
from the first page rather than viewing a mixed snapshot.

## API and SDK

Human inventory reads require `inventory_read`:

```text
GET /api/enterprise/runtime-remediations?deploymentId=...&limit=...&nextToken=...
```

Machine mutations require both a live scoped service identity and the exact
`runtime_remediation` capability:

```text
POST /machine/v1/enterprise/runtime-remediations/{deploymentId}/{agentId}/claim
POST /machine/v1/enterprise/runtime-remediations/{deploymentId}/{agentId}/report
```

Every mutation binds `instructionId`, `expectedTaskRevision` and `requestId`.
Reports additionally contain only `installed` or `failed` plus an allowed fixed
reason code.

`RuntimeRemediationClient` provides typed list, claim, installed-report and
failed-report methods. It has no install, download or command API. Use a bearer
with only `inventory_read` and `runtime_remediation`, store it in an approved
secret manager, rotate it and restrict its network path to the control plane.
GET and POST redirects are disabled so that bearer cannot cross origins.

## Provider adapter gate

This coordination foundation must not be described as hosted Intune or Jamf
delivery. Before the control plane itself dispatches privileged provider work,
a separate reviewed design must add:

1. an immutable, signed, platform/architecture-specific delivery-package
   registry with exact S3 object version and provider package identity;
2. a fleet-wide bijective managed-device, installation and agent binding tied
   to current complete MDM evidence;
3. dedicated IAM-authenticated adapter workers and tenant-tagged provider
   secrets that are never returned to a browser;
4. a transactional outbox and provider idempotency/unknown-outcome handling;
5. pre-install online reauthorization so rollback invalidates already delivered
   target intent; and
6. job-bound post-dispatch attestation evidence if causal installation proof is
   required in addition to current-state compliance.

Until those controls exist, an enterprise operator uses this queue to
coordinate its own authenticated MDM workflow. Physical MDM delivery and live
Claude Code/Codex upgrade/rollback acceptance remain open.

## Verification

Automated contracts prove:

- policy-only roles, human operators, ordinary agent tokens and `runtime_write`
  machine credentials cannot claim or report remediation work;
- only the exact `runtime_remediation` machine route is admitted;
- browser-supplied members, URLs, commands, paths and executable content never
  enter an instruction;
- deployment-bound pagination cannot be replayed across deployment scope;
- active leases cannot be stolen and retries are idempotent;
- changed rollout authority invalidates stale reports;
- malformed task state and raw failure reasons fail closed;
- task and primary audit evidence commit together; and
- `installed` never becomes `verified` until exact fresh attestation exists.

Live P1-FLT-06/07 acceptance still requires a representative Claude Code and
Codex population upgraded and rolled back through the chosen enterprise MDM
channel.
