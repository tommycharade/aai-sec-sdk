# Policy governance design

This design defines the governed policy lifecycle required by P1-POL-01,
P1-POL-02 and the foundation of P1-POL-04. The provider-neutral reference
control plane and AWS adapter implement this lifecycle; the management UI must
expose the same honest review and promotion contract before hosted rollout.
Editing policy content must never silently replace the authority applied to
enrolled agents.

## Security boundary and threat model

Policy JSON, names, version identifiers, transition requests and browser role
claims are untrusted. An author may try to approve their own change, mutate a
reviewed version, activate against a newer base, bypass staging through a
legacy route, replay a decision, or use a cross-tenant policy identifier.

The control plane therefore:

- derives tenant, subject and role authority from authenticated context;
- stores every proposed version as an immutable ledger entry once submitted;
- permits content changes only while a version is `draft`;
- permits `draft -> review` only to the draft author or another policy writer;
- permits approval or rejection only through `policy_approval` authority;
- rejects self-approval even when the author also holds an approval-capable
  role; a second authenticated subject must approve;
- requires a non-empty decision rationale and records author, submitter,
  approver, stager and activator identities and timestamps;
- requires `review -> approved -> staged -> active` in order;
- compares the version's `baseVersion` with the current active version at
  staging and activation, so concurrent policy changes fail closed;
- updates the active policy snapshot and retires the prior active ledger entry
  in one transaction or conditional write; and
- keeps group and runtime policy resolution bound only to the active snapshot.

An active version is immutable. Rejected, superseded and retired versions
remain content-minimised audit evidence and cannot be reactivated. A new draft
is created from the then-current active version.

## Data model

The existing policy record remains the active lookup used by groups and agent
policy resolution. It contains `version: 0` and an empty configuration until a
new policy has completed governance. Existing policies are migrated as active
ledger entries without interrupting fleet coverage.

Each policy version records:

- policy and tenant identity;
- monotonic version and active `baseVersion`;
- validated name and configuration plus a deterministic content hash;
- lifecycle state;
- author and creation time;
- submission, decision, staging and activation identities/times; and
- a bounded approval or rejection rationale.

The operator list returns active metadata plus the latest governance state. A
separate version endpoint returns review content. Groups cannot select a policy
that has no active version.

## API and role contract

```text
POST /api/enterprise/policies
POST /api/enterprise/policies/{policyId}/versions
GET  /api/enterprise/policies/{policyId}/versions
GET  /api/enterprise/policies/{policyId}/versions/{version}
POST /api/enterprise/policies/{policyId}/versions/{version}/submit
POST /api/enterprise/policies/{policyId}/versions/{version}/decision
POST /api/enterprise/policies/{policyId}/versions/{version}/stage
POST /api/enterprise/policies/{policyId}/versions/{version}/activate
```

Policy writers create and submit drafts. Policy approvers decide, stage and
activate versions. Platform administrators retain wildcard authority but still
cannot self-approve. Activation includes `expectedActiveVersion` and fails
with conflict if another version became active.

The decision body contains `decision: approved|rejected` and `reason`. Stage
and activation do not accept policy content. Legacy version creation now
creates a draft; no policy-write route directly mutates active authority.

## Operator journey

1. An author edits a typed policy form and saves a draft.
2. The review screen shows active-versus-draft semantic changes, affected
   groups and agents, and the immutable content hash.
3. The author submits the version. The editor becomes read-only.
4. Another authenticated subject approves or rejects it with a rationale.
5. An approver stages the approved version after confirming the active base.
6. Activation atomically changes fleet authority; agent convergence remains a
   separate rollout and enforcement measurement.

The UI must not imply that approval, staging or activation proves endpoint
convergence. It must show the active version separately from a pending version.

## Acceptance evidence

Contracts must prove migration of existing active policies, no-active new
policies, immutable submitted/active content, self-approval denial, exact role
checks, cross-tenant denial, replay and out-of-order transition denial,
stale-base conflicts, atomic activation, group rejection for inactive policy,
active policy resolution during review, complete audit attribution and honest
UI state. The AWS adapter uses conditional writes for lifecycle steps and one
DynamoDB transaction for activation, so a concurrent activation cannot
partially update the candidate, retired predecessor, or active policy snapshot.

Historical simulation, signed policy bundles, scheduling, inheritance,
time-limited exceptions and measured endpoint convergence remain separate P1
requirements and are not claimed by this lifecycle foundation.
