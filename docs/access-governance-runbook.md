# Emergency access and access certification runbook

This runbook covers the hosted control plane's break-glass workflow and
periodic operator access export. These controls complement normal Microsoft
Entra ID and SCIM lifecycle authority; they do not replace directory
provisioning, conditional access, or customer access-review approval.

## Security boundary

Emergency authority is server-owned and evaluated for every API mutation. It
is never copied into browser state, model output, a policy document, or a
long-lived Cognito group. A request:

- targets only the immutable subject from the requester's signed token;
- contains one or more exact capabilities, never a wildcard or role;
- lasts between 5 and 60 minutes after approval;
- expires if a different administrator does not decide it within 15 minutes;
- requires a server-owned strong-authentication assertion and signed
  authentication time no older than 10 minutes from both requester and
  approver;
- cannot be approved, denied, or revoked by its requester;
- cannot request, approve, deny or revoke another emergency grant using
  emergency authority; those control actions require the operator's normal
  directory-derived capability;
- becomes ineffective immediately after expiry or revocation; and
- emits independently stored request, decision, revocation and export audit
  events without prompts, credentials, token contents, or raw tool data.

Each authority transition and its content-minimised DynamoDB audit ledger item
commit in one conditional transaction. S3 audit replication happens only
after that durable commit; a replication outage cannot produce active
authority without a ledger event or make a committed decision look
uncommitted. Operators must alert on the content-free replication warning and
reconcile the ledger into the retained audit bucket.

The API conditionally changes pending and active records so concurrent,
replayed, stale and self-approved decisions fail closed. Emergency evidence is
retained after authority expires. A control-plane lookup failure grants no
emergency capability.

## Entra prerequisite

Bind the exact Entra enterprise application to a Conditional Access policy
that requires MFA for every operator who can request or approve emergency
access. After live verification, deploy with
`ENTRA_STRONG_AUTH_ENFORCED=true`. The Cognito pre-token trigger then emits a
server-owned `aai:strong_auth_enforced` claim only for the exact configured
Entra provider. No mapped user attribute or browser value can create it.

After deployment, inspect a synthetic pilot token without retaining it and
confirm that Cognito emits fresh `auth_time`, exact Entra provenance and the
server-owned strong-authentication assertion. Missing, stale, malformed or
unproven evidence is denied even when the operator has the normal
incident-response or identity-administration capability. This deployment
assertion is not a substitute for retaining the Entra Conditional Access
configuration and sign-in evidence.

## Request and approval journey

1. Open **Identity & trust** and select **Request emergency access**.
2. Reference the active incident and explain why normal least-privilege access
   cannot restore service.
3. Select only the exact capabilities needed and the shortest useful duration.
4. Reauthenticate with MFA if the current authentication is more than 10
   minutes old, then submit.
5. A different platform administrator independently validates the incident,
   requester, scope and duration before choosing **Approve bounded grant** or
   **Deny**.
6. Confirm the UI reports the grant as active and shows its expiry. Exercise
   one intended recovery action and one capability outside the grant; retain
   the allow and deny request IDs.
7. Select **Revoke now** as soon as recovery is complete. Confirm the next API
   call using the emergency capability is denied without waiting for token
   expiry.

Do not create a shared emergency account, map a permanent directory group to
`platform-admin`, lengthen a grant through direct database changes, or treat an
active incident as permission to bypass the SDK execution boundary.

## Certification export

An auditor or platform administrator can select **Generate and download JSON**
in **Identity & trust**. The tenant-scoped artifact contains:

- every bounded SCIM-provisioned operator, including active state and immutable
  directory object ID;
- current group membership and exact group-to-role mappings;
- the canonical role-to-capability matrix;
- every delegated role, organization/project/deployment scope, expiry and
  revocation state;
- pending, active, expired, denied and revoked break-glass records;
- generation time and a SHA-256 digest of the complete review payload.

The API refuses a partial oversized SCIM inventory. If SCIM is not configured,
the artifact is explicitly marked `complete: false`; it must not be signed off
as quarterly access certification. The export event is audited with its digest
and operator count.

The artifact contains operator names and identifiers and must be handled as
access-governance evidence under the customer's retention and privacy rules.
The digest detects accidental or unrecorded content change; it is not a digital
signature, immutable storage guarantee, or proof that a human completed the
review.

## Delegated operator access

Use **Identity & trust → Delegated operator access** for normal least-privilege
operations, not break glass. The target must be an active SCIM operator when
SCIM is configured. Select one non-admin canonical role, an organization,
project or deployment, an expiry no longer than 366 days, and a reviewable
business rationale. The API rejects self-delegation and never allows
`platform-admin` or identity governance to be delegated.

After creating the grant, remove any broader Entra group membership that would
still assign a tenant-wide role. Verify the operator can manage one in-scope
synthetic resource and receives HTTP 403 for a sibling resource. Revoke the
grant and repeat the in-scope action to prove immediate denial. The complete
procedure and API contract are in
[Delegated administration](delegated-administration.md).

## Acceptance evidence

Before enterprise rollout, retain synthetic evidence that proves:

1. missing MFA and authentication older than 10 minutes are denied;
2. request-body subjects, wildcard capabilities and durations over 60 minutes
   are rejected;
3. the requester cannot decide their own request;
4. a second administrator can approve the exact scope once, while replay and
   concurrent decisions fail;
5. granted authority cannot perform an unrequested capability;
6. expiry and revocation remove authority on the next API request;
7. a cross-tenant subject receives no grant;
8. delegated authority permits one descendant resource, denies a sibling,
   expires automatically and is denied immediately after revocation;
9. the certification export is complete, digest-verifiable and auditor-only;
   and
10. every lifecycle transition has content-minimised durable audit evidence.

Source-level contract tests provide repeatable adversarial evidence. They do
not replace a deployed Entra MFA, API Gateway claim-projection and two-person
pilot exercise.
