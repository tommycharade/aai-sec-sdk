# Delegated administration

Delegated administration lets a central identity team give an operator one
canonical or custom job inside one tenant, business unit, project, environment
or deployment without adding that operator to a tenant-wide Cognito role
group. It is the resource-scoped authorization layer required for large
enterprises where one platform team must not automatically control every
business unit.

## Security boundary

Authentication, tenant entitlement, directory lifecycle, tenant-wide roles
and delegated authority remain separate facts:

```text
Entra OIDC identity -> active SCIM operator -> tenant binding
                   -> tenant-wide mapped roles OR live delegated grants
                   -> capability + exact resource lineage -> API operation
```

The browser submits a selected operator, role and resource only as a proposal.
The API resolves the authenticated administrator from signed token claims,
loads the target operator from active SCIM state when SCIM is configured,
loads the tenant/business-unit/project/environment/deployment boundary from
tenant-owned records, and
commits the grant with immutable audit evidence. Browser claims, model output
and request JSON cannot assert that a grant exists or choose another tenant.

Each protected mutation resolves the grant again with a consistent DynamoDB
read. Expiry and revocation therefore take effect without waiting for token
renewal. A lookup failure, malformed lineage, missing parent, stale grant or
unknown route grants no delegated authority.

## Canonical roles

`platform-admin` is deliberately not delegatable. A scoped operator cannot
manage SCIM mappings, create or approve break-glass access, create another
delegation, or obtain tenant-wide runtime administration.

| Role | Delegated capability | Typical scope |
| --- | --- | --- |
| `fleet-operator` | Fleet lifecycle | Organization, project or deployment |
| `policy-author` | Policy, Skill and MCP authoring | Organization |
| `policy-approver` | Independent policy and action review | Organization |
| `security-operator` | Action decisions and security response | Organization, project or deployment where the target can be resolved |
| `incident-responder` | Containment and response | Organization, project or deployment |
| `auditor` | Scope-filtered evidence reads | Organization, project or deployment |

## Custom roles

An identity administrator can compose an immutable custom role only from this
code-owned safe capability vocabulary:

| Capability | Permitted authority |
| --- | --- |
| `approval_decision` | Decide exact pending agent actions in scope |
| `evidence_read` | Read redacted evidence in scope |
| `fleet_write` | Operate scoped fleet resources |
| `incident_response` | Contain scoped agents and manage scoped incidents |
| `inventory_read` | Read scoped inventory |
| `policy_approval` | Approve scoped policy versions |
| `policy_simulation` | Run non-mutating scoped policy simulation |
| `policy_write` | Author scoped policy, Skill and MCP resources |

Wildcard, platform, identity, integration, runtime, discovery, endpoint
provider and machine-credential administration are not in this vocabulary.
The API rejects unsupported or duplicate capabilities; UI or request JSON
cannot add one.

Custom roles have a four-state lifecycle: `draft`, `active`, `rejected` and
`retired`. Creation produces revision 1 and no authority. A different identity
administrator must approve or reject the exact draft, producing revision 2.
Capabilities cannot be edited: changing authority requires a new role ID and a
new review. A grant stores the exact active revision and authority digest, but
the API reloads the live role on every decision. Retirement produces revision
3 and immediately invalidates every existing grant bound to revision 2.

Custom roles are not Entra or Cognito groups. A forged custom-role group claim
provides no authority. Entra/SCIM establishes the principal and canonical
tenant-wide groups; the control plane's live custom-role and grant records
establish scoped authority.

## Scope semantics

| UI label | API scope type | Coverage |
| --- | --- | --- |
| Tenant | `tenant` | Exact AAI tenant and all resolvable descendants |
| Business unit | `organization` | Exact organization and its projects/deployments |
| Project | `project` | Exact project and its deployments |
| Environment | `environment` | Deployments whose server-owned environment exactly matches |
| Deployment | `deployment` | One exact deployment |

Every resolved lineage includes the tenant. Environment matching is exact and
tenant-local; it is not a caller-provided tag expression. Batch operations are
authorized only when every selected target is covered by one or more live
grants that provide the required capability.

Tenant-wide evidence, identity governance and routes whose target cannot be
resolved are intentionally unavailable to delegated-only operators. Existing
canonical Cognito role groups remain tenant-wide; moving an operator from a
tenant-wide role into delegated administration requires removing that group
membership as an independent directory change.

## Operator journey

1. Provision the operator through Entra SCIM and confirm that the account is
   active.
2. Open **Identity & trust** and select **Delegate access**.
3. Select a canonical role or an independently approved custom role.
4. Select the tenant, business unit, project, environment or deployment scope,
   exact resource and expiry.
5. Enter a business rationale of at least 20 characters.
6. Review the effective role capabilities, scope and resulting active grant.
7. Remove any tenant-wide Entra group mapping that would otherwise provide
   broader authority.
8. Revoke the grant from the same ledger when the job ends. Expiry provides a
   second mandatory end condition.

The UI displays names for usability, but submits immutable Entra object IDs
and server-owned resource IDs. It does not expose SCIM credentials or allow a
manually typed role capability.

## API contract

Identity administrators use:

- `GET /enterprise/identity/custom-roles` to review the tenant catalog;
- `POST /enterprise/identity/custom-roles` to create an immutable draft;
- `POST /enterprise/identity/custom-roles/{roleId}/decision` to independently
  approve or reject revision 1;
- `POST /enterprise/identity/custom-roles/{roleId}/retire` to invalidate an
  active role and every bound grant;
- `GET /enterprise/identity/delegated-grants` to review the complete bounded
  tenant ledger;
- `POST /enterprise/identity/delegated-grants` to create an expiring grant;
- `POST /enterprise/identity/delegated-grants/{grantId}/revoke` to revoke a
  live grant conditionally.

Grant creation accepts `principalId`, `roleType` (`canonical` or `custom`), one
bounded `role`, `scopeType`, `scopeId`, `durationDays` from 1 through 366, and
`reason`. Omitting `roleType` preserves the schema-v1 canonical behavior. A
custom grant binds `roleRevision`, `roleDigest` and a presentation-only role
name snapshot. The server creates the grant ID, timestamps, revision and audit
digest. Self-delegation is denied.
Create and revoke state transitions use one DynamoDB transaction for the
authority record and immutable identity-governance audit item; secondary S3
replication remains best effort after that durable commit.

`GET /enterprise/identity` returns the current operator's visible grants and,
for a tenant identity administrator, the active SCIM operator selector and
resource scope catalog. The access-certification artifact schema version 3
includes every custom role and delegated grant with revision/digest and active,
expired or revoked state.

### Schema migration

Access-certification consumers that require schema version 2 must be upgraded
before this control-plane version is deployed. Version 3 adds `customRoles`
and adds `roleType`, `roleLabel`, `roleRevision` and `roleDigest` to delegated
grant projections. Canonical grants remain present with `roleType: canonical`
and null revision/digest. The control plane no longer emits schema version 2;
silently dropping the new fields would make a review incomplete.

## Acceptance evidence

Contract and adversarial tests prove:

- an organization-scoped fleet operator can create a deployment only under
  that organization;
- a sibling organization and another tenant are denied;
- project and deployment descendants are resolved from server records;
- a forged `aai:delegated` claim provides no authority;
- expired and revoked grants stop authorizing immediately;
- delegated authority cannot manage delegated or break-glass authority;
- self-delegation and `platform-admin` delegation are rejected;
- a custom-role author cannot decide their own draft;
- concurrent or stale custom-role decisions commit neither authority nor false
  decision audit evidence;
- draft and rejected roles cannot be granted;
- wildcard and platform-only capabilities cannot enter a custom role;
- custom grants bind the exact approved revision and authority digest;
- a tenant scope cannot name another tenant and an environment scope matches
  only exact server-owned deployment environments;
- altered role capabilities, digest, revision or grant binding deny authority;
- retirement invalidates an existing grant on the next request;
- a forged Cognito custom-role group grants nothing;
- delegated-only inventory reads omit out-of-scope records;
- group membership and policy assignment reject missing records, missing
  ownership and every cross-organization authority edge;
- Entra token issuance accepts an active SCIM operator with a live delegated
  grant without copying that role into tenant-wide Cognito groups.

Live Entra joiner/mover/leaver and multi-business-unit acceptance still
requires the customer tenant configuration described in the
[Entra SCIM runbook](entra-scim-runbook.md). Software scope enforcement is not
a substitute for independent directory governance or endpoint attestation.
