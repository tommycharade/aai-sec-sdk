# Delegated administration

Delegated administration lets a central identity team give an operator one
canonical job inside one organization, project or deployment without adding
that operator to a tenant-wide Cognito role group. It is the resource-scoped
authorization layer required for large enterprises where one platform team
must not automatically control every business unit.

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
loads the organization/project/deployment from tenant-owned records, and
commits the grant with immutable audit evidence. Browser claims, model output
and request JSON cannot assert that a grant exists or choose another tenant.

Each protected mutation resolves the grant again with a consistent DynamoDB
read. Expiry and revocation therefore take effect without waiting for token
renewal. A lookup failure, malformed lineage, missing parent, stale grant or
unknown route grants no delegated authority.

## Supported roles and scopes

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

An organization grant contains its projects and deployments. A project grant
contains its deployments. A deployment grant is exact. Batch operations are
authorized only when every selected deployment is covered by one or more live
grants that provide the required role capability.

Tenant-wide evidence, identity governance and routes whose target cannot be
resolved are intentionally unavailable to delegated-only operators. Existing
canonical Cognito role groups remain tenant-wide; moving an operator from a
tenant-wide role into delegated administration requires removing that group
membership as an independent directory change.

## Operator journey

1. Provision the operator through Entra SCIM and confirm that the account is
   active.
2. Open **Identity & trust** and select **Delegate access**.
3. Select the operator, canonical role, scope type, exact resource and expiry.
4. Enter a business rationale of at least 20 characters.
5. Review the resulting active grant in the delegated-access ledger.
6. Remove any tenant-wide Entra group mapping that would otherwise provide
   broader authority.
7. Revoke the grant from the same ledger when the job ends. Expiry provides a
   second mandatory end condition.

The UI displays names for usability, but submits immutable Entra object IDs
and server-owned resource IDs. It does not expose SCIM credentials or allow a
manually typed role capability.

## API contract

Identity administrators use:

- `GET /enterprise/identity/delegated-grants` to review the complete bounded
  tenant ledger;
- `POST /enterprise/identity/delegated-grants` to create an expiring grant;
- `POST /enterprise/identity/delegated-grants/{grantId}/revoke` to revoke a
  live grant conditionally.

Creation accepts `principalId`, one non-admin canonical `role`, `scopeType`,
`scopeId`, `durationDays` from 1 through 366, and `reason`. The server creates
the grant ID, timestamps, revision and audit digest. Self-delegation is denied.
Create and revoke state transitions use one DynamoDB transaction for the
authority record and immutable identity-governance audit item; secondary S3
replication remains best effort after that durable commit.

`GET /enterprise/identity` returns the current operator's visible grants and,
for a tenant identity administrator, the active SCIM operator selector and
resource scope catalog. The access-certification artifact schema version 2
includes every delegated grant and its active, expired or revoked state.

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
- delegated-only inventory reads omit out-of-scope records;
- group membership and policy assignment reject missing records, missing
  ownership and every cross-organization authority edge;
- Entra token issuance accepts an active SCIM operator with a live delegated
  grant without copying that role into tenant-wide Cognito groups.

Live Entra joiner/mover/leaver and multi-business-unit acceptance still
requires the customer tenant configuration described in the
[Entra SCIM runbook](entra-scim-runbook.md). Software scope enforcement is not
a substitute for independent directory governance or endpoint attestation.
