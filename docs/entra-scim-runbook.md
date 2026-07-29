# Microsoft Entra SCIM lifecycle runbook

This runbook connects Microsoft Entra automatic provisioning to the hosted
control plane. It covers operator joiner, mover and leaver actions. It does not
provision Claude Code or Codex agents; agent enrollment remains a separate
fleet workflow.

## Security boundary

- The SCIM endpoint is public at the network layer because Microsoft Entra must
  call it. Every request requires a tenant-specific bearer resolved from AWS
  Secrets Manager and compared in constant time.
- The request cannot choose an AAI tenant. One deployed endpoint is bound to
  the configured `ENTRA_AAI_TENANT_ID`.
- Entra `externalId` and the signed OIDC `oid` claim must contain the same
  directory object UUID. Email addresses and display names are never identity
  keys.
- SCIM users and groups grant no authority by themselves. A platform
  administrator must map an exact provisioned group to one canonical role in
  **Identity & trust**. An unmapped or inactive group grants no access.
- Cognito access and ID tokens live for five minutes. Every refresh reruns the
  pre-token lifecycle lookup. A deactivated, unprovisioned or roleless Entra
  identity cannot obtain another token.
- The OIDC client secret and SCIM bearer are distinct secrets. Neither is
  returned by the API, embedded in the UI, or accepted from browser state.

## Deployment

Create a random SCIM bearer of at least 32 characters and store it as either a
raw Secrets Manager `SecretString` or JSON with one `token` field. Restrict
read access to the generated SCIM Lambda role.

Deploy all OIDC variables plus the SCIM secret name:

```bash
ENTRA_TENANT_ID=<entra-directory-uuid> \
ENTRA_CLIENT_ID=<entra-application-client-id> \
ENTRA_CLIENT_SECRET_NAME=<oidc-secret-name> \
ENTRA_AAI_TENANT_ID=<provisioned-aai-tenant-id> \
ENTRA_SCIM_TOKEN_SECRET_NAME=<scim-bearer-secret-name> \
ENTRA_STRONG_AUTH_ENFORCED=true \
AWS_PROFILE=p1 AWS_REGION=eu-west-2 npm run deploy
```

Record the `MicrosoftEntraScimEndpoint` stack output. The stack rejects a SCIM
secret configured without the complete Entra OIDC binding.

## Entra enterprise application setup

1. Use a single-tenant enterprise application and the Cognito callback ending
   in `/oauth2/idpresponse` for sign-in.
2. Include the Entra object ID as the OIDC `oid` claim. Cognito maps it to the
   non-writable browser attribute `custom:entra_object_id`.
3. Bind the enterprise application to a Conditional Access policy requiring
   MFA for emergency-access requesters and approvers. After live verification,
   deploy with `ENTRA_STRONG_AUTH_ENFORCED=true`; the pre-token trigger emits
   the server-owned assertion without using a mutable user attribute.
4. Open **Provisioning**, select automatic provisioning and enter the SCIM
   endpoint as the tenant URL.
5. Enter the dedicated SCIM bearer. Do not reuse the OIDC client secret.
6. Scope provisioning to assigned users and groups. Ensure the user object ID
   is sent as `externalId`, `userName` is populated, and group object IDs are
   sent as `externalId`.
7. Test the connection, run on-demand provisioning for a synthetic pilot user
   and group, then start the provisioning job.
8. Open **Identity & trust**. Confirm the user/group counts and sync age, then
   map the pilot group to the least-privilege canonical role.

Microsoft Entra supports creating, updating and deactivating users and groups,
and adding or removing group membership through SCIM. The adapter deliberately
rejects unsupported filters, unknown users, malformed UUIDs, more than 20
operations per request and inventories beyond its bounded response limit.

## Acceptance procedure

Use synthetic identities and retain redaction-safe timestamps and result IDs.

Before testing with a real Entra pilot identity, run the deployment acceptance
command. It discovers the endpoint from CloudFormation, reads the dedicated
bearer directly from Secrets Manager, rejects an invalid bearer, and exercises
synthetic joiner, mover and leaver behavior. The bearer is never accepted as a
command argument or written to output:

```bash
ENTRA_SCIM_TOKEN_SECRET_NAME=<scim-bearer-secret-name> \
ENTRA_AAI_TENANT_ID=<provisioned-aai-tenant-id> \
PYTHONPATH=src python scripts/test_aws_entra_scim.py \
  --stack-name AaiSecControlPlane \
  --profile p1 \
  --region eu-west-2
```

Exit status `0` proves the live SCIM endpoint behavior. Exit status `2` means
the stack or required operator inputs are not configured and must never be
recorded as an acceptance pass. Exit status `1` means configured behavior
failed. Exact synthetic user, group and membership records are removed on exit;
content-minimised lifecycle audit records are intentionally retained.

### Joiner

1. Assign a new pilot operator and mapped group to the Entra application.
2. Run on-demand provisioning and confirm the UI active-user count changes.
3. Sign in as the operator.
4. Verify the token receives only the mapped canonical role.
5. Call one permitted API and one API belonging to another role; retain the
   success and HTTP 403 evidence.

### Mover

1. Move the operator from the original Entra group to a different mapped
   group.
2. Confirm SCIM removes and adds the exact memberships.
3. Wait for the current token to expire or sign out and back in.
4. Prove the old capability is denied and the new capability is permitted.

### Leaver

1. Disable or unassign the operator in Entra and run provisioning.
2. Confirm the UI disabled-user count changes.
3. Attempt token refresh and a new login; both must fail.
4. Verify any already-issued operator token stops working within five minutes.
5. Retain the lifecycle audit record and the denied authentication evidence.

## Operations and incident response

- **Provisioning failure:** do not create a local Cognito group workaround.
  Keep the user unprivileged, inspect Entra provisioning logs and the SCIM
  Lambda error alarm, then retry the idempotent operation.
- **Inventory degraded:** the UI refuses to display a partial inventory after
  the bounded limit. Reduce assignment scope or use a future paginated
  administration API; do not assign roles from partial data.
- **Suspected SCIM bearer exposure:** rotate the Secrets Manager value, wait up
  to five minutes for the Lambda cache to expire, update Entra and verify the
  old bearer receives HTTP 401. If immediate invalidation is required, publish
  a new Lambda version or force cold starts while updating Entra.
- **Incorrect group mapping:** unmap the group in **Identity & trust**. New
  tokens receive no role from it; current tokens expire within five minutes.
- **Emergency access:** use the separate, time-bound, recent-MFA break-glass
  workflow in **Identity & trust**. SCIM remains normal lifecycle authority;
  emergency grants are exact server-owned capabilities and never directory
  group workarounds. Follow the
  [access-governance runbook](access-governance-runbook.md).

## Current limitations

This implementation advances P0-06 but does not complete it. The automated
command proves the deployed SCIM protocol once configured; real Entra OIDC
sign-in and joiner/mover/leaver acceptance, configurable provisioning SLO
alarms, immediate global token
revocation and delegated administrative scopes remain outstanding. The
break-glass and access-certification contracts are implemented but still need
the deployed two-person Entra MFA acceptance exercise. Splunk remains a
non-delivering stub.
