# Persistent Microsoft Entra deployment guard

## Decision

Microsoft Entra identity configuration is deployment-owned, but it must not be
ephemeral. The supported AWS deployment workflow stores a strict, secret-free
manifest in an encrypted AWS Systems Manager Parameter Store parameter and
reloads it for every deployment. OIDC and SCIM secret values remain in AWS
Secrets Manager and are never copied into the manifest, repository, browser,
Lambda environment or command output.

The parameter name is stack-specific:

```text
/aai-sec/<stack-name>/entra-deployment
```

This closes an operational authority gap in the original environment-variable
workflow: a routine CDK deployment from a clean shell could otherwise omit the
six Entra variables and remove federation from the Cognito client.

## Typed manifest

Use `infra/aws-control-plane/entra-deployment.example.json` as the schema-v1
template. The parser rejects unknown, missing and duplicate fields; noncanonical
UUIDs; reused OIDC/SCIM secrets; invalid AWS secret names; an absent AAI tenant;
and a deployment that does not explicitly assert reviewed Conditional Access.

`conditionalAccessEvidenceRef` is an opaque change, ticket or evidence
identifier. It must not contain a password, token or exported sign-in record.
The confirmation records deployment intent; it does not independently inspect
the customer's Conditional Access policy or prove that MFA occurred.

## Workflow

1. Deploy the base stack and provision the AAI tenant that will own the
   enterprise directory.
2. Create separate OIDC and SCIM secret values in AWS Secrets Manager.
3. Copy the example manifest outside the repository and populate only IDs,
   secret resource names and the Conditional Access evidence reference.
4. Run a read-only preflight:

   ```bash
   python3 scripts/deploy_aws_control_plane.py check \
     --config /secure/path/entra-deployment.json \
     --profile p1 --region eu-west-2
   ```

5. After reviewing the MFA-enforcing policy evidence, persist the manifest:

   ```bash
   python3 scripts/deploy_aws_control_plane.py configure \
     --config /secure/path/entra-deployment.json \
     --confirm-conditional-access \
     --profile p1 --region eu-west-2
   ```

6. Deploy from `infra/aws-control-plane` with `npm run deploy`. The command
   reloads the manifest, repeats preflight, injects only secret names into CDK,
   and verifies that CloudFormation reports OIDC and SCIM configured.
7. Run the live SCIM acceptance command and the real OIDC joiner, mover, leaver
   and two-person MFA exercises in the Entra runbook.

`status` reports only configuration posture:

```bash
python3 scripts/deploy_aws_control_plane.py status \
  --profile p1 --region eu-west-2
```

## Security invariants

- A configured stack without its persisted manifest cannot use the supported
  deployment command. Missing deployment state fails closed instead of
  silently removing enterprise SSO.
- The preflight requires an exact tenant-specific Microsoft issuer and fixed
  authorization, token and signing-key endpoints. `common`, `organizations`,
  redirects and foreign hosts are rejected.
- OIDC and SCIM secret values are read only into bounded process memory for
  shape validation. They are never sent to CDK or rendered in output.
- The manifest binds one Entra directory to one existing server-owned AAI
  tenant. Browser state cannot select the tenant.
- Persistence requires an explicit Conditional Access confirmation. The
  deployment flag is still an administrator assertion and must be backed by
  retained customer evidence and live MFA acceptance.
- Direct use of `npx cdk deploy` is an unsupported administrative bypass. CI,
  runbooks and operators must use `npm run deploy`; AWS IAM and change control
  remain responsible for restricting who may update the stack directly.

## Failure and recovery

Malformed persisted state, inaccessible secrets, a missing AAI tenant,
unexpected OIDC metadata and incomplete post-deployment outputs all stop the
workflow. No command automatically creates or rotates secret values.

If the SSM parameter is lost while Entra remains configured, recover it from
approved change evidence and run `check` before `configure`. Do not disable the
guard or redeploy with empty Entra variables. Parameter and stack updates are
visible in AWS CloudTrail; the product's access-certification export remains a
separate application-level record.

## Test evidence

`tests/test_deploy_aws_control_plane.py` covers strict parsing, duplicate fields,
MFA confirmation, separate secret references, bounded secret shapes, exact
tenant-specific discovery, existing AAI tenant binding, missing-manifest
denial, deployment environment contents and post-deployment verification.
Synthetic values are used throughout.
