# AWS hosted control plane

This repository contains a deployable serverless proof of the enterprise
control-plane path in `infra/aws-control-plane`. It is designed for the
current hosted UI workflow: authenticate an operator with Cognito, inspect an
enrolled agent, create policies and groups, assign an agent, resolve its
effective policy, verify its enrollment, and activate an emergency stop.

## Deployed environment

The current development deployment uses AWS account `396510133537`, profile
`p1`, and region `eu-west-2`.

| Resource | Current value |
| --- | --- |
| Hosted UI | `https://d2ir54klde64bd.cloudfront.net` |
| API | `https://lwg33pxwk8.execute-api.eu-west-2.amazonaws.com` |
| Cognito domain | `https://aai-sec-10133537.auth.eu-west-2.amazoncognito.com` |
| Stack | `AaiSecControlPlane` |

Do not commit generated environment files or credentials. The current
bootstrap operator is disposable and must be replaced before sharing this
deployment.

## Deploy

```bash
cd infra/aws-control-plane
npm install
AWS_PROFILE=p1 AWS_REGION=eu-west-2 npm run deploy
```

`npm run deploy` is the supported deployment boundary. It loads persistent
identity configuration through `scripts/deploy_aws_control_plane.py`; do not
replace it with a direct `npx cdk deploy` command.

The Cognito managed-login domain retains the original deployed CloudFormation
logical ID even though its construct now uses a token-safe low-level resource.
Changing or removing that override would make CloudFormation attempt to create
the same globally unique domain as a second resource. Treat the synthesized
logical-ID contract as a deployment compatibility guard.

The stack creates:

- Cognito User Pool Managed Login with authorization-code OAuth;
- Cognito self-signup with email confirmation and a post-confirmation trigger
  that provisions an isolated 14-day trial tenant with a safe default policy;
- seven canonical Cognito groups for capability-based operator RBAC;
- optional Microsoft Entra ID tenant-specific OIDC federation, with its client
  secret resolved from AWS Secrets Manager at deployment time;
- optional tenant-bound Microsoft Entra SCIM provisioning, with a separate
  bearer resolved only by the SCIM Lambda from AWS Secrets Manager;
- API Gateway HTTP API with Cognito JWT authorizer;
- Lambda control-plane handler;
- optional isolated GitHub policy-source verifier Lambda with no DynamoDB or
  signing authority;
- an AWS-managed Entra, Intune and GitHub discovery collector, EventBridge Scheduler invocation
  role, KMS key, connector dead-letter queue and collector alarms;
- on-demand DynamoDB control and presence tables; the control table expires
  short-lived records by `ttl` and has a decision-timeline index for bounded
  reverse-chronological dashboard reads;
- a retained, point-in-time-recoverable DynamoDB idempotency table with TTL;
- an S3 Object Lock audit bucket;
- a due-time assurance-schedule index, sixteen bounded EventBridge dispatcher
  shards, a dedicated signed-report worker queue and DLQ, and a reserved-
  concurrency report worker;
- a retained private, encrypted and versioned integrity-baseline bucket whose
  exact object versions are digest-bound to committed source-control generations;
- a separate retained private, encrypted and versioned discovery-page bucket;
  page keys are tenant-derived and exact object versions and SHA-256 digests are
  bound into DynamoDB before a generation can become current;
- an SNS security-alert topic wired to Lambda and idempotency CloudWatch
  alarms (subscribe the enterprise SOC endpoint before production);
- a private S3 UI bucket behind CloudFront.

## Enterprise data boundary

Routine deployments create a retained rotating service-managed data key for
retained control-plane stores. To bind a customer-managed key, approved
retained-data Regions and operator access, copy
`infra/aws-control-plane/data-boundary-private.example.json` for PrivateLink or
`infra/aws-control-plane/data-boundary.example.json` for legacy IP restriction
to a protected path and
replace every synthetic value. The KMS key must be enabled, symmetric,
customer-owned, same-account and same-Region, with automatic rotation enabled.

```bash
python3 scripts/deploy_aws_control_plane.py check-data-boundary \
  --config /protected/path/data-boundary.json \
  --profile p1 --region eu-west-2

python3 scripts/deploy_aws_control_plane.py configure-data-boundary \
  --config /protected/path/data-boundary.json \
  --confirm-data-boundary-review \
  --profile p1 --region eu-west-2

python3 scripts/deploy_aws_control_plane.py deploy \
  --profile p1 --region eu-west-2
```

The configuration command persists only the secret-free reviewed manifest in
an encrypted stack-specific SSM parameter. Deploy erases ambient boundary
variables, re-verifies the key and recovery Region, then checks the resulting
CloudFormation outputs. Losing this manifest after configuration blocks future
deployment. The example CIDR is synthetic and must not be reused.

Schema version 1 restricts authenticated human routes by API Gateway source
IPv4 address. For private operator access, use schema version 2, set
`operatorAccessMode` to `private-link`, set `operatorAllowedIpv4Cidrs` to an
empty list, and provide `operatorVpcEndpointIds` plus
`privateAccessEvidenceRef`. Each endpoint must be a same-account, available
interface endpoint for `com.amazonaws.<region>.execute-api` with private DNS
enabled. The preflight rejects wrong-service, wrong-account, unavailable or
non-private-DNS endpoints.

Private mode deploys a Cognito-authorized private REST API and emits
`PrivateOperatorApiUrl`. Configure the production UI API base URL to that
output. Operators must reach the VPC endpoint through an approved VPN or Direct
Connect path and customer DNS. The public `ApiUrl` remains for separately
authenticated machine, enrollment and agent traffic; it cannot serve human
tenant routes in private mode. Review the VPC endpoint policy, endpoint security
groups, DNS, routing and Entra Conditional Access, then retain live allow/deny
evidence before production acceptance.

The approved Region claim
covers retained DynamoDB, tenant-data S3, SQS and SNS state; CloudFront,
Cognito/Entra processing, CloudWatch logs, static assets, provider secrets and
dedicated signing keys have separate boundaries. Review the deletion classes
and acceptance requirements in [Enterprise data boundary](enterprise-data-boundary-design.md).

API Gateway exposes JWT claim values to Lambda as strings even when Cognito's
source claim is an array. The handler therefore applies bounded parsing to
`cognito:groups` and compares only exact role names. Verify both an authorized
group member and a lookalike unauthorized group through API Gateway after each
authorizer or Cognito configuration change; direct Lambda test events alone do
not prove the deployed claim projection.

Mutating routes are classified into `runtime_admin`, `policy_write`,
`policy_approval`, `fleet_write`, `approval_decision`, or
`incident_response`; identity lifecycle changes additionally require
`identity_admin`; access-certification export requires
`access_certification_read`. A role must grant the exact capability. Entra proves the
operator identity but does not select the AAI tenant or grant a product role:
the deployment maps the configured Entra tenant to one provisioned AAI tenant,
and Cognito-managed groups remain the authorization source. This separation
prevents a browser-supplied tenant, group, or upstream claim from widening
authority.

## Reviewed policy GitHub source

The hosted policy import is disabled unless both an exact credential reference
and an explicit repository allow-list are present at synthesis. For schema-v2
production authority, store the GitHub App private key as an exact JSON object
in Secrets Manager:

```json
{"privateKeyPem":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"}
```

The GitHub App installation requires read-only **Contents**, **Metadata** and
**Pull requests** access only for every allow-listed policy repository. It must
not receive repository administration, Actions, issue, deployment or write
permissions. Copy
`infra/aws-control-plane/policy-github-deployment.example.json` to a protected
location, set the exact secret name, repositories and an opaque security-review
evidence reference, then validate and persist the reviewed authority:

```bash
python3 scripts/deploy_aws_control_plane.py check-policy-github \
  --config /protected/path/policy-github-deployment.json \
  --profile p1 --region eu-west-2
python3 scripts/deploy_aws_control_plane.py configure-policy-github \
  --config /protected/path/policy-github-deployment.json \
  --confirm-policy-github-review \
  --profile p1 --region eu-west-2
python3 scripts/deploy_aws_control_plane.py deploy \
  --profile p1 --region eu-west-2
```

Schema-v2 repositories must belong to the same App installation owner. The
dedicated broker mints a repository- and permission-scoped one-hour token for
each import; no installation token is stored or manually rotated. Repository
identities are exact `github.com/owner/name` values; wildcards, branches and
abbreviated commit IDs are rejected. The secret-free manifest is
stored in an encrypted, stack-specific SSM parameter. Routine deployments erase
ambient policy-source variables and load only that persisted authority. If a
configured stack loses its manifest, deployment fails instead of silently
disabling the verifier. Schema-v1 externally rotated `{"token":"..."}` secrets
remain supported only to migrate a controlled pilot.

The dedicated token broker owns the private key and installation-token exchange
but has no DynamoDB, KMS signing or control-plane mutation access. The verifier
can invoke only that broker, receives the short-lived token in memory and owns
the remaining bounded GitHub reads. The main handler can invoke only the
verifier and cannot read either credential. It
revalidates the worker response and atomically writes an inactive draft plus
immutable provenance. Import never submits, approves, stages, activates or
assigns a policy. Export uses the existing asymmetric policy-signing KMS key.

Hosted routes are:

```text
POST /enterprise/policies/imports
GET  /enterprise/policies/imports/{importId}
POST /enterprise/policies/{policyId}/versions/{version}/export
```

Before a pilot, prove one successful reviewed import, one disallowed repository,
one unsigned commit, one dismissed latest review, one cross-tenant document,
one verifier outage, one replay and one transaction race. Retain the import,
review, draft, export signature and denial evidence. Synthetic CI proves the
software contract but is not live GitHub acceptance.

See [GitHub App policy-source authentication](github-app-policy-source-auth-design.md)
for JWT, permission, migration and failure-boundary details.

## Microsoft Entra ID federation

Create a single-tenant Microsoft Entra application registration. Configure its
web redirect URI as the Cognito domain followed by `/oauth2/idpresponse`. Store
the client secret in AWS Secrets Manager. To enable lifecycle provisioning,
create a different 32-character-or-longer SCIM bearer secret and enforce MFA
for the enterprise application with Conditional Access.

Copy `infra/aws-control-plane/entra-deployment.example.json` to a protected
location outside the repository and fill in the IDs, secret resource names and
an opaque Conditional Access evidence reference. Validate and persist it:

```bash
python3 scripts/deploy_aws_control_plane.py check \
  --config /secure/path/entra-deployment.json \
  --profile p1 --region eu-west-2

python3 scripts/deploy_aws_control_plane.py configure \
  --config /secure/path/entra-deployment.json \
  --confirm-conditional-access \
  --profile p1 --region eu-west-2

cd infra/aws-control-plane
AWS_PROFILE=p1 AWS_REGION=eu-west-2 npm run deploy
```

The encrypted Parameter Store manifest keeps identity references present on
subsequent deployments. A configured stack with a missing manifest fails
closed instead of silently removing federation. Preflight also requires both
secrets, the bound AAI tenant and exact tenant-specific Microsoft OIDC metadata.
The generated OIDC provider requests only
`openid`, `email`, and `profile`; its secret is a CloudFormation dynamic
reference and is not copied to Lambda or output values.

See the [persistent Entra deployment guard](entra-deployment-guard-design.md)
for guarantees, non-guarantees and recovery.

The pre-token trigger emits a server-owned strong-authentication assertion
only when `ENTRA_STRONG_AUTH_ENFORCED=true` and the exact configured Entra
provider authenticated the operator. No mutable user attribute or browser
value can create it. Break-glass request and decision routes require that
assertion plus `auth_time` no older than 10 minutes. Set the deployment flag
only after enforcing MFA for these operators with Entra Conditional Access;
retain the policy and sign-in evidence and prove the deployed API Gateway claim
projection before pilot use.

A Cognito pre-token trigger inspects the server-owned federated identity and
adds provider provenance to ID and access tokens. The API compares the Entra
tenant claim to the deployment configuration before resolving the mapped AAI
tenant. These provenance claims are not role authority.

When SCIM is enabled, Entra provisions users, groups and memberships into a
tenant-bound retained DynamoDB lifecycle table. A platform administrator maps
each exact Entra group UUID to one canonical role in **Identity & trust**.
The pre-token trigger then replaces Cognito groups from that live mapping;
unprovisioned, inactive and roleless identities fail closed. Five-minute
access and ID tokens bound leaver and mover convergence. Without the SCIM
secret, the UI truthfully reports lifecycle provisioning as not configured.
Follow the [Entra SCIM lifecycle runbook](entra-scim-runbook.md).

After provisioning, a tenant identity administrator can assign an expiring
non-admin role to one active Entra object for an existing organization,
project or deployment in **Identity & trust → Delegated operator access**. The
pre-token trigger verifies that the SCIM identity has either a tenant-wide
mapped role or a live delegated grant, but it never copies the delegated role
into Cognito groups. The control-plane Lambda resolves the exact resource
lineage and grant state on every mutation, so expiry and revocation are
immediate. The pre-token trigger therefore also needs read-only access to the
control table; CDK declares that permission and the `CONTROL_TABLE`
environment value. Follow the
[delegated administration design](delegated-administration.md) and prove one
in-scope allow plus one sibling-resource deny before pilot use.

| Canonical role | Capability |
| --- | --- |
| `platform-admin` | All administrative capabilities; reserve for tenant administration and break glass |
| `security-operator` | Exact-action approval and incident response |
| `policy-author` | Policy, Skill and MCP resource changes |
| `policy-approver` | Independently review, stage and activate governed policy versions |
| `fleet-operator` | Deployments, groups and agent lifecycle |
| `incident-responder` | Emergency stop, containment and alert response |
| `auditor` | Read-only evidence and access-certification export |

After deployment, retain evidence for one successful Entra login, tenant
resolution, every permitted role action, every denied cross-role action, an
unknown role, and a mismatched Entra tenant. Federation configuration alone is
not enterprise SSO acceptance evidence.

The current pilot's post-deployment result is recorded in
[AWS pilot acceptance evidence](aws-pilot-acceptance-2026-07-29.md). Entra OIDC
and SCIM are not configured in that environment, so the source contracts must
not be presented as live federation acceptance.

## AWS-managed Entra, Intune and GitHub discovery

After deployment, CloudFormation outputs `DiscoverySecretKmsKeyArn` and
`DiscoveryProviderSecretNamePrefix`. A platform administrator can also obtain
these non-secret values from **Coverage → Inventory sources → Add source**.
Create the Entra application with Microsoft Graph application permission
`User.Read.All` only, grant tenant-admin consent, and store its credential as
an exact JSON object:

```json
{
  "tenantId": "<entra-directory-uuid>",
  "clientId": "<entra-application-uuid>",
  "clientSecret": "<secret>"
}
```

For Intune managed-device population, create a separate application with only
Microsoft Graph application permission
`DeviceManagementManagedDevices.Read.All`, grant tenant-admin consent, and use
the same three-field secret schema. The UI optionally accepts opaque Entra user
ID to business-unit mappings; names and email addresses are not accepted.
Intune does not prove installed binaries, active processes or project roots, so
coverage remains unavailable until a separate endpoint publisher commits
current `installation` evidence.

For GitHub, use an organization-approved fine-grained token covering all
repositories, with repository metadata read-only and no code-content,
administration, Actions or write access. Store exactly:

```json
{
  "token": "<github-token>"
}
```

Create the secret under
`aai-sec/discovery/providers/{aaiTenantId}/`, encrypt it with the output KMS
key, and apply exactly these tags:

```text
aai-sec:tenant-id={aaiTenantId}
aai-sec:purpose=discovery-provider
```

Paste only the returned ARN into the UI and select a fixed interval. The
control-plane Lambda can describe that secret but cannot read its value. It
creates a separate connector credential directly in Secrets Manager and a
delayed EventBridge schedule; neither secret is returned to the browser or
included in source-directory responses. The dedicated collector can read only
the tagged provider/connector namespaces, contacts fixed Entra/Graph/API hosts,
and publishes through the same atomic generation contract as an external
collector. For GitHub, also enter the exact organization and a reviewed mapping
from every active repository full name to a SHA-256 project-root digest and one
or both expected hosts (`claude-code`, `codex-cli`). The UI supports typed rows
and schema-checked JSON import. The saved read model exposes only organization
and mapping count.

Treat **Scheduled**, **Healthy** and **Current evidence** as distinct states.
Only a successful collection plus atomic commit produces Current evidence.
Disable revokes ingestion authority before schedule deletion. Investigate
`cleanupRequired`, collector Lambda errors, and messages in
`DiscoveryCollectorDlqArn`; follow
[AWS-managed discovery connectors](scheduled-discovery-connectors-design.md)
for fixed failure codes and non-guarantees.

Before production use, independently prove that the GitHub token can enumerate
all repositories in the organization. The API cannot reveal a repository that
the token itself is not permitted to see. Retain the permission review and an
independent repository count as deployment evidence.

The authenticated `GET /enterprise/identity` route returns redaction-safe
provider status, tenant hint, active roles and the enforced role matrix. It
never returns the OIDC client ID or secret. `GET /enterprise/integrations`
currently reports Splunk as a stub with `deliveryVerified: false`; no Splunk
event delivery is implemented or claimed.

`POST /enterprise/identity/break-glass/requests` creates a self-targeted,
exact-capability request lasting 5–60 minutes. A different platform
administrator uses the request-specific `approve`, `deny`, or `revoke` route;
the server conditionally enforces state, MFA freshness, requester separation
and expiry. `GET /enterprise/identity/access-certification` is auditor-only and
returns a digest-bound review artifact. Follow the
[emergency access and access certification runbook](access-governance-runbook.md).

The control plane also exposes a separate agent boundary. An operator creates a
short-lived bootstrap secret for a registered agent; the agent exchanges it
once at `POST /agent/enroll` and receives a 15-minute bearer session. The
session is bound to the deployment, agent, and registered immutable project
root and can call only heartbeat, decision evidence, effective-policy, and
exact approval routes. Enrollment must present the registered root before the
one-time secret is consumed. Every subsequent agent request sends its
canonical-root digest; the control plane compares it to both the session scope
and the live agent registration. Bootstrap secrets are hashed at rest and
consumed conditionally, so the control plane does not accept a tenant or agent
identity from an enrollment request body. Project-root binding prevents
cross-checkout credential reuse but is not a substitute for device attestation
against an attacker controlling the same OS account.
Register the root exactly as `pwd -P` reports it on the target host. Relative
paths, `/`, trailing separators, repeated separators, and `.`/`..` segments are
rejected before immutable agent inventory is created. The generated installer
rechecks the live directory before accepting the copied credential.
During authenticated heartbeats, the control plane rotates the bearer when it
is within five minutes of expiry and invalidates the previous bearer. The
reference gateway adopts the replacement in memory, allowing a healthy process
and publishes it atomically to the SDK-owned, user-private host credential
cache. Claude hooks and Codex/MCP processes can therefore adopt the current
bearer without writing credentials into project configuration. Missed
heartbeats, failed renewal, an unsafe cache, and emergency stops remain
fail-closed.

The heartbeat response also carries server-owned `controlState`. A normal AWS
agent client requires an explicit boolean `executionAllowed`; missing state is
not interpreted as a legacy allow. Quarantined agents may submit heartbeat and
attestation evidence, but the client then fails closed before normal service
continues. Effective policy, approval and managed-package routes independently
recheck the same live response controls.

Security operators manage endpoint-derived cases through
`/enterprise/cases`. Containment creates an exact agent quarantine without
rewriting deployment, group or fleet stop state. Session revocation increments
the agent's authority revision, invalidating old bearer and bootstrap material.
Release performs live recovery checks. These controls do not isolate the
device or terminate arbitrary local processes; integrate an MDM/EDR adapter
before making that operational claim.

Canonical incident responders, security operators, auditors and platform
administrators can export one retained case from the Incidents workspace. The
browser downloads only after verifying the server's canonical content digest.
Verify the downloaded file again on any machine from a trusted checkout:

```bash
python3 scripts/verify_incident_case_export.py \
  ~/Downloads/aai-incident-CASE_ID-DIGEST.json
```

A successful verifier prints the case identifier, full SHA-256 digest and
evidence counts. Preserve the JSON with the corresponding Object-Lock audit
record. Do not treat the artifact as proof of MDM/EDR isolation or as a digital
signature; add those deployment evidence sources separately.

Agent identity lifecycle is independent from presence and emergency stop. A
fleet operator can call `POST /enterprise/agents/{deployment}/{agent}/revoke`
with `expectedLifecycleRevision` and a bounded reason. The transition is
irreversible: every agent route and bootstrap exchange checks the live agent
record, so existing sessions and unused bootstrap material fail immediately
without waiting for their TTL. `replace` atomically creates a distinct offline
successor and inherits group membership while revoking the predecessor;
operators must enroll the successor with fresh material. `offboard` is allowed
only after revocation and replaces operational fields with a content-minimised
tombstone. Lifecycle authority and immutable DynamoDB evidence commit in one
transaction; S3 audit is a secondary best-effort replica of that already
durable event.

New registrations also require accountable ownership. The operator supplies a
stable owner identity, display name, monitored business mailbox and typed
criticality; the Lambda derives team and environment from the deployment.
When Entra SCIM is enabled, the owner must be an active directory object.
Ownership reviews expire after 90 days and are renewed through
`PUT /enterprise/agents/{deployment}/{agent}/ownership` with an expected
ownership revision and retained rationale. Missing or stale ownership is shown
in inventory and prevents positive enrollment verification; it is not inferred
from heartbeat presence.

Heartbeats can also report the exact managed-host bundle loaded by Claude Code
or Codex. A deployment configuration must first contain a complete
`managedHost` desired identity (host/client version, platform, policy ID and
version, and lowercase SHA-256 bundle digest). The Lambda validates a closed
report schema, compares desired and observed values, and returns the derived
posture in agent inventory and verification. Missing, stale and conflicting
evidence blocks a positive verification result. The report carries no file
contents, commands, MCP credentials or environment values.

The stack also creates a synthetic least-privilege role for scope
verification. In the current `p1` deployment, IAM simulation allowed
`s3:GetObject` only below the `tenant-demo/agent-claude-local/` prefix and
returned `implicitDeny` for the sibling agent prefix. Replace this role and
repeat the simulation for every real provider integration; it is intentionally
not a universal agent role.

The runtime can use the exported idempotency table with
`agentic_security.DynamoDbIdempotencyStore`. Its conditional claim and
terminal-write contract is covered by local fake-table tests and a live AWS
test across a new adapter instance. The table is not a substitute for
provider-side IAM: applications must still scope any cloud credentials used by
their tools to the exact operation and resource.

For AWS-backed tools, `AwsStsCredentialBroker` adds a second enforcement
layer. A trusted deployment policy builder returns an `AwsScopePolicy` bound
to the live tool and resource IDs; the adapter refuses a mismatch and calls
STS with a short-lived inline session policy. AWS intersects that policy with
the role policy, so neither model output nor the SDK can expand the role's
permissions. The role's identity policy and AWS IAM policy-simulation result
remain deployment evidence and must be retained with the environment.

Remote approvals can be requested by an enrolled agent at
`POST /agent/{deployment}/{agent}/approvals/request`, reviewed at
`GET /enterprise/approvals`, and decided by an authenticated operator at
`POST /enterprise/approvals/{approvalId}/decision`. The decision requires an
operator rationale. Approved grants are consumed once at the agent boundary;
the binding includes the tenant, enrolled agent, tool, proposal, task,
principal, and action hash. A denial, expiry, replay, concurrent second
decision, or binding mismatch returns no authority. The legacy direct operator
grant at `POST /enterprise/approvals` remains available for bounded automation.

The UI build is uploaded separately because its public configuration depends on
the deployed API, Cognito client, and CloudFront URLs:

```bash
cd ../..
npm --prefix aai-sec-ui run build
aws --profile p1 s3 sync aai-sec-ui/dist/ s3://<UiBucketName>/ --delete
```

## First sign-in

The hosted UI's **Start free trial** action sends a visitor to Cognito Managed
Login. After email confirmation, the post-confirmation Lambda creates a
server-generated `trial-*` tenant, a trial workspace, a deny-by-default policy,
and a user-subject-to-tenant mapping. It also adds the user to
`platform-admin`, which permits management actions only inside that mapped
tenant. The API never trusts a tenant in request JSON. Existing administrator
accounts may continue to use the immutable `custom:tenant_id` claim; new trial
users resolve through the server-side subject mapping and fail closed if it is
missing or unprovisioned.

The first-run console then prepares a pilot foundation before offering any host
installer. It creates a project under the provisioned organization, a bounded
deployment under that project, and a policy group bound to the safe default.
That default permits project-confined reads plus exact `pwd`, `ls`, `git
status`, `git status --short`, `git diff --stat`, and `git log --oneline`
commands; all other native commands remain denied unless explicitly governed.
`POST /api/enterprise/projects` and `POST /api/enterprise/deployments` reject
unknown or mismatched parents and duplicate identifiers. Agent registration
requires an existing deployment and derives organization, project,
environment, and region from that server-owned record; browser-supplied values
cannot change ownership. Registration and bootstrap exchange leave presence
offline. Only an authenticated runtime heartbeat marks the agent connected.

### Runtime attestation manifests

The control-plane Lambda packages
`infra/aws-control-plane/lambda/runtime-manifests.json` and its paired
`runtime-manifests.provenance.json`. CDK pins both SHA-256 digests into the
function environment. CDK rejects malformed, duplicate, unsupported or stale
bundle/approval pairs during synthesis, and Lambda revalidates both exact files
at startup. The checked-in manifest bundle is deliberately empty, with an
empty approval record bound to those exact bytes, so a fresh development
deployment reports runtime attestation as `not_configured`; this is not
production-ready posture.

Before production enrollment, independently verify the intended release and
populate one exact manifest for each approved `claude-code` or `codex-cli` SDK
version. Each object must use the schema documented in
[Runtime attestation design](runtime-attestation-design.md) and contain the
release SDK revision plus SHA-256 identifiers for source origin, installed
package, MCP gateway and native hook. Use
`scripts/generate_runtime_manifests.py` from a clean tag checkout; it validates
the published evidence bundle and both GitHub artifact attestations before
writing the exact manifest and provenance pair. Do not copy values from an
enrolled endpoint or hand-edit either file. Commit the reviewed pair, run
`make check`, synthesize CDK and deploy the changed Lambda before onboarding
that release. The complete command and trust assumptions are in
[Runtime attestation design](runtime-attestation-design.md).

After configuration, each heartbeat obtains a 60-second one-time challenge.
Evidence is accepted only inside a 90-second observation window and compliant
posture expires after five minutes. A mismatch quarantines the agent, removes
its live session and denies effective-policy, decision and approval calls. The
operator verification endpoint exposes status, freshness, SDK version,
revision and bounded reason codes without returning local paths or file
content. Recovery requires restoring approved artifacts and re-enrolling; do
not clear the retained audit history.

After deployment, operators can inspect the exact release authority and
tenant-scoped adoption without handling artifact bytes:

```text
GET /api/enterprise/runtime-releases
GET /api/enterprise/version-compliance?limit=250
# Continue only with the opaque nextToken returned by the preceding page.
GET /api/enterprise/version-compliance?limit=250&nextToken=...
```

The first route projects only manifests with exact provenance coverage. The
second compares active agents with each deployment's desired SDK version and
fresh runtime-attestation evidence in bounded tenant-bound pages. Both require
explicit human inventory-read authority or an `inventory_read` machine
identity; policy-only roles are denied. They are read-only: the UI cannot
upload or approve a runtime release. See [Approved runtime releases and
version compliance](runtime-release-compliance-design.md).

The stack selects Cognito Managed Login version 2 and declares the AAI Security
branding style in CloudFormation, including the dark/teal form treatment and
logo asset. This keeps the authentication handoff visually consistent with the
public landing page and makes the signup presentation reproducible on a fresh
deployment. The branding resource is presentation-only; Cognito remains the
authentication authority and the API remains the authorization boundary.

For a production launch, replace the shared development callback URL with the
controlled deployment hostname, configure a verified email delivery path, set
the trial lifecycle/retention policy, and add abuse controls such as signup
rate limits and domain or invitation policy.

Create an operator with a tenant claim using an administrator session:

```bash
aws --profile p1 cognito-idp admin-create-user \
  --user-pool-id <UserPoolId> \
  --username <operator-email> \
  --temporary-password '<temporary-password>' \
  --message-action SUPPRESS \
  --user-attributes \
    Name=email,Value=<operator-email> \
    Name=email_verified,Value=true \
    Name=custom:tenant_id,Value=<tenant-id>
```

The operator must complete the password change in Cognito. The browser keeps
the claim-bearing Cognito identity token in memory and uses PKCE; long-lived
bearer tokens must not be placed in Vite environment files or source control.

## Verification

### Policy signing trust

The stack creates a retained asymmetric P-256 KMS key and outputs
`PolicySigningKeyArn`. Export its public key using an operator AWS profile:

```bash
POLICY_KEY_ARN="$(aws cloudformation describe-stacks \
  --stack-name AaiSecControlPlane --profile p1 --region eu-west-2 \
  --query 'Stacks[0].Outputs[?OutputKey==`PolicySigningKeyArn`].OutputValue' \
  --output text)"
python3 scripts/export_policy_trust_bundle.py \
  --profile p1 --region eu-west-2 --key-arn "$POLICY_KEY_ARN" \
  --output "$PWD/policy-trust.json"
sudo install -d -o root -g wheel -m 0755 "/Library/Application Support/AAISecurity"
sudo install -o root -g wheel -m 0644 "$PWD/policy-trust.json" \
  "/Library/Application Support/AAISecurity/policy-trust.json"
```

Use `root:root` and `/etc/aai-security/policy-trust.json` on Linux. Public key
bytes are not secret, but the installed file is authority-sensitive: a process
that can replace it can choose a different signer. Do not download and trust a
key from an effective-policy response. Rotation distributes an overlapping
old/new trust bundle before the control plane selects the new signer.

The reproducible deployment smoke test requires AWS credentials with access
to invoke the control-plane Lambda and the two DynamoDB tables. It creates and
removes synthetic records and must be run against a non-production tenant:

```bash
AWS_PROFILE=p1 AWS_REGION=eu-west-2 python scripts/test_aws_control_plane.py \
  --api-url https://<api-id>.execute-api.eu-west-2.amazonaws.com \
  --function-name <control-plane-lambda> \
  --control-table <control-table> \
  --idempotency-table <idempotency-table> \
  --audit-bucket <audit-bucket> \
  --alerts-topic-arn <security-alerts-topic-arn> \
  --alerts-queue-arn <security-alerts-queue-arn> \
  --policy-trust-bundle "$PWD/policy-trust.json" \
  --region eu-west-2 --profile p1
```

The test prints one passing result only after it has checked unauthenticated
401 handling, synthetic agent registration and one-time enrollment, denial of
heartbeats with a missing or mismatched project-root digest, acceptance of the
enrolled digest, agent emergency-stop enforcement and recovery, exact approval
consumption and replay refusal, a two-process DynamoDB claim race, restart
replay, terminal write, and a `GuardedRuntime` execution that replays the typed
`ExecutionResult` without invoking the synthetic side effect twice. It also
checks the deployed audit bucket's compliance retention, versioning, and
inability to delete a retained object version, and publishes a synthetic alert
through SNS to verify delivery into the durable SQS operations queue.
It also verifies the tenant-bound KMS signature locally against the explicitly
supplied public trust bundle; successful HTTPS transport alone is insufficient.

Endpoint detection adds a five-minute EventBridge rule, a sharded tenant GSI,
a dedicated retry-exhaustion DLQ and a CloudWatch alarm. New endpoint alerts
are normalized onto the existing SNS/SQS operations channel. This is a real
AWS operations path; the separately displayed Splunk integration remains a
non-delivering stub.

The first deployment is verified by:

1. CloudFront returning the hosted UI with HTTP 200.
2. API Gateway returning HTTP 401 without a JWT.
3. Cognito redirecting an authorization-code request to Managed Login.
4. Lambda inventory returning the seeded Claude Code agent.
5. Lambda policy creation returning HTTP 201.
6. Lambda group creation and agent assignment succeeding.

The container adapter has a separate local evidence probe. Build a pinned
worker image and run:

```bash
docker build --tag aai-sec-isolation-probe:2026-07-27 tests/fixtures/docker-worker
image_ref="$(docker image inspect aai-sec-isolation-probe:2026-07-27 --format '{{.Id}}')"
python3 scripts/test_docker_sandbox.py --image "$image_ref"
```

The probe must report UID `65532`, blocked network access, a read-only root
filesystem, dropped capabilities, `no_new_privs`, and failed privilege
escalation, mount, and process-memory probes. Pin an immutable image digest and independently test the Docker
daemon/host before using this boundary for hostile workloads; use a managed
microVM where the host kernel is outside the trust boundary.

For each real provider/tool role, run the IAM scope check with one permitted
resource and one sibling resource. The check requires an AWS `allowed` result
for the first and an `implicitDeny` or `explicitDeny` for the second:

```bash
AWS_PROFILE=p1 AWS_REGION=eu-west-2 python3 scripts/test_aws_iam_scope.py \
  --role-arn <provider-tool-role-arn> \
  --action <provider-action> \
  --allowed-resource <permitted-resource-arn> \
  --denied-resource <sibling-resource-arn> \
  --region eu-west-2 --profile p1
```

The alert queue's retry and dead-letter behavior can be verified with a
synthetic message. The script deletes only the matching synthetic DLQ message:

```bash
AWS_PROFILE=p1 AWS_REGION=eu-west-2 python3 scripts/test_aws_alert_recovery.py \
  --queue-url <security-alert-queue-url> \
  --dlq-url <security-alert-dlq-url> \
  --region eu-west-2 --profile p1
```
7. Effective-policy resolution returning the assigned policy.
8. Agent emergency-stop activation returning HTTP 200, effective-policy
   retrieval failing closed with HTTP 409 while stopped, and recovery returning
   HTTP 200.
9. The deployed agent enrollment contract returning HTTP 201, refusing token
   reuse and URL identity mismatches, and returning HTTP 200 for heartbeat and
   effective-policy retrieval.
10. The deployed approval contract accepting one exact action and rejecting its
    replay.
11. The deployed DynamoDB idempotency table accepting an atomic claim,
    surviving a new adapter instance, and retaining the terminal result.

### Cross-region audit recovery

Deploy the immutable replica stack in the recovery region first. Copy the
example manifest to a protected location, record the exact bucket ARN and
review reference, then validate and persist it:

```bash
AWS_PROFILE=p1 AWS_REGION=eu-west-2 npm run deploy:replica

python3 scripts/deploy_aws_control_plane.py check-recovery \
  --config /secure/path/audit-recovery.json \
  --profile p1 --region eu-west-2

python3 scripts/deploy_aws_control_plane.py configure-recovery \
  --config /secure/path/audit-recovery.json \
  --confirm-recovery-controls \
  --profile p1 --region eu-west-2

cd infra/aws-control-plane
AWS_PROFILE=p1 AWS_REGION=eu-west-2 npm run deploy
```

Do not pass replica settings directly as shell environment variables. The
deployer discards ambient values and uses only the persisted reviewed manifest.
Once configured, a missing manifest blocks deployment so a routine release
cannot silently disable recovery.

The replication rule enables S3 replication metrics and routes failed or
untracked replication operations to the durable security-alert SNS/SQS channel.
Monitor that queue alongside the Batch Operations completion report; do not use
the CloudWatch metric alone as proof that every version recovered.

Live replication does not repair older versions. After a new destination or a
configuration outage, run the bounded Batch Replication repair using the stack
outputs `AuditBucketName`, `EvidenceReportBucketName` and
`AuditBatchReplicationRoleArn`:

The repair also reprocesses versions already marked `COMPLETED`. This is
necessary when source Object Lock retention was extended after their first
replication; a matching object count alone does not prove retention parity.

```bash
AWS_PROFILE=p1 python3 scripts/backfill_aws_audit_replication.py \
  --source-bucket <primary-audit-bucket> \
  --report-bucket <evidence-report-bucket> \
  --role-arn <audit-batch-replication-role-arn> \
  --region eu-west-2 --profile p1
```

Then independently verify every retained object version:

```bash
AWS_PROFILE=p1 python3 scripts/verify_aws_audit_recovery.py \
  --source-bucket <primary-audit-bucket> --source-region eu-west-2 \
  --replica-bucket <replica-bucket> --replica-region eu-west-1 \
  --profile p1
```

Use `scripts/test_aws_audit_replication.py` as the smaller live-write smoke test.
See the [persistent audit-recovery deployment guard](audit-recovery-deployment-guard-design.md)
for its guarantees and failure posture.

The Lambda also rejects a validly signed operator token when its tenant has no
independent provisioning record. The development `tenant-demo` record is
bootstrapped explicitly for the pilot; production tenants must be provisioned
by an administrative workflow before operators can access them.

The browser still requires an operator to complete the first-login password
change before the authenticated UI can be exercised interactively.

## Important production limitations

### Tenant evidence governance

The hosted **Evidence** workspace and `/api/enterprise/evidence` routes inspect
live retained object versions. New audit objects explicitly apply the tenant's
365–3,650-day COMPLIANCE retention and carry a creation-time SHA-256 metadata
binding. Security operators can only increase tenant retention and can place or
release legal hold on one exact tenant object version. Auditors can verify and
export but cannot mutate.

The synchronous assurance/export fast path is 250 versions. Above that bound it
returns `incomplete`; start a tenant-wide job from **Evidence** or
`POST /api/enterprise/evidence/jobs`. The FIFO worker verifies every retained
version as of a fixed cutoff, stores 30-day derived pages separately from WORM
audit records, and commits the final page-chain digest to retained audit
evidence. EventBridge starts due scans every 15 minutes; changed evidence gaps
publish to the existing durable security-alert SNS/SQS channel. Monitor the
worker and schedule DLQ alarms and treat `pending` alert delivery as unresolved.

Retention changes above 250 versions use a separate retention FIFO queue and
worker. The API first makes the longer period authoritative for future writes,
then waits beyond the evidence-writer timeout and extends every pre-cutover
version. Monitor `EvidenceRetentionWorkerErrors`,
`EvidenceRetentionWorkerDlqNotEmpty` and `EvidenceRetentionScheduleDlqNotEmpty`;
a failed job leaves the longer future policy active and requires reconciliation,
not rollback. Follow [Asynchronous tenant retention](asynchronous-retention-design.md)
and retain separate live cross-region count/order/hash/retention recovery
evidence.

The **Assurance** workspace can create and schedule executive or auditor signed
snapshots. Snapshot JSON and its deterministic creation audit are written to
the same tenant-prefixed Object Lock bucket, not the 30-day derived-report
bucket. DynamoDB records the exact S3 version and all reads are version-pinned.
Amazon S3 replication retains source version IDs, so the activated recovery
cell can resolve the same immutable version after replication completes. During
replication lag the API returns `503`; it never serves a different latest
version. See [Amazon S3 replication](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html)
and [Enterprise assurance reports](enterprise-assurance-reports-design.md).

`AssuranceReportSigningKeyArn` is a dedicated retained multi-Region ECDSA P-256
key, separate from executable-policy signing. The recovery stack creates
`AssuranceReportSigningReplicaKeyArn`, and active-cell verification requires
that exact replica. `ASSURANCE_REPORT_VERIFICATION_KEY_ARNS` lists current and
historical local-Region replicas by stable MRK identity. During rotation,
deploy and register the new local replica before signing with it. Retain every
historical key and registry entry until all snapshots it signed exceed their
longest Object Lock retention. CDK uses `RETAIN` and a 30-day pending-deletion
window, but snapshot retention is the stricter deletion boundary.

Use the guarded two-phase workflow rather than changing key environment
variables manually. Before preparation, retain one real pre-rotation snapshot
verification fixture containing only its 32-byte identity-envelope digest and
KMS signature; it need not contain report content.

```bash
python3 scripts/rotate_aws_assurance_signer.py prepare \
  --state .local/assurance-signer-rotation.json \
  --regional-recovery-config .local/regional-recovery.json \
  --fixture .local/pre-rotation-signature.json \
  --approval-evidence-ref change/ASSURANCE-ROTATION-42 \
  --profile p1 --confirm-two-phase-cutover

python3 scripts/rotate_aws_assurance_signer.py promote \
  --state .local/assurance-signer-rotation.json \
  --regional-recovery-config .local/regional-recovery.json \
  --passive-config .local/passive-cell.json \
  --profile p1 --confirm-two-phase-cutover

python3 scripts/rotate_aws_assurance_signer.py verify \
  --state .local/assurance-signer-rotation.json \
  --regional-recovery-config .local/regional-recovery.json \
  --fixture .local/pre-rotation-signature.json --profile p1
```

`prepare` checkpoints the candidate primary MRK before replication, discovers
an already-created replica after interruption, deploys passive trust with the
old current replica as historical, then verifies shared identity and a
pre-rotation signature in both Regions. It does not change active signing
authority.
`promote` advances through `authority_persisted`, `primary_promoted` and
`passive_converged` checkpoints. Each phase re-reads live state, so interruption
after SSM, primary CloudFormation or passive CloudFormation safely resumes.
Every future routine deployment reloads persisted authority and refuses a
missing or stale manifest outside this guarded transition. Preflight compares
the complete ordered deployed history: removal, reordering, substitution or
truncation fails before CDK executes. `verify` repeats
pre-rotation verification and records `verified`. Synthesized IAM verification
requires old keys to have `kms:Verify` only and the new current key to be the
sole report signer.

The fixture is bounded to 16 KiB and contains exactly one Base64-encoded
32-byte SHA-256 digest plus a 1–1,024-byte signature. Verification requires KMS
to return `SignatureValid: true`, the exact requested key ARN and
`ECDSA_SHA_256`; malformed Base64, wrong key, wrong algorithm and oversized
content fail closed.

The history remains bounded to eight keys. Synthesis, runtime startup, trust
preparation and active-cell verification reject malformed, duplicate,
foreign, overlapping or reordered authority. Do not remove an entry while any
retained snapshot still names its MRK identity.

Report state is isolated under `ASSURANCE#{tenant}`. The worker may read the
control table to derive posture, but can write only `PutItem` constrained by
`dynamodb:LeadingKeys` to that partition. It has no policy-signing key ARN or
grant, no presence/SCIM/idempotency-table access, and only the snapshot and
deterministic-audit S3 prefixes. Guarded active-cell verification rejects
broader writes, unrelated-table reads, unscoped S3 access or key substitution.

Monitor `AssuranceReportWorkerErrors`, `AssuranceReportWorkerDlqNotEmpty` and
`AssuranceReportScheduleDlqNotEmpty`. A worker DLQ entry is a revision-bound
job, while a schedule-DLQ entry is a failed shard dispatch. Do not manually
construct a replacement snapshot. Resolve the dependency, confirm the stored
schedule claim still matches, redrive the worker message, and verify the exact
snapshot through the API. A stale claim may be replaced only through a
revision-guarded schedule update after its 15-minute recovery window.
Malformed due records are quarantined out of the schedule GSI and emit a
security alert with counts only. Repair the retained schedule record through a
reviewed schedule save before re-enabling it; never copy its malformed index
fields back directly. Transient claim or quarantine provider failures fail the
dispatcher invocation and preserve the due index for retry.

The recovery stack stages the same queue, worker and sixteen dispatcher rules.
In standby, all report event mappings/rules are disabled, worker concurrency is
zero and signing authority is absent. The guarded active-cell transition must
establish those authorities before the recovery endpoint can create reports.

### Secure-webhook operations

The stack provisions `WebhookDeliveryQueue` and its five-receive FIFO DLQ, a
separate scheduled-dispatch DLQ, `WebhookDeliveryWorker`, and a rotating
`WebhookSecretKey`. The API role may create, version and schedule deletion only
under `aai-sec/webhooks/*`, encrypt with that key and send to the delivery
queue. The worker can read only that secret prefix, decrypt with that key,
update the control table, write terminal audit evidence and consume the queue;
it has no Cognito or policy-signing permissions.

Monitor `WebhookDeliveryDeadLetters` and `WebhookDispatchDeadLetters`. A DLQ
item contains only tenant and delivery identity; inspect the retained delivery
record and immutable terminal audit before redrive. Redrive preserves the
delivery ID, so the customer receiver must atomically deduplicate it. Verify
deployment egress controls restrict the worker to approved public receiver
origins, because application DNS checks alone cannot eliminate DNS rebinding.
Follow the creation, receiver verification and rotation procedure in
[Secure webhooks](secure-webhooks-design.md). No live receiver is configured by
CDK and the Splunk stub is unchanged.

This is the first AWS deployment slice, not a production security
certification. Before production use:

- add a server-side entitlement table instead of relying only on the Cognito
  tenant claim;
- rotate enrollment/session signing material and integrate enterprise device
  attestation for agent identity;
- connect every runtime deployment to the idempotency table and retain the
  process-crash/retry evidence with the release;
- provision provider-specific IAM roles and prove tool/resource scope with
  provider policy simulation and denied-action tests;
- retain the Docker probe and add hostile escape tests; use a genuine microVM
  or WASM isolation boundary when the Docker daemon/host is not trusted;
- add API throttling and WAF rules;
- connect the alert queue to the enterprise PagerDuty/SIEM/SOC workflow and
  retain delivery and recovery artifacts;
- replace seeded data with migration/bootstrap tooling;
- add full contract tests against DynamoDB and API Gateway;
- remove the temporary operator and configure enterprise SAML/OIDC federation;
- run `make check` and the AWS staging load/security test suite.

The Lambda boundary preserves tenant scope from verified Cognito claims and
stores audit evidence in the retained Object Lock bucket. Execution authority
still remains in the enrolled SDK deployment; the hosted UI does not execute
agent tools.
