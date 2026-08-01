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
- an AWS-managed Entra, Intune and GitHub discovery collector, EventBridge Scheduler invocation
  role, KMS key, connector dead-letter queue and collector alarms;
- on-demand DynamoDB control and presence tables; the control table expires
  short-lived records by `ttl` and has a decision-timeline index for bounded
  reverse-chronological dashboard reads;
- a retained, point-in-time-recoverable DynamoDB idempotency table with TTL;
- an S3 Object Lock audit bucket;
- an SNS security-alert topic wired to Lambda and idempotency CloudWatch
  alarms (subscribe the enterprise SOC endpoint before production);
- a private S3 UI bucket behind CloudFront.

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

## Microsoft Entra ID federation

Create a single-tenant Microsoft Entra application registration. Configure its
web redirect URI as the Cognito domain followed by `/oauth2/idpresponse`. Store
the client secret in AWS Secrets Manager. To enable lifecycle provisioning,
create a different 32-character-or-longer SCIM bearer secret, enforce MFA for
the enterprise application with Conditional Access, and deploy with all six
variables:

```bash
ENTRA_TENANT_ID=<entra-directory-uuid> \
ENTRA_CLIENT_ID=<entra-application-client-id> \
ENTRA_CLIENT_SECRET_NAME=<secrets-manager-secret-name> \
ENTRA_AAI_TENANT_ID=<provisioned-aai-tenant-id> \
ENTRA_SCIM_TOKEN_SECRET_NAME=<scim-bearer-secret-name> \
ENTRA_STRONG_AUTH_ENFORCED=true \
AWS_PROFILE=p1 AWS_REGION=eu-west-2 npm run deploy
```

The deployment fails if only some values are present or if the Entra tenant is
not a tenant-specific UUID. The generated OIDC provider requests only
`openid`, `email`, and `profile`; its secret is a CloudFormation dynamic
reference and is not copied to Lambda or output values.

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

Deploy the immutable replica stack in the recovery region first, then pass its
bucket ARN when deploying the primary stack:

```bash
AWS_PROFILE=p1 AWS_REGION=eu-west-2 npm run deploy:replica
AWS_PROFILE=p1 AWS_REGION=eu-west-2 \
  AUDIT_REPLICA_BUCKET_ARN=arn:aws:s3:::<replica-bucket> \
  AUDIT_REPLICA_REGION=eu-west-1 npm run deploy
```

The replica bucket is versioned and uses S3 Object Lock compliance retention.
The repeatable verification command is:

```bash
AWS_PROFILE=p1 python3 scripts/test_aws_audit_replication.py \
  --source-bucket <primary-audit-bucket> --source-region eu-west-2 \
  --replica-bucket <replica-bucket> --replica-region eu-west-1 \
  --profile p1
```

The 2026-07-27 pilot test received a replica with `ReplicationStatus=REPLICA`,
preserved synthetic metadata, and `COMPLIANCE` Object Lock retention.

The Lambda also rejects a validly signed operator token when its tenant has no
independent provisioning record. The development `tenant-demo` record is
bootstrapped explicitly for the pilot; production tenants must be provisioned
by an administrative workflow before operators can access them.

The browser still requires an operator to complete the first-login password
change before the authenticated UI can be exercised interactively.

## Important production limitations

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
