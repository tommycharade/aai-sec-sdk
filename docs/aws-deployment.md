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
- Cognito `platform-admin` and `security-operator` groups for mutation RBAC;
- API Gateway HTTP API with Cognito JWT authorizer;
- Lambda control-plane handler;
- on-demand DynamoDB control and presence tables;
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

The control plane also exposes a separate agent boundary. An operator creates a
short-lived bootstrap secret for a registered agent; the agent exchanges it
once at `POST /agent/enroll` and receives a 15-minute bearer session. The
session is bound to the deployment and agent identifiers and can call only
heartbeat, effective-policy, and exact approval-consumption routes. Bootstrap
secrets are hashed at rest and consumed conditionally, so the control plane
does not accept a tenant or agent identity from an enrollment request body.
During authenticated heartbeats, the control plane rotates the bearer when it
is within five minutes of expiry and invalidates the previous bearer. The
reference gateway adopts the replacement in memory, allowing a healthy process
to remain enrolled without writing credentials into Claude Code or Codex CLI
configuration. Missed heartbeats, failed renewal, and emergency stops remain
fail-closed.

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
`POST /api/enterprise/projects` and `POST /api/enterprise/deployments` reject
unknown or mismatched parents and duplicate identifiers. Agent registration
requires an existing deployment and derives organization, project,
environment, and region from that server-owned record; browser-supplied values
cannot change ownership. Registration and bootstrap exchange leave presence
offline. Only an authenticated runtime heartbeat marks the agent connected.

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
  --region eu-west-2 --profile p1
```

The test prints one passing result only after it has checked unauthenticated
401 handling, synthetic agent registration and one-time enrollment, heartbeat,
agent emergency-stop enforcement and recovery, exact approval consumption and
replay refusal, a two-process DynamoDB claim race, restart replay, terminal
write, and a `GuardedRuntime` execution that replays the typed
`ExecutionResult` without invoking the synthetic side effect twice. It also
checks the deployed audit bucket's compliance retention, versioning, and
inability to delete a retained object version, and publishes a synthetic alert
through SNS to verify delivery into the durable SQS operations queue.

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
