# Passive regional control-plane cell

## Decision

The recovery Region contains production-shaped API, worker, queue, alert and
private UI-origin resources, but **no executable control-plane authority**.
Creating these resources is not failover and cannot make the recovery Region
active. Activation is a separate, reviewed infrastructure transition after the
identity, policy-trust, data, audit and routing gates in the
[regional recovery design](regional-control-plane-recovery-design.md) pass.

The first recovery cell is `eu-west-1`; the active cell remains `eu-west-2`.
The passive stack imports the existing Global Table replicas and immutable
audit replica by exact deployment-owned names. It never creates a second copy
of authoritative state.

## Threat and trust boundary

A reachable but stale recovery API could widen policy, replay approvals or
create split-brain state. DNS isolation alone is insufficient because an
attacker might discover an `execute-api` origin or invoke Lambda directly.
Standby therefore uses independent controls at every invocation boundary:

1. API Gateway's default `execute-api` endpoint is disabled and the stack
   creates no custom domain.
2. Every Lambda has reserved concurrency `0`, so direct invocation cannot run
   code.
3. Every EventBridge schedule is disabled.
4. Every SQS event-source mapping is created disabled.
5. Runtime roles receive read-only Global Table access, no audit-object write,
   no queue-send authority and no KMS signing grant.
6. The private UI bucket blocks all public access and has no CloudFront
   distribution or deployment URL.
7. The stack creates no Route 53, Global Accelerator, ARC or other traffic
   resource.

These controls are intentionally redundant. Weakening any one must not create
an active cell.

## Resources

The passive stack contains:

- an HTTP API with the same agent, endpoint-evidence, discovery and
  operator-route shapes as the primary, bound to the recovery Cognito issuer;
- the control-plane handler, evidence worker and retention worker code assets;
- Region-local FIFO work queues and dead-letter queues;
- disabled endpoint-detection, rollout, assurance and retention schedules;
- a Region-local security-alert topic, durable queue and dead-letter queue;
- a retained, encrypted, TLS-only private UI origin bucket;
- CloudWatch alarms for Lambda errors, queue backlog and dead-letter messages.

The stack emits resource identities and `staged-not-serving`, but deliberately
does not emit an API URL or UI URL.

## Required deployment inputs

Inputs are deployment identifiers, not secrets:

- four exact Global Table names;
- immutable audit replica bucket name;
- recovery multi-Region KMS replica ARN;
- recovery Cognito user-pool ID and client ID;
- primary Region and recovery Region.
- exact 12-digit recovery AWS account ID.

Synthesis rejects missing, malformed, cross-account or wrong-Region values.
Identity inputs cannot be substituted with the primary user pool: the user-pool
ID must start with the configured recovery Region.

The account ID uses the dedicated `RECOVERY_AWS_ACCOUNT_ID` input rather than
CDK's ambient default-account variable. This prevents credential discovery from
silently changing the account against which KMS trust is validated.

## Build-time acceptance

The passive-cell CI job synthesizes the stack with synthetic identifiers and
then inspects the resulting CloudFormation, rather than trusting construct
intent. The verifier rejects serving origins, enabled compute/event sources,
wildcard or mutation IAM authority, missing UI encryption/TLS controls and
unsafe outputs:

```bash
npm --prefix infra/aws-control-plane ci
RECOVERY_AWS_ACCOUNT_ID=111111111111 \
RECOVERY_REGION=eu-west-1 PRIMARY_REGION=eu-west-2 \
RECOVERY_CONTROL_TABLE=AaiControl \
RECOVERY_PRESENCE_TABLE=AaiPresence \
RECOVERY_IDEMPOTENCY_TABLE=AaiIdempotency \
RECOVERY_SCIM_TABLE=AaiScim \
RECOVERY_AUDIT_BUCKET=aai-audit-replica-111111 \
RECOVERY_POLICY_SIGNING_KEY_ARN=arn:aws:kms:eu-west-1:111111111111:key/mrk-1234567890abcdef1234567890abcdef \
RECOVERY_USER_POOL_ID=eu-west-1_AbCdEf123 \
RECOVERY_USER_POOL_CLIENT_ID=abcdefghij1234567890 \
npm --prefix infra/aws-control-plane run synth:passive -- --quiet
python3 scripts/verify_passive_regional_cell.py \
  infra/aws-control-plane/cdk.out/AaiSecPassiveRegionalCell.template.json
```

Synthetic acceptance proves the infrastructure contract only. A live deploy
requires real recovery identity and provider-state checks; passing this command
does not authorize deployment or activation.

## Provider-state deployment guard

Operators must use `scripts/deploy_aws_passive_cell.py`; direct `cdk deploy` is
not the approved path. The guard uses two secret-free reviewed manifests:

- `regional-recovery.json`, previously persisted after the storage/trust
  exercises; and
- `passive-cell.json`, based on
  `infra/aws-control-plane/passive-cell.example.json`.

The guard derives table, audit-bucket, signing-replica and AWS-account
identities from CloudFormation, KMS and STS. It does not accept those identities
from ambient shell variables. It requires protected primary/recovery Cognito
pools with matching security posture, the same tenant-specific Microsoft Entra
OIDC issuer, an Entra-enabled recovery app client, configured primary SCIM and
an identity-acceptance evidence reference. This comparison is necessary because
Cognito's provider API does not expose a standalone replica-relationship proof.
Population and lifecycle continuity therefore still require the retained live
acceptance referenced in the manifest.

Run the three stages in order:

```bash
python3 scripts/deploy_aws_passive_cell.py check \
  --config /absolute/path/to/passive-cell.json \
  --regional-recovery-config /absolute/path/to/regional-recovery.json \
  --profile p1

python3 scripts/deploy_aws_passive_cell.py prepare \
  --config /absolute/path/to/passive-cell.json \
  --regional-recovery-config /absolute/path/to/regional-recovery.json \
  --profile p1 \
  --confirm-identity-foundation

python3 scripts/deploy_aws_passive_cell.py deploy \
  --config /absolute/path/to/passive-cell.json \
  --regional-recovery-config /absolute/path/to/regional-recovery.json \
  --profile p1 \
  --confirm-non-serving-deployment
```

`check` is read-only except for local CDK synthesis. `prepare` persists the
exact secret-free authority as an encrypted SSM parameter only after all checks
pass. `deploy` requires a byte-equivalent persisted manifest, repeats every
provider and template check, and deploys only `AaiSecPassiveRegionalCell`.
The deploy stage rechecks the verified template SHA-256 and consumes the exact
`cdk.out` assembly; it never re-synthesizes unreviewed code. None of the commands
can activate it.

## Activation contract

Activation is prohibited until retained evidence proves:

- endpoint trust convergence is 100% and the multi-Region signer is active;
- the recovery Cognito replica and Entra federation passed real sign-in and
  lifecycle tests;
- all four Global Tables are active, protected and inside the RPO;
- bidirectional immutable audit replication is enabled and verified;
- pending jobs have been reconciled from authoritative records;
- a stable custom API/auth domain is ready and direct origins remain closed;
- an independently approved activation manifest identifies the exact stack,
  revisions, Regions, signer, identity and evidence digests.

The activation change must then grant only the required write/sign/send
permissions, raise bounded Lambda concurrency, enable event sources and
schedules, deploy the UI artifact, attach the custom domains and finally move
traffic. It must not rely on a browser-authored status or automatic health
check. Failback uses the same gates in reverse.

The implemented read-only activation authority and provider-state preflight
are documented in the
[regional activation and exercise design](regional-activation-and-exercise-design.md).
They add no path that can mutate this standby posture.

## Guarantees and non-guarantees

The passive stack guarantees that its deployed default cannot serve API/UI
traffic or execute Lambda code and that its roles cannot sign policy or mutate
authoritative state. It reduces recovery time by pre-provisioning code and
Region-local delivery resources.

It does not provide failover, an SLA, identity replication, audit continuity,
endpoint routing, signer cutover or load evidence. P0-11 remains Partial until
the complete recovery exercise passes.
