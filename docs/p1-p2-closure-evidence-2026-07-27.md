# P1/P2 closure evidence — 2026-07-27

This record is the current evidence audit for the critical adopter findings.
It distinguishes source and pilot evidence from controls that require facts
from a particular production deployment.

## Findings and evidence

| Finding | Current result | Evidence |
| --- | --- | --- |
| Published checksum bundle | Resolved for public `v1.0.1` | `docs/release-evidence-v1.0.1.md`; independent checksum/SBOM verification passed. |
| Tag-bound provenance | Resolved for public `v1.0.1` | `docs/release-evidence-v1.0.1.md`; both GitHub attestations passed against `refs/tags/v1.0.1`. |
| Uncertain idempotency persistence | Resolved in source | Runtime timeout, cancellation, and handler-failure tests; `DynamoDbIdempotencyStore` returns typed terminal state and live smoke exercises it. |
| Stale mutation figures and timeout | Resolved | Release workflow and current review evidence use the exact release bundle and bounded 600-second run. |
| Exact published bundle verification | Resolved | Tag-only release workflow downloads and verifies the published GitHub Release before the workflow succeeds. |
| Mutable authorization facts | Resolved | Recursive argument freezing and defensive handler copies are covered by adversarial component tests. |
| Durable idempotency deployment evidence | Pilot evidence supplied | Live AWS smoke runs two independent processes against DynamoDB, tests restart replay, terminal persistence, and runtime replay. |
| Immutable audit deployment evidence | Pilot evidence supplied | S3 Object Lock compliance retention, versioning, and retained-version deletion refusal pass live. Audit records use unique keys and retained versions. |
| Provider IAM enforcement | Reference pilot evidence supplied | Live IAM simulation proves the synthetic scoped role allows its tenant prefix and implicitly denies a sibling prefix. Real production tool roles still require their own simulations. |
| Remote policy and approvals | Pilot evidence supplied | Live agent enrollment, policy assignment, exact approval consumption, replay refusal, and emergency-stop enforcement/recovery pass. |
| Agent readiness verification | Resolved and live-tested | The deployed `/enterprise/agents/{deployment}/{agent}/verify` endpoint now requires registration, a fresh connected heartbeat, a valid group/policy assignment, and an inactive emergency stop. The live smoke test proves unassigned and stopped agents are rejected and assigned/recovered agents are accepted. |
| Operational alert delivery and recovery | Pilot evidence supplied | CloudWatch alarms publish to SNS; synthetic alert delivery to encrypted SQS and redrive of an unacknowledged alert to its DLQ are live-tested. PagerDuty/SIEM ownership remains deployment-specific. |
| Cross-region audit recovery | Pilot evidence supplied | A separately deployed `eu-west-1` Object-Lock replica receives S3 CRR objects with `ReplicationStatus=REPLICA`, preserved metadata, and compliance retention. |
| Container isolation boundary | Pilot evidence supplied | `DockerSandboxToolHandler` now rejects mutable image tags and `scripts/test_docker_sandbox.py` ran against a sha256-pinned local worker image, observing UID `65532`, blocked network access, a read-only root filesystem, dropped capabilities, `no_new_privs`, failed privilege escalation, blocked mount, and blocked process-memory probes. Docker daemon/host hardening, escape tests beyond these probes, and microVM/WASM evidence remain deployment-specific. |

## Verification commands

Repository quality gates:

```bash
make check
make package-check
make security-check
cd aai-sec-ui && npm run check
```

AWS pilot smoke:

```bash
AWS_PROFILE=p1 AWS_REGION=eu-west-2 python3 scripts/test_aws_control_plane.py \
  --api-url https://lwg33pxwk8.execute-api.eu-west-2.amazonaws.com \
  --function-name AaiSecControlPlane-ControlPlaneHandler9D89D4EC-2Mr58QONVYaM \
  --control-table AaiSecControlPlane-ControlPlaneTable34018A4D-1JYK4I7DQWA3D \
  --idempotency-table AaiSecControlPlane-IdempotencyTable22A5A209-1LXF0SYF83EEH \
  --audit-bucket aaiseccontrolplane-auditbucketb01e0ae8-wgrcz2izyuj2 \
  --alerts-topic-arn arn:aws:sns:eu-west-2:396510133537:AaiSecControlPlane-SecurityAlertsF84E29CE-8113JplvkH7o \
  --alerts-queue-arn arn:aws:sqs:eu-west-2:396510133537:AaiSecControlPlane-SecurityAlertsQueue4468E46B-ILuFo6zT2RVg \
  --region eu-west-2 --profile p1
```

Observed result:

```text
AWS control-plane smoke passed: auth, enrollment, heartbeat, policy, agent verification, approval replay, emergency-stop enforcement/recovery, and multi-process/runtime-connected durable idempotency, and WORM audit retention, and SNS/SQS alert delivery
```

Provider-role scope check:

```bash
AWS_PROFILE=p1 AWS_REGION=eu-west-2 python3 scripts/test_aws_iam_scope.py \
  --role-arn arn:aws:iam::396510133537:role/AaiSecControlPlane-ScopedToolRole3191AFF5-UUZQ44BWHrrj \
  --action s3:GetObject \
  --allowed-resource arn:aws:s3:::aaiseccontrolplane-auditbucketb01e0ae8-wgrcz2izyuj2/tenant=tenant-demo/agent-claude-local/object.json \
  --denied-resource arn:aws:s3:::aaiseccontrolplane-auditbucketb01e0ae8-wgrcz2izyuj2/tenant=tenant-demo/other-agent/object.json \
  --region eu-west-2 --profile p1
```

Observed result:

```text
AWS IAM scope passed: s3:GetObject allowed for the configured resource and denied for the sibling resource
```

Alert recovery check:

```bash
AWS_PROFILE=p1 AWS_REGION=eu-west-2 python3 scripts/test_aws_alert_recovery.py \
  --queue-url https://sqs.eu-west-2.amazonaws.com/396510133537/AaiSecControlPlane-SecurityAlertsQueue4468E46B-ILuFo6zT2RVg \
  --dlq-url https://sqs.eu-west-2.amazonaws.com/396510133537/AaiSecControlPlane-SecurityAlertsDlq67EAFD64-UYpb76yEQ4Bt \
  --region eu-west-2 --profile p1
```

Observed result:

```text
AWS alert recovery passed: unacknowledged synthetic alert reached the SQS DLQ
```

Docker isolation probe:

```bash
docker build --tag aai-sec-isolation-probe:2026-07-27 tests/fixtures/docker-worker
image_ref="$(docker image inspect aai-sec-isolation-probe:2026-07-27 --format '{{.Id}}')"
python3 scripts/test_docker_sandbox.py --image "$image_ref"
```

Observed result:

```text
Docker isolation passed: {'capabilities_dropped': True, 'filesystem_read_only': True, 'mount_blocked': True, 'network_blocked': True, 'no_new_privileges': True, 'process_memory_blocked': True, 'privilege_escalation_blocked': True, 'uid': 65532}
```

## Adoption decision

The original source-level P1/P2 findings are resolved and the AWS pilot now
has retained evidence for the durable reference paths above. The overall
high-impact production gate remains conditional until the actual deployment
retains: real provider/tool IAM simulations, hostile-code escape or microVM
evidence, and alert ownership and recovery procedures. These cannot be
truthfully inferred from a generic SDK or synthetic pilot role.
