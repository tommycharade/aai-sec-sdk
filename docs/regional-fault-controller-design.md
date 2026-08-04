# Regional dependency fault controller

## Decision

Regional dependency failure testing requires a server-managed compensation
workflow. A local script that attaches an IAM deny and later removes it is not
acceptable: process termination, network loss or operator interruption could
leave the target cell unavailable indefinitely.

`scripts/plan_aws_regional_fault_exercise.py` implements the read-only authority
boundary. `RegionalFaultControllerStack` packages the private Lambda, Scheduler
and Step Functions runtime in the independent coordination Region. Its first
task independently reads the witness journal, both live processed templates,
every stack-owned Lambda/mapping/rule and the complete bounded Route 53 zone.
It proceeds only while the source is fenced, the target exactly matches its
reviewed active template, routing remains exclusively on the source and the
generation marker matches the witness. Target-role probes cover S3 audit
writes, four consistent DynamoDB reads, KMS public-key/sign operations and a
dedicated SQS canary queue. Cognito remains deliberately unsupported.

## Authority contract

Schema v1 requires exactly:

- a canonical fault UUID and the existing transition UUID;
- the schema-v4 transition authority digest and direction;
- exact target Region and expected `primary` or `recovery` cell role;
- exact target runtime stack and retained processed-template SHA-256;
- third-Region coordination authority and current routing generation;
- one dependency from `audit`, `cognito`, `dynamodb`, `kms` or `queue`;
- a 30–300-second maximum fault duration;
- the exact two-person approval digest and ordered Entra principal UUIDs;
- a canonical SHA-256 reference to the exact immutable activation evidence S3
  bucket, key, version and content digest;
- expiry after the current time, no later than 15 minutes or transition expiry;
- `faultPermitted: true`; and
- `automaticFaultInjection: false`.

Failover may target only the recovery runtime; failback only primary. Changed
templates, routing generations, approvers, dependencies, durations or Regions
change or invalidate authority. Unknown, missing and duplicate fields fail
closed.

## Required durable workflow

The planner emits this order and no alternate order:

1. independently verify target active-but-not-routed and source fenced;
2. create an independent cleanup watchdog;
3. apply one code-owned deny boundary to the exact target execution role;
4. verify the named dependency is unavailable from the target;
5. prove synthetic execution is denied with no bypass;
6. remove the exact deny boundary;
7. prove dependency and target recovery;
8. remove the watchdog; and
9. seal content-free fault evidence.

The implementation uses a Step Functions workflow for normal and exception
compensation plus an EventBridge Scheduler one-time watchdog. The
watchdog must be armed before the deny is applied and must invoke cleanup even
if the workflow, caller or network disappears. Normal cleanup can remove the
watchdog only after independently proving the deny no longer exists.

## Implemented controller primitives

`scripts/regional_fault_controller_lambda.py` and
`scripts/regional_fault_cleanup_lambda.py` implement the provider mutation
boundary that the state machine will invoke. They are Lambda handlers, not HTTP
or model-facing entry points. Every normal operation reparses the complete
schema-v4 transition and schema-v1 fault authority. The cleanup handler accepts
only a fault UUID, authority digest and target cell role because cleanup must
remain possible after approval expiry.

The implemented sequence enforces these invariants:

- one third-Region transaction proves the fault UUID has no retained evidence
  while acquiring the single active lock for its target;
- a lost acquire response is retryable only while the same digest remains in
  `LOCKED`; a completed authority or duplicate workflow that observes an
  advanced state is rejected;
- the Scheduler watchdog is created before the lock becomes
  `WATCHDOG_ARMED`;
- `apply-deny` performs a strongly consistent lock read and refuses IAM
  mutation unless that exact digest is armed;
- a complete, non-truncated live inline-policy inventory rejects an out-of-band
  or stranded Regional fault deny before another can be attached;
- policy and role names are derived from the reviewed UUID and deployment-owned
  cell outputs;
- primary and recovery have separate immutable resource maps, so failback
  cannot reuse a recovery bucket, table, key or queue alias;
- normal and watchdog cleanup tolerate an already-absent exact policy but never
  broaden the deletion target; and
- successful or watchdog cleanup transactionally retains content-free evidence
  and releases the active lock.

Authority must cover the requested fault duration plus a 30-second normal
cleanup margin. The independently scheduled cleanup runs 60 seconds after the
maximum fault duration and deliberately does not require live approval.

## Implemented private orchestration

`infra/aws-control-plane/lib/regional-fault-controller-stack.ts` synthesizes a
private Standard Step Functions workflow with this exact normal path:

```text
probe preconditions -> acquire lock -> arm watchdog -> apply deny
-> prove dependency unavailable -> prove execution denied/no bypass
-> remove deny -> prove dependency and target recovery
-> disarm watchdog -> seal evidence
```

The precondition probe runs before the lock, Scheduler or IAM operations. An
acquire failure attempts exact unarmed-lock release. Every failure from
watchdog arming through watchdog disarming invokes the independent cleanup
Lambda immediately; cleanup failure leaves the separately scheduled watchdog
armed and raises both Lambda and workflow alarms. Provider-service retries are
bounded to three attempts. Application failures are not blindly retried.

The state machine has no API Gateway, UI route, model-facing operation or
`states:StartExecution` grant. Error logs exclude execution data so the
activation manifest and fault authority do not enter CloudWatch. Controller,
cleanup, probe, Scheduler and workflow roles are separate. Only the controller
can attach a policy, and only to the two deployment-owned target handler roles.
Cleanup can only delete the UUID-derived policy. Watchdog delivery failures go
to a 14-day encrypted, retained SQS DLQ. The retained workflow stack enables
CloudFormation termination protection. Controller, cleanup, probe,
workflow-failure and DLQ alarms use the deployment-owned security SNS topic.

CloudWatch Logs delivery APIs do not support resource-level IAM permissions.
The workflow role therefore has `Resource: *` only for the exact documented
log-delivery control-plane actions; it has no log-content read, other wildcard
action or public execution authority. The independent verifier rejects any
broader wildcard.

The stack requires exact, same-account deployment inputs for both cells:

- target Region and real handler role ARN;
- audit bucket ARN;
- exactly four DynamoDB table ARNs;
- signing KMS key ARN;
- one to four queue ARNs;
- third-Region journal table name and ARN; and
- third-Region security alert topic ARN.

Partition and account come from the exact journal ARN, never ambient CDK
credentials. Primary and recovery resource maps cannot alias each other.

## Code-owned dependency boundaries

Operators and UI payloads may select only the dependency name. They may never
supply IAM actions, resources, policy JSON, role names or probe commands. The
controller derives these from exact provider-discovered target resources and a
code-owned map. Every deny policy is named from the fault UUID, affects only the
target handler role and is rejected if any other Regional fault policy exists.

Both primary and recovery cell stacks now export
`RegionalFaultTargetExecutionRoleArn` from the actual control-handler Lambda
role. The active and passive cell verifiers require that output to resolve via
`Fn::GetAtt` to one IAM role used by exactly one handler with the expected cell
role. A missing, substituted, worker or literal role identity fails synthesis
verification. This is deployment-owned discovery input; it is not fault
execution authority by itself.

The provider boundaries are:

| Dependency | Target-only failure boundary | Recovery proof |
| --- | --- | --- |
| Audit | Exact target audit write path | Content-free canary write succeeds after restoration |
| Cognito | Unsupported: authentication is outside the handler role | Unsupported: fails before mutation |
| DynamoDB | Exact target handler access to four authoritative tables | Consistent canary reads and governed agent heartbeat recover |
| KMS | Exact target signing/verification key calls | Target policy signing and enrolled verification recover |
| Queue | Exact target evidence/retention queue operations | Revision-bound synthetic job dispatch and zero-conflict check recover |

A mocked error flag is not dependency evidence. The witness-region probe
directly invokes the exact target control-plane Lambda with a non-HTTP internal
event. The operation therefore runs under the same handler role receiving the
deny. Only real AWS `AccessDenied`/`AccessDeniedException` observations satisfy
the outage phases; recovery requires a successful provider operation with
digest-bound, content-free evidence. Queue probes use a dedicated one-day
canary queue and never contaminate evidence-worker traffic.

The IAM boundary implementation currently enables `audit`, `dynamodb`, `kms`
and `queue`. `cognito` fails closed before IAM mutation: API Gateway validates
target Cognito tokens outside the Lambda execution role, so attaching a handler
deny would be false evidence rather than an identity failure exercise.

## Threats and controls

| Threat | Control | Failure posture |
| --- | --- | --- |
| Fault targets serving source | Direction, cell role, source fence and active-not-routed proof | Workflow not started |
| Operator supplies broad IAM deny | Dependency name only; actions/resources are code-owned and provider-derived | Request rejected |
| Fault survives caller crash | Step Functions compensation plus separately armed Scheduler watchdog | Automatic exact cleanup |
| Two faults overlap | One active Regional fault policy and workflow execution per target | Later request rejected |
| Old approval is replayed | Exact approval digest/principals, transition digest and short expiry | Authority rejected |
| Runtime changed after review | Exact processed-template digest and live runtime verification | Workflow not started |
| Cleanup removes another fault | UUID-derived exact policy identity and authority digest | Cleanup rejected |
| Simulated flag self-certifies outage | Real provider denial and independent synthetic route probe | Evidence rejected |
| Recovery is assumed after delete | Live provider and target-route recovery checks | Workflow remains failed/alerted |

## Operator usage

Keep both files outside source control:

```bash
python3 scripts/plan_aws_regional_fault_exercise.py \
  --manifest /secure/path/activation-draft.json \
  --fault-authority /secure/path/dynamodb-fault.json
```

Exit code `0` prints `faultExecuted: false`, a canonical authority digest and
the compensated plan. Exit code `2` prints the first blocker. There is no
confirmation or execute flag because this tranche is read-only.

## Synthesis and verification

The dedicated `regional-fault-controller-iac` CI job installs the pinned CDK
lock, synthesizes the stack and runs
`scripts/verify_regional_fault_controller_stack.py`. The verifier requires the
exact 18-state order, all compensation edges, bounded retries, explicit manual
non-Cognito readiness status, three isolated Lambda identities, one schedule
group, one encrypted DLQ, five alarms, the exact eight-file Lambda asset,
exact journal/role/probe IAM and zero public execution grants.
Adversarial tests reject a precondition bypass, missing compensation, broad IAM,
ambient probe authority, authority-bearing API resource, unsafe log capture,
weakened DLQ, changed templates, runtime drift, partial source fencing, early
routing and falsely ready status.

## Current non-guarantees

The authority parser, exact target-handler discovery, live precondition reader,
code-owned IAM boundaries, single-writer lock, Scheduler creation, expiry-safe
cleanup handlers, target-role canaries and private compensated Step Functions
topology are implemented and synthetically tested. They are not deployed. The
stack deliberately creates no API/UI route or `states:StartExecution` grant;
production execution authority must be separately restricted to the reviewed
operator workflow. The precondition reader uses narrowly enumerated read-only
AWS APIs, several of which require `Resource: *`; runtime validation binds every
observation to the approved account, Regions, stack names, processed-template
digests, hosted zone and journal state. Cognito remains unsupported rather than
simulated. No live fault has been injected and no recovery SLO is claimed.
The generic AWS exercise adapter therefore continues to reject dependency and
consistency evidence, and P0-11 remains **Partial**.
