# Regional dependency fault controller

## Decision

Regional dependency failure testing requires a server-managed compensation
workflow. A local script that attaches an IAM deny and later removes it is not
acceptable: process termination, network loss or operator interruption could
leave the target cell unavailable indefinitely.

`scripts/plan_aws_regional_fault_exercise.py` implements the first read-only
authority boundary. It validates one exact request and emits the mandatory
workflow order. It has no IAM, Lambda, Scheduler, Step Functions, DNS or traffic
mutation operation.

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

The implementation phase will use a Step Functions workflow for normal and
exception compensation plus an EventBridge Scheduler one-time watchdog. The
watchdog must be armed before the deny is applied and must invoke cleanup even
if the workflow, caller or network disappears. Normal cleanup can remove the
watchdog only after independently proving the deny no longer exists.

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

The final provider implementation must define a real safe probe for each
dependency:

| Dependency | Target-only failure boundary | Recovery proof |
| --- | --- | --- |
| Audit | Exact target audit write path | Content-free canary is durably written and read back |
| Cognito | Exact target identity dependency, never source/customer identity | Target canary authentication succeeds after restoration |
| DynamoDB | Exact target handler access to four authoritative tables | Consistent canary reads and governed agent heartbeat recover |
| KMS | Exact target signing/verification key calls | Target policy signing and enrolled verification recover |
| Queue | Exact target evidence/retention queue operations | Revision-bound synthetic job dispatch and zero-conflict check recover |

A mocked error flag is not dependency evidence. The controller must observe a
real provider denial produced by its exact target boundary and independently
observe recovery after removal.

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

## Current non-guarantees

The authority parser, plan and exact target-handler role discovery are
implemented and synthetically tested. The Step Functions controller, watchdog,
code-owned IAM boundaries and real dependency probes are not yet implemented.
No live fault has been injected.
The generic AWS exercise adapter therefore continues to reject dependency and
consistency evidence, and P0-11 remains **Partial**.
