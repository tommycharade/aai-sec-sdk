# Enterprise Claude Code rollout plan

**Status:** next delivery goal
**Scope:** real Claude Code deployment on the operator's device, followed by
enterprise-readiness evidence
**Deferred:** SIEM, PagerDuty and external SOC alert integration

## Objective

Prove that the SDK can be onboarded to a real Claude Code project, centrally
managed through the control plane, and safely operated through the complete
lifecycle:

```text
onboard → verify → assign policy → enforce → monitor → change → stop → recover
```

The test must use the actual Claude Code process and project configuration on
the operator's device. Synthetic API and MCP tests remain useful supporting
evidence, but they cannot be the only acceptance evidence.

## Explicit scope decision

SIEM, PagerDuty and external SOC routing are parked for a later goal. They are
not required to complete this device-validation goal, and the product must not
claim that external incident routing is available. Local audit evidence,
control-plane alerts and emergency-stop response remain in scope.

Parking this integration does not waive the other enterprise safeguards. The
rollout remains blocked for consequential enterprise workloads until identity,
runtime authority, credential scope, isolation, resilience, scale and audit
requirements are evidenced.

## Work plan

### 1. Prepare the device test environment

- Confirm the supported Claude Code version and installation path.
- Select a disposable test project with synthetic files and no credentials.
- Confirm the SDK branch, release/version and control-plane endpoint.
- Use a dedicated test tenant, deployment ID and agent ID.
- Confirm the user can sign in to the hosted control plane and has the required
  operator role.
- Capture a clean baseline of the project's Claude configuration before
  onboarding.

The test must never use production repositories, real secrets, destructive
commands or unredacted personal data.

### 2. Onboard Claude Code

- Run the documented onboarding script from the selected project root.
- Verify that existing Claude configuration is preserved and backups are made.
- Verify `.claude/settings.json`, `.claude/aai-sec-config.json` and `.mcp.json`.
- Confirm no bearer token or credential is written to project files.
- Start Claude Code from the expected project root.
- Confirm the `agentic-security` MCP server is visible with `/mcp`.
- Verify the agent appears in the hosted Enterprise UI with the expected
  deployment, project and identity metadata.

### 3. Prove policy enforcement with Claude Code

Execute a safe, synthetic test matrix through the real Claude Code session:

| Test | Expected result | Evidence |
| --- | --- | --- |
| Allowed read-only action | Executes successfully | Claude output, SDK decision and audit event |
| Denied native tool/action | Does not execute | Denial reason and audit event |
| Approval-required action | Pauses and requires the matching approval | Approval request, decision and audit event |
| Wrong or replayed approval | Does not execute | Failed authorization evidence |
| Unknown tool or malformed arguments | Fails closed | SDK test result and audit event |
| Out-of-scope project path | Denied | Path/resource decision evidence |
| Budget or timeout boundary | Admission stops at the configured limit | Runtime result and audit event |
| Missing or expired identity/policy | Fails closed | Host and control-plane evidence |

The test runner should produce a machine-readable report and a redacted human
summary. Each result must identify the policy version, agent, action category,
expected result, observed result and evidence reference.

### 4. Prove central management

From the hosted UI:

- create or select a safe policy;
- create a group and assign the policy;
- add the enrolled Claude Code agent to the group;
- verify the effective policy shown for the agent;
- change the group policy and observe the desired/applied state;
- verify heartbeat and policy refresh from the real deployment;
- remove the agent from the group and confirm the resulting fail-closed state;
- record all mutations in the control-plane audit trail.

The UI must show clear loading, stale, denied and empty states. A missing API
response must not appear as a healthy empty enterprise page.

### 5. Prove rollout and emergency response

- Stage a policy or integration change to the test agent.
- Confirm the rollout status and version transition in the UI.
- Activate an agent-level emergency stop.
- Attempt a consequential synthetic action through the real Claude Code path.
- Confirm the action is blocked and the stop state is visible.
- Verify the deployment authority's process/credential response where the local
  adapter supports it; otherwise record the limitation explicitly.
- Clear the stop only after explicit confirmation.
- Run post-stop synthetic verification and confirm recovery evidence.
- Roll back to the known-good configuration and verify convergence.

### 6. Review enterprise gaps

After the device test, classify every result as:

- **Pass:** demonstrated against the real host with retained evidence;
- **Conditional:** works in the reference path but needs deployment-owned
  proof;
- **Fail:** the control is absent, bypassable or unclear;
- **Deferred:** intentionally excluded from this goal, currently SIEM/PagerDuty/
  SOC routing only.

No conditional result may be presented as production certification.

## Exit criteria

This goal is complete only when:

1. the real Claude Code project is onboarded reproducibly;
2. allowed, denied, approval, replay, malformed, scope and limit behaviours are
   demonstrated through the real host;
3. the agent is centrally grouped and policy-managed through the UI;
4. rollout, drift/heartbeat, emergency stop, recovery and rollback are tested;
5. redacted audit evidence is retained for each consequential test;
6. all defects found are fixed or explicitly accepted as deployment-owned;
7. the hosted UI and onboarding instructions are updated to match reality;
8. SIEM/PagerDuty/SOC integration is recorded as deferred, not silently omitted;
9. a final enterprise rollout decision identifies what remains blocked.

## What remains blocked after this goal unless separately proven

- enterprise-wide consequential use without production SSO/MFA/RBAC evidence;
- credentialed or destructive actions without real broker and IAM evidence;
- hostile-code workloads without a stronger isolation boundary;
- fleet-scale rollout without measured capacity, convergence and DR evidence;
- external SOC alert routing until the deferred integration goal is completed.

## Follow-on goal

Implement and validate enterprise incident integrations: SIEM export, PagerDuty
or equivalent on-call routing, alert ownership, retry semantics, incident
linkage and end-to-end recovery exercises.
