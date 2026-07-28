# Enterprise user journeys

These journeys describe the intended low-friction workflow for a central
security or platform team managing many agent deployments.

## Journey 1: Onboard an agent

**Actor:** Platform engineer or local developer using an approved enrollment
link.

1. Open **Agents → Add agent**.
2. Select Claude Code, Codex CLI or GitHub Copilot Agent.
3. Choose the organization, project/repository and deployment environment.
4. Select an existing group or choose **Create group and policy**.
5. Copy the generated one-command installer, or run it through the approved
   deployment mechanism.
6. Review the files, commands and SDK version that will be changed.
7. Run the installer from the target project/workspace.
8. Return to the UI and select **Verify enrollment**.
9. The UI checks host configuration, authenticated identity, heartbeat, policy
   assignment and a synthetic safe/approval/denied action set.
10. The agent becomes **Healthy**, **Needs attention** or **Blocked** with an
    explanation and next action.

Success means the agent is registered, assigned to a group, reporting the
expected policy version and passing verification. A local configuration file
alone is never shown as enrolled.

## Journey 2: Create and assign a policy

**Actor:** Central security administrator.

1. Open **Policies → Create policy**.
2. Use the typed sections for identity/scope, tools, Claude controls, command
   rules, approvals, limits, credentials, isolation and data handling.
3. Review the effective-policy preview.
4. See affected groups and agent counts before saving.
5. Save as a new version with a change reason.
6. Select **Validate** to run schema, safety and compatibility checks.
7. Choose **Stage to group** and select a canary percentage.
8. Review the rollout diff and affected deployments.
9. Activate the canary and wait for health/synthetic verification.
10. Expand the rollout or pause and roll back.

The user should never need to construct JSON for normal operation. Advanced
JSON remains available only behind an expert option and must map back through
the same typed validation.

## Journey 3: Manage groups

**Actor:** Central platform administrator.

1. Open **Enterprise → Groups**.
2. Create a group with a clear name, owner and purpose.
3. Select the policy version that applies to the group.
4. Filter the agent inventory by host, environment, region or status.
5. Add agents individually or by a reviewed bulk selection.
6. Review the effective policy and expected impact.
7. Confirm the membership change.
8. Monitor enrollment, drift and health from the group detail view.

Membership changes must be audited and must not silently alter an active
session. New actions are evaluated against the live authority.

## Journey 4: Monitor the enterprise

**Actor:** Security operations engineer.

The dashboard should answer, without navigation:

- How many agents are healthy, degraded, offline or blocked?
- Which groups have policy drift?
- Which deployments have failed verification or rollout checks?
- How many actions were allowed, denied or awaiting approval?
- Are audit, telemetry, credential and isolation dependencies healthy?
- Which agents have not heartbeated within the expected window?

From the dashboard, the operator can open a filtered fleet view, group view,
agent detail, audit event or deployment rollout without losing the active
filters.

## Journey 5: Respond to an incident

**Actor:** Security operations engineer.

1. Open the alert or suspicious audit event.
2. Review the agent, deployment, group, policy version, action, resource and
   evidence chain.
3. Choose **Stop deployment**, **Stop group** or **Stop agent** according to
   the incident scope.
4. Confirm the action and record the incident reason.
5. The UI shows the stop state and affected agents immediately.
6. Revoke or rotate dependent credentials through the configured broker.
7. Roll back the policy or SDK configuration if the change is implicated.
8. Run a synthetic verification before clearing the stop.
9. Clear the stop only with explicit confirmation.
10. Export the redacted incident evidence and retain the audit reference.

The UI should make the safe response the shortest path, while requiring
stronger confirmation for broader scope and irreversible actions.

## Journey 6: Upgrade an integration

**Actor:** Platform engineer.

1. Open **Integrations → Host profiles**.
2. Select the host and target SDK version.
3. Review compatibility warnings and generated configuration diff.
4. Stage the upgrade to a canary group.
5. Verify host connection, policy enforcement and runtime health.
6. Expand, pause or roll back.

The upgrade view must separate SDK version, host configuration version and
policy version so operators can identify which change caused a failure.
