# Enterprise user journeys

These journeys describe the intended low-friction workflow for a central
security or platform team managing many agent deployments.

## Journey 0: Connect Microsoft Entra ID

**Actor:** Enterprise identity or platform administrator.

1. Open **Identity and access**. The overview shows the verified foundations
   and directs an unconfigured tenant to **Entra setup**.
2. Register a single-tenant Entra application using the displayed Cognito
   redirect URI and bind pilot administrators to an MFA-enforcing Conditional
   Access policy.
3. Create separate OIDC and SCIM secrets in AWS Secrets Manager. Neither value
   is pasted into the browser.
4. Download the secret-free deployment manifest and populate the Entra tenant,
   client, secret-resource names, AAI tenant and retained Conditional Access
   evidence reference outside the repository.
5. Copy and run the read-only preflight, reviewed-reference persistence and
   guarded deployment commands from the setup workspace.
6. Configure Entra automatic provisioning with the deployed SCIM endpoint.
7. Open **Directory & roles**, confirm current lifecycle evidence, and map
   exact provisioned groups to the smallest canonical roles.
8. Exercise a joiner, mover and leaver, including one permitted and one denied
   API action for each role transition.
9. Use **Emergency access** for the separate two-person recent-MFA exercise and
   **Access reviews** to export the digest-bound certification artifact.

Success means OIDC, SCIM lifecycle, role transition, role denial and
independently approved emergency access have live retained evidence. A
downloaded manifest, configured identity provider or successful synthetic
SCIM contract alone is never displayed as acceptance.

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

### Journey 4a: Establish population coverage

**Actor:** Endpoint, identity, or security operations engineer.

1. Configure deployment-owned identity, endpoint, and source-control collectors.
2. Publish complete, short-lived snapshots through source-scoped authority.
3. Open **Coverage** and confirm all required sources are current.
4. Review the expected Claude Code and Codex denominator before using any
   percentage.
5. Investigate unmanaged or duplicate instances, inactive owners/users, and
   active enrollments absent from the expected inventory.
6. Connect a missing agent or use the Agents lifecycle controls for a verified
   leaver or orphan.
7. Export the content-hashed report for assessment evidence.

If any source is missing, incomplete, or stale, the journey stops at source
recovery. The UI must not present a percentage or recommend destructive action
from absence alone.

## Journey 5: Respond to an incident

**Actor:** Security operations engineer.

1. Open **Incidents** and select an uncased endpoint alert.
2. Record an investigation rationale to create a retained case.
3. Review the server-derived endpoint-to-agent binding, policy, groups,
   evidence age and timeline. If the binding is missing, ambiguous or changed,
   response controls remain disabled; the operator cannot select an agent.
4. Choose **Quarantine execution** for the exactly bound agent. This withholds
   SDK execution authority but preserves heartbeat and attestation evidence.
5. Revoke the agent's existing sessions when compromise is plausible.
6. Use independent fleet, deployment, group or agent stops only when the
   incident scope requires them. Clearing one control does not clear another.
7. Remediate the endpoint, policy or SDK configuration and acknowledge or
   resolve the source alert as appropriate.
8. Select **Release quarantine**. The server rechecks binding, endpoint health,
   agent verification, independent stop scopes and alert readiness.
9. Resolve and then close the case; the revisioned timeline remains retained.
10. Select **Export verified JSON**. The console asks the control plane for the
    complete bounded package, verifies its canonical SHA-256 digest locally and
    only then creates the download. It shows the retained digest and counts.
11. Run `python3 scripts/verify_incident_case_export.py FILE.json` from a
    trusted SDK checkout before sharing or importing the package elsewhere.
12. Compare the receipt digest with the immutable audit record when chain of
    custody matters. Use MDM/EDR separately if device, process or network
    isolation is required.

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

## Journey 7: Govern durable evidence

1. Open **Evidence**. Do not use the decision table as proof until the assurance
   banner has completed its live object-version verification.
2. Confirm **Integrity verified**, **Retention**, **Legal holds**, **Delete
   markers** and inventory completeness match the records schedule.
3. To extend retention, select the longer period and enter the approved records
   schedule/change reference. The control plane extends all bounded existing
   versions before changing future-record policy; it refuses reductions.
4. Select one retained version to place or release legal hold. Confirm the exact
   object version and provide the approved legal authority. The rationale is
   hashed rather than stored as case narrative.
5. Choose **Export verified manifest**. The API refuses partial or mismatched
   evidence, and the browser independently verifies the canonical digest before
   download.
6. Use **Decision evidence** below the assurance controls for redacted runtime
   investigation. Tool arguments, credentials and sensitive output are not
   included.

For more than 250 retained versions, the current synchronous path deliberately
shows `incomplete` and blocks export/retention mutation. Never accept a sampled
UI list as the complete tenant record.
