# Product Owner review: enterprise Claude Code rollout

**Review date:** 2026-07-27
**Decision owner:** Product Owner
**Target outcome:** safe, centrally managed, enterprise-wide Claude Code rollout

## Executive decision

The product has a credible security foundation and a useful control-plane
direction, but it is not yet ready for an unrestricted enterprise-wide Claude
Code rollout.

I recommend a **conditional go for a design-partner rollout** and a **no-go
for broad production rollout** until the launch gates in this document have
deployment evidence. The distinction matters: most remaining blockers are not
missing UI fields. They are proof that the control plane is connected to the
real Claude Code process, identity, credential, isolation, incident and
enterprise operations systems.

The product should now be Claude Code-first. Codex CLI and GitHub Copilot
Agent remain important integration targets, but exposing all three as equal
first-class experiences before Claude Code is proven increases complexity and
weakens the rollout story.

## Product outcome

An enterprise security or platform team must be able to:

1. onboard a Claude Code project with a repeatable, scoped installer;
2. assign it to a centrally managed group and policy;
3. see whether the agent is enrolled, healthy, current and enforcing;
4. roll out changes progressively with a visible desired-versus-applied state;
5. stop an affected agent, group or deployment and prove what stopped;
6. route and own the resulting incident;
7. produce redacted, immutable evidence of the decision and response.

The UI is successful when an operator can answer “what needs attention, what is
the safe next action, and what evidence proves the result?” without understanding
the SDK's internal adapter model.

## Feedback disposition

| Feedback or concern | Product decision | Priority |
| --- | --- | --- |
| Emergency stop may not revoke credentials or terminate the real process | Treat stop as incomplete until the live deployment authority proves process termination, credential revocation and recovery verification | P1 launch gate |
| No acceptance evidence with actual Claude Code binaries and supported versions | Add a host acceptance suite and supported-version matrix; synthetic MCP tests alone are insufficient | P1 launch gate |
| Alerts are not yet connected to enterprise SOC ownership | Park PagerDuty/SIEM/SOC routing for a follow-on goal; retain local alerts, acknowledgement and audit evidence in this rollout | Deferred |
| Production SSO, federation and mandatory MFA are not proven | Require enterprise IdP integration, MFA policy, RBAC and tenant-bound authorization before broad rollout | P1 launch gate |
| Provider/tool IAM proof is synthetic or reference-only | Run least-privilege simulations for every production credential/tool role | P1 launch gate |
| Control-plane DR and fleet-scale performance are not proven | Define target fleet size, RTO/RPO, load tests and failure exercises | P1/P2 |
| Enrollment does not establish device/binary provenance | Add approved host identity and binary/version attestation or document an accepted compensating control | P2 |
| Investigation workflow is basic | Add searchable, filterable evidence, ownership, incident linkage, export and bulk response | P2 |
| UI is becoming complicated | Simplify information architecture and use progressive disclosure; do not reduce policy editor capability | P1 product usability |
| Claude, Codex and Copilot are presented together | Make Claude Code the primary rollout path; keep other hosts behind integrations until their acceptance criteria are met | P1 scope control |

## Recommended information architecture

The current model has useful capabilities, but “Enterprise fleet” is carrying
too much of the product and “Agents” overlaps with it. The recommended top-level
navigation is:

| Primary area | What it owns | Primary users |
| --- | --- | --- |
| **Overview** | Actionable fleet health and items needing attention | Everyone |
| **Fleet** | Unified deployments, projects, groups and agents | Platform, SecOps |
| **Rollouts** | Desired/applied versions, canaries, pauses and rollback | Platform |
| **Incidents** | Alerts, ownership, emergency stops and recovery | SecOps |
| **Policy** | Typed policy editor and effective-policy preview | Security admin |
| **Evidence** | Audit, compliance evidence, exports and release proof | SecOps, auditors |
| **Admin** | Identity, integrations, runtime dependencies and tenant settings | Platform admin |

The policy page remains the detailed, typed editor. It should not be flattened
or replaced with a simpler JSON screen.

The existing `Agents`, `Integrations`, `Settings` and `Audit trail` destinations
should become either Fleet subsections, Admin subsections or Evidence tabs. This
removes navigation duplication without removing capability.

### Overview requirements

The landing page should contain only information that leads to an action:

- healthy, degraded, offline, blocked and stopped agent counts;
- policy drift and failed verification counts;
- pending or paused rollouts;
- open incidents and unowned high-severity alerts;
- control-plane dependency health;
- a “Needs attention” queue with a direct next action.

Avoid placing configuration forms, provider choices or long technical status
lists on Overview.

### Fleet requirements

Fleet should use one hierarchy:

```text
organization → project → deployment → Claude Code agent
```

The list must support search, saved filters and bulk selection by team,
environment, region, version, group, policy, drift, heartbeat and health. A
detail page should show identity, last heartbeat, policy/version state, recent
verification, active stop state and links to rollout and evidence. It should
not duplicate policy authoring controls.

### Rollouts requirements

Every rollout should show, before confirmation:

- target groups/deployments and agent count;
- policy, SDK and host configuration versions;
- current versus desired state;
- canary percentage and health criteria;
- required approvals and change reason;
- pause and rollback conditions.

The live view should make convergence explicit: `staged`, `canary`, `active`,
`paused`, `rolling back`, `converged`, `drifted` or `failed`.

### Incidents requirements

Incidents should be an operational queue, not another audit table. Each row
needs severity, state, owner, first/last seen, affected scope, policy or
deployment version, and a direct response. Operators need acknowledge, assign,
link to an incident record, stop the smallest safe scope, view evidence and run
post-stop verification. Clearing a stop must require explicit confirmation and
show the recovery checks.

### Admin requirements

Move infrequent, high-risk or deployment-owned configuration here:

- SSO, MFA, roles and tenant settings;
- Claude Code host profiles and onboarding defaults;
- Codex and GitHub Copilot integrations;
- policy/approval/audit/credential/isolation providers;
- retention, telemetry and notification destinations.

Admin pages should be role-gated and should clearly label settings that are
only references until a deployment-owned adapter is connected.

## User journey changes

### First Claude Code deployment

The shortest supported path should be:

1. **Onboard deployment** from Fleet.
2. Select Claude Code, project, environment and owner.
3. Select an existing group and policy, or use a safe default.
4. Review the exact files and commands that will change.
5. Copy/run the scoped installer.
6. Return to the wizard and run verification.
7. See heartbeat, policy, synthetic allowed/approval/denied checks and host version.
8. Finish with the deployment in `pending`, `healthy` or `blocked`, with one next action.

Do not make a user visit Integrations, Agents, Enterprise and Settings to
complete this journey.

### Policy change

The existing Policy journey is retained:

1. create a typed policy;
2. review effective behavior and affected groups;
3. validate and version it;
4. start a canary rollout from the affected-group action;
5. monitor convergence in Rollouts.

The policy editor should link into rollout review, but should not absorb fleet
operations.

### Incident response

An operator should be able to go from Overview alert to action in three clicks
or fewer: open incident, inspect affected scope/evidence, stop or assign.
Recovery and export can follow from the incident detail page.

## Enterprise launch gates

Broad rollout should be blocked until all of the following are demonstrated in
the target AWS deployment, using real Claude Code hosts where applicable:

1. **Authentication and authorization:** enterprise SSO/federation, mandatory
   MFA, tenant isolation, role separation and audit of privileged operations.
2. **Claude Code acceptance:** supported-version matrix, real project-scoped
   onboarding, upgrade, restart, offline and rollback tests.
3. **Runtime authority:** an emergency stop terminates or disables the actual
   Claude Code execution path and revokes dependent credentials; clearing it
   requires successful verification.
4. **Policy convergence:** desired/applied policy, SDK and host configuration
   state is visible and reaches a defined SLA at the target fleet size.
5. **Incident operations:** local high-severity alerts, acknowledgement,
   emergency response and retained ownership/evidence are proven. External
   SOC/on-call routing is explicitly deferred to a follow-on goal.
6. **Least privilege:** every production tool and credential role has a
   recorded allow/deny simulation and a negative cross-tenant/cross-agent test.
7. **Resilience:** control-plane backup/restore, RTO/RPO, dependency outage,
   queue failure and fleet-scale load evidence are retained.
8. **Evidence:** an auditor can retrieve a redacted chain for onboarding,
   policy change, rollout, stop, recovery and operator identity.
9. **Release integrity:** the hosted UI authentication fix and all rollout
   components are committed, tagged, reproducibly built and deployed from the
   release artifact.

The launch review should record the target fleet size and heartbeat/convergence
SLO rather than accepting “works at small scale” as evidence.

## Prioritised roadmap

### Now: remove enterprise rollout blockers

- Finish the real Claude Code host acceptance harness and version matrix.
- Bind emergency stop to the production process supervisor and credential broker.
- Complete SSO/MFA/RBAC and privileged-action review.
- Connect and test SOC/PagerDuty/SIEM routing and ownership.
- Define and test the initial fleet scale, convergence SLO and DR objectives.
- Commit, tag and redeploy the current hosted UI/authentication fix.
- Consolidate the UI navigation around Overview, Fleet, Rollouts, Incidents,
  Policy, Evidence and Admin.

### Next: make operations efficient at scale

- Add saved filters, bulk remediation/quarantine and maintenance windows.
- Add searchable investigation cases, comments, incident links and exports.
- Add device/binary attestation and drift remediation workflows.
- Add rollout health trends and automatic pause/rollback criteria.
- Add role-specific dashboards and operator workload views.

### Later: broaden the platform

- Promote Codex CLI and GitHub Copilot Agent only after host-specific acceptance.
- Add stronger isolation options such as microVM/WASM where required.
- Add advanced enterprise reporting and optional commercial operational features.

## Product acceptance criteria for the simplified UI

- A new operator can identify the highest-priority issue from Overview in under
  30 seconds.
- A platform engineer can onboard one Claude Code deployment without visiting
  more than one guided flow.
- A security administrator can create and validate a policy without leaving the
  Policy page.
- A SecOps operator can stop the smallest affected scope from Incidents and
  locate the retained evidence without knowing API endpoint names.
- A fleet operator can filter and bulk-select agents without confusing agent,
  deployment, group and policy scope.
- Advanced configuration remains available to administrators but is hidden
  from normal operator workflows.
- Every destructive or broad operation shows scope, impact, confirmation and
  recovery state.
- Empty, loading, stale and permission-denied states explain what the user can
  do next; no blank enterprise page is acceptable.

## Final PO recommendation

Prioritise **enterprise Claude Code operations** over breadth. Keep the strong
typed Policy experience, reduce the rest of the UI to a small set of operational
surfaces, and make every remaining capability reachable from the relevant
object or incident. Approve a controlled design-partner rollout now only where
the deployment-owned controls are explicitly bounded. Do not describe the
product as ready for enterprise-wide consequential use until the nine launch
gates have retained evidence.

## Resolution update — 2026-08-05

The approved information architecture is now implemented in the UI branch.
The sidebar contains exactly seven primary workspaces: Overview, Fleet,
Rollouts, Incidents, Policy, Evidence and Admin. The previous peer destinations
are preserved as contextual tabs:

- Fleet owns Groups, Agents, Coverage and Connect agents;
- Incidents owns Cases, Approvals and Workflows;
- Policy owns Policies and Skills & MCP;
- Evidence owns Decision history and Assurance; and
- Admin owns Identity & access, API access, Webhooks, Data boundaries and SDK
  runtime.

Deployments remains the focused Rollouts destination and keeps its existing
internal rollout and runtime-release views. Every prior hash route remains
valid, and a regression test proves a legacy Data boundaries deep link selects
Admin without changing the route. This resolves the navigation-consolidation
item; it does not by itself satisfy the live host, identity, provider, fleet
scale or disaster-recovery acceptance gates above.
