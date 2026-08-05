# Enterprise console navigation

## Decision

The console presents seven stable operator workspaces: **Overview**, **Fleet**,
**Rollouts**, **Incidents**, **Policy**, **Evidence** and **Admin**. This replaces
an eighteen-destination sidebar whose Monitor, Control and Administration
categories forced operators to understand the implementation before choosing a
task.

The change affects presentation and routing only. It does not alter SDK policy,
operator authorization, agent authority or control-plane APIs.

## Route ownership

| Workspace | Default route | Contextual routes |
| --- | --- | --- |
| Overview | `#overview` | Overview |
| Fleet | `#fleet` | Groups, Agents, Coverage, Connect agents |
| Rollouts | `#administration` | Deployments; its internal rollout and runtime-release views remain unchanged |
| Incidents | `#incidents` | Cases, Approvals, Workflows |
| Policy | `#policy` | Policies, Skills & MCP |
| Evidence | `#audit` | Decision history, Assurance |
| Admin | `#trust` | Identity & access, API access, Webhooks, Data boundaries, SDK runtime |

The sidebar opens the default route. A contextual tab changes the existing hash
route. Loading an existing route directly derives and highlights its owning
workspace without rewriting the hash. Entity routes such as
`#agents/agent/<id>` keep their object focus.

## Trust boundary and secure behavior

The route map is code-owned. Control-plane data can populate a page, but cannot
add, remove or remap security controls in navigation. Unknown hashes retain the
existing fail-safe behavior and open Overview. Authorization remains a
server-side decision on every read and mutation; hiding or showing a tab is not
an authorization control.

This design guarantees:

- exactly seven primary navigation choices;
- retention of every existing console destination;
- bookmark, refresh and browser-history compatibility;
- visible current-workspace and current-destination state; and
- usable narrow-screen navigation without document-level overflow.

It does not guarantee that a backend integration is configured, that a user is
authorized to mutate a resource, or that live enterprise acceptance has passed.
Those states must remain explicit in the destination page.

## Operator journeys

### Connect a Claude Code deployment

1. Open Fleet.
2. Select Connect agents.
3. Complete the guided enrollment and first-decision proof.
4. Return to Agents or Groups without leaving the Fleet workspace.

### Investigate and respond

1. Open Incidents and select a case.
2. Use Approvals when the held action—not the agent—is the response object.
3. Use Workflows to inspect delivery to the configured external case system.
4. Open Evidence when retained decision or assurance proof is required.

### Change policy safely

1. Open Policy and edit a typed policy.
2. Select governed Skills & MCP resources from the same workspace.
3. Submit and activate through the existing independent-review lifecycle.
4. Open Rollouts to monitor deployment convergence.

## Verification

Automated UI tests count the seven sidebar controls, assert their exact labels,
exercise every changed operator journey, and prove legacy deep-link selection.
The full UI quality gate runs TypeScript checks, all component and adversarial
tests, and a production build. Browser acceptance covers desktop and 390-pixel
mobile layouts, current-state accessibility and document overflow.
