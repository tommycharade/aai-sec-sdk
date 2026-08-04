# Policy editor

The Policy editor is a UI-first editor for what an agent is allowed to do. A
policy is a versioned, validated, tenant-scoped declaration that can be
assigned to one or more enterprise groups. The runtime remains the authority: the model cannot
change a policy, approval, identity, credential, or isolation decision.

## Design rules

- Use typed form sections and validated fields; arbitrary JSON is an expert
  workflow, not the primary user experience.
- Deny by default and require explicit allow-lists.
- Evaluate policy with the live action, resource, principal, purpose and policy
  version on every consequential action.
- Show a complete effective-policy preview before saving or activating.
- Version every change, retain an audit record, and support comparison and
  rollback through the enterprise control plane.
- Policy values may narrow authority but must never disable SDK invariants such
  as fail-closed authorization, approval replay protection or redaction.

## Policy fields

The editor presents these sections as typed form groups:

1. Identity and scope
2. Tool permissions
3. Claude native-tool controls
4. Command rules
5. Approval rules
6. Resource limits
7. Credential requirements
8. Isolation requirements
9. Data capture and redaction
10. Review, validation and versioning

| Feature | What the editor should configure |
| --- | --- |
| Local allow-list policy | Allowed tools, principals and resources. |
| OPA policy adapter | A policy-provider reference; endpoint and credentials belong in the wider UI. |
| Cedar policy adapter | A policy-provider reference; endpoint and credentials belong in the wider UI. |
| Allowed tools | Explicit registered-tool allow-list. Unknown tools remain denied. |
| Allowed principals | Identities that may perform actions under this policy. |
| Approval requirements | Which tools, resources, risk classes or command patterns require approval. |
| Scoped approval grants | Required binding to action, resource, principal, purpose and policy context. |
| Approval expiry | Maximum approval time-to-live. |
| Claude command rules | Command patterns that are allowed, denied or approval-required. |
| Claude built-in tool allow-list | Native Claude tools such as Read, Glob, Grep, Bash, Edit and Write. |
| Action budget | Maximum actions per task or session. |
| Concurrency limit | Maximum simultaneous actions. |
| Fan-out limit | Maximum delegated or parallel branches. |
| Cost budget | Maximum model or tool cost units. |
| Delegation depth | Maximum recursive delegation depth. |
| Rate limit | Maximum actions per second. |
| Execution timeout | Maximum operation duration. |
| Timed-out worker limit | Maximum timed-out workers before further work is denied. |
| Credential scope enforcement | Required action, resource, principal and purpose scope. |
| Credential TTL | Maximum permitted credential lifetime for actions under this policy. |
| High-risk isolation requirement | Whether high-risk actions require verified isolation evidence. |
| Sensitive-data redaction | Mandatory redaction profile and protected fields. |
| Tool-content capture | Disabled, metadata-only or bounded content capture. Default: restrictive. |
| Safe default configuration | A restrictive starting template for new policies. |

## Provider references versus policy decisions

The editor may select a provider or reference an external policy, but it must
not contain provider secrets or pretend to own an external policy engine. The
wider UI owns provider endpoints, authentication, health and deployment
configuration. The runtime consumes the resulting policy decision and fails
closed when the provider is unavailable or returns an invalid result.

## Policy inventory, detail and activation

The Policy page opens on the current-policy inventory. Each row shows the
policy name and identifier, current version, author, date written, number of
groups and number of enrolled agents receiving it. Select a row to open the
policy detail view.

The detail view shows the stored configuration as a human-readable summary
grouped into policy sections, along with the groups assigned to it and the
total affected-agent count. Choose **View JSON** when raw configuration
inspection is needed, or **Edit policy** to open the typed form.
Saving validates the configuration and creates an immutable pending draft; it
does not change fleet authority. The author submits it, a different subject
approves or rejects with rationale, an approver stages the exact version, and
explicit activation atomically replaces the active central policy. A cancel
action leaves the current version unchanged.

## Review and activation

The editor shows an effective-policy preview before saving. The preview must
include allowed actions, denied actions, approval-required actions, maximum
limits, credential and isolation requirements, redaction/capture behaviour, and
the groups and agents affected by the policy.

Before activation, display:

- tools and principals allowed;
- tools, commands and resources denied;
- approval-required actions;
- action, time, cost, concurrency, rate and delegation limits;
- credential and isolation requirements;
- redaction and content-capture behaviour;
- groups and agents affected by the policy.

The pending-version view also shows a semantic authority diff and a bounded
historical simulation. The diff calls out newly expanded or restricted
authority, approval changes, limits, credential/isolation requirements and
data-capture changes. Simulation uses only retained redacted evidence. It shows
determinate coverage and never guesses the result of a redacted shell command
or an MCP call whose server identity was not retained. The activation dialogue
opens only after a simulation has been run for the exact pending content hash
and selected lookback window.

Saving a policy is not the same as activating it. Activation should be an
explicit, audited operation with validation, version selection and a clear
rollback path.

## Time-limited exceptions

Temporary exceptions are managed separately beneath the policy inventory. The
typed workflow selects one exact enrolled agent, loads its sole group and
current base policy, and permits temporary edits only to SDK tools, Claude
built-in tools, registered Skills/MCP servers, command allow/deny/approval
patterns and the maximum-action budget. Identity scope, approval provider,
credentials, isolation, data capture, telemetry and redaction remain inherited
and the API repeats this closed-field validation.

Every request includes an accountable owner, business purpose and expiry from
15 minutes to seven days. A different authenticated policy approver must
approve it. Activation creates a distinct KMS-signed derived policy bundle;
the UI then shows its exact scope, semantic authority diff, lifecycle evidence
and server-clock countdown. Expiry, revocation, agent/group reassignment or a
base-policy change restores the normal signed policy automatically. The UI
does not describe an approved draft as applied and does not treat an active
control-plane exception as endpoint-convergence evidence.

## Reuse, inheritance and Git

Reusable policy components are exact independently approved policy versions,
never mutable “latest” pointers. The editor shows local intent separately from
the effective restrictive composition and explains which component produced or
narrowed every field. Git import creates a draft only; provider-observed review
and signature evidence cannot replace normal independent control-plane
approval. See [Policy composition and GitOps](policy-composition-and-gitops-design.md).

## Out of scope

The editor must not expose switches for security invariants such as dynamic
tool lookup, bypassing the runtime, trusting model-supplied identity,
disabling approval replay protection or disabling mandatory redaction.

## Advanced JSON

Expert users may inspect and edit the generated JSON representation. Applying
advanced JSON first parses the document, validates the closed policy schema and
maps it back into the typed editor. Unknown sections, unknown fields, invalid
budget values, `denyByDefault: false`, attempts to disable redaction and
immutable safeguard fields are rejected before submission. The backend repeats
its own validation; browser validation is only an early usability check.
