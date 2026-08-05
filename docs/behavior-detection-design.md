# Explainable agent behavior detection

This design adds a production-shaped slice of P1-SOC-06 and P1-SOC-07 to the
hosted control plane. It extends the existing independently reviewed response
rule ledger with an **alert-only** agent-activity rule. It does not let
agent-reported telemetry quarantine an endpoint automatically and it does not
claim that the parked Splunk stub delivers these alerts.

## Customer outcome

Security operations can define a typed, versioned rule for Claude Code and
Codex activity, preview the current baseline, route the exact immutable version
through two-person approval, and activate it. A matching rule creates one
deduplicated alert that explains:

- the observed signal and affected enrolled agent;
- the current-window count;
- the historical baseline count and normalized expected count;
- the configured threshold and sensitivity multiplier;
- whether the baseline was complete enough to evaluate; and
- the rule version and content hash that produced the result.

The catalogue covers newly observed tools, newly observed MCP servers,
denied-action spikes, approval-request spikes, overall decision-volume spikes,
outside-project activity and configuration errors. Independently derived
repository and configuration integrity signals use their own alert-only trust
boundary rather than being mixed with agent-reported behavior.

## Trust boundaries

Agent decision reports are authenticated, content-minimised observations, not
authorization facts. The control plane derives tenant, deployment, agent,
host, policy version and server time from the live enrolled session. MCP server
identity may be reported only as a bounded identifier and is retained as an
untrusted observation. It is never used to grant execution authority.

Behavior rules therefore have a fixed `create_alert` action. They cannot use
the automatic `quarantine_agent` action reserved for independently derived
endpoint evidence. A human incident responder may open a case and apply the
existing case-owned quarantine after reviewing the evidence and confirming the
server-owned enrolled-agent binding.

The model, endpoint and browser cannot choose a tenant, agent, policy,
timestamp, alert identifier, rule version, baseline result or threshold
outcome.

## Closed rule language

An agent-activity configuration contains only:

- source `agent_activity`;
- one or more fixed signal types;
- Claude Code and/or Codex host scope;
- alert severity;
- a 1–30 day historical lookback;
- a 5–60 minute current window;
- 1–2,000 minimum historical events;
- 1–100 minimum current events;
- a 1.5–10.0 sensitivity multiplier;
- fixed action `create_alert`; and
- deterministic evaluation priority.

Signal lists use OR semantics. Host scope and the selected signal use AND
semantics. Unknown fields, empty sets, non-finite numbers and out-of-range
values fail closed.

## Baseline and evaluation

The evaluator reads at most 2,000 observations from a DynamoDB
`BehaviorAgentTimeline` partition whose key is the exact tenant and enrolled
agent. One noisy agent therefore cannot consume another agent's history bound.
Decision and agent approval-request observations share the partition and are
retained for the maximum 30-day behavior lookback; approval capability expiry
continues to use the separate `expires_at` authority field.

The secondary index is eventually consistent. When an authenticated report
causes an evaluation, the handler merges the just-persisted, server-derived
observation directly into that evaluation so index propagation cannot omit the
triggering action. Earlier observations can still take a short time to appear.
This can delay an alert but cannot grant authority: behavior rules are
alert-only, and the fleet readiness API labels this consistency model.

Existing records do not contain the sparse-index keys. A conditional,
tenant-owned migration marker starts a 30-day safety window in which each
exact-agent index result is merged with the bounded legacy tenant timeline.
Any index, legacy or combined truncation marks that agent incomplete and
produces no anomaly claim. After the maximum retention window, only the
exact-agent index is authoritative.

The evaluator uses server receipt time and splits evidence into a current
window and an immediately preceding historical window. A truncated history,
missing or hash-invalid active rule version, malformed retained evidence or
insufficient historical sample produces a content-minimised
`baseline_insufficient` outcome and no alert.

For volume signals, the expected current count is the historical matching
count normalized to the current-window duration. The threshold is the larger
of `minimumCurrentEvents` and `ceil(expected × multiplier)`. New-tool and
new-MCP signals require the observed identity to be absent from the historical
window and to reach `minimumCurrentEvents` in the current window.

One deterministic alert identity binds tenant, rule version, signal, agent,
window start and the SHA-256 digest of the observed dimension. Re-evaluation
cannot create duplicates. Raw prompts, arguments, commands, paths, tool output,
credentials and approval rationale are never retained in the alert.

## Governance and operator journey

The existing rule lifecycle remains `draft -> review -> approved -> active`.
The author cannot approve their own version. Activation compares the exact
active base version, and active versions are immutable. Disabling a rule
immediately removes future detection authority; restoring a superseded version
uses the existing audited rollback path.

The evidence source is immutable for the lifetime of a rule ID. A later
version cannot convert `agent_activity` into `endpoint_evidence` and thereby
upgrade an alert-only identity into automatic containment. Operators must
create and independently review a distinct rule for a different trust boundary.

The Incidents workspace presents **Detection & response rules**. The editor
first asks whether the rule is endpoint containment or behavior detection,
then shows only controls valid for that trust boundary. The preview reports
baseline readiness, matches and thresholds without creating alerts or changing
agent authority. Every control includes contextual help.

The Incidents workspace also provides a paginated **Behavior baselines** view.
The control plane, not the browser, returns each active agent's `ready`,
`warming`, `incomplete` or `not_configured` posture, event bounds, migration
state and rule-by-rule minimum sample progress. The response deliberately
excludes prompts, arguments, results, credentials, project paths and tool
identities. Operators are warned about incomplete history and eventual index
consistency instead of being shown false reassurance.

## Alert, case and delivery behavior

Behavior alerts use the same open, acknowledged and case-owned lifecycle as
endpoint alerts. Their agent binding is derived from the authenticated decision
record and revalidated against current lifecycle, group and policy state before
any case response. The UI distinguishes agent-reported activity from
independently derived endpoint posture.

Each newly materialized window-bound alert enters the existing durable SNS/SQS
operations channel and tenant webhooks when the destination explicitly
subscribes to `behavior.alert.opened`. A later window produces a new
deterministic alert; it never mutates earlier behavior evidence into a reopened
occurrence. Splunk remains `deliveryVerified: false`.

## Failure modes and non-guarantees

- An offline, tampered or bypassed host may omit activity. Runtime attestation,
  managed configuration and complete discovery remain separate P0 controls.
- A behavioral match proves that retained reports crossed a configured
  threshold; it does not prove malicious intent.
- A missing or incomplete baseline yields no alert and an explicit degraded
  result; the system never fabricates normal behavior.
- The readiness view may briefly trail newly reported activity because its
  exact-agent secondary-index reads are eventually consistent. The triggering
  action is merged synchronously only in the alert evaluator.
- Alert-only rules do not widen or automatically remove agent authority.
- The first catalogue does not close repository/configuration anomaly,
  third-party credential revocation, MDM/EDR isolation or SIEM delivery.

## Required evidence

Tests must cover strict schema validation, two-person governance, baseline
normalization, insufficient/truncated history, new identities, spike
thresholds, exact host scope, idempotent alerts, tenant isolation, untrusted MCP
identity, alert acknowledgement, case binding, manual containment, webhook
schema, redaction and disabled/rolled-back versions. The full repository and UI
quality gates must pass before deployment.
