# Approved automatic response rules

This design implements the first production-shaped slice of P1-SOC-02 and
P1-SOC-06. It permits an independently approved, versioned endpoint detection
rule to create a case and quarantine exactly one authoritatively correlated
Claude Code or Codex agent. It never grants authority, selects a browser-
supplied target, disables evidence collection or claims device isolation.

## Customer outcome

Security teams can author a typed rule, preview it against current retained
alerts, submit it for independent review and activate an immutable version.
When a matching server-derived endpoint detection occurs, the control plane:

1. re-derives a unique current endpoint-to-agent binding;
2. applies the rule's rate and cooldown safeguards;
3. creates a deterministic retained incident case owned by that rule version;
4. creates case-owned investigative quarantine for the exact bound agent; and
5. retains a content-minimised, content-hashed execution outcome and emits the
   corresponding audit event.

The agent can continue sending heartbeat and attestation evidence, but policy,
approval, decision-reporting and managed-package authority fail closed. Release
remains a deliberate incident-response action guarded by live recovery checks.

## Deliberately bounded rule language

Version one is a typed form, not executable code or a general expression
language:

- source is fixed to `endpoint_evidence`;
- reason codes come from the server-owned endpoint detection catalogue;
- severities are selected from `medium`, `high` and `critical`;
- host scope is `claude-code`, `codex`, or both;
- action is fixed to `quarantine_agent`;
- `maxActionsPerHour` is between 1 and 25; and
- `agentCooldownSeconds` is between 300 and 86,400.

All selected reason codes and severities use OR semantics within their field;
fields use AND semantics. Empty selections are rejected. Session or brokered-
credential revocation is not bundled into version one: those stronger actions
remain explicit until P1-SOC-04 supplies independently tested credential-
broker adapters.

## Governance lifecycle

Each rule has one mutable summary and immutable version records. A version
moves through `draft`, `review`, `approved`, `active`, `superseded` or
`rejected`. Its author cannot approve it. Activation requires an independently
approved version based on the current active version. Activating a replacement
atomically supersedes the old version. An authorized operator can immediately
disable the active rule because reducing automatic authority must not wait for
a new approval cycle; re-enabling requires activation of an approved version.

`security-operator` and `platform-admin` may author and independently approve
rules. `incident-responder` can read rules and executions but cannot establish
new autonomous authority. Delegated or upstream Entra claims do not directly
grant these capabilities; Cognito's canonical product roles remain the source
of authorization.

## Evaluation and idempotency

Evaluation runs after scheduled endpoint reconciliation and after authenticated
endpoint security-event materialization. Active rules are ordered by priority
then stable rule ID. One execution identity binds tenant, rule version, alert
ID and alert occurrence. It is written once and is safe to retry.

Only an uncased alert can be claimed. If a prior invocation created the exact
rule-owned case but stopped before quarantine or outcome persistence, a retry
may resume that same operation. A rule never takes over an operator-owned case
or a case owned by another rule. Later matching rules retain a skipped outcome
with an explicit reason.

## Fail-closed safeguards

Automatic containment is skipped and evidenced when any of these is true:

- the rule is disabled, unapproved, malformed or stale;
- the alert no longer matches the active immutable version;
- endpoint evidence is stale, unmanaged, absent or correlates to zero or more
  than one active agent;
- the active-version or alert occurrence changed;
- the hourly rule limit or per-agent cooldown is reached;
- another case already owns the alert;
- the agent lifecycle is inactive or another quarantine already owns it; or
- transactional case or containment persistence fails.

Limits are evaluated from strongly read, bounded tenant records. Exceeding the
safe tenant bound fails the evaluation rather than silently ignoring older
actions.

Hourly and cooldown authority is reserved in one conditional DynamoDB
transaction before case mutation. A concurrent trigger may consume the final
slot, forcing the loser to re-read and skip. A dependency failure after
reservation conservatively consumes that slot and cooldown; it can reduce
automation but cannot permit the rule to exceed its approved authority.

The authoritative case timeline and response-execution record are retained in
DynamoDB. Object-store audit replication is separate: an audit-export failure
does not erase an already committed quarantine, and the content-hashed response
record remains available for reconciliation. This release does not claim a
transaction spanning DynamoDB and S3.

## Preview and operator journey

Preview never creates a case or containment. It returns current matching alerts
with the derived binding status and one of: `would_contain`,
`binding_unavailable`, `already_cased`, `hourly_limit`, or `agent_cooldown`.
The UI explains the resulting SDK authority, shows exact safeguards and makes
the independent approval boundary visible before activation.

The Incidents workspace has separate **Cases** and **Response rules** views.
The rules view starts with governed inventory and health metadata, then opens a
focused detail/editor with active version, pending change, recent outcomes,
preview, submit, approve, activate and disable actions.

Operator reads may reconcile alert presentation but never invoke automatic
containment. Consequential evaluation is reached only from the five-minute
scheduled detector or an authenticated endpoint-security event write.

## Non-guarantees

Quarantine is an SDK/control-plane authority restriction. It does not kill a
process, isolate a laptop, block network traffic, revoke a third-party token or
prove that an offline endpoint received the change. Splunk remains a clearly
labelled non-delivering stub. MDM/EDR isolation, credential-broker revocation,
portable rule signatures and anomaly baselines remain separate requirements.

## Acceptance evidence

Contracts must prove two-subject approval, immutable active versions, exact
matching, preview without mutation, idempotent retries, deterministic ordering,
hourly and cooldown limits, tenant isolation, unbound/ambiguous denial, no case
takeover, quarantine authority, manual recovery gates and secret-free evidence.
AWS acceptance must use real DynamoDB numbers and a real Lambda invocation,
verify the exact agent is denied execution after automatic containment, release
the synthetic quarantine through the guarded path, and remove every synthetic
control record.
