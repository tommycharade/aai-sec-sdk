# Incident-driven credential revocation

This design lets an incident responder remove brokered cloud authority from one
server-bound Claude Code or Codex agent without editing policy or handling a
credential. It implements the software foundation of P1-SOC-04 and strengthens
the P0-09 cloud credential boundary.

## Security invariant

> A case may narrow credential authority only for its current exact agent
> binding. The browser, model and runtime cannot choose that identity, broker
> scope, revocation state or recovery result.

The control plane re-derives the case binding for every mutation. A request
contains the case revision and binding digest, but never an agent ID or broker
list. Revocation applies to every current and future registered broker for the
bound agent, preventing a newly registered broker from bypassing an active
response.

```text
case + current server binding
             |
             v
 exact-agent credential control ----> retained case timeline
             |
             v
 machine-only live authority check
       | deny            | allow
       v                 v
 no mint/use        scoped broker mint
                           |
                  live check before use
```

## SDK contract

`RevocationAwareCredentialBroker` wraps any provider-neutral
`CredentialBroker`. It asks an injected `CredentialAuthorityChecker` for an
exact `agent_key`, broker ID and credential scope:

1. immediately before a credential is minted;
2. immediately after the provider returns it; and
3. before every `ScopedCredential.with_secret()` use.

`ACTIVE` permits the next step. `REVOKED`, `UNAVAILABLE`, malformed decisions
and checker failures deny authority. The wrapper preserves the provider
credential's ID, exact scope and lifetime while composing—not replacing—its
existing validity callback. It can therefore narrow authority but cannot
widen the provider broker's policy or lifetime.

A provider operation already executing cannot be recalled by this SDK. The
next callback-checked use and every new mint are blocked. Deployment adapters
must not unwrap a credential once and retain its secret outside the callback.

## Hosted control-plane contract

The hosted AWS control plane provides:

```text
POST /api/enterprise/cases/{caseId}/credentials/revoke
POST /api/enterprise/cases/{caseId}/credentials/restore
POST /machine/v1/enterprise/credential-brokers/{brokerId}/authority/check
```

Revocation requires `incident_response`, the live case revision, current
binding digest and a bounded redaction-safe rationale. The server records a
case-owned control with its exact agent key, revision, actor, time and an
evidentiary snapshot of active broker IDs. Enforcement intentionally covers
future brokers as well as that snapshot.

The authority check is available only to a service identity with
`credential_broker_runtime`. It accepts a closed, typed request and derives
tenant, broker registration and control state from storage. Human Cognito
sessions cannot call it. Machine identities cannot create or clear incident
controls. Denied checks retain only fixed reason data and a request digest—not
the credential, secret or token.

## Recovery

Restoration is a separate optimistic-concurrency mutation. It fails closed
unless:

- the case still has the same exact current binding;
- the credential-control revision is current;
- no case quarantine or independent fleet, deployment, group or agent stop is
  active;
- all normal server-owned agent verification checks pass; and
- the source posture alert is resolved, or the event alert is acknowledged or
  resolved.

An active credential control blocks case resolution and closure. The UI can
request recovery but cannot override a failed check.

## Operator experience

The incident workspace shows credential authority separately from quarantine
and session revocation. It identifies the exact agent, whether the control is
live, the broker snapshot and the consequence for new mints and active
callback-checked credentials. The confirmation explains that an already
in-flight provider request may complete. Restore remains unavailable while
quarantine is active.

## Test and acceptance boundary

Automated contracts prove exact-agent and cross-tenant isolation, current and
future broker denial, machine/human capability separation, stale-revision
denial, case-transition blocking, recovery gates, content minimisation and SDK
pre-mint/post-mint/use-time fail-closed behavior.

This does not complete P0-09 production acceptance. Each customer must still
exercise approved real AWS, Azure and GCP roles, provider expiry and outage,
least privilege, callback discipline and measured revocation latency. Provider
work already in flight remains outside the SDK's recall boundary.
