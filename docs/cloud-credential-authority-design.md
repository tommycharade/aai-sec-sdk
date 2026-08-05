# Cloud credential authority

This design provides short-lived, least-privilege cloud credentials to an
already-authorized agent action. It supports AWS STS, Microsoft Entra workload
identity for Azure, and Google Cloud workload identity without placing cloud
secrets in policy, model context, project files, browser state, or audit data.

The feature is an adapter boundary, not a universal cloud login. A deployment
must still create provider roles, trust relationships, token-exchange clients,
network controls, and a revocation source.

## Threat and invariant

Long-lived credentials in an agent process can be copied, replayed, widened,
or exfiltrated. The invariant is therefore:

> A credential may be minted only after action authorization and remains usable
> only for the exact provider, principal, audience, tool, resources, scopes,
> lifetime, broker revision, and live revocation epoch that were approved.

Model output cannot select a principal, audience, policy, provider client,
revocation result, or credential value. Provider tokens remain behind the
`ScopedCredential.with_secret()` capability and are not serializable.

```text
validated action + host identity + live policy
                    |
                    v
        exact CloudScopePolicy match
                    |
                    v
     deployment-owned token exchange client
                    |
                    v
   private ScopedCredential capability registry
                    |
                    v
      handler callback + live revocation check
```

## SDK contract

`CloudWorkloadCredentialBroker` is provider-neutral. The Azure and GCP named
brokers narrow construction to their respective provider. Each broker accepts:

- an immutable `CloudScopePolicy` with exact principal, audience, scopes,
  allowed tools, allowed resources, and maximum lifetime;
- an injected `CloudTokenExchangeClient`; and
- an injected revocation checker.

The exchange client receives a `CloudProviderGrant` only after scope
validation. It returns a `ProviderToken`; it must not return identity or policy
claims for the SDK to trust. The broker rejects policy widening, malformed
lifetimes, provider mismatch, wrong tools/resources and failed revocation
checks before a token becomes usable.

`AwsStsCredentialBroker` applies the same live-revocation property to AWS STS.
Its grant identity contains the role session name and a hash of the access-key
identifier, never the secret or session token.

AWS STS has a 900-second provider minimum, so AWS registrations and SDK mints
reject shorter lifetimes rather than presenting a five-minute SDK capability
around a still-valid fifteen-minute provider token. Azure and GCP may use
60-second registrations. Every provider response is rejected if its own
validity exceeds the requested maximum.

## Hosted control-plane authority

The hosted control plane separates human configuration from machine evidence:

1. A platform administrator registers a secret-free broker configuration in
   **Connect agents → Cloud credentials**. Registration is blocked by default.
2. A separately issued service identity with only
   `credential_broker_runtime` submits fresh adapter evidence.
3. The server binds that evidence to the tenant, broker ID, configuration
   hash, provider, principal, audience, exact tool/resource lists, maximum TTL,
   revision, revocation epoch, and server clock.
4. The machine authority route returns `executionAllowed: true` only while the
   broker is active and the exact evidence is fresh.
5. A human revocation atomically advances revision and revocation epoch. Old
   evidence can no longer authorize new grants.

An incident case can additionally create an exact-agent credential control.
`RevocationAwareCredentialBroker` checks that authority before and after mint
and before every credential callback. It applies across all current and future
registered brokers for that agent without changing policy or exposing a token.
Recovery is server-gated; see [Incident-driven credential
revocation](incident-credential-revocation-design.md).

Human browser authority cannot submit provider evidence. Machine authority
cannot register, widen, or revoke a broker. Evidence older than five minutes,
or with a validity period beyond fifteen minutes, fails closed.

The local SQLite control plane deliberately shows registrations as
`unverified` and `executionAllowed: false`: it tests schema, tenant isolation,
and lifecycle but does not impersonate a cloud provider.

## Operator journey

The UI displays registration posture separately from runtime authority. An
operator can see exact scope, principal, audience, TTL, configuration digest,
revision, revocation epoch, evidence age and evidence expiry. The registration
form is typed, provider-aware, and contains no secret field. Its submit action
is labelled **Register — keep blocked**.

Revocation requires an accountable reason and warns that callback-checked
active credentials are blocked on their next use; provider work already in
flight may still complete. The UI does not claim a registration is usable
until fresh machine evidence exists.

## Guarantees and non-guarantees

The implementation guarantees closed schemas, exact scope checks, bounded
lifetimes, tenant isolation, content-minimised evidence, live callback checks,
and fail-closed behavior for stale, missing, malformed, revoked, or
unavailable authority.

It does not prove that a cloud role is least privilege, terminate provider
sessions already executing, secure the provider's own token endpoint, replace
a sandbox, or provide hardware-backed workload identity. Network policy,
provider IAM review, secret-manager configuration and live cloud acceptance
remain deployment responsibilities.

## Production acceptance

For each provider, retain evidence that:

1. the registered principal and audience match a reviewed production role;
2. an allowed synthetic action receives only its approved scopes/resources;
3. a widened scope, wrong tool, wrong resource and wrong tenant are denied;
4. expiry blocks use without relying on browser state;
5. revocation blocks a new mint and a callback-checked active credential;
6. provider outage and revocation-check failure deny authority;
7. no credential appears in UI responses, logs, policy, telemetry, or audit;
8. role permissions and token lifetime are independently reviewed.

Until those exercises are run against customer-approved AWS, Azure and GCP
accounts, P0-09 remains **Partial**.
