# Production isolation authority

## Status

This design implements the P0-10 product and SDK foundation. It does **not**
claim that a customer host, Docker daemon, microVM service, WASM runtime, or
endpoint sandbox has passed an independent production escape assessment.
P0-10 therefore remains **Partial** until the selected deployment boundary and
its host assumptions complete live acceptance.

## Outcome

An operator can register a reviewed isolation profile, select it in a governed
policy, observe whether fresh runtime evidence matches it, and revoke it. A
protected SDK tool executes only when the host supplies evidence that is:

- bound to the authenticated tenant, principal, agent, task, purpose, tool,
  resources, and one-use nonce;
- signed or otherwise authenticated by a deployment-owned verifier;
- fresh and shorter-lived than policy ceilings;
- tied to an immutable workload digest and exact profile digest;
- one of the explicit profiles and boundary kinds accepted by policy; and
- still live according to the deployment revocation source.

Registration is desired state, not execution authority. The hosted control
plane derives `executionAllowed`; the browser cannot set it.

## Threat and trust-boundary review

| Threat | Control | Remaining assumption |
| --- | --- | --- |
| A model claims it used a sandbox | Evidence comes only from the registered handler and host-owned verifier | The host integration must keep evidence credentials away from the model and worker |
| A weaker sandbox is substituted | Policy selects exact reviewed profile digests and boundary kinds | Reviewers must assess whether the selected boundary is suitable for the workload |
| A mutable image changes after review | Workloads require an immutable `sha256:` content reference | Registry and host content-addressing must be correctly operated |
| Evidence is replayed for another action | The action binding hashes principal, tenant, agent, task, purpose, tool, resources, and nonce | The trusted issuer must include the SDK-provided binding unchanged |
| Old evidence is reused | Issued time, expiry, age, TTL, revision, and revocation epoch are checked | Clocks and the live revocation source must be trustworthy |
| Browser operators forge proof | Human routes register/revoke; only `isolation_runtime` machine identities submit evidence | Service-identity credentials must be protected and rotated |
| Network, filesystem, process, or resource policy is omitted | The profile uses a closed typed constraint schema and mandatory safeguards | Platform adapters must prove actual enforcement, not merely echo configuration |
| Sandbox proof is valid but launch controls differ | `DockerSandboxToolHandler` refuses profile/launch mismatch before runtime use | Other adapters must provide the same exact binding contract |
| Evidence leaks a signing secret | UI and audit views contain identifiers and digests only | Provider-specific transport must redact proof material before telemetry export |

The host remains the execution authority. The control plane governs profile
lifecycle and posture; it does not remotely create a local sandbox by itself.

## Architecture

```text
operator UI                  hosted control plane            enrolled runtime
    |                                |                              |
    | register desired profile       |                              |
    |------------------------------->| status = unverified          |
    | select profile in policy       |                              |
    |------------------------------->| validate exact reference     |
    |                                |                              |
    |                                |<-- machine profile evidence --|
    |                                | derive verified/stale/revoked |
    |                                |                              |
    |                                |<-- read live authority -------|
    |                                |                              |
    |                                |                    proposal + nonce
    |                                |                    platform attestation
    |                                |                    exact profile verify
    |                                |                    permit or fail closed
```

The runtime verification path does not depend on a browser response. A
deployment adapter supplies trusted profile and revocation data directly to
`ProductionIsolationVerifier`; the hosted posture API supports central
operations and evidence monitoring.

## Typed SDK model

### `IsolationConstraints`

Every profile declares:

- read-only filesystem;
- no network or an exact destination allow-list;
- isolated process namespace;
- memory, PID, CPU, and duration ceilings;
- no credentials or brokered-only credentials;
- no new privileges; and
- dropped capabilities.

The SDK rejects zero, negative, ambiguous, duplicated, wildcard, or
effectively unbounded values. The UI and hosted API additionally make the
read-only filesystem, process namespace, no-new-privileges, and dropped-
capabilities safeguards immutable.

### `IsolationProfile`

A profile binds a stable profile ID, provider, boundary kind, positive
revision, immutable workload digest, and complete constraints. Its
`configuration_digest` changes if any execution-affecting field changes.

Container, microVM, WASM, and endpoint sandbox are separate boundary kinds.
They are intentionally not represented by a universal numeric strength: a
policy lists reviewed profile digests and permitted boundary kinds explicitly.

### `IsolationAttestation`

Compatibility fields support the original callback verifier. Production
verification additionally requires issued time, evidence ID, profile digest,
workload digest, exact action binding, signature, and key ID. Legacy callback
evidence is visibly labelled and cannot satisfy a
`ProductionIsolationVerifier` requirement.

Issuers and verifiers use `isolation_attestation_payload()` as the canonical
schema-versioned UTF-8 signing payload. It covers every authority-bearing
claim and excludes only the signature, preventing provider integrations from
silently signing different field subsets or encodings.

### `IsolationVerification`

The verifier returns a structured result instead of an ambiguous boolean. A
successful result retains only the provider, boundary, evidence ID, profile
digest, workload digest, verification time, and expiry. The execution permit
and redacted `action_executed` event retain that identity; signatures and proof
material are excluded.

## Live Docker adapter

`DockerSandboxToolHandler` supports an optional exact profile and a
deployment-owned attestation provider. When enabled, construction fails unless
the profile matches the handler's immutable image digest and launch controls.
The fixed invocation includes:

- no shell expansion;
- `--network=none`;
- a read-only root filesystem;
- all Linux capabilities dropped;
- `no-new-privileges`;
- non-root UID/GID `65532`;
- explicit memory, PID, and CPU limits;
- a bounded, non-executable, non-setuid temporary filesystem;
- bounded wall-clock wait and output size; and
- no credential field in the worker payload.

This proves a real container integration contract, not Docker daemon or host
kernel security. Host hardening, daemon authorization, seccomp/AppArmor or
SELinux configuration, runtime patching, and independent escape assessment
remain deployment evidence.

## Control-plane lifecycle

Human `platform-admin` authority can:

1. register a secret-free profile;
2. review posture and immutable configuration identity; and
3. revoke a profile with an audited reason and optimistic revision.

A service identity with only `isolation_runtime` can:

1. read exact current authority; and
2. submit short-lived evidence for the current profile revision.

It cannot register, weaken, or revoke profiles. A human identity cannot submit
runtime evidence. Evidence must match the full current configuration and the
closed check set:

- boundary created;
- workload digest verified;
- filesystem enforced;
- network enforced;
- process controls enforced;
- resource limits enforced;
- credential isolation enforced; and
- escape probe passed.

Missing, false, extra, future-dated, stale, overlong, mismatched, cross-tenant,
or concurrently outdated evidence is rejected. Evidence expiry and revocation
make `executionAllowed` false using the server clock.

The local SQLite control plane supports tenant-scoped registration and
revocation for development. It always reports `unverified` and
`executionAllowed: false`; local persistence cannot impersonate platform
evidence.

## Policy and managed-agent journey

1. Open **Connect agents → Isolation profiles**.
2. Register one immutable workload and restrictive controls. The button says
   **Register — keep blocked**.
3. Issue a machine identity with only `isolation_runtime`.
4. Deploy the selected platform adapter and submit short-lived proof.
5. Confirm **Boundary verified**, the evidence expiry, profile digest,
   workload digest, revision, and revocation epoch.
6. Open the policy editor and select the profile under **Accepted isolation
   profiles**.
7. Submit, independently approve, stage, and activate the policy normally.
8. Confirm the enrolled runtime receives the managed profile and fails closed
   when evidence becomes missing, stale, mismatched, or revoked.

Policy composition intersects accepted profile IDs. Components cannot widen a
local policy to a profile that every contributing policy did not accept. An
empty intersection is valid fail-closed authority.

## Evidence and observability

Security events are content-minimised and correlate:

- profile registration, configuration hash, actor, and revision;
- machine verification, evidence digest, observation, and expiry;
- runtime action, exact profile/workload digest, boundary, and evidence ID;
- stale or rejected evidence reason;
- profile revocation, actor, reason, revision, and revocation epoch; and
- policy versions and agent groups that accept the profile.

Audit events never record a signing key, signature, credential, worker input,
or untrusted worker output as isolation proof.

## Failure behaviour

The action is denied before handler execution when:

- the handler has no attestation provider;
- evidence is malformed, missing, stale, expired, future-issued, or too long-
  lived;
- any action binding differs;
- the profile or workload digest differs;
- policy does not accept the exact profile or boundary;
- signature verification fails or raises;
- revocation checking returns false or raises; or
- the profile is missing, stale, disabled, or revoked centrally.

There is no fallback to subprocess execution, a weaker profile, cached browser
state, or a handler-provided boolean.

## Acceptance evidence and remaining production work

| P0-10 criterion | Repository evidence | Production evidence still required |
| --- | --- | --- |
| Verify boundary before execution and record identity/configuration | Production verifier, structured permit evidence, redacted action audit, attested Docker contract | Live selected platform adapter and retained customer run evidence |
| Escape, network, filesystem, process and exhaustion denied/contained | Docker probe, exact control contract, adversarial mismatch/outage/replay tests | Independent hostile-code suite against production host and runtime |
| Missing, stale or weaker evidence fails closed | SDK, hosted API and tenant-contract tests | Customer SLO measurement and outage exercise |
| Independent assessment covers boundary and host assumptions | Required and documented | Named independent assessor, scope, findings, remediation and approval |

Before changing P0-10 to Complete, retain:

- selected production boundary and workload-risk rationale;
- immutable runtime and worker versions;
- host/daemon/runtime hardening configuration;
- escape, forbidden network, filesystem, process, credential, and resource-
  exhaustion results;
- evidence expiry, replay, outage, revocation, and rollback results;
- platform owner and security approver sign-off; and
- independent assessment report and remediation disposition.
