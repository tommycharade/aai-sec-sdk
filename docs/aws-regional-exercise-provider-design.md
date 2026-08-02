# AWS Regional recovery exercise provider

## Outcome and trust boundary

`scripts/run_aws_regional_recovery_exercise.py` is the first live AWS adapter
for the bounded Regional recovery harness. It measures the target cell through
the authenticated agent routes used by managed Claude Code and Codex hosts:

1. `POST heartbeat` validates enrolled identity, project root, runtime
   attestation and managed configuration, then renews the session;
2. `GET effective-policy` proves current signed policy delivery; and
3. `POST decisions` writes deterministic, content-free, replay-safe evidence
   bound to the transition and exact enrolled agent.

The generic harness—not the adapter—calculates population completeness, p99
latency, error rate and acceptance. The adapter cannot return an aggregate pass
assertion. Its dependency and consistency methods deliberately fail until the
separate fault-controller authority is implemented.

## Synthetic fleet authority

Pre-enrolled sessions are stored only in AWS Secrets Manager in the transition
target Region and the same account as the dedicated routing role. The secret is
limited to one MiB and has this exact schema:

```json
{
  "schemaVersion": 1,
  "transitionId": "00000000-0000-4000-8000-000000000000",
  "authoritySha256": "<schema-v4 transition authority digest>",
  "targetRegion": "eu-west-1",
  "apiBaseUrl": "https://api-recovery.example.com",
  "agents": [
    {
      "agentNumber": 0,
      "deploymentId": "synthetic-deployment-0",
      "agentId": "synthetic-agent-0",
      "accessToken": "<short-lived synthetic session token>",
      "projectRootSha256": "<synthetic project-root digest>",
      "heartbeat": {}
    }
  ]
}
```

Agent numbers must form the exact range from zero to fleet size minus one;
deployment/agent pairs must be unique. The URL must be HTTPS with no port,
path, query, credentials or fragment and exactly equal the target Region's
schema-v4 canary domain. Transition UUID, authority digest, Region and fleet
size must match. Heartbeat bodies are bounded to 128 KiB and contain only the
synthetic attestation and managed-configuration evidence required by policy.

Do not place this JSON in source control, shell history, evidence output or
operator chat. The command requests only `AWSCURRENT`; output contains
latencies and counts, never tokens, heartbeat content or policy content.

## Network and replay controls

- TLS certificate validation uses the operating-system trust store.
- Redirects are disabled so a target response cannot forward a bearer token.
- Responses are bounded to one MiB; requests have a 0.1–30-second timeout.
- A failed heartbeat stops before policy or decision calls; a failed policy
  read stops before decision write.
- Renewed heartbeat tokens remain only in process memory.
- Decision ID and action digest are SHA-256 over transition authority plus the
  deployment and agent identity, so retries use server duplicate handling.
- The server derives tenant, policy, version and observation time and marks the
  record as agent-reported evidence.

## Operator usage

Run only against a prepared, active-but-not-routed target canary with synthetic
agents enrolled, assigned exactly one policy and reporting current attestation
and managed configuration:

```bash
python3 scripts/run_aws_regional_recovery_exercise.py \
  --manifest /secure/path/activation-draft.json \
  --synthetic-fleet-secret-arn \
    arn:aws:secretsmanager:eu-west-1:111111111111:secret:aai/regional/fleet-AbCdEf \
  --profile p1 \
  --max-workers 64
```

Exit code `0` prints only the verified `load` section accepted by the generic
harness. Exit code `2` reports the first blocker. A synthetic contract test is
not live load evidence; the customer run must retain this output with complete
dependency, consistency, backup and operations sections.

## Fault-controller design gate

Dependency injection must not be generic AWS mutation code. The next boundary
requires a schema-bound exercise role that affects only the
active-but-not-routed target cell and one synthetic tenant. It must apply one
fault at a time, prove target denial and source continuity, restore exact
template-bound state, and verify recovery before advancing. DNS, Global Table
data, source-cell IAM, customer identity and signing-key material remain outside
that role. Until this exists, `exercise_dependency` and
`exercise_consistency` fail closed.

## Threats and controls

| Threat | Control | Failure posture |
| --- | --- | --- |
| Secret from another exercise is replayed | UUID, authority digest, Region/domain and fleet binding | Secret rejected |
| Bearer token is redirected | HTTPS-only URL and disabled redirects | Request fails |
| One credential represents multiple agents | Complete numeric range and unique identities | Fleet rejected |
| Failed heartbeat is hidden by later success | No later calls and maximum failed latency | Aggregate exercise fails |
| Decision retry creates duplicate evidence | Deterministic digest and server idempotency | Exact duplicate only |
| Adapter self-certifies unavailable controls | Dependency/consistency methods raise | Complete exercise cannot pass |

## Current non-guarantees

The implementation is contract-tested but has not run against the live AWS
target. It does not provision agents, generate attestation/managed evidence,
inject dependency failures, prove backup/key recovery or move traffic. P0-11
remains **Partial**.
