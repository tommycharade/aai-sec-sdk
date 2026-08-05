# Synthetic Intune continuation acceptance — 2026-08-05

## Outcome

The maximum supported 500-target continuation scenario passed against the
production Intune delivery handler and its production page, prune, assignment
and continuation functions. The test began with 500 desired devices and 81
stale group members. It reached `assigned_reported` only after exact membership
convergence and one required assignment.

This is deterministic **synthetic control evidence**. Microsoft Graph, AWS
queues, DynamoDB, Secrets Manager and S3 were replaced by network-incapable
in-memory contract adapters. It is not live Microsoft Intune acceptance, a
network throughput result, a production capacity claim or runtime attestation.

## Reproduce it

From the repository root, run:

```bash
python3 scripts/run_synthetic_intune_continuation_acceptance.py \
  --target-count 500 \
  --stale-member-count 81 \
  --output /tmp/aai-intune-continuation-evidence.json
```

The optional JSON file is written atomically with mode `0600`. It contains
counts, fixed states, invariant results and a scenario digest. It contains no
raw device registration, directory object, group, application or assignment
identifiers.

## Observed evidence

| Measure | Result |
| --- | ---: |
| Desired targets | 500 |
| Initial stale members | 81 |
| Immutable pages | 13 |
| Handler invocations | 16 |
| Opaque continuations | 15 |
| Authority reloads | 599 |
| Membership additions | 500 |
| Membership removals | 81 |
| Assignment mutations | 1 |
| Maximum provider mutations in one invocation | 40 |
| Terminal state | `assigned_reported` |
| Terminal continuation revision | 15 |
| Scenario SHA-256 | `b1a263698c440c2d7da327a053f1b2b06c3639e0e59e95bb1988f19cffbcdc0d` |

All of the following assertions passed:

- exact desired membership was reproduced;
- all desired targets were added and all stale members were removed;
- only one required application assignment was created;
- no invocation exceeded the 40-mutation bound;
- progress reached all 500 targets before completion;
- every continuation contained only tenant, command and revision identity;
- exactly one terminal evidence record was emitted; and
- no raw provider identifier appeared in handler results, continuation
  messages or terminal evidence.

The handler performed 599 complete-authority reloads: one at the start of each
of 16 invocations, one before each of 500 additions, one before each of 81
removals, one before assignment and one final reload before terminal evidence.

## Adversarial coverage

The acceptance contract rejects cohorts below the large-command boundary,
cohorts above 500, stale-member counts outside zero to 500 and booleans passed
as integers. Existing worker contracts additionally prove stale-message repair
without page replay, persist-before-send recovery, changed continuation denial,
bounded stale-member pruning, no early assignment, provider redirect denial
and content-minimised terminal failures.

## Remaining live acceptance

Before a customer pilot can rely on this path, an authorized operator must run
the same bounded cohort through a customer-owned non-production Microsoft
Intune tenant using approved Claude Code and Codex packages. That exercise must
retain Graph throttling, retry, queue interruption, authority-change,
assignment, post-install attestation and measured elapsed-time evidence. Only
that exercise can support provider-compatibility and customer-capacity claims.
