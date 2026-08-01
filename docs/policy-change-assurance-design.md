# Policy change assurance design

This design completes the first production-shaped implementation of
P1-POL-03 (historical simulation) and P1-POL-04 (semantic change view).
Its purpose is to let an enterprise reviewer understand a policy change before
activation without executing historical actions or pretending redacted data is
still available.

## Security boundary

Policy content, version identifiers, lookback values and retained agent
decision reports are untrusted inputs. Historical agent reports are
operational evidence, not authorization facts. The host remains the authority
for every live execution decision.

The control plane therefore:

- loads the candidate only from the authenticated tenant's immutable policy
  version ledger;
- accepts only a pending `draft`, `review`, `approved` or `staged` version;
- rejects a candidate whose base version is no longer the active policy;
- permits simulation only to policy authors, policy approvers and platform
  administrators;
- accepts one closed request field, `lookbackDays`, bounded from 1 to 90;
- samples at most the 250 most recent retained decisions and reports when that
  evidence window is truncated;
- filters evidence to the candidate policy and authenticated tenant;
- never executes an action, creates an approval or changes policy authority;
- returns `indeterminate` when redaction removed facts needed for prediction;
  and
- hashes the candidate identity and exact simulated evidence so the UI can
  display which result was reviewed.

Simulation does not prove that a policy is safe. It predicts behavior only for
the retained sample. It cannot reconstruct shell commands from action digests,
infer an MCP server identity from a tool name, predict unseen actions or prove
endpoint convergence.

## Semantic change contract

Every policy-version view now contains a `changeSummary` with:

- changed typed sections;
- individual changes to principals, tools, native tools, commands, skills, MCP
  servers, approvals and credential scopes;
- before/after values for limits, providers, credential requirements,
  isolation and data capture; and
- totals for authority expansion, restriction, approval changes, data-capture
  changes and changes requiring reviewer judgement.

The change effects are explanations, not authorization decisions. An added
allow-list entry is an authority expansion; a removed allow entry is a
restriction. Raising a maximum budget or approval TTL is an expansion. Lowering
one is a restriction. Increased content capture is highlighted as a privacy
risk. Provider and requirement changes are marked for explicit review rather
than assigned a misleading safe/unsafe label.

## Historical simulation API

```text
POST /api/enterprise/policies/{policyId}/versions/{version}/simulate
Content-Type: application/json

{"lookbackDays": 30}
```

The response includes:

- candidate policy/version/base identity and content hash;
- a deterministic simulation hash;
- sampled, determined, indeterminate and changed counts;
- predicted allow, deny and approval-required counts;
- transition totals such as `allowed_to_denied`;
- affected group and agent identities;
- bounded, content-minimised per-decision results; and
- explicit `mutated: false` evidence.

Shell-command evidence is indeterminate because raw command text is not
retained. MCP evidence is indeterminate unless an exact tool-level rule is
sufficient, because the current decision record does not retain MCP server
identity. These are honest coverage gaps, not errors to suppress.

## Operator journey

1. Open a policy and review the pending immutable version.
2. Read the semantic authority diff, with expansions and data-capture changes
   visually prominent.
3. Select a 7, 30 or 90-day historical window and run the read-only simulation.
4. Review prediction coverage, changed decisions and every indeterminate class.
5. Complete independent approval and staging.
6. Run a current simulation for the exact staged content hash.
7. Open activation only after the UI has that current result; acknowledge both
   predicted changes and uncertainty before activating.
8. Monitor endpoint convergence separately. Simulation never claims rollout.

## Acceptance evidence

The AWS contract tests prove semantic classification, stable simulation hashes,
lookback exclusion, exact policy scope, role separation, cross-tenant denial,
malformed-window rejection, bounded redacted evidence, explicit command/MCP
indeterminacy and zero control-plane mutation. UI tests prove simulation is
required before the activation confirmation opens and that uncertainty appears
in the final authority-change dialogue.

