# SDK engineering guardrails

This document is the project’s working contract. It applies before the first runtime implementation and remains the review standard as the SDK grows.

## 1. Product and architecture guardrails

The SDK is an agent execution-security runtime. Its job is to constrain and evidence actions. It is not an LLM safety oracle, IAM replacement, sandbox implementation, compliance certification, or business authorization system.

The core must remain:

- deterministic at the execution boundary;
- fail-closed for unknown or unsafe conditions;
- framework- and model-provider-neutral;
- small enough to audit;
- usable as middleware or as a low-level execution primitive;
- explicit about which controls are local and which are delegated to infrastructure.

The canonical flow is:

```text
proposal -> normalize -> schema/business validation -> policy -> approval
         -> budget/idempotency -> scoped execution -> result handling -> audit
```

No side effect or privileged credential mint may happen before all applicable checks complete.

## 2. Security guardrails

### Authority

- Model output is untrusted input.
- Tool names and arguments are untrusted input.
- Tool results, retrieved documents, memory, and inter-agent messages are untrusted observations.
- The caller principal is obtained from authenticated application context, never from the model.
- Authorization is evaluated per action with live arguments and resource identity.
- Delegation can only narrow authority.

### Defaults

- Deny unknown tools.
- Deny missing or invalid identity, policy, scope, approval, or provenance.
- Require explicit opt-in for write, destructive, external-egress, code-execution, and secret-reading actions.
- Bound steps, wall time, concurrency, fan-out, rate, and cost.
- Make every consequential action idempotent or explicitly document why it cannot be.
- Make all security decisions observable.

### Data handling

- Never use real credentials, customer data, secrets, or production destinations in tests or examples.
- Redact/tokenize before events leave the process; content capture is opt-in.
- Keep sensitive re-identification data separate from normal audit records.
- Treat logs, traces, approval systems, and policy stores as security-sensitive systems.

## 3. API and SDK clarity guardrails

- Public types use descriptive names and typed fields.
- Security-sensitive values use dedicated types where confusion is plausible (`Principal`, `Resource`, `PolicyVersion`, `ApprovalId`).
- Prefer structured decisions such as `ALLOW`, `DENY`, `APPROVAL_REQUIRED`, and `RETRYABLE_ERROR` over `True`/`False`.
- Exceptions are reserved for programmer/configuration failures; expected policy outcomes are data.
- No hidden network calls, credential acquisition, retries, or approval prompts in constructors.
- Async and sync APIs must have equivalent semantics and documented cancellation behavior when they are introduced; the current core is synchronous only.
- Every public method documents inputs, outputs, side effects, failure modes, security assumptions, and an example.
- Configuration must be inspectable and serializable without exposing secrets.
- Breaking changes require a migration note and a versioning decision.

## 4. Coding standards

- Python 3.11+; type annotations on public and security-sensitive code.
- Small modules with one clear responsibility.
- No mutable module-level security state.
- No `eval`, `exec`, dynamic imports, shell calls, or unrestricted HTTP clients in the core.
- Explicit timeouts and bounded retries for every integration.
- Deterministic clocks, IDs, randomness, and external clients must be injectable in tests.
- Avoid logging raw prompts, tool arguments, tokens, credentials, or tool results.
- Comments explain security invariants and trust boundaries, not syntax.
- Every public module, class, function, method, exception, and configuration field has a docstring explaining purpose, inputs, outputs, side effects, failure modes, and security assumptions.
- Non-obvious security decisions have nearby comments that explain the invariant and the consequence of weakening it.
- Public examples are complete enough to copy, run, and adapt; abbreviated examples are labelled as such.
- Dependencies are pinned/locked in application examples and reviewed for security relevance.

## 5. Testing guardrails

Every security control needs a positive test and a negative/bypass test. At minimum:

- unit tests for normalization, validation, policy composition, budgets, approvals, idempotency, redaction, and event generation;
- property or fuzz tests for untrusted tool arguments and policy boundary values;
- contract tests for each provider/infrastructure adapter;
- integration tests proving no side effect occurs on denial, timeout, expiry, or cancellation;
- replay tests proving an approval cannot be reused outside its scope or TTL;
- concurrency tests for idempotency, rate limits, and kill switches;
- adversarial tests for unknown tools, forged principals, parameter injection, prompt-injected destinations, delegation widening, and result poisoning;
- documentation examples executed as tests where practical.

Test quality is measured by behavior and coverage of security branches, not only line coverage. The project target is at least 90% line coverage for the core and 100% coverage of deny/approval/expiry paths.

## 6. Documentation guardrails

This is an open-source project. Documentation is part of the product, not an afterthought.

- The root README is generated from `docs/README.md`; edit the source, then run `make docs`.
- Full documentation lives under `docs/` and is published as a MkDocs site.
- Every public API has narrative documentation, a reference entry, and at least one usage example.
- Security behavior is explained in terms of trust boundaries, guarantees, non-guarantees, and failure modes.
- Code examples must include comments at security-sensitive boundaries and must not hide important behavior behind unexplained helpers.
- Documentation examples use synthetic identities, data, secrets, and destinations.
- Examples are executed in CI or have an explicit test that keeps them runnable.
- Source code is Apache-2.0; documentation is CC BY 4.0 unless explicitly marked otherwise.
- Licence, NOTICE, trademark, and contribution terms are checked before the first public release.
- A release must pass package-build validation and include LICENSE/NOTICE in published artifacts.
- The documentation site must build with warnings treated as errors.
- Links, navigation, README generation, and API reference generation are checked in CI.

Every feature should answer:

1. What threat or failure does it address?
2. Which trust boundary does it enforce?
3. What does it guarantee and what does it not guarantee?
4. What are the secure defaults?
5. How does an engineer use it safely?
6. How is it tested and observed?
7. What infrastructure must still be configured?

Examples must be runnable or clearly labelled conceptual. Examples must show failure handling and must not normalize insecure shortcuts.

## 7. Review and release guardrails

Reviewers must reject changes that:

- bypass the central execution boundary;
- weaken a default without an explicit configuration and threat-model rationale;
- add a public API without docs and tests;
- add public code without docstrings and explanatory security comments;
- edit the generated README directly instead of updating its source;
- introduce documentation links or navigation that fail the documentation build;
- add an integration without timeout, error, and contract tests;
- capture sensitive content by default;
- claim standards or regulatory compliance without authoritative verification;
- change policy semantics without migration and regression evidence.

Before release, run `make check`, review the dependency diff, update the changelog, and verify the package contains no credentials or generated sensitive artifacts.

### Definition of done

A change is done only when its behavior is documented, its security assumptions are explicit, its failure modes and bypass attempts are tested, its telemetry is defined, and the full quality gate passes.
