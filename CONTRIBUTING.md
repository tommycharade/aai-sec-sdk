# Contributing

Read [AGENTS.md](AGENTS.md) and [docs/guardrails.md](docs/guardrails.md) before making changes.

Code is contributed under Apache License 2.0 unless a separate written agreement says otherwise. Contributors must have the right to submit their work and must not submit third-party material whose licence is incompatible with the project. See [the licensing policy](docs/license.md).

## Workflow

1. Describe the threat, user-facing behavior, trust boundary, and intended secure default.
2. Add a focused design note or update the relevant documentation for non-trivial changes.
3. Implement the smallest public surface that solves the problem.
4. Add positive, negative, boundary, and adversarial tests.
5. Run `make check`.
6. Update the changelog for user-visible or breaking changes.

## Definition of done

A change is complete only when its behavior is documented, its security assumptions are explicit, its failure modes are tested, its telemetry is defined, and the full quality gate passes.

Do not merge a feature merely because the happy path works. For this SDK, denial, expiry, cancellation, malformed input, provider failure, replay, and bypass attempts are first-class behavior.
