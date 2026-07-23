# Project governance

## Scope

This project is maintained as an open-source Apache-2.0 SDK. The maintainers
are responsible for protecting the execution-security boundary, preserving
the documented licence, and keeping releases reproducible.

## Maintainers

The repository owner and listed code owners act as the initial maintainers.
Maintainers review security-sensitive changes, approve releases, coordinate
private vulnerability reports, and may reject changes that weaken the
fail-closed invariants in `AGENTS.md` and `docs/guardrails.md`.

## Changes and review

Normal changes should be submitted as pull requests with the required tests,
documentation, threat-model updates, and `make check` evidence. Security
boundary changes require maintainer review. At least one maintainer approval is
required before merging a security-sensitive change once branch protection is
enabled.

## Releases

Releases are cut from reviewed commits on `main` using the checklist in
`docs/releasing.md`. The maintainer who publishes a release is responsible for
confirming its licence metadata, artefact contents, dependency audit, and
changelog entry.

## Security decisions

Potential vulnerabilities must use the private channel described in
`SECURITY.md`. Public issue reports must not contain live credentials, customer
data, or exploit targets.
