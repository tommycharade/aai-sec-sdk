# Agentic AI Security SDK

The Agentic AI Security SDK is an open-source execution-security runtime for agentic systems. It is designed around a simple boundary:

> The model proposes; the host validates, authorizes, approves, executes, records, and can stop.

## Start here

- [Getting started](getting-started.md)
- [Security model](security-model.md)
- [Operational runbooks](runbooks.md)
- [Testing and assurance](testing.md)
- [Production readiness](production-readiness.md)
- [Architecture](architecture.md)
- [End-to-end example](end-to-end-example.md)
- [API design](api.md)
- [Runnable example](end-to-end-example.md)
- [Engineering guardrails](guardrails.md)
- [Licensing](license.md)
- [Contributing](contributing.md)
- [Governance](../GOVERNANCE.md)
- [Releasing](releasing.md)
- [SDK assessment](../SDK-assessment.md)
- [Online documentation](https://tommycharade.github.io/aai-sec-sdk/)

## Project status

The core runtime, synthetic reference application, typed idempotency and
isolation contracts, phase-specific timeout outcomes, bounded HTTP
policy/approval adapters, token broker, audit exporters, and process-boundary
integration surfaces are available. The execution boundary now exposes typed
action facts, permits, centralized pre-execution authorization, and lifecycle
gates while preserving the `GuardedRuntime` entry point. See [production readiness](production-readiness.md)
for the exact boundary between SDK guarantees and deployment responsibilities.

## Development

```bash
make docs       # regenerate README and build the site
make check      # run all quality and documentation gates
```

For release adoption, use the standalone checksum, SBOM, commit/tag, and
provenance verification procedure in [Releasing](releasing.md); build success
alone is not release evidence.

The root `README.md` is generated from this page. Do not edit the generated file directly.
