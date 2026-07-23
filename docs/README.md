# Agentic AI Security SDK

The Agentic AI Security SDK is an open-source execution-security runtime for agentic systems. It is designed around a simple boundary:

> The model proposes; the host validates, authorizes, approves, executes, records, and can stop.

## Start here

- [Getting started](getting-started.md)
- [Security model](security-model.md)
- [Architecture](architecture.md)
- [End-to-end example](end-to-end-example.md)
- [API design](api.md)
- [Runnable example](end-to-end-example.md)
- [Engineering guardrails](guardrails.md)
- [Licensing](license.md)
- [Contributing](contributing.md)
- [Releasing](releasing.md)
- [SDK assessment](../SDK-assessment.md)

## Project status

The core runtime and a complete synthetic reference application are available;
provider-specific integrations remain separate adapter work.

## Development

```bash
make docs       # regenerate README and build the site
make check      # run all quality and documentation gates
```

The root `README.md` is generated from this page. Do not edit the generated file directly.
