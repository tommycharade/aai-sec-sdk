<!-- THIS FILE IS GENERATED. Edit docs/README.md and run `make docs`. -->

# Agentic AI Security SDK

The Agentic AI Security SDK is an open-source execution-security runtime for agentic systems. It is designed around a simple boundary:

> The model proposes; the host validates, authorizes, approves, executes, records, and can stop.

## Start here

- [Getting started](docs/getting-started.md)
- [Security model](docs/security-model.md)
- [Architecture](docs/architecture.md)
- [End-to-end example](docs/end-to-end-example.md)
- [API design](docs/api.md)
- [Runnable example](docs/end-to-end-example.md)
- [Engineering guardrails](docs/guardrails.md)
- [Licensing](docs/license.md)
- [Contributing](docs/contributing.md)
- [Governance](GOVERNANCE.md)
- [Releasing](docs/releasing.md)
- [SDK assessment](SDK-assessment.md)

## Project status

The core runtime and a complete synthetic reference application are available;
provider-specific integrations remain separate adapter work.

## Development

```bash
make docs       # regenerate README and build the site
make check      # run all quality and documentation gates
```

The root `README.md` is generated from this page. Do not edit the generated file directly.
