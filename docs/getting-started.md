# Getting started

The SDK is released under Apache-2.0. Clone the
repository, install the development dependencies, and validate the project:

```bash
git clone https://github.com/tommycharade/aai-sec-sdk.git
cd aai-sec-sdk
python3 -m pip install -e '.[dev,docs]'
make check
```

When using the runtime, the intended integration shape is:

1. Create an authenticated execution context.
2. Register tools explicitly with typed arguments and impact metadata.
3. Pass model proposals to the SDK execution boundary.
4. Handle structured executed, denied, approval-required, and failed outcomes.
5. Export the resulting trace and audit events.

The SDK does not make an LLM trustworthy. It limits what an incorrect or manipulated model can cause at the execution boundary.

## Run the example

```bash
python examples/support_agent.py
```

The example demonstrates read, write, approval, credential, idempotency, audit,
cross-tenant, and emergency-stop paths using synthetic data. It deliberately
does not connect to a model or network. Read [Production readiness](production-readiness.md)
before connecting real tools.
