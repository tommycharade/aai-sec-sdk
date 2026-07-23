# Contributing

Read [AGENTS.md](https://github.com/tommycharade/aai-sec-sdk/blob/main/AGENTS.md), [CONTRIBUTING.md](https://github.com/tommycharade/aai-sec-sdk/blob/main/CONTRIBUTING.md), and [the engineering guardrails](guardrails.md) before changing code.

Project ownership, review responsibilities, security decisions, and release
authority are described in [GOVERNANCE.md](https://github.com/tommycharade/aai-sec-sdk/blob/main/GOVERNANCE.md).

## Documentation requirements

Public modules, classes, functions, methods, exceptions, and configuration fields require docstrings. Security-sensitive code requires comments explaining the trust boundary and invariant. New public behavior requires a narrative guide, API reference entry, runnable example where practical, and tests.

## Local checks

```bash
make docs
make check
```

Do not edit the generated root README directly. Update `docs/README.md` and regenerate it.
