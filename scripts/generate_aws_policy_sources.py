#!/usr/bin/env python3
"""Generate standalone policy-source modules for the AWS Lambda asset.

The SDK modules are canonical. The Lambda asset is intentionally self-contained,
so generation replaces only package-relative imports with standalone imports and
an equivalent local configuration-error base. Provider and schema semantics stay
verbatim and CI rejects a stale generated copy.
"""

from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    ROOT / "src/agentic_security/policy_sources.py": ROOT
    / "infra/aws-control-plane/lambda/policy_sources.py",
    ROOT / "src/agentic_security/github_policy_source.py": ROOT
    / "infra/aws-control-plane/lambda/github_policy_source.py",
}
ERROR_IMPORT = "from .errors import SecurityConfigurationError\n"
ERROR_SUPPORT = '''
# Generated deployment support; edit the SDK source and rerun the generator.
class SecurityConfigurationError(ValueError):
    """Standalone Lambda configuration failure base class."""
'''


def rendered(source_path: Path) -> str:
    """Render one canonical module with only deterministic import rewrites."""
    source = source_path.read_text(encoding="utf-8")
    if source_path.name == "policy_sources.py":
        if source.count(ERROR_IMPORT) != 1:
            raise RuntimeError("canonical policy-source error import changed")
        return source.replace(ERROR_IMPORT, ERROR_SUPPORT, 1)
    package_import = "from .policy_sources import ("
    if source.count(package_import) != 1:
        raise RuntimeError("canonical GitHub policy-source import changed")
    return source.replace(package_import, "from policy_sources import (", 1)


def main() -> int:
    """Write generated modules or verify checked-in deployment copies."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for source, target in SOURCES.items():
        expected = rendered(source)
        if args.check:
            if not target.exists() or target.read_text(encoding="utf-8") != expected:
                raise SystemExit(f"AWS {target.name} runtime is out of date")
        else:
            target.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
