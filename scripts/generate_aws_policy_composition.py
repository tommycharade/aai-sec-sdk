#!/usr/bin/env python3
"""Generate the standalone AWS Lambda policy-composition runtime module.

The SDK module is canonical. AWS Lambda assets cannot import the installed SDK,
so generation replaces only package-local immutability/error dependencies with
equivalent local definitions. Merge rules and graph semantics remain verbatim.
"""

from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/agentic_security/policy_composition.py"
TARGET = ROOT / "infra/aws-control-plane/lambda/policy_composition.py"
PACKAGE_IMPORTS = (
    "from .components import freeze_value\nfrom .errors import SecurityConfigurationError\n"
)
LAMBDA_SUPPORT = '''# Generated deployment support; edit the SDK source and rerun the generator.
class SecurityConfigurationError(ValueError):
    """Standalone Lambda configuration failure base class."""


class _FrozenMapping(Mapping[Any, Any]):
    """Minimal read-only mapping used by generated Lambda evidence."""

    def __init__(self, values: Mapping[Any, Any]) -> None:
        self._values = dict(values)

    def __getitem__(self, key: Any) -> Any:
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mapping):
            return dict(self.items()) == dict(other.items())
        return NotImplemented


class _FrozenList(tuple[Any, ...]):
    """Tuple-backed immutable representation of a JSON list."""

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (list, tuple)):
            return tuple(self) == tuple(other)
        return NotImplemented


def freeze_value(value: Any) -> Any:
    """Recursively freeze JSON data without importing the complete SDK."""
    if isinstance(value, Mapping):
        return _FrozenMapping({key: freeze_value(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return _FrozenList(freeze_value(item) for item in value)
    return value
'''


def rendered() -> str:
    """Return deterministic standalone source or fail if canonical imports drift."""
    source = SOURCE.read_text(encoding="utf-8")
    if source.count(PACKAGE_IMPORTS) != 1:
        raise RuntimeError("canonical policy composition package imports changed")
    return source.replace(PACKAGE_IMPORTS, LAMBDA_SUPPORT, 1)


def main() -> int:
    """Write the generated module or verify that the checked-in copy is current."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = rendered()
    if args.check:
        if not TARGET.exists() or TARGET.read_text(encoding="utf-8") != expected:
            raise SystemExit("AWS policy composition runtime is out of date")
        return 0
    TARGET.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
