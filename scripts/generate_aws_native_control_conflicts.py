#!/usr/bin/env python3
"""Generate the standalone AWS Lambda native-control conflict analyzer.

The provider-neutral SDK module is canonical. The Lambda deployment asset
cannot import the installed package, so this generator copies the side-effect
free module verbatim and parity tests prevent control-plane drift.
"""

from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/agentic_security/native_control_conflicts.py"
TARGET = ROOT / "infra/aws-control-plane/lambda/native_control_conflicts.py"


def rendered() -> str:
    """Return deterministic standalone source from the canonical SDK module."""
    return SOURCE.read_text(encoding="utf-8")


def main() -> int:
    """Write the generated module or verify the checked-in copy is current."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = rendered()
    if args.check:
        if not TARGET.exists() or TARGET.read_text(encoding="utf-8") != expected:
            raise SystemExit("AWS native-control conflict analyzer is out of date")
        return 0
    TARGET.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
