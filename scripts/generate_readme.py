"""Generate the public README from the documentation source page.

Keeping one source of truth prevents the repository README and the online
documentation from diverging. The generated marker is also checked in CI.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "README.md"
TARGET = ROOT / "README.md"
MARKER = "<!-- THIS FILE IS GENERATED. Edit docs/README.md and run `make docs`. -->"


def generated_text() -> str:
    """Return the root README content with its generated-file marker."""
    source = SOURCE.read_text(encoding="utf-8")
    # The source page is rendered inside MkDocs at ``docs/README.md`` but the
    # generated copy is rendered by GitHub at the repository root. Translate
    # local Markdown targets so both locations resolve to real files.
    source = re.sub(r"\]\((?!https?://|mailto:|#)([^)]+)\)", _root_link, source)
    return f"{MARKER}\n\n{source}"


def _root_link(match: re.Match[str]) -> str:
    """Translate one relative documentation link for the root README."""
    target = match.group(1)
    suffix = ""
    if "#" in target:
        target, anchor = target.split("#", 1)
        suffix = f"#{anchor}"
    if target.startswith("../"):
        target = target[3:]
    elif not target.startswith("docs/"):
        target = f"docs/{target}"
    return f"]({target}{suffix})"


def main() -> int:
    """Generate README or verify that it matches its documentation source."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = generated_text()
    if args.check:
        if TARGET.read_text(encoding="utf-8") != expected:
            print("README.md is stale; run `make docs`.")
            return 1
        print("README.md is up to date.")
        return 0
    TARGET.write_text(expected, encoding="utf-8")
    print("Generated README.md from docs/README.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
