"""Write immutable release subject metadata used by clean verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    """Record the exact source commit, tag, and artifact subjects."""
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    artifacts = sorted(
        path.name
        for path in args.directory.iterdir()
        if path.suffix == ".whl" or path.name.endswith(".tar.gz")
    )
    if not artifacts or not args.commit or not args.tag:
        raise ValueError("release metadata requires commit, tag, and built artifacts")
    output = args.directory / "RELEASE-METADATA.json"
    output.write_text(
        json.dumps(
            {
                "schema": 1,
                "commit": args.commit,
                "tag": args.tag,
                "subjects": artifacts,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
