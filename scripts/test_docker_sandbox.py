#!/usr/bin/env python3
"""Run the real Docker isolation probe for the SDK adapter."""

from __future__ import annotations

import argparse

from agentic_security import DockerSandboxToolHandler, Principal
from agentic_security.types import ExecutionContext


def main() -> int:
    """Require the container to enforce the documented minimum boundary."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Immutable sha256-pinned worker image")
    args = parser.parse_args()
    context = ExecutionContext(
        "agent:docker-evidence",
        Principal("principal:docker-evidence", tenant="tenant:docker-evidence"),
        "task:docker-evidence",
        "Docker isolation evidence",
        tenant="tenant:docker-evidence",
    )
    result = DockerSandboxToolHandler(args.image)(context, {"synthetic": True})
    if result.get("uid") != 65532:
        raise RuntimeError(f"worker was not non-root: {result}")
    if result.get("network_blocked") is not True:
        raise RuntimeError(f"worker network was not blocked: {result}")
    if result.get("filesystem_read_only") is not True:
        raise RuntimeError(f"worker root filesystem was writable: {result}")
    for control in (
        "capabilities_dropped",
        "mount_blocked",
        "no_new_privileges",
        "process_memory_blocked",
        "privilege_escalation_blocked",
    ):
        if result.get(control) is not True:
            raise RuntimeError(f"worker failed isolation control {control}: {result}")
    print(f"Docker isolation passed: {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
