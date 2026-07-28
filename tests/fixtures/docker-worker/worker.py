"""Synthetic isolation probe used by the Docker adapter evidence test."""

from __future__ import annotations

import ctypes
import json
import os
import socket
import sys


def _status_value(name: str) -> str:
    """Read one kernel-reported process status value without host access."""
    for line in open("/proc/self/status", encoding="utf-8"):
        key, separator, value = line.partition(":")
        if separator and key == name:
            return value.strip()
    return ""


def main() -> None:
    """Report enforced restrictions and failed privilege probes."""
    json.loads(sys.stdin.read())
    network_blocked = False
    try:
        with socket.create_connection(("198.51.100.1", 80), timeout=0.5):
            pass
    except OSError:
        network_blocked = True
    filesystem_read_only = False
    try:
        with open("/root/aai-sec-isolation-probe", "w", encoding="utf-8") as stream:
            stream.write("unexpected")
    except OSError:
        filesystem_read_only = True
    privilege_escalation_blocked = False
    try:
        os.setuid(0)
    except OSError:
        privilege_escalation_blocked = True
    no_new_privileges = _status_value("NoNewPrivs") == "1"
    capabilities_dropped = _status_value("CapEff") in {"0", "0000000000000000"}
    libc = ctypes.CDLL(None, use_errno=True)
    mount_result = libc.mount(b"tmpfs", b"/tmp", b"tmpfs", 0, b"size=1m")
    mount_blocked = mount_result != 0
    if mount_result == 0:
        libc.umount2(b"/tmp", 2)
    process_memory_blocked = False
    try:
        with open("/proc/1/mem", "rb") as stream:
            stream.read(1)
    except OSError:
        process_memory_blocked = True
    print(
        json.dumps(
            {
                "capabilities_dropped": capabilities_dropped,
                "uid": os.getuid(),
                "network_blocked": network_blocked,
                "filesystem_read_only": filesystem_read_only,
                "mount_blocked": mount_blocked,
                "no_new_privileges": no_new_privileges,
                "process_memory_blocked": process_memory_blocked,
                "privilege_escalation_blocked": privilege_escalation_blocked,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
