"""Concrete deployment adapters for durable audit, HTTP policy, approvals, and sandboxes."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import selectors
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from shutil import which
from threading import Lock
from typing import Any, cast

try:  # pragma: no cover - platform import
    import fcntl
except ImportError:  # pragma: no cover - Windows deployments use remote audit
    fcntl = None  # type: ignore[assignment]

from .approvals import ApprovalConsumption, ApprovalOutcome, ApprovalProvider
from .audit import AuditEvent, AuditExporter, redact
from .http import JsonHttpClient
from .policy_adapters import CedarPolicyEngine, OpaPolicyEngine


class HttpOpaPolicyEngine(OpaPolicyEngine):
    """OPA adapter backed by an authenticated, timeout-bounded JSON endpoint."""

    def __init__(self, client: JsonHttpClient) -> None:
        """Create an OPA client adapter from an explicitly configured transport."""
        super().__init__(client.post)


class HttpCedarPolicyEngine(CedarPolicyEngine):
    """Cedar adapter backed by an authenticated, timeout-bounded JSON endpoint."""

    def __init__(self, client: JsonHttpClient) -> None:
        """Create a Cedar client adapter from an explicitly configured transport."""
        super().__init__(client.post)


class HttpApprovalProvider(ApprovalProvider):
    """Approval provider that consumes exact action bindings through a JSON API."""

    def __init__(self, client: JsonHttpClient) -> None:
        """Create an approval adapter from an authenticated JSON transport."""
        self.client = client

    def consume(
        self,
        approval_id: str,
        context: Any,
        tool_name: str,
        proposal_id: str,
        action_hash: str,
    ) -> ApprovalConsumption:
        """Atomically ask the service to consume the exact live action grant."""
        response = self.client.post(
            {
                "approval_id": approval_id,
                "task_id": context.task_id,
                "principal_id": context.principal.id,
                "tenant": context.tenant,
                "tool_name": tool_name,
                "proposal_id": proposal_id,
                "action_hash": action_hash,
            }
        )
        if response.get("approved") is True:
            return ApprovalConsumption(ApprovalOutcome.CONSUMED, "approval service consumed grant")
        if response.get("approved") is False:
            return ApprovalConsumption(
                ApprovalOutcome.NOT_CONSUMED, "approval service rejected grant"
            )
        return ApprovalConsumption(ApprovalOutcome.UNKNOWN, "approval service returned no decision")


class HttpAuditExporter(AuditExporter):
    """Export redacted audit events to an authenticated remote collector.

    The collector must return ``{"accepted": true}`` only after durable
    acceptance.  HTTP failures, malformed responses, and negative
    acknowledgements raise so :class:`ReplicatedAuditSink` fails closed.
    """

    def __init__(self, client: JsonHttpClient) -> None:
        """Create an exporter using an explicitly configured HTTPS client."""
        self.client = client

    def export(self, event: AuditEvent) -> None:
        """Send one complete event and require an explicit durable acknowledgement."""
        response = self.client.post(
            {
                "event_type": event.event_type,
                "request_id": event.request_id,
                "payload": redact(event.payload),
                "timestamp": event.timestamp,
                "previous_hash": event.previous_hash,
                "event_hash": event.event_hash,
            }
        )
        if response.get("accepted") is not True:
            raise RuntimeError("remote audit collector did not acknowledge durable acceptance")


@dataclass(frozen=True, slots=True)
class SubprocessToolHandler:
    """Run a JSON tool worker in a separate process without shell expansion.

    The worker receives only identity, tenant, purpose, and validated
    arguments. Credentials are intentionally excluded. Deployments requiring
    stronger isolation should run the worker under an OS/container sandbox.
    """

    command: tuple[str, ...]
    timeout_seconds: float = 10.0
    max_output_bytes: int = 1_000_000
    environment: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Reject shell-like or unbounded subprocess configurations."""
        if not self.command or any(not isinstance(part, str) or not part for part in self.command):
            raise ValueError("sandbox command must be a non-empty argument tuple")
        if (
            not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
            or self.max_output_bytes <= 0
        ):
            raise ValueError("sandbox timeout and output limit must be finite and positive")

    def __call__(self, context: Any, arguments: Any) -> Any:
        """Execute the worker and parse one bounded JSON result."""
        payload = json.dumps(
            {
                "agent_id": context.agent_id,
                "principal_id": context.principal.id,
                "tenant": context.tenant,
                "task_id": context.task_id,
                "purpose": context.purpose,
                "arguments": arguments,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        process = subprocess.Popen(  # noqa: S603 - explicit configured argv, shell disabled
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(self.environment),
            shell=False,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        output = bytearray()
        selector = selectors.DefaultSelector()
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE)
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        deadline = datetime.now(UTC).timestamp() + self.timeout_seconds
        input_offset = 0
        try:
            while selector.get_map():
                remaining = deadline - datetime.now(UTC).timestamp()
                if remaining <= 0:
                    process.kill()
                    process.wait()
                    raise TimeoutError("sandbox worker timed out")
                for key, _ in selector.select(remaining):
                    stream = cast(Any, key.fileobj)
                    if stream is process.stdin:
                        try:
                            written = os.write(process.stdin.fileno(), payload[input_offset:])
                        except (BlockingIOError, BrokenPipeError):
                            written = 0
                        input_offset += written
                        if input_offset == len(payload) or process.poll() is not None:
                            selector.unregister(process.stdin)
                            process.stdin.close()
                        continue
                    chunk = stream.read(65536)
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    if stream is process.stdout:
                        output.extend(chunk)
                        if len(output) > self.max_output_bytes:
                            process.kill()
                            process.wait()
                            raise ValueError("sandbox worker output exceeds configured size")
            process.wait()
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
                process.wait()
        if process.returncode != 0:
            raise RuntimeError("sandbox worker failed")
        return json.loads(bytes(output))


@dataclass(frozen=True, slots=True)
class DockerSandboxToolHandler:
    """Run a fixed worker image inside a restrictive Docker container.

    The image is deployment-owned and must be pinned by digest in production.
    The worker receives the same bounded JSON contract as
    :class:`SubprocessToolHandler`, while Docker enforces no network, a
    read-only root filesystem, dropped Linux capabilities, non-root UID,
    disabled privilege escalation, and bounded PIDs/memory. This is a real
    container boundary, but Docker daemon and host kernel hardening remain
    deployment responsibilities; hostile workloads should use a separately
    managed microVM when that trust boundary is insufficient.
    """

    image: str
    timeout_seconds: float = 10.0
    max_output_bytes: int = 1_000_000
    memory_limit: str = "256m"
    pids_limit: int = 64

    def __post_init__(self) -> None:
        """Reject image names and resource settings that make isolation ambiguous."""
        # Registry manifests use ``name@sha256:...`` while a locally built
        # image is addressed by Docker as ``sha256:...``. Both are immutable
        # content identifiers; mutable names and tags remain rejected.
        if not re.fullmatch(r"(?:.+@)?sha256:[0-9a-f]{64}", self.image):
            raise ValueError("sandbox image must be an immutable sha256 digest reference")
        if (
            not math.isfinite(self.timeout_seconds)
            or self.pids_limit <= 0
            or self.max_output_bytes <= 0
        ):
            raise ValueError("sandbox limits must be positive")
        if not self.memory_limit or any(character.isspace() for character in self.memory_limit):
            raise ValueError("sandbox memory limit must be a single Docker value")

    def __call__(self, context: Any, arguments: Any) -> Any:
        """Invoke the pinned image with fixed isolation flags and no shell."""
        docker_executable = which("docker")
        if docker_executable is None:
            raise RuntimeError("Docker executable is not available on the host")
        command = (
            docker_executable,
            "run",
            "--interactive",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--user=65532:65532",
            f"--memory={self.memory_limit}",
            f"--pids-limit={self.pids_limit}",
            "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
            self.image,
        )
        return SubprocessToolHandler(
            command=command,
            timeout_seconds=self.timeout_seconds,
            max_output_bytes=self.max_output_bytes,
            environment={},
        )(context, arguments)


class JsonlAuditSink:
    """Durable JSONL audit sink with fsync, locking, and hash verification.

    This is a local evidence adapter, not a tamper-proof forensic service.
    Production deployments should replicate events to an access-controlled
    WORM/object-lock or SIEM destination. ``max_bytes`` fails closed before a
    write so operators cannot silently lose the audit chain during rotation.
    """

    def __init__(self, path: str | Path, max_bytes: int = 100_000_000) -> None:
        """Open a deployment-selected audit path without creating parent trees."""
        if max_bytes <= 0:
            raise ValueError("audit maximum size must be positive")
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self._previous_hash = self._read_previous_hash()

    def _read_previous_hash(self) -> str:
        """Validate the existing chain and return its final event hash.

        A final hash alone is not sufficient evidence: an earlier line may
        have been altered while the last line remains untouched.  Refuse to
        append to a chain that cannot be fully verified so operators cannot
        accidentally extend corrupted evidence.
        """
        if not self.path.exists() or self.path.stat().st_size == 0:
            return "0" * 64
        with self.path.open(encoding="utf-8") as stream:
            previous_hash = "0" * 64
            for line in stream:
                value = json.loads(line)
                payload = value["payload"]
                canonical = json.dumps(
                    [
                        value["event_type"],
                        value["request_id"],
                        payload,
                        value["timestamp"],
                        previous_hash,
                    ],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                event_hash = value["event_hash"]
                if (
                    value["previous_hash"] != previous_hash
                    or not isinstance(event_hash, str)
                    or hashlib.sha256(canonical).hexdigest() != event_hash
                ):
                    raise ValueError("audit file hash chain is corrupt")
                previous_hash = event_hash
            return previous_hash

    def append(self, event_type: str, request_id: str, payload: dict[str, Any]) -> Any:
        """Append one redacted event atomically and flush it to durable storage."""
        with self._lock:
            safe_payload = redact(payload)
            with self._lock_path.open("a+", encoding="utf-8") as lock_stream:
                if fcntl is not None:
                    fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX)
                try:
                    # Each instance may have opened before another process
                    # appended. Refresh the chain head while holding the
                    # interprocess lock, immediately before hashing/writing.
                    self._previous_hash = self._read_previous_hash()
                    timestamp = datetime.now(UTC).isoformat()
                    canonical = json.dumps(
                        [event_type, request_id, safe_payload, timestamp, self._previous_hash],
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                    event_hash = hashlib.sha256(canonical).hexdigest()
                    event = AuditEvent(
                        event_type,
                        request_id,
                        safe_payload,
                        timestamp,
                        self._previous_hash,
                        event_hash,
                    )
                    serialized = (
                        json.dumps(
                            {
                                "event_type": event.event_type,
                                "request_id": event.request_id,
                                "payload": event.payload,
                                "timestamp": event.timestamp,
                                "previous_hash": event.previous_hash,
                                "event_hash": event.event_hash,
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    current_size = self.path.stat().st_size if self.path.exists() else 0
                    if current_size + len(serialized.encode()) > self.max_bytes:
                        raise RuntimeError("audit sink is full; rotate or export before continuing")
                    with self.path.open("a", encoding="utf-8") as stream:
                        stream.write(serialized)
                        stream.flush()
                        os.fsync(stream.fileno())
                    self._previous_hash = event_hash
                finally:
                    if fcntl is not None:
                        fcntl.flock(lock_stream.fileno(), fcntl.LOCK_UN)
            return event

    def verify(self) -> bool:
        """Verify every JSONL event and return false for corruption."""
        previous_hash = "0" * 64
        try:
            with self.path.open(encoding="utf-8") as stream:
                for line in stream:
                    value = json.loads(line)
                    payload = value["payload"]
                    canonical = json.dumps(
                        [
                            value["event_type"],
                            value["request_id"],
                            payload,
                            value["timestamp"],
                            previous_hash,
                        ],
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                    if (
                        value["previous_hash"] != previous_hash
                        or hashlib.sha256(canonical).hexdigest() != value["event_hash"]
                    ):
                        return False
                    previous_hash = value["event_hash"]
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return False
        return True
