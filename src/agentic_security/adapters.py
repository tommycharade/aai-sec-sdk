"""Concrete deployment adapters for durable audit, HTTP policy, approvals, and sandboxes."""

from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any

try:  # pragma: no cover - platform import
    import fcntl
except ImportError:  # pragma: no cover - Windows deployments use remote audit
    fcntl = None  # type: ignore[assignment]

from .approvals import ApprovalProvider
from .audit import AuditEvent, redact
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
    ) -> bool:
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
        return response.get("approved") is True


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
    isolated: bool = field(default=True, init=False, repr=False, compare=False)

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
        try:
            completed = subprocess.run(  # noqa: S603 - explicit configured argv, shell disabled
                self.command,
                input=payload,
                capture_output=True,
                check=False,
                env=dict(self.environment),
                shell=False,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("sandbox worker timed out") from exc
        if completed.returncode != 0:
            raise RuntimeError("sandbox worker failed")
        if len(completed.stdout) > self.max_output_bytes:
            raise ValueError("sandbox worker output exceeds configured size")
        return json.loads(completed.stdout)


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
        """Recover the last event hash so a restart continues the chain."""
        if not self.path.exists() or self.path.stat().st_size == 0:
            return "0" * 64
        with self.path.open(encoding="utf-8") as stream:
            lines = stream.readlines()
        last = lines[-1]
        value = json.loads(last)
        previous = value.get("event_hash")
        if not isinstance(previous, str) or len(previous) != 64:
            raise ValueError("audit file has an invalid final event hash")
        return previous

    def append(self, event_type: str, request_id: str, payload: dict[str, Any]) -> Any:
        """Append one redacted event atomically and flush it to durable storage."""
        with self._lock:
            if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                raise RuntimeError("audit sink is full; rotate or export before continuing")
            safe_payload = redact(payload)
            timestamp = datetime.now(UTC).isoformat()
            canonical = json.dumps(
                [event_type, request_id, safe_payload, timestamp, self._previous_hash],
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            event_hash = hashlib.sha256(canonical).hexdigest()
            event = AuditEvent(
                event_type, request_id, safe_payload, timestamp, self._previous_hash, event_hash
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
            with self._lock_path.open("a+", encoding="utf-8") as lock_stream:
                if fcntl is not None:
                    fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX)
                try:
                    with self.path.open("a", encoding="utf-8") as stream:
                        stream.write(serialized)
                        stream.flush()
                        os.fsync(stream.fileno())
                finally:
                    if fcntl is not None:
                        fcntl.flock(lock_stream.fileno(), fcntl.LOCK_UN)
            self._previous_hash = event_hash
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
