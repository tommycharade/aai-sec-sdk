"""Secure host-side cache for rotated enterprise agent sessions.

The cache lets short-lived hook processes and the long-running MCP gateway use
the same current bearer without placing it in project configuration. It is a
host credential cache, not an authority source: deployment and agent identity
remain constructor-owned, and the control plane revalidates every request.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

_MAX_RECORD_BYTES = 4_096


class AgentSessionStoreError(RuntimeError):
    """Report an unsafe, unreadable, or unwritable host session cache."""


@dataclass(frozen=True, repr=False)
class AgentSessionCredential:
    """One deployment-bound bearer and its absolute Unix expiry time.

    The value is sensitive and deliberately has no custom string
    representation. Callers must never log, serialize, or display ``token``.
    """

    token: str
    expires_at: int

    def __post_init__(self) -> None:
        """Reject malformed credentials before they reach the cache."""
        if not isinstance(self.token, str) or not 16 <= len(self.token) <= 4_096:
            raise ValueError("agent session token must contain 16-4096 characters")
        if isinstance(self.expires_at, bool) or not isinstance(self.expires_at, int):
            raise ValueError("agent session expiry must be an integer Unix timestamp")


class AgentSessionStore:
    """Atomically share a rotated agent bearer outside project configuration.

    Files are scoped by control-plane URL, deployment, and agent, stored under
    a user-only directory, and rejected if symlinked, non-regular, foreign
    owned, or accessible by group/other users. The cache does not refresh or
    authorize a session; it only transfers the latest control-plane-issued
    credential between trusted processes running as the same OS user.
    """

    def __init__(
        self,
        base_url: str,
        deployment_id: str,
        agent_id: str,
        *,
        directory: Path | None = None,
        now: Callable[[], float] | None = None,
    ) -> None:
        """Bind the store to immutable routing identity without doing I/O.

        Args:
            base_url: HTTPS control-plane origin, or localhost HTTP for tests.
            deployment_id: Server-registered deployment identifier.
            agent_id: Server-registered agent identifier.
            directory: Optional user-private cache directory for integration
                tests or a deployment-owned host location.
            now: Injectable clock used only to reject expired credentials.

        Raises:
            ValueError: If routing identity or the endpoint is malformed.
            AgentSessionStoreError: If the host cannot verify POSIX owner-only
                storage semantics for the plaintext reference cache.
        """
        if not _supports_private_posix_storage():
            raise AgentSessionStoreError(
                "agent session cache requires POSIX ownership and file-mode enforcement"
            )
        parsed = urlsplit(base_url.rstrip("/"))
        local_http = parsed.scheme == "http" and parsed.hostname in {
            "localhost",
            "127.0.0.1",
            "::1",
        }
        if not parsed.hostname or parsed.scheme != "https" and not local_http:
            raise ValueError("agent session control-plane URL must use HTTPS outside localhost")
        if not _identifier(deployment_id) or not _identifier(agent_id):
            raise ValueError("agent session deployment and agent IDs must be safe identifiers")
        if now is not None and not callable(now):
            raise ValueError("agent session clock must be callable")
        self.base_url = base_url.rstrip("/")
        self.deployment_id = deployment_id
        self.agent_id = agent_id
        self.directory = (
            directory or Path.home() / ".local" / "state" / "aai-sec" / "agent-sessions"
        )
        scope = f"{self.base_url}\0{deployment_id}\0{agent_id}".encode()
        self.path = self.directory / f"{hashlib.sha256(scope).hexdigest()}.json"
        self._now = now or time.time

    def load(self) -> AgentSessionCredential | None:
        """Return the current unexpired credential, or ``None`` if unavailable.

        Missing, expired, or malformed content fails closed as unavailable.
        Unsafe filesystem ownership, permissions, types, or symlinks raise
        :class:`AgentSessionStoreError` so deployments can surface tampering.
        No bearer value is included in an exception.
        """
        if not self.path.exists() and not self.path.is_symlink():
            return None
        self._prepare_directory()
        self._validate_file()
        descriptor = -1
        try:
            # Read one byte beyond the contract limit so attacker-controlled
            # cache content cannot force an unbounded allocation before it is
            # rejected. O_NOFOLLOW plus descriptor metadata validation closes
            # the symlink-swap race between the preceding path check and read.
            descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
            self._validate_file_details(os.fstat(descriptor))
            encoded = os.read(descriptor, _MAX_RECORD_BYTES + 1)
            if len(encoded) > _MAX_RECORD_BYTES:
                return None
            raw = encoded.decode("utf-8")
            value = json.loads(raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            if isinstance(exc, OSError):
                raise AgentSessionStoreError("agent session cache could not be read") from exc
            return None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if not isinstance(value, dict) or set(value) != {
            "version",
            "deploymentId",
            "agentId",
            "token",
            "expiresAt",
        }:
            return None
        if (
            value.get("version") != 1
            or value.get("deploymentId") != self.deployment_id
            or value.get("agentId") != self.agent_id
        ):
            return None
        try:
            credential = AgentSessionCredential(value["token"], value["expiresAt"])
        except (KeyError, ValueError):
            return None
        if credential.expires_at <= int(self._now()):
            return None
        return credential

    def save(self, credential: AgentSessionCredential) -> None:
        """Atomically persist the latest control-plane-issued credential.

        The destination directory is created with mode ``0700`` and the file
        with mode ``0600``. Existing unsafe paths are rejected rather than
        followed or silently repaired. The temporary file is removed on error.
        """
        if not isinstance(credential, AgentSessionCredential):
            raise TypeError("credential must be an AgentSessionCredential")
        if credential.expires_at <= int(self._now()):
            raise ValueError("cannot cache an expired agent session")
        self._prepare_directory()
        if self.path.exists() or self.path.is_symlink():
            self._validate_file()
        payload = json.dumps(
            {
                "version": 1,
                "deploymentId": self.deployment_id,
                "agentId": self.agent_id,
                "token": credential.token,
                "expiresAt": credential.expires_at,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        descriptor = -1
        temporary_name = ""
        try:
            descriptor, temporary_name = tempfile.mkstemp(prefix=".session-", dir=self.directory)
            os.chmod(temporary_name, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
                descriptor = -1
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
            os.replace(temporary_name, self.path)
            temporary_name = ""
            os.chmod(self.path, 0o600)
        except OSError as exc:
            raise AgentSessionStoreError("agent session cache could not be written") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_name:
                try:
                    os.unlink(temporary_name)
                except OSError:
                    pass

    def _prepare_directory(self) -> None:
        """Create and validate a user-only, non-symlink cache directory."""
        try:
            # Inspect the SDK-owned cache path and its immediate state roots;
            # following a parent link could redirect a correctly mode-0600
            # file into a location outside the operator's intended boundary.
            protected_parents = (self.directory, *self.directory.parents[:3])
            if any(path.is_symlink() for path in protected_parents):
                raise AgentSessionStoreError("agent session directory must not be a symlink")
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            details = self.directory.stat()
        except OSError as exc:
            raise AgentSessionStoreError("agent session directory is unavailable") from exc
        if not stat.S_ISDIR(details.st_mode):
            raise AgentSessionStoreError("agent session path is not a directory")
        if details.st_mode & 0o077:
            raise AgentSessionStoreError("agent session directory must use mode 0700")
        if hasattr(os, "getuid") and details.st_uid != os.getuid():
            raise AgentSessionStoreError("agent session directory must be owned by this user")

    def _validate_file(self) -> None:
        """Reject cache paths that could disclose or redirect the bearer."""
        try:
            details = self.path.lstat()
        except OSError as exc:
            raise AgentSessionStoreError("agent session cache metadata is unavailable") from exc
        self._validate_file_details(details)

    def _validate_file_details(self, details: os.stat_result) -> None:
        """Validate file metadata obtained from either a path or descriptor."""
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
            raise AgentSessionStoreError("agent session cache must be a regular non-symlink file")
        if details.st_mode & 0o077:
            raise AgentSessionStoreError("agent session cache must use mode 0600")
        if hasattr(os, "getuid") and details.st_uid != os.getuid():
            raise AgentSessionStoreError("agent session cache must be owned by this user")


def _identifier(value: object) -> bool:
    """Return whether a routing identifier is bounded and unambiguous."""
    return isinstance(value, str) and bool(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value)
    )


def _supports_private_posix_storage() -> bool:
    """Return whether owner-only POSIX file protections can be verified.

    The reference store intentionally fails closed on Windows and other hosts
    without a numeric effective user identity. Those deployments need an
    adapter backed by a platform keychain, protected credential service, or
    equivalent ACL-aware broker rather than this plaintext-on-disk cache.
    """
    return os.name == "posix" and hasattr(os, "getuid") and hasattr(os, "O_NOFOLLOW")
