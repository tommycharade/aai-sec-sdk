"""Security and lifecycle tests for the host agent-session cache."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from agentic_security import (
    AgentSessionCredential,
    AgentSessionStore,
    AgentSessionStoreError,
)

TOKEN = "synthetic-session-token-1234"  # noqa: S105 - synthetic test credential
ROTATED = "synthetic-rotated-token-5678"  # noqa: S105 - synthetic test credential


def session_store(directory: Path, *, now: int = 1_000) -> AgentSessionStore:
    """Build one deterministic synthetic deployment cache."""
    return AgentSessionStore(
        "https://fleet.example.test",
        "deployment-test",
        "agent-test",
        directory=directory,
        now=lambda: now,
    )


def test_session_store_round_trips_and_rotates_with_private_permissions(
    tmp_path: Path,
) -> None:
    """Rotation is atomic, scoped, and never exposes the bearer in a path."""
    directory = tmp_path / "sessions"
    store = session_store(directory)
    store.save(AgentSessionCredential(TOKEN, 1_900))

    assert store.load() == AgentSessionCredential(TOKEN, 1_900)
    assert directory.stat().st_mode & 0o777 == 0o700
    assert store.path.stat().st_mode & 0o777 == 0o600
    assert TOKEN not in str(store.path)

    store.save(AgentSessionCredential(ROTATED, 2_000))
    assert store.load() == AgentSessionCredential(ROTATED, 2_000)
    assert TOKEN not in store.path.read_text(encoding="utf-8")
    assert TOKEN not in repr(store.load())


@pytest.mark.parametrize(
    "payload",
    [
        "not-json",
        "{}",
        json.dumps(
            {
                "version": 1,
                "deploymentId": "different-deployment",
                "agentId": "agent-test",
                "token": TOKEN,
                "expiresAt": 1_900,
            }
        ),
        json.dumps(
            {
                "version": 1,
                "deploymentId": "deployment-test",
                "agentId": "agent-test",
                "token": TOKEN,
                "expiresAt": 999,
            }
        ),
    ],
)
def test_session_store_fails_closed_for_untrusted_content(
    tmp_path: Path,
    payload: str,
) -> None:
    """Malformed, mismatched, and expired cache records grant no session."""
    store = session_store(tmp_path)
    store.path.write_text(payload, encoding="utf-8")
    os.chmod(store.path, 0o600)

    assert store.load() is None


def test_session_store_rejects_symlinks_and_broad_permissions(tmp_path: Path) -> None:
    """Filesystem redirection and cross-user disclosure attempts fail closed."""
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    os.chmod(target, 0o600)
    symlink_store = session_store(tmp_path / "symlink-cache")
    symlink_store.directory.mkdir(mode=0o700)
    os.symlink(target, symlink_store.path)
    with pytest.raises(AgentSessionStoreError, match="non-symlink"):
        symlink_store.load()

    broad_store = session_store(tmp_path / "broad-cache")
    broad_store.save(AgentSessionCredential(TOKEN, 1_900))
    os.chmod(broad_store.path, 0o644)
    with pytest.raises(AgentSessionStoreError, match="0600"):
        broad_store.load()

    os.chmod(broad_store.path, 0o600)
    os.chmod(broad_store.directory, 0o755)  # noqa: S103 - adversarial fixture
    with pytest.raises(AgentSessionStoreError, match="0700"):
        broad_store.load()


def test_session_store_rejects_invalid_identity_and_expired_write(tmp_path: Path) -> None:
    """Caller-controlled scope and stale bearers cannot enter the cache."""
    with pytest.raises(ValueError, match="safe identifiers"):
        AgentSessionStore(
            "https://fleet.example.test",
            "../deployment",
            "agent-test",
            directory=tmp_path,
        )
    with pytest.raises(ValueError, match="expired"):
        session_store(tmp_path).save(AgentSessionCredential(TOKEN, 1_000))
    with pytest.raises(ValueError, match="16-4096"):
        AgentSessionCredential("short", 1_900)


def test_session_store_rejects_invalid_endpoint_clock_and_credential_types(
    tmp_path: Path,
) -> None:
    """Programmer errors cannot create an ambiguous credential boundary."""
    with pytest.raises(ValueError, match="HTTPS"):
        AgentSessionStore("http://fleet.example.test", "deployment", "agent")
    with pytest.raises(ValueError, match="clock"):
        AgentSessionStore(
            "https://fleet.example.test",
            "deployment",
            "agent",
            now=cast(Callable[[], float], 123),
        )
    with pytest.raises(ValueError, match="Unix timestamp"):
        AgentSessionCredential(TOKEN, True)
    with pytest.raises(TypeError, match="AgentSessionCredential"):
        session_store(tmp_path).save(cast(AgentSessionCredential, TOKEN))


def test_session_store_missing_oversized_and_invalid_credentials_fail_closed(
    tmp_path: Path,
) -> None:
    """Bounded parsing rejects absent, oversized, and malformed records."""
    store = session_store(tmp_path)
    assert store.load() is None

    store.path.write_text("x" * 4_097, encoding="utf-8")
    os.chmod(store.path, 0o600)
    assert store.load() is None

    store.path.write_text(
        json.dumps(
            {
                "version": 1,
                "deploymentId": "deployment-test",
                "agentId": "agent-test",
                "token": "short",
                "expiresAt": 1_900,
            }
        ),
        encoding="utf-8",
    )
    assert store.load() is None


def test_session_store_removes_temporary_file_when_atomic_replace_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A failed rotation leaves neither a partial credential nor temp secret."""
    store = session_store(tmp_path)

    def fail_replace(_source: object, _destination: object) -> None:
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(AgentSessionStoreError, match="could not be written"):
        store.save(AgentSessionCredential(TOKEN, 1_900))
    assert not list(tmp_path.glob(".session-*"))


def test_session_store_rejects_symlinked_parent_and_foreign_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Parent redirection and a different effective owner fail before use."""
    target = tmp_path / "real"
    target.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    os.symlink(target, linked)
    with pytest.raises(AgentSessionStoreError, match="must not be a symlink"):
        session_store(linked / "sessions").save(AgentSessionCredential(TOKEN, 1_900))

    owned_store = session_store(tmp_path / "owned")
    owned_store.save(AgentSessionCredential(TOKEN, 1_900))
    actual_uid = os.getuid() if hasattr(os, "getuid") else 0
    monkeypatch.setattr(os, "getuid", lambda: actual_uid + 1)
    with pytest.raises(AgentSessionStoreError, match="owned by this user"):
        owned_store.load()
