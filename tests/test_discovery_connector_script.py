"""Tests for the source-scoped atomic discovery publisher."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest


def _module() -> Any:
    path = Path(__file__).parents[1] / "scripts/publish_discovery_generation.py"
    spec = importlib.util.spec_from_file_location("publish_discovery_generation", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_publisher_uploads_pages_then_commits_returned_hashes() -> None:
    module = _module()
    calls: list[tuple[str, str, str, dict[str, Any]]] = []

    def request(
        url: str, method: str, token: str, body: dict[str, Any], **_: Any
    ) -> dict[str, Any]:
        calls.append((url, method, token, body))
        if "/pages/" in url:
            return {"pageHash": f"{len(calls):064x}"}
        return {"revision": 4}

    result = module.publish_generation(
        api_url="https://control.example.invalid",
        tenant_id="tenant-a",
        source_id="github-a",
        token="synthetic-source-token",  # noqa: S106
        generation="generation-a",
        expected_revision=3,
        observed_at=100,
        expires_at=200,
        observations=[{"kind": "repository", "id": str(index)} for index in range(3)],
        page_size=2,
        request_json=request,
    )
    assert result == {"revision": 4}
    assert [call[1] for call in calls] == ["POST", "PUT", "PUT", "POST"]
    assert calls[0][3]["pageCount"] == 2
    assert calls[-1][3] == {"pageHashes": [f"{2:064x}", f"{3:064x}"]}
    assert all(call[2] == "synthetic-source-token" for call in calls)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"token": ""}, "credential"),
        ({"page_size": 0}, "page size"),
        ({"expected_revision": -1}, "revision"),
        ({"api_url": "http://control.example.invalid"}, "HTTPS"),
    ],
)
def test_publisher_rejects_unsafe_local_configuration(change: dict[str, Any], message: str) -> None:
    module = _module()
    values: dict[str, Any] = {
        "api_url": "https://control.example.invalid",
        "tenant_id": "tenant-a",
        "source_id": "source-a",
        "token": "synthetic-source-token",
        "generation": "generation-a",
        "expected_revision": 0,
        "observed_at": 100,
        "expires_at": 200,
        "observations": [{"kind": "identity", "id": "user-a", "active": True}],
        "request_json": lambda *_args, **_kwargs: {},
    }
    values.update(change)
    with pytest.raises(module.DiscoveryPublishError, match=message):
        module.publish_generation(**values)


def test_publisher_stops_before_commit_when_a_page_response_is_invalid() -> None:
    module = _module()
    methods: list[str] = []

    def request(_url: str, method: str, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        methods.append(method)
        return {} if method == "PUT" else {"created": True}

    with pytest.raises(module.DiscoveryPublishError, match="page hash"):
        module.publish_generation(
            api_url="https://control.example.invalid",
            tenant_id="tenant-a",
            source_id="source-a",
            token="synthetic-source-token",  # noqa: S106
            generation="generation-a",
            expected_revision=0,
            observed_at=100,
            expires_at=200,
            observations=[{"kind": "identity", "id": "user-a", "active": True}],
            request_json=request,
        )
    assert methods == ["POST", "PUT"]
