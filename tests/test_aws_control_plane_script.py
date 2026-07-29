"""Contract tests for the deployed AWS acceptance harness."""

from __future__ import annotations

import json
import urllib.request
from typing import Any

from scripts import test_aws_control_plane


class _Response:
    """Minimal HTTPS response used to inspect the outgoing smoke request."""

    status = 200

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps({"status": "connected"}).encode()


def test_request_sends_project_root_digest_only_when_explicitly_bound(monkeypatch: Any) -> None:
    """The harness must distinguish bound heartbeats from bypass attempts."""
    requests: list[Any] = []

    def urlopen(request: Any, **_kwargs: object) -> _Response:
        requests.append(request)
        return _Response()

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)

    test_aws_control_plane._request(
        "https://control-plane.example.test/agent/deployment/agent/heartbeat",
        "POST",
    )
    test_aws_control_plane._request(
        "https://control-plane.example.test/agent/deployment/agent/heartbeat",
        "POST",
        project_root_digest="a" * 64,
    )

    assert requests[0].get_header("X-aai-project-root-digest") is None
    assert requests[1].get_header("X-aai-project-root-digest") == "a" * 64
