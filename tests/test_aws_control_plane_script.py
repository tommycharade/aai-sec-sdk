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


def test_agent_stop_requires_typed_server_owned_control_state() -> None:
    """The live harness must reject legacy or incomplete stop responses."""
    valid = {
        "controlState": {
            "executionAllowed": False,
            "evidenceAllowed": True,
            "activeStopScopes": ["deployment", "agent"],
            "quarantine": None,
        }
    }

    assert test_aws_control_plane._agent_stop_is_enforced(409, valid) is True
    assert test_aws_control_plane._agent_stop_is_enforced(409, {"emergencyStop": True}) is False
    assert (
        test_aws_control_plane._agent_stop_is_enforced(
            409,
            {
                "controlState": {
                    "executionAllowed": False,
                    "evidenceAllowed": True,
                    "activeStopScopes": ["group"],
                }
            },
        )
        is False
    )
    assert test_aws_control_plane._agent_stop_is_enforced(200, valid) is False
