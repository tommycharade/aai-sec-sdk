"""Contracts for the secret-safe hosted endpoint evidence transport."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest


def _module() -> Any:
    path = Path(__file__).parents[1] / "scripts/publish_endpoint_evidence.py"
    spec = importlib.util.spec_from_file_location("publish_endpoint_evidence", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _report(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "keyId": "key-a",
                "payload": {
                    "schemaVersion": 1,
                    "observedAt": 1,
                    "device": {"id": "device-a", "managed": True},
                    "installations": [],
                },
                "signature": "a" * 64,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_publisher_uses_https_header_and_never_places_secret_in_url(tmp_path: Path) -> None:
    module = _module()
    captured: dict[str, Any] = {}

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_: Any) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return b'{"accepted":true,"duplicate":false,"deviceId":"device-a"}'

    def opener(request: Any, **kwargs: Any) -> Response:
        captured.update({"request": request, "kwargs": kwargs})
        return Response()

    secret = "s" * 32
    result = module.publish_report(
        api_url="https://control.example.test/api/ignored",
        tenant_id="tenant-a",
        device_id="device-a",
        report_path=_report(tmp_path / "report.json"),
        secret=secret,
        opener=opener,
    )
    request = captured["request"]
    assert result["accepted"] is True
    assert request.full_url == "https://control.example.test/endpoint-evidence/tenant-a/device-a"
    assert request.get_header("Authorization") == f"Bearer {secret}"
    assert secret not in request.full_url
    assert captured["kwargs"]["timeout"] == 10


@pytest.mark.parametrize(
    "url",
    ["http://control.example.test", "https://user:pass@control.example.test", "/relative"],
)
def test_publisher_rejects_unsafe_origins_and_device_mismatch(tmp_path: Path, url: str) -> None:
    module = _module()
    with pytest.raises(module.EndpointPublishError):
        module.publish_report(
            api_url=url,
            tenant_id="tenant-a",
            device_id="device-a",
            report_path=_report(tmp_path / "report.json"),
            secret="s" * 32,
        )
    with pytest.raises(module.EndpointPublishError, match="device identity"):
        module.publish_report(
            api_url="https://control.example.test",
            tenant_id="tenant-a",
            device_id="device-b",
            report_path=_report(tmp_path / "mismatch.json"),
            secret="s" * 32,
        )


def test_cli_has_no_plaintext_secret_option() -> None:
    module = _module()
    options = {option for action in module._parser()._actions for option in action.option_strings}
    assert "--secret" not in options
