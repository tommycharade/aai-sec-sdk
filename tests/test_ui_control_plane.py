"""Contract and adversarial tests for the optional UI control plane."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from agentic_security import (
    ControlPlaneApplication,
    ControlPlaneConfigurationError,
    ControlPlaneStore,
    validate_configuration,
)
from agentic_security.ui_control_plane import _bool, _number, _positive_int, _text

TOKEN = "synthetic-local-token-1234"  # noqa: S105 - synthetic test credential


def request(
    app: ControlPlaneApplication,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    token: str | None = TOKEN,
) -> tuple[str, dict[str, Any]]:
    """Call the WSGI boundary with a synthetic authenticated request."""
    encoded = json.dumps(body).encode() if body is not None else b""
    status: list[str] = []

    def start_response(value: str, _headers: list[tuple[str, str]]) -> None:
        status.append(value)

    environ: dict[str, Any] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(encoded)),
        "wsgi.input": io.BytesIO(encoded),
    }
    if token is not None:
        environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    payload = b"".join(app(environ, start_response))
    return status[0], json.loads(payload or b"{}")


def test_control_plane_requires_bearer_authentication(tmp_path: Path) -> None:
    app = ControlPlaneApplication(ControlPlaneStore(tmp_path / "config.json"), TOKEN)

    status, payload = request(app, "GET", "/api/configuration", token=None)

    assert status.startswith("401")
    assert payload == {"error": "authentication required"}


def test_control_plane_reads_saves_and_reloads_complete_configuration(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    app = ControlPlaneApplication(ControlPlaneStore(path), TOKEN)
    _, initial = request(app, "GET", "/api/configuration")
    initial["runtime"]["maxActions"] = 7

    status, saved = request(app, "PUT", "/api/configuration", initial)
    reloaded = ControlPlaneStore(path).snapshot()

    assert status.startswith("200")
    assert saved["runtime"]["maxActions"] == 7
    assert reloaded["runtime"]["maxActions"] == 7


def test_configuration_rejects_unknown_fields_and_capture_without_redaction() -> None:
    invalid = {
        "runtime": {"unexpected": True},
        "claudeCode": {},
    }
    with pytest.raises(ControlPlaneConfigurationError):
        validate_configuration(invalid)


def test_control_plane_fails_closed_for_unsafe_capture_configuration(tmp_path: Path) -> None:
    app = ControlPlaneApplication(ControlPlaneStore(tmp_path / "config.json"), TOKEN)
    _, configuration = request(app, "GET", "/api/configuration")
    configuration["runtime"]["redactSensitiveData"] = False
    configuration["runtime"]["captureToolContent"] = True

    status, payload = request(app, "PUT", "/api/configuration", configuration)

    assert status.startswith("400")
    assert "requires sensitive-data redaction" in payload["error"]


def test_emergency_stop_is_persisted_and_dashboard_becomes_critical(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    app = ControlPlaneApplication(ControlPlaneStore(path), TOKEN)

    status, dashboard = request(app, "POST", "/api/emergency-stop")
    reloaded = ControlPlaneStore(path)

    assert status.startswith("200")
    assert dashboard["emergencyStop"] is True
    assert dashboard["posture"] == "critical"
    assert reloaded.snapshot()["dashboard"]["emergencyStop"] is True


@pytest.mark.parametrize(
    ("validator", "value"),
    [
        (_bool, "yes"),
        (_number, "one"),
        (_number, 0),
        (_positive_int, True),
        (_positive_int, 0),
        (_positive_int, 10_000_001),
        (_text, 42),
        (
            _text,
            "",
        ),
    ],
)
def test_scalar_configuration_validators_reject_ambiguous_values(
    validator: Any, value: Any
) -> None:
    """The config boundary must not coerce values into safety settings."""
    with pytest.raises(ControlPlaneConfigurationError):
        if validator is _text:
            validator(value, "field", allow_empty=False)
        else:
            validator(value, "field")


def test_control_plane_rejects_corrupt_persisted_state_and_short_tokens(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(ControlPlaneConfigurationError):
        ControlPlaneStore(path)
    store = ControlPlaneStore(tmp_path / "other.json")
    with pytest.raises(ValueError):
        ControlPlaneApplication(store, "short")
    with pytest.raises(ValueError):
        ControlPlaneApplication(store, TOKEN, max_body_bytes=0)


def test_wsgi_boundary_handles_options_routes_bodies_and_cors(tmp_path: Path) -> None:
    app = ControlPlaneApplication(ControlPlaneStore(tmp_path / "config.json"), TOKEN)

    status, _ = request(app, "OPTIONS", "/api/configuration", token=None)
    assert status.startswith("204")
    status, payload = request(app, "PATCH", "/api/configuration")
    assert status.startswith("405") and payload["error"] == "method not allowed"
    status, payload = request(app, "GET", "/unknown")
    assert status.startswith("404") and payload["error"] == "endpoint not found"

    status, payload = request(app, "PUT", "/api/configuration", {"bad": True})
    assert status.startswith("400") and "runtime" in payload["error"]

    encoded = b"{"  # Malformed JSON reaches the bounded body parser.
    responses: list[str] = []

    def start_response(value: str, _headers: list[tuple[str, str]]) -> None:
        responses.append(value)

    malformed = {
        "REQUEST_METHOD": "PUT",
        "PATH_INFO": "/api/configuration",
        "CONTENT_LENGTH": str(len(encoded)),
        "wsgi.input": io.BytesIO(encoded),
        "HTTP_AUTHORIZATION": f"Bearer {TOKEN}",
    }
    body = b"".join(app(malformed, start_response))
    assert responses[-1].startswith("400")
    assert json.loads(body)["error"] == "request is not valid JSON"

    status, _ = request(app, "GET", "/api/dashboard")
    assert status.startswith("200")
