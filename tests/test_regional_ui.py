"""Unit and adversarial tests for the private-bucket Regional UI handler."""

from __future__ import annotations

import importlib.util
import io
import sys
import types
from pathlib import Path
from typing import Any

import pytest


class _S3:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        self.calls.append((Bucket, Key))
        return {"Body": io.BytesIO(b"asset"), "ContentType": "text/plain"}


def _load(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, _S3]:
    s3 = _S3()
    boto3 = types.ModuleType("boto3")
    boto3.client = lambda _name: s3  # type: ignore[attr-defined]
    botocore = types.ModuleType("botocore")
    exceptions = types.ModuleType("botocore.exceptions")
    exceptions.ClientError = type("ClientError", (Exception,), {})  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.exceptions", exceptions)
    path = Path(__file__).parents[1] / "infra/aws-control-plane/lambda/regional_ui.py"
    spec = importlib.util.spec_from_file_location("aai_regional_ui", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, s3


def _event(path: str = "/") -> dict[str, Any]:
    return {"rawPath": path, "requestContext": {"http": {"method": "GET"}}}


def test_handler_serves_asset_with_exact_browser_trust_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, s3 = _load(monkeypatch)
    monkeypatch.setenv("REGIONAL_UI_BUCKET", "private-ui")
    monkeypatch.setenv("REGIONAL_UI_API_ORIGIN", "https://api.security.example.com")
    monkeypatch.setenv("REGIONAL_UI_COGNITO_ORIGIN", "https://login.security.example.com")
    response = module.handler(_event(), None)
    assert s3.calls == [("private-ui", "index.html")]
    assert response["statusCode"] == 200
    assert "https://api.security.example.com" in response["headers"]["content-security-policy"]
    assert "https://login.security.example.com" in response["headers"]["content-security-policy"]
    assert response["headers"]["x-frame-options"] == "DENY"


def test_cache_policy_is_immutable_only_for_content_hashed_assets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, _s3 = _load(monkeypatch)
    assert module._read_asset("private-ui", "app.js")[2] == ("public, max-age=300, must-revalidate")
    assert module._read_asset("private-ui", "app.1234abcd.js")[2] == (
        "public, max-age=31536000, immutable"
    )


@pytest.mark.parametrize("path", ["/../secret", "/a/../../secret", "/%2e%2e/secret", "/a\\b"])
def test_handler_denies_path_traversal(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    module, _s3 = _load(monkeypatch)
    with pytest.raises(ValueError, match="denied|unsafe"):
        module._asset_key(_event(path))


@pytest.mark.parametrize(
    "name,value",
    [
        ("REGIONAL_UI_API_ORIGIN", "http://api.security.example.com"),
        ("REGIONAL_UI_COGNITO_ORIGIN", "https://login.security.example.com/path"),
    ],
)
def test_handler_rejects_substituted_browser_origin(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    module, _s3 = _load(monkeypatch)
    monkeypatch.setenv("REGIONAL_UI_BUCKET", "private-ui")
    monkeypatch.setenv("REGIONAL_UI_API_ORIGIN", "https://api.security.example.com")
    monkeypatch.setenv("REGIONAL_UI_COGNITO_ORIGIN", "https://login.security.example.com")
    monkeypatch.setenv(name, value)
    with pytest.raises(RuntimeError, match="exact HTTPS origin"):
        module.handler(_event(), None)
