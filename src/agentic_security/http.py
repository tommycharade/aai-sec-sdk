"""Small authenticated JSON-over-HTTPS transport used by integration adapters."""

from __future__ import annotations

import json
from collections.abc import Mapping
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .errors import SecurityConfigurationError


class JsonHttpClient:
    """POST JSON to one configured endpoint with an explicit network timeout.

    The client deliberately owns no credential discovery or retry policy. The
    caller supplies authenticated headers and decides whether a retry is safe
    for the target operation.
    """

    def __init__(
        self,
        endpoint: str,
        headers: Mapping[str, str] | None = None,
        timeout_seconds: float = 5.0,
        allow_insecure_localhost: bool = False,
    ) -> None:
        """Configure a JSON endpoint; HTTPS is required except explicit localhost tests."""
        parsed = urlparse(endpoint)
        local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not (allow_insecure_localhost and local):
            raise SecurityConfigurationError("integration endpoints must use HTTPS")
        if timeout_seconds <= 0:
            raise SecurityConfigurationError("HTTP timeout must be positive")
        self.endpoint = endpoint
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.timeout_seconds = timeout_seconds

    def post(self, payload: Mapping[str, object]) -> Mapping[str, object]:
        """POST one JSON object and fail on non-JSON or non-object responses."""
        request = Request(  # noqa: S310 - endpoint scheme validated in __init__
            self.endpoint,
            data=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
            headers=self.headers,
            method="POST",
        )
        with urlopen(request, timeout=self.timeout_seconds) as response:  # noqa: S310
            value = json.loads(response.read())
        if not isinstance(value, Mapping):
            raise ValueError("integration response must be a JSON object")
        return value
