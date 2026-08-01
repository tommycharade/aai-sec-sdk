#!/usr/bin/env python3
"""Publish one signed endpoint report to the hosted control plane.

The per-device secret is read only from an environment variable and placed in
the HTTPS Authorization header. It is never accepted as a command argument,
written to output, or included in an exception message.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


class EndpointPublishError(RuntimeError):
    """Report a local contract, transport or fail-closed service failure."""


def _identifier(value: str, label: str) -> str:
    """Validate one URL-safe opaque control-plane identifier."""
    if not _IDENTIFIER.fullmatch(value):
        raise EndpointPublishError(f"{label} is invalid")
    return value


def _report(path: Path, device_id: str) -> bytes:
    """Read a bounded report and prove its visible device binding."""
    try:
        if path.stat().st_size > 1_000_000:
            raise EndpointPublishError("endpoint report exceeds one megabyte")
        value: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EndpointPublishError("endpoint report could not be read") from error
    if not isinstance(value, dict) or set(value) != {"keyId", "payload", "signature"}:
        raise EndpointPublishError("endpoint report has an invalid schema")
    payload = value.get("payload")
    device = payload.get("device") if isinstance(payload, dict) else None
    if not isinstance(device, dict) or device.get("id") != device_id:
        raise EndpointPublishError("endpoint report device identity mismatch")
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def publish_report(
    *,
    api_url: str,
    tenant_id: str,
    device_id: str,
    report_path: Path,
    secret: str,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> dict[str, Any]:
    """Publish one report with bounded idempotent retries and an explicit timeout."""
    tenant = _identifier(tenant_id, "tenantId")
    device = _identifier(device_id, "deviceId")
    if len(secret.encode()) < 32:
        raise EndpointPublishError("endpoint credential is missing or too short")
    parsed = urllib.parse.urlsplit(api_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise EndpointPublishError("control-plane API URL must be an HTTPS origin")
    origin = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")
    url = f"{origin}/endpoint-evidence/{urllib.parse.quote(tenant)}/{urllib.parse.quote(device)}"
    body = _report(report_path, device)
    # The origin was reduced to an HTTPS-only authority above; no request URL
    # is accepted directly from report or model content.
    request = urllib.request.Request(  # noqa: S310
        url,
        data=body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/json",
            "User-Agent": "aai-security-endpoint-publisher/1",
        },
    )
    for attempt in range(3):
        try:
            with opener(request, timeout=10, context=ssl.create_default_context()) as response:
                result = json.loads(response.read(1_000_001))
                if not isinstance(result, dict) or result.get("accepted") is not True:
                    raise EndpointPublishError("control plane returned an invalid acknowledgement")
                return result
        except urllib.error.HTTPError as error:
            if error.code < 500 or attempt == 2:
                raise EndpointPublishError(
                    f"control plane rejected endpoint evidence (HTTP {error.code})"
                ) from error
        except (urllib.error.URLError, TimeoutError) as error:
            if attempt == 2:
                raise EndpointPublishError(
                    "endpoint evidence transport failed after bounded retries"
                ) from error
        time.sleep(2**attempt)
    raise EndpointPublishError("endpoint evidence transport failed")


def _parser() -> argparse.ArgumentParser:
    """Build a command line that never accepts plaintext credential material."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--secret-env", default="AAI_ENDPOINT_EVIDENCE_KEY")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Publish one report and print only its content-free acknowledgement."""
    arguments = _parser().parse_args(argv)
    try:
        result = publish_report(
            api_url=arguments.api_url,
            tenant_id=arguments.tenant_id,
            device_id=arguments.device_id,
            report_path=arguments.report,
            secret=os.environ.get(arguments.secret_env, ""),
        )
    except EndpointPublishError as error:
        print(f"Endpoint evidence publication failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
