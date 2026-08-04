#!/usr/bin/env python3
"""Publish a normalized inventory file through atomic discovery ingestion.

The connector deliberately does not collect credentials from arguments or the
input file. A deployment injects the source-scoped bearer through an environment
variable, and the script sends only normalized observations accepted by the
control plane. Partial uploads remain invisible until the final commit succeeds.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import certifi

_DEFAULT_PAGE_SIZE = 1_000
_MAX_PAGE_SIZE = 1_000
_DEFAULT_TIMEOUT_SECONDS = 15.0


class DiscoveryPublishError(RuntimeError):
    """Report a bounded connector validation or transport failure."""


def _read_observations(path: Path) -> list[dict[str, Any]]:
    """Read a synthetic or deployment-owned normalized observation array."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DiscoveryPublishError(f"could not read normalized inventory: {error}") from error
    if isinstance(value, dict) and set(value) == {"observations"}:
        value = value["observations"]
    if not isinstance(value, list) or not value:
        raise DiscoveryPublishError("inventory must be a non-empty JSON observation array")
    if not all(isinstance(item, dict) for item in value):
        raise DiscoveryPublishError("every inventory observation must be an object")
    return value


def _endpoint(api_url: str, tenant_id: str, source_id: str) -> str:
    """Build an HTTPS ingestion endpoint without accepting URL path injection."""
    parsed = urllib.parse.urlsplit(api_url.rstrip("/"))
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise DiscoveryPublishError("api-url must be an HTTPS API Gateway origin")
    tenant_path = urllib.parse.quote(tenant_id, safe="")
    source_path = urllib.parse.quote(source_id, safe="")
    return f"{api_url.rstrip('/')}/discovery-ingest/{tenant_path}/{source_path}/generations"


def _request_json(
    url: str,
    method: str,
    token: str,
    body: dict[str, Any],
    *,
    timeout_seconds: float,
    open_request: Callable[..., Any] = urllib.request.urlopen,
) -> dict[str, Any]:
    """Send one bounded JSON request without logging secret or observation content."""
    if urllib.parse.urlsplit(url).scheme != "https":
        raise DiscoveryPublishError("control-plane request URL must use HTTPS")
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    # The exact URL is scheme-checked above; S310 cannot infer that guard.
    request = urllib.request.Request(  # noqa: S310
        url,
        data=encoded,
        method=method,
        headers={
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "user-agent": "aai-sec-discovery-connector/1",
        },
    )
    try:
        with open_request(
            request,
            timeout=timeout_seconds,
            context=ssl.create_default_context(cafile=certifi.where()),
        ) as response:
            payload = response.read()
    except urllib.error.HTTPError as error:
        raise DiscoveryPublishError(
            f"control plane rejected {method} with HTTP {error.code}"
        ) from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise DiscoveryPublishError(f"control-plane request failed: {error}") from error
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise DiscoveryPublishError("control plane returned malformed JSON") from error
    if not isinstance(value, dict):
        raise DiscoveryPublishError("control plane returned an invalid response")
    return value


def publish_generation(
    *,
    api_url: str,
    tenant_id: str,
    source_id: str,
    token: str,
    generation: str,
    expected_revision: int,
    observed_at: int,
    expires_at: int,
    observations: Sequence[dict[str, Any]],
    page_size: int = _DEFAULT_PAGE_SIZE,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    request_json: Callable[..., dict[str, Any]] = _request_json,
) -> dict[str, Any]:
    """Upload and atomically commit one bounded normalized generation.

    Args:
        api_url: HTTPS control-plane API Gateway origin without a path.
        tenant_id: Deployment-provisioned tenant identifier.
        source_id: Source identifier bound to the connector credential.
        token: Source-scoped secret supplied by the deployment environment.
        generation: Unique immutable generation identifier.
        expected_revision: Live source revision used for optimistic concurrency.
        observed_at: Unix time at which collection completed.
        expires_at: Unix time after which evidence is no longer current.
        observations: Content-minimised records matching the source schema.
        page_size: Records per page, from 1 through 1,000.
        timeout_seconds: Timeout applied independently to each HTTP operation.
        request_json: Injectable transport for deterministic tests.

    Returns:
        The committed source metadata returned by the control plane.

    Raises:
        DiscoveryPublishError: If local validation or any remote phase fails.

    Security:
        The token is used only in the Authorization header and is never returned
        or logged. Uploads have no effect until the hash-bound commit succeeds.
    """
    if not token:
        raise DiscoveryPublishError("connector credential is required")
    if isinstance(expected_revision, bool) or expected_revision < 0:
        raise DiscoveryPublishError("expected revision must be a non-negative integer")
    if not 1 <= page_size <= _MAX_PAGE_SIZE:
        raise DiscoveryPublishError("page size must be between 1 and 1000")
    if not observations:
        raise DiscoveryPublishError("at least one observation is required")
    pages = [
        list(observations[index : index + page_size])
        for index in range(0, len(observations), page_size)
    ]
    if len(pages) > 20:
        raise DiscoveryPublishError("generation exceeds the 20,000-observation control-plane limit")
    base = _endpoint(api_url, tenant_id, source_id)
    common = {"timeout_seconds": timeout_seconds}
    request_json(
        base,
        "POST",
        token,
        {
            "generation": generation,
            "expectedRevision": expected_revision,
            "observedAt": observed_at,
            "expiresAt": expires_at,
            "pageCount": len(pages),
        },
        **common,
    )
    page_hashes = []
    for page_number, page in enumerate(pages):
        result = request_json(
            f"{base}/{urllib.parse.quote(generation, safe='')}/pages/{page_number}",
            "PUT",
            token,
            {"observations": page},
            **common,
        )
        page_hash = result.get("pageHash")
        if not isinstance(page_hash, str) or len(page_hash) != 64:
            raise DiscoveryPublishError("control plane did not return a valid page hash")
        page_hashes.append(page_hash)
    return request_json(
        f"{base}/{urllib.parse.quote(generation, safe='')}/commit",
        "POST",
        token,
        {"pageHashes": page_hashes},
        **common,
    )


def _parser() -> argparse.ArgumentParser:
    """Build the command-line contract without accepting plaintext secret flags."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--valid-for-seconds", type=int, default=900)
    parser.add_argument("--page-size", type=int, default=_DEFAULT_PAGE_SIZE)
    parser.add_argument("--token-env", default="AAI_DISCOVERY_CONNECTOR_TOKEN")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Publish one file and print only non-sensitive committed metadata."""
    arguments = _parser().parse_args(argv)
    try:
        observations = _read_observations(arguments.input)
        token = os.environ.get(arguments.token_env, "")
        observed_at = int(time.time())
        result = publish_generation(
            api_url=arguments.api_url,
            tenant_id=arguments.tenant_id,
            source_id=arguments.source_id,
            token=token,
            generation=arguments.generation,
            expected_revision=arguments.expected_revision,
            observed_at=observed_at,
            expires_at=observed_at + arguments.valid_for_seconds,
            observations=observations,
            page_size=arguments.page_size,
        )
    except DiscoveryPublishError as error:
        print(f"Discovery publication failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
