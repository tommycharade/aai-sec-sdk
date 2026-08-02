"""Serve bounded static UI assets from one private regional S3 bucket.

The Lambda has no control-plane, credential, routing, or write authority. The
bucket identity comes from deployment configuration, never from the request.
"""

from __future__ import annotations

import base64
import mimetypes
import os
import posixpath
import re
import urllib.parse

import boto3
from botocore.exceptions import ClientError

S3 = boto3.client("s3")
_MAX_ASSET_BYTES = 5_000_000
_SECURITY_HEADERS = {
    "cross-origin-opener-policy": "same-origin",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}


def _https_origin(name: str) -> str:
    """Return one deployment-owned HTTPS origin for the browser trust policy."""
    value = os.environ.get(name, "")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.hostname != parsed.hostname.lower()
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.geturl() != value
    ):
        raise RuntimeError(f"{name} must be one exact HTTPS origin")
    return value


def _asset_key(event: object) -> str:
    """Return one normalized object key without accepting traversal aliases."""
    if not isinstance(event, dict):
        raise ValueError("regional UI event must be an object")
    request = event.get("requestContext")
    http = request.get("http") if isinstance(request, dict) else None
    method = http.get("method") if isinstance(http, dict) else None
    path = event.get("rawPath")
    if method not in {"GET", "HEAD"} or not isinstance(path, str) or len(path) > 2048:
        raise ValueError("regional UI request is invalid")
    try:
        decoded = urllib.parse.unquote(path, errors="strict")
    except UnicodeError as error:
        raise ValueError("regional UI path encoding is invalid") from error
    if "\x00" in decoded or "\\" in decoded:
        raise ValueError("regional UI path contains unsafe characters")
    stripped = decoded.lstrip("/")
    normalized = posixpath.normpath(stripped)
    if normalized in {"", "."}:
        return "index.html"
    if normalized == ".." or normalized.startswith("../") or normalized != stripped:
        raise ValueError("regional UI path traversal is denied")
    return normalized


def _read_asset(bucket: str, key: str) -> tuple[bytes, str, str]:
    """Read one bounded asset, falling back to the SPA index for missing keys."""
    selected = key
    try:
        response = S3.get_object(Bucket=bucket, Key=selected)
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code not in {"NoSuchKey", "404", "NotFound"} or key == "index.html":
            raise
        selected = "index.html"
        response = S3.get_object(Bucket=bucket, Key=selected)
    body = response.get("Body")
    if not hasattr(body, "read"):
        raise RuntimeError("regional UI asset body is unavailable")
    try:
        payload = body.read(_MAX_ASSET_BYTES + 1)
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    if not isinstance(payload, bytes) or len(payload) > _MAX_ASSET_BYTES:
        raise RuntimeError("regional UI asset exceeds 5 MB")
    content_type = response.get("ContentType")
    if not isinstance(content_type, str) or not content_type:
        content_type = mimetypes.guess_type(selected)[0] or "application/octet-stream"
    if selected == "index.html":
        cache = "no-store"
    elif re.search(r"(?:^|[.-])[0-9a-f]{8,}(?:[.-]|$)", selected, re.IGNORECASE):
        cache = "public, max-age=31536000, immutable"
    else:
        cache = "public, max-age=300, must-revalidate"
    return payload, content_type, cache


def handler(event: object, _context: object) -> dict[str, object]:
    """Return one private-bucket UI asset with restrictive browser headers."""
    bucket = os.environ.get("REGIONAL_UI_BUCKET", "")
    if not bucket or len(bucket) > 63:
        raise RuntimeError("regional UI bucket authority is unavailable")
    api_origin = _https_origin("REGIONAL_UI_API_ORIGIN")
    cognito_origin = _https_origin("REGIONAL_UI_COGNITO_ORIGIN")
    key = _asset_key(event)
    payload, content_type, cache = _read_asset(bucket, key)
    method = event["requestContext"]["http"]["method"]  # type: ignore[index]
    return {
        "statusCode": 200,
        "headers": {
            **_SECURITY_HEADERS,
            "content-security-policy": (
                "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
                f"connect-src 'self' {api_origin} {cognito_origin}; "
                "form-action 'self'; img-src 'self' data:; object-src 'none'; "
                "script-src 'self'; style-src 'self' 'unsafe-inline'"
            ),
            "cache-control": cache,
            "content-type": content_type,
        },
        "isBase64Encoded": True,
        "body": "" if method == "HEAD" else base64.b64encode(payload).decode("ascii"),
    }
