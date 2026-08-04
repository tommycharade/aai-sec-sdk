"""Sign and verify bounded webhook messages without trusting decoded content.

Webhook signatures bind the exact HTTP body, delivery identifier, and server
timestamp.  Verification therefore receives raw bytes rather than a decoded
mapping: parsing and re-serializing JSON before verification could otherwise
change the bytes being authorized.  Replay state belongs to the receiving
application and must be committed atomically through :class:`WebhookReplayStore`.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

_DELIVERY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SIGNATURE = re.compile(r"^v1=([0-9a-f]{64})$")
_MAX_PAYLOAD_BYTES = 65_536
_MIN_SECRET_BYTES = 32


class WebhookVerificationStatus(StrEnum):
    """Fail-closed outcome of one webhook verification attempt."""

    VERIFIED = "verified"
    INVALID = "invalid"
    EXPIRED = "expired"
    REPLAYED = "replayed"


@dataclass(frozen=True, slots=True)
class WebhookVerification:
    """Structured webhook result that never treats an unknown state as valid.

    Attributes:
        status: Authoritative verification outcome.
        delivery_id: Validated delivery identifier, or an empty string when
            request metadata was malformed.
        key_id: Key that matched the signature, or an empty string on failure.
        reason: Content-free explanation suitable for diagnostics.
    """

    status: WebhookVerificationStatus
    delivery_id: str = ""
    key_id: str = ""
    reason: str = ""

    @property
    def verified(self) -> bool:
        """Return true only after signature, freshness, and replay checks pass."""
        return self.status is WebhookVerificationStatus.VERIFIED


class WebhookReplayStore(Protocol):
    """Atomic receiver-owned store for accepted delivery identifiers."""

    def claim(self, delivery_id: str, expires_at: int) -> bool:
        """Claim one delivery until ``expires_at`` or return false if already claimed.

        Implementations must make the check-and-write atomic.  A database
        outage or indeterminate commit must raise; callers fail closed.
        """


def _signed_bytes(timestamp: int, delivery_id: str, payload: bytes) -> bytes:
    """Build the version-one byte sequence shared by signer and verifier."""
    return str(timestamp).encode("ascii") + b"." + delivery_id.encode("ascii") + b"." + payload


def sign_webhook(
    payload: bytes,
    *,
    delivery_id: str,
    timestamp: int,
    key_id: str,
    secret: bytes,
) -> dict[str, str]:
    """Return transport headers that authenticate one exact webhook body.

    Args:
        payload: Exact bytes that will be sent in the HTTP request body.
        delivery_id: Sender-generated identifier used for receiver deduplication.
        timestamp: Sender Unix timestamp included in the signature.
        key_id: Non-secret identifier for selecting receiver key material.
        secret: At least 32 bytes of application-owned HMAC key material.

    Returns:
        A fresh header mapping containing version, delivery, timestamp, key,
        and HMAC-SHA256 signature values.

    Raises:
        ValueError: If any input is malformed or exceeds a security bound.

    Security:
        The caller owns secret storage and must transmit ``payload`` unchanged.
        This function performs no I/O and does not retain the supplied secret.
    """
    if not isinstance(payload, bytes) or len(payload) > _MAX_PAYLOAD_BYTES:
        raise ValueError("webhook payload must be bytes no larger than 65536 bytes")
    if (
        not isinstance(timestamp, int)
        or isinstance(timestamp, bool)
        or not 0 <= timestamp <= 9_999_999_999
    ):
        raise ValueError("webhook timestamp must be a bounded non-negative integer")
    if not isinstance(delivery_id, str) or not _DELIVERY_ID.fullmatch(delivery_id):
        raise ValueError("webhook delivery ID is invalid")
    if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
        raise ValueError("webhook key ID is invalid")
    if not isinstance(secret, bytes) or len(secret) < _MIN_SECRET_BYTES:
        raise ValueError("webhook secret must contain at least 32 bytes")
    signature = hmac.new(
        secret,
        _signed_bytes(timestamp, delivery_id, payload),
        hashlib.sha256,
    ).hexdigest()
    return {
        "AAI-Webhook-Version": "1",
        "AAI-Webhook-Id": delivery_id,
        "AAI-Webhook-Timestamp": str(timestamp),
        "AAI-Webhook-Key-Id": key_id,
        "AAI-Webhook-Signature": f"v1={signature}",
    }


def verify_webhook(
    payload: bytes,
    headers: Mapping[str, str],
    *,
    keys: Mapping[str, bytes],
    replay_store: WebhookReplayStore,
    now: Callable[[], int] | None = None,
    tolerance_seconds: int = 300,
) -> WebhookVerification:
    """Verify exact bytes, timestamp freshness, and single-use delivery identity.

    Args:
        payload: Unmodified request body bytes.
        headers: Case-insensitive webhook headers from the HTTP request.
        keys: Receiver-owned key IDs mapped to HMAC secrets. During rotation,
            include both current and previous keys.
        replay_store: Atomic store used only after a signature matches.
        now: Injectable Unix-time source for deterministic tests.
        tolerance_seconds: Maximum absolute sender clock skew, from 30 to 900.

    Returns:
        A structured result. Malformed, stale, unknown-key, altered, replayed,
        and replay-store-failure requests never return ``VERIFIED``.

    Security:
        Key material and replay authority must come from authenticated host
        configuration, never from webhook content or model output.
    """
    if (
        not isinstance(payload, bytes)
        or len(payload) > _MAX_PAYLOAD_BYTES
        or not isinstance(tolerance_seconds, int)
        or isinstance(tolerance_seconds, bool)
        or not 30 <= tolerance_seconds <= 900
    ):
        return WebhookVerification(WebhookVerificationStatus.INVALID, reason="invalid bounds")
    if not isinstance(headers, Mapping) or not isinstance(keys, Mapping):
        return WebhookVerification(WebhookVerificationStatus.INVALID, reason="invalid mappings")
    normalized: dict[str, str] = {}
    try:
        for name, value in headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                return WebhookVerification(
                    WebhookVerificationStatus.INVALID, reason="malformed headers"
                )
            lowered = name.lower()
            # Differently-cased duplicates are ambiguous after HTTP framework
            # normalization and must not gain last-value-wins authority.
            if lowered in normalized:
                return WebhookVerification(
                    WebhookVerificationStatus.INVALID, reason="duplicate headers"
                )
            normalized[lowered] = value
    except Exception:
        return WebhookVerification(WebhookVerificationStatus.INVALID, reason="malformed headers")
    if normalized.get("aai-webhook-version") != "1":
        return WebhookVerification(WebhookVerificationStatus.INVALID, reason="unsupported version")
    delivery_id = normalized.get("aai-webhook-id", "")
    timestamp_text = normalized.get("aai-webhook-timestamp", "")
    candidates = [
        (
            normalized.get("aai-webhook-key-id", ""),
            normalized.get("aai-webhook-signature", ""),
        )
    ]
    previous_key = normalized.get("aai-webhook-previous-key-id")
    previous_signature = normalized.get("aai-webhook-previous-signature")
    if previous_key is not None or previous_signature is not None:
        candidates.append((previous_key or "", previous_signature or ""))
    if (
        not _DELIVERY_ID.fullmatch(delivery_id)
        or not timestamp_text.isascii()
        or not timestamp_text.isdigit()
        or len(timestamp_text) > 10
        or any(
            not _KEY_ID.fullmatch(key_id) or not _SIGNATURE.fullmatch(signature)
            for key_id, signature in candidates
        )
    ):
        return WebhookVerification(WebhookVerificationStatus.INVALID, reason="malformed metadata")
    timestamp = int(timestamp_text)
    try:
        current = int(time.time()) if now is None else now()
    except Exception:
        return WebhookVerification(WebhookVerificationStatus.INVALID, reason="clock unavailable")
    if not isinstance(current, int) or isinstance(current, bool):
        return WebhookVerification(WebhookVerificationStatus.INVALID, reason="invalid clock")
    if abs(current - timestamp) > tolerance_seconds:
        return WebhookVerification(
            WebhookVerificationStatus.EXPIRED,
            delivery_id=delivery_id,
            reason="timestamp outside tolerance",
        )
    matched_key = ""
    for candidate_key, candidate_signature in candidates:
        try:
            secret = keys.get(candidate_key)
        except Exception:
            return WebhookVerification(
                WebhookVerificationStatus.INVALID, reason="key store unavailable"
            )
        if not isinstance(secret, bytes) or len(secret) < _MIN_SECRET_BYTES:
            continue
        supplied = _SIGNATURE.fullmatch(candidate_signature)
        assert supplied is not None  # Guarded by the schema check above.
        expected = hmac.new(
            secret,
            _signed_bytes(timestamp, delivery_id, payload),
            hashlib.sha256,
        ).hexdigest()
        if hmac.compare_digest(supplied.group(1), expected):
            matched_key = candidate_key
            break
    if not matched_key:
        return WebhookVerification(
            WebhookVerificationStatus.INVALID,
            delivery_id=delivery_id,
            reason="unknown key or signature mismatch",
        )
    try:
        claimed = replay_store.claim(delivery_id, timestamp + tolerance_seconds)
    except Exception:
        return WebhookVerification(
            WebhookVerificationStatus.INVALID,
            delivery_id=delivery_id,
            key_id=matched_key,
            reason="replay store unavailable",
        )
    return WebhookVerification(
        WebhookVerificationStatus.VERIFIED if claimed else WebhookVerificationStatus.REPLAYED,
        delivery_id=delivery_id,
        key_id=matched_key,
        reason="accepted" if claimed else "delivery already claimed",
    )
