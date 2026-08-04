from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from agentic_security.webhooks import (
    WebhookVerificationStatus,
    sign_webhook,
    verify_webhook,
)


@dataclass
class ReplayStore:
    claimed: dict[str, int] = field(default_factory=dict)
    fail: bool = False

    def claim(self, delivery_id: str, expires_at: int) -> bool:
        if self.fail:
            raise RuntimeError("synthetic unavailable store")
        if delivery_id in self.claimed:
            return False
        self.claimed[delivery_id] = expires_at
        return True


def test_webhook_signature_binds_raw_payload_identity_and_time() -> None:
    secret = b"s" * 32
    payload = b'{"event":"agent.quarantined"}'
    headers = sign_webhook(
        payload,
        delivery_id="delivery-123",
        timestamp=1_800_000_000,
        key_id="key-2026-08",
        secret=secret,
    )
    replay = ReplayStore()

    result = verify_webhook(
        payload,
        headers,
        keys={"key-2026-08": secret},
        replay_store=replay,
        now=lambda: 1_800_000_010,
    )

    assert result.status is WebhookVerificationStatus.VERIFIED
    assert result.verified is True
    assert replay.claimed == {"delivery-123": 1_800_000_300}


@pytest.mark.parametrize(
    ("change", "status"),
    [
        ("payload", WebhookVerificationStatus.INVALID),
        ("delivery", WebhookVerificationStatus.INVALID),
        ("timestamp", WebhookVerificationStatus.INVALID),
        ("key", WebhookVerificationStatus.INVALID),
        ("signature", WebhookVerificationStatus.INVALID),
        ("version", WebhookVerificationStatus.INVALID),
    ],
)
def test_webhook_verification_rejects_mutation_and_unknown_authority(
    change: str, status: WebhookVerificationStatus
) -> None:
    secret = b"a" * 32
    payload = b"{}"
    headers = sign_webhook(
        payload,
        delivery_id="delivery-1",
        timestamp=1000,
        key_id="key-1",
        secret=secret,
    )
    if change == "payload":
        payload = b'{"changed":true}'
    elif change == "delivery":
        headers["AAI-Webhook-Id"] = "delivery-2"
    elif change == "timestamp":
        headers["AAI-Webhook-Timestamp"] = "1001"
    elif change == "key":
        headers["AAI-Webhook-Key-Id"] = "unknown"
    elif change == "signature":
        headers["AAI-Webhook-Signature"] = "v1=" + "0" * 64
    else:
        headers["AAI-Webhook-Version"] = "2"

    result = verify_webhook(
        payload,
        headers,
        keys={"key-1": secret},
        replay_store=ReplayStore(),
        now=lambda: 1000,
    )

    assert result.status is status
    assert result.verified is False


def test_webhook_freshness_replay_and_store_outage_fail_closed() -> None:
    secret = b"b" * 32
    headers = sign_webhook(
        b"{}", delivery_id="delivery-2", timestamp=2_000, key_id="key-2", secret=secret
    )
    replay = ReplayStore()
    assert (
        verify_webhook(
            b"{}", headers, keys={"key-2": secret}, replay_store=replay, now=lambda: 2_301
        ).status
        is WebhookVerificationStatus.EXPIRED
    )
    assert (
        verify_webhook(
            b"{}", headers, keys={"key-2": secret}, replay_store=replay, now=lambda: 2_000
        ).status
        is WebhookVerificationStatus.VERIFIED
    )
    assert (
        verify_webhook(
            b"{}", headers, keys={"key-2": secret}, replay_store=replay, now=lambda: 2_000
        ).status
        is WebhookVerificationStatus.REPLAYED
    )
    assert (
        verify_webhook(
            b"{}",
            headers,
            keys={"key-2": secret},
            replay_store=ReplayStore(fail=True),
            now=lambda: 2_000,
        ).status
        is WebhookVerificationStatus.INVALID
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"payload": b"x" * 65_537},
        {"delivery_id": "contains space"},
        {"timestamp": -1},
        {"timestamp": 10_000_000_000},
        {"key_id": "contains:colon"},
        {"secret": b"short"},
    ],
)
def test_webhook_signer_rejects_unsafe_inputs(kwargs: dict[str, object]) -> None:
    values: dict[str, object] = {
        "payload": b"{}",
        "delivery_id": "delivery-3",
        "timestamp": 3_000,
        "key_id": "key-3",
        "secret": b"c" * 32,
    }
    values.update(kwargs)
    with pytest.raises(ValueError):
        sign_webhook(**values)  # type: ignore[arg-type]


def test_webhook_verifier_accepts_case_insensitive_headers_and_overlapping_keys() -> None:
    old = b"o" * 32
    new_headers = sign_webhook(
        b"{}", delivery_id="delivery-4", timestamp=4_000, key_id="new-key", secret=b"n" * 32
    )
    old_headers = sign_webhook(
        b"{}", delivery_id="delivery-4", timestamp=4_000, key_id="old-key", secret=old
    )
    new_headers["AAI-Webhook-Previous-Key-Id"] = old_headers["AAI-Webhook-Key-Id"]
    new_headers["AAI-Webhook-Previous-Signature"] = old_headers["AAI-Webhook-Signature"]
    headers = {key.lower(): value for key, value in new_headers.items()}
    result = verify_webhook(
        b"{}",
        headers,
        keys={"old-key": old},
        replay_store=ReplayStore(),
        now=lambda: 4_000,
    )
    assert result.status is WebhookVerificationStatus.VERIFIED
    assert result.key_id == "old-key"


def test_webhook_verifier_rejects_ambiguous_headers_and_clock_failure() -> None:
    secret = b"s" * 32
    headers = sign_webhook(
        b"{}", delivery_id="delivery-5", timestamp=5_000, key_id="key-5", secret=secret
    )
    headers["aai-webhook-id"] = headers["AAI-Webhook-Id"]
    assert (
        verify_webhook(
            b"{}", headers, keys={"key-5": secret}, replay_store=ReplayStore(), now=lambda: 5_000
        ).status
        is WebhookVerificationStatus.INVALID
    )

    clean = {name: value for name, value in headers.items() if name != "aai-webhook-id"}

    def unavailable_clock() -> int:
        raise RuntimeError("synthetic clock outage")

    assert (
        verify_webhook(
            b"{}",
            clean,
            keys={"key-5": secret},
            replay_store=ReplayStore(),
            now=unavailable_clock,
        ).status
        is WebhookVerificationStatus.INVALID
    )
