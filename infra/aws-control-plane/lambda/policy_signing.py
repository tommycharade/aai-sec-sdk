"""Canonicalize and sign immutable tenant policy authority with AWS KMS.

This module deliberately contains no database or HTTP behavior. Activation and
trial provisioning call the same bounded contract, preventing signer drift.
The private key never enters Lambda memory; KMS receives only a SHA-256 digest.
"""

import base64
import hashlib
import hmac
import json
import math
import re

ALGORITHM = "ECDSA_SHA_256"
MAX_POLICY_BYTES = 1_000_000
MAX_DEPTH = 12
MAX_COLLECTION_ITEMS = 2_000
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
KMS_KEY_ARN = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:[0-9]{12}:key/"
    r"(?:[0-9a-f-]{36}|mrk-[0-9a-f]{32})$"
)


def _bounded_json(value, depth=0):
    """Reject non-JSON and structurally unbounded authority before signing."""
    if depth > MAX_DEPTH:
        raise ValueError("policy configuration nesting is too deep")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("policy configuration contains a non-finite number")
        return
    if isinstance(value, list):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ValueError("policy configuration collection is too large")
        for item in value:
            _bounded_json(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ValueError("policy configuration object is too large")
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 256:
                raise ValueError("policy configuration object key is invalid")
            _bounded_json(item, depth + 1)
        return
    raise ValueError("policy configuration contains a non-JSON value")


def canonical_policy_payload(tenant_id, policy_id, version, configuration):
    """Return SDK-compatible canonical payload bytes and configuration hash."""
    if not isinstance(tenant_id, str) or not IDENTIFIER.fullmatch(tenant_id):
        raise ValueError("policy tenant ID is invalid")
    if not isinstance(policy_id, str) or not IDENTIFIER.fullmatch(policy_id):
        raise ValueError("policy ID is invalid")
    if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
        raise ValueError("policy version must be positive")
    if not isinstance(configuration, dict):
        raise ValueError("policy configuration must be an object")
    _bounded_json(configuration)
    configuration_bytes = json.dumps(
        configuration,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(configuration_bytes) > MAX_POLICY_BYTES:
        raise ValueError("policy configuration is too large")
    content_hash = hashlib.sha256(configuration_bytes).hexdigest()
    payload = json.dumps(
        {
            "configuration": configuration,
            "contentHash": content_hash,
            "policyId": policy_id,
            "schemaVersion": 1,
            "tenantId": tenant_id,
            "version": version,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return payload, content_hash


def sign_policy_bundle(kms_client, key_id, tenant_id, policy_id, version, configuration, signed_at):
    """Sign exact effective authority and return its wire-safe immutable bundle."""
    if not isinstance(key_id, str) or not KMS_KEY_ARN.fullmatch(key_id):
        raise RuntimeError("policy signing key must be an exact KMS key ARN")
    if isinstance(signed_at, bool) or not isinstance(signed_at, int) or signed_at <= 0:
        raise ValueError("policy signing time must be positive")
    payload, content_hash = canonical_policy_payload(
        tenant_id, policy_id, version, configuration
    )
    result = kms_client.sign(
        KeyId=key_id,
        Message=hashlib.sha256(payload).digest(),
        MessageType="DIGEST",
        SigningAlgorithm=ALGORITHM,
    )
    signature = result.get("Signature")
    if (
        result.get("KeyId") != key_id
        or result.get("SigningAlgorithm") != ALGORITHM
        or not isinstance(signature, bytes)
        or not signature
    ):
        raise RuntimeError("KMS returned invalid policy signing evidence")
    return {
        "schemaVersion": 1,
        "tenantId": tenant_id,
        "policyId": policy_id,
        "version": version,
        "configuration": configuration,
        "contentHash": content_hash,
        "integrity": {
            "algorithm": ALGORITHM,
            "keyId": key_id,
            "signature": base64.b64encode(signature).decode("ascii"),
            "signedAt": signed_at,
        },
    }


def bundle_from_record(tenant_id, policy_id, version, record):
    """Reconstruct one exact wire bundle from an active immutable record."""
    configuration = record.get("effective_configuration")
    integrity = record.get("bundle_integrity")
    content_hash = record.get("effective_content_hash")
    if (
        not isinstance(configuration, dict)
        or not isinstance(integrity, dict)
        or not isinstance(content_hash, str)
    ):
        raise RuntimeError("active policy version has no signed effective authority")
    payload, calculated_hash = canonical_policy_payload(
        tenant_id, policy_id, version, configuration
    )
    del payload
    if not hmac_compare(content_hash, calculated_hash):
        raise RuntimeError("active policy signed content hash is inconsistent")
    if set(integrity) != {"algorithm", "keyId", "signature", "signedAt"}:
        raise RuntimeError("active policy signing evidence is malformed")
    return {
        "schemaVersion": 1,
        "tenantId": tenant_id,
        "policyId": policy_id,
        "version": version,
        "configuration": configuration,
        "contentHash": content_hash,
        "integrity": integrity,
    }


def hmac_compare(left, right):
    """Compare public digests through one constant-time equality path."""
    return hmac.compare_digest(left, right)
