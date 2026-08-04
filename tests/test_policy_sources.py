"""Adversarial contracts for reviewed policy-as-code source boundaries."""

from __future__ import annotations

import hashlib
import json

import pytest

from agentic_security.policy_sources import (
    CallbackPolicyExportSigner,
    PolicyExportSignature,
    PolicySourceDocument,
    PolicySourceRequest,
    PolicySourceVerificationError,
    VerifiedPolicySource,
)


def _document(**overrides: object) -> bytes:
    value: dict[str, object] = {
        "schemaVersion": 1,
        "policyId": "policy-engineering",
        "organizationId": "org-example",
        "name": "Engineering agents",
        "componentRefs": [{"policyId": "policy-baseline", "version": 4, "contentHash": "a" * 64}],
        "localConfiguration": {
            "policy": {"denyByDefault": True},
            "budgets": {"maxActions": 10},
        },
    }
    value.update(overrides)
    return json.dumps(value).encode()


def _verified(**overrides: object) -> VerifiedPolicySource:
    values: dict[str, object] = {
        "provider": "github",
        "repository": "github.com/example/security-policy",
        "commit_sha": "b" * 40,
        "blob_sha": "c" * 40,
        "path": "policies/engineering.json",
        "content": _document(),
        "pull_request": "github.com/example/security-policy/pull/42",
        "reviewed_by": ("reviewer@example.invalid",),
        "signer_identity": "signer@example.invalid",
        "retrieved_at": 1_800_000_000,
    }
    values.update(overrides)
    return VerifiedPolicySource(**values)  # type: ignore[arg-type]


def test_policy_source_document_is_canonical_and_content_bound() -> None:
    document = PolicySourceDocument.from_bytes(_document())

    assert document.policy_id == "policy-engineering"
    assert document.component_refs[0]["version"] == 4
    assert (
        document.canonical_bytes()
        == json.dumps(document.wire(), sort_keys=True, separators=(",", ":")).encode()
    )
    assert document.content_digest == hashlib.sha256(document.canonical_bytes()).hexdigest()
    wire = document.wire()
    wire["localConfiguration"]["policy"]["denyByDefault"] = False
    assert document.wire()["localConfiguration"]["policy"]["denyByDefault"] is True


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (
            b'{"schemaVersion":1,"schemaVersion":1,"policyId":"p","organizationId":"o",'
            b'"name":"n","componentRefs":[],"localConfiguration":{}}',
            "duplicate keys",
        ),
        (_document(extra="unknown"), "schema is invalid"),
        (b"schemaVersion: 1\npolicyId: policy-engineering\n", "valid JSON"),
        (b"\xff", "UTF-8"),
        (_document(schemaVersion=2), "schema is invalid"),
        (_document(policyId="../other"), "policy ID is invalid"),
        (_document(organizationId=""), "organization ID is invalid"),
        (_document(name=" "), "name is invalid"),
        (_document(componentRefs="latest"), "componentRefs is invalid"),
        (_document(componentRefs=[{}]), "component reference is invalid"),
        (
            _document(
                componentRefs=[{"policyId": "../bad", "version": 1, "contentHash": "a" * 64}]
            ),
            "component policy ID is invalid",
        ),
        (
            _document(
                componentRefs=[{"policyId": "baseline", "version": True, "contentHash": "a" * 64}]
            ),
            "component version is invalid",
        ),
        (
            _document(
                componentRefs=[{"policyId": "baseline", "version": 1, "contentHash": "latest"}]
            ),
            "content hash is invalid",
        ),
        (_document(localConfiguration=[]), "localConfiguration must be an object"),
        (_document(localConfiguration={"": True}), "object key is invalid"),
        (_document(localConfiguration={"value": float("nan")}), "non-finite number"),
        (_document(localConfiguration={"values": list(range(10_001))}), "collection is too large"),
        (_document(localConfiguration={str(i): i for i in range(2_001)}), "object is too large"),
    ],
)
def test_policy_source_document_rejects_ambiguous_authority(content: bytes, message: str) -> None:
    with pytest.raises(PolicySourceVerificationError, match=message):
        PolicySourceDocument.from_bytes(content)


def test_policy_source_document_rejects_duplicate_components_and_size_bombs() -> None:
    reference = {"policyId": "baseline", "version": 1, "contentHash": "a" * 64}
    with pytest.raises(PolicySourceVerificationError, match="must be unique"):
        PolicySourceDocument.from_bytes(_document(componentRefs=[reference, reference]))
    with pytest.raises(PolicySourceVerificationError, match="1 MiB"):
        PolicySourceDocument.from_bytes(b"{" + b" " * 1_048_576 + b"}")


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"repository": "example/security"}, "repository is invalid"),
        ({"commit_sha": "main"}, "full object ID"),
        ({"commit_sha": "A" * 40}, "full object ID"),
        ({"path": "/policies/a.json"}, "path is invalid"),
        ({"path": "policies/../secret.json"}, "path is invalid"),
    ],
)
def test_policy_source_request_requires_exact_immutable_location(
    kwargs: dict[str, str], message: str
) -> None:
    values = {
        "repository": "github.com/example/security-policy",
        "commit_sha": "b" * 40,
        "path": "policies/engineering.json",
    }
    values.update(kwargs)
    with pytest.raises(PolicySourceVerificationError, match=message):
        PolicySourceRequest(**values)


def test_verified_source_binds_review_signature_and_content_evidence() -> None:
    source = _verified()

    assert source.evidence()["reviewVerified"] is True
    assert source.evidence()["rawContentDigest"] == hashlib.sha256(source.content).hexdigest()
    assert len(source.evidence_digest) == 64


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"review_verified": False}, "review and signature"),
        ({"signature_verified": False}, "review and signature"),
        ({"reviewed_by": ()}, "reviewers are invalid"),
        ({"reviewed_by": ("same", "same")}, "reviewers are invalid"),
        ({"blob_sha": "mutable"}, "blob ID is invalid"),
        ({"provider": ""}, "provider is invalid"),
        ({"pull_request": ""}, "pull request evidence is invalid"),
        ({"signer_identity": ""}, "signer identity is invalid"),
        ({"retrieved_at": True}, "retrieval time is invalid"),
        ({"content": b"{}"}, "schema is invalid"),
    ],
)
def test_verified_source_fails_closed_on_missing_provider_evidence(
    kwargs: dict[str, object], message: str
) -> None:
    with pytest.raises(PolicySourceVerificationError, match=message):
        _verified(**kwargs)


def test_callback_export_signer_validates_provider_result_and_normalizes_failures() -> None:
    signature = PolicyExportSignature(
        key_id="kms-key-synthetic",
        algorithm="ECDSA_SHA_256",
        signature=b"synthetic-signature",
        signed_at=1_800_000_001,
    )
    signer = CallbackPolicyExportSigner(lambda payload: signature)

    assert signer.sign(b"canonical-export") is signature
    assert signature.wire()["signature"] == "c3ludGhldGljLXNpZ25hdHVyZQ=="

    with pytest.raises(PolicySourceVerificationError, match="returned invalid"):
        CallbackPolicyExportSigner(lambda payload: "invalid").sign(b"canonical-export")  # type: ignore[arg-type,return-value]

    def fail(payload: bytes) -> PolicyExportSignature:
        raise RuntimeError("provider detail must not escape")

    with pytest.raises(PolicySourceVerificationError, match="signing failed") as error:
        CallbackPolicyExportSigner(fail).sign(b"canonical-export")
    assert "provider detail" not in str(error.value)
    with pytest.raises(PolicySourceVerificationError, match="payload is invalid"):
        signer.sign(b"")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"key_id": ""},
        {"algorithm": ""},
        {"signature": b""},
        {"signed_at": True},
    ],
)
def test_policy_export_signature_rejects_incomplete_integrity(
    kwargs: dict[str, object],
) -> None:
    """A signing provider cannot return structurally incomplete evidence."""
    values: dict[str, object] = {
        "key_id": "kms-key-synthetic",
        "algorithm": "ECDSA_SHA_256",
        "signature": b"synthetic-signature",
        "signed_at": 1_800_000_001,
    }
    values.update(kwargs)
    with pytest.raises(PolicySourceVerificationError):
        PolicyExportSignature(**values)  # type: ignore[arg-type]
