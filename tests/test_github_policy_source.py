"""GitHub policy source adapter contracts with synthetic provider responses."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Mapping
from typing import Any

import pytest

from agentic_security.github_policy_source import (
    GitHubHttpResponse,
    GitHubPolicySourceVerifier,
)
from agentic_security.policy_sources import (
    PolicySourceRequest,
    PolicySourceVerificationError,
)

COMMIT = "b" * 40
BLOB = "c" * 40
REPOSITORY = "github.com/example/security-policy"
PATH = "policies/engineering.json"
SYNTHETIC_CREDENTIAL = "synthetic-installation-credential"  # noqa: S105 - non-secret fixture.


def _source() -> bytes:
    return json.dumps(
        {
            "schemaVersion": 1,
            "policyId": "policy-engineering",
            "organizationId": "org-example",
            "name": "Engineering agents",
            "componentRefs": [],
            "localConfiguration": {"policy": {"denyByDefault": True}},
        }
    ).encode()


class SyntheticGitHubTransport:
    """Return deterministic provider fixtures without network or credentials."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, Mapping[str, str], float]] = []
        self.posts: list[tuple[str, Mapping[str, str], bytes, float]] = []
        self.commit: dict[str, Any] = {
            "sha": COMMIT,
            "committer": {"login": "signed-author"},
            "commit": {"verification": {"verified": True, "reason": "valid"}},
        }
        self.content: dict[str, Any] = {
            "type": "file",
            "sha": BLOB,
            "encoding": "base64",
            "size": len(_source()),
            "content": base64.b64encode(_source()).decode(),
        }
        self.pulls: list[dict[str, Any]] = [
            {
                "number": 42,
                "state": "closed",
                "merged_at": "2026-08-04T10:00:00Z",
                "merge_commit_sha": COMMIT,
                "head": {"sha": "d" * 40},
            }
        ]
        self.reviews: dict[int, object] = {
            1: [
                {
                    "user": {"login": "independent-reviewer"},
                    "state": "APPROVED",
                    "submitted_at": "2026-08-04T09:00:00Z",
                }
            ]
        }
        self.status = 200
        self.redirect = False
        self.signature: dict[str, Any] = {
            "data": {
                "repository": {
                    "object": {
                        "oid": COMMIT,
                        "signature": {
                            "isValid": True,
                            "state": "VALID",
                            "signer": {"login": "signed-author"},
                        },
                    }
                }
            }
        }

    def get(
        self, url: str, *, headers: Mapping[str, str], timeout_seconds: float
    ) -> GitHubHttpResponse:
        self.requests.append((url, dict(headers), timeout_seconds))
        value: object
        if "/contents/" in url:
            value = self.content
        elif "/commits/" in url and url.endswith("/pulls?per_page=100"):
            value = self.pulls
        elif "/pulls/42/reviews" in url:
            page = int(url.rsplit("page=", 1)[1])
            value = self.reviews.get(page, [])
        else:
            value = self.commit
        return GitHubHttpResponse(
            status=self.status,
            headers={},
            body=json.dumps(value).encode(),
            final_url=f"{url}&redirected=true" if self.redirect else url,
        )

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> GitHubHttpResponse:
        """Return deterministic GraphQL signature identity evidence."""
        self.posts.append((url, dict(headers), body, timeout_seconds))
        return GitHubHttpResponse(
            status=self.status,
            headers={},
            body=json.dumps(self.signature).encode(),
            final_url=f"{url}?redirected=true" if self.redirect else url,
        )


def _verifier(
    transport: SyntheticGitHubTransport, token: object | None = None
) -> GitHubPolicySourceVerifier:
    token = SYNTHETIC_CREDENTIAL if token is None else token

    def token_provider() -> str:
        if isinstance(token, Exception):
            raise token
        return token  # type: ignore[return-value]

    return GitHubPolicySourceVerifier(
        token_provider=token_provider,
        transport=transport,
        now=lambda: 1_800_000_000,
    )


def _request(**overrides: str) -> PolicySourceRequest:
    values = {"repository": REPOSITORY, "commit_sha": COMMIT, "path": PATH}
    values.update(overrides)
    return PolicySourceRequest(**values)


def test_github_verifier_binds_commit_blob_review_signature_and_fixed_origin() -> None:
    transport = SyntheticGitHubTransport()

    verified = _verifier(transport).verify(_request())

    assert verified.repository == REPOSITORY
    assert verified.commit_sha == COMMIT
    assert verified.blob_sha == BLOB
    assert verified.reviewed_by == ("github:independent-reviewer",)
    assert verified.signer_identity == "github:signed-author"
    assert verified.pull_request == "github.com/example/security-policy/pull/42"
    assert len(transport.requests) == 4 and len(transport.posts) == 1
    assert all(
        url.startswith("https://api.github.com/repos/example/security-policy/")
        for url, _, _ in transport.requests
    )
    assert all(
        headers["Authorization"] == f"Bearer {SYNTHETIC_CREDENTIAL}"
        for _, headers, _ in transport.requests
    )
    assert all(timeout == 10.0 for _, _, timeout in transport.requests)
    assert transport.posts[0][0] == "https://api.github.com/graphql"
    assert transport.posts[0][3] == 10.0
    assert json.loads(transport.posts[0][2])["variables"] == {
        "owner": "example",
        "name": "security-policy",
        "oid": COMMIT,
    }


def test_latest_review_state_must_remain_an_independent_approval() -> None:
    transport = SyntheticGitHubTransport()
    transport.reviews[1] = [
        {
            "user": {"login": "independent-reviewer"},
            "state": "APPROVED",
            "submitted_at": "2026-08-04T08:00:00Z",
        },
        {
            "user": {"login": "independent-reviewer"},
            "state": "DISMISSED",
            "submitted_at": "2026-08-04T09:00:00Z",
        },
    ]

    with pytest.raises(PolicySourceVerificationError, match="latest independent approval"):
        _verifier(transport).verify(_request())


def test_commit_signer_cannot_be_the_only_reviewer() -> None:
    transport = SyntheticGitHubTransport()
    transport.reviews[1] = [
        {
            "user": {"login": "signed-author"},
            "state": "APPROVED",
            "submitted_at": "2026-08-04T09:00:00Z",
        }
    ]

    with pytest.raises(PolicySourceVerificationError, match="latest independent approval"):
        _verifier(transport).verify(_request())


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.commit.update({"sha": "d" * 40}), "different commit"),
        (
            lambda value: value.commit["commit"]["verification"].update({"verified": False}),
            "signature is not verified",
        ),
        (
            lambda value: value.signature["data"]["repository"]["object"]["signature"].update(
                {"signer": None}
            ),
            "signer is unavailable",
        ),
        (
            lambda value: value.signature["data"]["repository"]["object"]["signature"].update(
                {"isValid": False}
            ),
            "signer is unavailable",
        ),
        (
            lambda value: setattr(value, "signature", {"errors": [{"message": "denied"}]}),
            "signer evidence is unavailable",
        ),
        (lambda value: setattr(value, "signature", []), "signer evidence is unavailable"),
        (lambda value: value.content.update({"type": "dir"}), "not an exact file blob"),
        (lambda value: value.content.update({"encoding": "utf-8"}), "encoding is unsupported"),
        (lambda value: value.content.update({"content": "%%%"}), "content is malformed"),
        (lambda value: value.content.update({"size": 1}), "size is inconsistent"),
        (lambda value: setattr(value, "pulls", []), "exactly one merged pull request"),
        (lambda value: value.pulls[0].update({"number": True}), "identity is invalid"),
        (lambda value: setattr(value, "pulls", {}), "unexpected collection"),
        (
            lambda value: value.pulls.append(dict(value.pulls[0], number=43)),
            "exactly one merged pull request",
        ),
        (lambda value: setattr(value, "status", 429), "was unavailable"),
        (lambda value: setattr(value, "redirect", True), "redirects are not permitted"),
    ],
)
def test_github_verifier_rejects_incomplete_or_ambiguous_provider_evidence(
    mutation: Callable[[SyntheticGitHubTransport], None], message: str
) -> None:
    transport = SyntheticGitHubTransport()
    mutation(transport)

    with pytest.raises(PolicySourceVerificationError, match=message):
        _verifier(transport).verify(_request())


def test_malformed_policy_is_rejected_before_review_calls() -> None:
    transport = SyntheticGitHubTransport()
    malformed = b'{"schemaVersion":1}'
    transport.content = dict(
        transport.content,
        size=len(malformed),
        content=base64.b64encode(malformed).decode(),
    )

    with pytest.raises(PolicySourceVerificationError, match="schema is invalid"):
        _verifier(transport).verify(_request())
    assert len(transport.requests) == 2 and len(transport.posts) == 1


def test_github_verifier_rejects_wrong_provider_and_malformed_reviews() -> None:
    """Provider type, host and every review object remain closed boundaries."""
    transport = SyntheticGitHubTransport()
    with pytest.raises(PolicySourceVerificationError, match="request is invalid"):
        _verifier(transport).verify("not-a-request")  # type: ignore[arg-type]
    with pytest.raises(PolicySourceVerificationError, match="must use github.com"):
        _verifier(transport).verify(_request(repository="gitlab.com/example/security-policy"))
    transport.reviews[1] = [{"state": "APPROVED"}]
    with pytest.raises(PolicySourceVerificationError, match="review is malformed"):
        _verifier(transport).verify(_request())


@pytest.mark.parametrize("token", ["", "token with spaces", RuntimeError("secret manager")])
def test_github_credential_failure_is_redacted_and_performs_no_request(token: object) -> None:
    transport = SyntheticGitHubTransport()

    with pytest.raises(PolicySourceVerificationError, match="credential is unavailable") as error:
        _verifier(transport, token).verify(_request())
    assert "secret manager" not in str(error.value)
    assert transport.requests == []


def test_review_pagination_is_bounded() -> None:
    transport = SyntheticGitHubTransport()
    full_page = [
        {
            "user": {"login": f"reviewer-{index}"},
            "state": "COMMENTED",
            "submitted_at": "2026-08-04T09:00:00Z",
        }
        for index in range(100)
    ]
    transport.reviews = {page: full_page for page in range(1, 6)}

    with pytest.raises(PolicySourceVerificationError, match="exceed the safe bound"):
        _verifier(transport).verify(_request())
    assert len([url for url, _, _ in transport.requests if "/reviews" in url]) == 5


def test_transport_failures_do_not_expose_provider_or_token_details() -> None:
    class FailingTransport(SyntheticGitHubTransport):
        def get(
            self, url: str, *, headers: Mapping[str, str], timeout_seconds: float
        ) -> GitHubHttpResponse:
            raise RuntimeError(f"provider failed with {headers['Authorization']}")

        def post_json(
            self,
            url: str,
            *,
            headers: Mapping[str, str],
            body: bytes,
            timeout_seconds: float,
        ) -> GitHubHttpResponse:
            raise RuntimeError(f"provider failed with {headers['Authorization']}")

    with pytest.raises(PolicySourceVerificationError, match="verification failed") as error:
        _verifier(FailingTransport()).verify(_request())
    assert SYNTHETIC_CREDENTIAL not in str(error.value)
