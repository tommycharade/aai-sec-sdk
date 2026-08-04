"""GitHub adapter for reviewed, signed, exact-commit policy sources.

The adapter accepts only a deployment-owned token callback and an injected
bounded HTTP transport. GitHub responses are untrusted: repository identity,
commit, blob, pull-request relation, latest independent approval, signature,
redirect behavior, pagination, and content bounds are checked before evidence
crosses the provider-neutral :class:`PolicySourceVerifier` boundary.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import quote

from policy_sources import (
    PolicySourceDocument,
    PolicySourceRequest,
    PolicySourceVerificationError,
    VerifiedPolicySource,
)

_API_ORIGIN = "https://api.github.com"
_MAX_RESPONSE_BYTES = 2_097_152
_MAX_REVIEW_PAGES = 5
_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class GitHubHttpResponse:
    """Bounded response metadata returned by a deployment HTTP transport."""

    status: int
    headers: Mapping[str, str]
    body: bytes
    final_url: str


class GitHubHttpTransport(Protocol):
    """Deployment-owned HTTP boundary used by the GitHub source verifier."""

    def get(
        self, url: str, *, headers: Mapping[str, str], timeout_seconds: float
    ) -> GitHubHttpResponse:
        """Return one response without following redirects silently."""

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> GitHubHttpResponse:
        """Post one bounded JSON request without following redirects silently."""


class GitHubPolicySourceVerifier:
    """Verify an exact GitHub policy blob against review and signature evidence."""

    def __init__(
        self,
        *,
        token_provider: Callable[[], str],
        transport: GitHubHttpTransport,
        now: Callable[[], float],
    ) -> None:
        """Bind deployment-owned credential, HTTP, and clock adapters.

        No credential or network operation occurs in the constructor. The
        token is resolved only for one verification call and is never returned,
        persisted, or included in an exception.
        """
        self._token_provider = token_provider
        self._transport = transport
        self._now = now

    def verify(self, request: PolicySourceRequest) -> VerifiedPolicySource:
        """Retrieve and verify one source or fail without creating authority."""
        if not isinstance(request, PolicySourceRequest):
            raise PolicySourceVerificationError("GitHub policy source request is invalid")
        parts = request.repository.split("/")
        if len(parts) != 3 or parts[0] != "github.com":
            raise PolicySourceVerificationError("GitHub repository must use github.com/owner/name")
        owner, repository = parts[1], parts[2]
        try:
            token = self._token_provider()
        except Exception as exc:
            raise PolicySourceVerificationError(
                "GitHub policy source credential is unavailable"
            ) from exc
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 8_192
            or any(char.isspace() for char in token)
        ):
            raise PolicySourceVerificationError("GitHub policy source credential is unavailable")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "aai-sec-sdk-policy-source",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        repository_path = f"/repos/{quote(owner, safe='')}/{quote(repository, safe='')}"
        commit = self._json(f"{_API_ORIGIN}{repository_path}/commits/{request.commit_sha}", headers)
        if commit.get("sha") != request.commit_sha:
            raise PolicySourceVerificationError("GitHub returned a different commit")
        verification = commit.get("commit")
        verification = (
            verification.get("verification") if isinstance(verification, Mapping) else None
        )
        if not isinstance(verification, Mapping) or verification.get("verified") is not True:
            raise PolicySourceVerificationError("GitHub commit signature is not verified")
        signer_login = self._verified_signer(owner, repository, request.commit_sha, headers)

        encoded_path = "/".join(quote(segment, safe="") for segment in request.path.split("/"))
        content = self._json(
            f"{_API_ORIGIN}{repository_path}/contents/{encoded_path}?ref={request.commit_sha}",
            headers,
        )
        if content.get("type") != "file" or not isinstance(content.get("sha"), str):
            raise PolicySourceVerificationError("GitHub policy source is not an exact file blob")
        if content.get("encoding") != "base64" or not isinstance(content.get("content"), str):
            raise PolicySourceVerificationError(
                "GitHub policy source content encoding is unsupported"
            )
        try:
            source_bytes = base64.b64decode(content["content"], validate=True)
        except (ValueError, TypeError, binascii.Error) as exc:
            raise PolicySourceVerificationError(
                "GitHub policy source content is malformed"
            ) from exc
        declared_size = content.get("size")
        if (
            isinstance(declared_size, bool)
            or not isinstance(declared_size, int)
            or declared_size != len(source_bytes)
        ):
            raise PolicySourceVerificationError("GitHub policy source size is inconsistent")
        # Parse before further provider calls so oversized or malformed source
        # cannot consume the bounded review-query budget.
        PolicySourceDocument.from_bytes(source_bytes)

        pulls = self._json_list(
            f"{_API_ORIGIN}{repository_path}/commits/{request.commit_sha}/pulls?per_page=100",
            headers,
        )
        qualifying = [
            pull
            for pull in pulls
            if pull.get("state") == "closed"
            and isinstance(pull.get("merged_at"), str)
            and (
                pull.get("merge_commit_sha") == request.commit_sha
                or (
                    isinstance(pull.get("head"), Mapping)
                    and pull["head"].get("sha") == request.commit_sha
                )
            )
        ]
        if len(qualifying) != 1:
            raise PolicySourceVerificationError(
                "GitHub commit must belong to exactly one merged pull request"
            )
        pull = qualifying[0]
        number = pull.get("number")
        if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
            raise PolicySourceVerificationError("GitHub pull request identity is invalid")
        reviewers = self._approved_reviewers(repository_path, number, headers, signer_login)
        return VerifiedPolicySource(
            provider="github",
            repository=request.repository,
            commit_sha=request.commit_sha,
            blob_sha=str(content["sha"]),
            path=request.path,
            content=source_bytes,
            pull_request=f"github.com/{owner}/{repository}/pull/{number}",
            reviewed_by=tuple(reviewers),
            signer_identity=f"github:{signer_login}",
            retrieved_at=int(self._now()),
        )

    def _verified_signer(
        self,
        owner: str,
        repository: str,
        commit_sha: str,
        headers: Mapping[str, str],
    ) -> str:
        """Resolve the user attached to GitHub's valid signature evidence.

        REST commit verification does not identify the signer. The GraphQL
        ``GitSignature.signer`` field is therefore required; the commit actor
        or committer must never be substituted for cryptographic identity.
        """
        query = (
            "query($owner:String!,$name:String!,$oid:GitObjectID!){"
            "repository(owner:$owner,name:$name){object(oid:$oid){... on Commit{"
            "oid signature{isValid state signer{login}}}}}}"
        )
        body = json.dumps(
            {
                "query": query,
                "variables": {"owner": owner, "name": repository, "oid": commit_sha},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        value = self._request_json_post(f"{_API_ORIGIN}/graphql", headers, body)
        if not isinstance(value, Mapping):
            raise PolicySourceVerificationError("GitHub verified signer evidence is unavailable")
        errors = value.get("errors")
        if errors is not None and errors != []:
            raise PolicySourceVerificationError("GitHub verified signer evidence is unavailable")
        data = value.get("data")
        repository_value = data.get("repository") if isinstance(data, Mapping) else None
        commit = repository_value.get("object") if isinstance(repository_value, Mapping) else None
        signature = commit.get("signature") if isinstance(commit, Mapping) else None
        signer = signature.get("signer") if isinstance(signature, Mapping) else None
        login = signer.get("login") if isinstance(signer, Mapping) else None
        if (
            not isinstance(commit, Mapping)
            or commit.get("oid") != commit_sha
            or not isinstance(signature, Mapping)
            or signature.get("isValid") is not True
            or signature.get("state") != "VALID"
            or not isinstance(login, str)
            or not login
            or len(login) > 256
        ):
            raise PolicySourceVerificationError("GitHub verified commit signer is unavailable")
        return login

    def _approved_reviewers(
        self,
        repository_path: str,
        number: int,
        headers: Mapping[str, str],
        signer_login: str,
    ) -> list[str]:
        """Return latest independent approvals across bounded review pages."""
        latest: dict[str, tuple[str, str]] = {}
        for page in range(1, _MAX_REVIEW_PAGES + 1):
            reviews = self._json_list(
                f"{_API_ORIGIN}{repository_path}/pulls/{number}/reviews?per_page=100&page={page}",
                headers,
            )
            for review in reviews:
                user = review.get("user")
                login = user.get("login") if isinstance(user, Mapping) else None
                state, submitted_at = review.get("state"), review.get("submitted_at")
                if (
                    not isinstance(login, str)
                    or not login
                    or not isinstance(state, str)
                    or not isinstance(submitted_at, str)
                ):
                    raise PolicySourceVerificationError("GitHub pull request review is malformed")
                previous = latest.get(login)
                if previous is None or submitted_at > previous[0]:
                    latest[login] = (submitted_at, state.upper())
            if len(reviews) < 100:
                break
        else:
            raise PolicySourceVerificationError("GitHub pull request reviews exceed the safe bound")
        approved = sorted(
            login
            for login, (_, state) in latest.items()
            if state == "APPROVED" and login != signer_login
        )
        if not approved:
            raise PolicySourceVerificationError(
                "GitHub policy source requires a latest independent approval"
            )
        return [f"github:{login}" for login in approved]

    def _json(self, url: str, headers: Mapping[str, str]) -> dict[str, Any]:
        """Retrieve one exact bounded object while rejecting redirects/errors."""
        value = self._request_json(url, headers)
        if not isinstance(value, Mapping):
            raise PolicySourceVerificationError("GitHub returned an unexpected object")
        return dict(value)

    def _json_list(self, url: str, headers: Mapping[str, str]) -> list[dict[str, Any]]:
        """Retrieve one exact bounded array of provider objects."""
        value = self._request_json(url, headers)
        if (
            not isinstance(value, list)
            or len(value) > 100
            or not all(isinstance(item, Mapping) for item in value)
        ):
            raise PolicySourceVerificationError("GitHub returned an unexpected collection")
        return [dict(item) for item in value]

    def _request_json(self, url: str, headers: Mapping[str, str]) -> Any:
        """Perform one bounded provider call with no redirect or error leakage."""
        try:
            response = self._transport.get(url, headers=headers, timeout_seconds=_TIMEOUT_SECONDS)
        except Exception as exc:
            raise PolicySourceVerificationError("GitHub policy source verification failed") from exc
        if not isinstance(response, GitHubHttpResponse):
            raise PolicySourceVerificationError(
                "GitHub policy source transport returned no evidence"
            )
        if response.final_url != url:
            raise PolicySourceVerificationError("GitHub policy source redirects are not permitted")
        if response.status != 200:
            raise PolicySourceVerificationError("GitHub policy source verification was unavailable")
        if not isinstance(response.body, bytes) or len(response.body) > _MAX_RESPONSE_BYTES:
            raise PolicySourceVerificationError("GitHub policy source response is too large")
        try:
            return json.loads(response.body)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PolicySourceVerificationError(
                "GitHub policy source response is malformed"
            ) from exc

    def _request_json_post(self, url: str, headers: Mapping[str, str], body: bytes) -> Any:
        """Perform one bounded GraphQL call while preserving transport invariants."""
        try:
            response = self._transport.post_json(
                url,
                headers={**headers, "Content-Type": "application/json"},
                body=body,
                timeout_seconds=_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            raise PolicySourceVerificationError("GitHub policy source verification failed") from exc
        if not isinstance(response, GitHubHttpResponse):
            raise PolicySourceVerificationError(
                "GitHub policy source transport returned no evidence"
            )
        if response.final_url != url:
            raise PolicySourceVerificationError("GitHub policy source redirects are not permitted")
        if response.status != 200:
            raise PolicySourceVerificationError("GitHub policy source verification was unavailable")
        if not isinstance(response.body, bytes) or len(response.body) > _MAX_RESPONSE_BYTES:
            raise PolicySourceVerificationError("GitHub policy source response is too large")
        try:
            return json.loads(response.body)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PolicySourceVerificationError(
                "GitHub policy source response is malformed"
            ) from exc


__all__ = ["GitHubHttpResponse", "GitHubHttpTransport", "GitHubPolicySourceVerifier"]
