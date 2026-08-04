"""Least-privilege AWS worker for reviewed GitHub policy-source evidence.

This Lambda owns the read-only GitHub credential and outbound provider calls.
It has no DynamoDB, policy-signing, or control-plane mutation authority. The
operator Lambda invokes it synchronously with one exact immutable locator and
revalidates the returned evidence before an atomic draft-only transaction.
"""

import base64
import json
import os
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import boto3
from github_policy_source import (
    GitHubHttpResponse,
    GitHubPolicySourceVerifier,
)
from policy_sources import PolicySourceRequest, PolicySourceVerificationError

_MAX_HTTP_BYTES = 2_097_152
_MAX_GRAPHQL_BODY_BYTES = 65_536
_SECRET_ARN = os.environ.get("POLICY_GITHUB_SECRET_ARN", "")
_TOKEN_BROKER_ARN = os.environ.get("POLICY_GITHUB_TOKEN_BROKER_ARN", "")
_ALLOWED_REPOSITORIES = frozenset(
    item.strip()
    for item in os.environ.get("POLICY_GITHUB_ALLOWED_REPOSITORIES", "").split(",")
    if item.strip()
)
_SECRETS = boto3.client("secretsmanager")
_LAMBDA = boto3.client("lambda")


class _NoRedirect(HTTPRedirectHandler):
    """Prevent provider redirects from changing the reviewed trust origin."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        """Reject every redirect; the verifier reports a closed provider failure."""
        return None


class AwsGitHubHttpTransport:
    """Bounded no-redirect HTTPS transport for the fixed GitHub API origin."""

    def __init__(self, opener=None):
        """Create transport without performing network or credential work."""
        self._opener = opener or build_opener(_NoRedirect())

    def get(self, url, *, headers, timeout_seconds):
        """Issue one bounded GET while retaining final-origin evidence."""
        return self._request(url, headers=headers, body=None, timeout_seconds=timeout_seconds)

    def post_json(self, url, *, headers, body, timeout_seconds):
        """Issue one bounded JSON POST for GitHub signature identity evidence."""
        if not isinstance(body, bytes) or not 1 <= len(body) <= _MAX_GRAPHQL_BODY_BYTES:
            raise PolicySourceVerificationError("GitHub GraphQL request is invalid")
        return self._request(url, headers=headers, body=body, timeout_seconds=timeout_seconds)

    def _request(self, url, *, headers, body, timeout_seconds):
        """Read at most one bounded response and normalize HTTP errors as evidence."""
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.netloc != "api.github.com"
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise PolicySourceVerificationError("GitHub policy source URL is not permitted")
        # The parsed origin is fixed above; no caller-controlled scheme or host
        # reaches urllib at this egress boundary.
        request = Request(  # noqa: S310
            url, data=body, headers=dict(headers), method="POST" if body else "GET"
        )
        try:
            response = self._opener.open(request, timeout=timeout_seconds)
        except HTTPError as error:
            response = error
        payload = response.read(_MAX_HTTP_BYTES + 1)
        if len(payload) > _MAX_HTTP_BYTES:
            raise PolicySourceVerificationError("GitHub policy source response is too large")
        return GitHubHttpResponse(
            status=int(response.status),
            headers={str(key): str(value) for key, value in response.headers.items()},
            body=payload,
            final_url=str(response.geturl()),
        )


def _github_token():
    """Resolve one short-lived token without exposing private-key authority."""
    if bool(_SECRET_ARN) == bool(_TOKEN_BROKER_ARN):
        raise PolicySourceVerificationError("GitHub policy source credential is unavailable")
    if _TOKEN_BROKER_ARN:
        if not _TOKEN_BROKER_ARN.startswith("arn:"):
            raise PolicySourceVerificationError("GitHub policy source credential is unavailable")
        try:
            response = _LAMBDA.invoke(
                FunctionName=_TOKEN_BROKER_ARN,
                InvocationType="RequestResponse",
                Payload=json.dumps({"schemaVersion": 1}, separators=(",", ":")).encode("utf-8"),
            )
            payload = response.get("Payload")
            body = payload.read(65_537) if payload is not None else b""
            value = json.loads(body)
        except Exception as error:
            raise PolicySourceVerificationError(
                "GitHub policy source credential is unavailable"
            ) from error
        current_time = time.time()
        if (
            response.get("StatusCode") != 200
            or response.get("FunctionError") is not None
            or len(body) > 65_536
            or not isinstance(value, dict)
            or set(value) != {"schemaVersion", "token", "expiresAt"}
            or value.get("schemaVersion") != 1
            or not isinstance(value.get("token"), str)
            or not 20 <= len(value["token"]) <= 512
            or value["token"] != value["token"].strip()
            or any(ord(character) < 33 or ord(character) > 126 for character in value["token"])
            or not isinstance(value.get("expiresAt"), int)
            or not current_time + 60 < value["expiresAt"] <= current_time + 3_900
        ):
            raise PolicySourceVerificationError("GitHub policy source credential is unavailable")
        return value["token"]
    if not _SECRET_ARN.startswith("arn:"):
        raise PolicySourceVerificationError("GitHub policy source credential is unavailable")
    try:
        result = _SECRETS.get_secret_value(SecretId=_SECRET_ARN, VersionStage="AWSCURRENT")
        value = json.loads(result.get("SecretString", ""))
    except Exception as error:
        raise PolicySourceVerificationError(
            "GitHub policy source credential is unavailable"
        ) from error
    if not isinstance(value, dict) or set(value) != {"token"}:
        raise PolicySourceVerificationError("GitHub policy source credential is unavailable")
    token = value.get("token")
    if not isinstance(token, str) or not token:
        raise PolicySourceVerificationError("GitHub policy source credential is unavailable")
    return token


def handler(event, _context):
    """Return verified content/evidence for one allow-listed immutable Git blob.

    The result contains no provider credential and grants no policy authority.
    Every failure is normalized so secret-manager or HTTP details cannot cross
    the Lambda invocation boundary.
    """
    try:
        if not isinstance(event, dict) or set(event) != {"repository", "commitSha", "path"}:
            raise PolicySourceVerificationError("policy source request schema is invalid")
        request = PolicySourceRequest(
            repository=event.get("repository"),
            commit_sha=event.get("commitSha"),
            path=event.get("path"),
        )
        if not _ALLOWED_REPOSITORIES or request.repository not in _ALLOWED_REPOSITORIES:
            raise PolicySourceVerificationError("GitHub policy source repository is not allowed")
        verified = GitHubPolicySourceVerifier(
            token_provider=_github_token,
            transport=AwsGitHubHttpTransport(),
            now=time.time,
        ).verify(request)
        return {
            "schemaVersion": 1,
            "evidence": verified.evidence(),
            "evidenceDigest": verified.evidence_digest,
            "contentBase64": base64.b64encode(verified.content).decode("ascii"),
        }
    except PolicySourceVerificationError as error:
        # The canonical errors are deliberately detail-safe. Do not include a
        # chained provider exception or event payload in the Lambda response.
        raise RuntimeError(str(error)) from None
