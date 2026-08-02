#!/usr/bin/env python3
"""Measure a deployed AWS target with pre-enrolled synthetic agent sessions.

The adapter exercises the same heartbeat, effective-policy and decision routes
used by managed Claude Code and Codex hosts. Synthetic session credentials are
loaded from AWS Secrets Manager and are never printed or included in evidence.
This slice intentionally implements load measurement only; dependency fault
injection remains a separately authorized target-cell operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts import run_regional_recovery_exercise as harness  # noqa: E402
from scripts import verify_aws_regional_activation as activation  # noqa: E402


class AwsRegionalExerciseError(RuntimeError):
    """Report malformed authority or an unsafe AWS exercise configuration."""


Requester = Callable[[str, str, bytes | None, dict[str, str], float], tuple[int, bytes]]
Clock = Callable[[], float]
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_SECRET_ARN = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:\d{12}:secret:"
    r"[A-Za-z0-9/_+=.@-]{1,512}$"
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Prevent bearer credentials from following target-controlled redirects."""

    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        """Return no redirected request for every redirect status."""
        return None


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON fields before they create ambiguous credentials."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AwsRegionalExerciseError(f"duplicate synthetic-agent field: {key}")
        result[key] = value
    return result


@dataclass(frozen=True)
class SyntheticAgentSession:
    """One secret synthetic session bound to an enrolled target agent."""

    agent_number: int
    deployment_id: str
    agent_id: str
    access_token: str
    project_root_sha256: str
    heartbeat: dict[str, Any]


@dataclass(frozen=True)
class SyntheticFleetAuthority:
    """Exact transition-bound synthetic fleet loaded from Secrets Manager."""

    transition_id: str
    authority_sha256: str
    target_region: str
    api_base_url: str
    agents: tuple[SyntheticAgentSession, ...]

    @classmethod
    def parse(
        cls,
        payload: str,
        manifest: activation.ActivationManifest,
    ) -> SyntheticFleetAuthority:
        """Parse exact credentials and bind them to one target canary."""
        if len(payload.encode()) > 1_048_576:
            raise AwsRegionalExerciseError("synthetic fleet secret exceeds one MiB")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except json.JSONDecodeError as error:
            raise AwsRegionalExerciseError("synthetic fleet secret is not JSON") from error
        fields = {
            "schemaVersion",
            "transitionId",
            "authoritySha256",
            "targetRegion",
            "apiBaseUrl",
            "agents",
        }
        if not isinstance(value, dict) or set(value) != fields or value["schemaVersion"] != 1:
            raise AwsRegionalExerciseError("synthetic fleet secret schema is invalid")
        expected_domain = (
            manifest.recovery_canary_api_domain
            if manifest.direction == "failover"
            else manifest.primary_canary_api_domain
        )
        base_url = value.get("apiBaseUrl")
        try:
            parsed_url = urlsplit(base_url) if isinstance(base_url, str) else None
            parsed_port = parsed_url.port if parsed_url is not None else None
        except ValueError as error:
            raise AwsRegionalExerciseError("synthetic fleet API URL is malformed") from error
        if (
            manifest.schema_version != 4
            or expected_domain is None
            or value.get("transitionId") != manifest.transition_id
            or value.get("authoritySha256") != manifest.authority_sha256()
            or value.get("targetRegion") != manifest.target_region
            or not isinstance(base_url, str)
            or parsed_url is None
            or parsed_url.scheme != "https"
            or parsed_url.hostname != expected_domain
            or parsed_port is not None
            or parsed_url.path not in {"", "/"}
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise AwsRegionalExerciseError(
                "synthetic fleet authority does not match the target canary"
            )
        raw_agents = value.get("agents")
        if (
            not isinstance(raw_agents, list)
            or len(raw_agents) != manifest.target_fleet_size
            or len(raw_agents) > 100_000
        ):
            raise AwsRegionalExerciseError("synthetic fleet size differs from transition authority")
        agents: list[SyntheticAgentSession] = []
        for raw in raw_agents:
            agent_fields = {
                "agentNumber",
                "deploymentId",
                "agentId",
                "accessToken",
                "projectRootSha256",
                "heartbeat",
            }
            if not isinstance(raw, dict) or set(raw) != agent_fields:
                raise AwsRegionalExerciseError("synthetic agent session schema is invalid")
            number = raw.get("agentNumber")
            deployment_id = raw.get("deploymentId")
            agent_id = raw.get("agentId")
            token = raw.get("accessToken")
            root_digest = raw.get("projectRootSha256")
            heartbeat = raw.get("heartbeat")
            if (
                isinstance(number, bool)
                or not isinstance(number, int)
                or not 0 <= number < len(raw_agents)
                or not isinstance(deployment_id, str)
                or not _ID.fullmatch(deployment_id)
                or not isinstance(agent_id, str)
                or not _ID.fullmatch(agent_id)
                or not isinstance(token, str)
                or not 32 <= len(token) <= 4096
                or not isinstance(root_digest, str)
                or not _SHA256.fullmatch(root_digest)
                or not isinstance(heartbeat, dict)
                or len(json.dumps(heartbeat, separators=(",", ":")).encode()) > 131_072
            ):
                raise AwsRegionalExerciseError("synthetic agent session is malformed")
            agents.append(
                SyntheticAgentSession(
                    number,
                    deployment_id,
                    agent_id,
                    token,
                    root_digest,
                    heartbeat,
                )
            )
        if {item.agent_number for item in agents} != set(range(len(agents))) or len(
            {(item.deployment_id, item.agent_id) for item in agents}
        ) != len(agents):
            raise AwsRegionalExerciseError(
                "synthetic agent identities are duplicated or incomplete"
            )
        agents.sort(key=lambda item: item.agent_number)
        return cls(
            manifest.transition_id,
            manifest.authority_sha256(),
            manifest.target_region,
            base_url.rstrip("/"),
            tuple(agents),
        )


def _request_json(
    url: str,
    method: str,
    body: bytes | None,
    headers: dict[str, str],
    timeout: float,
) -> tuple[int, bytes]:
    """Perform one bounded HTTPS request without redirect or ambient cookies."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise AwsRegionalExerciseError("target request URL is not bounded HTTPS")
    request = urllib.request.Request(  # noqa: S310 - exact HTTPS scheme is checked above
        url, data=body, headers=headers, method=method
    )
    opener = urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            payload = response.read(1_048_577)
            if len(payload) > 1_048_576:
                raise AwsRegionalExerciseError("target response exceeds one MiB")
            return int(response.status), payload
    except urllib.error.HTTPError as error:
        payload = error.read(1_048_577)
        if len(payload) > 1_048_576:
            raise AwsRegionalExerciseError("target error response exceeds one MiB") from error
        return int(error.code), payload


class AwsAgentLoadAdapter:
    """Measure real target-canary agent routes using isolated sessions."""

    def __init__(
        self,
        fleet: SyntheticFleetAuthority,
        *,
        requester: Requester = _request_json,
        clock: Clock = time.monotonic,
        timeout_seconds: float = 5.0,
    ) -> None:
        """Create a bounded adapter without making network calls."""
        if not 0.1 <= timeout_seconds <= 30:
            raise AwsRegionalExerciseError("request timeout is outside its bound")
        self._fleet = fleet
        self._requester = requester
        self._clock = clock
        self._timeout = timeout_seconds
        self._tokens = [item.access_token for item in fleet.agents]
        self._locks = [threading.Lock() for _ in fleet.agents]

    def _call(
        self,
        agent: SyntheticAgentSession,
        token: str,
        method: str,
        action: str,
        body: dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, Any], float]:
        """Call one exact agent route and parse a bounded JSON object."""
        encoded = (
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            if body is not None
            else None
        )
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "X-AAI-Project-Root-Digest": agent.project_root_sha256,
        }
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        url = f"{self._fleet.api_base_url}/agent/{agent.deployment_id}/{agent.agent_id}/{action}"
        started = self._clock()
        status, payload = self._requester(url, method, encoded, headers, self._timeout)
        elapsed_ms = (self._clock() - started) * 1000
        if not math.isfinite(elapsed_ms) or elapsed_ms < 0 or elapsed_ms > 60_000:
            raise AwsRegionalExerciseError("target request clock is invalid")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except json.JSONDecodeError as error:
            raise AwsRegionalExerciseError("target returned malformed JSON") from error
        if not isinstance(value, dict):
            raise AwsRegionalExerciseError("target response must be a JSON object")
        return status, value, elapsed_ms

    def measure_agent(self, agent_number: int) -> harness.LoadObservation:
        """Measure one heartbeat, policy read and idempotent decision write."""
        if isinstance(agent_number, bool) or not 0 <= agent_number < len(self._fleet.agents):
            raise AwsRegionalExerciseError("synthetic agent number is outside the fleet")
        agent = self._fleet.agents[agent_number]
        with self._locks[agent_number]:
            token = self._tokens[agent_number]
            heartbeat_status, heartbeat, heartbeat_ms = self._call(
                agent, token, "POST", "heartbeat", agent.heartbeat
            )
            renewed = heartbeat.get("accessToken")
            if (
                heartbeat_status != 200
                or heartbeat.get("status") != "connected"
                or not isinstance(renewed, str)
                or not 32 <= len(renewed) <= 4096
            ):
                return harness.LoadObservation(
                    f"{agent.deployment_id}:{agent.agent_id}",
                    heartbeat_ms,
                    60_000,
                    60_000,
                    False,
                )
            token = renewed
            self._tokens[agent_number] = renewed
            policy_status, _, policy_ms = self._call(agent, token, "GET", "effective-policy")
            if policy_status != 200:
                return harness.LoadObservation(
                    f"{agent.deployment_id}:{agent.agent_id}",
                    heartbeat_ms,
                    policy_ms,
                    60_000,
                    False,
                )
            decision_id = hashlib.sha256(
                f"{self._fleet.authority_sha256}:{agent.deployment_id}:{agent.agent_id}".encode()
            ).hexdigest()
            decision_status, decision, decision_ms = self._call(
                agent,
                token,
                "POST",
                "decisions",
                {
                    "decisionId": decision_id,
                    "source": "sdk_runtime",
                    "toolName": "regional-exercise.synthetic-read",
                    "decision": "allowed",
                    "resourceKind": "sdk_tool",
                    "reasonCode": "explicit_allow",
                    "actionDigest": decision_id,
                },
            )
            succeeded = bool(
                decision_status == 202
                and decision.get("accepted") is True
                and decision.get("decisionId") == decision_id
            )
            return harness.LoadObservation(
                agent_id=f"{agent.deployment_id}:{agent.agent_id}",
                heartbeat_ms=heartbeat_ms,
                policy_read_ms=policy_ms,
                decision_write_ms=decision_ms,
                succeeded=succeeded,
            )

    def exercise_dependency(self, dependency: str) -> harness.DependencyObservation:
        """Refuse to self-certify a dependency fault without its authority plane."""
        raise AwsRegionalExerciseError(
            f"dependency fault controller is not implemented for {dependency}"
        )

    def exercise_consistency(self, control: str) -> harness.ConsistencyObservation:
        """Refuse to self-certify consistency from load-route responses."""
        raise AwsRegionalExerciseError(
            f"consistency evidence controller is not implemented for {control}"
        )


def load_fleet_secret(
    client: Any,
    secret_arn: str,
    manifest: activation.ActivationManifest,
) -> SyntheticFleetAuthority:
    """Read one exact Secrets Manager version without exposing credentials."""
    secret_parts = secret_arn.split(":", 5)
    routing_parts = (
        manifest.routing_role_arn.split(":", 5)
        if isinstance(manifest.routing_role_arn, str)
        else []
    )
    if (
        not _SECRET_ARN.fullmatch(secret_arn)
        or len(secret_parts) != 6
        or len(routing_parts) != 6
        or secret_parts[3] != manifest.target_region
        or secret_parts[4] != routing_parts[4]
    ):
        raise AwsRegionalExerciseError("synthetic fleet secret ARN is invalid")
    try:
        response = client.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")
    except Exception as error:
        raise AwsRegionalExerciseError("synthetic fleet secret cannot be read") from error
    payload = response.get("SecretString")
    if not isinstance(payload, str) or response.get("ARN") != secret_arn:
        raise AwsRegionalExerciseError("synthetic fleet secret response is malformed")
    return SyntheticFleetAuthority.parse(payload, manifest)


def _parser() -> argparse.ArgumentParser:
    """Build the read-only target load-measurement command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--synthetic-fleet-secret-arn", required=True)
    parser.add_argument("--profile", default="p1")
    parser.add_argument("--max-workers", type=int, default=64)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Measure live target agent routes and print content-free load evidence."""
    arguments = _parser().parse_args(argv)
    try:
        manifest = activation.ActivationManifest.parse(
            arguments.manifest.read_text(encoding="utf-8")
        )
        if not _REGION.fullmatch(manifest.target_region):
            raise AwsRegionalExerciseError("target Region is invalid")
        import boto3

        session = boto3.Session(profile_name=arguments.profile)
        fleet = load_fleet_secret(
            session.client("secretsmanager", region_name=manifest.target_region),
            arguments.synthetic_fleet_secret_arn,
            manifest,
        )
        evidence = harness.run_load_exercise(
            AwsAgentLoadAdapter(fleet),
            target_fleet_size=manifest.target_fleet_size,
            max_workers=arguments.max_workers,
        )
        print(json.dumps({"load": evidence, "status": "target-load-measured"}, sort_keys=True))
    except (
        OSError,
        UnicodeError,
        activation.RegionalActivationVerificationError,
        harness.RegionalRecoveryExerciseError,
        AwsRegionalExerciseError,
    ) as error:
        print(f"AWS regional exercise failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
