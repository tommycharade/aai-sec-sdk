"""Reconcile approved endpoint-delivery cohorts through Microsoft Intune.

The worker is an isolated trust boundary. It receives only a tenant and opaque
command identity, reloads every live authority record, verifies the complete
cohort, and only then reads the tenant-tagged credential. Microsoft Graph IDs
and credentials exist only in worker memory. The deployment feature gate is
off by default and is checked before DynamoDB or Secrets Manager access.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import boto3
from boto3.dynamodb.conditions import Key

TABLE = boto3.resource("dynamodb").Table(os.environ["CONTROL_TABLE"])
SECRETS = boto3.client("secretsmanager")
S3 = boto3.client("s3")
SQS = boto3.client("sqs")

_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_PAGE_COUNT = 20
# One continuation resolves one sealed page. The total bound matches the
# control-plane's strongly bounded agent and command inventory.
_MAX_TARGETS = 500
_PAGE_SIZE = 40
_MAX_MUTATIONS_PER_INVOCATION = 40
_MAX_CONTINUATION_REVISIONS = 64
_MAX_ATTEMPTS = 5
_EVIDENCE_MAX_AGE_SECONDS = 15 * 60
_EVIDENCE_FUTURE_SKEW_SECONDS = 5 * 60
_GRAPH_ORIGIN = "https://graph.microsoft.com"
_LOGIN_ORIGIN = "https://login.microsoftonline.com"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")


class AuthorityError(RuntimeError):
    """Represent one fixed fail-closed authority reason safe for persistence."""

    def __init__(self, code: str) -> None:
        """Retain only a fixed code, never provider or credential content."""
        super().__init__(code)
        self.code = code


class ProviderRetryable(RuntimeError):
    """Represent provider propagation or availability that may safely retry."""

    def __init__(self, code: str) -> None:
        """Retain only a fixed content-free retry reason."""
        super().__init__(code)
        self.code = code


class _NoRedirects(HTTPRedirectHandler):
    """Reject redirects before a bearer can cross an origin boundary."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        """Return no redirected request; urllib exposes the 3xx response."""
        return None


def _key(tenant: str, kind: str, identifier: str) -> dict[str, str]:
    """Return one tenant-scoped DynamoDB key."""
    return {"pk": f"TENANT#{tenant}", "sk": f"{kind}#{identifier}"}


def _identifier(value: object, field: str) -> str:
    """Validate a bounded persisted identifier."""
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise AuthorityError(f"invalid_{field}")
    return value


def _uuid(value: object, field: str) -> str:
    """Validate one canonical lowercase UUID."""
    if not isinstance(value, str) or not _UUID.fullmatch(value):
        raise AuthorityError(f"invalid_{field}")
    try:
        normalized = str(uuid.UUID(value))
    except ValueError as error:
        raise AuthorityError(f"invalid_{field}") from error
    if normalized != value:
        raise AuthorityError(f"invalid_{field}")
    return value


def _digest(value: object, field: str) -> str:
    """Validate one lowercase SHA-256 identity."""
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise AuthorityError(f"invalid_{field}")
    return value


def _plain(value: object) -> object:
    """Normalize DynamoDB numbers before canonical hashing."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    return value


def _hash(value: object) -> str:
    """Hash one JSON-safe authority object canonically."""
    return hashlib.sha256(
        json.dumps(_plain(value), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _list(tenant: str, kind: str, *, limit: int) -> list[dict[str, object]]:
    """Strongly list one bounded tenant record kind or fail on truncation."""
    result = TABLE.query(
        KeyConditionExpression=Key("pk").eq(f"TENANT#{tenant}") & Key("sk").begins_with(f"{kind}#"),
        ConsistentRead=True,
        Limit=limit + 1,
    )
    items = result.get("Items", [])
    if result.get("LastEvaluatedKey") or len(items) > limit:
        raise AuthorityError(f"{kind.lower()}_inventory_exceeded")
    return [dict(item) for item in items]


def _deployment_gate() -> None:
    """Require explicit immutable deployment evidence before any worker access."""
    enabled = os.environ.get("ENDPOINT_DELIVERY_DISPATCH_ENABLED")
    evidence = os.environ.get("ENDPOINT_DELIVERY_ENABLEMENT_EVIDENCE_SHA256", "")
    if enabled != "true" or not _DIGEST.fullmatch(evidence):
        raise RuntimeError("endpoint delivery worker is deployment-disabled")


def _command_instruction(value: object) -> dict[str, object]:
    """Validate the complete package/cohort command schema."""
    fields = {
        "schemaVersion",
        "provider",
        "providerVersion",
        "providerContentHash",
        "deploymentId",
        "host",
        "releaseId",
        "packageId",
        "packageManifestSha256",
        "packageObjectSha256",
        "packageStorageIdentitySha256",
        "providerPackageIdentitySha256",
        "packageSignatureEvidenceSha256",
        "packageApproverEvidenceSha256",
        "releaseEvidenceSha256",
        "packageBundleSha256",
        "packageApprovalBundleSha256",
        "rolloutRevision",
        "rolloutState",
        "targetCount",
        "cohortDigest",
        "pages",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise AuthorityError("command_schema_invalid")
    if value.get("schemaVersion") != 1 or value.get("provider") != "intune":
        raise AuthorityError("command_schema_invalid")
    for field in (
        "providerContentHash",
        "packageManifestSha256",
        "packageObjectSha256",
        "packageStorageIdentitySha256",
        "providerPackageIdentitySha256",
        "packageSignatureEvidenceSha256",
        "packageApproverEvidenceSha256",
        "releaseEvidenceSha256",
        "packageBundleSha256",
        "packageApprovalBundleSha256",
        "cohortDigest",
    ):
        _digest(value.get(field), field)
    for field in ("deploymentId", "releaseId", "packageId"):
        _identifier(value.get(field), field)
    if value.get("host") not in {"claude-code", "codex-cli"}:
        raise AuthorityError("command_host_invalid")
    for field in ("providerVersion", "rolloutRevision", "targetCount"):
        item = value.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item < 1:
            raise AuthorityError(f"command_{field}_invalid")
    if value.get("targetCount") > _MAX_TARGETS:
        raise AuthorityError("command_target_limit_exceeded")
    if value.get("rolloutState") not in {"canary", "active", "rolling_back"}:
        raise AuthorityError("command_rollout_state_invalid")
    pages = value.get("pages")
    if not isinstance(pages, list) or not 1 <= len(pages) <= _MAX_PAGE_COUNT:
        raise AuthorityError("command_pages_invalid")
    for page in pages:
        if not isinstance(page, dict) or set(page) != {"id", "pageDigest", "targetCount"}:
            raise AuthorityError("command_page_reference_invalid")
        _digest(page.get("id"), "page_id")
        _digest(page.get("pageDigest"), "page_digest")
        count = page.get("targetCount")
        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= _PAGE_SIZE:
            raise AuthorityError("command_page_count_invalid")
    if sum(int(page["targetCount"]) for page in pages) != value["targetCount"]:
        raise AuthorityError("command_page_coverage_invalid")
    return value


def _target_instruction(value: object, command: dict[str, object]) -> dict[str, object]:
    """Validate one exact endpoint target against its parent command."""
    fields = {
        "schemaVersion",
        "provider",
        "providerVersion",
        "providerContentHash",
        "deploymentId",
        "agentKey",
        "agentId",
        "agentLifecycleRevision",
        "directoryDeviceRegistrationId",
        "deviceId",
        "installationId",
        "operatingSystem",
        "architecture",
        "releaseId",
        "packageId",
        "packageManifestSha256",
        "packageObjectSha256",
        "packageStorageIdentitySha256",
        "providerPackageIdentitySha256",
        "packageSignatureEvidenceSha256",
        "packageApproverEvidenceSha256",
        "packageBundleSha256",
        "packageApprovalBundleSha256",
        "bindingDigest",
        "endpointEvidenceRevision",
        "endpointEvidenceDigest",
        "endpointEvidenceObservedAt",
        "rolloutRevision",
        "rolloutState",
    }
    if not isinstance(value, dict) or set(value) != fields or value.get("schemaVersion") != 1:
        raise AuthorityError("target_schema_invalid")
    shared = {
        "provider": "provider",
        "providerVersion": "providerVersion",
        "providerContentHash": "providerContentHash",
        "deploymentId": "deploymentId",
        "releaseId": "releaseId",
        "packageId": "packageId",
        "packageManifestSha256": "packageManifestSha256",
        "packageObjectSha256": "packageObjectSha256",
        "packageStorageIdentitySha256": "packageStorageIdentitySha256",
        "providerPackageIdentitySha256": "providerPackageIdentitySha256",
        "packageSignatureEvidenceSha256": "packageSignatureEvidenceSha256",
        "packageApproverEvidenceSha256": "packageApproverEvidenceSha256",
        "packageBundleSha256": "packageBundleSha256",
        "packageApprovalBundleSha256": "packageApprovalBundleSha256",
        "rolloutRevision": "rolloutRevision",
        "rolloutState": "rolloutState",
    }
    if any(value.get(field) != command.get(parent) for field, parent in shared.items()):
        raise AuthorityError("target_command_binding_changed")
    for field in ("agentKey", "agentId", "deviceId", "installationId"):
        _identifier(value.get(field), field)
    _uuid(value.get("directoryDeviceRegistrationId"), "directory_device_registration_id")
    for field in (
        "providerContentHash",
        "packageManifestSha256",
        "packageObjectSha256",
        "packageStorageIdentitySha256",
        "providerPackageIdentitySha256",
        "packageSignatureEvidenceSha256",
        "packageApproverEvidenceSha256",
        "packageBundleSha256",
        "packageApprovalBundleSha256",
        "bindingDigest",
        "endpointEvidenceDigest",
    ):
        _digest(value.get(field), field)
    for field in (
        "agentLifecycleRevision",
        "endpointEvidenceRevision",
        "endpointEvidenceObservedAt",
    ):
        item = value.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item < 1:
            raise AuthorityError(f"target_{field}_invalid")
    if value.get("operatingSystem") not in {"darwin", "windows", "linux"}:
        raise AuthorityError("target_operating_system_invalid")
    if value.get("architecture") not in {"arm64", "x86_64"}:
        raise AuthorityError("target_architecture_invalid")
    return value


def _discovery_devices(tenant: str, now: int) -> dict[str, dict[str, object]]:
    """Load current committed MDM device identity without trusting endpoint reports."""
    devices: dict[str, dict[str, object]] = {}
    for source in _list(tenant, "DISCOVERY_SOURCE", limit=100):
        if (
            source.get("sourceKind") != "endpoint"
            or source.get("complete") is not True
            or int(source.get("expiresAt", 0)) <= now
        ):
            continue
        observations = source.get("observations")
        if observations is None:
            source_id = _identifier(source.get("sourceId"), "source_id")
            generation = _identifier(source.get("generation"), "generation")
            page_count = int(source.get("pageCount", 0))
            if not 1 <= page_count <= 100:
                raise AuthorityError("discovery_page_count_invalid")
            page_records = {
                int(page.get("pageNumber", -1)): page
                for page in _list(tenant, "DISCOVERY_PAGE", limit=1000)
                if page.get("sourceId") == source_id and page.get("generation") == generation
            }
            if set(page_records) != set(range(page_count)):
                raise AuthorityError("discovery_pages_incomplete")
            observations = []
            for page_number in range(page_count):
                page = page_records[page_number]
                page_observations = page.get("observations")
                if page_observations is None:
                    key = page.get("pageObjectKey")
                    version = page.get("pageObjectVersionId")
                    expected = page.get("pageObjectSha256")
                    if (
                        not isinstance(key, str)
                        or not key.startswith(f"tenant={tenant}/discovery-pages/")
                        or not isinstance(version, str)
                        or not _DIGEST.fullmatch(str(expected))
                    ):
                        raise AuthorityError("discovery_page_reference_invalid")
                    response = S3.get_object(
                        Bucket=os.environ.get("DISCOVERY_PAGE_BUCKET", ""),
                        Key=key,
                        VersionId=version,
                    )
                    stream = response.get("Body")
                    body = stream.read(1_048_577) if hasattr(stream, "read") else stream
                    if (
                        not isinstance(body, bytes)
                        or not 1 <= len(body) <= 1_048_576
                        or not hashlib.sha256(body).hexdigest() == expected
                    ):
                        raise AuthorityError("discovery_page_integrity_invalid")
                    try:
                        document = json.loads(body)
                    except (UnicodeDecodeError, json.JSONDecodeError) as error:
                        raise AuthorityError("discovery_page_malformed") from error
                    if (
                        not isinstance(document, dict)
                        or document.get("sourceId") != source_id
                        or document.get("generation") != generation
                        or document.get("pageNumber") != page_number
                        or document.get("pageHash") != page.get("pageHash")
                    ):
                        raise AuthorityError("discovery_page_scope_changed")
                    page_observations = document.get("observations")
                if not isinstance(page_observations, list):
                    raise AuthorityError("discovery_page_observations_invalid")
                observations.extend(page_observations)
        if not isinstance(observations, list):
            raise AuthorityError("discovery_observations_invalid")
        for observation in observations:
            if not isinstance(observation, dict) or observation.get("kind") != "device":
                continue
            allowed = {
                "kind",
                "id",
                "managed",
                "businessUnit",
                "userIds",
                "directoryDeviceRegistrationId",
            }
            if not {"kind", "id", "managed"}.issubset(observation) or not set(observation).issubset(
                allowed
            ):
                raise AuthorityError("device_observation_schema_invalid")
            device_id = _identifier(observation.get("id"), "device_id")
            registration = observation.get("directoryDeviceRegistrationId")
            if registration is not None:
                _uuid(registration, "directory_device_registration_id")
            normalized = {
                "id": device_id,
                "managed": observation.get("managed") is True,
                "directoryDeviceRegistrationId": registration,
            }
            if device_id in devices and devices[device_id] != normalized:
                raise AuthorityError("device_identity_ambiguous")
            devices[device_id] = normalized
    return devices


def _current_binding(
    target: dict[str, object],
    evidence: dict[str, object],
    agent: dict[str, object],
    agents: list[dict[str, object]],
    device: dict[str, object],
    now: int,
) -> dict[str, object]:
    """Reproduce the server-derived endpoint binding from current authority.

    Endpoint evidence may describe installations but may never select an
    enrolled agent. The worker independently correlates every active agent's
    server-owned project root and host, requires one unique candidate, and
    then reconstructs the exact policy-free binding hashed by the API.
    """
    observed_at = int(evidence.get("observedAt", 0))
    if (
        observed_at <= now - _EVIDENCE_MAX_AGE_SECONDS
        or observed_at > now + _EVIDENCE_FUTURE_SKEW_SECONDS
    ):
        raise AuthorityError("endpoint_evidence_not_current")
    payload = _plain(evidence.get("payload"))
    if not isinstance(payload, dict) or set(payload) != {
        "schemaVersion",
        "observedAt",
        "device",
        "installations",
    }:
        raise AuthorityError("endpoint_evidence_schema_invalid")
    if payload.get("schemaVersion") != 2 or payload.get("observedAt") != observed_at:
        raise AuthorityError("endpoint_platform_evidence_invalid")
    endpoint = payload.get("device")
    installations = payload.get("installations")
    if not isinstance(endpoint, dict) or not isinstance(installations, list):
        raise AuthorityError("endpoint_evidence_schema_invalid")
    operating_system = endpoint.get("operatingSystem")
    if operating_system not in {"darwin", "windows", "linux"}:
        raise AuthorityError("endpoint_platform_evidence_invalid")
    architecture = endpoint.get("architecture")
    if (
        endpoint.get("id") != target.get("deviceId")
        or operating_system != target.get("operatingSystem")
        or architecture != target.get("architecture")
    ):
        raise AuthorityError("endpoint_platform_evidence_changed")

    candidates: dict[str, tuple[dict[str, object], str, str]] = {}
    installation_ids: dict[str, set[str]] = {}
    for installation in installations:
        if not isinstance(installation, dict):
            raise AuthorityError("endpoint_installation_schema_invalid")
        installation_id = _identifier(installation.get("id"), "installation_id")
        if installation.get("deviceId") != target.get("deviceId"):
            raise AuthorityError("endpoint_installation_device_changed")
        host = installation.get("host")
        root_digest = installation.get("projectRootDigest")
        if host not in {"claude-code", "codex-cli"}:
            raise AuthorityError("endpoint_installation_host_invalid")
        _digest(root_digest, "project_root_digest")
        for candidate in agents:
            project_root = candidate.get("project_root")
            if (
                candidate.get("lifecycle_state", "active") != "active"
                or candidate.get("status") == "quarantined"
                or candidate.get("attestation_status") == "quarantined"
                or candidate.get("emergencyStop") is True
                or not isinstance(project_root, str)
                or not project_root
                or candidate.get("host") != host
                or hashlib.sha256(project_root.encode()).hexdigest() != root_digest
            ):
                continue
            candidate_key = f"{candidate.get('deployment_id')}:{candidate.get('id')}"
            candidates[candidate_key] = (candidate, str(host), str(root_digest))
            installation_ids.setdefault(candidate_key, set()).add(installation_id)
    if len(candidates) != 1:
        raise AuthorityError("endpoint_binding_not_unique")
    agent_key, (bound_agent, host, root_digest) = next(iter(candidates.items()))
    ids = sorted(installation_ids[agent_key])
    if (
        agent_key != target.get("agentKey")
        or bound_agent.get("id") != agent.get("id")
        or host != target.get("host", host)
        or ids != [target.get("installationId")]
    ):
        raise AuthorityError("endpoint_binding_changed")
    binding = {
        "status": "bound",
        "reasonCode": "unique_current_match",
        "deviceId": target["deviceId"],
        "agentKey": agent_key,
        "deploymentId": bound_agent.get("deployment_id"),
        "agentId": bound_agent.get("id"),
        "host": host,
        "operatingSystem": operating_system,
        "architecture": architecture,
        "projectRootDigest": root_digest,
        "installationIds": ids,
        "evidenceRevision": int(evidence.get("revision", 0)),
        "evidenceObservedAt": observed_at,
        "evidenceDigest": evidence.get("reportDigest"),
        "agentLifecycleRevision": int(bound_agent.get("lifecycle_revision", 0)),
        "groupIds": [],
        "policyId": None,
        "policyVersion": None,
        "directoryDeviceRegistrationId": device.get("directoryDeviceRegistrationId"),
    }
    return {**binding, "bindingDigest": _hash(binding)}


def _load_authority(
    tenant: str, command_id: str
) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]]]:
    """Reload and verify the complete latest command before secret access."""
    command = TABLE.get_item(
        Key=_key(tenant, "ENDPOINT_DELIVERY_COMMAND", command_id), ConsistentRead=True
    ).get("Item")
    if not command or command.get("tenant_id") != tenant or command.get("id") != command_id:
        raise AuthorityError("command_not_found")
    # A FIFO message can win the race with the dispatcher's best-effort
    # pending->queued projection. The immutable outbox keys and latest-authority
    # pointer remain the authorization boundary, so pending is safe to consume.
    if command.get("status") not in {
        "pending",
        "queued",
        "continuing",
        "retryable",
        "resolving_targets",
    }:
        raise AuthorityError("command_state_invalid")
    instruction = _command_instruction(_plain(command.get("instruction")))
    if not _digest(command.get("instruction_digest"), "instruction_digest") == _hash(instruction):
        raise AuthorityError("command_digest_invalid")
    if instruction.get("packageBundleSha256") != os.environ.get(
        "DELIVERY_PACKAGES_SHA256"
    ) or instruction.get("packageApprovalBundleSha256") != os.environ.get(
        "DELIVERY_PACKAGE_APPROVALS_SHA256"
    ):
        raise AuthorityError("package_authority_changed")
    deployment_id = str(instruction["deploymentId"])
    package_id = str(instruction["packageId"])
    pointer = TABLE.get_item(
        Key=_key(
            tenant,
            "ENDPOINT_DELIVERY_AUTHORITY",
            f"{deployment_id}:{package_id}",
        ),
        ConsistentRead=True,
    ).get("Item")
    if (
        not pointer
        or pointer.get("command_id") != command_id
        or pointer.get("instruction_digest") != command.get("instruction_digest")
        or pointer.get("cohort_digest") != instruction.get("cohortDigest")
    ):
        raise AuthorityError("command_superseded")
    provider_version = int(instruction["providerVersion"])
    provider_root = TABLE.get_item(
        Key=_key(tenant, "ENDPOINT_PROVIDER", "intune"), ConsistentRead=True
    ).get("Item")
    provider = TABLE.get_item(
        Key=_key(tenant, "ENDPOINT_PROVIDER_VERSION", f"intune:{provider_version}"),
        ConsistentRead=True,
    ).get("Item")
    if (
        not provider_root
        or provider_root.get("governance_state") != "active"
        or int(provider_root.get("active_version", 0)) != provider_version
        or not provider
        or provider.get("state") != "active"
        or provider.get("content_hash") != instruction.get("providerContentHash")
    ):
        raise AuthorityError("provider_authority_changed")
    configuration = _plain(provider.get("configuration"))
    if (
        not isinstance(configuration, dict)
        or configuration.get("provider") != "intune"
        or deployment_id not in configuration.get("deploymentIds", [])
        or _hash(configuration) != provider.get("content_hash")
    ):
        raise AuthorityError("provider_scope_changed")
    rollout = TABLE.get_item(
        Key=_key(tenant, "RUNTIME_ROLLOUT", deployment_id), ConsistentRead=True
    ).get("Item")
    if (
        not rollout
        or int(rollout.get("revision", 0)) != instruction.get("rolloutRevision")
        or rollout.get("state") != instruction.get("rolloutState")
    ):
        raise AuthorityError("rollout_authority_changed")
    now = int(time.time())
    devices = _discovery_devices(tenant, now)
    agents = _list(tenant, "AGENT", limit=500)
    targets: list[dict[str, object]] = []
    target_refs: list[dict[str, str]] = []
    for page_ref in instruction["pages"]:
        page = TABLE.get_item(
            Key=_key(tenant, "ENDPOINT_DELIVERY_COHORT_PAGE", str(page_ref["id"])),
            ConsistentRead=True,
        ).get("Item")
        if (
            not page
            or page.get("page_digest") != page_ref["pageDigest"]
            or int(page.get("target_count", 0)) != page_ref["targetCount"]
            or _hash(_plain(page.get("payload"))) != page.get("page_digest")
        ):
            raise AuthorityError("cohort_page_changed")
        payload = _plain(page.get("payload"))
        refs = payload.get("targets") if isinstance(payload, dict) else None
        if not isinstance(refs, list) or len(refs) != page_ref["targetCount"]:
            raise AuthorityError("cohort_page_coverage_changed")
        for target_ref in refs:
            if not isinstance(target_ref, dict) or set(target_ref) != {"id", "instructionDigest"}:
                raise AuthorityError("target_reference_invalid")
            target_id = _digest(target_ref.get("id"), "target_id")
            target = TABLE.get_item(
                Key=_key(tenant, "ENDPOINT_DELIVERY_TARGET", target_id),
                ConsistentRead=True,
            ).get("Item")
            if not target or target.get("instruction_digest") != target_ref.get(
                "instructionDigest"
            ):
                raise AuthorityError("target_record_changed")
            target_instruction = _target_instruction(_plain(target.get("instruction")), instruction)
            if _hash(target_instruction) != target.get("instruction_digest"):
                raise AuthorityError("target_digest_invalid")
            agent = TABLE.get_item(
                Key=_key(tenant, "AGENT", str(target_instruction["agentKey"])),
                ConsistentRead=True,
            ).get("Item")
            if (
                not agent
                or agent.get("lifecycle_state", "active") != "active"
                or int(agent.get("lifecycle_revision", 0))
                != target_instruction["agentLifecycleRevision"]
                or agent.get("status") == "quarantined"
                or agent.get("attestation_status") == "quarantined"
                or agent.get("emergencyStop") is True
                or agent.get("id") != target_instruction["agentId"]
                or agent.get("deployment_id") != deployment_id
                or agent.get("host") != instruction["host"]
            ):
                raise AuthorityError("agent_authority_changed")
            evidence = TABLE.get_item(
                Key=_key(tenant, "ENDPOINT_EVIDENCE", str(target_instruction["deviceId"])),
                ConsistentRead=True,
            ).get("Item")
            if (
                not evidence
                or int(evidence.get("revision", 0))
                != target_instruction["endpointEvidenceRevision"]
                or evidence.get("reportDigest") != target_instruction["endpointEvidenceDigest"]
                or int(evidence.get("observedAt", 0))
                != target_instruction["endpointEvidenceObservedAt"]
            ):
                raise AuthorityError("endpoint_evidence_changed")
            device = devices.get(str(target_instruction["deviceId"]))
            if (
                not device
                or device.get("managed") is not True
                or device.get("directoryDeviceRegistrationId")
                != target_instruction["directoryDeviceRegistrationId"]
            ):
                raise AuthorityError("managed_device_authority_changed")
            binding = _current_binding(target_instruction, evidence, agent, agents, device, now)
            if binding.get("bindingDigest") != target_instruction["bindingDigest"]:
                raise AuthorityError("endpoint_binding_digest_changed")
            targets.append(target_instruction)
            target_refs.append(
                {"id": target_id, "instructionDigest": str(target["instruction_digest"])}
            )
    if (
        len(targets) != instruction["targetCount"]
        or _hash(target_refs) != instruction["cohortDigest"]
    ):
        raise AuthorityError("cohort_digest_changed")
    return command, configuration, targets


def _secret_arn(tenant: str, value: object) -> str:
    """Validate exact delivery namespace, KMS key and tenant-purpose tags."""
    prefix = os.environ.get("ENDPOINT_DELIVERY_SECRET_PREFIX", "")
    partition = os.environ.get("AWS_PARTITION", "aws")
    region = os.environ.get("AWS_REGION", "")
    account = os.environ.get("AWS_ACCOUNT_ID", "")
    expected = f"arn:{partition}:secretsmanager:{region}:{account}:secret:{prefix}{tenant}/"
    if not isinstance(value, str) or not value.startswith(expected) or len(value) > 1024:
        raise AuthorityError("provider_secret_scope_invalid")
    description = SECRETS.describe_secret(SecretId=value)
    tags = {
        item.get("Key"): item.get("Value")
        for item in description.get("Tags", [])
        if isinstance(item, dict)
    }
    if (
        description.get("ARN") != value
        or description.get("DeletedDate") is not None
        or description.get("KmsKeyId") != os.environ.get("ENDPOINT_DELIVERY_SECRET_KMS_KEY_ARN")
        or tags
        != {
            "aai-sec:tenant-id": tenant,
            "aai-sec:purpose": "endpoint-delivery-provider",
        }
    ):
        raise AuthorityError("provider_secret_metadata_changed")
    return value


def _credentials(
    tenant: str, configuration: dict[str, object], command: dict[str, object]
) -> dict[str, object]:
    """Read and validate only the approved Intune resource mapping in memory."""
    response = SECRETS.get_secret_value(
        SecretId=_secret_arn(tenant, configuration.get("providerSecretArn"))
    )
    try:
        value = json.loads(response.get("SecretString", ""))
    except (TypeError, json.JSONDecodeError) as error:
        raise AuthorityError("provider_secret_malformed") from error
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schemaVersion",
            "clientId",
            "clientSecret",
            "resources",
        }
        or value.get("schemaVersion") != 1
    ):
        raise AuthorityError("provider_secret_schema_invalid")
    _uuid(value.get("clientId"), "client_id")
    secret = value.get("clientSecret")
    if not isinstance(secret, str) or not 20 <= len(secret.encode()) <= 4096:
        raise AuthorityError("provider_client_secret_invalid")
    resources = value.get("resources")
    if not isinstance(resources, list) or not 1 <= len(resources) <= 250:
        raise AuthorityError("provider_resource_registry_invalid")
    instruction = command["instruction"]
    matches = []
    for resource in resources:
        if not isinstance(resource, dict) or set(resource) != {
            "deploymentId",
            "providerPackageIdentitySha256",
            "mobileAppId",
            "mobileAppEvidenceSha256",
            "groupId",
            "groupEvidenceSha256",
        }:
            raise AuthorityError("provider_resource_schema_invalid")
        _identifier(resource.get("deploymentId"), "resource_deployment_id")
        _digest(resource.get("providerPackageIdentitySha256"), "resource_package_identity")
        _uuid(resource.get("mobileAppId"), "mobile_app_id")
        _digest(resource.get("mobileAppEvidenceSha256"), "mobile_app_evidence")
        _uuid(resource.get("groupId"), "group_id")
        _digest(resource.get("groupEvidenceSha256"), "group_evidence")
        if hashlib.sha256(str(resource["mobileAppId"]).encode()).hexdigest() != resource.get(
            "providerPackageIdentitySha256"
        ):
            raise AuthorityError("provider_app_package_identity_changed")
        if resource.get("deploymentId") == instruction.get("deploymentId") and resource.get(
            "providerPackageIdentitySha256"
        ) == instruction.get("providerPackageIdentitySha256"):
            matches.append(resource)
    if len(matches) != 1:
        raise AuthorityError("provider_resource_mapping_ambiguous")
    return {"clientId": value["clientId"], "clientSecret": secret, "resource": matches[0]}


def _public_host(host: str) -> None:
    """Require every fixed provider hostname to resolve only to global addresses."""
    addresses = {
        result[4][0]
        for result in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        if result[4]
    }
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise AuthorityError("provider_origin_resolution_invalid")


def _request(
    method: str,
    url: str,
    *,
    token: str | None = None,
    body: dict[str, object] | None = None,
    encoded: bytes | None = None,
) -> tuple[int, dict[str, object]]:
    """Perform one bounded fixed-origin no-redirect request."""
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.port not in {None, 443}
        or parsed.hostname not in {"graph.microsoft.com", "login.microsoftonline.com"}
    ):
        raise AuthorityError("provider_request_origin_invalid")
    _public_host(str(parsed.hostname))
    headers = {"Accept": "application/json", "User-Agent": "aai-sec-intune/1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = encoded
    if encoded is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if body is not None:
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method)  # noqa: S310
    response = build_opener(_NoRedirects()).open(request, timeout=8.0)
    status = int(getattr(response, "status", 0))
    raw = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise AuthorityError("provider_response_oversized")
    if not 200 <= status < 300:
        raise HTTPError(url, status, "non-success", {}, None)
    if not raw:
        return status, {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise AuthorityError("provider_response_malformed") from error
    if not isinstance(value, dict):
        raise AuthorityError("provider_response_malformed")
    return status, value


def _token(provider_tenant_id: str, credentials: dict[str, object]) -> str:
    """Acquire one tenant-specific application token without persisting it."""
    _uuid(provider_tenant_id, "provider_tenant_id")
    _, response = _request(
        "POST",
        f"{_LOGIN_ORIGIN}/{provider_tenant_id}/oauth2/v2.0/token",
        encoded=urlencode(
            {
                "client_id": credentials["clientId"],
                "client_secret": credentials["clientSecret"],
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            }
        ).encode(),
    )
    token = response.get("access_token")
    if response.get("token_type") != "Bearer" or not isinstance(token, str) or not token:
        raise AuthorityError("provider_token_invalid")
    return token


def _collection(url: str, token: str) -> list[dict[str, object]]:
    """Read a bounded Graph collection while constraining every next link."""
    items: list[dict[str, object]] = []
    current = url
    for _ in range(_MAX_PAGE_COUNT):
        _, response = _request("GET", current, token=token)
        values = response.get("value")
        if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
            raise AuthorityError("provider_collection_invalid")
        items.extend(values)
        if len(items) > 1000:
            raise AuthorityError("provider_collection_oversized")
        next_link = response.get("@odata.nextLink")
        if next_link is None:
            return items
        parsed = urlsplit(next_link) if isinstance(next_link, str) else None
        if (
            parsed is None
            or parsed.scheme != "https"
            or parsed.hostname != "graph.microsoft.com"
            or not parsed.path.startswith("/v1.0/")
            or parsed.username
            or parsed.password
            or parsed.port not in {None, 443}
        ):
            raise AuthorityError("provider_pagination_origin_invalid")
        current = next_link
    raise AuthorityError("provider_pagination_exceeded")


def _resource_evidence(value: dict[str, object], fields: tuple[str, ...]) -> str:
    """Hash only reviewed provider metadata fields."""
    if any(field not in value for field in fields):
        raise AuthorityError("provider_resource_evidence_incomplete")
    return _hash({field: value[field] for field in fields})


def _provider_context(
    configuration: dict[str, object], credentials: dict[str, object]
) -> tuple[str, str, str]:
    """Load and verify the reviewed provider group and application identity."""
    resource = credentials["resource"]
    if not isinstance(resource, dict):
        raise AuthorityError("provider_resource_schema_invalid")
    token = _token(str(configuration["providerTenantId"]), credentials)
    group_id = str(resource["groupId"])
    app_id = str(resource["mobileAppId"])
    _, group = _request(
        "GET",
        f"{_GRAPH_ORIGIN}/v1.0/groups/{group_id}"
        "?$select=id,displayName,description,securityEnabled,mailEnabled",
        token=token,
    )
    if (
        group.get("id") != group_id
        or _resource_evidence(
            group, ("id", "displayName", "description", "securityEnabled", "mailEnabled")
        )
        != resource["groupEvidenceSha256"]
    ):
        raise AuthorityError("provider_group_ownership_changed")
    if group.get("securityEnabled") is not True or group.get("mailEnabled") is not False:
        raise AuthorityError("provider_group_type_invalid")
    _, app = _request(
        "GET",
        f"{_GRAPH_ORIGIN}/v1.0/deviceAppManagement/mobileApps/{app_id}"
        "?$select=id,displayName,publisher,createdDateTime,lastModifiedDateTime",
        token=token,
    )
    if (
        app.get("id") != app_id
        or _resource_evidence(
            app,
            ("id", "displayName", "publisher", "createdDateTime", "lastModifiedDateTime"),
        )
        != resource["mobileAppEvidenceSha256"]
    ):
        raise AuthorityError("provider_app_identity_changed")
    return token, group_id, app_id


def _reconcile_graph(
    configuration: dict[str, object],
    credentials: dict[str, object],
    targets: list[dict[str, object]],
    reauthorize: Callable[[], object],
) -> dict[str, object]:
    """Converge one dedicated group and one independent required assignment."""
    token, group_id, app_id = _provider_context(configuration, credentials)
    resolved = []
    for target in targets:
        registration = str(target["directoryDeviceRegistrationId"])
        _, device = _request(
            "GET",
            f"{_GRAPH_ORIGIN}/v1.0/devices(deviceId='{quote(registration, safe='')}')"
            "?$select=id,deviceId,accountEnabled",
            token=token,
        )
        object_id = _uuid(device.get("id"), "directory_object_id")
        if device.get("deviceId") != registration or device.get("accountEnabled") is False:
            raise AuthorityError("provider_device_resolution_changed")
        resolved.append(object_id)
    if len(set(resolved)) != len(resolved):
        raise AuthorityError("provider_device_resolution_ambiguous")
    desired = set(resolved)
    members = _collection(
        f"{_GRAPH_ORIGIN}/v1.0/groups/{group_id}/members?$select=id,deviceId&$top=999",
        token,
    )
    current = {_uuid(item.get("id"), "group_member_id") for item in members}
    for object_id in sorted(desired - current):
        reauthorize()
        _request(
            "POST",
            f"{_GRAPH_ORIGIN}/v1.0/groups/{group_id}/members/$ref",
            token=token,
            body={"@odata.id": f"{_GRAPH_ORIGIN}/v1.0/directoryObjects/{object_id}"},
        )
    for object_id in sorted(current - desired):
        reauthorize()
        _request(
            "DELETE",
            f"{_GRAPH_ORIGIN}/v1.0/groups/{group_id}/members/{object_id}/$ref",
            token=token,
        )
    assignments = _collection(
        f"{_GRAPH_ORIGIN}/v1.0/deviceAppManagement/mobileApps/{app_id}/assignments"
        "?$select=id,intent,target",
        token,
    )
    matching = [
        item
        for item in assignments
        if isinstance(item.get("target"), dict) and item["target"].get("groupId") == group_id
    ]
    if len(matching) > 1:
        raise AuthorityError("provider_assignment_ambiguous")
    if matching and matching[0].get("intent") != "required":
        raise AuthorityError("provider_assignment_intent_changed")
    if not matching:
        reauthorize()
        _request(
            "POST",
            f"{_GRAPH_ORIGIN}/v1.0/deviceAppManagement/mobileApps/{app_id}/assignments",
            token=token,
            body={
                "@odata.type": "#microsoft.graph.mobileAppAssignment",
                "intent": "required",
                "target": {
                    "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                    "groupId": group_id,
                },
            },
        )
    reproduced_members = _collection(
        f"{_GRAPH_ORIGIN}/v1.0/groups/{group_id}/members?$select=id&$top=999",
        token,
    )
    if {_uuid(item.get("id"), "group_member_id") for item in reproduced_members} != desired:
        raise ProviderRetryable("provider_membership_not_converged")
    reproduced_assignments = _collection(
        f"{_GRAPH_ORIGIN}/v1.0/deviceAppManagement/mobileApps/{app_id}/assignments"
        "?$select=id,intent,target",
        token,
    )
    reproduced = [
        item
        for item in reproduced_assignments
        if item.get("intent") == "required"
        and isinstance(item.get("target"), dict)
        and item["target"].get("groupId") == group_id
    ]
    if len(reproduced) != 1:
        raise ProviderRetryable("provider_assignment_not_converged")
    return {
        "groupReferenceSha256": hashlib.sha256(group_id.encode()).hexdigest(),
        "appReferenceSha256": hashlib.sha256(app_id.encode()).hexdigest(),
        "assignmentReferenceSha256": hashlib.sha256(
            str(reproduced[0].get("id", "")).encode()
        ).hexdigest(),
        "targetCount": len(desired),
    }


def _group_member_inventory(token: str, group_id: str) -> list[tuple[str, str | None]]:
    """Return bounded device members as validated object/registration identities."""
    members = _collection(
        f"{_GRAPH_ORIGIN}/v1.0/groups/{group_id}/members?$select=id,deviceId&$top=999",
        token,
    )
    result: list[tuple[str, str | None]] = []
    seen_objects: set[str] = set()
    for member in members:
        object_id = _uuid(member.get("id"), "group_member_id")
        if object_id in seen_objects:
            raise AuthorityError("provider_group_membership_ambiguous")
        seen_objects.add(object_id)
        registration_value = member.get("deviceId")
        registration = (
            _uuid(registration_value, "group_member_registration_id")
            if registration_value is not None
            else None
        )
        result.append((object_id, registration))
    return result


def _resolve_directory_target(target: dict[str, object], token: str) -> tuple[str, str]:
    """Resolve one current Entra registration through the fixed Graph endpoint."""
    registration = _uuid(
        target.get("directoryDeviceRegistrationId"),
        "directory_device_registration_id",
    )
    _, device = _request(
        "GET",
        f"{_GRAPH_ORIGIN}/v1.0/devices(deviceId='{quote(registration, safe='')}')"
        "?$select=id,deviceId,accountEnabled",
        token=token,
    )
    object_id = _uuid(device.get("id"), "directory_object_id")
    if device.get("deviceId") != registration or device.get("accountEnabled") is False:
        raise AuthorityError("provider_device_resolution_changed")
    return object_id, registration


def _reconcile_graph_page(
    configuration: dict[str, object],
    credentials: dict[str, object],
    targets: list[dict[str, object]],
    reauthorize: Callable[[], object],
) -> dict[str, object]:
    """Add and reproduce one immutable page without pruning the complete group."""
    if not 1 <= len(targets) <= _PAGE_SIZE:
        raise AuthorityError("continuation_page_target_count_invalid")
    token, group_id, _app_id = _provider_context(configuration, credentials)
    members = _group_member_inventory(token, group_id)
    by_registration = {
        registration: object_id for object_id, registration in members if registration is not None
    }
    if len(by_registration) != sum(registration is not None for _, registration in members):
        raise AuthorityError("provider_group_membership_ambiguous")
    object_ids = {object_id for object_id, _registration in members}
    expected: dict[str, str] = {}
    resolved_objects: set[str] = set()
    for target in targets:
        object_id, registration = _resolve_directory_target(target, token)
        if (
            registration in expected
            or (registration in by_registration and by_registration[registration] != object_id)
            or object_id in resolved_objects
        ):
            raise AuthorityError("provider_device_resolution_ambiguous")
        if object_id in object_ids and by_registration.get(registration) != object_id:
            raise AuthorityError("provider_device_resolution_changed")
        expected[registration] = object_id
        resolved_objects.add(object_id)
        if registration not in by_registration:
            reauthorize()
            _request(
                "POST",
                f"{_GRAPH_ORIGIN}/v1.0/groups/{group_id}/members/$ref",
                token=token,
                body={"@odata.id": f"{_GRAPH_ORIGIN}/v1.0/directoryObjects/{object_id}"},
            )
    reproduced_members = _group_member_inventory(token, group_id)
    reproduced = {
        registration: object_id
        for object_id, registration in reproduced_members
        if registration is not None
    }
    if len(reproduced) != sum(
        registration is not None for _object_id, registration in reproduced_members
    ) or any(
        reproduced.get(registration) != object_id for registration, object_id in expected.items()
    ):
        raise ProviderRetryable("provider_page_membership_not_converged")
    return {
        "pageTargetCount": len(expected),
        "pageRegistrationDigest": _hash(sorted(expected)),
    }


def _finalize_graph_continuation(
    configuration: dict[str, object],
    credentials: dict[str, object],
    targets: list[dict[str, object]],
    reauthorize: Callable[[], object],
) -> tuple[bool, dict[str, object] | None, int]:
    """Prune bounded group drift, assign the app and reproduce exact provider state."""
    token, group_id, app_id = _provider_context(configuration, credentials)
    desired_registrations = [
        _uuid(target.get("directoryDeviceRegistrationId"), "directory_device_registration_id")
        for target in targets
    ]
    desired = set(desired_registrations)
    if len(desired) != len(desired_registrations):
        raise AuthorityError("provider_device_resolution_ambiguous")
    members = _group_member_inventory(token, group_id)
    observed = [registration for _object_id, registration in members if registration is not None]
    if len(set(observed)) != len(observed):
        raise AuthorityError("provider_group_membership_ambiguous")
    if not desired.issubset(set(observed)):
        raise ProviderRetryable("provider_membership_not_converged")
    extras = sorted(object_id for object_id, registration in members if registration not in desired)
    for object_id in extras[:_MAX_MUTATIONS_PER_INVOCATION]:
        reauthorize()
        _request(
            "DELETE",
            f"{_GRAPH_ORIGIN}/v1.0/groups/{group_id}/members/{object_id}/$ref",
            token=token,
        )
    if len(extras) > _MAX_MUTATIONS_PER_INVOCATION:
        return False, None, _MAX_MUTATIONS_PER_INVOCATION
    reproduced_members = _group_member_inventory(token, group_id)
    if {registration for _object_id, registration in reproduced_members} != desired:
        raise ProviderRetryable("provider_membership_not_converged")
    assignments = _collection(
        f"{_GRAPH_ORIGIN}/v1.0/deviceAppManagement/mobileApps/{app_id}/assignments"
        "?$select=id,intent,target",
        token,
    )
    matching = [
        item
        for item in assignments
        if isinstance(item.get("target"), dict) and item["target"].get("groupId") == group_id
    ]
    if len(matching) > 1:
        raise AuthorityError("provider_assignment_ambiguous")
    if matching and matching[0].get("intent") != "required":
        raise AuthorityError("provider_assignment_intent_changed")
    if not matching:
        reauthorize()
        _request(
            "POST",
            f"{_GRAPH_ORIGIN}/v1.0/deviceAppManagement/mobileApps/{app_id}/assignments",
            token=token,
            body={
                "@odata.type": "#microsoft.graph.mobileAppAssignment",
                "intent": "required",
                "target": {
                    "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                    "groupId": group_id,
                },
            },
        )
    reproduced_assignments = _collection(
        f"{_GRAPH_ORIGIN}/v1.0/deviceAppManagement/mobileApps/{app_id}/assignments"
        "?$select=id,intent,target",
        token,
    )
    reproduced = [
        item
        for item in reproduced_assignments
        if item.get("intent") == "required"
        and isinstance(item.get("target"), dict)
        and item["target"].get("groupId") == group_id
    ]
    if len(reproduced) != 1:
        raise ProviderRetryable("provider_assignment_not_converged")
    return (
        True,
        {
            "groupReferenceSha256": hashlib.sha256(group_id.encode()).hexdigest(),
            "appReferenceSha256": hashlib.sha256(app_id.encode()).hexdigest(),
            "assignmentReferenceSha256": hashlib.sha256(
                str(reproduced[0].get("id", "")).encode()
            ).hexdigest(),
            "targetCount": len(desired),
        },
        len(extras),
    )


def _transition(
    command: dict[str, object],
    *,
    status: str,
    attempt: int,
    reason: str | None = None,
    evidence: dict[str, object] | None = None,
    continuation: dict[str, object] | None = None,
) -> dict[str, object]:
    """Optimistically persist one content-minimised worker transition."""
    updated = {
        **{key: value for key, value in command.items() if not key.startswith("delivery_outbox_")},
        "status": status,
        "attempt_count": attempt,
        "failure_code": reason,
        "provider_evidence": evidence,
        "updated_at": int(time.time()),
        **(continuation or {}),
    }
    TABLE.put_item(
        Item=updated,
        ConditionExpression="#status = :status AND attempt_count = :attempt",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": command.get("status"),
            ":attempt": int(command.get("attempt_count", 0)),
        },
    )
    return updated


def _audit_terminal(tenant: str, command: dict[str, object]) -> None:
    """Retain terminal content-minimised provider evidence under Object Lock."""
    evidence = {
        "schemaVersion": 1,
        "tenantId": tenant,
        "commandId": command.get("id"),
        "deploymentId": command.get("deployment_id"),
        "packageId": command.get("package_id"),
        "rolloutRevision": int(command.get("rollout_revision", 0)),
        "targetCount": int(command.get("target_count", 0)),
        "cohortDigest": command.get("cohort_digest"),
        "status": command.get("status"),
        "attemptCount": int(command.get("attempt_count", 0)),
        "failureCode": command.get("failure_code"),
        "providerEvidence": command.get("provider_evidence"),
        "continuationRevision": int(command.get("continuation_revision", 0)),
        "continuationStage": command.get("continuation_stage", "not_started"),
        "completedTargets": int(command.get("continuation_completed_targets", 0)),
        "mutationCount": int(command.get("continuation_mutation_count", 0)),
        "occurredAt": int(command.get("updated_at", time.time())),
    }
    body = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    S3.put_object(
        Bucket=os.environ["AUDIT_BUCKET"],
        Key=(
            f"tenant={tenant}/endpoint-delivery/"
            f"{int(command.get('updated_at', time.time()))}-{command.get('id')}.json"
        ),
        Body=body,
        ContentType="application/json",
        Metadata={"content-sha256": hashlib.sha256(body).hexdigest(), "schema-version": "1"},
        ObjectLockMode="COMPLIANCE",
        ObjectLockRetainUntilDate=datetime.now(UTC) + timedelta(days=365),
    )


def _continuation_queue_url() -> str:
    """Validate the deployment-owned FIFO URL used only for opaque continuations."""
    value = os.environ.get("ENDPOINT_DELIVERY_QUEUE_URL", "")
    parsed = urlsplit(value)
    region = os.environ.get("AWS_REGION", "")
    account = os.environ.get("AWS_ACCOUNT_ID", "")
    suffix = "amazonaws.com.cn" if os.environ.get("AWS_PARTITION") == "aws-cn" else "amazonaws.com"
    expected_host = f"sqs.{region}.{suffix}"
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected_host
        or parsed.username
        or parsed.password
        or parsed.port not in {None, 443}
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith(f"/{account}/")
        or not parsed.path.endswith(".fifo")
    ):
        raise RuntimeError("endpoint delivery continuation queue is invalid")
    return value


def _enqueue_continuation(tenant: str, command_id: str, revision: int) -> None:
    """Send one idempotent opaque continuation after durable state advancement."""
    if not 1 <= revision <= _MAX_CONTINUATION_REVISIONS:
        raise AuthorityError("continuation_revision_invalid")
    SQS.send_message(
        QueueUrl=_continuation_queue_url(),
        MessageBody=json.dumps(
            {
                "tenantId": tenant,
                "commandId": command_id,
                "continuationRevision": revision,
            },
            separators=(",", ":"),
        ),
        MessageGroupId=tenant,
        MessageDeduplicationId=f"{command_id}:{revision}",
    )


def _page_targets(
    instruction: dict[str, object], targets: list[dict[str, object]], page_index: int
) -> list[dict[str, object]]:
    """Select one immutable page from the already reauthorized complete cohort."""
    pages = instruction["pages"]
    if not isinstance(pages, list) or not 0 <= page_index < len(pages):
        raise AuthorityError("continuation_page_invalid")
    counts = [int(page["targetCount"]) for page in pages]
    start = sum(counts[:page_index])
    selected = targets[start : start + counts[page_index]]
    if len(selected) != counts[page_index]:
        raise AuthorityError("continuation_page_coverage_changed")
    return selected


def _advance_continuation(
    tenant: str,
    command: dict[str, object],
    *,
    attempt: int,
    stage: str,
    page: int,
    completed_targets: int,
    mutation_count: int,
) -> dict[str, object]:
    """Persist a monotonic continuation and then idempotently enqueue it."""
    current_revision = int(command.get("continuation_revision", 0))
    next_revision = current_revision + 1
    if next_revision > _MAX_CONTINUATION_REVISIONS:
        raise AuthorityError("continuation_revision_limit_exceeded")
    updated = _transition(
        command,
        status="continuing",
        attempt=attempt,
        continuation={
            "continuation_revision": next_revision,
            "continuation_stage": stage,
            "continuation_page": page,
            "continuation_completed_targets": completed_targets,
            "continuation_mutation_count": mutation_count,
        },
    )
    try:
        _enqueue_continuation(tenant, str(command["id"]), next_revision)
    except Exception:
        # The older FIFO record will be retried. It observes the durable newer
        # revision and repairs this exact message without repeating a page.
        try:
            _transition(
                updated,
                status="retryable",
                attempt=attempt,
                reason="continuation_enqueue_failed",
            )
        except Exception:
            # Preserve the first durable advancement if the diagnostic status
            # races. The old record still repairs the same exact revision.
            pass
        raise RuntimeError("endpoint delivery continuation requires retry") from None
    return updated


def _continue_large_command(
    tenant: str,
    command: dict[str, object],
    configuration: dict[str, object],
    targets: list[dict[str, object]],
    *,
    attempt: int,
) -> dict[str, object]:
    """Resolve one page or one bounded prune step for a large sealed cohort."""
    instruction = _command_instruction(_plain(command.get("instruction")))
    pages = instruction["pages"]
    if not isinstance(pages, list):
        raise AuthorityError("command_pages_invalid")
    stage = command.get("continuation_stage", "resolving_pages")
    page = int(command.get("continuation_page", 0))
    completed_targets = int(command.get("continuation_completed_targets", 0))
    mutation_count = int(command.get("continuation_mutation_count", 0))
    if (
        stage not in {"resolving_pages", "pruning"}
        or not 0 <= page <= len(pages)
        or not 0 <= completed_targets <= len(targets)
        or not 0 <= mutation_count <= _MAX_TARGETS * 2
    ):
        raise AuthorityError("continuation_state_invalid")
    credentials = _credentials(tenant, configuration, command)

    def reauthorize() -> object:
        """Reload the complete live cohort before one provider mutation."""
        return _load_authority(tenant, str(command["id"]))

    if stage == "resolving_pages":
        selected = _page_targets(instruction, targets, page)
        progress = _reconcile_graph_page(
            configuration,
            credentials,
            selected,
            reauthorize,
        )
        next_completed = completed_targets + int(progress["pageTargetCount"])
        next_page = page + 1
        next_stage = "pruning" if next_page == len(pages) else "resolving_pages"
        advanced = _advance_continuation(
            tenant,
            command,
            attempt=attempt,
            stage=next_stage,
            page=next_page,
            completed_targets=next_completed,
            mutation_count=mutation_count,
        )
        return {
            "status": "continuing",
            "commandId": command["id"],
            "continuationRevision": advanced["continuation_revision"],
            "completedTargets": next_completed,
            "targetCount": len(targets),
        }
    complete, evidence, removed = _finalize_graph_continuation(
        configuration,
        credentials,
        targets,
        reauthorize,
    )
    if not complete:
        advanced = _advance_continuation(
            tenant,
            command,
            attempt=attempt,
            stage="pruning",
            page=page,
            completed_targets=completed_targets,
            mutation_count=mutation_count + removed,
        )
        return {
            "status": "continuing",
            "commandId": command["id"],
            "continuationRevision": advanced["continuation_revision"],
            "completedTargets": completed_targets,
            "targetCount": len(targets),
        }
    # Provider convergence is channel evidence only. Reproduce all server-owned
    # authority once more before sealing that evidence as terminal.
    reauthorize()
    completed = _transition(
        command,
        status="assigned_reported",
        attempt=attempt,
        evidence=evidence,
        continuation={
            "continuation_stage": "complete",
            "continuation_page": page,
            "continuation_completed_targets": len(targets),
            "continuation_mutation_count": mutation_count + removed,
        },
    )
    _audit_terminal(tenant, completed)
    return {
        "status": "assigned_reported",
        "commandId": command["id"],
        "targetCount": len(targets),
    }


def _event_record(event: object) -> tuple[str, str, int, int]:
    """Validate the exact single-record FIFO invocation contract."""
    if not isinstance(event, dict) or set(event) != {"Records"}:
        raise ValueError("endpoint delivery worker event is invalid")
    records = event.get("Records")
    if not isinstance(records, list) or len(records) != 1:
        raise ValueError("endpoint delivery worker requires one FIFO record")
    record = records[0]
    if not isinstance(record, dict) or record.get("eventSource") != "aws:sqs":
        raise ValueError("endpoint delivery worker source is invalid")
    try:
        body = json.loads(record.get("body", ""))
        receive_count = int(record.get("attributes", {}).get("ApproximateReceiveCount", "0"))
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("endpoint delivery worker envelope is malformed") from error
    if not isinstance(body, dict) or set(body) not in (
        {"tenantId", "commandId"},
        {"tenantId", "commandId", "continuationRevision"},
    ):
        raise ValueError("endpoint delivery worker body is invalid")
    tenant = _identifier(body.get("tenantId"), "tenant_id")
    command_id = _digest(body.get("commandId"), "command_id")
    if not 1 <= receive_count <= _MAX_ATTEMPTS:
        raise ValueError("endpoint delivery receive count is invalid")
    continuation_revision = body.get("continuationRevision", 0)
    if (
        isinstance(continuation_revision, bool)
        or not isinstance(continuation_revision, int)
        or not 0 <= continuation_revision <= _MAX_CONTINUATION_REVISIONS
    ):
        raise ValueError("endpoint delivery continuation revision is invalid")
    return tenant, command_id, receive_count, continuation_revision


def handler(event, context):  # noqa: ANN001, ANN201, ARG001
    """Reauthorize and converge one opaque Intune package/cohort command."""
    _deployment_gate()
    tenant, command_id, receive_count, message_revision = _event_record(event)
    command: dict[str, object] | None = None
    attempt = receive_count
    try:
        command, configuration, targets = _load_authority(tenant, command_id)
        current_revision = int(command.get("continuation_revision", 0))
        if message_revision != current_revision:
            if message_revision < current_revision and command.get("status") in {
                "continuing",
                "retryable",
                "resolving_targets",
            }:
                _enqueue_continuation(tenant, command_id, current_revision)
                return {
                    "status": "continuation_repaired",
                    "commandId": command_id,
                    "continuationRevision": current_revision,
                }
            raise AuthorityError("continuation_revision_changed")
        attempt = int(command.get("attempt_count", 0)) + 1
        command = _transition(command, status="resolving_targets", attempt=attempt)
        if len(targets) > _PAGE_SIZE:
            return _continue_large_command(
                tenant,
                command,
                configuration,
                targets,
                attempt=attempt,
            )
        credentials = _credentials(tenant, configuration, command)
        evidence = _reconcile_graph(
            configuration,
            credentials,
            targets,
            lambda: _load_authority(tenant, command_id),
        )
        # Provider reads are not runtime proof. Recheck every server-owned
        # authority record once more before reporting provider convergence.
        _load_authority(tenant, command_id)
        completed = _transition(
            command,
            status="assigned_reported",
            attempt=attempt,
            evidence=evidence,
        )
        _audit_terminal(tenant, completed)
        return {
            "status": "assigned_reported",
            "commandId": command_id,
            "targetCount": completed.get("target_count"),
        }
    except AuthorityError as error:
        if command is None:
            command = TABLE.get_item(
                Key=_key(tenant, "ENDPOINT_DELIVERY_COMMAND", command_id), ConsistentRead=True
            ).get("Item")
        if command and command.get("status") in {
            "pending",
            "queued",
            "continuing",
            "retryable",
            "resolving_targets",
        }:
            terminal = _transition(
                command,
                status="superseded" if error.code == "command_superseded" else "blocked",
                attempt=attempt,
                reason=error.code,
            )
            _audit_terminal(tenant, terminal)
            return {"status": terminal["status"], "failureCode": error.code}
        raise
    except (ProviderRetryable, HTTPError, URLError, TimeoutError, OSError) as error:
        if command is None:
            raise
        if isinstance(error, HTTPError) and 300 <= error.code < 400:
            terminal = _transition(
                command,
                status="blocked",
                attempt=attempt,
                reason="provider_redirect_denied",
            )
            _audit_terminal(tenant, terminal)
            return {"status": "blocked", "failureCode": terminal["failure_code"]}
        if isinstance(error, HTTPError) and error.code in {400, 401, 403, 404}:
            terminal = _transition(
                command,
                status="blocked",
                attempt=attempt,
                reason=f"provider_http_{error.code}",
            )
            _audit_terminal(tenant, terminal)
            return {"status": "blocked", "failureCode": terminal["failure_code"]}
        reason = (
            "provider_retry_exhausted" if receive_count >= _MAX_ATTEMPTS else "provider_retryable"
        )
        failed = _transition(
            command,
            status="failed" if receive_count >= _MAX_ATTEMPTS else "retryable",
            attempt=attempt,
            reason=reason,
        )
        if receive_count >= _MAX_ATTEMPTS:
            _audit_terminal(tenant, failed)
            return {"status": "failed", "failureCode": reason}
        # Suppress the provider exception chain because HTTP URLs may contain
        # directory identifiers and transport errors may include network data.
        raise RuntimeError("Intune provider reconciliation requires retry") from None
