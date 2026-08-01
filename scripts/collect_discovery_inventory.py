#!/usr/bin/env python3
"""Collect content-minimised Entra, endpoint, or GitHub discovery inventory.

Tokens are read only from named environment variables. Output is normalized
JSON on stdout so it can be reviewed before publication with
``publish_discovery_generation.py``. No connector token, provider token, raw
project path, email address, login name, prompt, command, or tool content is
emitted.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import certifi

_MAX_PROVIDER_PAGES = 100
_TIMEOUT_SECONDS = 15.0
_SUPPORTED_HOSTS = frozenset({"claude-code", "codex-cli"})
_UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


class DiscoveryCollectionError(RuntimeError):
    """Report a bounded collector schema, credential, or transport failure."""


def _get_json(
    url: str,
    token: str,
    *,
    allowed_host: str,
    timeout_seconds: float = _TIMEOUT_SECONDS,
    open_request: Callable[..., Any] = urllib.request.urlopen,
) -> Any:
    """Read one provider page after enforcing HTTPS and an exact host allow-list."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != allowed_host:
        raise DiscoveryCollectionError("provider pagination escaped its allowed HTTPS origin")
    if not token:
        raise DiscoveryCollectionError("provider credential is required")
    request = urllib.request.Request(  # noqa: S310 -- URL is checked immediately above.
        url,
        headers={
            "authorization": f"Bearer {token}",
            "accept": "application/json",
            "user-agent": "aai-sec-discovery-collector/1",
        },
    )
    try:
        with open_request(
            request,
            timeout=timeout_seconds,
            context=ssl.create_default_context(cafile=certifi.where()),
        ) as response:
            payload = response.read()
    except urllib.error.HTTPError as error:
        raise DiscoveryCollectionError(f"provider returned HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise DiscoveryCollectionError(f"provider request failed: {error}") from error
    try:
        return json.loads(payload)
    except json.JSONDecodeError as error:
        raise DiscoveryCollectionError("provider returned malformed JSON") from error


def collect_entra_users(
    token: str,
    *,
    get_json: Callable[..., Any] = _get_json,
) -> list[dict[str, Any]]:
    """Collect opaque Entra IDs, active state and optional department only."""
    url: str | None = (
        "https://graph.microsoft.com/v1.0/users?$select=id,accountEnabled,department&$top=999"
    )
    observations: list[dict[str, Any]] = []
    seen: set[str] = set()
    for _ in range(_MAX_PROVIDER_PAGES):
        if url is None:
            return observations
        page = get_json(url, token, allowed_host="graph.microsoft.com")
        if not isinstance(page, dict) or not isinstance(page.get("value"), list):
            raise DiscoveryCollectionError("Entra returned an invalid users page")
        for user in page["value"]:
            if not isinstance(user, dict) or set(user) - {"id", "accountEnabled", "department"}:
                raise DiscoveryCollectionError("Entra user record has an unexpected schema")
            identifier = user.get("id")
            active = user.get("accountEnabled")
            if not isinstance(identifier, str) or not identifier or not isinstance(active, bool):
                raise DiscoveryCollectionError("Entra user identity or state is invalid")
            if identifier in seen:
                raise DiscoveryCollectionError("Entra returned a duplicate user identity")
            seen.add(identifier)
            observation: dict[str, Any] = {
                "kind": "identity",
                "id": identifier,
                "active": active,
            }
            department = user.get("department")
            if isinstance(department, str) and department.strip():
                observation["businessUnit"] = department.strip()
            observations.append(observation)
        next_url = page.get("@odata.nextLink")
        if next_url is not None and not isinstance(next_url, str):
            raise DiscoveryCollectionError("Entra pagination link is invalid")
        url = next_url
    raise DiscoveryCollectionError("Entra pagination exceeded the 100-page bound")


def _intune_url(value: str) -> str:
    """Constrain Intune pagination to the selected managed-device fields."""
    parsed = urllib.parse.urlsplit(value)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "graph.microsoft.com"
        or parsed.path != "/v1.0/deviceManagement/managedDevices"
        or parsed.fragment
        or set(query) - {"$select", "$top", "$skiptoken"}
        or query.get("$select") != ["id,userId"]
        or query.get("$top") != ["100"]
        or len(query.get("$skiptoken", [])) > 1
        or any(len(item) > 1_024 for item in query.get("$skiptoken", []))
    ):
        raise DiscoveryCollectionError("Intune pagination escaped the managed-device query")
    return value


def _intune_business_units(path: Path | None) -> dict[str, str]:
    """Read an optional exact map from opaque Entra user ID to reporting label."""
    if path is None:
        return {}
    value = _read_json(path, "Intune business-unit mapping")
    rows = (
        value.get("userBusinessUnits")
        if isinstance(value, dict) and set(value) == {"userBusinessUnits"}
        else None
    )
    if not isinstance(rows, list) or len(rows) > 500:
        raise DiscoveryCollectionError("Intune business-unit mapping has an invalid schema")
    result: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"userId", "businessUnit"}:
            raise DiscoveryCollectionError("Intune business-unit mapping row is invalid")
        user_id = row.get("userId")
        business_unit = row.get("businessUnit")
        if (
            not isinstance(user_id, str)
            or _UUID_PATTERN.fullmatch(user_id) is None
            or user_id in result
            or not isinstance(business_unit, str)
            or not business_unit.strip()
            or len(business_unit.strip()) > 128
        ):
            raise DiscoveryCollectionError("Intune business-unit mapping row is invalid")
        result[user_id] = business_unit.strip()
    return result


def collect_intune_devices(
    token: str,
    mapping_path: Path | None = None,
    *,
    get_json: Callable[..., Any] = _get_json,
) -> list[dict[str, Any]]:
    """Collect opaque managed-device and optional user IDs from Intune v1.0."""
    business_units = _intune_business_units(mapping_path)
    url: str | None = (
        "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
        "?$select=id,userId&$top=100"
    )
    observations: list[dict[str, Any]] = []
    seen: set[str] = set()
    for _ in range(_MAX_PROVIDER_PAGES):
        if url is None:
            return observations
        page = get_json(_intune_url(url), token, allowed_host="graph.microsoft.com")
        if not isinstance(page, dict) or set(page) - {
            "value",
            "@odata.nextLink",
            "@odata.context",
        }:
            raise DiscoveryCollectionError("Intune returned an invalid managed-devices page")
        devices = page.get("value")
        if not isinstance(devices, list) or len(devices) > 100:
            raise DiscoveryCollectionError("Intune returned an invalid managed-devices page")
        for device in devices:
            if not isinstance(device, dict) or set(device) - {"id", "userId"}:
                raise DiscoveryCollectionError("Intune device record has an unexpected schema")
            identifier = device.get("id")
            user_id = device.get("userId")
            if (
                not isinstance(identifier, str)
                or _UUID_PATTERN.fullmatch(identifier) is None
                or identifier in seen
                or user_id not in (None, "")
                and (not isinstance(user_id, str) or _UUID_PATTERN.fullmatch(user_id) is None)
            ):
                raise DiscoveryCollectionError("Intune device identity is invalid")
            seen.add(identifier)
            observation: dict[str, Any] = {
                "kind": "device",
                "id": identifier,
                "managed": True,
                "userIds": [user_id] if user_id else [],
            }
            if user_id in business_units:
                observation["businessUnit"] = business_units[user_id]
            observations.append(observation)
        next_url = page.get("@odata.nextLink")
        if next_url is not None and not isinstance(next_url, str):
            raise DiscoveryCollectionError("Intune pagination link is invalid")
        url = next_url
    raise DiscoveryCollectionError("Intune pagination exceeded the 100-page bound")


def _read_json(path: Path, label: str) -> Any:
    """Read one deployment-owned JSON document with a bounded error surface."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DiscoveryCollectionError(f"could not read {label}: {error}") from error


def collect_github_repositories(
    organization: str,
    token: str,
    mapping_path: Path,
    *,
    get_json: Callable[..., Any] = _get_json,
) -> list[dict[str, Any]]:
    """Collect mapped GitHub repositories without inferring local project paths.

    The mapping is keyed by repository full name and supplies an independently
    calculated SHA-256 project-root digest, expected hosts and optional business
    unit. Repositories missing that deployment-owned mapping fail collection.
    """
    mappings = _read_json(mapping_path, "GitHub repository mapping")
    if not isinstance(mappings, dict):
        raise DiscoveryCollectionError("GitHub repository mapping must be an object")
    observations: list[dict[str, Any]] = []
    organization_path = urllib.parse.quote(organization, safe="")
    for page_number in range(1, _MAX_PROVIDER_PAGES + 1):
        url = (
            f"https://api.github.com/orgs/{organization_path}/repos"
            f"?per_page=100&page={page_number}&type=all"
        )
        page = get_json(url, token, allowed_host="api.github.com")
        if not isinstance(page, list):
            raise DiscoveryCollectionError("GitHub returned an invalid repository page")
        for repository in page:
            if not isinstance(repository, dict):
                raise DiscoveryCollectionError("GitHub repository record is invalid")
            repository_id = repository.get("id")
            full_name = repository.get("full_name")
            archived = repository.get("archived")
            if (
                not isinstance(repository_id, int)
                or not isinstance(full_name, str)
                or not isinstance(archived, bool)
            ):
                raise DiscoveryCollectionError("GitHub repository identity is invalid")
            if archived:
                continue
            mapping = mappings.get(full_name)
            if not isinstance(mapping, dict):
                raise DiscoveryCollectionError(f"active repository lacks mapping: {full_name}")
            allowed = {"projectRootDigest", "expectedHosts", "businessUnit"}
            if set(mapping) - allowed:
                raise DiscoveryCollectionError("GitHub repository mapping has unknown fields")
            digest = mapping.get("projectRootDigest")
            hosts = mapping.get("expectedHosts")
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
                or not isinstance(hosts, list)
                or not hosts
                or not set(hosts).issubset(_SUPPORTED_HOSTS)
                or len(hosts) != len(set(hosts))
            ):
                raise DiscoveryCollectionError("GitHub repository mapping is unsafe")
            observation: dict[str, Any] = {
                "kind": "repository",
                "id": str(repository_id),
                "projectRootDigest": digest,
                "expectedHosts": sorted(hosts),
            }
            business_unit = mapping.get("businessUnit")
            if isinstance(business_unit, str) and business_unit.strip():
                observation["businessUnit"] = business_unit.strip()
            observations.append(observation)
        if len(page) < 100:
            return observations
    raise DiscoveryCollectionError("GitHub pagination exceeded the 100-page bound")


def collect_endpoint_export(path: Path) -> list[dict[str, Any]]:
    """Normalize a deployment-owned endpoint export with an exact safe schema."""
    value = _read_json(path, "endpoint export")
    if not isinstance(value, dict) or set(value) != {"devices", "installations"}:
        raise DiscoveryCollectionError("endpoint export must contain devices and installations")
    devices = value["devices"]
    installations = value["installations"]
    if not isinstance(devices, list) or not isinstance(installations, list):
        raise DiscoveryCollectionError("endpoint export collections must be arrays")
    observations: list[dict[str, Any]] = []
    schemas = {
        "device": ({"id", "managed"}, {"id", "managed", "businessUnit", "userIds"}),
        "installation": (
            {"id", "deviceId", "host", "projectRootDigest", "binaryPresent", "processActive"},
            {
                "id",
                "deviceId",
                "host",
                "projectRootDigest",
                "binaryPresent",
                "processActive",
                "userId",
                "repositoryId",
                "businessUnit",
            },
        ),
    }
    for kind, records in (("device", devices), ("installation", installations)):
        required, allowed = schemas[kind]
        for record in records:
            if (
                not isinstance(record, dict)
                or not required.issubset(record)
                or set(record) - allowed
            ):
                raise DiscoveryCollectionError(f"endpoint {kind} record has an invalid schema")
            observations.append({"kind": kind, **record})
    identities = [(item["kind"], item.get("id")) for item in observations]
    if len(identities) != len(set(identities)):
        raise DiscoveryCollectionError("endpoint export contains duplicate identities")
    return observations


def _parser() -> argparse.ArgumentParser:
    """Build explicit source-specific command contracts."""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="source", required=True)
    entra = subparsers.add_parser("entra")
    entra.add_argument("--token-env", default="AZURE_GRAPH_TOKEN")
    intune = subparsers.add_parser("intune")
    intune.add_argument("--mapping", type=Path)
    intune.add_argument("--token-env", default="AZURE_GRAPH_TOKEN")
    github = subparsers.add_parser("github")
    github.add_argument("--organization", required=True)
    github.add_argument("--mapping", required=True, type=Path)
    github.add_argument("--token-env", default="GITHUB_TOKEN")
    endpoint = subparsers.add_parser("endpoint")
    endpoint.add_argument("--input", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Collect one source and write only normalized observations to stdout."""
    arguments = _parser().parse_args(argv)
    try:
        if arguments.source == "entra":
            observations = collect_entra_users(os.environ.get(arguments.token_env, ""))
        elif arguments.source == "intune":
            observations = collect_intune_devices(
                os.environ.get(arguments.token_env, ""), arguments.mapping
            )
        elif arguments.source == "github":
            observations = collect_github_repositories(
                arguments.organization,
                os.environ.get(arguments.token_env, ""),
                arguments.mapping,
            )
        else:
            observations = collect_endpoint_export(arguments.input)
    except DiscoveryCollectionError as error:
        print(f"Discovery collection failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"observations": observations}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
