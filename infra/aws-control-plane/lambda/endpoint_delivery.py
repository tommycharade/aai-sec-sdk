"""Validate immutable endpoint delivery packages without exposing object locators."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from pathlib import Path, PurePosixPath
from typing import Any

_PACKAGE_FIELDS = {
    "schemaVersion",
    "releaseId",
    "host",
    "operatingSystem",
    "architecture",
    "packageFormat",
    "bucketArn",
    "objectKey",
    "objectVersionId",
    "objectSha256",
    "providerPackageIdentitySha256",
    "packageSignatureEvidenceSha256",
    "releaseEvidenceSha256",
}
_APPROVAL_FIELDS = {
    "packageId",
    "manifestSha256",
    "approvedAt",
    "approverEvidenceSha256",
}
_PLATFORM_FORMATS = {
    "darwin": frozenset({"pkg"}),
    "linux": frozenset({"deb", "rpm"}),
    "windows": frozenset({"msi", "msix"}),
}
_ARCHITECTURES = frozenset({"arm64", "x86_64"})
_HOSTS = frozenset({"claude-code", "codex-cli"})
_MAX_PACKAGES = 64
_MAX_BUNDLE_BYTES = 131_072


class DeliveryPackageError(ValueError):
    """Raised when package authority is incomplete, ambiguous, or misleading."""


def _sha256(contents: bytes) -> str:
    """Return one lowercase SHA-256 identity."""
    return hashlib.sha256(contents).hexdigest()


def _digest(value: Any, label: str) -> str:
    """Require one exact lowercase SHA-256 value."""
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise DeliveryPackageError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _text(value: Any, label: str, maximum: int) -> str:
    """Return bounded printable text without control characters."""
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise DeliveryPackageError(f"{label} is invalid")
    return value


def _object_key(value: Any) -> str:
    """Validate a bounded relative S3 object key without traversal semantics."""
    key = _text(value, "objectKey", 512)
    path = PurePosixPath(key)
    if key.startswith(("/", "\\")) or "\\" in key or ".." in path.parts or key.endswith("/"):
        raise DeliveryPackageError("objectKey is unsafe")
    return key


def _canonical_manifest(value: dict[str, Any]) -> bytes:
    """Encode a normalized manifest for stable package and approval binding."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _load_bundle(environment_name: str, filename: str) -> bytes:
    """Load a bounded deployment bundle from an exact environment value or file."""
    configured = os.environ.get(environment_name)
    contents = (
        configured.encode()
        if configured is not None
        else Path(__file__).with_name(filename).read_bytes()
    )
    if len(contents) > _MAX_BUNDLE_BYTES:
        raise DeliveryPackageError(f"{filename} exceeds the safe bound")
    expected = os.environ.get(f"{environment_name}_SHA256", "")
    if expected and not secrets.compare_digest(_sha256(contents), expected):
        raise DeliveryPackageError(f"{filename} deployment integrity failed")
    return contents


def _runtime_releases(runtime_catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index the exact approved runtime releases required by delivery packages."""
    releases = runtime_catalog.get("releases") if isinstance(runtime_catalog, dict) else None
    if not isinstance(releases, list):
        raise DeliveryPackageError("runtime release authority is malformed")
    result: dict[str, dict[str, Any]] = {}
    for release in releases:
        if not isinstance(release, dict) or not isinstance(release.get("id"), str):
            raise DeliveryPackageError("runtime release authority is malformed")
        if release["id"] in result:
            raise DeliveryPackageError("runtime release authority is ambiguous")
        result[release["id"]] = release
    return result


def _package(value: Any, runtime_releases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Normalize one package and bind it to one exact approved runtime release."""
    if not isinstance(value, dict) or set(value) != _PACKAGE_FIELDS:
        raise DeliveryPackageError("delivery package schema is invalid")
    if value.get("schemaVersion") != 1:
        raise DeliveryPackageError("delivery package schema version is unsupported")
    release_id = _text(value.get("releaseId"), "releaseId", 128)
    release = runtime_releases.get(release_id)
    if release is None:
        raise DeliveryPackageError("delivery package release is not approved")
    host = value.get("host")
    if host not in _HOSTS or release.get("host") != host:
        raise DeliveryPackageError("delivery package host does not match its release")
    operating_system = value.get("operatingSystem")
    package_format = value.get("packageFormat")
    if (
        operating_system not in _PLATFORM_FORMATS
        or package_format not in _PLATFORM_FORMATS[operating_system]
    ):
        raise DeliveryPackageError("delivery package format is unsupported for its platform")
    architecture = value.get("architecture")
    if architecture not in _ARCHITECTURES:
        raise DeliveryPackageError("delivery package architecture is unsupported")
    bucket_arn = _text(value.get("bucketArn"), "bucketArn", 256)
    if (
        re.fullmatch(r"arn:(?:aws|aws-us-gov):s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket_arn)
        is None
    ):
        raise DeliveryPackageError("bucketArn must identify one S3 bucket")
    object_version = _text(value.get("objectVersionId"), "objectVersionId", 256)
    if object_version == "null":
        raise DeliveryPackageError("objectVersionId must be an immutable S3 object version")
    release_evidence = _digest(value.get("releaseEvidenceSha256"), "releaseEvidenceSha256")
    if release.get("releaseEvidenceSha256") != release_evidence:
        raise DeliveryPackageError("delivery package release evidence does not match its release")
    normalized = {
        "schemaVersion": 1,
        "releaseId": release_id,
        "host": host,
        "operatingSystem": operating_system,
        "architecture": architecture,
        "packageFormat": package_format,
        "bucketArn": bucket_arn,
        "objectKey": _object_key(value.get("objectKey")),
        "objectVersionId": object_version,
        "objectSha256": _digest(value.get("objectSha256"), "objectSha256"),
        "providerPackageIdentitySha256": _digest(
            value.get("providerPackageIdentitySha256"), "providerPackageIdentitySha256"
        ),
        "packageSignatureEvidenceSha256": _digest(
            value.get("packageSignatureEvidenceSha256"),
            "packageSignatureEvidenceSha256",
        ),
        "releaseEvidenceSha256": release_evidence,
    }
    manifest_sha256 = _sha256(_canonical_manifest(normalized))
    return {
        **normalized,
        "id": f"delivery:{manifest_sha256}",
        "manifestSha256": manifest_sha256,
    }


def delivery_package_authority(runtime_catalog: dict[str, Any]) -> dict[str, Any]:
    """Return validated private package records and a locator-free public catalog.

    The caller must never serialize ``entries`` directly. It contains the exact
    S3 locator needed only by a future IAM-authenticated provider worker.
    """
    package_bytes = _load_bundle("DELIVERY_PACKAGES", "delivery-packages.json")
    approval_bytes = _load_bundle("DELIVERY_PACKAGE_APPROVALS", "delivery-packages.approvals.json")
    try:
        package_values = json.loads(package_bytes)
        approval_bundle = json.loads(approval_bytes)
    except json.JSONDecodeError as error:
        raise DeliveryPackageError("delivery package authority is malformed JSON") from error
    if not isinstance(package_values, list) or len(package_values) > _MAX_PACKAGES:
        raise DeliveryPackageError("delivery package bundle must contain at most 64 entries")
    releases = _runtime_releases(runtime_catalog)
    entries = [_package(value, releases) for value in package_values]
    platform_keys = [
        (
            entry["releaseId"],
            entry["operatingSystem"],
            entry["architecture"],
        )
        for entry in entries
    ]
    if len(platform_keys) != len(set(platform_keys)) or len(
        {entry["id"] for entry in entries}
    ) != len(entries):
        raise DeliveryPackageError("delivery package platform authority is ambiguous")

    if (
        not isinstance(approval_bundle, dict)
        or set(approval_bundle) != {"schemaVersion", "packageBundleSha256", "approvals"}
        or approval_bundle.get("schemaVersion") != 1
        or approval_bundle.get("packageBundleSha256") != _sha256(package_bytes)
        or not isinstance(approval_bundle.get("approvals"), list)
        or len(approval_bundle["approvals"]) > _MAX_PACKAGES
    ):
        raise DeliveryPackageError("delivery package approval bundle is invalid or stale")
    approvals: dict[str, dict[str, Any]] = {}
    for value in approval_bundle["approvals"]:
        if not isinstance(value, dict) or set(value) != _APPROVAL_FIELDS:
            raise DeliveryPackageError("delivery package approval schema is invalid")
        package_id = _text(value.get("packageId"), "packageId", 80)
        if package_id in approvals:
            raise DeliveryPackageError("delivery package approval identity is ambiguous")
        approved_at = value.get("approvedAt")
        if (
            not isinstance(approved_at, str)
            or re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", approved_at) is None
        ):
            raise DeliveryPackageError("delivery package approval date is invalid")
        approvals[package_id] = {
            "manifestSha256": _digest(value.get("manifestSha256"), "manifestSha256"),
            "approvedAt": approved_at,
            "approverEvidenceSha256": _digest(
                value.get("approverEvidenceSha256"), "approverEvidenceSha256"
            ),
        }
    if set(approvals) != {entry["id"] for entry in entries}:
        raise DeliveryPackageError("delivery package approvals do not exactly cover the bundle")

    public_packages = []
    for entry in sorted(
        entries,
        key=lambda item: (
            item["host"],
            item["releaseId"],
            item["operatingSystem"],
            item["architecture"],
        ),
    ):
        approval = approvals[entry["id"]]
        if approval["manifestSha256"] != entry["manifestSha256"]:
            raise DeliveryPackageError("delivery package approval does not match its manifest")
        storage_identity = _sha256(
            json.dumps(
                {
                    "bucketArn": entry["bucketArn"],
                    "objectKey": entry["objectKey"],
                    "objectVersionId": entry["objectVersionId"],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )
        public_packages.append(
            {
                "id": entry["id"],
                "releaseId": entry["releaseId"],
                "host": entry["host"],
                "operatingSystem": entry["operatingSystem"],
                "architecture": entry["architecture"],
                "packageFormat": entry["packageFormat"],
                "manifestSha256": entry["manifestSha256"],
                "objectSha256": entry["objectSha256"],
                "storageIdentitySha256": storage_identity,
                "providerPackageIdentitySha256": entry["providerPackageIdentitySha256"],
                "packageSignatureEvidenceSha256": entry["packageSignatureEvidenceSha256"],
                "releaseEvidenceSha256": entry["releaseEvidenceSha256"],
                "approvedAt": approval["approvedAt"],
                "approverEvidenceSha256": approval["approverEvidenceSha256"],
            }
        )
    return {
        "entries": entries,
        "catalog": {
            "schemaVersion": 1,
            "status": "configured" if public_packages else "not_configured",
            "packageBundleSha256": _sha256(package_bytes),
            "approvalBundleSha256": _sha256(approval_bytes),
            "packages": public_packages,
        },
    }
