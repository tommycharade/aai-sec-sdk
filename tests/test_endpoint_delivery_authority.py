"""Adversarial contracts for immutable endpoint delivery package authority."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from types import ModuleType

import pytest


def _module() -> ModuleType:
    """Load the Lambda module from the production asset directory."""
    path = (
        Path(__file__).resolve().parents[1] / "infra/aws-control-plane/lambda/endpoint_delivery.py"
    )
    specification = importlib.util.spec_from_file_location("aai_endpoint_delivery", path)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _digest(value: bytes) -> str:
    """Return a lowercase synthetic SHA-256 identity."""
    return hashlib.sha256(value).hexdigest()


def _runtime_catalog() -> dict[str, object]:
    """Return one approved synthetic Claude Code runtime release."""
    return {
        "schemaVersion": 1,
        "status": "configured",
        "releases": [
            {
                "id": "claude-code:1.1.0",
                "host": "claude-code",
                "releaseEvidenceSha256": "3" * 64,
            }
        ],
    }


def _package() -> dict[str, object]:
    """Return one closed synthetic delivery manifest."""
    return {
        "schemaVersion": 1,
        "releaseId": "claude-code:1.1.0",
        "host": "claude-code",
        "operatingSystem": "darwin",
        "architecture": "arm64",
        "packageFormat": "pkg",
        "bucketArn": "arn:aws:s3:::synthetic-aai-release-bucket",
        "objectKey": "releases/v1.1.0/aai-sec.pkg",
        "objectVersionId": "synthetic-object-version-1",
        "objectSha256": "0" * 64,
        "providerPackageIdentitySha256": "1" * 64,
        "packageSignatureEvidenceSha256": "2" * 64,
        "releaseEvidenceSha256": "3" * 64,
    }


def _configure(
    monkeypatch: pytest.MonkeyPatch,
    module: ModuleType,
    packages: list[dict[str, object]],
    *,
    approval_transform: Callable[[dict[str, object]], None] | None = None,
) -> None:
    """Install exact synthetic bundle bytes and matching approval authority."""
    package_bytes = (json.dumps(packages, indent=2) + "\n").encode()
    approvals = []
    for package in packages:
        normalized = json.dumps(package, sort_keys=True, separators=(",", ":")).encode()
        manifest_digest = _digest(normalized)
        approvals.append(
            {
                "packageId": f"delivery:{manifest_digest}",
                "manifestSha256": manifest_digest,
                "approvedAt": "2026-08-05",
                "approverEvidenceSha256": "4" * 64,
            }
        )
    approval = {
        "schemaVersion": 1,
        "packageBundleSha256": _digest(package_bytes),
        "approvals": approvals,
    }
    if approval_transform is not None:
        approval_transform(approval)
    approval_bytes = (json.dumps(approval, indent=2) + "\n").encode()
    monkeypatch.setenv("DELIVERY_PACKAGES", package_bytes.decode())
    monkeypatch.setenv("DELIVERY_PACKAGES_SHA256", _digest(package_bytes))
    monkeypatch.setenv("DELIVERY_PACKAGE_APPROVALS", approval_bytes.decode())
    monkeypatch.setenv("DELIVERY_PACKAGE_APPROVALS_SHA256", _digest(approval_bytes))


def test_checked_in_empty_catalog_is_honestly_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    for name in (
        "DELIVERY_PACKAGES",
        "DELIVERY_PACKAGES_SHA256",
        "DELIVERY_PACKAGE_APPROVALS",
        "DELIVERY_PACKAGE_APPROVALS_SHA256",
    ):
        monkeypatch.delenv(name, raising=False)
    authority = module.delivery_package_authority(_runtime_catalog())
    assert authority["entries"] == []
    assert authority["catalog"]["status"] == "not_configured"
    assert authority["catalog"]["packages"] == []


def test_approved_package_projection_omits_locator_and_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    _configure(monkeypatch, module, [_package()])
    authority = module.delivery_package_authority(_runtime_catalog())
    package = authority["catalog"]["packages"][0]
    assert authority["catalog"]["status"] == "configured"
    assert package["releaseId"] == "claude-code:1.1.0"
    assert set(package).isdisjoint(
        {"bucketArn", "objectKey", "objectVersionId", "credential", "command", "url"}
    )
    assert package["storageIdentitySha256"] != package["objectSha256"]


@pytest.mark.parametrize(
    "unsafe_key",
    ["../aai-sec.pkg", "releases/../../aai-sec.pkg", "/aai-sec.pkg", "releases\\aai.pkg"],
)
def test_object_key_traversal_and_platform_paths_fail_closed(
    monkeypatch: pytest.MonkeyPatch, unsafe_key: str
) -> None:
    module = _module()
    package = _package()
    package["objectKey"] = unsafe_key
    _configure(monkeypatch, module, [package])
    with pytest.raises(module.DeliveryPackageError, match="objectKey is unsafe"):
        module.delivery_package_authority(_runtime_catalog())


def test_unknown_manifest_field_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    package = _package()
    package["browserApproved"] = True
    _configure(monkeypatch, module, [package])
    with pytest.raises(module.DeliveryPackageError, match="schema is invalid"):
        module.delivery_package_authority(_runtime_catalog())


def test_unapproved_or_cross_host_release_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    package = _package()
    package["releaseId"] = "codex-cli:1.1.0"
    _configure(monkeypatch, module, [package])
    with pytest.raises(module.DeliveryPackageError, match="release is not approved"):
        module.delivery_package_authority(_runtime_catalog())


def test_mutable_s3_object_version_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    package = _package()
    package["objectVersionId"] = "null"
    _configure(monkeypatch, module, [package])
    with pytest.raises(module.DeliveryPackageError, match="immutable S3 object version"):
        module.delivery_package_authority(_runtime_catalog())


def test_duplicate_platform_authority_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    first = _package()
    second = deepcopy(first)
    second["objectVersionId"] = "synthetic-object-version-2"
    second["objectSha256"] = "5" * 64
    _configure(monkeypatch, module, [first, second])
    with pytest.raises(module.DeliveryPackageError, match="platform authority is ambiguous"):
        module.delivery_package_authority(_runtime_catalog())


def test_multiple_formats_for_same_platform_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Package selection must not depend on bundle order or an inferred package manager."""
    module = _module()
    deb = _package()
    deb.update(
        operatingSystem="linux",
        packageFormat="deb",
        objectKey="releases/v1.1.0/aai-sec.deb",
    )
    rpm = deepcopy(deb)
    rpm.update(
        packageFormat="rpm",
        objectKey="releases/v1.1.0/aai-sec.rpm",
        objectVersionId="synthetic-object-version-2",
        objectSha256="5" * 64,
    )
    _configure(monkeypatch, module, [deb, rpm])
    with pytest.raises(module.DeliveryPackageError, match="platform authority is ambiguous"):
        module.delivery_package_authority(_runtime_catalog())


def test_stale_or_surplus_approval_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()

    def add_surplus(approval: dict[str, object]) -> None:
        approvals = approval["approvals"]
        assert isinstance(approvals, list)
        approvals.append(
            {
                "packageId": f"delivery:{'9' * 64}",
                "manifestSha256": "9" * 64,
                "approvedAt": "2026-08-05",
                "approverEvidenceSha256": "8" * 64,
            }
        )

    _configure(monkeypatch, module, [_package()], approval_transform=add_surplus)
    with pytest.raises(module.DeliveryPackageError, match="do not exactly cover"):
        module.delivery_package_authority(_runtime_catalog())


def test_environment_bundle_integrity_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    _configure(monkeypatch, module, [_package()])
    monkeypatch.setenv("DELIVERY_PACKAGES_SHA256", "f" * 64)
    with pytest.raises(module.DeliveryPackageError, match="deployment integrity failed"):
        module.delivery_package_authority(_runtime_catalog())
