"""Contract tests for content-minimised reference inventory collectors."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest


def _module() -> Any:
    path = Path(__file__).parents[1] / "scripts/collect_discovery_inventory.py"
    spec = importlib.util.spec_from_file_location("collect_discovery_inventory", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_entra_collector_follows_allowed_pagination_and_minimises_identity() -> None:
    module = _module()
    pages = iter(
        [
            {
                "value": [{"id": "opaque-a", "accountEnabled": True, "department": "Platform"}],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?page=2",
            },
            {"value": [{"id": "opaque-b", "accountEnabled": False, "department": None}]},
        ]
    )
    result = module.collect_entra_users(
        "synthetic-graph-token",  # noqa: S106
        get_json=lambda *_args, **_kwargs: next(pages),
    )
    assert result == [
        {"kind": "identity", "id": "opaque-a", "active": True, "businessUnit": "Platform"},
        {"kind": "identity", "id": "opaque-b", "active": False},
    ]
    assert "mail" not in json.dumps(result)


def test_entra_collector_rejects_unrequested_sensitive_fields() -> None:
    module = _module()
    with pytest.raises(module.DiscoveryCollectionError, match="unexpected schema"):
        module.collect_entra_users(
            "synthetic-graph-token",  # noqa: S106
            get_json=lambda *_args, **_kwargs: {
                "value": [{"id": "opaque-a", "accountEnabled": True, "mail": "x@example.invalid"}]
            },
        )


def test_intune_collector_is_path_bounded_and_content_minimised(tmp_path: Path) -> None:
    module = _module()
    mapping = tmp_path / "mapping.json"
    mapping.write_text(
        json.dumps(
            {
                "userBusinessUnits": [
                    {
                        "userId": "33333333-3333-4333-8333-333333333333",
                        "businessUnit": "Platform",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    pages = iter(
        [
            {
                "value": [
                    {
                        "id": "11111111-1111-4111-8111-111111111111",
                        "userId": "33333333-3333-4333-8333-333333333333",
                    }
                ],
                "@odata.nextLink": (
                    "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
                    "?$select=id,userId&$top=100&$skiptoken=synthetic"
                ),
            },
            {"value": []},
        ]
    )
    result = module.collect_intune_devices(
        "synthetic-graph-token",  # noqa: S106
        mapping,
        get_json=lambda *_args, **_kwargs: next(pages),
    )
    assert result == [
        {
            "kind": "device",
            "id": "11111111-1111-4111-8111-111111111111",
            "managed": True,
            "userIds": ["33333333-3333-4333-8333-333333333333"],
            "businessUnit": "Platform",
        }
    ]
    assert "deviceName" not in json.dumps(result)


def test_intune_collector_rejects_broader_pagination_and_sensitive_fields() -> None:
    module = _module()
    with pytest.raises(module.DiscoveryCollectionError, match="escaped"):
        module.collect_intune_devices(
            "synthetic-graph-token",  # noqa: S106
            get_json=lambda *_args, **_kwargs: {
                "value": [],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$top=100",
            },
        )
    with pytest.raises(module.DiscoveryCollectionError, match="unexpected schema"):
        module.collect_intune_devices(
            "synthetic-graph-token",  # noqa: S106
            get_json=lambda *_args, **_kwargs: {
                "value": [
                    {
                        "id": "11111111-1111-4111-8111-111111111111",
                        "userId": None,
                        "deviceName": "sensitive",
                    }
                ]
            },
        )


def test_github_collector_requires_deployment_owned_project_mapping(tmp_path: Path) -> None:
    module = _module()
    mapping = tmp_path / "mapping.json"
    mapping.write_text("{}", encoding="utf-8")
    with pytest.raises(module.DiscoveryCollectionError, match="lacks mapping"):
        module.collect_github_repositories(
            "synthetic-org",
            "synthetic-github-token",  # noqa: S106
            mapping,
            get_json=lambda *_args, **_kwargs: [
                {"id": 7, "full_name": "synthetic-org/repository-a", "archived": False}
            ],
        )


def test_github_collector_emits_digest_not_raw_path(tmp_path: Path) -> None:
    module = _module()
    mapping = tmp_path / "mapping.json"
    mapping.write_text(
        json.dumps(
            {
                "synthetic-org/repository-a": {
                    "projectRootDigest": "a" * 64,
                    "expectedHosts": ["claude-code", "codex-cli"],
                }
            }
        ),
        encoding="utf-8",
    )
    result = module.collect_github_repositories(
        "synthetic-org",
        "synthetic-github-token",  # noqa: S106
        mapping,
        get_json=lambda *_args, **_kwargs: [
            {"id": 7, "full_name": "synthetic-org/repository-a", "archived": False}
        ],
    )
    assert result == [
        {
            "kind": "repository",
            "id": "7",
            "projectRootDigest": "a" * 64,
            "expectedHosts": ["claude-code", "codex-cli"],
        }
    ]


def test_endpoint_collector_rejects_unknown_content(tmp_path: Path) -> None:
    module = _module()
    export = tmp_path / "endpoint.json"
    export.write_text(
        json.dumps(
            {
                "devices": [{"id": "device-a", "managed": True, "serialNumber": "sensitive"}],
                "installations": [],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(module.DiscoveryCollectionError, match="invalid schema"):
        module.collect_endpoint_export(export)
