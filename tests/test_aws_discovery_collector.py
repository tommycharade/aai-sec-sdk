"""Security contracts for the AWS-managed discovery collector Lambda."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import types
import urllib.error
from email.message import Message
from pathlib import Path
from typing import Any

import pytest


class FakeCollectorTable:
    """Minimal tenant-scoped DynamoDB double for collector posture tests."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}
        self.updates = 0

    def get_item(self, *, Key: dict[str, str], **_: Any) -> dict[str, Any]:
        item = self.items.get((Key["pk"], Key["sk"]))
        return {} if item is None else {"Item": dict(item)}

    def update_item(
        self,
        *,
        Key: dict[str, str],
        UpdateExpression: str,
        ConditionExpression: str,
        ExpressionAttributeValues: dict[str, Any],
        **_: Any,
    ) -> None:
        referenced_values = set(re.findall(r":[A-Za-z][A-Za-z0-9_]*", UpdateExpression))
        referenced_values.update(re.findall(r":[A-Za-z][A-Za-z0-9_]*", ConditionExpression))
        assert set(ExpressionAttributeValues) == referenced_values
        item = self.items.get((Key["pk"], Key["sk"]))
        if (
            item is None
            or item.get("revision") != ExpressionAttributeValues[":revision"]
            or item.get("status") == "disabled"
        ):
            raise RuntimeError("conditional check failed")
        status = ExpressionAttributeValues[":status"]
        item["status"] = status
        if status == "running":
            item["lastAttemptAt"] = ExpressionAttributeValues[":now"]
        elif status == "healthy":
            item["lastSuccessAt"] = ExpressionAttributeValues[":now"]
            item["consecutiveFailures"] = 0
            item.pop("lastErrorCode", None)
        else:
            item["lastErrorCode"] = ExpressionAttributeValues[":error"]
            item["consecutiveFailures"] = item.get("consecutiveFailures", 0) + 1
        self.updates += 1


class FakeSecrets:
    """Secrets Manager double that counts reads without logging values."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.reads: list[str] = []

    def get_secret_value(self, *, SecretId: str, VersionStage: str) -> dict[str, str]:
        assert VersionStage == "AWSCURRENT"
        self.reads.append(SecretId)
        if SecretId not in self.values:
            raise RuntimeError("secret not found")
        return {"SecretString": self.values[SecretId]}


def _load_collector(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, FakeCollectorTable, FakeSecrets]:
    """Load the deployable module with deterministic AWS service doubles."""
    table = FakeCollectorTable()
    secrets = FakeSecrets()
    fake_boto3 = types.ModuleType("boto3")
    fake_boto3.resource = lambda service: types.SimpleNamespace(  # type: ignore[attr-defined]
        Table=lambda name: table
    )
    fake_boto3.client = lambda service: secrets  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    monkeypatch.setenv("CONTROL_TABLE", "synthetic-control-table")
    monkeypatch.setenv("CONTROL_PLANE_API_URL", "https://api.example.invalid")
    path = (
        Path(__file__).parents[1]
        / "infra"
        / "aws-control-plane"
        / "lambda"
        / "discovery_collector.py"
    )
    spec = importlib.util.spec_from_file_location("aai_discovery_collector", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, table, secrets


def _configuration(module: Any, **changes: Any) -> dict[str, Any]:
    """Build one digest-bound synthetic scheduler event."""
    value = {
        "schemaVersion": 1,
        "tenantId": "tenant-synthetic",
        "sourceId": "entra-production",
        "provider": "entra",
        "providerSecretArn": (
            "arn:aws:secretsmanager:eu-west-2:123456789012:secret:"
            "aai-sec/discovery/providers/tenant-synthetic/entra-AbCdEf"
        ),
        "connectorSecretArn": (
            "arn:aws:secretsmanager:eu-west-2:123456789012:secret:"
            "aai-sec/discovery/connectors/a/b-AbCdEf"
        ),
        "providerConfigurationDigest": module._canonical_digest({}),
        "jobRevision": 1,
        "validitySeconds": 1_800,
        **changes,
    }
    value["configurationDigest"] = module._canonical_digest(value)
    return value


def _install_job(table: FakeCollectorTable, configuration: dict[str, Any]) -> None:
    """Store the exact live job against which schedule input is checked."""
    table.items[
        (
            f"TENANT#{configuration['tenantId']}",
            f"DISCOVERY_JOB#{configuration['sourceId']}",
        )
    ] = {
        "revision": configuration["jobRevision"],
        "status": "scheduled",
        "provider": configuration["provider"],
        "providerSecretArn": configuration["providerSecretArn"],
        "connectorSecretArn": configuration["connectorSecretArn"],
        "configurationDigest": configuration["configurationDigest"],
        "providerConfigurationDigest": configuration["providerConfigurationDigest"],
        "consecutiveFailures": 0,
    }


def test_managed_collector_publishes_and_records_healthy_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A live digest-bound job reads both secrets and publishes one generation."""
    module, table, secrets = _load_collector(monkeypatch)
    configuration = _configuration(module)
    _install_job(table, configuration)
    secrets.values[configuration["providerSecretArn"]] = json.dumps(
        {
            "tenantId": "11111111-1111-4111-8111-111111111111",
            "clientId": "22222222-2222-4222-8222-222222222222",
            "clientSecret": "synthetic-client-secret",
        }
    )
    secrets.values[configuration["connectorSecretArn"]] = json.dumps(
        {"token": "synthetic-connector-token"}
    )
    monkeypatch.setattr(module, "_entra_access_token", lambda credentials: "ephemeral-token")
    monkeypatch.setattr(
        module,
        "_collect_entra_users",
        lambda token: [{"kind": "identity", "id": "user-a", "active": True}],
    )
    published: list[tuple[str, list[dict[str, Any]]]] = []

    def publish(
        config: dict[str, Any], token: str, observations: list[dict[str, Any]], *, now: int
    ) -> dict[str, Any]:
        published.append((token, observations))
        return {"generation": "entra-synthetic", "revision": 1, "observationCount": 1}

    monkeypatch.setattr(module, "_publish", publish)
    monkeypatch.setattr(module.time, "time", lambda: 1_785_000_000)

    result = module.handler(configuration, None)

    job = table.items[("TENANT#tenant-synthetic", "DISCOVERY_JOB#entra-production")]
    assert result == {
        "status": "healthy",
        "generation": "entra-synthetic",
        "revision": 1,
        "observationCount": 1,
    }
    assert secrets.reads == [
        configuration["providerSecretArn"],
        configuration["connectorSecretArn"],
    ]
    assert published == [
        (
            "synthetic-connector-token",
            [{"kind": "identity", "id": "user-a", "active": True}],
        )
    ]
    assert job["status"] == "healthy"
    assert job["lastAttemptAt"] == 1_785_000_000
    assert job["lastSuccessAt"] == 1_785_000_000
    assert job["consecutiveFailures"] == 0


def test_managed_github_collector_uses_digest_bound_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GitHub collection receives only the live, digest-bound repository map."""
    module, table, secrets = _load_collector(monkeypatch)
    provider_configuration = {
        "organization": "example-enterprise",
        "repositories": [
            {
                "fullName": "example-enterprise/.github",
                "projectRootDigest": "a" * 64,
                "expectedHosts": ["claude-code", "codex-cli"],
                "businessUnit": "Platform",
            }
        ],
    }
    configuration = _configuration(
        module,
        sourceId="github-production",
        provider="github",
        providerSecretArn=(
            "arn:aws:secretsmanager:eu-west-2:123456789012:secret:"
            "aai-sec/discovery/providers/tenant-synthetic/github-AbCdEf"
        ),
        providerConfigurationDigest=module._canonical_digest(provider_configuration),
    )
    _install_job(table, configuration)
    job_key = ("TENANT#tenant-synthetic", "DISCOVERY_JOB#github-production")
    table.items[job_key]["providerConfiguration"] = provider_configuration
    secrets.values[configuration["providerSecretArn"]] = json.dumps(
        {"token": "synthetic-github-token-value"}
    )
    secrets.values[configuration["connectorSecretArn"]] = json.dumps(
        {"token": "synthetic-connector-token"}
    )
    collected: list[tuple[str, dict[str, Any]]] = []

    def collect_github(token: str, value: dict[str, Any]) -> list[dict[str, Any]]:
        collected.append((token, value))
        return [
            {
                "kind": "repository",
                "id": "101",
                "projectRootDigest": "a" * 64,
                "expectedHosts": ["claude-code", "codex-cli"],
            }
        ]

    monkeypatch.setattr(
        module,
        "_collect_github_repositories",
        collect_github,
    )
    monkeypatch.setattr(
        module,
        "_publish",
        lambda *args, **kwargs: {
            "generation": "github-synthetic",
            "revision": 1,
            "observationCount": 1,
        },
    )

    result = module.handler(configuration, None)

    assert result["status"] == "healthy"
    assert collected == [
        (
            "synthetic-github-token-value",
            {
                "organization": "example-enterprise",
                "repositories": {
                    "example-enterprise/.github": {
                        "projectRootDigest": "a" * 64,
                        "expectedHosts": ["claude-code", "codex-cli"],
                        "businessUnit": "Platform",
                    }
                },
            },
        )
    ]
    assert secrets.reads == [
        configuration["providerSecretArn"],
        configuration["connectorSecretArn"],
    ]


def test_managed_intune_collector_publishes_only_minimised_device_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Intune collection cannot invent binary, process, or project evidence."""
    module, table, secrets = _load_collector(monkeypatch)
    user_id = "33333333-3333-4333-8333-333333333333"
    provider_configuration = {
        "userBusinessUnits": [{"userId": user_id, "businessUnit": "Platform"}]
    }
    configuration = _configuration(
        module,
        sourceId="intune-production",
        provider="intune",
        providerSecretArn=(
            "arn:aws:secretsmanager:eu-west-2:123456789012:secret:"
            "aai-sec/discovery/providers/tenant-synthetic/intune-AbCdEf"
        ),
        providerConfigurationDigest=module._canonical_digest(provider_configuration),
    )
    _install_job(table, configuration)
    job_key = ("TENANT#tenant-synthetic", "DISCOVERY_JOB#intune-production")
    table.items[job_key]["providerConfiguration"] = provider_configuration
    secrets.values[configuration["providerSecretArn"]] = json.dumps(
        {
            "tenantId": "11111111-1111-4111-8111-111111111111",
            "clientId": "22222222-2222-4222-8222-222222222222",
            "clientSecret": "synthetic-client-secret",
        }
    )
    secrets.values[configuration["connectorSecretArn"]] = json.dumps(
        {"token": "synthetic-connector-token"}
    )
    monkeypatch.setattr(module, "_entra_access_token", lambda credentials: "ephemeral-token")
    monkeypatch.setattr(
        module,
        "_open_json",
        lambda *args, **kwargs: {
            "@odata.context": (
                "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/"
                "managedDevices(id,userId,azureADDeviceId)"
            ),
            "value": [
                {
                    "id": "44444444-4444-4444-8444-444444444444",
                    "userId": user_id,
                    "azureADDeviceId": "55555555-5555-4555-8555-555555555555",
                }
            ],
        },
    )
    published: list[list[dict[str, Any]]] = []

    def publish(
        config: dict[str, Any], token: str, observations: list[dict[str, Any]], *, now: int
    ) -> dict[str, Any]:
        published.append(observations)
        return {"generation": "intune-synthetic", "revision": 1, "observationCount": 1}

    monkeypatch.setattr(module, "_publish", publish)

    result = module.handler(configuration, None)

    assert result["status"] == "healthy"
    assert published == [
        [
            {
                "kind": "device",
                "id": "44444444-4444-4444-8444-444444444444",
                "managed": True,
                "directoryDeviceRegistrationId": ("55555555-5555-4555-8555-555555555555"),
                "userIds": [user_id],
                "businessUnit": "Platform",
            }
        ]
    ]
    serialized = json.dumps(published)
    for forbidden in ("binaryPresent", "processActive", "projectRootDigest", "deviceName"):
        assert forbidden not in serialized


def test_intune_pagination_and_provider_fields_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Intune follows only the exact Graph collection and rejects excess data."""
    module, _, _ = _load_collector(monkeypatch)
    invalid_next = (
        "https://graph.microsoft.com/v1.0/users?$select=id,userId&$top=100&$skiptoken=opaque"
    )
    monkeypatch.setattr(
        module,
        "_open_json",
        lambda *args, **kwargs: {"value": [], "@odata.nextLink": invalid_next},
    )
    with pytest.raises(module.ManagedDiscoveryError) as escaped:
        module._collect_intune_devices("synthetic-token", {})
    assert escaped.value.code == "provider_response_invalid"

    monkeypatch.setattr(
        module,
        "_open_json",
        lambda *args, **kwargs: {
            "value": [
                {
                    "id": "44444444-4444-4444-8444-444444444444",
                    "userId": None,
                    "azureADDeviceId": "55555555-5555-4555-8555-555555555555",
                    "deviceName": "must-not-be-accepted",
                }
            ]
        },
    )
    with pytest.raises(module.ManagedDiscoveryError) as overbroad:
        module._collect_intune_devices("synthetic-token", {})
    assert overbroad.value.code == "provider_response_invalid"

    monkeypatch.setattr(
        module,
        "_open_json",
        lambda *args, **kwargs: {
            "value": [
                {
                    "id": "44444444-4444-4444-8444-444444444444",
                    "userId": None,
                    "azureADDeviceId": "not-a-directory-registration-id",
                }
            ]
        },
    )
    with pytest.raises(module.ManagedDiscoveryError) as malformed_identity:
        module._collect_intune_devices("synthetic-token", {})
    assert malformed_identity.value.code == "provider_response_invalid"


def test_intune_configuration_tamper_fails_before_secret_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale attribution digest cannot cause provider or connector secret reads."""
    module, table, secrets = _load_collector(monkeypatch)
    provider_configuration: dict[str, Any] = {"userBusinessUnits": []}
    configuration = _configuration(
        module,
        sourceId="intune-production",
        provider="intune",
        providerConfigurationDigest=module._canonical_digest(provider_configuration),
    )
    _install_job(table, configuration)
    table.items[("TENANT#tenant-synthetic", "DISCOVERY_JOB#intune-production")][
        "providerConfiguration"
    ] = {
        "userBusinessUnits": [
            {
                "userId": "33333333-3333-4333-8333-333333333333",
                "businessUnit": "Tampered",
            }
        ]
    }
    secrets.values[configuration["providerSecretArn"]] = "{}"

    with pytest.raises(RuntimeError, match="configuration_invalid"):
        module.handler(configuration, None)

    assert secrets.reads == []


def test_github_collection_is_bounded_and_requires_complete_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unmapped or token-hidden repositories never publish a partial denominator."""
    module, _, _ = _load_collector(monkeypatch)
    configured = {
        "organization": "example-enterprise",
        "repositories": {
            "example-enterprise/repository-a": {
                "projectRootDigest": "b" * 64,
                "expectedHosts": ["claude-code"],
            }
        },
    }
    requests: list[Any] = []

    def unmapped(request: Any, **_: Any) -> list[dict[str, Any]]:
        requests.append(request)
        return [{"id": 101, "full_name": "example-enterprise/repository-b", "archived": False}]

    monkeypatch.setattr(module, "_open_json", unmapped)
    with pytest.raises(module.ManagedDiscoveryError) as caught:
        module._collect_github_repositories("synthetic-github-token-value", configured)
    assert caught.value.code == "provider_mapping_incomplete"
    assert requests[0].full_url == (
        "https://api.github.com/orgs/example-enterprise/repos"
        "?per_page=100&page=1&type=all&sort=full_name&direction=asc"
    )
    assert requests[0].headers["Authorization"] == "Bearer synthetic-github-token-value"
    assert requests[0].headers["X-github-api-version"] == "2022-11-28"

    monkeypatch.setattr(module, "_open_json", lambda *args, **kwargs: [])
    with pytest.raises(module.ManagedDiscoveryError) as hidden:
        module._collect_github_repositories("synthetic-github-token-value", configured)
    assert hidden.value.code == "provider_mapping_incomplete"


def test_github_collection_minimises_provider_records_and_ignores_archived_unmapped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only mapped active repository identity and correlation fields are retained."""
    module, _, _ = _load_collector(monkeypatch)
    configured = {
        "organization": "example-enterprise",
        "repositories": {
            "example-enterprise/.github": {
                "projectRootDigest": "c" * 64,
                "expectedHosts": ["codex-cli"],
                "businessUnit": "Security",
            }
        },
    }
    monkeypatch.setattr(
        module,
        "_open_json",
        lambda *args, **kwargs: [
            {
                "id": 201,
                "full_name": "Example-Enterprise/.GitHub",
                "archived": False,
                "private": True,
                "description": "must not persist",
            },
            {
                "id": 202,
                "full_name": "example-enterprise/retired",
                "archived": True,
            },
        ],
    )

    assert module._collect_github_repositories("synthetic-github-token-value", configured) == [
        {
            "kind": "repository",
            "id": "201",
            "projectRootDigest": "c" * 64,
            "expectedHosts": ["codex-cli"],
            "businessUnit": "Security",
        }
    ]


def test_github_configuration_tamper_fails_before_provider_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A job mapping changed without its digest cannot reach GitHub."""
    module, table, secrets = _load_collector(monkeypatch)
    provider_configuration = {
        "organization": "example-enterprise",
        "repositories": [
            {
                "fullName": "example-enterprise/repository-a",
                "projectRootDigest": "d" * 64,
                "expectedHosts": ["claude-code"],
            }
        ],
    }
    configuration = _configuration(
        module,
        sourceId="github-production",
        provider="github",
        providerConfigurationDigest=module._canonical_digest(provider_configuration),
    )
    _install_job(table, configuration)
    table.items[("TENANT#tenant-synthetic", "DISCOVERY_JOB#github-production")][
        "providerConfiguration"
    ] = provider_configuration | {"organization": "tampered-enterprise"}

    with pytest.raises(RuntimeError, match="configuration_invalid"):
        module.handler(configuration, None)

    assert secrets.reads == []


@pytest.mark.parametrize("token", ["short", "synthetic token with spaces", "x" * 513])
def test_github_collection_rejects_unsafe_token_before_network(
    monkeypatch: pytest.MonkeyPatch, token: str
) -> None:
    """Malformed provider credentials never enter an authorization header."""
    module, _, _ = _load_collector(monkeypatch)
    requested = False

    def open_json(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal requested
        requested = True
        return []

    monkeypatch.setattr(module, "_open_json", open_json)
    with pytest.raises(module.ManagedDiscoveryError) as caught:
        module._collect_github_repositories(
            token,
            {"organization": "example-enterprise", "repositories": {}},
        )
    assert caught.value.code == "provider_secret_unavailable"
    assert requested is False


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value | {"provider": "arbitrary"},
        lambda value: value | {"unknown": True},
        lambda value: value | {"tenantId": "../tenant"},
        lambda value: value | {"validitySeconds": 86_401},
        lambda value: value | {"configurationDigest": "0" * 64},
    ],
)
def test_managed_collector_rejects_forged_schedule_before_secret_access(
    monkeypatch: pytest.MonkeyPatch, mutation: Any
) -> None:
    """Malformed and digest-forged scheduler input never reaches a secret."""
    module, table, secrets = _load_collector(monkeypatch)
    configuration = mutation(_configuration(module))

    with pytest.raises(RuntimeError, match="configuration_invalid"):
        module.handler(configuration, None)

    assert secrets.reads == []
    assert table.updates == 0


def test_managed_collector_rejects_stale_job_before_secret_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A replaced schedule revision cannot reuse current provider authority."""
    module, table, secrets = _load_collector(monkeypatch)
    configuration = _configuration(module)
    _install_job(table, configuration)
    table.items[("TENANT#tenant-synthetic", "DISCOVERY_JOB#entra-production")]["revision"] = 2

    with pytest.raises(RuntimeError, match="configuration_invalid"):
        module.handler(configuration, None)

    assert secrets.reads == []
    assert table.updates == 0


def test_managed_collector_records_content_free_secret_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Provider-secret failure degrades health without leaking an ARN or value."""
    module, table, _ = _load_collector(monkeypatch)
    configuration = _configuration(module)
    _install_job(table, configuration)

    with pytest.raises(RuntimeError, match="provider_secret_unavailable"):
        module.handler(configuration, None)

    output = capsys.readouterr().out
    job = table.items[("TENANT#tenant-synthetic", "DISCOVERY_JOB#entra-production")]
    assert json.loads(output) == {
        "event": "managed_discovery_failed",
        "code": "provider_secret_unavailable",
    }
    assert configuration["providerSecretArn"] not in output
    assert job["status"] == "degraded"
    assert job["lastErrorCode"] == "provider_secret_unavailable"
    assert job["consecutiveFailures"] == 1


def test_entra_exchange_uses_exact_tenant_endpoint_and_minimum_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Token renewal cannot select a caller-controlled host, path, or scope."""
    module, _, _ = _load_collector(monkeypatch)
    requests: list[Any] = []

    def open_json(request: Any, *, error_code: str) -> dict[str, str]:
        requests.append(request)
        assert error_code == "provider_response_invalid"
        return {"access_token": "ephemeral-access", "token_type": "Bearer"}

    monkeypatch.setattr(module, "_open_json", open_json)
    token = module._entra_access_token(
        {
            "tenantId": "11111111-1111-4111-8111-111111111111",
            "clientId": "22222222-2222-4222-8222-222222222222",
            "clientSecret": "synthetic-secret",
        }
    )

    body = urllib_parse(requests[0].data)
    assert token == "ephemeral-access"  # noqa: S105 - synthetic test value
    assert requests[0].full_url == (
        "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/oauth2/v2.0/token"
    )
    assert body == {
        "client_id": ["22222222-2222-4222-8222-222222222222"],
        "client_secret": ["synthetic-secret"],
        "grant_type": ["client_credentials"],
        "scope": ["https://graph.microsoft.com/.default"],
    }


def urllib_parse(value: bytes) -> dict[str, list[str]]:
    """Decode one form body for endpoint-contract assertions."""
    import urllib.parse

    return urllib.parse.parse_qs(value.decode())


def test_entra_pagination_rejects_egress_or_filter_manipulation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provider continuation links cannot redirect token-bearing requests."""
    module, _, _ = _load_collector(monkeypatch)
    responses = [
        {
            "value": [{"id": "user-a", "accountEnabled": True}],
            "@odata.nextLink": "https://evil.example.test/v1.0/users?$select=id,accountEnabled,department&$top=100",
        }
    ]
    monkeypatch.setattr(module, "_open_json", lambda request, **kwargs: responses.pop(0))

    with pytest.raises(module.ManagedDiscoveryError) as caught:
        module._collect_entra_users("ephemeral-token")

    assert caught.value.code == "provider_response_invalid"

    with pytest.raises(module.ManagedDiscoveryError) as filtered:
        module._validated_graph_url(
            "https://graph.microsoft.com/v1.0/users"
            "?$select=id,accountEnabled,department&$top=100&$filter=accountEnabled"
        )
    assert filtered.value.code == "provider_response_invalid"


def test_atomic_publisher_uses_live_revision_and_hash_bound_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Managed publication retains the existing three-phase visibility boundary."""
    module, table, _ = _load_collector(monkeypatch)
    configuration = _configuration(module)
    table.items[("TENANT#tenant-synthetic", "DISCOVERY_SOURCE#entra-production")] = {"revision": 7}
    calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(url: str, method: str, token: str, body: dict[str, Any]) -> dict[str, Any]:
        calls.append((url, method, body))
        if method == "PUT":
            return {"pageHash": f"{len(calls):064x}"}
        if url.endswith("/commit"):
            return {"revision": 8}
        return {"status": "uploading"}

    monkeypatch.setattr(module, "_ingestion_request", request)
    monkeypatch.setattr(module.uuid, "uuid4", lambda: types.SimpleNamespace(hex="a" * 32))
    observations = [
        {"kind": "identity", "id": f"user-{index}", "active": True} for index in range(1_001)
    ]

    result = module._publish(configuration, "connector-token", observations, now=1_785_000_000)

    assert result["revision"] == 8
    assert [method for _, method, _ in calls] == ["POST", "PUT", "PUT", "POST"]
    assert calls[0][2]["pageCount"] == 2
    assert len(calls[1][2]["observations"]) == 1_000
    assert len(calls[2][2]["observations"]) == 1
    assert calls[0][2]["expectedRevision"] == 7
    assert calls[0][2]["pageCount"] == 2
    assert calls[-1][2]["pageHashes"] == [f"{2:064x}", f"{3:064x}"]


def test_provider_http_authentication_error_is_content_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTTP response bodies never become exception text or job reason codes."""
    module, _, _ = _load_collector(monkeypatch)

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise urllib.error.HTTPError(
            "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
            401,
            "synthetic secret detail",
            Message(),
            None,
        )

    monkeypatch.setattr(module, "_urlopen", fail)
    request = module.urllib.request.Request("https://login.microsoftonline.com/tenant")
    with pytest.raises(module.ManagedDiscoveryError) as caught:
        module._open_json(request, error_code="provider_response_invalid")
    assert caught.value.code == "provider_authentication_failed"
    assert "synthetic secret detail" not in str(caught.value)


def test_provider_redirect_is_rejected_without_constructing_a_follow_up_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OAuth and Graph authorization cannot be redirected to another origin."""
    module, _, _ = _load_collector(monkeypatch)
    handler = module._RejectRedirect()
    request = module.urllib.request.Request(
        "https://graph.microsoft.com/v1.0/users",
        headers={"Authorization": "Bearer synthetic-token"},
    )
    assert (
        handler.redirect_request(
            request,
            None,
            302,
            "redirect",
            {},
            "https://attacker.example.invalid/collect",
        )
        is None
    )


def test_ingestion_uses_redirect_safe_opener_and_exact_json_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Publication uses one redirect-safe request with no implicit data argument."""
    module, _, _ = _load_collector(monkeypatch)
    requests: list[Any] = []

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return b'{"status":"uploading"}'

    def open_request(request: Any) -> Response:
        requests.append(request)
        return Response()

    monkeypatch.setattr(module, "_urlopen", open_request)
    result = module._ingestion_request(
        "https://control.example.invalid/discovery-ingest/tenant/source/generations",
        "POST",
        "synthetic-connector-token",
        {"generation": "synthetic-generation"},
    )
    assert result == {"status": "uploading"}
    assert len(requests) == 1
    assert requests[0].method == "POST"
    assert json.loads(requests[0].data) == {"generation": "synthetic-generation"}
