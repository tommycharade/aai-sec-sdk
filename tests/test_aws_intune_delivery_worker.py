"""Security contract tests for the isolated Microsoft Intune delivery worker."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest


class _Client:
    """Minimal AWS client whose unexpected use fails a test."""

    def __getattr__(self, name: str) -> Any:
        """Reject every unconfigured AWS operation."""
        raise AssertionError(f"unexpected AWS operation: {name}")


@pytest.fixture
def worker(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the worker without importing the real AWS runtime."""
    table = _Client()
    secrets = _Client()
    s3 = _Client()
    sqs = _Client()
    boto3 = types.ModuleType("boto3")
    boto3.resource = lambda _name: types.SimpleNamespace(Table=lambda _table: table)  # type: ignore[attr-defined]
    boto3.client = lambda name: {"secretsmanager": secrets, "s3": s3, "sqs": sqs}[name]  # type: ignore[attr-defined]
    dynamodb = types.ModuleType("boto3.dynamodb")
    conditions = types.ModuleType("boto3.dynamodb.conditions")
    conditions.Key = lambda name: types.SimpleNamespace(eq=lambda value: (name, value))  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "boto3.dynamodb", dynamodb)
    monkeypatch.setitem(sys.modules, "boto3.dynamodb.conditions", conditions)
    monkeypatch.setenv("CONTROL_TABLE", "control")
    path = Path(__file__).parents[1] / "infra/aws-control-plane/lambda/intune_delivery_worker.py"
    spec = importlib.util.spec_from_file_location("aai_intune_delivery_worker", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _binding_values(module: Any, now: int) -> tuple[dict[str, Any], ...]:
    """Build one synthetic current endpoint-to-agent authority set."""
    project_root = "/synthetic/project"
    root_digest = hashlib.sha256(project_root.encode()).hexdigest()
    registration = "11111111-1111-4111-8111-111111111111"
    target = {
        "deviceId": "device-1",
        "agentKey": "deployment-1:agent-1",
        "installationId": "install-1",
        "operatingSystem": "darwin",
        "architecture": "arm64",
    }
    evidence = {
        "revision": 3,
        "observedAt": now,
        "reportDigest": "a" * 64,
        "payload": {
            "schemaVersion": 2,
            "observedAt": now,
            "device": {
                "id": "device-1",
                "managed": True,
                "operatingSystem": "darwin",
                "architecture": "arm64",
            },
            "installations": [
                {
                    "id": "install-1",
                    "deviceId": "device-1",
                    "host": "claude-code",
                    "projectRootDigest": root_digest,
                }
            ],
        },
    }
    agent = {
        "id": "agent-1",
        "deployment_id": "deployment-1",
        "host": "claude-code",
        "project_root": project_root,
        "lifecycle_state": "active",
        "lifecycle_revision": 7,
    }
    device = {
        "id": "device-1",
        "managed": True,
        "directoryDeviceRegistrationId": registration,
    }
    return target, evidence, agent, device


def test_deployment_gate_fails_before_any_aws_access(
    worker: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default deployment cannot read authority or credentials."""
    monkeypatch.delenv("ENDPOINT_DELIVERY_DISPATCH_ENABLED", raising=False)
    with pytest.raises(RuntimeError, match="deployment-disabled"):
        worker.handler({}, None)


def test_current_binding_is_reconstructed_and_detects_ambiguity(worker: Any) -> None:
    """Endpoint claims cannot select an agent when server correlation is ambiguous."""
    now = 2_000_000_000
    target, evidence, agent, device = _binding_values(worker, now)
    binding = worker._current_binding(target, evidence, agent, [agent], device, now)
    assert binding["agentKey"] == target["agentKey"]
    assert binding["bindingDigest"] == worker._hash(
        {key: value for key, value in binding.items() if key != "bindingDigest"}
    )
    duplicate = {**agent, "id": "agent-2"}
    with pytest.raises(worker.AuthorityError, match="endpoint_binding_not_unique"):
        worker._current_binding(target, evidence, agent, [agent, duplicate], device, now)


def test_current_binding_rejects_stale_or_changed_platform(worker: Any) -> None:
    """Dispatch cannot outlive signed evidence or silently change platform."""
    now = 2_000_000_000
    target, evidence, agent, device = _binding_values(worker, now)
    evidence["observedAt"] = now - worker._EVIDENCE_MAX_AGE_SECONDS
    evidence["payload"]["observedAt"] = evidence["observedAt"]
    with pytest.raises(worker.AuthorityError, match="endpoint_evidence_not_current"):
        worker._current_binding(target, evidence, agent, [agent], device, now)


def test_graph_reconciliation_preserves_unrelated_assignments(
    worker: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The worker creates one assignment without replacing customer assignments."""
    group_id = "22222222-2222-4222-8222-222222222222"
    app_id = "33333333-3333-4333-8333-333333333333"
    object_id = "44444444-4444-4444-8444-444444444444"
    group = {
        "id": group_id,
        "displayName": "AAI deployment-1",
        "description": "Dedicated managed cohort",
        "securityEnabled": True,
        "mailEnabled": False,
    }
    app = {
        "id": app_id,
        "displayName": "AAI runtime",
        "publisher": "AAI Security",
        "createdDateTime": "2026-08-05T00:00:00Z",
        "lastModifiedDateTime": "2026-08-05T00:00:00Z",
    }
    resource = {
        "groupId": group_id,
        "groupEvidenceSha256": worker._resource_evidence(
            group, ("id", "displayName", "description", "securityEnabled", "mailEnabled")
        ),
        "mobileAppId": app_id,
        "mobileAppEvidenceSha256": worker._resource_evidence(
            app,
            ("id", "displayName", "publisher", "createdDateTime", "lastModifiedDateTime"),
        ),
    }
    calls: list[tuple[str, str, object]] = []

    def request(method: str, url: str, **kwargs: Any) -> tuple[int, dict[str, Any]]:
        calls.append((method, url, kwargs.get("body")))
        if "/groups/" in url and "?$select" in url:
            return 200, group
        if "/mobileApps/" in url and "?$select=id,displayName" in url:
            return 200, app
        if "/devices(" in url:
            return 200, {
                "id": object_id,
                "deviceId": "11111111-1111-4111-8111-111111111111",
                "accountEnabled": True,
            }
        return 204, {}

    collections = iter(
        [
            [],
            [
                {
                    "id": "unrelated",
                    "intent": "available",
                    "target": {"groupId": "55555555-5555-4555-8555-555555555555"},
                }
            ],
            [{"id": object_id}],
            [
                {
                    "id": "assignment-1",
                    "intent": "required",
                    "target": {"groupId": group_id},
                }
            ],
        ]
    )
    monkeypatch.setattr(worker, "_token", lambda *_args: "synthetic-token")
    monkeypatch.setattr(worker, "_request", request)
    monkeypatch.setattr(worker, "_collection", lambda *_args: next(collections))
    evidence = worker._reconcile_graph(
        {"providerTenantId": "66666666-6666-4666-8666-666666666666"},
        {"resource": resource},
        [{"directoryDeviceRegistrationId": "11111111-1111-4111-8111-111111111111"}],
        lambda: None,
    )
    assert evidence["targetCount"] == 1
    assert any(method == "POST" and url.endswith("/assignments") for method, url, _ in calls)
    assert not any(method == "DELETE" and "/assignments/" in url for method, url, _ in calls)


def test_credential_registry_binds_raw_app_id_to_approved_package(
    worker: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A secret cannot relabel an arbitrary Intune app as an approved package."""
    app_id = "33333333-3333-4333-8333-333333333333"
    resource = {
        "deploymentId": "deployment-1",
        "providerPackageIdentitySha256": "0" * 64,
        "mobileAppId": app_id,
        "mobileAppEvidenceSha256": "1" * 64,
        "groupId": "22222222-2222-4222-8222-222222222222",
        "groupEvidenceSha256": "2" * 64,
    }
    secret = {
        "schemaVersion": 1,
        "clientId": "44444444-4444-4444-8444-444444444444",
        "clientSecret": "synthetic-secret-value",
        "resources": [resource],
    }
    monkeypatch.setattr(worker, "_secret_arn", lambda *_args: "synthetic-arn")
    monkeypatch.setattr(
        worker,
        "SECRETS",
        types.SimpleNamespace(
            get_secret_value=lambda **_kwargs: {"SecretString": json.dumps(secret)}
        ),
    )
    command = {
        "instruction": {
            "deploymentId": "deployment-1",
            "providerPackageIdentitySha256": "0" * 64,
        }
    }
    with pytest.raises(worker.AuthorityError, match="provider_app_package_identity_changed"):
        worker._credentials("tenant-1", {"providerSecretArn": "synthetic"}, command)


def test_provider_propagation_is_retryable(worker: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Eventual consistency cannot be misreported as permanent authority drift."""
    monkeypatch.setenv("ENDPOINT_DELIVERY_DISPATCH_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_DELIVERY_ENABLEMENT_EVIDENCE_SHA256", "f" * 64)
    command = {"status": "queued", "attempt_count": 0, "target_count": 1}
    monkeypatch.setattr(
        worker,
        "_load_authority",
        lambda *_args: (command, {"providerTenantId": "x"}, [{}]),
    )
    monkeypatch.setattr(worker, "_credentials", lambda *_args: {})
    monkeypatch.setattr(
        worker,
        "_reconcile_graph",
        lambda *_args: (_ for _ in ()).throw(worker.ProviderRetryable("provider_pending")),
    )
    transitions: list[str] = []

    def transition(value: dict[str, Any], *, status: str, **kwargs: Any) -> dict[str, Any]:
        transitions.append(status)
        return {**value, "status": status, **kwargs}

    monkeypatch.setattr(worker, "_transition", transition)
    event = {
        "Records": [
            {
                "eventSource": "aws:sqs",
                "body": json.dumps({"tenantId": "tenant-1", "commandId": "a" * 64}),
                "attributes": {"ApproximateReceiveCount": "1"},
            }
        ]
    }
    with pytest.raises(RuntimeError, match="requires retry"):
        worker.handler(event, None)
    assert transitions == ["resolving_targets", "retryable"]


def test_provider_redirect_is_terminal_and_content_minimised(
    worker: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A redirect cannot move the bearer or leak its target through retry logs."""
    monkeypatch.setenv("ENDPOINT_DELIVERY_DISPATCH_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_DELIVERY_ENABLEMENT_EVIDENCE_SHA256", "f" * 64)
    command = {"status": "queued", "attempt_count": 0, "target_count": 1}
    monkeypatch.setattr(
        worker,
        "_load_authority",
        lambda *_args: (command, {"providerTenantId": "x"}, [{}]),
    )
    monkeypatch.setattr(worker, "_credentials", lambda *_args: {})
    monkeypatch.setattr(
        worker,
        "_reconcile_graph",
        lambda *_args: (_ for _ in ()).throw(
            worker.HTTPError("https://untrusted.invalid/device-id", 302, "redirect", {}, None)
        ),
    )
    monkeypatch.setattr(
        worker,
        "_transition",
        lambda value, *, status, reason=None, **kwargs: {
            **value,
            "status": status,
            "failure_code": reason,
            **kwargs,
        },
    )
    audits: list[dict[str, Any]] = []
    monkeypatch.setattr(worker, "_audit_terminal", lambda _tenant, value: audits.append(value))
    event = {
        "Records": [
            {
                "eventSource": "aws:sqs",
                "body": json.dumps({"tenantId": "tenant-1", "commandId": "a" * 64}),
                "attributes": {"ApproximateReceiveCount": "1"},
            }
        ]
    }
    result = worker.handler(event, None)
    assert result == {"status": "blocked", "failureCode": "provider_redirect_denied"}
    assert audits[0]["failure_code"] == "provider_redirect_denied"
    assert "untrusted" not in json.dumps(audits)


def test_large_page_adds_only_missing_members_and_reproduces_before_progress(
    worker: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One continuation page is idempotent and cannot prune the wider cohort."""
    group_id = "22222222-2222-4222-8222-222222222222"
    first_registration = "11111111-1111-4111-8111-111111111111"
    second_registration = "33333333-3333-4333-8333-333333333333"
    first_object = "44444444-4444-4444-8444-444444444444"
    second_object = "55555555-5555-4555-8555-555555555555"
    inventories = iter(
        [
            [(first_object, first_registration)],
            [(first_object, first_registration), (second_object, second_registration)],
        ]
    )
    monkeypatch.setattr(
        worker,
        "_provider_context",
        lambda *_args: ("synthetic-token", group_id, "66666666-6666-4666-8666-666666666666"),
    )
    monkeypatch.setattr(worker, "_group_member_inventory", lambda *_args: next(inventories))
    monkeypatch.setattr(
        worker,
        "_resolve_directory_target",
        lambda target, _token: {
            first_registration: (first_object, first_registration),
            second_registration: (second_object, second_registration),
        }[target["directoryDeviceRegistrationId"]],
    )
    calls: list[tuple[str, str, object]] = []

    def request(method: str, url: str, **kwargs: Any) -> tuple[int, dict[str, Any]]:
        calls.append((method, url, kwargs.get("body")))
        return 204, {}

    monkeypatch.setattr(worker, "_request", request)
    reauthorizations: list[bool] = []

    progress = worker._reconcile_graph_page(
        {},
        {},
        [
            {"directoryDeviceRegistrationId": first_registration},
            {"directoryDeviceRegistrationId": second_registration},
        ],
        lambda: reauthorizations.append(True),
    )

    assert progress["pageTargetCount"] == 2
    assert len(reauthorizations) == 1
    assert [method for method, _url, _body in calls] == ["POST"]
    assert second_object in json.dumps(calls)
    assert first_object not in json.dumps(calls)
    assert set(progress) == {"pageTargetCount", "pageRegistrationDigest"}


def test_large_finalize_prunes_only_one_bounded_chunk_before_assignment(
    worker: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A large stale group cannot reach assignment before bounded exact pruning."""
    group_id = "22222222-2222-4222-8222-222222222222"
    desired_registration = "11111111-1111-4111-8111-111111111111"
    desired_object = "33333333-3333-4333-8333-333333333333"
    extras = [
        (f"{index:08x}-0000-4000-8000-{index:012x}", None)
        for index in range(1, worker._MAX_MUTATIONS_PER_INVOCATION + 2)
    ]
    monkeypatch.setattr(
        worker,
        "_provider_context",
        lambda *_args: ("synthetic-token", group_id, "44444444-4444-4444-8444-444444444444"),
    )
    monkeypatch.setattr(
        worker,
        "_group_member_inventory",
        lambda *_args: [(desired_object, desired_registration), *extras],
    )
    calls: list[tuple[str, str]] = []

    def request(method: str, url: str, **_kwargs: Any) -> tuple[int, dict[str, Any]]:
        calls.append((method, url))
        return 204, {}

    monkeypatch.setattr(worker, "_request", request)
    monkeypatch.setattr(
        worker,
        "_collection",
        lambda *_args: (_ for _ in ()).throw(AssertionError("assignment read was premature")),
    )
    reauthorizations: list[bool] = []

    complete, evidence, removed = worker._finalize_graph_continuation(
        {},
        {},
        [{"directoryDeviceRegistrationId": desired_registration}],
        lambda: reauthorizations.append(True),
    )

    assert complete is False
    assert evidence is None
    assert removed == worker._MAX_MUTATIONS_PER_INVOCATION
    assert len(reauthorizations) == worker._MAX_MUTATIONS_PER_INVOCATION
    assert len(calls) == worker._MAX_MUTATIONS_PER_INVOCATION
    assert all(method == "DELETE" and "/members/" in url for method, url in calls)


def test_stale_continuation_repairs_current_revision_without_repeating_work(
    worker: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A redelivered old FIFO message can only repair the latest durable step."""
    monkeypatch.setenv("ENDPOINT_DELIVERY_DISPATCH_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_DELIVERY_ENABLEMENT_EVIDENCE_SHA256", "f" * 64)
    command = {
        "id": "a" * 64,
        "status": "continuing",
        "continuation_revision": 2,
        "attempt_count": 1,
    }
    monkeypatch.setattr(worker, "_load_authority", lambda *_args: (command, {}, [{}] * 41))
    enqueued: list[tuple[str, str, int]] = []
    monkeypatch.setattr(
        worker,
        "_enqueue_continuation",
        lambda tenant, command_id, revision: enqueued.append((tenant, command_id, revision)),
    )
    monkeypatch.setattr(
        worker,
        "_transition",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("stale work repeated")),
    )
    event = {
        "Records": [
            {
                "eventSource": "aws:sqs",
                "body": json.dumps(
                    {
                        "tenantId": "tenant-1",
                        "commandId": "a" * 64,
                        "continuationRevision": 1,
                    }
                ),
                "attributes": {"ApproximateReceiveCount": "2"},
            }
        ]
    }

    result = worker.handler(event, None)

    assert result["status"] == "continuation_repaired"
    assert result["continuationRevision"] == 2
    assert enqueued == [("tenant-1", "a" * 64, 2)]


def test_continuation_queue_is_fixed_and_message_is_opaque(
    worker: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Self-continuation cannot choose an origin or include provider identity."""
    monkeypatch.setenv("AWS_REGION", "eu-west-2")
    monkeypatch.setenv("AWS_ACCOUNT_ID", "111111111111")
    monkeypatch.setenv(
        "ENDPOINT_DELIVERY_QUEUE_URL",
        "https://sqs.eu-west-2.amazonaws.com/111111111111/endpoint-delivery.fifo",
    )
    messages: list[dict[str, Any]] = []
    monkeypatch.setattr(
        worker,
        "SQS",
        types.SimpleNamespace(send_message=lambda **value: messages.append(value)),
    )

    worker._enqueue_continuation("tenant-1", "a" * 64, 3)

    assert json.loads(messages[0]["MessageBody"]) == {
        "tenantId": "tenant-1",
        "commandId": "a" * 64,
        "continuationRevision": 3,
    }
    assert messages[0]["MessageDeduplicationId"] == f"{'a' * 64}:3"
    monkeypatch.setenv("ENDPOINT_DELIVERY_QUEUE_URL", "https://untrusted.invalid/a.fifo")
    with pytest.raises(RuntimeError, match="queue is invalid"):
        worker._enqueue_continuation("tenant-1", "a" * 64, 4)


def test_large_sealed_command_is_admitted_but_remains_bounded(worker: Any) -> None:
    """Forty-one targets use continuation while an oversized cohort fails closed."""
    instruction = {
        "schemaVersion": 1,
        "provider": "intune",
        "providerVersion": 1,
        "providerContentHash": "0" * 64,
        "deploymentId": "deployment-1",
        "host": "claude-code",
        "releaseId": "release-1",
        "packageId": "package-1",
        "packageManifestSha256": "1" * 64,
        "packageObjectSha256": "2" * 64,
        "packageStorageIdentitySha256": "3" * 64,
        "providerPackageIdentitySha256": "4" * 64,
        "packageSignatureEvidenceSha256": "5" * 64,
        "packageApproverEvidenceSha256": "6" * 64,
        "releaseEvidenceSha256": "7" * 64,
        "packageBundleSha256": "8" * 64,
        "packageApprovalBundleSha256": "9" * 64,
        "rolloutRevision": 1,
        "rolloutState": "canary",
        "targetCount": 41,
        "cohortDigest": "a" * 64,
        "pages": [
            {"id": "b" * 64, "pageDigest": "c" * 64, "targetCount": 40},
            {"id": "d" * 64, "pageDigest": "e" * 64, "targetCount": 1},
        ],
    }

    assert worker._command_instruction(instruction)["targetCount"] == 41
    with pytest.raises(worker.AuthorityError, match="command_target_limit_exceeded"):
        worker._command_instruction({**instruction, "targetCount": 501})


def test_large_command_advances_exact_pages_then_enters_pruning(
    worker: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Server-owned page state advances monotonically and never skips a target."""
    pages = [
        {"id": "b" * 64, "pageDigest": "c" * 64, "targetCount": 40},
        {"id": "d" * 64, "pageDigest": "e" * 64, "targetCount": 1},
    ]
    instruction = {"pages": pages}
    command: dict[str, Any] = {
        "id": "a" * 64,
        "instruction": instruction,
        "continuation_revision": 0,
        "continuation_stage": "resolving_pages",
        "continuation_page": 0,
        "continuation_completed_targets": 0,
        "continuation_mutation_count": 0,
    }
    targets = [{"index": index} for index in range(41)]
    monkeypatch.setattr(worker, "_command_instruction", lambda _value: instruction)
    monkeypatch.setattr(worker, "_credentials", lambda *_args: {})
    selected_pages: list[list[int]] = []

    def reconcile_page(
        _configuration: object,
        _credentials: object,
        selected: list[dict[str, int]],
        _reauthorize: object,
    ) -> dict[str, int]:
        selected_pages.append([target["index"] for target in selected])
        return {"pageTargetCount": len(selected)}

    monkeypatch.setattr(worker, "_reconcile_graph_page", reconcile_page)
    advances: list[dict[str, Any]] = []

    def advance(_tenant: str, value: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        advances.append(kwargs)
        return {**value, "continuation_revision": int(value["continuation_revision"]) + 1}

    monkeypatch.setattr(worker, "_advance_continuation", advance)

    first = worker._continue_large_command("tenant-1", command, {}, targets, attempt=1)
    command.update(
        {
            "continuation_revision": 1,
            "continuation_page": 1,
            "continuation_completed_targets": 40,
        }
    )
    second = worker._continue_large_command("tenant-1", command, {}, targets, attempt=2)

    assert selected_pages == [list(range(40)), [40]]
    assert advances[0] == {
        "attempt": 1,
        "stage": "resolving_pages",
        "page": 1,
        "completed_targets": 40,
        "mutation_count": 0,
    }
    assert advances[1]["stage"] == "pruning"
    assert advances[1]["page"] == 2
    assert advances[1]["completed_targets"] == 41
    assert first["continuationRevision"] == 1
    assert second["continuationRevision"] == 2


def test_lost_continuation_send_preserves_new_revision_as_retryable(
    worker: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Persist-before-send failure remains visible and repairable without page replay."""
    command: dict[str, Any] = {
        "id": "a" * 64,
        "status": "resolving_targets",
        "attempt_count": 1,
        "continuation_revision": 0,
    }
    transitions: list[dict[str, Any]] = []

    def transition(value: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        updated = {
            **value,
            "status": kwargs["status"],
            "failure_code": kwargs.get("reason"),
            **kwargs.get("continuation", {}),
        }
        transitions.append(updated)
        return updated

    monkeypatch.setattr(worker, "_transition", transition)
    monkeypatch.setattr(
        worker,
        "_enqueue_continuation",
        lambda *_args: (_ for _ in ()).throw(OSError("synthetic queue outage")),
    )

    with pytest.raises(RuntimeError, match="continuation requires retry"):
        worker._advance_continuation(
            "tenant-1",
            command,
            attempt=1,
            stage="resolving_pages",
            page=1,
            completed_targets=40,
            mutation_count=0,
        )

    assert transitions[0]["continuation_revision"] == 1
    assert transitions[1]["status"] == "retryable"
    assert transitions[1]["failure_code"] == "continuation_enqueue_failed"
