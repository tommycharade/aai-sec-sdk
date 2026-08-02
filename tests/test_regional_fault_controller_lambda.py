"""Adversarial tests for the durable Regional fault mutation boundary."""

from __future__ import annotations

import importlib
import json
from typing import Any

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]


def _module() -> Any:
    return importlib.import_module("scripts.regional_fault_controller_lambda")


def _cleanup() -> Any:
    return importlib.import_module("scripts.regional_fault_cleanup_lambda")


def _manifest() -> dict[str, Any]:
    return {
        "schemaVersion": 4,
        "transitionId": "12345678-1234-4234-8234-123456789abc",
        "direction": "failover",
        "primaryRegion": "eu-west-2",
        "recoveryRegion": "eu-west-1",
        "sourceRegion": "eu-west-2",
        "targetRegion": "eu-west-1",
        "stableApiDomain": "api.security.example.com",
        "stableUiDomain": "security.example.com",
        "route53HostedZoneId": "Z1234567890ABC",
        "targetFleetSize": 1000,
        "rtoMinutes": 30,
        "rpoSeconds": 60,
        "evidenceBundle": {
            "bucketArn": "arn:aws:s3:::synthetic-evidence",
            "key": "regional-activation/synthetic.json",
            "versionId": "version-1",
            "sha256": "a" * 64,
        },
        "approvalEvidenceRef": "change/DR-123",
        "expiresAt": 1600,
        "activationPermitted": True,
        "automaticActivation": False,
        "coordinationRegion": "eu-central-1",
        "journalTableName": "AaiSecRegionalTransitionJournal",
        "expectedRoutingGeneration": 0,
        "approvals": [
            {
                "principalId": "22345678-1234-4234-8234-123456789abc",
                "evidenceRef": "entra/approval-a",
                "approvedAt": 990,
                "strongAuthAt": 970,
            },
            {
                "principalId": "32345678-1234-4234-8234-123456789abc",
                "evidenceRef": "entra/approval-b",
                "approvedAt": 995,
                "strongAuthAt": 980,
            },
        ],
        "primaryIngressStackName": "AaiSecPrimaryRegionalIngress",
        "recoveryIngressStackName": "AaiSecRecoveryRegionalIngress",
        "primaryCanaryApiDomain": "api-primary.security.example.com",
        "primaryCanaryUiDomain": "primary.security.example.com",
        "recoveryCanaryApiDomain": "api-recovery.security.example.com",
        "recoveryCanaryUiDomain": "recovery.security.example.com",
        "routingMarkerName": "routing-generation.security.example.com",
        "routingRoleArn": "arn:aws:iam::111111111111:role/AaiSecRegionalRouting",
        "routingAuthorityEvidenceRef": "change/ROUTING-123",
        "primaryRuntimeStackName": "AaiSecControlPlane",
        "primaryRuntimeTemplateSha256": "b" * 64,
        "recoveryRuntimeStackName": "AaiSecPassiveRegionalCell",
        "recoveryRuntimeTemplateSha256": "c" * 64,
    }


def _authority(dependency: str = "dynamodb") -> dict[str, Any]:
    module = _module()
    manifest = module.activation.ActivationManifest.parse(json.dumps(_manifest()), now=1000)
    return {
        "schemaVersion": 1,
        "faultId": "42345678-1234-4234-8234-123456789abc",
        "transitionId": manifest.transition_id,
        "transitionAuthoritySha256": manifest.authority_sha256(),
        "direction": "failover",
        "targetRegion": "eu-west-1",
        "targetCellRole": "recovery",
        "targetRuntimeStackName": manifest.recovery_runtime_stack_name,
        "targetRuntimeTemplateSha256": manifest.recovery_runtime_template_sha256,
        "coordinationRegion": "eu-central-1",
        "expectedRoutingGeneration": 0,
        "dependency": dependency,
        "maximumFaultSeconds": 120,
        "approvalSha256": manifest.approval_sha256(),
        "approverPrincipalIds": [item.principal_id for item in manifest.approvals],
        "activationEvidenceRef": module.fault.activation_evidence_ref(manifest.evidence),
        "expiresAt": 1400,
        "faultPermitted": True,
        "automaticFaultInjection": False,
    }


def _event(operation: str, dependency: str = "dynamodb") -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "operation": operation,
        "manifest": _manifest(),
        "faultAuthority": _authority(dependency),
    }


def _config() -> Any:
    module = _module()
    return module.ControllerConfig(
        module.CellBoundary(
            "arn:aws:iam::111111111111:role/PrimaryHandler",
            "arn:aws:s3:::synthetic-primary-audit",
            tuple(
                f"arn:aws:dynamodb:eu-west-2:111111111111:table/PrimaryTable{index}"
                for index in range(4)
            ),
            "arn:aws:kms:eu-west-2:111111111111:key/mrk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ("arn:aws:sqs:eu-west-2:111111111111:primary-queue",),
        ),
        module.CellBoundary(
            "arn:aws:iam::111111111111:role/RecoveryHandler",
            "arn:aws:s3:::synthetic-audit",
            tuple(
                f"arn:aws:dynamodb:eu-west-1:111111111111:table/Table{index}" for index in range(4)
            ),
            "arn:aws:kms:eu-west-1:111111111111:key/mrk-1234567890abcdef1234567890abcdef",
            ("arn:aws:sqs:eu-west-1:111111111111:synthetic-queue",),
        ),
        "AaiSecRegionalTransitionJournal",
        "aai-sec-regional-fault-watchdogs",
        "arn:aws:iam::111111111111:role/FaultWatchdog",
        "arn:aws:lambda:eu-central-1:111111111111:function:AaiSecFaultCleanup",
    )


class FakeDynamoDB:
    """Minimal stateful DynamoDB contract for lock sequencing tests."""

    def __init__(self, item: dict[str, Any] | None = None) -> None:
        self.item = item
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def put_item(self, **kwargs: Any) -> None:
        self.calls.append(("put_item", kwargs))
        if self.item is not None:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "exists"}},
                "PutItem",
            )
        self.item = kwargs["Item"]

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_item", kwargs))
        return {"Item": self.item} if self.item is not None else {}

    def update_item(self, **kwargs: Any) -> None:
        self.calls.append(("update_item", kwargs))
        assert self.item is not None
        values = kwargs["ExpressionAttributeValues"]
        for candidate in (":armed", ":applied", ":removed", ":disarmed", ":complete", ":cleaned"):
            if candidate in values:
                self.item["state"] = values[candidate]

    def delete_item(self, **kwargs: Any) -> None:
        self.calls.append(("delete_item", kwargs))
        self.item = None

    def transact_write_items(self, **kwargs: Any) -> None:
        self.calls.append(("transact_write_items", kwargs))
        self.item = None


class Recorder:
    """Record provider calls without performing external side effects."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Any:
        def record(**kwargs: Any) -> dict[str, Any]:
            self.calls.append((name, kwargs))
            return {}

        return record


def _digest(dependency: str = "dynamodb") -> str:
    module = _module()
    manifest = module.activation.ActivationManifest.parse(json.dumps(_manifest()), now=1000)
    authority = module.fault.RegionalFaultAuthority.parse(
        json.dumps(_authority(dependency)), manifest, now=1000
    )
    return str(authority.sha256())


def test_apply_refuses_mutation_until_independent_watchdog_is_armed() -> None:
    module = _module()
    dynamodb = FakeDynamoDB(
        {
            "authoritySha256": {"S": _digest()},
            "state": {"S": "LOCKED"},
        }
    )
    iam = Recorder()
    with pytest.raises(module.RegionalFaultControllerError, match="watchdog is not armed"):
        module.execute(
            _event("apply-deny"),
            config=_config(),
            dynamodb=dynamodb,
            iam=iam,
            scheduler=Recorder(),
            now=1000,
        )
    assert iam.calls == []


def test_watchdog_is_independent_bounded_and_content_free() -> None:
    module = _module()
    dynamodb = FakeDynamoDB({"authoritySha256": {"S": _digest()}, "state": {"S": "LOCKED"}})
    scheduler = Recorder()
    module.execute(
        _event("arm-watchdog"),
        config=_config(),
        dynamodb=dynamodb,
        iam=Recorder(),
        scheduler=scheduler,
        now=1000,
    )
    name, call = scheduler.calls[0]
    assert name == "create_schedule"
    assert call["ScheduleExpression"] == "at(1970-01-01T00:19:40)"
    assert call["ActionAfterCompletion"] == "DELETE"
    payload = json.loads(call["Target"]["Input"])
    assert set(payload) == {"schemaVersion", "faultId", "authoritySha256", "targetCellRole"}
    assert "manifest" not in call["Target"]["Input"]


def test_apply_uses_only_code_owned_exact_dynamodb_boundary() -> None:
    module = _module()
    dynamodb = FakeDynamoDB({"authoritySha256": {"S": _digest()}, "state": {"S": "WATCHDOG_ARMED"}})
    iam = Recorder()
    module.execute(
        _event("apply-deny"),
        config=_config(),
        dynamodb=dynamodb,
        iam=iam,
        scheduler=Recorder(),
        now=1000,
    )
    name, call = iam.calls[0]
    assert name == "put_role_policy"
    assert call["RoleName"] == "RecoveryHandler"
    assert call["PolicyName"] == "AaiSecRegionalFault-42345678-1234-4234-8234-123456789abc"
    policy = json.loads(call["PolicyDocument"])
    assert policy["Statement"][0]["Effect"] == "Deny"
    assert policy["Statement"][0]["Resource"] == [
        item for arn in _config().recovery.table_arns for item in (arn, f"{arn}/index/*")
    ]
    assert all(action.startswith("dynamodb:") for action in policy["Statement"][0]["Action"])


def test_unsupported_cognito_boundary_fails_before_iam_mutation() -> None:
    module = _module()
    dynamodb = FakeDynamoDB(
        {
            "authoritySha256": {"S": _digest("cognito")},
            "state": {"S": "WATCHDOG_ARMED"},
        }
    )
    iam = Recorder()
    with pytest.raises(module.RegionalFaultControllerError, match="no safe target-role boundary"):
        module.execute(
            _event("apply-deny", "cognito"),
            config=_config(),
            dynamodb=dynamodb,
            iam=iam,
            scheduler=Recorder(),
            now=1000,
        )
    assert iam.calls == []


def test_single_writer_lock_rejects_overlapping_fault() -> None:
    module = _module()
    with pytest.raises(module.RegionalFaultControllerError, match="another target-cell fault"):
        module.execute(
            _event("acquire"),
            config=_config(),
            dynamodb=FakeDynamoDB({"state": {"S": "DENY_APPLIED"}}),
            iam=Recorder(),
            scheduler=Recorder(),
            now=1000,
        )


def test_same_fault_acquire_is_retry_safe_after_lost_response() -> None:
    module = _module()
    dynamodb = FakeDynamoDB(
        {
            "authoritySha256": {"S": _digest()},
            "state": {"S": "WATCHDOG_ARMED"},
        }
    )
    result = module.execute(
        _event("acquire"),
        config=_config(),
        dynamodb=dynamodb,
        iam=Recorder(),
        scheduler=Recorder(),
        now=1000,
    )
    assert result["status"] == "already-completed"


def test_failed_watchdog_creation_can_release_only_the_unarmed_exact_lock() -> None:
    module = _module()
    dynamodb = FakeDynamoDB(
        {
            "authoritySha256": {"S": _digest()},
            "state": {"S": "LOCKED"},
        }
    )
    module.execute(
        _event("release-unarmed-lock"),
        config=_config(),
        dynamodb=dynamodb,
        iam=Recorder(),
        scheduler=Recorder(),
        now=1000,
    )
    assert dynamodb.item is None
    call = dynamodb.calls[-1][1]
    assert call["ConditionExpression"] == "authoritySha256 = :digest AND #state = :locked"


@pytest.mark.parametrize(
    ("dependency", "action_prefix", "resources"),
    [
        ("audit", "s3:", ["arn:aws:s3:::synthetic-audit/*"]),
        (
            "kms",
            "kms:",
            ["arn:aws:kms:eu-west-1:111111111111:key/mrk-1234567890abcdef1234567890abcdef"],
        ),
        ("queue", "sqs:", ["arn:aws:sqs:eu-west-1:111111111111:synthetic-queue"]),
    ],
)
def test_every_enabled_boundary_is_service_and_resource_exact(
    dependency: str, action_prefix: str, resources: list[str]
) -> None:
    module = _module()
    manifest = module.activation.ActivationManifest.parse(json.dumps(_manifest()), now=1000)
    authority = module.fault.RegionalFaultAuthority.parse(
        json.dumps(_authority(dependency)), manifest, now=1000
    )
    policy = module._boundary(authority, _config())
    statement = policy["Statement"][0]
    assert statement["Resource"] == resources
    assert all(action.startswith(action_prefix) for action in statement["Action"])
    assert "*" not in statement["Action"]


def test_failback_derives_primary_resources_without_recovery_aliases() -> None:
    module = _module()
    manifest_value = _manifest()
    manifest_value.update(
        {
            "direction": "failback",
            "sourceRegion": "eu-west-1",
            "targetRegion": "eu-west-2",
        }
    )
    manifest = module.activation.ActivationManifest.parse(json.dumps(manifest_value), now=1000)
    authority_value = _authority("audit")
    authority_value.update(
        {
            "transitionAuthoritySha256": manifest.authority_sha256(),
            "direction": "failback",
            "targetRegion": "eu-west-2",
            "targetCellRole": "primary",
            "targetRuntimeStackName": manifest.primary_runtime_stack_name,
            "targetRuntimeTemplateSha256": manifest.primary_runtime_template_sha256,
            "approvalSha256": manifest.approval_sha256(),
            "activationEvidenceRef": module.fault.activation_evidence_ref(manifest.evidence),
        }
    )
    authority = module.fault.RegionalFaultAuthority.parse(
        json.dumps(authority_value), manifest, now=1000
    )
    policy = module._boundary(authority, _config())
    assert policy["Statement"][0]["Resource"] == ["arn:aws:s3:::synthetic-primary-audit/*"]
    assert _config().target(authority.target_cell_role).role_arn.endswith("/PrimaryHandler")


def test_success_seals_content_free_evidence_and_releases_lock() -> None:
    module = _module()
    dynamodb = FakeDynamoDB(
        {
            "authoritySha256": {"S": _digest()},
            "state": {"S": "WATCHDOG_DISARMED"},
        }
    )
    module.execute(
        _event("seal-evidence"),
        config=_config(),
        dynamodb=dynamodb,
        iam=Recorder(),
        scheduler=Recorder(),
        now=1000,
    )
    assert dynamodb.item is None
    transaction = dynamodb.calls[-1][1]["TransactItems"]
    evidence = transaction[0]["Put"]["Item"]
    assert evidence["status"] == {"S": "COMPLETE"}
    assert set(evidence) == {
        "pk",
        "sk",
        "authoritySha256",
        "targetCellRole",
        "dependency",
        "status",
        "completedAt",
    }


def test_cleanup_remains_authorized_after_expiry_but_requires_exact_lock() -> None:
    cleanup = _cleanup()
    digest = _digest()
    event = {
        "schemaVersion": 1,
        "faultId": "42345678-1234-4234-8234-123456789abc",
        "authoritySha256": digest,
        "targetCellRole": "recovery",
    }
    dynamodb = FakeDynamoDB(
        {
            "faultId": {"S": event["faultId"]},
            "authoritySha256": {"S": digest},
            "state": {"S": "DENY_APPLIED"},
        }
    )
    iam = Recorder()
    result = cleanup.cleanup(event, config=_config(), dynamodb=dynamodb, iam=iam)
    assert result["status"] == "watchdog-cleaned"
    assert dynamodb.item is None
    assert iam.calls[0][1] == {
        "RoleName": "RecoveryHandler",
        "PolicyName": "AaiSecRegionalFault-42345678-1234-4234-8234-123456789abc",
    }

    changed = dict(event, authoritySha256="0" * 64)
    different_lock = FakeDynamoDB(
        {
            "faultId": {"S": event["faultId"]},
            "authoritySha256": {"S": digest},
            "state": {"S": "DENY_APPLIED"},
        }
    )
    with pytest.raises(cleanup.RegionalFaultControllerError, match="lock authority differs"):
        cleanup.cleanup(changed, config=_config(), dynamodb=different_lock, iam=Recorder())


def test_unknown_fields_and_automatic_authority_fail_before_provider_calls() -> None:
    module = _module()
    provider = Recorder()
    changed = _event("acquire") | {"roleArn": _config().primary.role_arn}
    with pytest.raises(module.RegionalFaultControllerError, match="event schema"):
        module.execute(
            changed,
            config=_config(),
            dynamodb=provider,
            iam=provider,
            scheduler=provider,
            now=1000,
        )
    assert provider.calls == []

    changed = _event("acquire")
    changed["faultAuthority"]["automaticFaultInjection"] = True
    with pytest.raises(module.RegionalFaultControllerError, match="authority is invalid"):
        module.execute(
            changed,
            config=_config(),
            dynamodb=provider,
            iam=provider,
            scheduler=provider,
            now=1000,
        )
    assert provider.calls == []
