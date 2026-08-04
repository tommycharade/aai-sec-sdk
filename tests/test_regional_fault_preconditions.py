"""Provider-shaped tests for live Regional fault preconditions."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
loaded_scripts = sys.modules.get("scripts")
if loaded_scripts is not None and getattr(loaded_scripts, "__file__", None) != str(
    ROOT / "scripts" / "__init__.py"
):
    sys.modules.pop("scripts", None)
journal = importlib.import_module("scripts.manage_aws_transition_journal")


def _modules() -> tuple[Any, Any]:
    """Return the verifier and canonical authority fixtures."""
    verifier = importlib.import_module("scripts.regional_fault_preconditions")
    path = Path(__file__).with_name("test_regional_fault_controller_lambda.py")
    spec = importlib.util.spec_from_file_location("regional_fault_precondition_fixtures", path)
    assert spec and spec.loader
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    return verifier, fixtures


def _authority() -> tuple[Any, Any]:
    """Parse one valid schema-v4 failover and dependency authority."""
    verifier, fixtures = _modules()
    manifest = verifier.activation.ActivationManifest.parse(
        __import__("json").dumps(fixtures._manifest()), now=1000
    )
    authority = verifier.fault.RegionalFaultAuthority.parse(
        __import__("json").dumps(fixtures._authority("dynamodb")), manifest, now=1000
    )
    return manifest, authority


def _state(manifest: Any) -> Any:
    """Return exact target-active-not-routed journal authority."""
    return journal.JournalState(
        generation=0,
        active_region=manifest.source_region,
        phase="TARGET_ACTIVE_NOT_ROUTED",
        revision=4,
        updated_at=999,
        last_completed_transition_id="",
        active_transition_id=manifest.transition_id,
        direction=manifest.direction,
        source_region=manifest.source_region,
        target_region=manifest.target_region,
        authority_sha256=manifest.authority_sha256(),
        evidence_sha256=manifest.evidence.sha256,
        approval_sha256=manifest.approval_sha256(),
        expires_at=manifest.expires_at,
    )


class RuntimeLambda:
    """Return one configured live execution state for all exact identities."""

    def __init__(self, *, fenced: bool, reserved: int | None = 5) -> None:
        self.fenced = fenced
        self.reserved = reserved

    def get_function_concurrency(self, **_kwargs: Any) -> dict[str, Any]:
        if self.fenced:
            return {"ReservedConcurrentExecutions": 0}
        return {} if self.reserved is None else {"ReservedConcurrentExecutions": self.reserved}

    def get_function_configuration(self, **_kwargs: Any) -> dict[str, Any]:
        return {"State": "Active", "LastUpdateStatus": "Successful"}

    def get_event_source_mapping(self, *, UUID: str) -> dict[str, Any]:
        return {"UUID": UUID, "State": "Disabled" if self.fenced else "Enabled"}


class RuntimeEvents:
    """Return one configured EventBridge state."""

    def __init__(self, *, fenced: bool) -> None:
        self.fenced = fenced

    def describe_rule(self, *, Name: str) -> dict[str, Any]:
        return {"Name": Name, "State": "DISABLED" if self.fenced else "ENABLED"}


def _resources() -> dict[str, tuple[tuple[str, str], ...]]:
    return {
        "AWS::Lambda::Function": (("Handler", "handler"), ("Worker", "worker")),
        "AWS::Lambda::EventSourceMapping": (("Mapping", "mapping"),),
        "AWS::Events::Rule": (("Rule", "rule"),),
    }


def _runtime_template(*, reserved: int | None = 5) -> dict[str, Any]:
    functions = {
        logical: {
            "Type": "AWS::Lambda::Function",
            "Properties": ({} if reserved is None else {"ReservedConcurrentExecutions": reserved}),
        }
        for logical in ("Handler", "Worker")
    }
    return {
        "Resources": {
            **functions,
            "Mapping": {
                "Type": "AWS::Lambda::EventSourceMapping",
                "Properties": {"Enabled": True},
            },
            "Rule": {
                "Type": "AWS::Events::Rule",
                "Properties": {"State": "ENABLED"},
            },
        }
    }


@pytest.mark.parametrize("fenced", [True, False])
def test_every_runtime_execution_path_is_read_live(fenced: bool) -> None:
    verifier, _ = _modules()

    def client(service: str, _region: str) -> Any:
        return RuntimeLambda(fenced=fenced) if service == "lambda" else RuntimeEvents(fenced=fenced)

    result = verifier._verify_runtime_state(
        _resources(),
        region="eu-west-2",
        fenced=fenced,
        client=client,
        template=None if fenced else _runtime_template(),
    )
    assert result == {
        "eventRuleCount": 1,
        "eventSourceMappingCount": 1,
        "functionCount": 2,
        "resourceSetSha256": verifier._canonical_sha256(_resources()),
        "status": "fenced" if fenced else "active",
    }


@pytest.mark.parametrize(
    ("method", "value", "message"),
    [
        ("get_function_concurrency", {"ReservedConcurrentExecutions": 1}, "not concurrency"),
        ("get_event_source_mapping", {"UUID": "mapping", "State": "Enabled"}, "mapping"),
        ("describe_rule", {"Name": "rule", "State": "ENABLED"}, "rule"),
    ],
)
def test_any_unfenced_source_path_rejects_the_exercise(
    method: str, value: dict[str, Any], message: str
) -> None:
    verifier, _ = _modules()
    lambda_client = RuntimeLambda(fenced=True)
    events_client = RuntimeEvents(fenced=True)
    setattr(
        lambda_client if hasattr(lambda_client, method) else events_client,
        method,
        lambda **_k: value,
    )

    def client(service: str, _region: str) -> Any:
        return lambda_client if service == "lambda" else events_client

    with pytest.raises(verifier.RegionalFaultPreconditionError, match=message):
        verifier._verify_runtime_state(_resources(), region="eu-west-2", fenced=True, client=client)


def test_active_target_accepts_reviewed_unreserved_lambda() -> None:
    verifier, _ = _modules()

    def client(service: str, _region: str) -> Any:
        return (
            RuntimeLambda(fenced=False, reserved=None)
            if service == "lambda"
            else RuntimeEvents(fenced=False)
        )

    result = verifier._verify_runtime_state(
        _resources(),
        region="eu-west-1",
        fenced=False,
        client=client,
        template=_runtime_template(reserved=None),
    )
    assert result["status"] == "active"


def test_active_target_rejects_concurrency_drift_from_reviewed_template() -> None:
    verifier, _ = _modules()

    def client(service: str, _region: str) -> Any:
        return (
            RuntimeLambda(fenced=False, reserved=4)
            if service == "lambda"
            else RuntimeEvents(fenced=False)
        )

    with pytest.raises(verifier.RegionalFaultPreconditionError, match="reviewed state"):
        verifier._verify_runtime_state(
            _resources(),
            region="eu-west-1",
            fenced=False,
            client=client,
            template=_runtime_template(reserved=5),
        )


def test_runtime_inventory_is_complete_logical_to_physical_and_bounded() -> None:
    verifier, _ = _modules()

    class CloudFormation:
        def list_stack_resources(self, **kwargs: Any) -> dict[str, Any]:
            if "NextToken" not in kwargs:
                return {
                    "StackResourceSummaries": [
                        {
                            "LogicalResourceId": "Handler",
                            "PhysicalResourceId": "handler",
                            "ResourceType": "AWS::Lambda::Function",
                            "ResourceStatus": "UPDATE_COMPLETE",
                        },
                        {
                            "LogicalResourceId": "Mapping",
                            "PhysicalResourceId": "mapping",
                            "ResourceType": "AWS::Lambda::EventSourceMapping",
                            "ResourceStatus": "UPDATE_COMPLETE",
                        },
                    ],
                    "NextToken": "page-2",
                }
            return {
                "StackResourceSummaries": [
                    {
                        "LogicalResourceId": "Rule",
                        "PhysicalResourceId": "rule",
                        "ResourceType": "AWS::Events::Rule",
                        "ResourceStatus": "UPDATE_COMPLETE",
                    }
                ]
            }

    assert verifier._runtime_resources(CloudFormation(), "Runtime") == {
        "AWS::Lambda::Function": (("Handler", "handler"),),
        "AWS::Lambda::EventSourceMapping": (("Mapping", "mapping"),),
        "AWS::Events::Rule": (("Rule", "rule"),),
    }


def test_runtime_inventory_rejects_repeated_pagination_token() -> None:
    verifier, _ = _modules()

    class CloudFormation:
        def list_stack_resources(self, **_kwargs: Any) -> dict[str, Any]:
            return {"StackResourceSummaries": [], "NextToken": "same"}

    with pytest.raises(verifier.RegionalFaultPreconditionError, match="pagination"):
        verifier._runtime_resources(CloudFormation(), "Runtime")


def test_complete_preconditions_bind_journal_templates_runtime_and_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier, _ = _modules()
    manifest, authority = _authority()
    state = _state(manifest)
    calls: list[tuple[str, str]] = []

    class CloudFormation:
        def describe_stacks(self, *, StackName: str) -> dict[str, Any]:
            return {"Stacks": [{"StackName": StackName, "StackStatus": "UPDATE_COMPLETE"}]}

    clients = {
        region: CloudFormation() for region in (manifest.source_region, manifest.target_region)
    }

    def client(service: str, region: str) -> Any:
        calls.append((service, region))
        return clients.get(region, object())

    monkeypatch.setattr(verifier.journal, "read_state", lambda *_a, **_k: state)
    monkeypatch.setattr(
        verifier,
        "_processed_template",
        lambda _client, name: (
            _runtime_template(),
            (
                authority.target_runtime_template_sha256
                if name == authority.target_runtime_stack_name
                else manifest.primary_runtime_template_sha256
            ),
        ),
    )
    monkeypatch.setattr(verifier, "_runtime_resources", lambda *_a, **_k: _resources())
    monkeypatch.setattr(
        verifier,
        "_verify_runtime_state",
        lambda _resources, *, fenced, **_k: {"status": "fenced" if fenced else "active"},
    )
    monkeypatch.setattr(
        verifier, "_verify_route", lambda *_a, **_k: {"recordCount": 3, "routeSha256": "c" * 64}
    )
    result = verifier.verify(
        manifest,
        authority,
        target_function_arn="arn:aws:lambda:eu-west-1:111111111111:function:handler",
        hosted_zone_id=manifest.hosted_zone_id,
        client=client,
        now=1000,
    )
    assert result["status"] == "verified-live-preconditions"
    assert result["journalRevision"] == 4
    assert len(result["evidenceSha256"]) == 64
    assert ("dynamodb", manifest.coordination_region) in calls


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("phase", "STABLE"),
        ("generation", 1),
        ("active_region", "eu-west-1"),
        ("active_transition_id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        ("authority_sha256", "0" * 64),
    ],
)
def test_stale_or_substituted_journal_state_fails_before_stack_reads(
    monkeypatch: pytest.MonkeyPatch, field: str, value: Any
) -> None:
    verifier, _ = _modules()
    manifest, authority = _authority()
    state = _state(manifest)
    changed = journal.JournalState(**{**state.__dict__, field: value})
    monkeypatch.setattr(verifier.journal, "read_state", lambda *_a, **_k: changed)
    calls: list[tuple[str, str]] = []

    def client(service: str, region: str) -> object:
        calls.append((service, region))
        return object()

    with pytest.raises(verifier.RegionalFaultPreconditionError, match="journal state differs"):
        verifier.verify(
            manifest,
            authority,
            target_function_arn="arn:aws:lambda:eu-west-1:111111111111:function:handler",
            hosted_zone_id=manifest.hosted_zone_id,
            client=client,
            now=1000,
        )
    assert calls == [("dynamodb", manifest.coordination_region)]


class IngressCloudFormation:
    """Return exact source or target ingress aliases."""

    def __init__(self, prefix: str) -> None:
        self.prefix = prefix

    def describe_stacks(self, *, StackName: str) -> dict[str, Any]:
        outputs = []
        for key, value in {
            "StableApiRegionalDomainName": f"{self.prefix}-api.execute-api.example",
            "StableApiRegionalHostedZoneId": f"Z{self.prefix.upper()}API",
            "StableUiRegionalDomainName": f"{self.prefix}-ui.execute-api.example",
            "StableUiRegionalHostedZoneId": f"Z{self.prefix.upper()}UI",
        }.items():
            outputs.append({"OutputKey": key, "OutputValue": value})
        return {
            "Stacks": [
                {
                    "StackName": StackName,
                    "StackStatus": "UPDATE_COMPLETE",
                    "Outputs": outputs,
                }
            ]
        }


class Paginator:
    """Return one bounded Route 53 page."""

    def __init__(self, records: list[dict[str, Any]]) -> None:
        self.records = records

    def paginate(self, **_kwargs: Any) -> list[dict[str, Any]]:
        return [{"ResourceRecordSets": self.records}]


class Route53:
    """Return one public hosted zone and exact record inventory."""

    def __init__(
        self,
        zone_id: str,
        records: list[dict[str, Any]],
        *,
        private: bool = False,
        zone_name: str = "security.example.com.",
    ) -> None:
        self.zone_id = zone_id
        self.records = records
        self.private = private
        self.zone_name = zone_name

    def get_hosted_zone(self, *, Id: str) -> dict[str, Any]:
        return {
            "HostedZone": {
                "Id": f"/hostedzone/{Id}",
                "Name": self.zone_name,
                "Config": {"PrivateZone": self.private},
            }
        }

    def get_paginator(self, name: str) -> Paginator:
        assert name == "list_resource_record_sets"
        return Paginator(self.records)


def _route_records(verifier: Any, manifest: Any, state: Any) -> list[dict[str, Any]]:
    source = IngressCloudFormation("source").describe_stacks(StackName="source")["Stacks"][0]
    outputs = verifier._outputs(source)
    marker_name = manifest.routing_marker_name
    assert isinstance(marker_name, str)
    return [
        verifier._alias_record(
            manifest.stable_api_domain,
            outputs["StableApiRegionalDomainName"],
            outputs["StableApiRegionalHostedZoneId"],
        ),
        verifier._alias_record(
            manifest.stable_ui_domain,
            outputs["StableUiRegionalDomainName"],
            outputs["StableUiRegionalHostedZoneId"],
        ),
        {
            "Name": f"{marker_name}.",
            "Type": "TXT",
            "TTL": 60,
            "ResourceRecords": [
                {"Value": (f'"aai-sec:v1:g={state.generation}:r={manifest.source_region}:t=none"')}
            ],
        },
    ]


def test_route_precondition_proves_stable_traffic_has_not_moved() -> None:
    verifier, _ = _modules()
    manifest, _ = _authority()
    state = _state(manifest)
    route53 = Route53(manifest.hosted_zone_id, _route_records(verifier, manifest, state))

    def client(service: str, region: str) -> Any:
        if service == "route53":
            return route53
        return IngressCloudFormation("source" if region == manifest.source_region else "target")

    result = verifier._verify_route(
        manifest, state, hosted_zone_id=manifest.hosted_zone_id, client=client
    )
    assert result["recordCount"] == 3
    assert len(result["routeSha256"]) == 64


@pytest.mark.parametrize(
    "failure",
    ["target-route", "marker", "private-zone", "wrong-zone", "wrong-zone-name"],
)
def test_route_substitution_or_early_cutover_fails_closed(failure: str) -> None:
    verifier, _ = _modules()
    manifest, _ = _authority()
    state = _state(manifest)
    records = _route_records(verifier, manifest, state)
    if failure == "target-route":
        records[0]["AliasTarget"]["DNSName"] = "target-api.execute-api.example."
        records[0]["AliasTarget"]["HostedZoneId"] = "ZTARGETAPI"
    elif failure == "marker":
        records[2]["ResourceRecords"][0]["Value"] = '"aai-sec:v1:g=1:r=eu-west-1:t=none"'
    route53 = Route53(
        manifest.hosted_zone_id,
        records,
        private=failure == "private-zone",
        zone_name=(
            "unrelated.example." if failure == "wrong-zone-name" else "security.example.com."
        ),
    )

    def client(service: str, region: str) -> Any:
        if service == "route53":
            return route53
        return IngressCloudFormation("source" if region == manifest.source_region else "target")

    with pytest.raises(verifier.RegionalFaultPreconditionError):
        verifier._verify_route(
            manifest,
            state,
            hosted_zone_id=("ZDIFFERENT" if failure == "wrong-zone" else manifest.hosted_zone_id),
            client=client,
        )
