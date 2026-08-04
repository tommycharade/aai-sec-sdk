"""Independently verify live AWS state before a Regional dependency fault.

The verifier is read-only. It repeats the single-writer journal check, binds
both runtime stacks to their reviewed processed-template digests, proves every
source execution path is fenced, proves every target path is active, and
requires stable Route 53 aliases to remain on the source. Returned evidence is
content-free and safe for the fault journal.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

from scripts import manage_aws_transition_journal as journal
from scripts import plan_aws_regional_fault_exercise as fault
from scripts import verify_aws_regional_activation as activation


class RegionalFaultPreconditionError(RuntimeError):
    """Report live state that cannot prove safe fault preconditions."""


ClientFactory = Callable[[str, str], Any]
_STACK_STABLE = {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
_RESOURCE_LIMITS = {
    "AWS::Lambda::Function": 50,
    "AWS::Lambda::EventSourceMapping": 20,
    "AWS::Events::Rule": 50,
}


def _canonical_sha256(value: object) -> str:
    """Hash one JSON-safe provider observation deterministically."""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _stack(client: Any, name: str) -> dict[str, Any]:
    """Return one exact stable stack without accepting deleted or duplicate state."""
    try:
        response = client.describe_stacks(StackName=name)
    except Exception as error:
        raise RegionalFaultPreconditionError("Regional stack is unavailable") from error
    stacks = response.get("Stacks")
    if (
        not isinstance(stacks, list)
        or len(stacks) != 1
        or not isinstance(stacks[0], dict)
        or stacks[0].get("StackName") != name
        or stacks[0].get("StackStatus") not in _STACK_STABLE
    ):
        raise RegionalFaultPreconditionError("Regional stack is not uniquely stable")
    return stacks[0]


def _processed_template(client: Any, name: str) -> tuple[dict[str, Any], str]:
    """Return and hash the exact live provider-processed CloudFormation template."""
    try:
        response = client.get_template(StackName=name, TemplateStage="Processed")
    except Exception as error:
        raise RegionalFaultPreconditionError("processed runtime template is unavailable") from error
    template = response.get("TemplateBody")
    stages = response.get("StagesAvailable")
    if (
        not isinstance(template, dict)
        or not isinstance(stages, list)
        or "Processed" not in stages
        or not isinstance(template.get("Resources"), dict)
        or not 1 <= len(template["Resources"]) <= 500
    ):
        raise RegionalFaultPreconditionError("processed runtime template is malformed")
    payload = json.dumps(template, sort_keys=True, separators=(",", ":")).encode()
    if len(payload) > 1_048_576:
        raise RegionalFaultPreconditionError("processed runtime template exceeds 1 MiB")
    return template, hashlib.sha256(payload).hexdigest()


def _runtime_resources(client: Any, name: str) -> dict[str, tuple[tuple[str, str], ...]]:
    """Discover complete bounded logical-to-physical runtime identities."""
    resources: dict[str, list[tuple[str, str]]] = {kind: [] for kind in _RESOURCE_LIMITS}
    token: str | None = None
    pages = 0
    while True:
        arguments = {"StackName": name}
        if token is not None:
            arguments["NextToken"] = token
        try:
            response = client.list_stack_resources(**arguments)
        except Exception as error:
            raise RegionalFaultPreconditionError("runtime inventory is unavailable") from error
        items = response.get("StackResourceSummaries")
        if not isinstance(items, list) or len(items) > 100:
            raise RegionalFaultPreconditionError("runtime inventory page is malformed")
        for item in items:
            if not isinstance(item, dict) or item.get("ResourceStatus", "").endswith("FAILED"):
                raise RegionalFaultPreconditionError("runtime resource state is malformed")
            kind = item.get("ResourceType")
            if kind not in resources:
                continue
            logical = item.get("LogicalResourceId")
            physical = item.get("PhysicalResourceId")
            if (
                not isinstance(logical, str)
                or not logical
                or not isinstance(physical, str)
                or not physical
                or any(logical == old[0] or physical == old[1] for old in resources[kind])
            ):
                raise RegionalFaultPreconditionError("runtime resource identity is ambiguous")
            resources[kind].append((logical, physical))
            if len(resources[kind]) > _RESOURCE_LIMITS[kind]:
                raise RegionalFaultPreconditionError("runtime resource inventory exceeds its bound")
        pages += 1
        if pages > 10:
            raise RegionalFaultPreconditionError("runtime inventory exceeds ten pages")
        next_token = response.get("NextToken")
        if next_token is None:
            break
        if not isinstance(next_token, str) or not next_token or next_token == token:
            raise RegionalFaultPreconditionError("runtime inventory pagination is malformed")
        token = next_token
    if any(not resources[kind] for kind in resources):
        raise RegionalFaultPreconditionError("runtime execution paths are incomplete")
    return {kind: tuple(sorted(values)) for kind, values in resources.items()}


def _template_properties(template: dict[str, Any], logical: str, kind: str) -> dict[str, Any]:
    """Return exact properties for one provider-discovered template resource."""
    raw = template.get("Resources", {}).get(logical)
    properties = raw.get("Properties") if isinstance(raw, dict) else None
    if (
        not isinstance(raw, dict)
        or raw.get("Type") != kind
        or not isinstance(properties, dict)
        or not all(isinstance(key, str) for key in properties)
    ):
        raise RegionalFaultPreconditionError("runtime resource differs from reviewed template")
    return {key: value for key, value in properties.items() if isinstance(key, str)}


def _verify_runtime_state(
    resources: dict[str, tuple[tuple[str, str], ...]],
    *,
    region: str,
    fenced: bool,
    client: ClientFactory,
    template: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Require source fencing or exact reviewed target execution state."""
    if not fenced and template is None:
        raise RegionalFaultPreconditionError("target runtime template is unavailable")
    lambda_client = client("lambda", region)
    events_client = client("events", region)
    for logical, name in resources["AWS::Lambda::Function"]:
        try:
            concurrency = lambda_client.get_function_concurrency(FunctionName=name)
            configuration = lambda_client.get_function_configuration(FunctionName=name)
        except Exception as error:
            raise RegionalFaultPreconditionError("runtime Lambda state is unavailable") from error
        reserved = concurrency.get("ReservedConcurrentExecutions")
        if fenced:
            if reserved != 0:
                raise RegionalFaultPreconditionError("source Lambda is not concurrency-fenced")
        else:
            assert template is not None
            properties = _template_properties(template, logical, "AWS::Lambda::Function")
            expected = properties.get("ReservedConcurrentExecutions")
            if expected is not None and (
                isinstance(expected, bool) or not isinstance(expected, int) or expected < 1
            ):
                raise RegionalFaultPreconditionError("target template Lambda is not active")
            if (
                (expected is None and "ReservedConcurrentExecutions" in concurrency)
                or (expected is not None and reserved != expected)
                or configuration.get("FunctionName") not in {None, name}
                or configuration.get("State") != "Active"
                or configuration.get("LastUpdateStatus") != "Successful"
            ):
                raise RegionalFaultPreconditionError("target Lambda differs from reviewed state")
    for logical, mapping in resources["AWS::Lambda::EventSourceMapping"]:
        try:
            response = lambda_client.get_event_source_mapping(UUID=mapping)
        except Exception as error:
            raise RegionalFaultPreconditionError(
                "event-source mapping state is unavailable"
            ) from error
        expected = "Disabled"
        if not fenced:
            assert template is not None
            properties = _template_properties(template, logical, "AWS::Lambda::EventSourceMapping")
            enabled = properties.get("Enabled", True)
            if not isinstance(enabled, bool):
                raise RegionalFaultPreconditionError("target mapping template is ambiguous")
            expected = "Enabled" if enabled else "Disabled"
        if response.get("UUID") != mapping or response.get("State") != expected:
            raise RegionalFaultPreconditionError("event-source mapping state differs")
    for logical, rule in resources["AWS::Events::Rule"]:
        try:
            response = events_client.describe_rule(Name=rule)
        except Exception as error:
            raise RegionalFaultPreconditionError("EventBridge rule state is unavailable") from error
        expected = "DISABLED"
        if not fenced:
            assert template is not None
            properties = _template_properties(template, logical, "AWS::Events::Rule")
            expected = properties.get("State", "ENABLED")
            if expected not in {"ENABLED", "DISABLED"}:
                raise RegionalFaultPreconditionError("target rule template is ambiguous")
        if response.get("Name") != rule or response.get("State") != expected:
            raise RegionalFaultPreconditionError("EventBridge rule state differs")
    return {
        "eventRuleCount": len(resources["AWS::Events::Rule"]),
        "eventSourceMappingCount": len(resources["AWS::Lambda::EventSourceMapping"]),
        "functionCount": len(resources["AWS::Lambda::Function"]),
        "resourceSetSha256": _canonical_sha256(resources),
        "status": "fenced" if fenced else "active",
    }


def _outputs(stack: dict[str, Any]) -> dict[str, str]:
    """Return exact unique string CloudFormation outputs."""
    raw = stack.get("Outputs")
    if not isinstance(raw, list) or len(raw) > 100:
        raise RegionalFaultPreconditionError("ingress outputs are malformed")
    result: dict[str, str] = {}
    for item in raw:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("OutputKey"), str)
            or not isinstance(item.get("OutputValue"), str)
            or item["OutputKey"] in result
        ):
            raise RegionalFaultPreconditionError("ingress output identity is ambiguous")
        result[item["OutputKey"]] = item["OutputValue"]
    return result


def _alias_record(name: str, dns: str, zone: str) -> dict[str, Any]:
    """Return the one supported stable Route 53 alias shape."""
    return {
        "Name": f"{name}.",
        "Type": "A",
        "AliasTarget": {
            "DNSName": f"{dns.rstrip('.')}.",
            "EvaluateTargetHealth": False,
            "HostedZoneId": zone,
        },
    }


def _records(route53: Any, zone_id: str, names: set[str]) -> dict[tuple[str, str], dict[str, Any]]:
    """Read a bounded complete hosted-zone inventory for the three authority names."""
    selected: dict[tuple[str, str], dict[str, Any]] = {}
    paginator = route53.get_paginator("list_resource_record_sets")
    count = 0
    try:
        pages = paginator.paginate(HostedZoneId=zone_id, PaginationConfig={"MaxItems": 10_000})
        page_count = 0
        for page in pages:
            page_count += 1
            if page_count > 34:
                raise RegionalFaultPreconditionError("Route 53 inventory exceeds 34 pages")
            items = page.get("ResourceRecordSets")
            if not isinstance(items, list) or len(items) > 300:
                raise RegionalFaultPreconditionError("Route 53 record page is malformed")
            for item in items:
                count += 1
                if count > 10_000:
                    raise RegionalFaultPreconditionError("Route 53 inventory exceeds its bound")
                if not isinstance(item, dict) or item.get("Name") not in names:
                    continue
                if item.get("Type") not in {"A", "TXT"}:
                    raise RegionalFaultPreconditionError("routing name has an unsupported record")
                key = (item["Name"], item["Type"])
                if key in selected:
                    raise RegionalFaultPreconditionError("routing record is duplicated")
                selected[key] = item
    except RegionalFaultPreconditionError:
        raise
    except Exception as error:
        raise RegionalFaultPreconditionError("Route 53 inventory is unavailable") from error
    return selected


def _verify_route(
    manifest: activation.ActivationManifest,
    state: journal.JournalState,
    *,
    hosted_zone_id: str,
    client: ClientFactory,
) -> dict[str, Any]:
    """Prove stable aliases and generation marker remain on the fenced source."""
    if hosted_zone_id != manifest.hosted_zone_id:
        raise RegionalFaultPreconditionError("hosted-zone deployment authority differs")
    if manifest.direction == "failover":
        source_stack, target_stack = (
            manifest.primary_ingress_stack_name,
            manifest.recovery_ingress_stack_name,
        )
    else:
        source_stack, target_stack = (
            manifest.recovery_ingress_stack_name,
            manifest.primary_ingress_stack_name,
        )
    if not isinstance(source_stack, str) or not isinstance(target_stack, str):
        raise RegionalFaultPreconditionError("ingress stack authority is incomplete")
    source = _outputs(_stack(client("cloudformation", manifest.source_region), source_stack))
    target = _outputs(_stack(client("cloudformation", manifest.target_region), target_stack))
    required = {
        "StableApiRegionalDomainName",
        "StableApiRegionalHostedZoneId",
        "StableUiRegionalDomainName",
        "StableUiRegionalHostedZoneId",
    }
    if not required <= set(source) or not required <= set(target):
        raise RegionalFaultPreconditionError("ingress alias authority is incomplete")
    source_records = {
        (f"{manifest.stable_api_domain}.", "A"): _alias_record(
            manifest.stable_api_domain,
            source["StableApiRegionalDomainName"],
            source["StableApiRegionalHostedZoneId"],
        ),
        (f"{manifest.stable_ui_domain}.", "A"): _alias_record(
            manifest.stable_ui_domain,
            source["StableUiRegionalDomainName"],
            source["StableUiRegionalHostedZoneId"],
        ),
    }
    target_records = {
        (f"{manifest.stable_api_domain}.", "A"): _alias_record(
            manifest.stable_api_domain,
            target["StableApiRegionalDomainName"],
            target["StableApiRegionalHostedZoneId"],
        ),
        (f"{manifest.stable_ui_domain}.", "A"): _alias_record(
            manifest.stable_ui_domain,
            target["StableUiRegionalDomainName"],
            target["StableUiRegionalHostedZoneId"],
        ),
    }
    if source_records == target_records:
        raise RegionalFaultPreconditionError("source and target ingress aliases are not distinct")
    marker_name = manifest.routing_marker_name
    if not isinstance(marker_name, str):
        raise RegionalFaultPreconditionError("routing marker authority is unavailable")
    transition = state.last_completed_transition_id or "none"
    marker = {
        "Name": f"{marker_name}.",
        "Type": "TXT",
        "TTL": 60,
        "ResourceRecords": [
            {
                "Value": (
                    f'"aai-sec:v1:g={state.generation}:r={manifest.source_region}:t={transition}"'
                )
            }
        ],
    }
    route53 = client("route53", manifest.primary_region)
    try:
        zone = route53.get_hosted_zone(Id=hosted_zone_id).get("HostedZone")
    except Exception as error:
        raise RegionalFaultPreconditionError("hosted zone is unavailable") from error
    if (
        not isinstance(zone, dict)
        or zone.get("Id") not in {hosted_zone_id, f"/hostedzone/{hosted_zone_id}"}
        or zone.get("Config", {}).get("PrivateZone") is not False
        or not isinstance(zone.get("Name"), str)
    ):
        raise RegionalFaultPreconditionError("hosted-zone authority differs")
    zone_name = zone["Name"].rstrip(".").lower()
    authority_names = (
        manifest.stable_api_domain,
        manifest.stable_ui_domain,
        marker_name,
    )
    if not zone_name or any(
        name.lower() != zone_name and not name.lower().endswith(f".{zone_name}")
        for name in authority_names
    ):
        raise RegionalFaultPreconditionError("routing names are outside the hosted zone")
    names = {f"{manifest.stable_api_domain}.", f"{manifest.stable_ui_domain}.", f"{marker_name}."}
    observed = _records(route53, hosted_zone_id, names)
    expected: dict[tuple[str, str], dict[str, Any]] = {
        **source_records,
        (f"{marker_name}.", "TXT"): marker,
    }
    if observed != expected or any(
        observed.get(key) == value for key, value in target_records.items()
    ):
        raise RegionalFaultPreconditionError("stable routing is not exclusively on the source")
    return {
        "recordCount": 3,
        "routeSha256": _canonical_sha256([observed[key] for key in sorted(observed)]),
    }


def verify(
    manifest: activation.ActivationManifest,
    authority: fault.RegionalFaultAuthority,
    *,
    target_function_arn: str,
    hosted_zone_id: str,
    client: ClientFactory,
    now: int,
) -> dict[str, Any]:
    """Verify all live preconditions and return content-free evidence."""
    try:
        state = journal.read_state(client("dynamodb", authority.coordination_region), manifest)
    except journal.TransitionJournalError as error:
        raise RegionalFaultPreconditionError("transition journal cannot prove authority") from error
    if (
        state.phase != "TARGET_ACTIVE_NOT_ROUTED"
        or state.generation != authority.expected_routing_generation
        or state.active_region != manifest.source_region
        or state.active_transition_id != authority.transition_id
        or state.authority_sha256 != authority.transition_authority_sha256
        or state.approval_sha256 != authority.approval_sha256
        or state.source_region != manifest.source_region
        or state.target_region != authority.target_region
        or state.expires_at != manifest.expires_at
        or now >= authority.expires_at
    ):
        raise RegionalFaultPreconditionError(
            "transition journal state differs from fault authority"
        )
    source_stack = (
        manifest.primary_runtime_stack_name
        if manifest.direction == "failover"
        else manifest.recovery_runtime_stack_name
    )
    target_stack = authority.target_runtime_stack_name
    source_digest = (
        manifest.primary_runtime_template_sha256
        if manifest.direction == "failover"
        else manifest.recovery_runtime_template_sha256
    )
    if not isinstance(source_stack, str) or not isinstance(source_digest, str):
        raise RegionalFaultPreconditionError("source runtime authority is incomplete")
    source_cfn = client("cloudformation", manifest.source_region)
    target_cfn = client("cloudformation", manifest.target_region)
    _stack(source_cfn, source_stack)
    _stack(target_cfn, target_stack)
    _source_template, observed_source_digest = _processed_template(source_cfn, source_stack)
    target_template, observed_target_digest = _processed_template(target_cfn, target_stack)
    if observed_source_digest != source_digest:
        raise RegionalFaultPreconditionError("source runtime template changed after approval")
    if observed_target_digest != authority.target_runtime_template_sha256:
        raise RegionalFaultPreconditionError("target runtime template changed after approval")
    source_resources = _runtime_resources(source_cfn, source_stack)
    target_resources = _runtime_resources(target_cfn, target_stack)
    if target_function_arn.rsplit(":", 1)[-1] not in {
        physical for _, physical in target_resources["AWS::Lambda::Function"]
    }:
        raise RegionalFaultPreconditionError("target probe function differs from runtime stack")
    source = _verify_runtime_state(
        source_resources, region=manifest.source_region, fenced=True, client=client
    )
    target = _verify_runtime_state(
        target_resources,
        region=manifest.target_region,
        fenced=False,
        client=client,
        template=target_template,
    )
    route = _verify_route(manifest, state, hosted_zone_id=hosted_zone_id, client=client)
    evidence = {
        "journalRevision": state.revision,
        "routing": route,
        "source": source,
        "target": target,
    }
    return {
        "schemaVersion": 1,
        "status": "verified-live-preconditions",
        "evidenceSha256": _canonical_sha256(evidence),
        "journalRevision": state.revision,
    }
