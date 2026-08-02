"""Adversarial contracts for transition-witness infrastructure."""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest


def _load() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "verify_transition_journal_stack.py"
    spec = importlib.util.spec_from_file_location("aai_verify_transition_journal", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _template() -> dict[str, Any]:
    return {
        "Resources": {
            "Key": {
                "Type": "AWS::KMS::Key",
                "Properties": {"EnableKeyRotation": True, "PendingWindowInDays": 30},
                "DeletionPolicy": "Retain",
                "UpdateReplacePolicy": "Retain",
            },
            "Alias": {"Type": "AWS::KMS::Alias", "Properties": {}},
            "Journal": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": "AaiSecRegionalTransitionJournal",
                    "BillingMode": "PAY_PER_REQUEST",
                    "DeletionProtectionEnabled": True,
                    "KeySchema": [
                        {"AttributeName": "pk", "KeyType": "HASH"},
                        {"AttributeName": "sk", "KeyType": "RANGE"},
                    ],
                    "AttributeDefinitions": [
                        {"AttributeName": "pk", "AttributeType": "S"},
                        {"AttributeName": "sk", "AttributeType": "S"},
                    ],
                    "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
                    "SSESpecification": {
                        "SSEEnabled": True,
                        "SSEType": "KMS",
                        "KMSMasterKeyId": {"Fn::GetAtt": ["Key", "Arn"]},
                    },
                    "Tags": [
                        {
                            "Key": "aai-sec:purpose",
                            "Value": "regional-transition-single-writer-witness",
                        },
                        {"Key": "aai-sec:replicated", "Value": "false"},
                    ],
                },
                "DeletionPolicy": "Retain",
                "UpdateReplacePolicy": "Retain",
            },
        },
        "Outputs": {"TransitionJournalStatus": {"Value": "uninitialized-single-writer-witness"}},
    }


def test_complete_witness_is_single_writer_retained_and_uninitialized() -> None:
    module = _load()
    assert module.verify(_template(), expected_table_name="AaiSecRegionalTransitionJournal") == {
        "status": "verified-uninitialized-single-writer-witness",
        "tableName": "AaiSecRegionalTransitionJournal",
        "customerManagedKeyCount": 1,
        "replicaCount": 0,
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["Resources"]["Journal"]["Properties"].update(
                {"Replicas": [{"Region": "eu-west-1"}]}
            ),
            "replicated",
        ),
        (
            lambda value: value["Resources"]["Journal"]["Properties"].update(
                {"DeletionProtectionEnabled": False}
            ),
            "unprotected",
        ),
        (
            lambda value: value["Resources"]["Journal"]["Properties"].pop("SSESpecification"),
            "table encryption",
        ),
        (
            lambda value: value["Resources"]["Key"]["Properties"].update(
                {"EnableKeyRotation": False}
            ),
            "lifecycle",
        ),
        (
            lambda value: value["Resources"].update(
                {"Function": {"Type": "AWS::Lambda::Function", "Properties": {}}}
            ),
            "unexpected resources",
        ),
        (
            lambda value: value["Outputs"].update({"JournalEndpoint": {"Value": "unsafe"}}),
            "advertises execution",
        ),
    ],
)
def test_witness_rejects_replication_weakening_or_runtime_authority(
    mutation: Any, message: str
) -> None:
    module = _load()
    value = copy.deepcopy(_template())
    mutation(value)
    with pytest.raises(module.TransitionJournalStackVerificationError, match=message):
        module.verify(value, expected_table_name="AaiSecRegionalTransitionJournal")


def test_stack_source_requires_three_distinct_regions_and_no_global_table() -> None:
    source = (
        Path(__file__).parents[1]
        / "infra/aws-control-plane/lib/regional-transition-journal-stack.ts"
    ).read_text(encoding="utf-8")
    assert (
        "new Set([witnessRegion, props.primaryRegion, props.recoveryRegion]).size !== 3" in source
    )
    assert "pointInTimeRecoveryEnabled: true" in source
    assert "deletionProtection: true" in source
    assert "replicationRegions" not in source
