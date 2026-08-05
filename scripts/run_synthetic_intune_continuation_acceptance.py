"""Run deterministic synthetic acceptance for bounded Intune continuation.

This harness executes the production Lambda handler and its production page,
prune, assignment, and continuation logic. AWS and Microsoft Graph are replaced
with an in-memory contract implementation, so the result proves deterministic
control behavior rather than live-provider compatibility or production
capacity. No network request, credential read, or persistent cloud mutation is
possible from this module.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import types
import uuid
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_WORKER_PATH = _PROJECT_ROOT / "infra/aws-control-plane/lambda/intune_delivery_worker.py"
_COMMAND_ID = "a" * 64
_TENANT_ID = "synthetic-tenant"


class SyntheticAcceptanceError(RuntimeError):
    """Report a failed acceptance invariant without exposing provider content."""


class _RejectingAwsClient:
    """Reject any AWS call not explicitly replaced by the synthetic harness."""

    def __getattr__(self, name: str) -> Any:
        """Fail closed if production code reaches an unexpected AWS operation."""
        raise SyntheticAcceptanceError(f"unexpected synthetic AWS operation: {name}")


def _load_worker() -> Any:
    """Load the production worker with network-incapable synthetic AWS clients."""
    rejecting = _RejectingAwsClient()
    boto3 = types.ModuleType("boto3")
    boto3.resource = lambda _name: types.SimpleNamespace(  # type: ignore[attr-defined]
        Table=lambda _table: rejecting
    )
    boto3.client = lambda _name: rejecting  # type: ignore[attr-defined]
    dynamodb = types.ModuleType("boto3.dynamodb")
    conditions = types.ModuleType("boto3.dynamodb.conditions")
    conditions.Key = lambda name: types.SimpleNamespace(  # type: ignore[attr-defined]
        eq=lambda value: (name, value)
    )
    previous = {
        name: sys.modules.get(name)
        for name in ("boto3", "boto3.dynamodb", "boto3.dynamodb.conditions")
    }
    sys.modules["boto3"] = boto3
    sys.modules["boto3.dynamodb"] = dynamodb
    sys.modules["boto3.dynamodb.conditions"] = conditions
    previous_control_table = os.environ.get("CONTROL_TABLE")
    os.environ["CONTROL_TABLE"] = "synthetic-control-table"
    try:
        spec = importlib.util.spec_from_file_location(
            "aai_synthetic_intune_delivery_worker", _WORKER_PATH
        )
        if spec is None or spec.loader is None:
            raise SyntheticAcceptanceError("production worker could not be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
        if previous_control_table is None:
            os.environ.pop("CONTROL_TABLE", None)
        else:
            os.environ["CONTROL_TABLE"] = previous_control_table


def _canonical_uuid(index: int) -> str:
    """Return a deterministic canonical UUID for synthetic provider identity."""
    return str(uuid.uuid5(uuid.NAMESPACE_OID, f"aai-synthetic:{index}"))


def _command_instruction(target_count: int) -> dict[str, object]:
    """Build one complete sealed production command with exact 40-target pages."""
    counts = [40] * (target_count // 40)
    if target_count % 40:
        counts.append(target_count % 40)
    pages = [
        {
            "id": hashlib.sha256(f"page-id:{index}".encode()).hexdigest(),
            "pageDigest": hashlib.sha256(f"page:{index}:{count}".encode()).hexdigest(),
            "targetCount": count,
        }
        for index, count in enumerate(counts)
    ]
    digests = [hashlib.sha256(f"field:{index}".encode()).hexdigest() for index in range(11)]
    return {
        "schemaVersion": 1,
        "provider": "intune",
        "providerVersion": 1,
        "providerContentHash": digests[0],
        "deploymentId": "synthetic-deployment",
        "host": "claude-code",
        "releaseId": "synthetic-release",
        "packageId": "synthetic-package",
        "packageManifestSha256": digests[1],
        "packageObjectSha256": digests[2],
        "packageStorageIdentitySha256": digests[3],
        "providerPackageIdentitySha256": digests[4],
        "packageSignatureEvidenceSha256": digests[5],
        "packageApproverEvidenceSha256": digests[6],
        "releaseEvidenceSha256": digests[7],
        "packageBundleSha256": digests[8],
        "packageApprovalBundleSha256": digests[9],
        "rolloutRevision": 1,
        "rolloutState": "canary",
        "targetCount": target_count,
        "cohortDigest": digests[10],
        "pages": pages,
    }


def run_acceptance(target_count: int = 500, stale_member_count: int = 81) -> dict[str, object]:
    """Execute and verify one bounded synthetic continuation scenario.

    Args:
        target_count: Exact desired cohort, restricted to the continuation path.
        stale_member_count: Existing non-desired group members to remove.

    Returns:
        Content-minimised evidence containing only counts, fixed states, and a
        digest of the synthetic scenario.

    Raises:
        ValueError: If the requested synthetic bounds are invalid.
        SyntheticAcceptanceError: If any security or convergence invariant fails.

    Security:
        The harness denies all unconfigured AWS calls and replaces Graph before
        enabling the production worker. Its evidence never contains raw device,
        directory-object, group, app, assignment, or credential identifiers.
    """
    if isinstance(target_count, bool) or not 41 <= target_count <= 500:
        raise ValueError("synthetic target count must be between 41 and 500")
    if isinstance(stale_member_count, bool) or not 0 <= stale_member_count <= 500:
        raise ValueError("synthetic stale-member count must be between 0 and 500")

    worker = _load_worker()
    previous_environment = {
        name: os.environ.get(name)
        for name in (
            "ENDPOINT_DELIVERY_DISPATCH_ENABLED",
            "ENDPOINT_DELIVERY_ENABLEMENT_EVIDENCE_SHA256",
        )
    }
    os.environ["ENDPOINT_DELIVERY_DISPATCH_ENABLED"] = "true"
    os.environ["ENDPOINT_DELIVERY_ENABLEMENT_EVIDENCE_SHA256"] = "f" * 64
    try:
        instruction = _command_instruction(target_count)
        targets = [
            {"directoryDeviceRegistrationId": _canonical_uuid(index + 1)}
            for index in range(target_count)
        ]
        target_objects = {
            target["directoryDeviceRegistrationId"]: _canonical_uuid(10_000 + index)
            for index, target in enumerate(targets)
        }
        stale_objects = {
            _canonical_uuid(20_000 + index): None for index in range(stale_member_count)
        }
        members: dict[str, str | None] = dict(stale_objects)
        command: dict[str, object] = {
            "id": _COMMAND_ID,
            "status": "queued",
            "attempt_count": 0,
            "instruction": instruction,
            "continuation_revision": 0,
            "continuation_stage": "resolving_pages",
            "continuation_page": 0,
            "continuation_completed_targets": 0,
            "continuation_mutation_count": 0,
            "target_count": target_count,
        }
        authority_reloads = 0
        membership_additions = 0
        membership_removals = 0
        assignment_mutations = 0
        assigned = False
        continuation_messages: list[dict[str, object]] = []
        audit_records: list[dict[str, object]] = []
        invocation_mutations: list[int] = []
        handler_results: list[dict[str, object]] = []

        def load_authority(_tenant: str, _command_id: str) -> tuple[object, object, object]:
            """Reproduce current complete authority for every synthetic reload."""
            nonlocal authority_reloads
            authority_reloads += 1
            return command, {}, targets

        def transition(value: dict[str, object], **kwargs: object) -> dict[str, object]:
            """Apply the production state transition contract in memory."""
            continuation = kwargs.get("continuation")
            if continuation is not None and not isinstance(continuation, dict):
                raise SyntheticAcceptanceError("continuation transition was not typed")
            command.update(value)
            command.update(
                {
                    "status": kwargs["status"],
                    "attempt_count": kwargs["attempt"],
                    "failure_code": kwargs.get("reason"),
                    "provider_evidence": kwargs.get("evidence"),
                    **(continuation or {}),
                }
            )
            return dict(command)

        def request(method: str, url: str, **kwargs: object) -> tuple[int, dict[str, object]]:
            """Implement only the exact Graph mutations allowed by the worker."""
            nonlocal membership_additions, membership_removals, assignment_mutations, assigned
            if method == "POST" and url.endswith("/members/$ref"):
                body = kwargs.get("body")
                if not isinstance(body, dict) or set(body) != {"@odata.id"}:
                    raise SyntheticAcceptanceError("membership mutation body widened")
                object_id = str(body["@odata.id"]).rsplit("/", 1)[-1]
                registrations = [
                    registration
                    for registration, expected_object in target_objects.items()
                    if expected_object == object_id
                ]
                if len(registrations) != 1:
                    raise SyntheticAcceptanceError("membership mutation target was not sealed")
                members[object_id] = registrations[0]
                membership_additions += 1
                return 204, {}
            if method == "DELETE" and "/members/" in url and url.endswith("/$ref"):
                object_id = url.rsplit("/members/", 1)[1].removesuffix("/$ref")
                if object_id not in members:
                    raise SyntheticAcceptanceError("unknown membership removal")
                members.pop(object_id)
                membership_removals += 1
                return 204, {}
            if method == "POST" and url.endswith("/assignments"):
                assigned = True
                assignment_mutations += 1
                return 204, {}
            raise SyntheticAcceptanceError(f"unexpected synthetic Graph operation: {method}")

        def collection(url: str, _token: str) -> list[dict[str, object]]:
            """Return only the exact assignment collection requested by production code."""
            if not url.endswith("?$select=id,intent,target"):
                raise SyntheticAcceptanceError("unexpected synthetic Graph collection")
            if not assigned:
                return []
            return [
                {
                    "id": _canonical_uuid(30_000),
                    "intent": "required",
                    "target": {"groupId": _canonical_uuid(40_000)},
                }
            ]

        worker._load_authority = load_authority
        worker._credentials = lambda *_args: {}
        worker._provider_context = lambda *_args: (
            "synthetic-memory-token",
            _canonical_uuid(40_000),
            _canonical_uuid(50_000),
        )
        worker._group_member_inventory = lambda *_args: sorted(members.items())
        worker._resolve_directory_target = lambda target, _token: (
            target_objects[target["directoryDeviceRegistrationId"]],
            target["directoryDeviceRegistrationId"],
        )
        worker._request = request
        worker._collection = collection
        worker._transition = transition
        worker._enqueue_continuation = lambda tenant, command_id, revision: (
            continuation_messages.append(
                {"tenantId": tenant, "commandId": command_id, "continuationRevision": revision}
            )
        )
        worker._audit_terminal = lambda _tenant, value: audit_records.append(
            {
                "status": value.get("status"),
                "targetCount": value.get("target_count"),
                "continuationRevision": value.get("continuation_revision"),
                "continuationStage": value.get("continuation_stage"),
                "completedTargets": value.get("continuation_completed_targets"),
                "mutationCount": value.get("continuation_mutation_count"),
                "providerEvidence": value.get("provider_evidence"),
            }
        )

        revision = 0
        while True:
            before = membership_additions + membership_removals + assignment_mutations
            result = worker.handler(
                {
                    "Records": [
                        {
                            "eventSource": "aws:sqs",
                            "body": json.dumps(
                                {
                                    "tenantId": _TENANT_ID,
                                    "commandId": _COMMAND_ID,
                                    "continuationRevision": revision,
                                }
                            ),
                            "attributes": {"ApproximateReceiveCount": "1"},
                        }
                    ]
                },
                None,
            )
            handler_results.append(result)
            invocation_mutations.append(
                membership_additions + membership_removals + assignment_mutations - before
            )
            if result.get("status") == "assigned_reported":
                break
            if result.get("status") != "continuing":
                raise SyntheticAcceptanceError("continuation did not converge")
            revision = int(result["continuationRevision"])
            if len(handler_results) > 64:
                raise SyntheticAcceptanceError("continuation exceeded its revision bound")

        expected_registrations = set(target_objects)
        observed_registrations = {value for value in members.values() if value is not None}
        projected = json.dumps(
            {"results": handler_results, "messages": continuation_messages, "audit": audit_records},
            sort_keys=True,
        )
        raw_identifiers = [*target_objects, *target_objects.values(), *stale_objects]
        invariants = {
            "exactMembership": observed_registrations == expected_registrations
            and len(members) == target_count,
            "allTargetsAdded": membership_additions == target_count,
            "allStaleMembersRemoved": membership_removals == stale_member_count,
            "singleRequiredAssignment": assignment_mutations == 1 and assigned,
            "boundedMutationsPerInvocation": max(invocation_mutations, default=0) <= 40,
            "terminalEvidenceOnce": len(audit_records) == 1,
            "completeProgress": command.get("continuation_completed_targets") == target_count
            and command.get("continuation_stage") == "complete",
            "opaqueContinuations": all(
                set(message) == {"tenantId", "commandId", "continuationRevision"}
                for message in continuation_messages
            ),
            "noRawProviderIdentifiersProjected": not any(
                identifier in projected for identifier in raw_identifiers
            ),
        }
        if not all(invariants.values()):
            failed = sorted(name for name, passed in invariants.items() if not passed)
            raise SyntheticAcceptanceError(f"synthetic acceptance failed: {','.join(failed)}")
        pages = instruction["pages"]
        if not isinstance(pages, list):
            raise SyntheticAcceptanceError("sealed pages were not typed")
        scenario = {
            "targetCount": target_count,
            "staleMemberCount": stale_member_count,
            "pageSize": 40,
            "pageCount": len(pages),
        }
        return {
            "schemaVersion": 1,
            "evidenceKind": "synthetic_intune_continuation",
            "provider": "intune",
            "liveProviderAcceptance": False,
            **scenario,
            "invocationCount": len(handler_results),
            "continuationCount": len(continuation_messages),
            "authorityReloadCount": authority_reloads,
            "membershipAdditionCount": membership_additions,
            "membershipRemovalCount": membership_removals,
            "assignmentMutationCount": assignment_mutations,
            "maximumObservedMutationsPerInvocation": max(invocation_mutations, default=0),
            "terminalStatus": command["status"],
            "continuationRevision": command["continuation_revision"],
            "invariants": invariants,
            "scenarioSha256": hashlib.sha256(
                json.dumps(scenario, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "limitations": [
                "in_memory_graph_contract",
                "no_live_microsoft_tenant",
                "no_network_or_cloud_capacity_measurement",
                "provider_assignment_is_not_runtime_attestation",
            ],
        }
    finally:
        for name, value in previous_environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _write_evidence(path: Path, encoded: str) -> None:
    """Atomically persist content-minimised evidence with mode ``0600``."""
    resolved = path.expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{resolved.name}.", dir=resolved.parent)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, resolved)
        os.chmod(resolved, 0o600)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main() -> int:
    """Run the bounded scenario and optionally write mode-0600 JSON evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-count", type=int, default=500)
    parser.add_argument("--stale-member-count", type=int, default=81)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    evidence = run_acceptance(args.target_count, args.stale_member_count)
    encoded = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        _write_evidence(args.output, encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
