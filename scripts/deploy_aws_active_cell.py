#!/usr/bin/env python3
"""Fence the source or deploy a verified active-but-not-routed recovery cell.

Every command repeats the live regional-activation preflight. Mutating commands
require a separate operator confirmation, and this module intentionally has no
DNS, CloudFront, Route 53, Global Accelerator, or traffic-routing operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts import deploy_aws_control_plane as control_plane  # noqa: E402
from scripts import deploy_aws_evidence_continuity as continuity  # noqa: E402
from scripts import deploy_aws_passive_cell as passive  # noqa: E402
from scripts import manage_aws_regional_recovery as recovery  # noqa: E402
from scripts import manage_aws_transition_journal as journal  # noqa: E402
from scripts import plan_aws_regional_activation as preflight  # noqa: E402
from scripts import verify_active_regional_cell as active_verifier  # noqa: E402
from scripts import verify_aws_regional_activation as activation  # noqa: E402


class ActiveCellDeploymentError(RuntimeError):
    """Report state that cannot prove a safe, bounded transition step."""


Runner = Callable[..., subprocess.CompletedProcess[str]]
Clock = Callable[[], float]
Sleeper = Callable[[float], None]
_RESOURCE_LIMITS = {
    "AWS::Lambda::Function": 50,
    "AWS::Lambda::EventSourceMapping": 20,
    "AWS::Events::Rule": 50,
}
_STACK_STABLE = {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
_ACCOUNT = re.compile(r"^\d{12}$")
_LAMBDA_CODE_SHA256 = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_REVISION_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SourceResources:
    """Exact provider-discovered source resources covered by one fence step."""

    functions: tuple[str, ...]
    event_source_mappings: tuple[str, ...]
    event_rules: tuple[str, ...]

    def canonical_json(self) -> str:
        """Return a deterministic representation used to bind fence evidence."""
        return json.dumps(
            {
                "eventRules": list(self.event_rules),
                "eventSourceMappings": list(self.event_source_mappings),
                "functions": list(self.functions),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def sha256(self) -> str:
        """Return the digest of the exact source resource set."""
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()


@dataclass(frozen=True)
class TargetResources:
    """Exact provider-discovered recovery runtime used for readiness checks."""

    handler: str
    workers: tuple[str, str]
    event_source_mappings: tuple[str, str]
    event_rules: tuple[str, str, str, str]

    def canonical_json(self) -> str:
        """Return the deterministic target resource identity set."""
        return json.dumps(
            {
                "eventRules": list(self.event_rules),
                "eventSourceMappings": list(self.event_source_mappings),
                "handler": self.handler,
                "workers": list(self.workers),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def sha256(self) -> str:
        """Return the target resource-set digest retained with readiness evidence."""
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()


def _aws(
    arguments: Sequence[str],
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Use the bounded AWS command boundary and normalize provider failures."""
    try:
        return recovery._aws(arguments, profile=profile, region=region, runner=runner)
    except recovery.RecoveryConfigurationError as error:
        raise ActiveCellDeploymentError(str(error)) from error


def discover_source_resources(
    regional: recovery.RegionalRecoveryManifest,
    *,
    stack_name: str | None = None,
    source_region: str | None = None,
    profile: str,
    runner: Runner = subprocess.run,
) -> SourceResources:
    """Discover a stable source stack and its complete bounded fence surface."""
    selected_stack = regional.stack_name if stack_name is None else stack_name
    selected_region = regional.primary_region if source_region is None else source_region
    stack = _aws(
        ["cloudformation", "describe-stacks", "--stack-name", selected_stack],
        profile=profile,
        region=selected_region,
        runner=runner,
    ).get("Stacks")
    if (
        not isinstance(stack, list)
        or len(stack) != 1
        or not isinstance(stack[0], dict)
        or stack[0].get("StackStatus") not in _STACK_STABLE
    ):
        raise ActiveCellDeploymentError("source stack is not stable")

    found: dict[str, list[str]] = {kind: [] for kind in _RESOURCE_LIMITS}
    token: str | None = None
    pages = 0
    while True:
        command = [
            "cloudformation",
            "list-stack-resources",
            "--stack-name",
            selected_stack,
        ]
        if token is not None:
            command.extend(["--next-token", token])
        response = _aws(
            command,
            profile=profile,
            region=selected_region,
            runner=runner,
        )
        pages += 1
        if pages > 10:
            raise ActiveCellDeploymentError("source resource discovery exceeded 10 pages")
        summaries = response.get("StackResourceSummaries")
        if not isinstance(summaries, list) or len(summaries) > 100:
            raise ActiveCellDeploymentError("source stack resources are malformed")
        for item in summaries:
            if not isinstance(item, dict):
                raise ActiveCellDeploymentError("source stack resource is malformed")
            kind = item.get("ResourceType")
            if kind not in found:
                continue
            physical_id = item.get("PhysicalResourceId")
            if not isinstance(physical_id, str) or not 1 <= len(physical_id) <= 512:
                raise ActiveCellDeploymentError("source fence resource identity is malformed")
            found[kind].append(physical_id)
            if len(found[kind]) > _RESOURCE_LIMITS[kind]:
                raise ActiveCellDeploymentError(f"source fence exceeds the {kind} resource bound")
        next_token = response.get("NextToken")
        if next_token is None:
            break
        if not isinstance(next_token, str) or not next_token or next_token == token:
            raise ActiveCellDeploymentError("source resource pagination is malformed")
        token = next_token

    if not found["AWS::Lambda::Function"]:
        raise ActiveCellDeploymentError("source stack has no Lambda functions to fence")
    if any(len(values) != len(set(values)) for values in found.values()):
        raise ActiveCellDeploymentError("source fence resource identities are duplicated")
    return SourceResources(
        tuple(sorted(found["AWS::Lambda::Function"])),
        tuple(sorted(found["AWS::Lambda::EventSourceMapping"])),
        tuple(sorted(found["AWS::Events::Rule"])),
    )


def discover_target_resources(
    *,
    stack_name: str,
    target_region: str,
    profile: str,
    runner: Runner = subprocess.run,
) -> TargetResources:
    """Discover the exact stable active-not-routed recovery runtime."""
    stack_response = _aws(
        ["cloudformation", "describe-stacks", "--stack-name", stack_name],
        profile=profile,
        region=target_region,
        runner=runner,
    )
    stacks = stack_response.get("Stacks")
    if (
        not isinstance(stacks, list)
        or len(stacks) != 1
        or not isinstance(stacks[0], dict)
        or stacks[0].get("StackStatus") not in _STACK_STABLE
    ):
        raise ActiveCellDeploymentError("target stack is not stable")
    try:
        status = passive._stack_output(stack_response, "PassiveCellStatus")
    except passive.PassiveCellDeploymentError as error:
        raise ActiveCellDeploymentError(str(error)) from error
    if status != "active-not-routed":
        raise ActiveCellDeploymentError("target stack is not active-not-routed")

    functions: dict[str, str] = {}
    mappings: list[str] = []
    rules: list[str] = []
    token: str | None = None
    for _page in range(1, 11):
        command = ["cloudformation", "list-stack-resources", "--stack-name", stack_name]
        if token is not None:
            command.extend(["--next-token", token])
        response = _aws(
            command,
            profile=profile,
            region=target_region,
            runner=runner,
        )
        summaries = response.get("StackResourceSummaries")
        if not isinstance(summaries, list) or len(summaries) > 100:
            raise ActiveCellDeploymentError("target stack resources are malformed")
        for item in summaries:
            if not isinstance(item, dict):
                raise ActiveCellDeploymentError("target stack resource is malformed")
            kind = item.get("ResourceType")
            logical = item.get("LogicalResourceId")
            physical = item.get("PhysicalResourceId")
            if kind not in {
                "AWS::Lambda::Function",
                "AWS::Lambda::EventSourceMapping",
                "AWS::Events::Rule",
            }:
                continue
            if (
                not isinstance(logical, str)
                or not logical
                or not isinstance(physical, str)
                or not 1 <= len(physical) <= 512
            ):
                raise ActiveCellDeploymentError("target runtime identity is malformed")
            if kind == "AWS::Lambda::Function":
                if logical.startswith("PassiveControlPlaneHandler"):
                    role = "handler"
                elif logical.startswith("PassiveEvidenceWorker"):
                    role = "evidence-worker"
                elif logical.startswith("PassiveRetentionWorker"):
                    role = "retention-worker"
                else:
                    raise ActiveCellDeploymentError("target contains an unknown Lambda function")
                if role in functions:
                    raise ActiveCellDeploymentError("target Lambda role is duplicated")
                functions[role] = physical
            elif kind == "AWS::Lambda::EventSourceMapping":
                mappings.append(physical)
            else:
                rules.append(physical)
        next_token = response.get("NextToken")
        if next_token is None:
            break
        if not isinstance(next_token, str) or not next_token or next_token == token:
            raise ActiveCellDeploymentError("target resource pagination is malformed")
        token = next_token
    else:
        raise ActiveCellDeploymentError("target resource discovery exceeded 10 pages")
    if (
        set(functions) != {"handler", "evidence-worker", "retention-worker"}
        or len(mappings) != 2
        or len(set(mappings)) != 2
        or len(rules) != 4
        or len(set(rules)) != 4
    ):
        raise ActiveCellDeploymentError("target runtime resource set is incomplete or ambiguous")
    ordered_mappings = sorted(mappings)
    ordered_rules = sorted(rules)
    return TargetResources(
        functions["handler"],
        (functions["evidence-worker"], functions["retention-worker"]),
        (ordered_mappings[0], ordered_mappings[1]),
        (ordered_rules[0], ordered_rules[1], ordered_rules[2], ordered_rules[3]),
    )


def verify_source_fence(
    resources: SourceResources,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Independently prove every discovered source execution path is disabled."""
    for rule in resources.event_rules:
        state = _aws(
            ["events", "describe-rule", "--name", rule],
            profile=profile,
            region=region,
            runner=runner,
        ).get("State")
        if state != "DISABLED":
            raise ActiveCellDeploymentError(f"source EventBridge rule is not disabled: {rule}")
    for mapping in resources.event_source_mappings:
        response = _aws(
            ["lambda", "get-event-source-mapping", "--uuid", mapping],
            profile=profile,
            region=region,
            runner=runner,
        )
        if response.get("UUID") != mapping or response.get("State") != "Disabled":
            raise ActiveCellDeploymentError(
                f"source Lambda event-source mapping is not disabled: {mapping}"
            )
    for function in resources.functions:
        concurrency = _aws(
            ["lambda", "get-function-concurrency", "--function-name", function],
            profile=profile,
            region=region,
            runner=runner,
        ).get("ReservedConcurrentExecutions")
        if concurrency != 0:
            raise ActiveCellDeploymentError(f"source Lambda is not concurrency-fenced: {function}")
    return {
        "eventRuleCount": len(resources.event_rules),
        "eventSourceMappingCount": len(resources.event_source_mappings),
        "functionCount": len(resources.functions),
        "resourceSetSha256": resources.sha256(),
        "status": "source-fence-verified",
    }


def verify_target_runtime(
    resources: TargetResources,
    manifest: activation.ActivationManifest,
    expected_environment: dict[str, str],
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Independently prove live target compute matches reviewed active authority."""
    required_environment = {
        "ACTIVATION_EVIDENCE_SHA256": expected_environment["RECOVERY_ACTIVATION_EVIDENCE_SHA256"],
        "POLICY_SIGNING_KEY_ARN": expected_environment["RECOVERY_POLICY_SIGNING_KEY_ARN"],
        "REGIONAL_POLICY_SIGNING_KEY_ARN": expected_environment["RECOVERY_POLICY_SIGNING_KEY_ARN"],
        "ENTRA_TENANT_ID": expected_environment["ENTRA_TENANT_ID"],
        "ENTRA_AAI_TENANT_ID": expected_environment["ENTRA_AAI_TENANT_ID"],
        **{
            "PASSIVE_CELL_MODE": "active",
            "RECOVERY_JOB_RECONCILIATION_ENABLED": "true",
            "ENTRA_PROVIDER_ENABLED": "true",
            "ENTRA_STRONG_AUTH_ENFORCED": "true",
        },
    }
    if required_environment["ACTIVATION_EVIDENCE_SHA256"] != manifest.evidence.sha256:
        raise ActiveCellDeploymentError("target environment names different activation evidence")
    expected_functions = {
        resources.handler: (100, "handler.handler", 512, 15),
        resources.workers[0]: (5, "evidence_worker.handler", 1024, 60),
        resources.workers[1]: (5, "retention_worker.handler", 1024, 60),
    }
    function_evidence: dict[str, dict[str, str]] = {}
    for function, (concurrency, handler, memory, timeout) in expected_functions.items():
        response = _aws(
            ["lambda", "get-function-configuration", "--function-name", function],
            profile=profile,
            region=manifest.target_region,
            runner=runner,
        )
        variables = response.get("Environment", {}).get("Variables")
        code_sha256 = response.get("CodeSha256")
        revision_id = response.get("RevisionId")
        if (
            response.get("FunctionName") != function
            or response.get("State") != "Active"
            or response.get("LastUpdateStatus") != "Successful"
            or response.get("Runtime") != "python3.13"
            or response.get("Handler") != handler
            or response.get("MemorySize") != memory
            or response.get("Timeout") != timeout
            or response.get("Architectures") != ["arm64"]
            or response.get("PackageType") != "Zip"
            or response.get("TracingConfig") != {"Mode": "PassThrough"}
            or response.get("ReservedConcurrentExecutions") != concurrency
            or not isinstance(code_sha256, str)
            or not _LAMBDA_CODE_SHA256.fullmatch(code_sha256)
            or not isinstance(revision_id, str)
            or not _REVISION_ID.fullmatch(revision_id)
            or not isinstance(variables, dict)
            or any(variables.get(key) != value for key, value in required_environment.items())
        ):
            raise ActiveCellDeploymentError(f"target Lambda authority is not live: {function}")
        function_evidence[function] = {
            "codeSha256": code_sha256,
            "revisionId": revision_id,
        }
    for mapping in resources.event_source_mappings:
        response = _aws(
            ["lambda", "get-event-source-mapping", "--uuid", mapping],
            profile=profile,
            region=manifest.target_region,
            runner=runner,
        )
        if response.get("UUID") != mapping or response.get("State") != "Enabled":
            raise ActiveCellDeploymentError(
                f"target event-source mapping is not enabled: {mapping}"
            )
    for rule in resources.event_rules:
        response = _aws(
            ["events", "describe-rule", "--name", rule],
            profile=profile,
            region=manifest.target_region,
            runner=runner,
        )
        if response.get("Name") != rule or response.get("State") != "ENABLED":
            raise ActiveCellDeploymentError(f"target EventBridge rule is not enabled: {rule}")
    return {
        "eventRuleCount": 4,
        "eventSourceMappingCount": 2,
        "functionCount": 3,
        "functions": function_evidence,
        "resourceSetSha256": resources.sha256(),
        "status": "target-runtime-live-not-routed",
    }


def _reconciliation_evidence_ref(manifest: activation.ActivationManifest) -> str:
    """Return a secret-free correlation value bound to exact transition authority."""
    return f"transition/{manifest.transition_id}/{manifest.authority_sha256()}"


def _reconciliation_result(
    response: object,
    *,
    mode: str,
    evidence_ref: str,
) -> dict[str, Any]:
    """Validate one bounded target reconciliation result from untrusted runtime output."""
    if not isinstance(response, dict) or set(response) != {
        "mode",
        "activationEvidenceRefSha256",
        "processedTenants",
        "plannedActions",
        "dispatchedJobs",
        "failedStaleJobs",
        "deferredJobs",
        "queueSource",
    }:
        raise ActiveCellDeploymentError("target reconciliation response schema is invalid")
    counts = {
        key: response[key]
        for key in (
            "processedTenants",
            "plannedActions",
            "dispatchedJobs",
            "failedStaleJobs",
            "deferredJobs",
        )
    }
    if any(
        isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100_000
        for value in counts.values()
    ):
        raise ActiveCellDeploymentError("target reconciliation counts are invalid")
    expected_ref_sha256 = hashlib.sha256(evidence_ref.encode()).hexdigest()
    if (
        response.get("mode") != mode
        or response.get("activationEvidenceRefSha256") != expected_ref_sha256
        or response.get("queueSource") != "authoritative-dynamodb-job-records"
        or (mode == "check" and (counts["dispatchedJobs"] or counts["failedStaleJobs"]))
        or (
            mode == "apply"
            and counts["plannedActions"] != counts["dispatchedJobs"] + counts["failedStaleJobs"]
        )
    ):
        raise ActiveCellDeploymentError("target reconciliation result is inconsistent")
    return response


def invoke_target_reconciliation(
    client: Any,
    function_name: str,
    manifest: activation.ActivationManifest,
    *,
    mode: str,
) -> dict[str, Any]:
    """Invoke the exact target handler synchronously and validate its complete result."""
    if mode not in {"check", "apply"}:
        raise ActiveCellDeploymentError("target reconciliation mode is unsupported")
    evidence_ref = _reconciliation_evidence_ref(manifest)
    payload = json.dumps(
        {
            "source": "aai.regional-recovery-jobs",
            "schemaVersion": 1,
            "mode": mode,
            "activationEvidenceRef": evidence_ref,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    try:
        response = client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=payload,
        )
        stream = response.get("Payload")
        if not hasattr(stream, "read"):
            raise ActiveCellDeploymentError("target reconciliation payload is unavailable")
        try:
            body = stream.read(1_048_577)
        finally:
            close = getattr(stream, "close", None)
            if callable(close):
                close()
    except ActiveCellDeploymentError:
        raise
    except Exception as error:
        raise ActiveCellDeploymentError("target reconciliation invocation failed") from error
    if (
        response.get("StatusCode") != 200
        or response.get("FunctionError") is not None
        or not isinstance(body, bytes)
        or len(body) > 1_048_576
    ):
        raise ActiveCellDeploymentError("target reconciliation Lambda reported failure")
    try:
        result = json.loads(body, object_pairs_hook=activation._strict_object)
    except (
        UnicodeError,
        json.JSONDecodeError,
        activation.RegionalActivationVerificationError,
    ) as error:
        raise ActiveCellDeploymentError("target reconciliation payload is malformed") from error
    return _reconciliation_result(result, mode=mode, evidence_ref=evidence_ref)


def reconcile_target_step(
    witness: Any,
    lambda_client: Any,
    manifest: activation.ActivationManifest,
    source_resources: SourceResources,
    target_resources: TargetResources,
    expected_environment: dict[str, str],
    *,
    profile: str,
    runner: Runner = subprocess.run,
    clock: Clock = time.time,
    sleeper: Sleeper = time.sleep,
    attempts: int = 60,
) -> dict[str, Any]:
    """Claim and reconcile target jobs, leaving traffic explicitly unrouted."""
    if isinstance(attempts, bool) or not 1 <= attempts <= 120:
        raise ActiveCellDeploymentError("target reconciliation attempts must be 1 through 120")
    claimed = journal.advance_phase(
        witness,
        manifest,
        expected_phase="TARGET_ACTIVE_NOT_ROUTED",
        next_phase="RECONCILING_TARGET_JOBS",
        now=int(clock()),
    )
    source_fence = verify_source_fence(
        source_resources,
        profile=profile,
        region=manifest.source_region,
        runner=runner,
    )
    runtime_before = verify_target_runtime(
        target_resources,
        manifest,
        expected_environment,
        profile=profile,
        runner=runner,
    )
    checked = invoke_target_reconciliation(
        lambda_client, target_resources.handler, manifest, mode="check"
    )
    applied = invoke_target_reconciliation(
        lambda_client, target_resources.handler, manifest, mode="apply"
    )
    final: dict[str, Any] | None = None
    for attempt in range(attempts):
        final = invoke_target_reconciliation(
            lambda_client, target_resources.handler, manifest, mode="check"
        )
        if final["plannedActions"] == 0:
            break
        if attempt + 1 < attempts:
            sleeper(10.0)
    if final is None or final["plannedActions"] != 0:
        raise ActiveCellDeploymentError("target jobs did not reconcile within the bounded window")
    runtime_after = verify_target_runtime(
        target_resources,
        manifest,
        expected_environment,
        profile=profile,
        runner=runner,
    )
    if runtime_after != runtime_before:
        raise ActiveCellDeploymentError("target runtime changed during reconciliation")
    step_evidence = {
        "applied": applied,
        "checked": checked,
        "final": final,
        "runtimeAfter": runtime_after,
        "runtimeBefore": runtime_before,
        "sourceFence": source_fence,
    }
    step_sha256 = hashlib.sha256(
        json.dumps(step_evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    completed = journal.advance_phase(
        witness,
        manifest,
        expected_phase="RECONCILING_TARGET_JOBS",
        next_phase="TARGET_JOBS_RECONCILED_NOT_ROUTED",
        now=int(clock()),
        step_evidence_sha256=step_sha256,
    )
    return {
        "journalClaim": claimed,
        "journal": completed["journal"],
        "reconciliation": step_evidence,
        "stepEvidenceSha256": step_sha256,
        "trafficRouted": False,
    }


def fence_source(
    resources: SourceResources,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Disable schedules and event sources before hard-throttling source Lambdas."""
    failures: list[str] = []
    operations = [
        (["events", "disable-rule", "--name", name], f"rule:{name}")
        for name in resources.event_rules
    ]
    operations.extend(
        (
            ["lambda", "update-event-source-mapping", "--uuid", uuid, "--enabled", "false"],
            f"mapping:{uuid}",
        )
        for uuid in resources.event_source_mappings
    )
    operations.extend(
        (
            [
                "lambda",
                "put-function-concurrency",
                "--function-name",
                name,
                "--reserved-concurrent-executions",
                "0",
            ],
            f"function:{name}",
        )
        for name in resources.functions
    )
    for command, label in operations:
        try:
            _aws(command, profile=profile, region=region, runner=runner)
        except ActiveCellDeploymentError:
            failures.append(label)
    if failures:
        # Continue through the bounded set, but never claim a partial fence succeeded.
        raise ActiveCellDeploymentError("source fence mutation failed for: " + ", ".join(failures))
    return verify_source_fence(resources, profile=profile, region=region, runner=runner)


def active_environment(
    manifest: activation.ActivationManifest,
    regional: recovery.RegionalRecoveryManifest,
    passive_cell: passive.PassiveCellManifest,
    verified: dict[str, Any],
    *,
    profile: str,
    runner: Runner = subprocess.run,
) -> dict[str, str]:
    """Derive active CDK inputs only from persisted and provider-verified authority."""
    outputs = recovery.stack_outputs(regional, profile=profile, runner=runner)
    trust = recovery.recovery_stack_outputs(regional, profile=profile, runner=runner)
    account = _aws(
        ["sts", "get-caller-identity"],
        profile=profile,
        region=regional.recovery_region,
        runner=runner,
    ).get("Account")
    if not isinstance(account, str) or not _ACCOUNT.fullmatch(account):
        raise ActiveCellDeploymentError("AWS account identity is malformed")
    entra = control_plane.load_persisted_manifest(
        regional.stack_name,
        profile=profile,
        region=regional.primary_region,
        runner=runner,
    )
    if entra is None:
        raise ActiveCellDeploymentError("persisted Microsoft Entra authority is unavailable")
    key_arn = trust.get("RegionalPolicySigningReplicaKeyArn")
    if verified.get("entraTenantId") != entra.entra_tenant_id:
        raise ActiveCellDeploymentError("retained Entra tenant differs from persisted authority")
    if verified.get("targetSigningKeyArn") != key_arn:
        raise ActiveCellDeploymentError("retained signing key differs from provider authority")
    environment = passive._deployment_environment(passive_cell, regional, outputs, trust, account)
    environment.update(
        {
            "AWS_DEFAULT_REGION": regional.recovery_region,
            "AWS_PROFILE": profile,
            "AWS_REGION": regional.recovery_region,
            "ENTRA_AAI_TENANT_ID": entra.aai_tenant_id,
            "ENTRA_STRONG_AUTH_ENFORCED": "true",
            "ENTRA_TENANT_ID": entra.entra_tenant_id,
            "RECOVERY_ACTIVATION_EVIDENCE_SHA256": manifest.evidence.sha256,
            "RECOVERY_CELL_MODE": "active",
        }
    )
    return environment


def prepare_active_template(
    passive_cell: passive.PassiveCellManifest,
    environment: dict[str, str],
    *,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Synthesize and independently verify one active-but-not-routed assembly."""
    infrastructure = _ROOT / "infra" / "aws-control-plane"
    try:
        result = runner(
            ["npm", "run", "synth:passive", "--", "--quiet"],
            cwd=infrastructure,
            env=environment,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ActiveCellDeploymentError("active-cell synthesis could not run") from error
    if result.returncode != 0:
        raise ActiveCellDeploymentError("active-cell synthesis failed")
    path = infrastructure / "cdk.out" / f"{passive_cell.stack_name}.template.json"
    try:
        payload = path.read_bytes()
        if len(payload) > 5_000_000:
            raise ActiveCellDeploymentError("active-cell template exceeds 5 MB")
        evidence = active_verifier.verify(
            json.loads(payload),
            activation_evidence_sha256=environment["RECOVERY_ACTIVATION_EVIDENCE_SHA256"],
            signing_key_arn=environment["RECOVERY_POLICY_SIGNING_KEY_ARN"],
            entra_tenant_id=environment["ENTRA_TENANT_ID"],
            aai_tenant_id=environment["ENTRA_AAI_TENANT_ID"],
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ActiveCellDeploymentError("synthesized active cell failed verification") from error
    evidence["templateSha256"] = hashlib.sha256(payload).hexdigest()
    return evidence


def deploy_active_template(
    stack_name: str,
    environment: dict[str, str],
    expected_sha256: str,
    *,
    runner: Runner = subprocess.run,
) -> None:
    """Deploy the exact verified assembly without resynthesis or traffic routing."""
    infrastructure = _ROOT / "infra" / "aws-control-plane"
    path = infrastructure / "cdk.out" / f"{stack_name}.template.json"
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise ActiveCellDeploymentError("verified active-cell template is missing") from error
    if digest != expected_sha256:
        raise ActiveCellDeploymentError("active-cell template changed after verification")
    try:
        result = runner(
            [
                "npx",
                "cdk",
                "--app",
                "cdk.out",
                "deploy",
                stack_name,
                "--require-approval",
                "never",
            ],
            cwd=infrastructure,
            env=environment,
            timeout=900,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ActiveCellDeploymentError("active-cell deployment could not run") from error
    if result.returncode != 0:
        raise ActiveCellDeploymentError("active-cell CloudFormation deployment failed")


def activate_target_step(
    witness: Any,
    manifest: activation.ActivationManifest,
    resources: SourceResources,
    passive_cell: passive.PassiveCellManifest,
    environment: dict[str, str],
    template_sha256: str,
    *,
    profile: str,
    runner: Runner = subprocess.run,
    clock: Clock = time.time,
) -> dict[str, Any]:
    """Claim, verify, deploy and only then finalize target runtime authority."""
    claimed = journal.advance_phase(
        witness,
        manifest,
        expected_phase="SOURCE_FENCED",
        next_phase="ACTIVATING_TARGET",
        now=int(clock()),
    )
    source_fence = verify_source_fence(
        resources,
        profile=profile,
        region=manifest.source_region,
        runner=runner,
    )
    deploy_active_template(
        passive_cell.stack_name,
        environment,
        template_sha256,
        runner=runner,
    )
    completed = journal.advance_phase(
        witness,
        manifest,
        expected_phase="ACTIVATING_TARGET",
        next_phase="TARGET_ACTIVE_NOT_ROUTED",
        now=int(clock()),
    )
    return {
        "journalClaim": claimed,
        "journal": completed["journal"],
        "sourceFence": source_fence,
    }


def _parser() -> argparse.ArgumentParser:
    """Build the bounded transition-step surface with no routing capability."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "check",
            "initialize-journal",
            "fence-source",
            "activate-target",
            "reconcile-target",
        ),
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--regional-recovery-config", type=Path, required=True)
    parser.add_argument("--evidence-continuity-config", type=Path, required=True)
    parser.add_argument("--passive-cell-config", type=Path, required=True)
    parser.add_argument("--profile", default="p1")
    parser.add_argument("--confirm-source-fence", action="store_true")
    parser.add_argument("--confirm-target-activation", action="store_true")
    parser.add_argument("--confirm-target-reconciliation", action="store_true")
    parser.add_argument("--confirm-journal-initialization", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Repeat preflight, then execute no more than one explicitly confirmed step."""
    arguments = _parser().parse_args(argv)
    try:
        manifest = activation.ActivationManifest.parse(
            arguments.manifest.read_text(encoding="utf-8")
        )
        regional = recovery.RegionalRecoveryManifest.parse(
            arguments.regional_recovery_config.read_text(encoding="utf-8")
        )
        evidence = continuity.EvidenceContinuityManifest.parse(
            arguments.evidence_continuity_config.read_text(encoding="utf-8")
        )
        passive_cell = passive.PassiveCellManifest.parse(
            arguments.passive_cell_config.read_text(encoding="utf-8")
        )
        import boto3

        session = boto3.Session(profile_name=arguments.profile)
        checked = preflight.provider_preflight(
            manifest,
            regional,
            evidence,
            passive_cell,
            profile=arguments.profile,
            s3_factory=lambda region: session.client("s3", region_name=region),
            expected_cell_status=(
                "active-not-routed"
                if arguments.command == "reconcile-target"
                else "staged-not-serving"
            ),
        )
        manifest.require_journal_authority()
        if arguments.command != "check" and manifest.direction != "failover":
            raise ActiveCellDeploymentError(
                "failback mutation is unavailable until the primary activation adapter exists"
            )
        verified = checked.get("verified")
        if (
            not isinstance(verified, dict)
            or verified.get("authoritySha256") != manifest.authority_sha256()
            or verified.get("approverPrincipalIds")
            != [approval.principal_id for approval in manifest.approvals]
        ):
            raise ActiveCellDeploymentError(
                "provider preflight did not bind journal and two-person authority"
            )
        witness = session.client("dynamodb", region_name=manifest.coordination_region)
        journal_posture = journal.verify_table_posture(witness, manifest)
        if arguments.command == "initialize-journal":
            if not arguments.confirm_journal_initialization:
                raise ActiveCellDeploymentError("--confirm-journal-initialization is required")
            initialized = journal.initialize_state(witness, manifest, now=int(time.time()))
            journal_state = journal.read_state(witness, manifest)
        else:
            initialized = None
            journal_state = journal.read_state(witness, manifest)
        source_stack_name = (
            regional.stack_name
            if manifest.source_region == regional.primary_region
            else passive_cell.stack_name
        )
        resources = discover_source_resources(
            regional,
            stack_name=source_stack_name,
            source_region=manifest.source_region,
            profile=arguments.profile,
        )
        result: dict[str, Any] = {
            "activationExecuted": False,
            "command": arguments.command,
            "preflightStatus": checked["status"],
            "journalPosture": journal_posture,
            "journal": journal_state.evidence(),
            "sourceResourceSetSha256": resources.sha256(),
            "trafficRouted": False,
        }
        if initialized is not None:
            result["journalInitialization"] = initialized
            result["status"] = "journal-initialized-primary-stable"
        elif arguments.command == "fence-source":
            if not arguments.confirm_source_fence:
                raise ActiveCellDeploymentError("--confirm-source-fence is required")
            result["journalClaim"] = journal.claim_source_fence(
                witness, manifest, now=int(time.time())
            )
            result["sourceFence"] = fence_source(
                resources,
                profile=arguments.profile,
                region=manifest.source_region,
            )
            result["journal"] = journal.advance_phase(
                witness,
                manifest,
                expected_phase="FENCING_SOURCE",
                next_phase="SOURCE_FENCED",
                now=int(time.time()),
            )["journal"]
        elif arguments.command == "reconcile-target":
            environment = active_environment(
                manifest,
                regional,
                passive_cell,
                checked["verified"],
                profile=arguments.profile,
            )
            if not arguments.confirm_target_reconciliation:
                raise ActiveCellDeploymentError("--confirm-target-reconciliation is required")
            target_resources = discover_target_resources(
                stack_name=passive_cell.stack_name,
                target_region=manifest.target_region,
                profile=arguments.profile,
            )
            result.update(
                reconcile_target_step(
                    witness,
                    session.client("lambda", region_name=manifest.target_region),
                    manifest,
                    resources,
                    target_resources,
                    environment,
                    profile=arguments.profile,
                )
            )
            result["activationExecuted"] = True
            result["status"] = "target-jobs-reconciled-not-routed"
        else:
            environment = active_environment(
                manifest,
                regional,
                passive_cell,
                checked["verified"],
                profile=arguments.profile,
            )
            template = prepare_active_template(passive_cell, environment)
            result["template"] = template
            if arguments.command == "activate-target":
                if not arguments.confirm_target_activation:
                    raise ActiveCellDeploymentError("--confirm-target-activation is required")
                target_result = activate_target_step(
                    witness,
                    manifest,
                    resources,
                    passive_cell,
                    environment,
                    template["templateSha256"],
                    profile=arguments.profile,
                )
                result.update(target_result)
                result["activationExecuted"] = True
                result["status"] = "target-active-not-routed"
            else:
                result["status"] = "verified-ready-for-separate-transition-steps"
        print(json.dumps(result, sort_keys=True))
    except (
        OSError,
        UnicodeError,
        activation.RegionalActivationVerificationError,
        recovery.RecoveryConfigurationError,
        continuity.EvidenceContinuityDeploymentError,
        passive.PassiveCellDeploymentError,
        control_plane.DeploymentConfigurationError,
        preflight.RegionalActivationPreflightError,
        journal.TransitionJournalError,
        ActiveCellDeploymentError,
    ) as error:
        print(f"Active-cell transition guard failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
