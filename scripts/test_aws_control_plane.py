#!/usr/bin/env python3
"""Exercise the deployed AWS control-plane security boundary.

This is an adopter-facing smoke test, not a unit-test replacement.  It uses
an operator-authorized Lambda invocation only to create a synthetic test
agent and approval; the agent enrollment, heartbeat, policy, approval replay,
unauthenticated API, and DynamoDB idempotency checks use the deployed AWS
services.  The synthetic records are removed before exit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Mapping
from concurrent.futures import ProcessPoolExecutor
from typing import Any, cast
from urllib.parse import urlparse


def _claim_worker(payload: Mapping[str, Any]) -> str:
    """Claim the same live operation from an independently spawned process."""
    import boto3

    from agentic_security import DynamoDbIdempotencyStore
    from agentic_security.idempotency import new_record

    session = boto3.Session(profile_name=payload["profile"], region_name=payload["region"])
    table = session.resource("dynamodb").Table(payload["table"])
    record = new_record(
        operation_key=str(payload["operation_key"]),
        action_fingerprint=str(payload["action_fingerprint"]),
        tenant=str(payload["tenant"]),
        principal_id="synthetic-process",
        tool_name="synthetic-process-race",
        resource_ids=("synthetic-process-resource",),
        ttl_seconds=300,
    )
    return DynamoDbIdempotencyStore(table).claim(record).status.value


def _event(path: str, method: str, body: Mapping[str, Any], tenant: str) -> dict[str, Any]:
    """Build an API Gateway v2 event for an operator-only smoke operation."""
    return {
        "rawPath": path,
        "body": json.dumps(body),
        "requestContext": {
            "http": {"method": method},
            "authorizer": {
                "jwt": {
                    "claims": {
                        "custom:tenant_id": tenant,
                        "cognito:groups": ["platform-admin"],
                        "sub": "aws-control-plane-smoke",
                    }
                }
            },
        },
    }


def _invoke(lambda_client: Any, function_name: str, event: Mapping[str, Any]) -> dict[str, Any]:
    """Invoke the deployed handler and require a successful Lambda call."""
    response = lambda_client.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(event).encode(),
    )
    payload = json.loads(response["Payload"].read())
    if response.get("FunctionError") or int(payload.get("statusCode", 500)) >= 500:
        raise RuntimeError(f"deployed Lambda failed: {payload}")
    return cast(dict[str, Any], payload)


def _request(
    url: str,
    method: str,
    body: Mapping[str, Any] | None = None,
    token: str | None = None,
    project_root_digest: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """Make one JSON request and return status plus decoded response.

    ``project_root_digest`` is supplied explicitly so the live acceptance test
    can prove that AWS agent sessions fail closed when this host-bound claim is
    missing or does not match the enrolled project root.
    """
    if urlparse(url).scheme != "https":
        raise ValueError("AWS control-plane smoke tests require an HTTPS endpoint")
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    if project_root_digest:
        headers["X-AAI-Project-Root-Digest"] = project_root_digest
    request = urllib.request.Request(  # noqa: S310 - HTTPS enforced above
        url,
        data=None if body is None else json.dumps(body).encode(),
        headers=headers,
        method=method,
    )
    try:
        import certifi

        context = ssl.create_default_context(cafile=certifi.where())
        with urllib.request.urlopen(  # noqa: S310 - HTTPS and CA context enforced above
            request, timeout=15, context=context
        ) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def main() -> int:
    """Run the smoke test and return a shell-friendly status code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", required=True, help="Deployed API Gateway URL")
    parser.add_argument("--function-name", required=True, help="Deployed Lambda function name")
    parser.add_argument("--control-table", required=True, help="Control-plane DynamoDB table name")
    parser.add_argument(
        "--idempotency-table", required=True, help="Idempotency DynamoDB table name"
    )
    parser.add_argument("--audit-bucket", required=True, help="Immutable audit S3 bucket name")
    parser.add_argument("--alerts-topic-arn", required=True, help="Security alerts SNS topic ARN")
    parser.add_argument("--alerts-queue-arn", required=True, help="Security alerts SQS queue ARN")
    parser.add_argument("--region", default=None, help="AWS region for the boto3 session")
    parser.add_argument("--profile", default=None, help="AWS profile for the boto3 session")
    parser.add_argument("--tenant", default="tenant-demo", help="Provisioned synthetic test tenant")
    parser.add_argument(
        "--allow-unconfigured-runtime-attestation",
        action="store_true",
        help=(
            "Continue only when runtime attestation is the sole failed verification check "
            "and the deployed control plane explicitly reports not_configured"
        ),
    )
    arguments = parser.parse_args()

    import boto3

    session = boto3.Session(profile_name=arguments.profile, region_name=arguments.region)
    lambda_client = session.client("lambda")
    s3_client = session.client("s3")
    sns_client = session.client("sns")
    sqs_client = session.client("sqs")
    control_table = session.resource("dynamodb").Table(arguments.control_table)
    idempotency_table = session.resource("dynamodb").Table(arguments.idempotency_table)
    suffix = uuid.uuid4().hex[:12]
    deployment_id = f"aws-smoke-deployment-{suffix}"
    template_id = f"aws-smoke-template-{suffix}"
    agent_id = f"aws-smoke-{suffix}"
    agent_key = f"{deployment_id}:{agent_id}"
    approval_id = f"aws-smoke-approval-{suffix}"
    session_token = ""
    replacement_session_token = ""
    unused_bootstrap_token = ""
    replacement_bootstrap_token = ""
    replacement_agent_id = f"{agent_id}-replacement"
    group_assigned = False
    membership_request_id = f"aws-smoke-membership-{suffix}"
    operation_key = f"aws-smoke-operation-{suffix}"
    try:
        unauthenticated, _ = _request(f"{arguments.api_url.rstrip('/')}/enterprise/agents", "GET")
        if unauthenticated != 401:
            raise RuntimeError(f"expected unauthenticated API 401, received {unauthenticated}")

        from agentic_security import (
            AgentHost,
            ManagedConfigurationCompiler,
            ManagedConfigurationEvidence,
            ManagedConfigurationSource,
            ManagedPlatform,
            ManagedPolicyIntent,
            NativeActionDecision,
            NativeActionRule,
        )

        managed_bundle = ManagedConfigurationCompiler().compile(
            ManagedPolicyIntent(
                policy_id="policy-safe-default",
                policy_version=1,
                action_rules=(
                    NativeActionRule("Read", NativeActionDecision.ALLOW, "synthetic read"),
                    NativeActionRule(
                        "Bash(git push *)",
                        NativeActionDecision.APPROVAL_REQUIRED,
                        "synthetic publish review",
                    ),
                ),
            ),
            host=AgentHost.CLAUDE_CODE,
            host_version="2.1.220",
            platform=ManagedPlatform.LINUX,
            hook_command="/opt/aai-security/hooks/claude-policy",
        )
        managed_desired = {
            "host": managed_bundle.host.value,
            "hostVersion": managed_bundle.host_version,
            "platform": managed_bundle.platform.value,
            "bundleHash": managed_bundle.bundle_hash,
            "policyId": managed_bundle.policy_id,
            "policyVersion": managed_bundle.policy_version,
        }
        deployment = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                "/enterprise/deployments",
                "POST",
                {
                    "organizationId": "org-demo",
                    "projectId": "project-demo",
                    "deploymentId": deployment_id,
                    "name": f"AWS smoke {suffix}",
                    "environment": "synthetic",
                    "region": arguments.region or "eu-west-2",
                    "team": "automated-acceptance",
                    "sdkVersion": "1.1.0",
                },
                arguments.tenant,
            ),
        )
        if deployment["statusCode"] != 201:
            raise RuntimeError(f"synthetic deployment creation failed: {deployment}")
        template = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                "/enterprise/templates",
                "POST",
                {
                    "templateId": template_id,
                    "name": f"AWS managed-host smoke {suffix}",
                    "configuration": {"managedHost": managed_desired},
                },
                arguments.tenant,
            ),
        )
        if template["statusCode"] != 201:
            raise RuntimeError(f"managed template creation failed: {template}")
        staged = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                "/enterprise/deployment-config",
                "POST",
                {"deploymentId": deployment_id, "templateId": template_id},
                arguments.tenant,
            ),
        )
        if staged["statusCode"] != 201:
            raise RuntimeError(f"managed deployment staging failed: {staged}")

        registered = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                "/enterprise/agents/register",
                "POST",
                {
                    "deploymentId": deployment_id,
                    "agentId": agent_id,
                    "host": "claude-code",
                    "projectRoot": "/synthetic/project",
                    # These browser-authored values are deliberately forged.
                    # The service must derive both fields from the deployment.
                    "environment": "forged-production",
                    "team": "forged-team",
                    "ownership": {
                        "ownerId": "aws-control-plane-smoke",
                        "ownerName": "Synthetic acceptance owner",
                        "businessContact": "acceptance@example.invalid",
                        "criticality": "low",
                    },
                },
                arguments.tenant,
            ),
        )
        if registered["statusCode"] != 201:
            raise RuntimeError(f"agent registration failed: {registered}")
        registered_body = json.loads(registered["body"])
        registered_ownership = registered_body.get("ownership", {})
        if (
            registered_body.get("environment") != "synthetic"
            or registered_body.get("team") != "automated-acceptance"
            or registered_ownership.get("status") != "current"
            or registered_ownership.get("revision") != 1
            or registered_ownership.get("team") != "automated-acceptance"
            or registered_ownership.get("environment") != "synthetic"
        ):
            raise RuntimeError(
                "agent registration trusted forged scope or omitted accountable ownership: "
                f"{registered_body}"
            )
        reviewed = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                f"/enterprise/agents/{deployment_id}/{agent_id}/ownership",
                "PUT",
                {
                    "expectedOwnershipRevision": 1,
                    "ownership": {
                        "ownerId": "aws-control-plane-smoke-reviewed",
                        "ownerName": "Reviewed synthetic acceptance owner",
                        "businessContact": "reviewed-acceptance@example.invalid",
                        "criticality": "medium",
                    },
                    "reason": "Synthetic quarterly ownership acceptance review completed.",
                },
                arguments.tenant,
            ),
        )
        reviewed_body = json.loads(reviewed["body"])
        reviewed_ownership = reviewed_body.get("ownership", {})
        if (
            reviewed["statusCode"] != 200
            or reviewed_ownership.get("status") != "current"
            or reviewed_ownership.get("revision") != 2
            or reviewed_ownership.get("ownerId") != "aws-control-plane-smoke-reviewed"
            or reviewed_ownership.get("criticality") != "medium"
            or reviewed_ownership.get("team") != "automated-acceptance"
            or reviewed_ownership.get("environment") != "synthetic"
        ):
            raise RuntimeError(f"agent ownership review failed: {reviewed}")
        stale_review = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                f"/enterprise/agents/{deployment_id}/{agent_id}/ownership",
                "PUT",
                {
                    "expectedOwnershipRevision": 1,
                    "ownership": {
                        "ownerId": "stale-overwrite",
                        "ownerName": "Stale overwrite attempt",
                        "businessContact": "stale@example.invalid",
                        "criticality": "critical",
                    },
                    "reason": "Synthetic stale ownership update must be rejected safely.",
                },
                arguments.tenant,
            ),
        )
        if stale_review["statusCode"] != 409:
            raise RuntimeError(f"stale ownership review was not rejected: {stale_review}")
        unassigned_verification = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                f"/enterprise/agents/{deployment_id}/{agent_id}/verify",
                "GET",
                {},
                arguments.tenant,
            ),
        )
        unassigned_verification_body = json.loads(unassigned_verification["body"])
        if (
            unassigned_verification["statusCode"] != 200
            or unassigned_verification_body.get("verified") is not False
            or unassigned_verification_body.get("checks", {})
            .get("policyAssignment", {})
            .get("passed")
            is not False
        ):
            raise RuntimeError(
                f"verification accepted an enrolled but unassigned agent: {unassigned_verification}"
            )
        groups = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                "/enterprise/groups",
                "GET",
                {},
                arguments.tenant,
            ),
        )
        group = next(
            (
                item
                for item in json.loads(groups["body"]).get("items", [])
                if item.get("id") == "group-platform"
            ),
            None,
        )
        if groups["statusCode"] != 200 or not group:
            raise RuntimeError(f"agent group inventory failed: {groups}")
        membership_revision = group.get("membershipRevision")
        membership_body = {
            "mode": "preview",
            "requestId": membership_request_id,
            "expectedMembershipRevision": membership_revision,
            "reason": "Synthetic bulk assignment acceptance with a partial outcome.",
            "agents": [
                {"deploymentId": deployment_id, "agentId": agent_id},
                {"deploymentId": deployment_id, "agentId": f"{agent_id}-missing"},
            ],
        }
        previewed = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                "/enterprise/groups/group-platform/agents/bulk",
                "POST",
                membership_body,
                arguments.tenant,
            ),
        )
        previewed_body = json.loads(previewed["body"])
        if (
            previewed["statusCode"] != 200
            or previewed_body.get("counts", {}).get("ready") != 1
            or previewed_body.get("counts", {}).get("rejected") != 1
            or previewed_body.get("canApply") is not True
        ):
            raise RuntimeError(f"bulk assignment preview failed: {previewed}")
        assigned = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                "/enterprise/groups/group-platform/agents/bulk",
                "POST",
                {**membership_body, "mode": "apply"},
                arguments.tenant,
            ),
        )
        assigned_body = json.loads(assigned["body"])
        if (
            assigned["statusCode"] != 207
            or assigned_body.get("counts", {}).get("applied") != 1
            or assigned_body.get("counts", {}).get("rejected") != 1
            or assigned_body.get("resultingMembershipRevision") != membership_revision + 1
        ):
            raise RuntimeError(f"bulk agent group assignment failed: {assigned}")
        group_assigned = True
        replayed = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                "/enterprise/groups/group-platform/agents/bulk",
                "POST",
                {**membership_body, "mode": "apply"},
                arguments.tenant,
            ),
        )
        if (
            replayed["statusCode"] != 207
            or json.loads(replayed["body"]).get("replayed") is not True
        ):
            raise RuntimeError(f"bulk assignment replay was not idempotent: {replayed}")
        stale_assignment = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                "/enterprise/groups/group-platform/agents/bulk",
                "POST",
                {
                    **membership_body,
                    "mode": "apply",
                    "requestId": f"{membership_request_id}-stale",
                },
                arguments.tenant,
            ),
        )
        if stale_assignment["statusCode"] != 409:
            raise RuntimeError(f"stale bulk assignment was not rejected: {stale_assignment}")
        stored_operation = control_table.get_item(
            Key={
                "pk": f"TENANT#{arguments.tenant}",
                "sk": f"GROUP_MEMBERSHIP_OPERATION#{membership_request_id}",
            },
            ConsistentRead=True,
        ).get("Item")
        if (
            not stored_operation
            or stored_operation.get("actor") != "aws-control-plane-smoke"
            or stored_operation.get("response", {}).get("counts", {}).get("applied") != 1
        ):
            raise RuntimeError("durable bulk assignment idempotency evidence is missing")
        from boto3.dynamodb.conditions import Key  # type: ignore[import-untyped]

        membership_audits = control_table.query(
            KeyConditionExpression=(
                Key("pk").eq(f"TENANT#{arguments.tenant}")
                & Key("sk").begins_with("GROUP_MEMBERSHIP_AUDIT#")
            ),
            ScanIndexForward=False,
            Limit=100,
            ConsistentRead=True,
        ).get("Items", [])
        matching_audit = next(
            (
                item
                for item in membership_audits
                if item.get("payload", {}).get("request_id") == membership_request_id
            ),
            None,
        )
        if (
            not matching_audit
            or matching_audit.get("event_type") != "group_membership_bulk_assigned"
            or matching_audit.get("payload", {}).get("rejected_count") != 1
        ):
            raise RuntimeError("durable bulk assignment audit evidence is missing")
        bootstrap = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                "/enterprise/agents/bootstrap",
                "POST",
                {"deploymentId": deployment_id, "agentId": agent_id, "ttlSeconds": 600},
                arguments.tenant,
            ),
        )
        bootstrap_token = json.loads(bootstrap["body"])["bootstrapToken"]
        enrolled_status, enrolled = _request(
            f"{arguments.api_url.rstrip('/')}/agent/enroll",
            "POST",
            {
                "bootstrapToken": bootstrap_token,
                "projectRoot": "/synthetic/project",
                "host": "claude-code",
            },
        )
        if enrolled_status != 201:
            raise RuntimeError(f"agent enrollment failed: {enrolled_status} {enrolled}")
        session_token = enrolled["accessToken"]
        project_root_digest = hashlib.sha256(b"/synthetic/project").hexdigest()
        from agentic_security import ControlPlaneAgentClient

        agent_client = ControlPlaneAgentClient(
            arguments.api_url,
            session_token,
            agent_id=agent_id,
            project_root="/synthetic/project",
            deployment_id=deployment_id,
            aws_agent_session=True,
        )
        if agent_client.register() != session_token:
            raise RuntimeError("AWS agent client attempted an unexpected enrollment")
        missing_managed_verification = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                f"/enterprise/agents/{deployment_id}/{agent_id}/verify",
                "GET",
                {},
                arguments.tenant,
            ),
        )
        missing_managed_body = json.loads(missing_managed_verification["body"])
        if (
            missing_managed_body.get("verified") is not False
            or missing_managed_body.get("checks", {}).get("managedConfiguration", {}).get("passed")
            is not False
        ):
            raise RuntimeError(
                "verification accepted missing managed-host evidence: "
                f"{missing_managed_verification}"
            )
        blocked_policy_status, _ = _request(
            f"{arguments.api_url.rstrip('/')}/agent/{deployment_id}/{agent_id}/effective-policy",
            "GET",
            token=session_token,
            project_root_digest=project_root_digest,
        )
        if blocked_policy_status != 403:
            raise RuntimeError(
                "effective policy was returned without managed-host evidence: "
                f"{blocked_policy_status}"
            )
        missing_root_status, _ = _request(
            f"{arguments.api_url.rstrip('/')}/agent/{deployment_id}/{agent_id}/heartbeat",
            "POST",
            token=session_token,
        )
        if missing_root_status != 403:
            raise RuntimeError(
                "heartbeat without the enrolled project-root digest did not fail closed: "
                f"{missing_root_status}"
            )
        mismatched_root_status, _ = _request(
            f"{arguments.api_url.rstrip('/')}/agent/{deployment_id}/{agent_id}/heartbeat",
            "POST",
            token=session_token,
            project_root_digest="0" * 64,
        )
        if mismatched_root_status != 403:
            raise RuntimeError(
                "heartbeat with a mismatched project-root digest did not fail closed: "
                f"{mismatched_root_status}"
            )
        heartbeat_status, _ = _request(
            f"{arguments.api_url.rstrip('/')}/agent/{deployment_id}/{agent_id}/heartbeat",
            "POST",
            token=session_token,
            project_root_digest=project_root_digest,
        )
        if heartbeat_status != 200:
            raise RuntimeError(
                f"heartbeat with the enrolled project-root digest failed: {heartbeat_status}"
            )
        observed_at = int(time.time())
        managed_evidence = ManagedConfigurationEvidence(
            host=managed_bundle.host,
            host_version=managed_bundle.host_version,
            platform=managed_bundle.platform,
            bundle_hash=managed_bundle.bundle_hash,
            policy_id=managed_bundle.policy_id,
            policy_version=managed_bundle.policy_version,
            source=ManagedConfigurationSource.ENDPOINT_MANAGED_FILE,
            verified_at=observed_at,
            expires_at=observed_at + 300,
        )
        managed_client = ControlPlaneAgentClient(
            arguments.api_url,
            session_token,
            agent_id=agent_id,
            project_root="/synthetic/project",
            deployment_id=deployment_id,
            aws_agent_session=True,
            managed_configuration_provider=lambda: managed_evidence,
        )
        if managed_client.heartbeat(session_token).get("status") != "connected":
            raise RuntimeError("AWS managed-host evidence heartbeat failed")
        effective = managed_client.effective_policy()
        if effective.get("policy", {}).get("id") != "policy-safe-default":
            raise RuntimeError("AWS agent client did not receive the assigned policy")
        connected_verification = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                f"/enterprise/agents/{deployment_id}/{agent_id}/verify",
                "GET",
                {},
                arguments.tenant,
            ),
        )
        connected_verification_body = json.loads(connected_verification["body"])
        runtime_attestation_proven = connected_verification_body.get("verified") is True
        if not runtime_attestation_proven:
            failed_checks = sorted(
                key
                for key, check in connected_verification_body.get("checks", {}).items()
                if check.get("passed") is not True
            )
            explicitly_unconfigured = (
                arguments.allow_unconfigured_runtime_attestation
                and failed_checks == ["runtimeAttestation"]
                and connected_verification_body.get("attestation", {}).get("status")
                == "not_configured"
            )
            if not explicitly_unconfigured:
                raise RuntimeError(
                    f"verification rejected a connected, assigned agent: {connected_verification}"
                )

        conflicting_evidence = ManagedConfigurationEvidence(
            host=managed_bundle.host,
            host_version=managed_bundle.host_version,
            platform=managed_bundle.platform,
            bundle_hash="f" * 64,
            policy_id=managed_bundle.policy_id,
            policy_version=managed_bundle.policy_version,
            source=ManagedConfigurationSource.ENDPOINT_MANAGED_FILE,
            verified_at=observed_at,
            expires_at=observed_at + 300,
        )
        conflicting_client = ControlPlaneAgentClient(
            arguments.api_url,
            session_token,
            agent_id=agent_id,
            project_root="/synthetic/project",
            deployment_id=deployment_id,
            aws_agent_session=True,
            managed_configuration_provider=lambda: conflicting_evidence,
        )
        conflicting_client.heartbeat(session_token)
        conflict_status, _ = _request(
            f"{arguments.api_url.rstrip('/')}/agent/{deployment_id}/{agent_id}/effective-policy",
            "GET",
            token=session_token,
            project_root_digest=project_root_digest,
        )
        if conflict_status != 403:
            raise RuntimeError(
                f"effective policy was returned for a conflicting host bundle: {conflict_status}"
            )
        managed_client.heartbeat(session_token)

        stopped = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                f"/enterprise/agents/{deployment_id}/{agent_id}/emergency-stop",
                "POST",
                {"active": True},
                arguments.tenant,
            ),
        )
        if stopped["statusCode"] != 200:
            raise RuntimeError(f"agent emergency stop activation failed: {stopped}")
        stopped_policy_status, stopped_policy = _request(
            f"{arguments.api_url.rstrip('/')}/agent/{deployment_id}/{agent_id}/effective-policy",
            "GET",
            token=session_token,
            project_root_digest=project_root_digest,
        )
        if stopped_policy_status != 409 or stopped_policy.get("emergencyStop") is not True:
            raise RuntimeError(
                "agent emergency stop was not enforced by effective-policy: "
                f"{stopped_policy_status} {stopped_policy}"
            )
        stopped_verification = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                f"/enterprise/agents/{deployment_id}/{agent_id}/verify",
                "GET",
                {},
                arguments.tenant,
            ),
        )
        stopped_verification_body = json.loads(stopped_verification["body"])
        if (
            stopped_verification_body.get("verified") is not False
            or stopped_verification_body.get("checks", {}).get("emergencyStop", {}).get("passed")
            is not False
        ):
            raise RuntimeError(
                f"verification accepted an emergency-stopped agent: {stopped_verification}"
            )
        resumed = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                f"/enterprise/agents/{deployment_id}/{agent_id}/emergency-stop",
                "POST",
                {"active": False},
                arguments.tenant,
            ),
        )
        if resumed["statusCode"] != 200:
            raise RuntimeError(f"agent emergency stop recovery failed: {resumed}")
        recovered_verification = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                f"/enterprise/agents/{deployment_id}/{agent_id}/verify",
                "GET",
                {},
                arguments.tenant,
            ),
        )
        recovered_verification_body = json.loads(recovered_verification["body"])
        recovered_failed_checks = sorted(
            key
            for key, check in recovered_verification_body.get("checks", {}).items()
            if check.get("passed") is not True
        )
        recovered_as_expected = recovered_verification_body.get("verified") is True or (
            arguments.allow_unconfigured_runtime_attestation
            and recovered_failed_checks == ["runtimeAttestation"]
            and recovered_verification_body.get("attestation", {}).get("status") == "not_configured"
        )
        if not recovered_as_expected:
            raise RuntimeError(
                f"verification rejected an emergency-stop-recovered agent: {recovered_verification}"
            )

        action = {
            "approvalId": approval_id,
            "agentKey": agent_key,
            "toolName": "synthetic-write",
            "proposalId": f"proposal-{suffix}",
            "taskId": f"task-{suffix}",
            "principalId": "synthetic-principal",
            "actionHash": hashlib.sha256(suffix.encode()).hexdigest(),
        }
        approval = _invoke(
            lambda_client,
            arguments.function_name,
            _event("/enterprise/approvals", "POST", action, arguments.tenant),
        )
        if approval["statusCode"] != 201:
            raise RuntimeError(f"approval creation failed: {approval}")
        consume = {
            "approval_id": action["approvalId"],
            **{key: action[key] for key in action if key != "approvalId"},
        }
        consume = {
            key.replace("Id", "_id").replace("Name", "_name").replace("Hash", "_hash"): value
            for key, value in consume.items()
        }
        first_status, first = _request(
            f"{arguments.api_url.rstrip('/')}/agent/{deployment_id}/{agent_id}/approvals/consume",
            "POST",
            body=consume,
            token=session_token,
            project_root_digest=project_root_digest,
        )
        replay_status, replay = _request(
            f"{arguments.api_url.rstrip('/')}/agent/{deployment_id}/{agent_id}/approvals/consume",
            "POST",
            body=consume,
            token=session_token,
            project_root_digest=project_root_digest,
        )
        if (
            first_status != 200
            or first.get("approved") is not True
            or replay_status != 200
            or replay.get("approved") is not False
        ):
            raise RuntimeError(f"approval replay contract failed: {first} / {replay}")

        from agentic_security import DynamoDbIdempotencyStore
        from agentic_security.idempotency import (
            IdempotencyClaimStatus,
            IdempotencyState,
            new_record,
        )

        record = new_record(
            operation_key=operation_key,
            action_fingerprint=f"fingerprint-{suffix}",
            tenant=arguments.tenant,
            principal_id="synthetic-principal",
            tool_name="synthetic-write",
            resource_ids=("synthetic-resource",),
            ttl_seconds=300,
        )
        store = DynamoDbIdempotencyStore(idempotency_table)
        if store.claim(record).status is not IdempotencyClaimStatus.CLAIMED:
            raise RuntimeError("DynamoDB idempotency claim was not atomic")
        if (
            DynamoDbIdempotencyStore(idempotency_table).claim(record).status
            is not IdempotencyClaimStatus.EXISTING
        ):
            raise RuntimeError("DynamoDB idempotency replay was not detected")
        race_operation_key = f"aws-smoke-process-race-{suffix}"
        race_payload = {
            "profile": arguments.profile,
            "region": arguments.region,
            "table": arguments.idempotency_table,
            "operation_key": race_operation_key,
            "action_fingerprint": f"process-fingerprint-{suffix}",
            "tenant": arguments.tenant,
        }
        with ProcessPoolExecutor(max_workers=2) as pool:
            race_statuses = tuple(pool.map(_claim_worker, (race_payload, race_payload)))
        if sorted(race_statuses) != sorted(
            [IdempotencyClaimStatus.CLAIMED.value, IdempotencyClaimStatus.EXISTING.value]
        ):
            raise RuntimeError(f"multi-process idempotency race was not atomic: {race_statuses}")
        if (
            store.complete(operation_key, {"synthetic": True}).state
            is not IdempotencyState.COMPLETED
        ):
            raise RuntimeError("DynamoDB terminal persistence failed")
        from agentic_security import (
            ActionProposal,
            ExecutionContext,
            GuardedRuntime,
            InMemoryAuditSink,
            Principal,
            ToolDefinition,
            ToolRegistry,
        )
        from agentic_security.policies import AllowListPolicy
        from agentic_security.runtime import RuntimeConfig

        calls: list[dict[str, Any]] = []

        def synthetic_handler(_context: Any, arguments: Any) -> dict[str, bool]:
            """Record one synthetic side effect and return its result."""
            calls.append(arguments)
            return {"ok": True}

        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="synthetic_write",
                handler=synthetic_handler,
                validator=lambda arguments: arguments,
                description="Synthetic AWS smoke action.",
                idempotency_required=True,
            )
        )
        runtime = GuardedRuntime(
            ExecutionContext(
                agent_id,
                Principal("synthetic-principal", tenant=arguments.tenant),
                f"task-{suffix}",
                "AWS control-plane smoke",
                tenant=arguments.tenant,
            ),
            registry,
            AllowListPolicy({"synthetic_write"}),
            InMemoryAuditSink(),
            config=RuntimeConfig(idempotency_store=DynamoDbIdempotencyStore(idempotency_table)),
        )
        runtime_proposal = ActionProposal(
            "synthetic_write",
            {"resource": "synthetic"},
            f"proposal-runtime-{suffix}",
            operation_key=f"aws-smoke-runtime-operation-{suffix}",
        )
        first_runtime = runtime.execute(runtime_proposal)
        second_runtime = runtime.execute(runtime_proposal)
        if (
            first_runtime.status.value != "executed"
            or second_runtime.status.value != "executed"
            or len(calls) != 1
        ):
            raise RuntimeError(
                "GuardedRuntime did not use live durable idempotency: "
                f"{first_runtime.status.value}/{second_runtime.status.value}/{len(calls)}"
            )
        lock = s3_client.get_object_lock_configuration(Bucket=arguments.audit_bucket)
        if lock.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") != "Enabled":
            raise RuntimeError("audit bucket Object Lock is not enabled")
        retention = lock["ObjectLockConfiguration"].get("Rule", {}).get("DefaultRetention", {})
        if retention.get("Mode") != "COMPLIANCE" or int(retention.get("Days", 0)) < 365:
            raise RuntimeError(f"audit bucket retention is not compliant: {retention}")
        if (
            s3_client.get_bucket_versioning(Bucket=arguments.audit_bucket).get("Status")
            != "Enabled"
        ):
            raise RuntimeError("audit bucket versioning is not enabled")
        objects = s3_client.list_objects_v2(Bucket=arguments.audit_bucket, MaxKeys=1).get(
            "Contents", []
        )
        if not objects:
            raise RuntimeError("audit bucket has no retained object to verify")
        audit_key = str(objects[0]["Key"])
        versions = s3_client.list_object_versions(
            Bucket=arguments.audit_bucket, Prefix=audit_key
        ).get("Versions", [])
        locked_version = next((item for item in versions if item.get("IsLatest")), None)
        if not locked_version:
            raise RuntimeError("audit object has no current version")
        try:
            s3_client.delete_object(
                Bucket=arguments.audit_bucket,
                Key=audit_key,
                VersionId=locked_version["VersionId"],
            )
        except Exception as error:
            if getattr(error, "response", {}).get("Error", {}).get("Code") not in {
                "AccessDenied",
                "InvalidRequest",
            }:
                raise
        else:
            raise RuntimeError("Object Lock allowed deletion of the current audit version")
        alert_marker = f"aws-alert-smoke-{suffix}"
        sns_client.publish(TopicArn=arguments.alerts_topic_arn, Message=alert_marker)
        queue_name = arguments.alerts_queue_arn.rsplit(":", 1)[-1]
        queue_url = sqs_client.get_queue_url(QueueName=queue_name)["QueueUrl"]
        alert_messages = sqs_client.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=10, MaxNumberOfMessages=1
        ).get("Messages", [])
        alert_message = next(
            (message for message in alert_messages if alert_marker in str(message.get("Body", ""))),
            None,
        )
        if alert_message is None:
            raise RuntimeError("security alert was not delivered to the durable SQS queue")
        sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=alert_message["ReceiptHandle"])

        unused_bootstrap = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                "/enterprise/agents/bootstrap",
                "POST",
                {"deploymentId": deployment_id, "agentId": agent_id},
                arguments.tenant,
            ),
        )
        if unused_bootstrap["statusCode"] != 201:
            raise RuntimeError(f"pre-replacement bootstrap issuance failed: {unused_bootstrap}")
        unused_bootstrap_token = json.loads(unused_bootstrap["body"])["bootstrapToken"]
        replacement = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                f"/enterprise/agents/{deployment_id}/{agent_id}/replace",
                "POST",
                {
                    "expectedLifecycleRevision": 1,
                    "replacementAgentId": replacement_agent_id,
                    "reason": "Synthetic managed device replacement acceptance exercise.",
                },
                arguments.tenant,
            ),
        )
        if replacement["statusCode"] != 201:
            raise RuntimeError(f"agent replacement failed: {replacement}")
        replacement_body = json.loads(replacement["body"])
        if (
            replacement_body.get("predecessor", {}).get("lifecycle_state") != "revoked"
            or replacement_body.get("replacement", {}).get("lifecycle_state") != "active"
            or replacement_body.get("requiresBootstrap") is not True
            or replacement_body.get("replacement", {}).get("owner_id")
            != "aws-control-plane-smoke-reviewed"
            or replacement_body.get("replacement", {}).get("ownership_revision") != 2
            or replacement_body.get("replacement", {}).get("team") != "automated-acceptance"
        ):
            raise RuntimeError(f"replacement lifecycle contract failed: {replacement_body}")
        denied_old_session, _ = _request(
            f"{arguments.api_url.rstrip('/')}/agent/{deployment_id}/{agent_id}/heartbeat",
            "POST",
            body={},
            token=session_token,
            project_root_digest=project_root_digest,
        )
        denied_old_bootstrap, _ = _request(
            f"{arguments.api_url.rstrip('/')}/agent/enroll",
            "POST",
            body={
                "bootstrapToken": unused_bootstrap_token,
                "projectRoot": "/synthetic/project",
            },
        )
        if denied_old_session != 403 or denied_old_bootstrap != 403:
            raise RuntimeError(
                "replacement did not immediately deny predecessor capabilities: "
                f"session={denied_old_session}, bootstrap={denied_old_bootstrap}"
            )
        replacement_bootstrap = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                "/enterprise/agents/bootstrap",
                "POST",
                {"deploymentId": deployment_id, "agentId": replacement_agent_id},
                arguments.tenant,
            ),
        )
        if replacement_bootstrap["statusCode"] != 201:
            raise RuntimeError(f"replacement bootstrap issuance failed: {replacement_bootstrap}")
        replacement_bootstrap_token = json.loads(replacement_bootstrap["body"])["bootstrapToken"]
        replacement_enrollment_status, replacement_enrollment = _request(
            f"{arguments.api_url.rstrip('/')}/agent/enroll",
            "POST",
            body={
                "bootstrapToken": replacement_bootstrap_token,
                "projectRoot": "/synthetic/project",
            },
        )
        if replacement_enrollment_status != 201:
            raise RuntimeError(
                "replacement did not require and accept fresh enrollment: "
                f"{replacement_enrollment_status} {replacement_enrollment}"
            )
        replacement_session_token = replacement_enrollment["accessToken"]
        offboarded = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                f"/enterprise/agents/{deployment_id}/{agent_id}/offboard",
                "POST",
                {
                    "expectedLifecycleRevision": 2,
                    "reason": "Synthetic evidence-retaining offboarding acceptance exercise.",
                },
                arguments.tenant,
            ),
        )
        offboarded_body = json.loads(offboarded["body"])
        if (
            offboarded["statusCode"] != 200
            or offboarded_body.get("lifecycle_state") != "deleted"
            or offboarded_body.get("project_root") != ""
            or not offboarded_body.get("project_root_hash")
        ):
            raise RuntimeError(f"evidence-retaining offboarding failed: {offboarded}")
        print(
            "AWS control-plane smoke passed: auth, enrollment, accountable ownership/CAS, "
            "bulk group preview/partial apply/replay/audit, "
            "heartbeat, managed-host "
            "missing/conflict enforcement, policy, agent verification, "
            "approval replay, emergency-stop enforcement/recovery, and "
            "multi-process/runtime-connected durable idempotency, and WORM audit "
            "retention, SNS/SQS alert delivery, and irreversible replacement/offboarding"
        )
        if not runtime_attestation_proven:
            print(
                "Runtime attestation remains explicitly not configured; this acceptance did not "
                "claim release provenance or full agent verification."
            )
        return 0
    finally:
        if session_token:
            control_table.delete_item(
                Key={
                    "pk": f"AGENT_SESSION#{hashlib.sha256(session_token.encode()).hexdigest()}",
                    "sk": "SESSION",
                }
            )
        if replacement_session_token:
            control_table.delete_item(
                Key={
                    "pk": (
                        "AGENT_SESSION#"
                        f"{hashlib.sha256(replacement_session_token.encode()).hexdigest()}"
                    ),
                    "sk": "SESSION",
                }
            )
        for bootstrap_token in (unused_bootstrap_token, replacement_bootstrap_token):
            if bootstrap_token:
                control_table.delete_item(
                    Key={
                        "pk": (
                            "AGENT_BOOTSTRAP#"
                            f"{hashlib.sha256(bootstrap_token.encode()).hexdigest()}"
                        ),
                        "sk": "TOKEN",
                    }
                )
        if group_assigned:
            _invoke(
                lambda_client,
                arguments.function_name,
                _event(
                    f"/enterprise/groups/group-platform/agents/{deployment_id}/{agent_id}",
                    "DELETE",
                    {},
                    arguments.tenant,
                ),
            )
            _invoke(
                lambda_client,
                arguments.function_name,
                _event(
                    (
                        "/enterprise/groups/group-platform/agents/"
                        f"{deployment_id}/{replacement_agent_id}"
                    ),
                    "DELETE",
                    {},
                    arguments.tenant,
                ),
            )
        control_table.delete_item(
            Key={"pk": f"TENANT#{arguments.tenant}", "sk": f"AGENT#{agent_key}"}
        )
        control_table.delete_item(
            Key={
                "pk": f"TENANT#{arguments.tenant}",
                "sk": f"AGENT#{deployment_id}:{replacement_agent_id}",
            }
        )
        control_table.delete_item(
            Key={"pk": f"TENANT#{arguments.tenant}", "sk": f"APPROVAL#{approval_id}"}
        )
        control_table.delete_item(
            Key={
                "pk": f"TENANT#{arguments.tenant}",
                "sk": f"GROUP_MEMBERSHIP_OPERATION#{membership_request_id}",
            }
        )
        for kind, item_id in (
            ("CONFIGURATION", deployment_id),
            ("TEMPLATE", template_id),
            ("DEPLOYMENT", deployment_id),
        ):
            control_table.delete_item(
                Key={"pk": f"TENANT#{arguments.tenant}", "sk": f"{kind}#{item_id}"}
            )
        idempotency_table.delete_item(Key={"pk": operation_key})
        idempotency_table.delete_item(Key={"pk": f"aws-smoke-runtime-operation-{suffix}"})
        idempotency_table.delete_item(Key={"pk": f"aws-smoke-process-race-{suffix}"})


if __name__ == "__main__":
    sys.exit(main())
