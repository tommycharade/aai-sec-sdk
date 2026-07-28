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
) -> tuple[int, dict[str, Any]]:
    """Make one JSON request and return status plus decoded response."""
    if urlparse(url).scheme != "https":
        raise ValueError("AWS control-plane smoke tests require an HTTPS endpoint")
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = f"Bearer {token}"
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
    deployment_id = "deployment-claude-local"
    agent_id = f"aws-smoke-{suffix}"
    agent_key = f"{deployment_id}:{agent_id}"
    approval_id = f"aws-smoke-approval-{suffix}"
    session_token = ""
    group_assigned = False
    operation_key = f"aws-smoke-operation-{suffix}"
    try:
        unauthenticated, _ = _request(f"{arguments.api_url.rstrip('/')}/enterprise/agents", "GET")
        if unauthenticated != 401:
            raise RuntimeError(f"expected unauthenticated API 401, received {unauthenticated}")

        registered = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                "/enterprise/agents/register",
                "POST",
                {
                    "deploymentId": deployment_id,
                    "agentId": agent_id,
                    "host": "AWS control-plane smoke",
                    "projectRoot": "/synthetic/project",
                },
                arguments.tenant,
            ),
        )
        if registered["statusCode"] != 201:
            raise RuntimeError(f"agent registration failed: {registered}")
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
        assigned = _invoke(
            lambda_client,
            arguments.function_name,
            _event(
                "/enterprise/groups/group-platform/agents",
                "POST",
                {"deploymentId": deployment_id, "agentId": agent_id},
                arguments.tenant,
            ),
        )
        if assigned["statusCode"] != 200:
            raise RuntimeError(f"agent group assignment failed: {assigned}")
        group_assigned = True
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
            {"bootstrapToken": bootstrap_token, "host": "AWS control-plane smoke"},
        )
        if enrolled_status != 201:
            raise RuntimeError(f"agent enrollment failed: {enrolled_status} {enrolled}")
        session_token = enrolled["accessToken"]
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
        effective = agent_client.effective_policy()
        if effective.get("policy", {}).get("id") != "policy-safe-default":
            raise RuntimeError("AWS agent client did not receive the assigned policy")
        if agent_client.heartbeat(session_token).get("status") != "connected":
            raise RuntimeError("AWS agent client heartbeat failed")
        heartbeat_status, _ = _request(
            f"{arguments.api_url.rstrip('/')}/agent/{deployment_id}/{agent_id}/heartbeat",
            "POST",
            token=session_token,
        )
        if heartbeat_status != 200:
            raise RuntimeError(f"heartbeat failed: {heartbeat_status}")
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
        if connected_verification_body.get("verified") is not True:
            raise RuntimeError(
                f"verification rejected a connected, assigned agent: {connected_verification}"
            )

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
        if recovered_verification_body.get("verified") is not True:
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
            consume,
            session_token,
        )
        replay_status, replay = _request(
            f"{arguments.api_url.rstrip('/')}/agent/{deployment_id}/{agent_id}/approvals/consume",
            "POST",
            consume,
            session_token,
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
        print(
            "AWS control-plane smoke passed: auth, enrollment, heartbeat, policy, "
            "agent verification, "
            "approval replay, emergency-stop enforcement/recovery, and "
            "multi-process/runtime-connected durable idempotency, and WORM audit "
            "retention, and SNS/SQS alert delivery"
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
        control_table.delete_item(
            Key={"pk": f"TENANT#{arguments.tenant}", "sk": f"AGENT#{agent_key}"}
        )
        control_table.delete_item(
            Key={"pk": f"TENANT#{arguments.tenant}", "sk": f"APPROVAL#{approval_id}"}
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
        idempotency_table.delete_item(Key={"pk": operation_key})
        idempotency_table.delete_item(Key={"pk": f"aws-smoke-runtime-operation-{suffix}"})
        idempotency_table.delete_item(Key={"pk": f"aws-smoke-process-race-{suffix}"})


if __name__ == "__main__":
    sys.exit(main())
