"""Run content-free Regional fault canaries inside the target handler role.

This module is reachable only through a direct Lambda invocation. API Gateway
events cannot match its exact top-level schema. The caller selects only a
code-owned dependency name; all resource identities come from this Lambda's
deployment environment so untrusted workflow input cannot redirect a probe.
"""

import hashlib
import json
import os
import re

try:
    import boto3
except ImportError:  # pragma: no cover - AWS Lambda provides boto3.
    boto3 = None


class RegionalFaultTargetError(RuntimeError):
    """Report a malformed or unsupported internal target probe."""


_FIELDS = {"source", "schemaVersion", "phase", "faultId", "authoritySha256", "dependency"}
_PHASES = {
    "dependency-unavailable",
    "execution-denied-no-bypass",
    "dependency-and-target-recovered",
}
_DEPENDENCIES = {"audit", "dynamodb", "kms", "queue"}
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _required(name):
    """Return one deployment-owned value without accepting ambient fallback."""
    value = os.environ.get(name, "").strip()
    if not value:
        raise RegionalFaultTargetError(f"{name} is required")
    return value


def _aws_client(service):
    """Create one AWS client or fail closed outside the Lambda runtime."""
    if boto3 is None:
        raise RegionalFaultTargetError("AWS provider is unavailable")
    return boto3.client(service)


def _evidence(event, status, operation_count, *, error_code=None):
    """Return a content-free observation bound to the complete probe request."""
    canonical = {
        "authoritySha256": event["authoritySha256"],
        "dependency": event["dependency"],
        "faultId": event["faultId"],
        "operationCount": operation_count,
        "phase": event["phase"],
        "providerStatus": status,
    }
    if error_code is not None:
        canonical["errorCode"] = error_code
    return {
        **canonical,
        "evidenceSha256": hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def _provider_error_code(error):
    """Extract only a bounded provider code; never return provider messages."""
    code = getattr(error, "response", {}).get("Error", {}).get("Code")
    return code if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9.:-]{1,80}", code) else None


def run(event, *, clients=None):
    """Perform one exact provider canary under the target Lambda execution role.

    Provider access denials are observations, not exceptions, because the
    independent witness must distinguish the intended IAM boundary from a
    malformed request or an unrelated runtime failure. All other failures
    escape and fail the Step Functions task closed.
    """
    if (
        not isinstance(event, dict)
        or set(event) != _FIELDS
        or event.get("source") != "aai.regional-fault-target-probe"
        or event.get("schemaVersion") != 1
        or event.get("phase") not in _PHASES
        or event.get("dependency") not in _DEPENDENCIES
        or not isinstance(event.get("faultId"), str)
        or not _UUID.fullmatch(event["faultId"])
        or not isinstance(event.get("authoritySha256"), str)
        or not _SHA256.fullmatch(event["authoritySha256"])
    ):
        raise RegionalFaultTargetError("Regional fault target event is invalid")
    factory = clients or {}
    dependency = event["dependency"]
    operation_count = 0
    try:
        if dependency == "audit":
            client = factory.get("s3") or _aws_client("s3")
            body = json.dumps(
                {"faultId": event["faultId"], "synthetic": True},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            key = f"regional-fault-canary/{event['faultId']}/{event['phase']}.json"
            client.put_object(
                Bucket=_required("AUDIT_BUCKET"),
                Key=key,
                Body=body,
                ContentType="application/json",
            )
            operation_count = 1
        elif dependency == "dynamodb":
            client = factory.get("dynamodb") or _aws_client("dynamodb")
            names = [
                _required("CONTROL_TABLE"),
                _required("PRESENCE_TABLE"),
                _required("IDEMPOTENCY_TABLE"),
                _required("SCIM_TABLE"),
            ]
            for name in names:
                client.get_item(
                    TableName=name,
                    Key={"pk": {"S": f"FAULT_CANARY#{event['faultId']}"}, "sk": {"S": "PROBE"}},
                    ConsistentRead=True,
                )
                operation_count += 1
        elif dependency == "kms":
            client = factory.get("kms") or _aws_client("kms")
            digest = hashlib.sha256(
                f"{event['faultId']}:{event['authoritySha256']}:{event['phase']}".encode()
            ).digest()
            key_id = _required("POLICY_SIGNING_KEY_ARN")
            client.get_public_key(KeyId=key_id)
            operation_count += 1
            client.sign(
                KeyId=key_id,
                Message=digest,
                MessageType="DIGEST",
                SigningAlgorithm="ECDSA_SHA_256",
            )
            operation_count += 1
        else:
            client = factory.get("sqs") or _aws_client("sqs")
            client.send_message(
                QueueUrl=_required("REGIONAL_FAULT_CANARY_QUEUE_URL"),
                MessageBody=json.dumps(
                    {"faultId": event["faultId"], "synthetic": True},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
            operation_count = 1
    except Exception as error:
        code = _provider_error_code(error)
        if code not in {"AccessDenied", "AccessDeniedException"}:
            raise
        return _evidence(event, "denied", operation_count, error_code=code)
    return _evidence(event, "available", operation_count)
