# Endpoint detection and response

The hosted control plane turns server-derived endpoint evidence health into a
durable, tenant-scoped security-operations workflow. It does not trust a
device-supplied health label and it does not describe acknowledgement as
remediation.

## Operating model

Every tenant that publishes endpoint-management inventory is registered in a
16-shard DynamoDB detection index. An EventBridge rule invokes the control
plane every five minutes. Each cycle loads the tenant's authoritative MDM
devices, current per-device credential and newest signed sensor report, then
derives health using the same function shown in the UI.

The cycle is bounded to 2,000 registered tenants. An oversized shard or tenant
inventory fails the invocation instead of silently omitting tenants.
EventBridge retries twice for at most one hour and sends an exhausted event to
a dedicated 14-day SQS dead-letter queue. A CloudWatch alarm publishes DLQ
growth to the control-plane security-alert topic.

Fresh operator reads also reconcile detections. This provides immediate UI
convergence without making a browser poll the only monitoring mechanism.

## Detection catalogue

The first catalogue covers:

- sensor not enrolled or credential revoked;
- fresh evidence required after credential rotation;
- missing or stale reports;
- stale or unmanaged MDM inventory;
- missing installation, binary or active process evidence;
- invalid report signatures; and
- validly signed replayed or reordered reports.

One root condition produces one deterministic opaque alert ID. For example, a
device without a credential produces `endpoint_sensor_not_enrolled`, not a
second derivative `endpoint_report_missing` alert. Repeated reconciliation does
not increase its occurrence count, revision or notification volume.

Continuous posture alerts resolve only when server-derived health recovers.
Signature and replay alerts describe observed security events and therefore
remain retained until an incident responder acknowledges them; a later clean
report cannot erase the event.

## Alert lifecycle

Alerts use `open`, `acknowledged` and `resolved` states with optimistic
revisions. The record contains only fixed messages, device ID, reason code,
severity, timestamps, occurrence count and delivery state. Report content,
project paths, user identity, sensor secrets and bearer digests are excluded.

Acknowledgement requires the `incident_response` capability, the live revision
and a 20-to-500-character investigation rationale. Known credential-shaped
text is rejected. The acknowledgement records ownership but does not:

- fix the endpoint condition;
- clear an emergency stop;
- stop Claude Code or Codex;
- revoke an agent identity; or
- prove delivery to Splunk.

The alert resolves automatically only after the underlying endpoint health
condition clears. A later recurrence reopens the same alert with a new
revision and sends a new notification.

## Delivery boundary

New and reopened alerts are published as normalized schema-1 JSON to the AWS
SNS security-alert topic. The subscribed encrypted SQS operations queue gives
14 days of durable, at-least-once delivery with a five-attempt dead-letter
policy. Alert ID and revision are included for consumer deduplication.

If notification delivery fails, the DynamoDB alert remains `pending`; the next
scheduled cycle retries it. Provider exception text and report content are not
logged.

Splunk remains an explicit product stub. The UI says **Splunk parked**, and the
integration contract continues to report `deliveryVerified: false`. The AWS
operations queue is real delivery evidence but must never be presented as
Splunk HEC delivery.

## API

Tenant operators with alert-read authority use:

```text
GET /api/enterprise/alerts
```

Incident responders acknowledge one live revision with:

```http
POST /api/enterprise/alerts/{alertId}/acknowledge
Content-Type: application/json

{
  "expectedRevision": 2,
  "reason": "Investigating with endpoint engineering under case INC-42."
}
```

Stale revisions, duplicate acknowledgement, insufficient roles, malformed
bodies and credential-shaped rationale fail closed.

## Response runbook

1. Open **Deployments → Rollouts & health** and select the endpoint detection.
2. Confirm the MDM device, credential state, report age and installation
   evidence under **Coverage → Endpoint sensors**.
3. Record the case owner and next action through acknowledgement.
4. Rotate or revoke the sensor credential if device identity is in doubt.
5. Use the existing agent or group emergency stop only after independently
   resolving the affected enrolled identity. Sensor evidence is observational
   and cannot grant itself containment authority.
6. Restore service only after a new signed report and current MDM inventory
   clear the condition.

## Approved automatic response

The **Incidents → Response rules** workspace can establish narrowly bounded
automatic containment for these server-derived detections. A typed rule fixes
the reason codes, severities, Claude Code/Codex host scope, hourly action limit,
per-agent cooldown and priority. Its only action is SDK quarantine of the exact
agent identified by a fresh unique server-derived binding.

Saving creates a draft, not authority. The author submits an immutable version;
a different subject approves it; and activation compares the exact current
active version. Operators can preview current matches without mutation,
immediately disable automatic authority, or atomically restore an independently
approved superseded version. Each match or safe skip has an idempotent,
content-hashed response record. Merely reading alerts cannot run containment.

See [Approved automatic response rules](automatic-response-rules-design.md) for
the rule language, governance lifecycle, non-guarantees and acceptance model.

## Limitations

This tranche provides detections, durable local delivery, revisioned incident
cases, authoritative endpoint-to-agent binding and approved automatic SDK
quarantine. It does not provide MDM/EDR device isolation, process termination,
network isolation, automatic third-party credential revocation, maintenance
windows, anomaly baselines or a production SIEM adapter. Those remain explicit
P1 work.
