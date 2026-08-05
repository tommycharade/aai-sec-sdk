# Security policy

## Supported versions

The supported stable line is `1.x`. The latest published patch receives
security fixes. For a normal patch release, the immediately preceding patch
remains supported for a 30-calendar-day fleet upgrade window. A release notice
may shorten that window only for an actively exploited or critical boundary
bypass and must state the reason, compensating control and effective date.
Development branches, forks and locally modified packages are not supported
releases.

This narrow policy is intentional for an execution-security boundary: adopters
must not assume that an older patch remains supported beyond its stated
overlap. Verify the installed artifact against the published checksum, SBOM and
provenance.

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues. Use the
canonical [GitHub private vulnerability reporting](https://github.com/tommycharade/aai-sec-sdk/security/advisories/new)
channel. There is
currently no separately staffed fallback intake. If GitHub private reporting
is unavailable, do not disclose the report publicly: retain it and retry the
private channel. The project owner must publish an alternate authenticated
intake before representing the hosted service as production-supported.

Include:

- affected version or commit;
- security boundary and component involved;
- minimal reproduction using synthetic data;
- impact and likely exploit path;
- any suggested mitigation.

Do not include credentials, customer data or live targets in a report. The
[vulnerability-management policy](docs/vulnerability-management.md) defines
severity, evidence, coordinated disclosure and calendar-time targets. Critical
reports are acknowledged within 4 hours, triaged within 24 hours, targeted for
mitigation within 24 hours and remediation within 7 days. High reports are
acknowledged within 8 hours, triaged within 48 hours, targeted for mitigation
within 72 hours and remediation within 30 days. Confirmed affected customers
are notified within 24 hours for critical and 48 hours for high severity.

These are open-source project response targets, not a contractual SLA or proof
of 24x7 staffing, and not a promise that every report is a vulnerability
or that a safe fix exists before investigation. A missed target requires a
named owner, rationale, compensating controls, an expiring exception and
continued customer updates; it is not silently reclassified.

The SDK is a security control component, not a guarantee that an agent is safe. Reports about bypasses of the execution boundary, identity confusion, approval replay, audit leakage, or unsafe defaults are especially valuable.

## Scope and disclosure

Security reports cover supported SDK artifacts and the reference hosted
control-plane code. Customer-created policies, external model behaviour,
unmanaged launch paths, permissive customer IAM and unsupported forks are not
automatically product vulnerabilities, although boundary failures involving
them may still be in scope.

We coordinate disclosure after affected-user containment and a verified fix or
mitigation are available. Open-source users should monitor GitHub security
advisories and releases. No public bug-bounty payment is offered unless a
separate written programme says otherwise.
