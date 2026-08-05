# Security policy

## Supported versions

The latest `1.x` release line receives security fixes. A superseded minor line
is supported only when the release notes explicitly state a temporary overlap.
Pre-`1.0` development releases are unsupported. Security fixes follow Semantic
Versioning unless preserving compatibility would leave the security boundary
unsafe.

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues. Use the
repository’s enabled GitHub private vulnerability reporting channel. If that
channel is unavailable, contact the maintainers through the repository’s
private security contact. The canonical intake route is
[GitHub private vulnerability reporting](https://github.com/tommycharade/aai-sec-sdk/security/advisories/new).

Include:

- affected version or commit;
- security boundary and component involved;
- minimal reproduction using synthetic data;
- impact and likely exploit path;
- any suggested mitigation.

For a report containing enough information to begin investigation, the public
targets are:

| Severity | Acknowledge | Initial assessment | Notify affected customers after impact confirmation | Remediation target |
| --- | ---: | ---: | ---: | ---: |
| Critical | 24 hours | 48 hours | 48 hours | 7 days |
| High | 48 hours | 120 hours | 120 hours | 30 days |
| Medium | 120 hours | 240 hours | Case-by-case | 90 days |
| Low | 240 hours | 480 hours | Case-by-case | 180 days |

These are calendar-time targets, not a claim that every report is valid or that
an unsafe fixed deadline overrides coordinated disclosure. Severity uses CVSS
v3.1 plus exploitability and impact on the documented security boundary. If a
target cannot be met, maintainers must document an owner, revised date,
compensating control and disclosure impact. Security fixes remain available to
open-source users; commercial support terms may tighten but cannot weaken these
targets. See [Vulnerability management](docs/vulnerability-management.md).

We investigate privately and coordinate disclosure after a fix or effective
mitigation is available. Do not include credentials, customer data, or live
targets in a report.

The SDK is a security control component, not a guarantee that an agent is safe. Reports about bypasses of the execution boundary, identity confusion, approval replay, audit leakage, or unsafe defaults are especially valuable.
