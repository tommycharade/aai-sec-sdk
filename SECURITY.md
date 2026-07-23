# Security policy

## Supported versions

Until the first stable release, only the latest `0.1.x` development line is supported. Security fixes may be released without preserving experimental APIs. After `1.0.0`, the support matrix will be maintained in the documentation and changelog.

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues. Use the
repository’s enabled GitHub private vulnerability reporting channel. If that
channel is unavailable, contact the maintainers through the repository’s
private security contact.

Include:

- affected version or commit;
- security boundary and component involved;
- minimal reproduction using synthetic data;
- impact and likely exploit path;
- any suggested mitigation.

We will acknowledge reports as soon as practical, investigate privately, and coordinate disclosure after a fix or mitigation is available. Do not include credentials, customer data, or live targets in a report.

The SDK is a security control component, not a guarantee that an agent is safe. Reports about bypasses of the execution boundary, identity confusion, approval replay, audit leakage, or unsafe defaults are especially valuable.
