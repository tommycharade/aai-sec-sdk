# Data processing and subprocessors

## Status

This is a technical disclosure for architecture and pilot planning. Legal
approval is still required. It is not an executed Data Processing Addendum
(DPA), and the hosted product must not process pilot personal data until the
contracting entity, controller/processor roles, transfer terms and customer
instructions are approved.

## Intended processing boundary

The open-source SDK can run entirely in the adopter's environment. In the
hosted enterprise control plane, the customer is expected to control agent
purpose, identity, policy and connected systems; the service processes bounded
security and operational metadata to enforce and evidence those instructions.

Default retained categories include tenant and opaque agent identifiers,
policy/version references, structured decisions, approval lifecycle, health,
configuration digests, timestamps and content-minimised audit evidence. Raw
prompts, tool arguments/results, credentials, source files and project paths
are excluded by default. Optional capture requires explicit policy,
classification, redaction and retention review.

## Technical subprocessor inventory

| Provider | Purpose | Customer content boundary | Region/transfer status |
| --- | --- | --- | --- |
| Amazon Web Services | Hosted compute, API, encrypted persistence, immutable evidence, queues, keys and monitoring | Bounded control-plane metadata and configured retained evidence | Customer-approved deployment Region; final legal transfer terms required |
| GitHub | Public source, private vulnerability reporting, CI and release provenance | Repository content and security reports; no hosted customer control-plane data by design | GitHub terms apply; final legal review required |

Microsoft Entra ID, customer GitHub organizations, ServiceNow, Jira,
PagerDuty, Splunk and cloud credential providers are customer-selected
integrations. Whether a provider is a customer processor, independent
controller or our subprocessor depends on the final hosted data flow and
contract; this document does not silently classify it.

No provider may be added to the hosted customer-data path without a purpose,
data-category, Region/transfer, retention, security and deletion review plus an
updated notice before use.

## DPA requirements before hosted pilot

The executed DPA must define:

- legal entities and controller/processor roles;
- documented processing instructions, purpose and duration;
- data-subject categories and personal-data fields;
- confidentiality, security measures and incident notification;
- deletion/return, retention and legal-hold behavior;
- approved subprocessors and change-notice/objection process;
- international-transfer mechanism and locations;
- audit/assistance duties and liability terms; and
- customer-specific optional integrations and capture settings.

Technical deletion classes, retention controls, customer-managed keys and
residency behavior are documented in [Enterprise data
boundaries](enterprise-data-boundary-design.md). Those controls support a DPA;
they do not substitute for one.
