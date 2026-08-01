# Policy change assurance live acceptance — 2026-08-01

## Scope

This acceptance exercised the deployed AWS control plane after SDK pull request
[#81](https://github.com/tommycharade/aai-sec-sdk/pull/81) and UI pull request
[#39](https://github.com/tommycharade/aai-sec-ui/pull/39) were merged. It used an
isolated synthetic tenant in AWS account `396510133537`, region `eu-west-2`.
No customer data or production credentials were used.

The test created an active policy, a pending immutable candidate, one group,
one synthetic agent binding and four redacted historical decisions. The
candidate removed Write authority, increased an action limit, removed one MCP
server and enabled audit content capture.

## Result

All acceptance assertions passed:

| Assertion | Result |
| --- | --- |
| Policy approver can read the semantic diff | Pass — HTTP 200 |
| Policy author can run simulation | Pass — HTTP 200 |
| Independent policy approver can run simulation | Pass — HTTP 200 |
| Fleet operator cannot run simulation | Pass — HTTP 403 |
| Other tenant cannot discover the candidate | Pass — HTTP 404 |
| Simulation is bound to the candidate content hash | Pass |
| Repeated simulations produce the same evidence hash | Pass |
| Simulation leaves the tenant partition unchanged | Pass |
| Evidence sample advertises the 250-decision bound | Pass |
| Redacted command and MCP evidence remains indeterminate | Pass |
| Candidate predicts the historical Write action would be denied | Pass |
| Semantic diff reports the action-limit authority expansion | Pass |
| Semantic diff reports increased data capture | Pass |

The live result sampled four decisions. Two were determinate, two were
indeterminate, one determinate decision changed, and determinate coverage was
50%. The semantic summary contained one authority expansion, four authority
restrictions and one data-capture change.

Candidate content hash:
`37e5fa5671d1fc701409453151fc222179686aede73eaf6b559a874dc186163e`

Simulation evidence hash:
`57da9f8fe4dc8334d99171ec9bf08ba7575a9fa4d00b8a7c3333c9d03bcfcf97`

## UI delivery evidence

CloudFormation updated the control-plane Lambda successfully. The UI build was
uploaded to the private S3 origin and CloudFront invalidation
`I2P09ZVFMRQS675BEIGN16Y6KN` completed. The production distribution served
`index-VPDreHnK.js` and `index-BifUCeFe.css` with HTTP 200. A clean browser
session rendered the public application without console errors.

## Cleanup and limits

The acceptance runner compared the complete synthetic tenant partition before
and after both simulation calls, then deleted both isolated tenant partitions.
It did not activate the candidate or execute an agent action.

This proves the deployed API contract, tenancy controls, role controls,
read-only behavior and honest handling of retained evidence for this scenario.
It does not prove that a simulation predicts unseen future actions, reconstruct
redacted command text, identifies an MCP server that was not retained, or proves
endpoint convergence. Those non-guarantees remain visible in the UI and the
[policy change assurance design](policy-change-assurance-design.md).
