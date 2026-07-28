# Release evidence: v1.0.1

This record captures an independent verification of the public `v1.0.1`
release, performed from a clean checkout on 2026-07-27.

## Source identity

- Tag: `v1.0.1`
- Release commit: `baa1fb5ae409655e0c6a25d9cca9ef4f46c130c7`
- Release workflow: `.github/workflows/release-artifacts.yml`

## Verification performed

The published GitHub Release assets were downloaded into a directory outside
the clean source checkout. The verifier was run with the checked-out tag:

```bash
python scripts/verify_release_evidence.py dist \
  --commit baa1fb5ae409655e0c6a25d9cca9ef4f46c130c7 \
  --tag v1.0.1
```

Result:

```text
Verified 2 artifact subjects, SBOM bindings, checksums, and tag v1.0.1.
```

GitHub attestations were then verified for both the wheel and source archive:

```bash
gh attestation verify dist/agentic_security_sdk-1.0.1-py3-none-any.whl \
  --repo tommycharade/aai-sec-sdk \
  --signer-workflow tommycharade/aai-sec-sdk/.github/workflows/release-artifacts.yml \
  --source-ref refs/tags/v1.0.1
gh attestation verify dist/agentic_security_sdk-1.0.1.tar.gz \
  --repo tommycharade/aai-sec-sdk \
  --signer-workflow tommycharade/aai-sec-sdk/.github/workflows/release-artifacts.yml \
  --source-ref refs/tags/v1.0.1
```

Both commands exited successfully. This evidence supersedes the historical
`v1.0.0` bundle finding; future releases must repeat the same independent
post-publication verification.
