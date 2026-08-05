"""Safely configure and deploy the AWS control plane from persistent authority.

The deployment manifest contains identifiers and secret *names*, never secret
values. It is stored as an encrypted SSM parameter so a later routine deploy
cannot accidentally remove a configured identity provider merely because one
operator shell omitted ephemeral environment variables.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class DeploymentConfigurationError(ValueError):
    """Raised when identity deployment input cannot prove a safe configuration."""


Runner = Callable[..., subprocess.CompletedProcess[str]]
UrlOpener = Callable[..., Any]
_MANIFEST_FIELDS = {
    "schemaVersion",
    "entraTenantId",
    "entraClientId",
    "entraClientSecretName",
    "aaiTenantId",
    "entraScimTokenSecretName",
    "strongAuthenticationEnforced",
    "conditionalAccessEvidenceRef",
}
_RECOVERY_MANIFEST_FIELDS = {
    "schemaVersion",
    "replicaBucketArn",
    "replicaRegion",
    "recoveryEvidenceRef",
}
_POLICY_GITHUB_MANIFEST_V1_FIELDS = {
    "schemaVersion",
    "credentialSecretName",
    "allowedRepositories",
    "reviewEvidenceRef",
}
_POLICY_GITHUB_MANIFEST_V2_FIELDS = {
    "schemaVersion",
    "appPrivateKeySecretName",
    "appClientId",
    "installationId",
    "allowedRepositories",
    "reviewEvidenceRef",
}
_ASSURANCE_SIGNER_MANIFEST_FIELDS = {
    "schemaVersion",
    "currentSignerArn",
    "historicalVerificationKeyArns",
    "recoveryRegion",
    "approvalEvidenceRef",
}
_DATA_BOUNDARY_MANIFEST_FIELDS = {
    "schemaVersion",
    "homeRegion",
    "approvedDataRegions",
    "customerManagedDataKeyArn",
    "operatorAccessMode",
    "operatorAllowedIpv4Cidrs",
    "keyPolicyEvidenceRef",
    "residencyEvidenceRef",
    "deletionEvidenceRef",
    "conditionalAccessEvidenceRef",
    "approvalEvidenceRef",
}
_AWS_SECRET_NAME = re.compile(r"^[A-Za-z0-9/_+=.@-]{1,512}$")
_AAI_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_EVIDENCE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,511}$")
_AWS_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/+-]{0,127}$")
_AWS_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_MRK_ARN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):kms:([a-z]{2}(?:-gov)?-[a-z]+-\d):(\d{12}):key/(mrk-[0-9a-f]{32})$"
)
_KMS_KEY_ARN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):kms:([a-z]{2}(?:-gov)?-[a-z]+-\d):(\d{12}):key/"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$",
    re.IGNORECASE,
)
_ENTRA_ENVIRONMENT_FIELDS = (
    "ENTRA_TENANT_ID",
    "ENTRA_CLIENT_ID",
    "ENTRA_CLIENT_SECRET_NAME",
    "ENTRA_AAI_TENANT_ID",
    "ENTRA_SCIM_TOKEN_SECRET_NAME",
    "ENTRA_STRONG_AUTH_ENFORCED",
)
_RECOVERY_ENVIRONMENT_FIELDS = ("AUDIT_REPLICA_BUCKET_ARN", "AUDIT_REPLICA_REGION")
_POLICY_GITHUB_ENVIRONMENT_FIELDS = (
    "POLICY_GITHUB_SECRET_NAME",
    "POLICY_GITHUB_APP_SECRET_NAME",
    "POLICY_GITHUB_APP_CLIENT_ID",
    "POLICY_GITHUB_INSTALLATION_ID",
    "POLICY_GITHUB_ALLOWED_REPOSITORIES",
)
_S3_BUCKET_ARN = re.compile(r"^arn:(aws|aws-us-gov|aws-cn):s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_GITHUB_REPOSITORY = re.compile(
    r"^github\.com/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,38})/[A-Za-z0-9_.-]{1,100}$"
)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys before they can create ambiguous authority."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeploymentConfigurationError(f"duplicate manifest field: {key}")
        result[key] = value
    return result


def _uuid(value: object, field: str) -> str:
    """Return one canonical UUID or reject aliases and tenant-independent values."""
    if not isinstance(value, str):
        raise DeploymentConfigurationError(f"{field} must be a UUID string")
    try:
        canonical = str(UUID(value))
    except ValueError as error:
        raise DeploymentConfigurationError(f"{field} must be a canonical UUID") from error
    if value.lower() != canonical:
        raise DeploymentConfigurationError(f"{field} must use canonical UUID spelling")
    return canonical


def _bounded_string(value: object, field: str, *, maximum: int = 256) -> str:
    """Validate one non-empty, trimmed manifest string."""
    if not isinstance(value, str) or value != value.strip() or not 1 <= len(value) <= maximum:
        raise DeploymentConfigurationError(f"{field} must be a bounded non-empty string")
    return value


@dataclass(frozen=True)
class EntraDeploymentManifest:
    """Typed, secret-free identity configuration persisted for repeatable deployment."""

    entra_tenant_id: str
    entra_client_id: str
    entra_client_secret_name: str
    aai_tenant_id: str
    entra_scim_token_secret_name: str
    conditional_access_evidence_ref: str

    @classmethod
    def parse(cls, payload: str) -> EntraDeploymentManifest:
        """Parse a strict schema-v1 manifest and require the enterprise-safe posture."""
        if len(payload.encode("utf-8")) > 16_384:
            raise DeploymentConfigurationError("manifest exceeds the 16 KiB bound")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise DeploymentConfigurationError("manifest is not valid JSON") from error
        if not isinstance(value, dict) or set(value) != _MANIFEST_FIELDS:
            raise DeploymentConfigurationError(
                "manifest fields do not exactly match schema version 1"
            )
        if value["schemaVersion"] != 1:
            raise DeploymentConfigurationError("manifest schemaVersion must be 1")
        if value["strongAuthenticationEnforced"] is not True:
            raise DeploymentConfigurationError(
                "strongAuthenticationEnforced must be true for an enterprise deployment"
            )
        client_secret = _bounded_string(value["entraClientSecretName"], "entraClientSecretName")
        scim_secret = _bounded_string(value["entraScimTokenSecretName"], "entraScimTokenSecretName")
        if not _AWS_SECRET_NAME.fullmatch(client_secret) or not _AWS_SECRET_NAME.fullmatch(
            scim_secret
        ):
            raise DeploymentConfigurationError(
                "Secrets Manager names contain unsupported characters"
            )
        if client_secret == scim_secret:
            raise DeploymentConfigurationError("OIDC and SCIM must use separate secrets")
        aai_tenant = _bounded_string(value["aaiTenantId"], "aaiTenantId", maximum=128)
        if not _AAI_TENANT.fullmatch(aai_tenant):
            raise DeploymentConfigurationError("aaiTenantId has an unsupported format")
        evidence_reference = _bounded_string(
            value["conditionalAccessEvidenceRef"],
            "conditionalAccessEvidenceRef",
            maximum=512,
        )
        if not _EVIDENCE_REFERENCE.fullmatch(evidence_reference):
            raise DeploymentConfigurationError(
                "conditionalAccessEvidenceRef must be an opaque non-secret reference"
            )
        return cls(
            entra_tenant_id=_uuid(value["entraTenantId"], "entraTenantId"),
            entra_client_id=_uuid(value["entraClientId"], "entraClientId"),
            entra_client_secret_name=client_secret,
            aai_tenant_id=aai_tenant,
            entra_scim_token_secret_name=scim_secret,
            conditional_access_evidence_ref=evidence_reference,
        )

    def canonical_json(self) -> str:
        """Return the stable secret-free representation stored in Parameter Store."""
        return json.dumps(
            {
                "aaiTenantId": self.aai_tenant_id,
                "conditionalAccessEvidenceRef": self.conditional_access_evidence_ref,
                "entraClientId": self.entra_client_id,
                "entraClientSecretName": self.entra_client_secret_name,
                "entraScimTokenSecretName": self.entra_scim_token_secret_name,
                "entraTenantId": self.entra_tenant_id,
                "schemaVersion": 1,
                "strongAuthenticationEnforced": True,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def deployment_environment(self) -> dict[str, str]:
        """Return only non-secret CDK environment values and secret references."""
        return {
            "ENTRA_TENANT_ID": self.entra_tenant_id,
            "ENTRA_CLIENT_ID": self.entra_client_id,
            "ENTRA_CLIENT_SECRET_NAME": self.entra_client_secret_name,
            "ENTRA_AAI_TENANT_ID": self.aai_tenant_id,
            "ENTRA_SCIM_TOKEN_SECRET_NAME": self.entra_scim_token_secret_name,
            "ENTRA_STRONG_AUTH_ENFORCED": "true",
        }


@dataclass(frozen=True)
class AuditRecoveryManifest:
    """Typed, secret-free configuration for immutable cross-region audit recovery."""

    replica_bucket_arn: str
    replica_region: str
    recovery_evidence_ref: str

    @classmethod
    def parse(cls, payload: str) -> AuditRecoveryManifest:
        """Parse one exact recovery manifest and reject ambiguous bucket authority."""
        if len(payload.encode("utf-8")) > 16_384:
            raise DeploymentConfigurationError("recovery manifest exceeds the 16 KiB bound")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise DeploymentConfigurationError("recovery manifest is not valid JSON") from error
        if not isinstance(value, dict) or set(value) != _RECOVERY_MANIFEST_FIELDS:
            raise DeploymentConfigurationError(
                "recovery manifest fields do not exactly match schema version 1"
            )
        if value["schemaVersion"] != 1:
            raise DeploymentConfigurationError("recovery manifest schemaVersion must be 1")
        bucket_arn = _bounded_string(value["replicaBucketArn"], "replicaBucketArn")
        if not _S3_BUCKET_ARN.fullmatch(bucket_arn):
            raise DeploymentConfigurationError("replicaBucketArn must be one exact S3 bucket ARN")
        replica_region = _bounded_string(value["replicaRegion"], "replicaRegion", maximum=32)
        if not _AWS_REGION.fullmatch(replica_region):
            raise DeploymentConfigurationError("replicaRegion is malformed")
        evidence_ref = _bounded_string(
            value["recoveryEvidenceRef"], "recoveryEvidenceRef", maximum=512
        )
        if not _EVIDENCE_REFERENCE.fullmatch(evidence_ref):
            raise DeploymentConfigurationError(
                "recoveryEvidenceRef must be an opaque non-secret reference"
            )
        return cls(bucket_arn, replica_region, evidence_ref)

    @property
    def replica_bucket_name(self) -> str:
        """Return the validated destination bucket name without accepting an object ARN."""
        return self.replica_bucket_arn.rsplit(":::", 1)[1]

    def canonical_json(self) -> str:
        """Return the deterministic representation stored in Parameter Store."""
        return json.dumps(
            {
                "recoveryEvidenceRef": self.recovery_evidence_ref,
                "replicaBucketArn": self.replica_bucket_arn,
                "replicaRegion": self.replica_region,
                "schemaVersion": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def deployment_environment(self) -> dict[str, str]:
        """Return the exact CDK variables authorized by the persisted manifest."""
        return {
            "AUDIT_REPLICA_BUCKET_ARN": self.replica_bucket_arn,
            "AUDIT_REPLICA_REGION": self.replica_region,
        }


@dataclass(frozen=True)
class PolicyGitHubDeploymentManifest:
    """Reviewed, secret-free authority for exact-version GitHub policy sources."""

    schema_version: int
    credential_secret_name: str | None
    app_private_key_secret_name: str | None
    app_client_id: str | None
    installation_id: str | None
    allowed_repositories: tuple[str, ...]
    review_evidence_ref: str

    @classmethod
    def parse(cls, payload: str) -> PolicyGitHubDeploymentManifest:
        """Parse a closed schema and reject wildcard or duplicate repository authority."""
        if len(payload.encode("utf-8")) > 16_384:
            raise DeploymentConfigurationError("policy GitHub manifest exceeds the 16 KiB bound")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise DeploymentConfigurationError(
                "policy GitHub manifest is not valid JSON"
            ) from error
        if not isinstance(value, dict) or value.get("schemaVersion") not in {1, 2}:
            raise DeploymentConfigurationError(
                "policy GitHub manifest fields require schemaVersion 1 or 2"
            )
        schema_version = value["schemaVersion"]
        expected_fields = (
            _POLICY_GITHUB_MANIFEST_V1_FIELDS
            if schema_version == 1
            else _POLICY_GITHUB_MANIFEST_V2_FIELDS
        )
        if set(value) != expected_fields:
            raise DeploymentConfigurationError(
                "policy GitHub manifest fields do not exactly match "
                f"schema version {schema_version}"
            )
        secret_field = "credentialSecretName" if schema_version == 1 else "appPrivateKeySecretName"
        secret_name = _bounded_string(value[secret_field], secret_field, maximum=512)
        if not _AWS_SECRET_NAME.fullmatch(secret_name):
            raise DeploymentConfigurationError(f"{secret_field} contains unsupported characters")
        repositories = value["allowedRepositories"]
        if (
            not isinstance(repositories, list)
            or not 1 <= len(repositories) <= 100
            or any(not isinstance(repository, str) for repository in repositories)
        ):
            raise DeploymentConfigurationError("allowedRepositories must contain 1-100 strings")
        normalized = tuple(repositories)
        if len(set(normalized)) != len(normalized) or any(
            not _GITHUB_REPOSITORY.fullmatch(repository) for repository in normalized
        ):
            raise DeploymentConfigurationError(
                "allowedRepositories must be unique exact github.com/owner/repository identities"
            )
        evidence_ref = _bounded_string(value["reviewEvidenceRef"], "reviewEvidenceRef", maximum=512)
        if not _EVIDENCE_REFERENCE.fullmatch(evidence_ref):
            raise DeploymentConfigurationError(
                "reviewEvidenceRef must be an opaque non-secret reference"
            )
        if schema_version == 1:
            return cls(1, secret_name, None, None, None, normalized, evidence_ref)
        client_id = _bounded_string(value["appClientId"], "appClientId", maximum=128)
        installation_id = _bounded_string(value["installationId"], "installationId", maximum=20)
        owners = {repository.split("/")[1].lower() for repository in normalized}
        if not re.fullmatch(r"[A-Za-z0-9._-]{6,128}", client_id):
            raise DeploymentConfigurationError("appClientId is malformed")
        if not re.fullmatch(r"[1-9][0-9]{0,19}", installation_id):
            raise DeploymentConfigurationError("installationId is malformed")
        if len(owners) != 1:
            raise DeploymentConfigurationError(
                "schema-v2 allowedRepositories must share one installation owner"
            )
        return cls(2, None, secret_name, client_id, installation_id, normalized, evidence_ref)

    def canonical_json(self) -> str:
        """Return the deterministic secret-free manifest persisted in Parameter Store."""
        value: dict[str, object] = {
            "allowedRepositories": list(self.allowed_repositories),
            "reviewEvidenceRef": self.review_evidence_ref,
            "schemaVersion": self.schema_version,
        }
        if self.schema_version == 1:
            value["credentialSecretName"] = self.credential_secret_name
        else:
            value.update(
                {
                    "appClientId": self.app_client_id,
                    "appPrivateKeySecretName": self.app_private_key_secret_name,
                    "installationId": self.installation_id,
                }
            )
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    def deployment_environment(self) -> dict[str, str]:
        """Return exact reviewed repository authority and one credential reference."""
        environment = {
            "POLICY_GITHUB_ALLOWED_REPOSITORIES": ",".join(self.allowed_repositories),
        }
        if self.schema_version == 1:
            environment["POLICY_GITHUB_SECRET_NAME"] = self.credential_secret_name or ""
        else:
            environment.update(
                {
                    "POLICY_GITHUB_APP_SECRET_NAME": self.app_private_key_secret_name or "",
                    "POLICY_GITHUB_APP_CLIENT_ID": self.app_client_id or "",
                    "POLICY_GITHUB_INSTALLATION_ID": self.installation_id or "",
                }
            )
        return environment


@dataclass(frozen=True)
class AssuranceSignerDeploymentManifest:
    """Persisted two-phase signer authority that routine deploys cannot forget."""

    current_signer_arn: str
    historical_verification_key_arns: tuple[str, ...]
    recovery_region: str
    approval_evidence_ref: str

    @classmethod
    def parse(cls, payload: str) -> AssuranceSignerDeploymentManifest:
        """Parse one exact current/history signer registry."""
        if len(payload.encode("utf-8")) > 16_384:
            raise DeploymentConfigurationError("assurance signer manifest exceeds 16 KiB")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise DeploymentConfigurationError("assurance signer manifest is invalid") from error
        if (
            not isinstance(value, dict)
            or set(value) != _ASSURANCE_SIGNER_MANIFEST_FIELDS
            or value.get("schemaVersion") != 1
        ):
            raise DeploymentConfigurationError("assurance signer manifest schema is invalid")
        current = value.get("currentSignerArn")
        history = value.get("historicalVerificationKeyArns")
        current_match = _MRK_ARN.fullmatch(current) if isinstance(current, str) else None
        if (
            current_match is None
            or not isinstance(history, list)
            or not 1 <= len(history) <= 8
            or len(set(history)) != len(history)
        ):
            raise DeploymentConfigurationError("assurance signer registry is invalid")
        for key_arn in history:
            match = _MRK_ARN.fullmatch(key_arn) if isinstance(key_arn, str) else None
            if (
                match is None
                or match.group(1) != current_match.group(1)
                or match.group(2) != current_match.group(2)
                or match.group(3) != current_match.group(3)
                or match.group(4) == current_match.group(4)
            ):
                raise DeploymentConfigurationError("historical assurance registry is invalid")
        recovery_region = _bounded_string(value.get("recoveryRegion"), "recoveryRegion", maximum=32)
        if not _AWS_REGION.fullmatch(recovery_region) or recovery_region == current_match.group(2):
            raise DeploymentConfigurationError("assurance signer recoveryRegion is invalid")
        evidence = _bounded_string(
            value.get("approvalEvidenceRef"), "approvalEvidenceRef", maximum=512
        )
        if not _EVIDENCE_REFERENCE.fullmatch(evidence):
            raise DeploymentConfigurationError("assurance signer evidence reference is invalid")
        assert isinstance(current, str)  # Narrowed by exact ARN validation above.
        return cls(current, tuple(history), recovery_region, evidence)

    def canonical_json(self) -> str:
        """Return stable, secret-free signer deployment authority."""
        return json.dumps(
            {
                "approvalEvidenceRef": self.approval_evidence_ref,
                "currentSignerArn": self.current_signer_arn,
                "historicalVerificationKeyArns": list(self.historical_verification_key_arns),
                "recoveryRegion": self.recovery_region,
                "schemaVersion": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def deployment_environment(self) -> dict[str, str]:
        """Return exact current and historical CDK authority."""
        return {
            "ASSURANCE_REPORT_SIGNING_KEY_ARN": self.current_signer_arn,
            "ASSURANCE_REPORT_HISTORICAL_VERIFICATION_KEY_ARNS": json.dumps(
                self.historical_verification_key_arns, separators=(",", ":")
            ),
        }


@dataclass(frozen=True)
class DataBoundaryDeploymentManifest:
    """Deployment-owned encryption, residency and operator-network authority."""

    home_region: str
    approved_data_regions: tuple[str, ...]
    customer_managed_data_key_arn: str
    operator_allowed_ipv4_cidrs: tuple[str, ...]
    key_policy_evidence_ref: str
    residency_evidence_ref: str
    deletion_evidence_ref: str
    conditional_access_evidence_ref: str
    approval_evidence_ref: str

    @classmethod
    def parse(cls, payload: str) -> DataBoundaryDeploymentManifest:
        """Parse one exact secret-free boundary and reject unsafe network aliases."""
        if len(payload.encode("utf-8")) > 16_384:
            raise DeploymentConfigurationError("data-boundary manifest exceeds 16 KiB")
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise DeploymentConfigurationError("data-boundary manifest is invalid") from error
        if (
            not isinstance(value, dict)
            or set(value) != _DATA_BOUNDARY_MANIFEST_FIELDS
            or value.get("schemaVersion") != 1
            or value.get("operatorAccessMode") != "ip-restricted"
        ):
            raise DeploymentConfigurationError("data-boundary manifest schema is invalid")
        home_region = _bounded_string(value.get("homeRegion"), "homeRegion", maximum=32)
        regions = value.get("approvedDataRegions")
        if (
            not _AWS_REGION.fullmatch(home_region)
            or not isinstance(regions, list)
            or not 1 <= len(regions) <= 4
            or any(
                not isinstance(region, str) or not _AWS_REGION.fullmatch(region)
                for region in regions
            )
            or regions != sorted(set(regions))
            or home_region not in regions
        ):
            raise DeploymentConfigurationError("approved data Regions are invalid")
        key_arn = value.get("customerManagedDataKeyArn")
        key_match = _KMS_KEY_ARN.fullmatch(key_arn) if isinstance(key_arn, str) else None
        if key_match is None or key_match.group(2) != home_region:
            raise DeploymentConfigurationError("customer-managed data key is invalid")
        cidrs = value.get("operatorAllowedIpv4Cidrs")
        if (
            not isinstance(cidrs, list)
            or not 1 <= len(cidrs) <= 32
            or any(not isinstance(cidr, str) for cidr in cidrs)
        ):
            raise DeploymentConfigurationError("operator IPv4 CIDRs are invalid")
        canonical_cidrs: list[str] = []
        for cidr in cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=True)
            except ValueError as error:
                raise DeploymentConfigurationError("operator IPv4 CIDRs are invalid") from error
            if (
                network.version != 4
                or network.is_private
                or network.is_loopback
                or network.is_link_local
                or network.is_multicast
                or network.is_reserved
                or network.is_unspecified
                or str(network) != cidr
            ):
                raise DeploymentConfigurationError(
                    "operator IPv4 CIDRs must be canonical public networks"
                )
            canonical_cidrs.append(cidr)
        if canonical_cidrs != sorted(set(canonical_cidrs)):
            raise DeploymentConfigurationError("operator IPv4 CIDRs must be sorted and unique")
        references = []
        for field in (
            "keyPolicyEvidenceRef",
            "residencyEvidenceRef",
            "deletionEvidenceRef",
            "conditionalAccessEvidenceRef",
            "approvalEvidenceRef",
        ):
            reference = _bounded_string(value.get(field), field, maximum=512)
            if not _EVIDENCE_REFERENCE.fullmatch(reference):
                raise DeploymentConfigurationError(f"{field} is invalid")
            references.append(reference)
        assert isinstance(key_arn, str)
        return cls(
            home_region,
            tuple(regions),
            key_arn,
            tuple(canonical_cidrs),
            *references,
        )

    @property
    def account_id(self) -> str:
        """Return the exact AWS account encoded by the validated key ARN."""
        match = _KMS_KEY_ARN.fullmatch(self.customer_managed_data_key_arn)
        assert match is not None
        return match.group(3)

    def canonical_json(self) -> str:
        """Return stable secret-free deployment authority for Parameter Store."""
        return json.dumps(
            {
                "approvalEvidenceRef": self.approval_evidence_ref,
                "approvedDataRegions": list(self.approved_data_regions),
                "conditionalAccessEvidenceRef": self.conditional_access_evidence_ref,
                "customerManagedDataKeyArn": self.customer_managed_data_key_arn,
                "deletionEvidenceRef": self.deletion_evidence_ref,
                "homeRegion": self.home_region,
                "keyPolicyEvidenceRef": self.key_policy_evidence_ref,
                "operatorAccessMode": "ip-restricted",
                "operatorAllowedIpv4Cidrs": list(self.operator_allowed_ipv4_cidrs),
                "residencyEvidenceRef": self.residency_evidence_ref,
                "schemaVersion": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def deployment_environment(self) -> dict[str, str]:
        """Return reviewed non-secret values consumed by CDK and Lambda."""
        return {
            "DATA_BOUNDARY_HOME_REGION": self.home_region,
            "DATA_BOUNDARY_APPROVED_REGIONS": json.dumps(
                self.approved_data_regions, separators=(",", ":")
            ),
            "DATA_BOUNDARY_KMS_KEY_ARN": self.customer_managed_data_key_arn,
            "DATA_BOUNDARY_OPERATOR_ACCESS_MODE": "ip-restricted",
            "DATA_BOUNDARY_OPERATOR_IPV4_CIDRS": json.dumps(
                self.operator_allowed_ipv4_cidrs, separators=(",", ":")
            ),
            "DATA_BOUNDARY_CONDITIONAL_ACCESS_EVIDENCE_REF": (self.conditional_access_evidence_ref),
            "DATA_BOUNDARY_APPROVAL_EVIDENCE_REF": self.approval_evidence_ref,
        }


def _aws(
    arguments: Sequence[str],
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Run one fixed AWS CLI operation and decode its bounded JSON response."""
    if not _AWS_PROFILE.fullmatch(profile) or not _AWS_REGION.fullmatch(region):
        raise DeploymentConfigurationError("AWS profile or region is malformed")
    command = ["aws", *arguments, "--profile", profile, "--region", region, "--output", "json"]
    result = runner(command, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        message = (
            result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "AWS CLI failed"
        )
        raise DeploymentConfigurationError(message[:500])
    if len(result.stdout.encode("utf-8")) > 1_048_576:
        raise DeploymentConfigurationError("AWS CLI response exceeds the 1 MiB bound")
    try:
        value = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as error:
        raise DeploymentConfigurationError("AWS CLI returned malformed JSON") from error
    if not isinstance(value, dict):
        raise DeploymentConfigurationError("AWS CLI returned an unexpected response")
    return value


def parameter_name(stack_name: str) -> str:
    """Return the stack-specific encrypted identity configuration path."""
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}", stack_name):
        raise DeploymentConfigurationError("stack name is invalid")
    return f"/aai-sec/{stack_name}/entra-deployment"


def recovery_parameter_name(stack_name: str) -> str:
    """Return the stack-specific encrypted audit-recovery configuration path."""
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}", stack_name):
        raise DeploymentConfigurationError("stack name is invalid")
    return f"/aai-sec/{stack_name}/audit-recovery"


def policy_github_parameter_name(stack_name: str) -> str:
    """Return the stack-specific encrypted reviewed GitHub authority path."""
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}", stack_name):
        raise DeploymentConfigurationError("stack name is invalid")
    return f"/aai-sec/{stack_name}/policy-github"


def assurance_signer_parameter_name(stack_name: str) -> str:
    """Return the persistent current/history assurance signer authority path."""
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}", stack_name):
        raise DeploymentConfigurationError("stack name is invalid")
    return f"/aai-sec/{stack_name}/assurance-signer"


def data_boundary_parameter_name(stack_name: str) -> str:
    """Return the persistent deployment-owned data-boundary path."""
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}", stack_name):
        raise DeploymentConfigurationError("stack name is invalid")
    return f"/aai-sec/{stack_name}/data-boundary"


def stack_outputs(
    stack_name: str,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
    allow_missing: bool = False,
) -> dict[str, str]:
    """Return bounded stack outputs without exposing resource secrets."""
    try:
        response = _aws(
            ["cloudformation", "describe-stacks", "--stack-name", stack_name],
            profile=profile,
            region=region,
            runner=runner,
        )
    except DeploymentConfigurationError as error:
        if allow_missing and "does not exist" in str(error):
            return {}
        raise
    stacks = response.get("Stacks")
    if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], dict):
        raise DeploymentConfigurationError("expected exactly one deployed control-plane stack")
    outputs = stacks[0].get("Outputs", [])
    if not isinstance(outputs, list) or len(outputs) > 100:
        raise DeploymentConfigurationError("stack outputs are malformed or oversized")
    result: dict[str, str] = {}
    for item in outputs:
        if not isinstance(item, dict):
            raise DeploymentConfigurationError("stack output is malformed")
        key, value = item.get("OutputKey"), item.get("OutputValue")
        if not isinstance(key, str) or not isinstance(value, str) or key in result:
            raise DeploymentConfigurationError("stack output identity is ambiguous")
        result[key] = value
    return result


def load_persisted_manifest(
    stack_name: str, *, profile: str, region: str, runner: Runner = subprocess.run
) -> EntraDeploymentManifest | None:
    """Load the encrypted deployment manifest, returning None only when absent."""
    name = parameter_name(stack_name)
    command = [
        "aws",
        "ssm",
        "get-parameter",
        "--name",
        name,
        "--with-decryption",
        "--profile",
        profile,
        "--region",
        region,
        "--output",
        "json",
    ]
    result = runner(command, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        error = result.stderr
        if "ParameterNotFound" in error:
            return None
        raise DeploymentConfigurationError((error.strip() or "SSM lookup failed")[-500:])
    try:
        response = json.loads(result.stdout)
        payload = response["Parameter"]["Value"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise DeploymentConfigurationError("persisted Entra manifest is malformed") from error
    if not isinstance(payload, str):
        raise DeploymentConfigurationError("persisted Entra manifest is not text")
    return EntraDeploymentManifest.parse(payload)


def load_persisted_recovery_manifest(
    stack_name: str, *, profile: str, region: str, runner: Runner = subprocess.run
) -> AuditRecoveryManifest | None:
    """Load immutable-recovery authority, returning None only when never configured."""
    result = runner(
        [
            "aws",
            "ssm",
            "get-parameter",
            "--name",
            recovery_parameter_name(stack_name),
            "--with-decryption",
            "--profile",
            profile,
            "--region",
            region,
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        if "ParameterNotFound" in result.stderr:
            return None
        raise DeploymentConfigurationError((result.stderr.strip() or "SSM lookup failed")[-500:])
    try:
        payload = json.loads(result.stdout)["Parameter"]["Value"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise DeploymentConfigurationError("persisted recovery manifest is malformed") from error
    if not isinstance(payload, str):
        raise DeploymentConfigurationError("persisted recovery manifest is not text")
    return AuditRecoveryManifest.parse(payload)


def load_persisted_policy_github_manifest(
    stack_name: str, *, profile: str, region: str, runner: Runner = subprocess.run
) -> PolicyGitHubDeploymentManifest | None:
    """Load reviewed GitHub policy authority, returning None only when absent."""
    result = runner(
        [
            "aws",
            "ssm",
            "get-parameter",
            "--name",
            policy_github_parameter_name(stack_name),
            "--with-decryption",
            "--profile",
            profile,
            "--region",
            region,
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        if "ParameterNotFound" in result.stderr:
            return None
        raise DeploymentConfigurationError((result.stderr.strip() or "SSM lookup failed")[-500:])
    try:
        payload = json.loads(result.stdout)["Parameter"]["Value"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise DeploymentConfigurationError(
            "persisted policy GitHub manifest is malformed"
        ) from error
    if not isinstance(payload, str):
        raise DeploymentConfigurationError("persisted policy GitHub manifest is not text")
    return PolicyGitHubDeploymentManifest.parse(payload)


def load_persisted_assurance_signer_manifest(
    stack_name: str, *, profile: str, region: str, runner: Runner = subprocess.run
) -> AssuranceSignerDeploymentManifest | None:
    """Load signer authority, returning None only before the first rotation."""
    result = runner(
        [
            "aws",
            "ssm",
            "get-parameter",
            "--name",
            assurance_signer_parameter_name(stack_name),
            "--with-decryption",
            "--profile",
            profile,
            "--region",
            region,
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        if "ParameterNotFound" in result.stderr:
            return None
        raise DeploymentConfigurationError((result.stderr.strip() or "SSM lookup failed")[-500:])
    try:
        payload = json.loads(result.stdout)["Parameter"]["Value"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise DeploymentConfigurationError(
            "persisted assurance signer manifest is malformed"
        ) from error
    if not isinstance(payload, str):
        raise DeploymentConfigurationError("persisted assurance signer manifest is not text")
    return AssuranceSignerDeploymentManifest.parse(payload)


def load_persisted_data_boundary_manifest(
    stack_name: str, *, profile: str, region: str, runner: Runner = subprocess.run
) -> DataBoundaryDeploymentManifest | None:
    """Load data-boundary authority, returning None only before configuration."""
    result = runner(
        [
            "aws",
            "ssm",
            "get-parameter",
            "--name",
            data_boundary_parameter_name(stack_name),
            "--with-decryption",
            "--profile",
            profile,
            "--region",
            region,
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        if "ParameterNotFound" in result.stderr:
            return None
        raise DeploymentConfigurationError((result.stderr.strip() or "SSM lookup failed")[-500:])
    try:
        payload = json.loads(result.stdout)["Parameter"]["Value"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise DeploymentConfigurationError(
            "persisted data-boundary manifest is malformed"
        ) from error
    if not isinstance(payload, str):
        raise DeploymentConfigurationError("persisted data-boundary manifest is not text")
    return DataBoundaryDeploymentManifest.parse(payload)


def _secret_value(name: str, *, profile: str, region: str, runner: Runner = subprocess.run) -> str:
    """Read a secret only into memory for shape validation and never print it."""
    response = _aws(
        ["secretsmanager", "get-secret-value", "--secret-id", name],
        profile=profile,
        region=region,
        runner=runner,
    )
    value = response.get("SecretString")
    if not isinstance(value, str):
        raise DeploymentConfigurationError(f"secret {name} must contain SecretString text")
    return value


def _scim_token(secret: str) -> str:
    """Accept a plain bearer or the runbook's exact one-field JSON representation."""
    token = secret
    if secret.startswith("{"):
        try:
            value = json.loads(secret, object_pairs_hook=_strict_object)
        except json.JSONDecodeError as error:
            raise DeploymentConfigurationError("SCIM secret contains malformed JSON") from error
        if (
            not isinstance(value, dict)
            or set(value) != {"token"}
            or not isinstance(value["token"], str)
        ):
            raise DeploymentConfigurationError("SCIM JSON secret must contain only token")
        token = value["token"]
    if (
        not 32 <= len(token) <= 512
        or token != token.strip()
        or any(ord(character) < 33 or ord(character) > 126 for character in token)
    ):
        raise DeploymentConfigurationError(
            "SCIM bearer must be 32-512 visible non-whitespace ASCII characters"
        )
    return token


def verify_policy_github_credential(
    manifest: PolicyGitHubDeploymentManifest,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> None:
    """Verify the selected GitHub credential shape without emitting its value."""
    secret_name = (
        manifest.credential_secret_name
        if manifest.schema_version == 1
        else manifest.app_private_key_secret_name
    )
    if secret_name is None:
        raise DeploymentConfigurationError("policy GitHub credential reference is missing")
    secret = _secret_value(secret_name, profile=profile, region=region, runner=runner)
    try:
        value = json.loads(secret, object_pairs_hook=_strict_object)
    except json.JSONDecodeError as error:
        raise DeploymentConfigurationError(
            "policy GitHub secret contains malformed JSON"
        ) from error
    if manifest.schema_version == 2:
        if (
            not isinstance(value, dict)
            or set(value) != {"privateKeyPem"}
            or not isinstance(value["privateKeyPem"], str)
            or len(value["privateKeyPem"].encode("utf-8")) > 32_768
        ):
            raise DeploymentConfigurationError(
                "policy GitHub App secret must contain only a bounded privateKeyPem"
            )
        try:
            key = serialization.load_pem_private_key(
                value["privateKeyPem"].encode("utf-8"), password=None
            )
        except (TypeError, ValueError) as error:
            raise DeploymentConfigurationError(
                "policy GitHub App private key is malformed"
            ) from error
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise DeploymentConfigurationError(
                "policy GitHub App private key must be RSA with at least 2048 bits"
            )
        return
    if (
        not isinstance(value, dict)
        or set(value) != {"token"}
        or not isinstance(value["token"], str)
    ):
        raise DeploymentConfigurationError("policy GitHub secret must contain only token")
    token = value["token"]
    if (
        not 20 <= len(token) <= 512
        or token != token.strip()
        or any(ord(character) < 33 or ord(character) > 126 for character in token)
    ):
        raise DeploymentConfigurationError(
            "policy GitHub token must be 20-512 visible non-whitespace ASCII characters"
        )


def verify_oidc_metadata(tenant_id: str, *, opener: UrlOpener = urllib.request.urlopen) -> None:
    """Verify bounded tenant-specific Microsoft OIDC discovery before deployment."""
    expected_issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    url = f"{expected_issuer}/.well-known/openid-configuration"
    # Both scheme and host are fixed above; tenant_id is a canonical UUID.
    request = urllib.request.Request(  # noqa: S310 - exact HTTPS Microsoft authority
        url, headers={"Accept": "application/json"}
    )
    try:
        with opener(request, timeout=5) as response:
            resolved_url = response.geturl()
            payload = response.read(65_537)
    except (OSError, urllib.error.URLError) as error:
        raise DeploymentConfigurationError("tenant-specific Entra OIDC discovery failed") from error
    if len(payload) > 65_536:
        raise DeploymentConfigurationError("Entra OIDC discovery response exceeds 64 KiB")
    if resolved_url != url:
        raise DeploymentConfigurationError("Entra OIDC discovery redirect is not allowed")
    try:
        metadata = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise DeploymentConfigurationError(
            "Entra OIDC discovery returned malformed JSON"
        ) from error
    if not isinstance(metadata, dict) or metadata.get("issuer") != expected_issuer:
        raise DeploymentConfigurationError("Entra OIDC issuer does not match the configured tenant")
    required = {
        "authorization_endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
        "token_endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        "jwks_uri": f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
    }
    if any(metadata.get(key) != value for key, value in required.items()):
        raise DeploymentConfigurationError("Entra OIDC metadata endpoints are not tenant-bound")


def preflight(
    manifest: EntraDeploymentManifest,
    stack_name: str,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
    opener: UrlOpener = urllib.request.urlopen,
) -> dict[str, str]:
    """Verify secrets, tenant existence and OIDC provenance without changing AWS."""
    outputs = stack_outputs(stack_name, profile=profile, region=region, runner=runner)
    control_table = outputs.get("ControlTableName")
    if not control_table:
        raise DeploymentConfigurationError("ControlTableName stack output is missing")
    oidc_secret = _secret_value(
        manifest.entra_client_secret_name, profile=profile, region=region, runner=runner
    )
    if (
        not 1 <= len(oidc_secret) <= 4096
        or oidc_secret != oidc_secret.strip()
        or oidc_secret.startswith(("{", "["))
        or any(ord(character) < 33 or ord(character) > 126 for character in oidc_secret)
    ):
        raise DeploymentConfigurationError("OIDC client secret has an invalid shape")
    _scim_token(
        _secret_value(
            manifest.entra_scim_token_secret_name,
            profile=profile,
            region=region,
            runner=runner,
        )
    )
    tenant = _aws(
        [
            "dynamodb",
            "get-item",
            "--table-name",
            control_table,
            "--key",
            json.dumps(
                {
                    "pk": {"S": f"TENANT#{manifest.aai_tenant_id}"},
                    "sk": {"S": "TENANT#root"},
                },
                separators=(",", ":"),
            ),
            "--consistent-read",
        ],
        profile=profile,
        region=region,
        runner=runner,
    )
    if not isinstance(tenant.get("Item"), dict):
        raise DeploymentConfigurationError("bound AAI tenant does not exist")
    verify_oidc_metadata(manifest.entra_tenant_id, opener=opener)
    return outputs


def persist_manifest(
    manifest: EntraDeploymentManifest,
    stack_name: str,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> None:
    """Persist only the reviewed non-secret manifest as an encrypted parameter."""
    _aws(
        [
            "ssm",
            "put-parameter",
            "--name",
            parameter_name(stack_name),
            "--type",
            "SecureString",
            "--overwrite",
            "--value",
            manifest.canonical_json(),
            "--description",
            "Persistent AAI Security Microsoft Entra deployment references",
        ],
        profile=profile,
        region=region,
        runner=runner,
    )


def verify_recovery_destination(
    manifest: AuditRecoveryManifest,
    *,
    profile: str,
    source_region: str,
    runner: Runner = subprocess.run,
) -> None:
    """Require a distinct, versioned destination with compliance-mode Object Lock."""
    if manifest.replica_region == source_region:
        raise DeploymentConfigurationError("replicaRegion must differ from the primary region")
    versioning = _aws(
        ["s3api", "get-bucket-versioning", "--bucket", manifest.replica_bucket_name],
        profile=profile,
        region=manifest.replica_region,
        runner=runner,
    )
    if versioning.get("Status") != "Enabled":
        raise DeploymentConfigurationError("replica bucket versioning is not enabled")
    lock = _aws(
        ["s3api", "get-object-lock-configuration", "--bucket", manifest.replica_bucket_name],
        profile=profile,
        region=manifest.replica_region,
        runner=runner,
    )
    configuration = lock.get("ObjectLockConfiguration")
    default = (
        configuration.get("Rule", {}).get("DefaultRetention", {})
        if isinstance(configuration, dict)
        else {}
    )
    if (
        not isinstance(configuration, dict)
        or configuration.get("ObjectLockEnabled") != "Enabled"
        or default.get("Mode") != "COMPLIANCE"
        or not isinstance(default.get("Days"), int)
        or default["Days"] < 365
    ):
        raise DeploymentConfigurationError(
            "replica bucket must default to at least 365 days of COMPLIANCE Object Lock"
        )


def persist_recovery_manifest(
    manifest: AuditRecoveryManifest,
    stack_name: str,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> None:
    """Persist reviewed recovery authority without storing credentials or evidence content."""
    _aws(
        [
            "ssm",
            "put-parameter",
            "--name",
            recovery_parameter_name(stack_name),
            "--type",
            "SecureString",
            "--overwrite",
            "--value",
            manifest.canonical_json(),
            "--description",
            "Persistent AAI Security immutable audit recovery references",
        ],
        profile=profile,
        region=region,
        runner=runner,
    )


def persist_policy_github_manifest(
    manifest: PolicyGitHubDeploymentManifest,
    stack_name: str,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> None:
    """Persist reviewed GitHub authority without storing its credential value."""
    _aws(
        [
            "ssm",
            "put-parameter",
            "--name",
            policy_github_parameter_name(stack_name),
            "--type",
            "SecureString",
            "--overwrite",
            "--value",
            manifest.canonical_json(),
            "--description",
            "Persistent AAI Security reviewed GitHub policy-source authority",
        ],
        profile=profile,
        region=region,
        runner=runner,
    )


def persist_assurance_signer_manifest(
    manifest: AssuranceSignerDeploymentManifest,
    stack_name: str,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> None:
    """Persist reviewed signer cutover authority for every future deployment."""
    _aws(
        [
            "ssm",
            "put-parameter",
            "--name",
            assurance_signer_parameter_name(stack_name),
            "--type",
            "SecureString",
            "--overwrite",
            "--value",
            manifest.canonical_json(),
            "--description",
            "Persistent AAI Security assurance signer rotation authority",
        ],
        profile=profile,
        region=region,
        runner=runner,
    )


def verify_data_boundary(
    manifest: DataBoundaryDeploymentManifest,
    *,
    profile: str,
    region: str,
    recovery: AuditRecoveryManifest | None = None,
    runner: Runner = subprocess.run,
) -> None:
    """Verify exact account, Region and KMS posture without changing AWS."""
    if manifest.home_region != region:
        raise DeploymentConfigurationError(
            "data-boundary homeRegion differs from deployment Region"
        )
    if recovery is not None and recovery.replica_region not in manifest.approved_data_regions:
        raise DeploymentConfigurationError("audit replica Region is outside approved data Regions")
    caller = _aws(["sts", "get-caller-identity"], profile=profile, region=region, runner=runner)
    if caller.get("Account") != manifest.account_id:
        raise DeploymentConfigurationError("customer-managed data key belongs to another account")
    response = _aws(
        ["kms", "describe-key", "--key-id", manifest.customer_managed_data_key_arn],
        profile=profile,
        region=region,
        runner=runner,
    )
    metadata = response.get("KeyMetadata")
    if (
        not isinstance(metadata, dict)
        or metadata.get("Arn") != manifest.customer_managed_data_key_arn
        or metadata.get("AWSAccountId") != manifest.account_id
        or metadata.get("KeyManager") != "CUSTOMER"
        or metadata.get("KeyState") != "Enabled"
        or metadata.get("Enabled") is not True
        or metadata.get("KeyUsage") != "ENCRYPT_DECRYPT"
        or metadata.get("KeySpec") != "SYMMETRIC_DEFAULT"
        or metadata.get("Origin") != "AWS_KMS"
    ):
        raise DeploymentConfigurationError("customer-managed data key posture is invalid")
    rotation = _aws(
        [
            "kms",
            "get-key-rotation-status",
            "--key-id",
            manifest.customer_managed_data_key_arn,
        ],
        profile=profile,
        region=region,
        runner=runner,
    )
    if rotation.get("KeyRotationEnabled") is not True:
        raise DeploymentConfigurationError("customer-managed data key rotation is not enabled")


def persist_data_boundary_manifest(
    manifest: DataBoundaryDeploymentManifest,
    stack_name: str,
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess.run,
) -> None:
    """Persist only reviewed, secret-free data-boundary authority."""
    _aws(
        [
            "ssm",
            "put-parameter",
            "--name",
            data_boundary_parameter_name(stack_name),
            "--type",
            "SecureString",
            "--overwrite",
            "--value",
            manifest.canonical_json(),
            "--description",
            "Persistent AAI Security encryption, residency and access boundary",
        ],
        profile=profile,
        region=region,
        runner=runner,
    )


def deploy(
    stack_name: str,
    *,
    profile: str,
    region: str,
    allow_assurance_signer_transition: bool = False,
    runner: Runner = subprocess.run,
) -> EntraDeploymentManifest | None:
    """Deploy with persisted identity configuration or refuse destructive omission."""
    manifest = load_persisted_manifest(stack_name, profile=profile, region=region, runner=runner)
    recovery = load_persisted_recovery_manifest(
        stack_name, profile=profile, region=region, runner=runner
    )
    policy_github = load_persisted_policy_github_manifest(
        stack_name, profile=profile, region=region, runner=runner
    )
    assurance_signer = load_persisted_assurance_signer_manifest(
        stack_name, profile=profile, region=region, runner=runner
    )
    data_boundary = load_persisted_data_boundary_manifest(
        stack_name, profile=profile, region=region, runner=runner
    )
    outputs = stack_outputs(
        stack_name,
        profile=profile,
        region=region,
        runner=runner,
        allow_missing=True,
    )
    if manifest is None and outputs.get("MicrosoftEntraIdStatus") == "configured":
        raise DeploymentConfigurationError(
            "stack has Entra configured but its persistent deployment manifest is missing"
        )
    if recovery is None and outputs.get("AuditReplicaBucketArn"):
        raise DeploymentConfigurationError(
            "stack has audit replication configured but its persistent recovery manifest is missing"
        )
    if policy_github is None and outputs.get("PolicyGitHubSourceStatus") == "configured":
        raise DeploymentConfigurationError(
            "stack has GitHub policy sources configured but its persistent manifest is missing"
        )
    if (
        assurance_signer is None
        and outputs.get("AssuranceReportSignerAuthorityStatus") == "persisted-rotation"
    ):
        raise DeploymentConfigurationError(
            "stack uses a rotated assurance signer but its persistent manifest is missing"
        )
    if data_boundary is None and outputs.get("DataBoundaryStatus") == "configured":
        raise DeploymentConfigurationError(
            "stack has a data boundary configured but its persistent manifest is missing"
        )
    if assurance_signer is not None and outputs:
        deployed_current = outputs.get("AssuranceReportSigningKeyArn")
        try:
            deployed_history_value = json.loads(
                outputs["AssuranceReportHistoricalVerificationKeyArns"]
            )
        except (KeyError, json.JSONDecodeError, TypeError) as error:
            raise DeploymentConfigurationError(
                "deployed assurance signer history is malformed"
            ) from error
        if not isinstance(deployed_history_value, list) or not all(
            isinstance(value, str) for value in deployed_history_value
        ):
            raise DeploymentConfigurationError("deployed assurance signer history is malformed")
        deployed_history = tuple(deployed_history_value)
        if deployed_current == assurance_signer.current_signer_arn:
            expected_deployed_history = assurance_signer.historical_verification_key_arns
        elif (
            allow_assurance_signer_transition
            and assurance_signer.historical_verification_key_arns
            and deployed_current == assurance_signer.historical_verification_key_arns[0]
        ):
            # Before the guarded cutover, current[old] + history[older] must
            # exactly equal the promoted manifest's history[old, older].
            expected_deployed_history = assurance_signer.historical_verification_key_arns[1:]
        else:
            raise DeploymentConfigurationError(
                "persisted assurance signer differs from deployed authority outside rotation"
            )
        if deployed_history != expected_deployed_history:
            raise DeploymentConfigurationError(
                "persisted assurance signer history differs from deployed authority"
            )
    environment = os.environ.copy()
    # Ambient shell state is not deployment authority. Remove every legacy
    # identity field before optionally loading the persisted reviewed manifest.
    for field in (
        *_ENTRA_ENVIRONMENT_FIELDS,
        *_RECOVERY_ENVIRONMENT_FIELDS,
        *_POLICY_GITHUB_ENVIRONMENT_FIELDS,
        "ASSURANCE_REPORT_SIGNING_KEY_ARN",
        "ASSURANCE_REPORT_HISTORICAL_VERIFICATION_KEY_ARNS",
        "DATA_BOUNDARY_HOME_REGION",
        "DATA_BOUNDARY_APPROVED_REGIONS",
        "DATA_BOUNDARY_KMS_KEY_ARN",
        "DATA_BOUNDARY_OPERATOR_ACCESS_MODE",
        "DATA_BOUNDARY_OPERATOR_IPV4_CIDRS",
        "DATA_BOUNDARY_CONDITIONAL_ACCESS_EVIDENCE_REF",
        "DATA_BOUNDARY_APPROVAL_EVIDENCE_REF",
    ):
        environment.pop(field, None)
    environment.update({"AWS_PROFILE": profile, "AWS_REGION": region})
    if manifest is not None:
        preflight(
            manifest,
            stack_name,
            profile=profile,
            region=region,
            runner=runner,
        )
        environment.update(manifest.deployment_environment())
    if recovery is not None:
        verify_recovery_destination(recovery, profile=profile, source_region=region, runner=runner)
        environment.update(recovery.deployment_environment())
    if policy_github is not None:
        verify_policy_github_credential(
            policy_github, profile=profile, region=region, runner=runner
        )
        environment.update(policy_github.deployment_environment())
    if assurance_signer is not None:
        if assurance_signer.current_signer_arn.split(":")[3] != region:
            raise DeploymentConfigurationError("assurance signer belongs to another region")
        environment.update(assurance_signer.deployment_environment())
    if data_boundary is not None:
        verify_data_boundary(
            data_boundary,
            profile=profile,
            region=region,
            recovery=recovery,
            runner=runner,
        )
        environment.update(data_boundary.deployment_environment())
    root = Path(__file__).resolve().parents[1]
    infrastructure = root / "infra" / "aws-control-plane"
    for command in (
        ["npm", "run", "build"],
        ["npx", "cdk", "deploy", stack_name, "--require-approval", "never"],
    ):
        result = runner(command, cwd=infrastructure, env=environment, check=False)
        if result.returncode != 0:
            raise DeploymentConfigurationError(f"deployment command failed: {' '.join(command)}")
    post = stack_outputs(stack_name, profile=profile, region=region, runner=runner)
    if manifest is not None and (
        post.get("MicrosoftEntraIdStatus") != "configured"
        or post.get("MicrosoftEntraScimStatus") != "configured"
        or not post.get("MicrosoftEntraScimEndpoint", "").startswith("https://")
    ):
        raise DeploymentConfigurationError("deployed Entra/SCIM posture is incomplete")
    if recovery is not None and (
        post.get("AuditReplicaBucketArn") != recovery.replica_bucket_arn
        or post.get("AuditReplicaRegion") != recovery.replica_region
        or not post.get("AuditBatchReplicationRoleArn", "").startswith("arn:")
    ):
        raise DeploymentConfigurationError("deployed audit-recovery posture is incomplete")
    if policy_github is not None and post.get("PolicyGitHubSourceStatus") != "configured":
        raise DeploymentConfigurationError("deployed GitHub policy-source posture is incomplete")
    if assurance_signer is not None and (
        post.get("AssuranceReportSignerAuthorityStatus") != "persisted-rotation"
        or post.get("AssuranceReportSigningKeyArn") != assurance_signer.current_signer_arn
        or post.get("AssuranceReportHistoricalVerificationKeyArns")
        != json.dumps(assurance_signer.historical_verification_key_arns, separators=(",", ":"))
    ):
        raise DeploymentConfigurationError("deployed assurance signer posture is incomplete")
    if data_boundary is not None and (
        post.get("DataBoundaryStatus") != "configured"
        or post.get("DataBoundaryHomeRegion") != data_boundary.home_region
        or post.get("DataBoundaryApprovedRegions")
        != json.dumps(data_boundary.approved_data_regions, separators=(",", ":"))
        or post.get("DataBoundaryKeyArn") != data_boundary.customer_managed_data_key_arn
        or post.get("DataBoundaryOperatorAccessMode") != "ip-restricted"
    ):
        raise DeploymentConfigurationError("deployed data-boundary posture is incomplete")
    return manifest


def _parser() -> argparse.ArgumentParser:
    """Build the intentionally small deployment command surface."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "check",
            "configure",
            "check-recovery",
            "configure-recovery",
            "check-policy-github",
            "configure-policy-github",
            "check-data-boundary",
            "configure-data-boundary",
            "deploy",
            "status",
        ),
    )
    parser.add_argument("--config", type=Path)
    parser.add_argument("--profile", default=os.environ.get("AWS_PROFILE", "p1"))
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "eu-west-2"))
    parser.add_argument("--stack-name", default="AaiSecControlPlane")
    parser.add_argument(
        "--confirm-conditional-access",
        action="store_true",
        help="Confirm the evidence reference points to an MFA-enforcing Conditional Access review",
    )
    parser.add_argument(
        "--confirm-policy-github-review",
        action="store_true",
        help="Confirm the exact repository allow-list and credential reference were reviewed",
    )
    parser.add_argument(
        "--confirm-recovery-controls",
        action="store_true",
        help="Confirm the recovery evidence reference records an approved cross-region review",
    )
    parser.add_argument(
        "--confirm-data-boundary-review",
        action="store_true",
        help="Confirm encryption, residency, deletion, network and Conditional Access evidence",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Validate, persist, deploy or inspect the enterprise identity configuration."""
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command in {"check", "configure"}:
            if arguments.config is None:
                raise DeploymentConfigurationError("--config is required")
            payload = arguments.config.read_text(encoding="utf-8")
            candidate_manifest = EntraDeploymentManifest.parse(payload)
            preflight(
                candidate_manifest,
                arguments.stack_name,
                profile=arguments.profile,
                region=arguments.region,
            )
            if arguments.command == "configure":
                if not arguments.confirm_conditional_access:
                    raise DeploymentConfigurationError(
                        "--confirm-conditional-access is required before persistence"
                    )
                persist_manifest(
                    candidate_manifest,
                    arguments.stack_name,
                    profile=arguments.profile,
                    region=arguments.region,
                )
            print(
                f"Entra deployment {arguments.command} passed for stack "
                f"{arguments.stack_name}; no secret values were emitted."
            )
        elif arguments.command in {"check-recovery", "configure-recovery"}:
            if arguments.config is None:
                raise DeploymentConfigurationError("--config is required")
            candidate_recovery = AuditRecoveryManifest.parse(
                arguments.config.read_text(encoding="utf-8")
            )
            verify_recovery_destination(
                candidate_recovery,
                profile=arguments.profile,
                source_region=arguments.region,
            )
            if arguments.command == "configure-recovery":
                if not arguments.confirm_recovery_controls:
                    raise DeploymentConfigurationError(
                        "--confirm-recovery-controls is required before persistence"
                    )
                persist_recovery_manifest(
                    candidate_recovery,
                    arguments.stack_name,
                    profile=arguments.profile,
                    region=arguments.region,
                )
            print(
                f"Audit recovery {arguments.command} passed for stack "
                f"{arguments.stack_name}; destination controls were verified."
            )
        elif arguments.command in {"check-policy-github", "configure-policy-github"}:
            if arguments.config is None:
                raise DeploymentConfigurationError("--config is required")
            candidate_policy_github = PolicyGitHubDeploymentManifest.parse(
                arguments.config.read_text(encoding="utf-8")
            )
            verify_policy_github_credential(
                candidate_policy_github,
                profile=arguments.profile,
                region=arguments.region,
            )
            if arguments.command == "configure-policy-github":
                if not arguments.confirm_policy_github_review:
                    raise DeploymentConfigurationError(
                        "--confirm-policy-github-review is required before persistence"
                    )
                persist_policy_github_manifest(
                    candidate_policy_github,
                    arguments.stack_name,
                    profile=arguments.profile,
                    region=arguments.region,
                )
            print(
                f"GitHub policy-source {arguments.command} passed for stack "
                f"{arguments.stack_name}; no credential values were emitted."
            )
        elif arguments.command in {"check-data-boundary", "configure-data-boundary"}:
            if arguments.config is None:
                raise DeploymentConfigurationError("--config is required")
            candidate_data_boundary = DataBoundaryDeploymentManifest.parse(
                arguments.config.read_text(encoding="utf-8")
            )
            persisted_recovery = load_persisted_recovery_manifest(
                arguments.stack_name,
                profile=arguments.profile,
                region=arguments.region,
            )
            verify_data_boundary(
                candidate_data_boundary,
                profile=arguments.profile,
                region=arguments.region,
                recovery=persisted_recovery,
            )
            if arguments.command == "configure-data-boundary":
                if not arguments.confirm_data_boundary_review:
                    raise DeploymentConfigurationError(
                        "--confirm-data-boundary-review is required before persistence"
                    )
                persist_data_boundary_manifest(
                    candidate_data_boundary,
                    arguments.stack_name,
                    profile=arguments.profile,
                    region=arguments.region,
                )
            print(
                f"Data-boundary {arguments.command} passed for stack "
                f"{arguments.stack_name}; no CIDRs or key policy content were emitted."
            )
        elif arguments.command == "deploy":
            active_manifest = deploy(
                arguments.stack_name, profile=arguments.profile, region=arguments.region
            )
            state = "configured" if active_manifest else "not configured"
            print(f"AWS control-plane deployment completed; Entra is {state}.")
        else:
            deployed_manifest = load_persisted_manifest(
                arguments.stack_name, profile=arguments.profile, region=arguments.region
            )
            deployed_recovery = load_persisted_recovery_manifest(
                arguments.stack_name, profile=arguments.profile, region=arguments.region
            )
            deployed_policy_github = load_persisted_policy_github_manifest(
                arguments.stack_name, profile=arguments.profile, region=arguments.region
            )
            deployed_data_boundary = load_persisted_data_boundary_manifest(
                arguments.stack_name, profile=arguments.profile, region=arguments.region
            )
            outputs = stack_outputs(
                arguments.stack_name, profile=arguments.profile, region=arguments.region
            )
            print(
                json.dumps(
                    {
                        "manifest": "configured" if deployed_manifest else "not-configured",
                        "oidc": outputs.get("MicrosoftEntraIdStatus", "unknown"),
                        "scim": outputs.get("MicrosoftEntraScimStatus", "unknown"),
                        "strongAuthentication": (
                            "declared-reviewed" if deployed_manifest else "not-configured"
                        ),
                        "auditRecovery": ("configured" if deployed_recovery else "not-configured"),
                        "policyGitHub": (
                            "configured" if deployed_policy_github else "not-configured"
                        ),
                        "dataBoundary": (
                            "configured" if deployed_data_boundary else "not-configured"
                        ),
                    },
                    sort_keys=True,
                )
            )
    except (DeploymentConfigurationError, OSError) as error:
        print(f"AWS control-plane deployment FAILED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
