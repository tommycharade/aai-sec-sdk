"""Create and validate digest-bound managed-host deployment packages.

The compiler remains pure and this module remains side-effect free.  It binds
compiled Claude Code or Codex configuration to the exact administrator-owned
executables that endpoint management must install first.  A deployment adapter
must obtain the expected package digest through an authenticated channel and
perform privileged writes; package bytes are never authority by themselves.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform as host_platform
import re
import stat
from dataclasses import dataclass
from typing import Any, Final

from .errors import SecurityConfigurationError
from .integrations import AgentHost
from .managed_configuration import (
    ManagedArtifact,
    ManagedConfigurationBundle,
    ManagedConfigurationEvidence,
    ManagedConfigurationSource,
    ManagedPlatform,
)
from .signed_policy import PolicyTrustStore

_SHA256: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_VERSION: Final[re.Pattern[str]] = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")
_IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_PACKAGE_BYTES: Final[int] = 3_000_000
_MAX_ARTIFACT_BYTES: Final[int] = 1_000_000
_MAX_EXECUTABLES: Final[int] = 8


def _duplicate_rejector(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting authority-confusing duplicate keys."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SecurityConfigurationError("managed deployment package contains duplicate keys")
        result[key] = value
    return result


def _required_text(value: object, label: str, maximum: int = 256) -> str:
    """Return one bounded non-empty string or reject malformed package input."""
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise SecurityConfigurationError(f"{label} must be a bounded non-empty string")
    return value


def _required_sha256(value: object, label: str) -> str:
    """Return one lowercase SHA-256 identifier or reject it."""
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise SecurityConfigurationError(f"{label} must be SHA-256")
    return value


def _expected_artifact_paths(host: AgentHost, platform: ManagedPlatform) -> tuple[str, ...]:
    """Return the complete documented managed-file set for one host platform."""
    if host is AgentHost.CLAUDE_CODE:
        root = {
            ManagedPlatform.MACOS: "/Library/Application Support/ClaudeCode",
            ManagedPlatform.LINUX: "/etc/claude-code",
            ManagedPlatform.WINDOWS: r"C:\Program Files\ClaudeCode",
        }[platform]
        return (
            f"{root}/managed-settings.json",
            f"{root}/managed-mcp.json",
        )
    if host is AgentHost.CODEX_CLI:
        return (
            r"C:\ProgramData\OpenAI\Codex\requirements.toml"
            if platform is ManagedPlatform.WINDOWS
            else "/etc/codex/requirements.toml",
        )
    raise SecurityConfigurationError("managed deployment host is unsupported")


def _policy_trust_path(platform: ManagedPlatform) -> str:
    """Return the administrator-owned signing-trust path for one platform."""
    return (
        r"C:\Program Files\AAI Security\trust\policy-signing.json"
        if platform is ManagedPlatform.WINDOWS
        else "/opt/aai-security/trust/policy-signing.json"
    )


def _policy_trust_artifact(store: PolicyTrustStore, platform: ManagedPlatform) -> ManagedArtifact:
    """Return one canonical digest-bound public trust artifact."""
    if not isinstance(store, PolicyTrustStore):
        raise SecurityConfigurationError("managed policy trust store must be typed")
    content = store.to_json()
    return ManagedArtifact(
        _policy_trust_path(platform),
        "application/json",
        content,
        hashlib.sha256(content.encode("utf-8")).hexdigest(),
    )


@dataclass(frozen=True, slots=True)
class ManagedExecutableRequirement:
    """Digest and path of one administrator-installed runtime prerequisite.

    The package does not contain or execute this file. Endpoint management must
    install it independently and the privileged installer verifies its regular
    file type, ownership, mode, executable bit and exact digest before changing
    host configuration.
    """

    path: str
    sha256: str

    def __post_init__(self) -> None:
        """Reject non-system paths and malformed executable identities."""
        _required_text(self.path, "managed executable path", 512)
        _required_sha256(self.sha256, "managed executable digest")
        allowed = self.path.startswith("/opt/aai-security/") or self.path.startswith(
            "C:\\Program Files\\AAI Security\\"
        )
        if not allowed or ".." in re.split(r"[/\\]", self.path):
            raise SecurityConfigurationError(
                "managed executable must use the administrator-owned AAI Security directory"
            )

    def to_wire(self) -> dict[str, str]:
        """Return the credential-free package representation."""
        return {"path": self.path, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class ManagedDeploymentPackage:
    """Canonical configuration package bound to desired state and prerequisites.

    The object is not self-authorizing. Callers must compare ``package_sha256``
    with a digest obtained through an authenticated control-plane or endpoint-
    management channel before installation.
    """

    host: AgentHost
    host_version: str
    platform: ManagedPlatform
    policy_id: str
    policy_version: int
    bundle_hash: str
    artifacts: tuple[ManagedArtifact, ...]
    required_executables: tuple[ManagedExecutableRequirement, ...]
    policy_trust: ManagedArtifact | None = None

    def __post_init__(self) -> None:
        """Require a complete exact host package with no ambiguous paths."""
        if not isinstance(self.host, AgentHost) or self.host not in {
            AgentHost.CLAUDE_CODE,
            AgentHost.CODEX_CLI,
        }:
            raise SecurityConfigurationError("managed deployment host is unsupported")
        if not isinstance(self.platform, ManagedPlatform):
            raise SecurityConfigurationError("managed deployment platform must be typed")
        if not isinstance(self.host_version, str) or _VERSION.fullmatch(self.host_version) is None:
            raise SecurityConfigurationError("managed deployment host version is invalid")
        if not isinstance(self.policy_id, str) or _IDENTIFIER.fullmatch(self.policy_id) is None:
            raise SecurityConfigurationError("managed deployment policy ID is invalid")
        if (
            isinstance(self.policy_version, bool)
            or not isinstance(self.policy_version, int)
            or self.policy_version <= 0
        ):
            raise SecurityConfigurationError("managed deployment policy version must be positive")
        _required_sha256(self.bundle_hash, "managed deployment bundle hash")
        if (
            not isinstance(self.artifacts, tuple)
            or not self.artifacts
            or not all(isinstance(artifact, ManagedArtifact) for artifact in self.artifacts)
        ):
            raise SecurityConfigurationError("managed deployment artifacts must be typed")
        expected_paths = _expected_artifact_paths(self.host, self.platform)
        actual_paths = tuple(artifact.path for artifact in self.artifacts)
        if actual_paths != expected_paths:
            raise SecurityConfigurationError(
                "managed deployment package must contain the complete ordered host file set"
            )
        for artifact in self.artifacts:
            encoded = artifact.content.encode("utf-8")
            if len(encoded) > _MAX_ARTIFACT_BYTES:
                raise SecurityConfigurationError("managed deployment artifact exceeds safe size")
            if not isinstance(artifact.media_type, str) or artifact.media_type not in {
                "application/json",
                "application/toml",
            }:
                raise SecurityConfigurationError(
                    "managed deployment artifact media type is invalid"
                )
            if (
                _required_sha256(artifact.sha256, "managed artifact digest")
                != hashlib.sha256(encoded).hexdigest()
            ):
                raise SecurityConfigurationError("managed deployment artifact digest is invalid")
        if (
            not isinstance(self.required_executables, tuple)
            or not 1 <= len(self.required_executables) <= _MAX_EXECUTABLES
            or not all(
                isinstance(item, ManagedExecutableRequirement) for item in self.required_executables
            )
        ):
            raise SecurityConfigurationError(
                "managed deployment requires one to eight typed executables"
            )
        executable_paths = [item.path for item in self.required_executables]
        if len(executable_paths) != len(set(executable_paths)):
            raise SecurityConfigurationError("managed deployment executable paths must be unique")
        expected_prefix = (
            "C:\\Program Files\\AAI Security\\"
            if self.platform is ManagedPlatform.WINDOWS
            else "/opt/aai-security/"
        )
        if any(not path.startswith(expected_prefix) for path in executable_paths):
            raise SecurityConfigurationError(
                "managed executable platform does not match the deployment package"
            )
        if self.policy_trust is not None:
            if not isinstance(self.policy_trust, ManagedArtifact):
                raise SecurityConfigurationError("managed policy trust artifact must be typed")
            encoded_trust = self.policy_trust.content.encode("utf-8")
            if (
                self.policy_trust.path != _policy_trust_path(self.platform)
                or self.policy_trust.media_type != "application/json"
                or not encoded_trust
                or len(encoded_trust) > 128_000
                or _required_sha256(self.policy_trust.sha256, "managed policy trust digest")
                != hashlib.sha256(encoded_trust).hexdigest()
            ):
                raise SecurityConfigurationError("managed policy trust artifact is invalid")
            try:
                trust = PolicyTrustStore.from_json(self.policy_trust.content)
            except (TypeError, ValueError) as error:
                raise SecurityConfigurationError(
                    "managed policy trust bundle is invalid"
                ) from error
            if trust.to_json() != self.policy_trust.content:
                raise SecurityConfigurationError("managed policy trust bundle is not canonical")

    @classmethod
    def from_bundle(
        cls,
        bundle: ManagedConfigurationBundle,
        *,
        required_executables: tuple[ManagedExecutableRequirement, ...],
        policy_trust_store: PolicyTrustStore | None = None,
    ) -> ManagedDeploymentPackage:
        """Bind a compiled bundle to exact endpoint-installed prerequisites."""
        if not isinstance(bundle, ManagedConfigurationBundle):
            raise SecurityConfigurationError("managed deployment requires a compiled bundle")
        return cls(
            host=bundle.host,
            host_version=bundle.host_version,
            platform=bundle.platform,
            policy_id=bundle.policy_id,
            policy_version=bundle.policy_version,
            bundle_hash=bundle.bundle_hash,
            artifacts=bundle.artifacts,
            required_executables=required_executables,
            policy_trust=(
                _policy_trust_artifact(policy_trust_store, bundle.platform)
                if policy_trust_store is not None
                else None
            ),
        )

    def with_policy_trust(self, store: PolicyTrustStore) -> ManagedDeploymentPackage:
        """Return schema-v2 bytes binding this package to reviewed public trust.

        The original immutable package is unchanged. Callers must distribute
        the resulting package digest and trust digest through authenticated,
        independent desired-state fields before installation.
        """
        return ManagedDeploymentPackage(
            host=self.host,
            host_version=self.host_version,
            platform=self.platform,
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            bundle_hash=self.bundle_hash,
            artifacts=self.artifacts,
            required_executables=self.required_executables,
            policy_trust=_policy_trust_artifact(store, self.platform),
        )

    @classmethod
    def from_json(
        cls,
        encoded: bytes,
        *,
        expected_package_sha256: str,
    ) -> ManagedDeploymentPackage:
        """Parse canonical bytes only after checking an out-of-band digest."""
        expected = _required_sha256(expected_package_sha256, "expected package digest")
        if not isinstance(encoded, bytes) or not encoded or len(encoded) > _MAX_PACKAGE_BYTES:
            raise SecurityConfigurationError("managed deployment package exceeds safe size")
        if hashlib.sha256(encoded).hexdigest() != expected:
            raise SecurityConfigurationError("managed deployment package digest does not match")
        try:
            value = json.loads(encoded.decode("utf-8"), object_pairs_hook=_duplicate_rejector)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SecurityConfigurationError("managed deployment package is malformed") from error
        package = cls._from_wire(value)
        if package.to_json() != encoded:
            raise SecurityConfigurationError("managed deployment package is not canonical")
        return package

    @classmethod
    def _from_wire(cls, value: object) -> ManagedDeploymentPackage:
        """Build a typed package from one exact schema-1 mapping."""
        fields_v1 = {
            "schemaVersion",
            "host",
            "hostVersion",
            "platform",
            "policyId",
            "policyVersion",
            "bundleHash",
            "artifacts",
            "requiredExecutables",
        }
        fields_v2 = fields_v1 | {"policyTrust"}
        if not isinstance(value, dict) or (
            value.get("schemaVersion") == 1
            and set(value) != fields_v1
            or value.get("schemaVersion") == 2
            and set(value) != fields_v2
            or value.get("schemaVersion") not in {1, 2}
        ):
            raise SecurityConfigurationError("managed deployment package schema is invalid")
        try:
            host = AgentHost(value["host"])
            platform = ManagedPlatform(value["platform"])
        except (TypeError, ValueError) as error:
            raise SecurityConfigurationError("managed deployment target is invalid") from error
        raw_artifacts = value.get("artifacts")
        raw_executables = value.get("requiredExecutables")
        policy_version = value.get("policyVersion")
        if (
            isinstance(policy_version, bool)
            or not isinstance(policy_version, int)
            or policy_version <= 0
        ):
            raise SecurityConfigurationError("managed deployment policy version must be positive")
        if not isinstance(raw_artifacts, list) or not isinstance(raw_executables, list):
            raise SecurityConfigurationError("managed deployment package lists are invalid")
        artifacts: list[ManagedArtifact] = []
        for item in raw_artifacts:
            if not isinstance(item, dict) or set(item) != {
                "path",
                "mediaType",
                "content",
                "sha256",
            }:
                raise SecurityConfigurationError("managed deployment artifact schema is invalid")
            artifacts.append(
                ManagedArtifact(
                    _required_text(item.get("path"), "managed artifact path", 512),
                    _required_text(item.get("mediaType"), "managed artifact media type", 64),
                    _required_text(
                        item.get("content"), "managed artifact content", _MAX_ARTIFACT_BYTES
                    ),
                    _required_sha256(item.get("sha256"), "managed artifact digest"),
                )
            )
        executables: list[ManagedExecutableRequirement] = []
        for item in raw_executables:
            if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
                raise SecurityConfigurationError("managed executable schema is invalid")
            executables.append(
                ManagedExecutableRequirement(
                    _required_text(item.get("path"), "managed executable path", 512),
                    _required_sha256(item.get("sha256"), "managed executable digest"),
                )
            )
        policy_trust: ManagedArtifact | None = None
        if value.get("schemaVersion") == 2:
            raw_trust = value.get("policyTrust")
            if not isinstance(raw_trust, dict) or set(raw_trust) != {
                "path",
                "mediaType",
                "content",
                "sha256",
            }:
                raise SecurityConfigurationError("managed policy trust schema is invalid")
            policy_trust = ManagedArtifact(
                _required_text(raw_trust.get("path"), "managed policy trust path", 512),
                _required_text(raw_trust.get("mediaType"), "managed policy trust media type", 64),
                _required_text(raw_trust.get("content"), "managed policy trust content", 128_000),
                _required_sha256(raw_trust.get("sha256"), "managed policy trust digest"),
            )
        return cls(
            host=host,
            host_version=_required_text(value.get("hostVersion"), "host version", 64),
            platform=platform,
            policy_id=_required_text(value.get("policyId"), "policy ID", 128),
            policy_version=policy_version,
            bundle_hash=_required_sha256(value.get("bundleHash"), "bundle hash"),
            artifacts=tuple(artifacts),
            required_executables=tuple(executables),
            policy_trust=policy_trust,
        )

    def to_wire(self) -> dict[str, object]:
        """Return the exact credential-free schema-1 package object."""
        value: dict[str, object] = {
            "schemaVersion": 2 if self.policy_trust is not None else 1,
            "host": self.host.value,
            "hostVersion": self.host_version,
            "platform": self.platform.value,
            "policyId": self.policy_id,
            "policyVersion": self.policy_version,
            "bundleHash": self.bundle_hash,
            "artifacts": [
                {
                    "path": artifact.path,
                    "mediaType": artifact.media_type,
                    "content": artifact.content,
                    "sha256": artifact.sha256,
                }
                for artifact in self.artifacts
            ],
            "requiredExecutables": [item.to_wire() for item in self.required_executables],
        }
        if self.policy_trust is not None:
            value["policyTrust"] = {
                "path": self.policy_trust.path,
                "mediaType": self.policy_trust.media_type,
                "content": self.policy_trust.content,
                "sha256": self.policy_trust.sha256,
            }
        return value

    def to_json(self) -> bytes:
        """Return deterministic canonical UTF-8 bytes used for digest pinning."""
        encoded = json.dumps(
            self.to_wire(), ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        if len(encoded) > _MAX_PACKAGE_BYTES:
            raise SecurityConfigurationError("managed deployment package exceeds safe size")
        return encoded

    @property
    def package_sha256(self) -> str:
        """Return the digest endpoint management must deliver out of band."""
        return hashlib.sha256(self.to_json()).hexdigest()

    def require_target(
        self,
        *,
        host: AgentHost,
        platform: ManagedPlatform,
        bundle_hash: str,
        policy_trust_bundle_sha256: str | None = None,
    ) -> None:
        """Reject cross-host, cross-platform or stale desired-state packages."""
        if not isinstance(host, AgentHost) or not isinstance(platform, ManagedPlatform):
            raise SecurityConfigurationError("managed deployment target must be typed")
        expected_bundle = _required_sha256(bundle_hash, "expected bundle hash")
        if self.host is not host or self.platform is not platform:
            raise SecurityConfigurationError("managed deployment package targets another host")
        if self.bundle_hash != expected_bundle:
            raise SecurityConfigurationError("managed deployment package is not desired state")
        actual_trust = self.policy_trust.sha256 if self.policy_trust is not None else None
        if policy_trust_bundle_sha256 is not None:
            expected_trust = _required_sha256(
                policy_trust_bundle_sha256, "expected policy trust digest"
            )
        else:
            expected_trust = None
        if actual_trust != expected_trust:
            raise SecurityConfigurationError("managed policy trust is not desired state")

    @property
    def policy_trust_bundle_sha256(self) -> str | None:
        """Return the managed trust digest, or ``None`` for a legacy v1 package."""
        return self.policy_trust.sha256 if self.policy_trust is not None else None


def _measure_artifact(artifact: ManagedArtifact, *, owner_uid: int) -> None:
    """Prove one exact administrator-owned regular file without following links."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(artifact.path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != owner_uid
                or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or metadata.st_size > _MAX_ARTIFACT_BYTES
            ):
                raise SecurityConfigurationError("managed deployment artifact is not protected")
            encoded = stream.read(_MAX_ARTIFACT_BYTES + 1)
    except OSError as error:
        raise SecurityConfigurationError(
            "managed deployment artifact cannot be measured"
        ) from error
    if (
        encoded != artifact.content.encode("utf-8")
        or hashlib.sha256(encoded).hexdigest() != artifact.sha256
    ):
        raise SecurityConfigurationError("managed deployment artifact content has drifted")


def measure_managed_deployment_package(
    package: ManagedDeploymentPackage,
    *,
    source: ManagedConfigurationSource,
    now: float,
    ttl_seconds: int = 300,
) -> ManagedConfigurationEvidence:
    """Measure native configuration and policy trust for one heartbeat.

    A schema-v2 package and its separately pinned trust digest are mandatory.
    Every file is reopened without following symlinks on each call. The result
    contains only identities and digests; it does not expose public-key bytes.
    """
    if not isinstance(package, ManagedDeploymentPackage) or package.policy_trust is None:
        raise SecurityConfigurationError("managed trust convergence requires a schema-v2 package")
    expected_platform = {
        "Darwin": ManagedPlatform.MACOS,
        "Linux": ManagedPlatform.LINUX,
        "Windows": ManagedPlatform.WINDOWS,
    }.get(host_platform.system())
    if expected_platform is None or package.platform is not expected_platform:
        raise SecurityConfigurationError("managed deployment package targets another platform")
    if package.platform is ManagedPlatform.WINDOWS:
        raise SecurityConfigurationError("Windows managed trust measurement requires an adapter")
    if (
        isinstance(now, bool)
        or not isinstance(now, (int, float))
        or now < 0
        or isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or not 30 <= ttl_seconds <= 600
    ):
        raise SecurityConfigurationError("managed trust measurement parameters are invalid")
    for artifact in (*package.artifacts, package.policy_trust):
        # Endpoint evidence is authoritative only for administrator-controlled
        # files. Keeping UID 0 inside this trust boundary prevents callers from
        # weakening the ownership invariant while still producing valid-looking
        # heartbeat evidence.
        _measure_artifact(artifact, owner_uid=0)
    return ManagedConfigurationEvidence(
        host=package.host,
        host_version=package.host_version,
        platform=package.platform,
        bundle_hash=package.bundle_hash,
        policy_id=package.policy_id,
        policy_version=package.policy_version,
        source=source,
        verified_at=now,
        expires_at=now + ttl_seconds,
        policy_trust_bundle_sha256=package.policy_trust.sha256,
    )


__all__ = [
    "ManagedDeploymentPackage",
    "ManagedExecutableRequirement",
    "measure_managed_deployment_package",
]
