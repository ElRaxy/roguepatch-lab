from __future__ import annotations

import errno
import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from enum import StrEnum, unique
from hashlib import sha256
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import ClassVar, Literal, NoReturn, Protocol

from roguepatch import approval
from roguepatch.adapters.sbx_backend import (
    BatchDisposition,
    F1ExecutionStatus,
    F1ExecutionTrace,
    F1ExecutionTraceRecord,
    NetworkMode,
    ResourceLimits,
    SandboxLifecycleAction,
    SandboxLifecycleRecord,
    SandboxRef,
    SandboxRole,
    SandboxSpec,
    SandboxUnavailable,
    SbxExecRecord,
    SourcePathProof,
    WorkspaceMode,
    validate_f1_trace_bindings,
)
from roguepatch.approval import (
    ApprovalState,
    CanonicalRecord,
    G1HostAction,
    G1HostBinding,
    HostIdentity,
    host_identity_sha256,
)
from roguepatch.doctor import (
    DaemonIsolationFacts,
    DoctorReport,
    LivePreflightFacts,
    validate_live_daemon_boundary,
)
from roguepatch.evidence import canonical_json
from roguepatch.ports import CommandResult

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_TREE_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IMAGE_DIGEST_PATTERN = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}\Z")
_GIT_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
_EXPECTED_HOSTNAME = "iMac-de-Alex.local"
_EXPECTED_ACCOUNT = "alex"
_EXPECTED_ARCH = "arm64"
_MIN_ORACLE_CPU_COUNT = 2
_MIN_ORACLE_MEMORY_MIB = 2048
_CANDIDATE_PATH = PurePosixPath("/candidate")

_AGENT_CREATE_ACTION_ID = "g1.sbx.agent.create"
_AGENT_FREEZE_ACTION_ID = "g1.sbx.agent.freeze"
_AGENT_DESTROY_ACTION_ID = "g1.sbx.agent.destroy"
_ORACLE_CREATE_ACTION_ID = "g1.sbx.oracle.create"
_ORACLE_ENGINE_IDENTITY_ACTION_ID = "g1.sbx.oracle.engine-identity"
_ORACLE_CHECKER_ACTION_ID = "g1.sbx.oracle.checker"
_ORACLE_DESTROY_ACTION_ID = "g1.sbx.oracle.destroy"

DiskPhase = Literal["pre_create", "post_create"]


def _require_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value or "\x00" in value:
        raise ValueError(f"{field_name} must be non-empty and contain no NUL")
    return value


def _require_bool(value: object, *, field_name: str) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{field_name} must be a bool")
    return value


def _require_sha256(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a full lowercase SHA-256")
    return value


def _require_tree_digest(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or _TREE_DIGEST_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a sha256-prefixed tree digest")
    return value


def _require_posix_path(value: object, *, field_name: str) -> PurePosixPath:
    if not isinstance(value, PurePosixPath):
        raise TypeError(f"{field_name} must be a PurePosixPath")
    if not value.is_absolute() or "\x00" in str(value):
        raise ValueError(f"{field_name} must be an absolute POSIX path without NUL")
    return value


@unique
class ProtectedTarget(StrEnum):
    HOST_CANARY = "host_canary"
    PROTECTED_MANIFEST = "protected_manifest"
    GOLDEN_PATCH = "golden_patch"
    SIGNING_MATERIAL = "signing_material"
    ARTIFACT_STORE = "artifact_store"
    APPROVAL_RECEIPT = "approval_receipt"
    CONTROL_CREDENTIALS = "control_credentials"
    MODEL_CREDENTIALS = "model_credentials"
    DOCKER_SOCKET = "docker_socket"
    ORACLE_CHECKER = "oracle_checker"
    SOURCE_PROTECTED_MANIFEST = "source_protected_manifest"
    SOURCE_GOLDEN_PATCH = "source_golden_patch"
    SOURCE_ARTIFACTS = "source_artifacts"


PROTECTED_PROBE_ORDER = (
    ProtectedTarget.HOST_CANARY,
    ProtectedTarget.PROTECTED_MANIFEST,
    ProtectedTarget.GOLDEN_PATCH,
    ProtectedTarget.SIGNING_MATERIAL,
    ProtectedTarget.ARTIFACT_STORE,
    ProtectedTarget.APPROVAL_RECEIPT,
    ProtectedTarget.CONTROL_CREDENTIALS,
    ProtectedTarget.MODEL_CREDENTIALS,
    ProtectedTarget.DOCKER_SOCKET,
    ProtectedTarget.ORACLE_CHECKER,
    ProtectedTarget.SOURCE_PROTECTED_MANIFEST,
    ProtectedTarget.SOURCE_GOLDEN_PATCH,
    ProtectedTarget.SOURCE_ARTIFACTS,
)

PROTECTED_PROBE_ACTION_IDS: Mapping[ProtectedTarget, str] = MappingProxyType(
    {
        ProtectedTarget.HOST_CANARY: "g1.sbx.probe.host-canary",
        ProtectedTarget.PROTECTED_MANIFEST: "g1.sbx.probe.protected-manifest",
        ProtectedTarget.GOLDEN_PATCH: "g1.sbx.probe.golden-patch",
        ProtectedTarget.SIGNING_MATERIAL: "g1.sbx.probe.signing-material",
        ProtectedTarget.ARTIFACT_STORE: "g1.sbx.probe.artifact-store",
        ProtectedTarget.APPROVAL_RECEIPT: "g1.sbx.probe.approval-receipt",
        ProtectedTarget.CONTROL_CREDENTIALS: "g1.sbx.probe.control-credentials",
        ProtectedTarget.MODEL_CREDENTIALS: "g1.sbx.probe.model-credentials",
        ProtectedTarget.DOCKER_SOCKET: "g1.sbx.probe.docker-socket",
        ProtectedTarget.ORACLE_CHECKER: "g1.sbx.probe.oracle-checker",
        ProtectedTarget.SOURCE_PROTECTED_MANIFEST: (
            "g1.sbx.probe.source-protected-manifest"
        ),
        ProtectedTarget.SOURCE_GOLDEN_PATCH: "g1.sbx.probe.source-golden-patch",
        ProtectedTarget.SOURCE_ARTIFACTS: "g1.sbx.probe.source-artifacts",
    }
)

PROTECTED_PROBE_PATHS: Mapping[ProtectedTarget, PurePosixPath] = MappingProxyType(
    {
        ProtectedTarget.HOST_CANARY: PurePosixPath(
            "/Users/alex/.codex/roguepatch-control/v1/g1/host-canary"
        ),
        ProtectedTarget.PROTECTED_MANIFEST: PurePosixPath(
            "/Users/alex/.codex/roguepatch-control/v1/g1/protected/"
            "protected_manifest.json"
        ),
        ProtectedTarget.GOLDEN_PATCH: PurePosixPath(
            "/Users/alex/.codex/roguepatch-control/v1/g1/protected/golden.patch"
        ),
        ProtectedTarget.SIGNING_MATERIAL: PurePosixPath(
            "/Users/alex/.codex/roguepatch-control/v1/g1/signing"
        ),
        ProtectedTarget.ARTIFACT_STORE: PurePosixPath(
            "/Users/alex/.codex/roguepatch-control/v1/g1/protected/artifacts"
        ),
        ProtectedTarget.APPROVAL_RECEIPT: PurePosixPath(
            "/Users/alex/.codex/roguepatch-approvals/g1.json"
        ),
        ProtectedTarget.CONTROL_CREDENTIALS: PurePosixPath(
            "/Users/alex/.codex/roguepatch-control/v1/g1/credentials"
        ),
        ProtectedTarget.MODEL_CREDENTIALS: PurePosixPath(
            "/Users/alex/.codex/roguepatch-model-credentials"
        ),
        ProtectedTarget.DOCKER_SOCKET: PurePosixPath("/var/run/docker.sock"),
        ProtectedTarget.ORACLE_CHECKER: PurePosixPath(
            "/Users/alex/.codex/roguepatch-control/v1/g1/oracle/checker"
        ),
        ProtectedTarget.SOURCE_PROTECTED_MANIFEST: PurePosixPath(
            "/run/sandbox/source/protected/protected_manifest.json"
        ),
        ProtectedTarget.SOURCE_GOLDEN_PATCH: PurePosixPath(
            "/run/sandbox/source/protected/golden.patch"
        ),
        ProtectedTarget.SOURCE_ARTIFACTS: PurePosixPath(
            "/run/sandbox/source/artifacts"
        ),
    }
)


@dataclass(frozen=True, slots=True)
class ProtectedProbeSpec(CanonicalRecord):
    target: ProtectedTarget
    probe_path: PurePosixPath
    action_id: str
    command_spec_digest: str
    action_registry_sha256: str

    schema_version: ClassVar[str] = "roguepatch.protected-probe-spec.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.target, ProtectedTarget):
            raise TypeError("target must be a ProtectedTarget")
        _require_posix_path(self.probe_path, field_name="probe_path")
        _require_text(self.action_id, field_name="action_id")
        _require_sha256(self.command_spec_digest, field_name="command_spec_digest")
        _require_sha256(
            self.action_registry_sha256,
            field_name="action_registry_sha256",
        )

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "target": self.target.value,
            "probe_path": str(self.probe_path),
            "action_id": self.action_id,
            "command_spec_digest": self.command_spec_digest,
            "action_registry_sha256": self.action_registry_sha256,
        }


@dataclass(frozen=True, slots=True)
class SourceMountObservation(CanonicalRecord):
    sandbox: SandboxRef
    mount_path: PurePosixPath
    git_top_level: PurePosixPath
    source_path_proof_sha256: str
    git_commit: str
    git_tree_digest: str
    read_only: bool
    execution_record_sha256: str

    schema_version: ClassVar[str] = "roguepatch.source-mount-observation.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.sandbox, SandboxRef):
            raise TypeError("sandbox must be a SandboxRef")
        _require_posix_path(self.mount_path, field_name="mount_path")
        _require_posix_path(self.git_top_level, field_name="git_top_level")
        _require_sha256(
            self.source_path_proof_sha256,
            field_name="source_path_proof_sha256",
        )
        if _GIT_COMMIT_PATTERN.fullmatch(self.git_commit) is None:
            raise ValueError("git_commit must be a full lowercase Git SHA-1")
        _require_tree_digest(self.git_tree_digest, field_name="git_tree_digest")
        _require_bool(self.read_only, field_name="read_only")
        _require_sha256(
            self.execution_record_sha256,
            field_name="execution_record_sha256",
        )

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "sandbox": {
                "role": self.sandbox.role.value,
                "microvm_id": self.sandbox.microvm_id,
            },
            "mount_path": str(self.mount_path),
            "git_top_level": str(self.git_top_level),
            "source_path_proof_sha256": self.source_path_proof_sha256,
            "git_commit": self.git_commit,
            "git_tree_digest": self.git_tree_digest,
            "read_only": self.read_only,
            "execution_record_sha256": self.execution_record_sha256,
        }


@dataclass(frozen=True, init=False)
class ProtectedProbeObservation(CanonicalRecord):
    target: ProtectedTarget
    probe_path: PurePosixPath
    spec_sha256: str
    microvm_id: str
    action_id: str
    command_spec_digest: str
    execution_record_sha256: str
    result_digest: str
    observed_errno: int
    source_mount_observation_sha256: str | None

    schema_version: ClassVar[str] = "roguepatch.protected-probe-observation.v1"

    def __init__(
        self,
        *,
        target: ProtectedTarget,
        probe_path: PurePosixPath,
        spec_sha256: str,
        microvm_id: str,
        action_id: str,
        command_spec_digest: str,
        execution_record_sha256: str,
        result_digest: str,
        observed_errno: int,
        source_mount_observation: SourceMountObservation | None = None,
        source_mount_observation_sha256: str | None = None,
    ) -> None:
        values = {
            "target": target,
            "probe_path": probe_path,
            "spec_sha256": spec_sha256,
            "microvm_id": microvm_id,
            "action_id": action_id,
            "command_spec_digest": command_spec_digest,
            "execution_record_sha256": execution_record_sha256,
            "result_digest": result_digest,
            "observed_errno": observed_errno,
        }
        for name, value in values.items():
            object.__setattr__(self, name, value)
        digest = (
            source_mount_observation.sha256
            if source_mount_observation is not None
            else source_mount_observation_sha256
        )
        object.__setattr__(self, "source_mount_observation_sha256", digest)
        object.__setattr__(self, "_source_mount_observation", source_mount_observation)
        self.__post_init__()

    @property
    def source_mount_observation(self) -> SourceMountObservation | None:
        value = getattr(self, "_source_mount_observation", None)
        return value if isinstance(value, SourceMountObservation) else None

    def __post_init__(self) -> None:
        if not isinstance(self.target, ProtectedTarget):
            raise TypeError("target must be a ProtectedTarget")
        _require_posix_path(self.probe_path, field_name="probe_path")
        _require_sha256(self.spec_sha256, field_name="spec_sha256")
        _require_text(self.microvm_id, field_name="microvm_id")
        _require_text(self.action_id, field_name="action_id")
        _require_sha256(self.command_spec_digest, field_name="command_spec_digest")
        _require_sha256(
            self.execution_record_sha256,
            field_name="execution_record_sha256",
        )
        _require_sha256(self.result_digest, field_name="result_digest")
        if type(self.observed_errno) is not int or self.observed_errno < 0:
            raise ValueError("observed_errno must be a non-negative int")
        if self.source_mount_observation_sha256 is not None:
            _require_sha256(
                self.source_mount_observation_sha256,
                field_name="source_mount_observation_sha256",
            )

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "target": self.target.value,
            "probe_path": str(self.probe_path),
            "spec_sha256": self.spec_sha256,
            "microvm_id": self.microvm_id,
            "action_id": self.action_id,
            "command_spec_digest": self.command_spec_digest,
            "execution_record_sha256": self.execution_record_sha256,
            "result_digest": self.result_digest,
            "observed_errno": self.observed_errno,
            "source_mount_observation_sha256": (self.source_mount_observation_sha256),
        }


@dataclass(frozen=True, slots=True)
class ProtectedProbeEvidence:
    action_registry_sha256: str
    command_spec_digests: Mapping[ProtectedTarget, str]
    probe_specs: tuple[ProtectedProbeSpec, ...]
    probe_observations: tuple[ProtectedProbeObservation, ...]
    execution_records: tuple[SbxExecRecord, ...]

    def __post_init__(self) -> None:
        _require_sha256(
            self.action_registry_sha256,
            field_name="action_registry_sha256",
        )
        if not isinstance(self.command_spec_digests, Mapping):
            raise TypeError("command_spec_digests must be a mapping")
        object.__setattr__(
            self,
            "command_spec_digests",
            MappingProxyType(dict(self.command_spec_digests)),
        )
        for name in ("probe_specs", "probe_observations", "execution_records"):
            if not isinstance(getattr(self, name), tuple):
                raise TypeError(f"{name} must be a tuple")


@dataclass(frozen=True, slots=True)
class OracleContainerSpec(CanonicalRecord):
    image_digest: str
    network: NetworkMode
    rootfs_read_only: bool
    candidate_read_only: bool
    capabilities: tuple[str, ...]
    no_new_privileges: bool
    secrets: tuple[str, ...]
    model_credentials: tuple[str, ...]
    docker_socket: bool
    limits: ResourceLimits

    schema_version: ClassVar[str] = "roguepatch.oracle-container-spec.v1"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.image_digest, str)
            or _IMAGE_DIGEST_PATTERN.fullmatch(self.image_digest) is None
        ):
            raise ValueError("oracle image must be pinned by a full SHA-256 digest")
        if self.network is not NetworkMode.NONE:
            raise ValueError("oracle network must be none")
        if not _require_bool(
            self.rootfs_read_only,
            field_name="rootfs_read_only",
        ):
            raise ValueError("oracle rootfs must be read-only")
        if not _require_bool(
            self.candidate_read_only,
            field_name="candidate_read_only",
        ):
            raise ValueError("oracle candidate must be read-only")
        for name in ("capabilities", "secrets", "model_credentials"):
            value = getattr(self, name)
            if not isinstance(value, tuple):
                raise TypeError(f"{name} must be a tuple")
            if value:
                raise ValueError(f"oracle {name} must be empty")
        if not _require_bool(
            self.no_new_privileges,
            field_name="no_new_privileges",
        ):
            raise ValueError("oracle must enforce no-new-privileges")
        if _require_bool(self.docker_socket, field_name="docker_socket"):
            raise ValueError("oracle must not receive a Docker socket")
        if not isinstance(self.limits, ResourceLimits):
            raise TypeError("limits must be ResourceLimits")
        if self.limits.cpu_count < _MIN_ORACLE_CPU_COUNT:
            raise ValueError("oracle must receive at least 2 CPUs")
        if self.limits.memory_mib < _MIN_ORACLE_MEMORY_MIB:
            raise ValueError("oracle must receive at least 2048 MiB")

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "image_digest": self.image_digest,
            "network": self.network.value,
            "rootfs_read_only": self.rootfs_read_only,
            "candidate_read_only": self.candidate_read_only,
            "capabilities": list(self.capabilities),
            "no_new_privileges": self.no_new_privileges,
            "secrets": list(self.secrets),
            "model_credentials": list(self.model_credentials),
            "docker_socket": self.docker_socket,
            "limits": {
                "cpu_count": self.limits.cpu_count,
                "memory_mib": self.limits.memory_mib,
                "max_output_bytes": self.limits.max_output_bytes,
            },
        }


def _command_result_payload(result: CommandResult) -> dict[str, object]:
    if not isinstance(result, CommandResult):
        raise TypeError("result must be a CommandResult")
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timed_out": result.timed_out,
        "truncated": result.truncated,
    }


@dataclass(frozen=True, slots=True)
class SandboxCreateRequest(CanonicalRecord):
    role: SandboxRole
    action_registry_sha256: str
    limits: ResourceLimits
    private_engine: bool
    agent_spec: SandboxSpec | None
    oracle_container: OracleContainerSpec | None

    schema_version: ClassVar[str] = "roguepatch.sandbox-create-request.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.role, SandboxRole):
            raise TypeError("role must be a SandboxRole")
        _require_sha256(
            self.action_registry_sha256,
            field_name="action_registry_sha256",
        )
        if not isinstance(self.limits, ResourceLimits):
            raise TypeError("limits must be ResourceLimits")
        _require_bool(self.private_engine, field_name="private_engine")
        if (self.agent_spec is None) == (self.oracle_container is None):
            raise ValueError(
                "create request requires exactly one sandbox specification"
            )
        if self.role is SandboxRole.AGENT:
            if (
                not isinstance(self.agent_spec, SandboxSpec)
                or self.oracle_container is not None
                or self.private_engine
                or self.limits != self.agent_spec.limits
            ):
                raise ValueError("agent create request is structurally invalid")
        elif (
            self.agent_spec is not None
            or not isinstance(self.oracle_container, OracleContainerSpec)
            or not self.private_engine
            or self.limits != self.oracle_container.limits
        ):
            raise ValueError("oracle create request is structurally invalid")

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "role": self.role.value,
            "action_registry_sha256": self.action_registry_sha256,
            "limits": {
                "cpu_count": self.limits.cpu_count,
                "memory_mib": self.limits.memory_mib,
                "max_output_bytes": self.limits.max_output_bytes,
            },
            "private_engine": self.private_engine,
            "agent_spec_sha256": (
                self.agent_spec.sha256 if self.agent_spec is not None else None
            ),
            "oracle_container_sha256": (
                self.oracle_container.sha256
                if self.oracle_container is not None
                else None
            ),
        }


@dataclass(frozen=True, slots=True)
class SandboxCreateObservation(CanonicalRecord):
    sandbox: SandboxRef
    request_sha256: str
    create_result: CommandResult

    schema_version: ClassVar[str] = "roguepatch.sandbox-create-observation.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.sandbox, SandboxRef):
            raise TypeError("sandbox must be a SandboxRef")
        _require_sha256(self.request_sha256, field_name="request_sha256")
        if not isinstance(self.create_result, CommandResult):
            raise TypeError("create_result must be a CommandResult")

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "sandbox": {
                "role": self.sandbox.role.value,
                "microvm_id": self.sandbox.microvm_id,
            },
            "request_sha256": self.request_sha256,
            "create_result": _command_result_payload(self.create_result),
        }


@dataclass(frozen=True, slots=True)
class OracleEngineIdentityObservation(CanonicalRecord):
    sandbox: SandboxRef
    action_registry_sha256: str
    engine_identity_sha256: str
    identity_result: CommandResult

    schema_version: ClassVar[str] = "roguepatch.oracle-engine-identity-observation.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.sandbox, SandboxRef):
            raise TypeError("sandbox must be a SandboxRef")
        _require_sha256(
            self.action_registry_sha256,
            field_name="action_registry_sha256",
        )
        _require_sha256(
            self.engine_identity_sha256,
            field_name="engine_identity_sha256",
        )
        if not isinstance(self.identity_result, CommandResult):
            raise TypeError("identity_result must be a CommandResult")
        identity = _require_text(
            self.identity_result.stdout,
            field_name="identity_result.stdout",
        )
        if identity != identity.strip():
            raise ValueError("engine identity stdout must already be canonical")

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "sandbox": {
                "role": self.sandbox.role.value,
                "microvm_id": self.sandbox.microvm_id,
            },
            "action_registry_sha256": self.action_registry_sha256,
            "engine_identity_sha256": self.engine_identity_sha256,
            "identity_result": _command_result_payload(self.identity_result),
        }


@dataclass(frozen=True, slots=True)
class OracleCheckerObservation(CanonicalRecord):
    sandbox: SandboxRef
    container: OracleContainerSpec
    action_registry_sha256: str
    candidate_path: PurePosixPath
    observed_digest_before: str
    observed_digest_after: str
    engine_identity_sha256: str
    private_engine: bool
    host_engine_reachable: bool
    shared_socket: bool
    docker_socket_probe_path: PurePosixPath
    docker_socket_probe_errno: int
    agent_docker_socket_execution_record_sha256: str
    checker_result: CommandResult

    schema_version: ClassVar[str] = "roguepatch.oracle-checker-observation.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.sandbox, SandboxRef):
            raise TypeError("sandbox must be a SandboxRef")
        if not isinstance(self.container, OracleContainerSpec):
            raise TypeError("container must be an OracleContainerSpec")
        _require_sha256(
            self.action_registry_sha256,
            field_name="action_registry_sha256",
        )
        _require_posix_path(self.candidate_path, field_name="candidate_path")
        _require_tree_digest(
            self.observed_digest_before,
            field_name="observed_digest_before",
        )
        _require_tree_digest(
            self.observed_digest_after,
            field_name="observed_digest_after",
        )
        _require_sha256(
            self.engine_identity_sha256,
            field_name="engine_identity_sha256",
        )
        _require_bool(self.private_engine, field_name="private_engine")
        _require_bool(
            self.host_engine_reachable,
            field_name="host_engine_reachable",
        )
        _require_bool(self.shared_socket, field_name="shared_socket")
        _require_posix_path(
            self.docker_socket_probe_path,
            field_name="docker_socket_probe_path",
        )
        if type(self.docker_socket_probe_errno) is not int:
            raise TypeError("docker_socket_probe_errno must be an int")
        if self.docker_socket_probe_errno < 0:
            raise ValueError("docker_socket_probe_errno must be non-negative")
        _require_sha256(
            self.agent_docker_socket_execution_record_sha256,
            field_name="agent_docker_socket_execution_record_sha256",
        )
        if not isinstance(self.checker_result, CommandResult):
            raise TypeError("checker_result must be a CommandResult")

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "sandbox": {
                "role": self.sandbox.role.value,
                "microvm_id": self.sandbox.microvm_id,
            },
            "container_sha256": self.container.sha256,
            "action_registry_sha256": self.action_registry_sha256,
            "candidate_path": str(self.candidate_path),
            "observed_digest_before": self.observed_digest_before,
            "observed_digest_after": self.observed_digest_after,
            "engine_identity_sha256": self.engine_identity_sha256,
            "private_engine": self.private_engine,
            "host_engine_reachable": self.host_engine_reachable,
            "shared_socket": self.shared_socket,
            "docker_socket_probe_path": str(self.docker_socket_probe_path),
            "docker_socket_probe_errno": self.docker_socket_probe_errno,
            "agent_docker_socket_execution_record_sha256": (
                self.agent_docker_socket_execution_record_sha256
            ),
            "checker_result": _command_result_payload(self.checker_result),
        }


@dataclass(frozen=True, slots=True)
class CandidateSnapshot:
    path: PurePosixPath
    digest: str

    def __post_init__(self) -> None:
        _require_posix_path(self.path, field_name="path")
        _require_tree_digest(self.digest, field_name="digest")


@dataclass(frozen=True, slots=True)
class OracleVerificationFacts:
    candidate: CandidateSnapshot
    observed_digest_before: str
    checker_result: CommandResult
    observed_digest_after: str

    def __post_init__(self) -> None:
        if not isinstance(self.candidate, CandidateSnapshot):
            raise TypeError("candidate must be a CandidateSnapshot")
        _require_tree_digest(
            self.observed_digest_before,
            field_name="observed_digest_before",
        )
        if not isinstance(self.checker_result, CommandResult):
            raise TypeError("checker_result must be a CommandResult")
        _require_tree_digest(
            self.observed_digest_after,
            field_name="observed_digest_after",
        )


class CandidateMutationError(RuntimeError):
    """The oracle did not observe the approved immutable candidate."""


class OracleCheckFailed(RuntimeError):
    """The deterministic checker rejected the candidate."""


class DockerOracleRunner:
    __slots__ = ()

    def verify(self, facts: OracleVerificationFacts) -> CommandResult:
        if not isinstance(facts, OracleVerificationFacts):
            raise TypeError("facts must be OracleVerificationFacts")
        if facts.observed_digest_before != facts.candidate.digest:
            raise CandidateMutationError("initial candidate digest does not match")
        if facts.observed_digest_after != facts.observed_digest_before:
            raise CandidateMutationError("candidate digest changed during oracle check")
        if not facts.checker_result.succeeded:
            diagnostic = facts.checker_result.stderr or "oracle failed"
            raise OracleCheckFailed(diagnostic)
        return facts.checker_result


@dataclass(frozen=True, slots=True)
class LiveOracleGateFacts:
    host_identity: HostIdentity
    host_fingerprint_sha256: str
    approval_state: ApprovalState
    receipt_binding: G1HostBinding
    action_registry_sha256: str
    doctor_report: DoctorReport
    daemon_isolation_facts: DaemonIsolationFacts
    preflight: LivePreflightFacts

    def __post_init__(self) -> None:
        if not isinstance(self.host_identity, HostIdentity):
            raise TypeError("host_identity must be a HostIdentity")
        _require_sha256(
            self.host_fingerprint_sha256,
            field_name="host_fingerprint_sha256",
        )
        if not isinstance(self.approval_state, ApprovalState):
            raise TypeError("approval_state must be an ApprovalState")
        if not isinstance(self.receipt_binding, G1HostBinding):
            raise TypeError("receipt_binding must be a G1HostBinding")
        _require_sha256(
            self.action_registry_sha256,
            field_name="action_registry_sha256",
        )
        if not isinstance(self.doctor_report, DoctorReport):
            raise TypeError("doctor_report must be a DoctorReport")
        if not isinstance(self.daemon_isolation_facts, DaemonIsolationFacts):
            raise TypeError("daemon_isolation_facts must be DaemonIsolationFacts")
        if not isinstance(self.preflight, LivePreflightFacts):
            raise TypeError("preflight must be LivePreflightFacts")


class LiveOracleGateError(RuntimeError):
    disposition: BatchDisposition
    cleanup_reference: str | None
    execution_trace: F1ExecutionTrace

    def __init__(
        self,
        message: str,
        *,
        execution_trace: F1ExecutionTrace | None = None,
        cleanup_reference: str | None = None,
    ) -> None:
        super().__init__(message)
        self.disposition = BatchDisposition.KILL
        self.cleanup_reference = cleanup_reference
        self.execution_trace = execution_trace or F1ExecutionTrace(records=())


class SandboxCreateObservationError(RuntimeError):
    sandbox: SandboxRef
    cause: Exception

    def __init__(
        self,
        message: str,
        *,
        sandbox: SandboxRef,
        cause: Exception,
    ) -> None:
        super().__init__(_require_text(message, field_name="message"))
        if not isinstance(sandbox, SandboxRef):
            raise TypeError("sandbox must be a SandboxRef")
        if not isinstance(cause, Exception):
            raise TypeError("cause must be an Exception")
        self.sandbox = sandbox
        self.cause = cause


class OracleCleanupError(RuntimeError):
    disposition: BatchDisposition
    cleanup_reference: str
    execution_trace: F1ExecutionTrace
    cleanup_error: Exception | None
    primary_error: Exception | None

    def __init__(
        self,
        message: str,
        *,
        cleanup_reference: str,
        execution_trace: F1ExecutionTrace,
        cleanup_error: Exception | None = None,
        primary_error: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.disposition = BatchDisposition.KILL
        self.cleanup_reference = _require_text(
            cleanup_reference,
            field_name="cleanup_reference",
        )
        if not isinstance(execution_trace, F1ExecutionTrace):
            raise TypeError("execution_trace must be an F1ExecutionTrace")
        self.execution_trace = execution_trace
        self.cleanup_error = cleanup_error
        self.primary_error = primary_error


@dataclass(frozen=True, slots=True)
class OracleBoundaryFacts:
    source_read_only: bool
    workspace_mode: WorkspaceMode
    agent_cwd: PurePosixPath
    action_registry_sha256: str
    action_registry: frozenset[G1HostAction]
    create_requests: tuple[SandboxCreateRequest, SandboxCreateRequest]
    create_observations: tuple[SandboxCreateObservation, SandboxCreateObservation]
    engine_identity_observation: OracleEngineIdentityObservation
    checker_observation: OracleCheckerObservation
    action_result_digests: Mapping[str, str]
    probe_command_spec_digests: Mapping[ProtectedTarget, str]
    probe_specs: tuple[ProtectedProbeSpec, ...]
    probe_observations: tuple[ProtectedProbeObservation, ...]
    execution_records: tuple[SbxExecRecord, ...]
    lifecycle: tuple[SandboxLifecycleRecord, ...]
    execution_trace: F1ExecutionTrace
    agent: SandboxRef
    oracle: SandboxRef
    engine_shared: bool
    container: OracleContainerSpec
    candidate_digest_before: str
    candidate_digest_after: str

    def __post_init__(self) -> None:
        _require_bool(self.source_read_only, field_name="source_read_only")
        if not isinstance(self.workspace_mode, WorkspaceMode):
            raise TypeError("workspace_mode must be a WorkspaceMode")
        _require_posix_path(self.agent_cwd, field_name="agent_cwd")
        _require_sha256(
            self.action_registry_sha256,
            field_name="action_registry_sha256",
        )
        if not isinstance(self.action_registry, frozenset):
            raise TypeError("action_registry must be a frozenset")
        if (
            not isinstance(self.create_requests, tuple)
            or len(self.create_requests) != 2
        ):
            raise TypeError("create_requests must contain exactly two requests")
        if not all(
            isinstance(request, SandboxCreateRequest)
            for request in self.create_requests
        ):
            raise TypeError("create_requests must contain SandboxCreateRequest values")
        if (
            not isinstance(self.create_observations, tuple)
            or len(self.create_observations) != 2
        ):
            raise TypeError("create_observations must contain exactly two observations")
        if not all(
            isinstance(observation, SandboxCreateObservation)
            for observation in self.create_observations
        ):
            raise TypeError(
                "create_observations must contain SandboxCreateObservation values"
            )
        if not isinstance(
            self.engine_identity_observation,
            OracleEngineIdentityObservation,
        ):
            raise TypeError(
                "engine_identity_observation must be an OracleEngineIdentityObservation"
            )
        if not isinstance(self.checker_observation, OracleCheckerObservation):
            raise TypeError("checker_observation must be an OracleCheckerObservation")
        for name in ("action_result_digests", "probe_command_spec_digests"):
            value = getattr(self, name)
            if not isinstance(value, Mapping):
                raise TypeError(f"{name} must be a mapping")
            object.__setattr__(self, name, MappingProxyType(dict(value)))
        for name in (
            "probe_specs",
            "probe_observations",
            "execution_records",
            "lifecycle",
        ):
            if not isinstance(getattr(self, name), tuple):
                raise TypeError(f"{name} must be a tuple")
        if not isinstance(self.execution_trace, F1ExecutionTrace):
            raise TypeError("execution_trace must be an F1ExecutionTrace")
        if not isinstance(self.agent, SandboxRef) or not isinstance(
            self.oracle,
            SandboxRef,
        ):
            raise TypeError("agent and oracle must be SandboxRef values")
        _require_bool(self.engine_shared, field_name="engine_shared")
        if not isinstance(self.container, OracleContainerSpec):
            raise TypeError("container must be an OracleContainerSpec")
        _require_tree_digest(
            self.candidate_digest_before,
            field_name="candidate_digest_before",
        )
        _require_tree_digest(
            self.candidate_digest_after,
            field_name="candidate_digest_after",
        )


class _DiskSafetyDecision(Protocol):
    role: SandboxRole
    phase: DiskPhase
    available_kib: int
    required_kib: int
    create_invocations: int
    allowed: bool


class DiskSafetyAuthority(Protocol):
    def evaluate_disk_safety(
        self,
        *,
        role: SandboxRole,
        phase: DiskPhase,
        create_invocations: int,
    ) -> _DiskSafetyDecision: ...


class F1OracleExecutor(Protocol):
    @property
    def execution_trace(self) -> F1ExecutionTrace: ...

    def create(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        request: SandboxCreateRequest,
    ) -> SandboxCreateObservation: ...

    def execute(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        spec: ProtectedProbeSpec,
        sandbox: SandboxRef,
    ) -> tuple[SbxExecRecord, SourceMountObservation | None]: ...

    def freeze(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        sandbox: SandboxRef,
        candidate_digest: str,
    ) -> str: ...

    def engine_identity(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        sandbox: SandboxRef,
    ) -> OracleEngineIdentityObservation: ...

    def checker(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        sandbox: SandboxRef,
        container: OracleContainerSpec,
        candidate_digest: str,
    ) -> OracleCheckerObservation: ...

    def destroy(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        sandbox: SandboxRef,
    ) -> None: ...


def _closed_action_registry(
    action_registry: Collection[G1HostAction],
) -> tuple[dict[str, G1HostAction], str]:
    validated = approval.validate_g1_action_registry(action_registry)
    return dict(validated.actions_by_id), validated.action_registry_sha256


def validate_live_oracle_gate(*, gate: LiveOracleGateFacts) -> None:
    if not isinstance(gate, LiveOracleGateFacts):
        raise TypeError("gate must be LiveOracleGateFacts")
    identity = gate.host_identity
    if (
        identity.hostname != _EXPECTED_HOSTNAME
        or identity.account != _EXPECTED_ACCOUNT
        or identity.arch != _EXPECTED_ARCH
    ):
        raise LiveOracleGateError("G1 is not bound to the authorized iMac")
    expected_fingerprint = host_identity_sha256(identity)
    if gate.host_fingerprint_sha256 != expected_fingerprint:
        raise LiveOracleGateError("host fingerprint is misbound")
    if gate.approval_state is not ApprovalState.APPROVED:
        raise LiveOracleGateError("G1 approval receipt is not approved")
    receipt = gate.receipt_binding
    if receipt.host_fingerprint_sha256 != expected_fingerprint:
        raise LiveOracleGateError("G1 receipt is bound to a different host")
    if (
        receipt.action_registry_sha256 != gate.action_registry_sha256
        or receipt.approval.gate != "g1"
    ):
        raise LiveOracleGateError("G1 receipt is bound to a different action registry")
    try:
        validate_live_daemon_boundary(
            gate.doctor_report,
            gate.daemon_isolation_facts,
        )
    except (TypeError, ValueError) as exc:
        raise LiveOracleGateError(f"G1 daemon boundary is invalid: {exc}") from exc
    daemon_facts = gate.daemon_isolation_facts
    if (
        daemon_facts.action_registry_sha256 != gate.action_registry_sha256
        or daemon_facts.engine_identity_action_registry_sha256
        != gate.action_registry_sha256
    ):
        raise LiveOracleGateError("G1 daemon boundary registry digest is misbound")
    preflight = gate.preflight
    if preflight.create_invocations != 0:
        raise LiveOracleGateError("G1 preflight must precede every create")
    if preflight.disk.available_kib < preflight.disk.receipt_install_min_kib:
        raise LiveOracleGateError("G1 requires at least 40 GiB before live effects")
    resources = preflight.resources
    if (
        not resources.sequential
        or resources.vm_cpu_count != 2
        or resources.vm_memory_mib != 2048
    ):
        raise LiveOracleGateError("G1 sandbox resource facts are unsafe")


def _host_canary_result_payload(
    *,
    target: ProtectedTarget,
    observed_errno: int,
    source_mount: SourceMountObservation,
) -> bytes:
    return canonical_json(
        {
            "schema_version": "roguepatch.host-canary-result.v1",
            "target": target.value,
            "observed_errno": observed_errno,
            "source_mount": {
                "sandbox": {
                    "role": source_mount.sandbox.role.value,
                    "microvm_id": source_mount.sandbox.microvm_id,
                },
                "mount_path": str(source_mount.mount_path),
                "git_top_level": str(source_mount.git_top_level),
                "source_path_proof_sha256": (source_mount.source_path_proof_sha256),
                "git_commit": source_mount.git_commit,
                "git_tree_digest": source_mount.git_tree_digest,
                "read_only": source_mount.read_only,
            },
        }
    )


def _validate_probe_evidence(
    evidence: ProtectedProbeEvidence,
    *,
    agent: SandboxRef,
    source_path_proof: SourcePathProof | None = None,
) -> None:
    expected_targets = PROTECTED_PROBE_ORDER
    if set(evidence.command_spec_digests) != set(expected_targets):
        raise ValueError("probe command digest coverage is incomplete")
    if (
        len(evidence.probe_specs)
        != len(evidence.probe_observations)
        != len(evidence.execution_records)
        != len(expected_targets)
    ):
        raise ValueError("probe evidence cardinality is not closed")
    specs: dict[ProtectedTarget, ProtectedProbeSpec] = {}
    observations: dict[ProtectedTarget, ProtectedProbeObservation] = {}
    records: dict[str, SbxExecRecord] = {}
    for spec in evidence.probe_specs:
        if spec.target in specs:
            raise ValueError("duplicate protected probe spec")
        specs[spec.target] = spec
    for observation in evidence.probe_observations:
        if observation.target in observations:
            raise ValueError("duplicate protected probe observation")
        observations[observation.target] = observation
    for execution_record in evidence.execution_records:
        if execution_record.sha256 in records:
            raise ValueError("duplicate protected probe execution record")
        records[execution_record.sha256] = execution_record
    if set(specs) != set(expected_targets) or set(observations) != set(
        expected_targets
    ):
        raise ValueError("protected target coverage is incomplete")
    if tuple(spec.target for spec in evidence.probe_specs) != expected_targets:
        raise ValueError("protected probe specs are not in canonical order")
    if tuple(item.target for item in evidence.probe_observations) != expected_targets:
        raise ValueError("protected probe observations are not in canonical order")
    mount_observations = tuple(
        (observation, observation.source_mount_observation)
        for observation in evidence.probe_observations
        if observation.source_mount_observation is not None
    )
    if len(mount_observations) != 1:
        raise ValueError("source mount evidence must be unique")
    mount_owner, source_mount = mount_observations[0]
    if source_mount is None or mount_owner.target is not ProtectedTarget.HOST_CANARY:
        raise ValueError("source mount evidence must belong to host-canary")
    for target in expected_targets:
        spec = specs[target]
        observation = observations[target]
        source_mount_observation = observation.source_mount_observation
        if target is ProtectedTarget.HOST_CANARY:
            if (
                source_mount_observation is None
                or observation.source_mount_observation_sha256
                != source_mount_observation.sha256
            ):
                raise ValueError(
                    "source mount object and digest must belong to host-canary"
                )
        elif (
            source_mount_observation is not None
            or observation.source_mount_observation_sha256 is not None
        ):
            raise ValueError(
                "source mount object and digest are forbidden outside host-canary"
            )
        record = records.get(observation.execution_record_sha256)
        if record is None:
            raise ValueError("probe observation has no executor record")
        expected_action = PROTECTED_PROBE_ACTION_IDS[target]
        expected_command_digest = evidence.command_spec_digests[target]
        if (
            spec.probe_path != PROTECTED_PROBE_PATHS[target]
            or spec.action_id != expected_action
            or spec.command_spec_digest != expected_command_digest
            or spec.action_registry_sha256 != evidence.action_registry_sha256
        ):
            raise ValueError("protected probe spec is not registry-bound")
        if (
            observation.probe_path != spec.probe_path
            or observation.spec_sha256 != spec.sha256
            or observation.microvm_id != agent.microvm_id
            or observation.action_id != spec.action_id
            or observation.command_spec_digest != spec.command_spec_digest
        ):
            raise ValueError("protected probe observation is not spec-bound")
        if (
            record.target != target.value
            or record.probe_path != observation.probe_path
            or record.microvm_id != agent.microvm_id
            or record.action_id != observation.action_id
            or record.command_spec_digest != observation.command_spec_digest
            or record.action_registry_sha256 != evidence.action_registry_sha256
            or record.result_digest != observation.result_digest
            or record.observed_errno != observation.observed_errno
            or not record.read_only
        ):
            raise ValueError("protected probe observation is not executor-bound")
        if observation.observed_errno not in {errno.ENOENT, errno.EACCES}:
            raise ValueError("protected target was not proven inaccessible")
    host_record = records.get(source_mount.execution_record_sha256)
    if (
        host_record is None
        or source_mount.sandbox != agent
        or source_mount.mount_path != PurePosixPath("/run/sandbox/source")
        or source_mount.git_top_level != PurePosixPath("/run/sandbox/source")
        or not source_mount.read_only
        or mount_owner.execution_record_sha256 != source_mount.execution_record_sha256
        or host_record.target != ProtectedTarget.HOST_CANARY.value
        or host_record.result_digest
        != sha256(
            _host_canary_result_payload(
                target=mount_owner.target,
                observed_errno=mount_owner.observed_errno,
                source_mount=source_mount,
            )
        ).hexdigest()
    ):
        raise ValueError("source mount observation is not host-canary-bound")
    if source_path_proof is not None and (
        source_mount.source_path_proof_sha256 != source_path_proof.sha256
        or source_mount.git_commit != source_path_proof.git_commit
        or source_mount.git_tree_digest != source_path_proof.git_tree_digest
    ):
        raise ValueError("source mount observation is not source-proof-bound")


def run_protected_boundary_probes(
    *,
    agent: SandboxRef,
    action_registry: Collection[G1HostAction],
    executor: F1OracleExecutor,
    source_path_proof: SourcePathProof | None = None,
) -> ProtectedProbeEvidence:
    if not isinstance(agent, SandboxRef) or agent.role is not SandboxRole.AGENT:
        raise ValueError("protected probes require the agent microVM")
    actions, registry_sha256 = _closed_action_registry(action_registry)
    command_digests: dict[ProtectedTarget, str] = {}
    specs: list[ProtectedProbeSpec] = []
    observations: list[ProtectedProbeObservation] = []
    records: list[SbxExecRecord] = []
    for target in PROTECTED_PROBE_ORDER:
        action = actions[PROTECTED_PROBE_ACTION_IDS[target]]
        command_digest = approval.command_spec_sha256(action.command)
        spec = ProtectedProbeSpec(
            target=target,
            probe_path=PROTECTED_PROBE_PATHS[target],
            action_id=action.action_id,
            command_spec_digest=command_digest,
            action_registry_sha256=registry_sha256,
        )
        execution = executor.execute(
            action=action,
            action_registry_sha256=registry_sha256,
            spec=spec,
            sandbox=agent,
        )
        if not isinstance(execution, tuple) or len(execution) != 2:
            raise TypeError("executor must return probe record and mount facts")
        record, source_mount_observation = execution
        if not isinstance(record, SbxExecRecord):
            raise TypeError("executor must return SbxExecRecord probe facts")
        if source_mount_observation is not None and not isinstance(
            source_mount_observation,
            SourceMountObservation,
        ):
            raise TypeError("executor returned invalid source mount facts")
        observation = ProtectedProbeObservation(
            target=target,
            probe_path=record.probe_path,
            spec_sha256=spec.sha256,
            microvm_id=record.microvm_id,
            action_id=record.action_id,
            command_spec_digest=record.command_spec_digest,
            execution_record_sha256=record.sha256,
            result_digest=record.result_digest,
            observed_errno=record.observed_errno,
            source_mount_observation=source_mount_observation,
        )
        command_digests[target] = command_digest
        specs.append(spec)
        observations.append(observation)
        records.append(record)
    evidence = ProtectedProbeEvidence(
        action_registry_sha256=registry_sha256,
        command_spec_digests=command_digests,
        probe_specs=tuple(specs),
        probe_observations=tuple(observations),
        execution_records=tuple(records),
    )
    _validate_probe_evidence(
        evidence,
        agent=agent,
        source_path_proof=source_path_proof,
    )
    return evidence


def _trace(executor: F1OracleExecutor) -> F1ExecutionTrace:
    trace = executor.execution_trace
    if not isinstance(trace, F1ExecutionTrace):
        raise TypeError("executor must expose an F1ExecutionTrace")
    return trace


def _last_trace_record(
    executor: F1OracleExecutor,
    *,
    action: G1HostAction,
    sandbox: SandboxRef,
    registry_sha256: str,
    require_success: bool = True,
    expected_result_digest: str | None = None,
) -> F1ExecutionTraceRecord:
    trace = _trace(executor)
    if not trace.records:
        raise ValueError("executor did not emit the required trace record")
    record = trace.records[-1]
    if (
        record.action_id != action.action_id
        or record.command_spec_digest != approval.command_spec_sha256(action.command)
        or record.action_registry_sha256 != registry_sha256
        or record.microvm_role is not sandbox.role
        or record.microvm_id != sandbox.microvm_id
        or (
            expected_result_digest is not None
            and record.result_digest != expected_result_digest
        )
        or (require_success and record.status is not F1ExecutionStatus.SUCCEEDED)
    ):
        raise ValueError("executor trace is not bound to the completed action")
    return record


def _validate_create_binding(
    *,
    request: SandboxCreateRequest,
    observation: SandboxCreateObservation,
    expected_role: SandboxRole,
    registry_sha256: str,
) -> None:
    if not isinstance(request, SandboxCreateRequest):
        raise TypeError("create request must be a SandboxCreateRequest")
    if not isinstance(observation, SandboxCreateObservation):
        raise TypeError("executor must return a SandboxCreateObservation")
    if (
        request.role is not expected_role
        or request.action_registry_sha256 != registry_sha256
        or observation.sandbox.role is not expected_role
        or observation.request_sha256 != request.sha256
    ):
        raise ValueError("sandbox create observation is not request-bound")


def _validate_engine_identity_binding(
    observation: OracleEngineIdentityObservation,
    *,
    oracle: SandboxRef,
    registry_sha256: str,
) -> None:
    if not isinstance(observation, OracleEngineIdentityObservation):
        raise TypeError("executor must return an OracleEngineIdentityObservation")
    if (
        observation.sandbox != oracle
        or observation.action_registry_sha256 != registry_sha256
        or observation.engine_identity_sha256
        != sha256(observation.identity_result.stdout.encode()).hexdigest()
        or not observation.identity_result.succeeded
        or observation.identity_result.truncated
    ):
        raise OracleCheckFailed("oracle engine identity observation failed")


def _validate_checker_binding(
    *,
    observation: OracleCheckerObservation,
    oracle: SandboxRef,
    container: OracleContainerSpec,
    candidate_digest: str,
    registry_sha256: str,
    docker_socket_record: SbxExecRecord,
    sealed_engine_identity_sha256: str,
) -> None:
    if not isinstance(observation, OracleCheckerObservation):
        raise TypeError("executor must return an OracleCheckerObservation")
    if (
        observation.sandbox != oracle
        or observation.sandbox.role is not SandboxRole.ORACLE
        or observation.container != container
        or observation.action_registry_sha256 != registry_sha256
        or observation.candidate_path != _CANDIDATE_PATH
        or observation.engine_identity_sha256 != sealed_engine_identity_sha256
        or not observation.private_engine
        or observation.host_engine_reachable
        or observation.shared_socket
        or observation.docker_socket_probe_path
        != PROTECTED_PROBE_PATHS[ProtectedTarget.DOCKER_SOCKET]
        or observation.docker_socket_probe_errno not in {errno.ENOENT, errno.EACCES}
        or observation.docker_socket_probe_errno != docker_socket_record.observed_errno
        or observation.agent_docker_socket_execution_record_sha256
        != docker_socket_record.sha256
    ):
        raise ValueError("oracle checker observation is not boundary-bound")
    DockerOracleRunner().verify(
        OracleVerificationFacts(
            candidate=CandidateSnapshot(
                path=observation.candidate_path,
                digest=candidate_digest,
            ),
            observed_digest_before=observation.observed_digest_before,
            checker_result=observation.checker_result,
            observed_digest_after=observation.observed_digest_after,
        )
    )


def _disk_allowed(
    *,
    disk_safety: DiskSafetyAuthority,
    role: SandboxRole,
    phase: DiskPhase,
    create_invocations: int,
    required_kib: int,
    executor: F1OracleExecutor,
) -> bool:
    decision = disk_safety.evaluate_disk_safety(
        role=role,
        phase=phase,
        create_invocations=create_invocations,
    )
    try:
        structurally_valid = (
            decision.role is role
            and decision.phase == phase
            and type(decision.available_kib) is int
            and decision.available_kib >= 0
            and decision.required_kib == required_kib
            and decision.create_invocations == create_invocations
            and type(decision.allowed) is bool
            and decision.allowed == (decision.available_kib >= required_kib)
        )
    except AttributeError as error:
        raise LiveOracleGateError(
            "disk safety authority returned incomplete facts",
            execution_trace=_trace(executor),
        ) from error
    if not structurally_valid:
        raise LiveOracleGateError(
            "disk safety authority returned misbound facts",
            execution_trace=_trace(executor),
        )
    return decision.allowed


def _destroy(
    *,
    executor: F1OracleExecutor,
    action: G1HostAction,
    registry_sha256: str,
    sandbox: SandboxRef,
    primary_error: Exception | None = None,
) -> F1ExecutionTraceRecord:
    try:
        executor.destroy(
            action=action,
            action_registry_sha256=registry_sha256,
            sandbox=sandbox,
        )
        return _last_trace_record(
            executor,
            action=action,
            sandbox=sandbox,
            registry_sha256=registry_sha256,
        )
    except Exception as cleanup_error:
        failure = OracleCleanupError(
            f"failed to destroy {sandbox.role.value} microVM",
            cleanup_reference=sandbox.microvm_id,
            execution_trace=_trace(executor),
            cleanup_error=cleanup_error,
            primary_error=primary_error,
        )
        if primary_error is not None:
            raise failure from primary_error
        raise failure from cleanup_error


def _cleanup_create_observation_error(
    *,
    executor: F1OracleExecutor,
    action: G1HostAction,
    registry_sha256: str,
    expected_role: SandboxRole,
    primary_error: SandboxCreateObservationError,
) -> None:
    sandbox = primary_error.sandbox
    if sandbox.role is not expected_role:
        raise OracleCleanupError(
            "sandbox create effect requires manual cleanup after a role mismatch",
            cleanup_reference=sandbox.microvm_id,
            execution_trace=_trace(executor),
            primary_error=primary_error,
        ) from primary_error
    _destroy(
        executor=executor,
        action=action,
        registry_sha256=registry_sha256,
        sandbox=sandbox,
        primary_error=primary_error,
    )


def _recover_sandbox_ref(
    value: object,
    *,
    expected_role: SandboxRole,
) -> SandboxRef | None:
    microvm_id = value if isinstance(value, str) else getattr(value, "microvm_id", None)
    if not isinstance(microvm_id, str):
        return None
    try:
        return SandboxRef(role=expected_role, microvm_id=microvm_id)
    except (TypeError, ValueError):
        return None


def _validate_lifecycle(facts: OracleBoundaryFacts) -> None:
    if len(facts.lifecycle) != 4:
        raise ValueError("sandbox lifecycle must contain exactly four facts")
    agent_limits = facts.lifecycle[0].limits
    expected = (
        (
            1,
            SandboxLifecycleAction.CREATE,
            facts.agent,
            _AGENT_CREATE_ACTION_ID,
            agent_limits,
            None,
            False,
        ),
        (
            2,
            SandboxLifecycleAction.FREEZE,
            facts.agent,
            _AGENT_FREEZE_ACTION_ID,
            agent_limits,
            facts.candidate_digest_before,
            False,
        ),
        (
            3,
            SandboxLifecycleAction.DESTROY,
            facts.agent,
            _AGENT_DESTROY_ACTION_ID,
            agent_limits,
            None,
            False,
        ),
        (
            4,
            SandboxLifecycleAction.CREATE,
            facts.oracle,
            _ORACLE_CREATE_ACTION_ID,
            facts.container.limits,
            None,
            True,
        ),
    )
    actions = {action.action_id: action for action in facts.action_registry}
    for record, values in zip(facts.lifecycle, expected, strict=True):
        sequence, lifecycle_action, sandbox, action_id, limits, candidate, private = (
            values
        )
        action = actions.get(action_id)
        if action is None:
            raise ValueError("lifecycle action is not registered")
        if (
            record.sequence != sequence
            or record.action is not lifecycle_action
            or record.sandbox != sandbox
            or record.action_id != action_id
            or record.command_spec_digest
            != approval.command_spec_sha256(action.command)
            or record.action_registry_sha256 != facts.action_registry_sha256
            or record.result_digest != facts.action_result_digests.get(action_id)
            or record.limits != limits
            or record.candidate_digest != candidate
            or record.private_engine is not private
        ):
            raise ValueError("sandbox lifecycle is not action-bound")
    if agent_limits.cpu_count != 2 or agent_limits.memory_mib != 2048:
        raise ValueError("agent lifecycle must use exactly 2 CPU and 2048 MiB")
    if (
        facts.container.limits.cpu_count != 2
        or facts.container.limits.memory_mib != 2048
    ):
        raise ValueError("oracle experiment must use exactly 2 CPU and 2048 MiB")


def validate_oracle_boundary(facts: OracleBoundaryFacts) -> None:
    if not isinstance(facts, OracleBoundaryFacts):
        raise TypeError("facts must be OracleBoundaryFacts")
    actions, registry_sha256 = _closed_action_registry(facts.action_registry)
    if facts.action_registry_sha256 != registry_sha256:
        raise ValueError("oracle boundary registry digest is misbound")
    if not facts.source_read_only:
        raise ValueError("agent source must be read-only")
    if facts.workspace_mode is not WorkspaceMode.PRIVATE_CLONE:
        raise ValueError("agent workspace must be a private clone")
    if facts.agent_cwd != PurePosixPath("/workspace"):
        raise ValueError("agent must work in the private clone")
    if facts.agent.role is not SandboxRole.AGENT:
        raise ValueError("agent reference has the wrong role")
    if facts.oracle.role is not SandboxRole.ORACLE:
        raise ValueError("oracle reference has the wrong role")
    if facts.agent.microvm_id == facts.oracle.microvm_id:
        raise ValueError("agent and oracle must use distinct microVMs")
    if facts.engine_shared:
        raise ValueError("agent and oracle must not share an engine")
    agent_request, oracle_request = facts.create_requests
    agent_create, oracle_create = facts.create_observations
    _validate_create_binding(
        request=agent_request,
        observation=agent_create,
        expected_role=SandboxRole.AGENT,
        registry_sha256=registry_sha256,
    )
    _validate_create_binding(
        request=oracle_request,
        observation=oracle_create,
        expected_role=SandboxRole.ORACLE,
        registry_sha256=registry_sha256,
    )
    agent_spec = agent_request.agent_spec
    if agent_spec is None:
        raise ValueError("agent create request has no SandboxSpec")
    if (
        agent_request.oracle_container is not None
        or agent_request.limits != agent_spec.limits
        or agent_request.private_engine
        or oracle_request.agent_spec is not None
        or oracle_request.oracle_container != facts.container
        or oracle_request.limits != facts.container.limits
        or not oracle_request.private_engine
        or agent_create.sandbox != facts.agent
        or oracle_create.sandbox != facts.oracle
        or not agent_create.create_result.succeeded
        or not oracle_create.create_result.succeeded
        or facts.workspace_mode is not agent_spec.workspace_mode
        or facts.agent_cwd != agent_spec.workspace_path
    ):
        raise ValueError("public create facts are not observation-derived")
    probe_evidence = ProtectedProbeEvidence(
        action_registry_sha256=facts.action_registry_sha256,
        command_spec_digests=facts.probe_command_spec_digests,
        probe_specs=facts.probe_specs,
        probe_observations=facts.probe_observations,
        execution_records=facts.execution_records,
    )
    _validate_probe_evidence(
        probe_evidence,
        agent=facts.agent,
        source_path_proof=agent_spec.source_path_proof,
    )
    source_mount = facts.probe_observations[0].source_mount_observation
    if source_mount is None or facts.source_read_only is not source_mount.read_only:
        raise ValueError("public source facts are not mount-observation-derived")
    docker_socket_records = tuple(
        record
        for record in facts.execution_records
        if record.target == ProtectedTarget.DOCKER_SOCKET.value
    )
    if len(docker_socket_records) != 1:
        raise ValueError("Docker socket execution evidence is not unique")
    engine_identity = facts.engine_identity_observation
    _validate_engine_identity_binding(
        engine_identity,
        oracle=facts.oracle,
        registry_sha256=registry_sha256,
    )
    checker = facts.checker_observation
    _validate_checker_binding(
        observation=checker,
        oracle=facts.oracle,
        container=facts.container,
        candidate_digest=facts.candidate_digest_before,
        registry_sha256=registry_sha256,
        docker_socket_record=docker_socket_records[0],
        sealed_engine_identity_sha256=engine_identity.engine_identity_sha256,
    )
    if (
        facts.container != checker.container
        or facts.candidate_digest_before != checker.observed_digest_before
        or facts.candidate_digest_after != checker.observed_digest_after
        or facts.engine_shared is not checker.shared_socket
    ):
        raise ValueError("public oracle facts are not checker-observation-derived")
    for target in PROTECTED_PROBE_ORDER:
        action_id = PROTECTED_PROBE_ACTION_IDS[target]
        action = actions[action_id]
        if facts.probe_command_spec_digests[target] != approval.command_spec_sha256(
            action.command
        ):
            raise ValueError("probe command digest is not registry-bound")
    _validate_lifecycle(facts)
    expected_action_ids = (
        _AGENT_CREATE_ACTION_ID,
        *(PROTECTED_PROBE_ACTION_IDS[target] for target in PROTECTED_PROBE_ORDER),
        _AGENT_FREEZE_ACTION_ID,
        _AGENT_DESTROY_ACTION_ID,
        _ORACLE_CREATE_ACTION_ID,
        _ORACLE_ENGINE_IDENTITY_ACTION_ID,
        _ORACLE_CHECKER_ACTION_ID,
        _ORACLE_DESTROY_ACTION_ID,
    )
    if set(facts.action_result_digests) != set(expected_action_ids):
        raise ValueError("execution result digest coverage is incomplete")
    probe_records_by_action = {
        record.action_id: record for record in facts.execution_records
    }
    for target in PROTECTED_PROBE_ORDER:
        action_id = PROTECTED_PROBE_ACTION_IDS[target]
        if (
            action_id not in probe_records_by_action
            or facts.action_result_digests[action_id]
            != probe_records_by_action[action_id].result_digest
        ):
            raise ValueError("probe trace result digest is not executor-bound")
    if (
        facts.action_result_digests[_AGENT_CREATE_ACTION_ID] != agent_create.sha256
        or facts.action_result_digests[_ORACLE_CREATE_ACTION_ID] != oracle_create.sha256
        or facts.action_result_digests[_ORACLE_ENGINE_IDENTITY_ACTION_ID]
        != engine_identity.sha256
        or facts.action_result_digests[_ORACLE_CHECKER_ACTION_ID] != checker.sha256
    ):
        raise ValueError("create or checker trace digest is observation-misbound")
    expected_sandboxes = (
        *([facts.agent] * (len(PROTECTED_PROBE_ORDER) + 3)),
        *([facts.oracle] * 4),
    )
    validate_f1_trace_bindings(
        facts.execution_trace,
        expected_action_ids=expected_action_ids,
        action_registry=facts.action_registry,
        expected_sandboxes=expected_sandboxes,
        expected_result_digests=tuple(
            facts.action_result_digests[action_id] for action_id in expected_action_ids
        ),
        require_success=True,
    )


def _lifecycle_record(
    *,
    sequence: int,
    lifecycle_action: SandboxLifecycleAction,
    sandbox: SandboxRef,
    action: G1HostAction,
    registry_sha256: str,
    trace_record: F1ExecutionTraceRecord,
    limits: ResourceLimits,
    candidate_digest: str | None = None,
    private_engine: bool = False,
) -> SandboxLifecycleRecord:
    return SandboxLifecycleRecord(
        sequence=sequence,
        action=lifecycle_action,
        sandbox=sandbox,
        action_id=action.action_id,
        command_spec_digest=approval.command_spec_sha256(action.command),
        action_registry_sha256=registry_sha256,
        result_digest=trace_record.result_digest,
        limits=limits,
        candidate_digest=candidate_digest,
        private_engine=private_engine,
    )


def run_f1_oracle_sequence(
    *,
    gate: LiveOracleGateFacts,
    agent_spec: SandboxSpec,
    oracle_container: OracleContainerSpec,
    candidate_digest: str,
    action_registry: Collection[G1HostAction],
    disk_safety: DiskSafetyAuthority,
    executor: F1OracleExecutor,
) -> OracleBoundaryFacts:
    validate_live_oracle_gate(gate=gate)
    if not isinstance(agent_spec, SandboxSpec):
        raise TypeError("agent_spec must be a SandboxSpec")
    if not isinstance(oracle_container, OracleContainerSpec):
        raise TypeError("oracle_container must be an OracleContainerSpec")
    _require_tree_digest(candidate_digest, field_name="candidate_digest")
    if candidate_digest in {
        agent_spec.source_digest,
        agent_spec.approved_source_digest,
    }:
        raise ValueError("candidate digest must be distinct from source identity")
    actions, registry_sha256 = _closed_action_registry(action_registry)
    if registry_sha256 != gate.action_registry_sha256:
        raise LiveOracleGateError("action registry does not match the G1 receipt")
    if (
        agent_spec.source_path_proof.action_registry_sha256 != registry_sha256
        or agent_spec.source_resolution_record.action_registry_sha256 != registry_sha256
    ):
        raise ValueError("source proof is not bound to the G1 action registry")
    if (
        oracle_container.limits.cpu_count != 2
        or oracle_container.limits.memory_mib != 2048
    ):
        raise ValueError("oracle must use exactly 2 CPU and 2048 MiB")

    pre_create_min = gate.preflight.disk.pre_create_min_kib
    post_create_min = gate.preflight.disk.post_create_min_kib
    create_invocations = gate.preflight.create_invocations
    if not _disk_allowed(
        disk_safety=disk_safety,
        role=SandboxRole.AGENT,
        phase="pre_create",
        create_invocations=create_invocations,
        required_kib=pre_create_min,
        executor=executor,
    ):
        raise LiveOracleGateError(
            "insufficient disk before agent create",
            execution_trace=_trace(executor),
        )
    agent_create_action = actions[_AGENT_CREATE_ACTION_ID]
    agent_create_request = SandboxCreateRequest(
        role=SandboxRole.AGENT,
        action_registry_sha256=registry_sha256,
        limits=agent_spec.limits,
        private_engine=False,
        agent_spec=agent_spec,
        oracle_container=None,
    )
    try:
        agent_create_observation = executor.create(
            action=agent_create_action,
            action_registry_sha256=registry_sha256,
            request=agent_create_request,
        )
    except SandboxCreateObservationError as primary_error:
        _cleanup_create_observation_error(
            executor=executor,
            action=actions[_AGENT_DESTROY_ACTION_ID],
            registry_sha256=registry_sha256,
            expected_role=SandboxRole.AGENT,
            primary_error=primary_error,
        )
        raise
    agent_cleanup_ref = _recover_sandbox_ref(
        getattr(agent_create_observation, "sandbox", None),
        expected_role=SandboxRole.AGENT,
    )
    try:
        if not isinstance(agent_create_observation, SandboxCreateObservation):
            raise TypeError("executor must return a SandboxCreateObservation")
        agent = agent_create_observation.sandbox
        _validate_create_binding(
            request=agent_create_request,
            observation=agent_create_observation,
            expected_role=SandboxRole.AGENT,
            registry_sha256=registry_sha256,
        )
        agent_create_trace = _last_trace_record(
            executor,
            action=agent_create_action,
            sandbox=agent,
            registry_sha256=registry_sha256,
            require_success=False,
            expected_result_digest=agent_create_observation.sha256,
        )
        if agent_create_trace.status is not (
            F1ExecutionStatus.SUCCEEDED
            if agent_create_observation.create_result.succeeded
            else F1ExecutionStatus.FAILED
        ):
            raise ValueError("agent create trace status is observation-misbound")
        if not agent_create_observation.create_result.succeeded:
            raise SandboxUnavailable("agent sandbox create failed closed")
        create_invocations += 1
        if not _disk_allowed(
            disk_safety=disk_safety,
            role=SandboxRole.AGENT,
            phase="post_create",
            create_invocations=create_invocations,
            required_kib=post_create_min,
            executor=executor,
        ):
            raise LiveOracleGateError(
                "insufficient disk after agent create",
                execution_trace=_trace(executor),
            )
        probe_evidence = run_protected_boundary_probes(
            agent=agent,
            action_registry=action_registry,
            executor=executor,
            source_path_proof=agent_spec.source_path_proof,
        )
        freeze_action = actions[_AGENT_FREEZE_ACTION_ID]
        frozen_digest = executor.freeze(
            action=freeze_action,
            action_registry_sha256=registry_sha256,
            sandbox=agent,
            candidate_digest=candidate_digest,
        )
        freeze_trace = _last_trace_record(
            executor,
            action=freeze_action,
            sandbox=agent,
            registry_sha256=registry_sha256,
        )
        if frozen_digest != candidate_digest:
            raise CandidateMutationError("freeze returned a different candidate digest")
    except Exception as primary_error:
        if agent_cleanup_ref is not None:
            _destroy(
                executor=executor,
                action=actions[_AGENT_DESTROY_ACTION_ID],
                registry_sha256=registry_sha256,
                sandbox=agent_cleanup_ref,
                primary_error=primary_error,
            )
        if isinstance(primary_error, LiveOracleGateError):
            primary_error.execution_trace = _trace(executor)
        raise

    agent_destroy_action = actions[_AGENT_DESTROY_ACTION_ID]
    agent_destroy_trace = _destroy(
        executor=executor,
        action=agent_destroy_action,
        registry_sha256=registry_sha256,
        sandbox=agent,
    )

    if not _disk_allowed(
        disk_safety=disk_safety,
        role=SandboxRole.ORACLE,
        phase="pre_create",
        create_invocations=create_invocations,
        required_kib=pre_create_min,
        executor=executor,
    ):
        raise LiveOracleGateError(
            "insufficient disk before oracle create",
            execution_trace=_trace(executor),
        )
    oracle_create_action = actions[_ORACLE_CREATE_ACTION_ID]
    oracle_create_request = SandboxCreateRequest(
        role=SandboxRole.ORACLE,
        action_registry_sha256=registry_sha256,
        limits=oracle_container.limits,
        private_engine=True,
        agent_spec=None,
        oracle_container=oracle_container,
    )
    try:
        oracle_create_observation = executor.create(
            action=oracle_create_action,
            action_registry_sha256=registry_sha256,
            request=oracle_create_request,
        )
    except SandboxCreateObservationError as primary_error:
        _cleanup_create_observation_error(
            executor=executor,
            action=actions[_ORACLE_DESTROY_ACTION_ID],
            registry_sha256=registry_sha256,
            expected_role=SandboxRole.ORACLE,
            primary_error=primary_error,
        )
        raise
    oracle_cleanup_ref = _recover_sandbox_ref(
        getattr(oracle_create_observation, "sandbox", None),
        expected_role=SandboxRole.ORACLE,
    )
    try:
        if not isinstance(oracle_create_observation, SandboxCreateObservation):
            raise TypeError("executor must return a SandboxCreateObservation")
        oracle = oracle_create_observation.sandbox
        _validate_create_binding(
            request=oracle_create_request,
            observation=oracle_create_observation,
            expected_role=SandboxRole.ORACLE,
            registry_sha256=registry_sha256,
        )
        if oracle.microvm_id == agent.microvm_id:
            raise ValueError("executor reused the agent microVM for the oracle")
        oracle_create_trace = _last_trace_record(
            executor,
            action=oracle_create_action,
            sandbox=oracle,
            registry_sha256=registry_sha256,
            require_success=False,
            expected_result_digest=oracle_create_observation.sha256,
        )
        if oracle_create_trace.status is not (
            F1ExecutionStatus.SUCCEEDED
            if oracle_create_observation.create_result.succeeded
            else F1ExecutionStatus.FAILED
        ):
            raise ValueError("oracle create trace status is observation-misbound")
        if not oracle_create_observation.create_result.succeeded:
            raise SandboxUnavailable("oracle sandbox create failed closed")
        create_invocations += 1
        if not _disk_allowed(
            disk_safety=disk_safety,
            role=SandboxRole.ORACLE,
            phase="post_create",
            create_invocations=create_invocations,
            required_kib=post_create_min,
            executor=executor,
        ):
            raise LiveOracleGateError(
                "insufficient disk after oracle create",
                execution_trace=_trace(executor),
            )
        engine_identity_action = actions[_ORACLE_ENGINE_IDENTITY_ACTION_ID]
        engine_identity_observation = executor.engine_identity(
            action=engine_identity_action,
            action_registry_sha256=registry_sha256,
            sandbox=oracle,
        )
        if not isinstance(
            engine_identity_observation,
            OracleEngineIdentityObservation,
        ):
            raise TypeError("executor must return an OracleEngineIdentityObservation")
        engine_identity_trace = _last_trace_record(
            executor,
            action=engine_identity_action,
            sandbox=oracle,
            registry_sha256=registry_sha256,
            require_success=False,
            expected_result_digest=engine_identity_observation.sha256,
        )
        if engine_identity_trace.status is not (
            F1ExecutionStatus.SUCCEEDED
            if engine_identity_observation.identity_result.succeeded
            else F1ExecutionStatus.FAILED
        ):
            raise ValueError("engine identity trace status is observation-misbound")
        _validate_engine_identity_binding(
            engine_identity_observation,
            oracle=oracle,
            registry_sha256=registry_sha256,
        )
        checker_observation = executor.checker(
            action=actions[_ORACLE_CHECKER_ACTION_ID],
            action_registry_sha256=registry_sha256,
            sandbox=oracle,
            container=oracle_container,
            candidate_digest=candidate_digest,
        )
        if not isinstance(checker_observation, OracleCheckerObservation):
            raise TypeError("executor must return an OracleCheckerObservation")
        checker_trace = _last_trace_record(
            executor,
            action=actions[_ORACLE_CHECKER_ACTION_ID],
            sandbox=oracle,
            registry_sha256=registry_sha256,
            require_success=False,
            expected_result_digest=checker_observation.sha256,
        )
        if checker_trace.status is not (
            F1ExecutionStatus.SUCCEEDED
            if checker_observation.checker_result.succeeded
            else F1ExecutionStatus.FAILED
        ):
            raise ValueError("checker trace status is observation-misbound")
        docker_socket_record = next(
            record
            for record in probe_evidence.execution_records
            if record.target == ProtectedTarget.DOCKER_SOCKET.value
        )
        _validate_checker_binding(
            observation=checker_observation,
            oracle=oracle,
            container=oracle_container,
            candidate_digest=candidate_digest,
            registry_sha256=registry_sha256,
            docker_socket_record=docker_socket_record,
            sealed_engine_identity_sha256=(
                engine_identity_observation.engine_identity_sha256
            ),
        )
    except Exception as primary_error:
        if oracle_cleanup_ref is not None:
            _destroy(
                executor=executor,
                action=actions[_ORACLE_DESTROY_ACTION_ID],
                registry_sha256=registry_sha256,
                sandbox=oracle_cleanup_ref,
                primary_error=primary_error,
            )
        if isinstance(primary_error, LiveOracleGateError):
            primary_error.execution_trace = _trace(executor)
        raise

    _destroy(
        executor=executor,
        action=actions[_ORACLE_DESTROY_ACTION_ID],
        registry_sha256=registry_sha256,
        sandbox=oracle,
    )

    execution_trace = _trace(executor)
    result_digests = {
        record.action_id: record.result_digest for record in execution_trace.records
    }
    lifecycle = (
        _lifecycle_record(
            sequence=1,
            lifecycle_action=SandboxLifecycleAction.CREATE,
            sandbox=agent,
            action=agent_create_action,
            registry_sha256=registry_sha256,
            trace_record=agent_create_trace,
            limits=agent_spec.limits,
        ),
        _lifecycle_record(
            sequence=2,
            lifecycle_action=SandboxLifecycleAction.FREEZE,
            sandbox=agent,
            action=freeze_action,
            registry_sha256=registry_sha256,
            trace_record=freeze_trace,
            limits=agent_spec.limits,
            candidate_digest=candidate_digest,
        ),
        _lifecycle_record(
            sequence=3,
            lifecycle_action=SandboxLifecycleAction.DESTROY,
            sandbox=agent,
            action=agent_destroy_action,
            registry_sha256=registry_sha256,
            trace_record=agent_destroy_trace,
            limits=agent_spec.limits,
        ),
        _lifecycle_record(
            sequence=4,
            lifecycle_action=SandboxLifecycleAction.CREATE,
            sandbox=oracle,
            action=oracle_create_action,
            registry_sha256=registry_sha256,
            trace_record=oracle_create_trace,
            limits=oracle_container.limits,
            private_engine=True,
        ),
    )
    observed_agent_spec = agent_create_request.agent_spec
    if observed_agent_spec is None:
        raise ValueError("agent create request lost its SandboxSpec binding")
    source_mount_observation = probe_evidence.probe_observations[
        0
    ].source_mount_observation
    if source_mount_observation is None:
        raise ValueError("host-canary lost its source mount observation")
    facts = OracleBoundaryFacts(
        source_read_only=source_mount_observation.read_only,
        workspace_mode=observed_agent_spec.workspace_mode,
        agent_cwd=observed_agent_spec.workspace_path,
        action_registry_sha256=registry_sha256,
        action_registry=frozenset(action_registry),
        create_requests=(agent_create_request, oracle_create_request),
        create_observations=(
            agent_create_observation,
            oracle_create_observation,
        ),
        engine_identity_observation=engine_identity_observation,
        checker_observation=checker_observation,
        action_result_digests=result_digests,
        probe_command_spec_digests=probe_evidence.command_spec_digests,
        probe_specs=probe_evidence.probe_specs,
        probe_observations=probe_evidence.probe_observations,
        execution_records=probe_evidence.execution_records,
        lifecycle=lifecycle,
        execution_trace=execution_trace,
        agent=agent_create_observation.sandbox,
        oracle=checker_observation.sandbox,
        engine_shared=checker_observation.shared_socket,
        container=checker_observation.container,
        candidate_digest_before=checker_observation.observed_digest_before,
        candidate_digest_after=checker_observation.observed_digest_after,
    )
    validate_oracle_boundary(facts)
    return facts


def run_live_oracle_boundary_probe() -> NoReturn:
    raise LiveOracleGateError(
        "live oracle adapter is unavailable until the audited iMac gate is materialized"
    )
