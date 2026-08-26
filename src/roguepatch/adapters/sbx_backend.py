from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass
from enum import StrEnum, unique
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import ClassVar, Protocol

from roguepatch.approval import (
    CanonicalRecord,
    G1HostAction,
    action_registry_sha256,
    command_spec_sha256,
    validate_g1_action_registry,
)
from roguepatch.evidence import canonical_json
from roguepatch.ports import CommandProbe, CommandResult

APPROVED_LAB_ROOT = Path("/Users/alex/RoguePatchLab")
APPROVED_SOURCE_REPOSITORY = (
    APPROVED_LAB_ROOT / ".roguepatch" / "public-fixtures" / "rp-001"
)
SBX_EXECUTABLE_ALLOWLIST = frozenset({"sbx"})
F1_TRACE_GENESIS_SHA256 = sha256(
    b"roguepatch.f1-execution-trace.v1:genesis"
).hexdigest()

_SOURCE_TARGET = PurePosixPath("/run/sandbox/source")
_PRIVATE_WORKSPACE = PurePosixPath("/workspace")
_SOURCE_RESOLUTION_ACTION_ID = "g1.source.resolve"
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_TREE_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GIT_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")


def _canonicalize(payload: object) -> bytes:
    return canonical_json(payload)


def _require_sha256(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a full lowercase SHA-256")
    return value


def _require_tree_digest(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or _TREE_DIGEST_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a sha256-prefixed tree digest")
    return value


def _require_git_commit(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or _GIT_COMMIT_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a full lowercase Git commit")
    return value


def _require_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value or "\x00" in value:
        raise ValueError(f"{field_name} must be non-empty and contain no NUL")
    return value


def _require_path(value: object, *, field_name: str) -> Path:
    if not isinstance(value, Path):
        raise TypeError(f"{field_name} must be a Path")
    if "\x00" in str(value):
        raise ValueError(f"{field_name} must contain no NUL")
    return value


def _require_posix_path(value: object, *, field_name: str) -> PurePosixPath:
    if not isinstance(value, PurePosixPath):
        raise TypeError(f"{field_name} must be a PurePosixPath")
    if not value.is_absolute() or "\x00" in str(value):
        raise ValueError(f"{field_name} must be an absolute POSIX path without NUL")
    return value


def _require_bool(value: object, *, field_name: str) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{field_name} must be a bool")
    return value


def _require_positive_int(value: object, *, field_name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} must be an int")
    if value <= 0:
        raise ValueError(f"{field_name} must be positive")
    return value


@unique
class SandboxRole(StrEnum):
    AGENT = "agent"
    ORACLE = "oracle"


@unique
class WorkspaceMode(StrEnum):
    PRIVATE_CLONE = "private_clone"


@unique
class NetworkMode(StrEnum):
    NONE = "none"


@unique
class SandboxLifecycleAction(StrEnum):
    CREATE = "create"
    FREEZE = "freeze"
    DESTROY = "destroy"


@unique
class F1ExecutionStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@unique
class BatchDisposition(StrEnum):
    KILL = "kill"


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    cpu_count: int
    memory_mib: int
    max_output_bytes: int

    def __post_init__(self) -> None:
        _require_positive_int(self.cpu_count, field_name="cpu_count")
        _require_positive_int(self.memory_mib, field_name="memory_mib")
        _require_positive_int(self.max_output_bytes, field_name="max_output_bytes")
        if self.max_output_bytes > 1_048_576:
            raise ValueError("max_output_bytes exceeds the closed capture limit")


@dataclass(frozen=True, slots=True)
class SandboxRef:
    role: SandboxRole
    microvm_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.role, SandboxRole):
            raise TypeError("role must be a SandboxRole")
        _require_text(self.microvm_id, field_name="microvm_id")


@dataclass(frozen=True, slots=True)
class HostMount:
    source: Path
    target: PurePosixPath
    read_only: bool

    def __post_init__(self) -> None:
        source = _require_path(self.source, field_name="source")
        if not source.is_absolute():
            raise ValueError("source must be absolute")
        _require_posix_path(self.target, field_name="target")
        _require_bool(self.read_only, field_name="read_only")


@dataclass(frozen=True, slots=True)
class SourcePathResolutionRecord(CanonicalRecord):
    requested_path: Path
    source_realpath: Path
    git_top_level: Path
    git_commit: str
    git_tree_digest: str
    lab_realpath: Path
    exists: bool
    contains_parent_reference: bool
    symlink_components: tuple[Path, ...]
    repository_clean: bool
    remote_names: tuple[str, ...]
    reserved_entries: tuple[Path, ...]
    fixture_parent_ignored: bool
    parent_checkout_clean: bool
    action_id: str
    command_spec_digest: str
    action_registry_sha256: str
    result_digest: str
    read_only: bool

    schema_version: ClassVar[str] = "roguepatch.source-path-resolution-record.v1"

    def __post_init__(self) -> None:
        _require_path(self.requested_path, field_name="requested_path")
        _require_path(self.source_realpath, field_name="source_realpath")
        _require_path(self.git_top_level, field_name="git_top_level")
        _require_git_commit(self.git_commit, field_name="git_commit")
        _require_tree_digest(self.git_tree_digest, field_name="git_tree_digest")
        _require_path(self.lab_realpath, field_name="lab_realpath")
        _require_bool(self.exists, field_name="exists")
        _require_bool(
            self.contains_parent_reference,
            field_name="contains_parent_reference",
        )
        if not isinstance(self.symlink_components, tuple):
            raise TypeError("symlink_components must be a tuple")
        for component in self.symlink_components:
            path = _require_path(component, field_name="symlink component")
            if not path.is_absolute():
                raise ValueError("symlink components must be absolute")
        _require_bool(self.repository_clean, field_name="repository_clean")
        if not isinstance(self.remote_names, tuple):
            raise TypeError("remote_names must be a tuple")
        for remote_name in self.remote_names:
            _require_text(remote_name, field_name="remote name")
        if not isinstance(self.reserved_entries, tuple):
            raise TypeError("reserved_entries must be a tuple")
        for reserved_entry in self.reserved_entries:
            path = _require_path(reserved_entry, field_name="reserved entry")
            if not path.is_absolute():
                raise ValueError("reserved entries must be absolute")
        _require_bool(
            self.fixture_parent_ignored,
            field_name="fixture_parent_ignored",
        )
        _require_bool(
            self.parent_checkout_clean,
            field_name="parent_checkout_clean",
        )
        _require_text(self.action_id, field_name="action_id")
        _require_sha256(self.command_spec_digest, field_name="command_spec_digest")
        _require_sha256(
            self.action_registry_sha256,
            field_name="action_registry_sha256",
        )
        _require_sha256(self.result_digest, field_name="result_digest")
        _require_bool(self.read_only, field_name="read_only")

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "requested_path": str(self.requested_path),
            "source_realpath": str(self.source_realpath),
            "git_top_level": str(self.git_top_level),
            "git_commit": self.git_commit,
            "git_tree_digest": self.git_tree_digest,
            "lab_realpath": str(self.lab_realpath),
            "exists": self.exists,
            "contains_parent_reference": self.contains_parent_reference,
            "symlink_components": [str(path) for path in self.symlink_components],
            "repository_clean": self.repository_clean,
            "remote_names": list(self.remote_names),
            "reserved_entries": [str(path) for path in self.reserved_entries],
            "fixture_parent_ignored": self.fixture_parent_ignored,
            "parent_checkout_clean": self.parent_checkout_clean,
            "action_id": self.action_id,
            "command_spec_digest": self.command_spec_digest,
            "action_registry_sha256": self.action_registry_sha256,
            "result_digest": self.result_digest,
            "read_only": self.read_only,
        }


@dataclass(frozen=True, slots=True)
class SourcePathProof(CanonicalRecord):
    requested_path: Path
    source_realpath: Path
    git_top_level: Path
    git_commit: str
    git_tree_digest: str
    lab_realpath: Path
    exists: bool
    contains_parent_reference: bool
    symlink_components: tuple[Path, ...]
    repository_clean: bool
    remote_names: tuple[str, ...]
    reserved_entries: tuple[Path, ...]
    fixture_parent_ignored: bool
    parent_checkout_clean: bool
    action_id: str
    command_spec_digest: str
    action_registry_sha256: str
    result_digest: str
    read_only: bool
    execution_record_sha256: str

    schema_version: ClassVar[str] = "roguepatch.source-path-proof.v1"

    def __post_init__(self) -> None:
        SourcePathResolutionRecord(
            requested_path=self.requested_path,
            source_realpath=self.source_realpath,
            git_top_level=self.git_top_level,
            git_commit=self.git_commit,
            git_tree_digest=self.git_tree_digest,
            lab_realpath=self.lab_realpath,
            exists=self.exists,
            contains_parent_reference=self.contains_parent_reference,
            symlink_components=self.symlink_components,
            repository_clean=self.repository_clean,
            remote_names=self.remote_names,
            reserved_entries=self.reserved_entries,
            fixture_parent_ignored=self.fixture_parent_ignored,
            parent_checkout_clean=self.parent_checkout_clean,
            action_id=self.action_id,
            command_spec_digest=self.command_spec_digest,
            action_registry_sha256=self.action_registry_sha256,
            result_digest=self.result_digest,
            read_only=self.read_only,
        )
        _require_sha256(
            self.execution_record_sha256,
            field_name="execution_record_sha256",
        )

    def _payload(self) -> dict[str, object]:
        payload = SourcePathResolutionRecord(
            requested_path=self.requested_path,
            source_realpath=self.source_realpath,
            git_top_level=self.git_top_level,
            git_commit=self.git_commit,
            git_tree_digest=self.git_tree_digest,
            lab_realpath=self.lab_realpath,
            exists=self.exists,
            contains_parent_reference=self.contains_parent_reference,
            symlink_components=self.symlink_components,
            repository_clean=self.repository_clean,
            remote_names=self.remote_names,
            reserved_entries=self.reserved_entries,
            fixture_parent_ignored=self.fixture_parent_ignored,
            parent_checkout_clean=self.parent_checkout_clean,
            action_id=self.action_id,
            command_spec_digest=self.command_spec_digest,
            action_registry_sha256=self.action_registry_sha256,
            result_digest=self.result_digest,
            read_only=self.read_only,
        )._payload()
        payload["schema_version"] = self.schema_version
        payload["execution_record_sha256"] = self.execution_record_sha256
        return payload


class SourcePathResolver(Protocol):
    def resolve(self, requested_path: Path) -> SourcePathResolutionRecord: ...


def _validate_source_resolution(record: SourcePathResolutionRecord) -> None:
    if not record.requested_path.is_absolute():
        raise ValueError("requested source path must be absolute")
    lexical_parent_reference = ".." in record.requested_path.parts
    if record.contains_parent_reference or lexical_parent_reference:
        raise ValueError("requested source path must not contain parent traversal")
    if not record.exists:
        raise ValueError("requested source path must exist")
    if record.symlink_components:
        raise ValueError("requested source path must not traverse symlinks")
    if not record.read_only:
        raise ValueError("source resolver must be read-only")
    if record.lab_realpath != APPROVED_LAB_ROOT:
        raise ValueError("lab realpath is outside the approved root")
    if not record.lab_realpath.is_absolute() or ".." in record.lab_realpath.parts:
        raise ValueError("lab realpath must be canonical and absolute")
    if record.requested_path != APPROVED_SOURCE_REPOSITORY:
        raise ValueError("requested source path is not the approved public fixture")
    if not record.source_realpath.is_absolute() or ".." in record.source_realpath.parts:
        raise ValueError("source realpath must be canonical and absolute")
    if record.source_realpath != APPROVED_SOURCE_REPOSITORY:
        raise ValueError("source realpath is not the approved public fixture")
    if record.git_top_level != APPROVED_SOURCE_REPOSITORY:
        raise ValueError("source must be an independent Git root")
    if not record.repository_clean:
        raise ValueError("public fixture repository must be clean")
    if record.remote_names:
        raise ValueError("public fixture repository must have no remotes")
    if record.reserved_entries:
        raise ValueError("public fixture contains reserved entries")
    if not record.fixture_parent_ignored:
        raise ValueError("public fixture parent must be ignored")
    if not record.parent_checkout_clean:
        raise ValueError("parent checkout must remain clean")


def _closed_action_registry(
    action_registry: Collection[G1HostAction],
) -> dict[str, G1HostAction]:
    return dict(validate_g1_action_registry(action_registry).actions_by_id)


def resolve_source_path(
    *,
    requested_path: Path,
    action_registry: Collection[G1HostAction],
    resolver: SourcePathResolver,
) -> tuple[SourcePathProof, SourcePathResolutionRecord]:
    requested = _require_path(requested_path, field_name="requested_path")
    actions = _closed_action_registry(action_registry)
    record = resolver.resolve(requested)
    if not isinstance(record, SourcePathResolutionRecord):
        raise TypeError("resolver must return SourcePathResolutionRecord")
    if record.requested_path != requested:
        raise ValueError("resolution record is not bound to the requested source")
    _validate_source_resolution(record)
    if record.action_id != _SOURCE_RESOLUTION_ACTION_ID:
        raise ValueError("source resolution action is not authorized")
    registered = actions.get(record.action_id)
    if registered is None:
        raise ValueError("source resolution action is not registered")
    if record.command_spec_digest != command_spec_sha256(registered.command):
        raise ValueError("source resolution command digest is misbound")
    if record.action_registry_sha256 != action_registry_sha256(
        frozenset(action_registry)
    ):
        raise ValueError("source resolution registry digest is misbound")
    proof = SourcePathProof(
        requested_path=record.requested_path,
        source_realpath=record.source_realpath,
        git_top_level=record.git_top_level,
        git_commit=record.git_commit,
        git_tree_digest=record.git_tree_digest,
        lab_realpath=record.lab_realpath,
        exists=record.exists,
        contains_parent_reference=record.contains_parent_reference,
        symlink_components=record.symlink_components,
        repository_clean=record.repository_clean,
        remote_names=record.remote_names,
        reserved_entries=record.reserved_entries,
        fixture_parent_ignored=record.fixture_parent_ignored,
        parent_checkout_clean=record.parent_checkout_clean,
        action_id=record.action_id,
        command_spec_digest=record.command_spec_digest,
        action_registry_sha256=record.action_registry_sha256,
        result_digest=record.result_digest,
        read_only=record.read_only,
        execution_record_sha256=record.sha256,
    )
    return proof, record


def _proof_matches_record(
    proof: SourcePathProof,
    record: SourcePathResolutionRecord,
) -> bool:
    return (
        proof.requested_path == record.requested_path
        and proof.source_realpath == record.source_realpath
        and proof.git_top_level == record.git_top_level
        and proof.git_commit == record.git_commit
        and proof.git_tree_digest == record.git_tree_digest
        and proof.lab_realpath == record.lab_realpath
        and proof.exists is record.exists
        and proof.contains_parent_reference is record.contains_parent_reference
        and proof.symlink_components == record.symlink_components
        and proof.repository_clean is record.repository_clean
        and proof.remote_names == record.remote_names
        and proof.reserved_entries == record.reserved_entries
        and proof.fixture_parent_ignored is record.fixture_parent_ignored
        and proof.parent_checkout_clean is record.parent_checkout_clean
        and proof.action_id == record.action_id
        and proof.command_spec_digest == record.command_spec_digest
        and proof.action_registry_sha256 == record.action_registry_sha256
        and proof.result_digest == record.result_digest
        and proof.read_only is record.read_only
        and proof.execution_record_sha256 == record.sha256
    )


@dataclass(frozen=True, slots=True)
class SandboxSpec(CanonicalRecord):
    role: SandboxRole
    source_path_proof: SourcePathProof
    source_resolution_record: SourcePathResolutionRecord
    source_mount: HostMount
    source_digest: str
    approved_source_digest: str
    workspace_mode: WorkspaceMode
    workspace_path: PurePosixPath
    additional_host_mounts: tuple[HostMount, ...]
    docker_socket: bool
    network: NetworkMode
    shared_skill_paths: tuple[Path, ...]
    limits: ResourceLimits

    schema_version: ClassVar[str] = "roguepatch.sandbox-spec.v1"

    def __post_init__(self) -> None:
        if self.role is not SandboxRole.AGENT:
            raise ValueError("private clone spec is only valid for the agent microVM")
        if not isinstance(self.source_path_proof, SourcePathProof):
            raise TypeError("source_path_proof must be a SourcePathProof")
        if not isinstance(
            self.source_resolution_record,
            SourcePathResolutionRecord,
        ):
            raise TypeError(
                "source_resolution_record must be a SourcePathResolutionRecord"
            )
        _validate_source_resolution(self.source_resolution_record)
        if not _proof_matches_record(
            self.source_path_proof,
            self.source_resolution_record,
        ):
            raise ValueError("source proof is not bound to its execution record")
        if not isinstance(self.source_mount, HostMount):
            raise TypeError("source_mount must be a HostMount")
        if self.source_mount.source != self.source_path_proof.source_realpath:
            raise ValueError("source mount is not bound to the canonical source")
        if self.source_mount.target != _SOURCE_TARGET:
            raise ValueError("source mount must use /run/sandbox/source")
        if not self.source_mount.read_only:
            raise ValueError("source mount must be read-only")
        _require_tree_digest(self.source_digest, field_name="source_digest")
        _require_tree_digest(
            self.approved_source_digest,
            field_name="approved_source_digest",
        )
        if self.source_digest != self.approved_source_digest:
            raise ValueError("source digest does not match the approved digest")
        if self.workspace_mode is not WorkspaceMode.PRIVATE_CLONE:
            raise ValueError("workspace must be a private clone")
        _require_posix_path(self.workspace_path, field_name="workspace_path")
        if self.workspace_path != _PRIVATE_WORKSPACE:
            raise ValueError("private clone workspace must be /workspace")
        if self.workspace_path == self.source_mount.target:
            raise ValueError("writable workspace must differ from the source mount")
        if not isinstance(self.additional_host_mounts, tuple):
            raise TypeError("additional_host_mounts must be a tuple")
        if self.additional_host_mounts:
            raise ValueError("additional host mounts are forbidden")
        _require_bool(self.docker_socket, field_name="docker_socket")
        if self.docker_socket:
            raise ValueError("Docker socket is forbidden")
        if self.network is not NetworkMode.NONE:
            raise ValueError("sandbox network must be none")
        if not isinstance(self.shared_skill_paths, tuple):
            raise TypeError("shared_skill_paths must be a tuple")
        if self.shared_skill_paths:
            raise ValueError("shared skill paths are forbidden")
        if not isinstance(self.limits, ResourceLimits):
            raise TypeError("limits must be ResourceLimits")
        if self.limits.cpu_count != 2 or self.limits.memory_mib != 2048:
            raise ValueError("sandbox must use exactly 2 CPU and 2048 MiB")

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "role": self.role.value,
            "source_path_proof": self.source_path_proof._payload(),
            "source_resolution_record": self.source_resolution_record._payload(),
            "source_mount": {
                "source": str(self.source_mount.source),
                "target": str(self.source_mount.target),
                "read_only": self.source_mount.read_only,
            },
            "source_digest": self.source_digest,
            "approved_source_digest": self.approved_source_digest,
            "workspace_mode": self.workspace_mode.value,
            "workspace_path": str(self.workspace_path),
            "additional_host_mounts": [
                {
                    "source": str(mount.source),
                    "target": str(mount.target),
                    "read_only": mount.read_only,
                }
                for mount in self.additional_host_mounts
            ],
            "docker_socket": self.docker_socket,
            "network": self.network.value,
            "shared_skill_paths": [str(path) for path in self.shared_skill_paths],
            "limits": {
                "cpu_count": self.limits.cpu_count,
                "memory_mib": self.limits.memory_mib,
                "max_output_bytes": self.limits.max_output_bytes,
            },
        }

    @classmethod
    def private_clone(
        cls,
        *,
        role: SandboxRole,
        source_repository: Path,
        source_path_proof: SourcePathProof,
        source_resolution_record: SourcePathResolutionRecord,
        source_digest: str,
        approved_source_digest: str,
        limits: ResourceLimits,
    ) -> SandboxSpec:
        repository = _require_path(
            source_repository,
            field_name="source_repository",
        )
        if repository != source_path_proof.requested_path:
            raise ValueError("source repository is not bound to its path proof")
        if source_digest != source_path_proof.git_tree_digest:
            raise ValueError("source digest does not match the proven Git tree")
        return cls(
            role=role,
            source_path_proof=source_path_proof,
            source_resolution_record=source_resolution_record,
            source_mount=HostMount(
                source=source_path_proof.source_realpath,
                target=_SOURCE_TARGET,
                read_only=True,
            ),
            source_digest=source_digest,
            approved_source_digest=approved_source_digest,
            workspace_mode=WorkspaceMode.PRIVATE_CLONE,
            workspace_path=_PRIVATE_WORKSPACE,
            additional_host_mounts=(),
            docker_socket=False,
            network=NetworkMode.NONE,
            shared_skill_paths=(),
            limits=limits,
        )


@dataclass(frozen=True, slots=True)
class SbxExecRecord(CanonicalRecord):
    target: str
    probe_path: PurePosixPath
    microvm_id: str
    action_id: str
    command_spec_digest: str
    action_registry_sha256: str
    result_digest: str
    observed_errno: int
    read_only: bool

    schema_version: ClassVar[str] = "roguepatch.sbx-exec-record.v1"

    def __post_init__(self) -> None:
        _require_text(self.target, field_name="target")
        _require_posix_path(self.probe_path, field_name="probe_path")
        _require_text(self.microvm_id, field_name="microvm_id")
        _require_text(self.action_id, field_name="action_id")
        _require_sha256(self.command_spec_digest, field_name="command_spec_digest")
        _require_sha256(
            self.action_registry_sha256,
            field_name="action_registry_sha256",
        )
        _require_sha256(self.result_digest, field_name="result_digest")
        if type(self.observed_errno) is not int or self.observed_errno < 0:
            raise ValueError("observed_errno must be a non-negative int")
        _require_bool(self.read_only, field_name="read_only")

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "probe_path": str(self.probe_path),
            "microvm_id": self.microvm_id,
            "action_id": self.action_id,
            "command_spec_digest": self.command_spec_digest,
            "action_registry_sha256": self.action_registry_sha256,
            "result_digest": self.result_digest,
            "observed_errno": self.observed_errno,
            "read_only": self.read_only,
        }


@dataclass(frozen=True, slots=True)
class SandboxLifecycleRecord(CanonicalRecord):
    sequence: int
    action: SandboxLifecycleAction
    sandbox: SandboxRef
    action_id: str
    command_spec_digest: str
    action_registry_sha256: str
    result_digest: str
    limits: ResourceLimits
    candidate_digest: str | None
    private_engine: bool

    schema_version: ClassVar[str] = "roguepatch.sandbox-lifecycle-record.v1"

    def __post_init__(self) -> None:
        _require_positive_int(self.sequence, field_name="sequence")
        if not isinstance(self.action, SandboxLifecycleAction):
            raise TypeError("action must be a SandboxLifecycleAction")
        if not isinstance(self.sandbox, SandboxRef):
            raise TypeError("sandbox must be a SandboxRef")
        _require_text(self.action_id, field_name="action_id")
        _require_sha256(self.command_spec_digest, field_name="command_spec_digest")
        _require_sha256(
            self.action_registry_sha256,
            field_name="action_registry_sha256",
        )
        _require_sha256(self.result_digest, field_name="result_digest")
        if not isinstance(self.limits, ResourceLimits):
            raise TypeError("limits must be ResourceLimits")
        if self.candidate_digest is not None:
            _require_tree_digest(
                self.candidate_digest,
                field_name="candidate_digest",
            )
        _require_bool(self.private_engine, field_name="private_engine")

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "action": self.action.value,
            "sandbox": {
                "role": self.sandbox.role.value,
                "microvm_id": self.sandbox.microvm_id,
            },
            "action_id": self.action_id,
            "command_spec_digest": self.command_spec_digest,
            "action_registry_sha256": self.action_registry_sha256,
            "result_digest": self.result_digest,
            "limits": {
                "cpu_count": self.limits.cpu_count,
                "memory_mib": self.limits.memory_mib,
                "max_output_bytes": self.limits.max_output_bytes,
            },
            "candidate_digest": self.candidate_digest,
            "private_engine": self.private_engine,
        }


@dataclass(frozen=True, slots=True)
class F1ExecutionTraceRecord(CanonicalRecord):
    sequence: int
    prev_record_sha256: str
    microvm_role: SandboxRole
    microvm_id: str
    action_id: str
    command_spec_digest: str
    action_registry_sha256: str
    result_digest: str
    status: F1ExecutionStatus

    schema_version: ClassVar[str] = "roguepatch.f1-execution-trace-record.v1"

    def __post_init__(self) -> None:
        _require_positive_int(self.sequence, field_name="sequence")
        _require_sha256(
            self.prev_record_sha256,
            field_name="prev_record_sha256",
        )
        if not isinstance(self.microvm_role, SandboxRole):
            raise TypeError("microvm_role must be a SandboxRole")
        _require_text(self.microvm_id, field_name="microvm_id")
        _require_text(self.action_id, field_name="action_id")
        _require_sha256(self.command_spec_digest, field_name="command_spec_digest")
        _require_sha256(
            self.action_registry_sha256,
            field_name="action_registry_sha256",
        )
        _require_sha256(self.result_digest, field_name="result_digest")
        if not isinstance(self.status, F1ExecutionStatus):
            raise TypeError("status must be an F1ExecutionStatus")

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "prev_record_sha256": self.prev_record_sha256,
            "microvm_role": self.microvm_role.value,
            "microvm_id": self.microvm_id,
            "action_id": self.action_id,
            "command_spec_digest": self.command_spec_digest,
            "action_registry_sha256": self.action_registry_sha256,
            "result_digest": self.result_digest,
            "status": self.status.value,
        }


@dataclass(frozen=True, slots=True)
class F1ExecutionTrace(CanonicalRecord):
    records: tuple[F1ExecutionTraceRecord, ...]

    schema_version: ClassVar[str] = "roguepatch.f1-execution-trace.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.records, tuple):
            raise TypeError("records must be a tuple")
        previous_sha256 = F1_TRACE_GENESIS_SHA256
        for sequence, record in enumerate(self.records, start=1):
            if not isinstance(record, F1ExecutionTraceRecord):
                raise TypeError("trace entries must be F1ExecutionTraceRecord values")
            if record.sequence != sequence:
                raise ValueError("trace sequence must be contiguous and start at one")
            if record.prev_record_sha256 != previous_sha256:
                raise ValueError("trace hash chain is broken")
            previous_sha256 = record.sha256

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "records": [record._payload() for record in self.records],
        }


def validate_f1_trace_bindings(
    trace: F1ExecutionTrace,
    *,
    expected_action_ids: tuple[str, ...],
    action_registry: Collection[G1HostAction],
    expected_sandboxes: tuple[SandboxRef, ...],
    expected_result_digests: tuple[str, ...],
    require_success: bool,
) -> None:
    if not isinstance(trace, F1ExecutionTrace):
        raise TypeError("trace must be an F1ExecutionTrace")
    actions = _closed_action_registry(action_registry)
    record_count = len(trace.records)
    if not (
        len(expected_action_ids)
        == len(expected_sandboxes)
        == len(expected_result_digests)
        == record_count
    ):
        raise ValueError("trace binding vectors must have identical closed cardinality")
    registry_sha256 = action_registry_sha256(frozenset(action_registry))
    for record, action_id, sandbox, result_digest in zip(
        trace.records,
        expected_action_ids,
        expected_sandboxes,
        expected_result_digests,
        strict=True,
    ):
        action = actions.get(action_id)
        if action is None or record.action_id != action_id:
            raise ValueError("trace action is missing, reordered, or unregistered")
        if (
            record.command_spec_digest != command_spec_sha256(action.command)
            or record.action_registry_sha256 != registry_sha256
        ):
            raise ValueError("trace action binding is invalid")
        if (
            record.microvm_role is not sandbox.role
            or record.microvm_id != sandbox.microvm_id
        ):
            raise ValueError("trace microVM binding is invalid")
        if record.result_digest != result_digest:
            raise ValueError("trace result binding is invalid")
        if require_success and record.status is not F1ExecutionStatus.SUCCEEDED:
            raise ValueError("successful trace contains a failed action")


class SandboxUnavailable(RuntimeError):
    """The authorized SBX runtime could not perform a registered action."""


class SandboxCleanupError(RuntimeError):
    disposition: BatchDisposition
    cleanup_reference: str
    execution_trace: F1ExecutionTrace

    def __init__(
        self,
        message: str,
        *,
        cleanup_reference: str,
        execution_trace: F1ExecutionTrace,
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


class F1TraceSink(Protocol):
    @property
    def execution_trace(self) -> F1ExecutionTrace: ...

    def append(
        self,
        *,
        sandbox: SandboxRef,
        action: G1HostAction,
        action_registry_sha256: str,
        result_digest: str,
        status: F1ExecutionStatus,
    ) -> F1ExecutionTraceRecord: ...


class InMemoryF1TraceSink:
    def __init__(self) -> None:
        self._records: list[F1ExecutionTraceRecord] = []

    @property
    def execution_trace(self) -> F1ExecutionTrace:
        return F1ExecutionTrace(records=tuple(self._records))

    def append(
        self,
        *,
        sandbox: SandboxRef,
        action: G1HostAction,
        action_registry_sha256: str,
        result_digest: str,
        status: F1ExecutionStatus,
    ) -> F1ExecutionTraceRecord:
        record = F1ExecutionTraceRecord(
            sequence=len(self._records) + 1,
            prev_record_sha256=(
                self._records[-1].sha256 if self._records else F1_TRACE_GENESIS_SHA256
            ),
            microvm_role=sandbox.role,
            microvm_id=sandbox.microvm_id,
            action_id=action.action_id,
            command_spec_digest=command_spec_sha256(action.command),
            action_registry_sha256=action_registry_sha256,
            result_digest=result_digest,
            status=status,
        )
        self._records.append(record)
        return record


def command_result_sha256(result: CommandResult) -> str:
    if not isinstance(result, CommandResult):
        raise TypeError("result must be a CommandResult")
    payload = {
        "schema_version": "roguepatch.command-result.v1",
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timed_out": result.timed_out,
        "truncated": result.truncated,
    }
    return sha256(_canonicalize(payload)).hexdigest()


def _command_probe_exception_sha256(error: Exception) -> str:
    error_type = type(error)
    payload = {
        "schema_version": "roguepatch.command-probe-exception.v1",
        "exception_type": f"{error_type.__module__}.{error_type.__qualname__}",
    }
    return sha256(_canonicalize(payload)).hexdigest()


class SbxBackend:
    def __init__(
        self,
        *,
        action_registry: Collection[G1HostAction],
        trace_sink: F1TraceSink,
        command_probe: CommandProbe,
    ) -> None:
        validated_registry = validate_g1_action_registry(action_registry)
        self._actions = dict(validated_registry.actions_by_id)
        if not hasattr(trace_sink, "execution_trace") or not callable(
            getattr(trace_sink, "append", None)
        ):
            raise TypeError("trace_sink must implement F1TraceSink")
        if not callable(getattr(command_probe, "run", None)):
            raise TypeError("command_probe must implement CommandProbe")
        self._trace_sink = trace_sink
        self._command_probe = command_probe
        self._action_registry_sha256 = validated_registry.action_registry_sha256

    @property
    def execution_trace(self) -> F1ExecutionTrace:
        return self._trace_sink.execution_trace

    def execute_registered(
        self,
        *,
        action: G1HostAction,
        sandbox: SandboxRef,
    ) -> CommandResult:
        registered = self._actions.get(action.action_id)
        if registered is None or registered != action:
            raise ValueError("action is not exactly registered")
        if (
            action.command.argv[0] not in SBX_EXECUTABLE_ALLOWLIST
            or action.command.shell
        ):
            raise ValueError("host executable fallback is forbidden")
        try:
            result = self._command_probe.run(action.command)
        except Exception as error:
            self._trace_sink.append(
                sandbox=sandbox,
                action=action,
                action_registry_sha256=self._action_registry_sha256,
                result_digest=_command_probe_exception_sha256(error),
                status=F1ExecutionStatus.FAILED,
            )
            raise SandboxUnavailable("registered SBX action failed closed") from error
        result_digest = command_result_sha256(result)
        self._trace_sink.append(
            sandbox=sandbox,
            action=action,
            action_registry_sha256=self._action_registry_sha256,
            result_digest=result_digest,
            status=(
                F1ExecutionStatus.SUCCEEDED
                if result.succeeded
                else F1ExecutionStatus.FAILED
            ),
        )
        if not result.succeeded:
            raise SandboxUnavailable("registered SBX action failed closed")
        return result
