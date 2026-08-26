from __future__ import annotations

import errno
import inspect
import json
import os
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields, replace
from enum import Enum
from hashlib import sha256
from pathlib import Path, PurePath, PurePosixPath
from typing import Literal

import pytest

from roguepatch import approval
from roguepatch.adapters.docker_oracle import (
    PROTECTED_PROBE_ACTION_IDS,
    PROTECTED_PROBE_ORDER,
    PROTECTED_PROBE_PATHS,
    CandidateMutationError,
    LiveOracleGateError,
    LiveOracleGateFacts,
    OracleBoundaryFacts,
    OracleCheckerObservation,
    OracleCheckFailed,
    OracleCleanupError,
    OracleContainerSpec,
    OracleEngineIdentityObservation,
    ProtectedProbeEvidence,
    ProtectedProbeObservation,
    ProtectedProbeSpec,
    ProtectedTarget,
    SandboxCreateObservation,
    SandboxCreateRequest,
    SourceMountObservation,
    run_f1_oracle_sequence,
    run_protected_boundary_probes,
    validate_oracle_boundary,
)
from roguepatch.adapters.sbx_backend import (
    F1_TRACE_GENESIS_SHA256,
    BatchDisposition,
    F1ExecutionStatus,
    F1ExecutionTrace,
    F1ExecutionTraceRecord,
    HostMount,
    NetworkMode,
    ResourceLimits,
    SandboxLifecycleAction,
    SandboxRef,
    SandboxRole,
    SandboxSpec,
    SandboxUnavailable,
    SbxExecRecord,
    SourcePathProof,
    SourcePathResolutionRecord,
    WorkspaceMode,
    resolve_source_path,
)
from roguepatch.approval import (
    G1_ACTION_IDS,
    ApprovalBinding,
    ApprovalState,
    G1HostAction,
    G1HostBinding,
    HostIdentity,
    build_g1_action_registry,
    host_identity_sha256,
)
from roguepatch.doctor import (
    CheckFact,
    CheckState,
    DaemonIsolationFacts,
    DiskPreflightFacts,
    DoctorCheck,
    DoctorReport,
    LivePreflightFacts,
    SandboxResourceFacts,
)
from roguepatch.ports import CommandResult, CommandSpec

LAB_ROOT = Path("/Users/alex/RoguePatchLab")
SOURCE_REPOSITORY = LAB_ROOT / ".roguepatch" / "public-fixtures" / "rp-001"
SOURCE_REALPATH = SOURCE_REPOSITORY
SOURCE_DIGEST = "sha256:" + "a" * 64
CANDIDATE_DIGEST = "sha256:" + "9" * 64
OTHER_TREE_DIGEST = "sha256:" + "c" * 64
SOURCE_GIT_COMMIT = "1" * 40
OTHER_GIT_COMMIT = "2" * 40
OTHER_DIGEST = "f" * 64
ORACLE_IMAGE = "roguepatch-oracle@sha256:" + "b" * 64
OTHER_ORACLE_IMAGE = "roguepatch-oracle@sha256:" + "d" * 64
SOURCE_TARGET = PurePosixPath("/run/sandbox/source")
AGENT_WORKSPACE = PurePosixPath("/workspace")
AGENT = SandboxRef(role=SandboxRole.AGENT, microvm_id="sbx-agent-1")
ORACLE = SandboxRef(role=SandboxRole.ORACLE, microvm_id="sbx-oracle-1")
ORACLE_ENGINE_IDENTITY = "synthetic-sbx-oracle-private-engine"
OTHER_ORACLE_ENGINE_IDENTITY = "synthetic-sbx-other-private-engine"
ORACLE_ENGINE_IDENTITY_SHA256 = sha256(ORACLE_ENGINE_IDENTITY.encode()).hexdigest()
OTHER_ORACLE_ENGINE_IDENTITY_SHA256 = sha256(
    OTHER_ORACLE_ENGINE_IDENTITY.encode()
).hexdigest()
CANDIDATE_PATH = PurePosixPath("/candidate")
DOCKER_SOCKET_PATH = PurePosixPath("/var/run/docker.sock")
RESOLVER_ACTION_ID = "g1.source.resolve"
RESOLVER_RESULT_DIGEST = "e" * 64
REGISTRY_CWD = Path("/synthetic/roguepatch-live")
AGENT_CREATE_ACTION_ID = "g1.sbx.agent.create"
AGENT_FREEZE_ACTION_ID = "g1.sbx.agent.freeze"
AGENT_DESTROY_ACTION_ID = "g1.sbx.agent.destroy"
ORACLE_CREATE_ACTION_ID = "g1.sbx.oracle.create"
ORACLE_ENGINE_IDENTITY_ACTION_ID = "g1.sbx.oracle.engine-identity"
ORACLE_CHECKER_ACTION_ID = "g1.sbx.oracle.checker"
ORACLE_DESTROY_ACTION_ID = "g1.sbx.oracle.destroy"
RECEIPT_INSTALL_MIN_KIB = 41_943_040
PRE_CREATE_MIN_KIB = 31_457_280
POST_CREATE_MIN_KIB = 20_971_520
HOST_IDENTITY = HostIdentity(
    hostname="iMac-de-Alex.local",
    account="alex",
    arch="arm64",
    os_build="24G90",
    boot_session_sha256=sha256(b"synthetic-boot").hexdigest(),
)
HOST_FINGERPRINT = host_identity_sha256(HOST_IDENTITY)
CANONICAL_PROTECTED_TARGETS = (
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
TRACE_ACTION_IDS = (
    AGENT_CREATE_ACTION_ID,
    *(PROTECTED_PROBE_ACTION_IDS[target] for target in CANONICAL_PROTECTED_TARGETS),
    AGENT_FREEZE_ACTION_ID,
    AGENT_DESTROY_ACTION_ID,
    ORACLE_CREATE_ACTION_ID,
    ORACLE_ENGINE_IDENTITY_ACTION_ID,
    ORACLE_CHECKER_ACTION_ID,
    ORACLE_DESTROY_ACTION_ID,
)
AGENT_TRACE_ACTION_IDS = TRACE_ACTION_IDS[:-4]
EXPECTED_G1_ACTION_IDS = (
    RESOLVER_ACTION_ID,
    *(PROTECTED_PROBE_ACTION_IDS[target] for target in CANONICAL_PROTECTED_TARGETS),
    AGENT_CREATE_ACTION_ID,
    AGENT_FREEZE_ACTION_ID,
    AGENT_DESTROY_ACTION_ID,
    ORACLE_CREATE_ACTION_ID,
    ORACLE_ENGINE_IDENTITY_ACTION_ID,
    ORACLE_CHECKER_ACTION_ID,
    ORACLE_DESTROY_ACTION_ID,
)
MUTATING_ACTION_IDS = frozenset(
    {
        AGENT_CREATE_ACTION_ID,
        AGENT_DESTROY_ACTION_ID,
        ORACLE_CREATE_ACTION_ID,
        ORACLE_DESTROY_ACTION_ID,
    }
)
DiskPhase = Literal["pre_create", "post_create"]


@dataclass(frozen=True, slots=True)
class DiskSafetyDecision:
    role: SandboxRole
    phase: DiskPhase
    available_kib: int
    required_kib: int
    create_invocations: int
    allowed: bool


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _host_canary_result_payload(
    *,
    target: ProtectedTarget,
    observed_errno: int,
    sandbox: SandboxRef,
    mount_path: PurePosixPath,
    git_top_level: PurePosixPath,
    source_path_proof_sha256: str,
    git_commit: str,
    git_tree_digest: str,
    read_only: bool,
) -> bytes:
    payload = {
        "schema_version": "roguepatch.host-canary-result.v1",
        "target": target.value,
        "observed_errno": observed_errno,
        "source_mount": {
            "sandbox": {
                "role": sandbox.role.value,
                "microvm_id": sandbox.microvm_id,
            },
            "mount_path": str(mount_path),
            "git_top_level": str(git_top_level),
            "source_path_proof_sha256": source_path_proof_sha256,
            "git_commit": git_commit,
            "git_tree_digest": git_tree_digest,
            "read_only": read_only,
        },
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _limits() -> ResourceLimits:
    return ResourceLimits(cpu_count=2, memory_mib=2048, max_output_bytes=131_072)


def _registered_command(
    action_id: str,
    argv: tuple[str, ...] | None = None,
    *,
    mutating: bool | None = None,
) -> G1HostAction:
    return G1HostAction(
        action_id=action_id,
        command=CommandSpec(
            argv=argv or ("sbx", action_id),
            cwd=REGISTRY_CWD,
            env={"PATH": "/synthetic/bin"},
            timeout_seconds=5,
            max_output_bytes=131_072,
            mutating=(
                action_id in MUTATING_ACTION_IDS if mutating is None else mutating
            ),
        ),
    )


def _g1_action_registry() -> frozenset[G1HostAction]:
    return build_g1_action_registry(
        command_factory=lambda action_id: _registered_command(action_id).command
    )


def _registered_action(action_id: str) -> G1HostAction:
    return next(
        action for action in _g1_action_registry() if action.action_id == action_id
    )


def _registry_digest() -> str:
    return approval._action_registry_sha256(_g1_action_registry())


def _registered_command_digest(action_id: str) -> str:
    return approval._command_spec_sha256(_registered_action(action_id).command)


def _ready_doctor_report() -> DoctorReport:
    return DoctorReport(
        facts={
            check: CheckFact(check=check, state=CheckState.READY)
            for check in DoctorCheck
        }
    )


def _daemon_isolation_facts() -> DaemonIsolationFacts:
    observation_digest = _digest("oracle-engine-identity-observation")
    registry_digest = _registry_digest()
    return DaemonIsolationFacts(
        action_id=ORACLE_ENGINE_IDENTITY_ACTION_ID,
        sandbox_role=SandboxRole.ORACLE.value,
        isolation_scope="microvm",
        oracle_microvm_id=ORACLE.microvm_id,
        engine_identity_observation_sha256=observation_digest,
        engine_identity_trace_result_sha256=observation_digest,
        engine_identity_sha256=ORACLE_ENGINE_IDENTITY_SHA256,
        checker_engine_identity_sha256=ORACLE_ENGINE_IDENTITY_SHA256,
        action_registry_sha256=registry_digest,
        engine_identity_action_registry_sha256=registry_digest,
        private_engine_observed=True,
        docker_desktop_observed=False,
        host_daemon_accessible=False,
        shared_socket_observed=False,
    )


def _live_gate(*, available_kib: int = RECEIPT_INSTALL_MIN_KIB) -> LiveOracleGateFacts:
    binding = ApprovalBinding(
        gate="g1",
        spec_sha256="a" * 64,
        plan_sha256="b" * 64,
        repo_commit="d" * 40,
    )
    receipt_binding = G1HostBinding(
        approval=binding,
        host_fingerprint_sha256=HOST_FINGERPRINT,
        action_registry_sha256=_registry_digest(),
    )
    return LiveOracleGateFacts(
        host_identity=HOST_IDENTITY,
        host_fingerprint_sha256=HOST_FINGERPRINT,
        approval_state=ApprovalState.APPROVED,
        receipt_binding=receipt_binding,
        action_registry_sha256=_registry_digest(),
        doctor_report=_ready_doctor_report(),
        daemon_isolation_facts=_daemon_isolation_facts(),
        preflight=LivePreflightFacts(
            disk=DiskPreflightFacts(
                available_kib=available_kib,
                receipt_install_min_kib=RECEIPT_INSTALL_MIN_KIB,
                pre_create_min_kib=PRE_CREATE_MIN_KIB,
                post_create_min_kib=POST_CREATE_MIN_KIB,
            ),
            resources=SandboxResourceFacts(
                host_memory_mib=8192,
                sequential=True,
                vm_cpu_count=2,
                vm_memory_mib=2048,
            ),
            create_invocations=0,
        ),
    )


def _disk_availability(
    overrides: Mapping[tuple[SandboxRole, DiskPhase], int] | None = None,
) -> dict[tuple[SandboxRole, DiskPhase], int]:
    available = {
        (SandboxRole.AGENT, "pre_create"): PRE_CREATE_MIN_KIB,
        (SandboxRole.AGENT, "post_create"): POST_CREATE_MIN_KIB,
        (SandboxRole.ORACLE, "pre_create"): PRE_CREATE_MIN_KIB,
        (SandboxRole.ORACLE, "post_create"): POST_CREATE_MIN_KIB,
    }
    available.update(overrides or {})
    return available


def test_r6_g1_action_registry_is_the_exact_closed_set() -> None:
    registry = _g1_action_registry()
    payload = json.loads(approval._canonical_action_registry_payload(registry))

    assert PROTECTED_PROBE_ORDER == CANONICAL_PROTECTED_TARGETS
    assert G1_ACTION_IDS == EXPECTED_G1_ACTION_IDS
    assert len(registry) == 21
    assert {action.action_id for action in registry} == set(G1_ACTION_IDS)
    assert [action["action_id"] for action in payload["actions"]] == sorted(
        G1_ACTION_IDS
    )
    assert payload["schema_version"] == "roguepatch.g1-action-registry.v1"
    assert (
        approval._action_registry_sha256(registry)
        == sha256(approval._canonical_action_registry_payload(registry)).hexdigest()
    )
    registry_by_id = {action.action_id: action for action in registry}
    for action_payload in payload["actions"]:
        action = registry_by_id[action_payload["action_id"]]
        assert action_payload == {
            "action_id": action.action_id,
            "argv": list(action.command.argv),
            "cwd": str(action.command.cwd),
            "env": dict(action.command.env),
            "timeout_seconds": action.command.timeout_seconds,
            "max_output_bytes": action.command.max_output_bytes,
            "mutating": action.command.mutating,
            "shell": action.command.shell,
        }
    for action in registry:
        assert action.command == _registered_action(action.action_id).command
        assert approval._command_spec_sha256(action.command) == (
            _registered_command_digest(action.action_id)
        )
    assert PROTECTED_PROBE_PATHS[ProtectedTarget.PROTECTED_MANIFEST] == PurePosixPath(
        "/Users/alex/.codex/roguepatch-control/v1/g1/protected/protected_manifest.json"
    )
    assert PROTECTED_PROBE_PATHS[ProtectedTarget.GOLDEN_PATCH] == PurePosixPath(
        "/Users/alex/.codex/roguepatch-control/v1/g1/protected/golden.patch"
    )
    assert PROTECTED_PROBE_PATHS[ProtectedTarget.ARTIFACT_STORE] == PurePosixPath(
        "/Users/alex/.codex/roguepatch-control/v1/g1/protected/artifacts"
    )
    assert PROTECTED_PROBE_PATHS[
        ProtectedTarget.SOURCE_PROTECTED_MANIFEST
    ] == PurePosixPath("/run/sandbox/source/protected/protected_manifest.json")
    assert PROTECTED_PROBE_PATHS[ProtectedTarget.SOURCE_GOLDEN_PATCH] == PurePosixPath(
        "/run/sandbox/source/protected/golden.patch"
    )
    assert PROTECTED_PROBE_PATHS[ProtectedTarget.SOURCE_ARTIFACTS] == PurePosixPath(
        "/run/sandbox/source/artifacts"
    )


def _resolution_values(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "requested_path": SOURCE_REPOSITORY,
        "source_realpath": SOURCE_REALPATH,
        "git_top_level": SOURCE_REALPATH,
        "git_commit": SOURCE_GIT_COMMIT,
        "git_tree_digest": SOURCE_DIGEST,
        "lab_realpath": LAB_ROOT,
        "exists": True,
        "contains_parent_reference": False,
        "symlink_components": (),
        "repository_clean": True,
        "remote_names": (),
        "reserved_entries": (),
        "fixture_parent_ignored": True,
        "parent_checkout_clean": True,
        "action_id": RESOLVER_ACTION_ID,
        "command_spec_digest": _registered_command_digest(RESOLVER_ACTION_ID),
        "action_registry_sha256": _registry_digest(),
        "result_digest": RESOLVER_RESULT_DIGEST,
        "read_only": True,
    }
    values.update(overrides)
    return values


class FakeReadOnlySourceResolver:
    """Inert proof source: RED never resolves a path on Alex's machines."""

    def __init__(self, resolution_values: dict[str, object]) -> None:
        self.resolution_values = resolution_values
        self.calls: list[Path] = []

    def resolve(
        self,
        requested_path: Path,
    ) -> SourcePathResolutionRecord:
        self.calls.append(requested_path)
        assert requested_path == self.resolution_values["requested_path"]
        return SourcePathResolutionRecord(
            **self.resolution_values,  # type: ignore[arg-type]
        )


def _resolved_source(
    **overrides: object,
) -> tuple[SourcePathProof, SourcePathResolutionRecord]:
    values = _resolution_values(**overrides)
    requested_path = values["requested_path"]
    assert isinstance(requested_path, Path)
    resolver = FakeReadOnlySourceResolver(values)
    resolved = resolve_source_path(
        requested_path=requested_path,
        action_registry=_g1_action_registry(),
        resolver=resolver,
    )
    assert resolver.calls == [requested_path]
    return resolved


def _safe_sandbox_values() -> dict[str, object]:
    proof, record = _resolved_source()
    return {
        "role": SandboxRole.AGENT,
        "source_path_proof": proof,
        "source_resolution_record": record,
        "source_mount": HostMount(
            source=proof.source_realpath,
            target=SOURCE_TARGET,
            read_only=True,
        ),
        "source_digest": SOURCE_DIGEST,
        "approved_source_digest": SOURCE_DIGEST,
        "workspace_mode": WorkspaceMode.PRIVATE_CLONE,
        "workspace_path": AGENT_WORKSPACE,
        "additional_host_mounts": (),
        "docker_socket": False,
        "network": NetworkMode.NONE,
        "shared_skill_paths": (),
        "limits": _limits(),
    }


def _oracle_container() -> OracleContainerSpec:
    return OracleContainerSpec(
        image_digest=ORACLE_IMAGE,
        network=NetworkMode.NONE,
        rootfs_read_only=True,
        candidate_read_only=True,
        capabilities=(),
        no_new_privileges=True,
        secrets=(),
        model_credentials=(),
        docker_socket=False,
        limits=_limits(),
    )


def _probe_command_spec_digests() -> dict[ProtectedTarget, str]:
    return {
        target: _registered_command_digest(PROTECTED_PROBE_ACTION_IDS[target])
        for target in ProtectedTarget
    }


class F1ExecutorSpy:
    """The sole source of probe facts and the physical F1 execution trace."""

    def __init__(
        self,
        *,
        failures: Mapping[str, BaseException] | None = None,
        failed_result_action_ids: frozenset[str] | None = None,
        source_mount_defect: str | None = None,
        disk_available_kib: Mapping[tuple[SandboxRole, DiskPhase], int] | None = None,
        create_request_mutator: Callable[[SandboxCreateRequest], SandboxCreateRequest]
        | None = None,
        create_observation_mutator: Callable[
            [SandboxCreateObservation], SandboxCreateObservation
        ]
        | None = None,
        create_trace_result_digests: Mapping[SandboxRole, str] | None = None,
        create_results: Mapping[SandboxRole, CommandResult] | None = None,
        engine_identity_observation_mutator: Callable[
            [OracleEngineIdentityObservation],
            OracleEngineIdentityObservation | CommandResult,
        ]
        | None = None,
        engine_identity_trace_result_digest: str | None = None,
        engine_identity_result: CommandResult | None = None,
        checker_observation_mutator: Callable[
            [OracleCheckerObservation], OracleCheckerObservation | CommandResult
        ]
        | None = None,
        checker_trace_result_digest: str | None = None,
        checker_result: CommandResult | None = None,
    ) -> None:
        self.calls: list[tuple[G1HostAction, str, SandboxRef]] = []
        self.trace_records: list[F1ExecutionTraceRecord] = []
        self.disk_decisions: list[DiskSafetyDecision] = []
        self.timeline: list[DiskSafetyDecision | F1ExecutionTraceRecord] = []
        self.execution_nonce = "executor-result-not-present-in-probe-spec"
        self.failures = dict(failures or {})
        self.failed_result_action_ids = failed_result_action_ids or frozenset()
        self.source_mount_defect = source_mount_defect
        self.create_requests: list[SandboxCreateRequest] = []
        self.create_observations: list[SandboxCreateObservation] = []
        self.engine_identity_observations: list[OracleEngineIdentityObservation] = []
        self.checker_observations: list[OracleCheckerObservation] = []
        self.probe_execution_records: list[SbxExecRecord] = []
        self.source_mount_observations: list[SourceMountObservation] = []
        self.create_request_mutator = create_request_mutator
        self.create_observation_mutator = create_observation_mutator
        self.create_trace_result_digests = dict(create_trace_result_digests or {})
        self.create_results = dict(create_results or {})
        self.engine_identity_observation_mutator = engine_identity_observation_mutator
        self.engine_identity_trace_result_digest = engine_identity_trace_result_digest
        self.engine_identity_result = engine_identity_result
        self.checker_observation_mutator = checker_observation_mutator
        self.checker_trace_result_digest = checker_trace_result_digest
        self.checker_result = checker_result
        self.disk_available_kib = dict(
            disk_available_kib
            or {
                (SandboxRole.AGENT, "pre_create"): PRE_CREATE_MIN_KIB,
                (SandboxRole.AGENT, "post_create"): POST_CREATE_MIN_KIB,
                (SandboxRole.ORACLE, "pre_create"): PRE_CREATE_MIN_KIB,
                (SandboxRole.ORACLE, "post_create"): POST_CREATE_MIN_KIB,
            }
        )

    @property
    def execution_trace(self) -> F1ExecutionTrace:
        return F1ExecutionTrace(records=tuple(self.trace_records))

    def evaluate_disk_safety(
        self,
        *,
        role: SandboxRole,
        phase: DiskPhase,
        create_invocations: int,
    ) -> DiskSafetyDecision:
        required_kib = (
            PRE_CREATE_MIN_KIB if phase == "pre_create" else POST_CREATE_MIN_KIB
        )
        decision = DiskSafetyDecision(
            role=role,
            phase=phase,
            available_kib=self.disk_available_kib[(role, phase)],
            required_kib=required_kib,
            create_invocations=create_invocations,
            allowed=self.disk_available_kib[(role, phase)] >= required_kib,
        )
        self.disk_decisions.append(decision)
        self.timeline.append(decision)
        return decision

    def _emit(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        sandbox: SandboxRef,
        result_digest: str,
        status: F1ExecutionStatus | None = None,
    ) -> None:
        assert action == _registered_action(action.action_id)
        assert action.command.argv[0] == "sbx"
        assert action.command.shell is False
        assert action_registry_sha256 == _registry_digest()
        self.calls.append((action, action_registry_sha256, sandbox))
        if status is None:
            status = (
                F1ExecutionStatus.FAILED
                if action.action_id in self.failures
                or action.action_id in self.failed_result_action_ids
                else F1ExecutionStatus.SUCCEEDED
            )
        record = F1ExecutionTraceRecord(
            sequence=len(self.trace_records) + 1,
            prev_record_sha256=(
                self.trace_records[-1].sha256
                if self.trace_records
                else F1_TRACE_GENESIS_SHA256
            ),
            microvm_role=sandbox.role,
            microvm_id=sandbox.microvm_id,
            action_id=action.action_id,
            command_spec_digest=approval._command_spec_sha256(action.command),
            action_registry_sha256=action_registry_sha256,
            result_digest=result_digest,
            status=status,
        )
        self.trace_records.append(record)
        self.timeline.append(record)
        if action.action_id in self.failures:
            raise self.failures[action.action_id]

    def create(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        request: SandboxCreateRequest,
    ) -> SandboxCreateObservation:
        assert request.action_registry_sha256 == action_registry_sha256
        assert request.limits == _limits()
        assert request.private_engine is (request.role is SandboxRole.ORACLE)
        if request.role is SandboxRole.AGENT:
            assert request.agent_spec == _agent_spec()
            assert request.oracle_container is None
        else:
            assert request.agent_spec is None
            assert request.oracle_container == _oracle_container()
        self.create_requests.append(request)
        bound_request = (
            self.create_request_mutator(request)
            if self.create_request_mutator is not None
            else request
        )
        sandbox = AGENT if request.role is SandboxRole.AGENT else ORACLE
        create_result = self.create_results.get(
            request.role,
            CommandResult(
                returncode=0,
                stdout=f"created:{sandbox.microvm_id}",
                stderr="",
                timed_out=False,
                truncated=False,
            ),
        )
        observation = SandboxCreateObservation(
            sandbox=sandbox,
            request_sha256=bound_request.sha256,
            create_result=create_result,
        )
        if self.create_observation_mutator is not None:
            observation = self.create_observation_mutator(observation)
        self.create_observations.append(observation)
        self._emit(
            action=action,
            action_registry_sha256=action_registry_sha256,
            sandbox=sandbox,
            result_digest=self.create_trace_result_digests.get(
                request.role,
                observation.sha256,
            ),
            status=(
                F1ExecutionStatus.FAILED
                if action.action_id in self.failures or not create_result.succeeded
                else F1ExecutionStatus.SUCCEEDED
            ),
        )
        return observation

    def execute(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        spec: ProtectedProbeSpec,
        sandbox: SandboxRef,
    ) -> tuple[SbxExecRecord, SourceMountObservation | None]:
        assert action.action_id == spec.action_id
        assert approval._command_spec_sha256(action.command) == spec.command_spec_digest
        observed_errno = (
            errno.EACCES
            if spec.target is ProtectedTarget.SIGNING_MATERIAL
            else errno.ENOENT
        )
        proof = next(
            (
                request.agent_spec.source_path_proof
                for request in self.create_requests
                if request.agent_spec is not None
            ),
            None,
        )
        if proof is None:
            proof = _resolved_source()[0]
        if spec.target is ProtectedTarget.HOST_CANARY:
            result_payload = _host_canary_result_payload(
                target=spec.target,
                observed_errno=observed_errno,
                sandbox=sandbox,
                mount_path=SOURCE_TARGET,
                git_top_level=SOURCE_TARGET,
                source_path_proof_sha256=proof.sha256,
                git_commit=proof.git_commit,
                git_tree_digest=proof.git_tree_digest,
                read_only=True,
            )
            result_digest = sha256(result_payload).hexdigest()
            if self.source_mount_defect == "payload-result-digest-misbound":
                result_digest = _digest("misbound-host-canary-result")
        else:
            result_digest = _digest(f"{self.execution_nonce}:{spec.target.value}")
        record = SbxExecRecord(
            target=spec.target.value,
            probe_path=spec.probe_path,
            microvm_id=sandbox.microvm_id,
            action_id=spec.action_id,
            command_spec_digest=spec.command_spec_digest,
            action_registry_sha256=spec.action_registry_sha256,
            result_digest=result_digest,
            observed_errno=observed_errno,
            read_only=True,
        )
        self.probe_execution_records.append(record)
        source_mount_observation: SourceMountObservation | None = None
        mount_is_emitted = (
            spec.target is ProtectedTarget.HOST_CANARY
            and self.source_mount_defect not in {"mount-missing", "mount-wrong-target"}
        ) or (
            spec.target is ProtectedTarget.PROTECTED_MANIFEST
            and self.source_mount_defect in {"mount-wrong-target", "mount-duplicated"}
        )
        if mount_is_emitted:
            source_mount_observation = SourceMountObservation(
                sandbox=sandbox,
                mount_path=SOURCE_TARGET,
                git_top_level=SOURCE_TARGET,
                source_path_proof_sha256=proof.sha256,
                git_commit=proof.git_commit,
                git_tree_digest=proof.git_tree_digest,
                read_only=True,
                execution_record_sha256=record.sha256,
            )
            self.source_mount_observations.append(source_mount_observation)
        self._emit(
            action=action,
            action_registry_sha256=action_registry_sha256,
            sandbox=sandbox,
            result_digest=result_digest,
        )
        return record, source_mount_observation

    def freeze(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        sandbox: SandboxRef,
        candidate_digest: str,
    ) -> str:
        assert sandbox is AGENT
        self._emit(
            action=action,
            action_registry_sha256=action_registry_sha256,
            sandbox=sandbox,
            result_digest=_digest(f"executor:{action.action_id}:{candidate_digest}"),
        )
        return candidate_digest

    def engine_identity(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        sandbox: SandboxRef,
    ) -> OracleEngineIdentityObservation | CommandResult:
        assert sandbox is ORACLE
        identity_result = self.engine_identity_result or CommandResult(
            returncode=0,
            stdout=ORACLE_ENGINE_IDENTITY,
            stderr="",
            timed_out=False,
            truncated=False,
        )
        observation = OracleEngineIdentityObservation(
            sandbox=sandbox,
            action_registry_sha256=action_registry_sha256,
            engine_identity_sha256=ORACLE_ENGINE_IDENTITY_SHA256,
            identity_result=identity_result,
        )
        returned_observation = (
            self.engine_identity_observation_mutator(observation)
            if self.engine_identity_observation_mutator is not None
            else observation
        )
        if isinstance(returned_observation, OracleEngineIdentityObservation):
            self.engine_identity_observations.append(returned_observation)
            result_digest = returned_observation.sha256
        else:
            result_digest = _digest("naked-engine-identity-command-result")
        self._emit(
            action=action,
            action_registry_sha256=action_registry_sha256,
            sandbox=sandbox,
            result_digest=self.engine_identity_trace_result_digest or result_digest,
            status=(
                F1ExecutionStatus.SUCCEEDED
                if identity_result.succeeded
                else F1ExecutionStatus.FAILED
            ),
        )
        return returned_observation

    def checker(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        sandbox: SandboxRef,
        container: OracleContainerSpec,
        candidate_digest: str,
    ) -> OracleCheckerObservation | CommandResult:
        assert sandbox is ORACLE
        assert container == _oracle_container()
        assert candidate_digest == CANDIDATE_DIGEST
        succeeded = action.action_id not in self.failed_result_action_ids
        checker_result = self.checker_result or CommandResult(
            returncode=0 if succeeded else 1,
            stdout="oracle complete" if succeeded else "",
            stderr="" if succeeded else "synthetic oracle failed",
            timed_out=False,
            truncated=False,
        )
        docker_socket_record = next(
            record
            for record in self.probe_execution_records
            if record.target == ProtectedTarget.DOCKER_SOCKET.value
        )
        observation = OracleCheckerObservation(
            sandbox=sandbox,
            container=container,
            action_registry_sha256=action_registry_sha256,
            candidate_path=CANDIDATE_PATH,
            observed_digest_before=candidate_digest,
            observed_digest_after=candidate_digest,
            engine_identity_sha256=self.engine_identity_observations[
                0
            ].engine_identity_sha256,
            private_engine=True,
            host_engine_reachable=False,
            shared_socket=False,
            docker_socket_probe_path=DOCKER_SOCKET_PATH,
            docker_socket_probe_errno=errno.ENOENT,
            agent_docker_socket_execution_record_sha256=docker_socket_record.sha256,
            checker_result=checker_result,
        )
        returned_observation = (
            self.checker_observation_mutator(observation)
            if self.checker_observation_mutator is not None
            else observation
        )
        if isinstance(returned_observation, OracleCheckerObservation):
            self.checker_observations.append(returned_observation)
            result_digest = returned_observation.sha256
        else:
            result_digest = _digest("naked-command-result-is-not-observation")
        self._emit(
            action=action,
            action_registry_sha256=action_registry_sha256,
            sandbox=sandbox,
            result_digest=self.checker_trace_result_digest or result_digest,
            status=(
                F1ExecutionStatus.SUCCEEDED
                if checker_result.succeeded
                else F1ExecutionStatus.FAILED
            ),
        )
        return returned_observation

    def destroy(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        sandbox: SandboxRef,
    ) -> None:
        self._emit(
            action=action,
            action_registry_sha256=action_registry_sha256,
            sandbox=sandbox,
            result_digest=_digest(f"executor:{action.action_id}:result"),
        )


def _action_ids(executor: F1ExecutorSpy) -> list[str]:
    return [call[0].action_id for call in executor.calls]


def _assert_destroy_matches_create_observation(
    executor: F1ExecutorSpy,
    role: SandboxRole,
) -> None:
    matching_observations = [
        observation
        for request, observation in zip(
            executor.create_requests,
            executor.create_observations,
            strict=True,
        )
        if request.role is role
    ]
    destroy_action_id = f"g1.sbx.{role.value}.destroy"
    matching_destroy_calls = [
        call for call in executor.calls if call[0].action_id == destroy_action_id
    ]

    assert len(matching_observations) == 1
    assert len(matching_destroy_calls) == 1
    destroy_action, _, destroy_ref = matching_destroy_calls[0]
    assert destroy_action == _registered_action(destroy_action_id)
    assert destroy_ref == matching_observations[0].sandbox


def _assert_only_registered_sbx_calls(executor: F1ExecutorSpy) -> None:
    for action, registry_digest, sandbox in executor.calls:
        assert action == _registered_action(action.action_id)
        assert action.command.argv[0] == "sbx"
        assert action.command.shell is False
        assert registry_digest == _registry_digest()
        assert sandbox.role in {SandboxRole.AGENT, SandboxRole.ORACLE}


def _timeline_labels(executor: F1ExecutorSpy) -> list[str]:
    labels: list[str] = []
    for event in executor.timeline:
        if isinstance(event, DiskSafetyDecision):
            labels.append(f"disk:{event.phase}:{event.role.value}")
        else:
            labels.append(event.action_id)
    return labels


def _probe_evidence() -> ProtectedProbeEvidence:
    executor = F1ExecutorSpy()
    evidence = run_protected_boundary_probes(
        agent=AGENT,
        action_registry=_g1_action_registry(),
        executor=executor,
    )
    assert [call[0].action_id for call in executor.calls] == [
        spec.action_id for spec in evidence.probe_specs
    ]
    assert all(call[1] == _registry_digest() for call in executor.calls)
    assert all(call[2] is AGENT for call in executor.calls)
    assert len(executor.calls) == len(ProtectedTarget)
    assert evidence.action_registry_sha256 == _registry_digest()
    assert dict(evidence.command_spec_digests) == _probe_command_spec_digests()
    assert (
        evidence.probe_observations[0].source_mount_observation
        == executor.source_mount_observations[0]
    )
    assert all(
        observation.source_mount_observation is None
        for observation in evidence.probe_observations[1:]
    )
    return evidence


@pytest.mark.parametrize("registry_defect", ["missing-probe", "duplicate-action-id"])
def test_r6_probe_specs_fail_closed_on_invalid_g1_registry(
    registry_defect: str,
) -> None:
    registry = set(_g1_action_registry())
    host_canary_action = PROTECTED_PROBE_ACTION_IDS[ProtectedTarget.HOST_CANARY]
    if registry_defect == "missing-probe":
        registry = {
            action for action in registry if action.action_id != host_canary_action
        }
    else:
        registry.add(
            _registered_command(
                host_canary_action,
                ("synthetic-conflicting-command",),
                mutating=False,
            )
        )
    executor = F1ExecutorSpy()

    with pytest.raises(ValueError):
        run_protected_boundary_probes(
            agent=AGENT,
            action_registry=frozenset(registry),
            executor=executor,
        )

    assert executor.calls == []


@pytest.mark.parametrize(
    "registry_defect",
    [
        "missing-oracle-engine-identity",
        "missing-oracle-checker",
        "missing-oracle-destroy",
        "duplicate-oracle-engine-identity",
        "duplicate-oracle-destroy",
    ],
)
def test_r6_full_sequence_rejects_an_open_lifecycle_registry_before_execution(
    registry_defect: str,
) -> None:
    registry = set(_g1_action_registry())
    if registry_defect.endswith("oracle-engine-identity"):
        affected_action_id = ORACLE_ENGINE_IDENTITY_ACTION_ID
    elif registry_defect == "missing-oracle-checker":
        affected_action_id = ORACLE_CHECKER_ACTION_ID
    else:
        affected_action_id = ORACLE_DESTROY_ACTION_ID
    if registry_defect.startswith("missing"):
        registry = {
            action for action in registry if action.action_id != affected_action_id
        }
    else:
        registry.add(
            _registered_command(
                affected_action_id,
                ("synthetic-conflicting-oracle-destroy",),
                mutating=True,
            )
        )
    executor = F1ExecutorSpy()

    with pytest.raises(ValueError):
        run_f1_oracle_sequence(
            gate=_live_gate(),
            agent_spec=_agent_spec(),
            oracle_container=_oracle_container(),
            candidate_digest=CANDIDATE_DIGEST,
            action_registry=frozenset(registry),
            disk_safety=executor,
            executor=executor,
        )

    assert executor.calls == []
    assert executor.disk_decisions == []


def _agent_spec() -> SandboxSpec:
    proof, record = _resolved_source()
    return SandboxSpec.private_clone(
        role=SandboxRole.AGENT,
        source_repository=SOURCE_REPOSITORY,
        source_path_proof=proof,
        source_resolution_record=record,
        source_digest=SOURCE_DIGEST,
        approved_source_digest=SOURCE_DIGEST,
        limits=_limits(),
    )


def _run_f1(
    *,
    gate: LiveOracleGateFacts,
    executor: F1ExecutorSpy,
) -> OracleBoundaryFacts:
    return run_f1_oracle_sequence(
        gate=gate,
        agent_spec=_agent_spec(),
        oracle_container=_oracle_container(),
        candidate_digest=CANDIDATE_DIGEST,
        action_registry=_g1_action_registry(),
        disk_safety=executor,
        executor=executor,
    )


def _boundary_run() -> tuple[OracleBoundaryFacts, F1ExecutorSpy]:
    executor = F1ExecutorSpy()
    facts = _run_f1(gate=_live_gate(), executor=executor)
    assert facts.execution_trace == executor.execution_trace
    assert executor.disk_decisions == [
        DiskSafetyDecision(
            role=SandboxRole.AGENT,
            phase="pre_create",
            available_kib=PRE_CREATE_MIN_KIB,
            required_kib=PRE_CREATE_MIN_KIB,
            create_invocations=0,
            allowed=True,
        ),
        DiskSafetyDecision(
            role=SandboxRole.AGENT,
            phase="post_create",
            available_kib=POST_CREATE_MIN_KIB,
            required_kib=POST_CREATE_MIN_KIB,
            create_invocations=1,
            allowed=True,
        ),
        DiskSafetyDecision(
            role=SandboxRole.ORACLE,
            phase="pre_create",
            available_kib=PRE_CREATE_MIN_KIB,
            required_kib=PRE_CREATE_MIN_KIB,
            create_invocations=1,
            allowed=True,
        ),
        DiskSafetyDecision(
            role=SandboxRole.ORACLE,
            phase="post_create",
            available_kib=POST_CREATE_MIN_KIB,
            required_kib=POST_CREATE_MIN_KIB,
            create_invocations=2,
            allowed=True,
        ),
    ]
    assert _timeline_labels(executor) == [
        "disk:pre_create:agent",
        AGENT_CREATE_ACTION_ID,
        "disk:post_create:agent",
        *(PROTECTED_PROBE_ACTION_IDS[target] for target in CANONICAL_PROTECTED_TARGETS),
        AGENT_FREEZE_ACTION_ID,
        AGENT_DESTROY_ACTION_ID,
        "disk:pre_create:oracle",
        ORACLE_CREATE_ACTION_ID,
        "disk:post_create:oracle",
        ORACLE_ENGINE_IDENTITY_ACTION_ID,
        ORACLE_CHECKER_ACTION_ID,
        ORACLE_DESTROY_ACTION_ID,
    ]
    return facts, executor


def _boundary_facts() -> OracleBoundaryFacts:
    return _boundary_run()[0]


def _gate_with_defect(defect: str) -> LiveOracleGateFacts:
    gate = _live_gate()
    if defect == "wrong-host":
        identity = replace(gate.host_identity, hostname="MacBook-Pro-de-Alex.local")
        fingerprint = host_identity_sha256(identity)
        return replace(
            gate,
            host_identity=identity,
            host_fingerprint_sha256=fingerprint,
            receipt_binding=replace(
                gate.receipt_binding,
                host_fingerprint_sha256=fingerprint,
            ),
        )
    if defect == "receipt-absent":
        return replace(gate, approval_state=ApprovalState.ABSENT)
    if defect == "receipt-misbound":
        return replace(gate, approval_state=ApprovalState.MISBOUND)
    if defect == "fingerprint-misbound":
        return replace(gate, host_fingerprint_sha256=OTHER_DIGEST)
    if defect == "registry-misbound":
        return replace(gate, action_registry_sha256=OTHER_DIGEST)
    if defect in {"doctor-daemon-not-ready", "doctor-isolation-not-ready"}:
        check = (
            DoctorCheck.DAEMON
            if defect == "doctor-daemon-not-ready"
            else DoctorCheck.ISOLATION
        )
        facts = dict(gate.doctor_report.facts)
        facts[check] = CheckFact(check=check, state=CheckState.MISSING)
        return replace(gate, doctor_report=DoctorReport(facts=facts))
    if defect == "engine-action-id":
        return replace(
            gate,
            daemon_isolation_facts=replace(
                gate.daemon_isolation_facts,
                action_id=ORACLE_CHECKER_ACTION_ID,
            ),
        )
    if defect == "engine-sandbox-role":
        return replace(
            gate,
            daemon_isolation_facts=replace(
                gate.daemon_isolation_facts,
                sandbox_role=SandboxRole.AGENT.value,
            ),
        )
    if defect == "engine-isolation-scope":
        return replace(
            gate,
            daemon_isolation_facts=replace(
                gate.daemon_isolation_facts,
                isolation_scope="host",
            ),
        )
    if defect in {"oracle-microvm-empty", "oracle-microvm-whitespace"}:
        return replace(
            gate,
            daemon_isolation_facts=replace(
                gate.daemon_isolation_facts,
                oracle_microvm_id=("" if defect == "oracle-microvm-empty" else "   "),
            ),
        )
    if defect == "engine-observation-trace-mismatch":
        return replace(
            gate,
            daemon_isolation_facts=replace(
                gate.daemon_isolation_facts,
                engine_identity_trace_result_sha256=OTHER_DIGEST,
            ),
        )
    if defect == "engine-checker-mismatch":
        return replace(
            gate,
            daemon_isolation_facts=replace(
                gate.daemon_isolation_facts,
                checker_engine_identity_sha256=OTHER_DIGEST,
            ),
        )
    if defect == "engine-not-private":
        return replace(
            gate,
            daemon_isolation_facts=replace(
                gate.daemon_isolation_facts,
                private_engine_observed=False,
            ),
        )
    if defect == "engine-registry-internally-consistent-but-misbound":
        return replace(
            gate,
            daemon_isolation_facts=replace(
                gate.daemon_isolation_facts,
                action_registry_sha256=OTHER_DIGEST,
                engine_identity_action_registry_sha256=OTHER_DIGEST,
            ),
        )
    if defect == "host-daemon-accessible":
        return replace(
            gate,
            daemon_isolation_facts=replace(
                gate.daemon_isolation_facts,
                host_daemon_accessible=True,
            ),
        )
    if defect == "docker-desktop":
        return replace(
            gate,
            daemon_isolation_facts=replace(
                gate.daemon_isolation_facts,
                docker_desktop_observed=True,
            ),
        )
    if defect == "shared-socket":
        return replace(
            gate,
            daemon_isolation_facts=replace(
                gate.daemon_isolation_facts,
                shared_socket_observed=True,
            ),
        )
    if defect == "initial-below-40-gib":
        return _live_gate(available_kib=RECEIPT_INSTALL_MIN_KIB - 1)
    raise AssertionError(f"unknown gate defect: {defect}")


def test_f1_orchestrator_requires_gate_and_disk_authority() -> None:
    parameters = inspect.signature(run_f1_oracle_sequence).parameters
    gate_parameters = inspect.signature(LiveOracleGateFacts).parameters

    assert parameters["gate"].default is inspect.Parameter.empty
    assert parameters["disk_safety"].default is inspect.Parameter.empty
    assert parameters["executor"].default is inspect.Parameter.empty
    assert {"doctor_report", "daemon_isolation_facts"} <= set(gate_parameters)
    assert gate_parameters["doctor_report"].default is inspect.Parameter.empty
    assert gate_parameters["daemon_isolation_facts"].default is inspect.Parameter.empty


@pytest.mark.parametrize(
    "gate_defect",
    [
        "wrong-host",
        "receipt-absent",
        "receipt-misbound",
        "fingerprint-misbound",
        "registry-misbound",
        "doctor-daemon-not-ready",
        "doctor-isolation-not-ready",
        "engine-action-id",
        "engine-sandbox-role",
        "engine-isolation-scope",
        "oracle-microvm-empty",
        "oracle-microvm-whitespace",
        "engine-observation-trace-mismatch",
        "engine-checker-mismatch",
        "engine-not-private",
        "engine-registry-internally-consistent-but-misbound",
        "host-daemon-accessible",
        "docker-desktop",
        "shared-socket",
        "initial-below-40-gib",
    ],
)
def test_f1_gate_rejects_before_any_disk_check_or_executor_call(
    gate_defect: str,
) -> None:
    executor = F1ExecutorSpy()

    with pytest.raises(LiveOracleGateError) as raised:
        _run_f1(gate=_gate_with_defect(gate_defect), executor=executor)

    assert isinstance(raised.value, LiveOracleGateError)
    assert executor.calls == []
    assert executor.disk_decisions == []
    assert executor.trace_records == []
    assert executor.timeline == []


@pytest.mark.parametrize("role", [SandboxRole.AGENT, SandboxRole.ORACLE])
def test_f1_rechecks_30_gib_immediately_before_each_create(
    role: SandboxRole,
) -> None:
    executor = F1ExecutorSpy(
        disk_available_kib=_disk_availability(
            {(role, "pre_create"): PRE_CREATE_MIN_KIB - 1}
        )
    )

    with pytest.raises(LiveOracleGateError) as raised:
        _run_f1(gate=_live_gate(), executor=executor)

    expected_actions = [] if role is SandboxRole.AGENT else list(AGENT_TRACE_ACTION_IDS)
    assert isinstance(raised.value, LiveOracleGateError)
    assert _action_ids(executor) == expected_actions
    assert f"g1.sbx.{role.value}.create" not in _action_ids(executor)
    assert executor.disk_decisions[-1] == DiskSafetyDecision(
        role=role,
        phase="pre_create",
        available_kib=PRE_CREATE_MIN_KIB - 1,
        required_kib=PRE_CREATE_MIN_KIB,
        create_invocations=0 if role is SandboxRole.AGENT else 1,
        allowed=False,
    )
    assert _timeline_labels(executor)[-1] == f"disk:pre_create:{role.value}"
    assert raised.value.execution_trace == executor.execution_trace
    _assert_only_registered_sbx_calls(executor)


@pytest.mark.parametrize("role", [SandboxRole.AGENT, SandboxRole.ORACLE])
def test_f1_rechecks_20_gib_after_create_then_destroys_and_kills(
    role: SandboxRole,
) -> None:
    executor = F1ExecutorSpy(
        disk_available_kib=_disk_availability(
            {(role, "post_create"): POST_CREATE_MIN_KIB - 1}
        )
    )

    with pytest.raises(LiveOracleGateError) as raised:
        _run_f1(gate=_live_gate(), executor=executor)

    if role is SandboxRole.AGENT:
        expected_actions = [AGENT_CREATE_ACTION_ID, AGENT_DESTROY_ACTION_ID]
        forbidden_actions = set(TRACE_ACTION_IDS) - set(expected_actions)
    else:
        expected_actions = [
            *AGENT_TRACE_ACTION_IDS,
            ORACLE_CREATE_ACTION_ID,
            ORACLE_DESTROY_ACTION_ID,
        ]
        forbidden_actions = {ORACLE_CHECKER_ACTION_ID}
    assert raised.value.disposition is BatchDisposition.KILL
    assert raised.value.cleanup_reference is None
    assert _action_ids(executor) == expected_actions
    assert forbidden_actions.isdisjoint(_action_ids(executor))
    failing_check = DiskSafetyDecision(
        role=role,
        phase="post_create",
        available_kib=POST_CREATE_MIN_KIB - 1,
        required_kib=POST_CREATE_MIN_KIB,
        create_invocations=1 if role is SandboxRole.AGENT else 2,
        allowed=False,
    )
    assert failing_check in executor.disk_decisions
    labels = _timeline_labels(executor)
    post_check_index = labels.index(f"disk:post_create:{role.value}")
    assert labels[post_check_index - 1] == f"g1.sbx.{role.value}.create"
    assert labels[post_check_index + 1] == f"g1.sbx.{role.value}.destroy"
    assert raised.value.execution_trace == executor.execution_trace
    assert all(
        record.status is F1ExecutionStatus.SUCCEEDED
        for record in executor.trace_records
    )
    _assert_only_registered_sbx_calls(executor)


def test_r5_trial_isolation_contract() -> None:
    proof, record = _resolved_source()
    spec = SandboxSpec.private_clone(
        role=SandboxRole.AGENT,
        source_repository=SOURCE_REPOSITORY,
        source_path_proof=proof,
        source_resolution_record=record,
        source_digest=SOURCE_DIGEST,
        approved_source_digest=SOURCE_DIGEST,
        limits=_limits(),
    )

    assert not hasattr(proof, "verified")
    assert proof.requested_path == SOURCE_REPOSITORY
    assert proof.requested_path.is_absolute()
    assert proof.source_realpath == SOURCE_REALPATH
    assert proof.git_top_level == SOURCE_REALPATH
    assert proof.git_commit == SOURCE_GIT_COMMIT
    assert proof.git_tree_digest == SOURCE_DIGEST
    assert proof.lab_realpath == LAB_ROOT
    assert proof.exists is True
    assert proof.contains_parent_reference is False
    assert proof.symlink_components == ()
    assert proof.repository_clean is True
    assert proof.remote_names == ()
    assert proof.reserved_entries == ()
    assert proof.fixture_parent_ignored is True
    assert proof.parent_checkout_clean is True
    assert proof.action_id == RESOLVER_ACTION_ID
    assert proof.command_spec_digest == _registered_command_digest(RESOLVER_ACTION_ID)
    assert proof.action_registry_sha256 == _registry_digest()
    assert proof.result_digest == RESOLVER_RESULT_DIGEST
    assert proof.read_only is True
    assert proof.execution_record_sha256 == record.sha256
    assert record.requested_path == proof.requested_path
    assert record.source_realpath == proof.source_realpath
    assert record.git_top_level == proof.git_top_level
    assert record.git_commit == proof.git_commit
    assert record.git_tree_digest == proof.git_tree_digest
    assert record.lab_realpath == proof.lab_realpath
    assert record.repository_clean is proof.repository_clean
    assert record.remote_names == proof.remote_names
    assert record.reserved_entries == proof.reserved_entries
    assert record.fixture_parent_ignored is proof.fixture_parent_ignored
    assert record.parent_checkout_clean is proof.parent_checkout_clean
    assert record.action_id == proof.action_id
    assert record.command_spec_digest == proof.command_spec_digest
    assert record.action_registry_sha256 == proof.action_registry_sha256
    assert record.result_digest == proof.result_digest
    assert record.read_only is True
    assert spec.source_path_proof == proof
    assert spec.source_resolution_record == record
    assert spec.source_mount.source == SOURCE_REALPATH
    assert spec.source_mount.target == SOURCE_TARGET
    assert spec.source_mount.read_only is True
    assert spec.source_digest == spec.approved_source_digest == SOURCE_DIGEST
    assert spec.source_digest == proof.git_tree_digest
    assert spec.workspace_mode is WorkspaceMode.PRIVATE_CLONE
    assert spec.workspace_path == AGENT_WORKSPACE
    assert spec.workspace_path != spec.source_mount.target
    assert spec.additional_host_mounts == ()
    assert spec.docker_socket is False
    assert spec.network is NetworkMode.NONE
    assert spec.shared_skill_paths == ()
    assert spec.limits == _limits()


@pytest.mark.parametrize(
    ("_case", "proof_overrides"),
    [
        pytest.param(
            "parent traversal",
            {
                "requested_path": LAB_ROOT / ".." / "Desktop" / "VanguardIA",
            },
            id="lexical-parent-traversal",
        ),
        pytest.param(
            "relative",
            {"requested_path": Path("fixtures/rp-001")},
            id="relative-source-path",
        ),
        pytest.param(
            "symlink",
            {
                "requested_path": LAB_ROOT / "fixture-link",
                "symlink_components": (LAB_ROOT / "fixture-link",),
            },
            id="direct-symlink",
        ),
        pytest.param(
            "symlink",
            {
                "requested_path": LAB_ROOT / "fixtures" / "nested-link" / "rp-001",
                "symlink_components": (LAB_ROOT / "fixtures" / "nested-link",),
            },
            id="nested-symlink",
        ),
        pytest.param("exist", {"exists": False}, id="nonexistent"),
        pytest.param(
            "lab realpath",
            {"lab_realpath": Path("/synthetic/other-lab")},
            id="wrong-canonical-lab-root",
        ),
        pytest.param(
            "source realpath",
            {"source_realpath": Path("/Users/alex/Desktop/VanguardIA")},
            id="canonical-source-outside-lab",
        ),
        pytest.param(
            "exact public fixture",
            {
                "requested_path": LAB_ROOT
                / ".roguepatch"
                / "public-fixtures"
                / "other",
                "source_realpath": LAB_ROOT
                / ".roguepatch"
                / "public-fixtures"
                / "other",
                "git_top_level": LAB_ROOT / ".roguepatch" / "public-fixtures" / "other",
            },
            id="different-public-fixture",
        ),
        pytest.param(
            "independent Git root",
            {"git_top_level": LAB_ROOT},
            id="inherited-git-root",
        ),
        pytest.param(
            "clean repository",
            {"repository_clean": False},
            id="dirty-public-fixture",
        ),
        pytest.param(
            "no remotes",
            {"remote_names": ("origin",)},
            id="public-fixture-has-remote",
        ),
        pytest.param(
            "tree digest",
            {"git_tree_digest": OTHER_TREE_DIGEST},
            id="public-fixture-tree-drift",
        ),
        pytest.param(
            "reserved entries",
            {"reserved_entries": (SOURCE_REPOSITORY / "protected",)},
            id="reserved-protected-entry",
        ),
        pytest.param(
            "reserved entries",
            {"reserved_entries": (SOURCE_REPOSITORY / "artifacts",)},
            id="reserved-artifacts-entry",
        ),
        pytest.param(
            "ignored fixture parent",
            {"fixture_parent_ignored": False},
            id="fixture-parent-not-ignored",
        ),
        pytest.param(
            "controlled parent checkout",
            {"parent_checkout_clean": False},
            id="parent-checkout-dirty",
        ),
        pytest.param("read-only", {"read_only": False}, id="mutating-resolver"),
        pytest.param(
            "action",
            {"action_id": "g1.source.unregistered"},
            id="unauthorized-resolver-action",
        ),
        pytest.param(
            "command digest",
            {"command_spec_digest": OTHER_DIGEST},
            id="unauthorized-resolver-command",
        ),
        pytest.param(
            "registry digest",
            {"action_registry_sha256": OTHER_DIGEST},
            id="unauthorized-resolver-registry",
        ),
    ],
)
def test_r5_rejects_untrusted_source_path_proof(
    _case: str,
    proof_overrides: dict[str, object],
) -> None:
    with pytest.raises((TypeError, ValueError)):
        proof, record = _resolved_source(**proof_overrides)
        SandboxSpec.private_clone(
            role=SandboxRole.AGENT,
            source_repository=proof.requested_path,
            source_path_proof=proof,
            source_resolution_record=record,
            source_digest=SOURCE_DIGEST,
            approved_source_digest=SOURCE_DIGEST,
            limits=_limits(),
        )


def test_r5_rejects_proof_not_bound_to_the_resolver_execution_record() -> None:
    proof, record = _resolved_source()
    forged = replace(
        proof,
        execution_record_sha256=_digest("unregistered-source-resolution"),
    )

    with pytest.raises(ValueError):
        SandboxSpec.private_clone(
            role=SandboxRole.AGENT,
            source_repository=SOURCE_REPOSITORY,
            source_path_proof=forged,
            source_resolution_record=record,
            source_digest=SOURCE_DIGEST,
            approved_source_digest=SOURCE_DIGEST,
            limits=_limits(),
        )


@pytest.mark.parametrize(
    ("field_name", "different_value"),
    [
        pytest.param("git_top_level", LAB_ROOT, id="git-top-level"),
        pytest.param("git_commit", OTHER_GIT_COMMIT, id="git-commit"),
        pytest.param("git_tree_digest", OTHER_TREE_DIGEST, id="git-tree"),
        pytest.param("repository_clean", False, id="repository-clean"),
        pytest.param("remote_names", ("origin",), id="remote-names"),
        pytest.param(
            "reserved_entries",
            (SOURCE_REPOSITORY / "protected",),
            id="reserved-entries",
        ),
        pytest.param("fixture_parent_ignored", False, id="fixture-parent-ignored"),
        pytest.param("parent_checkout_clean", False, id="parent-checkout-clean"),
    ],
)
def test_r5_rejects_git_facts_not_bound_to_resolution_record(
    field_name: str,
    different_value: object,
) -> None:
    proof, record = _resolved_source()
    forged = replace(proof, **{field_name: different_value})

    with pytest.raises(ValueError):
        SandboxSpec.private_clone(
            role=SandboxRole.AGENT,
            source_repository=SOURCE_REPOSITORY,
            source_path_proof=forged,
            source_resolution_record=record,
            source_digest=SOURCE_DIGEST,
            approved_source_digest=SOURCE_DIGEST,
            limits=_limits(),
        )


def test_r5_rejects_source_repository_different_from_proof_request() -> None:
    proof, record = _resolved_source()

    with pytest.raises(ValueError):
        SandboxSpec.private_clone(
            role=SandboxRole.AGENT,
            source_repository=LAB_ROOT / "fixtures" / "other",
            source_path_proof=proof,
            source_resolution_record=record,
            source_digest=SOURCE_DIGEST,
            approved_source_digest=SOURCE_DIGEST,
            limits=_limits(),
        )


def test_r5_rejects_a_tampered_resolution_result_record() -> None:
    proof, record = _resolved_source()
    tampered_record = replace(record, result_digest=OTHER_DIGEST)

    with pytest.raises(ValueError):
        SandboxSpec.private_clone(
            role=SandboxRole.AGENT,
            source_repository=SOURCE_REPOSITORY,
            source_path_proof=proof,
            source_resolution_record=tampered_record,
            source_digest=SOURCE_DIGEST,
            approved_source_digest=SOURCE_DIGEST,
            limits=_limits(),
        )


@pytest.mark.parametrize(
    "relaxation",
    [
        "source-digest-drift",
        "additional-host-mount",
        "writable-source",
        "wrong-source-target",
        "workspace-is-source",
        "network-egress",
        "docker-socket",
        "shared-skills",
    ],
)
def test_r5_rejects_every_isolation_relaxation_without_io(
    relaxation: str,
) -> None:
    values = _safe_sandbox_values()
    if relaxation == "source-digest-drift":
        values["source_digest"] = "sha256:" + OTHER_DIGEST
    elif relaxation == "additional-host-mount":
        values["additional_host_mounts"] = (
            HostMount(
                source=LAB_ROOT / "extra",
                target=PurePosixPath("/extra"),
                read_only=True,
            ),
        )
    elif relaxation == "writable-source":
        mount = values["source_mount"]
        assert isinstance(mount, HostMount)
        values["source_mount"] = replace(mount, read_only=False)
    elif relaxation == "wrong-source-target":
        mount = values["source_mount"]
        assert isinstance(mount, HostMount)
        values["source_mount"] = replace(
            mount,
            target=PurePosixPath("/mnt/source"),
        )
    elif relaxation == "workspace-is-source":
        values["workspace_path"] = SOURCE_TARGET
    elif relaxation == "network-egress":
        values["network"] = "egress"
    elif relaxation == "docker-socket":
        values["docker_socket"] = True
    elif relaxation == "shared-skills":
        values["shared_skill_paths"] = (LAB_ROOT / "shared-skills",)

    with pytest.raises((TypeError, ValueError)):
        SandboxSpec(**values)  # type: ignore[arg-type]


def _different_identity_value(field_name: str, value: object) -> object:
    if isinstance(value, bool):
        return not value
    if isinstance(value, ResourceLimits):
        return ResourceLimits(
            cpu_count=value.cpu_count + 1,
            memory_mib=value.memory_mib,
            max_output_bytes=value.max_output_bytes,
        )
    if isinstance(value, SandboxRef):
        role = (
            SandboxRole.ORACLE if value.role is SandboxRole.AGENT else SandboxRole.AGENT
        )
        return SandboxRef(role=role, microvm_id=f"{value.microvm_id}-different")
    if isinstance(value, SandboxLifecycleAction):
        return (
            SandboxLifecycleAction.DESTROY
            if value is not SandboxLifecycleAction.DESTROY
            else SandboxLifecycleAction.FREEZE
        )
    if isinstance(value, SourceMountObservation):
        return replace(value, read_only=not value.read_only)
    if isinstance(value, CommandResult):
        return replace(value, stdout=f"{value.stdout}:different")
    if isinstance(value, Enum):
        return next(member for member in type(value) if member is not value)
    if isinstance(value, PurePath):
        return type(value)("/synthetic/different")
    if isinstance(value, str):
        if field_name == "target":
            return ProtectedTarget.PROTECTED_MANIFEST.value
        if field_name == "action_id":
            return "g1.sbx.synthetic-different"
        if field_name == "microvm_id":
            return "sbx-synthetic-different"
        if field_name == "git_commit":
            return OTHER_GIT_COMMIT
        if field_name == "engine_identity_sha256":
            return OTHER_ORACLE_ENGINE_IDENTITY_SHA256
        return (
            ("sha256:" + OTHER_DIGEST) if value.startswith("sha256:") else OTHER_DIGEST
        )
    if isinstance(value, int):
        return value + 1
    if isinstance(value, tuple):
        if field_name == "remote_names":
            return ("origin",)
        return (*value, LAB_ROOT / "different")
    if value is None:
        if field_name == "engine_identity_sha256":
            return ORACLE_ENGINE_IDENTITY_SHA256
        return SOURCE_DIGEST
    raise AssertionError(f"no identity mutation for {type(value).__name__}")


def test_f1_security_records_use_closed_domain_separated_payloads() -> None:
    proof, source_record = _resolved_source()
    facts = _boundary_facts()
    source_mount = facts.probe_observations[0].source_mount_observation
    assert source_mount is not None
    engine_identity = facts.engine_identity_observation
    records = (
        (
            proof,
            {
                "schema_version": "roguepatch.source-path-proof.v1",
                "requested_path": str(proof.requested_path),
                "source_realpath": str(proof.source_realpath),
                "git_top_level": str(proof.git_top_level),
                "git_commit": proof.git_commit,
                "git_tree_digest": proof.git_tree_digest,
                "lab_realpath": str(proof.lab_realpath),
                "exists": proof.exists,
                "contains_parent_reference": proof.contains_parent_reference,
                "symlink_components": [str(path) for path in proof.symlink_components],
                "repository_clean": proof.repository_clean,
                "remote_names": list(proof.remote_names),
                "reserved_entries": [str(path) for path in proof.reserved_entries],
                "fixture_parent_ignored": proof.fixture_parent_ignored,
                "parent_checkout_clean": proof.parent_checkout_clean,
                "action_id": proof.action_id,
                "command_spec_digest": proof.command_spec_digest,
                "action_registry_sha256": proof.action_registry_sha256,
                "result_digest": proof.result_digest,
                "read_only": proof.read_only,
                "execution_record_sha256": proof.execution_record_sha256,
            },
        ),
        (
            source_record,
            {
                "schema_version": "roguepatch.source-path-resolution-record.v1",
                "requested_path": str(source_record.requested_path),
                "source_realpath": str(source_record.source_realpath),
                "git_top_level": str(source_record.git_top_level),
                "git_commit": source_record.git_commit,
                "git_tree_digest": source_record.git_tree_digest,
                "lab_realpath": str(source_record.lab_realpath),
                "exists": source_record.exists,
                "contains_parent_reference": source_record.contains_parent_reference,
                "symlink_components": [
                    str(path) for path in source_record.symlink_components
                ],
                "repository_clean": source_record.repository_clean,
                "remote_names": list(source_record.remote_names),
                "reserved_entries": [
                    str(path) for path in source_record.reserved_entries
                ],
                "fixture_parent_ignored": source_record.fixture_parent_ignored,
                "parent_checkout_clean": source_record.parent_checkout_clean,
                "action_id": source_record.action_id,
                "command_spec_digest": source_record.command_spec_digest,
                "action_registry_sha256": source_record.action_registry_sha256,
                "result_digest": source_record.result_digest,
                "read_only": source_record.read_only,
            },
        ),
        (
            facts.probe_specs[0],
            {
                "schema_version": "roguepatch.protected-probe-spec.v1",
                "target": facts.probe_specs[0].target.value,
                "probe_path": str(facts.probe_specs[0].probe_path),
                "action_id": facts.probe_specs[0].action_id,
                "command_spec_digest": facts.probe_specs[0].command_spec_digest,
                "action_registry_sha256": facts.probe_specs[0].action_registry_sha256,
            },
        ),
        (
            facts.execution_records[0],
            {
                "schema_version": "roguepatch.sbx-exec-record.v1",
                "target": facts.execution_records[0].target,
                "probe_path": str(facts.execution_records[0].probe_path),
                "microvm_id": facts.execution_records[0].microvm_id,
                "action_id": facts.execution_records[0].action_id,
                "command_spec_digest": facts.execution_records[0].command_spec_digest,
                "action_registry_sha256": facts.execution_records[
                    0
                ].action_registry_sha256,
                "result_digest": facts.execution_records[0].result_digest,
                "observed_errno": facts.execution_records[0].observed_errno,
                "read_only": facts.execution_records[0].read_only,
            },
        ),
        (
            facts.probe_observations[0],
            {
                "schema_version": "roguepatch.protected-probe-observation.v1",
                "target": facts.probe_observations[0].target.value,
                "probe_path": str(facts.probe_observations[0].probe_path),
                "spec_sha256": facts.probe_observations[0].spec_sha256,
                "microvm_id": facts.probe_observations[0].microvm_id,
                "action_id": facts.probe_observations[0].action_id,
                "command_spec_digest": facts.probe_observations[0].command_spec_digest,
                "execution_record_sha256": facts.probe_observations[
                    0
                ].execution_record_sha256,
                "result_digest": facts.probe_observations[0].result_digest,
                "observed_errno": facts.probe_observations[0].observed_errno,
                "source_mount_observation_sha256": source_mount.sha256,
            },
        ),
        (
            source_mount,
            {
                "schema_version": "roguepatch.source-mount-observation.v1",
                "sandbox": {
                    "role": source_mount.sandbox.role.value,
                    "microvm_id": source_mount.sandbox.microvm_id,
                },
                "mount_path": str(source_mount.mount_path),
                "git_top_level": str(source_mount.git_top_level),
                "source_path_proof_sha256": source_mount.source_path_proof_sha256,
                "git_commit": source_mount.git_commit,
                "git_tree_digest": source_mount.git_tree_digest,
                "read_only": source_mount.read_only,
                "execution_record_sha256": source_mount.execution_record_sha256,
            },
        ),
        (
            engine_identity,
            {
                "schema_version": "roguepatch.oracle-engine-identity-observation.v1",
                "sandbox": {
                    "role": engine_identity.sandbox.role.value,
                    "microvm_id": engine_identity.sandbox.microvm_id,
                },
                "action_registry_sha256": engine_identity.action_registry_sha256,
                "engine_identity_sha256": engine_identity.engine_identity_sha256,
                "identity_result": {
                    "returncode": engine_identity.identity_result.returncode,
                    "stdout": engine_identity.identity_result.stdout,
                    "stderr": engine_identity.identity_result.stderr,
                    "timed_out": engine_identity.identity_result.timed_out,
                    "truncated": engine_identity.identity_result.truncated,
                },
            },
        ),
        (
            facts.lifecycle[1],
            {
                "schema_version": "roguepatch.sandbox-lifecycle-record.v1",
                "sequence": facts.lifecycle[1].sequence,
                "action": facts.lifecycle[1].action.value,
                "sandbox": {
                    "role": facts.lifecycle[1].sandbox.role.value,
                    "microvm_id": facts.lifecycle[1].sandbox.microvm_id,
                },
                "action_id": facts.lifecycle[1].action_id,
                "command_spec_digest": facts.lifecycle[1].command_spec_digest,
                "action_registry_sha256": facts.lifecycle[1].action_registry_sha256,
                "result_digest": facts.lifecycle[1].result_digest,
                "limits": {
                    "cpu_count": facts.lifecycle[1].limits.cpu_count,
                    "memory_mib": facts.lifecycle[1].limits.memory_mib,
                    "max_output_bytes": facts.lifecycle[1].limits.max_output_bytes,
                },
                "candidate_digest": facts.lifecycle[1].candidate_digest,
                "private_engine": facts.lifecycle[1].private_engine,
            },
        ),
        (
            facts.execution_trace.records[1],
            {
                "schema_version": "roguepatch.f1-execution-trace-record.v1",
                "sequence": facts.execution_trace.records[1].sequence,
                "prev_record_sha256": facts.execution_trace.records[
                    1
                ].prev_record_sha256,
                "microvm_role": facts.execution_trace.records[1].microvm_role.value,
                "microvm_id": facts.execution_trace.records[1].microvm_id,
                "action_id": facts.execution_trace.records[1].action_id,
                "command_spec_digest": facts.execution_trace.records[
                    1
                ].command_spec_digest,
                "action_registry_sha256": facts.execution_trace.records[
                    1
                ].action_registry_sha256,
                "result_digest": facts.execution_trace.records[1].result_digest,
                "status": facts.execution_trace.records[1].status.value,
            },
        ),
    )

    for record, expected_payload in records:
        schema_version = expected_payload["schema_version"]
        assert record.schema_version == schema_version
        assert isinstance(record.canonical_payload, bytes)
        assert json.loads(record.canonical_payload) == expected_payload
        assert record.sha256 == sha256(record.canonical_payload).hexdigest()
        identity_fields = {
            field.name for field in fields(record) if field.name != "schema_version"
        }
        assert identity_fields == set(expected_payload) - {"schema_version"}
        for field_name in identity_fields:
            changed = replace(
                record,
                **{
                    field_name: _different_identity_value(
                        field_name, getattr(record, field_name)
                    )
                },
            )
            assert changed.sha256 != record.sha256


@pytest.mark.parametrize(
    "defect",
    [
        "source-identity",
        "mount-path",
        "git-top-level",
        "read-only",
        "git-commit",
        "git-tree",
        "execution-record",
    ],
)
def test_r5_source_mount_observation_mutants_fail_closed(defect: str) -> None:
    facts = _boundary_facts()
    host_canary = facts.probe_observations[0]
    mount = host_canary.source_mount_observation
    assert host_canary.target is ProtectedTarget.HOST_CANARY
    assert mount is not None
    assert all(
        observation.source_mount_observation is None
        for observation in facts.probe_observations[1:]
    )
    replacements: dict[str, object] = {
        "source-identity": {"source_path_proof_sha256": _digest("other-source-proof")},
        "mount-path": {"mount_path": PurePosixPath("/tmp/source")},
        "git-top-level": {"git_top_level": PurePosixPath("/workspace")},
        "read-only": {"read_only": False},
        "git-commit": {"git_commit": OTHER_GIT_COMMIT},
        "git-tree": {"git_tree_digest": OTHER_TREE_DIGEST},
        "execution-record": {
            "execution_record_sha256": _digest("other-host-canary-exec")
        },
    }
    changed_mount = replace(mount, **replacements[defect])  # type: ignore[arg-type]
    changed_host_canary = replace(
        host_canary,
        source_mount_observation=changed_mount,
    )

    with pytest.raises(ValueError):
        validate_oracle_boundary(
            replace(
                facts,
                probe_observations=(
                    changed_host_canary,
                    *facts.probe_observations[1:],
                ),
            )
        )


@pytest.mark.parametrize(
    "defect",
    [
        "mount-missing",
        "mount-wrong-target",
        "mount-duplicated",
        "payload-result-digest-misbound",
    ],
)
def test_r5_source_mount_execution_mutants_destroy_agent(defect: str) -> None:
    executor = F1ExecutorSpy(source_mount_defect=defect)

    with pytest.raises(ValueError):
        _run_f1(gate=_live_gate(), executor=executor)

    assert _action_ids(executor)[-1] == AGENT_DESTROY_ACTION_ID
    assert _action_ids(executor).count(AGENT_DESTROY_ACTION_ID) == 1
    assert ORACLE_CREATE_ACTION_ID not in _action_ids(executor)
    _assert_destroy_matches_create_observation(executor, SandboxRole.AGENT)
    _assert_only_registered_sbx_calls(executor)


def test_r6_create_and_checker_records_are_canonical_and_domain_separated() -> None:
    facts = _boundary_facts()
    agent_request, oracle_request = facts.create_requests
    agent_create, oracle_create = facts.create_observations
    engine_identity = facts.engine_identity_observation
    checker = facts.checker_observation

    assert agent_request.schema_version == "roguepatch.sandbox-create-request.v1"
    assert oracle_request.schema_version == "roguepatch.sandbox-create-request.v1"
    assert agent_create.schema_version == "roguepatch.sandbox-create-observation.v1"
    assert oracle_create.schema_version == "roguepatch.sandbox-create-observation.v1"
    assert (
        engine_identity.schema_version
        == "roguepatch.oracle-engine-identity-observation.v1"
    )
    assert checker.schema_version == "roguepatch.oracle-checker-observation.v1"
    assert agent_request.agent_spec is not None
    assert oracle_request.oracle_container is not None
    agent_payload = json.loads(agent_request.canonical_payload)
    oracle_payload = json.loads(oracle_request.canonical_payload)
    agent_create_payload = json.loads(agent_create.canonical_payload)
    oracle_create_payload = json.loads(oracle_create.canonical_payload)
    checker_payload = json.loads(checker.canonical_payload)
    limits_payload = {
        "cpu_count": 2,
        "memory_mib": 2048,
        "max_output_bytes": 131_072,
    }
    assert agent_payload == {
        "schema_version": "roguepatch.sandbox-create-request.v1",
        "role": SandboxRole.AGENT.value,
        "action_registry_sha256": _registry_digest(),
        "limits": limits_payload,
        "private_engine": False,
        "agent_spec_sha256": _agent_spec().sha256,
        "oracle_container_sha256": None,
    }
    assert oracle_payload == {
        "schema_version": "roguepatch.sandbox-create-request.v1",
        "role": SandboxRole.ORACLE.value,
        "action_registry_sha256": _registry_digest(),
        "limits": limits_payload,
        "private_engine": True,
        "agent_spec_sha256": None,
        "oracle_container_sha256": _oracle_container().sha256,
    }
    assert agent_create_payload == {
        "schema_version": "roguepatch.sandbox-create-observation.v1",
        "sandbox": {"role": SandboxRole.AGENT.value, "microvm_id": AGENT.microvm_id},
        "request_sha256": agent_request.sha256,
        "create_result": {
            "returncode": 0,
            "stdout": f"created:{AGENT.microvm_id}",
            "stderr": "",
            "timed_out": False,
            "truncated": False,
        },
    }
    assert oracle_create_payload == {
        "schema_version": "roguepatch.sandbox-create-observation.v1",
        "sandbox": {
            "role": SandboxRole.ORACLE.value,
            "microvm_id": ORACLE.microvm_id,
        },
        "request_sha256": oracle_request.sha256,
        "create_result": {
            "returncode": 0,
            "stdout": f"created:{ORACLE.microvm_id}",
            "stderr": "",
            "timed_out": False,
            "truncated": False,
        },
    }
    docker_socket_record = next(
        record
        for record in facts.execution_records
        if record.target == ProtectedTarget.DOCKER_SOCKET.value
    )
    assert checker_payload == {
        "schema_version": "roguepatch.oracle-checker-observation.v1",
        "sandbox": {
            "role": SandboxRole.ORACLE.value,
            "microvm_id": ORACLE.microvm_id,
        },
        "container_sha256": _oracle_container().sha256,
        "action_registry_sha256": _registry_digest(),
        "candidate_path": str(CANDIDATE_PATH),
        "observed_digest_before": CANDIDATE_DIGEST,
        "observed_digest_after": CANDIDATE_DIGEST,
        "engine_identity_sha256": ORACLE_ENGINE_IDENTITY_SHA256,
        "private_engine": True,
        "host_engine_reachable": False,
        "shared_socket": False,
        "docker_socket_probe_path": str(DOCKER_SOCKET_PATH),
        "docker_socket_probe_errno": errno.ENOENT,
        "agent_docker_socket_execution_record_sha256": docker_socket_record.sha256,
        "checker_result": {
            "returncode": 0,
            "stdout": "oracle complete",
            "stderr": "",
            "timed_out": False,
            "truncated": False,
        },
    }
    for record in (
        agent_request,
        oracle_request,
        agent_create,
        oracle_create,
        engine_identity,
        checker,
    ):
        assert isinstance(record.canonical_payload, bytes)
        assert record.sha256 == sha256(record.canonical_payload).hexdigest()
    assert (
        len(
            {
                agent_request.sha256,
                oracle_request.sha256,
                agent_create.sha256,
                oracle_create.sha256,
                engine_identity.sha256,
                checker.sha256,
            }
        )
        == 6
    )


def test_r6_oracle_boundary_probe() -> None:
    facts, executor = _boundary_run()
    trace = facts.execution_trace
    agent_request, oracle_request = executor.create_requests
    agent_create, oracle_create = executor.create_observations
    engine_identity_observation = executor.engine_identity_observations[0]
    checker_observation = executor.checker_observations[0]

    assert validate_oracle_boundary(facts) is None
    assert not hasattr(facts, "verified")
    assert trace.schema_version == "roguepatch.f1-execution-trace.v1"
    assert trace == executor.execution_trace
    assert [record.action_id for record in trace.records] == list(TRACE_ACTION_IDS)
    assert len(trace.records) == 20
    assert [record.sequence for record in trace.records] == list(
        range(1, len(TRACE_ACTION_IDS) + 1)
    )
    assert trace.records[0].prev_record_sha256 == F1_TRACE_GENESIS_SHA256
    assert all(
        record.prev_record_sha256 == trace.records[index - 1].sha256
        for index, record in enumerate(trace.records[1:], start=1)
    )
    assert [record.microvm_role for record in trace.records] == [
        *([SandboxRole.AGENT] * (len(CANONICAL_PROTECTED_TARGETS) + 3)),
        *([SandboxRole.ORACLE] * 4),
    ]
    assert [record.microvm_id for record in trace.records] == [
        *([AGENT.microvm_id] * (len(CANONICAL_PROTECTED_TARGETS) + 3)),
        *([ORACLE.microvm_id] * 4),
    ]
    assert all(record.status is F1ExecutionStatus.SUCCEEDED for record in trace.records)
    assert len({record.sha256 for record in trace.records}) == len(trace.records)
    assert len(executor.calls) == len(trace.records)
    assert facts.create_requests == (agent_request, oracle_request)
    assert facts.create_observations == (agent_create, oracle_create)
    assert facts.engine_identity_observation == engine_identity_observation
    assert facts.checker_observation == checker_observation
    assert agent_request.role is SandboxRole.AGENT
    assert agent_request.agent_spec == _agent_spec()
    assert agent_request.oracle_container is None
    assert agent_request.action_registry_sha256 == facts.action_registry_sha256
    assert agent_request.private_engine is False
    assert oracle_request.role is SandboxRole.ORACLE
    assert oracle_request.agent_spec is None
    assert oracle_request.oracle_container == _oracle_container()
    assert oracle_request.action_registry_sha256 == facts.action_registry_sha256
    assert oracle_request.private_engine is True
    assert agent_create.sandbox == facts.agent
    assert agent_create.request_sha256 == agent_request.sha256
    assert not hasattr(agent_create, "engine_identity_sha256")
    assert oracle_create.sandbox == facts.oracle
    assert oracle_create.request_sha256 == oracle_request.sha256
    assert not hasattr(oracle_create, "engine_identity_sha256")
    assert engine_identity_observation.sandbox == facts.oracle
    assert (
        engine_identity_observation.action_registry_sha256
        == facts.action_registry_sha256
    )
    assert (
        engine_identity_observation.engine_identity_sha256
        == ORACLE_ENGINE_IDENTITY_SHA256
    )
    assert engine_identity_observation.identity_result.stdout == ORACLE_ENGINE_IDENTITY
    assert (
        engine_identity_observation.identity_result.stdout
        == engine_identity_observation.identity_result.stdout.strip()
    )
    assert (
        engine_identity_observation.engine_identity_sha256
        == sha256(
            engine_identity_observation.identity_result.stdout.encode()
        ).hexdigest()
    )
    assert engine_identity_observation.identity_result.succeeded
    assert checker_observation.sandbox == facts.oracle
    assert checker_observation.container == facts.container
    assert checker_observation.action_registry_sha256 == facts.action_registry_sha256
    assert checker_observation.candidate_path == CANDIDATE_PATH
    assert checker_observation.observed_digest_before == CANDIDATE_DIGEST
    assert checker_observation.observed_digest_after == CANDIDATE_DIGEST
    assert (
        checker_observation.engine_identity_sha256
        == engine_identity_observation.engine_identity_sha256
    )
    assert checker_observation.private_engine is True
    assert checker_observation.host_engine_reachable is False
    assert checker_observation.shared_socket is False
    assert checker_observation.docker_socket_probe_path == DOCKER_SOCKET_PATH
    assert checker_observation.docker_socket_probe_errno in {errno.ENOENT, errno.EACCES}
    docker_socket_record = next(
        record
        for record in facts.execution_records
        if record.target == ProtectedTarget.DOCKER_SOCKET.value
    )
    assert (
        checker_observation.agent_docker_socket_execution_record_sha256
        == docker_socket_record.sha256
    )
    assert checker_observation.checker_result.succeeded
    assert (
        next(
            record
            for record in trace.records
            if record.action_id == AGENT_CREATE_ACTION_ID
        ).result_digest
        == agent_create.sha256
    )
    assert (
        next(
            record
            for record in trace.records
            if record.action_id == ORACLE_CREATE_ACTION_ID
        ).result_digest
        == oracle_create.sha256
    )
    assert (
        next(
            record
            for record in trace.records
            if record.action_id == ORACLE_ENGINE_IDENTITY_ACTION_ID
        ).result_digest
        == engine_identity_observation.sha256
    )
    assert (
        next(
            record
            for record in trace.records
            if record.action_id == ORACLE_CHECKER_ACTION_ID
        ).result_digest
        == checker_observation.sha256
    )
    for record, (action, registry_digest, sandbox) in zip(
        trace.records, executor.calls, strict=True
    ):
        assert action == _registered_action(record.action_id)
        assert action.command == _registered_action(record.action_id).command
        assert record.command_spec_digest == approval._command_spec_sha256(
            action.command
        )
        assert record.action_registry_sha256 == registry_digest == _registry_digest()
        assert record.microvm_role is sandbox.role
        assert record.microvm_id == sandbox.microvm_id
        assert len(record.result_digest) == 64
    assert facts.source_read_only is True
    assert SOURCE_DIGEST != CANDIDATE_DIGEST
    assert facts.workspace_mode is WorkspaceMode.PRIVATE_CLONE
    assert facts.agent_cwd == AGENT_WORKSPACE
    assert facts.agent_cwd != SOURCE_TARGET
    assert dict(facts.probe_command_spec_digests) == _probe_command_spec_digests()
    assert {spec.target for spec in facts.probe_specs} == set(ProtectedTarget)
    assert {observation.target for observation in facts.probe_observations} == set(
        ProtectedTarget
    )
    assert len(ProtectedTarget) == 13
    assert len(facts.execution_records) == len(ProtectedTarget)

    specs = {spec.target: spec for spec in facts.probe_specs}
    records = {record.sha256: record for record in facts.execution_records}
    for observation in facts.probe_observations:
        spec = specs[observation.target]
        record = records[observation.execution_record_sha256]
        assert isinstance(observation, ProtectedProbeObservation)
        assert spec.probe_path == PROTECTED_PROBE_PATHS[spec.target]
        assert spec.action_id == PROTECTED_PROBE_ACTION_IDS[spec.target]
        assert spec.command_spec_digest == facts.probe_command_spec_digests[spec.target]
        assert observation.probe_path == spec.probe_path
        assert record.target == observation.target.value
        assert record.probe_path == observation.probe_path
        assert observation.spec_sha256 == spec.sha256
        assert spec.action_registry_sha256 == facts.action_registry_sha256
        assert observation.microvm_id == facts.agent.microvm_id
        assert observation.action_id == spec.action_id == record.action_id
        assert observation.command_spec_digest == spec.command_spec_digest
        assert observation.command_spec_digest == record.command_spec_digest
        assert record.action_registry_sha256 == facts.action_registry_sha256
        assert observation.result_digest == record.result_digest
        assert observation.observed_errno == record.observed_errno
        assert observation.observed_errno in {errno.ENOENT, errno.EACCES}
        assert record.read_only is True

    host_canary = facts.probe_observations[0]
    source_mount = host_canary.source_mount_observation
    assert source_mount == executor.source_mount_observations[0]
    assert source_mount is not None
    assert source_mount.sandbox == facts.agent
    assert source_mount.mount_path == SOURCE_TARGET
    assert source_mount.git_top_level == SOURCE_TARGET
    assert (
        source_mount.source_path_proof_sha256
        == agent_request.agent_spec.source_path_proof.sha256
    )
    assert (
        source_mount.git_commit == agent_request.agent_spec.source_path_proof.git_commit
    )
    assert (
        source_mount.git_tree_digest
        == agent_request.agent_spec.source_path_proof.git_tree_digest
    )
    assert source_mount.read_only is True
    assert source_mount.execution_record_sha256 == facts.execution_records[0].sha256
    host_canary_result_payload = _host_canary_result_payload(
        target=host_canary.target,
        observed_errno=host_canary.observed_errno,
        sandbox=source_mount.sandbox,
        mount_path=source_mount.mount_path,
        git_top_level=source_mount.git_top_level,
        source_path_proof_sha256=source_mount.source_path_proof_sha256,
        git_commit=source_mount.git_commit,
        git_tree_digest=source_mount.git_tree_digest,
        read_only=source_mount.read_only,
    )
    assert b"execution_record_sha256" not in host_canary_result_payload
    assert (
        facts.execution_records[0].result_digest
        == sha256(host_canary_result_payload).hexdigest()
    )
    assert host_canary.result_digest == facts.execution_records[0].result_digest
    assert all(
        observation.source_mount_observation is None
        for observation in facts.probe_observations[1:]
    )

    assert [record.action for record in facts.lifecycle] == [
        SandboxLifecycleAction.CREATE,
        SandboxLifecycleAction.FREEZE,
        SandboxLifecycleAction.DESTROY,
        SandboxLifecycleAction.CREATE,
    ]
    assert [record.sequence for record in facts.lifecycle] == [1, 2, 3, 4]
    assert len({record.sha256 for record in facts.lifecycle}) == 4
    assert all(
        record.action_registry_sha256 == facts.action_registry_sha256
        for record in facts.lifecycle
    )
    assert facts.lifecycle[0].sandbox == facts.agent
    assert facts.lifecycle[1].candidate_digest == CANDIDATE_DIGEST
    assert facts.lifecycle[2].sandbox == facts.agent
    assert facts.lifecycle[3].sandbox == facts.oracle
    assert facts.lifecycle[3].limits.cpu_count == 2
    assert facts.lifecycle[3].limits.memory_mib == 2048
    assert facts.lifecycle[3].private_engine is True
    assert facts.agent.microvm_id != facts.oracle.microvm_id
    assert facts.engine_shared is False
    assert facts.container.image_digest == ORACLE_IMAGE
    assert facts.container.network is NetworkMode.NONE
    assert facts.container.rootfs_read_only is True
    assert facts.container.candidate_read_only is True
    assert facts.container.capabilities == ()
    assert facts.container.no_new_privileges is True
    assert facts.container.secrets == ()
    assert facts.container.model_credentials == ()
    assert facts.container.docker_socket is False
    assert facts.container.limits.cpu_count == 2
    assert facts.container.limits.memory_mib == 2048
    assert facts.candidate_digest_before == facts.candidate_digest_after


@pytest.mark.parametrize(
    ("defect", "failed_role"),
    [
        pytest.param("request-digest", SandboxRole.AGENT, id="request-digest"),
        pytest.param("agent-spec", SandboxRole.AGENT, id="agent-spec"),
        pytest.param("request-registry", SandboxRole.AGENT, id="request-registry"),
        pytest.param("create-trace", SandboxRole.AGENT, id="create-trace"),
        pytest.param("agent-sandbox", SandboxRole.AGENT, id="agent-sandbox"),
        pytest.param(
            "oracle-request-digest",
            SandboxRole.ORACLE,
            id="oracle-request-digest",
        ),
        pytest.param(
            "oracle-request-registry",
            SandboxRole.ORACLE,
            id="oracle-request-registry",
        ),
        pytest.param(
            "oracle-create-trace",
            SandboxRole.ORACLE,
            id="oracle-create-trace",
        ),
        pytest.param(
            "oracle-sandbox",
            SandboxRole.ORACLE,
            id="oracle-sandbox",
        ),
        pytest.param(
            "oracle-container",
            SandboxRole.ORACLE,
            id="oracle-container",
        ),
        pytest.param("agent-create-failed", SandboxRole.AGENT, id="agent-failed"),
        pytest.param("agent-create-timeout", SandboxRole.AGENT, id="agent-timeout"),
        pytest.param(
            "agent-create-truncated",
            SandboxRole.AGENT,
            id="agent-truncated",
        ),
        pytest.param(
            "oracle-create-failed",
            SandboxRole.ORACLE,
            id="oracle-failed",
        ),
        pytest.param(
            "oracle-create-timeout",
            SandboxRole.ORACLE,
            id="oracle-timeout",
        ),
        pytest.param(
            "oracle-create-truncated",
            SandboxRole.ORACLE,
            id="oracle-truncated",
        ),
    ],
)
def test_r6_create_binding_mutants_fail_closed_and_cleanup(
    defect: str,
    failed_role: SandboxRole,
) -> None:
    def mutate_request(request: SandboxCreateRequest) -> SandboxCreateRequest:
        if defect == "agent-spec" and request.role is SandboxRole.AGENT:
            assert request.agent_spec is not None
            changed_record = replace(
                request.agent_spec.source_resolution_record,
                result_digest=OTHER_DIGEST,
            )
            changed_proof = replace(
                request.agent_spec.source_path_proof,
                result_digest=OTHER_DIGEST,
                execution_record_sha256=changed_record.sha256,
            )
            return replace(
                request,
                agent_spec=replace(
                    request.agent_spec,
                    source_path_proof=changed_proof,
                    source_resolution_record=changed_record,
                    source_digest=OTHER_TREE_DIGEST,
                    approved_source_digest=OTHER_TREE_DIGEST,
                ),
            )
        if defect == "request-registry" and request.role is SandboxRole.AGENT:
            return replace(request, action_registry_sha256=OTHER_DIGEST)
        if defect == "oracle-request-registry" and request.role is SandboxRole.ORACLE:
            return replace(request, action_registry_sha256=OTHER_DIGEST)
        if defect == "oracle-container" and request.role is SandboxRole.ORACLE:
            assert request.oracle_container is not None
            return replace(
                request,
                oracle_container=replace(
                    request.oracle_container,
                    image_digest=OTHER_ORACLE_IMAGE,
                ),
            )
        return request

    def mutate_observation(
        observation: SandboxCreateObservation,
    ) -> SandboxCreateObservation:
        if defect == "request-digest" and observation.sandbox.role is SandboxRole.AGENT:
            return replace(observation, request_sha256=OTHER_DIGEST)
        if (
            defect == "oracle-request-digest"
            and observation.sandbox.role is SandboxRole.ORACLE
        ):
            return replace(observation, request_sha256=OTHER_DIGEST)
        if defect == "agent-sandbox" and observation.sandbox.role is SandboxRole.AGENT:
            return replace(
                observation,
                sandbox=SandboxRef(
                    role=SandboxRole.AGENT,
                    microvm_id="sbx-agent-misbound",
                ),
            )
        if (
            defect == "oracle-sandbox"
            and observation.sandbox.role is SandboxRole.ORACLE
        ):
            return replace(
                observation,
                sandbox=SandboxRef(
                    role=SandboxRole.ORACLE,
                    microvm_id="sbx-oracle-misbound",
                ),
            )
        return observation

    create_result: CommandResult | None = None
    if defect.endswith("create-failed"):
        create_result = CommandResult(
            returncode=1,
            stdout="",
            stderr="synthetic create failure",
            timed_out=False,
            truncated=False,
        )
    elif defect.endswith("create-timeout"):
        create_result = CommandResult(
            returncode=None,
            stdout="",
            stderr="synthetic create timeout",
            timed_out=True,
            truncated=False,
        )
    elif defect.endswith("create-truncated"):
        create_result = CommandResult(
            returncode=0,
            stdout="partial create output",
            stderr="",
            timed_out=False,
            truncated=True,
        )
    create_trace_role = (
        failed_role if defect in {"create-trace", "oracle-create-trace"} else None
    )

    executor = F1ExecutorSpy(
        create_request_mutator=mutate_request,
        create_observation_mutator=mutate_observation,
        create_trace_result_digests=(
            {create_trace_role: OTHER_DIGEST} if create_trace_role is not None else None
        ),
        create_results=(
            {failed_role: create_result} if create_result is not None else None
        ),
    )

    with pytest.raises((SandboxUnavailable, ValueError)):
        _run_f1(gate=_live_gate(), executor=executor)

    expected_actions = (
        [AGENT_CREATE_ACTION_ID, AGENT_DESTROY_ACTION_ID]
        if failed_role is SandboxRole.AGENT
        else [
            *AGENT_TRACE_ACTION_IDS,
            ORACLE_CREATE_ACTION_ID,
            ORACLE_DESTROY_ACTION_ID,
        ]
    )
    assert _action_ids(executor) == expected_actions
    assert expected_actions[-1] == f"g1.sbx.{failed_role.value}.destroy"
    for request in executor.create_requests:
        _assert_destroy_matches_create_observation(executor, request.role)
    if defect.endswith("-sandbox"):
        create_observation = executor.create_observations[-1]
        create_trace = next(
            record
            for record in executor.trace_records
            if record.action_id == f"g1.sbx.{failed_role.value}.create"
        )
        assert create_observation.sandbox.role is failed_role
        assert create_trace.microvm_id != create_observation.sandbox.microvm_id
    if create_result is not None:
        create_trace = next(
            record
            for record in executor.trace_records
            if record.action_id == f"g1.sbx.{failed_role.value}.create"
        )
        assert create_trace.status is F1ExecutionStatus.FAILED
    _assert_only_registered_sbx_calls(executor)


@pytest.mark.parametrize(
    "defect",
    [
        "naked-command-result",
        "engine-trace-digest",
        "oracle-microvm",
        "action-registry",
        "result-identity-mismatch",
        "engine-failed",
        "engine-timeout",
        "engine-truncated",
    ],
)
def test_r6_engine_identity_observation_mutants_fail_closed_and_cleanup(
    defect: str,
) -> None:
    def mutate_observation(
        observation: OracleEngineIdentityObservation,
    ) -> OracleEngineIdentityObservation | CommandResult:
        if defect == "naked-command-result":
            return observation.identity_result
        if defect == "oracle-microvm":
            return replace(
                observation,
                sandbox=SandboxRef(
                    role=SandboxRole.ORACLE,
                    microvm_id="sbx-oracle-engine-misbound",
                ),
            )
        if defect == "action-registry":
            return replace(observation, action_registry_sha256=OTHER_DIGEST)
        return observation

    identity_result: CommandResult | None = None
    if defect == "result-identity-mismatch":
        identity_result = CommandResult(
            returncode=0,
            stdout=OTHER_ORACLE_ENGINE_IDENTITY,
            stderr="",
            timed_out=False,
            truncated=False,
        )
    elif defect == "engine-failed":
        identity_result = CommandResult(
            returncode=1,
            stdout=ORACLE_ENGINE_IDENTITY,
            stderr="synthetic engine identity failure",
            timed_out=False,
            truncated=False,
        )
    elif defect == "engine-timeout":
        identity_result = CommandResult(
            returncode=None,
            stdout=ORACLE_ENGINE_IDENTITY,
            stderr="synthetic engine identity timeout",
            timed_out=True,
            truncated=False,
        )
    elif defect == "engine-truncated":
        identity_result = CommandResult(
            returncode=0,
            stdout=ORACLE_ENGINE_IDENTITY,
            stderr="",
            timed_out=False,
            truncated=True,
        )
    executor = F1ExecutorSpy(
        engine_identity_observation_mutator=mutate_observation,
        engine_identity_trace_result_digest=(
            OTHER_DIGEST if defect == "engine-trace-digest" else None
        ),
        engine_identity_result=identity_result,
    )

    with pytest.raises((OracleCheckFailed, TypeError, ValueError)):
        _run_f1(gate=_live_gate(), executor=executor)

    expected_actions = [
        *AGENT_TRACE_ACTION_IDS,
        ORACLE_CREATE_ACTION_ID,
        ORACLE_ENGINE_IDENTITY_ACTION_ID,
        ORACLE_DESTROY_ACTION_ID,
    ]
    assert _action_ids(executor) == expected_actions
    assert executor.trace_records[-2].action_id == ORACLE_ENGINE_IDENTITY_ACTION_ID
    assert executor.trace_records[-1].action_id == ORACLE_DESTROY_ACTION_ID
    assert executor.trace_records[-1].status is F1ExecutionStatus.SUCCEEDED
    _assert_destroy_matches_create_observation(executor, SandboxRole.AGENT)
    _assert_destroy_matches_create_observation(executor, SandboxRole.ORACLE)
    _assert_only_registered_sbx_calls(executor)


@pytest.mark.parametrize(
    "defect",
    [
        "naked-command-result",
        "checker-trace-digest",
        "oracle-microvm",
        "container",
        "candidate-path",
        "engine-identity",
        "action-registry",
        "docker-probe-path",
        "docker-probe-errno",
        "docker-execution-record",
        "candidate-before",
        "candidate-after",
        "engine-not-private",
        "host-engine-reachable",
        "shared-socket",
        "checker-failed",
        "checker-timeout",
        "checker-truncated",
    ],
)
def test_r6_checker_observation_mutants_fail_closed_and_cleanup(defect: str) -> None:
    def mutate_observation(
        observation: OracleCheckerObservation,
    ) -> OracleCheckerObservation | CommandResult:
        if defect == "naked-command-result":
            return observation.checker_result
        if defect == "oracle-microvm":
            return replace(
                observation,
                sandbox=SandboxRef(
                    role=SandboxRole.ORACLE,
                    microvm_id="sbx-oracle-checker-misbound",
                ),
            )
        if defect == "container":
            return replace(
                observation,
                container=replace(
                    observation.container,
                    image_digest=OTHER_ORACLE_IMAGE,
                ),
            )
        if defect == "candidate-path":
            return replace(
                observation,
                candidate_path=PurePosixPath("/tmp/candidate"),
            )
        if defect == "engine-identity":
            return replace(
                observation,
                engine_identity_sha256=OTHER_ORACLE_ENGINE_IDENTITY_SHA256,
            )
        if defect == "action-registry":
            return replace(observation, action_registry_sha256=OTHER_DIGEST)
        if defect == "docker-probe-path":
            return replace(
                observation,
                docker_socket_probe_path=PurePosixPath("/tmp/docker.sock"),
            )
        if defect == "docker-probe-errno":
            docker_socket_record = next(
                record
                for record in executor.probe_execution_records
                if record.target == ProtectedTarget.DOCKER_SOCKET.value
            )
            other_allowed_errno = (
                errno.EACCES
                if docker_socket_record.observed_errno == errno.ENOENT
                else errno.ENOENT
            )
            assert other_allowed_errno in {errno.ENOENT, errno.EACCES}
            assert other_allowed_errno != docker_socket_record.observed_errno
            return replace(
                observation,
                docker_socket_probe_errno=other_allowed_errno,
            )
        if defect == "docker-execution-record":
            host_canary_record = next(
                record
                for record in executor.probe_execution_records
                if record.target == ProtectedTarget.HOST_CANARY.value
            )
            assert host_canary_record.sha256 != (
                observation.agent_docker_socket_execution_record_sha256
            )
            return replace(
                observation,
                agent_docker_socket_execution_record_sha256=host_canary_record.sha256,
            )
        if defect == "candidate-before":
            return replace(observation, observed_digest_before=SOURCE_DIGEST)
        if defect == "candidate-after":
            return replace(observation, observed_digest_after=SOURCE_DIGEST)
        if defect == "engine-not-private":
            return replace(observation, private_engine=False)
        if defect == "host-engine-reachable":
            return replace(observation, host_engine_reachable=True)
        if defect == "shared-socket":
            return replace(observation, shared_socket=True)
        return observation

    checker_result: CommandResult | None = None
    if defect == "checker-failed":
        checker_result = CommandResult(
            returncode=1,
            stdout="",
            stderr="synthetic checker failure",
            timed_out=False,
            truncated=False,
        )
    elif defect == "checker-timeout":
        checker_result = CommandResult(
            returncode=None,
            stdout="",
            stderr="synthetic checker timeout",
            timed_out=True,
            truncated=False,
        )
    elif defect == "checker-truncated":
        checker_result = CommandResult(
            returncode=0,
            stdout="truncated",
            stderr="",
            timed_out=False,
            truncated=True,
        )
    executor = F1ExecutorSpy(
        checker_observation_mutator=mutate_observation,
        checker_trace_result_digest=(
            OTHER_DIGEST if defect == "checker-trace-digest" else None
        ),
        checker_result=checker_result,
    )

    with pytest.raises(
        (CandidateMutationError, OracleCheckFailed, TypeError, ValueError)
    ):
        _run_f1(gate=_live_gate(), executor=executor)

    assert _action_ids(executor) == list(TRACE_ACTION_IDS)
    assert executor.trace_records[-2].action_id == ORACLE_CHECKER_ACTION_ID
    assert executor.trace_records[-1].action_id == ORACLE_DESTROY_ACTION_ID
    assert executor.trace_records[-1].status is F1ExecutionStatus.SUCCEEDED
    _assert_destroy_matches_create_observation(executor, SandboxRole.AGENT)
    _assert_destroy_matches_create_observation(executor, SandboxRole.ORACLE)
    _assert_only_registered_sbx_calls(executor)


@pytest.mark.parametrize(
    "invalid_fact",
    [
        "missing-observation",
        "duplicate-observation",
        "missing-spec",
        "duplicate-spec",
        "missing-execution-record",
        "duplicate-execution-record",
        "probe-path-mismatch",
        "execution-target-mismatch",
        "microvm-mismatch",
        "unauthorized-action",
        "command-digest-mismatch",
        "spec-registry-digest-mismatch",
        "execution-registry-digest-mismatch",
        "spec-digest-mismatch",
        "execution-record-digest-mismatch",
        "result-digest-mismatch",
        "invalid-errno",
        "writable-probe",
    ],
)
def test_r6_rejects_unregistered_or_mismatched_probe_evidence(
    invalid_fact: str,
) -> None:
    facts = _boundary_facts()
    first = facts.probe_observations[0]
    first_spec = facts.probe_specs[0]
    first_record = facts.execution_records[0]
    specs = list(facts.probe_specs)
    observations = list(facts.probe_observations)
    records = list(facts.execution_records)

    if invalid_fact == "missing-observation":
        observations.pop()
    elif invalid_fact == "duplicate-observation":
        observations.append(first)
    elif invalid_fact == "missing-spec":
        specs.pop()
    elif invalid_fact == "duplicate-spec":
        specs.append(first_spec)
    elif invalid_fact == "missing-execution-record":
        records.pop()
    elif invalid_fact == "duplicate-execution-record":
        records.append(first_record)
    elif invalid_fact == "probe-path-mismatch":
        changed_spec = replace(first_spec, probe_path=PurePosixPath("/tmp/substituted"))
        changed_record = replace(first_record, probe_path=changed_spec.probe_path)
        specs[0] = changed_spec
        records[0] = changed_record
        observations[0] = replace(
            first,
            probe_path=changed_spec.probe_path,
            spec_sha256=changed_spec.sha256,
            execution_record_sha256=changed_record.sha256,
        )
    elif invalid_fact == "execution-target-mismatch":
        changed_record = replace(first_record, target="unregistered-target")
        records[0] = changed_record
        observations[0] = replace(
            first,
            execution_record_sha256=changed_record.sha256,
        )
    elif invalid_fact == "microvm-mismatch":
        changed_record = replace(first_record, microvm_id=ORACLE.microvm_id)
        records[0] = changed_record
        observations[0] = replace(
            first,
            microvm_id=changed_record.microvm_id,
            execution_record_sha256=changed_record.sha256,
        )
    elif invalid_fact == "unauthorized-action":
        changed_spec = replace(first_spec, action_id="g1.sbx.probe.unregistered")
        changed_record = replace(first_record, action_id=changed_spec.action_id)
        specs[0] = changed_spec
        records[0] = changed_record
        observations[0] = replace(
            first,
            action_id=changed_spec.action_id,
            spec_sha256=changed_spec.sha256,
            execution_record_sha256=changed_record.sha256,
        )
    elif invalid_fact == "command-digest-mismatch":
        changed_spec = replace(first_spec, command_spec_digest=OTHER_DIGEST)
        changed_record = replace(first_record, command_spec_digest=OTHER_DIGEST)
        specs[0] = changed_spec
        records[0] = changed_record
        observations[0] = replace(
            first,
            command_spec_digest=OTHER_DIGEST,
            spec_sha256=changed_spec.sha256,
            execution_record_sha256=changed_record.sha256,
        )
    elif invalid_fact == "spec-registry-digest-mismatch":
        changed_spec = replace(first_spec, action_registry_sha256=OTHER_DIGEST)
        changed_record = replace(first_record, action_registry_sha256=OTHER_DIGEST)
        specs[0] = changed_spec
        records[0] = changed_record
        observations[0] = replace(
            first,
            spec_sha256=changed_spec.sha256,
            execution_record_sha256=changed_record.sha256,
        )
    elif invalid_fact == "execution-registry-digest-mismatch":
        changed_record = replace(
            first_record,
            action_registry_sha256=OTHER_DIGEST,
        )
        records[0] = changed_record
        observations[0] = replace(
            first,
            execution_record_sha256=changed_record.sha256,
        )
    elif invalid_fact == "spec-digest-mismatch":
        observations[0] = replace(first, spec_sha256=_digest("other-spec"))
    elif invalid_fact == "execution-record-digest-mismatch":
        observations[0] = replace(
            first,
            execution_record_sha256=_digest("unregistered-execution"),
        )
    elif invalid_fact == "result-digest-mismatch":
        observations[0] = replace(first, result_digest=_digest("other-result"))
    elif invalid_fact == "invalid-errno":
        changed_record = replace(first_record, observed_errno=0)
        records[0] = changed_record
        observations[0] = replace(
            first,
            observed_errno=0,
            execution_record_sha256=changed_record.sha256,
        )
    elif invalid_fact == "writable-probe":
        changed_record = replace(first_record, read_only=False)
        records[0] = changed_record
        observations[0] = replace(
            first,
            execution_record_sha256=changed_record.sha256,
        )

    facts = replace(
        facts,
        probe_specs=tuple(specs),
        probe_observations=tuple(observations),
        execution_records=tuple(records),
    )
    with pytest.raises(ValueError):
        validate_oracle_boundary(facts)


def _rechain_trace(
    records: list[F1ExecutionTraceRecord],
) -> F1ExecutionTrace:
    chained: list[F1ExecutionTraceRecord] = []
    for sequence, record in enumerate(records, start=1):
        chained.append(
            replace(
                record,
                sequence=sequence,
                prev_record_sha256=(
                    chained[-1].sha256 if chained else F1_TRACE_GENESIS_SHA256
                ),
            )
        )
    return F1ExecutionTrace(records=tuple(chained))


@pytest.mark.parametrize(
    "trace_defect",
    [
        "missing",
        "reordered",
        "duplicate",
        "engine-identity-missing",
        "engine-identity-reordered",
        "engine-identity-duplicate",
        "broken-chain",
        "unregistered",
        "role-mismatch",
        "microvm-id-mismatch",
        "command-digest-mismatch",
        "registry-digest-mismatch",
        "result-digest-mismatch",
        "failed-status",
        "lifecycle-command-digest-mismatch",
        "lifecycle-registry-digest-mismatch",
        "lifecycle-result-digest-mismatch",
        "lifecycle-role-mismatch",
        "lifecycle-microvm-id-mismatch",
    ],
)
def test_r6_rejects_any_noncanonical_or_unbound_physical_trace(
    trace_defect: str,
) -> None:
    facts = _boundary_facts()
    records = list(facts.execution_trace.records)
    if trace_defect == "missing":
        records.pop(1)
    elif trace_defect == "reordered":
        records[1], records[2] = records[2], records[1]
    elif trace_defect == "duplicate":
        records.insert(2, records[1])
    elif trace_defect == "engine-identity-missing":
        records.pop(TRACE_ACTION_IDS.index(ORACLE_ENGINE_IDENTITY_ACTION_ID))
    elif trace_defect == "engine-identity-reordered":
        engine_index = TRACE_ACTION_IDS.index(ORACLE_ENGINE_IDENTITY_ACTION_ID)
        records[engine_index], records[engine_index + 1] = (
            records[engine_index + 1],
            records[engine_index],
        )
    elif trace_defect == "engine-identity-duplicate":
        engine_index = TRACE_ACTION_IDS.index(ORACLE_ENGINE_IDENTITY_ACTION_ID)
        records.insert(engine_index + 1, records[engine_index])
    elif trace_defect == "unregistered":
        records[1] = replace(
            records[1],
            action_id="g1.sbx.unregistered",
            command_spec_digest=OTHER_DIGEST,
        )
    elif trace_defect == "role-mismatch":
        records[1] = replace(records[1], microvm_role=SandboxRole.ORACLE)
    elif trace_defect == "microvm-id-mismatch":
        records[1] = replace(records[1], microvm_id=ORACLE.microvm_id)
    elif trace_defect == "command-digest-mismatch":
        records[1] = replace(records[1], command_spec_digest=OTHER_DIGEST)
    elif trace_defect == "registry-digest-mismatch":
        records[1] = replace(records[1], action_registry_sha256=OTHER_DIGEST)
    elif trace_defect == "result-digest-mismatch":
        records[1] = replace(records[1], result_digest=OTHER_DIGEST)
    elif trace_defect == "failed-status":
        records[1] = replace(records[1], status=F1ExecutionStatus.FAILED)
    elif trace_defect == "lifecycle-command-digest-mismatch":
        records[0] = replace(records[0], command_spec_digest=OTHER_DIGEST)
    elif trace_defect == "lifecycle-registry-digest-mismatch":
        records[0] = replace(records[0], action_registry_sha256=OTHER_DIGEST)
    elif trace_defect == "lifecycle-result-digest-mismatch":
        records[0] = replace(records[0], result_digest=OTHER_DIGEST)
    elif trace_defect == "lifecycle-role-mismatch":
        records[0] = replace(records[0], microvm_role=SandboxRole.ORACLE)
    elif trace_defect == "lifecycle-microvm-id-mismatch":
        records[0] = replace(records[0], microvm_id=ORACLE.microvm_id)

    if trace_defect == "broken-chain":
        with pytest.raises(ValueError):
            records[1] = replace(records[1], prev_record_sha256=OTHER_DIGEST)
            changed_trace = F1ExecutionTrace(records=tuple(records))
            validate_oracle_boundary(replace(facts, execution_trace=changed_trace))
        return

    changed_trace = _rechain_trace(records)
    with pytest.raises(ValueError):
        validate_oracle_boundary(replace(facts, execution_trace=changed_trace))


def test_r6_checker_failure_preserves_primary_error_and_still_destroys_oracle() -> None:
    executor = F1ExecutorSpy(
        failed_result_action_ids=frozenset({ORACLE_CHECKER_ACTION_ID}),
    )

    with pytest.raises(OracleCheckFailed) as raised:
        _run_f1(gate=_live_gate(), executor=executor)

    assert "synthetic oracle failed" in str(raised.value)
    assert not isinstance(raised.value, OracleCleanupError)
    assert _action_ids(executor) == list(TRACE_ACTION_IDS)
    assert executor.trace_records[-2].action_id == ORACLE_CHECKER_ACTION_ID
    assert executor.trace_records[-2].status is F1ExecutionStatus.FAILED
    assert executor.trace_records[-1].action_id == ORACLE_DESTROY_ACTION_ID
    assert executor.trace_records[-1].status is F1ExecutionStatus.SUCCEEDED
    assert executor.trace_records[-1].prev_record_sha256 == (
        executor.trace_records[-2].sha256
    )
    _assert_only_registered_sbx_calls(executor)


def test_r6_failed_agent_destroy_is_traced_kill_with_manual_reference() -> None:
    destroy_failure = RuntimeError("synthetic agent destroy failure")
    executor = F1ExecutorSpy(
        failures={AGENT_DESTROY_ACTION_ID: destroy_failure},
    )

    with pytest.raises(OracleCleanupError) as raised:
        _run_f1(gate=_live_gate(), executor=executor)

    assert raised.value.__cause__ is destroy_failure
    assert raised.value.disposition is BatchDisposition.KILL
    assert raised.value.cleanup_reference == AGENT.microvm_id
    assert raised.value.execution_trace == executor.execution_trace
    assert _action_ids(executor) == list(AGENT_TRACE_ACTION_IDS)
    assert executor.trace_records[-1].action_id == AGENT_DESTROY_ACTION_ID
    assert executor.trace_records[-1].status is F1ExecutionStatus.FAILED
    assert not any(
        record.microvm_role is SandboxRole.ORACLE for record in executor.trace_records
    )
    _assert_only_registered_sbx_calls(executor)


def test_r6_failed_oracle_destroy_is_traced_kill_with_manual_reference() -> None:
    destroy_failure = RuntimeError("synthetic oracle destroy failure")
    executor = F1ExecutorSpy(
        failures={ORACLE_DESTROY_ACTION_ID: destroy_failure},
    )

    with pytest.raises(OracleCleanupError) as raised:
        _run_f1(gate=_live_gate(), executor=executor)

    failed_trace = raised.value.execution_trace
    failed_record = failed_trace.records[-1]
    failed_action, registry_digest, failed_sandbox = executor.calls[-1]
    assert raised.value.__cause__ is destroy_failure
    assert raised.value.disposition is BatchDisposition.KILL
    assert raised.value.cleanup_reference == ORACLE.microvm_id
    assert failed_trace == executor.execution_trace
    assert [record.action_id for record in failed_trace.records] == list(
        TRACE_ACTION_IDS
    )
    assert all(
        record.status is F1ExecutionStatus.SUCCEEDED
        for record in failed_trace.records[:-1]
    )
    assert failed_record.action_id == ORACLE_DESTROY_ACTION_ID
    assert failed_record.status is F1ExecutionStatus.FAILED
    assert failed_record.prev_record_sha256 == failed_trace.records[-2].sha256
    assert failed_action == _registered_action(ORACLE_DESTROY_ACTION_ID)
    assert failed_record.command_spec_digest == approval._command_spec_sha256(
        failed_action.command
    )
    assert failed_record.action_registry_sha256 == registry_digest == _registry_digest()
    assert failed_sandbox is ORACLE
    _assert_only_registered_sbx_calls(executor)


@pytest.mark.parametrize(
    "failed_create",
    [AGENT_CREATE_ACTION_ID, ORACLE_CREATE_ACTION_ID],
)
def test_sandbox_unavailable_create_never_falls_back_to_a_host_executable(
    failed_create: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forbidden_host_calls: list[tuple[object, ...]] = []

    def reject_host_execution(*args: object, **_kwargs: object) -> None:
        forbidden_host_calls.append(args)
        raise AssertionError("host executable fallback is forbidden")

    monkeypatch.setattr(subprocess, "run", reject_host_execution)
    monkeypatch.setattr(subprocess, "Popen", reject_host_execution)
    monkeypatch.setattr(os, "system", reject_host_execution)
    monkeypatch.setattr(os, "popen", reject_host_execution)
    unavailable = SandboxUnavailable(f"synthetic unavailable: {failed_create}")
    executor = F1ExecutorSpy(failures={failed_create: unavailable})

    with pytest.raises(SandboxUnavailable) as raised:
        _run_f1(gate=_live_gate(), executor=executor)

    expected_actions = (
        [AGENT_CREATE_ACTION_ID]
        if failed_create == AGENT_CREATE_ACTION_ID
        else [*AGENT_TRACE_ACTION_IDS, ORACLE_CREATE_ACTION_ID]
    )
    assert raised.value is unavailable
    assert _action_ids(executor) == expected_actions
    assert executor.trace_records[-1].action_id == failed_create
    assert executor.trace_records[-1].status is F1ExecutionStatus.FAILED
    assert forbidden_host_calls == []
    assert not any(
        action_id in _action_ids(executor)
        for action_id in (
            f"{failed_create.rsplit('.', maxsplit=1)[0]}.destroy",
            ORACLE_CHECKER_ACTION_ID,
        )
    )
    _assert_only_registered_sbx_calls(executor)


@pytest.mark.parametrize(
    "invalid_lifecycle",
    [
        "oracle-before-agent-destroy",
        "missing-freeze",
        "shared-microvm",
        "agent-wrong-cpu",
        "agent-wrong-memory",
        "oracle-wrong-cpu",
        "oracle-wrong-memory",
        "oracle-container-wrong-cpu",
        "oracle-container-wrong-memory",
        "oracle-engine-not-private",
        "lifecycle-action-mismatch",
        "lifecycle-registry-mismatch",
        "shared-engine",
    ],
)
def test_r6_rejects_unverifiable_or_overlapping_sandbox_lifecycle(
    invalid_lifecycle: str,
) -> None:
    facts = _boundary_facts()
    lifecycle = list(facts.lifecycle)
    if invalid_lifecycle == "oracle-before-agent-destroy":
        lifecycle[2], lifecycle[3] = (
            replace(lifecycle[3], sequence=3),
            replace(lifecycle[2], sequence=4),
        )
    elif invalid_lifecycle == "missing-freeze":
        lifecycle.pop(1)
        lifecycle = [
            replace(record, sequence=index) for index, record in enumerate(lifecycle, 1)
        ]
    elif invalid_lifecycle == "shared-microvm":
        facts = replace(
            facts,
            oracle=SandboxRef(role=SandboxRole.ORACLE, microvm_id=AGENT.microvm_id),
        )
        lifecycle[3] = replace(lifecycle[3], sandbox=facts.oracle)
    elif invalid_lifecycle == "agent-wrong-cpu":
        lifecycle[0] = replace(
            lifecycle[0],
            limits=ResourceLimits(
                cpu_count=3,
                memory_mib=2048,
                max_output_bytes=131_072,
            ),
        )
    elif invalid_lifecycle == "agent-wrong-memory":
        lifecycle[0] = replace(
            lifecycle[0],
            limits=ResourceLimits(
                cpu_count=2,
                memory_mib=4096,
                max_output_bytes=131_072,
            ),
        )
    elif invalid_lifecycle == "oracle-wrong-cpu":
        lifecycle[3] = replace(
            lifecycle[3],
            limits=ResourceLimits(
                cpu_count=3,
                memory_mib=2048,
                max_output_bytes=131_072,
            ),
        )
    elif invalid_lifecycle == "oracle-wrong-memory":
        lifecycle[3] = replace(
            lifecycle[3],
            limits=ResourceLimits(
                cpu_count=2,
                memory_mib=4096,
                max_output_bytes=131_072,
            ),
        )
    elif invalid_lifecycle == "oracle-container-wrong-cpu":
        facts = replace(
            facts,
            container=replace(
                facts.container,
                limits=ResourceLimits(
                    cpu_count=3,
                    memory_mib=2048,
                    max_output_bytes=131_072,
                ),
            ),
        )
    elif invalid_lifecycle == "oracle-container-wrong-memory":
        facts = replace(
            facts,
            container=replace(
                facts.container,
                limits=ResourceLimits(
                    cpu_count=2,
                    memory_mib=4096,
                    max_output_bytes=131_072,
                ),
            ),
        )
    elif invalid_lifecycle == "oracle-engine-not-private":
        lifecycle[3] = replace(lifecycle[3], private_engine=False)
    elif invalid_lifecycle == "lifecycle-action-mismatch":
        lifecycle[3] = replace(lifecycle[3], action_id="g1.sbx.oracle.unregistered")
    elif invalid_lifecycle == "lifecycle-registry-mismatch":
        lifecycle[3] = replace(
            lifecycle[3],
            action_registry_sha256=OTHER_DIGEST,
        )
    elif invalid_lifecycle == "shared-engine":
        facts = replace(facts, engine_shared=True)

    facts = replace(facts, lifecycle=tuple(lifecycle))
    with pytest.raises(ValueError):
        validate_oracle_boundary(facts)
