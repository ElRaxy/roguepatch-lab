from __future__ import annotations

import errno
import inspect
import json
import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, fields, replace
from enum import Enum
from hashlib import sha256
from pathlib import Path, PurePath, PurePosixPath
from typing import Literal

import pytest
from roguepatch.adapters.docker_oracle import (
    PROTECTED_PROBE_ACTION_IDS,
    PROTECTED_PROBE_ORDER,
    PROTECTED_PROBE_PATHS,
    LiveOracleGateError,
    LiveOracleGateFacts,
    OracleBoundaryFacts,
    OracleCheckFailed,
    OracleCleanupError,
    OracleContainerSpec,
    ProtectedProbeEvidence,
    ProtectedProbeObservation,
    ProtectedProbeSpec,
    ProtectedTarget,
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

from roguepatch import approval
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
    DiskPreflightFacts,
    LivePreflightFacts,
    SandboxResourceFacts,
)
from roguepatch.ports import CommandResult, CommandSpec

LAB_ROOT = Path("/Users/alex/RoguePatchLab")
SOURCE_REPOSITORY = LAB_ROOT / "fixtures" / "rp-001"
SOURCE_REALPATH = SOURCE_REPOSITORY
SOURCE_DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "f" * 64
ORACLE_IMAGE = "roguepatch-oracle@sha256:" + "b" * 64
SOURCE_TARGET = PurePosixPath("/run/sandbox/source")
AGENT_WORKSPACE = PurePosixPath("/workspace")
AGENT = SandboxRef(role=SandboxRole.AGENT, microvm_id="sbx-agent-1")
ORACLE = SandboxRef(role=SandboxRole.ORACLE, microvm_id="sbx-oracle-1")
RESOLVER_ACTION_ID = "g1.source.resolve"
RESOLVER_RESULT_DIGEST = "e" * 64
REGISTRY_CWD = Path("/synthetic/roguepatch-live")
AGENT_CREATE_ACTION_ID = "g1.sbx.agent.create"
AGENT_FREEZE_ACTION_ID = "g1.sbx.agent.freeze"
AGENT_DESTROY_ACTION_ID = "g1.sbx.agent.destroy"
ORACLE_CREATE_ACTION_ID = "g1.sbx.oracle.create"
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
)
TRACE_ACTION_IDS = (
    AGENT_CREATE_ACTION_ID,
    *(PROTECTED_PROBE_ACTION_IDS[target] for target in CANONICAL_PROTECTED_TARGETS),
    AGENT_FREEZE_ACTION_ID,
    AGENT_DESTROY_ACTION_ID,
    ORACLE_CREATE_ACTION_ID,
    ORACLE_CHECKER_ACTION_ID,
    ORACLE_DESTROY_ACTION_ID,
)
AGENT_TRACE_ACTION_IDS = TRACE_ACTION_IDS[:-3]
EXPECTED_G1_ACTION_IDS = (
    RESOLVER_ACTION_ID,
    *(PROTECTED_PROBE_ACTION_IDS[target] for target in CANONICAL_PROTECTED_TARGETS),
    AGENT_CREATE_ACTION_ID,
    AGENT_FREEZE_ACTION_ID,
    AGENT_DESTROY_ACTION_ID,
    ORACLE_CREATE_ACTION_ID,
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
    assert len(registry) == 17
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


def _resolution_values(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "requested_path": SOURCE_REPOSITORY,
        "source_realpath": SOURCE_REALPATH,
        "lab_realpath": LAB_ROOT,
        "exists": True,
        "contains_parent_reference": False,
        "symlink_components": (),
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
        disk_available_kib: Mapping[tuple[SandboxRole, DiskPhase], int] | None = None,
    ) -> None:
        self.calls: list[tuple[G1HostAction, str, SandboxRef]] = []
        self.trace_records: list[F1ExecutionTraceRecord] = []
        self.disk_decisions: list[DiskSafetyDecision] = []
        self.timeline: list[DiskSafetyDecision | F1ExecutionTraceRecord] = []
        self.execution_nonce = "executor-result-not-present-in-probe-spec"
        self.failures = dict(failures or {})
        self.failed_result_action_ids = failed_result_action_ids or frozenset()
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
    ) -> None:
        assert action == _registered_action(action.action_id)
        assert action.command.argv[0] == "sbx"
        assert action.command.shell is False
        assert action_registry_sha256 == _registry_digest()
        self.calls.append((action, action_registry_sha256, sandbox))
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
        role: SandboxRole,
        limits: ResourceLimits,
        private_engine: bool,
    ) -> SandboxRef:
        assert limits == _limits()
        assert private_engine is (role is SandboxRole.ORACLE)
        sandbox = AGENT if role is SandboxRole.AGENT else ORACLE
        self._emit(
            action=action,
            action_registry_sha256=action_registry_sha256,
            sandbox=sandbox,
            result_digest=_digest(f"executor:{action.action_id}:result"),
        )
        return sandbox

    def execute(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        spec: ProtectedProbeSpec,
        sandbox: SandboxRef,
    ) -> SbxExecRecord:
        assert action.action_id == spec.action_id
        assert approval._command_spec_sha256(action.command) == spec.command_spec_digest
        result_digest = _digest(f"{self.execution_nonce}:{spec.target.value}")
        record = SbxExecRecord(
            target=spec.target.value,
            probe_path=spec.probe_path,
            microvm_id=sandbox.microvm_id,
            action_id=spec.action_id,
            command_spec_digest=spec.command_spec_digest,
            action_registry_sha256=spec.action_registry_sha256,
            result_digest=result_digest,
            observed_errno=(
                errno.EACCES
                if spec.target is ProtectedTarget.SIGNING_MATERIAL
                else errno.ENOENT
            ),
            read_only=True,
        )
        self._emit(
            action=action,
            action_registry_sha256=action_registry_sha256,
            sandbox=sandbox,
            result_digest=result_digest,
        )
        return record

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

    def checker(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        sandbox: SandboxRef,
        container: OracleContainerSpec,
        candidate_digest: str,
    ) -> CommandResult:
        assert sandbox is ORACLE
        assert container == _oracle_container()
        assert candidate_digest == SOURCE_DIGEST
        self._emit(
            action=action,
            action_registry_sha256=action_registry_sha256,
            sandbox=sandbox,
            result_digest=_digest(f"executor:{action.action_id}:result"),
        )
        succeeded = action.action_id not in self.failed_result_action_ids
        return CommandResult(
            returncode=0 if succeeded else 1,
            stdout="oracle complete" if succeeded else "",
            stderr="" if succeeded else "synthetic oracle failed",
            timed_out=False,
            truncated=False,
        )

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
    ["missing-oracle-checker", "missing-oracle-destroy", "duplicate-oracle-destroy"],
)
def test_r6_full_sequence_rejects_an_open_lifecycle_registry_before_execution(
    registry_defect: str,
) -> None:
    registry = set(_g1_action_registry())
    affected_action_id = (
        ORACLE_CHECKER_ACTION_ID
        if registry_defect == "missing-oracle-checker"
        else ORACLE_DESTROY_ACTION_ID
    )
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
            candidate_digest=SOURCE_DIGEST,
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
        candidate_digest=SOURCE_DIGEST,
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
    if defect == "initial-below-40-gib":
        return _live_gate(available_kib=RECEIPT_INSTALL_MIN_KIB - 1)
    raise AssertionError(f"unknown gate defect: {defect}")


def test_f1_orchestrator_requires_gate_and_disk_authority() -> None:
    parameters = inspect.signature(run_f1_oracle_sequence).parameters

    assert parameters["gate"].default is inspect.Parameter.empty
    assert parameters["disk_safety"].default is inspect.Parameter.empty
    assert parameters["executor"].default is inspect.Parameter.empty


@pytest.mark.parametrize(
    "gate_defect",
    [
        "wrong-host",
        "receipt-absent",
        "receipt-misbound",
        "fingerprint-misbound",
        "registry-misbound",
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
    assert proof.lab_realpath == LAB_ROOT
    assert proof.exists is True
    assert proof.contains_parent_reference is False
    assert proof.symlink_components == ()
    assert proof.action_id == RESOLVER_ACTION_ID
    assert proof.command_spec_digest == _registered_command_digest(RESOLVER_ACTION_ID)
    assert proof.action_registry_sha256 == _registry_digest()
    assert proof.result_digest == RESOLVER_RESULT_DIGEST
    assert proof.read_only is True
    assert proof.execution_record_sha256 == record.sha256
    assert record.requested_path == proof.requested_path
    assert record.source_realpath == proof.source_realpath
    assert record.lab_realpath == proof.lab_realpath
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
        return (
            ("sha256:" + OTHER_DIGEST) if value.startswith("sha256:") else OTHER_DIGEST
        )
    if isinstance(value, int):
        return value + 1
    if isinstance(value, tuple):
        return (*value, LAB_ROOT / "different")
    if value is None:
        return SOURCE_DIGEST
    raise AssertionError(f"no identity mutation for {type(value).__name__}")


def test_f1_security_records_use_closed_domain_separated_payloads() -> None:
    proof, source_record = _resolved_source()
    facts = _boundary_facts()
    records = (
        (
            proof,
            {
                "schema_version": "roguepatch.source-path-proof.v1",
                "requested_path": str(proof.requested_path),
                "source_realpath": str(proof.source_realpath),
                "lab_realpath": str(proof.lab_realpath),
                "exists": proof.exists,
                "contains_parent_reference": proof.contains_parent_reference,
                "symlink_components": [str(path) for path in proof.symlink_components],
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
                "lab_realpath": str(source_record.lab_realpath),
                "exists": source_record.exists,
                "contains_parent_reference": source_record.contains_parent_reference,
                "symlink_components": [
                    str(path) for path in source_record.symlink_components
                ],
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


def test_r6_oracle_boundary_probe() -> None:
    facts, executor = _boundary_run()
    trace = facts.execution_trace

    assert validate_oracle_boundary(facts) is None
    assert not hasattr(facts, "verified")
    assert trace.schema_version == "roguepatch.f1-execution-trace.v1"
    assert trace == executor.execution_trace
    assert [record.action_id for record in trace.records] == list(TRACE_ACTION_IDS)
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
        *([SandboxRole.ORACLE] * 3),
    ]
    assert [record.microvm_id for record in trace.records] == [
        *([AGENT.microvm_id] * (len(CANONICAL_PROTECTED_TARGETS) + 3)),
        *([ORACLE.microvm_id] * 3),
    ]
    assert all(record.status is F1ExecutionStatus.SUCCEEDED for record in trace.records)
    assert len({record.sha256 for record in trace.records}) == len(trace.records)
    assert len(executor.calls) == len(trace.records)
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
    assert facts.workspace_mode is WorkspaceMode.PRIVATE_CLONE
    assert facts.agent_cwd == AGENT_WORKSPACE
    assert facts.agent_cwd != SOURCE_TARGET
    assert dict(facts.probe_command_spec_digests) == _probe_command_spec_digests()
    assert {spec.target for spec in facts.probe_specs} == set(ProtectedTarget)
    assert {observation.target for observation in facts.probe_observations} == set(
        ProtectedTarget
    )
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
    assert facts.lifecycle[1].candidate_digest == SOURCE_DIGEST
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
