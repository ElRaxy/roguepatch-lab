from __future__ import annotations

import inspect
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from roguepatch import approval
from roguepatch.adapters import docker_oracle
from roguepatch.adapters.docker_oracle import (
    LiveOracleGateError,
    LiveOracleGateFacts,
    run_f1_oracle_sequence,
    validate_live_oracle_gate,
)
from roguepatch.adapters.sbx_backend import SBX_EXECUTABLE_ALLOWLIST, SbxBackend
from roguepatch.approval import (
    G1_ACTION_IDS,
    ApprovalBinding,
    ApprovalState,
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
from roguepatch.ports import CommandSpec

RECEIPT_INSTALL_MIN_KIB = 41_943_040
PRE_CREATE_MIN_KIB = 31_457_280
POST_CREATE_MIN_KIB = 20_971_520
REGISTRY_CWD = Path("/synthetic/roguepatch-live")
MUTATING_ACTION_IDS = frozenset(
    {
        "g1.sbx.agent.create",
        "g1.sbx.agent.destroy",
        "g1.sbx.oracle.create",
        "g1.sbx.oracle.destroy",
    }
)
HOST_IDENTITY = HostIdentity(
    hostname="iMac-de-Alex.local",
    account="alex",
    arch="arm64",
    os_build="24G90",
    boot_session_sha256=sha256(b"synthetic-boot").hexdigest(),
)
HOST_FINGERPRINT = host_identity_sha256(HOST_IDENTITY)


def _command_factory(action_id: str) -> CommandSpec:
    return CommandSpec(
        argv=("sbx", action_id),
        cwd=REGISTRY_CWD,
        env={"PATH": "/synthetic/bin"},
        timeout_seconds=5,
        max_output_bytes=131_072,
        mutating=action_id in MUTATING_ACTION_IDS,
    )


G1_ACTION_REGISTRY = build_g1_action_registry(command_factory=_command_factory)
ACTION_REGISTRY_DIGEST = approval._action_registry_sha256(G1_ACTION_REGISTRY)
ENGINE_IDENTITY_DIGEST = sha256(b"synthetic-private-oracle-engine").hexdigest()
ENGINE_OBSERVATION_DIGEST = sha256(b"synthetic-engine-observation").hexdigest()


def _ready_doctor_report() -> DoctorReport:
    return DoctorReport(
        facts={
            check: CheckFact(check=check, state=CheckState.READY)
            for check in DoctorCheck
        }
    )


def _daemon_isolation_facts() -> DaemonIsolationFacts:
    return DaemonIsolationFacts(
        action_id="g1.sbx.oracle.engine-identity",
        sandbox_role="oracle",
        isolation_scope="microvm",
        oracle_microvm_id="synthetic-oracle-microvm",
        engine_identity_observation_sha256=ENGINE_OBSERVATION_DIGEST,
        engine_identity_trace_result_sha256=ENGINE_OBSERVATION_DIGEST,
        engine_identity_sha256=ENGINE_IDENTITY_DIGEST,
        checker_engine_identity_sha256=ENGINE_IDENTITY_DIGEST,
        action_registry_sha256=ACTION_REGISTRY_DIGEST,
        engine_identity_action_registry_sha256=ACTION_REGISTRY_DIGEST,
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
        action_registry_sha256=ACTION_REGISTRY_DIGEST,
    )
    preflight = LivePreflightFacts(
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
    )
    return LiveOracleGateFacts(
        host_identity=HOST_IDENTITY,
        host_fingerprint_sha256=HOST_FINGERPRINT,
        approval_state=ApprovalState.APPROVED,
        receipt_binding=receipt_binding,
        action_registry_sha256=ACTION_REGISTRY_DIGEST,
        preflight=preflight,
        doctor_report=_ready_doctor_report(),
        daemon_isolation_facts=_daemon_isolation_facts(),
    )


def test_live_gate_is_an_inert_validator_bound_to_the_closed_registry() -> None:
    gate = _live_gate()

    assert tuple(inspect.signature(validate_live_oracle_gate).parameters) == ("gate",)
    assert validate_live_oracle_gate(gate=gate) is None
    assert {action.action_id for action in G1_ACTION_REGISTRY} == set(G1_ACTION_IDS)
    assert len(G1_ACTION_REGISTRY) == 21
    assert gate.receipt_binding.action_registry_sha256 == ACTION_REGISTRY_DIGEST
    assert gate.daemon_isolation_facts.action_registry_sha256 == ACTION_REGISTRY_DIGEST
    assert gate.daemon_isolation_facts.engine_identity_sha256 == ENGINE_IDENTITY_DIGEST
    assert gate.doctor_report.ready is True
    assert gate.preflight.create_invocations == 0


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    (
        ("docker_desktop_observed", True),
        ("host_daemon_accessible", True),
        ("shared_socket_observed", True),
        ("private_engine_observed", False),
        ("engine_identity_trace_result_sha256", "e" * 64),
        ("checker_engine_identity_sha256", "e" * 64),
        ("engine_identity_action_registry_sha256", "f" * 64),
    ),
)
def test_live_gate_rejects_unsafe_or_misbound_r1_daemon_facts(
    field: str,
    unsafe_value: object,
) -> None:
    safe_gate = _live_gate()
    unsafe_facts = replace(
        safe_gate.daemon_isolation_facts,
        **{field: unsafe_value},
    )

    with pytest.raises(
        LiveOracleGateError, match="daemon|engine|Docker|socket|registry"
    ):
        validate_live_oracle_gate(
            gate=replace(safe_gate, daemon_isolation_facts=unsafe_facts)
        )


def test_live_gate_rejects_a_not_ready_doctor_report_without_effects() -> None:
    safe_gate = _live_gate()
    not_ready_report = DoctorReport(
        facts={
            check: CheckFact(
                check=check,
                state=(
                    CheckState.MISSING
                    if check is DoctorCheck.DAEMON
                    else CheckState.READY
                ),
                diagnostic="daemon missing" if check is DoctorCheck.DAEMON else "",
            )
            for check in DoctorCheck
        }
    )

    assert tuple(inspect.signature(validate_live_oracle_gate).parameters) == ("gate",)
    with pytest.raises(LiveOracleGateError, match="doctor|daemon|ready"):
        validate_live_oracle_gate(
            gate=replace(safe_gate, doctor_report=not_ready_report)
        )


def test_live_gate_r1_facts_have_no_default_or_bypass() -> None:
    gate_parameters = inspect.signature(LiveOracleGateFacts).parameters

    assert gate_parameters["doctor_report"].default is inspect.Parameter.empty
    assert gate_parameters["daemon_isolation_facts"].default is inspect.Parameter.empty
    assert "daemon_facts_optional" not in gate_parameters
    assert "allow_host_daemon" not in gate_parameters
    assert "allow_docker_desktop" not in gate_parameters


def test_f1_exposes_no_second_mutating_gate_or_untraced_backend_path() -> None:
    assert not hasattr(docker_oracle, "run_gated_oracle_sequence")
    orchestrator_parameters = inspect.signature(run_f1_oracle_sequence).parameters
    assert {
        "gate",
        "agent_spec",
        "oracle_container",
        "candidate_digest",
        "action_registry",
        "disk_safety",
        "executor",
    }.issubset(orchestrator_parameters)
    assert orchestrator_parameters["gate"].default is inspect.Parameter.empty
    assert orchestrator_parameters["disk_safety"].default is inspect.Parameter.empty
    assert orchestrator_parameters["executor"].default is inspect.Parameter.empty
    backend_parameters = inspect.signature(SbxBackend).parameters
    assert {"action_registry", "trace_sink"}.issubset(backend_parameters)
    assert "fallback" not in orchestrator_parameters
    assert "fallback" not in backend_parameters


def test_sbx_is_the_exact_and_only_runtime_executable() -> None:
    runtime_actions = tuple(
        action
        for action in G1_ACTION_REGISTRY
        if action.action_id != "g1.source.resolve"
    )

    assert SBX_EXECUTABLE_ALLOWLIST == frozenset({"sbx"})
    assert len(runtime_actions) == 20
    assert all(action.command.argv[0] == "sbx" for action in runtime_actions)
    assert all(action.command.shell is False for action in runtime_actions)
