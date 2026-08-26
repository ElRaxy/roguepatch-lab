from __future__ import annotations

import inspect
from hashlib import sha256
from pathlib import Path

from roguepatch.adapters.docker_oracle import (
    LiveOracleGateFacts,
    run_f1_oracle_sequence,
    validate_live_oracle_gate,
)
from roguepatch.adapters.sbx_backend import SBX_EXECUTABLE_ALLOWLIST, SbxBackend

from roguepatch import approval
from roguepatch.adapters import docker_oracle
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
    DiskPreflightFacts,
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
    )


def test_live_gate_is_an_inert_validator_bound_to_the_closed_registry() -> None:
    gate = _live_gate()

    assert tuple(inspect.signature(validate_live_oracle_gate).parameters) == ("gate",)
    assert validate_live_oracle_gate(gate=gate) is None
    assert {action.action_id for action in G1_ACTION_REGISTRY} == set(G1_ACTION_IDS)
    assert len(G1_ACTION_REGISTRY) == 17
    assert gate.receipt_binding.action_registry_sha256 == ACTION_REGISTRY_DIGEST
    assert gate.preflight.create_invocations == 0


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
    assert len(runtime_actions) == 16
    assert all(action.command.argv[0] == "sbx" for action in runtime_actions)
    assert all(action.command.shell is False for action in runtime_actions)
