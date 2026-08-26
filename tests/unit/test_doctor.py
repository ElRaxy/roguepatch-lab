from __future__ import annotations

import importlib.util
import inspect
import json
import os
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from roguepatch import approval
from roguepatch import doctor as doctor_module
from roguepatch.adapters import docker_oracle
from roguepatch.adapters.docker_oracle import (
    SandboxCreateObservation,
    SandboxCreateRequest,
    run_f1_oracle_sequence,
)
from roguepatch.adapters.fake_backend import FakeApprovalStore, FakeCommandProbe
from roguepatch.adapters.sbx_backend import (
    F1ExecutionStatus,
    InMemoryF1TraceSink,
    ResourceLimits,
    SandboxRef,
    SandboxRole,
    SandboxUnavailable,
    SbxBackend,
)
from roguepatch.approval import (
    ApprovalBinding,
    ApprovalState,
    ApprovalStore,
    G1HostAction,
    G1HostBinding,
    HostIdentity,
    host_identity_payload,
    host_identity_sha256,
    run_approved_mutation,
    run_host_approved_mutation,
)
from roguepatch.doctor import (
    CheckState,
    DaemonIsolationFacts,
    DiskPreflightFacts,
    DoctorCheck,
    DoctorProbe,
    LivePreflightFacts,
    PreflightStatus,
    SandboxResourceFacts,
    evaluate_live_preflight,
    run_doctor,
    validate_live_daemon_boundary,
)
from roguepatch.ports import CommandResult, CommandSpec

_FROZEN_F1_PATH = Path(__file__).parents[1] / "acceptance/test_r05_r06_isolation.py"
_FROZEN_F1_SPEC = importlib.util.spec_from_file_location(
    "roguepatch_frozen_f1_contract",
    _FROZEN_F1_PATH,
)
assert _FROZEN_F1_SPEC is not None and _FROZEN_F1_SPEC.loader is not None
frozen_f1 = importlib.util.module_from_spec(_FROZEN_F1_SPEC)
sys.modules[_FROZEN_F1_SPEC.name] = frozen_f1
_FROZEN_F1_SPEC.loader.exec_module(frozen_f1)

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
ABSOLUTE_CWD = Path("/synthetic/roguepatch")
RAW_BOOT_SESSION = "synthetic-boot-session-never-persist"
HOST_IDENTITY = HostIdentity(
    hostname="iMac-de-Alex.local",
    account="alex",
    arch="arm64",
    os_build="24G90",
    boot_session_sha256=sha256(RAW_BOOT_SESSION.encode()).hexdigest(),
)
HOST_FINGERPRINT = host_identity_sha256(HOST_IDENTITY)
ACTION_REGISTRY_DIGEST = "e" * 64
LOW_DISK_AVAILABLE_KIB = 13_736_346
RECEIPT_INSTALL_MIN_KIB = 41_943_040
PRE_CREATE_MIN_KIB = 31_457_280
POST_CREATE_MIN_KIB = 20_971_520


@pytest.fixture(autouse=True)
def _fixed_approval_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(approval, "_alex_uid", lambda: os.getuid(), raising=False)
    monkeypatch.setattr(approval, "_utc_now", lambda: NOW, raising=False)
    monkeypatch.setattr(
        approval,
        "_collect_host_identity",
        lambda: HOST_IDENTITY,
        raising=False,
    )


def _binding() -> ApprovalBinding:
    return ApprovalBinding(
        gate="g1",
        spec_sha256="a" * 64,
        plan_sha256="b" * 64,
        repo_commit="c" * 40,
    )


def _host_binding(
    *,
    host_fingerprint_sha256: str = HOST_FINGERPRINT,
    action_registry_sha256: str = ACTION_REGISTRY_DIGEST,
) -> G1HostBinding:
    return G1HostBinding(
        approval=_binding(),
        host_fingerprint_sha256=host_fingerprint_sha256,
        action_registry_sha256=action_registry_sha256,
    )


def _command(name: str, *, mutating: bool = False) -> CommandSpec:
    return CommandSpec(
        argv=("synthetic-probe", name),
        cwd=ABSOLUTE_CWD,
        env={"PATH": "/synthetic/bin"},
        timeout_seconds=5,
        max_output_bytes=4096,
        mutating=mutating,
    )


def _host_action(
    command: CommandSpec,
    *,
    action_id: str = "g1.sbx.create",
) -> G1HostAction:
    return G1HostAction(action_id=action_id, command=command)


def _result(*, ready: bool = True) -> CommandResult:
    return CommandResult(
        returncode=0 if ready else 1,
        stdout="ready" if ready else "",
        stderr="" if ready else "missing",
        timed_out=False,
        truncated=False,
    )


def _doctor_probes() -> tuple[DoctorProbe, ...]:
    return tuple(
        DoctorProbe(check=check, command=_command(check.value)) for check in DoctorCheck
    )


def _disk_facts(**overrides: object) -> DiskPreflightFacts:
    values: dict[str, object] = {
        "available_kib": LOW_DISK_AVAILABLE_KIB,
        "receipt_install_min_kib": RECEIPT_INSTALL_MIN_KIB,
        "pre_create_min_kib": PRE_CREATE_MIN_KIB,
        "post_create_min_kib": POST_CREATE_MIN_KIB,
    }
    values.update(overrides)
    return DiskPreflightFacts(**values)  # type: ignore[arg-type]


def _resource_facts(**overrides: object) -> SandboxResourceFacts:
    values: dict[str, object] = {
        "host_memory_mib": 8192,
        "sequential": True,
        "vm_cpu_count": 2,
        "vm_memory_mib": 2048,
    }
    values.update(overrides)
    return SandboxResourceFacts(**values)  # type: ignore[arg-type]


def _live_preflight_facts(*, create_invocations: int = 0) -> LivePreflightFacts:
    return LivePreflightFacts(
        disk=_disk_facts(),
        resources=_resource_facts(),
        create_invocations=create_invocations,
    )


def _receipt(
    binding: G1HostBinding,
    *,
    approved_at: datetime = NOW - timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(minutes=10),
) -> dict[str, object]:
    return {
        "schema_version": "1",
        "gate": binding.approval.gate,
        "decision": "approved",
        "approved_by": "alex",
        "approved_at": approved_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "spec_sha256": binding.approval.spec_sha256,
        "plan_sha256": binding.approval.plan_sha256,
        "repo_commit": binding.approval.repo_commit,
        "host_fingerprint_sha256": binding.host_fingerprint_sha256,
        "action_registry_sha256": binding.action_registry_sha256,
    }


def _write_receipt(root: Path, receipt: object, *, mode: int = 0o600) -> Path:
    path = root / "g1.json"
    if isinstance(receipt, str):
        path.write_text(receipt)
    else:
        path.write_text(json.dumps(receipt))
    path.chmod(mode)
    return path


def test_command_spec_is_frozen_and_closes_process_options() -> None:
    env = {"PATH": "/synthetic/bin"}
    command = _command("doctor")
    env["PATH"] = "/mutated"

    assert command.argv == ("synthetic-probe", "doctor")
    assert command.env == {"PATH": "/synthetic/bin"}
    assert command.shell is False
    assert command.cwd.is_absolute()

    with pytest.raises(TypeError, match="tuple"):
        CommandSpec(
            argv=cast(tuple[str, ...], ["not", "a", "tuple"]),
            cwd=ABSOLUTE_CWD,
            env={},
            timeout_seconds=1,
            max_output_bytes=1,
        )
    with pytest.raises(ValueError, match="absolute"):
        CommandSpec(
            argv=("probe",),
            cwd=Path("relative"),
            env={},
            timeout_seconds=1,
            max_output_bytes=1,
        )
    with pytest.raises(ValueError, match="allowlisted"):
        CommandSpec(
            argv=("probe",),
            cwd=ABSOLUTE_CWD,
            env={"SECRET": "not-allowed"},
            timeout_seconds=1,
            max_output_bytes=1,
        )
    with pytest.raises(ValueError, match="shell"):
        CommandSpec(
            argv=("probe",),
            cwd=ABSOLUTE_CWD,
            env={},
            timeout_seconds=1,
            max_output_bytes=1,
            shell=True,
        )


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        pytest.param("timeout_seconds", 0, "timeout", id="zero-timeout"),
        pytest.param("timeout_seconds", 301, "timeout", id="large-timeout"),
        pytest.param("max_output_bytes", 0, "output", id="zero-output"),
        pytest.param("max_output_bytes", 1_048_577, "output", id="large-output"),
    ],
)
def test_command_spec_rejects_unsafe_limits(
    field: str,
    value: int,
    reason: str,
) -> None:
    values: dict[str, object] = {
        "argv": ("probe",),
        "cwd": ABSOLUTE_CWD,
        "env": {},
        "timeout_seconds": 1,
        "max_output_bytes": 1,
    }
    values[field] = value

    with pytest.raises(ValueError, match=reason):
        CommandSpec(**values)  # type: ignore[arg-type]


def test_truncated_command_output_never_counts_as_success() -> None:
    result = CommandResult(
        returncode=0,
        stdout="partial",
        stderr="",
        timed_out=False,
        truncated=True,
    )

    assert result.succeeded is False


def test_doctor_reports_ready_only_when_every_read_only_probe_succeeds() -> None:
    probes = _doctor_probes()
    command_probe = FakeCommandProbe(
        results={probe.command.argv: _result() for probe in probes}
    )

    report = run_doctor(command_probe, probes)

    assert report.ready is True
    assert report.exit_code == 0
    assert all(fact.state is CheckState.READY for fact in report.facts.values())
    assert command_probe.calls == tuple(probe.command for probe in probes)
    assert command_probe.mutating_calls == ()


def test_r1_daemon_ready_requires_private_oracle_engine() -> None:
    probes = _doctor_probes()
    report = run_doctor(
        FakeCommandProbe(
            results={probe.command.argv: _result() for probe in probes},
        ),
        probes,
    )
    registry_digest = "3" * 64
    observation_digest = "1" * 64
    engine_digest = "2" * 64
    facts = DaemonIsolationFacts(
        action_id="g1.sbx.oracle.engine-identity",
        sandbox_role="oracle",
        isolation_scope="microvm",
        oracle_microvm_id="oracle-vm-observed-001",
        engine_identity_observation_sha256=observation_digest,
        engine_identity_trace_result_sha256=observation_digest,
        engine_identity_sha256=engine_digest,
        checker_engine_identity_sha256=engine_digest,
        action_registry_sha256=registry_digest,
        engine_identity_action_registry_sha256=registry_digest,
        private_engine_observed=True,
        docker_desktop_observed=False,
        host_daemon_accessible=False,
        shared_socket_observed=False,
    )

    assert report.ready is True
    assert report.fact_for(DoctorCheck.DAEMON).state is CheckState.READY
    with pytest.raises((TypeError, ValueError), match="daemon|facts|isolation"):
        validate_live_daemon_boundary(report, None)
    assert validate_live_daemon_boundary(report, facts) is None

    rejected_mutations: tuple[tuple[str, object], ...] = (
        ("action_id", "g1.sbx.oracle.checker"),
        ("sandbox_role", "agent"),
        ("isolation_scope", "host"),
        ("oracle_microvm_id", ""),
        ("oracle_microvm_id", "   "),
        ("engine_identity_trace_result_sha256", "4" * 64),
        ("checker_engine_identity_sha256", "4" * 64),
        ("engine_identity_action_registry_sha256", "4" * 64),
        ("private_engine_observed", False),
        ("docker_desktop_observed", True),
        ("host_daemon_accessible", True),
        ("shared_socket_observed", True),
    )
    for field, value in rejected_mutations:
        with pytest.raises(
            ValueError, match="daemon|engine|oracle|microvm|digest|socket"
        ):
            validate_live_daemon_boundary(report, replace(facts, **{field: value}))


def test_doctor_contract_includes_isolation() -> None:
    assert DoctorCheck.ISOLATION.value == "isolation"


def test_low_disk_preflight_derives_blocked_without_any_create() -> None:
    facts = _live_preflight_facts()
    decision = evaluate_live_preflight(facts)

    assert "create_allowed" not in inspect.signature(LivePreflightFacts).parameters
    assert facts.disk.available_kib == LOW_DISK_AVAILABLE_KIB
    assert facts.disk.available_kib / (1024 * 1024) == pytest.approx(13.1)
    assert facts.disk.receipt_install_min_kib == RECEIPT_INSTALL_MIN_KIB
    assert facts.disk.pre_create_min_kib == PRE_CREATE_MIN_KIB
    assert facts.disk.post_create_min_kib == POST_CREATE_MIN_KIB
    assert facts.resources.host_memory_mib == 8192
    assert facts.resources.sequential is True
    assert facts.resources.vm_cpu_count == 2
    assert facts.resources.vm_memory_mib == 2048
    assert facts.create_invocations == 0
    assert decision.status is PreflightStatus.BLOCKED_LOW_DISK
    assert decision.receipt_allowed is False
    assert decision.install_allowed is False
    assert decision.create_allowed is False
    assert decision.post_create_safe is False


def test_preflight_permissions_are_derived_true_at_the_exact_high_watermark() -> None:
    facts = replace(
        _live_preflight_facts(),
        disk=_disk_facts(available_kib=RECEIPT_INSTALL_MIN_KIB),
    )
    decision = evaluate_live_preflight(facts)

    assert decision.status is PreflightStatus.READY
    assert decision.receipt_allowed is True
    assert decision.install_allowed is True
    assert decision.create_allowed is True
    assert decision.post_create_safe is True


@pytest.mark.parametrize(
    ("available_kib", "create_allowed", "post_create_safe"),
    [
        pytest.param(
            PRE_CREATE_MIN_KIB - 1,
            False,
            True,
            id="below-pre-create",
        ),
        pytest.param(
            PRE_CREATE_MIN_KIB,
            True,
            True,
            id="at-pre-create",
        ),
        pytest.param(
            POST_CREATE_MIN_KIB - 1,
            False,
            False,
            id="below-post-create",
        ),
        pytest.param(
            POST_CREATE_MIN_KIB,
            False,
            True,
            id="at-post-create",
        ),
    ],
)
def test_preflight_derives_each_create_disk_boundary(
    available_kib: int,
    create_allowed: bool,
    post_create_safe: bool,
) -> None:
    facts = replace(
        _live_preflight_facts(),
        disk=_disk_facts(available_kib=available_kib),
    )
    decision = evaluate_live_preflight(facts)

    assert decision.create_allowed is create_allowed
    assert decision.post_create_safe is post_create_safe


@pytest.mark.parametrize(
    ("field", "wrong_value"),
    [
        pytest.param(
            "receipt_install_min_kib",
            RECEIPT_INSTALL_MIN_KIB - 1,
            id="receipt-install-threshold",
        ),
        pytest.param(
            "pre_create_min_kib",
            PRE_CREATE_MIN_KIB - 1,
            id="pre-create-threshold",
        ),
        pytest.param(
            "post_create_min_kib",
            POST_CREATE_MIN_KIB - 1,
            id="post-create-threshold",
        ),
    ],
)
def test_disk_preflight_rejects_threshold_drift(
    field: str,
    wrong_value: int,
) -> None:
    with pytest.raises(ValueError):
        _disk_facts(**{field: wrong_value})


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    [
        pytest.param("sequential", False, id="concurrent-vms"),
        pytest.param("vm_cpu_count", 3, id="cpu-drift"),
        pytest.param("vm_memory_mib", 4096, id="memory-drift"),
    ],
)
def test_sandbox_resource_facts_reject_policy_drift(
    field: str,
    unsafe_value: object,
) -> None:
    with pytest.raises(ValueError):
        _resource_facts(**{field: unsafe_value})


def test_low_disk_preflight_kills_if_a_create_was_attempted() -> None:
    decision = evaluate_live_preflight(_live_preflight_facts(create_invocations=1))

    assert decision.status is PreflightStatus.KILL_UNSAFE_CREATE
    assert decision.create_allowed is False


def test_doctor_rejects_a_mutation_disguised_as_an_inspection() -> None:
    disguised_mutations = (
        CommandSpec(
            argv=("docker", "desktop", "start"),
            cwd=ABSOLUTE_CWD,
            env={"PATH": "/synthetic/bin"},
            timeout_seconds=5,
            max_output_bytes=4096,
            mutating=False,
        ),
        CommandSpec(
            argv=("synthetic-probe", "daemon"),
            cwd=ABSOLUTE_CWD,
            env={"PATH": "/attacker-controlled/bin"},
            timeout_seconds=5,
            max_output_bytes=4096,
            mutating=False,
        ),
    )

    for disguised_mutation in disguised_mutations:
        with pytest.raises(ValueError, match="registered read-only command"):
            DoctorProbe(check=DoctorCheck.DAEMON, command=disguised_mutation)


def test_doctor_fails_closed_for_missing_configuration_and_probe_errors() -> None:
    daemon = DoctorProbe(check=DoctorCheck.DAEMON, command=_command("daemon"))

    missing = run_doctor(
        FakeCommandProbe(results={daemon.command.argv: _result()}), [daemon]
    )

    assert missing.exit_code == 2
    assert missing.fact_for(DoctorCheck.SBX).state is CheckState.ERROR

    class BrokenProbe:
        def run(self, command: CommandSpec) -> CommandResult:
            raise OSError(command.argv[0])

    errored = run_doctor(BrokenProbe(), _doctor_probes())

    assert errored.exit_code == 2
    assert all(fact.state is CheckState.ERROR for fact in errored.facts.values())

    class InvalidProbe:
        def run(self, command: CommandSpec) -> CommandResult:
            raise ValueError(command.argv[0])

    invalid = run_doctor(InvalidProbe(), _doctor_probes())

    assert invalid.exit_code == 2
    assert all(fact.state is CheckState.ERROR for fact in invalid.facts.values())


def test_doctor_rejects_mutating_and_duplicate_probe_definitions() -> None:
    with pytest.raises(ValueError, match="read-only"):
        DoctorProbe(
            check=DoctorCheck.DAEMON,
            command=_command("daemon", mutating=True),
        )

    duplicate = DoctorProbe(check=DoctorCheck.DAEMON, command=_command("daemon"))
    with pytest.raises(ValueError, match="duplicate"):
        run_doctor(FakeCommandProbe(results={}), [duplicate, duplicate])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("gate", "g2", id="wrong-gate"),
        pytest.param("spec_sha256", "short", id="short-spec"),
        pytest.param("plan_sha256", "A" * 64, id="uppercase-plan"),
        pytest.param("repo_commit", "short", id="short-commit"),
    ],
)
def test_approval_binding_requires_exact_g1_digests(field: str, value: str) -> None:
    values = {
        "gate": "g1",
        "spec_sha256": "a" * 64,
        "plan_sha256": "b" * 64,
        "repo_commit": "c" * 40,
    }
    values[field] = value

    with pytest.raises(ValueError):
        ApprovalBinding(**values)


@pytest.mark.parametrize(
    "field",
    ["spec_sha256", "plan_sha256", "repo_commit"],
)
def test_approval_binding_rejects_non_text_digests(field: str) -> None:
    values: dict[str, object] = {
        "gate": "g1",
        "spec_sha256": "a" * 64,
        "plan_sha256": "b" * 64,
        "repo_commit": "c" * 40,
    }
    values[field] = 1

    with pytest.raises(TypeError, match=field):
        ApprovalBinding(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("host_fingerprint_sha256", "short", id="short-host"),
        pytest.param("action_registry_sha256", "A" * 64, id="uppercase-registry"),
    ],
)
def test_g1_host_binding_requires_exact_host_and_registry_digests(
    field: str,
    value: str,
) -> None:
    values: dict[str, object] = {
        "approval": _binding(),
        "host_fingerprint_sha256": HOST_FINGERPRINT,
        "action_registry_sha256": ACTION_REGISTRY_DIGEST,
    }
    values[field] = value

    with pytest.raises(ValueError):
        G1HostBinding(**values)  # type: ignore[arg-type]


def test_host_identity_payload_is_domain_separated_and_never_contains_raw_boot() -> (
    None
):
    payload = host_identity_payload(HOST_IDENTITY)
    decoded = json.loads(payload)

    assert list(inspect.signature(HostIdentity).parameters) == [
        "hostname",
        "account",
        "arch",
        "os_build",
        "boot_session_sha256",
    ]
    assert isinstance(payload, bytes)
    assert decoded == {
        "schema_version": "roguepatch.host-fingerprint.v1",
        "hostname": HOST_IDENTITY.hostname,
        "account": HOST_IDENTITY.account,
        "arch": HOST_IDENTITY.arch,
        "os_build": HOST_IDENTITY.os_build,
        "boot_session_sha256": HOST_IDENTITY.boot_session_sha256,
    }
    assert RAW_BOOT_SESSION.encode() not in payload


@pytest.mark.parametrize(
    ("field", "different_value"),
    [
        pytest.param("hostname", "other-host.local", id="hostname"),
        pytest.param("account", "other-account", id="account"),
        pytest.param("arch", "x86_64", id="arch"),
        pytest.param("os_build", "24G91", id="os-build"),
        pytest.param("boot_session_sha256", "f" * 64, id="boot-session"),
    ],
)
def test_host_identity_fingerprint_binds_every_identity_field(
    field: str,
    different_value: str,
) -> None:
    changed = replace(HOST_IDENTITY, **{field: different_value})
    identity_fields = (
        "hostname",
        "account",
        "arch",
        "os_build",
        "boot_session_sha256",
    )

    assert {
        name
        for name in identity_fields
        if getattr(HOST_IDENTITY, name) != getattr(changed, name)
    } == {field}
    assert host_identity_sha256(HOST_IDENTITY) != host_identity_sha256(changed)


def test_host_fingerprint_is_derived_from_the_collected_host_not_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROGUEPATCH_HOSTNAME", "attacker-controlled.local")
    monkeypatch.setenv("ROGUEPATCH_BOOT_SESSION", RAW_BOOT_SESSION)

    assert approval._host_fingerprint_sha256() == host_identity_sha256(HOST_IDENTITY)


def test_production_approval_store_has_no_path_or_environment_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert list(inspect.signature(ApprovalStore).parameters) == []
    assert list(inspect.signature(ApprovalStore().check).parameters) == ["expected"]
    with pytest.raises(TypeError):
        ApprovalStore(Path("/tmp/not-allowed"))  # type: ignore[call-arg]

    monkeypatch.setenv("ROGUEPATCH_APPROVAL_ROOT", "/tmp/not-allowed")

    assert approval._APPROVAL_ROOT == Path("/Users/alex/.codex/roguepatch-approvals")


def test_approval_store_accepts_only_a_current_exact_private_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _host_binding()
    _write_receipt(tmp_path, _receipt(binding))
    monkeypatch.setattr(approval, "_APPROVAL_ROOT", tmp_path)

    assert ApprovalStore().check(binding) is ApprovalState.APPROVED


def test_approval_store_distinguishes_absent_expired_and_misbound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _host_binding()
    monkeypatch.setattr(approval, "_APPROVAL_ROOT", tmp_path)
    store = ApprovalStore()

    assert store.check(binding) is ApprovalState.ABSENT

    _write_receipt(
        tmp_path,
        _receipt(
            binding,
            approved_at=NOW - timedelta(minutes=2),
            expires_at=NOW - timedelta(minutes=1),
        ),
    )
    assert store.check(binding) is ApprovalState.EXPIRED

    changed = _receipt(binding)
    changed["spec_sha256"] = "d" * 64
    _write_receipt(tmp_path, changed)
    assert store.check(binding) is ApprovalState.MISBOUND


@pytest.mark.parametrize(
    "mutation",
    ["public-mode", "unknown-field", "malformed-json", "wrong-owner"],
)
def test_approval_store_fails_closed_on_untrusted_file_metadata_or_shape(
    mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _host_binding()
    receipt = _receipt(binding)
    if mutation == "unknown-field":
        receipt["extra"] = True
    payload: object = "{" if mutation == "malformed-json" else receipt
    path = _write_receipt(
        tmp_path,
        payload,
        mode=0o644 if mutation == "public-mode" else 0o600,
    )
    monkeypatch.setattr(approval, "_APPROVAL_ROOT", tmp_path)
    if mutation == "wrong-owner":
        owner = path.stat().st_uid
        monkeypatch.setattr(approval, "_alex_uid", lambda: owner + 1)

    assert ApprovalStore().check(binding) is ApprovalState.MISBOUND


def test_approval_store_rejects_symlinked_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _host_binding()
    target = tmp_path / "receipt-target.json"
    target.write_text(json.dumps(_receipt(binding)))
    target.chmod(0o600)
    (tmp_path / "g1.json").symlink_to(target)
    monkeypatch.setattr(approval, "_APPROVAL_ROOT", tmp_path)

    assert ApprovalStore().check(binding) is ApprovalState.MISBOUND


def test_approval_store_fails_closed_on_non_utf8_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "g1.json"
    path.write_bytes(b"\xff\xfe\xfd")
    path.chmod(0o600)
    monkeypatch.setattr(approval, "_APPROVAL_ROOT", tmp_path)

    assert ApprovalStore().check(_host_binding()) is ApprovalState.MISBOUND


def test_approval_store_fails_closed_on_invalid_clock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _host_binding()
    _write_receipt(tmp_path, _receipt(binding))
    monkeypatch.setattr(approval, "_APPROVAL_ROOT", tmp_path)
    monkeypatch.setattr(approval, "_utc_now", lambda: cast(datetime, "not-a-datetime"))

    assert ApprovalStore().check(binding) is ApprovalState.MISBOUND


def test_approval_store_rejects_duplicate_json_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _host_binding()
    receipt = _receipt(binding)
    payload = json.dumps(receipt).replace(
        '"decision": "approved"',
        '"decision": "approved", "decision": "approved"',
    )
    _write_receipt(tmp_path, payload)
    monkeypatch.setattr(approval, "_APPROVAL_ROOT", tmp_path)

    assert ApprovalStore().check(binding) is ApprovalState.MISBOUND


def test_approval_store_rejects_timestamp_outside_schema_format(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _host_binding()
    receipt = _receipt(binding)
    receipt["approved_at"] = "2026-08-25 11:59:00+00:00"
    _write_receipt(tmp_path, receipt)
    monkeypatch.setattr(approval, "_APPROVAL_ROOT", tmp_path)

    assert ApprovalStore().check(binding) is ApprovalState.MISBOUND


def test_approved_mutation_invokes_the_injected_probe_once() -> None:
    command = _command("start-sandbox", mutating=True)
    result = _result()
    probe = FakeCommandProbe(results={command.argv: result})
    store = FakeApprovalStore(state=ApprovalState.APPROVED)

    outcome = run_approved_mutation(
        store=store,
        expected=_binding(),
        probe=probe,
        command=command,
    )

    assert outcome.invoked is True
    assert outcome.exit_code == 0
    assert outcome.result is result
    assert probe.calls == (command,)
    assert probe.mutating_calls == (command,)


def test_approved_mutation_rejects_a_read_only_command_before_store_access() -> None:
    store = FakeApprovalStore(state=ApprovalState.APPROVED)

    with pytest.raises(ValueError, match="mutating"):
        run_approved_mutation(
            store=store,
            expected=_binding(),
            probe=FakeCommandProbe(results={}),
            command=_command("doctor"),
        )

    assert store.check_calls == ()


def test_host_mutation_path_does_not_accept_an_injected_approval_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert "store" not in inspect.signature(run_host_approved_mutation).parameters
    command = _command("start-sandbox", mutating=True)
    probe = FakeCommandProbe(results={command.argv: _result()})
    monkeypatch.setattr(approval, "_APPROVAL_ROOT", tmp_path)
    monkeypatch.setattr(
        approval,
        "_G1_HOST_ACTION_REGISTRY",
        frozenset({_host_action(command)}),
    )

    outcome = run_host_approved_mutation(
        expected=_binding(),
        probe=probe,
        command=command,
    )

    assert outcome.approval_state is ApprovalState.ABSENT
    assert outcome.invoked is False
    assert probe.calls == ()


def test_host_mutation_path_rejects_actions_absent_from_the_bound_commit() -> None:
    command = _command("start-sandbox", mutating=True)
    probe = FakeCommandProbe(results={command.argv: _result()})

    with pytest.raises(ValueError, match="registered G1 host action"):
        run_host_approved_mutation(
            expected=_binding(),
            probe=probe,
            command=command,
        )

    assert probe.calls == ()


def test_host_mutation_rejects_a_receipt_copied_from_another_host_before_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = _command("start-sandbox", mutating=True)
    probe = FakeCommandProbe(results={command.argv: _result()})
    registry = frozenset({_host_action(command)})
    monkeypatch.setattr(approval, "_G1_HOST_ACTION_REGISTRY", registry)
    registry_digest = approval._action_registry_sha256()
    copied_host_fingerprint = "f" * 64
    _write_receipt(
        tmp_path,
        _receipt(
            _host_binding(
                host_fingerprint_sha256=copied_host_fingerprint,
                action_registry_sha256=registry_digest,
            )
        ),
    )
    monkeypatch.setattr(approval, "_APPROVAL_ROOT", tmp_path)
    monkeypatch.setenv(
        "ROGUEPATCH_HOST_FINGERPRINT_SHA256",
        copied_host_fingerprint,
    )

    assert (
        "host_fingerprint_sha256"
        not in inspect.signature(run_host_approved_mutation).parameters
    )
    assert (
        "action_registry_sha256"
        not in inspect.signature(run_host_approved_mutation).parameters
    )
    outcome = run_host_approved_mutation(
        expected=_binding(),
        probe=probe,
        command=command,
    )

    assert outcome.approval_state is ApprovalState.MISBOUND
    assert outcome.invoked is False
    assert probe.calls == ()


def test_action_registry_digest_binds_action_id_and_closed_process_payload() -> None:
    command = _command("start-sandbox", mutating=True)
    registered = _host_action(command)
    renamed = _host_action(command, action_id="g1.sbx.create-renamed")
    payload = json.loads(
        approval._canonical_action_registry_payload(frozenset({registered}))
    )

    assert payload == {
        "schema_version": "roguepatch.g1-action-registry.v1",
        "actions": [
            {
                "action_id": "g1.sbx.create",
                "argv": ["synthetic-probe", "start-sandbox"],
                "cwd": str(ABSOLUTE_CWD),
                "env": {"PATH": "/synthetic/bin"},
                "timeout_seconds": 5,
                "max_output_bytes": 4096,
                "mutating": True,
                "shell": False,
            }
        ],
    }
    assert registered.command == renamed.command
    assert approval._action_registry_sha256(
        frozenset({registered})
    ) != approval._action_registry_sha256(frozenset({renamed}))


def test_action_registry_document_orders_actions_by_stable_identifier() -> None:
    later = _host_action(
        _command("later", mutating=True),
        action_id="g1.z-last",
    )
    earlier = _host_action(
        _command("earlier", mutating=True),
        action_id="g1.a-first",
    )
    payload = json.loads(
        approval._canonical_action_registry_payload(frozenset({later, earlier}))
    )

    assert payload["schema_version"] == "roguepatch.g1-action-registry.v1"
    assert [action["action_id"] for action in payload["actions"]] == [
        "g1.a-first",
        "g1.z-last",
    ]


@pytest.mark.parametrize(
    ("field", "different_value"),
    [
        pytest.param(
            "argv",
            ("synthetic-probe", "start-sandbox-renamed"),
            id="argv",
        ),
        pytest.param("cwd", ABSOLUTE_CWD / "alternate", id="cwd"),
        pytest.param(
            "env",
            {"PATH": "/synthetic/alternate-bin"},
            id="env",
        ),
        pytest.param("timeout_seconds", 6, id="timeout"),
        pytest.param("max_output_bytes", 8192, id="max-output"),
    ],
)
def test_action_registry_digest_binds_every_command_identity_field(
    field: str,
    different_value: object,
) -> None:
    baseline = _command("start-sandbox", mutating=True)
    values: dict[str, object] = {
        "argv": baseline.argv,
        "cwd": baseline.cwd,
        "env": dict(baseline.env),
        "timeout_seconds": baseline.timeout_seconds,
        "max_output_bytes": baseline.max_output_bytes,
        "mutating": baseline.mutating,
        "shell": baseline.shell,
    }
    values[field] = different_value
    changed = CommandSpec(**values)  # type: ignore[arg-type]
    identity_fields = (
        "argv",
        "cwd",
        "env",
        "timeout_seconds",
        "max_output_bytes",
    )

    assert {
        name
        for name in identity_fields
        if getattr(baseline, name) != getattr(changed, name)
    } == {field}
    assert changed.mutating is baseline.mutating is True
    assert changed.shell is baseline.shell is False
    assert approval._action_registry_sha256(
        frozenset({_host_action(baseline)})
    ) != approval._action_registry_sha256(frozenset({_host_action(changed)}))


def test_host_mutation_rejects_action_registry_drift_before_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = _command("start-sandbox", mutating=True)
    probe = FakeCommandProbe(results={command.argv: _result()})
    bound_registry = frozenset({_host_action(command)})
    monkeypatch.setattr(approval, "_G1_HOST_ACTION_REGISTRY", bound_registry)
    bound_digest = approval._action_registry_sha256()
    _write_receipt(
        tmp_path,
        _receipt(_host_binding(action_registry_sha256=bound_digest)),
    )
    monkeypatch.setattr(approval, "_APPROVAL_ROOT", tmp_path)
    drifted_registry = frozenset(
        {_host_action(command, action_id="g1.sbx.create-renamed")}
    )
    monkeypatch.setattr(approval, "_G1_HOST_ACTION_REGISTRY", drifted_registry)

    outcome = run_host_approved_mutation(
        expected=_binding(),
        probe=probe,
        command=command,
    )

    assert outcome.approval_state is ApprovalState.MISBOUND
    assert outcome.invoked is False
    assert probe.calls == ()


def test_approval_schema_matches_the_closed_runtime_contract() -> None:
    schema_path = Path(__file__).parents[2] / "schemas" / "approval.schema.json"
    schema = json.loads(schema_path.read_text())

    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == approval._G1_RECEIPT_FIELDS
    assert schema["properties"]["gate"] == {"const": "g1"}
    assert schema["properties"]["decision"] == {"const": "approved"}
    assert schema["properties"]["host_fingerprint_sha256"]["pattern"]
    assert schema["properties"]["action_registry_sha256"]["pattern"]


def _closed_g1_registry(
    *,
    changed_action_id: str | None = None,
    mutated_mutability_action_id: str | None = None,
) -> frozenset[G1HostAction]:
    def command_factory(action_id: str) -> CommandSpec:
        suffix = f"{action_id}-drifted" if action_id == changed_action_id else action_id
        expected_mutating = action_id in frozen_f1.MUTATING_ACTION_IDS
        return CommandSpec(
            argv=("sbx", suffix),
            cwd=ABSOLUTE_CWD,
            env={"PATH": "/synthetic/bin"},
            timeout_seconds=5,
            max_output_bytes=4096,
            mutating=(
                not expected_mutating
                if action_id == mutated_mutability_action_id
                else expected_mutating
            ),
        )

    return approval.build_g1_action_registry(command_factory=command_factory)


def test_g1_registry_accepts_only_the_closed_21_action_mutability_policy() -> None:
    registry = _closed_g1_registry()

    assert len(registry) == 21
    assert {action.action_id for action in registry} == set(approval.G1_ACTION_IDS)
    assert {
        action.action_id for action in registry if action.command.mutating
    } == frozen_f1.MUTATING_ACTION_IDS


@pytest.mark.parametrize("mutated_action_id", approval.G1_ACTION_IDS)
def test_g1_registry_rejects_each_inverted_action_mutability(
    mutated_action_id: str,
) -> None:
    with pytest.raises(ValueError, match="mutating"):
        _closed_g1_registry(mutated_mutability_action_id=mutated_action_id)


def test_public_g1_registry_authority_rejects_partial_registry() -> None:
    registry = _closed_g1_registry()
    partial = frozenset(
        action for action in registry if action.action_id != "g1.sbx.oracle.destroy"
    )
    validator = getattr(approval, "validate_g1_action_registry", lambda _value: None)

    with pytest.raises(ValueError, match="exact closed G1"):
        validator(partial)


def test_public_g1_registry_authority_binds_exact_command_specs() -> None:
    registry = _closed_g1_registry()
    validated = getattr(approval, "validate_g1_action_registry", lambda value: value)(
        registry
    )
    changed = next(
        action
        for action in _closed_g1_registry(changed_action_id="g1.sbx.agent.create")
        if action.action_id == "g1.sbx.agent.create"
    )

    require_action = getattr(validated, "require_action", lambda action: action)
    with pytest.raises(ValueError, match="exactly registered"):
        require_action(changed)


def test_public_digest_api_preserves_frozen_private_compatibility() -> None:
    registry = _closed_g1_registry()
    public_command_digest = getattr(approval, "command_spec_sha256", lambda _value: "")
    public_registry_payload = getattr(
        approval,
        "canonical_action_registry_payload",
        lambda _value: b"",
    )
    public_registry_digest = getattr(
        approval,
        "action_registry_sha256",
        lambda _value: "",
    )
    action = next(iter(registry))

    assert public_command_digest(action.command) == approval._command_spec_sha256(
        action.command
    )
    assert public_registry_payload(
        registry
    ) == approval._canonical_action_registry_payload(registry)
    assert public_registry_digest(registry) == approval._action_registry_sha256(
        registry
    )


def test_source_proof_registry_mismatch_is_rejected_before_create() -> None:
    agent_spec = frozen_f1._agent_spec()
    changed_record = replace(
        agent_spec.source_resolution_record,
        action_registry_sha256=frozen_f1.OTHER_DIGEST,
    )
    changed_proof = replace(
        agent_spec.source_path_proof,
        action_registry_sha256=frozen_f1.OTHER_DIGEST,
        execution_record_sha256=changed_record.sha256,
    )
    changed_spec = replace(
        agent_spec,
        source_path_proof=changed_proof,
        source_resolution_record=changed_record,
    )
    executor = frozen_f1.F1ExecutorSpy()

    with pytest.raises(ValueError, match="source proof.*registry"):
        run_f1_oracle_sequence(
            gate=frozen_f1._live_gate(),
            agent_spec=changed_spec,
            oracle_container=frozen_f1._oracle_container(),
            candidate_digest=frozen_f1.CANDIDATE_DIGEST,
            action_registry=frozen_f1._g1_action_registry(),
            disk_safety=executor,
            executor=executor,
        )

    assert executor.calls == []
    assert executor.disk_decisions == []


@pytest.mark.parametrize(
    "limits",
    [
        ResourceLimits(cpu_count=3, memory_mib=2048, max_output_bytes=131_072),
        ResourceLimits(cpu_count=2, memory_mib=4096, max_output_bytes=131_072),
    ],
)
def test_oracle_exact_limits_are_rejected_before_any_create(
    limits: ResourceLimits,
) -> None:
    executor = frozen_f1.F1ExecutorSpy()
    oracle_container = replace(frozen_f1._oracle_container(), limits=limits)

    with pytest.raises(ValueError, match="exactly 2 CPU and 2048 MiB"):
        run_f1_oracle_sequence(
            gate=frozen_f1._live_gate(),
            agent_spec=frozen_f1._agent_spec(),
            oracle_container=oracle_container,
            candidate_digest=frozen_f1.CANDIDATE_DIGEST,
            action_registry=frozen_f1._g1_action_registry(),
            disk_safety=executor,
            executor=executor,
        )

    assert executor.calls == []
    assert executor.disk_decisions == []


class _InvalidCreateRefExecutor(frozen_f1.F1ExecutorSpy):
    def __init__(self, *, invalid_role: SandboxRole) -> None:
        super().__init__()
        self.invalid_role = invalid_role

    def create(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        request: SandboxCreateRequest,
    ) -> SandboxCreateObservation:
        created = super().create(
            action=action,
            action_registry_sha256=action_registry_sha256,
            request=request,
        )
        if request.role is self.invalid_role:
            wrong_role = (
                SandboxRole.ORACLE
                if request.role is SandboxRole.AGENT
                else SandboxRole.AGENT
            )
            return replace(
                created,
                sandbox=SandboxRef(
                    role=wrong_role,
                    microvm_id=created.sandbox.microvm_id,
                ),
            )
        return created


@pytest.mark.parametrize("role", [SandboxRole.AGENT, SandboxRole.ORACLE])
def test_invalid_create_ref_is_cleaned_up_using_recoverable_identifier(
    role: SandboxRole,
) -> None:
    executor = _InvalidCreateRefExecutor(invalid_role=role)

    with pytest.raises(ValueError, match="create observation is not request-bound"):
        frozen_f1._run_f1(gate=frozen_f1._live_gate(), executor=executor)

    action_ids = [call[0].action_id for call in executor.calls]
    create_id = f"g1.sbx.{role.value}.create"
    destroy_id = f"g1.sbx.{role.value}.destroy"
    assert action_ids[action_ids.index(create_id) + 1] == destroy_id


class _MissingCreateTraceExecutor(frozen_f1.F1ExecutorSpy):
    def create(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        request: SandboxCreateRequest,
    ) -> SandboxCreateObservation:
        created = super().create(
            action=action,
            action_registry_sha256=action_registry_sha256,
            request=request,
        )
        if request.role is SandboxRole.AGENT:
            self.trace_records.pop()
        return created


def test_missing_create_trace_still_cleans_up_agent() -> None:
    executor = _MissingCreateTraceExecutor()

    with pytest.raises(ValueError, match="required trace record"):
        frozen_f1._run_f1(gate=frozen_f1._live_gate(), executor=executor)

    assert [call[0].action_id for call in executor.calls] == [
        frozen_f1.AGENT_CREATE_ACTION_ID,
        frozen_f1.AGENT_DESTROY_ACTION_ID,
    ]


class _MisboundCreateTraceExecutor(frozen_f1.F1ExecutorSpy):
    def create(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        request: SandboxCreateRequest,
    ) -> SandboxCreateObservation:
        created = super().create(
            action=action,
            action_registry_sha256=action_registry_sha256,
            request=request,
        )
        if request.role is SandboxRole.AGENT:
            self.trace_records[-1] = replace(
                self.trace_records[-1],
                action_registry_sha256=frozen_f1.OTHER_DIGEST,
            )
        return created


def test_misbound_create_trace_still_cleans_up_agent() -> None:
    executor = _MisboundCreateTraceExecutor()

    with pytest.raises(ValueError, match="trace is not bound"):
        frozen_f1._run_f1(gate=frozen_f1._live_gate(), executor=executor)

    assert [call[0].action_id for call in executor.calls] == [
        frozen_f1.AGENT_CREATE_ACTION_ID,
        frozen_f1.AGENT_DESTROY_ACTION_ID,
    ]


def test_probe_trace_result_digest_is_bound_to_the_executor_record() -> None:
    facts = frozen_f1._boundary_facts()
    execution_record = facts.execution_records[0]
    changed_result_digest = frozen_f1.OTHER_DIGEST
    assert changed_result_digest != execution_record.result_digest
    trace_records = list(facts.execution_trace.records)
    trace_index = next(
        index
        for index, record in enumerate(trace_records)
        if record.action_id == execution_record.action_id
    )
    trace_records[trace_index] = replace(
        trace_records[trace_index],
        result_digest=changed_result_digest,
    )
    changed_result_digests = dict(facts.action_result_digests)
    changed_result_digests[execution_record.action_id] = changed_result_digest
    changed_trace = frozen_f1._rechain_trace(trace_records)

    with pytest.raises(ValueError, match="probe.*executor|result.*digest"):
        docker_oracle.validate_oracle_boundary(
            replace(
                facts,
                execution_trace=changed_trace,
                action_result_digests=changed_result_digests,
            )
        )


def test_non_host_canary_probe_rejects_mount_digest_without_object() -> None:
    facts = frozen_f1._boundary_facts()
    observations = list(facts.probe_observations)
    probe_index = next(
        index
        for index, observation in enumerate(observations)
        if observation.target is not frozen_f1.ProtectedTarget.HOST_CANARY
    )
    assert observations[probe_index].source_mount_observation is None
    observations[probe_index] = replace(
        observations[probe_index],
        source_mount_observation_sha256=frozen_f1.OTHER_DIGEST,
    )

    with pytest.raises(ValueError, match="source mount.*host-canary|mount.*object"):
        docker_oracle.validate_oracle_boundary(
            replace(facts, probe_observations=tuple(observations))
        )


def test_invalid_create_ref_cleanup_failure_keeps_manual_reference() -> None:
    cleanup_error = RuntimeError("synthetic cleanup failure after invalid ref")
    executor = _InvalidCreateRefExecutor(invalid_role=SandboxRole.AGENT)
    executor.failures[frozen_f1.AGENT_DESTROY_ACTION_ID] = cleanup_error

    with pytest.raises(frozen_f1.OracleCleanupError) as raised:
        frozen_f1._run_f1(gate=frozen_f1._live_gate(), executor=executor)

    assert raised.value.cleanup_reference == frozen_f1.AGENT.microvm_id
    assert raised.value.cleanup_error is cleanup_error
    assert isinstance(raised.value.primary_error, ValueError)


class _PostCreateDiskErrorExecutor(frozen_f1.F1ExecutorSpy):
    def __init__(self, *, failing_role: SandboxRole) -> None:
        super().__init__()
        self.failing_role = failing_role

    def evaluate_disk_safety(
        self,
        *,
        role: SandboxRole,
        phase: frozen_f1.DiskPhase,
        create_invocations: int,
    ) -> frozen_f1.DiskSafetyDecision:
        if role is self.failing_role and phase == "post_create":
            raise RuntimeError(f"synthetic disk authority failure: {role.value}")
        return super().evaluate_disk_safety(
            role=role,
            phase=phase,
            create_invocations=create_invocations,
        )


@pytest.mark.parametrize("role", [SandboxRole.AGENT, SandboxRole.ORACLE])
def test_post_create_disk_authority_exception_still_destroys_vm(
    role: SandboxRole,
) -> None:
    executor = _PostCreateDiskErrorExecutor(failing_role=role)

    with pytest.raises(RuntimeError, match="disk authority failure"):
        frozen_f1._run_f1(gate=frozen_f1._live_gate(), executor=executor)

    action_ids = [call[0].action_id for call in executor.calls]
    create_id = f"g1.sbx.{role.value}.create"
    destroy_id = f"g1.sbx.{role.value}.destroy"
    assert action_ids[action_ids.index(create_id) + 1] == destroy_id


class _AbsentSandboxCreateObservationError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        sandbox: SandboxRef,
        cause: Exception,
    ) -> None:
        super().__init__(message)
        self.sandbox = sandbox
        self.cause = cause


class _PostEffectCreateErrorExecutor(frozen_f1.F1ExecutorSpy):
    def __init__(self, *, failing_role: SandboxRole) -> None:
        super().__init__()
        self.failing_role = failing_role
        self.create_cause = RuntimeError(
            f"synthetic create observation failure: {failing_role.value}"
        )
        self.create_error: RuntimeError | None = None

    def create(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        request: SandboxCreateRequest,
    ) -> SandboxCreateObservation:
        observation = super().create(
            action=action,
            action_registry_sha256=action_registry_sha256,
            request=request,
        )
        if request.role is self.failing_role:
            error_type = getattr(
                docker_oracle,
                "SandboxCreateObservationError",
                _AbsentSandboxCreateObservationError,
            )
            self.create_error = error_type(
                "sandbox effect exists but create observation is unavailable",
                sandbox=observation.sandbox,
                cause=self.create_cause,
            )
            raise self.create_error from self.create_cause
        return observation


class _WrongRolePostEffectCreateErrorExecutor(frozen_f1.F1ExecutorSpy):
    def __init__(self, *, failing_role: SandboxRole) -> None:
        super().__init__()
        self.failing_role = failing_role
        self.create_error: docker_oracle.SandboxCreateObservationError | None = None

    def create(
        self,
        *,
        action: G1HostAction,
        action_registry_sha256: str,
        request: SandboxCreateRequest,
    ) -> SandboxCreateObservation:
        observation = super().create(
            action=action,
            action_registry_sha256=action_registry_sha256,
            request=request,
        )
        if request.role is self.failing_role:
            wrong_role = (
                SandboxRole.ORACLE
                if request.role is SandboxRole.AGENT
                else SandboxRole.AGENT
            )
            self.create_error = docker_oracle.SandboxCreateObservationError(
                "sandbox effect exists but its observation has the wrong role",
                sandbox=SandboxRef(
                    role=wrong_role,
                    microvm_id=observation.sandbox.microvm_id,
                ),
                cause=RuntimeError("synthetic wrong-role create observation"),
            )
            raise self.create_error
        return observation


@pytest.mark.parametrize("role", [SandboxRole.AGENT, SandboxRole.ORACLE])
def test_wrong_role_create_error_fails_closed_with_exact_manual_reference(
    role: SandboxRole,
) -> None:
    executor = _WrongRolePostEffectCreateErrorExecutor(failing_role=role)
    expected_ref = frozen_f1.AGENT if role is SandboxRole.AGENT else frozen_f1.ORACLE
    destroy_action_id = f"g1.sbx.{role.value}.destroy"

    with pytest.raises(frozen_f1.OracleCleanupError) as raised:
        frozen_f1._run_f1(gate=frozen_f1._live_gate(), executor=executor)

    assert executor.create_error is not None
    assert executor.create_error.sandbox.role is not role
    assert executor.create_error.sandbox.microvm_id == expected_ref.microvm_id
    assert raised.value.disposition is frozen_f1.BatchDisposition.KILL
    assert raised.value.cleanup_reference == expected_ref.microvm_id
    assert raised.value.primary_error is executor.create_error
    assert destroy_action_id not in [call[0].action_id for call in executor.calls]
    assert all(
        call[0].action_id == f"g1.sbx.{call[2].role.value}.destroy"
        for call in executor.calls
        if call[0].action_id.endswith(".destroy")
    )


@pytest.mark.parametrize("role", [SandboxRole.AGENT, SandboxRole.ORACLE])
def test_post_effect_create_error_destroys_exact_recoverable_vm(
    role: SandboxRole,
) -> None:
    executor = _PostEffectCreateErrorExecutor(failing_role=role)

    with pytest.raises(RuntimeError) as raised:
        frozen_f1._run_f1(gate=frozen_f1._live_gate(), executor=executor)

    action_ids = [call[0].action_id for call in executor.calls]
    create_id = f"g1.sbx.{role.value}.create"
    destroy_id = f"g1.sbx.{role.value}.destroy"
    assert action_ids[action_ids.index(create_id) + 1] == destroy_id
    assert raised.value is executor.create_error
    assert type(raised.value) is getattr(
        docker_oracle,
        "SandboxCreateObservationError",
        None,
    )
    assert raised.value.sandbox.role is role
    assert raised.value.cause is executor.create_cause
    assert raised.value.__cause__ is executor.create_cause


@pytest.mark.parametrize("role", [SandboxRole.AGENT, SandboxRole.ORACLE])
def test_post_effect_create_cleanup_failure_preserves_manual_reference_and_primary(
    role: SandboxRole,
) -> None:
    cleanup_error = RuntimeError(f"synthetic destroy failure: {role.value}")
    executor = _PostEffectCreateErrorExecutor(failing_role=role)
    executor.failures[f"g1.sbx.{role.value}.destroy"] = cleanup_error

    with pytest.raises(frozen_f1.OracleCleanupError) as raised:
        frozen_f1._run_f1(gate=frozen_f1._live_gate(), executor=executor)

    assert executor.create_error is not None
    assert raised.value.cleanup_reference == executor.create_error.sandbox.microvm_id
    assert raised.value.cleanup_error is cleanup_error
    assert raised.value.primary_error is executor.create_error


def test_sbx_backend_rejects_partial_registry_before_probe() -> None:
    registry = _closed_g1_registry()
    partial = frozenset(
        action for action in registry if action.action_id != "g1.sbx.oracle.destroy"
    )
    probe = FakeCommandProbe(results={})

    with pytest.raises(ValueError, match="exact closed G1"):
        SbxBackend(
            action_registry=partial,
            trace_sink=InMemoryF1TraceSink(),
            command_probe=probe,
        )

    assert probe.calls == ()


@pytest.mark.parametrize(
    "result",
    [
        CommandResult(
            returncode=1,
            stdout="",
            stderr="failed",
            timed_out=False,
            truncated=False,
        ),
        CommandResult(
            returncode=None,
            stdout="",
            stderr="timeout",
            timed_out=True,
            truncated=False,
        ),
        CommandResult(
            returncode=0,
            stdout="partial",
            stderr="",
            timed_out=False,
            truncated=True,
        ),
    ],
)
def test_sbx_backend_traces_then_fails_closed_on_unsafe_result(
    result: CommandResult,
) -> None:
    registry = _closed_g1_registry()
    action = next(item for item in registry if item.action_id == "g1.sbx.agent.create")
    probe = FakeCommandProbe(results={action.command.argv: result})
    trace_sink = InMemoryF1TraceSink()
    backend = SbxBackend(
        action_registry=registry,
        trace_sink=trace_sink,
        command_probe=probe,
    )

    with pytest.raises(SandboxUnavailable, match="registered SBX action failed"):
        backend.execute_registered(
            action=action,
            sandbox=SandboxRef(role=SandboxRole.AGENT, microvm_id="agent-unit"),
        )

    assert probe.calls == (action.command,)
    assert trace_sink.execution_trace.records[-1].status is F1ExecutionStatus.FAILED


class _RaisingCommandProbe:
    def __init__(self, error: Exception) -> None:
        self.error = error
        self.calls: list[CommandSpec] = []

    def run(self, command: CommandSpec) -> CommandResult:
        self.calls.append(command)
        raise self.error


def test_sbx_backend_probe_exception_emits_one_bound_failed_record() -> None:
    registry = _closed_g1_registry()
    action = next(item for item in registry if item.action_id == "g1.sbx.agent.create")
    sandbox = SandboxRef(role=SandboxRole.AGENT, microvm_id="agent-probe-error")
    probe_error = RuntimeError("synthetic command probe transport failure")
    probe = _RaisingCommandProbe(probe_error)
    trace_sink = InMemoryF1TraceSink()
    backend = SbxBackend(
        action_registry=registry,
        trace_sink=trace_sink,
        command_probe=probe,
    )

    with pytest.raises(
        SandboxUnavailable, match="registered SBX action failed"
    ) as raised:
        backend.execute_registered(action=action, sandbox=sandbox)

    assert raised.value.__cause__ is probe_error
    assert probe.calls == [action.command]
    assert len(trace_sink.execution_trace.records) == 1
    record = trace_sink.execution_trace.records[0]
    assert record.status is F1ExecutionStatus.FAILED
    assert record.action_id == action.action_id
    assert record.microvm_role is sandbox.role
    assert record.microvm_id == sandbox.microvm_id
    assert record.command_spec_digest == approval.command_spec_sha256(action.command)
    assert record.action_registry_sha256 == approval.action_registry_sha256(registry)


def test_sbx_backend_rejects_action_command_drift_without_probe_fallback() -> None:
    registry = _closed_g1_registry()
    registered = next(
        item for item in registry if item.action_id == "g1.sbx.agent.create"
    )
    drifted = G1HostAction(
        action_id=registered.action_id,
        command=replace(
            registered.command,
            argv=("sbx", "g1.sbx.agent.create-drifted"),
        ),
    )
    probe = FakeCommandProbe(results={})
    backend = SbxBackend(
        action_registry=registry,
        trace_sink=InMemoryF1TraceSink(),
        command_probe=probe,
    )

    with pytest.raises(ValueError, match="exactly registered"):
        backend.execute_registered(
            action=drifted,
            sandbox=SandboxRef(role=SandboxRole.AGENT, microvm_id="agent-unit"),
        )

    assert probe.calls == ()


DISCOVERY_RECEIPT_PATH = Path(
    "/Users/alex/.codex/roguepatch-approvals/g1-discovery.json"
)
DISCOVERY_CONTROL_ROOT = Path("/Users/alex/.codex/roguepatch-control/v1/g1-discovery")
DISCOVERY_SOURCE_PATH = Path(
    "/Users/alex/RoguePatchLab/.roguepatch/public-fixtures/rp-001"
)
DISCOVERY_DIAGNOSTIC_VM_ID = "roguepatch-g1-discovery"
DISCOVERY_BASELINE_ACTION_IDS = (
    "g1-discovery.install-standalone",
    "g1-discovery.inspect-read-only",
)
DISCOVERY_DIAGNOSTIC_ACTION_IDS = (
    "g1-discovery.diagnostic-create",
    "g1-discovery.diagnostic-exec",
    "g1-discovery.diagnostic-destroy",
)


def _offline_discovery_command(action_id: str, *, mutating: bool) -> CommandSpec:
    return CommandSpec(
        argv=("offline-discovery-record", action_id),
        cwd=ABSOLUTE_CWD,
        env={"PATH": "/synthetic/bin"},
        timeout_seconds=5,
        max_output_bytes=4096,
        mutating=mutating,
    )


def _offline_discovery_record(action_id: str, *, mutating: bool) -> object:
    return doctor_module.G1DiscoveryActionRecord(
        action_id=action_id,
        command=_offline_discovery_command(action_id, mutating=mutating),
    )


def _offline_discovery_registry() -> object:
    return doctor_module.build_g1_discovery_offline_registry(
        records=(
            _offline_discovery_record(
                DISCOVERY_BASELINE_ACTION_IDS[0],
                mutating=True,
            ),
            _offline_discovery_record(
                DISCOVERY_BASELINE_ACTION_IDS[1],
                mutating=False,
            ),
        ),
        receipt_path=DISCOVERY_RECEIPT_PATH,
        control_root=DISCOVERY_CONTROL_ROOT,
        public_source_path=DISCOVERY_SOURCE_PATH,
    )


def _offline_discovery_diagnostic_profile() -> object:
    return doctor_module.build_g1_discovery_diagnostic_profile(
        records=(
            _offline_discovery_record(
                DISCOVERY_DIAGNOSTIC_ACTION_IDS[0],
                mutating=True,
            ),
            _offline_discovery_record(
                DISCOVERY_DIAGNOSTIC_ACTION_IDS[1],
                mutating=False,
            ),
            _offline_discovery_record(
                DISCOVERY_DIAGNOSTIC_ACTION_IDS[2],
                mutating=True,
            ),
        ),
        diagnostic_microvm_id=DISCOVERY_DIAGNOSTIC_VM_ID,
        cleanup_required=True,
    )


def _discovery_receipt(
    *,
    registry: object,
    diagnostic_profile: object | None,
) -> object:
    receipt = doctor_module.G1DiscoveryReceiptBinding(
        approved_by="alex",
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        spec_sha256="a" * 64,
        plan_sha256="b" * 64,
        repo_commit="c" * 40,
        host_fingerprint_sha256=HOST_FINGERPRINT,
        action_registry_sha256=registry.sha256,
        diagnostic_profile_sha256=(
            diagnostic_profile.sha256 if diagnostic_profile is not None else None
        ),
    )
    return receipt


def _discovery_authority_facts(*, diagnostic: bool = False) -> object:
    registry = _offline_discovery_registry()
    profile = _offline_discovery_diagnostic_profile() if diagnostic else None
    return doctor_module.G1DiscoveryAuthorityFacts(
        receipt_path=DISCOVERY_RECEIPT_PATH,
        receipt_owner="alex",
        receipt_mode=0o600,
        observed_at=NOW,
        expected_spec_sha256="a" * 64,
        expected_plan_sha256="b" * 64,
        expected_repo_commit="c" * 40,
        expected_host_fingerprint_sha256=HOST_FINGERPRINT,
        receipt=_discovery_receipt(
            registry=registry,
            diagnostic_profile=profile,
        ),
        action_registry=registry,
        diagnostic_profile=profile,
    )


def test_r2_discovery_registry_and_receipt_are_exactly_bound() -> None:
    facts = _discovery_authority_facts(diagnostic=True)
    authority = doctor_module.validate_g1_discovery_authority(facts)
    registry = facts.action_registry
    diagnostic_profile = facts.diagnostic_profile
    assert diagnostic_profile is not None
    registry_payload = json.loads(registry.canonical_payload)
    diagnostic_payload = json.loads(diagnostic_profile.canonical_payload)
    receipt = facts.receipt
    receipt_payload = json.loads(receipt.canonical_payload)

    assert registry.schema_version == "roguepatch.g1-discovery-action-registry.v1"
    assert registry_payload == {
        "schema_version": "roguepatch.g1-discovery-action-registry.v1",
        "receipt_path": str(DISCOVERY_RECEIPT_PATH),
        "control_root": str(DISCOVERY_CONTROL_ROOT),
        "public_source_path": str(DISCOVERY_SOURCE_PATH),
        "actions": [
            {
                "action_id": record.action_id,
                **approval.command_spec_payload(record.command),
            }
            for record in sorted(registry.records, key=lambda item: item.action_id)
        ],
    }
    assert {record.action_id for record in registry.records} == set(
        DISCOVERY_BASELINE_ACTION_IDS
    )
    assert all(
        not record.action_id.startswith("g1-discovery.diagnostic-")
        for record in registry.records
    )
    assert registry.sha256 == sha256(registry.canonical_payload).hexdigest()
    assert diagnostic_payload == {
        "schema_version": "roguepatch.g1-discovery-diagnostic-profile.v1",
        "diagnostic_microvm_id": DISCOVERY_DIAGNOSTIC_VM_ID,
        "cleanup_required": True,
        "actions": [
            {
                "action_id": record.action_id,
                **approval.command_spec_payload(record.command),
            }
            for record in diagnostic_profile.records
        ],
    }
    assert [record.action_id for record in diagnostic_profile.records] == list(
        DISCOVERY_DIAGNOSTIC_ACTION_IDS
    )
    for invalid_records in (
        diagnostic_profile.records[:-1],
        (*diagnostic_profile.records, diagnostic_profile.records[1]),
    ):
        with pytest.raises(ValueError, match="diagnostic.*create.*exec.*destroy"):
            doctor_module.build_g1_discovery_diagnostic_profile(
                records=invalid_records,
                diagnostic_microvm_id=DISCOVERY_DIAGNOSTIC_VM_ID,
                cleanup_required=True,
            )
    assert (
        diagnostic_profile.sha256
        == sha256(diagnostic_profile.canonical_payload).hexdigest()
    )
    assert receipt.schema_version == "roguepatch.g1-discovery-receipt.v1"
    assert receipt_payload == {
        "schema_version": "roguepatch.g1-discovery-receipt.v1",
        "gate": "g1-discovery",
        "decision": "approved",
        "approved_by": "alex",
        "approved_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
        "spec_sha256": "a" * 64,
        "plan_sha256": "b" * 64,
        "repo_commit": "c" * 40,
        "host_fingerprint_sha256": HOST_FINGERPRINT,
        "action_registry_sha256": registry.sha256,
        "diagnostic_profile_sha256": diagnostic_profile.sha256,
    }
    assert receipt.action_registry_sha256 == registry.sha256
    assert receipt.diagnostic_profile_sha256 == diagnostic_profile.sha256
    assert authority.baseline_creates_microvm is False
    assert authority.candidate_regeneration_required is True
    assert authority.g1_receipt_regeneration_required is True
    assert authority.discovery_receipt_reusable_as_g1 is False
    assert authority.counts_as_f1_evidence is False


def test_r2_discovery_rejects_trials_and_agent_code() -> None:
    live_factory = doctor_module.build_g1_discovery_live_registry

    with pytest.raises((TypeError, ValueError), match="observed inputs"):
        live_factory(observed_inputs=None)

    expected_cwd = Path("/Users/alex/RoguePatchLab")
    expected_env = {"PATH": "/opt/homebrew/bin:/usr/bin:/bin"}
    invalid_commands = (
        (
            CommandSpec(
                argv=("TODO",),
                cwd=expected_cwd,
                env=expected_env,
                timeout_seconds=5,
                max_output_bytes=4096,
            ),
            False,
            "placeholder",
        ),
        (
            CommandSpec(
                argv=("offline-discovery-record", "fixture-action"),
                cwd=expected_cwd,
                env=expected_env,
                timeout_seconds=5,
                max_output_bytes=4096,
            ),
            False,
            "placeholder|offline",
        ),
        *(
            (
                CommandSpec(
                    argv=(executable, "-c", "true"),
                    cwd=expected_cwd,
                    env=expected_env,
                    timeout_seconds=5,
                    max_output_bytes=4096,
                ),
                False,
                "shell|interpreter",
            )
            for executable in ("sh", "bash", "zsh", "python3", "node")
        ),
        (
            CommandSpec(
                argv=("env", "python3", "probe.py"),
                cwd=expected_cwd,
                env=expected_env,
                timeout_seconds=5,
                max_output_bytes=4096,
            ),
            False,
            "shell|interpreter",
        ),
        *(
            (
                CommandSpec(
                    argv=argv,
                    cwd=expected_cwd,
                    env=expected_env,
                    timeout_seconds=5,
                    max_output_bytes=4096,
                ),
                False,
                error,
            )
            for argv, error in (
                (("docker", "run"), "Docker"),
                (("roguepatch", "run"), "trial|agent"),
                (("codex", "exec"), "Codex|agent"),
                (("observed-tool", str(DISCOVERY_SOURCE_PATH / "agent.py")), "code"),
                (("observed-tool", str(DISCOVERY_SOURCE_PATH / "task.toml")), "task"),
            )
        ),
        (
            CommandSpec(
                argv=("observed-tool",),
                cwd=Path("/tmp"),
                env=expected_env,
                timeout_seconds=5,
                max_output_bytes=4096,
            ),
            False,
            "cwd",
        ),
        (
            CommandSpec(
                argv=("observed-tool",),
                cwd=expected_cwd,
                env={"PATH": "/tmp/bin"},
                timeout_seconds=5,
                max_output_bytes=4096,
            ),
            False,
            "env",
        ),
        (
            CommandSpec(
                argv=("observed-tool",),
                cwd=expected_cwd,
                env=expected_env,
                timeout_seconds=5,
                max_output_bytes=4096,
                mutating=True,
            ),
            False,
            "mutating",
        ),
    )
    for command, expected_mutating, error in invalid_commands:
        with pytest.raises((TypeError, ValueError), match=error):
            observed = doctor_module.G1DiscoveryObservedCommand(
                action_id="g1-discovery.inspect-read-only",
                command=command,
                observed_argv=command.argv,
                expected_cwd=expected_cwd,
                expected_env=expected_env,
                expected_mutating=expected_mutating,
            )
            live_factory(observed_inputs=(observed,))

    with pytest.raises(ValueError, match="shell"):
        CommandSpec(
            argv=("observed-tool",),
            cwd=expected_cwd,
            env=expected_env,
            timeout_seconds=5,
            max_output_bytes=4096,
            shell=True,
        )

    invalid_authority = (
        (
            {"observed_at": NOW - timedelta(seconds=1)},
            "observed|approved",
        ),
        (
            {"receipt": replace(_discovery_authority_facts().receipt, expires_at=NOW)},
            "expired",
        ),
        (
            {
                "receipt": replace(
                    _discovery_authority_facts().receipt, approved_by="mallory"
                )
            },
            "approver",
        ),
        ({"receipt_path": Path("/tmp/g1-discovery.json")}, "path"),
        ({"receipt_owner": "root"}, "owner"),
        ({"receipt_mode": 0o644}, "mode"),
        ({"expected_host_fingerprint_sha256": "f" * 64}, "host"),
        ({"expected_spec_sha256": "f" * 64}, "spec"),
        ({"expected_plan_sha256": "f" * 64}, "plan"),
        ({"expected_repo_commit": "f" * 40}, "repo|commit"),
        (
            {
                "receipt": replace(
                    _discovery_authority_facts().receipt,
                    action_registry_sha256="f" * 64,
                )
            },
            "registry",
        ),
        (
            {
                "receipt": replace(
                    _discovery_authority_facts(diagnostic=True).receipt,
                    diagnostic_profile_sha256="f" * 64,
                ),
                "diagnostic_profile": _discovery_authority_facts(
                    diagnostic=True
                ).diagnostic_profile,
            },
            "diagnostic.*profile",
        ),
    )
    for changes, error in invalid_authority:
        with pytest.raises((TypeError, ValueError), match=error):
            doctor_module.validate_g1_discovery_authority(
                replace(_discovery_authority_facts(), **changes)
            )


class _DiscoveryEffectExecutor:
    def __init__(self) -> None:
        self.calls: list[object] = []

    def execute(self, action: object) -> CommandResult:
        self.calls.append(action)
        return _result()


class _DiscoveryMaterializer:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def materialize_receipt(self, _authority: object) -> None:
        self.calls.append("receipt")

    def materialize_sidecars(self, _authority: object) -> None:
        self.calls.append("sidecars")


def test_r2_discovery_requires_40_gib_before_any_effect() -> None:
    run_discovery = doctor_module.run_g1_discovery
    authority = doctor_module.validate_g1_discovery_authority(
        _discovery_authority_facts()
    )
    blocked_executor = _DiscoveryEffectExecutor()
    blocked_materializer = _DiscoveryMaterializer()

    blocked = run_discovery(
        authority=authority,
        live_registry=None,
        available_kib=RECEIPT_INSTALL_MIN_KIB - 1,
        materializer=blocked_materializer,
        executor=blocked_executor,
    )

    assert blocked.status is PreflightStatus.BLOCKED_LOW_DISK
    assert blocked.invoked is False
    assert blocked.effect_count == 0
    assert blocked_materializer.calls == []
    assert blocked_executor.calls == []

    for unavailable_live_registry in (None, authority.action_registry):
        threshold_executor = _DiscoveryEffectExecutor()
        threshold_materializer = _DiscoveryMaterializer()
        with pytest.raises((TypeError, ValueError), match="live.*registry|observed"):
            run_discovery(
                authority=authority,
                live_registry=unavailable_live_registry,
                available_kib=RECEIPT_INSTALL_MIN_KIB,
                materializer=threshold_materializer,
                executor=threshold_executor,
            )

        assert threshold_materializer.calls == []
        assert threshold_executor.calls == []
