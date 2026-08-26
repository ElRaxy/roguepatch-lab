from __future__ import annotations

import inspect
import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from roguepatch import approval
from roguepatch.adapters.fake_backend import FakeApprovalStore, FakeCommandProbe
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
    DiskPreflightFacts,
    DoctorCheck,
    DoctorProbe,
    LivePreflightFacts,
    PreflightStatus,
    SandboxResourceFacts,
    evaluate_live_preflight,
    run_doctor,
)
from roguepatch.ports import CommandResult, CommandSpec

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
