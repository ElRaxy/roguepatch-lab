from __future__ import annotations

import inspect
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from roguepatch import approval
from roguepatch.adapters.fake_backend import FakeApprovalStore, FakeCommandProbe
from roguepatch.approval import (
    ApprovalBinding,
    ApprovalState,
    ApprovalStore,
    run_approved_mutation,
    run_host_approved_mutation,
)
from roguepatch.doctor import CheckState, DoctorCheck, DoctorProbe, run_doctor
from roguepatch.ports import CommandResult, CommandSpec

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
ABSOLUTE_CWD = Path("/synthetic/roguepatch")


@pytest.fixture(autouse=True)
def _fixed_approval_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(approval, "_alex_uid", lambda: os.getuid(), raising=False)
    monkeypatch.setattr(approval, "_utc_now", lambda: NOW, raising=False)


def _binding() -> ApprovalBinding:
    return ApprovalBinding(
        gate="g1",
        spec_sha256="a" * 64,
        plan_sha256="b" * 64,
        repo_commit="c" * 40,
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


def _receipt(
    binding: ApprovalBinding,
    *,
    approved_at: datetime = NOW - timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(minutes=10),
) -> dict[str, object]:
    return {
        "schema_version": "1",
        "gate": binding.gate,
        "decision": "approved",
        "approved_by": "alex",
        "approved_at": approved_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "spec_sha256": binding.spec_sha256,
        "plan_sha256": binding.plan_sha256,
        "repo_commit": binding.repo_commit,
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
    binding = _binding()
    _write_receipt(tmp_path, _receipt(binding))
    monkeypatch.setattr(approval, "_APPROVAL_ROOT", tmp_path)

    assert ApprovalStore().check(binding) is ApprovalState.APPROVED


def test_approval_store_distinguishes_absent_expired_and_misbound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
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
    binding = _binding()
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
    binding = _binding()
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

    assert ApprovalStore().check(_binding()) is ApprovalState.MISBOUND


def test_approval_store_fails_closed_on_invalid_clock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    _write_receipt(tmp_path, _receipt(binding))
    monkeypatch.setattr(approval, "_APPROVAL_ROOT", tmp_path)
    monkeypatch.setattr(approval, "_utc_now", lambda: cast(datetime, "not-a-datetime"))

    assert ApprovalStore().check(binding) is ApprovalState.MISBOUND


def test_approval_store_rejects_duplicate_json_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
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
    binding = _binding()
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
        frozenset({approval._host_action_key(command)}),
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


def test_approval_schema_matches_the_closed_runtime_contract() -> None:
    schema_path = Path(__file__).parents[2] / "schemas" / "approval.schema.json"
    schema = json.loads(schema_path.read_text())

    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == approval._G1_RECEIPT_FIELDS
    assert schema["properties"]["gate"] == {"const": "g1"}
    assert schema["properties"]["decision"] == {"const": "approved"}
