from pathlib import Path

import pytest

from roguepatch.adapters.fake_backend import FakeApprovalStore, FakeCommandProbe
from roguepatch.approval import (
    ApprovalBinding,
    ApprovalState,
    run_approved_mutation,
)
from roguepatch.doctor import CheckState, DoctorCheck, DoctorProbe, run_doctor
from roguepatch.ports import CommandResult, CommandSpec

PROBE_CWD = Path("/synthetic/roguepatch")


def _command(name: str, *, mutating: bool = False) -> CommandSpec:
    return CommandSpec(
        argv=("synthetic-probe", name),
        cwd=PROBE_CWD,
        env={"PATH": "/synthetic/bin"},
        timeout_seconds=5,
        max_output_bytes=4096,
        mutating=mutating,
    )


def _doctor_probes() -> tuple[DoctorProbe, ...]:
    return tuple(
        DoctorProbe(check=check, command=_command(check.value)) for check in DoctorCheck
    )


@pytest.mark.parametrize("missing_check", list(DoctorCheck))
def test_r1_doctor_fails_closed(missing_check: DoctorCheck) -> None:
    probes = _doctor_probes()
    results = {
        probe.command.argv: CommandResult(
            returncode=1 if probe.check is missing_check else 0,
            stdout="",
            stderr="missing" if probe.check is missing_check else "",
            timed_out=False,
            truncated=False,
        )
        for probe in probes
    }
    command_probe = FakeCommandProbe(results=results)

    report = run_doctor(command_probe, probes)

    assert report.exit_code == 2
    assert report.ready is False
    assert report.fact_for(missing_check).state is CheckState.MISSING
    assert set(report.facts) == set(DoctorCheck)
    assert command_probe.mutating_calls == ()


@pytest.mark.parametrize(
    "approval_state",
    [
        ApprovalState.ABSENT,
        ApprovalState.EXPIRED,
        ApprovalState.MISBOUND,
    ],
)
def test_r2_human_gate_blocks_side_effects(
    approval_state: ApprovalState,
) -> None:
    command = _command("start-sandbox", mutating=True)
    command_probe = FakeCommandProbe(
        results={
            command.argv: CommandResult(
                returncode=0,
                stdout="started",
                stderr="",
                timed_out=False,
                truncated=False,
            )
        }
    )
    approvals = FakeApprovalStore(state=approval_state)
    expected = ApprovalBinding(
        gate="g1",
        spec_sha256="a" * 64,
        plan_sha256="b" * 64,
        repo_commit="c" * 40,
    )

    outcome = run_approved_mutation(
        store=approvals,
        expected=expected,
        probe=command_probe,
        command=command,
    )

    assert outcome.exit_code == 2
    assert outcome.invoked is False
    assert outcome.approval_state is approval_state
    assert approvals.check_calls == (expected,)
    assert command_probe.calls == ()
    assert command_probe.mutating_calls == ()
