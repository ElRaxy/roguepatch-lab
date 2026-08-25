from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum, unique
from types import MappingProxyType

from roguepatch.ports import CommandProbe, CommandSpec


@unique
class DoctorCheck(StrEnum):
    DAEMON = "daemon"
    SBX = "sbx"
    PINS = "pins"
    AUTH = "auth"
    ISOLATION = "isolation"


@unique
class CheckState(StrEnum):
    READY = "ready"
    MISSING = "missing"
    ERROR = "error"


_DoctorCommandKey = tuple[
    tuple[str, ...],
    str,
    tuple[tuple[str, str], ...],
    int,
    int,
]


def _doctor_command_key(command: CommandSpec) -> _DoctorCommandKey:
    return (
        command.argv,
        str(command.cwd),
        tuple(sorted(command.env.items())),
        command.timeout_seconds,
        command.max_output_bytes,
    )


# Task 3 admits only inert fake probes; Task 4 may add audited real inspections after G1.
_DOCTOR_COMMAND_REGISTRY: Mapping[DoctorCheck, frozenset[_DoctorCommandKey]] = (
    MappingProxyType(
        {
            check: frozenset(
                {
                    (
                        ("synthetic-probe", check.value),
                        "/synthetic/roguepatch",
                        (("PATH", "/synthetic/bin"),),
                        5,
                        4096,
                    )
                }
            )
            for check in DoctorCheck
        }
    )
)


@dataclass(frozen=True, slots=True)
class DoctorProbe:
    check: DoctorCheck
    command: CommandSpec

    def __post_init__(self) -> None:
        if not isinstance(self.check, DoctorCheck):
            raise TypeError("check must be a DoctorCheck")
        if not isinstance(self.command, CommandSpec):
            raise TypeError("command must be a CommandSpec")
        if self.command.mutating:
            raise ValueError("doctor probes must be read-only")
        if (
            _doctor_command_key(self.command)
            not in _DOCTOR_COMMAND_REGISTRY[self.check]
        ):
            raise ValueError("doctor probe is not a registered read-only command")


@dataclass(frozen=True, slots=True)
class CheckFact:
    check: DoctorCheck
    state: CheckState
    diagnostic: str = ""


@dataclass(frozen=True, slots=True)
class DoctorReport:
    facts: Mapping[DoctorCheck, CheckFact]

    def __post_init__(self) -> None:
        frozen = dict(self.facts)
        if set(frozen) != set(DoctorCheck):
            raise ValueError("doctor report must contain every required check")
        object.__setattr__(self, "facts", MappingProxyType(frozen))

    @property
    def ready(self) -> bool:
        return all(fact.state is CheckState.READY for fact in self.facts.values())

    @property
    def exit_code(self) -> int:
        return 0 if self.ready else 2

    def fact_for(self, check: DoctorCheck) -> CheckFact:
        return self.facts[check]


def run_doctor(
    command_probe: CommandProbe,
    probes: Sequence[DoctorProbe],
) -> DoctorReport:
    configured: dict[DoctorCheck, DoctorProbe] = {}
    for probe in probes:
        if probe.check in configured:
            raise ValueError(f"duplicate doctor probe: {probe.check.value}")
        configured[probe.check] = probe

    facts: dict[DoctorCheck, CheckFact] = {}
    for check in DoctorCheck:
        configured_probe = configured.get(check)
        if configured_probe is None:
            facts[check] = CheckFact(
                check=check,
                state=CheckState.ERROR,
                diagnostic="probe not configured",
            )
            continue
        try:
            result = command_probe.run(configured_probe.command)
        except Exception as error:  # noqa: BLE001 - adapter boundary must fail closed
            facts[check] = CheckFact(
                check=check,
                state=CheckState.ERROR,
                diagnostic=type(error).__name__,
            )
            continue
        state = CheckState.READY if result.succeeded else CheckState.MISSING
        diagnostic = "" if result.succeeded else (result.stderr or "probe failed")
        facts[check] = CheckFact(check=check, state=state, diagnostic=diagnostic)

    return DoctorReport(facts=facts)
