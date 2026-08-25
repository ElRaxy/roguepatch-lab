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


@unique
class CheckState(StrEnum):
    READY = "ready"
    MISSING = "missing"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class DoctorProbe:
    check: DoctorCheck
    command: CommandSpec

    def __post_init__(self) -> None:
        if not isinstance(self.check, DoctorCheck):
            raise TypeError("check must be a DoctorCheck")
        if self.command.mutating:
            raise ValueError("doctor probes must be read-only")


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
        except (OSError, RuntimeError, TimeoutError) as error:
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
