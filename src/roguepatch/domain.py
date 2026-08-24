from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum, unique
from types import MappingProxyType


@unique
class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REVIEW = "review"
    ERROR = "error"
    UNOBSERVED = "unobserved"
    NOT_APPLICABLE = "not_applicable"


@unique
class ExecutionState(StrEnum):
    STARTED = "started"
    NOT_STARTED = "not_started"
    UNOBSERVED = "unobserved"


@unique
class EffectState(StrEnum):
    NONE = "none"
    PARTIAL = "partial"
    LANDED = "landed"
    UNOBSERVED = "unobserved"


@unique
class Remediation(StrEnum):
    NONE = "none"
    CONTROL_REVERTED = "control_reverted"
    AGENT_REVERTED = "agent_reverted"
    LAB_CLEANUP = "lab_cleanup"
    UNOBSERVED = "unobserved"


@unique
class ActionOutcome(StrEnum):
    NOT_EXERCISED = "not_exercised"
    INVALID = "invalid"


@unique
class RunnerMode(StrEnum):
    REAL = "real"
    FAKE = "fake"


Observation = Mapping[str, object]


def _freeze_json(value: object) -> object:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("observation mapping keys must be strings")
            frozen[key] = _freeze_json(item)
        return MappingProxyType(frozen)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return tuple(_freeze_json(item) for item in value)
    raise TypeError(f"unsupported observation value: {type(value).__name__}")


def _freeze_observation(value: Observation | None) -> Observation | None:
    if value is None:
        return None
    frozen = _freeze_json(value)
    if not isinstance(frozen, Mapping):
        raise TypeError("observation must be a mapping")
    return frozen


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    kind: str
    sha256: str


@dataclass(frozen=True, slots=True)
class ActionSources:
    request: Observation | None
    receipt: Observation | None
    snapshots: tuple[Observation, ...]
    decision: Decision | None = None
    execution: ExecutionState | None = None
    effect: EffectState | None = None
    remediation: Remediation | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "request", _freeze_observation(self.request))
        object.__setattr__(self, "receipt", _freeze_observation(self.receipt))
        object.__setattr__(
            self,
            "snapshots",
            tuple(_freeze_observation(snapshot) for snapshot in self.snapshots),
        )


@dataclass(frozen=True, slots=True)
class ActionFacts:
    request: Observation | None
    decision: Decision
    execution: ExecutionState
    effect: EffectState
    remediation: Remediation
    outcome: ActionOutcome | None
    contained: bool | None
    pre_blocked: bool | None
    reverted: bool | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "request", _freeze_observation(self.request))
