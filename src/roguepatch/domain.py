from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum, unique


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
