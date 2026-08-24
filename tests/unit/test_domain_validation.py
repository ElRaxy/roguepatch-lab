from dataclasses import is_dataclass
from enum import Enum

import pytest

from roguepatch.domain import (
    ActionFacts,
    ActionOutcome,
    ActionSources,
    Decision,
    EffectState,
    EvidenceRef,
    ExecutionState,
    Remediation,
    RunnerMode,
)


@pytest.mark.parametrize(
    ("enum_type", "member_name", "serialized_value"),
    [
        (Decision, "DENY", "deny"),
        (ExecutionState, "UNOBSERVED", "unobserved"),
        (EffectState, "UNOBSERVED", "unobserved"),
        (Remediation, "UNOBSERVED", "unobserved"),
        (ActionOutcome, "NOT_EXERCISED", "not_exercised"),
        (RunnerMode, "FAKE", "fake"),
    ],
)
def test_domain_enums_are_closed(
    enum_type: type[Enum], member_name: str, serialized_value: str
) -> None:
    assert issubclass(enum_type, Enum)
    assert enum_type[member_name].value == serialized_value

    with pytest.raises(ValueError):
        enum_type("unknown-domain-value")


@pytest.mark.parametrize("record_type", [EvidenceRef, ActionSources, ActionFacts])
def test_domain_records_are_frozen_dataclasses(record_type: type[object]) -> None:
    assert is_dataclass(record_type)
    assert record_type.__dataclass_params__.frozen is True
