from dataclasses import FrozenInstanceError, is_dataclass
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
from roguepatch.normalize import normalize_action


def _request_observation() -> dict[str, object]:
    return {
        "target": "docs/release.md",
        "metadata": {"resolved_target": "docs/release.md"},
    }


def _snapshot_observation() -> dict[str, object]:
    return {
        "phase": "final",
        "tree": {"digest": "sha256:final-clean"},
    }


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
def test_domain_records_are_dataclasses(record_type: type[object]) -> None:
    assert is_dataclass(record_type)


@pytest.mark.parametrize("record_name", ["sources", "facts"])
@pytest.mark.parametrize("mutation_depth", ["root", "nested"])
def test_request_observations_are_detached_from_caller_mutation(
    record_name: str, mutation_depth: str
) -> None:
    request = _request_observation()
    expected_request = _request_observation()
    sources = ActionSources(request=request, receipt=None, snapshots=())
    facts = normalize_action(sources)

    if mutation_depth == "root":
        request["target"] = "mutated-root.txt"
    else:
        metadata = request["metadata"]
        assert isinstance(metadata, dict)
        metadata["resolved_target"] = "mutated-nested.txt"

    preserved_request = sources.request if record_name == "sources" else facts.request
    assert preserved_request == expected_request


@pytest.mark.parametrize("mutation_depth", ["root", "nested"])
def test_direct_action_facts_detach_request_from_caller_mutation(
    mutation_depth: str,
) -> None:
    request = _request_observation()
    expected_request = _request_observation()
    facts = ActionFacts(
        request=request,
        decision=Decision.UNOBSERVED,
        execution=ExecutionState.UNOBSERVED,
        effect=EffectState.UNOBSERVED,
        remediation=Remediation.UNOBSERVED,
        outcome=None,
        contained=None,
        pre_blocked=None,
        reverted=None,
    )

    if mutation_depth == "root":
        request["target"] = "mutated-root.txt"
    else:
        metadata = request["metadata"]
        assert isinstance(metadata, dict)
        metadata["resolved_target"] = "mutated-nested.txt"

    assert facts.request == expected_request


@pytest.mark.parametrize("mutation_depth", ["root", "nested"])
def test_snapshot_observations_are_detached_from_caller_mutation(
    mutation_depth: str,
) -> None:
    snapshot = _snapshot_observation()
    expected_snapshot = _snapshot_observation()
    sources = ActionSources(request=None, receipt=None, snapshots=(snapshot,))
    facts = normalize_action(sources)

    if mutation_depth == "root":
        snapshot["phase"] = "mutated-root"
    else:
        tree = snapshot["tree"]
        assert isinstance(tree, dict)
        tree["digest"] = "sha256:mutated-nested"

    assert sources.snapshots == (expected_snapshot,)
    assert facts.request is None


@pytest.mark.parametrize(
    ("instance", "field_name"),
    [
        (EvidenceRef(kind="request", sha256="sha256:evidence"), "kind"),
        (
            ActionSources(request=None, receipt=None, snapshots=()),
            "request",
        ),
        (
            ActionFacts(
                request=None,
                decision=Decision.UNOBSERVED,
                execution=ExecutionState.UNOBSERVED,
                effect=EffectState.UNOBSERVED,
                remediation=Remediation.UNOBSERVED,
                outcome=ActionOutcome.NOT_EXERCISED,
                contained=None,
                pre_blocked=None,
                reverted=None,
            ),
            "request",
        ),
    ],
)
def test_domain_records_enforce_frozen_slots(instance: object, field_name: str) -> None:
    with pytest.raises(FrozenInstanceError):
        setattr(instance, field_name, None)

    assert not hasattr(instance, "__dict__")


@pytest.mark.parametrize(
    ("receipt", "decision", "execution", "effect", "remediation"),
    [
        ({"source": "native-control"}, None, None, None, None),
        (None, None, ExecutionState.STARTED, None, None),
        (None, None, None, EffectState.LANDED, None),
        (None, Decision.DENY, None, None, None),
        (None, None, None, None, Remediation.CONTROL_REVERTED),
    ],
)
def test_no_request_with_action_evidence_is_invalid(
    receipt: dict[str, str] | None,
    decision: Decision | None,
    execution: ExecutionState | None,
    effect: EffectState | None,
    remediation: Remediation | None,
) -> None:
    result = normalize_action(
        ActionSources(
            request=None,
            receipt=receipt,
            snapshots=(),
            decision=decision,
            execution=execution,
            effect=effect,
            remediation=remediation,
        )
    )

    assert result.outcome is ActionOutcome.INVALID


@pytest.mark.parametrize(
    ("decision", "remediation"),
    [
        (Decision.UNOBSERVED, None),
        (Decision.NOT_APPLICABLE, None),
        (None, Remediation.UNOBSERVED),
    ],
)
def test_no_request_with_non_evidence_markers_is_not_exercised(
    decision: Decision | None,
    remediation: Remediation | None,
) -> None:
    result = normalize_action(
        ActionSources(
            request=None,
            receipt=None,
            snapshots=(),
            decision=decision,
            remediation=remediation,
        )
    )

    assert result.outcome is ActionOutcome.NOT_EXERCISED
