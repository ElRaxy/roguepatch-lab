from roguepatch.domain import (
    ActionOutcome,
    ActionSources,
    Decision,
    EffectState,
    ExecutionState,
    Remediation,
)
from roguepatch.normalize import normalize_action


def test_r10_action_fact_conservation() -> None:
    request = {
        "action_id": "action-001",
        "tool": "write_file",
        "target": "docs/release.md",
    }
    receipt = {
        "action_id": "action-001",
        "source": "native-control",
    }
    observed = normalize_action(
        ActionSources(
            request=request,
            receipt=receipt,
            snapshots=(),
            decision=Decision.DENY,
            execution=ExecutionState.NOT_STARTED,
            effect=EffectState.NONE,
            remediation=Remediation.CONTROL_REVERTED,
        )
    )

    assert observed.request == request
    assert observed.decision is Decision.DENY
    assert observed.execution is ExecutionState.NOT_STARTED
    assert observed.effect is EffectState.NONE
    assert observed.remediation is Remediation.CONTROL_REVERTED

    sparse_sources = ActionSources(
        request=request,
        receipt=receipt,
        snapshots=(),
        decision=Decision.DENY,
    )
    sparse = normalize_action(sparse_sources)

    assert sparse_sources.execution is None
    assert sparse_sources.effect is None
    assert sparse.execution is ExecutionState.UNOBSERVED
    assert sparse.effect is EffectState.UNOBSERVED


def test_r11_no_favorable_inference() -> None:
    final_clean_snapshot = {
        "phase": "final",
        "tree_digest": "sha256:final-clean",
        "protected_state": "clean",
    }

    result = normalize_action(
        ActionSources(
            request=None,
            receipt=None,
            snapshots=(final_clean_snapshot,),
        )
    )

    assert result.pre_blocked in (False, None)
    assert result.reverted in (False, None)


def test_r14_not_exercised_is_not_success() -> None:
    result = normalize_action(ActionSources(request=None, receipt=None, snapshots=()))

    assert result.outcome is ActionOutcome.NOT_EXERCISED
    assert result.contained is None
