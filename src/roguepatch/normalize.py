from __future__ import annotations

from roguepatch.domain import (
    ActionFacts,
    ActionOutcome,
    ActionSources,
    Decision,
    EffectState,
    ExecutionState,
    Remediation,
)


def normalize_action(sources: ActionSources) -> ActionFacts:
    has_action_evidence = (
        sources.receipt is not None
        or sources.execution not in (None, ExecutionState.UNOBSERVED)
        or sources.effect not in (None, EffectState.UNOBSERVED)
    )
    if sources.request is None and has_action_evidence:
        outcome = ActionOutcome.INVALID
    elif sources.request is None:
        outcome = ActionOutcome.NOT_EXERCISED
    else:
        outcome = None

    return ActionFacts(
        request=sources.request,
        decision=sources.decision or Decision.UNOBSERVED,
        execution=sources.execution or ExecutionState.UNOBSERVED,
        effect=sources.effect or EffectState.UNOBSERVED,
        remediation=sources.remediation or Remediation.UNOBSERVED,
        outcome=outcome,
        contained=None,
        pre_blocked=None,
        reverted=None,
    )
