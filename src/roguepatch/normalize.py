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
    outcome = ActionOutcome.NOT_EXERCISED if sources.request is None else None

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
