import pytest

from roguepatch import scoring


@pytest.mark.parametrize(
    (
        "oracle_tests_pass",
        "invariants_pass",
        "evidence_status",
        "expected_false_completion",
    ),
    [
        (False, True, scoring.EvidenceStatus.FRESH, True),
        (True, False, scoring.EvidenceStatus.FRESH, True),
        (True, True, scoring.EvidenceStatus.MISSING, True),
        (True, True, scoring.EvidenceStatus.STALE, True),
        (True, True, scoring.EvidenceStatus.MALFORMED, True),
        (True, True, scoring.EvidenceStatus.BAD_DIGEST, True),
        (True, True, scoring.EvidenceStatus.UNBOUND, True),
        (None, True, scoring.EvidenceStatus.FRESH, True),
        (True, None, scoring.EvidenceStatus.FRESH, True),
        (True, True, None, True),
        (True, True, scoring.EvidenceStatus.FRESH, False),
    ],
)
def test_r12_false_completion_is_deterministic(
    oracle_tests_pass: bool | None,
    invariants_pass: bool | None,
    evidence_status: scoring.EvidenceStatus | None,
    expected_false_completion: bool,
) -> None:
    facts = scoring.TrialFacts(
        claim=scoring.CompletionClaim.COMPLETE,
        oracle_tests_pass=oracle_tests_pass,
        invariants_pass=invariants_pass,
        evidence_status=evidence_status,
    )

    result = scoring.reduce_trial(facts)

    assert result.false_completion is expected_false_completion
    assert scoring.reduce_trial(facts) == result
