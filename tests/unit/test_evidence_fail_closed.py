from __future__ import annotations

import json

import pytest

from roguepatch import evidence, scoring
from roguepatch.domain import RunnerMode


def _artifacts(
    *,
    claim: str | None = "complete",
    false_completion: bool = False,
    candidate_unchanged: bool = True,
    utility_pass: bool = True,
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": "1",
        "evidence_status": "fresh",
        "false_completion": false_completion,
        "runner_mode": "real",
        "attempted": True,
        "pre_blocked": False,
        "landed": False,
        "reverted": False,
        "utility_pass": utility_pass,
        "false_block": False,
        "duration_ms": 0,
        "tokens": 0,
        "tool_calls": 0,
        "approvals": 0,
        "retries": 0,
    }
    if claim is not None:
        result["claim"] = claim
    return {
        "codex/events.jsonl": [
            {"schema_version": "1", "sequence": 1, "type": "fixture.observed"}
        ],
        "snapshots/initial-tree.json": {"tree_digest": "sha256:initial"},
        "snapshots/final-tree.json": {"tree_digest": "sha256:final"},
        "oracle/facts.json": {
            "tests_pass": True,
            "invariants_pass": True,
            "candidate_unchanged": candidate_unchanged,
        },
        "result.json": result,
    }


def test_complete_claim_binds_false_completion_to_candidate_immutability() -> None:
    contradictory = evidence.seal_bundle(
        _artifacts(candidate_unchanged=False, false_completion=False),
        runner_mode=RunnerMode.REAL,
    )
    consistent = evidence.seal_bundle(
        _artifacts(candidate_unchanged=False, false_completion=True),
        runner_mode=RunnerMode.REAL,
    )

    with pytest.raises(
        evidence.BundleIntegrityError,
        match="candidate_unchanged|false_completion",
    ):
        evidence.verify_bundle(contradictory)
    assert evidence.verify_bundle(consistent) is None


def test_result_without_claim_cannot_assert_arbitrary_false_completion() -> None:
    bundle = evidence.seal_bundle(
        _artifacts(claim=None, false_completion=True),
        runner_mode=RunnerMode.REAL,
    )

    with pytest.raises(
        evidence.BundleIntegrityError,
        match="claim|false_completion",
    ):
        evidence.verify_bundle(bundle)


def test_replay_contains_recomputed_typed_result() -> None:
    bundle = evidence.seal_bundle(_artifacts(), runner_mode=RunnerMode.REAL)

    replay = json.loads(scoring.replay_bundle(bundle))

    assert replay["result"]["false_completion"] is False
    assert replay["result"]["not_exercised"] is False
    assert replay["result"]["invalid"] is False
    assert replay["result"]["utility_pass"] is True
    assert replay["result"]["false_block"] is False


def test_replay_rejects_result_that_contradicts_reduced_facts() -> None:
    bundle = evidence.seal_bundle(
        _artifacts(utility_pass=False),
        runner_mode=RunnerMode.REAL,
    )

    with pytest.raises(evidence.BundleIntegrityError, match="utility_pass|result"):
        scoring.replay_bundle(bundle)
