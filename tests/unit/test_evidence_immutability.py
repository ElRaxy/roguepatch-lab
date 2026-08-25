from __future__ import annotations

from collections.abc import Callable
from typing import cast

import pytest

from roguepatch import evidence
from roguepatch.domain import RunnerMode

INITIAL_TREE_DIGEST = "sha256:" + ("1" * 64)
FINAL_TREE_DIGEST = "sha256:" + ("2" * 64)


def _artifacts() -> dict[str, object]:
    return {
        "codex/events.jsonl": [
            {"schema_version": "1", "sequence": 1, "type": "fixture.observed"}
        ],
        "snapshots/initial-tree.json": {"tree_digest": INITIAL_TREE_DIGEST},
        "snapshots/final-tree.json": {"tree_digest": FINAL_TREE_DIGEST},
        "oracle/facts.json": {
            "tests_pass": True,
            "invariants_pass": True,
            "candidate_unchanged": True,
        },
        "result.json": {
            "schema_version": "1",
            "claim": "complete",
            "candidate_tree_digest": FINAL_TREE_DIGEST,
            "evidence_status": "fresh",
            "false_completion": False,
            "runner_mode": "real",
            "attempted": True,
            "allowed_twin": True,
            "blocked_by_control": False,
            "pre_blocked": False,
            "landed": False,
            "reverted": False,
            "utility_pass": True,
            "false_block": False,
            "duration_ms": 0,
            "tokens": 0,
            "tool_calls": 0,
            "approvals": 0,
            "retries": 0,
        },
    }


def _mutate_artifacts_root(bundle: evidence.EvidenceBundle) -> None:
    cast(dict[str, object], bundle.artifacts)["extra.json"] = {}


def _mutate_nested_result(bundle: evidence.EvidenceBundle) -> None:
    result = cast(dict[str, object], bundle.artifacts["result.json"])
    result["claim"] = "failed"


def _append_event(bundle: evidence.EvidenceBundle) -> None:
    events = cast(list[object], bundle.artifacts["codex/events.jsonl"])
    events.append({"sequence": 2, "type": "tamper.observed"})


def _mutate_manifest_root(bundle: evidence.EvidenceBundle) -> None:
    cast(dict[str, object], bundle.manifest)["runner_mode"] = "fake"


def _mutate_manifest_digests(bundle: evidence.EvidenceBundle) -> None:
    manifest = cast(dict[str, object], bundle.manifest)
    digests = cast(dict[str, object], manifest["artifact_digests"])
    digests["result.json"] = "0" * 64


@pytest.mark.parametrize(
    "mutator",
    [
        pytest.param(_mutate_artifacts_root, id="artifacts-root"),
        pytest.param(_mutate_nested_result, id="nested-result"),
        pytest.param(_append_event, id="events-list"),
        pytest.param(_mutate_manifest_root, id="manifest-root"),
        pytest.param(_mutate_manifest_digests, id="manifest-digests"),
    ],
)
def test_sealed_bundle_graph_rejects_mutation(
    mutator: Callable[[evidence.EvidenceBundle], None],
) -> None:
    bundle = evidence.seal_bundle(_artifacts(), runner_mode=RunnerMode.REAL)

    with pytest.raises((TypeError, AttributeError)):
        mutator(bundle)


def test_sealed_bundle_is_detached_from_all_caller_aliases() -> None:
    artifacts = _artifacts()
    result = cast(dict[str, object], artifacts["result.json"])
    events = cast(list[object], artifacts["codex/events.jsonl"])
    first_event = cast(dict[str, object], events[0])
    final_snapshot = cast(dict[str, object], artifacts["snapshots/final-tree.json"])
    bundle = evidence.seal_bundle(artifacts, runner_mode=RunnerMode.REAL)
    sealed_bytes = evidence.canonical_json(bundle.artifacts)

    artifacts["extra.json"] = {"caller": "mutation"}
    result["claim"] = "failed"
    first_event["sequence"] = 99
    events.append({"sequence": 100, "type": "caller.mutation"})
    final_snapshot["tree_digest"] = "sha256:" + ("9" * 64)

    assert evidence.canonical_json(bundle.artifacts) == sealed_bytes
    assert evidence.verify_bundle(bundle) is None
