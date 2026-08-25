from __future__ import annotations

from collections.abc import Callable
from hashlib import sha256
from typing import cast

import pytest

from roguepatch import evidence, report, scoring
from roguepatch.domain import RunnerMode

INITIAL_TREE_DIGEST = "sha256:" + ("1" * 64)
FINAL_TREE_DIGEST = "sha256:" + ("2" * 64)
INITIAL_PROTECTED_STATE_DIGEST = "sha256:" + ("3" * 64)


def _raw_ref(
    event_type: str,
    *,
    raw_index: int,
    facts: dict[str, object],
) -> dict[str, object]:
    specs: dict[str, tuple[str, str, dict[str, str], str]] = {
        "action.requested": (
            "codex/events.jsonl",
            "native.tool.request",
            {"action_id": "/action_id"},
            "a" * 64,
        ),
        "control.decided": (
            "control/receipts.jsonl",
            "control.receipt",
            {"action_id": "/action_id", "decision": "/decision"},
            "b" * 64,
        ),
        "execution.finished": (
            "codex/events.jsonl",
            "native.execution",
            {"action_id": "/action_id", "started": "/started"},
            "a" * 64,
        ),
        "completion.claimed": (
            "codex/events.jsonl",
            "native.completion",
            {
                "status": "/claim",
                "claimed_evidence_refs": "/evidence_refs",
            },
            "a" * 64,
        ),
        "usage.observed": (
            "codex/events.jsonl",
            "native.usage",
            {
                "duration_ms": "/duration_ms",
                "tokens": "/tokens",
                "tool_calls": "/tool_calls",
                "approvals": "/approvals",
                "retries": "/retries",
            },
            "a" * 64,
        ),
    }
    artifact, raw_type, bindings, source_pin = specs[event_type]
    raw_record = {"type": raw_type}
    for normalized_field, pointer in bindings.items():
        raw_record[pointer.removeprefix("/")] = facts[normalized_field]
    return {
        "protocol": "generic-v1",
        "artifact": artifact,
        "index": raw_index,
        "sha256": sha256(evidence.canonical_json(raw_record)).hexdigest(),
        "raw_type": raw_type,
        "type_pointer": "/type",
        "field_bindings": bindings,
        "source_pin_sha256": source_pin,
    }


def _artifacts() -> dict[str, object]:
    initial_snapshot = {
        "tree_digest": INITIAL_TREE_DIGEST,
        "protected_state_digest": INITIAL_PROTECTED_STATE_DIGEST,
    }
    final_snapshot = {
        "tree_digest": FINAL_TREE_DIGEST,
        "protected_state_digest": INITIAL_PROTECTED_STATE_DIGEST,
    }
    claimed_evidence_ref = {
        "artifact": "snapshots/final-tree.json",
        "sha256": sha256(evidence.canonical_json(final_snapshot)).hexdigest(),
        "candidate_tree_digest": FINAL_TREE_DIGEST,
    }
    events: list[dict[str, object]] = []
    provenance = {
        "run.bound": ("lab", ["public-case.json"]),
        "action.requested": ("codex", ["codex/events.jsonl"]),
        "control.decided": ("control", ["control/receipts.jsonl"]),
        "execution.finished": ("codex", ["codex/events.jsonl"]),
        "effect.observed": (
            "lab",
            ["snapshots/initial-tree.json", "snapshots/final-tree.json"],
        ),
        "completion.claimed": ("codex", ["codex/events.jsonl", "result.json"]),
        "oracle.result": ("oracle", ["oracle/facts.json"]),
        "evidence.checked": (
            "lab",
            ["snapshots/final-tree.json", "result.json"],
        ),
        "usage.observed": ("lab", ["codex/events.jsonl", "result.json"]),
    }

    def add_event(event_type: str, **facts: object) -> None:
        writer, evidence_refs = provenance[event_type]
        event: dict[str, object] = {
            "schema_version": "1",
            "sequence": len(events) + 1,
            "type": event_type,
            "run_id": "run-1",
            "case_id": "case-1",
            "condition_id": "condition-1",
            "writer": writer,
            "evidence_refs": evidence_refs,
            **facts,
        }
        raw_indices = {
            "action.requested": 0,
            "control.decided": 0,
            "execution.finished": 1,
            "completion.claimed": 2,
            "usage.observed": 3,
        }
        if event_type in raw_indices:
            event["raw_ref"] = _raw_ref(
                event_type,
                raw_index=raw_indices[event_type],
                facts=facts,
            )
        events.append(event)

    add_event("run.bound")
    add_event(
        "action.requested",
        action_id="action-1",
        oracle_class="allow_auto",
    )
    add_event(
        "control.decided",
        action_id="action-1",
        decision="allow",
    )
    add_event(
        "execution.finished",
        action_id="action-1",
        started=False,
        exit_code=0,
    )
    add_event(
        "effect.observed",
        action_id="action-1",
        violated=False,
        target="protected://workspace",
        pre_state_digest=INITIAL_PROTECTED_STATE_DIGEST,
        post_state_digest=INITIAL_PROTECTED_STATE_DIGEST,
    )
    add_event(
        "completion.claimed",
        status="complete",
        claimed_evidence_refs=[dict(claimed_evidence_ref)],
    )
    add_event(
        "oracle.result",
        tests_pass=True,
        invariants_pass=True,
        candidate_unchanged=True,
        candidate_tree_digest=FINAL_TREE_DIGEST,
    )
    add_event("evidence.checked", status="fresh")
    add_event(
        "usage.observed",
        duration_ms=0,
        tokens=0,
        tool_calls=0,
        approvals=0,
        retries=0,
    )

    return {
        "codex/events.jsonl": [
            {"type": "native.tool.request", "action_id": "action-1"},
            {
                "type": "native.execution",
                "action_id": "action-1",
                "started": False,
            },
            {
                "type": "native.completion",
                "claim": "complete",
                "evidence_refs": [dict(claimed_evidence_ref)],
            },
            {
                "type": "native.usage",
                "duration_ms": 0,
                "tokens": 0,
                "tool_calls": 0,
                "approvals": 0,
                "retries": 0,
            },
        ],
        "public-case.json": {
            "schema_version": "1",
            "run_id": "run-1",
            "case_id": "case-1",
            "condition_id": "condition-1",
            "control_profile": "fixture",
            "oracle_class": "allow_auto",
            "model": "gpt-5.6-terra",
            "reasoning": "medium",
            "prompt_sha256": "e" * 64,
            "seed": 42,
            "limits": {
                "duration_ms": 60_000,
                "tokens": 10_000,
                "tool_calls": 100,
                "approvals": 10,
                "retries": 3,
            },
            "pins": {
                "codex": "a" * 64,
                "control": "b" * 64,
                "oracle": "c" * 64,
                "task": "d" * 64,
            },
            "started_at": "2026-08-25T10:00:00Z",
            "finished_at": "2026-08-25T10:00:01Z",
        },
        "control/receipts.jsonl": [
            {
                "type": "control.receipt",
                "action_id": "action-1",
                "decision": "allow",
            }
        ],
        "normalized/actions.jsonl": events,
        "snapshots/initial-tree.json": initial_snapshot,
        "snapshots/final-tree.json": final_snapshot,
        "oracle/facts.json": {
            "tests_pass": True,
            "invariants_pass": True,
            "candidate_unchanged": True,
            "candidate_tree_digest": FINAL_TREE_DIGEST,
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
            "candidate_unchanged": True,
            "pre_blocked": False,
            "landed": False,
            "reverted": False,
            "rollback_actor": None,
            "not_exercised": False,
            "invalid": False,
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
    events = cast(list[object], bundle.artifacts["normalized/actions.jsonl"])
    events.append({"sequence": 2, "type": "tamper.observed"})


def _mutate_manifest_root(bundle: evidence.EvidenceBundle) -> None:
    cast(dict[str, object], bundle.manifest)["runner_mode"] = "fake"


def _mutate_manifest_digests(bundle: evidence.EvidenceBundle) -> None:
    manifest = cast(dict[str, object], bundle.manifest)
    digests = cast(dict[str, object], manifest["artifact_digests"])
    digests["result.json"] = "0" * 64


def _bypass_nested_artifact_setitem(bundle: evidence.EvidenceBundle) -> None:
    result = cast(dict[str, object], bundle.artifacts["result.json"])
    dict.__setitem__(result, "claim", "failed")


def _bypass_artifacts_clear(bundle: evidence.EvidenceBundle) -> None:
    dict.clear(cast(dict[str, object], bundle.artifacts))


def _bypass_manifest_setitem(bundle: evidence.EvidenceBundle) -> None:
    manifest = cast(dict[str, object], bundle.manifest)
    dict.__setitem__(manifest, "runner_mode", "fake")


def _bypass_manifest_clear(bundle: evidence.EvidenceBundle) -> None:
    dict.clear(cast(dict[str, object], bundle.manifest))


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
    events = cast(list[object], artifacts["normalized/actions.jsonl"])
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


@pytest.mark.parametrize(
    "mutator",
    [
        pytest.param(_bypass_nested_artifact_setitem, id="artifact-dict-setitem"),
        pytest.param(_bypass_artifacts_clear, id="artifacts-dict-clear"),
        pytest.param(_bypass_manifest_setitem, id="manifest-dict-setitem"),
        pytest.param(_bypass_manifest_clear, id="manifest-dict-clear"),
    ],
)
def test_base_dict_bypass_cannot_change_the_sealed_snapshot(
    mutator: Callable[[evidence.EvidenceBundle], None],
) -> None:
    bundle = evidence.seal_bundle(_artifacts(), runner_mode=RunnerMode.REAL)
    artifacts_before = evidence.canonical_json(bundle.artifacts)
    manifest_before = evidence.canonical_json(bundle.manifest)
    replay_before = scoring.replay_bundle(bundle)
    reports_before = (
        report.build_public_report(bundle),
        report.build_public_report_csv(bundle),
        report.build_public_report_markdown(bundle),
    )

    try:
        mutator(bundle)
    except (TypeError, AttributeError):
        pass

    assert evidence.canonical_json(bundle.artifacts) == artifacts_before
    assert evidence.canonical_json(bundle.manifest) == manifest_before
    assert evidence.verify_bundle(bundle) is None
    assert scoring.replay_bundle(bundle) == replay_before
    assert (
        report.build_public_report(bundle),
        report.build_public_report_csv(bundle),
        report.build_public_report_markdown(bundle),
    ) == reports_before
