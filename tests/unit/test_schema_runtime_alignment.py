from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import cast

import pytest

from roguepatch import evidence
from roguepatch.domain import RunnerMode

SCHEMA_ROOT = Path(__file__).parents[2] / "schemas"
MIN_SAFE_INTEGER = -((1 << 53) - 1)
MAX_SAFE_INTEGER = (1 << 53) - 1
INITIAL_TREE_DIGEST = "sha256:" + ("1" * 64)
FINAL_TREE_DIGEST = "sha256:" + ("2" * 64)


def _load_schema(name: str) -> dict[str, object]:
    loaded = json.loads((SCHEMA_ROOT / name).read_text())
    assert isinstance(loaded, dict)
    return cast(dict[str, object], loaded)


def _complete_artifacts(*, claim: str = "complete") -> dict[str, object]:
    return {
        "codex/events.jsonl": [
            {"schema_version": "1", "sequence": 1, "type": "fixture.observed"}
        ],
        "public-case.json": {
            "schema_version": "1",
            "run_id": "run-1",
            "case_id": "case-1",
            "condition_id": "condition-1",
            "control_profile": "baseline",
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
        "snapshots/initial-tree.json": {"tree_digest": INITIAL_TREE_DIGEST},
        "snapshots/final-tree.json": {"tree_digest": FINAL_TREE_DIGEST},
        "oracle/facts.json": {
            "tests_pass": True,
            "invariants_pass": True,
            "candidate_unchanged": True,
        },
        "result.json": {
            "schema_version": "1",
            "claim": claim,
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


def _integer_schemas(value: object) -> Iterator[Mapping[str, object]]:
    if isinstance(value, Mapping):
        if value.get("type") == "integer":
            yield value
        for nested in value.values():
            yield from _integer_schemas(nested)
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes):
        for nested in value:
            yield from _integer_schemas(nested)


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        pytest.param("codex/events.jsonl", "not-an-array", id="events-not-array"),
        pytest.param("codex/events.jsonl", [1], id="event-not-object"),
        pytest.param("snapshots/initial-tree.json", 7, id="initial-not-object"),
        pytest.param("snapshots/final-tree.json", 7, id="final-not-object"),
    ],
)
def test_runtime_rejects_artifact_shapes_forbidden_by_schema(
    path: str,
    payload: object,
) -> None:
    artifacts = _complete_artifacts()
    artifacts[path] = payload
    bundle = evidence.seal_bundle(artifacts, runner_mode=RunnerMode.REAL)

    with pytest.raises(
        evidence.BundleIntegrityError,
        match="event|snapshot|artifact",
    ):
        evidence.verify_bundle(bundle)


@pytest.mark.parametrize(
    ("candidate_digest", "final_digest", "location"),
    [
        pytest.param("sha256:short", FINAL_TREE_DIGEST, "candidate", id="candidate"),
        pytest.param(FINAL_TREE_DIGEST, "sha256:short", "final", id="final"),
    ],
)
def test_runtime_requires_full_sha256_for_complete_tree_bindings(
    candidate_digest: str,
    final_digest: str,
    location: str,
) -> None:
    artifacts = _complete_artifacts()
    result = cast(dict[str, object], artifacts["result.json"])
    final_snapshot = cast(dict[str, object], artifacts["snapshots/final-tree.json"])
    result["candidate_tree_digest"] = candidate_digest
    final_snapshot["tree_digest"] = final_digest
    bundle = evidence.seal_bundle(artifacts, runner_mode=RunnerMode.REAL)

    with pytest.raises(
        evidence.BundleIntegrityError,
        match=rf"malformed.*{location}|{location}.*malformed",
    ):
        evidence.verify_bundle(bundle)


@pytest.mark.parametrize("claim", ["complete", "blocked", "failed"])
@pytest.mark.parametrize("location", ["candidate", "final"])
@pytest.mark.parametrize(
    "malformed_digest",
    [
        pytest.param("sha256:short", id="abbreviated"),
        pytest.param("sha256:" + ("g" * 64), id="non-hex"),
    ],
)
def test_every_claim_rejects_malformed_tree_bindings(
    claim: str,
    location: str,
    malformed_digest: str,
) -> None:
    artifacts = _complete_artifacts(claim=claim)
    result = cast(dict[str, object], artifacts["result.json"])
    final_snapshot = cast(dict[str, object], artifacts["snapshots/final-tree.json"])
    if location == "candidate":
        result["candidate_tree_digest"] = malformed_digest
    else:
        final_snapshot["tree_digest"] = malformed_digest
    bundle = evidence.seal_bundle(artifacts, runner_mode=RunnerMode.REAL)

    with pytest.raises(
        evidence.BundleIntegrityError,
        match=rf"malformed.*{location}|{location}.*malformed",
    ):
        evidence.verify_bundle(bundle)


@pytest.mark.parametrize("claim", ["complete", "blocked", "failed"])
def test_every_claim_requires_a_candidate_tree_binding(claim: str) -> None:
    artifacts = _complete_artifacts(claim=claim)
    result = cast(dict[str, object], artifacts["result.json"])
    del result["candidate_tree_digest"]
    bundle = evidence.seal_bundle(artifacts, runner_mode=RunnerMode.REAL)

    with pytest.raises(evidence.BundleIntegrityError, match="candidate.*binding"):
        evidence.verify_bundle(bundle)


def test_schema_tree_digest_matches_runtime_contract() -> None:
    schema = _load_schema("evidence-bundle.schema.json")
    definitions = cast(dict[str, object], schema["$defs"])
    tree_digest = cast(dict[str, object], definitions["tree_digest"])
    pattern = cast(str, tree_digest["pattern"])

    assert re.fullmatch(pattern, FINAL_TREE_DIGEST)
    for invalid in (
        "",
        "sha256:",
        "sha256:short",
        "sha256:" + ("g" * 64),
    ):
        assert re.fullmatch(pattern, invalid) is None


def test_schema_and_runtime_share_artifact_container_shapes() -> None:
    schema = _load_schema("evidence-bundle.schema.json")
    properties = cast(dict[str, object], schema["properties"])
    artifacts_schema = cast(dict[str, object], properties["artifacts"])
    artifact_properties = cast(dict[str, object], artifacts_schema["properties"])
    events_schema = cast(dict[str, object], artifact_properties["codex/events.jsonl"])

    assert events_schema["type"] == "array"
    assert events_schema["items"] == {"$ref": "#/$defs/json_object"}
    assert artifact_properties["snapshots/initial-tree.json"] == {
        "$ref": "#/$defs/json_object"
    }
    assert artifact_properties["snapshots/final-tree.json"] == {
        "$ref": "#/$defs/final_tree_snapshot"
    }


def test_claimed_schema_binds_the_complete_experiment_identity() -> None:
    schema = _load_schema("evidence-bundle.schema.json")
    definitions = cast(dict[str, object], schema["$defs"])
    public_case = cast(dict[str, object], definitions["public_case"])
    expected_fields = {
        "schema_version",
        "run_id",
        "case_id",
        "condition_id",
        "control_profile",
        "oracle_class",
        "model",
        "reasoning",
        "prompt_sha256",
        "seed",
        "limits",
        "pins",
        "started_at",
        "finished_at",
    }

    assert set(cast(list[str], public_case["required"])) == expected_fields
    assert public_case["additionalProperties"] is False
    properties = cast(dict[str, object], public_case["properties"])
    limits = cast(dict[str, object], properties["limits"])
    pins = cast(dict[str, object], properties["pins"])
    assert set(cast(list[str], limits["required"])) == {
        "duration_ms",
        "tokens",
        "tool_calls",
        "approvals",
        "retries",
    }
    assert set(cast(list[str], pins["required"])) == {
        "codex",
        "control",
        "oracle",
        "task",
    }


def test_claimed_schema_matches_the_closed_raw_ref_runtime_contract() -> None:
    schema = _load_schema("evidence-bundle.schema.json")
    definitions = cast(dict[str, object], schema["$defs"])
    raw_ref = cast(dict[str, object], definitions["raw_ref"])
    claimed_event = cast(dict[str, object], definitions["claimed_event"])
    raw_ref_fields = {
        "protocol",
        "artifact",
        "index",
        "sha256",
        "raw_type",
        "type_pointer",
        "field_bindings",
        "source_pin_sha256",
    }

    assert set(cast(list[str], raw_ref["required"])) == raw_ref_fields
    assert raw_ref["additionalProperties"] is False
    raw_ref_properties = cast(dict[str, object], raw_ref["properties"])
    raw_index = cast(dict[str, object], raw_ref_properties["index"])
    assert raw_index == {
        "type": "integer",
        "minimum": 0,
        "maximum": MAX_SAFE_INTEGER,
    }
    event_properties = cast(dict[str, object], claimed_event["properties"])
    assert event_properties["raw_ref"] == {"$ref": "#/$defs/raw_ref"}
    conditionals = cast(list[dict[str, object]], claimed_event["allOf"])
    assert any(
        "raw_ref" in cast(list[str], conditional.get("then", {}).get("required", []))
        for conditional in conditionals
    )


def test_claimed_schema_binds_oracle_to_the_current_candidate_tree() -> None:
    schema = _load_schema("evidence-bundle.schema.json")
    definitions = cast(dict[str, object], schema["$defs"])
    oracle_facts = cast(dict[str, object], definitions["claimed_oracle_facts"])
    claimed_event = cast(dict[str, object], definitions["claimed_event"])

    assert "candidate_tree_digest" in cast(list[str], oracle_facts["required"])
    oracle_properties = cast(dict[str, object], oracle_facts["properties"])
    assert oracle_properties["candidate_tree_digest"] == {"$ref": "#/$defs/tree_digest"}
    oracle_conditional = next(
        conditional
        for conditional in cast(list[dict[str, object]], claimed_event["allOf"])
        if conditional.get("if", {}).get("properties", {}).get("type", {}).get("const")
        == "oracle.result"
    )
    assert "candidate_tree_digest" in cast(
        list[str], oracle_conditional["then"]["required"]
    )


def test_claimed_schema_requires_protected_checkpoints_and_typed_rollback_actor() -> (
    None
):
    schema = _load_schema("evidence-bundle.schema.json")
    definitions = cast(dict[str, object], schema["$defs"])
    protected_snapshot = cast(dict[str, object], definitions["claimed_tree_snapshot"])
    claimed_event = cast(dict[str, object], definitions["claimed_event"])

    assert set(cast(list[str], protected_snapshot["required"])) == {
        "tree_digest",
        "protected_state_digest",
    }
    conditionals = cast(list[dict[str, object]], claimed_event["allOf"])
    rollback = next(
        conditional
        for conditional in conditionals
        if conditional.get("if", {}).get("properties", {}).get("type", {}).get("const")
        == "rollback.observed"
    )
    rollback_then = cast(dict[str, object], rollback["then"])
    assert {
        "violation_id",
        "actor",
        "restored",
        "target",
        "pre_state_digest",
        "post_state_digest",
    }.issubset(cast(list[str], rollback_then["required"]))
    rollback_properties = cast(dict[str, object], rollback_then["properties"])
    assert rollback_properties["actor"] == {"enum": ["control", "agent", "lab_cleanup"]}


def test_claimed_completion_schema_separates_provenance_from_claimed_refs() -> None:
    evidence_schema = _load_schema("evidence-bundle.schema.json")
    definitions = cast(dict[str, object], evidence_schema["$defs"])
    claimed_ref = cast(dict[str, object], definitions["claimed_evidence_ref"])
    completion_ref = cast(dict[str, object], definitions["completion_raw_ref"])
    claimed_event = cast(dict[str, object], definitions["claimed_event"])
    agent_result = _load_schema("agent-result.schema.json")

    assert set(cast(list[str], claimed_ref["required"])) == {
        "artifact",
        "sha256",
        "candidate_tree_digest",
    }
    assert claimed_ref["additionalProperties"] is False
    completion_properties = cast(dict[str, object], completion_ref["properties"])
    bindings = cast(dict[str, object], completion_properties["field_bindings"])
    assert set(cast(list[str], bindings["required"])) == {
        "status",
        "claimed_evidence_refs",
    }
    assert "evidence_refs" in cast(list[str], agent_result["required"])
    completion = next(
        conditional
        for conditional in cast(list[dict[str, object]], claimed_event["allOf"])
        if conditional.get("if", {}).get("properties", {}).get("type", {}).get("const")
        == "completion.claimed"
    )
    completion_properties = cast(dict[str, object], completion["then"]["properties"])
    captured_refs = cast(
        dict[str, object], completion_properties["claimed_evidence_refs"]
    )
    assert captured_refs["items"] == {"$ref": "#/$defs/json_value"}
    agent_properties = cast(dict[str, object], agent_result["properties"])
    agent_refs = cast(dict[str, object], agent_properties["evidence_refs"])
    assert agent_refs["items"] == {"$ref": "#/$defs/json_value"}


def test_claimed_result_schema_preserves_nullable_rollback_actor() -> None:
    schema = _load_schema("evidence-bundle.schema.json")
    definitions = cast(dict[str, object], schema["$defs"])
    trial_result = cast(dict[str, object], definitions["trial_result"])
    properties = cast(dict[str, object], trial_result["properties"])

    assert properties["rollback_actor"] == {
        "enum": [None, "control", "agent", "lab_cleanup"]
    }


def test_all_schema_integers_stay_inside_rfc8785_safe_range() -> None:
    schemas = [
        _load_schema("agent-result.schema.json"),
        _load_schema("evidence-bundle.schema.json"),
    ]
    integer_schemas = [node for schema in schemas for node in _integer_schemas(schema)]

    assert integer_schemas
    for integer_schema in integer_schemas:
        minimum = integer_schema.get("minimum")
        maximum = integer_schema.get("maximum")
        assert type(minimum) is int
        assert type(maximum) is int
        assert MIN_SAFE_INTEGER <= minimum <= MAX_SAFE_INTEGER
        assert MIN_SAFE_INTEGER <= maximum <= MAX_SAFE_INTEGER


def test_runtime_rejects_integers_outside_rfc8785_safe_range() -> None:
    assert evidence.canonical_json(
        {"minimum": MIN_SAFE_INTEGER, "maximum": MAX_SAFE_INTEGER}
    )
    for unsafe in (MIN_SAFE_INTEGER - 1, MAX_SAFE_INTEGER + 1):
        with pytest.raises(evidence.CanonicalizationError):
            evidence.canonical_json({"unsafe": unsafe})
