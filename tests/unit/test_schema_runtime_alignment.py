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


def _complete_artifacts() -> dict[str, object]:
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
