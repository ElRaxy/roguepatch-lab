from __future__ import annotations

import json
from collections.abc import Callable

import pytest

from roguepatch import evidence, report
from roguepatch.domain import RunnerMode

INITIAL_TREE_DIGEST = "sha256:" + ("1" * 64)
FINAL_TREE_DIGEST = "sha256:" + ("2" * 64)


def _bundle(runner_mode: RunnerMode) -> evidence.EvidenceBundle:
    artifacts: dict[str, object] = {
        "codex/events.jsonl": [
            {
                "schema_version": "1",
                "sequence": 1,
                "type": "diagnostic.observed",
                "private_reasoning": "must-not-publish",
                "score": 99,
            }
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
            "runner_mode": runner_mode.value,
            "attempted": True,
            "allowed_twin": True,
            "blocked_by_control": False,
            "candidate_unchanged": True,
            "pre_blocked": False,
            "landed": False,
            "reverted": False,
            "not_exercised": False,
            "invalid": False,
            "utility_pass": True,
            "false_block": False,
            "duration_ms": 5,
            "tokens": 2,
            "tool_calls": 1,
            "approvals": 0,
            "retries": 0,
        },
    }
    return evidence.seal_bundle(artifacts, runner_mode=runner_mode)


@pytest.mark.parametrize(
    "renderer_name",
    [
        "build_public_report",
        "build_public_report_csv",
        "build_public_report_markdown",
    ],
)
def test_public_formats_are_byte_stable_and_allowlisted(renderer_name: str) -> None:
    renderer: Callable[[evidence.EvidenceBundle], bytes] = getattr(
        report, renderer_name
    )
    bundle = _bundle(RunnerMode.REAL)

    first = renderer(bundle)
    second = renderer(bundle)

    assert isinstance(first, bytes)
    assert second == first
    assert b"false_completion" in first
    assert b"must-not-publish" not in first
    assert b"private_reasoning" not in first
    assert b"score" not in first


def test_json_public_report_remains_canonical_and_factual() -> None:
    payload = json.loads(report.build_public_report(_bundle(RunnerMode.REAL)))

    assert set(payload) == {
        "schema_version",
        "runner_mode",
        "manifest_sha256",
        "result",
    }
    assert payload["result"]["false_completion"] is False


@pytest.mark.parametrize(
    "renderer_name",
    [
        "build_public_report",
        "build_public_report_csv",
        "build_public_report_markdown",
    ],
)
def test_every_public_format_rejects_fake_evidence(renderer_name: str) -> None:
    renderer: Callable[[evidence.EvidenceBundle], bytes] = getattr(
        report, renderer_name
    )

    with pytest.raises(report.UnpublishableBundle, match="runner_mode=fake"):
        renderer(_bundle(RunnerMode.FAKE))
