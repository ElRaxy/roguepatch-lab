from collections.abc import Mapping
from dataclasses import replace
from hashlib import sha256

import pytest
import rfc8785

from roguepatch import evidence, report, scoring
from roguepatch.domain import ActionSources, RunnerMode


def _artifacts(evidence_status: str = "fresh") -> dict[str, object]:
    return {
        "codex/events.jsonl": [
            {
                "schema_version": "1",
                "sequence": 1,
                "type": "action.requested",
            }
        ],
        "snapshots/initial-tree.json": {"tree_digest": "sha256:initial"},
        "snapshots/final-tree.json": {"tree_digest": "sha256:final"},
        "oracle/facts.json": {
            "tests_pass": True,
            "invariants_pass": True,
            "candidate_unchanged": True,
        },
        "result.json": {
            "evidence_status": evidence_status,
            "false_completion": False,
        },
    }


def _metric_row(runner_mode: RunnerMode) -> dict[str, object]:
    return {
        "runner_mode": runner_mode,
        "attempted": True,
        "pre_blocked": False,
        "landed": True,
        "reverted": False,
        "false_completion": False,
        "utility_pass": True,
        "false_block": False,
        "duration_ms": 100,
        "tokens": 10,
        "tool_calls": 2,
        "approvals": 0,
        "retries": 0,
    }


def test_canonical_json_matches_rfc8785_and_rejects_nested_floats() -> None:
    value = {"z": [3, 2, 1], "a": {"unicode": "á"}}

    assert evidence.canonical_json(value) == rfc8785.dumps(value)
    with pytest.raises(evidence.CanonicalizationError, match="float"):
        evidence.canonical_json({"outer": [{"not_allowed": 1.5}]})


def test_r15_bundle_digest_closure() -> None:
    artifacts = _artifacts()
    bundle = evidence.seal_bundle(artifacts, runner_mode=RunnerMode.REAL)
    artifact_digests = bundle.manifest["artifact_digests"]
    assert isinstance(artifact_digests, Mapping)

    assert set(artifact_digests) == set(artifacts)
    for path, payload in artifacts.items():
        assert artifact_digests[path] == sha256(rfc8785.dumps(payload)).hexdigest()
    assert bundle.manifest_sha256 == sha256(rfc8785.dumps(bundle.manifest)).hexdigest()
    assert evidence.verify_bundle(bundle) is None

    tampered_artifacts = dict(bundle.artifacts)
    tampered_artifacts["result.json"] = {
        "evidence_status": "fresh",
        "false_completion": True,
    }
    with pytest.raises(evidence.BundleIntegrityError, match="digest"):
        evidence.verify_bundle(replace(bundle, artifacts=tampered_artifacts))

    missing_required = _artifacts()
    del missing_required["oracle/facts.json"]
    with pytest.raises(evidence.BundleIntegrityError, match="missing.*oracle"):
        evidence.seal_bundle(missing_required, runner_mode=RunnerMode.REAL)

    dangling_digests = dict(artifact_digests)
    dangling_digests["dangling.json"] = sha256(b"dangling").hexdigest()
    dangling_manifest = {
        **bundle.manifest,
        "artifact_digests": dangling_digests,
    }
    dangling = replace(
        bundle,
        manifest=dangling_manifest,
        manifest_sha256=sha256(rfc8785.dumps(dangling_manifest)).hexdigest(),
    )
    with pytest.raises(evidence.BundleIntegrityError, match="dangling"):
        evidence.verify_bundle(dangling)

    stale = evidence.seal_bundle(_artifacts("stale"), runner_mode=RunnerMode.REAL)
    with pytest.raises(evidence.BundleIntegrityError, match="stale"):
        evidence.verify_bundle(stale)

    malformed_digests = dict(artifact_digests)
    malformed_digests["result.json"] = "not-a-sha256"
    malformed_manifest = {
        **bundle.manifest,
        "artifact_digests": malformed_digests,
    }
    malformed = replace(
        bundle,
        manifest=malformed_manifest,
        manifest_sha256=sha256(rfc8785.dumps(malformed_manifest)).hexdigest(),
    )
    with pytest.raises(evidence.BundleIntegrityError, match="malformed"):
        evidence.verify_bundle(malformed)


def test_r16_replay_is_byte_identical() -> None:
    artifacts = _artifacts()
    reverse_order = dict(reversed(tuple(artifacts.items())))
    bundle = evidence.seal_bundle(artifacts, runner_mode=RunnerMode.REAL)
    reordered_bundle = evidence.seal_bundle(reverse_order, runner_mode=RunnerMode.REAL)

    first = scoring.replay_bundle(bundle)
    second = scoring.replay_bundle(bundle)
    reordered = scoring.replay_bundle(reordered_bundle)

    source_request = {
        "z": [3, 2, 1],
        "a": {"nested": ["x", "y"]},
    }
    sources = ActionSources(
        request=source_request,
        receipt=None,
        snapshots=({"tree": ["initial", "final"]},),
    )

    assert isinstance(first, bytes)
    assert second == first
    assert reordered == first
    assert evidence.canonical_json(sources.request) == rfc8785.dumps(source_request)
    assert evidence.canonical_json(sources.snapshots) == rfc8785.dumps(
        [{"tree": ["initial", "final"]}]
    )


def test_r17_fake_bundle_cannot_publish() -> None:
    fake_bundle = evidence.seal_bundle(_artifacts(), runner_mode=RunnerMode.FAKE)

    assert fake_bundle.counts_as_real_evidence is False
    with pytest.raises(report.UnpublishableBundle, match="runner_mode=fake"):
        report.build_public_report(fake_bundle)

    real_bundle = evidence.seal_bundle(_artifacts(), runner_mode=RunnerMode.REAL)
    for rows in (
        [_metric_row(RunnerMode.FAKE)],
        [_metric_row(RunnerMode.REAL), _metric_row(RunnerMode.FAKE)],
    ):
        with pytest.raises(scoring.IneligibleEvidenceError, match="runner_mode=fake"):
            scoring.build_metrics(rows)

    forged_mode = replace(real_bundle, runner_mode=RunnerMode.FAKE)
    with pytest.raises(evidence.BundleIntegrityError, match="runner_mode"):
        evidence.verify_bundle(forged_mode)
