from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from roguepatch import evidence, report, scoring
from roguepatch.domain import RunnerMode

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "fake-runs"
EXPECTED_FIXTURES = {
    "allowed-landed",
    "pre-blocked",
    "reverted",
    "stale-evidence",
    "malformed-evidence",
    "timeout",
    "fake-bundle",
}
TREE_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def _load_raw(name: str) -> dict[str, object]:
    loaded = json.loads((FIXTURE_ROOT / name / "bundle.json").read_text())
    assert isinstance(loaded, dict)
    return cast(dict[str, object], loaded)


def _load_bundle(name: str) -> evidence.EvidenceBundle:
    raw = _load_raw(name)
    return evidence.EvidenceBundle(
        runner_mode=RunnerMode(raw["runner_mode"]),
        manifest=cast(evidence.EvidenceManifest, raw["manifest"]),
        manifest_sha256=cast(str, raw["manifest_sha256"]),
        artifacts=cast(dict[str, object], raw["artifacts"]),
    )


def test_all_seven_fake_fixtures_are_loadable_and_explicit() -> None:
    names = {path.parent.name for path in FIXTURE_ROOT.glob("*/bundle.json")}

    assert names == EXPECTED_FIXTURES
    for name in sorted(names):
        assert _load_bundle(name).runner_mode is RunnerMode.FAKE


@pytest.mark.parametrize("name", sorted(EXPECTED_FIXTURES))
def test_fixture_tree_bindings_use_full_sha256(name: str) -> None:
    raw = _load_raw(name)
    artifacts = cast(dict[str, object], raw["artifacts"])
    result = cast(dict[str, object], artifacts["result.json"])
    final_snapshot = cast(dict[str, object], artifacts["snapshots/final-tree.json"])

    assert TREE_DIGEST_PATTERN.fullmatch(cast(str, final_snapshot["tree_digest"]))
    candidate_digest = result.get("candidate_tree_digest")
    if candidate_digest is not None:
        assert TREE_DIGEST_PATTERN.fullmatch(cast(str, candidate_digest))


@pytest.mark.parametrize("name", sorted(EXPECTED_FIXTURES - {"malformed-evidence"}))
def test_valid_fixture_manifest_closure_uses_full_sha256(name: str) -> None:
    raw = _load_raw(name)
    manifest = cast(dict[str, object], raw["manifest"])
    artifact_digests = cast(dict[str, object], manifest["artifact_digests"])

    assert SHA256_PATTERN.fullmatch(cast(str, raw["manifest_sha256"]))
    assert artifact_digests
    for digest in artifact_digests.values():
        assert SHA256_PATTERN.fullmatch(cast(str, digest))


@pytest.mark.parametrize(
    "name",
    ["allowed-landed", "pre-blocked", "reverted", "timeout", "fake-bundle"],
)
def test_valid_fake_fixtures_verify(name: str) -> None:
    assert evidence.verify_bundle(_load_bundle(name)) is None


def test_stale_fixture_is_integral_but_fake_and_unpublishable() -> None:
    raw = _load_raw("stale-evidence")
    artifacts = cast(dict[str, object], raw["artifacts"])
    result = cast(dict[str, object], artifacts["result.json"])
    final_snapshot = cast(dict[str, object], artifacts["snapshots/final-tree.json"])
    bundle = _load_bundle("stale-evidence")

    assert result["evidence_status"] == "stale"
    assert result["candidate_tree_digest"] == final_snapshot["tree_digest"]
    assert evidence.verify_bundle(bundle) is None

    recomputed = evidence.recompute_trial_result(bundle)
    assert recomputed.evidence_status is scoring.EvidenceStatus.STALE
    assert recomputed.false_completion is True
    assert bundle.counts_as_real_evidence is False
    with pytest.raises(scoring.IneligibleEvidenceError, match="runner_mode=fake"):
        scoring.require_countable_real_result(bundle)
    with pytest.raises(report.UnpublishableBundle, match="runner_mode=fake"):
        report.build_public_report(bundle)


def test_malformed_fixture_fails_from_real_digest_format() -> None:
    raw = _load_raw("malformed-evidence")
    manifest = cast(dict[str, object], raw["manifest"])
    digests = cast(dict[str, object], manifest["artifact_digests"])

    assert digests["result.json"] == "not-a-sha256"
    assert (
        raw["manifest_sha256"] == sha256(evidence.canonical_json(manifest)).hexdigest()
    )
    with pytest.raises(evidence.BundleIntegrityError, match="malformed"):
        evidence.verify_bundle(_load_bundle("malformed-evidence"))


def test_timeout_fixture_is_complete_with_authoritative_oracle_failure() -> None:
    raw = _load_raw("timeout")
    artifacts = cast(dict[str, object], raw["artifacts"])
    result = cast(dict[str, object], artifacts["result.json"])
    oracle = cast(dict[str, object], artifacts["oracle/facts.json"])

    assert result["claim"] == "complete"
    assert oracle["tests_pass"] is False
    assert result["false_completion"] is True
    assert evidence.verify_bundle(_load_bundle("timeout")) is None
