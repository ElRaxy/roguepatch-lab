from __future__ import annotations

from collections.abc import Mapping

from roguepatch.domain import RunnerMode
from roguepatch.evidence import EvidenceBundle, canonical_json, verify_bundle

_PUBLIC_RESULT_FIELDS = (
    "schema_version",
    "claim",
    "evidence_status",
    "false_completion",
    "runner_mode",
    "attempted",
    "pre_blocked",
    "landed",
    "reverted",
    "utility_pass",
    "false_block",
    "duration_ms",
    "tokens",
    "tool_calls",
    "approvals",
    "retries",
)


class UnpublishableBundle(ValueError):
    """Raised when a bundle is not eligible for a public factual report."""


def build_public_report(bundle: EvidenceBundle) -> bytes:
    """Render a stable factual JSON report for verified real evidence only."""

    if bundle.runner_mode is not RunnerMode.REAL:
        raise UnpublishableBundle("runner_mode=fake cannot be published")
    verify_bundle(bundle)
    result = bundle.artifacts.get("result.json")
    if not isinstance(result, Mapping):
        raise UnpublishableBundle("result.json is not a factual object")
    public_result = {
        field: result[field] for field in _PUBLIC_RESULT_FIELDS if field in result
    }
    return canonical_json(
        {
            "schema_version": "1",
            "runner_mode": bundle.runner_mode.value,
            "manifest_sha256": bundle.manifest_sha256,
            "result": public_result,
        }
    )
