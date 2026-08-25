from __future__ import annotations

import csv
import io
from collections.abc import Mapping

from roguepatch.evidence import (
    EvidenceBundle,
    canonical_json,
)
from roguepatch.scoring import require_countable_real_result

_PUBLIC_RESULT_FIELDS = (
    "schema_version",
    "claim",
    "evidence_status",
    "runner_mode",
    "attempted",
    "allowed_twin",
    "blocked_by_control",
    "candidate_unchanged",
    "pre_blocked",
    "landed",
    "reverted",
    "false_completion",
    "not_exercised",
    "invalid",
    "utility_pass",
    "false_block",
    "duration_ms",
    "tokens",
    "tool_calls",
    "approvals",
    "retries",
)
_PUBLIC_ROOT_FIELDS = ("schema_version", "runner_mode", "manifest_sha256")


class UnpublishableBundle(ValueError):
    """Raised when a bundle is not eligible for a public factual report."""


def _public_payload(bundle: EvidenceBundle) -> dict[str, object]:
    try:
        result = require_countable_real_result(bundle).to_mapping()
    except (TypeError, ValueError) as error:
        raise UnpublishableBundle(str(error)) from error
    public_result = {
        field: result[field] for field in _PUBLIC_RESULT_FIELDS if field in result
    }
    return {
        "schema_version": "1",
        "runner_mode": bundle.runner_mode.value,
        "manifest_sha256": bundle.manifest_sha256,
        "result": public_result,
    }


def build_public_report(bundle: EvidenceBundle) -> bytes:
    """Render stable canonical JSON for verified real evidence only."""

    return canonical_json(_public_payload(bundle))


def _flat_public_items(payload: Mapping[str, object]) -> list[tuple[str, object]]:
    result = payload.get("result")
    if not isinstance(result, Mapping):
        raise UnpublishableBundle("reduced result is not a factual object")
    items = [(field, payload[field]) for field in _PUBLIC_ROOT_FIELDS]
    items.extend(
        (f"result.{field}", result[field])
        for field in _PUBLIC_RESULT_FIELDS
        if field in result
    )
    return items


def _scalar_text(value: object) -> str:
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def build_public_report_csv(bundle: EvidenceBundle) -> bytes:
    """Render stable one-row CSV from the same factual allowlist as JSON."""

    items = _flat_public_items(_public_payload(bundle))
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(field for field, _ in items)
    writer.writerow(_scalar_text(value) for _, value in items)
    return buffer.getvalue().encode("utf-8")


def build_public_report_markdown(bundle: EvidenceBundle) -> bytes:
    """Render stable Markdown from the same factual allowlist as JSON."""

    items = _flat_public_items(_public_payload(bundle))
    lines = [
        "# RoguePatch factual report",
        "",
        "| Field | Value |",
        "| --- | --- |",
    ]
    for field, value in items:
        text = _scalar_text(value).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {field} | {text} |")
    return ("\n".join(lines) + "\n").encode("utf-8")
