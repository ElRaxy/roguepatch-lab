from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import TypedDict, cast

import rfc8785

from roguepatch.domain import RunnerMode
from roguepatch.scoring import (
    CompletionClaim,
    EvidenceStatus,
    TrialFacts,
    reduce_trial,
)

REQUIRED_ARTIFACTS = frozenset(
    {
        "codex/events.jsonl",
        "snapshots/initial-tree.json",
        "snapshots/final-tree.json",
        "oracle/facts.json",
        "result.json",
    }
)
_MANIFEST_KEYS = frozenset({"schema_version", "runner_mode", "artifact_digests"})
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_RESULT_KEYS = frozenset(
    {
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
    }
)
_BOOLEAN_RESULT_FIELDS = frozenset(
    {
        "false_completion",
        "attempted",
        "pre_blocked",
        "landed",
        "reverted",
        "utility_pass",
        "false_block",
    }
)
_COST_RESULT_FIELDS = frozenset(
    {"duration_ms", "tokens", "tool_calls", "approvals", "retries"}
)
type JsonValue = None | bool | int | str | list[JsonValue] | dict[str, JsonValue]


class EvidenceManifest(TypedDict):
    schema_version: str
    runner_mode: str
    artifact_digests: dict[str, str]


class CanonicalizationError(ValueError):
    """Raised when a value is outside the supported JSON evidence domain."""


class BundleIntegrityError(ValueError):
    """Raised when a bundle cannot prove a closed evidence graph."""


def _to_plain_json(value: object, *, location: str = "$") -> JsonValue:
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        raise CanonicalizationError(f"float is forbidden at {location}")
    if isinstance(value, Mapping):
        plain: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"JSON object key is not a string at {location}"
                )
            plain[key] = _to_plain_json(item, location=f"{location}.{key}")
        return plain
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [
            _to_plain_json(item, location=f"{location}[{index}]")
            for index, item in enumerate(value)
        ]
    raise CanonicalizationError(
        f"unsupported non-JSON type {type(value).__name__} at {location}"
    )


def _plain_mapping(value: object, *, location: str) -> dict[str, JsonValue]:
    plain = _to_plain_json(value, location=location)
    if not isinstance(plain, dict):
        raise CanonicalizationError(f"expected JSON object at {location}")
    return plain


def canonical_json(value: object) -> bytes:
    """Return RFC 8785 bytes for the deliberately float-free JSON domain."""

    try:
        return rfc8785.dumps(_to_plain_json(value))
    except CanonicalizationError:
        raise
    except (rfc8785.CanonicalizationError, ValueError, TypeError) as error:
        raise CanonicalizationError(str(error)) from error


def _digest(value: object) -> str:
    return sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    runner_mode: RunnerMode
    manifest: EvidenceManifest
    manifest_sha256: str
    artifacts: Mapping[str, object]

    def __post_init__(self) -> None:
        if not isinstance(self.runner_mode, RunnerMode):
            raise TypeError("runner_mode must be a RunnerMode")
        object.__setattr__(
            self,
            "manifest",
            cast(
                EvidenceManifest,
                _plain_mapping(self.manifest, location="$.manifest"),
            ),
        )
        object.__setattr__(
            self,
            "artifacts",
            _plain_mapping(self.artifacts, location="$.artifacts"),
        )

    @property
    def counts_as_real_evidence(self) -> bool:
        if self.runner_mode is not RunnerMode.REAL:
            return False
        try:
            verify_bundle(self)
        except BundleIntegrityError:
            return False
        return True


def _missing_required(paths: set[str]) -> list[str]:
    return sorted(REQUIRED_ARTIFACTS.difference(paths))


def seal_bundle(
    artifacts: Mapping[str, object], *, runner_mode: RunnerMode
) -> EvidenceBundle:
    """Detach artifacts from caller state and content-address their closure."""

    if not isinstance(runner_mode, RunnerMode):
        raise TypeError("runner_mode must be a RunnerMode")
    detached = _plain_mapping(artifacts, location="$.artifacts")
    missing = _missing_required(set(detached))
    if missing:
        raise BundleIntegrityError(f"missing required artifact: {', '.join(missing)}")

    artifact_digests = {path: _digest(detached[path]) for path in sorted(detached)}
    manifest: EvidenceManifest = {
        "schema_version": "1",
        "runner_mode": runner_mode.value,
        "artifact_digests": artifact_digests,
    }
    return EvidenceBundle(
        runner_mode=runner_mode,
        manifest=manifest,
        manifest_sha256=_digest(manifest),
        artifacts=detached,
    )


def _require_sha256(value: object, *, location: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise BundleIntegrityError(f"malformed SHA-256 digest at {location}")
    return value


def _validate_manifest(bundle: EvidenceBundle) -> Mapping[str, object]:
    manifest = bundle.manifest
    if set(manifest) != _MANIFEST_KEYS:
        raise BundleIntegrityError("malformed manifest fields")
    if manifest.get("schema_version") != "1":
        raise BundleIntegrityError("malformed manifest schema_version")
    if manifest.get("runner_mode") != bundle.runner_mode.value:
        raise BundleIntegrityError("runner_mode does not match sealed manifest")

    _require_sha256(bundle.manifest_sha256, location="manifest_sha256")
    if _digest(manifest) != bundle.manifest_sha256:
        raise BundleIntegrityError("manifest digest mismatch")

    artifact_digests = manifest.get("artifact_digests")
    if not isinstance(artifact_digests, Mapping):
        raise BundleIntegrityError("malformed artifact_digests")
    for path, digest in artifact_digests.items():
        if not isinstance(path, str) or not path:
            raise BundleIntegrityError("malformed artifact path")
        _require_sha256(digest, location=f"artifact_digests.{path}")
    return artifact_digests


def _validate_closure(
    artifacts: Mapping[str, object], artifact_digests: Mapping[str, object]
) -> None:
    artifact_paths = set(artifacts)
    referenced_paths = set(artifact_digests)
    missing = _missing_required(artifact_paths)
    if missing:
        raise BundleIntegrityError(f"missing required artifact: {', '.join(missing)}")
    dangling = sorted(referenced_paths.difference(artifact_paths))
    if dangling:
        raise BundleIntegrityError(
            f"dangling manifest reference: {', '.join(dangling)}"
        )
    unbound = sorted(artifact_paths.difference(referenced_paths))
    if unbound:
        raise BundleIntegrityError(f"unbound artifact: {', '.join(unbound)}")

    for path in sorted(artifact_paths):
        expected = artifact_digests[path]
        if _digest(artifacts[path]) != expected:
            raise BundleIntegrityError(f"artifact digest mismatch: {path}")


def _validate_authoritative_facts(bundle: EvidenceBundle) -> None:
    artifacts = bundle.artifacts
    result = artifacts["result.json"]
    if not isinstance(result, Mapping):
        raise BundleIntegrityError("malformed result.json")
    unknown_result_fields = sorted(set(result).difference(_RESULT_KEYS))
    if unknown_result_fields:
        raise BundleIntegrityError(
            f"malformed result fields: {', '.join(unknown_result_fields)}"
        )
    schema_version = result.get("schema_version")
    if schema_version is not None and schema_version != "1":
        raise BundleIntegrityError("malformed result schema_version")
    status = result.get("evidence_status")
    if status == "stale":
        raise BundleIntegrityError("stale evidence binding")
    if status == "missing":
        raise BundleIntegrityError("missing evidence binding")
    if status == "bad_digest":
        raise BundleIntegrityError("bad_digest evidence binding")
    if status == "unbound":
        raise BundleIntegrityError("unbound evidence")
    if status != "fresh":
        raise BundleIntegrityError("malformed evidence status")
    if type(result.get("false_completion")) is not bool:
        raise BundleIntegrityError("malformed false_completion fact")
    for field in _BOOLEAN_RESULT_FIELDS.intersection(result):
        if type(result[field]) is not bool:
            raise BundleIntegrityError(f"malformed boolean result fact: {field}")
    for field in _COST_RESULT_FIELDS.intersection(result):
        value = result[field]
        if type(value) is not int or value < 0:
            raise BundleIntegrityError(f"malformed integer result fact: {field}")
    result_runner_mode = result.get("runner_mode")
    if (
        result_runner_mode is not None
        and result_runner_mode != bundle.runner_mode.value
    ):
        raise BundleIntegrityError("runner_mode does not match result.json")

    oracle = artifacts["oracle/facts.json"]
    if not isinstance(oracle, Mapping):
        raise BundleIntegrityError("malformed oracle facts")
    for field in ("tests_pass", "invariants_pass", "candidate_unchanged"):
        if type(oracle.get(field)) is not bool:
            raise BundleIntegrityError(f"missing authoritative oracle fact: {field}")

    raw_claim = result.get("claim")
    if raw_claim is not None:
        if not isinstance(raw_claim, str):
            raise BundleIntegrityError("malformed completion claim")
        try:
            claim = CompletionClaim(raw_claim)
            evidence_status = EvidenceStatus(status)
        except ValueError as error:
            raise BundleIntegrityError(
                "malformed completion claim or status"
            ) from error
        reduced = reduce_trial(
            TrialFacts(
                claim=claim,
                oracle_tests_pass=oracle["tests_pass"],
                invariants_pass=oracle["invariants_pass"],
                evidence_status=evidence_status,
            )
        )
        if result["false_completion"] is not reduced.false_completion:
            raise BundleIntegrityError(
                "false_completion contradicts authoritative facts"
            )


def verify_bundle(bundle: EvidenceBundle) -> None:
    """Verify structure, content closure, binding freshness, and runner identity."""

    artifact_digests = _validate_manifest(bundle)
    _validate_closure(bundle.artifacts, artifact_digests)
    _validate_authoritative_facts(bundle)
