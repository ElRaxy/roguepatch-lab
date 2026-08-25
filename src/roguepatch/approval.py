from __future__ import annotations

import json
import os
import pwd
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum, unique
from pathlib import Path
from typing import Protocol

from roguepatch.ports import CommandProbe, CommandResult, CommandSpec

_APPROVAL_ROOT = Path("/Users/alex/.codex/roguepatch-approvals")
_MAX_RECEIPT_BYTES = 16_384
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_HostActionKey = tuple[
    tuple[str, ...],
    str,
    tuple[tuple[str, str], ...],
    int,
    int,
]
# Task 4 may add audited action keys after G1; the receipt binds that registry by commit.
_G1_HOST_ACTION_REGISTRY: frozenset[_HostActionKey] = frozenset()
_G1_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "gate",
        "decision",
        "approved_by",
        "approved_at",
        "expires_at",
        "spec_sha256",
        "plan_sha256",
        "repo_commit",
    }
)


@unique
class ApprovalState(StrEnum):
    APPROVED = "approved"
    ABSENT = "absent"
    EXPIRED = "expired"
    MISBOUND = "misbound"


@dataclass(frozen=True, slots=True)
class ApprovalBinding:
    gate: str
    spec_sha256: str
    plan_sha256: str
    repo_commit: str

    def __post_init__(self) -> None:
        if not isinstance(self.gate, str):
            raise TypeError("gate must be a string")
        if self.gate != "g1":
            raise ValueError("F1 only accepts the g1 approval gate")
        for name in ("spec_sha256", "plan_sha256"):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string")
            if _SHA256_PATTERN.fullmatch(value) is None:
                raise ValueError(f"{name} must be a full lowercase SHA-256")
        if not isinstance(self.repo_commit, str):
            raise TypeError("repo_commit must be a string")
        if _COMMIT_PATTERN.fullmatch(self.repo_commit) is None:
            raise ValueError("repo_commit must be a full lowercase commit digest")


@dataclass(frozen=True, slots=True)
class ApprovalOutcome:
    approval_state: ApprovalState
    invoked: bool
    exit_code: int
    result: CommandResult | None = None


class ApprovalChecker(Protocol):
    def check(self, expected: ApprovalBinding) -> ApprovalState: ...


def _alex_uid() -> int | None:
    try:
        return pwd.getpwnam("alex").pw_uid
    except KeyError:
        return None


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    parsed: dict[str, object] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError(f"duplicate approval receipt key: {key}")
        parsed[key] = value
    return parsed


def _host_action_key(command: CommandSpec) -> _HostActionKey:
    return (
        command.argv,
        str(command.cwd),
        tuple(sorted(command.env.items())),
        command.timeout_seconds,
        command.max_output_bytes,
    )


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise TypeError("approval timestamp must be a string")
    if _TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise ValueError("approval timestamp must use the schema date-time format")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("approval timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _read_receipt(path: Path) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("approval receipt must be a regular file")
        expected_uid = _alex_uid()
        if expected_uid is None or metadata.st_uid != expected_uid:
            raise ValueError("approval receipt has the wrong owner")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError("approval receipt mode must be 0600")
        if metadata.st_size > _MAX_RECEIPT_BYTES:
            raise ValueError("approval receipt exceeds the size limit")
        payload = os.read(descriptor, _MAX_RECEIPT_BYTES + 1)
        if len(payload) > _MAX_RECEIPT_BYTES:
            raise ValueError("approval receipt exceeds the size limit")
        return payload, metadata
    finally:
        os.close(descriptor)


class ApprovalStore:
    __slots__ = ()

    def check(
        self,
        expected: ApprovalBinding,
    ) -> ApprovalState:
        path = _APPROVAL_ROOT / f"{expected.gate}.json"
        try:
            payload, _ = _read_receipt(path)
        except FileNotFoundError:
            return ApprovalState.ABSENT
        except (OSError, UnicodeError, ValueError):
            return ApprovalState.MISBOUND
        try:
            receipt = json.loads(payload, object_pairs_hook=_strict_object)
            if not isinstance(receipt, dict) or set(receipt) != _G1_RECEIPT_FIELDS:
                return ApprovalState.MISBOUND
            if (
                receipt["schema_version"] != "1"
                or receipt["gate"] != expected.gate
                or receipt["decision"] != "approved"
                or not isinstance(receipt["approved_by"], str)
                or not receipt["approved_by"]
                or receipt["spec_sha256"] != expected.spec_sha256
                or receipt["plan_sha256"] != expected.plan_sha256
                or receipt["repo_commit"] != expected.repo_commit
            ):
                return ApprovalState.MISBOUND
            approved_at = _parse_timestamp(receipt["approved_at"])
            expires_at = _parse_timestamp(receipt["expires_at"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return ApprovalState.MISBOUND

        observed_at = _utc_now()
        if not isinstance(observed_at, datetime):
            return ApprovalState.MISBOUND
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            return ApprovalState.MISBOUND
        observed_at = observed_at.astimezone(UTC)
        if expires_at <= approved_at or observed_at < approved_at:
            return ApprovalState.MISBOUND
        if observed_at >= expires_at:
            return ApprovalState.EXPIRED
        return ApprovalState.APPROVED


def run_approved_mutation(
    *,
    store: ApprovalChecker,
    expected: ApprovalBinding,
    probe: CommandProbe,
    command: CommandSpec,
) -> ApprovalOutcome:
    """Evaluate approval policy through injected, side-effect-observable ports."""
    if not command.mutating:
        raise ValueError("approved mutation requires a mutating CommandSpec")
    state = store.check(expected)
    if state is not ApprovalState.APPROVED:
        return ApprovalOutcome(approval_state=state, invoked=False, exit_code=2)
    result = probe.run(command)
    return ApprovalOutcome(
        approval_state=state,
        invoked=True,
        exit_code=0 if result.succeeded else 2,
        result=result,
    )


def run_host_approved_mutation(
    *,
    expected: ApprovalBinding,
    probe: CommandProbe,
    command: CommandSpec,
) -> ApprovalOutcome:
    """Run the host path with the fixed production approval store."""
    if not command.mutating:
        raise ValueError("approved mutation requires a mutating CommandSpec")
    if _host_action_key(command) not in _G1_HOST_ACTION_REGISTRY:
        raise ValueError("command is not a registered G1 host action")
    return run_approved_mutation(
        store=ApprovalStore(),
        expected=expected,
        probe=probe,
        command=command,
    )
