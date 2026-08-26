from __future__ import annotations

import json
import os
import pwd
import re
import stat
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum, unique
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import ClassVar, Protocol, TypeVar

from roguepatch.evidence import canonical_json
from roguepatch.ports import CommandProbe, CommandResult, CommandSpec

_APPROVAL_ROOT = Path("/Users/alex/.codex/roguepatch-approvals")
_MAX_RECEIPT_BYTES = 16_384
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_CommandSpecKey = tuple[
    tuple[str, ...],
    str,
    tuple[tuple[str, str], ...],
    int,
    int,
    bool,
    bool,
]
G1_ACTION_IDS = (
    "g1.source.resolve",
    "g1.sbx.probe.host-canary",
    "g1.sbx.probe.protected-manifest",
    "g1.sbx.probe.golden-patch",
    "g1.sbx.probe.signing-material",
    "g1.sbx.probe.artifact-store",
    "g1.sbx.probe.approval-receipt",
    "g1.sbx.probe.control-credentials",
    "g1.sbx.probe.model-credentials",
    "g1.sbx.probe.docker-socket",
    "g1.sbx.probe.oracle-checker",
    "g1.sbx.probe.source-protected-manifest",
    "g1.sbx.probe.source-golden-patch",
    "g1.sbx.probe.source-artifacts",
    "g1.sbx.agent.create",
    "g1.sbx.agent.freeze",
    "g1.sbx.agent.destroy",
    "g1.sbx.oracle.create",
    "g1.sbx.oracle.engine-identity",
    "g1.sbx.oracle.checker",
    "g1.sbx.oracle.destroy",
)
_G1_MUTATING_ACTION_IDS = frozenset(
    {
        "g1.sbx.agent.create",
        "g1.sbx.agent.destroy",
        "g1.sbx.oracle.create",
        "g1.sbx.oracle.destroy",
    }
)
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
        "host_fingerprint_sha256",
        "action_registry_sha256",
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
class HostIdentity:
    hostname: str
    account: str
    arch: str
    os_build: str
    boot_session_sha256: str

    def __post_init__(self) -> None:
        for name in ("hostname", "account", "arch", "os_build"):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string")
            if not value or value != value.strip() or "\x00" in value:
                raise ValueError(f"{name} must be a non-empty normalized string")
        if not isinstance(self.boot_session_sha256, str):
            raise TypeError("boot_session_sha256 must be a string")
        if _SHA256_PATTERN.fullmatch(self.boot_session_sha256) is None:
            raise ValueError("boot_session_sha256 must be a full lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class G1HostBinding:
    approval: ApprovalBinding
    host_fingerprint_sha256: str
    action_registry_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.approval, ApprovalBinding):
            raise TypeError("approval must be an ApprovalBinding")
        for name in ("host_fingerprint_sha256", "action_registry_sha256"):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string")
            if _SHA256_PATTERN.fullmatch(value) is None:
                raise ValueError(f"{name} must be a full lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class G1HostAction:
    action_id: str
    command: CommandSpec

    def __post_init__(self) -> None:
        if not isinstance(self.action_id, str):
            raise TypeError("action_id must be a string")
        if not self.action_id.startswith("g1.") or "\x00" in self.action_id:
            raise ValueError("action_id must be a non-empty G1 identifier")
        if not isinstance(self.command, CommandSpec):
            raise TypeError("command must be a CommandSpec")

    def __hash__(self) -> int:
        return hash((self.action_id, _command_spec_key(self.command)))


# Live argv are deliberately absent until Task 4 resolves them from current official
# SBX documentation. An empty registry makes the production path fail closed.
_G1_HOST_ACTION_REGISTRY: frozenset[G1HostAction] = frozenset()


@dataclass(frozen=True, slots=True)
class ApprovalOutcome:
    approval_state: ApprovalState
    invoked: bool
    exit_code: int
    result: CommandResult | None = None


_BindingT_contra = TypeVar("_BindingT_contra", contravariant=True)


class ApprovalChecker(Protocol[_BindingT_contra]):
    def check(self, expected: _BindingT_contra) -> ApprovalState: ...


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


class CanonicalRecord:
    schema_version: ClassVar[str]

    def _payload(self) -> dict[str, object]:
        raise NotImplementedError

    @property
    def canonical_payload(self) -> bytes:
        return canonical_json(self._payload())

    @property
    def sha256(self) -> str:
        return sha256(self.canonical_payload).hexdigest()


def _command_spec_key(command: CommandSpec) -> _CommandSpecKey:
    return (
        command.argv,
        str(command.cwd),
        tuple(sorted(command.env.items())),
        command.timeout_seconds,
        command.max_output_bytes,
        command.mutating,
        command.shell,
    )


def command_spec_payload(command: CommandSpec) -> dict[str, object]:
    if not isinstance(command, CommandSpec):
        raise TypeError("command must be a CommandSpec")
    return {
        "argv": list(command.argv),
        "cwd": str(command.cwd),
        "env": dict(command.env),
        "timeout_seconds": command.timeout_seconds,
        "max_output_bytes": command.max_output_bytes,
        "mutating": command.mutating,
        "shell": command.shell,
    }


def command_spec_sha256(command: CommandSpec) -> str:
    return sha256(canonical_json(command_spec_payload(command))).hexdigest()


def _command_spec_payload(command: CommandSpec) -> dict[str, object]:
    return command_spec_payload(command)


def _command_spec_sha256(command: CommandSpec) -> str:
    return command_spec_sha256(command)


def build_g1_action_registry(
    *,
    command_factory: Callable[[str], CommandSpec],
) -> frozenset[G1HostAction]:
    if not callable(command_factory):
        raise TypeError("command_factory must be callable")
    actions: list[G1HostAction] = []
    for action_id in G1_ACTION_IDS:
        command = command_factory(action_id)
        if not isinstance(command, CommandSpec):
            raise TypeError("command_factory must return CommandSpec instances")
        actions.append(G1HostAction(action_id=action_id, command=command))
    registry = frozenset(actions)
    validate_g1_action_registry(registry)
    return registry


def canonical_action_registry_payload(
    registry: frozenset[G1HostAction],
) -> bytes:
    if not isinstance(registry, frozenset):
        raise TypeError("registry must be a frozenset")
    actions_by_id: dict[str, G1HostAction] = {}
    for action in registry:
        if not isinstance(action, G1HostAction):
            raise TypeError("registry entries must be G1HostAction instances")
        if action.action_id in actions_by_id:
            raise ValueError("registry action identifiers must be unique")
        actions_by_id[action.action_id] = action
    actions = [
        {
            "action_id": action_id,
            **command_spec_payload(actions_by_id[action_id].command),
        }
        for action_id in sorted(actions_by_id)
    ]
    return canonical_json(
        {
            "schema_version": "roguepatch.g1-action-registry.v1",
            "actions": actions,
        }
    )


def action_registry_sha256(
    registry: frozenset[G1HostAction] | None = None,
) -> str:
    selected = _G1_HOST_ACTION_REGISTRY if registry is None else registry
    return sha256(canonical_action_registry_payload(selected)).hexdigest()


def _canonical_action_registry_payload(
    registry: frozenset[G1HostAction],
) -> bytes:
    return canonical_action_registry_payload(registry)


def _action_registry_sha256(
    registry: frozenset[G1HostAction] | None = None,
) -> str:
    return action_registry_sha256(registry)


@dataclass(frozen=True, slots=True)
class ValidatedG1ActionRegistry:
    registry: frozenset[G1HostAction]
    action_registry_sha256: str
    actions_by_id: Mapping[str, G1HostAction]

    def __post_init__(self) -> None:
        if not isinstance(self.registry, frozenset):
            raise TypeError("registry must be a frozenset")
        if _SHA256_PATTERN.fullmatch(self.action_registry_sha256) is None:
            raise ValueError("action_registry_sha256 must be a full lowercase SHA-256")
        if not isinstance(self.actions_by_id, Mapping):
            raise TypeError("actions_by_id must be a mapping")
        object.__setattr__(
            self,
            "actions_by_id",
            MappingProxyType(dict(self.actions_by_id)),
        )

    def require_action(self, action: G1HostAction) -> G1HostAction:
        if not isinstance(action, G1HostAction):
            raise TypeError("action must be a G1HostAction")
        registered = self.actions_by_id.get(action.action_id)
        if registered != action:
            raise ValueError("action is not exactly registered")
        return registered

    def action(self, action_id: str) -> G1HostAction:
        if not isinstance(action_id, str):
            raise TypeError("action_id must be a string")
        try:
            return self.actions_by_id[action_id]
        except KeyError as error:
            raise ValueError("action is not registered") from error


def validate_g1_action_registry(
    registry: Collection[G1HostAction],
) -> ValidatedG1ActionRegistry:
    if not isinstance(registry, Collection):
        raise TypeError("registry must be a collection")
    actions_by_id: dict[str, G1HostAction] = {}
    for action in registry:
        if not isinstance(action, G1HostAction):
            raise TypeError("registry entries must be G1HostAction instances")
        if action.action_id in actions_by_id:
            raise ValueError("registry action identifiers must be unique")
        actions_by_id[action.action_id] = action
    if len(actions_by_id) != len(G1_ACTION_IDS) or set(actions_by_id) != set(
        G1_ACTION_IDS
    ):
        raise ValueError("registry is not the exact closed G1 set")
    for action_id, action in actions_by_id.items():
        if action.command.mutating is not (action_id in _G1_MUTATING_ACTION_IDS):
            raise ValueError("G1 action has an invalid mutating policy")
        if action_id.startswith("g1.sbx.") and (
            action.command.argv[0] != "sbx" or action.command.shell
        ):
            raise ValueError("G1 SBX actions must use the exact sbx executable")
    frozen = frozenset(registry)
    return ValidatedG1ActionRegistry(
        registry=frozen,
        action_registry_sha256=action_registry_sha256(frozen),
        actions_by_id=actions_by_id,
    )


def host_identity_payload(identity: HostIdentity) -> bytes:
    if not isinstance(identity, HostIdentity):
        raise TypeError("identity must be a HostIdentity")
    return canonical_json(
        {
            "schema_version": "roguepatch.host-fingerprint.v1",
            "hostname": identity.hostname,
            "account": identity.account,
            "arch": identity.arch,
            "os_build": identity.os_build,
            "boot_session_sha256": identity.boot_session_sha256,
        }
    )


def host_identity_sha256(identity: HostIdentity) -> str:
    return sha256(host_identity_payload(identity)).hexdigest()


def _collect_host_identity() -> HostIdentity:
    raise RuntimeError("the audited live host identity collector is not configured")


def _host_fingerprint_sha256() -> str:
    return host_identity_sha256(_collect_host_identity())


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
        expected: G1HostBinding,
    ) -> ApprovalState:
        if not isinstance(expected, G1HostBinding):
            return ApprovalState.MISBOUND
        path = _APPROVAL_ROOT / f"{expected.approval.gate}.json"
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
                or receipt["gate"] != expected.approval.gate
                or receipt["decision"] != "approved"
                or not isinstance(receipt["approved_by"], str)
                or not receipt["approved_by"]
                or receipt["spec_sha256"] != expected.approval.spec_sha256
                or receipt["plan_sha256"] != expected.approval.plan_sha256
                or receipt["repo_commit"] != expected.approval.repo_commit
                or receipt["host_fingerprint_sha256"]
                != expected.host_fingerprint_sha256
                or receipt["action_registry_sha256"] != expected.action_registry_sha256
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
    store: ApprovalChecker[ApprovalBinding],
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
    if not any(action.command == command for action in _G1_HOST_ACTION_REGISTRY):
        raise ValueError("command is not a registered G1 host action")
    try:
        host_binding = G1HostBinding(
            approval=expected,
            host_fingerprint_sha256=_host_fingerprint_sha256(),
            action_registry_sha256=action_registry_sha256(),
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return ApprovalOutcome(
            approval_state=ApprovalState.MISBOUND,
            invoked=False,
            exit_code=2,
        )
    state = ApprovalStore().check(host_binding)
    if state is not ApprovalState.APPROVED:
        return ApprovalOutcome(approval_state=state, invoked=False, exit_code=2)
    result = probe.run(command)
    return ApprovalOutcome(
        approval_state=state,
        invoked=True,
        exit_code=0 if result.succeeded else 2,
        result=result,
    )
