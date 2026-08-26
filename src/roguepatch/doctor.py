from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, unique
from pathlib import Path
from types import MappingProxyType

from roguepatch.approval import CanonicalRecord, command_spec_payload
from roguepatch.ports import CommandProbe, CommandSpec


@unique
class DoctorCheck(StrEnum):
    DAEMON = "daemon"
    SBX = "sbx"
    PINS = "pins"
    AUTH = "auth"
    ISOLATION = "isolation"


@unique
class CheckState(StrEnum):
    READY = "ready"
    MISSING = "missing"
    ERROR = "error"


_RECEIPT_INSTALL_MIN_KIB = 40 * 1024 * 1024
_PRE_CREATE_MIN_KIB = 30 * 1024 * 1024
_POST_CREATE_MIN_KIB = 20 * 1024 * 1024
_IMAC_MEMORY_MIB = 8 * 1024
_SANDBOX_CPU_COUNT = 2
_SANDBOX_MEMORY_MIB = 2 * 1024


@dataclass(frozen=True, slots=True)
class DiskPreflightFacts:
    available_kib: int
    receipt_install_min_kib: int
    pre_create_min_kib: int
    post_create_min_kib: int

    def __post_init__(self) -> None:
        if type(self.available_kib) is not int:
            raise TypeError("available_kib must be an int")
        if self.available_kib < 0:
            raise ValueError("available_kib cannot be negative")
        expected_thresholds = {
            "receipt_install_min_kib": _RECEIPT_INSTALL_MIN_KIB,
            "pre_create_min_kib": _PRE_CREATE_MIN_KIB,
            "post_create_min_kib": _POST_CREATE_MIN_KIB,
        }
        for name, expected in expected_thresholds.items():
            value = getattr(self, name)
            if type(value) is not int:
                raise TypeError(f"{name} must be an int")
            if value != expected:
                raise ValueError(f"{name} must equal the frozen F1 threshold")


@dataclass(frozen=True, slots=True)
class SandboxResourceFacts:
    host_memory_mib: int
    sequential: bool
    vm_cpu_count: int
    vm_memory_mib: int

    def __post_init__(self) -> None:
        if type(self.host_memory_mib) is not int:
            raise TypeError("host_memory_mib must be an int")
        if self.host_memory_mib != _IMAC_MEMORY_MIB:
            raise ValueError("host_memory_mib must match the authorized iMac")
        if type(self.sequential) is not bool:
            raise TypeError("sequential must be a bool")
        if not self.sequential:
            raise ValueError("F1 sandboxes must run sequentially")
        if type(self.vm_cpu_count) is not int:
            raise TypeError("vm_cpu_count must be an int")
        if self.vm_cpu_count != _SANDBOX_CPU_COUNT:
            raise ValueError("each F1 sandbox must use exactly 2 CPUs")
        if type(self.vm_memory_mib) is not int:
            raise TypeError("vm_memory_mib must be an int")
        if self.vm_memory_mib != _SANDBOX_MEMORY_MIB:
            raise ValueError("each F1 sandbox must use exactly 2048 MiB")


@dataclass(frozen=True, slots=True)
class LivePreflightFacts:
    disk: DiskPreflightFacts
    resources: SandboxResourceFacts
    create_invocations: int

    def __post_init__(self) -> None:
        if not isinstance(self.disk, DiskPreflightFacts):
            raise TypeError("disk must be DiskPreflightFacts")
        if not isinstance(self.resources, SandboxResourceFacts):
            raise TypeError("resources must be SandboxResourceFacts")
        if type(self.create_invocations) is not int:
            raise TypeError("create_invocations must be an int")
        if self.create_invocations < 0:
            raise ValueError("create_invocations cannot be negative")


@unique
class PreflightStatus(StrEnum):
    READY = "ready"
    BLOCKED_LOW_DISK = "blocked_low_disk"
    KILL_UNSAFE_CREATE = "kill_unsafe_create"


@dataclass(frozen=True, slots=True)
class LivePreflightDecision:
    status: PreflightStatus
    receipt_allowed: bool
    install_allowed: bool
    create_allowed: bool
    post_create_safe: bool


def evaluate_live_preflight(facts: LivePreflightFacts) -> LivePreflightDecision:
    if not isinstance(facts, LivePreflightFacts):
        raise TypeError("facts must be LivePreflightFacts")
    disk = facts.disk
    receipt_allowed = disk.available_kib >= disk.receipt_install_min_kib
    create_allowed = disk.available_kib >= disk.pre_create_min_kib
    post_create_safe = disk.available_kib >= disk.post_create_min_kib
    unsafe_create = facts.create_invocations > 0 and (
        not create_allowed or not post_create_safe
    )
    if unsafe_create:
        status = PreflightStatus.KILL_UNSAFE_CREATE
    elif receipt_allowed:
        status = PreflightStatus.READY
    else:
        status = PreflightStatus.BLOCKED_LOW_DISK
    return LivePreflightDecision(
        status=status,
        receipt_allowed=receipt_allowed,
        install_allowed=receipt_allowed,
        create_allowed=create_allowed,
        post_create_safe=post_create_safe,
    )


_DoctorCommandKey = tuple[
    tuple[str, ...],
    str,
    tuple[tuple[str, str], ...],
    int,
    int,
]


def _doctor_command_key(command: CommandSpec) -> _DoctorCommandKey:
    return (
        command.argv,
        str(command.cwd),
        tuple(sorted(command.env.items())),
        command.timeout_seconds,
        command.max_output_bytes,
    )


# Task 3 admits only inert fake probes; Task 4 may add audited real inspections after G1.
_DOCTOR_COMMAND_REGISTRY: Mapping[DoctorCheck, frozenset[_DoctorCommandKey]] = (
    MappingProxyType(
        {
            check: frozenset(
                {
                    (
                        ("synthetic-probe", check.value),
                        "/synthetic/roguepatch",
                        (("PATH", "/synthetic/bin"),),
                        5,
                        4096,
                    )
                }
            )
            for check in DoctorCheck
        }
    )
)


@dataclass(frozen=True, slots=True)
class DoctorProbe:
    check: DoctorCheck
    command: CommandSpec

    def __post_init__(self) -> None:
        if not isinstance(self.check, DoctorCheck):
            raise TypeError("check must be a DoctorCheck")
        if not isinstance(self.command, CommandSpec):
            raise TypeError("command must be a CommandSpec")
        if self.command.mutating:
            raise ValueError("doctor probes must be read-only")
        if (
            _doctor_command_key(self.command)
            not in _DOCTOR_COMMAND_REGISTRY[self.check]
        ):
            raise ValueError("doctor probe is not a registered read-only command")


@dataclass(frozen=True, slots=True)
class CheckFact:
    check: DoctorCheck
    state: CheckState
    diagnostic: str = ""


@dataclass(frozen=True, slots=True)
class DoctorReport:
    facts: Mapping[DoctorCheck, CheckFact]

    def __post_init__(self) -> None:
        frozen = dict(self.facts)
        if set(frozen) != set(DoctorCheck):
            raise ValueError("doctor report must contain every required check")
        object.__setattr__(self, "facts", MappingProxyType(frozen))

    @property
    def ready(self) -> bool:
        return all(fact.state is CheckState.READY for fact in self.facts.values())

    @property
    def exit_code(self) -> int:
        return 0 if self.ready else 2

    def fact_for(self, check: DoctorCheck) -> CheckFact:
        return self.facts[check]


def run_doctor(
    command_probe: CommandProbe,
    probes: Sequence[DoctorProbe],
) -> DoctorReport:
    configured: dict[DoctorCheck, DoctorProbe] = {}
    for probe in probes:
        if probe.check in configured:
            raise ValueError(f"duplicate doctor probe: {probe.check.value}")
        configured[probe.check] = probe

    facts: dict[DoctorCheck, CheckFact] = {}
    for check in DoctorCheck:
        configured_probe = configured.get(check)
        if configured_probe is None:
            facts[check] = CheckFact(
                check=check,
                state=CheckState.ERROR,
                diagnostic="probe not configured",
            )
            continue
        try:
            result = command_probe.run(configured_probe.command)
        except Exception as error:  # noqa: BLE001 - adapter boundary must fail closed
            facts[check] = CheckFact(
                check=check,
                state=CheckState.ERROR,
                diagnostic=type(error).__name__,
            )
            continue
        state = CheckState.READY if result.succeeded else CheckState.MISSING
        diagnostic = "" if result.succeeded else (result.stderr or "probe failed")
        facts[check] = CheckFact(check=check, state=state, diagnostic=diagnostic)

    return DoctorReport(facts=facts)


_G1_DISCOVERY_RECEIPT_PATH = Path(
    "/Users/alex/.codex/roguepatch-approvals/g1-discovery.json"
)
_G1_DISCOVERY_CONTROL_ROOT = Path(
    "/Users/alex/.codex/roguepatch-control/v1/g1-discovery"
)
_G1_DISCOVERY_PUBLIC_SOURCE_PATH = Path(
    "/Users/alex/RoguePatchLab/.roguepatch/public-fixtures/rp-001"
)
_G1_DISCOVERY_BASELINE_ACTIONS = {
    "g1-discovery.install-standalone": True,
    "g1-discovery.inspect-read-only": False,
}
_G1_DISCOVERY_DIAGNOSTIC_ACTIONS = (
    ("g1-discovery.diagnostic-create", True),
    ("g1-discovery.diagnostic-exec", False),
    ("g1-discovery.diagnostic-destroy", True),
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")


def _require_sha256(value: object, *, field: str) -> None:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field} must be a full lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class DaemonIsolationFacts:
    action_id: str
    sandbox_role: str
    isolation_scope: str
    oracle_microvm_id: str
    engine_identity_observation_sha256: str
    engine_identity_trace_result_sha256: str
    engine_identity_sha256: str
    checker_engine_identity_sha256: str
    action_registry_sha256: str
    engine_identity_action_registry_sha256: str
    private_engine_observed: bool
    docker_desktop_observed: bool
    host_daemon_accessible: bool
    shared_socket_observed: bool


def validate_live_daemon_boundary(
    report: DoctorReport,
    facts: DaemonIsolationFacts | None,
) -> None:
    if not isinstance(report, DoctorReport):
        raise TypeError("daemon report must be a DoctorReport")
    if (
        not report.ready
        or report.fact_for(DoctorCheck.DAEMON).state is not CheckState.READY
        or report.fact_for(DoctorCheck.ISOLATION).state is not CheckState.READY
    ):
        raise ValueError("daemon and isolation checks must be ready")
    if not isinstance(facts, DaemonIsolationFacts):
        raise TypeError("daemon isolation facts are required")
    if facts.action_id != "g1.sbx.oracle.engine-identity":
        raise ValueError("daemon engine observation action is not authorized")
    if facts.sandbox_role != "oracle":
        raise ValueError("daemon engine observation must belong to the oracle")
    if facts.isolation_scope != "microvm":
        raise ValueError("daemon engine isolation scope must be microvm")
    if (
        not isinstance(facts.oracle_microvm_id, str)
        or not facts.oracle_microvm_id
        or facts.oracle_microvm_id != facts.oracle_microvm_id.strip()
    ):
        raise ValueError("oracle microvm id must be concrete")
    digest_fields = (
        "engine_identity_observation_sha256",
        "engine_identity_trace_result_sha256",
        "engine_identity_sha256",
        "checker_engine_identity_sha256",
        "action_registry_sha256",
        "engine_identity_action_registry_sha256",
    )
    for field in digest_fields:
        _require_sha256(getattr(facts, field), field=f"daemon {field}")
    if (
        facts.engine_identity_observation_sha256
        != facts.engine_identity_trace_result_sha256
    ):
        raise ValueError("daemon engine observation digest is not trace-bound")
    if facts.engine_identity_sha256 != facts.checker_engine_identity_sha256:
        raise ValueError("daemon engine identity digest is not checker-bound")
    if facts.action_registry_sha256 != facts.engine_identity_action_registry_sha256:
        raise ValueError("daemon engine observation registry digest is misbound")
    if facts.private_engine_observed is not True:
        raise ValueError("daemon engine must be private")
    if facts.docker_desktop_observed is not False:
        raise ValueError("Docker Desktop is forbidden for the daemon boundary")
    if facts.host_daemon_accessible is not False:
        raise ValueError("host daemon access is forbidden")
    if facts.shared_socket_observed is not False:
        raise ValueError("shared daemon socket is forbidden")


def _discovery_command_key(command: CommandSpec) -> tuple[object, ...]:
    return (
        command.argv,
        str(command.cwd),
        tuple(sorted(command.env.items())),
        command.timeout_seconds,
        command.max_output_bytes,
        command.mutating,
        command.shell,
    )


@dataclass(frozen=True, slots=True)
class G1DiscoveryActionRecord:
    action_id: str
    command: CommandSpec

    def __post_init__(self) -> None:
        if not isinstance(self.action_id, str) or not self.action_id.startswith(
            "g1-discovery."
        ):
            raise ValueError("action_id must be a G1 discovery identifier")
        if not isinstance(self.command, CommandSpec):
            raise TypeError("command must be a CommandSpec")

    def __hash__(self) -> int:
        return hash((self.action_id, _discovery_command_key(self.command)))


@dataclass(frozen=True, slots=True)
class G1DiscoveryOfflineRegistry(CanonicalRecord):
    schema_version = "roguepatch.g1-discovery-action-registry.v1"

    records: tuple[G1DiscoveryActionRecord, ...]
    receipt_path: Path
    control_root: Path
    public_source_path: Path

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "receipt_path": str(self.receipt_path),
            "control_root": str(self.control_root),
            "public_source_path": str(self.public_source_path),
            "actions": [
                {
                    "action_id": record.action_id,
                    **command_spec_payload(record.command),
                }
                for record in sorted(self.records, key=lambda item: item.action_id)
            ],
        }


def build_g1_discovery_offline_registry(
    *,
    records: Sequence[G1DiscoveryActionRecord],
    receipt_path: Path,
    control_root: Path,
    public_source_path: Path,
) -> G1DiscoveryOfflineRegistry:
    frozen_records = tuple(records)
    if any(not isinstance(item, G1DiscoveryActionRecord) for item in frozen_records):
        raise TypeError("records must contain G1DiscoveryActionRecord values")
    actual = {item.action_id: item.command.mutating for item in frozen_records}
    if actual != _G1_DISCOVERY_BASELINE_ACTIONS or len(frozen_records) != 2:
        raise ValueError(
            "offline discovery registry must contain the two baseline actions"
        )
    if receipt_path != _G1_DISCOVERY_RECEIPT_PATH:
        raise ValueError("discovery receipt path is not authorized")
    if control_root != _G1_DISCOVERY_CONTROL_ROOT:
        raise ValueError("discovery control root is not authorized")
    if public_source_path != _G1_DISCOVERY_PUBLIC_SOURCE_PATH:
        raise ValueError("discovery public source path is not authorized")
    return G1DiscoveryOfflineRegistry(
        records=frozen_records,
        receipt_path=receipt_path,
        control_root=control_root,
        public_source_path=public_source_path,
    )


@dataclass(frozen=True, slots=True)
class G1DiscoveryDiagnosticProfile(CanonicalRecord):
    schema_version = "roguepatch.g1-discovery-diagnostic-profile.v1"

    records: tuple[G1DiscoveryActionRecord, ...]
    diagnostic_microvm_id: str
    cleanup_required: bool

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "diagnostic_microvm_id": self.diagnostic_microvm_id,
            "cleanup_required": self.cleanup_required,
            "actions": [
                {
                    "action_id": record.action_id,
                    **command_spec_payload(record.command),
                }
                for record in self.records
            ],
        }


def build_g1_discovery_diagnostic_profile(
    *,
    records: Sequence[G1DiscoveryActionRecord],
    diagnostic_microvm_id: str,
    cleanup_required: bool,
) -> G1DiscoveryDiagnosticProfile:
    frozen_records = tuple(records)
    expected = _G1_DISCOVERY_DIAGNOSTIC_ACTIONS
    actual = tuple((item.action_id, item.command.mutating) for item in frozen_records)
    if actual != expected:
        raise ValueError(
            "diagnostic profile must contain exactly create, exec, destroy in order"
        )
    if diagnostic_microvm_id != "roguepatch-g1-discovery":
        raise ValueError("diagnostic microVM id is not authorized")
    if cleanup_required is not True:
        raise ValueError("diagnostic create, exec, destroy requires cleanup")
    return G1DiscoveryDiagnosticProfile(
        records=frozen_records,
        diagnostic_microvm_id=diagnostic_microvm_id,
        cleanup_required=cleanup_required,
    )


@dataclass(frozen=True, slots=True)
class G1DiscoveryReceiptBinding(CanonicalRecord):
    schema_version = "roguepatch.g1-discovery-receipt.v1"

    approved_by: str
    approved_at: datetime
    expires_at: datetime
    spec_sha256: str
    plan_sha256: str
    repo_commit: str
    host_fingerprint_sha256: str
    action_registry_sha256: str
    diagnostic_profile_sha256: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.approved_by, str) or not self.approved_by:
            raise ValueError("discovery approver must be a non-empty string")
        for name in ("approved_at", "expires_at"):
            value = getattr(self, name)
            if not isinstance(value, datetime) or value.tzinfo is None:
                raise ValueError(f"{name} must be a timezone-aware datetime")
        for name in (
            "spec_sha256",
            "plan_sha256",
            "host_fingerprint_sha256",
            "action_registry_sha256",
        ):
            _require_sha256(getattr(self, name), field=name)
        if (
            not isinstance(self.repo_commit, str)
            or _COMMIT_PATTERN.fullmatch(self.repo_commit) is None
        ):
            raise ValueError("repo commit must be a full lowercase commit digest")
        if self.diagnostic_profile_sha256 is not None:
            _require_sha256(
                self.diagnostic_profile_sha256,
                field="diagnostic profile digest",
            )

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "gate": "g1-discovery",
            "decision": "approved",
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "spec_sha256": self.spec_sha256,
            "plan_sha256": self.plan_sha256,
            "repo_commit": self.repo_commit,
            "host_fingerprint_sha256": self.host_fingerprint_sha256,
            "action_registry_sha256": self.action_registry_sha256,
            "diagnostic_profile_sha256": self.diagnostic_profile_sha256,
        }


@dataclass(frozen=True, slots=True)
class G1DiscoveryAuthorityFacts:
    receipt_path: Path
    receipt_owner: str
    receipt_mode: int
    observed_at: datetime
    expected_spec_sha256: str
    expected_plan_sha256: str
    expected_repo_commit: str
    expected_host_fingerprint_sha256: str
    receipt: G1DiscoveryReceiptBinding
    action_registry: G1DiscoveryOfflineRegistry
    diagnostic_profile: G1DiscoveryDiagnosticProfile | None


@dataclass(frozen=True, slots=True)
class G1DiscoveryAuthority:
    action_registry: G1DiscoveryOfflineRegistry
    diagnostic_profile: G1DiscoveryDiagnosticProfile | None
    baseline_creates_microvm: bool = False
    candidate_regeneration_required: bool = True
    g1_receipt_regeneration_required: bool = True
    discovery_receipt_reusable_as_g1: bool = False
    counts_as_f1_evidence: bool = False


def validate_g1_discovery_authority(
    facts: G1DiscoveryAuthorityFacts,
) -> G1DiscoveryAuthority:
    if not isinstance(facts, G1DiscoveryAuthorityFacts):
        raise TypeError("facts must be G1DiscoveryAuthorityFacts")
    if facts.receipt_path != _G1_DISCOVERY_RECEIPT_PATH:
        raise ValueError("discovery receipt path is not authorized")
    if facts.receipt_owner != "alex":
        raise ValueError("discovery receipt owner must be alex")
    if facts.receipt_mode != 0o600:
        raise ValueError("discovery receipt mode must be 0600")
    if facts.observed_at < facts.receipt.approved_at:
        raise ValueError("discovery observed_at cannot precede approved_at")
    if (
        facts.receipt.expires_at <= facts.receipt.approved_at
        or facts.observed_at >= facts.receipt.expires_at
    ):
        raise ValueError("discovery receipt is expired")
    if facts.receipt.approved_by != "alex":
        raise ValueError("discovery receipt approver must be Alex")
    expected_bindings = (
        ("spec", facts.expected_spec_sha256, facts.receipt.spec_sha256),
        ("plan", facts.expected_plan_sha256, facts.receipt.plan_sha256),
        ("repo commit", facts.expected_repo_commit, facts.receipt.repo_commit),
        (
            "host",
            facts.expected_host_fingerprint_sha256,
            facts.receipt.host_fingerprint_sha256,
        ),
        (
            "registry",
            facts.action_registry.sha256,
            facts.receipt.action_registry_sha256,
        ),
    )
    for label, expected, actual in expected_bindings:
        if expected != actual:
            raise ValueError(f"discovery {label} binding does not match")
    profile_digest = (
        facts.diagnostic_profile.sha256
        if facts.diagnostic_profile is not None
        else None
    )
    if facts.receipt.diagnostic_profile_sha256 != profile_digest:
        raise ValueError("discovery diagnostic profile binding does not match")
    return G1DiscoveryAuthority(
        action_registry=facts.action_registry,
        diagnostic_profile=facts.diagnostic_profile,
    )


@dataclass(frozen=True, slots=True)
class G1DiscoveryObservedCommand:
    action_id: str
    command: CommandSpec
    observed_argv: tuple[str, ...]
    expected_cwd: Path
    expected_env: Mapping[str, str]
    expected_mutating: bool

    def __post_init__(self) -> None:
        if not isinstance(self.action_id, str) or not self.action_id.startswith(
            "g1-discovery."
        ):
            raise ValueError("action_id must be a G1 discovery identifier")
        if not isinstance(self.command, CommandSpec):
            raise TypeError("command must be a CommandSpec")
        if not isinstance(self.observed_argv, tuple):
            raise TypeError("observed_argv must be a tuple")
        if (
            not isinstance(self.expected_cwd, Path)
            or not self.expected_cwd.is_absolute()
        ):
            raise ValueError("expected cwd must be an absolute Path")
        if not isinstance(self.expected_env, Mapping):
            raise TypeError("expected env must be a mapping")
        if type(self.expected_mutating) is not bool:
            raise TypeError("expected mutating flag must be a bool")
        if self.observed_argv != self.command.argv:
            raise ValueError("observed argv does not match the command")
        if self.command.cwd != self.expected_cwd:
            raise ValueError("observed command cwd does not match")
        if dict(self.command.env) != dict(self.expected_env):
            raise ValueError("observed command env does not match")
        if self.command.mutating is not self.expected_mutating:
            raise ValueError("observed command mutating flag does not match")
        object.__setattr__(
            self, "expected_env", MappingProxyType(dict(self.expected_env))
        )
        self._reject_unsafe_argv()

    def _reject_unsafe_argv(self) -> None:
        argv = self.command.argv
        executable = Path(argv[0]).name.lower()
        lowered = tuple(item.lower() for item in argv)
        if executable == "todo" or executable == "offline-discovery-record":
            raise ValueError("placeholder or offline command is forbidden")
        interpreters = {"sh", "bash", "zsh", "python", "python3", "node"}
        if executable in interpreters or (
            executable == "env" and len(argv) > 1 and Path(argv[1]).name in interpreters
        ):
            raise ValueError("shell or interpreter commands are forbidden")
        if executable in {"docker", "docker.exe"}:
            raise ValueError("Docker commands are forbidden")
        if executable == "roguepatch":
            raise ValueError("trial or agent commands are forbidden")
        if executable == "codex":
            raise ValueError("Codex agent commands are forbidden")
        if any(item.endswith("agent.py") for item in lowered):
            raise ValueError("agent code is forbidden")
        if any(item.endswith("task.toml") for item in lowered):
            raise ValueError("task definitions are forbidden")


@dataclass(frozen=True, slots=True)
class G1DiscoveryLiveRegistry:
    """Marker type with no productive constructor until discovery records facts."""

    observed_inputs: tuple[G1DiscoveryObservedCommand, ...]

    def __post_init__(self) -> None:
        raise ValueError("live registry has no authorized observed inputs yet")


def build_g1_discovery_live_registry(
    *, observed_inputs: Sequence[G1DiscoveryObservedCommand] | None
) -> G1DiscoveryLiveRegistry:
    if observed_inputs is None:
        raise ValueError("observed inputs are required for the live registry")
    frozen_inputs = tuple(observed_inputs)
    if not frozen_inputs:
        raise ValueError("observed inputs are required for the live registry")
    if any(not isinstance(item, G1DiscoveryObservedCommand) for item in frozen_inputs):
        raise TypeError("observed inputs must be G1DiscoveryObservedCommand values")
    raise ValueError("observed inputs are not yet authorized for a live registry")


@dataclass(frozen=True, slots=True)
class G1DiscoveryDecision:
    status: PreflightStatus
    invoked: bool
    effect_count: int


def run_g1_discovery(
    *,
    authority: G1DiscoveryAuthority,
    live_registry: G1DiscoveryLiveRegistry | None,
    available_kib: int,
    materializer: object,
    executor: object,
) -> G1DiscoveryDecision:
    if not isinstance(authority, G1DiscoveryAuthority):
        raise TypeError("authority must be validated discovery authority")
    if type(available_kib) is not int:
        raise TypeError("available_kib must be an int")
    if available_kib < 0:
        raise ValueError("available_kib cannot be negative")
    if available_kib < _RECEIPT_INSTALL_MIN_KIB:
        return G1DiscoveryDecision(
            status=PreflightStatus.BLOCKED_LOW_DISK,
            invoked=False,
            effect_count=0,
        )
    if not isinstance(live_registry, G1DiscoveryLiveRegistry):
        raise TypeError("live registry requires authorized observed inputs")
    raise ValueError("live registry execution is unavailable without observed inputs")
