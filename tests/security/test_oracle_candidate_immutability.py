from __future__ import annotations

import inspect
from pathlib import PurePosixPath

import pytest
from roguepatch.adapters.docker_oracle import (
    CandidateMutationError,
    CandidateSnapshot,
    DockerOracleRunner,
    OracleCheckFailed,
    OracleContainerSpec,
    OracleVerificationFacts,
)
from roguepatch.adapters.sbx_backend import NetworkMode, ResourceLimits

from roguepatch.ports import CommandResult

BEFORE = "sha256:" + "a" * 64
AFTER = "sha256:" + "b" * 64
ORACLE_IMAGE = "roguepatch-oracle@sha256:" + "c" * 64


def _limits() -> ResourceLimits:
    return ResourceLimits(cpu_count=2, memory_mib=2048, max_output_bytes=65_536)


def _container_spec(**overrides: object) -> OracleContainerSpec:
    values: dict[str, object] = {
        "image_digest": ORACLE_IMAGE,
        "network": NetworkMode.NONE,
        "rootfs_read_only": True,
        "candidate_read_only": True,
        "capabilities": (),
        "no_new_privileges": True,
        "secrets": (),
        "model_credentials": (),
        "docker_socket": False,
        "limits": _limits(),
    }
    values.update(overrides)
    return OracleContainerSpec(**values)  # type: ignore[arg-type]


def _result(*, succeeded: bool = True) -> CommandResult:
    return CommandResult(
        returncode=0 if succeeded else 1,
        stdout="oracle complete" if succeeded else "",
        stderr="" if succeeded else "oracle failed",
        timed_out=False,
        truncated=False,
    )


def _verification_facts(**overrides: object) -> OracleVerificationFacts:
    values: dict[str, object] = {
        "candidate": CandidateSnapshot(
            path=PurePosixPath("/candidate"),
            digest=BEFORE,
        ),
        "observed_digest_before": BEFORE,
        "checker_result": _result(),
        "observed_digest_after": BEFORE,
    }
    values.update(overrides)
    return OracleVerificationFacts(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    [
        pytest.param("image_digest", "roguepatch-oracle:latest", id="mutable-image"),
        pytest.param("network", "bridge", id="network-egress"),
        pytest.param("rootfs_read_only", False, id="writable-rootfs"),
        pytest.param("candidate_read_only", False, id="writable-candidate"),
        pytest.param("capabilities", ("SYS_ADMIN",), id="capability"),
        pytest.param("no_new_privileges", False, id="privilege-escalation"),
        pytest.param("secrets", ("synthetic-secret",), id="secret"),
        pytest.param("model_credentials", ("model-token",), id="model-credential"),
        pytest.param("docker_socket", True, id="docker-socket"),
        pytest.param(
            "limits",
            ResourceLimits(
                cpu_count=1,
                memory_mib=2048,
                max_output_bytes=65_536,
            ),
            id="oracle-cpu-drift",
        ),
        pytest.param(
            "limits",
            ResourceLimits(
                cpu_count=2,
                memory_mib=1024,
                max_output_bytes=65_536,
            ),
            id="oracle-memory-drift",
        ),
    ],
)
def test_oracle_container_rejects_every_boundary_relaxation(
    field: str,
    unsafe_value: object,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        _container_spec(**{field: unsafe_value})


def test_oracle_runner_is_an_inert_verifier_not_a_second_execution_path() -> None:
    runner = DockerOracleRunner()
    facts = _verification_facts()

    assert "runtime" not in inspect.signature(DockerOracleRunner).parameters
    assert "executor" not in inspect.signature(DockerOracleRunner).parameters
    assert tuple(inspect.signature(runner.verify).parameters) == ("facts",)
    assert not any(
        hasattr(runner, operation)
        for operation in ("create", "prepare_oracle", "run_container", "destroy")
    )
    assert runner.verify(facts) == facts.checker_result


@pytest.mark.parametrize(
    ("facts", "error", "message"),
    [
        pytest.param(
            _verification_facts(observed_digest_before=AFTER),
            CandidateMutationError,
            "initial candidate digest",
            id="initial-digest-mismatch",
        ),
        pytest.param(
            _verification_facts(observed_digest_after=AFTER),
            CandidateMutationError,
            "candidate digest changed",
            id="checker-mutated-candidate",
        ),
        pytest.param(
            _verification_facts(checker_result=_result(succeeded=False)),
            OracleCheckFailed,
            "oracle failed",
            id="checker-failed",
        ),
    ],
)
def test_inert_oracle_verifier_fails_closed_on_untrusted_observations(
    facts: OracleVerificationFacts,
    error: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error, match=message):
        DockerOracleRunner().verify(facts)
