from __future__ import annotations

import errno
import inspect
import json
import os
from hashlib import sha256
from pathlib import Path, PurePosixPath

import pytest

LIVE_ENABLED = os.environ.get("ROGUEPATCH_LIVE") == "1"

pytestmark = pytest.mark.skipif(
    not LIVE_ENABLED,
    reason="requires explicit ROGUEPATCH_LIVE=1 on the authorized iMac",
)


def test_real_oracle_runs_in_a_distinct_hardened_microvm() -> None:
    from roguepatch import approval
    from roguepatch.adapters.docker_oracle import (
        PROTECTED_PROBE_ACTION_IDS,
        PROTECTED_PROBE_ORDER,
        PROTECTED_PROBE_PATHS,
        OracleEngineIdentityObservation,
        ProtectedTarget,
        SourceMountObservation,
        run_live_oracle_boundary_probe,
        validate_oracle_boundary,
    )
    from roguepatch.adapters.sbx_backend import (
        F1_TRACE_GENESIS_SHA256,
        F1ExecutionStatus,
        NetworkMode,
        SandboxLifecycleAction,
        SandboxRole,
        WorkspaceMode,
    )
    from roguepatch.approval import G1_ACTION_IDS, ApprovalState, host_identity_sha256
    from roguepatch.doctor import PreflightStatus

    assert list(inspect.signature(run_live_oracle_boundary_probe).parameters) == []
    live = run_live_oracle_boundary_probe()
    facts = live.boundary
    required_targets = {
        ProtectedTarget.HOST_CANARY,
        ProtectedTarget.PROTECTED_MANIFEST,
        ProtectedTarget.GOLDEN_PATCH,
        ProtectedTarget.SIGNING_MATERIAL,
        ProtectedTarget.ARTIFACT_STORE,
        ProtectedTarget.APPROVAL_RECEIPT,
        ProtectedTarget.CONTROL_CREDENTIALS,
        ProtectedTarget.MODEL_CREDENTIALS,
        ProtectedTarget.DOCKER_SOCKET,
        ProtectedTarget.ORACLE_CHECKER,
        ProtectedTarget.SOURCE_PROTECTED_MANIFEST,
        ProtectedTarget.SOURCE_GOLDEN_PATCH,
        ProtectedTarget.SOURCE_ARTIFACTS,
    }
    canonical_targets = (
        ProtectedTarget.HOST_CANARY,
        ProtectedTarget.PROTECTED_MANIFEST,
        ProtectedTarget.GOLDEN_PATCH,
        ProtectedTarget.SIGNING_MATERIAL,
        ProtectedTarget.ARTIFACT_STORE,
        ProtectedTarget.APPROVAL_RECEIPT,
        ProtectedTarget.CONTROL_CREDENTIALS,
        ProtectedTarget.MODEL_CREDENTIALS,
        ProtectedTarget.DOCKER_SOCKET,
        ProtectedTarget.ORACLE_CHECKER,
        ProtectedTarget.SOURCE_PROTECTED_MANIFEST,
        ProtectedTarget.SOURCE_GOLDEN_PATCH,
        ProtectedTarget.SOURCE_ARTIFACTS,
    )
    expected_trace_action_ids = (
        "g1.sbx.agent.create",
        *(PROTECTED_PROBE_ACTION_IDS[target] for target in canonical_targets),
        "g1.sbx.agent.freeze",
        "g1.sbx.agent.destroy",
        "g1.sbx.oracle.create",
        "g1.sbx.oracle.engine-identity",
        "g1.sbx.oracle.checker",
        "g1.sbx.oracle.destroy",
    )

    assert live.host_identity.hostname == "iMac-de-Alex.local"
    assert live.host_identity.account == "alex"
    assert live.host_identity.arch == "arm64"
    assert live.host_identity.os_build
    assert live.host_fingerprint_sha256 == host_identity_sha256(live.host_identity)
    assert live.lab_root == Path("/Users/alex/RoguePatchLab")
    assert live.host_fallback_allowed is False
    assert live.sbx_executable == "sbx"
    assert live.approval_state is ApprovalState.APPROVED
    assert live.receipt_binding.host_fingerprint_sha256 == live.host_fingerprint_sha256
    assert live.receipt_binding.action_registry_sha256 == live.action_registry_sha256
    assert live.preflight_decision.status is PreflightStatus.READY
    assert live.preflight_decision.receipt_allowed is True
    assert live.preflight_decision.install_allowed is True
    assert live.preflight_decision.create_allowed is True
    assert live.preflight.disk.available_kib >= 41_943_040
    assert live.preflight.create_invocations == 0
    assert live.create_invocations == 2
    assert len(live.pre_create_available_kib) == 2
    assert len(live.post_create_available_kib) == 2
    assert all(available >= 31_457_280 for available in live.pre_create_available_kib)
    assert all(available >= 20_971_520 for available in live.post_create_available_kib)
    assert PROTECTED_PROBE_ORDER == canonical_targets
    assert PROTECTED_PROBE_PATHS[
        ProtectedTarget.SOURCE_PROTECTED_MANIFEST
    ] == PurePosixPath("/run/sandbox/source/protected/protected_manifest.json")
    assert PROTECTED_PROBE_PATHS[ProtectedTarget.SOURCE_GOLDEN_PATCH] == PurePosixPath(
        "/run/sandbox/source/protected/golden.patch"
    )
    assert PROTECTED_PROBE_PATHS[ProtectedTarget.SOURCE_ARTIFACTS] == PurePosixPath(
        "/run/sandbox/source/artifacts"
    )
    action_registry = {action.action_id: action for action in live.action_registry}
    assert set(action_registry) == set(G1_ACTION_IDS)
    assert set(action_registry) == {
        "g1.source.resolve",
        *(PROTECTED_PROBE_ACTION_IDS[target] for target in canonical_targets),
        "g1.sbx.agent.create",
        "g1.sbx.agent.freeze",
        "g1.sbx.agent.destroy",
        "g1.sbx.oracle.create",
        "g1.sbx.oracle.engine-identity",
        "g1.sbx.oracle.checker",
        "g1.sbx.oracle.destroy",
    }
    assert len(action_registry) == 21
    trace = facts.execution_trace
    assert trace.schema_version == "roguepatch.f1-execution-trace.v1"
    assert [record.action_id for record in trace.records] == list(
        expected_trace_action_ids
    )
    assert len(trace.records) == 20
    assert [record.sequence for record in trace.records] == list(range(1, 21))
    assert trace.records[0].prev_record_sha256 == F1_TRACE_GENESIS_SHA256
    assert all(
        record.prev_record_sha256 == trace.records[index - 1].sha256
        for index, record in enumerate(trace.records[1:], start=1)
    )
    assert all(record.status is F1ExecutionStatus.SUCCEEDED for record in trace.records)
    assert [record.microvm_role for record in trace.records] == [
        *([SandboxRole.AGENT] * 16),
        *([SandboxRole.ORACLE] * 4),
    ]
    assert [record.microvm_id for record in trace.records] == [
        *([facts.agent.microvm_id] * 16),
        *([facts.oracle.microvm_id] * 4),
    ]
    for record in trace.records:
        registered = action_registry[record.action_id]
        assert record.command_spec_digest == approval._command_spec_sha256(
            registered.command
        )
        assert record.action_registry_sha256 == live.action_registry_sha256
        assert len(record.result_digest) == 64

    assert validate_oracle_boundary(facts) is None
    assert not hasattr(facts, "verified")
    assert facts.source_read_only is True
    assert facts.workspace_mode is WorkspaceMode.PRIVATE_CLONE
    assert facts.agent_cwd != PurePosixPath("/run/sandbox/source")
    specs = {spec.target: spec for spec in facts.probe_specs}
    observations = {
        observation.target: observation for observation in facts.probe_observations
    }
    records = {record.sha256: record for record in facts.execution_records}
    assert set(specs) == set(observations) == required_targets
    assert len(facts.probe_specs) == len(facts.probe_observations)
    assert len(required_targets) == 13
    assert len(facts.execution_records) == len(required_targets)
    for target in required_targets:
        spec = specs[target]
        observation = observations[target]
        record = records[observation.execution_record_sha256]
        assert spec.probe_path == PROTECTED_PROBE_PATHS[target]
        assert spec.action_id == PROTECTED_PROBE_ACTION_IDS[target]
        assert spec.action_registry_sha256 == facts.action_registry_sha256
        assert spec.command_spec_digest == facts.probe_command_spec_digests[target]
        assert observation.probe_path == spec.probe_path == record.probe_path
        assert observation.spec_sha256 == spec.sha256
        assert observation.microvm_id == facts.agent.microvm_id
        assert observation.action_id == spec.action_id == record.action_id
        assert observation.command_spec_digest == spec.command_spec_digest
        assert observation.command_spec_digest == record.command_spec_digest
        assert record.action_registry_sha256 == facts.action_registry_sha256
        assert observation.result_digest == record.result_digest
        assert observation.observed_errno == record.observed_errno
        assert observation.observed_errno in {errno.ENOENT, errno.EACCES}
        assert record.read_only is True
    assert observations[ProtectedTarget.HOST_CANARY].observed_errno == errno.ENOENT
    host_canary = observations[ProtectedTarget.HOST_CANARY]
    source_mount = host_canary.source_mount_observation
    assert isinstance(source_mount, SourceMountObservation)
    agent_spec = facts.create_requests[0].agent_spec
    assert agent_spec is not None
    agent_source_proof = agent_spec.source_path_proof
    assert source_mount.sandbox == facts.agent
    assert source_mount.mount_path == PurePosixPath("/run/sandbox/source")
    assert source_mount.git_top_level == source_mount.mount_path
    assert source_mount.source_path_proof_sha256 == agent_source_proof.sha256
    assert source_mount.git_commit == agent_source_proof.git_commit
    assert source_mount.git_tree_digest == agent_source_proof.git_tree_digest
    assert source_mount.read_only is True
    assert source_mount.execution_record_sha256 == facts.execution_records[0].sha256
    host_canary_result = {
        "schema_version": "roguepatch.host-canary-result.v1",
        "target": host_canary.target.value,
        "observed_errno": host_canary.observed_errno,
        "source_mount": {
            "sandbox": {
                "role": source_mount.sandbox.role.value,
                "microvm_id": source_mount.sandbox.microvm_id,
            },
            "mount_path": str(source_mount.mount_path),
            "git_top_level": str(source_mount.git_top_level),
            "source_path_proof_sha256": source_mount.source_path_proof_sha256,
            "git_commit": source_mount.git_commit,
            "git_tree_digest": source_mount.git_tree_digest,
            "read_only": source_mount.read_only,
        },
    }
    host_canary_result_digest = sha256(
        json.dumps(
            host_canary_result,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    assert host_canary.result_digest == host_canary_result_digest
    assert facts.execution_records[0].result_digest == host_canary_result_digest
    assert all(
        observation.source_mount_observation is None
        for observation in facts.probe_observations[1:]
    )

    engine_identity = facts.engine_identity_observation
    checker = facts.checker_observation
    assert isinstance(engine_identity, OracleEngineIdentityObservation)
    assert engine_identity.sandbox == facts.oracle
    assert engine_identity.action_registry_sha256 == facts.action_registry_sha256
    assert engine_identity.identity_result.succeeded
    assert (
        engine_identity.identity_result.stdout
        == engine_identity.identity_result.stdout.strip()
    )
    assert (
        engine_identity.engine_identity_sha256
        == sha256(engine_identity.identity_result.stdout.encode()).hexdigest()
    )
    assert not hasattr(facts.create_observations[0], "engine_identity_sha256")
    assert not hasattr(facts.create_observations[1], "engine_identity_sha256")
    assert checker.sandbox == facts.oracle
    assert checker.action_registry_sha256 == facts.action_registry_sha256
    assert checker.engine_identity_sha256 == engine_identity.engine_identity_sha256
    assert (
        next(
            record
            for record in trace.records
            if record.action_id == "g1.sbx.oracle.engine-identity"
        ).result_digest
        == engine_identity.sha256
    )
    assert [record.action for record in facts.lifecycle] == [
        SandboxLifecycleAction.CREATE,
        SandboxLifecycleAction.FREEZE,
        SandboxLifecycleAction.DESTROY,
        SandboxLifecycleAction.CREATE,
    ]
    assert [record.sequence for record in facts.lifecycle] == [1, 2, 3, 4]
    assert len({record.sha256 for record in facts.lifecycle}) == 4
    assert all(
        record.action_registry_sha256 == facts.action_registry_sha256
        for record in facts.lifecycle
    )
    assert facts.lifecycle[0].sandbox == facts.agent
    assert facts.lifecycle[2].sandbox == facts.agent
    assert facts.lifecycle[3].sandbox == facts.oracle
    assert facts.lifecycle[3].limits.cpu_count == 2
    assert facts.lifecycle[3].limits.memory_mib == 2048
    assert facts.lifecycle[3].private_engine is True
    assert facts.agent.microvm_id != facts.oracle.microvm_id
    assert facts.engine_shared is False
    assert facts.container.network is NetworkMode.NONE
    assert facts.container.rootfs_read_only is True
    assert facts.container.candidate_read_only is True
    assert facts.container.capabilities == ()
    assert facts.container.no_new_privileges is True
    assert facts.container.secrets == ()
    assert facts.container.model_credentials == ()
    assert facts.container.docker_socket is False
    assert facts.candidate_digest_before == facts.candidate_digest_after
