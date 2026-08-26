from __future__ import annotations

import os
from pathlib import Path

import pytest

LIVE_ENABLED = os.environ.get("ROGUEPATCH_LIVE") == "1"
IMAC_LAB_ROOT = Path("/Users/alex/RoguePatchLab")

pytestmark = pytest.mark.skipif(
    not LIVE_ENABLED,
    reason="requires explicit ROGUEPATCH_LIVE=1 on the authorized iMac",
)


def test_real_preflight_uses_only_the_local_imac_lab() -> None:
    from roguepatch.adapters.sbx_backend import run_live_preflight

    from roguepatch.doctor import PreflightStatus, evaluate_live_preflight

    facts = run_live_preflight()
    safety = facts.preflight
    decision = evaluate_live_preflight(safety)
    proof = facts.source_path_proof
    record = facts.source_resolution_record

    assert not hasattr(facts, "ready")
    assert facts.lab_root == IMAC_LAB_ROOT
    assert proof.requested_path == facts.source_repository
    assert proof.lab_realpath == IMAC_LAB_ROOT
    assert proof.source_realpath.is_relative_to(proof.lab_realpath)
    assert proof.exists is True
    assert proof.contains_parent_reference is False
    assert proof.symlink_components == ()
    assert proof.read_only is True
    assert proof.action_id == "g1.source.resolve"
    assert len(proof.command_spec_digest) == 64
    assert len(proof.result_digest) == 64
    assert proof.execution_record_sha256 == record.sha256
    assert record.requested_path == proof.requested_path
    assert record.source_realpath == proof.source_realpath
    assert record.lab_realpath == proof.lab_realpath
    assert record.action_id == proof.action_id
    assert record.command_spec_digest == proof.command_spec_digest
    assert record.result_digest == proof.result_digest
    assert record.read_only is True
    assert facts.source_digest == facts.approved_source_digest
    assert facts.sbx_executable == "sbx"
    assert facts.host_fallback_allowed is False
    assert safety.disk.receipt_install_min_kib == 41_943_040
    assert safety.disk.pre_create_min_kib == 31_457_280
    assert safety.disk.post_create_min_kib == 20_971_520
    assert safety.resources.host_memory_mib == 8192
    assert safety.resources.sequential is True
    assert safety.resources.vm_cpu_count == 2
    assert safety.resources.vm_memory_mib == 2048
    assert safety.create_invocations == 0
    assert decision.receipt_allowed is (
        safety.disk.available_kib >= safety.disk.receipt_install_min_kib
    )
    assert decision.install_allowed is decision.receipt_allowed
    assert decision.create_allowed is (
        safety.disk.available_kib >= safety.disk.pre_create_min_kib
    )
    assert decision.post_create_safe is (
        safety.disk.available_kib >= safety.disk.post_create_min_kib
    )
    expected_status = (
        PreflightStatus.READY
        if safety.disk.available_kib >= safety.disk.receipt_install_min_kib
        else PreflightStatus.BLOCKED_LOW_DISK
    )
    assert decision.status is expected_status
