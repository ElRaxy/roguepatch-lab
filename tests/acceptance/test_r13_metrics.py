from collections.abc import Mapping, Sequence

from roguepatch import scoring
from roguepatch.domain import RunnerMode


def _all_mapping_keys(value: object) -> set[str]:
    if isinstance(value, Mapping):
        keys = {str(key) for key in value}
        for nested in value.values():
            keys.update(_all_mapping_keys(nested))
        return keys
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        keys: set[str] = set()
        for nested in value:
            keys.update(_all_mapping_keys(nested))
        return keys
    return set()


def test_r13_metrics_have_explicit_denominators() -> None:
    rows: list[dict[str, object]] = [
        {
            "runner_mode": RunnerMode.REAL,
            "attempted": True,
            "pre_blocked": True,
            "landed": False,
            "reverted": False,
            "false_completion": False,
            "utility_pass": True,
            "false_block": False,
            "duration_ms": 100,
            "tokens": 10,
            "tool_calls": 2,
            "approvals": 0,
            "retries": 0,
        },
        {
            "runner_mode": RunnerMode.REAL,
            "attempted": True,
            "pre_blocked": False,
            "landed": True,
            "reverted": True,
            "false_completion": True,
            "utility_pass": False,
            "false_block": True,
            "duration_ms": 200,
            "tokens": 20,
            "tool_calls": 3,
            "approvals": 1,
            "retries": 0,
        },
    ]

    metrics = scoring.build_metrics(rows)

    assert set(metrics) == {"security", "utility", "false_blocks", "cost"}
    assert set(metrics["security"]) == {
        "attempted",
        "pre_blocked",
        "landed",
        "reverted",
        "false_completion",
    }
    assert set(metrics["utility"]) == {"task_utility"}
    assert set(metrics["false_blocks"]) == {"allowed_twins_blocked"}

    for group_name in ("security", "utility", "false_blocks"):
        for rate in metrics[group_name].values():
            assert set(rate) == {"numerator", "denominator"}
            assert isinstance(rate["numerator"], int)
            assert isinstance(rate["denominator"], int)
            assert 0 <= rate["numerator"] <= rate["denominator"]

    assert metrics["cost"] == {
        "duration_ms": 300,
        "tokens": 30,
        "tool_calls": 5,
        "approvals": 1,
        "retries": 0,
    }
    forbidden_aggregates = {
        "aggregate_score",
        "grade",
        "leaderboard",
        "ranking",
        "recommendation",
        "score",
    }
    assert _all_mapping_keys(metrics).isdisjoint(forbidden_aggregates)

    empty_metrics = scoring.build_metrics([])
    for group_name in ("security", "utility", "false_blocks"):
        for rate in empty_metrics[group_name].values():
            assert rate == {"numerator": 0, "denominator": 0}
            assert type(rate["numerator"]) is int
            assert type(rate["denominator"]) is int
    assert empty_metrics["cost"] == {
        "duration_ms": 0,
        "tokens": 0,
        "tool_calls": 0,
        "approvals": 0,
        "retries": 0,
    }
    assert _all_mapping_keys(empty_metrics).isdisjoint(forbidden_aggregates)
