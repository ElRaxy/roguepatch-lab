from __future__ import annotations

from collections.abc import Mapping

from roguepatch.approval import ApprovalBinding, ApprovalState
from roguepatch.ports import CommandResult, CommandSpec


class FakeCommandProbe:
    def __init__(self, *, results: Mapping[tuple[str, ...], CommandResult]) -> None:
        self._results = dict(results)
        self._calls: list[CommandSpec] = []

    @property
    def calls(self) -> tuple[CommandSpec, ...]:
        return tuple(self._calls)

    @property
    def mutating_calls(self) -> tuple[CommandSpec, ...]:
        return tuple(command for command in self._calls if command.mutating)

    def run(self, command: CommandSpec) -> CommandResult:
        self._calls.append(command)
        return self._results.get(
            command.argv,
            CommandResult(
                returncode=127,
                stdout="",
                stderr="unconfigured fake command",
                timed_out=False,
                truncated=False,
            ),
        )


class FakeApprovalStore:
    def __init__(self, *, state: ApprovalState) -> None:
        if not isinstance(state, ApprovalState):
            raise TypeError("state must be an ApprovalState")
        self._state = state
        self._check_calls: list[ApprovalBinding] = []

    @property
    def check_calls(self) -> tuple[ApprovalBinding, ...]:
        return tuple(self._check_calls)

    def check(self, expected: ApprovalBinding) -> ApprovalState:
        self._check_calls.append(expected)
        return self._state
