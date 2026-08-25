from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol

_ALLOWED_ENV_KEYS = frozenset({"DOCKER_HOST", "LANG", "LC_ALL", "PATH", "TMPDIR"})
_MAX_TIMEOUT_SECONDS = 300
_MAX_CAPTURE_BYTES = 1_048_576


@dataclass(frozen=True, slots=True)
class CommandSpec:
    argv: tuple[str, ...]
    cwd: Path
    env: Mapping[str, str]
    timeout_seconds: int
    max_output_bytes: int
    mutating: bool = False
    shell: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.argv, tuple) or not self.argv:
            raise TypeError("argv must be a non-empty tuple")
        if any(
            not isinstance(arg, str) or not arg or "\x00" in arg for arg in self.argv
        ):
            raise ValueError("argv entries must be non-empty strings without NUL")
        if not isinstance(self.cwd, Path) or not self.cwd.is_absolute():
            raise ValueError("cwd must be an explicit absolute Path")
        if not isinstance(self.env, Mapping):
            raise TypeError("env must be an explicit mapping")
        frozen_env: dict[str, str] = {}
        for key, value in self.env.items():
            if key not in _ALLOWED_ENV_KEYS:
                raise ValueError(f"environment key is not allowlisted: {key}")
            if not isinstance(value, str) or "\x00" in value:
                raise ValueError("environment values must be strings without NUL")
            frozen_env[key] = value
        object.__setattr__(self, "env", MappingProxyType(frozen_env))
        if (
            type(self.timeout_seconds) is not int
            or not 1 <= self.timeout_seconds <= _MAX_TIMEOUT_SECONDS
        ):
            raise ValueError("timeout_seconds is outside the safe range")
        if (
            type(self.max_output_bytes) is not int
            or not 1 <= self.max_output_bytes <= _MAX_CAPTURE_BYTES
        ):
            raise ValueError("max_output_bytes is outside the safe range")
        if type(self.mutating) is not bool:
            raise TypeError("mutating must be a bool")
        if type(self.shell) is not bool or self.shell:
            raise ValueError("shell must be exactly False")


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool

    def __post_init__(self) -> None:
        if self.returncode is not None and type(self.returncode) is not int:
            raise TypeError("returncode must be an int or None")
        if not isinstance(self.stdout, str) or not isinstance(self.stderr, str):
            raise TypeError("captured output must be text")
        if type(self.timed_out) is not bool or type(self.truncated) is not bool:
            raise TypeError("timed_out and truncated must be bools")
        if self.timed_out and self.returncode is not None:
            raise ValueError("a timed-out command cannot have a returncode")

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.truncated


class CommandProbe(Protocol):
    def run(self, command: CommandSpec) -> CommandResult: ...
