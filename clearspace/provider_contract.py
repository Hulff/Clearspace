"""GTK-free data contracts for analysis providers and command generation."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
import shutil
import subprocess
from typing import Literal, Protocol

from .contracts import Risk

RiskLevel = Literal["low", "medium", "high", "critical"]
RowAction = Literal["trash_path", "tool_command", "inspect_only"]
ErrorKind = Literal[
    "protected",
    "in_use",
    "outside_root",
    "permission",
    "not_found",
    "tool_missing",
    "socket_denied",
    "timeout",
    "unsafe_name",
    "symlink",
    "critical",
    "inspect_only",
    "invalid_row",
    "unexpected",
]

PROVIDER_ROW_LIMIT = 200
SCANNER_SCHEMA_VERSION = 1


def risk_to_provider_level(risk: Risk) -> RiskLevel:
    """Map legacy domain Risk enum values to the v2 provider RiskLevel."""
    mapping: dict[Risk, RiskLevel] = {
        Risk.LOW: "low",
        Risk.MODERATE: "medium",
        Risk.USER_DATA: "high",
        Risk.CRITICAL: "critical",
    }
    return mapping[risk]


@dataclass(frozen=True, slots=True)
class ClassifiedError:
    """Structured, display-safe failure for a provider or blocked row."""

    kind: ErrorKind
    message: str
    path: Path | None = None
    errno: int | None = None


@dataclass(frozen=True, slots=True)
class ProtectedPath:
    """Canonicalized path protection rule compared strictly by components."""

    path: Path
    rule: str
    include_descendants: bool


@dataclass(frozen=True, slots=True)
class Row:
    """A single candidate item produced by an analysis mode provider."""

    id: str
    label: str
    size_bytes: int | None
    risk: RiskLevel
    action: RowAction
    path: Path | None = None
    argv: Sequence[str] | None = None
    needs_admin: bool = False
    warnings: Sequence[str] = ()
    allowed_root: Path | None = None
    mtime_ns: int | None = None
    error: ClassifiedError | None = None

    def __post_init__(self) -> None:
        if self.size_bytes is not None and (
            type(self.size_bytes) is not int or self.size_bytes < 0
        ):
            raise ValueError("size_bytes must be a non-negative int or None")
        if self.argv is not None:
            object.__setattr__(self, "argv", tuple(self.argv))
        object.__setattr__(self, "warnings", tuple(self.warnings))


@dataclass(frozen=True, slots=True)
class ProviderResult:
    """Bounded batch result returned by a mode provider."""

    rows: Sequence[Row]
    smaller_count: int
    smaller_bytes: int
    error: ClassifiedError | None = None

    def __post_init__(self) -> None:
        normalized_rows = tuple(self.rows)
        if len(normalized_rows) > PROVIDER_ROW_LIMIT:
            raise ValueError(f"ProviderResult cannot exceed {PROVIDER_ROW_LIMIT} rows")
        if type(self.smaller_count) is not int or self.smaller_count < 0:
            raise ValueError("smaller_count must be a non-negative int")
        if type(self.smaller_bytes) is not int or self.smaller_bytes < 0:
            raise ValueError("smaller_bytes must be a non-negative int")
        object.__setattr__(self, "rows", normalized_rows)


@dataclass(frozen=True, slots=True)
class CommandProbeResult:
    """Captured output from an allowlisted read-only subprocess probe."""

    returncode: int
    stdout: str
    stderr: str


ReadOnlyRunner = Callable[[Sequence[str], float], CommandProbeResult]

_ALLOWED_READONLY_PROBES: frozenset[tuple[str, ...]] = frozenset(
    {
        ("go", "env", "GOCACHE"),
        ("journalctl", "--disk-usage"),
        ("docker", "system", "df", "--format", "{{json .}}"),
        ("pacman", "-Qdtq"),
    }
)


def run_readonly_subprocess(
    argv: Sequence[str],
    timeout: float = 5.0,
) -> CommandProbeResult:
    """Execute an allowlisted read-only probe without a shell."""
    command = tuple(argv)
    if not command or any(not isinstance(part, str) or not part for part in command):
        raise ValueError("argv must be a non-empty sequence of non-empty strings")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if command not in _ALLOWED_READONLY_PROBES:
        raise ValueError(f"Command {command[0]!r} is not in the read-only allowlist")
    completed = subprocess.run(
        list(command),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
    )
    return CommandProbeResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


@dataclass(frozen=True, slots=True)
class ProviderContext:
    """Explicit runtime environment inputs injected into providers."""

    xdg_cache_home: Path
    xdg_data_home: Path
    xdg_state_home: Path
    xdg_config_home: Path
    downloads_dir: Path | None
    scan_db_path: Path | None
    scan_root: Path | None
    os_release_path: Path
    run_readonly_command: ReadOnlyRunner
    protected_paths: tuple[ProtectedPath, ...]
    home_dir: Path | None = None
    environ: Mapping[str, str] = field(default_factory=dict)
    which: Callable[[str], str | None] = shutil.which
    large_files_min_bytes: int = 0
    large_files_downloads_only: bool = False
    system_log_dir: Path = Path("/var/log")
    pacman_cache_dir: Path = Path("/var/cache/pacman/pkg")


class Provider(Protocol):
    """GTK-free analysis mode provider."""

    id: str
    label: str

    def load(self, context: ProviderContext) -> ProviderResult: ...
