# Provider Contract

Status: Phase 1 draft for review. Implementation starts only after user approval.

## Purpose

Each analysis mode in Clearspace is backed by a GTK-free provider of pure domain
logic. A provider discovers and measures local candidates lazily when its mode
is opened, runs off the GTK main thread in bounded batches, and returns at most
200 display rows plus precomputed aggregates for omitted smaller items.

Providers never select items, never mutate the filesystem, never terminate
processes, and never execute cleanup commands.

## Analysis modes

| Mode ID | UI label (pt-BR) | Role |
|---|---|---|
| `folders` | `Pastas` | Existing directory tree scanner flow (primary flow; behavior unchanged) |
| `docker` | `Docker` | Read-only Docker disk usage (`docker system df`); volumes are `inspect_only` |
| `caches` | `Caches` | Declarative `$XDG_CACHE_HOME` and developer tool caches |
| `logs` | `Logs` | System journal usage (`journalctl --disk-usage`) and `$XDG_STATE_HOME` / readable logs |
| `large_files` | `Arquivos grandes` | Top regular files from the scanner SQLite database + XDG Downloads shortcut |
| `trash` | `Lixeira` | `$XDG_DATA_HOME/Trash/files` inventory by size and age (`inspect_only`) |
| `packages` | `Pacotes` | Arch Linux (`pacman`) package cache and orphan inspection |

## Data model

```python
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

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


@dataclass(frozen=True, slots=True)
class ClassifiedError:
    kind: ErrorKind
    message: str                 # localized (pt-BR), safe display text; never file contents
    path: Path | None = None
    errno: int | None = None


@dataclass(frozen=True, slots=True)
class Row:
    id: str                       # stable registry/provider ID, e.g. "cache.go.build"
    label: str                    # localized (pt-BR), single-line display label
    size_bytes: int | None        # allocated bytes (st_blocks * 512) when file-backed
    risk: RiskLevel
    action: RowAction
    path: Path | None = None      # only when action == "trash_path"
    argv: tuple[str, ...] | None = None  # only when action == "tool_command"; fixed registry argv
    needs_admin: bool = False
    warnings: tuple[str, ...] = ()
    allowed_root: Path | None = None     # containment root for action == "trash_path"
    mtime_ns: int | None = None          # optional timestamp (e.g. Trash age sorting/display)
    error: ClassifiedError | None = None # optional per-row read/discovery error


@dataclass(frozen=True, slots=True)
class ProviderResult:
    rows: tuple[Row, ...]         # LIMIT 200, ordered by size_bytes DESC, id ASC
    smaller_count: int            # precomputed count of omitted rows ("N itens menores")
    smaller_bytes: int            # precomputed total allocated bytes of omitted rows
    error: ClassifiedError | None = None
```

Constructors normalize `Sequence[str]` / `Sequence[Row]` inputs (`list` or
`tuple`) into immutable tuples so callers and tests using list literals work
without exposing mutable state.

### Risk mapping

Existing `clearspace.contracts.Risk` values map deterministically to provider
`RiskLevel`:

- `Risk.LOW` -> `"low"`
- `Risk.MODERATE` -> `"medium"`
- `Risk.USER_DATA` -> `"high"`
- `Risk.CRITICAL` -> `"critical"`

## Row invariants

1. `action == "trash_path"`:
   - `path` and `allowed_root` are required absolute `Path` objects (`path != allowed_root`).
   - `argv` must be `None`; `needs_admin` must be `False`.
   - `path` is an untrusted candidate that the command generator must
     re-canonicalize and revalidate before emitting `gio trash -- <path>`.
2. `action == "tool_command"`:
   - `argv` is a non-empty tuple of strings copied verbatim from a declarative
     registry entry; `path` and `allowed_root` must be `None`.
   - No filename, path placeholder, user text, environment variable expansion,
     or file content may be interpolated into `argv`.
   - `needs_admin=True` routes the generated command to the separate
     administrator block; Clearspace never executes it.
3. `action == "inspect_only"`:
   - Never generates a command. `path` and `argv` must be `None`.
   - Mandatory for all user data: Trash items, Docker volumes, browser profiles,
     AI/ML models (e.g. Hugging Face), Git repositories, project dependencies
     (`node_modules`), `~/.config`, `~/.vscode`, databases, and system logs not
     managed by a fixed tool procedure.
4. `risk == "critical"` and `error is not None`:
   - Never selectable for command generation and never emit commands.
5. Sizing:
   - Filesystem-backed measurements are read-only, do not follow symlinks
     (`lstat` / `follow_symlinks=False`), stay on a single `st_dev`, count hardlinked
     regular files once per `(st_dev, st_ino)`, and report allocated disk usage
     as `st_blocks * 512`.
   - `size_bytes` is `None` only when a tool cannot report a byte size without
     running a destructive operation; otherwise `size_bytes >= 0`.
6. Bounds and ordering:
   - `len(rows) <= 200`.
   - Rows sort by `(size_bytes is not None, size_bytes or -1)` descending, then
     `id` ascending.
   - Omitted items beyond the 200-row cap are summarized in `smaller_count` and
     `smaller_bytes` without instantiating UI widgets per node.

## Provider interface and execution rules

```python
@dataclass(frozen=True, slots=True)
class ProviderContext:
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
    environ: Mapping[str, str] = ...
    which: Callable[[str], str | None] = shutil.which
    large_files_min_bytes: int = 0
    large_files_downloads_only: bool = False
    system_log_dir: Path = Path("/var/log")
    pacman_cache_dir: Path = Path("/var/cache/pacman/pkg")


class Provider(Protocol):
    id: str
    label: str

    def load(self, context: ProviderContext) -> ProviderResult: ...
```

- **No GTK imports**: provider modules must never import `gi`.
- **No machine-specific constants**: all paths come from `ProviderContext`
  (resolved via XDG in production and `tmp_path` in tests).
- **Read-only subprocesses only**: `run_readonly_command` accepts an explicit
  `Sequence[str]` argument vector (`shell=False`), enforces a finite timeout,
  captures output without shell pipelines, and is mocked in unit tests. Allowed
  read-only probes are strictly non-destructive (e.g. `go env GOCACHE`,
  `journalctl --disk-usage`, `docker system df`, `pacman -Qdtq`).
- **Failure handling**: exceptions are never swallowed. Provider-level failures
  populate `ProviderResult.error` with a `ClassifiedError` (`tool_missing`,
  `socket_denied`, `permission`, `not_found`, `timeout`, `unexpected`) so the UI
  exits the loading state and offers "Tentar de novo".

## Per-mode specifications

### 1. `caches`
- Declarative registry targets under `xdg_cache_home` and standard developer
  caches (npm, pnpm, Gradle, Cargo, Go, pip) detected at runtime.
- Regenerable caches carry `risk="low"` and warning informing that cached data
  will be downloaded or rebuilt again.
- Actions use either `trash_path` (for safe cache directories under an allowed
  cache root) or fixed `tool_command` entries (`["pip", "cache", "purge"]`,
  `["go", "clean", "-cache"]`, `["pnpm", "store", "prune"]`,
  `["npm", "cache", "clean", "--force"]`).
- Whole cache directories are never blanket-protected; protection uses exact
  canonical component matching (`ProtectedPath`).

### 2. `trash`
- Reads `xdg_data_home / "Trash" / "files"` (and optional `.trashinfo` deletion
  timestamps in `Trash/info`, falling back to `st_mtime_ns`).
- Every row has `action="inspect_only"` and `risk="high"`. Never generates
  cleanup commands.

### 3. `large_files`
- Validates SQLite `PRAGMA user_version` against `docs/scanner-contract.md`
  before running queries, and provides an XDG Downloads filter/shortcut.
- Queries the completed read-only scan database for regular files above the
  configured minimum size threshold (`min_blocks = ceil(min_bytes / 512)`):

```sql
SELECT id, parent_id, name, size_blocks, mtime
FROM nodes
WHERE is_dir = 0 AND error IS NULL AND size_blocks >= ?
ORDER BY size_blocks DESC, name COLLATE BINARY ASC, id ASC
LIMIT 200;
```

```sql
SELECT COUNT(*) AS smaller_count, COALESCE(SUM(size_blocks), 0) AS smaller_blocks
FROM (
    SELECT size_blocks
    FROM nodes
    WHERE is_dir = 0 AND error IS NULL AND size_blocks >= ?
    ORDER BY size_blocks DESC, name COLLATE BINARY ASC, id ASC
    LIMIT -1 OFFSET 200
);
```

- Full paths are reconstructed via `parent_id` lookup up to `parent_id IS NULL`
  only for the <= 200 returned rows, keeping memory O(limit).
- Rows matching protected rules or user-data categories are marked non-actionable
  (`inspect_only` or `critical`) according to `RuleEngine` and `ProtectedPath`.

### 4. `logs`
- Probes `["journalctl", "--disk-usage"]` (read-only) and offers fixed admin
  `tool_command` `["journalctl", "--vacuum-size=200M"]` (`needs_admin=True`,
  `risk="medium"`).
- Lists readable log files under `xdg_state_home` (`trash_path` with
  `allowed_root=xdg_state_home`) and readable `/var/log` entries (`inspect_only`
  when root-owned).

### 5. `docker`
- Probes `["docker", "system", "df", "--format", "{{json .}}"]` (read-only).
- Actionable `tool_command` rows use fixed registry vectors only:
  `["docker", "image", "prune"]`, `["docker", "container", "prune"]`, and
  `["docker", "builder", "prune"]`.
- **Volumes row is strictly `action="inspect_only"`, `risk="high"`**, and never
  produces a command.
- Missing `docker` binary -> `tool_missing`; socket `EACCES`/`permission denied`
  -> `socket_denied`; stopped daemon / unreachable socket -> classified error
  with retry button.

### 6. `packages` (Arch Linux)
- Enabled only when `os_release_path` (`/etc/os-release`) identifies Arch Linux
  (`ID=arch` or `arch` in `ID_LIKE`); on other distributions returns a clean
  informational state without invoking `pacman`.
- Measures `/var/cache/pacman/pkg` (`st_blocks * 512`, read-only) and lists
  orphan packages via read-only `["pacman", "-Qdtq"]`.
- Package cache cleanup uses fixed admin `tool_command` `["paccache", "-r"]`
  (`needs_admin=True`).

## Contract constraints on existing procedures

1. **`cargo-build-cache` (`{path}/Cargo.toml` in `clearspace/rules.py`)**:
   Dynamic path interpolation in `argv` is forbidden by this contract. Cargo
   target directories discovered on disk must either use validated `trash_path`
   or remain `inspect_only`; `{path}` placeholders are never expanded into
   generated commands.
2. **Orphan package removal (`pacman -Rns`)**:
   Command substitution (`$(pacman -Qdtq)`) is forbidden in generated scripts.
   In Phase 5, orphan removal either remains `inspect_only` + static
   instructions or requires an explicit static-safe specification approved by
   the user (strict package-name allowlist `^[a-z0-9@._+][a-z0-9@._+-]*$` after
   `["pacman", "-Rns", "--", ...]`, never raw stdout interpolation).
