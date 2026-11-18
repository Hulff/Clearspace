# Command Generator Contract

Status: Phase 1 draft for review. Clearspace never executes the generated
script; the output is text for the user to inspect, copy, and paste in a
terminal if they choose.

## Purpose

The command generator is a pure, deterministic domain function. It receives the
rows explicitly selected by the user during review, re-canonicalizes and
revalidates every item against filesystem and security invariants at generation
time, and returns:

1. A copy-only shell script containing independent commands.
2. The metadata of rows included in the script.
3. The list of blocked rows with classified reasons.

The generator module must never import `gi`, never call `subprocess`, never
mutate the filesystem, and never access the network. Read-only `lstat`/`resolve`
calls on local paths for generation-time revalidation are the only permitted I/O.

## Interface

```python
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .provider_contract import ClassifiedError, ProtectedPath, Row


@dataclass(frozen=True, slots=True)
class ProtectedPath:
    path: Path
    rule: str
    include_descendants: bool     # False for "/" and $HOME; True for "/usr", "~/.ssh", etc.


@dataclass(frozen=True, slots=True)
class BlockedItem:
    row_id: str
    label: str
    reason: ClassifiedError


@dataclass(frozen=True, slots=True)
class GeneratedItem:
    row_id: str
    label: str
    action: Literal["trash_path", "tool_command"]
    size_bytes: int | None
    needs_admin: bool
    command_line: str


@dataclass(frozen=True, slots=True)
class CommandGenerationResult:
    script: str                   # empty string when generated is empty
    generated: tuple[GeneratedItem, ...]
    blocked: tuple[BlockedItem, ...]
    warnings: tuple[str, ...] = ()


def generate_commands(
    rows: Sequence[Row],
    *,
    protected_paths: Sequence[ProtectedPath],
) -> CommandGenerationResult: ...
```

## Generation rules and security invariants

### 1. Untrusted names and control-character blocking
- File names, paths, and labels are untrusted input.
- Any row whose `label`, `path` string, or `argv` token contains `\x00` (NUL),
  `\n`, `\r`, or any Unicode control/format character (categories `Cc` and `Cf`,
  including ANSI escapes and bidirectional overrides) is **blocked** with
  `ClassifiedError(kind="unsafe_name", ...)` and omitted from both commands and
  comments.

### 2. Actionable vs. blocked row filtering
- Rows with `action == "inspect_only"` are blocked (`kind="inspect_only"`).
- Rows with `risk == "critical"` are blocked (`kind="critical"`).
- Rows with `row.error is not None` are blocked preserving `row.error`.
- User-data categories (Trash, Docker volumes, browser profiles, models,
  repositories, `node_modules`, `~/.config`, `~/.vscode`, databases) must be
  `inspect_only` at provider level and are rejected if ever passed in.

### 3. Generation-time filesystem revalidation (`trash_path`)
For each `trash_path` row:
1. Require absolute `path` and absolute `allowed_root`, with no `".."` segments.
2. Validate `allowed_root` via `lstat()`: must exist, be a real directory (not a
   symlink), and not match a protected root.
3. Walk every path component from `allowed_root` to `path` using `lstat()`:
   - Missing entry -> blocked (`kind="not_found"`).
   - Permission denied -> blocked (`kind="permission"`).
   - Any symlink component -> blocked (`kind="symlink"`, or `"outside_root"` /
     `"protected"` when its target escapes `allowed_root` or hits a protected
     rule).
4. Resolve canonical path strictly (`resolve(strict=True)`):
   - Must stay strictly inside `allowed_root` via component comparison
     (`canonical.is_relative_to(canonical_root)` and `canonical != canonical_root`);
     otherwise blocked (`kind="outside_root"`).
   - Must reside on the same `st_dev` as `allowed_root` and be a regular file or
     directory.
   - Must not match any `ProtectedPath`:
     - When `include_descendants=False` (`/` and `$HOME` itself): blocked if
       `canonical == protected.path`.
     - When `include_descendants=True` (`/usr`, `/etc`, `/boot`, `/var`, `/proc`,
       `/sys`, `/dev`, `/run`, `~/.ssh`, `~/.gnupg`, credentials, editor user
       data): blocked if `canonical.is_relative_to(protected.path)`.
5. Render exclusively as:

```sh
gio trash -- <shlex.quote(str(canonical))>
```

- Leading `--` prevents option injection on filenames starting with `-`.
- `shlex.quote` neutralizes spaces, single/double quotes, `$()`, backticks, `;`,
  `&`, `|`, `*`, `?`, and Unicode characters so `shlex.split(line)` returns
  `["gio", "trash", "--", str(canonical)]` verbatim.
- **Never emit `rm`, `rm -rf`, permanent deletion, globs, or fallback logic** if
  `gio trash` fails in the user's terminal.
- Deduplicate overlapping selections: if both an ancestor directory and its
  descendant are valid `trash_path` rows, emit only the ancestor.

### 4. Fixed registry tool commands (`tool_command`)
- `argv` must be non-empty, immutable, free of placeholders (such as `{path}`),
  and originate from the static registry.
- Render non-admin tool commands as `shlex.join(row.argv)`.
- Render admin tool commands (`needs_admin=True`) as
  `shlex.join(("sudo", *row.argv))` **only** inside the dedicated administrator
  section. `sudo` never appears outside the administrator section.

### 5. Independent command layout
When `generated` is non-empty, `script` uses independent lines (no `&&`, `||`,
`;`, pipelines `|`, `$(...)`, backticks, or `set -e`) so a single command failure
does not abort subsequent commands:

```sh
# Clearspace — revise cada comando antes de colar no terminal.
df -h --output=avail /

# <label> (~<formatted_size>)
gio trash -- '/caminho/seguro/exemplo'

# <label_ferramenta> (~<formatted_size>)
go clean -cache

# === Requer administrador (revise com atenção) ===
# <label_admin> (~<formatted_size>)
sudo journalctl --vacuum-size=200M

df -h --output=avail /
```

- The administrator header is omitted when no generated item has
  `needs_admin=True`.
- When all selected rows are blocked (or `rows` is empty), `script == ""`.

## Review UI and JSONL history contract

- **Review screen**:
  - Displays the generated script, estimated total size, blocked items with
    their classified reasons, informational notes (including `/proc`
    app-in-use warnings), the notice **"Revise antes de colar no terminal"**,
    and a **Copiar** button (disabled/hidden if `script == ""`).
  - Never auto-copies and never runs any command.
  - Offers **"Reescanear"** so the user can measure real freed disk space via
    `os.statvfs` after running commands externally.
- **JSONL history**:
  - Records only event `"command_generated"` containing `schema_version`,
    timestamp, generated row IDs/actions/sizes/`needs_admin`, and blocked row
    IDs + `reason.kind`.
  - Never records `"success"` or claims that space was freed, and does not
    persist file contents.

## Mandatory test matrix (`tmp_path`, no GTK, no real cleanup execution)

1. **Hostile filenames**: spaces, `'`, `"`, `$(touch x)`, `` `id` ``, `;`, `&`,
   leading `-rf`, Unicode, literal `*` and `?` -> `shlex.split(command_line)`
   equals `["gio", "trash", "--", str(expected_path)]`.
2. **Control characters**: `\n`, `\r`, `\x00`, ANSI escape `\x1b`, Unicode `Cf`
   in path or label -> item in `blocked` (`unsafe_name`), absent from `script`.
3. **No forbidden constructs**: unquoted AST/token check confirms `rm` is never
   emitted as a command, `sudo` never appears outside the admin block, and no
   command line uses `&&`, `|`, command substitution, or unquoted globs.
4. **Policy blocks**: exact/component protected paths (`/` and `$HOME` exact;
   `~/.ssh`, `/etc`, credentials subtrees), `critical`, `inspect_only`, and
   Docker volumes produce zero commands.
5. **TOCTOU / revalidation**: item deleted after scan (`not_found`) or replaced
   by symlink pointing outside `allowed_root` (`outside_root` / `symlink`) or to
   `~/.ssh` (`protected`) is caught during `generate_commands` and blocked.
6. **History**: JSONL entry has `event == "command_generated"` and never claims
   execution success.
