"""GTK-free analysis mode providers (Caches, Trash, Large Files, Logs, Docker, Packages)."""

from __future__ import annotations

import errno
import json
import os
import re
import sqlite3
import stat
import subprocess
import time
import unicodedata
from collections.abc import Callable, Sequence
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .contracts import Node
from .core import format_bytes
from .executor import ActiveProcessPath, discover_active_paths
from .provider_contract import (
    PROVIDER_ROW_LIMIT,
    SCANNER_SCHEMA_VERSION,
    ClassifiedError,
    ProtectedPath,
    Provider,
    ProviderContext,
    ProviderResult,
    RiskLevel,
    Row,
    risk_to_provider_level,
)
from .rules import RuleEngine, RuleEvaluation

REGENERABLE_CACHE_WARNING = (
    "Cache regenerável: o conteúdo será baixado de novo ou recriado quando necessário."
)
TRASH_INSPECT_WARNING = (
    "Item na lixeira (somente inspeção); nenhum comando é gerado pelo Clearspace."
)
USER_DATA_CACHE_WARNING = (
    "Dados de usuário ou modelos detectados; mantido somente para inspeção."
)
CREDENTIALS_CACHE_WARNING = (
    "Credenciais ou chaves detectadas; item bloqueado para proteção."
)

_UNSAFE_UNICODE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_MAX_TRASHINFO_BYTES = 8192

_USER_DATA_CACHE_NAMES = frozenset(
    {
        "huggingface",
        "mozilla",
        "firefox",
        "chromium",
        "google-chrome",
        "braveSoftware".casefold(),
        "vivaldi",
        "keyrings",
        "trash",
    }
)
_CREDENTIAL_CACHE_NAMES = frozenset(
    {
        ".ssh",
        ".gnupg",
        "credentials",
        "secrets",
    }
)


@dataclass(frozen=True, slots=True)
class CacheTargetSpec:
    """Declarative specification for a developer or runtime cache target."""

    id: str
    label: str
    resolve_paths: Callable[[ProviderContext, Path], tuple[tuple[Path, Path], ...]]
    tool_binary: str | None = None
    tool_argv: tuple[str, ...] | None = None


def measure_allocated_bytes(
    path: Path,
    *,
    seen_inodes: set[tuple[int, int]] | None = None,
) -> int:
    """Return read-only disk usage (st_blocks * 512) without following symlinks.

    Stays on ``path``'s ``st_dev`` and counts hardlinked regular files once per
    ``(st_dev, st_ino)``. Raises ``OSError`` if ``path`` itself cannot be
    inspected via ``lstat``.
    """
    inodes = set() if seen_inodes is None else seen_inodes
    root_stat = path.lstat()
    root_dev = root_stat.st_dev

    total = _stat_allocated_bytes(root_stat, inodes)
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        return total

    stack: list[Path] = [path]
    while stack:
        current_dir = stack.pop()
        try:
            with os.scandir(current_dir) as iterator:
                entries = list(iterator)
        except OSError:
            if current_dir == path:
                raise
            continue

        for entry in entries:
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if entry_stat.st_dev != root_dev:
                continue
            total += _stat_allocated_bytes(entry_stat, inodes)
            if stat.S_ISDIR(entry_stat.st_mode) and not stat.S_ISLNK(entry_stat.st_mode):
                stack.append(Path(entry.path))
    return total


def _stat_allocated_bytes(
    info: os.stat_result,
    seen_inodes: set[tuple[int, int]],
) -> int:
    if not stat.S_ISDIR(info.st_mode) and info.st_nlink > 1:
        inode_key = (info.st_dev, info.st_ino)
        if inode_key in seen_inodes:
            return 0
        seen_inodes.add(inode_key)
    blocks = getattr(info, "st_blocks", 0)
    return max(0, int(blocks)) * 512


def finalize_provider_rows(
    rows: Sequence[Row],
    *,
    error: ClassifiedError | None = None,
) -> ProviderResult:
    """Sort rows deterministically, cap at 200, and precompute smaller totals."""
    ordered = sorted(
        rows,
        key=lambda row: (
            0 if row.size_bytes is not None else 1,
            -(row.size_bytes if row.size_bytes is not None else -1),
            row.id,
        ),
    )
    visible = ordered[:PROVIDER_ROW_LIMIT]
    omitted = ordered[PROVIDER_ROW_LIMIT:]
    smaller_count = len(omitted)
    smaller_bytes = sum(row.size_bytes or 0 for row in omitted)
    return ProviderResult(
        rows=tuple(visible),
        smaller_count=smaller_count,
        smaller_bytes=smaller_bytes,
        error=error,
    )


def format_age_pt_br(mtime_ns: int | None, *, now_ns: int | None = None) -> str:
    """Format an item's timestamp age in localized pt-BR text."""
    if mtime_ns is None:
        return "idade desconhecida"
    reference_ns = time.time_ns() if now_ns is None else now_ns
    elapsed_seconds = max(0, int((reference_ns - mtime_ns) // 1_000_000_000))
    if elapsed_seconds < 60:
        return "agora mesmo"
    if elapsed_seconds < 3600:
        minutes = elapsed_seconds // 60
        return "há 1 min" if minutes == 1 else f"há {minutes} min"
    if elapsed_seconds < 86400:
        hours = elapsed_seconds // 3600
        return "há 1 h" if hours == 1 else f"há {hours} h"
    days = elapsed_seconds // 86400
    return "há 1 dia" if days == 1 else f"há {days} dias"


def classify_os_error(error: OSError, path: Path | None = None) -> ClassifiedError:
    """Classify filesystem OS errors without swallowing details."""
    err_no = error.errno
    if isinstance(error, PermissionError) or err_no in {errno.EACCES, errno.EPERM}:
        return ClassifiedError(
            kind="permission",
            message="Sem permissão para inspecionar este local.",
            path=path,
            errno=err_no,
        )
    if isinstance(error, FileNotFoundError) or err_no in {errno.ENOENT, errno.ENOTDIR}:
        return ClassifiedError(
            kind="not_found",
            message="O diretório esperado não foi encontrado.",
            path=path,
            errno=err_no,
        )
    return ClassifiedError(
        kind="unexpected",
        message="Falha ao ler metadados do sistema de arquivos.",
        path=path,
        errno=err_no,
    )


def _has_unsafe_text(value: str) -> bool:
    if "\x00" in value or "\n" in value or "\r" in value:
        return True
    return any(unicodedata.category(ch) in _UNSAFE_UNICODE_CATEGORIES for ch in value)


def _sanitize_label(value: str) -> str:
    cleaned = "".join(
        ch
        for ch in value
        if ch not in ("\x00", "\n", "\r")
        and unicodedata.category(ch) not in _UNSAFE_UNICODE_CATEGORIES
    )
    return cleaned or "<nome com caracteres de controle>"


def _safe_id_slug(value: str) -> str:
    cleaned = _sanitize_label(value).replace("/", "_")
    return cleaned or "unsafe_entry"


def _unique_row_id(base_id: str, used_ids: set[str]) -> str:
    candidate = base_id
    suffix = 2
    while candidate in used_ids:
        candidate = f"{base_id}#{suffix}"
        suffix += 1
    used_ids.add(candidate)
    return candidate


def _resolve_home_dir(context: ProviderContext) -> Path:
    if context.home_dir is not None:
        return context.home_dir
    if context.xdg_cache_home.name == ".cache":
        return context.xdg_cache_home.parent
    return Path.home()


def _env_abs_path(context: ProviderContext, key: str) -> Path | None:
    raw = context.environ.get(key, "").strip()
    if not raw or _has_unsafe_text(raw):
        return None
    candidate = Path(raw)
    if not candidate.is_absolute() or ".." in candidate.parts:
        return None
    return candidate


def _resolve_pip_paths(context: ProviderContext, _home: Path) -> tuple[tuple[Path, Path], ...]:
    custom = _env_abs_path(context, "PIP_CACHE_DIR")
    target = custom if custom is not None else context.xdg_cache_home / "pip"
    return ((target, target.parent),)


def _resolve_go_paths(context: ProviderContext, _home: Path) -> tuple[tuple[Path, Path], ...]:
    custom = _env_abs_path(context, "GOCACHE")
    if custom is not None:
        return ((custom, custom.parent),)
    if context.which("go") is not None:
        try:
            probe = context.run_readonly_command(("go", "env", "GOCACHE"), 5.0)
        except (OSError, subprocess.SubprocessError):
            probe = None
        if probe is not None and probe.returncode == 0:
            raw = probe.stdout.strip()
            if raw and not _has_unsafe_text(raw):
                probed = Path(raw)
                if probed.is_absolute() and ".." not in probed.parts:
                    return ((probed, probed.parent),)
    fallback = context.xdg_cache_home / "go-build"
    return ((fallback, fallback.parent),)


def _resolve_pnpm_paths(context: ProviderContext, _home: Path) -> tuple[tuple[Path, Path], ...]:
    cache_dir = context.xdg_cache_home / "pnpm"
    store_dir = context.xdg_data_home / "pnpm" / "store"
    return ((cache_dir, context.xdg_cache_home), (store_dir, store_dir.parent))


def _resolve_npm_paths(context: ProviderContext, home: Path) -> tuple[tuple[Path, Path], ...]:
    custom = _env_abs_path(context, "NPM_CONFIG_CACHE")
    if custom is not None:
        return ((custom, custom.parent),)
    dot_npm = home / ".npm"
    xdg_npm = context.xdg_cache_home / "npm"
    return ((dot_npm, home), (xdg_npm, context.xdg_cache_home))


def _resolve_gradle_paths(context: ProviderContext, home: Path) -> tuple[tuple[Path, Path], ...]:
    gradle_home = _env_abs_path(context, "GRADLE_USER_HOME") or (home / ".gradle")
    return ((gradle_home / "caches", gradle_home),)


def _resolve_cargo_paths(context: ProviderContext, home: Path) -> tuple[tuple[Path, Path], ...]:
    cargo_home = _env_abs_path(context, "CARGO_HOME") or (home / ".cargo")
    registry_dir = cargo_home / "registry"
    return ((registry_dir / "cache", registry_dir),)


CACHE_TARGETS: tuple[CacheTargetSpec, ...] = (
    CacheTargetSpec(
        id="cache.pip",
        label="Cache do pip",
        resolve_paths=_resolve_pip_paths,
        tool_binary="pip",
        tool_argv=("pip", "cache", "purge"),
    ),
    CacheTargetSpec(
        id="cache.go.build",
        label="Cache de build do Go",
        resolve_paths=_resolve_go_paths,
        tool_binary="go",
        tool_argv=("go", "clean", "-cache"),
    ),
    CacheTargetSpec(
        id="cache.pnpm",
        label="Cache e store do pnpm",
        resolve_paths=_resolve_pnpm_paths,
        tool_binary="pnpm",
        tool_argv=("pnpm", "store", "prune"),
    ),
    CacheTargetSpec(
        id="cache.npm",
        label="Cache do npm",
        resolve_paths=_resolve_npm_paths,
        tool_binary="npm",
        tool_argv=("npm", "cache", "clean", "--force"),
    ),
    CacheTargetSpec(
        id="cache.gradle",
        label="Cache do Gradle",
        resolve_paths=_resolve_gradle_paths,
    ),
    CacheTargetSpec(
        id="cache.cargo.registry",
        label="Cache de pacotes do Cargo",
        resolve_paths=_resolve_cargo_paths,
    ),
)


def _is_real_safe_subpath(candidate: Path, allowed_root: Path) -> tuple[Path, Path] | None:
    """Verify via lstat that allowed_root and candidate exist without symlinks."""
    if not candidate.is_absolute() or not allowed_root.is_absolute():
        return None
    if ".." in candidate.parts or ".." in allowed_root.parts:
        return None
    try:
        root_stat = allowed_root.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        return None
    try:
        canonical_root = allowed_root.resolve(strict=True)
    except OSError:
        return None
    if not candidate.is_relative_to(allowed_root) or candidate == allowed_root:
        return None
    current = allowed_root
    for part in candidate.relative_to(allowed_root).parts:
        current = current / part
        try:
            comp_stat = current.lstat()
        except OSError:
            return None
        if stat.S_ISLNK(comp_stat.st_mode) or comp_stat.st_dev != root_stat.st_dev:
            return None
    try:
        canonical_candidate = candidate.resolve(strict=True)
    except OSError:
        return None
    if not canonical_candidate.is_relative_to(canonical_root):
        return None
    return canonical_candidate, canonical_root


def _has_git_marker(directory: Path) -> bool:
    try:
        (directory / ".git").lstat()
        return True
    except OSError:
        return False


def _classify_cache_protection(
    canonical_path: Path,
    protected_paths: tuple[ProtectedPath, ...],
) -> tuple[RiskLevel, str] | None:
    name_lower = canonical_path.name.casefold()
    if name_lower in _CREDENTIAL_CACHE_NAMES:
        return ("critical", CREDENTIALS_CACHE_WARNING)
    if name_lower in _USER_DATA_CACHE_NAMES:
        return ("high", USER_DATA_CACHE_WARNING)
    if _has_git_marker(canonical_path):
        return ("high", "Repositório Git detectado; mantido somente para inspeção.")

    for rule in protected_paths:
        rule_path = rule.path.resolve(strict=False)
        hit = False
        if rule.include_descendants and canonical_path.is_relative_to(rule_path):
            hit = True
        elif not rule.include_descendants and canonical_path == rule_path:
            hit = True
        elif rule_path != canonical_path and rule_path.is_relative_to(canonical_path):
            hit = True
        if hit:
            lowered_rule = rule.rule.casefold()
            if "credential" in lowered_rule or "ssh" in lowered_rule or "gpg" in lowered_rule:
                return ("critical", CREDENTIALS_CACHE_WARNING)
            return ("high", USER_DATA_CACHE_WARNING)
    return None


class CachesProvider:
    """Discover XDG and developer caches without blanket-blocking ~/.cache."""

    id = "caches"
    label = "Caches"

    def load(self, context: ProviderContext) -> ProviderResult:
        home = _resolve_home_dir(context)
        claimed_canonical: set[Path] = set()
        rows: list[Row] = []

        for spec in CACHE_TARGETS:
            existing_pairs: list[tuple[Path, Path]] = []
            for candidate, allowed_root in spec.resolve_paths(context, home):
                verified = _is_real_safe_subpath(candidate, allowed_root)
                if verified is not None:
                    existing_pairs.append(verified)

            if not existing_pairs:
                continue

            seen_inodes: set[tuple[int, int]] = set()
            total_bytes = 0
            readable = False
            for canonical_target, _ in existing_pairs:
                claimed_canonical.add(canonical_target)
                try:
                    total_bytes += measure_allocated_bytes(
                        canonical_target, seen_inodes=seen_inodes
                    )
                    readable = True
                except OSError:
                    continue
            if not readable:
                continue

            primary_path, primary_root = existing_pairs[0]
            protection = _classify_cache_protection(primary_path, context.protected_paths)
            if protection is not None:
                risk, note = protection
                rows.append(
                    Row(
                        id=spec.id,
                        label=spec.label,
                        size_bytes=total_bytes,
                        risk=risk,
                        action="inspect_only",
                        warnings=(note,),
                    )
                )
                continue

            has_tool = (
                spec.tool_binary is not None
                and spec.tool_argv is not None
                and context.which(spec.tool_binary) is not None
            )
            if has_tool and spec.tool_argv is not None:
                rows.append(
                    Row(
                        id=spec.id,
                        label=spec.label,
                        size_bytes=total_bytes,
                        risk="low",
                        action="tool_command",
                        argv=spec.tool_argv,
                        warnings=(REGENERABLE_CACHE_WARNING,),
                    )
                )
            elif len(existing_pairs) == 1:
                rows.append(
                    Row(
                        id=spec.id,
                        label=spec.label,
                        size_bytes=total_bytes,
                        risk="low",
                        action="trash_path",
                        path=primary_path,
                        allowed_root=primary_root,
                        warnings=(REGENERABLE_CACHE_WARNING,),
                    )
                )
            else:
                for idx, (target_path, target_root) in enumerate(existing_pairs, start=1):
                    try:
                        part_bytes = measure_allocated_bytes(target_path)
                    except OSError:
                        continue
                    suffix = "" if idx == 1 else f".{idx}"
                    rows.append(
                        Row(
                            id=f"{spec.id}{suffix}",
                            label=f"{spec.label} ({target_path.name})",
                            size_bytes=part_bytes,
                            risk="low",
                            action="trash_path",
                            path=target_path,
                            allowed_root=target_root,
                            warnings=(REGENERABLE_CACHE_WARNING,),
                        )
                    )

        xdg_error = self._collect_xdg_cache_children(context, claimed_canonical, rows)
        if xdg_error is not None and not rows:
            return ProviderResult(rows=(), smaller_count=0, smaller_bytes=0, error=xdg_error)
        return finalize_provider_rows(rows, error=xdg_error)

    def _collect_xdg_cache_children(
        self,
        context: ProviderContext,
        claimed_canonical: set[Path],
        rows: list[Row],
    ) -> ClassifiedError | None:
        cache_root = context.xdg_cache_home
        try:
            root_stat = cache_root.lstat()
        except FileNotFoundError:
            return None
        except OSError as error:
            return classify_os_error(error, cache_root)

        if stat.S_ISLNK(root_stat.st_mode):
            return ClassifiedError(
                kind="symlink",
                message="O diretório de cache XDG é um symlink e não é seguido.",
                path=cache_root,
            )
        if not stat.S_ISDIR(root_stat.st_mode):
            return ClassifiedError(
                kind="invalid_row",
                message="O caminho de cache XDG não é um diretório.",
                path=cache_root,
            )

        try:
            canonical_cache_root = cache_root.resolve(strict=True)
            with os.scandir(canonical_cache_root) as iterator:
                entries = list(iterator)
        except OSError as error:
            return classify_os_error(error, cache_root)

        used_ids = {row.id for row in rows}
        for entry in entries:
            raw_name = entry.name
            entry_path = canonical_cache_root / raw_name
            try:
                entry_stat = entry_path.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(entry_stat.st_mode) or entry_stat.st_dev != root_stat.st_dev:
                continue
            if not stat.S_ISDIR(entry_stat.st_mode) and not stat.S_ISREG(entry_stat.st_mode):
                continue
            if entry_path in claimed_canonical or any(
                claimed.is_relative_to(entry_path) for claimed in claimed_canonical
            ):
                continue

            row_id = _unique_row_id(f"cache.xdg.{_safe_id_slug(raw_name)}", used_ids)
            if _has_unsafe_text(raw_name) or _has_unsafe_text(str(entry_path)):
                rows.append(
                    Row(
                        id=row_id,
                        label=f"Cache: {_sanitize_label(raw_name)}",
                        size_bytes=0,
                        risk="low",
                        action="inspect_only",
                        error=ClassifiedError(
                            kind="unsafe_name",
                            message="Nome do cache contém caracteres de controle.",
                            path=entry_path,
                        ),
                    )
                )
                continue

            try:
                size_bytes = measure_allocated_bytes(entry_path)
            except OSError as error:
                rows.append(
                    Row(
                        id=row_id,
                        label=f"Cache: {raw_name}",
                        size_bytes=0,
                        risk="low",
                        action="inspect_only",
                        error=classify_os_error(error, entry_path),
                    )
                )
                continue

            protection = _classify_cache_protection(entry_path, context.protected_paths)
            if protection is not None:
                risk, note = protection
                rows.append(
                    Row(
                        id=row_id,
                        label=f"Cache: {raw_name}",
                        size_bytes=size_bytes,
                        risk=risk,
                        action="inspect_only",
                        warnings=(note,),
                    )
                )
                continue

            rows.append(
                Row(
                    id=row_id,
                    label=f"Cache: {raw_name}",
                    size_bytes=size_bytes,
                    risk="low",
                    action="trash_path",
                    path=entry_path,
                    allowed_root=canonical_cache_root,
                    warnings=(REGENERABLE_CACHE_WARNING,),
                )
            )
        return None


class TrashProvider:
    """Read-only inventory of XDG Trash items by allocated size and deletion age."""

    id = "trash"
    label = "Lixeira"

    def load(self, context: ProviderContext) -> ProviderResult:
        trash_root = context.xdg_data_home / "Trash"
        files_dir = trash_root / "files"
        info_dir = trash_root / "info"

        for directory in (trash_root, files_dir):
            try:
                dir_stat = directory.lstat()
            except FileNotFoundError:
                return ProviderResult(rows=(), smaller_count=0, smaller_bytes=0)
            except OSError as error:
                return ProviderResult(
                    rows=(),
                    smaller_count=0,
                    smaller_bytes=0,
                    error=classify_os_error(error, directory),
                )

            if stat.S_ISLNK(dir_stat.st_mode):
                return ProviderResult(
                    rows=(),
                    smaller_count=0,
                    smaller_bytes=0,
                    error=ClassifiedError(
                        kind="symlink",
                        message="O diretório da lixeira é um symlink e não é seguido.",
                        path=directory,
                    ),
                )
            if not stat.S_ISDIR(dir_stat.st_mode):
                return ProviderResult(
                    rows=(),
                    smaller_count=0,
                    smaller_bytes=0,
                    error=ClassifiedError(
                        kind="invalid_row",
                        message="O caminho da lixeira não é um diretório válido.",
                        path=directory,
                    ),
                )

        try:
            with os.scandir(files_dir) as iterator:
                entries = list(iterator)
        except OSError as error:
            return ProviderResult(
                rows=(),
                smaller_count=0,
                smaller_bytes=0,
                error=classify_os_error(error, files_dir),
            )

        rows: list[Row] = []
        seen_inodes: set[tuple[int, int]] = set()
        used_ids: set[str] = set()
        now_ns = time.time_ns()

        for entry in entries:
            raw_name = entry.name
            entry_path = files_dir / raw_name
            row_id = _unique_row_id(f"trash.item.{_safe_id_slug(raw_name)}", used_ids)

            try:
                entry_stat = entry_path.lstat()
                size_bytes = measure_allocated_bytes(entry_path, seen_inodes=seen_inodes)
            except OSError as error:
                rows.append(
                    Row(
                        id=row_id,
                        label=_sanitize_label(raw_name),
                        size_bytes=0,
                        risk="high",
                        action="inspect_only",
                        error=classify_os_error(error, entry_path),
                    )
                )
                continue

            deletion_ns = _read_trashinfo_deletion_ns(info_dir, raw_name)
            resolved_ns = deletion_ns if deletion_ns is not None else entry_stat.st_mtime_ns
            age_text = format_age_pt_br(resolved_ns, now_ns=now_ns)

            row_error: ClassifiedError | None = None
            if _has_unsafe_text(raw_name):
                row_error = ClassifiedError(
                    kind="unsafe_name",
                    message="Nome na lixeira contém caracteres de controle.",
                    path=entry_path,
                )

            rows.append(
                Row(
                    id=row_id,
                    label=_sanitize_label(raw_name),
                    size_bytes=size_bytes,
                    risk="high",
                    action="inspect_only",
                    mtime_ns=resolved_ns,
                    warnings=(f"Movido para a lixeira {age_text}.", TRASH_INSPECT_WARNING),
                    error=row_error,
                )
            )

        return finalize_provider_rows(rows)


def _read_trashinfo_deletion_ns(info_dir: Path, item_name: str) -> int | None:
    if "/" in item_name or "\x00" in item_name:
        return None
    info_path = info_dir / f"{item_name}.trashinfo"
    try:
        info_stat = info_path.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(info_stat.st_mode) or not stat.S_ISREG(info_stat.st_mode):
        return None
    if info_stat.st_size > _MAX_TRASHINFO_BYTES:
        return None

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(info_path, flags)
        try:
            raw_bytes = os.read(fd, _MAX_TRASHINFO_BYTES)
        finally:
            os.close(fd)
    except OSError:
        return None

    text = raw_bytes.decode("utf-8", errors="replace")
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if not sep or key.strip() != "DeletionDate":
            continue
        cleaned = value.strip()
        try:
            parsed = datetime.fromisoformat(cleaned)
        except ValueError:
            return None
        return int(parsed.timestamp() * 1_000_000_000)
    return None


def collect_review_advisories(
    rows: Sequence[Row],
    *,
    home_dir: Path | None = None,
    active_paths: Sequence[ActiveProcessPath] | None = None,
) -> tuple[str, ...]:
    """Build non-blocking informational notes for the review screen.

    Checks active processes via ``/proc`` (matching only when a process ``cwd``
    or open descriptor lies *inside* or equals the selected path, never an
    ancestor), differing owner UID, unwriteable parent directory, and cross-device
    trash support.
    """
    resolved_home = (home_dir if home_dir is not None else Path.home()).resolve(strict=False)
    try:
        home_dev: int | None = resolved_home.stat().st_dev
    except OSError:
        home_dev = None

    if active_paths is None:
        discovered: list[ActiveProcessPath] = []
        seen_roots: set[Path] = set()
        for row in rows:
            if row.action == "trash_path" and row.allowed_root is not None:
                try:
                    canon_root = row.allowed_root.resolve(strict=True)
                except OSError:
                    continue
                if canon_root in seen_roots:
                    continue
                seen_roots.add(canon_root)
                try:
                    discovered.extend(discover_active_paths(canon_root))
                except RuntimeError:
                    continue
        resolved_active: Sequence[ActiveProcessPath] = discovered
    else:
        resolved_active = active_paths

    notes: dict[str, None] = {}
    euid = os.geteuid()
    for row in rows:
        if row.action != "trash_path" or row.path is None:
            continue
        label = _sanitize_label(row.label)
        try:
            info = row.path.lstat()
            canonical = row.path.resolve(strict=True)
        except OSError:
            continue

        for entry in resolved_active:
            try:
                proc_target = entry.path.resolve(strict=False)
            except OSError:
                continue
            if proc_target.is_relative_to(canonical):
                notes.setdefault(
                    f"{label}: aplicação em uso ({entry.application} em {proc_target}).",
                    None,
                )

        if info.st_uid != euid:
            notes.setdefault(f"{label}: pertence a outro usuário (UID {info.st_uid}).", None)

        parent = canonical.parent
        if not os.access(parent, os.W_OK):
            notes.setdefault(f"{label}: diretório pai sem permissão de escrita.", None)

        if home_dev is not None and info.st_dev != home_dev:
            notes.setdefault(
                f"{label}: está em partição diferente do home (lixeira pode não estar disponível).",
                None,
            )
    return tuple(notes)


RISK_LABELS_PT_BR: dict[RiskLevel, str] = {
    "low": "Baixo",
    "medium": "Médio",
    "high": "Alto",
    "critical": "Crítico",
}


def is_row_selectable(row: Row) -> bool:
    """Return True only when a row is eligible for user selection in the UI."""
    return (
        row.action in {"trash_path", "tool_command"}
        and row.risk != "critical"
        and row.error is None
    )


_INSPECT_ONLY_CATEGORIES = frozenset(
    {
        "trash",
        "browser_profile",
        "container_volume",
        "model_or_dataset",
        "git_repository",
        "game_data",
    }
)


@dataclass(frozen=True, slots=True)
class TreeNodeEligibility:
    """Selection eligibility and pt-BR reason for a Pastas directory-tree node."""

    selectable: bool
    reason: str | None = None


def evaluate_tree_node_eligibility(
    node: Node,
    *,
    scan_root: Path,
    home_dir: Path | None = None,
    protected_paths: Sequence[ProtectedPath] = (),
    inspection_roots: Sequence[Path] = (),
    evaluation: RuleEvaluation | None = None,
) -> TreeNodeEligibility:
    """Determine whether a Pastas tree node may be marked for command generation."""
    if node.aggregate_count > 0 or node.is_more_row:
        return TreeNodeEligibility(False, "Linha informativa agrupada.")
    if node.error:
        return TreeNodeEligibility(False, node.error)
    if _has_unsafe_text(node.name) or _has_unsafe_text(str(node.path)):
        return TreeNodeEligibility(
            False, "Nome contém caracteres de controle inseguros."
        )

    resolved_home = (home_dir if home_dir is not None else Path.home()).resolve(
        strict=False
    )
    canon_scan = scan_root.resolve(strict=False)
    canonical = node.path.resolve(strict=False)

    if canonical == canon_scan:
        return TreeNodeEligibility(
            False,
            "Raiz da varredura: expanda a pasta para selecionar itens internos.",
        )
    if canonical == resolved_home or canonical == Path("/"):
        return TreeNodeEligibility(False, "Diretório protegido pelo Clearspace.")

    for rule in protected_paths:
        target = rule.path.resolve(strict=False)
        if canonical == target:
            return TreeNodeEligibility(
                False, "Caminho protegido ou somente para inspeção."
            )
        if rule.include_descendants and canonical.is_relative_to(target):
            return TreeNodeEligibility(
                False, "Caminho protegido ou somente para inspeção."
            )

    for root in inspection_roots:
        target = root.resolve(strict=False)
        if canonical == target or canonical.is_relative_to(target):
            return TreeNodeEligibility(False, "Dados do usuário: somente inspeção.")

    if node.is_dir:
        for rule in protected_paths:
            if not rule.include_descendants:
                continue
            target = rule.path.resolve(strict=False)
            if target != canonical and target.is_relative_to(canonical):
                return TreeNodeEligibility(
                    False,
                    "Contém subpastas protegidas ou de inspeção; expanda a pasta para selecionar itens individuais.",
                )
        for root in inspection_roots:
            target = root.resolve(strict=False)
            if target != canonical and target.is_relative_to(canonical):
                return TreeNodeEligibility(
                    False,
                    "Contém subpastas protegidas ou de inspeção; expanda a pasta para selecionar itens individuais.",
                )

    if (
        node.name == "node_modules"
        or _path_has_repo_or_node_modules(canonical, canon_scan) is not None
    ):
        return TreeNodeEligibility(
            False, "Repositório ou node_modules: somente inspeção."
        )

    if not node.is_dir and _is_database_file(canonical):
        return TreeNodeEligibility(False, "Banco de dados local: somente inspeção.")

    if evaluation is not None:
        if evaluation.risk.value == "critical" or evaluation.category == "credentials":
            return TreeNodeEligibility(
                False, "Risco crítico (credenciais ou sistema): seleção bloqueada."
            )
        if (
            evaluation.category in _INSPECT_ONLY_CATEGORIES
            or evaluation.risk.value == "user_data"
        ):
            return TreeNodeEligibility(False, "Dados do usuário: somente inspeção.")

    return TreeNodeEligibility(True, None)


def build_folder_selection_rows(
    selected_paths: Sequence[Path],
    *,
    scan_root: Path,
    sizes_by_path: dict[Path, int] | None = None,
    evaluations_by_path: dict[Path, RuleEvaluation] | None = None,
    protected_paths: Sequence[ProtectedPath] = (),
    inspection_roots: Sequence[Path] = (),
) -> tuple[Row, ...]:
    """Convert selected Pastas paths into provider contract Rows for command generation."""
    canon_scan = scan_root.resolve(strict=False)
    sizes = sizes_by_path or {}
    evaluations = evaluations_by_path or {}
    fallback_engine = RuleEngine(
        command_runner=lambda *_a, **_kw: subprocess.CompletedProcess(
            [], 0, stdout="", stderr=""
        )
    )
    used_ids: set[str] = set()
    rows: list[Row] = []

    for path in selected_paths:
        try:
            rel_display = str(path.relative_to(canon_scan))
        except ValueError:
            try:
                rel_display = str(path.resolve(strict=False).relative_to(canon_scan))
            except ValueError:
                rel_display = path.name or str(path)

        safe_label = _sanitize_label(rel_display)
        row_id = _unique_row_id(f"folders.{_safe_id_slug(rel_display)}", used_ids)
        size_bytes = sizes.get(path)

        if _has_unsafe_text(rel_display) or _has_unsafe_text(str(path)):
            rows.append(
                Row(
                    id=row_id,
                    label=safe_label,
                    size_bytes=size_bytes,
                    risk="medium",
                    action="inspect_only",
                    error=ClassifiedError(
                        kind="unsafe_name",
                        message="Caminho contém caracteres de controle inseguros.",
                        path=path,
                    ),
                )
            )
            continue

        try:
            info = path.lstat()
            is_dir = stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
        except OSError:
            is_dir = False

        ev = evaluations.get(path)
        if ev is None:
            ev = fallback_engine.evaluate(
                Node(path=path, name=path.name, is_dir=is_dir, size_bytes=size_bytes or 0)
            )

        canonical = path.resolve(strict=False)
        is_inspect_root = any(
            canonical == r.resolve(strict=False)
            or canonical.is_relative_to(r.resolve(strict=False))
            for r in inspection_roots
        )
        is_user_data = (
            is_inspect_root
            or path.name == "node_modules"
            or _path_has_repo_or_node_modules(canonical, canon_scan) is not None
            or (not is_dir and _is_database_file(canonical))
            or ev.category in _INSPECT_ONLY_CATEGORIES
            or ev.risk.value == "user_data"
        )

        if ev.risk.value == "critical" or ev.category == "credentials":
            rows.append(
                Row(
                    id=row_id,
                    label=safe_label,
                    size_bytes=size_bytes,
                    risk="critical",
                    action="inspect_only",
                    warnings=ev.warnings,
                )
            )
            continue

        if is_user_data:
            rows.append(
                Row(
                    id=row_id,
                    label=safe_label,
                    size_bytes=size_bytes,
                    risk="high",
                    action="inspect_only",
                    warnings=ev.warnings
                    or ("Dados do usuário ou projeto: somente inspeção.",),
                )
            )
            continue

        rows.append(
            Row(
                id=row_id,
                label=safe_label,
                size_bytes=size_bytes,
                risk=risk_to_provider_level(ev.risk),
                action="trash_path",
                path=path,
                allowed_root=canon_scan,
                warnings=ev.warnings,
            )
        )

    return tuple(rows)


def format_smaller_summary_pt_br(smaller_count: int, smaller_bytes: int) -> str:
    """Format the omitted-items summary line in pt-BR."""
    if smaller_count <= 0:
        return ""
    noun = "item menor omitido" if smaller_count == 1 else "itens menores omitidos"
    return f"+ {smaller_count} {noun} ({format_bytes(smaller_bytes)})"


_DATABASE_SUFFIXES = frozenset(
    {
        ".sqlite",
        ".sqlite3",
        ".db",
        ".db3",
        ".mdb",
        ".duckdb",
        ".jsonl",
    }
)
_LOG_SUFFIXES = frozenset({".log", ".out", ".err", ".old"})
_JOURNAL_SIZE_RE = re.compile(
    r"(\d+(?:[.,]\d+)?)\s*([KMGTPE]?)(?:i?B)?\b",
    re.IGNORECASE,
)
_UNIT_MULTIPLIERS: dict[str, int] = {
    "": 1,
    "B": 1,
    "K": 1024,
    "M": 1024**2,
    "G": 1024**3,
    "T": 1024**4,
    "P": 1024**5,
    "E": 1024**6,
}

LARGE_FILES_TOP_SQL = (
    "SELECT id, parent_id, name, size_blocks, mtime "
    "FROM nodes "
    "WHERE is_dir = 0 AND error IS NULL AND size_blocks >= ? "
    "ORDER BY size_blocks DESC, name COLLATE BINARY ASC, id ASC "
    f"LIMIT {PROVIDER_ROW_LIMIT};"
)

LARGE_FILES_SMALLER_SQL = (
    "SELECT COUNT(*) AS smaller_count, COALESCE(SUM(size_blocks), 0) AS smaller_blocks "
    "FROM ("
    "    SELECT size_blocks "
    "    FROM nodes "
    "    WHERE is_dir = 0 AND error IS NULL AND size_blocks >= ? "
    "    ORDER BY size_blocks DESC, name COLLATE BINARY ASC, id ASC "
    f"    LIMIT -1 OFFSET {PROVIDER_ROW_LIMIT}"
    ");"
)

LARGE_FILES_SUBTREE_TOP_SQL = (
    "WITH RECURSIVE subtree(id) AS ("
    "    SELECT ? "
    "    UNION ALL "
    "    SELECT n.id FROM nodes n JOIN subtree s ON n.parent_id = s.id WHERE n.is_dir = 1"
    ") "
    "SELECT n.id, n.parent_id, n.name, n.size_blocks, n.mtime "
    "FROM nodes n "
    "WHERE n.is_dir = 0 AND n.error IS NULL AND n.size_blocks >= ? "
    "  AND n.parent_id IN (SELECT id FROM subtree) "
    "ORDER BY n.size_blocks DESC, n.name COLLATE BINARY ASC, n.id ASC "
    f"LIMIT {PROVIDER_ROW_LIMIT};"
)

LARGE_FILES_SUBTREE_SMALLER_SQL = (
    "WITH RECURSIVE subtree(id) AS ("
    "    SELECT ? "
    "    UNION ALL "
    "    SELECT n.id FROM nodes n JOIN subtree s ON n.parent_id = s.id WHERE n.is_dir = 1"
    ") "
    "SELECT COUNT(*) AS smaller_count, COALESCE(SUM(size_blocks), 0) AS smaller_blocks "
    "FROM ("
    "    SELECT n.size_blocks "
    "    FROM nodes n "
    "    WHERE n.is_dir = 0 AND n.error IS NULL AND n.size_blocks >= ? "
    "      AND n.parent_id IN (SELECT id FROM subtree) "
    "    ORDER BY n.size_blocks DESC, n.name COLLATE BINARY ASC, n.id ASC "
    f"    LIMIT -1 OFFSET {PROVIDER_ROW_LIMIT}"
    ");"
)


def parse_journal_usage_bytes(output: str) -> int | None:
    """Extract journal disk usage in bytes from ``journalctl --disk-usage``."""
    if not output:
        return None
    lower = output.casefold()
    idx = lower.find("take up")
    target = output[idx + len("take up") :] if idx >= 0 else output
    match = _JOURNAL_SIZE_RE.search(target)
    if match is None:
        return None
    raw_num = match.group(1).replace(",", ".")
    unit = (match.group(2) or "B").upper()
    try:
        numeric = float(raw_num)
    except ValueError:
        return None
    multiplier = _UNIT_MULTIPLIERS.get(unit)
    if multiplier is None or numeric < 0:
        return None
    return int(numeric * multiplier)


def _path_has_repo_or_node_modules(candidate: Path, allowed_root: Path) -> str | None:
    if _has_git_marker(allowed_root):
        return "Arquivo dentro de repositório Git (somente inspeção)."
    if not candidate.is_relative_to(allowed_root):
        return None
    current = allowed_root
    parts = candidate.relative_to(allowed_root).parts[:-1]
    for part in parts:
        current = current / part
        if part == "node_modules":
            return "Arquivo em node_modules (somente inspeção)."
        if _has_git_marker(current):
            return "Arquivo dentro de repositório Git (somente inspeção)."
    return None


def _is_database_file(path: Path) -> bool:
    name_lower = path.name.casefold()
    if any(name_lower.endswith(ext) for ext in _DATABASE_SUFFIXES):
        return True
    return False


def _build_large_file_row(
    *,
    row_id: str,
    file_path: Path,
    allowed_root: Path,
    size_bytes: int,
    mtime_ns: int | None,
    protected_paths: tuple[ProtectedPath, ...],
    rule_engine: RuleEngine,
) -> Row:
    try:
        rel_display = str(file_path.relative_to(allowed_root))
    except ValueError:
        rel_display = file_path.name

    safe_label = _sanitize_label(rel_display)
    if _has_unsafe_text(rel_display) or _has_unsafe_text(str(file_path)):
        return Row(
            id=row_id,
            label=safe_label,
            size_bytes=size_bytes,
            risk="medium",
            action="inspect_only",
            mtime_ns=mtime_ns,
            error=ClassifiedError(
                kind="unsafe_name",
                message="Caminho do arquivo contém caracteres de controle.",
                path=file_path,
            ),
        )

    protection = _classify_cache_protection(file_path, protected_paths)
    if protection is not None:
        risk, note = protection
        return Row(
            id=row_id,
            label=safe_label,
            size_bytes=size_bytes,
            risk=risk,
            action="inspect_only",
            mtime_ns=mtime_ns,
            warnings=(note,),
        )

    repo_note = _path_has_repo_or_node_modules(file_path, allowed_root)
    if repo_note is not None:
        return Row(
            id=row_id,
            label=safe_label,
            size_bytes=size_bytes,
            risk="high",
            action="inspect_only",
            mtime_ns=mtime_ns,
            warnings=(repo_note,),
        )

    if _is_database_file(file_path):
        return Row(
            id=row_id,
            label=safe_label,
            size_bytes=size_bytes,
            risk="high",
            action="inspect_only",
            mtime_ns=mtime_ns,
            warnings=("Banco de dados ou histórico local (somente inspeção).",),
        )

    node = Node(path=file_path, name=file_path.name, is_dir=False, size_bytes=size_bytes)
    category = rule_engine.classify(node)
    if category == "credentials":
        return Row(
            id=row_id,
            label=safe_label,
            size_bytes=size_bytes,
            risk="critical",
            action="inspect_only",
            mtime_ns=mtime_ns,
            warnings=(CREDENTIALS_CACHE_WARNING,),
        )
    if category in {
        "trash",
        "browser_profile",
        "container_volume",
        "model_or_dataset",
        "git_repository",
        "game_data",
    }:
        return Row(
            id=row_id,
            label=safe_label,
            size_bytes=size_bytes,
            risk="high",
            action="inspect_only",
            mtime_ns=mtime_ns,
            warnings=(USER_DATA_CACHE_WARNING,),
        )

    evaluation = rule_engine.evaluate(node, category=category)
    return Row(
        id=row_id,
        label=safe_label,
        size_bytes=size_bytes,
        risk=risk_to_provider_level(evaluation.risk),
        action="trash_path",
        path=file_path,
        allowed_root=allowed_root,
        mtime_ns=mtime_ns,
        warnings=evaluation.warnings,
    )


class LargeFilesProvider:
    """Query top regular files from the versioned scanner SQLite DB or XDG Downloads."""

    id = "large_files"
    label = "Arquivos grandes"

    def load(self, context: ProviderContext) -> ProviderResult:
        min_bytes = max(0, int(context.large_files_min_bytes))
        min_blocks = (min_bytes + 511) // 512
        rule_engine = RuleEngine()

        if context.scan_db_path is None:
            if context.large_files_downloads_only and context.downloads_dir is not None:
                return self._scan_direct_directory(
                    context.downloads_dir, min_blocks, context.protected_paths, rule_engine
                )
            return ProviderResult(
                rows=(),
                smaller_count=0,
                smaller_bytes=0,
                error=ClassifiedError(
                    kind="not_found",
                    message=(
                        "Nenhuma varredura concluída na aba Pastas. "
                        "Execute uma varredura ou ative o atalho 'Apenas Downloads'."
                    ),
                ),
            )

        db_path = context.scan_db_path
        if not db_path.is_file():
            return ProviderResult(
                rows=(),
                smaller_count=0,
                smaller_bytes=0,
                error=ClassifiedError(
                    kind="not_found",
                    message="O banco SQLite da varredura não está mais disponível; reescaneie.",
                    path=db_path,
                ),
            )

        if context.scan_root is None:
            return ProviderResult(
                rows=(),
                smaller_count=0,
                smaller_bytes=0,
                error=ClassifiedError(
                    kind="invalid_row",
                    message="Raiz da varredura ausente no contexto.",
                ),
            )

        try:
            canonical_root = context.scan_root.resolve(strict=True)
        except OSError as error:
            return ProviderResult(
                rows=(),
                smaller_count=0,
                smaller_bytes=0,
                error=classify_os_error(error, context.scan_root),
            )

        if context.large_files_downloads_only:
            if context.downloads_dir is None:
                return ProviderResult(rows=(), smaller_count=0, smaller_bytes=0)
            try:
                canonical_dl = context.downloads_dir.resolve(strict=True)
            except FileNotFoundError:
                return ProviderResult(rows=(), smaller_count=0, smaller_bytes=0)
            except OSError as error:
                return ProviderResult(
                    rows=(),
                    smaller_count=0,
                    smaller_bytes=0,
                    error=classify_os_error(error, context.downloads_dir),
                )
            if not canonical_dl.is_relative_to(canonical_root):
                return self._scan_direct_directory(
                    canonical_dl, min_blocks, context.protected_paths, rule_engine
                )
        else:
            canonical_dl = None

        try:
            with closing(
                sqlite3.connect(f"{db_path.as_uri()}?mode=ro", uri=True)
            ) as conn:
                ver_row = conn.execute("PRAGMA user_version").fetchone()
                user_version = ver_row[0] if ver_row is not None else None
                if user_version != SCANNER_SCHEMA_VERSION:
                    return ProviderResult(
                        rows=(),
                        smaller_count=0,
                        smaller_bytes=0,
                        error=ClassifiedError(
                            kind="invalid_row",
                            message=(
                                f"Versão do banco SQLite incompatível "
                                f"(encontrada: {user_version}, esperada: {SCANNER_SCHEMA_VERSION}). "
                                "Reescaneie na aba Pastas ou recompile o scanner."
                            ),
                            path=db_path,
                        ),
                    )

                if canonical_dl is not None:
                    subtree_id = _find_node_id_for_path(conn, canonical_root, canonical_dl)
                    if subtree_id is None:
                        return ProviderResult(rows=(), smaller_count=0, smaller_bytes=0)
                    db_rows = conn.execute(
                        LARGE_FILES_SUBTREE_TOP_SQL, (subtree_id, min_blocks)
                    ).fetchall()
                    smaller_count, smaller_blocks = conn.execute(
                        LARGE_FILES_SUBTREE_SMALLER_SQL, (subtree_id, min_blocks)
                    ).fetchone()
                else:
                    db_rows = conn.execute(
                        LARGE_FILES_TOP_SQL, (min_blocks,)
                    ).fetchall()
                    smaller_count, smaller_blocks = conn.execute(
                        LARGE_FILES_SMALLER_SQL, (min_blocks,)
                    ).fetchone()

                parent_cache: dict[int, tuple[int | None, str]] = {}
                built_rows: list[Row] = []
                for node_id, parent_id, name, size_blocks, mtime in db_rows:
                    full_path = _reconstruct_node_path(
                        conn,
                        canonical_root,
                        parent_id,
                        name,
                        parent_cache,
                    )
                    built_rows.append(
                        _build_large_file_row(
                            row_id=f"large_file.db.{node_id}",
                            file_path=full_path,
                            allowed_root=canonical_root,
                            size_bytes=max(0, int(size_blocks)) * 512,
                            mtime_ns=int(mtime) if mtime is not None else None,
                            protected_paths=context.protected_paths,
                            rule_engine=rule_engine,
                        )
                    )
        except sqlite3.Error as error:
            return ProviderResult(
                rows=(),
                smaller_count=0,
                smaller_bytes=0,
                error=ClassifiedError(
                    kind="unexpected",
                    message=f"Falha ao consultar banco SQLite: {error}",
                    path=db_path,
                ),
            )

        return ProviderResult(
            rows=tuple(built_rows),
            smaller_count=max(0, int(smaller_count)),
            smaller_bytes=max(0, int(smaller_blocks)) * 512,
        )

    def _scan_direct_directory(
        self,
        directory: Path,
        min_blocks: int,
        protected_paths: tuple[ProtectedPath, ...],
        rule_engine: RuleEngine,
    ) -> ProviderResult:
        try:
            root_stat = directory.lstat()
        except FileNotFoundError:
            return ProviderResult(rows=(), smaller_count=0, smaller_bytes=0)
        except OSError as error:
            return ProviderResult(
                rows=(),
                smaller_count=0,
                smaller_bytes=0,
                error=classify_os_error(error, directory),
            )
        if stat.S_ISLNK(root_stat.st_mode):
            return ProviderResult(
                rows=(),
                smaller_count=0,
                smaller_bytes=0,
                error=ClassifiedError(
                    kind="symlink",
                    message="O diretório Downloads aponta para um symlink.",
                    path=directory,
                ),
            )
        if not stat.S_ISDIR(root_stat.st_mode):
            return ProviderResult(rows=(), smaller_count=0, smaller_bytes=0)

        try:
            canonical_dir = directory.resolve(strict=True)
        except OSError as error:
            return ProviderResult(
                rows=(),
                smaller_count=0,
                smaller_bytes=0,
                error=classify_os_error(error, directory),
            )

        rows: list[Row] = []
        used_ids: set[str] = set()
        seen_inodes: set[tuple[int, int]] = set()
        stack: list[Path] = [canonical_dir]

        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    entries = list(iterator)
            except OSError:
                continue
            for entry in entries:
                entry_path = current / entry.name
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISLNK(info.st_mode) or info.st_dev != root_stat.st_dev:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    stack.append(entry_path)
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                alloc_bytes = _stat_allocated_bytes(info, seen_inodes)
                if (alloc_bytes // 512) < min_blocks:
                    continue
                rel_slug = _safe_id_slug(str(entry_path.relative_to(canonical_dir)))
                row_id = _unique_row_id(f"large_file.dl.{rel_slug}", used_ids)
                rows.append(
                    _build_large_file_row(
                        row_id=row_id,
                        file_path=entry_path,
                        allowed_root=canonical_dir,
                        size_bytes=alloc_bytes,
                        mtime_ns=info.st_mtime_ns,
                        protected_paths=protected_paths,
                        rule_engine=rule_engine,
                    )
                )
        return finalize_provider_rows(rows)


def _find_node_id_for_path(
    conn: sqlite3.Connection,
    canonical_root: Path,
    target_dir: Path,
) -> int | None:
    root_row = conn.execute(
        "SELECT id FROM nodes WHERE parent_id IS NULL LIMIT 1"
    ).fetchone()
    if root_row is None:
        return None
    current_id: int = root_row[0]
    if target_dir == canonical_root:
        return current_id
    for part in target_dir.relative_to(canonical_root).parts:
        child_row = conn.execute(
            "SELECT id FROM nodes WHERE parent_id = ? AND name = ? AND is_dir = 1 LIMIT 1",
            (current_id, part),
        ).fetchone()
        if child_row is None:
            return None
        current_id = child_row[0]
    return current_id


def _reconstruct_node_path(
    conn: sqlite3.Connection,
    canonical_root: Path,
    parent_id: int | None,
    leaf_name: str,
    cache: dict[int, tuple[int | None, str]],
) -> Path:
    parts: list[str] = [leaf_name]
    cursor = parent_id
    while cursor is not None:
        cached = cache.get(cursor)
        if cached is None:
            row = conn.execute(
                "SELECT parent_id, name FROM nodes WHERE id = ? LIMIT 1",
                (cursor,),
            ).fetchone()
            if row is None:
                break
            cached = (row[0], row[1])
            cache[cursor] = cached
        next_parent, dir_name = cached
        if next_parent is not None:
            parts.append(dir_name)
        cursor = next_parent
    parts.reverse()
    return canonical_root.joinpath(*parts)


def _looks_like_log_file(file_path: Path, state_root: Path) -> bool:
    name_lower = file_path.name.casefold()
    if ".log." in name_lower or any(name_lower.endswith(ext) for ext in _LOG_SUFFIXES):
        return True
    try:
        rel_parts = file_path.relative_to(state_root).parts[:-1]
    except ValueError:
        rel_parts = ()
    return any(part.casefold() in {"log", "logs"} for part in rel_parts)


class LogsProvider:
    """Inspect systemd journal usage, XDG state logs, and readable /var/log files."""

    id = "logs"
    label = "Logs"

    def load(self, context: ProviderContext) -> ProviderResult:
        rows: list[Row] = []
        used_ids: set[str] = set()
        provider_error: ClassifiedError | None = None

        if context.which("journalctl") is not None:
            try:
                probe = context.run_readonly_command(("journalctl", "--disk-usage"), 5.0)
            except subprocess.TimeoutExpired:
                provider_error = ClassifiedError(
                    kind="timeout",
                    message="Tempo esgotado ao consultar journalctl --disk-usage.",
                )
                probe = None
            except FileNotFoundError:
                probe = None
            except PermissionError as error:
                provider_error = classify_os_error(error)
                probe = None
            except OSError as error:
                provider_error = classify_os_error(error)
                probe = None

            if probe is not None and probe.returncode == 0:
                journal_bytes = parse_journal_usage_bytes(probe.stdout)
                row_id = _unique_row_id("logs.systemd.journal", used_ids)
                rows.append(
                    Row(
                        id=row_id,
                        label="Journal do sistema (systemd)",
                        size_bytes=journal_bytes,
                        risk="medium",
                        action="tool_command",
                        argv=("journalctl", "--vacuum-size=200M"),
                        needs_admin=True,
                        warnings=(
                            "Reduz entradas antigas do journal até 200 MiB (requer administrador).",
                        ),
                    )
                )

        state_error = self._collect_state_logs(context, rows, used_ids)
        if provider_error is None and state_error is not None:
            provider_error = state_error

        self._collect_system_logs(context.system_log_dir, rows, used_ids)

        if provider_error is not None and not rows:
            return ProviderResult(
                rows=(), smaller_count=0, smaller_bytes=0, error=provider_error
            )
        return finalize_provider_rows(rows, error=provider_error)

    def _collect_state_logs(
        self,
        context: ProviderContext,
        rows: list[Row],
        used_ids: set[str],
    ) -> ClassifiedError | None:
        state_root = context.xdg_state_home
        try:
            root_stat = state_root.lstat()
        except FileNotFoundError:
            return None
        except OSError as error:
            return classify_os_error(error, state_root)

        if stat.S_ISLNK(root_stat.st_mode):
            return ClassifiedError(
                kind="symlink",
                message="O diretório XDG_STATE_HOME é um symlink e não é seguido.",
                path=state_root,
            )
        if not stat.S_ISDIR(root_stat.st_mode):
            return None

        try:
            canonical_state = state_root.resolve(strict=True)
        except OSError as error:
            return classify_os_error(error, state_root)

        seen_inodes: set[tuple[int, int]] = set()
        stack: list[Path] = [canonical_state]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    entries = list(iterator)
            except OSError:
                continue
            for entry in entries:
                entry_path = current / entry.name
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISLNK(info.st_mode) or info.st_dev != root_stat.st_dev:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    stack.append(entry_path)
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue

                rel_str = str(entry_path.relative_to(canonical_state))
                row_id = _unique_row_id(f"logs.state.{_safe_id_slug(rel_str)}", used_ids)
                size_bytes = _stat_allocated_bytes(info, seen_inodes)

                if _has_unsafe_text(rel_str) or _has_unsafe_text(str(entry_path)):
                    rows.append(
                        Row(
                            id=row_id,
                            label=f"Estado: {_sanitize_label(rel_str)}",
                            size_bytes=size_bytes,
                            risk="low",
                            action="inspect_only",
                            mtime_ns=info.st_mtime_ns,
                            error=ClassifiedError(
                                kind="unsafe_name",
                                message="Nome do log contém caracteres de controle.",
                                path=entry_path,
                            ),
                        )
                    )
                    continue

                if (
                    _is_database_file(entry_path)
                    or _classify_cache_protection(entry_path, context.protected_paths)
                    is not None
                    or _path_has_repo_or_node_modules(entry_path, canonical_state)
                    is not None
                ):
                    rows.append(
                        Row(
                            id=row_id,
                            label=f"Estado: {rel_str}",
                            size_bytes=size_bytes,
                            risk="high",
                            action="inspect_only",
                            mtime_ns=info.st_mtime_ns,
                            warnings=(
                                "Arquivo de estado ou banco de dados (somente inspeção).",
                            ),
                        )
                    )
                    continue

                if _looks_like_log_file(entry_path, canonical_state):
                    rows.append(
                        Row(
                            id=row_id,
                            label=f"Log do usuário: {rel_str}",
                            size_bytes=size_bytes,
                            risk="low",
                            action="trash_path",
                            path=entry_path,
                            allowed_root=canonical_state,
                            mtime_ns=info.st_mtime_ns,
                            warnings=("Arquivo de log em $XDG_STATE_HOME.",),
                        )
                    )
        return None

    def _collect_system_logs(
        self,
        sys_log_root: Path,
        rows: list[Row],
        used_ids: set[str],
    ) -> None:
        try:
            root_stat = sys_log_root.lstat()
        except OSError:
            return
        if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
            return
        try:
            canonical_sys = sys_log_root.resolve(strict=True)
        except OSError:
            return

        seen_inodes: set[tuple[int, int]] = set()
        stack: list[Path] = [canonical_sys]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    entries = list(iterator)
            except OSError:
                continue
            for entry in entries:
                entry_path = current / entry.name
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISLNK(info.st_mode) or info.st_dev != root_stat.st_dev:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    # Skip raw binary journal dir when journalctl already summarizes it.
                    if entry.name == "journal":
                        continue
                    stack.append(entry_path)
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                rel_str = str(entry_path.relative_to(canonical_sys))
                size_bytes = _stat_allocated_bytes(info, seen_inodes)
                row_id = _unique_row_id(f"logs.system.{_safe_id_slug(rel_str)}", used_ids)
                rows.append(
                    Row(
                        id=row_id,
                        label=f"/var/log/{_sanitize_label(rel_str)}",
                        size_bytes=size_bytes,
                        risk="medium",
                        action="inspect_only",
                        mtime_ns=info.st_mtime_ns,
                        warnings=(
                            "Log do sistema (somente inspeção; gerenciado pelo sistema).",
                        ),
                    )
                )


_DOCKER_SIZE_RE = re.compile(
    r"^\s*([0-9]+(?:\.[0-9]+)?)\s*(B|kB|KB|MB|GB|TB|PB|KiB|MiB|GiB|TiB|PiB)\b"
)
_DOCKER_SIZE_UNITS: dict[str, int] = {
    "B": 1,
    "kB": 1000,
    "KB": 1000,
    "MB": 1000**2,
    "GB": 1000**3,
    "TB": 1000**4,
    "PB": 1000**5,
    "KiB": 1024,
    "MiB": 1024**2,
    "GiB": 1024**3,
    "TiB": 1024**4,
    "PiB": 1024**5,
}


def _parse_docker_size(raw: object) -> int | None:
    """Parse human-readable Docker df sizes such as '1.2GB (80%)' or '800MiB'."""
    if not isinstance(raw, str):
        return None
    head = raw.split("(", 1)[0].strip()
    match = _DOCKER_SIZE_RE.match(head)
    if match is None:
        return None
    value = float(match.group(1))
    unit = match.group(2)
    return int(value * _DOCKER_SIZE_UNITS[unit])


class DockerProvider:
    """Read-only Docker disk usage provider (`docker system df --format '{{json .}}'`)."""

    id = "docker"
    label = "Docker"

    def load(self, context: ProviderContext) -> ProviderResult:
        if context.which("docker") is None:
            return ProviderResult(
                rows=(),
                smaller_count=0,
                smaller_bytes=0,
                error=ClassifiedError(
                    kind="tool_missing",
                    message="Docker não encontrado no sistema.",
                ),
            )

        try:
            probe = context.run_readonly_command(
                ["docker", "system", "df", "--format", "{{json .}}"],
                timeout=10.0,
            )
        except FileNotFoundError:
            return ProviderResult(
                rows=(),
                smaller_count=0,
                smaller_bytes=0,
                error=ClassifiedError(
                    kind="tool_missing",
                    message="Docker não encontrado no sistema.",
                ),
            )
        except subprocess.TimeoutExpired:
            return ProviderResult(
                rows=(),
                smaller_count=0,
                smaller_bytes=0,
                error=ClassifiedError(
                    kind="timeout",
                    message="Tempo esgotado ao consultar o Docker.",
                ),
            )
        except PermissionError as exc:
            return ProviderResult(
                rows=(),
                smaller_count=0,
                smaller_bytes=0,
                error=ClassifiedError(
                    kind="socket_denied",
                    message=f"Sem permissão para acessar o socket do Docker: {exc}",
                    errno=exc.errno,
                ),
            )
        except OSError as exc:
            return ProviderResult(
                rows=(),
                smaller_count=0,
                smaller_bytes=0,
                error=ClassifiedError(
                    kind="unexpected",
                    message=f"Erro ao consultar o Docker: {exc}",
                    errno=exc.errno,
                ),
            )

        if probe.returncode != 0:
            stderr_text = probe.stderr.strip()
            lowered = stderr_text.casefold()
            if "permission denied" in lowered or "eacces" in lowered:
                return ProviderResult(
                    rows=(),
                    smaller_count=0,
                    smaller_bytes=0,
                    error=ClassifiedError(
                        kind="socket_denied",
                        message="Sem permissão para acessar o socket do Docker.",
                    ),
                )
            return ProviderResult(
                rows=(),
                smaller_count=0,
                smaller_bytes=0,
                error=ClassifiedError(
                    kind="unexpected",
                    message="Não foi possível consultar o Docker (daemon parado ou inacessível).",
                ),
            )

        rows: list[Row] = []
        for raw_line in probe.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue

            df_type = str(entry.get("Type") or "").strip()
            size_bytes = _parse_docker_size(entry.get("Reclaimable"))
            if size_bytes is None:
                size_bytes = _parse_docker_size(entry.get("Size"))

            total_count = str(entry.get("TotalCount") or "").strip()
            active_count = str(entry.get("Active") or "").strip()
            counts_suffix = (
                f" ({total_count} total, {active_count} ativos)"
                if total_count and active_count
                else ""
            )

            if df_type == "Images":
                rows.append(
                    Row(
                        id="docker.images",
                        label=f"Imagens Docker sem uso{counts_suffix}",
                        size_bytes=size_bytes,
                        risk="low",
                        action="tool_command",
                        argv=("docker", "image", "prune"),
                        warnings=("Remove imagens Docker não utilizadas por containers.",),
                    )
                )
            elif df_type == "Containers":
                rows.append(
                    Row(
                        id="docker.containers",
                        label=f"Containers Docker parados{counts_suffix}",
                        size_bytes=size_bytes,
                        risk="low",
                        action="tool_command",
                        argv=("docker", "container", "prune"),
                        warnings=("Remove apenas containers parados.",),
                    )
                )
            elif df_type == "Build Cache":
                rows.append(
                    Row(
                        id="docker.build_cache",
                        label="Cache de build do Docker",
                        size_bytes=size_bytes,
                        risk="low",
                        action="tool_command",
                        argv=("docker", "builder", "prune"),
                        warnings=("Cache regenerável em builds futuros.",),
                    )
                )
            elif df_type == "Local Volumes":
                rows.append(
                    Row(
                        id="docker.volumes",
                        label=f"Volumes Docker locais{counts_suffix}",
                        size_bytes=size_bytes,
                        risk="high",
                        action="inspect_only",
                        warnings=(
                            "Dados de volumes Docker (somente inspeção); nunca é removido automaticamente.",
                        ),
                    )
                )

        return finalize_provider_rows(rows)


def _is_arch_linux(os_release_path: Path) -> bool:
    try:
        text = os_release_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    os_id = ""
    id_like = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        cleaned = value.strip().strip('"').strip("'").casefold()
        if key == "ID":
            os_id = cleaned
        elif key == "ID_LIKE":
            id_like = cleaned
    return os_id == "arch" or "arch" in id_like.split()


class PackagesProvider:
    """Arch Linux package cache and orphan packages provider."""

    id = "packages"
    label = "Pacotes"

    def load(self, context: ProviderContext) -> ProviderResult:
        if not _is_arch_linux(context.os_release_path):
            return ProviderResult(rows=(), smaller_count=0, smaller_bytes=0, error=None)

        rows: list[Row] = []
        error: ClassifiedError | None = None

        cache_dir = context.pacman_cache_dir
        if cache_dir.exists():
            try:
                cache_bytes = measure_allocated_bytes(cache_dir)
            except PermissionError as exc:
                error = ClassifiedError(
                    kind="permission",
                    message=f"Sem permissão para medir {cache_dir}.",
                    path=cache_dir,
                    errno=exc.errno,
                )
                cache_bytes = 0
            except OSError as exc:
                error = ClassifiedError(
                    kind="unexpected",
                    message=f"Erro ao medir {cache_dir}: {exc}",
                    path=cache_dir,
                    errno=exc.errno,
                )
                cache_bytes = 0

            if cache_bytes > 0:
                if context.which("paccache") is not None:
                    cache_argv: tuple[str, ...] = ("paccache", "-r")
                else:
                    cache_argv = ("pacman", "-Sc")
                rows.append(
                    Row(
                        id="packages.pacman.cache",
                        label="Cache de pacotes do pacman",
                        size_bytes=cache_bytes,
                        risk="medium",
                        action="tool_command",
                        argv=cache_argv,
                        needs_admin=True,
                        warnings=(
                            "Mantém versões recentes ou limpa pacotes não instalados; requer administrador.",
                        ),
                    )
                )

        if context.which("pacman") is not None:
            try:
                probe = context.run_readonly_command(["pacman", "-Qdtq"], timeout=10.0)
            except FileNotFoundError:
                if error is None and not rows:
                    error = ClassifiedError(
                        kind="tool_missing",
                        message="pacman não encontrado no sistema.",
                    )
            except subprocess.TimeoutExpired:
                if error is None:
                    error = ClassifiedError(
                        kind="timeout",
                        message="Tempo esgotado ao consultar pacotes órfãos.",
                    )
            except OSError as exc:
                if error is None:
                    error = ClassifiedError(
                        kind="unexpected",
                        message=f"Erro ao consultar pacotes órfãos com pacman -Qdtq: {exc}",
                        errno=exc.errno,
                    )
            else:
                if probe.returncode == 0:
                    orphans = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
                    if orphans:
                        preview = ", ".join(_sanitize_label(name) for name in orphans[:5])
                        extra = f" (+{len(orphans) - 5})" if len(orphans) > 5 else ""
                        rows.append(
                            Row(
                                id="packages.pacman.orphans",
                                label=f"Pacotes órfãos ({len(orphans)}): {preview}{extra}",
                                size_bytes=None,
                                risk="medium",
                                action="inspect_only",
                                warnings=(
                                    "Somente inspeção: revise os pacotes órfãos antes de remover manualmente.",
                                ),
                            )
                        )
                elif probe.returncode == 1 and not probe.stdout.strip() and not probe.stderr.strip():
                    # `pacman -Qdtq` exits with status 1 and empty output when there are 0 orphans.
                    pass
                elif error is None:
                    error = ClassifiedError(
                        kind="unexpected",
                        message="Falha ao consultar pacotes órfãos com pacman -Qdtq.",
                    )
        elif not rows and error is None:
            error = ClassifiedError(
                kind="tool_missing",
                message="pacman não encontrado no sistema.",
            )

        return finalize_provider_rows(rows, error=error if not rows else None)


PROVIDERS: dict[str, Provider] = {
    CachesProvider.id: CachesProvider(),
    TrashProvider.id: TrashProvider(),
    LargeFilesProvider.id: LargeFilesProvider(),
    LogsProvider.id: LogsProvider(),
    DockerProvider.id: DockerProvider(),
    PackagesProvider.id: PackagesProvider(),
}


def get_provider(mode_id: str) -> Provider | None:
    """Return the registered domain provider for ``mode_id``, if implemented."""
    return PROVIDERS.get(mode_id)
