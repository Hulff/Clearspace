"""Reviewed, item-at-a-time filesystem actions for Clearspace."""

from __future__ import annotations

import logging
import os
import errno
import shutil
import stat
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Callable, Protocol

from .contracts import Risk

logger = logging.getLogger(__name__)
PERMANENT_CONFIRMATION = "EXCLUIR PERMANENTEMENTE"
TRASH_NOTICE = "O espaço só é liberado ao esvaziar a lixeira."
SYSTEM_PROTECTED = ("/", "/usr", "/etc", "/boot", "/var", "/proc", "/sys", "/dev", "/run")


class FileAction(StrEnum):
    TRASH = "trash"
    PERMANENT = "permanent_delete"


class HistorySink(Protocol):
    def append(self, record: dict) -> None: ...


class TrashAdapter(Protocol):
    def __call__(self, path: Path) -> None: ...


class GioTrash:
    """Move a path to the desktop trash through Gio, imported only on use."""

    def __call__(self, path: Path) -> None:
        try:
            import gi
            gi.require_version("Gio", "2.0")
            from gi.repository import Gio
        except (ImportError, ValueError) as error:
            raise RuntimeError("Gio não está disponível; nenhum arquivo foi movido") from error
        moved = Gio.File.new_for_path(str(path)).trash(None)
        if not moved:
            raise OSError(f"Gio não conseguiu mover {path} para a lixeira")


@dataclass(frozen=True)
class ReviewedItem:
    path: Path
    size_bytes: int
    risk: Risk
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class CleanupReview:
    allowed_root: Path
    items: tuple[ReviewedItem, ...]
    total_size_bytes: int
    maximum_risk: Risk
    active_paths: tuple[Path, ...] = ()
    notice: str = TRASH_NOTICE


@dataclass(frozen=True)
class ItemResult:
    path: Path
    action: FileAction
    success: bool
    record: dict


class UnsafePathError(ValueError):
    """Raised when a selected path violates filesystem safety rules."""


def build_review(
    paths: list[Path] | tuple[Path, ...],
    *,
    allowed_root: Path,
    risks: dict[Path, Risk] | None = None,
    warnings: dict[Path, tuple[str, ...]] | None = None,
    active_paths: tuple[Path, ...] | None = None,
) -> CleanupReview:
    """Validate and measure a minimal, reviewed set of paths under a root."""
    root = _canonical_root(allowed_root)
    if active_paths is None:
        active_paths = discover_active_paths(root)
    risks = risks or {}
    warnings = warnings or {}
    validated: list[tuple[Path, Path, os.stat_result]] = []
    for raw_path in paths:
        path, info = _validate_path(raw_path, root, active_paths)
        validated.append((raw_path, path, info))
    minimal = _minimal_paths(tuple(path for _, path, _ in validated))
    items: list[ReviewedItem] = []
    seen_inodes: set[tuple[int, int]] = set()
    for raw_path in minimal:
        path, info = next((path, info) for _, path, info in validated if path == raw_path)
        size = _tree_allocated_size(path, root, info.st_dev, seen_inodes)
        selected_raw = next(raw for raw, canonical, _ in validated if canonical == raw_path)
        risk = risks.get(selected_raw, risks.get(raw_path, Risk.MODERATE))
        item_warnings = warnings.get(selected_raw, warnings.get(raw_path, ()))
        items.append(ReviewedItem(path, size, risk, tuple(item_warnings)))
    if not items:
        raise ValueError("Selecione ao menos um item para revisar")
    max_risk = max((item.risk for item in items), key=_risk_rank)
    return CleanupReview(root, tuple(items), sum(item.size_bytes for item in items), max_risk,
                         tuple(Path(path).resolve(strict=False) for path in active_paths))


def discover_active_paths(allowed_root: Path) -> tuple[Path, ...]:
    """Find open files and working directories under a scan root via procfs.

    This reads link targets only; it never opens application files. Call again
    immediately before each item so newly active paths are protected too.
    """
    root = allowed_root.resolve(strict=True)
    proc = Path("/proc")
    active: set[Path] = set()
    try:
        processes = tuple(proc.iterdir())
    except OSError as error:
        logger.warning("Could not inspect procfs for active paths: %s", error)
        raise RuntimeError(f"Não foi possível verificar dados ativos em /proc: {error}") from error
    for process in processes:
        if not process.name.isdecimal():
            continue
        try:
            status = (process / "status").read_text(encoding="ascii")
        except FileNotFoundError:
            continue
        except OSError as error:
            # /proc entries are inherently racy: a process may exit or become
            # inaccessible after enumeration. Its vanished descriptors cannot
            # keep files active, so skip that process and continue scanning.
            if error.errno in {errno.ENOENT, errno.ESRCH, errno.EACCES, errno.EPERM}:
                continue
            raise RuntimeError(
                f"Não foi possível verificar processos ativos ({process.name}): {error}"
            ) from error
        uid_line = next((line for line in status.splitlines() if line.startswith("Uid:")), None)
        if uid_line is None:
            raise RuntimeError(f"Não foi possível determinar o usuário do processo {process.name}")
        try:
            process_uids = {int(value) for value in uid_line.split()[1:4]}
        except ValueError as error:
            raise RuntimeError(f"UID inválido no processo {process.name}") from error
        if os.getuid() not in process_uids and os.geteuid() not in process_uids:
            continue
        sources = [process / "cwd"]
        try:
            sources.extend((process / "fd").iterdir())
        except FileNotFoundError:
            continue
        except OSError as error:
            if error.errno in {errno.ENOENT, errno.ESRCH, errno.EACCES, errno.EPERM}:
                continue
            raise RuntimeError(
                f"Não foi possível inspecionar descritores do processo {process.name}: {error}"
            ) from error
        for source in sources:
            try:
                raw_target = os.readlink(source)
            except FileNotFoundError:
                continue
            except OSError as error:
                if error.errno in {
                    errno.ENOENT, errno.ESRCH, errno.EACCES, errno.EPERM,
                }:
                    continue
                raise RuntimeError(
                    f"Não foi possível verificar caminho ativo {source}: {error}"
                ) from error
            if raw_target.endswith(" (deleted)"):
                raw_target = raw_target[:-10]
            target = Path(raw_target)
            if not target.is_absolute():
                continue
            try:
                canonical = target.resolve(strict=False)
                canonical.relative_to(root)
            except (OSError, ValueError):
                continue
            active.add(canonical)
    return tuple(sorted(active))


class ItemExecutor:
    """Revalidate each reviewed item immediately before its single action."""

    def __init__(
        self,
        history: HistorySink,
        *,
        trash: TrashAdapter | None = None,
        active_paths: Callable[[], tuple[Path, ...]] | tuple[Path, ...] | None = None,
    ) -> None:
        self.history = history
        self.trash = trash or GioTrash()
        self.active_paths = active_paths

    def execute_one(
        self,
        review: CleanupReview,
        path: Path,
        action: FileAction = FileAction.TRASH,
        *,
        user_data_confirmed: bool = False,
        typed_confirmation: str | None = None,
    ) -> ItemResult:
        """Execute exactly one item after its review and confirmation."""
        action = FileAction(action)
        item = next((candidate for candidate in review.items if candidate.path == path), None)
        if item is None:
            raise ValueError("O item não pertence à revisão confirmada")
        started_at = time.time()
        before_df = _disk_usage_record(review.allowed_root)
        failure: str | None = None
        size_at_execution = item.size_bytes

        try:
            if self.active_paths is None:
                current_active = discover_active_paths(review.allowed_root)
            else:
                current_active = (
                    self.active_paths() if callable(self.active_paths) else self.active_paths
                )
            active_paths = tuple(review.active_paths) + tuple(current_active)
            if item.risk is Risk.CRITICAL:
                raise UnsafePathError("Risco crítico bloqueia qualquer exclusão")
            if item.risk is Risk.USER_DATA and not user_data_confirmed:
                raise UnsafePathError("Dados pessoais exigem confirmação reforçada")
            if action is FileAction.PERMANENT:
                if typed_confirmation != PERMANENT_CONFIRMATION:
                    raise UnsafePathError(
                        f'Digite exatamente "{PERMANENT_CONFIRMATION}" para confirmar'
                    )
                if item.risk is Risk.CRITICAL:
                    raise UnsafePathError("Exclusão permanente bloqueada para risco crítico")

            checked_path, info = _validate_path(item.path, review.allowed_root, active_paths)
            size_at_execution = _tree_allocated_size(checked_path, review.allowed_root, info.st_dev)
            if action is FileAction.TRASH:
                # Validate once more at the point of the Gio operation.
                _validate_path(checked_path, review.allowed_root, active_paths)
                self.trash(checked_path)
            elif action is FileAction.PERMANENT:
                _permanent_remove(checked_path, review.allowed_root, active_paths)
            else:
                raise ValueError(f"Ação desconhecida: {action}")
        except Exception as error:
            failure = str(error)
            logger.warning("File action %s failed for %s: %s", action, path, error)

        after_df = _disk_usage_record(review.allowed_root)
        finished_at = time.time()
        record = {
            "schema_version": 1,
            "path": str(item.path),
            "size_bytes": size_at_execution,
            "action": action.value,
            "started_at": started_at,
            "finished_at": finished_at,
            "result": "failed" if failure else "success",
            "failure_details": failure,
            "filesystem_before": before_df,
            "filesystem_after": after_df,
        }
        try:
            self.history.append(record)
        except Exception as error:
            # A completed filesystem operation without its required audit row
            # must not be reported as a successful, fully recorded action.
            record["result"] = "failed"
            record["failure_details"] = "; ".join(
                value for value in (failure, f"falha ao gravar histórico: {error}") if value
            )
            failure = record["failure_details"]
            logger.exception("Could not append action to JSONL history")
        return ItemResult(item.path, action, failure is None, record)


def _minimal_paths(paths: list[Path] | tuple[Path, ...]) -> tuple[Path, ...]:
    ordered = sorted(set(paths), key=lambda path: (len(path.parts), str(path)))
    result: list[Path] = []
    for path in ordered:
        if not any(_is_below(path, parent) for parent in result):
            result.append(path)
    return tuple(result)


def _canonical_root(root: Path) -> Path:
    if ".." in root.parts:
        raise UnsafePathError("A raiz permitida não pode conter '..'")
    try:
        info = root.lstat()
    except OSError as error:
        raise UnsafePathError(f"Raiz permitida não está disponível: {error}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise UnsafePathError("A raiz permitida deve ser um diretório real, sem symlink")
    canonical = root.resolve(strict=True)
    if _is_protected(canonical, canonical, ()):
        raise UnsafePathError(f"Raiz protegida: {canonical}")
    return canonical


def _validate_path(
    candidate: Path,
    root: Path,
    active_paths: tuple[Path, ...],
) -> tuple[Path, os.stat_result]:
    if ".." in candidate.parts:
        raise UnsafePathError(f"Caminho com '..' bloqueado: {candidate}")
    lexical = candidate if candidate.is_absolute() else root / candidate
    try:
        lexical.relative_to(root)
    except ValueError as error:
        raise UnsafePathError(f"Caminho fora da raiz permitida: {candidate}") from error
    if lexical == root:
        raise UnsafePathError("A raiz permitida não pode ser alterada")

    current = root
    relative = lexical.relative_to(root)
    for part in relative.parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as error:
            raise UnsafePathError(f"Caminho não pode ser validado: {error}") from error
        if stat.S_ISLNK(info.st_mode):
            raise UnsafePathError(f"Symlink bloqueado: {current}")

    try:
        canonical = lexical.resolve(strict=True)
        canonical.relative_to(root)
        info = canonical.lstat()
    except (OSError, ValueError) as error:
        raise UnsafePathError(f"Caminho escapou da raiz ou não existe: {candidate}") from error
    if _is_protected(canonical, root, active_paths):
        raise UnsafePathError(f"Caminho protegido: {canonical}")
    root_device = root.stat().st_dev
    if info.st_dev != root_device:
        raise UnsafePathError("Caminho está em outro filesystem")
    if not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode):
        raise UnsafePathError("Somente arquivos regulares e diretórios podem ser alterados")
    _validate_nested_links(canonical, root, root_device, active_paths)
    return canonical, info


def _validate_nested_links(path: Path, root: Path, root_device: int,
                           active_paths: tuple[Path, ...]) -> None:
    if not path.is_dir():
        return
    try:
        with os.scandir(path) as entries:
            children = list(entries)
    except OSError as error:
        raise UnsafePathError(f"Não foi possível revisar o diretório {path}: {error}") from error
    for entry in children:
        child = Path(entry.path)
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError as error:
            raise UnsafePathError(f"Não foi possível revisar {child}: {error}") from error
        if info.st_dev != root_device:
            raise UnsafePathError(f"Subdiretório em outro filesystem: {child}")
        if stat.S_ISLNK(info.st_mode):
            try:
                target = child.resolve(strict=False)
                target.relative_to(root)
            except (OSError, ValueError) as error:
                raise UnsafePathError(f"Symlink escapa da raiz permitida: {child}") from error
            if _is_protected(target, root, active_paths):
                raise UnsafePathError(f"Symlink aponta para dado protegido: {child}")
        elif stat.S_ISDIR(info.st_mode):
            _validate_nested_links(child, root, root_device, active_paths)
        if _is_protected(child, root, active_paths):
            raise UnsafePathError(f"Árvore inclui dado protegido/ativo: {child}")


def _tree_allocated_size(
    path: Path,
    root: Path,
    root_device: int,
    seen_inodes: set[tuple[int, int]] | None = None,
) -> int:
    if not _is_below(path, root):
        raise UnsafePathError(f"Caminho fora da raiz permitida: {path}")
    total = 0
    seen_inodes = seen_inodes if seen_inodes is not None else set()
    pending = [path]
    while pending:
        current = pending.pop()
        try:
            info = current.lstat()
        except OSError as error:
            raise UnsafePathError(f"Não foi possível medir {current}: {error}") from error
        if info.st_dev != root_device:
            raise UnsafePathError(f"Filesystem diferente durante medição: {current}")
        if stat.S_ISLNK(info.st_mode):
            continue
        if stat.S_ISDIR(info.st_mode):
            total += info.st_blocks * 512
            try:
                with os.scandir(current) as entries:
                    pending.extend(Path(entry.path) for entry in entries)
            except OSError as error:
                raise UnsafePathError(f"Não foi possível medir {current}: {error}") from error
            continue
        if not stat.S_ISREG(info.st_mode):
            raise UnsafePathError(f"Tipo de arquivo não suportado: {current}")
        inode = (info.st_dev, info.st_ino)
        if inode not in seen_inodes:
            seen_inodes.add(inode)
            total += info.st_blocks * 512
    return total


def _permanent_remove(path: Path, root: Path, active_paths: tuple[Path, ...]) -> None:
    """Delete through directory descriptors, never resolving symlink entries."""
    relative = path.relative_to(root)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_fd = os.dup(root_fd)
        try:
            for component in relative.parts[:-1]:
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = next_fd
            name = relative.parts[-1]
            _remove_entry_at(parent_fd, name, root, path, active_paths, root.stat().st_dev)
        finally:
            os.close(parent_fd)
    finally:
        os.close(root_fd)


def _remove_entry_at(parent_fd: int, name: str, root: Path, path: Path,
                     active_paths: tuple[Path, ...], root_device: int) -> None:
    full_path = path
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if info.st_dev != root_device:
        raise UnsafePathError(f"Filesystem diferente durante exclusão: {full_path}")
    if stat.S_ISLNK(info.st_mode):
        parent = full_path.parent
        _validate_path(parent, root, active_paths)
        link_target = os.readlink(name, dir_fd=parent_fd)
        resolved_target = (parent / link_target).resolve(strict=False)
        if not _is_below(resolved_target, root) or _is_protected(
            resolved_target, root, active_paths
        ):
            raise UnsafePathError(f"Symlink agora aponta para fora/área protegida: {full_path}")
        # Unlink only the directory entry. No operation opens or follows target.
        os.unlink(name, dir_fd=parent_fd)
        return
    _validate_path(full_path, root, active_paths)
    if stat.S_ISDIR(info.st_mode):
        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                           dir_fd=parent_fd)
        try:
            with os.scandir(child_fd) as entries:
                names = [entry.name for entry in entries]
            for child_name in names:
                _remove_entry_at(child_fd, child_name, root, full_path / child_name,
                                 active_paths, root_device)
        finally:
            os.close(child_fd)
        os.rmdir(name, dir_fd=parent_fd)
    elif stat.S_ISREG(info.st_mode):
        os.unlink(name, dir_fd=parent_fd)
    else:
        raise UnsafePathError(f"Tipo de arquivo protegido: {full_path}")


def _is_protected(path: Path, root: Path, active_paths: tuple[Path, ...]) -> bool:
    resolved = path.resolve(strict=False)
    protected = [Path(value).resolve(strict=False) for value in SYSTEM_PROTECTED]
    protected_home = Path.home().resolve(strict=False)
    for protected_root in protected:
        if (resolved == protected_root if protected_root == Path("/")
                else _is_below(resolved, protected_root)):
            return True
    if resolved == protected_home:
        return True
    for active in active_paths:
        active_resolved = active.resolve(strict=False)
        if _is_below(resolved, active_resolved) or _is_below(active_resolved, resolved):
            return True
    try:
        resolved.relative_to(root)
    except ValueError:
        return True
    return False


def _disk_usage_record(path: Path) -> dict | None:
    try:
        usage = shutil.disk_usage(path)
    except OSError as error:
        return {"error": str(error)}
    return {"total_bytes": usage.total, "free_bytes": usage.free}


def _is_below(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _risk_rank(risk: Risk) -> int:
    return {Risk.LOW: 0, Risk.MODERATE: 1, Risk.USER_DATA: 2, Risk.CRITICAL: 3}[risk]
