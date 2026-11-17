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
    trash_supported: bool | None = None


@dataclass(frozen=True)
class CleanupReview:
    allowed_root: Path
    items: tuple[ReviewedItem, ...]
    total_size_bytes: int
    maximum_risk: Risk
    active_paths: tuple[Path | ActiveProcessPath, ...] = ()
    notice: str = TRASH_NOTICE


@dataclass(frozen=True)
class ItemResult:
    path: Path
    action: FileAction
    success: bool
    record: dict


class UnsafePathError(ValueError):
    """Raised when a selected path violates filesystem safety rules."""


class ActiveApplicationError(UnsafePathError):
    """Raised when a selected path is currently used by an application."""


class ProtectedPathError(UnsafePathError):
    """Raised when an explicit protected-root rule matches a path."""


class OutsideScanRootError(UnsafePathError):
    """Raised when a canonical path is outside the selected scan root."""


@dataclass(frozen=True, slots=True)
class ActiveProcessPath:
    path: Path
    application: str


def build_review(
    paths: list[Path] | tuple[Path, ...],
    *,
    allowed_root: Path,
    risks: dict[Path, Risk] | None = None,
    warnings: dict[Path, tuple[str, ...]] | None = None,
    active_paths: tuple[Path, ...] | None = None,
    trash_support: Callable[[Path], bool | None] | None = None,
    home_device: int | None = None,
) -> CleanupReview:
    """Validate and measure a minimal, reviewed set of paths under a root."""
    root = _canonical_root(allowed_root)
    if active_paths is None:
        active_paths = discover_active_paths(root)
    risks = risks or {}
    warnings = warnings or {}
    if home_device is None:
        home_device = Path.home().stat().st_dev
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
        item_warnings = list(warnings.get(selected_raw, warnings.get(raw_path, ())))
        item_warnings.extend(_permission_warnings(path, info))
        supported = trash_support(path) if trash_support is not None else None
        if info.st_dev != home_device:
            supported = False
        if info.st_dev != home_device or supported is False:
            item_warnings.append("Este local não tem lixeira (partição diferente do home)")
        items.append(ReviewedItem(path, size, risk, tuple(dict.fromkeys(item_warnings)), supported))
    if not items:
        raise ValueError("Selecione ao menos um item para revisar")
    max_risk = max((item.risk for item in items), key=_risk_rank)
    return CleanupReview(root, tuple(items), sum(item.size_bytes for item in items), max_risk,
                         tuple(
                             ActiveProcessPath(path.path.resolve(strict=False), path.application)
                             if isinstance(path, ActiveProcessPath)
                             else Path(path).resolve(strict=False)
                             for path in active_paths
                         ))


def discover_active_paths(allowed_root: Path) -> tuple[ActiveProcessPath, ...]:
    """Find open files and working directories under a scan root via procfs.

    This reads link targets only; it never opens application files. Call again
    immediately before each item so newly active paths are protected too.
    """
    root = allowed_root.resolve(strict=True)
    proc = Path("/proc")
    active: set[ActiveProcessPath] = set()
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
        try:
            comm = (process / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            comm = "Aplicativo"
        application = _application_label(comm)
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
            active.add(ActiveProcessPath(canonical, application))
    return tuple(sorted(active, key=lambda item: (str(item.path), item.application)))


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
        error_kind: str | None = None
        exception_type: str | None = None
        exception_class: str | None = None
        error_errno: int | None = None
        glib_domain: str | None = None
        glib_code: int | None = None
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
            error_kind = _error_kind(error)
            exception_type = type(error).__name__
            exception_class = f"{type(error).__module__}.{type(error).__qualname__}"
            error_errno = getattr(error, "errno", None)
            glib_domain = getattr(error, "domain", None)
            glib_code = getattr(error, "code", None)
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
            "failure_kind": error_kind,
            "failure_message": _failure_message(error_kind, failure),
            "exception_type": exception_type,
            "exception_class": exception_class,
            "errno": error_errno,
            "glib_domain": glib_domain,
            "glib_code": glib_code,
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

    def record_skip(self, review: CleanupReview, item: ReviewedItem) -> ItemResult:
        """Record an explicitly skipped item in the reviewed plan."""
        now = time.time()
        record = {
            "schema_version": 1,
            "path": str(item.path),
            "size_bytes": item.size_bytes,
            "action": FileAction.TRASH.value,
            "started_at": now,
            "finished_at": now,
            "result": "failed",
            "failure_kind": "trash_unavailable",
            "failure_details": "Item ignorado por escolha do usuário; nenhum fallback foi executado.",
            "failure_message": "Lixeira indisponível neste filesystem; item ignorado.",
        }
        self.history.append(record)
        return ItemResult(item.path, FileAction.TRASH, False, record)


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
    match = _protected_rule_match(canonical)
    if match:
        rule, protected_path = match
        raise ProtectedPathError(
            f"Caminho protegido (raiz protegida) pela regra '{rule}': {protected_path}"
        )
    return canonical


def _validate_path(
    candidate: Path,
    root: Path,
    active_paths: tuple[Path | ActiveProcessPath, ...],
) -> tuple[Path, os.stat_result]:
    if ".." in candidate.parts:
        raise UnsafePathError(f"Caminho com '..' bloqueado: {candidate}")
    lexical = candidate if candidate.is_absolute() else root / candidate
    try:
        lexical.relative_to(root)
    except ValueError as error:
        raise OutsideScanRootError(
            f"Caminho fora da raiz do scan: {candidate} (raiz: {root})"
        ) from error
    if lexical == root:
        raise UnsafePathError("A raiz permitida não pode ser alterada")

    current = root
    relative = lexical.relative_to(root)
    for part in relative.parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as error:
            if isinstance(error, (PermissionError, FileNotFoundError)):
                raise
            raise UnsafePathError(f"Caminho não pode ser validado: {error}") from error
        if stat.S_ISLNK(info.st_mode):
            try:
                canonical_link_target = current.resolve(strict=True)
            except OSError as error:
                raise UnsafePathError(f"Symlink não pode ser canonicalizado: {current}") from error
            if not _is_below(canonical_link_target, root):
                raise OutsideScanRootError(
                    f"Symlink aponta para fora da raiz do scan: {current} "
                    f"(destino: {canonical_link_target}; raiz: {root})"
                )
            protected_match = _protected_rule_match(canonical_link_target)
            if protected_match:
                rule, protected_path = protected_match
                raise ProtectedPathError(
                    f"Caminho protegido pela regra '{rule}': {protected_path} "
                    f"(via symlink {current})"
                )
            raise UnsafePathError(f"Symlink bloqueado: {current}")

    try:
        canonical = lexical.resolve(strict=True)
        canonical.relative_to(root)
        info = canonical.lstat()
    except (OSError, ValueError) as error:
        if isinstance(error, (PermissionError, FileNotFoundError)):
            raise
        raise UnsafePathError(f"Caminho escapou da raiz ou não existe: {candidate}") from error
    match = _protected_rule_match(canonical)
    if match:
        rule, protected_path = match
        raise ProtectedPathError(
            f"Caminho protegido (raiz protegida) pela regra '{rule}': {protected_path}"
        )
    active_application = _active_application_match(canonical, active_paths)
    if active_application is not None:
        raise ActiveApplicationError(
            f"Aplicação em uso: {active_application.application} está usando "
            f"{active_application.path}. Feche o aplicativo e tente novamente."
        )
    active_path = _active_path_match(canonical, active_paths)
    if active_path is not None:
        raise UnsafePathError(f"Caminho protegido/ativo: {active_path}")
    try:
        canonical.relative_to(root)
    except ValueError as error:
        raise OutsideScanRootError(
            f"Caminho fora da raiz do scan: {canonical} (raiz: {root})"
        ) from error
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
        if isinstance(error, (PermissionError, FileNotFoundError)):
            raise
        raise UnsafePathError(f"Não foi possível revisar o diretório {path}: {error}") from error
    for entry in children:
        child = Path(entry.path)
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError as error:
            if isinstance(error, (PermissionError, FileNotFoundError)):
                raise
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
            if isinstance(error, (PermissionError, FileNotFoundError)):
                raise
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
                if isinstance(error, (PermissionError, FileNotFoundError)):
                    raise
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


def _is_protected(path: Path, root: Path,
                  active_paths: tuple[Path | ActiveProcessPath, ...]) -> bool:
    resolved = path.resolve(strict=False)
    if _protected_rule_match(resolved):
        return True
    for active in active_paths:
        if isinstance(active, ActiveProcessPath):
            continue
        active_resolved = active.resolve(strict=False)
        if _is_below(resolved, active_resolved) or _is_below(active_resolved, resolved):
            return True
    try:
        resolved.relative_to(root)
    except ValueError:
        return True
    return False


def _protected_rule_match(path: Path) -> tuple[str, Path] | None:
    resolved = path.resolve(strict=False)
    home = Path.home().resolve(strict=False)
    exact_roots = [
        (f"system root {value}", Path(value).resolve(strict=False))
        for value in SYSTEM_PROTECTED
    ]
    exact_roots.append(("home directory", home))
    for relative, rule in (
        (".ssh", "SSH credentials"),
        (".gnupg", "GPG credentials"),
        (".aws", "cloud credentials"),
        (".azure", "Azure credentials"),
        (".kube", "Kubernetes credentials"),
        (".docker/config.json", "Docker credentials"),
        (".git-credentials", "Git credentials"),
        (".netrc", "netrc credentials"),
        (".npmrc", "npm credentials"),
        (".pypirc", "PyPI credentials"),
        (".config/Code/User", "VS Code user data"),
        (".config/credentials", "user credentials"),
        (".config/gcloud", "Google Cloud credentials"),
        (".local/share/keyrings", "desktop keyring"),
    ):
        exact_roots.append((rule, home / relative))
    for rule, protected_root in exact_roots:
        if protected_root == Path("/"):
            if resolved == protected_root:
                return rule, protected_root
        elif rule == "home directory":
            if resolved == protected_root:
                return rule, protected_root
        elif _is_below(resolved, protected_root):
            return rule, protected_root
    return None


def _active_application_match(
    path: Path,
    active_paths: tuple[Path | ActiveProcessPath, ...],
) -> ActiveProcessPath | None:
    for active in active_paths:
        if not isinstance(active, ActiveProcessPath):
            continue
        active_path = active.path.resolve(strict=False)
        if _is_below(path, active_path) or _is_below(active_path, path):
            return active
    return None


def _active_path_match(path: Path, active_paths: tuple[Path | ActiveProcessPath, ...]) -> Path | None:
    for active in active_paths:
        if isinstance(active, ActiveProcessPath):
            continue
        active_path = active.resolve(strict=False)
        if _is_below(path, active_path) or _is_below(active_path, path):
            return active_path
    return None


def _application_label(comm: str) -> str:
    normalized = comm.casefold()
    if normalized in {"code", "code-oss", "code-insiders", "codium"}:
        return "Visual Studio Code"
    return comm or "Aplicativo"


def _permission_warnings(path: Path, info: os.stat_result) -> tuple[str, ...]:
    warnings = []
    if info.st_uid != os.getuid():
        warnings.append(
            f"O item pertence ao UID {info.st_uid}, diferente do usuário atual; "
            "o sistema pode negar a operação. Procedimento recomendado: solicite ao dono "
            "ou administrador que ajuste a propriedade/permissões fora do Clearspace."
        )
    try:
        parent_info = path.parent.stat()
        writable = bool(parent_info.st_mode & 0o222) and os.access(
            path.parent, os.W_OK | os.X_OK
        )
    except OSError:
        writable = False
    if not writable:
        warnings.append(
            "A pasta pai não permite escrita ao usuário atual; a ação provavelmente falhará. "
            "Ajuste as permissões da pasta pelo gerenciador de arquivos ou peça ao dono "
            "para fazê-lo. Clearspace não executa comandos privilegiados."
        )
    return tuple(warnings)


def _error_kind(error: Exception) -> str:
    if isinstance(error, ActiveApplicationError):
        return "application_in_use"
    if isinstance(error, OutsideScanRootError):
        return "outside_scan_root"
    if isinstance(error, ProtectedPathError):
        return "app_protected"
    if isinstance(error, UnsafePathError):
        return "app_protected"
    if isinstance(error, FileNotFoundError):
        return "missing"
    if isinstance(error, PermissionError):
        return "filesystem_permission"
    if isinstance(error, OSError) and error.errno in {errno.EACCES, errno.EPERM}:
        return "filesystem_permission"
    if getattr(error, "domain", None) == "g-io-error-quark":
        code = getattr(error, "code", None)
        if code == 14:  # G_IO_ERROR_PERMISSION_DENIED
            return "filesystem_permission"
        if code == 1:  # G_IO_ERROR_NOT_FOUND
            return "missing"
        if code in {15, 16}:  # G_IO_ERROR_NOT_SUPPORTED / NOT_MOUNTED
            return "trash_unavailable"
    return "operation_failed"


def _failure_message(kind: str | None, details: str | None) -> str | None:
    messages = {
        "app_protected": "Item protegido pelo Clearspace.",
        "application_in_use": "Aplicação em uso; feche o aplicativo e tente novamente.",
        "outside_scan_root": "Caminho fora da raiz do scan.",
        "filesystem_permission": "Sem permissão do sistema de arquivos.",
        "trash_unavailable": "A lixeira não está disponível neste filesystem.",
        "missing": "O item não existe mais.",
    }
    if details is None:
        return None
    return f"{messages.get(kind, 'A operação falhou.')} {details}"


def gio_trash_supported(path: Path) -> bool | None:
    """Return Gio's can-trash attribute, or None if the query is unavailable."""
    try:
        import gi
        gi.require_version("Gio", "2.0")
        from gi.repository import Gio
        file = Gio.File.new_for_path(str(path))
        info = file.query_info(
            Gio.FILE_ATTRIBUTE_ACCESS_CAN_TRASH,
            Gio.FileQueryInfoFlags.NONE,
            None,
        )
        return info.get_attribute_boolean(Gio.FILE_ATTRIBUTE_ACCESS_CAN_TRASH)
    except Exception as error:
        logger.info("Could not query trash support for %s: %s", path, error)
        return None


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
