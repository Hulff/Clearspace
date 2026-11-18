"""Pure, GTK-free command generator for reviewed Clearspace rows."""

from __future__ import annotations

import errno
import os
import shlex
import stat
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .core import format_bytes
from .provider_contract import ClassifiedError, ProtectedPath, Row

SCRIPT_HEADER_COMMENT = "# Clearspace — revise cada comando antes de colar no terminal."
ADMIN_SECTION_HEADER = "# === Requer administrador (revise com atenção) ==="
DF_SPACE_CHECK_COMMAND = "df -h --output=avail /"

_VALID_RISKS = frozenset({"low", "medium", "high", "critical"})
_ALLOWED_TOOL_BINARIES = frozenset(
    {
        "pip",
        "go",
        "pnpm",
        "npm",
        "journalctl",
        "docker",
        "paccache",
        "pacman",
    }
)
_ALLOWED_DOCKER_SUBCOMMANDS = frozenset(
    {
        ("image", "prune"),
        ("container", "prune"),
        ("builder", "prune"),
    }
)
_UNSAFE_UNICODE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})

_SYSTEM_EXACT_PROTECTED = ("/",)
_SYSTEM_SUBTREE_PROTECTED = (
    "/usr",
    "/etc",
    "/boot",
    "/var",
    "/proc",
    "/sys",
    "/dev",
    "/run",
)
_HOME_SUBTREE_PROTECTED = (
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
    (".config", "user configuration"),
    (".config/Code/User", "VS Code user data"),
    (".config/credentials", "user credentials"),
    (".config/gcloud", "Google Cloud credentials"),
    (".vscode", "VS Code extensions and user state"),
    (".mozilla", "Firefox browser profiles"),
    (".cache/huggingface", "Hugging Face models"),
    (".local/share/huggingface", "Hugging Face models and datasets"),
    (".local/share/docker/volumes", "rootless Docker volumes"),
    (".local/share/containers/storage/volumes", "rootless container volumes"),
    (".local/share/keyrings", "desktop keyring"),
    (".local/share/Trash", "user Trash"),
)


@dataclass(frozen=True, slots=True)
class BlockedItem:
    """A selected row rejected during command generation."""

    row_id: str
    label: str
    reason: ClassifiedError


@dataclass(frozen=True, slots=True)
class GeneratedItem:
    """A validated row rendered into a single independent shell command."""

    row_id: str
    label: str
    action: Literal["trash_path", "tool_command"]
    size_bytes: int | None
    needs_admin: bool
    command_line: str


@dataclass(frozen=True, slots=True)
class CommandGenerationResult:
    """Complete output of command generation for the review screen."""

    script: str
    generated: tuple[GeneratedItem, ...]
    blocked: tuple[BlockedItem, ...]
    warnings: tuple[str, ...] = ()
    user_script: str = ""
    admin_script: str = ""


@dataclass(frozen=True, slots=True)
class _ValidatedCandidate:
    row: Row
    item: GeneratedItem
    canonical_trash_path: Path | None = None


def default_protected_paths(home: Path | None = None) -> tuple[ProtectedPath, ...]:
    """Build the runtime canonicalized protected-path policy."""
    resolved_home = (home if home is not None else Path.home()).resolve(strict=False)
    rules: list[ProtectedPath] = []
    for raw in _SYSTEM_EXACT_PROTECTED:
        rules.append(
            ProtectedPath(
                path=Path(raw).resolve(strict=False),
                rule=f"system root {raw}",
                include_descendants=False,
            )
        )
    for raw in _SYSTEM_SUBTREE_PROTECTED:
        rules.append(
            ProtectedPath(
                path=Path(raw).resolve(strict=False),
                rule=f"system directory {raw}",
                include_descendants=True,
            )
        )
    rules.append(
        ProtectedPath(
            path=resolved_home,
            rule="user home directory",
            include_descendants=False,
        )
    )
    for relative, description in _HOME_SUBTREE_PROTECTED:
        rules.append(
            ProtectedPath(
                path=resolved_home / relative,
                rule=description,
                include_descendants=True,
            )
        )
    return tuple(rules)


def generate_commands(
    rows: Sequence[Row],
    *,
    protected_paths: Sequence[ProtectedPath] | None = None,
) -> CommandGenerationResult:
    """Validate selected rows and build a copy-only script of independent commands."""
    policy = _normalize_policy(
        default_protected_paths() if protected_paths is None else protected_paths
    )
    validated: list[_ValidatedCandidate] = []
    blocked: list[BlockedItem] = []

    for row in rows:
        safe_id = _sanitize_for_error_display(row.id)
        safe_label = _sanitize_for_error_display(row.label)
        unsafe_error = _check_row_strings(row)
        if unsafe_error is not None:
            blocked.append(BlockedItem(row_id=safe_id, label=safe_label, reason=unsafe_error))
            continue

        if row.error is not None:
            sanitized_reason = ClassifiedError(
                kind=row.error.kind,
                message=_sanitize_for_error_display(row.error.message),
                path=row.error.path,
                errno=row.error.errno,
            )
            blocked.append(BlockedItem(row_id=row.id, label=row.label, reason=sanitized_reason))
            continue

        if row.risk not in _VALID_RISKS:
            blocked.append(
                BlockedItem(
                    row_id=row.id,
                    label=row.label,
                    reason=ClassifiedError("invalid_row", "Nível de risco inválido."),
                )
            )
            continue

        if row.risk == "critical":
            blocked.append(
                BlockedItem(
                    row_id=row.id,
                    label=row.label,
                    reason=ClassifiedError(
                        "critical", "Itens de risco crítico são bloqueados pelo Clearspace."
                    ),
                )
            )
            continue

        if row.action == "inspect_only":
            blocked.append(
                BlockedItem(
                    row_id=row.id,
                    label=row.label,
                    reason=ClassifiedError(
                        "inspect_only",
                        "Item somente para inspeção; nenhum comando é gerado.",
                    ),
                )
            )
            continue

        if row.action == "trash_path":
            candidate_or_error = _validate_trash_row(row, policy)
        elif row.action == "tool_command":
            candidate_or_error = _validate_tool_row(row)
        else:
            candidate_or_error = ClassifiedError("invalid_row", "Ação desconhecida na linha.")

        if isinstance(candidate_or_error, ClassifiedError):
            blocked.append(BlockedItem(row_id=row.id, label=row.label, reason=candidate_or_error))
        else:
            validated.append(candidate_or_error)

    surviving = _deduplicate_covered_trash_paths(validated)
    generated = tuple(entry.item for entry in surviving)
    warnings = _collect_warnings(surviving)
    user_items = tuple(item for item in generated if not item.needs_admin)
    admin_items = tuple(item for item in generated if item.needs_admin)
    user_script = _render_block(user_items) if user_items else ""
    admin_script = _render_block(admin_items) if admin_items else ""
    script = _render_block(generated) if generated else ""

    return CommandGenerationResult(
        script=script,
        generated=generated,
        blocked=tuple(blocked),
        warnings=warnings,
        user_script=user_script,
        admin_script=admin_script,
    )


def _has_unsafe_characters(value: str) -> bool:
    if "\x00" in value or "\n" in value or "\r" in value:
        return True
    for ch in value:
        if unicodedata.category(ch) in _UNSAFE_UNICODE_CATEGORIES:
            return True
    return False


def _sanitize_for_error_display(value: str) -> str:
    if not isinstance(value, str):
        return "<inválido>"
    cleaned = "".join(
        ch
        for ch in value
        if ch not in ("\x00", "\n", "\r")
        and unicodedata.category(ch) not in _UNSAFE_UNICODE_CATEGORIES
    )
    return cleaned or "<nome bloqueado>"


def _check_row_strings(row: Row) -> ClassifiedError | None:
    if not isinstance(row.id, str) or not row.id or _has_unsafe_characters(row.id):
        return ClassifiedError(
            "unsafe_name",
            "Identificador do item contém caracteres de controle ou inválidos.",
        )
    if not isinstance(row.label, str) or not row.label or _has_unsafe_characters(row.label):
        return ClassifiedError(
            "unsafe_name",
            "Rótulo do item contém quebra de linha, NUL ou caractere de controle.",
        )
    if row.path is not None:
        raw_path = os.fspath(row.path)
        if not isinstance(raw_path, str) or _has_unsafe_characters(raw_path):
            return ClassifiedError(
                "unsafe_name",
                "Caminho contém quebra de linha, NUL, surrogate ou caractere de controle.",
            )
    if row.allowed_root is not None:
        raw_root = os.fspath(row.allowed_root)
        if not isinstance(raw_root, str) or _has_unsafe_characters(raw_root):
            return ClassifiedError(
                "unsafe_name",
                "Raiz permitida contém caractere de controle ou inválido.",
            )
    if row.argv is not None:
        for arg in row.argv:
            if not isinstance(arg, str) or _has_unsafe_characters(arg):
                return ClassifiedError(
                    "unsafe_name",
                    "Comando contém quebra de linha, NUL ou caractere de controle.",
                )
    for warning in row.warnings:
        if not isinstance(warning, str) or _has_unsafe_characters(warning):
            return ClassifiedError(
                "unsafe_name",
                "Aviso do item contém caractere de controle ou inválido.",
            )
    return None


def _normalize_policy(
    protected_paths: Sequence[ProtectedPath],
) -> tuple[ProtectedPath, ...]:
    normalized: list[ProtectedPath] = []
    seen: set[tuple[Path, bool]] = set()
    for entry in protected_paths:
        for candidate_path in (entry.path, _canonicalize_policy_path(entry.path)):
            key = (candidate_path, entry.include_descendants)
            if key not in seen:
                seen.add(key)
                normalized.append(
                    ProtectedPath(
                        path=candidate_path,
                        rule=entry.rule,
                        include_descendants=entry.include_descendants,
                    )
                )
    return tuple(normalized)


def _canonicalize_policy_path(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except OSError:
        return path


def _match_protected(
    path: Path,
    policy: tuple[ProtectedPath, ...],
    *,
    check_enclosing_directory: bool = False,
) -> ProtectedPath | None:
    for rule in policy:
        if rule.include_descendants:
            if path.is_relative_to(rule.path):
                return rule
        elif path == rule.path:
            return rule
        if check_enclosing_directory and rule.path != path and rule.path.is_relative_to(path):
            return rule
    return None


def _has_git_marker(directory: Path) -> bool:
    try:
        (directory / ".git").lstat()
        return True
    except OSError:
        return False


def _validate_tool_row(row: Row) -> _ValidatedCandidate | ClassifiedError:
    if row.path is not None or row.allowed_root is not None:
        return ClassifiedError(
            "invalid_row", "Comando de ferramenta não pode carregar caminho direto."
        )
    if not row.argv:
        return ClassifiedError("invalid_row", "Comando de ferramenta sem argumentos fixos.")
    binary = row.argv[0]
    if (
        not binary
        or "/" in binary
        or binary.startswith("-")
        or binary not in _ALLOWED_TOOL_BINARIES
    ):
        return ClassifiedError(
            "invalid_row",
            "Executável fora da lista fixa permitida no registry.",
        )
    for arg in row.argv:
        if not arg or "{" in arg or "}" in arg:
            return ClassifiedError(
                "invalid_row",
                "Argumentos dinâmicos ou placeholders não são permitidos.",
            )

    if binary == "docker":
        if any("volume" in arg.casefold() for arg in row.argv[1:]):
            return ClassifiedError(
                "invalid_row",
                "Volumes Docker são somente para inspeção e nunca geram comando.",
            )
        if tuple(row.argv[1:3]) not in _ALLOWED_DOCKER_SUBCOMMANDS:
            return ClassifiedError(
                "invalid_row",
                "Subcomando Docker fora do contrato permitido.",
            )

    full_argv = ("sudo", *row.argv) if row.needs_admin else tuple(row.argv)
    command_line = shlex.join(full_argv)
    return _ValidatedCandidate(
        row=row,
        item=GeneratedItem(
            row_id=row.id,
            label=row.label,
            action="tool_command",
            size_bytes=row.size_bytes,
            needs_admin=bool(row.needs_admin),
            command_line=command_line,
        ),
    )


def _validate_trash_row(
    row: Row,
    policy: tuple[ProtectedPath, ...],
) -> _ValidatedCandidate | ClassifiedError:
    if row.argv is not None or row.needs_admin:
        return ClassifiedError(
            "invalid_row",
            "Ação de lixeira não aceita argv nem elevação de administrador.",
        )
    if row.path is None or row.allowed_root is None:
        return ClassifiedError(
            "invalid_row",
            "Caminho e raiz permitida são obrigatórios para mover para a lixeira.",
        )

    candidate = row.path
    allowed_root = row.allowed_root

    if not candidate.is_absolute() or not allowed_root.is_absolute():
        return ClassifiedError(
            "outside_root",
            "Caminho e raiz permitida devem ser absolutos.",
            path=candidate,
        )

    if ".." in candidate.parts or ".." in allowed_root.parts:
        return ClassifiedError(
            "outside_root",
            "Segmentos '..' não são permitidos em caminhos selecionados.",
            path=candidate,
        )

    lexical_protected = _match_protected(
        candidate, policy, check_enclosing_directory=True
    )
    if lexical_protected is not None:
        return ClassifiedError(
            "protected",
            f"Caminho protegido ({lexical_protected.rule}).",
            path=candidate,
        )

    try:
        root_stat = allowed_root.lstat()
    except OSError as error:
        return _classify_os_error(error, allowed_root)

    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        return ClassifiedError(
            "symlink" if stat.S_ISLNK(root_stat.st_mode) else "invalid_row",
            "A raiz permitida deve ser um diretório real, sem symlink.",
            path=allowed_root,
        )

    try:
        canonical_root = allowed_root.resolve(strict=True)
    except OSError as error:
        return _classify_os_error(error, allowed_root)

    root_protected = _match_protected(canonical_root, policy)
    if root_protected is not None and root_protected.include_descendants:
        return ClassifiedError(
            "protected",
            f"Raiz protegida ({root_protected.rule}).",
            path=canonical_root,
        )

    if not candidate.is_relative_to(allowed_root) or candidate == allowed_root:
        return ClassifiedError(
            "outside_root",
            "Caminho fora da raiz permitida.",
            path=candidate,
        )

    if _has_git_marker(canonical_root):
        return ClassifiedError(
            "inspect_only",
            "Repositórios Git são somente para inspeção.",
            path=candidate,
        )

    relative_parts = candidate.relative_to(allowed_root).parts
    current = allowed_root
    for part in relative_parts:
        current = current / part
        if part == "node_modules":
            return ClassifiedError(
                "inspect_only",
                "Dependências node_modules são somente para inspeção.",
                path=current,
            )
        try:
            comp_stat = current.lstat()
        except OSError as error:
            return _classify_os_error(error, current)
        if stat.S_ISLNK(comp_stat.st_mode):
            return _classify_symlink_component(current, canonical_root, policy)
        if comp_stat.st_dev != root_stat.st_dev:
            return ClassifiedError(
                "outside_root",
                "Caminho atravessa outro filesystem.",
                path=current,
            )
        if stat.S_ISDIR(comp_stat.st_mode) and _has_git_marker(current):
            return ClassifiedError(
                "inspect_only",
                "Repositórios Git são somente para inspeção.",
                path=current,
            )

    try:
        canonical = candidate.resolve(strict=True)
        final_stat = canonical.lstat()
    except OSError as error:
        return _classify_os_error(error, candidate)

    if stat.S_ISLNK(final_stat.st_mode):
        return _classify_symlink_component(canonical, canonical_root, policy)

    if not canonical.is_relative_to(canonical_root) or canonical == canonical_root:
        return ClassifiedError(
            "outside_root",
            "Caminho canonicalizado escapou da raiz permitida.",
            path=canonical,
        )

    protected_hit = _match_protected(
        canonical, policy, check_enclosing_directory=True
    )
    if protected_hit is not None:
        return ClassifiedError(
            "protected",
            f"Caminho protegido ({protected_hit.rule}).",
            path=canonical,
        )

    if final_stat.st_dev != root_stat.st_dev:
        return ClassifiedError(
            "outside_root",
            "Caminho está em outro filesystem.",
            path=canonical,
        )

    if not stat.S_ISREG(final_stat.st_mode) and not stat.S_ISDIR(final_stat.st_mode):
        return ClassifiedError(
            "invalid_row",
            "Somente arquivos regulares e diretórios podem ir para a lixeira.",
            path=canonical,
        )

    canonical_str = str(canonical)
    if _has_unsafe_characters(canonical_str):
        return ClassifiedError(
            "unsafe_name",
            "Caminho canonicalizado contém caractere de controle ou inválido.",
            path=canonical,
        )

    command_line = f"gio trash -- {shlex.quote(canonical_str)}"
    return _ValidatedCandidate(
        row=row,
        item=GeneratedItem(
            row_id=row.id,
            label=row.label,
            action="trash_path",
            size_bytes=row.size_bytes,
            needs_admin=False,
            command_line=command_line,
        ),
        canonical_trash_path=canonical,
    )


def _classify_symlink_component(
    symlink_path: Path,
    canonical_root: Path,
    policy: tuple[ProtectedPath, ...],
) -> ClassifiedError:
    try:
        target = symlink_path.resolve(strict=False)
    except OSError:
        return ClassifiedError(
            "symlink",
            "Symlink não pode ser resolvido com segurança.",
            path=symlink_path,
        )

    protected_hit = _match_protected(
        target, policy, check_enclosing_directory=True
    )
    if protected_hit is not None:
        return ClassifiedError(
            "protected",
            f"Symlink aponta para caminho protegido ({protected_hit.rule}).",
            path=symlink_path,
        )

    if not target.is_relative_to(canonical_root) or target == canonical_root:
        return ClassifiedError(
            "outside_root",
            "Symlink aponta para fora da raiz permitida.",
            path=symlink_path,
        )

    return ClassifiedError(
        "symlink",
        "Symlinks são bloqueados na geração de comandos.",
        path=symlink_path,
    )


def _classify_os_error(error: OSError, path: Path) -> ClassifiedError:
    err_no = error.errno
    if isinstance(error, PermissionError) or err_no in {errno.EACCES, errno.EPERM}:
        return ClassifiedError(
            "permission",
            "Sem permissão para validar o caminho no sistema de arquivos.",
            path=path,
            errno=err_no,
        )
    if isinstance(error, FileNotFoundError) or err_no in {errno.ENOENT, errno.ENOTDIR}:
        return ClassifiedError(
            "not_found",
            "O item não existe mais no sistema de arquivos.",
            path=path,
            errno=err_no,
        )
    return ClassifiedError(
        "unexpected",
        "Falha ao inspecionar metadados do caminho.",
        path=path,
        errno=err_no,
    )


def _deduplicate_covered_trash_paths(
    candidates: list[_ValidatedCandidate],
) -> list[_ValidatedCandidate]:
    trash_paths = [
        entry.canonical_trash_path
        for entry in candidates
        if entry.canonical_trash_path is not None
    ]
    seen_trash: set[Path] = set()
    kept: list[_ValidatedCandidate] = []
    for entry in candidates:
        path = entry.canonical_trash_path
        if path is None:
            kept.append(entry)
            continue
        if path in seen_trash:
            continue
        if any(other != path and path.is_relative_to(other) for other in trash_paths):
            continue
        seen_trash.add(path)
        kept.append(entry)
    return kept


def _collect_warnings(candidates: list[_ValidatedCandidate]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for entry in candidates:
        for warning in entry.row.warnings:
            seen.setdefault(warning, None)
    return tuple(seen)


def _render_block(items: tuple[GeneratedItem, ...] | list[GeneratedItem]) -> str:
    """Render independent command lines without `#` comments so interactive zsh/bash can paste safely."""
    lines: list[str] = [DF_SPACE_CHECK_COMMAND]
    for item in items:
        lines.append(item.command_line)
    lines.append(DF_SPACE_CHECK_COMMAND)
    return "\n".join(lines) + "\n"


def _render_script(generated: tuple[GeneratedItem, ...]) -> str:
    return _render_block(generated)
