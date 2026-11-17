"""GTK-free scan-root validation, XDG locations, and scan option helpers."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from .executor import SYSTEM_PROTECTED


class ScanRootError(ValueError):
    """A selected scan root is missing, unsafe, or not a directory."""


@dataclass(frozen=True, slots=True)
class ScanOptions:
    include_hidden: bool = True
    stay_on_disk_only: bool = True


def scanner_arguments(options: ScanOptions) -> dict[str, bool]:
    """Map user-facing scan options to the Python scanner keyword arguments."""
    return {
        "include_hidden": options.include_hidden,
        "stay_on_device": options.stay_on_disk_only,
    }


def validate_scan_root(
    path: str | Path,
    *,
    protected_roots: Iterable[str | Path] = SYSTEM_PROTECTED,
) -> Path:
    """Canonicalize an existing real directory and reject protected roots.

    Every component is checked with ``lstat`` before resolving so selecting a
    symlink cannot silently redirect the scanner to its target.
    """
    canonical = canonical_directory(path)
    for protected_value in protected_roots:
        protected = Path(protected_value).resolve(strict=False)
        if protected == Path("/"):
            blocked = canonical == protected
        else:
            blocked = canonical == protected or canonical.is_relative_to(protected)
        if blocked:
            raise ScanRootError("This system folder is protected. Choose a user folder instead.")
    return canonical


def canonical_directory(path: str | Path) -> Path:
    """Return an existing canonical directory, rejecting symlink components."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    if ".." in candidate.parts:
        raise ScanRootError("Choose a folder path without '..' components.")
    candidate = Path(os.path.normpath(candidate))

    current = Path(candidate.anchor)
    for index, component in enumerate(candidate.parts[1:]):
        current = current / component
        try:
            info = current.lstat()
        except OSError as error:
            raise ScanRootError(f"Cannot access this folder: {error.strerror or error}.") from error
        if stat.S_ISLNK(info.st_mode):
            raise ScanRootError("Choose a real folder; symbolic links are not scanned.")
        if index < len(candidate.parts[1:]) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ScanRootError("The selected path contains a non-folder component.")

    try:
        canonical = candidate.resolve(strict=True)
    except OSError as error:
        raise ScanRootError(f"This folder is unavailable: {error.strerror or error}.") from error
    if not canonical.is_dir():
        raise ScanRootError("Choose an existing folder to scan.")
    return canonical


def resolve_xdg_locations(
    *,
    home_dir: str | Path,
    cache_dir: str | Path | None,
    downloads_dir: str | Path | None,
    config_dir: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Path | None]:
    """Resolve Home, XDG cache, and Downloads paths supplied by GLib/XDG.

    GLib provides the primary values. Standard XDG fallbacks are used for the
    cache and user Downloads directory when GLib has no configured value.
    """
    env = os.environ if environ is None else environ
    home = Path(home_dir).expanduser()
    if not home.is_absolute():
        raise ValueError("GLib home directory must be absolute")

    cache: Path | None
    if cache_dir:
        cache = Path(cache_dir).expanduser()
    else:
        configured_cache = env.get("XDG_CACHE_HOME", "").strip()
        cache = Path(configured_cache).expanduser() if configured_cache else home / ".cache"
        if not cache.is_absolute():
            cache = home / ".cache"

    downloads = Path(downloads_dir).expanduser() if downloads_dir else None
    if downloads is None and config_dir:
        downloads = _read_xdg_download_dir(Path(config_dir), home)
    return {"home": home, "caches": cache, "downloads": downloads}


def _read_xdg_download_dir(config_dir: Path, home: Path) -> Path | None:
    user_dirs_file = config_dir / "user-dirs.dirs"
    try:
        lines = user_dirs_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        key, separator, raw_value = line.partition("=")
        if not separator or key.strip() != "XDG_DOWNLOAD_DIR":
            continue
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        value = value.replace("${HOME}", str(home)).replace("$HOME", str(home))
        if "$" in value or "`" in value:
            return None
        result = Path(value).expanduser()
        return result if result.is_absolute() else home / result
    return None


def recent_scan_record(records: Iterable[dict]) -> dict | None:
    """Return the newest well-formed local scan record from newest-first JSONL."""
    for record in records:
        if (
            record.get("record_type") == "scan"
            and isinstance(record.get("path"), str)
            and isinstance(record.get("size_bytes"), int)
            and record["size_bytes"] >= 0
            and isinstance(record.get("timestamp"), (int, float))
        ):
            return record
    return None


def format_age(seconds: float) -> str:
    age = max(0, int(seconds))
    if age < 60:
        return "just now"
    if age < 3600:
        return f"{age // 60} min ago"
    if age < 86400:
        return f"{age // 3600} hr ago"
    days = age // 86400
    return f"{days} day ago" if days == 1 else f"{days} days ago"
