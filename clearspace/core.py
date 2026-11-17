"""Local inventory, cleanup actions, and structured history for Clearspace."""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


logger = logging.getLogger(__name__)




def format_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.1f} {unit}" if unit != "B" else f"{int(amount)} B"
        amount /= 1024
    return f"{amount:.1f} TiB"


@dataclass(frozen=True)
class DirectorySize:
    bytes: int
    errors: tuple[str, ...] = ()
    missing: bool = False

    @property
    def partial(self) -> bool:
        return bool(self.errors) and not self.missing


def directory_size(path: Path) -> DirectorySize:
    """Measure a directory without following symlinks or crossing filesystems."""
    total = 0
    errors: list[str] = []

    def record_error(error: OSError) -> None:
        message = f"{error.filename or path}: {error.strerror or error}"
        errors.append(message)
        logger.warning("Could not read during scan: %s", message)

    try:
        root_info = path.lstat()
    except FileNotFoundError as error:
        record_error(error)
        return DirectorySize(0, tuple(errors), missing=True)
    except OSError as error:
        record_error(error)
        return DirectorySize(0, tuple(errors))
    if stat.S_ISLNK(root_info.st_mode):
        return DirectorySize(root_info.st_size)
    root_device = root_info.st_dev

    try:
        for current, dirs, files in os.walk(path, followlinks=False, onerror=record_error):
            current_path = Path(current)
            try:
                if current_path.stat().st_dev != root_device:
                    dirs[:] = []
                    continue
            except OSError as error:
                record_error(error)
                dirs[:] = []
                continue
            kept_dirs = []
            for name in dirs:
                candidate = current_path / name
                try:
                    info = candidate.lstat()
                except OSError as error:
                    record_error(error)
                    continue
                if stat.S_ISLNK(info.st_mode):
                    total += info.st_size
                elif info.st_dev == root_device:
                    kept_dirs.append(name)
            dirs[:] = kept_dirs
            for name in files:
                candidate = current_path / name
                try:
                    info = candidate.lstat()
                    if stat.S_ISLNK(info.st_mode):
                        total += info.st_size
                    elif info.st_dev != root_device:
                        continue
                    else:
                        total += info.st_size
                except OSError as error:
                    record_error(error)
    except OSError as error:
        record_error(error)
    return DirectorySize(total, tuple(errors))


@dataclass(frozen=True)
class Candidate:
    id: str
    title: str
    description: str
    path: str | None
    size: int | None
    command: tuple[str, ...] | None
    risk: str
    available: bool = True
    read_error: str | None = None
    partial: bool = False


def inspection_only_paths(home: Path | None = None) -> tuple[Path, ...]:
    """Return data-bearing registry roots that must remain inspection-only."""
    home = home or Path.home()
    return tuple(home / relative for relative in (
        ".local/share/Trash",
        ".cache/huggingface",
        ".local/share/PrismLauncher",
        ".config/Postman",
        ".gradle",
        ".codex",
        ".cache/yay",
    ))


def discover_candidates() -> list[Candidate]:
    home = Path.home()
    candidates: list[Candidate] = []
    inspection_paths = inspection_only_paths(home)

    def add_path(key: str, title: str, path: Path, description: str, risk: str) -> None:
        result = directory_size(path)
        errors = list(result.errors)
        if result.missing:
            candidates.append(Candidate(key, title, description, str(path), None, None, risk,
                                         False, "; ".join(errors) or "diretório inexistente"))
            return
        if path.is_symlink():
            message = f"{path}: caminho é um symlink; alvo não seguido"
            logger.warning("Could not read during scan: %s", message)
            candidates.append(Candidate(key, title, description, str(path), 0, None, risk,
                                         False, message))
            return
        candidates.append(Candidate(key, title, description, str(path), result.bytes, None, risk,
                                     True, "; ".join(errors) or None, result.partial))

    add_path("go-build", "Go build cache", home / ".cache/go-build",
             "Compiled build artifacts. Go rebuilds them as needed.", "Low risk")
    add_path("vscode-cpp", "VS Code C/C++ index cache", home / ".cache/vscode-cpptools",
             "Extension indexing data. Close VS Code first; indexes will be rebuilt.", "Moderate risk")
    add_path("trash", "Trash", inspection_paths[0],
             "Files here may still be wanted. Review them in your file manager.", "Personal data · inspect only")
    add_path("huggingface", "Hugging Face files", inspection_paths[1],
             "May contain large models and datasets that are expensive to download again.", "Personal data · inspect only")
    add_path("prism", "PrismLauncher data", inspection_paths[2],
             "May contain Minecraft worlds, instances, and modpacks.", "Personal data · inspect only")
    add_path("postman", "Postman data", inspection_paths[3],
             "May contain local settings, workspaces, and application data.", "Personal data · inspect only")
    add_path("gradle", "Gradle data", inspection_paths[4],
             "May contain build caches, wrapper distributions, and project state.", "Personal data · inspect only")
    add_path("codex", "Codex data", inspection_paths[5],
             "May contain local configuration and user data.", "Personal data · inspect only")
    add_path("yay", "yay package cache", inspection_paths[6],
             "May contain package build files and cached sources.", "Personal data · inspect only")

    if shutil.which("go"):
        candidates.append(Candidate("go-clean", "Go build cache (Go tool)", None,
            "Use Go's own cache cleanup command.", None, ("go", "clean", "-cache"), "Low risk"))
    if shutil.which("pnpm"):
        candidates.append(Candidate("pnpm-prune", "Unused pnpm store packages", None,
            "Prune packages pnpm considers unreferenced by known projects.", None,
            ("pnpm", "store", "prune"), "Moderate risk"))
    if shutil.which("docker"):
        try:
            result = subprocess.run(["docker", "system", "df"], capture_output=True,
                                    text=True, timeout=10, check=False)
            if result.returncode == 0:
                inventory = result.stdout.strip() or "Docker returned no inventory details."
                candidates.append(Candidate("docker-inventory", "Docker disk usage", inventory,
                    None, None, None, "Personal data · inspect only"))
            else:
                error = (result.stderr.strip() or result.stdout.strip()
                         or f"docker system df exited with status {result.returncode}")
                logger.warning("Docker inventory failed: %s", error)
                candidates.append(Candidate("docker-inventory", "Docker disk usage",
                    "Não foi possível ler: " + error, None, None, None,
                    "Personal data · inspect only", read_error=error))
        except (OSError, subprocess.SubprocessError) as error:
            message = str(error)
            logger.warning("Docker inventory failed: %s", message)
            candidates.append(Candidate("docker-inventory", "Docker disk usage",
                "Não foi possível ler: " + message, None, None, None,
                "Personal data · inspect only", read_error=message))
        candidates.append(Candidate("docker-build", "Docker build cache", None,
            "Remove unused build cache. Future image builds may take longer.", None,
            ("docker", "builder", "prune", "-a", "-f"), "Moderate risk"))
    if shutil.which("npm"):
        npm_cache = subprocess.run(["npm", "config", "get", "cache"], capture_output=True, text=True, timeout=5)
        cache_path = Path(npm_cache.stdout.strip()).expanduser() if npm_cache.returncode == 0 else home / ".npm"
        add_path("npm-cache", "npm cache", cache_path,
                 "Cached packages can be downloaded again. npm cache verify is a non-destructive alternative.", "Low risk")
    if shutil.which("journalctl"):
        result = subprocess.run(["journalctl", "--disk-usage"], capture_output=True, text=True, timeout=5)
        amount = None
        if result.returncode == 0:
            import re
            match = re.search(r"([\d.]+)\s*(B|K|M|G|T)B?", result.stdout, re.I)
            if match:
                amount = int(float(match.group(1)) * (1024 ** ("BKMGT".index(match.group(2).upper()))))
        candidates.append(Candidate("journal", "System journal", None,
            "Reduce archived logs to approximately 200 MiB. Requires administrator access, so this app does not execute it.",
            amount, None, "System action · inspect only", shutil.which("journalctl") is not None))
    return candidates


class History:
    def __init__(self, path: Path | None = None):
        self.path = path or Path.home() / ".local/share/clearspace/history.jsonl"

    def append(self, record: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    def record_scan(
        self,
        path: Path,
        size_bytes: int,
        *,
        partial: bool = False,
        timestamp: float | None = None,
        directories: int | None = None,
    ) -> None:
        """Remember scan metadata locally without storing file contents."""
        record = {
            "schema_version": 1,
            "record_type": "scan",
            "timestamp": time.time() if timestamp is None else timestamp,
            "path": str(path),
            "size_bytes": max(0, int(size_bytes)),
            "partial": bool(partial),
        }
        if directories is not None:
            record["directories"] = max(0, int(directories))
        self.append(record)

    def latest_scan(self) -> dict | None:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return None
        for line in reversed(lines):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (
                isinstance(record, dict)
                and record.get("record_type") == "scan"
                and isinstance(record.get("path"), str)
                and isinstance(record.get("size_bytes"), int)
                and record["size_bytes"] >= 0
                and isinstance(record.get("timestamp"), (int, float))
            ):
                return record
        return None

    def latest_scan_for(self, path: Path) -> dict | None:
        """Return the latest complete scan with a directory count for this root."""
        try:
            requested = Path(path).resolve()
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except (FileNotFoundError, OSError):
            return None
        for line in reversed(lines):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            if (
                record.get("record_type") != "scan"
                or record.get("partial") is True
                or type(record.get("directories")) is not int
                or record["directories"] < 0
                or not isinstance(record.get("path"), str)
            ):
                continue
            try:
                recorded_path = Path(record["path"]).resolve()
            except OSError:
                continue
            if recorded_path == requested:
                return record
        return None

    def recent(self, limit: int = 8) -> list[dict]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        records = []
        for line in reversed(lines):
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if len(records) >= limit:
                break
        return records


def execute_cleanup(candidate: Candidate, history: History,
                    on_finish: Callable[[dict], None]) -> None:
    """Block the legacy bulk-command path in favor of reviewed item actions."""
    if candidate.command is None:
        raise ValueError("This candidate has no executable cleanup action")
    started = time.time()
    record = {
        "schema_version": 2,
        "action_id": candidate.id,
        "title": candidate.title,
        "path": candidate.path,
        "size_bytes": candidate.size,
        "action": "blocked_legacy_command",
        "started_at": started,
        "finished_at": time.time(),
        "result": "failed",
        "exit_code": 126,
        "failure_details": (
            "Execução direta de comandos foi desativada. Use a revisão item a item "
            "com o executor seguro."
        ),
    }
    history.append(record)
    on_finish(record)
