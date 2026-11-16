"""Process boundary and read-only SQLite client for the Rust scanner."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Callable

from .contracts import Node


class RustScannerError(RuntimeError):
    """The scanner process or its output violated the documented contract."""


class RustTreeScanner:
    def __init__(
        self,
        root_path: Path,
        *,
        max_visible_children: int = 100,
        binary: Path | None = None,
        progress: Callable[[dict], None] | None = None,
        cache_dir: Path | None = None,
        exclusions: tuple[Path, ...] = (),
    ) -> None:
        self.root_path = Path(root_path)
        self.max_visible_children = max_visible_children
        self.binary = binary or self._find_binary()
        if self.binary is None:
            raise RustScannerError("clearspace-scan binary was not found")
        self.progress = progress
        cache_root: Path | None
        if cache_dir is not None:
            cache_root = cache_dir
        else:
            cache_root = Path(
                os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")
            ) / "clearspace" / "scans"
            try:
                cache_inside_scan_root = cache_root.resolve().is_relative_to(
                    self.root_path.resolve()
                )
            except OSError:
                cache_inside_scan_root = True
            if cache_inside_scan_root:
                cache_root = None
        if cache_root is not None:
            try:
                cache_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            except OSError:
                if cache_dir is not None:
                    raise
                cache_root = None
        try:
            self._temporary_directory = tempfile.TemporaryDirectory(
                prefix="scan-", dir=cache_root
            )
        except OSError:
            if cache_dir is not None or cache_root is None:
                raise
            self._temporary_directory = tempfile.TemporaryDirectory(prefix="scan-")
        self.database_path = Path(self._temporary_directory.name) / "inventory.sqlite"
        self.exclusions = tuple(exclusions)
        self.report: dict[str, int | float | str] = {}
        self._closed = False

    @staticmethod
    def _find_binary() -> Path | None:
        override = os.environ.get("CLEARSPACE_SCAN_BIN")
        if override:
            path = Path(override)
            return path if path.is_file() else None
        project = Path(__file__).resolve().parent.parent / "scanner" / "target"
        for profile in ("release", "debug"):
            candidate = project / profile / "clearspace-scan"
            if candidate.is_file():
                return candidate
        located = shutil.which("clearspace-scan")
        return Path(located) if located else None

    @classmethod
    def available(cls) -> bool:
        return cls._find_binary() is not None

    def scan_root(self) -> Node:
        argv = [str(self.binary), str(self.root_path), "--db", str(self.database_path)]
        for excluded in self.exclusions:
            argv.extend(("--exclude", str(excluded)))
        try:
            process = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                shell=False,
            )
        except OSError as error:
            raise RustScannerError(f"could not start clearspace-scan: {error}") from error

        events: list[dict] = []
        terminal: dict | None = None
        started = False
        previous_progress = {key: 0 for key in ("directories", "files", "errors", "allocated_bytes")}
        try:
            assert process.stdout is not None
            for line in process.stdout:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as error:
                    raise RustScannerError("scanner emitted malformed JSONL") from error
                if not isinstance(event, dict) or event.get("protocol_version") != 1:
                    raise RustScannerError("scanner emitted an unsupported protocol event")
                if terminal is not None:
                    raise RustScannerError("scanner emitted data after its terminal event")
                kind = event.get("event")
                if not isinstance(kind, str):
                    raise RustScannerError("scanner event is missing its event name")
                if kind == "started":
                    if started or events:
                        raise RustScannerError("scanner emitted started more than once or out of order")
                    started = True
                elif not started:
                    raise RustScannerError("scanner emitted data before started")
                if kind == "progress":
                    for key in previous_progress:
                        value = event.get(key)
                        if not isinstance(value, int) or value < previous_progress[key]:
                            raise RustScannerError(f"scanner progress has invalid {key}")
                        previous_progress[key] = value
                if kind in {"completed", "failed"}:
                    terminal = event
                elif kind not in {"started", "progress"}:
                    raise RustScannerError(f"unknown scanner event: {kind}")
                events.append(event)
                if self.progress and kind == "progress":
                    self.progress(event)
            stderr = process.stderr.read() if process.stderr else ""
            status = process.wait()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        if not started:
            raise RustScannerError("scanner stream did not start with a started event")
        if terminal is None:
            raise RustScannerError("scanner stream is missing a terminal event")
        if (status == 0) != (terminal.get("event") == "completed"):
            raise RustScannerError("scanner exit status disagrees with its terminal event")
        if status != 0:
            message = terminal.get("message") or stderr.strip() or "scan failed"
            raise RustScannerError(str(message))

        self._validate_completion(terminal)
        self.report = {
            key: terminal[key]
            for key in (
                "nodes",
                "directories",
                "files",
                "errors",
                "symlinks_skipped",
                "other_filesystems_skipped",
                "allocated_bytes",
            )
        }
        self.report["elapsed_seconds"] = terminal["duration_ms"] / 1000
        self.report["backend"] = "Rust"
        self._root_id = terminal["root_id"]
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT size_blocks, mtime, error, partial FROM nodes WHERE id=?",
                (self._root_id,),
            ).fetchone()
        if row is None:
            raise RustScannerError("completed database does not contain its root node")
        return Node(
            self.root_path,
            self.root_path.name or str(self.root_path),
            True,
            row[0] * 512,
            error=row[2],
            children_loaded=False,
            size_is_partial=bool(row[3]),
            selectable=False,
        )

    @staticmethod
    def _validate_completion(event: dict) -> None:
        required = (
            "root_id",
            "nodes",
            "directories",
            "files",
            "errors",
            "symlinks_skipped",
            "other_filesystems_skipped",
            "allocated_bytes",
            "duration_ms",
        )
        for key in required:
            if not isinstance(event.get(key), int) or event[key] < 0:
                raise RustScannerError(f"completed event has invalid {key}")

    def _connect(self) -> sqlite3.Connection:
        uri = self.database_path.as_uri() + "?mode=ro"
        return sqlite3.connect(uri, uri=True)

    def expand(self, node: Node) -> list[Node]:
        if not node.is_dir or node.children_loaded:
            return node.children
        with closing(self._connect()) as connection:
            parent_id = self._node_id(node.path, connection)
            children = connection.execute(
                "SELECT id, name, is_dir, size_blocks, mtime, error, partial "
                "FROM nodes WHERE parent_id=? "
                "ORDER BY size_blocks DESC, name COLLATE BINARY ASC LIMIT ?",
                (parent_id, self.max_visible_children),
            ).fetchall()
            item_count, hidden_blocks = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(size_blocks),0) FROM ("
                "SELECT size_blocks FROM nodes WHERE parent_id=? "
                "ORDER BY size_blocks DESC, name COLLATE BINARY ASC LIMIT -1 OFFSET ?)" ,
                (parent_id, self.max_visible_children),
            ).fetchone()
        node.children = [
            Node(
                node.path / name,
                name,
                bool(is_dir),
                size_blocks * 512,
                error=error,
                children_loaded=not bool(is_dir),
                size_is_partial=bool(partial),
                selectable=error is None,
            )
            for _id, name, is_dir, size_blocks, _mtime, error, partial in children
        ]
        if item_count:
            from .contracts import Node as TreeNode

            node.children.append(
                TreeNode(
                    node.path / ".clearspace-aggregate-row",
                    f"{item_count} itens menores",
                    False,
                    hidden_blocks * 512,
                    children_loaded=True,
                    selectable=False,
                    aggregate_count=item_count,
                )
            )
        node.children_loaded = True
        return node.children

    def _node_id(self, path: Path, connection: sqlite3.Connection) -> int:
        if path == self.root_path:
            return self._root_id
        relative = path.relative_to(self.root_path)
        name = relative.name
        parent_path = self.root_path.joinpath(*relative.parts[:-1])
        parent_id = self._node_id(parent_path, connection)
        row = connection.execute(
            "SELECT id FROM nodes WHERE parent_id=? AND name=? LIMIT 1",
            (parent_id, name),
        ).fetchone()
        if row is None:
            raise RustScannerError(f"directory is missing from scan database: {path}")
        return row[0]

    def close(self) -> None:
        if not self._closed:
            self._temporary_directory.cleanup()
            self._closed = True
