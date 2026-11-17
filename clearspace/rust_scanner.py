"""Process boundary and read-only SQLite client for the Rust scanner."""

from __future__ import annotations

import json
import os
import signal
import shutil
import sqlite3
import subprocess
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Callable

from .contracts import Node
from .progress import ProgressEvent, ScanState


class RustScannerError(RuntimeError):
    """The scanner process or its output violated the documented contract."""


def progress_event_from_rust(
    event: dict,
    *,
    elapsed_ms: int,
    prior_directories: int | None = None,
) -> ProgressEvent:
    """Validate and adapt one Rust protocol-v2 live progress snapshot."""
    if event.get("protocol_version") != 2 or event.get("event") != "progress":
        raise ValueError("unsupported Rust progress event")
    counters = (
        "dirs_done",
        "dirs_queued",
        "dirs_total_est",
        "files",
        "allocated_bytes",
        "errors",
    )
    values: dict[str, int] = {}
    for key in counters:
        value = event.get(key)
        if type(value) is not int or value < 0:
            raise ValueError(f"Rust progress event has invalid {key}")
        values[key] = value
    if values["dirs_done"] + values["dirs_queued"] != values["dirs_total_est"]:
        raise ValueError("Rust progress directory estimate is inconsistent")
    current_path = event.get("current_path")
    if not isinstance(current_path, str):
        raise ValueError("Rust progress event has invalid current_path")
    items = event.get("largest_items")
    if not isinstance(items, list) or len(items) > 4:
        raise ValueError("Rust progress event has invalid largest_items")
    largest_items = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Rust progress event has invalid largest_items entry")
        name, path, size = item.get("name"), item.get("path"), item.get("bytes")
        if (
            not isinstance(name, str)
            or not isinstance(path, str)
            or type(size) is not int
            or size < 0
        ):
            raise ValueError("Rust progress event has invalid largest_items entry")
        largest_items.append((name, path, size))
    total = values["dirs_total_est"]
    if prior_directories is not None:
        total = max(total, max(0, int(prior_directories)))
    return ProgressEvent(
        dirs_done=values["dirs_done"],
        dirs_total_est=total,
        files=values["files"],
        bytes=values["allocated_bytes"],
        elapsed_ms=max(0, int(elapsed_ms)),
        current_path=current_path,
        state=ScanState.RUNNING,
        partial=values["errors"] > 0,
        largest_items=tuple(largest_items),
    )


class RustTreeScanner:
    def __init__(
        self,
        root_path: Path,
        *,
        max_visible_children: int = 200,
        binary: Path | None = None,
        progress: Callable[[dict], None] | None = None,
        cache_dir: Path | None = None,
        exclusions: tuple[Path, ...] = (),
        include_hidden: bool = True,
        stay_on_device: bool = True,
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
        self.include_hidden = include_hidden
        self.stay_on_device = stay_on_device
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

    def scan_root(self, *, cancel_event=None, pause_event=None) -> Node:
        argv = [str(self.binary), str(self.root_path), "--db", str(self.database_path)]
        if not self.include_hidden:
            argv.append("--exclude-hidden")
        if not self.stay_on_device:
            argv.append("--cross-filesystems")
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
        previous_progress = {
            key: 0
            for key in (
                "directories",
                "dirs_done",
                "dirs_total_est",
                "files",
                "errors",
                "allocated_bytes",
            )
        }
        try:
            assert process.stdout is not None
            for line in process.stdout:
                if cancel_event is not None and cancel_event.is_set():
                    process.terminate()
                    process.wait()
                    raise RustScannerError("scan cancelled")
                if pause_event is not None and not pause_event.is_set():
                    process.send_signal(signal.SIGSTOP)
                    while not pause_event.wait(timeout=0.1):
                        if cancel_event is not None and cancel_event.is_set():
                            process.terminate()
                            process.wait()
                            raise RustScannerError("scan cancelled")
                    process.send_signal(signal.SIGCONT)
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as error:
                    raise RustScannerError("scanner emitted malformed JSONL") from error
                if not isinstance(event, dict) or event.get("protocol_version") != 2:
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
                    try:
                        progress_event_from_rust(event, elapsed_ms=0)
                    except ValueError as error:
                        raise RustScannerError(str(error)) from error
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
                "dirs_done",
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
                "SELECT size_blocks, mtime, error, partial, child_count, child_size_blocks "
                "FROM nodes WHERE id=?",
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
            node_id=self._root_id,
            child_count=row[4],
            child_size_bytes=row[5] * 512,
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
            "dirs_done",
            "dirs_queued",
            "dirs_total_est",
            "duration_ms",
        )
        for key in required:
            if type(event.get(key)) is not int or event[key] < 0:
                raise RustScannerError(f"completed event has invalid {key}")
        if event["dirs_queued"] != 0 or event["dirs_done"] != event["dirs_total_est"]:
            raise RustScannerError("completed event has inconsistent directory estimate")
        if not isinstance(event["current_path"], str):
            raise RustScannerError("completed event has invalid current_path")
        if not isinstance(event["largest_items"], list) or len(event["largest_items"]) > 4:
            raise RustScannerError("completed event has invalid largest_items")
        for item in event["largest_items"]:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("name"), str)
                or not isinstance(item.get("path"), str)
                or type(item.get("bytes")) is not int
                or item["bytes"] < 0
            ):
                raise RustScannerError("completed event has invalid largest_items entry")

    def _connect(self) -> sqlite3.Connection:
        uri = self.database_path.as_uri() + "?mode=ro"
        return sqlite3.connect(uri, uri=True)

    def _expand_legacy(self, node: Node) -> list[Node]:
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

    def expand(self, node: Node) -> list[Node]:
        if not node.is_dir or node.children_loaded:
            return node.children
        node.children = self.load_children_page(
            node,
            offset=0,
            limit=self.max_visible_children,
            include_more=False,
        )
        node.children_loaded = True
        return node.children

    def load_children_page(
        self,
        node: Node,
        *,
        offset: int = 0,
        limit: int | None = None,
        include_more: bool = True,
    ) -> list[Node]:
        """Read one size-sorted child page from the private scan database."""
        if not node.is_dir or offset < 0:
            return []
        page_size = self.max_visible_children if limit is None else max(1, int(limit))
        parent_id = node.node_id
        with closing(self._connect()) as connection:
            if parent_id is None:
                parent_id = self._node_id(node.path, connection)
            rows = connection.execute(
                "SELECT id,parent_id,name,is_dir,size_blocks,error,partial,child_count,child_size_blocks "
                "FROM nodes WHERE parent_id=? "
                "ORDER BY size_blocks DESC, name COLLATE BINARY ASC LIMIT ? OFFSET ?",
                (parent_id, page_size, offset),
            ).fetchall()
        page = [
            Node(
                node.path / name,
                name,
                bool(is_dir),
                size_blocks * 512,
                error=error,
                children_loaded=not bool(is_dir),
                size_is_partial=bool(partial),
                selectable=error is None,
                node_id=node_id,
                parent_id=row_parent_id,
                child_count=child_count,
                child_size_bytes=child_size_blocks * 512,
            )
            for (
                node_id, row_parent_id, name, is_dir, size_blocks, error,
                partial, child_count, child_size_blocks,
            ) in rows
        ]
        remaining_count = max(0, node.child_count - offset - len(page))
        if remaining_count:
            remaining_size = max(
                0,
                node.child_size_bytes
                - node.loaded_child_size_bytes
                - sum(child.size_bytes for child in page),
            )
            page.append(Node(
                node.path / ".clearspace-aggregate-row",
                f"{remaining_count:,} smaller items",
                False,
                remaining_size,
                children_loaded=True,
                selectable=False,
                aggregate_count=remaining_count,
                parent_id=parent_id,
            ))
            if include_more:
                next_offset = offset + len(rows)
                page.append(Node(
                    node.path / ".clearspace-show-more-row",
                    f"Showing the biggest {next_offset:,} of {node.child_count:,} · Show more",
                    False,
                    0,
                    children_loaded=True,
                    selectable=False,
                    parent_id=parent_id,
                    is_more_row=True,
                    more_offset=next_offset,
                ))
        return page

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
