"""GTK-free filesystem tree scanner for Clearspace."""

from __future__ import annotations

import logging
import heapq
import os
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .contracts import Node, classify_scan_error
from .progress import ProgressEvent, ProgressThrottle, ScanState, TopKTracker

logger = logging.getLogger(__name__)


@dataclass
class TreeScanner:
    """Read a complete tree without following links.

    The caller should run ``scan_root`` in a worker thread and hand the
    resulting tree to the UI only after the scan finishes.
    """

    root_path: Path
    max_visible_children: int = 100
    _root_device: int | None = field(default=None, init=False, repr=False)
    _seen_inodes: set[tuple[int, int]] = field(default_factory=set, init=False, repr=False)
    _root_node: Node | None = field(default=None, init=False, repr=False)
    _directory_metadata_bytes: dict[Path, int] = field(default_factory=dict, init=False, repr=False)
    report: dict[str, int | float] = field(default_factory=dict, init=False)
    top_items: TopKTracker = field(default_factory=TopKTracker, init=False, repr=False)
    _progress: Callable[[ProgressEvent], None] | None = field(default=None, init=False, repr=False)
    _cancel_event: threading.Event | None = field(default=None, init=False, repr=False)
    _pause_event: threading.Event | None = field(default=None, init=False, repr=False)
    _throttle: ProgressThrottle = field(default_factory=ProgressThrottle, init=False, repr=False)
    _started_at: float = field(default=0.0, init=False, repr=False)
    _dirs_done: int = field(default=0, init=False, repr=False)
    _include_hidden: bool = field(default=True, init=False, repr=False)
    _stay_on_device: bool = field(default=True, init=False, repr=False)

    def scan_root(
        self,
        *,
        progress: Callable[[ProgressEvent], None] | None = None,
        cancel_event: threading.Event | None = None,
        pause_event: threading.Event | None = None,
        include_hidden: bool = True,
        stay_on_device: bool = True,
    ) -> Node:
        """Create the root node and measure every reachable directory."""
        started = time.monotonic()
        self._started_at = started
        self._progress = progress
        self._cancel_event = cancel_event
        self._pause_event = pause_event
        self._include_hidden = include_hidden
        self._stay_on_device = stay_on_device
        self._dirs_done = 0
        self._throttle = ProgressThrottle()
        self.top_items = TopKTracker()
        self._root_device = None
        self._seen_inodes.clear()
        self._directory_metadata_bytes.clear()
        self.report = {
            "directories": 0,
            "files": 0,
            "errors": 0,
            "symlinks_skipped": 0,
            "other_filesystems_skipped": 0,
            "hidden_skipped": 0,
            "allocated_bytes": 0,
        }
        root_path = Path(os.path.abspath(self.root_path))
        current = Path(root_path.anchor)
        for component in root_path.parts[1:]:
            current = current / component
            try:
                info = current.lstat()
            except OSError as error:
                self._log_error(current, error)
                self.report["errors"] += 1
                root = Node(root_path, root_path.name, True, 0,
                            error=self._error_text(error), error_kind=classify_scan_error(error),
                            children_loaded=True,
                            size_is_partial=True, selectable=False)
                self._finish_report(root, started)
                self._emit_progress(current, state=ScanState.ERROR, partial=True, force=True)
                return root
            if stat.S_ISLNK(info.st_mode):
                root = Node(root_path, root_path.name, True, 0,
                            error=f"symlink não seguido: {current}", children_loaded=True,
                            size_is_partial=True, selectable=False)
                self._finish_report(root, started)
                self._emit_progress(current, state=ScanState.ERROR, partial=True, force=True)
                return root
        self.root_path = root_path
        root = self._node_for(self.root_path, is_root=True)
        root.selectable = False
        self._root_node = root
        self._expand_recursively(root)
        self._finish_report(root, started)
        if self._cancelled():
            self._emit_progress(root.path, state=ScanState.CANCELLED,
                                 partial=True, force=True)
        elif root.error:
            self._emit_progress(root.path, state=ScanState.ERROR,
                                 partial=True, force=True)
        else:
            self._emit_progress(root.path, state=ScanState.DONE,
                                 partial=root.size_is_partial, force=True)
        return root

    def _finish_report(self, root: Node, started: float) -> None:
        self.report["allocated_bytes"] = root.size_bytes
        self.report["elapsed_seconds"] = round(time.monotonic() - started, 3)

    def _emit_progress(
        self,
        path: Path,
        *,
        state: ScanState = ScanState.RUNNING,
        partial: bool = False,
        force: bool = False,
    ) -> None:
        if self._progress is None:
            return
        terminal = state in {ScanState.CANCELLED, ScanState.DONE, ScanState.ERROR}
        if not force and not self._throttle.should_publish(terminal=terminal):
            return
        self._progress(ProgressEvent(
            dirs_done=self._dirs_done,
            dirs_total_est=int(self.report.get("directories", 0)),
            files=int(self.report.get("files", 0)),
            bytes=int(self.report.get("allocated_bytes", 0)),
            elapsed_ms=int((time.monotonic() - self._started_at) * 1000),
            current_path=str(path),
            state=state,
            partial=partial,
            largest_items=self.top_items.snapshot(),
            unreadable_count=int(self.report.get("errors", 0)),
        ))

    def _checkpoint(self) -> bool:
        if self._cancelled():
            return False
        if self._pause_event is not None:
            while not self._pause_event.wait(timeout=0.1):
                if self._cancelled():
                    return False
        return not self._cancelled()

    def _cancelled(self) -> bool:
        return self._cancel_event is not None and self._cancel_event.is_set()

    def _expand_recursively(self, node: Node) -> None:
        if not node.is_dir or node.children_loaded:
            return
        self.expand(node)
        pending = node.children
        node.children = []
        largest: list[tuple[int, int, Node]] = []
        hidden_size = 0
        hidden_count = 0
        total_size = 0
        for index, child in enumerate(pending):
            if child is None:
                continue
            if child.is_dir:
                if self._checkpoint():
                    self._expand_recursively(child)
                elif not child.children_loaded:
                    child.size_is_partial = True
                    node.size_is_partial = True
            if child.error or child.size_is_partial:
                node.size_is_partial = True
            total_size += child.size_bytes
            if len(largest) < self.max_visible_children:
                heapq.heappush(largest, (child.size_bytes, index, child))
            elif self.max_visible_children and child.size_bytes > largest[0][0]:
                _size, _index, removed = heapq.heapreplace(
                    largest, (child.size_bytes, index, child)
                )
                hidden_size += removed.size_bytes
                hidden_count += 1
            else:
                hidden_size += child.size_bytes
                hidden_count += 1
            pending[index] = None
        if node.children_loaded:
            node.children = [
                entry for _size, _index, entry in sorted(
                    largest, key=lambda item: item[0], reverse=True
                )
            ]
            if hidden_count:
                node.children.append(Node(
                    path=node.path / ".clearspace-aggregate-row",
                    name=f"{hidden_count} itens menores",
                    is_dir=False,
                    size_bytes=hidden_size,
                    children_loaded=True,
                    selectable=False,
                    aggregate_count=hidden_count,
                ))
            node.size_bytes = self._directory_metadata_bytes.get(node.path, 0) + total_size
            if self._progress is not None and node.path != self.root_path:
                self.top_items.add(node.name, node.path, node.size_bytes)
            self._dirs_done += 1
            if self._cancelled():
                node.size_is_partial = True
            self._emit_progress(node.path, partial=node.size_is_partial)
        del pending

    def expand(self, node: Node) -> list[Node]:
        """Load one directory level, sorting largest entries first."""
        if not node.is_dir or node.children_loaded:
            return node.children
        directory_fd = None
        try:
            if not self._checkpoint():
                node.size_is_partial = True
                node.children_loaded = True
                return node.children
            directory_fd = self._open_directory_fd(node.path)
            with os.scandir(directory_fd) as iterator:
                children: list[Node] = []
                for index, entry in enumerate(iterator):
                    # Checking control once per batch keeps pause/cancel responsive
                    # without taking an Event lock for every filesystem entry.
                    if index % 64 == 0 and not self._checkpoint():
                        node.size_is_partial = True
                        break
                    if not self._include_hidden and entry.name.startswith("."):
                        self.report["hidden_skipped"] += 1
                        continue
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError as error:
                        self.report["errors"] += 1
                        child = Node(
                            node.path / entry.name,
                            entry.name,
                            False,
                            0,
                            error=self._error_text(error),
                            error_kind=classify_scan_error(error),
                            size_is_partial=True,
                            selectable=False,
                        )
                        children.append(child)
                        self._log_error(child.path, error)
                        self._emit_progress(child.path)
                        continue

                    path = node.path / entry.name
                    if stat.S_ISLNK(info.st_mode):
                        # Symlink targets are never inspected or traversed.
                        self.report["symlinks_skipped"] += 1
                        continue
                    if self._stay_on_device and info.st_dev != self._root_device:
                        self.report["other_filesystems_skipped"] += 1
                        continue

                    size = self._allocated_size(info, path)
                    child = Node(path, entry.name, stat.S_ISDIR(info.st_mode), size)
                    self.report["directories" if child.is_dir else "files"] += 1
                    if self._progress is not None and not child.is_dir:
                        self.top_items.add(child.name, child.path, child.size_bytes)
                    children.append(child)
                    self._emit_progress(path)
        except OSError as error:
            self._set_error(node, error)
            node.children_loaded = True
            return node.children
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

        if self._cancelled():
            node.size_is_partial = True
        children.sort(key=lambda item: item.size_bytes, reverse=True)
        node.children = children
        node.children_loaded = True
        node.size_bytes = sum(child.size_bytes for child in children)
        if self._cancelled():
            node.size_is_partial = True
        return children

    def _open_directory_fd(self, path: Path) -> int:
        """Open a tree directory from its root using O_NOFOLLOW at each step."""
        relative = path.relative_to(self.root_path)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory_fd = os.open(self.root_path, flags)
        try:
            for component in relative.parts:
                next_fd = os.open(component, flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            return directory_fd
        except Exception:
            os.close(directory_fd)
            raise

    def _node_for(self, path: Path, *, is_root: bool = False) -> Node:
        try:
            info = path.lstat()
        except OSError as error:
            node = Node(path, path.name or str(path), True, 0,
                        error=self._error_text(error), size_is_partial=True,
                        selectable=False, error_kind=classify_scan_error(error))
            self._log_error(path, error)
            return node

        if stat.S_ISLNK(info.st_mode):
            return Node(path, path.name, False, 0, error="symlink não seguido")
        if self._root_device is None:
            self._root_device = info.st_dev
        if self._stay_on_device and info.st_dev != self._root_device:
            return Node(path, path.name, stat.S_ISDIR(info.st_mode), 0,
                        error="filesystem diferente; ignorado")

        is_dir = stat.S_ISDIR(info.st_mode)
        if is_dir:
            self.report["directories"] += 1
            self._directory_metadata_bytes[path] = info.st_blocks * 512
        if not is_dir:
            self.report["files"] += 1
            size = self._allocated_size(info, path)
            return Node(path, path.name, False, size, children_loaded=True)
        return Node(path, path.name or str(path), True, self._allocated_size(info, path),
                    children_loaded=not is_root)

    def _allocated_size(self, info: os.stat_result, path: Path) -> int:
        if stat.S_ISDIR(info.st_mode):
            size = info.st_blocks * 512
            self.report["allocated_bytes"] += size
            return size
        inode = (info.st_dev, info.st_ino)
        if info.st_nlink > 1:
            if inode in self._seen_inodes:
                return 0
            self._seen_inodes.add(inode)
        size = info.st_blocks * 512
        self.report["allocated_bytes"] += size
        return size

    def _set_error(self, node: Node, error: OSError) -> None:
        self.report["errors"] += 1
        node.error = self._error_text(error)
        node.error_kind = classify_scan_error(error)
        node.size_is_partial = True
        node.selectable = False
        self._log_error(node.path, error)

    @staticmethod
    def _error_text(error: OSError) -> str:
        return f"não foi possível ler: {error.strerror or error}"

    @staticmethod
    def _log_error(path: Path, error: OSError) -> None:
        logger.warning("Scan failed for %s: %s", path, error)
