"""GTK-free filesystem tree scanner for Clearspace."""

from __future__ import annotations

import logging
import heapq
import os
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path

from .contracts import Node

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

    def scan_root(self) -> Node:
        """Create the root node and measure every reachable directory."""
        started = time.monotonic()
        self.report = {
            "directories": 0,
            "files": 0,
            "errors": 0,
            "symlinks_skipped": 0,
            "other_filesystems_skipped": 0,
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
                return Node(root_path, root_path.name, True, 0,
                            error=self._error_text(error), children_loaded=True,
                            selectable=False)
            if stat.S_ISLNK(info.st_mode):
                return Node(root_path, root_path.name, True, 0,
                            error=f"symlink não seguido: {current}", children_loaded=True,
                            selectable=False)
        self.root_path = root_path
        root = self._node_for(self.root_path, is_root=True)
        root.selectable = False
        self._root_node = root
        self._expand_recursively(root)
        self.report["allocated_bytes"] = root.size_bytes
        self.report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        return root

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
                self._expand_recursively(child)
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
        del pending

    def expand(self, node: Node) -> list[Node]:
        """Load one directory level, sorting largest entries first."""
        if not node.is_dir or node.children_loaded:
            return node.children
        directory_fd = None
        try:
            directory_fd = self._open_directory_fd(node.path)
            with os.scandir(directory_fd) as iterator:
                entries = []
                for entry in iterator:
                    try:
                        info = entry.stat(follow_symlinks=False)
                        entries.append((entry.name, info, None))
                    except OSError as error:
                        entries.append((entry.name, None, error))
        except OSError as error:
            self._set_error(node, error)
            node.children_loaded = True
            return node.children
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

        children: list[Node] = []
        for name, info, error in entries:
            path = node.path / name
            if error:
                self.report["errors"] += 1
                child = Node(path, name, False, 0, error=self._error_text(error),
                             selectable=False)
                children.append(child)
                self._log_error(path, error)
                continue

            if stat.S_ISLNK(info.st_mode):
                # Symlink targets are never inspected and symlink nodes are not
                # selectable for cleanup through the tree scanner.
                self.report["symlinks_skipped"] += 1
                continue
            if info.st_dev != self._root_device:
                self.report["other_filesystems_skipped"] += 1
                continue

            size = self._allocated_size(info, path)
            child = Node(path, name, stat.S_ISDIR(info.st_mode), size)
            self.report["directories" if child.is_dir else "files"] += 1
            children.append(child)

        children.sort(key=lambda item: item.size_bytes, reverse=True)
        node.children = children
        node.children_loaded = True
        node.size_bytes = sum(child.size_bytes for child in children)
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
            node = Node(path, path.name or str(path), True, 0, error=self._error_text(error))
            self._log_error(path, error)
            return node

        if stat.S_ISLNK(info.st_mode):
            return Node(path, path.name, False, 0, error="symlink não seguido")
        if self._root_device is None:
            self._root_device = info.st_dev
        if info.st_dev != self._root_device:
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
            return info.st_blocks * 512
        inode = (info.st_dev, info.st_ino)
        if info.st_nlink > 1:
            if inode in self._seen_inodes:
                return 0
            self._seen_inodes.add(inode)
        return info.st_blocks * 512

    def _set_error(self, node: Node, error: OSError) -> None:
        self.report["errors"] += 1
        node.error = self._error_text(error)
        node.size_is_partial = node.size_bytes > 0
        node.selectable = False
        self._log_error(node.path, error)

    @staticmethod
    def _error_text(error: OSError) -> str:
        return f"não foi possível ler: {error.strerror or error}"

    @staticmethod
    def _log_error(path: Path, error: OSError) -> None:
        logger.warning("Scan failed for %s: %s", path, error)
