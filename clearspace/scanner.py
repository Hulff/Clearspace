"""GTK-free, lazy filesystem tree scanner for Clearspace."""

from __future__ import annotations

import logging
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .contracts import Node

logger = logging.getLogger(__name__)


@dataclass
class TreeScanner:
    """Read one directory level at a time without following links.

    Directory sizes are accumulated during expansion. A directory node's
    initial size is its own allocated metadata; after expansion it is updated
    to include the entries measured in its children. Results can be handed to
    a GTK adapter which schedules model changes with GLib.idle_add.
    """

    root_path: Path
    max_visible_children: int = 200
    _root_device: int | None = field(default=None, init=False, repr=False)
    _seen_inodes: set[tuple[int, int]] = field(default_factory=set, init=False, repr=False)

    def scan_root(self) -> Node:
        """Create the root node and enumerate only its immediate children."""
        root = self._node_for(self.root_path, is_root=True)
        self.expand(root)
        return root

    def expand(self, node: Node) -> list[Node]:
        """Load one directory level, sorting largest entries first."""
        if not node.is_dir or node.children_loaded:
            return node.children
        try:
            with os.scandir(node.path) as iterator:
                entries = list(iterator)
        except OSError as error:
            self._set_error(node, error)
            node.children_loaded = True
            return node.children

        children: list[Node] = []
        for entry in entries:
            path = Path(entry.path)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as error:
                child = Node(path, entry.name, False, 0, error=self._error_text(error))
                children.append(child)
                self._log_error(path, error)
                continue

            if stat.S_ISLNK(info.st_mode):
                # Symlink targets are never inspected and symlink nodes are not
                # selectable for cleanup through the tree scanner.
                continue
            if info.st_dev != self._root_device:
                continue

            size = self._allocated_size(info, path)
            child = Node(path, entry.name, stat.S_ISDIR(info.st_mode), size)
            children.append(child)

        children.sort(key=lambda item: item.size_bytes, reverse=True)
        total_count = len(children)
        if total_count > self.max_visible_children:
            visible = children[: self.max_visible_children]
            hidden = children[self.max_visible_children :]
            hidden_size = sum(item.size_bytes for item in hidden)
            visible.append(Node(
                path=node.path,
                name=f"{len(hidden)} itens menores",
                is_dir=False,
                size_bytes=hidden_size,
                children_loaded=True,
                selectable=False,
            ))
            children = visible

        node.children = children
        node.children_loaded = True
        node.size_bytes = sum(child.size_bytes for child in children)
        return children

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
        if not is_dir:
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
        node.error = self._error_text(error)
        node.size_is_partial = node.size_bytes > 0
        self._log_error(node.path, error)

    @staticmethod
    def _error_text(error: OSError) -> str:
        return f"não foi possível ler: {error.strerror or error}"

    @staticmethod
    def _log_error(path: Path, error: OSError) -> None:
        logger.warning("Scan failed for %s: %s", path, error)
