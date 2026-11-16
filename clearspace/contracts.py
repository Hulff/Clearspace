"""GTK-free domain contracts shared by Clearspace features."""

from __future__ import annotations

import fnmatch
import shutil
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol


class SelectionState(StrEnum):
    UNCHECKED = "unchecked"
    CHECKED = "checked"
    PARTIAL = "partial"


@dataclass(slots=True)
class Node:
    """A filesystem entry and its measured, on-disk usage."""

    path: Path
    name: str
    is_dir: bool
    size_bytes: int
    error: str | None = None
    children_loaded: bool = False
    children: list[Node] = field(default_factory=list)
    size_is_partial: bool = False
    selectable: bool = True
    aggregate_count: int = 0

    def __post_init__(self) -> None:
        if self.size_bytes < 0:
            raise ValueError("size_bytes cannot be negative")
        if not self.is_dir and self.children:
            raise ValueError("file nodes cannot have children")


@dataclass
class SelectionModel:
    """Tracks checked nodes and exposes minimal paths and estimated size."""

    roots: list[Node]
    _checked: set[Path] = field(default_factory=set, repr=False)

    def set_checked(self, node: Node, checked: bool) -> None:
        """Set a node's selection, clearing descendants when checking it."""
        if not node.selectable:
            return
        if checked:
            self._checked = {
                path for path in self._checked
                if not _is_at_or_below(path, node.path)
            }
            self._checked.add(node.path)
        else:
            self._checked = {
                path for path in self._checked
                if not _is_at_or_below(path, node.path)
            }

    def state(self, node: Node) -> SelectionState:
        if node.path in self._checked:
            return SelectionState.CHECKED
        descendants = [path for path in self._checked if _is_at_or_below(path, node.path)]
        if not descendants:
            return SelectionState.UNCHECKED
        return SelectionState.PARTIAL

    @property
    def selected_paths(self) -> tuple[Path, ...]:
        """Return selected paths with any selected ancestor represented once."""
        ordered = sorted(self._checked, key=lambda path: (len(path.parts), str(path)))
        minimal: list[Path] = []
        for path in ordered:
            if not any(_is_at_or_below(path, parent) for parent in minimal):
                minimal.append(path)
        return tuple(minimal)

    @property
    def estimated_size_bytes(self) -> int:
        nodes = {
            node.path: node for root in self.roots for node in _walk(root)
            if node.selectable
        }
        return sum(nodes[path].size_bytes for path in self.selected_paths if path in nodes)


def _is_at_or_below(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _walk(node: Node):
    yield node
    for child in node.children:
        yield from _walk(child)


class Risk(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    USER_DATA = "user_data"
    CRITICAL = "critical"


class MatcherKind(StrEnum):
    GLOB = "glob"
    NAME = "name"
    CATEGORY = "category"


@dataclass(frozen=True)
class RuleMatcher:
    kind: MatcherKind
    value: str

    def matches(self, *, name: str, category: str, path: Path) -> bool:
        if self.kind is MatcherKind.NAME:
            return name == self.value
        if self.kind is MatcherKind.CATEGORY:
            return category == self.value
        return fnmatch.fnmatchcase(path.as_posix(), self.value)


@dataclass(frozen=True)
class Rule:
    matcher: RuleMatcher
    risk: Risk
    message: str
    recommended_procedure_id: str | None = None


@dataclass
class Procedure:
    id: str
    label: str
    argv: list[str]
    requires_admin: bool
    side_effects: str
    regenerable: bool
    executable: str | None = None

    def __post_init__(self) -> None:
        if not self.id or not self.label:
            raise ValueError("procedure id and label are required")
        if not self.argv or any(not isinstance(arg, str) for arg in self.argv):
            raise ValueError("procedure argv must be a non-empty list of strings")

    @property
    def available(self) -> bool:
        """Whether the declared tool is installed, regardless of execution policy."""
        tool = self.executable or self.argv[0]
        return shutil.which(tool) is not None

    @property
    def command_to_copy(self) -> tuple[str, ...] | None:
        return tuple(self.argv) if self.requires_admin else None


class ProposedActionKind(StrEnum):
    SELECT_NODE = "select_node"
    OPEN_PROCEDURE = "open_procedure"
    EXPLAIN_RISK = "explain_risk"


@dataclass(frozen=True)
class ProposedAction:
    kind: ProposedActionKind
    target: str


@dataclass(frozen=True)
class AssistantReply:
    text: str
    proposed_actions: tuple[ProposedAction, ...] = ()


class Assistant(Protocol):
    def respond(self, message: str, context: object) -> AssistantReply: ...
