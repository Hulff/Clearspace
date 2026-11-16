from pathlib import Path

import pytest

from clearspace.contracts import (
    MatcherKind,
    Node,
    Procedure,
    Risk,
    Rule,
    RuleMatcher,
    SelectionModel,
    SelectionState,
)


def make_tree(tmp_path: Path) -> tuple[Node, Node, Node]:
    root_path = tmp_path / "root"
    folder_path = root_path / "folder"
    file_path = folder_path / "item"
    file_node = Node(file_path, "item", False, 30)
    folder_node = Node(folder_path, "folder", True, 30, children=[file_node])
    root_node = Node(root_path, "root", True, 50, children=[folder_node])
    return root_node, folder_node, file_node


def test_selection_states_and_minimal_paths(tmp_path: Path) -> None:
    root, folder, file_node = make_tree(tmp_path)
    selection = SelectionModel([root])

    selection.set_checked(file_node, True)
    assert selection.state(root) is SelectionState.PARTIAL
    assert selection.state(folder) is SelectionState.PARTIAL
    assert selection.state(file_node) is SelectionState.CHECKED
    assert selection.selected_paths == (file_node.path,)
    assert selection.estimated_size_bytes == 30

    selection.set_checked(folder, True)
    assert selection.selected_paths == (folder.path,)
    assert selection.estimated_size_bytes == 30
    assert selection.state(file_node) is SelectionState.UNCHECKED

    selection.set_checked(root, True)
    assert selection.selected_paths == (root.path,)
    assert selection.estimated_size_bytes == 50


def test_unchecking_parent_clears_selected_descendants(tmp_path: Path) -> None:
    root, folder, file_node = make_tree(tmp_path)
    selection = SelectionModel([root])
    selection.set_checked(file_node, True)
    selection.set_checked(folder, False)

    assert selection.state(folder) is SelectionState.UNCHECKED
    assert selection.selected_paths == ()


def test_procedure_availability_and_admin_copy_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("clearspace.contracts.shutil.which", lambda tool: "/usr/bin/tool")
    normal = Procedure("normal", "Normal", ["tool", "clean"], False, "Rebuildable", True)
    admin = Procedure("admin", "Admin", ["tool", "clean"], True, "System change", False)

    assert normal.available
    assert normal.command_to_copy is None
    assert not admin.available
    assert admin.command_to_copy == ("tool", "clean")


def test_rules_match_general_glob_name_and_category() -> None:
    glob_rule = Rule(RuleMatcher(MatcherKind.GLOB, "**/build"), Risk.LOW, "Regenerable")
    name_rule = Rule(RuleMatcher(MatcherKind.NAME, "node_modules"), Risk.MODERATE, "Build dependencies")
    category_rule = Rule(RuleMatcher(MatcherKind.CATEGORY, "credentials"), Risk.CRITICAL, "Protected data")

    assert glob_rule.matcher.matches(name="build", category="cache", path=Path("project/build"))
    assert name_rule.matcher.matches(name="node_modules", category="project", path=Path("project/node_modules"))
    assert category_rule.matcher.matches(name="keys", category="credentials", path=Path("config/keys"))
