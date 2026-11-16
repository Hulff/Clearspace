from __future__ import annotations

import os
from pathlib import Path

import pytest

from clearspace.contracts import SelectionModel
from clearspace.scanner import TreeScanner


def test_scans_hidden_entries_and_expands_lazily(tmp_path: Path) -> None:
    root_path = tmp_path / "root"
    child_path = root_path / ".hidden"
    child_path.mkdir(parents=True)
    (child_path / "payload").write_bytes(b"hidden contents")

    scanner = TreeScanner(root_path)
    root = scanner.scan_root()

    assert root.children_loaded
    hidden = next(node for node in root.children if node.name == ".hidden")
    assert not hidden.children_loaded
    payload = scanner.expand(hidden)
    assert [node.name for node in payload] == ["payload"]
    assert hidden.children_loaded


def test_symlink_targets_are_not_followed(tmp_path: Path) -> None:
    root_path = tmp_path / "root"
    outside = tmp_path / "outside"
    root_path.mkdir()
    outside.mkdir()
    (outside / "secret").write_bytes(b"secret data")
    (root_path / "linked").symlink_to(outside, target_is_directory=True)

    root = TreeScanner(root_path).scan_root()

    assert all(node.name != "linked" for node in root.children)


def test_permission_denied_directory_is_visible_as_error(tmp_path: Path) -> None:
    root_path = tmp_path / "root"
    blocked_path = root_path / "blocked"
    blocked_path.mkdir(parents=True)
    blocked_path.chmod(0)
    try:
        scanner = TreeScanner(root_path)
        root = scanner.scan_root()
        blocked = next(node for node in root.children if node.name == "blocked")
        scanner.expand(blocked)
        assert blocked.error and "não foi possível ler:" in blocked.error
        assert blocked.children_loaded
    except StopIteration:
        pytest.skip("filesystem does not expose the chmod 000 directory")
    finally:
        blocked_path.chmod(0o700)


def test_missing_root_is_reported(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"

    node = TreeScanner(missing).scan_root()

    assert node.error and "não foi possível ler:" in node.error


def test_hardlinks_count_once_and_large_directories_aggregate(tmp_path: Path) -> None:
    root_path = tmp_path / "root"
    root_path.mkdir()
    original = root_path / "a"
    original.write_bytes(b"shared payload")
    try:
        os.link(original, root_path / "b")
    except OSError as error:
        pytest.skip(f"hardlinks are unavailable: {error}")
    for index in range(3):
        (root_path / f"file-{index}").write_bytes(b"x")

    root = TreeScanner(root_path, max_visible_children=2).scan_root()
    aggregate = next(node for node in root.children if node.name.endswith("itens menores"))
    selection = SelectionModel([root])
    selection.set_checked(aggregate, True)

    assert aggregate.selectable is False
    assert selection.selected_paths == ()
    assert len(root.children) == 3  # 2 visible entries + aggregate
    assert root.size_bytes > 0
