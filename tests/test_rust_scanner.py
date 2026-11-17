from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from clearspace import rust_scanner
from clearspace.rust_scanner import RustTreeScanner
from clearspace.scanner import TreeScanner


BIN = Path(__file__).resolve().parents[1] / "scanner" / "target" / "release" / "clearspace-scan"


def test_protocol_v2_progress_preserves_paths_top_k_and_previous_estimate() -> None:
    assert hasattr(rust_scanner, "progress_event_from_rust"), "protocol v2 adapter is missing"
    event = rust_scanner.progress_event_from_rust(
        {
            "protocol_version": 2,
            "event": "progress",
            "dirs_done": 4,
            "dirs_queued": 3,
            "dirs_total_est": 7,
            "directories": 4,
            "files": 9,
            "allocated_bytes": 1024,
            "errors": 1,
            "unreadable_count": 2,
            "current_path": "/scan/root/subdir",
            "largest_items": [
                {"name": "large.bin", "path": "/scan/root/large.bin", "bytes": 512}
            ],
        },
        elapsed_ms=25,
        prior_directories=11,
    )

    assert event.dirs_done == 4
    assert event.dirs_total_est == 11
    assert event.files == 9
    assert event.bytes == 1024
    assert event.current_path == "/scan/root/subdir"
    assert event.largest_items == (("large.bin", "/scan/root/large.bin", 512),)
    assert event.partial
    assert event.unreadable_count == 2


def test_protocol_v2_progress_rejects_an_oversized_top_list() -> None:
    assert hasattr(rust_scanner, "progress_event_from_rust"), "protocol v2 adapter is missing"
    payload = {
        "protocol_version": 2,
        "event": "progress",
        "dirs_done": 1,
        "dirs_queued": 0,
        "dirs_total_est": 1,
        "directories": 1,
        "files": 0,
        "allocated_bytes": 0,
        "errors": 0,
        "current_path": "/scan/root",
        "largest_items": [
            {"name": str(index), "path": f"/scan/root/{index}", "bytes": index}
            for index in range(5)
        ],
    }
    with pytest.raises(ValueError, match="largest_items"):
        rust_scanner.progress_event_from_rust(payload, elapsed_ms=0)


def _children(scanner, node):
    scanner.expand(node)
    return {child.name: child for child in node.children if not child.aggregate_count}


@pytest.mark.skipif(not BIN.is_file(), reason="build scanner Rust with cargo build --release")
def test_rust_and_python_scanners_match_synthetic_tree_and_du(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    nested = root / ".hidden-dir"
    nested.mkdir(parents=True)
    (root / ".hidden-file").write_bytes(b"hidden" * 2000)
    (nested / "payload").write_bytes(b"payload" * 1700)
    try:
        os.link(nested / "payload", root / "hardlink")
    except OSError as error:
        pytest.skip(f"hardlinks unavailable: {error}")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "not-counted").write_bytes(b"outside" * 3000)
    (root / "symlink").symlink_to(outside, target_is_directory=True)
    for index in range(15):
        (root / f"small-{index}").write_bytes(bytes([index]) * (index + 1))

    python_scanner = TreeScanner(root, max_visible_children=100)
    python_root = python_scanner.scan_root()
    rust_scanner = RustTreeScanner(
        root,
        max_visible_children=100,
        binary=BIN,
        cache_dir=tmp_path / "private-cache",
    )
    try:
        rust_root = rust_scanner.scan_root()
        assert python_root.size_bytes == rust_root.size_bytes

        python_children = _children(python_scanner, python_root)
        rust_children = _children(rust_scanner, rust_root)
        assert set(python_children) == set(rust_children)
        assert "symlink" not in rust_children
        assert python_children[".hidden-file"].size_bytes == rust_children[".hidden-file"].size_bytes
        assert python_children[".hidden-dir"].size_bytes == rust_children[".hidden-dir"].size_bytes
        assert sorted((python_children["hardlink"].size_bytes,
                       _children(python_scanner, python_children[".hidden-dir"])["payload"].size_bytes)) == sorted(
            (rust_children["hardlink"].size_bytes,
             _children(rust_scanner, rust_children[".hidden-dir"])["payload"].size_bytes)
        )
        assert rust_scanner.report["errors"] == python_scanner.report["errors"] == 0
        assert rust_scanner.report["symlinks_skipped"] == python_scanner.report["symlinks_skipped"] == 1

        du = shutil.which("du")
        if du:
            completed = subprocess.run(
                [du, "-sx", "--block-size=512", "--exclude=symlink", str(root)],
                check=True,
                capture_output=True,
                text=True,
                shell=False,
            )
            du_blocks = int(completed.stdout.split()[0])
            assert rust_root.size_bytes == du_blocks * 512
    finally:
        rust_scanner.close()


@pytest.mark.skipif(not BIN.is_file(), reason="build scanner Rust with cargo build --release")
def test_rust_and_python_mark_inaccessible_subtrees_partial(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    blocked = root / "blocked"
    blocked.mkdir(parents=True)
    (blocked / "secret").write_bytes(b"synthetic inaccessible data")
    blocked.chmod(0)
    try:
        readable = list(blocked.iterdir())
    except PermissionError:
        readable = None
    db_cache = tmp_path / "private-cache"
    rust_scanner = RustTreeScanner(root, binary=BIN, cache_dir=db_cache)
    try:
        python_root = TreeScanner(root).scan_root()
        rust_root = rust_scanner.scan_root()
        python_blocked = next(node for node in python_root.children if node.name == "blocked")
        rust_blocked = next(node for node in _children(rust_scanner, rust_root).values() if node.name == "blocked")
        if readable is None:
            assert python_root.size_is_partial
            assert rust_root.size_is_partial
            assert python_blocked.size_is_partial
            assert rust_blocked.size_is_partial
            assert rust_scanner.report["errors"] == 1
        else:
            pytest.skip("the current user can read mode-000 directories")
    finally:
        blocked.chmod(0o700)
        rust_scanner.close()


@pytest.mark.skipif(not BIN.is_file(), reason="build scanner Rust with cargo build --release")
def test_private_database_is_moved_outside_a_root_that_contains_xdg_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "scan-root"
    root.mkdir()
    monkeypatch.setenv("XDG_CACHE_HOME", str(root / ".cache"))
    scanner = RustTreeScanner(root, binary=BIN)
    try:
        assert not scanner.database_path.is_relative_to(root)
    finally:
        scanner.close()
