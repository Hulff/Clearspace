from pathlib import Path

from clearspace.core import directory_size


def test_counts_hidden_files(tmp_path: Path) -> None:
    hidden = tmp_path / ".hidden"
    hidden.write_bytes(b"hidden data")

    result = directory_size(tmp_path)

    assert result.bytes == len(b"hidden data")
    assert result.errors == ()


def test_counts_symlink_without_following_it(tmp_path: Path) -> None:
    target = tmp_path / "outside-target"
    target.mkdir()
    (target / "payload").write_bytes(b"payload")
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    link = scanned / "link"
    link.symlink_to(target, target_is_directory=True)

    result = directory_size(scanned)

    assert result.bytes == link.lstat().st_size
    assert result.errors == ()


def test_symlink_scan_root_does_not_read_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "payload").write_bytes(b"payload")
    link = tmp_path / "root-link"
    link.symlink_to(target, target_is_directory=True)

    result = directory_size(link)

    assert result.bytes == link.lstat().st_size
    assert result.errors == ()


def test_permission_error_is_reported(tmp_path: Path) -> None:
    import os
    import pytest

    if os.geteuid() == 0:
        pytest.skip("root can read chmod 000 directories")

    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "payload").write_bytes(b"cannot read directory entry")
    blocked.chmod(0)
    try:
        result = directory_size(tmp_path)
    finally:
        blocked.chmod(0o700)

    assert result.errors
    assert "Permission denied" in result.errors[0]
    assert result.partial


def test_missing_target_is_reported(tmp_path: Path) -> None:
    result = directory_size(tmp_path / "absent")

    assert result.bytes == 0
    assert result.missing
    assert result.errors


def test_scan_history_stores_directory_count_and_matches_canonical_root(tmp_path: Path) -> None:
    from clearspace.core import History
    import inspect

    assert hasattr(History, "latest_scan_for"), "same-root scan lookup is missing"
    assert "directories" in inspect.signature(History.record_scan).parameters

    root = tmp_path / "scan-root"
    root.mkdir()
    history = History(tmp_path / "history.jsonl")
    history.record_scan(root / ".." / "scan-root", 100, directories=7, timestamp=1)

    assert history.latest_scan_for(root.resolve()) == {
        "schema_version": 1,
        "record_type": "scan",
        "timestamp": 1,
        "path": str(root / ".." / "scan-root"),
        "size_bytes": 100,
        "partial": False,
        "directories": 7,
    }


def test_scan_history_ignores_partial_and_legacy_directory_estimates(tmp_path: Path) -> None:
    from clearspace.core import History
    import inspect

    assert hasattr(History, "latest_scan_for"), "same-root scan lookup is missing"
    assert "directories" in inspect.signature(History.record_scan).parameters

    root = tmp_path / "scan-root"
    root.mkdir()
    history = History(tmp_path / "history.jsonl")
    history.record_scan(root, 100, directories=5, timestamp=1)
    history.record_scan(root, 200, directories=9, partial=True, timestamp=2)
    history.append({
        "schema_version": 1,
        "record_type": "scan",
        "timestamp": 3,
        "path": str(root),
        "size_bytes": 300,
        "partial": False,
    })

    assert history.latest_scan_for(root) is not None
    assert history.latest_scan_for(root)["directories"] == 5
