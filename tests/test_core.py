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
