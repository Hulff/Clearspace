from __future__ import annotations

from pathlib import Path

import pytest

from clearspace.core import History
from clearspace.locations import (
    ScanOptions,
    ScanRootError,
    format_age,
    recent_scan_record,
    resolve_xdg_locations,
    scanner_arguments,
    validate_scan_root,
)


def test_scan_root_validation_accepts_temp_directory_and_rejects_protected(
    tmp_path: Path,
) -> None:
    root = tmp_path / "chosen"
    root.mkdir()
    protected = tmp_path / "system"
    protected_child = protected / "nested"
    protected_child.mkdir(parents=True)

    assert validate_scan_root(root) == root.resolve()
    with pytest.raises(ScanRootError, match="protected"):
        validate_scan_root(protected_child, protected_roots=(protected,))


def test_scan_root_validation_rejects_symlinks_and_files(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    file_path = tmp_path / "file"
    file_path.write_text("fixture", encoding="utf-8")

    with pytest.raises(ScanRootError, match="symbolic links"):
        validate_scan_root(link)
    with pytest.raises(ScanRootError, match="folder"):
        validate_scan_root(file_path)


def test_xdg_locations_use_glib_values_then_standard_fallbacks(tmp_path: Path) -> None:
    home = tmp_path / "home"
    config = tmp_path / "config"
    config.mkdir()
    configured_downloads = home / "custom-downloads"
    (config / "user-dirs.dirs").write_text(
        'XDG_DOWNLOAD_DIR="${HOME}/custom-downloads"\n', encoding="utf-8"
    )
    xdg_cache = tmp_path / "xdg-cache"

    paths = resolve_xdg_locations(
        home_dir=home,
        cache_dir=None,
        downloads_dir=None,
        config_dir=config,
        environ={"XDG_CACHE_HOME": str(xdg_cache)},
    )

    assert paths == {
        "home": home,
        "caches": xdg_cache,
        "downloads": configured_downloads,
    }


def test_xdg_cache_falls_back_to_home_cache_and_missing_download_is_hidden(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    paths = resolve_xdg_locations(
        home_dir=home,
        cache_dir=None,
        downloads_dir=None,
        config_dir=tmp_path / "missing-config",
        environ={},
    )

    assert paths["caches"] == home / ".cache"
    assert paths["downloads"] is None


def test_scan_options_map_to_scanner_arguments() -> None:
    assert scanner_arguments(ScanOptions(False, False)) == {
        "include_hidden": False,
        "stay_on_device": False,
    }


def test_recent_scan_lookup_reads_only_synthetic_local_history(tmp_path: Path) -> None:
    history = History(tmp_path / "history.jsonl")
    first = tmp_path / "first"
    second = tmp_path / "second"
    history.record_scan(first, 100, timestamp=1000)
    history.append({"record_type": "cleanup", "path": str(first)})
    history.record_scan(second, 200, partial=True, timestamp=2000)

    record = history.latest_scan()

    assert record is not None
    assert record["path"] == str(second)
    assert record["size_bytes"] == 200
    assert record["partial"] is True
    assert recent_scan_record(history.recent()) == record
    assert format_age(90) == "1 min ago"
