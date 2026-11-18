"""TDD and SQLite contract tests for Phase 4 providers (Large Files and Logs)."""

from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from clearspace.command_generator import (
    ADMIN_SECTION_HEADER,
    default_protected_paths,
    generate_commands,
)
from clearspace.provider_contract import (
    PROVIDER_ROW_LIMIT,
    SCANNER_SCHEMA_VERSION,
    CommandProbeResult,
    ProviderContext,
)
from clearspace.providers import (
    LargeFilesProvider,
    LogsProvider,
    get_provider,
    parse_journal_usage_bytes,
)
from clearspace.rust_scanner import RustScannerError, RustTreeScanner

BIN = Path(__file__).resolve().parents[1] / "scanner" / "target" / "release" / "clearspace-scan"


def _write_sized(path: Path, payload: bytes) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path.lstat().st_blocks * 512


def _make_phase4_context(
    tmp_path: Path,
    *,
    scan_db_path: Path | None = None,
    scan_root: Path | None = None,
    downloads_dir: Path | None = None,
    system_log_dir: Path | None = None,
    large_files_min_bytes: int = 0,
    large_files_downloads_only: bool = False,
    available_tools: set[str] | None = None,
    probe_outputs: dict[tuple[str, ...], CommandProbeResult | Exception] | None = None,
) -> tuple[ProviderContext, list[tuple[str, ...]]]:
    home = tmp_path / "home"
    xdg_cache = home / ".cache"
    xdg_data = home / ".local" / "share"
    xdg_state = home / ".local" / "state"
    xdg_config = home / ".config"
    dl_dir = downloads_dir if downloads_dir is not None else (home / "Downloads")
    sys_logs = system_log_dir if system_log_dir is not None else (tmp_path / "var_log")
    for directory in (home, xdg_cache, xdg_data, xdg_state, xdg_config, dl_dir):
        directory.mkdir(parents=True, exist_ok=True)

    tools = available_tools if available_tools is not None else {"journalctl"}
    probes = probe_outputs or {}
    calls: list[tuple[str, ...]] = []

    def fake_runner(argv, timeout: float) -> CommandProbeResult:
        key = tuple(argv)
        calls.append(key)
        assert timeout > 0
        outcome = probes.get(key, CommandProbeResult(returncode=1, stdout="", stderr="unmocked"))
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def fake_which(binary: str) -> str | None:
        return f"/usr/bin/{binary}" if binary in tools else None

    os_release = tmp_path / "os-release"
    os_release.write_text("ID=arch\n", encoding="utf-8")

    ctx = ProviderContext(
        xdg_cache_home=xdg_cache,
        xdg_data_home=xdg_data,
        xdg_state_home=xdg_state,
        xdg_config_home=xdg_config,
        downloads_dir=dl_dir,
        scan_db_path=scan_db_path,
        scan_root=scan_root,
        os_release_path=os_release,
        run_readonly_command=fake_runner,
        protected_paths=default_protected_paths(home),
        home_dir=home,
        environ={},
        which=fake_which,
        large_files_min_bytes=large_files_min_bytes,
        large_files_downloads_only=large_files_downloads_only,
        system_log_dir=sys_logs,
    )
    return ctx, calls


@pytest.mark.skipif(not BIN.is_file(), reason="build scanner Rust with cargo build --release")
def test_rust_scanner_writes_schema_version_pragma_and_supports_version_flag(
    tmp_path: Path,
) -> None:
    ver_proc = subprocess.run(
        [str(BIN), "--version"],
        capture_output=True,
        text=True,
        check=True,
        shell=False,
    )
    assert "clearspace-scan" in ver_proc.stdout
    assert f"schema={SCANNER_SCHEMA_VERSION}" in ver_proc.stdout

    scan_root = tmp_path / "scan_root"
    scan_root.mkdir()
    _write_sized(scan_root / "sample.bin", b"A" * 4096)
    db_path = tmp_path / "db" / "scan.sqlite"

    completed_proc = subprocess.run(
        [str(BIN), str(scan_root), "--db", str(db_path)],
        capture_output=True,
        text=True,
        check=True,
        shell=False,
    )
    events = [json.loads(line) for line in completed_proc.stdout.splitlines()]
    completed_event = events[-1]
    assert completed_event["event"] == "completed"
    assert completed_event["schema_version"] == SCANNER_SCHEMA_VERSION

    with sqlite3.connect(f"{db_path.as_uri()}?mode=ro", uri=True) as conn:
        user_ver = conn.execute("PRAGMA user_version").fetchone()[0]
    assert user_ver == SCANNER_SCHEMA_VERSION


@pytest.mark.skipif(not BIN.is_file(), reason="build scanner Rust with cargo build --release")
def test_large_files_contract_against_real_rust_scanner_database(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    downloads = home / "Downloads"
    videos = home / "Videos"
    repo = home / "projects" / "demo_repo"
    (repo / ".git").mkdir(parents=True)
    ssh_dir = home / ".ssh"

    iso_bytes = _write_sized(downloads / "arch-test.iso", b"I" * 32768)
    video_bytes = _write_sized(videos / "recording.mkv", b"V" * 16384)
    _write_sized(repo / "artifact.bin", b"R" * 12288)
    _write_sized(ssh_dir / "id_ed25519", b"K" * 8192)
    _write_sized(home / "local.sqlite", b"D" * 8192)

    # Add > 200 smaller files to exercise LIMIT 200 + smaller_count/smaller_bytes.
    for idx in range(205):
        _write_sized(home / "bulk" / f"tiny_{idx:03d}.dat", b"t" * 512)

    scanner = RustTreeScanner(home, binary=BIN, cache_dir=tmp_path / "scan_cache")
    try:
        scanner.scan_root()
        ctx, _ = _make_phase4_context(
            tmp_path,
            scan_db_path=scanner.database_path,
            scan_root=scanner.root_path,
            downloads_dir=downloads,
            large_files_min_bytes=0,
        )
        result = LargeFilesProvider().load(ctx)
        assert result.error is None
        assert len(result.rows) == PROVIDER_ROW_LIMIT
        assert result.smaller_count == 10  # 210 regular files total - 200 visible
        assert result.smaller_bytes > 0

        top_by_label = {row.label: row for row in result.rows[:6]}
        iso_row = next(r for r in result.rows if r.label.endswith("arch-test.iso"))
        assert iso_row.size_bytes == iso_bytes
        assert iso_row.action == "trash_path"
        assert iso_row.allowed_root == scanner.root_path

        video_row = next(r for r in result.rows if r.label.endswith("recording.mkv"))
        assert video_row.size_bytes == video_bytes
        assert video_row.action == "trash_path"

        # Git repo file, SSH credential, and SQLite database must NOT be trashable.
        repo_row = next(r for r in result.rows if r.label.endswith("artifact.bin"))
        assert repo_row.action == "inspect_only"

        ssh_row = next(r for r in result.rows if r.label.endswith("id_ed25519"))
        assert ssh_row.action == "inspect_only"
        assert ssh_row.risk == "critical"

        db_row = next(r for r in result.rows if r.label.endswith("local.sqlite"))
        assert db_row.action == "inspect_only"
        assert top_by_label  # sanity check

        # Minimum size filter keeps only >= 14 KiB files (iso + video).
        filtered_ctx, _ = _make_phase4_context(
            tmp_path,
            scan_db_path=scanner.database_path,
            scan_root=scanner.root_path,
            downloads_dir=downloads,
            large_files_min_bytes=14 * 1024,
        )
        filtered = LargeFilesProvider().load(filtered_ctx)
        assert [r.path.name for r in filtered.rows if r.path] == [
            "arch-test.iso",
            "recording.mkv",
        ]

        # Downloads-only shortcut keeps only entries inside XDG Downloads.
        dl_ctx, _ = _make_phase4_context(
            tmp_path,
            scan_db_path=scanner.database_path,
            scan_root=scanner.root_path,
            downloads_dir=downloads,
            large_files_min_bytes=1024,
            large_files_downloads_only=True,
        )
        dl_res = LargeFilesProvider().load(dl_ctx)
        assert len(dl_res.rows) == 1
        assert dl_res.rows[0].path == downloads / "arch-test.iso"

        gen = generate_commands([iso_row, video_row], protected_paths=ctx.protected_paths)
        assert gen.blocked == ()
        assert len(gen.generated) == 2
    finally:
        scanner.close()


def test_large_files_rejects_mismatched_sqlite_schema_version_and_supports_downloads_fallback(
    tmp_path: Path,
) -> None:
    bad_db = tmp_path / "bad_version.sqlite"
    with sqlite3.connect(bad_db) as conn:
        conn.execute("PRAGMA user_version = 999;")
        conn.execute(
            "CREATE TABLE nodes (id INTEGER PRIMARY KEY, parent_id INTEGER, "
            "name TEXT NOT NULL, is_dir INTEGER NOT NULL, size_blocks INTEGER NOT NULL, "
            "mtime INTEGER, error TEXT, partial INTEGER NOT NULL DEFAULT 0, "
            "child_count INTEGER NOT NULL DEFAULT 0, child_size_blocks INTEGER NOT NULL DEFAULT 0);"
        )

    ctx, _ = _make_phase4_context(
        tmp_path,
        scan_db_path=bad_db,
        scan_root=tmp_path / "home",
    )
    mismatch = LargeFilesProvider().load(ctx)
    assert mismatch.error is not None
    assert mismatch.error.kind == "invalid_row"
    assert "versão" in mismatch.error.message.casefold()

    # Also verify RustTreeScanner._connect rejects incompatible user_version.
    dummy_scanner = object.__new__(RustTreeScanner)
    dummy_scanner.database_path = bad_db
    with pytest.raises(RustScannerError, match="(?i)versão"):
        dummy_scanner._connect()

    # Without an active scan DB, Downloads shortcut scans XDG Downloads directly.
    dl_dir = tmp_path / "home" / "Downloads"
    _write_sized(dl_dir / "installer.tar.zst", b"Z" * 16384)
    dl_only_ctx, _ = _make_phase4_context(
        tmp_path,
        scan_db_path=None,
        scan_root=None,
        downloads_dir=dl_dir,
        large_files_downloads_only=True,
    )
    dl_fallback = LargeFilesProvider().load(dl_only_ctx)
    assert dl_fallback.error is None
    assert len(dl_fallback.rows) == 1
    assert dl_fallback.rows[0].path == dl_dir / "installer.tar.zst"


def test_logs_provider_parses_journal_discovers_state_and_system_logs_and_separates_admin(
    tmp_path: Path,
) -> None:
    assert parse_journal_usage_bytes("Archived and active journals take up 320.0M in the file system.") == 320 * 1024 * 1024
    assert parse_journal_usage_bytes("Archived and active journals take up 1.5G in the file system.") == int(1.5 * 1024**3)

    sys_logs = tmp_path / "var_log"
    _write_sized(sys_logs / "pacman.log", b"P" * 8192)

    ctx, calls = _make_phase4_context(
        tmp_path,
        system_log_dir=sys_logs,
        probe_outputs={
            ("journalctl", "--disk-usage"): CommandProbeResult(
                returncode=0,
                stdout="Archived and active journals take up 256.0M in the file system.\n",
                stderr="",
            )
        },
    )
    state_log = ctx.xdg_state_home / "app" / "service.log"
    state_log_bytes = _write_sized(state_log, b"L" * 8192)
    # Non-log SQLite state database in XDG_STATE_HOME must stay inspect_only!
    _write_sized(ctx.xdg_state_home / "app" / "history.sqlite", b"S" * 8192)

    result = LogsProvider().load(ctx)
    assert result.error is None
    assert ("journalctl", "--disk-usage") in calls

    rows_by_id = {row.id: row for row in result.rows}
    journal_row = rows_by_id["logs.systemd.journal"]
    assert journal_row.action == "tool_command"
    assert journal_row.argv == ("journalctl", "--vacuum-size=200M")
    assert journal_row.needs_admin is True
    assert journal_row.risk == "medium"
    assert journal_row.size_bytes == 256 * 1024 * 1024

    user_log_row = next(r for r in result.rows if r.path == state_log)
    assert user_log_row.action == "trash_path"
    assert user_log_row.size_bytes == state_log_bytes
    assert user_log_row.allowed_root == ctx.xdg_state_home.resolve()

    sys_log_row = next(r for r in result.rows if "pacman.log" in r.label)
    assert sys_log_row.action == "inspect_only"
    assert sys_log_row.path is None

    state_db_row = next(
        (r for r in result.rows if "history.sqlite" in r.label),
        None,
    )
    if state_db_row is not None:
        assert state_db_row.action == "inspect_only"

    # Generate commands: user log goes to user section, journalctl goes to admin block!
    gen = generate_commands([user_log_row, journal_row], protected_paths=ctx.protected_paths)
    assert gen.blocked == ()
    assert not any(line.lstrip().startswith("#") for line in gen.script.splitlines())
    assert "gio trash --" in gen.user_script
    assert "sudo" not in gen.user_script
    assert "sudo journalctl --vacuum-size=200M" in gen.admin_script
    assert "gio trash --" not in gen.admin_script


def test_logs_provider_classifies_timeout_and_registers_phase4_providers(
    tmp_path: Path,
) -> None:
    assert isinstance(get_provider("large_files"), LargeFilesProvider)
    assert isinstance(get_provider("logs"), LogsProvider)

    ctx, _ = _make_phase4_context(
        tmp_path,
        probe_outputs={
            ("journalctl", "--disk-usage"): subprocess.TimeoutExpired(
                cmd=["journalctl", "--disk-usage"], timeout=5.0
            )
        },
    )
    res = LogsProvider().load(ctx)
    assert res.error is not None
    assert res.error.kind == "timeout"
