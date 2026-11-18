"""TDD tests for Phase 3 providers (Caches and Trash) in synthetic tmp_path trees."""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from clearspace.command_generator import default_protected_paths, generate_commands
from clearspace.provider_contract import (
    PROVIDER_ROW_LIMIT,
    CommandProbeResult,
    ProtectedPath,
    ProviderContext,
    run_readonly_subprocess,
)
from clearspace.providers import (
    RISK_LABELS_PT_BR,
    CachesProvider,
    TrashProvider,
    collect_review_advisories,
    format_age_pt_br,
    format_smaller_summary_pt_br,
    get_provider,
    is_row_selectable,
    measure_allocated_bytes,
)


def _write_sized_file(path: Path, payload: bytes = b"x" * 4096) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path.lstat().st_blocks * 512


def _make_context(
    tmp_path: Path,
    *,
    available_tools: set[str] | None = None,
    probe_outputs: dict[tuple[str, ...], CommandProbeResult | Exception] | None = None,
    environ: dict[str, str] | None = None,
    extra_protected: tuple[ProtectedPath, ...] = (),
) -> tuple[ProviderContext, list[tuple[str, ...]]]:
    home = tmp_path / "home"
    xdg_cache = home / ".cache"
    xdg_data = home / ".local" / "share"
    xdg_state = home / ".local" / "state"
    xdg_config = home / ".config"
    for directory in (home, xdg_cache, xdg_data, xdg_state, xdg_config):
        directory.mkdir(parents=True, exist_ok=True)

    tools = available_tools or set()
    probes = probe_outputs or {}
    calls: list[tuple[str, ...]] = []

    def fake_runner(argv, timeout: float) -> CommandProbeResult:
        key = tuple(argv)
        calls.append(key)
        assert timeout > 0
        outcome = probes.get(key, CommandProbeResult(returncode=1, stdout="", stderr="not mocked"))
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def fake_which(binary: str) -> str | None:
        return f"/usr/bin/{binary}" if binary in tools else None

    os_release = tmp_path / "os-release"
    os_release.write_text("ID=arch\n", encoding="utf-8")

    protected = default_protected_paths(home) + extra_protected
    ctx = ProviderContext(
        xdg_cache_home=xdg_cache,
        xdg_data_home=xdg_data,
        xdg_state_home=xdg_state,
        xdg_config_home=xdg_config,
        downloads_dir=home / "Downloads",
        scan_db_path=None,
        scan_root=None,
        os_release_path=os_release,
        run_readonly_command=fake_runner,
        protected_paths=protected,
        home_dir=home,
        environ=environ or {},
        which=fake_which,
    )
    return ctx, calls


def test_measure_allocated_bytes_counts_hardlinks_once_and_ignores_symlinks(
    tmp_path: Path,
) -> None:
    tree = tmp_path / "sample_cache"
    first = tree / "a.bin"
    second = tree / "b_hardlink.bin"
    outside = tmp_path / "outside_secret.bin"
    _write_sized_file(outside, b"Z" * 16384)

    file_alloc = _write_sized_file(first, b"A" * 8192)
    os.link(first, second)
    (tree / "escape_link").symlink_to(outside)

    seen_inodes: set[tuple[int, int]] = set()
    total = measure_allocated_bytes(tree, seen_inodes=seen_inodes)
    dir_alloc = tree.lstat().st_blocks * 512
    link_alloc = (tree / "escape_link").lstat().st_blocks * 512

    # Hardlinked regular file is counted once; symlink target is never followed.
    assert total == dir_alloc + file_alloc + link_alloc


def test_caches_provider_discovers_xdg_and_dev_caches_with_tool_and_trash_actions(
    tmp_path: Path,
) -> None:
    ctx, calls = _make_context(
        tmp_path,
        available_tools={"pip", "go", "pnpm", "npm"},
        probe_outputs={
            ("go", "env", "GOCACHE"): CommandProbeResult(
                returncode=0,
                stdout=f"{tmp_path / 'home' / '.cache' / 'go-build'}\n",
                stderr="",
            )
        },
    )
    assert ctx.home_dir is not None

    _write_sized_file(ctx.xdg_cache_home / "pip" / "http" / "wheel.whl", b"p" * 8192)
    _write_sized_file(ctx.xdg_cache_home / "go-build" / "00" / "obj.a", b"g" * 8192)
    _write_sized_file(ctx.xdg_cache_home / "pnpm" / "dlx" / "pkg.tgz", b"n" * 4096)
    _write_sized_file(ctx.home_dir / ".npm" / "_cacache" / "index.json", b"m" * 4096)
    _write_sized_file(ctx.home_dir / ".gradle" / "caches" / "modules-2" / "jar.bin", b"j" * 8192)
    _write_sized_file(ctx.home_dir / ".cargo" / "registry" / "cache" / "crate.crate", b"c" * 4096)
    _write_sized_file(ctx.xdg_cache_home / "mesa_shader_cache" / "shader.bin", b"s" * 4096)

    provider = CachesProvider()
    result = provider.load(ctx)

    assert result.error is None
    assert ("go", "env", "GOCACHE") in calls
    rows_by_id = {row.id: row for row in result.rows}

    assert rows_by_id["cache.pip"].action == "tool_command"
    assert rows_by_id["cache.pip"].argv == ("pip", "cache", "purge")
    assert rows_by_id["cache.pip"].path is None

    assert rows_by_id["cache.go.build"].action == "tool_command"
    assert rows_by_id["cache.go.build"].argv == ("go", "clean", "-cache")

    assert rows_by_id["cache.pnpm"].action == "tool_command"
    assert rows_by_id["cache.pnpm"].argv == ("pnpm", "store", "prune")

    assert rows_by_id["cache.npm"].action == "tool_command"
    assert rows_by_id["cache.npm"].argv == ("npm", "cache", "clean", "--force")

    assert rows_by_id["cache.gradle"].action == "trash_path"
    assert rows_by_id["cache.gradle"].path == ctx.home_dir / ".gradle" / "caches"
    assert rows_by_id["cache.gradle"].allowed_root == ctx.home_dir / ".gradle"

    assert rows_by_id["cache.cargo.registry"].action == "trash_path"
    assert rows_by_id["cache.cargo.registry"].path == (
        ctx.home_dir / ".cargo" / "registry" / "cache"
    )

    shader_row = rows_by_id["cache.xdg.mesa_shader_cache"]
    assert shader_row.action == "trash_path"
    assert shader_row.path == ctx.xdg_cache_home / "mesa_shader_cache"
    assert shader_row.allowed_root == ctx.xdg_cache_home.resolve()

    # No duplicate XDG generic rows for pip/go-build/pnpm.
    assert "cache.xdg.pip" not in rows_by_id
    assert "cache.xdg.go-build" not in rows_by_id
    assert "cache.xdg.pnpm" not in rows_by_id

    for row in result.rows:
        assert row.risk == "low"
        assert any("será baixado de novo" in w for w in row.warnings)

    # Every actionable cache row must pass command_generator cleanly.
    gen = generate_commands(result.rows, protected_paths=ctx.protected_paths)
    assert gen.blocked == ()
    assert len(gen.generated) == len(result.rows)


def test_caches_provider_falls_back_to_trash_path_when_cli_tools_absent(
    tmp_path: Path,
) -> None:
    ctx, calls = _make_context(tmp_path, available_tools=set())
    assert ctx.home_dir is not None

    _write_sized_file(ctx.xdg_cache_home / "pip" / "pkg.whl", b"p" * 4096)
    _write_sized_file(ctx.xdg_cache_home / "go-build" / "obj", b"g" * 4096)
    _write_sized_file(ctx.home_dir / ".npm" / "_cacache" / "blob", b"n" * 4096)

    result = CachesProvider().load(ctx)
    assert calls == []
    rows_by_id = {row.id: row for row in result.rows}

    for row_id in ("cache.pip", "cache.go.build", "cache.npm"):
        row = rows_by_id[row_id]
        assert row.action == "trash_path"
        assert row.argv is None
        assert row.path is not None
        assert row.allowed_root is not None

    gen = generate_commands(result.rows, protected_paths=ctx.protected_paths)
    assert gen.blocked == ()
    assert len(gen.generated) == 3


def test_caches_provider_protects_exact_user_data_subdir_without_blocking_whole_cache(
    tmp_path: Path,
) -> None:
    ctx, _ = _make_context(tmp_path)
    _write_sized_file(ctx.xdg_cache_home / "huggingface" / "hub" / "weights.bin", b"w" * 8192)
    _write_sized_file(ctx.xdg_cache_home / "thumbnails" / "thumb.png", b"t" * 4096)

    result = CachesProvider().load(ctx)
    rows_by_id = {row.id: row for row in result.rows}

    hf_row = rows_by_id["cache.xdg.huggingface"]
    assert hf_row.action == "inspect_only"
    assert hf_row.risk == "high"
    assert hf_row.path is None

    thumb_row = rows_by_id["cache.xdg.thumbnails"]
    assert thumb_row.action == "trash_path"
    assert thumb_row.risk == "low"

    gen = generate_commands([hf_row, thumb_row], protected_paths=ctx.protected_paths)
    assert [item.row_id for item in gen.generated] == ["cache.xdg.thumbnails"]
    assert [item.row_id for item in gen.blocked] == ["cache.xdg.huggingface"]


def test_caches_provider_enforces_200_row_limit_and_precomputes_smaller_items(
    tmp_path: Path,
) -> None:
    ctx, _ = _make_context(tmp_path)
    for idx in range(215):
        payload = b"x" * (4096 if idx < 200 else 512)
        _write_sized_file(ctx.xdg_cache_home / f"app_{idx:03d}" / "entry.bin", payload)

    result = CachesProvider().load(ctx)
    assert result.error is None
    assert len(result.rows) == PROVIDER_ROW_LIMIT
    assert result.smaller_count == 15
    assert result.smaller_bytes > 0
    sizes = [row.size_bytes or 0 for row in result.rows]
    assert sizes == sorted(sizes, reverse=True)


def test_trash_provider_lists_items_by_size_parses_trashinfo_and_stays_inspect_only(
    tmp_path: Path,
) -> None:
    ctx, _ = _make_context(tmp_path)
    trash_files = ctx.xdg_data_home / "Trash" / "files"
    trash_info = ctx.xdg_data_home / "Trash" / "info"
    trash_files.mkdir(parents=True)
    trash_info.mkdir(parents=True)

    big_bytes = _write_sized_file(trash_files / "archive.tar", b"A" * 16384)
    small_bytes = _write_sized_file(trash_files / "notes.txt", b"B" * 2048)

    (trash_info / "archive.tar.trashinfo").write_text(
        "[Trash Info]\nPath=/tmp/synthetic/archive.tar\nDeletionDate=2026-11-10T12:30:00\n",
        encoding="utf-8",
    )

    result = TrashProvider().load(ctx)
    assert result.error is None
    assert [row.label for row in result.rows] == ["archive.tar", "notes.txt"]
    assert result.rows[0].size_bytes == big_bytes
    assert result.rows[1].size_bytes == small_bytes

    expected_dt = datetime(2026, 11, 10, 12, 30, 0)
    assert result.rows[0].mtime_ns == int(expected_dt.timestamp() * 1_000_000_000)
    assert result.rows[1].mtime_ns is not None

    for row in result.rows:
        assert row.action == "inspect_only"
        assert row.risk == "high"
        assert row.path is None
        assert row.argv is None

    # Trash items never generate commands even if passed to generate_commands.
    gen = generate_commands(result.rows, protected_paths=ctx.protected_paths)
    assert gen.generated == ()
    assert gen.script == ""
    assert len(gen.blocked) == 2


def test_trash_provider_handles_missing_trash_and_classifies_permission_and_symlink(
    tmp_path: Path,
) -> None:
    ctx, _ = _make_context(tmp_path)
    # Missing Trash/files is normal on fresh accounts -> empty result, no error.
    empty = TrashProvider().load(ctx)
    assert empty.error is None
    assert empty.rows == ()
    assert empty.smaller_count == 0
    assert empty.smaller_bytes == 0

    # Symlinked Trash/files is rejected as classified error ("symlink").
    trash_root = ctx.xdg_data_home / "Trash"
    trash_root.mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (trash_root / "files").symlink_to(elsewhere)
    symlink_res = TrashProvider().load(ctx)
    assert symlink_res.error is not None
    assert symlink_res.error.kind == "symlink"

    # Unreadable Trash/files directory -> classified error ("permission").
    (trash_root / "files").unlink()
    real_files = trash_root / "files"
    real_files.mkdir(mode=0o000)
    try:
        if os.geteuid() != 0:
            perm_res = TrashProvider().load(ctx)
            assert perm_res.error is not None
            assert perm_res.error.kind == "permission"
    finally:
        real_files.chmod(0o700)


def test_provider_registry_and_age_formatter_and_readonly_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert isinstance(get_provider("caches"), CachesProvider)
    assert isinstance(get_provider("trash"), TrashProvider)
    assert get_provider("nonexistent") is None

    now_ns = int(datetime(2026, 11, 17, 12, 0, 0, tzinfo=timezone.utc).timestamp() * 1e9)
    two_days_ago_ns = now_ns - int(2 * 86400 * 1e9)
    assert "2 dias" in format_age_pt_br(two_days_ago_ns, now_ns=now_ns)

    # Disallowed binaries cannot be invoked through run_readonly_subprocess.
    with pytest.raises(ValueError, match="not in the read-only allowlist"):
        run_readonly_subprocess(["rm", "-rf", str(tmp_path)], 2.0)

    def fake_subproc_run(argv, **kwargs):
        assert kwargs["shell"] is False
        assert kwargs["check"] is False
        return subprocess.CompletedProcess(argv, 0, stdout="/tmp/gocache\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_subproc_run)
    probe = run_readonly_subprocess(["go", "env", "GOCACHE"], 3.0)
    assert probe.returncode == 0
    assert probe.stdout == "/tmp/gocache\n"


def test_git_repo_in_cache_is_inspect_only_and_review_advisories_ignore_ancestor_cwd(
    tmp_path: Path,
) -> None:
    from clearspace.executor import ActiveProcessPath

    ctx, _ = _make_context(tmp_path)
    assert ctx.home_dir is not None

    aur_clone = ctx.xdg_cache_home / "aur_pkg_repo"
    (aur_clone / ".git").mkdir(parents=True)
    _write_sized_file(aur_clone / "PKGBUILD", b"pkgname=demo\n")

    shader_dir = ctx.xdg_cache_home / "shaders"
    shader_file = shader_dir / "pipeline.cache"
    _write_sized_file(shader_file, b"S" * 4096)

    result = CachesProvider().load(ctx)
    rows_by_id = {row.id: row for row in result.rows}
    assert rows_by_id["cache.xdg.aur_pkg_repo"].action == "inspect_only"
    assert rows_by_id["cache.xdg.aur_pkg_repo"].risk == "high"

    shader_row = rows_by_id["cache.xdg.shaders"]
    active = (
        # Ancestor cwd (e.g. compositor running in $HOME) MUST NOT trigger advisory.
        ActiveProcessPath(path=ctx.home_dir, application="Hyprland"),
        # Descendant open file inside shaders MUST trigger advisory.
        ActiveProcessPath(path=shader_file, application="GameApp"),
    )
    notes = collect_review_advisories([shader_row], home_dir=ctx.home_dir, active_paths=active)
    assert any("GameApp" in note for note in notes)
    assert not any("Hyprland" in note for note in notes)


def test_ui_helpers_and_no_gtk_import_in_domain_modules(tmp_path: Path) -> None:
    import sys

    ctx, _ = _make_context(tmp_path)
    _write_sized_file(ctx.xdg_cache_home / "ok_cache" / "f.bin", b"1" * 4096)
    _write_sized_file(ctx.xdg_cache_home / "huggingface" / "m.bin", b"2" * 4096)
    result = CachesProvider().load(ctx)
    rows_by_id = {row.id: row for row in result.rows}

    assert is_row_selectable(rows_by_id["cache.xdg.ok_cache"]) is True
    assert is_row_selectable(rows_by_id["cache.xdg.huggingface"]) is False
    assert RISK_LABELS_PT_BR["low"] == "Baixo"
    assert RISK_LABELS_PT_BR["critical"] == "Crítico"
    assert format_smaller_summary_pt_br(0, 0) == ""
    assert "3 itens menores omitidos" in format_smaller_summary_pt_br(3, 12288)

    # Pure logic modules must never pull in gi when imported in headless tests.
    assert "gi" not in sys.modules


