"""Regression tests for Pastas tree eligibility and v2 command generation."""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from clearspace.command_generator import default_protected_paths, generate_commands
from clearspace.contracts import Node
from clearspace.core import inspection_only_paths
from clearspace.executor import ActiveProcessPath
from clearspace.providers import (
    build_folder_selection_rows,
    collect_review_advisories,
    evaluate_tree_node_eligibility,
)
from clearspace.rules import RuleEngine


def test_inspection_only_paths_excludes_regenerable_caches(tmp_path: Path) -> None:
    home = tmp_path / "home"
    roots = inspection_only_paths(home)

    assert (home / ".local/share/Trash") in roots
    assert (home / ".cache/huggingface") in roots
    assert (home / ".gradle") not in roots
    assert (home / ".cache/yay") not in roots
    assert (home / ".codex") not in roots


def test_tree_node_eligibility_allows_regenerable_caches_and_regular_items(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    cache_dir = home / ".cache"
    yay_cache = cache_dir / "yay"
    go_cache = cache_dir / "go-build"
    hf_models = cache_dir / "huggingface"
    gradle_dir = home / ".gradle"
    gradle_caches = gradle_dir / "caches"
    downloads_dir = home / "Downloads"
    iso_file = downloads_dir / "linux-live.iso"
    repo_dir = home / "projects" / "app"
    node_modules = repo_dir / "node_modules"
    ssh_dir = home / ".ssh"
    config_dir = home / ".config"
    local_dir = home / ".local"
    trash_dir = local_dir / "share" / "Trash"
    db_file = downloads_dir / "places.sqlite"

    for directory in (
        yay_cache,
        go_cache,
        hf_models,
        gradle_caches,
        downloads_dir,
        repo_dir / ".git",
        node_modules,
        ssh_dir,
        config_dir,
        trash_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)
    iso_file.write_bytes(b"iso")
    db_file.write_bytes(b"sqlite")

    engine = RuleEngine(
        command_runner=lambda *a, **kw: subprocess.CompletedProcess(
            [], 0, stdout="", stderr=""
        )
    )
    protected = default_protected_paths(home)
    inspect_roots = inspection_only_paths(home)

    def check(path: Path, is_dir: bool = True):
        node = Node(path=path, name=path.name, is_dir=is_dir, size_bytes=4096)
        ev = engine.evaluate(node)
        return evaluate_tree_node_eligibility(
            node,
            scan_root=home,
            home_dir=home,
            protected_paths=protected,
            inspection_roots=inspect_roots,
            evaluation=ev,
        )

    # Regenerable caches and normal files/folders must be selectable!
    for allowed_dir in (yay_cache, go_cache, gradle_dir, gradle_caches, downloads_dir):
        res = check(allowed_dir, is_dir=True)
        assert res.selectable is True, f"{allowed_dir} should be selectable, got {res}"
        assert res.reason is None

    iso_res = check(iso_file, is_dir=False)
    assert iso_res.selectable is True
    assert iso_res.reason is None

    # Root / home itself is not bulk-selectable
    root_res = check(home, is_dir=True)
    assert root_res.selectable is False
    assert root_res.reason is not None

    # Enclosing ancestors of protected/inspect-only paths give an expand hint
    for ancestor in (cache_dir, local_dir, local_dir / "share"):
        anc_res = check(ancestor, is_dir=True)
        assert anc_res.selectable is False
        assert anc_res.reason is not None
        assert "expanda" in anc_res.reason.casefold()

    # Protected and user-data (inspect_only) targets are blocked with reason
    for blocked_dir in (hf_models, repo_dir, node_modules, ssh_dir, config_dir, trash_dir):
        blk_res = check(blocked_dir, is_dir=True)
        assert blk_res.selectable is False, f"{blocked_dir} must not be selectable"
        assert blk_res.reason is not None

    db_res = check(db_file, is_dir=False)
    assert db_res.selectable is False
    assert db_res.reason is not None


def test_folder_selection_generates_gio_trash_commands_and_never_rm(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    downloads = home / "Downloads"
    yay_cache = home / ".cache" / "yay"
    downloads.mkdir(parents=True)
    yay_cache.mkdir(parents=True)

    hostile_file = downloads / "relatorio final (1).tar.gz"
    hostile_file.write_bytes(b"data" * 200)
    (yay_cache / "pkg.tar.zst").write_bytes(b"pkg" * 100)

    engine = RuleEngine()
    protected = default_protected_paths(home)

    selected = (hostile_file, yay_cache)
    evaluations = {
        p: engine.evaluate(Node(p, p.name, p.is_dir(), 4096)) for p in selected
    }
    sizes = {hostile_file: 4096, yay_cache: 8192}

    rows = build_folder_selection_rows(
        selected,
        scan_root=home,
        sizes_by_path=sizes,
        evaluations_by_path=evaluations,
        protected_paths=protected,
    )
    gen = generate_commands(rows, protected_paths=protected)

    assert len(gen.generated) == 2
    assert not gen.blocked
    assert "rm " not in gen.script
    assert "rm -" not in gen.script

    cmd_lines = [
        line
        for line in gen.script.splitlines()
        if line.strip() and not line.startswith("#") and not line.startswith("df ")
    ]
    parsed_argvs = [shlex.split(line) for line in cmd_lines]
    assert ["gio", "trash", "--", str(hostile_file.resolve())] in parsed_argvs
    assert ["gio", "trash", "--", str(yay_cache.resolve())] in parsed_argvs


def test_folder_selection_blocks_user_data_and_ancestor_proc_cwd_is_ignored(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    downloads = home / "Downloads"
    repo = home / "work" / "service"
    (repo / ".git").mkdir(parents=True)
    downloads.mkdir(parents=True)
    archive = downloads / "backup.zip"
    archive.write_bytes(b"zip")

    protected = default_protected_paths(home)
    engine = RuleEngine(
        command_runner=lambda *a, **kw: subprocess.CompletedProcess(
            [], 0, stdout="", stderr=""
        )
    )

    rows = build_folder_selection_rows(
        (archive, repo),
        scan_root=home,
        sizes_by_path={archive: 4096, repo: 8192},
        evaluations_by_path={
            archive: engine.evaluate(Node(archive, archive.name, False, 4096)),
            repo: engine.evaluate(Node(repo, repo.name, True, 8192)),
        },
        protected_paths=protected,
    )
    gen = generate_commands(rows, protected_paths=protected)

    assert len(gen.generated) == 1
    assert gen.generated[0].command_line == f"gio trash -- {shlex.quote(str(archive.resolve()))}"
    assert len(gen.blocked) == 1
    assert gen.blocked[0].reason.kind == "inspect_only"

    # Compositor with cwd at home must NOT flag descendant archive as in use
    advisories_ancestor = collect_review_advisories(
        rows,
        home_dir=home,
        active_paths=(ActiveProcessPath(home, "Hyprland"),),
    )
    assert not any("Hyprland" in note for note in advisories_ancestor)

    # Process holding open file inside selected target DOES emit informational note
    advisories_exact = collect_review_advisories(
        rows,
        home_dir=home,
        active_paths=(ActiveProcessPath(archive, "ark"),),
    )
    assert any("ark" in note for note in advisories_exact)
