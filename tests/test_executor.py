from __future__ import annotations

import os
from pathlib import Path

import pytest

from clearspace.contracts import Node, Risk
from clearspace.core import Candidate, History, execute_cleanup
from clearspace.executor import (
    ActiveApplicationError,
    ActiveProcessPath,
    OutsideScanRootError,
    PERMANENT_CONFIRMATION,
    FileAction,
    ItemExecutor,
    UnsafePathError,
    build_review,
    _error_kind,
    _protected_rule_match,
)
import clearspace.executor as executor_module
from clearspace.rules import RuleEngine


class MemoryHistory:
    def __init__(self):
        self.records = []

    def append(self, record):
        self.records.append(record)


class FakeTrash:
    def __init__(self, error: Exception | None = None):
        self.paths = []
        self.error = error

    def __call__(self, path: Path):
        if self.error:
            raise self.error
        self.paths.append(path)


def make_target(tmp_path: Path, name="target") -> tuple[Path, Path]:
    root = tmp_path / "allowed"
    root.mkdir()
    target = root / name
    target.write_bytes(b"sample content")
    return root, target


def test_review_is_minimal_and_gio_trash_is_itemwise(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    folder = root / "folder"
    folder.mkdir(parents=True)
    child = folder / "child"
    child.write_bytes(b"child data")
    history = MemoryHistory()
    trash = FakeTrash()
    review = build_review([folder, child], allowed_root=root)
    result = ItemExecutor(history, trash=trash).execute_one(review, folder)

    assert [item.path for item in review.items] == [folder]
    assert review.total_size_bytes > 0
    assert "esvaziar a lixeira" in review.notice
    assert result.success
    assert trash.paths == [folder]
    assert len(history.records) == 1
    assert history.records[0]["action"] == "trash"
    assert history.records[0]["result"] == "success"
    assert "started_at" in history.records[0] and "finished_at" in history.records[0]
    assert history.records[0]["filesystem_before"]["free_bytes"]


def test_user_data_requires_reinforced_confirmation(tmp_path: Path) -> None:
    root, target = make_target(tmp_path)
    review = build_review([target], allowed_root=root, risks={target: Risk.USER_DATA})
    history = MemoryHistory()
    trash = FakeTrash()
    executor = ItemExecutor(history, trash=trash)

    denied = executor.execute_one(review, target)
    allowed = executor.execute_one(review, target, user_data_confirmed=True)

    assert not denied.success
    assert "confirmação reforçada" in denied.record["failure_details"]
    assert allowed.success
    assert len(trash.paths) == 1


def test_critical_is_blocked_and_permanent_needs_typed_confirmation(tmp_path: Path) -> None:
    root, target = make_target(tmp_path)
    critical_review = build_review([target], allowed_root=root, risks={target: Risk.CRITICAL})
    trash = FakeTrash()
    history = MemoryHistory()
    executor = ItemExecutor(history, trash=trash)

    critical = executor.execute_one(critical_review, target, user_data_confirmed=True)
    assert not critical.success
    assert "Risco crítico" in critical.record["failure_details"]
    assert trash.paths == []

    normal_review = build_review([target], allowed_root=root)
    wrong_word = executor.execute_one(normal_review, target, FileAction.PERMANENT,
                                      typed_confirmation="yes")
    assert not wrong_word.success
    assert PERMANENT_CONFIRMATION in wrong_word.record["failure_details"]


def test_paths_outside_root_and_active_data_are_blocked(tmp_path: Path) -> None:
    root, target = make_target(tmp_path)
    outside = tmp_path / "outside"
    outside.write_bytes(b"not in allowed root")
    with pytest.raises(UnsafePathError, match="fora da raiz"):
        build_review([outside], allowed_root=root)

    with pytest.raises(UnsafePathError, match="protegido"):
        build_review([target], allowed_root=root, active_paths=(target,))

    with pytest.raises(UnsafePathError, match="raiz permitida"):
        build_review([root], allowed_root=root)


def test_canonical_protected_roots_are_blocked(tmp_path: Path, monkeypatch) -> None:
    root, _target = make_target(tmp_path)
    protected = root / "system-area"
    protected.mkdir()
    (protected / "config").write_text("synthetic", encoding="utf-8")
    monkeypatch.setattr(executor_module, "SYSTEM_PROTECTED", (str(protected),))

    with pytest.raises(UnsafePathError, match="protegido"):
        build_review([protected / "config"], allowed_root=root)


def test_nested_symlink_outside_root_blocks_the_whole_review(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    folder = root / "folder"
    folder.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (folder / "escape").symlink_to(outside, target_is_directory=True)

    with pytest.raises(UnsafePathError, match="Symlink escapa"):
        build_review([folder], allowed_root=root)


def test_revalidation_rejects_symlink_swap_after_review(tmp_path: Path) -> None:
    root, target = make_target(tmp_path)
    external = tmp_path / "external"
    external.write_bytes(b"outside")
    review = build_review([target], allowed_root=root)
    target.unlink()
    target.symlink_to(external)
    trash = FakeTrash()

    result = ItemExecutor(MemoryHistory(), trash=trash).execute_one(review, target)

    assert not result.success
    assert "Symlink aponta para fora da raiz do scan" in result.record["failure_details"]
    assert result.record["failure_kind"] == "outside_scan_root"
    assert trash.paths == []
    assert external.read_bytes() == b"outside"


def test_revalidation_detects_data_becoming_active(tmp_path: Path) -> None:
    root, target = make_target(tmp_path)
    review = build_review([target], allowed_root=root)
    active = []
    trash = FakeTrash()
    active.append(target)

    result = ItemExecutor(
        MemoryHistory(), trash=trash, active_paths=lambda: tuple(active)
    ).execute_one(review, target)

    assert not result.success
    assert "protegido" in result.record["failure_details"]
    assert trash.paths == []


def test_failed_gio_action_is_logged_as_failure(tmp_path: Path) -> None:
    root, target = make_target(tmp_path)
    review = build_review([target], allowed_root=root)
    history = MemoryHistory()
    result = ItemExecutor(history, trash=FakeTrash(OSError("trash unavailable"))).execute_one(
        review, target
    )

    assert not result.success
    assert result.record["result"] == "failed"
    assert "trash unavailable" in result.record["failure_details"]
    assert history.records == [result.record]


def test_chosen_root_outside_home_is_the_single_path_source(tmp_path: Path) -> None:
    root = tmp_path / "chosen-folder"
    root.mkdir()
    target = root / "nested" / "cache.bin"
    target.parent.mkdir()
    target.write_bytes(b"cache")
    review = build_review([target], allowed_root=root, active_paths=())
    history = MemoryHistory()
    trash = FakeTrash()

    result = ItemExecutor(history, trash=trash, active_paths=()).execute_one(review, target)

    assert root != Path.home()
    assert review.allowed_root == root.resolve()
    assert review.items[0].path == target.resolve()
    assert result.success
    assert trash.paths == [root / "nested" / "cache.bin"]
    assert history.records[0]["path"] == str(target.resolve())
    for protected_root in (Path("/"), Path("/usr"), Path.home()):
        with pytest.raises(UnsafePathError, match="protegida"):
            build_review([], allowed_root=protected_root, active_paths=())
    with pytest.raises(UnsafePathError, match="fora da raiz"):
        build_review([Path.home() / "not-a-target"], allowed_root=root, active_paths=())


def test_permission_failure_is_recorded_and_later_item_still_executes(tmp_path: Path) -> None:
    root = tmp_path / "chosen"
    blocked_parent = root / "read-only"
    writable_parent = root / "writable"
    blocked_parent.mkdir(parents=True)
    writable_parent.mkdir()
    blocked = blocked_parent / "blocked.bin"
    later = writable_parent / "later.bin"
    blocked.write_bytes(b"blocked")
    later.write_bytes(b"later")
    blocked_parent.chmod(0o555)
    try:
        review = build_review(
            [blocked, later], allowed_root=root, active_paths=()
        )
        assert any("não permite escrita" in warning for warning in review.items[0].warnings)
        history = MemoryHistory()
        executor = ItemExecutor(history, active_paths=())
        first = executor.execute_one(
            review, blocked, FileAction.PERMANENT,
            typed_confirmation=PERMANENT_CONFIRMATION,
        )
        second = executor.execute_one(
            review, later, FileAction.PERMANENT,
            typed_confirmation=PERMANENT_CONFIRMATION,
        )

        assert not first.success
        assert first.record["failure_kind"] == "filesystem_permission"
        assert first.record["exception_type"] == "PermissionError"
        assert second.success
        assert not later.exists()
        assert len(history.records) == 2
    finally:
        blocked_parent.chmod(0o755)


def test_missing_and_protected_items_have_distinct_failure_categories(tmp_path: Path) -> None:
    root, target = make_target(tmp_path)
    review = build_review([target], allowed_root=root, active_paths=())
    target.unlink()

    missing = ItemExecutor(MemoryHistory(), active_paths=()).execute_one(review, target)
    assert not missing.success
    assert missing.record["failure_kind"] == "missing"
    assert missing.record["exception_type"] == "FileNotFoundError"

    protected = root / "protected"
    protected.write_text("protected", encoding="utf-8")
    previous = executor_module.SYSTEM_PROTECTED
    executor_module.SYSTEM_PROTECTED = (*previous, str(protected))
    try:
        with pytest.raises(UnsafePathError, match="protegido"):
            build_review([protected], allowed_root=root, active_paths=())
        assert executor_module._error_kind(UnsafePathError("blocked")) == "app_protected"
    finally:
        executor_module.SYSTEM_PROTECTED = previous


def test_gio_not_supported_retains_domain_and_code_as_trash_unavailable() -> None:
    class GioLikeError(Exception):
        domain = "g-io-error-quark"
        code = 15

    assert executor_module._error_kind(GioLikeError()) == "trash_unavailable"


def test_gio_code_15_is_lixeira_indisponivel_not_permission(tmp_path: Path) -> None:
    class GioLikeError(Exception):
        domain = "g-io-error-quark"
        code = 15

    root, target = make_target(tmp_path)
    review = build_review([target], allowed_root=root, active_paths=(),
                          trash_support=lambda _path: False)
    result = ItemExecutor(
        MemoryHistory(), trash=FakeTrash(GioLikeError()), active_paths=()
    ).execute_one(review, target)

    assert not result.success
    assert result.record["failure_kind"] == "trash_unavailable"
    assert result.record["failure_kind"] != "filesystem_permission"
    assert result.record["glib_domain"] == "g-io-error-quark"
    assert result.record["glib_code"] == 15


def test_review_flags_item_on_filesystem_different_from_home(tmp_path: Path) -> None:
    root, target = make_target(tmp_path)
    home_device = target.stat().st_dev + 1
    review = build_review([target], allowed_root=root, active_paths=(),
                          home_device=home_device, trash_support=lambda _path: True)

    assert review.items[0].trash_supported is False
    assert "Este local não tem lixeira (partição diferente do home)" in review.items[0].warnings


def test_review_warns_when_item_owner_differs(tmp_path: Path, monkeypatch) -> None:
    root, target = make_target(tmp_path)
    monkeypatch.setattr(executor_module.os, "getuid", lambda: target.stat().st_uid + 1)

    review = build_review([target], allowed_root=root, active_paths=())

    assert any("pertence ao UID" in warning for warning in review.items[0].warnings)


def test_permanent_delete_removes_tree_without_following_internal_symlink(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    folder = root / "folder"
    folder.mkdir(parents=True)
    (folder / "file").write_bytes(b"inside")
    outside = root / "outside"
    outside.write_bytes(b"keep")
    (folder / "link").symlink_to(outside)
    review = build_review([folder], allowed_root=root)

    result = ItemExecutor(MemoryHistory()).execute_one(
        review, folder, FileAction.PERMANENT,
        typed_confirmation=PERMANENT_CONFIRMATION,
    )

    assert result.success
    assert not folder.exists()
    assert outside.read_bytes() == b"keep"


def test_legacy_command_cleanup_is_blocked_and_logged(tmp_path: Path, monkeypatch) -> None:
    history = History(tmp_path / "history.jsonl")
    finished = []
    candidate = Candidate(
        "fixture-command", "Fixture", "", None, None, ("dangerous-tool", "--all"), "Moderate"
    )
    monkeypatch.setattr(
        "clearspace.core.subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("legacy command must not execute"),
    )

    execute_cleanup(candidate, history, finished.append)

    record = history.recent(1)[0]
    assert record["result"] == "failed"
    assert record["action"] == "blocked_legacy_command"
    assert "desativada" in record["failure_details"]
    assert finished == [record]


def test_explicit_protected_roots_and_registry_caches(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for protected in (
        Path("/"), Path("/usr"), home, home / ".ssh", home / ".gnupg",
        home / ".config/Code/User",
    ):
        assert _protected_rule_match(protected) is not None
    assert _protected_rule_match(Path("/usr/share")) is not None
    assert _protected_rule_match(home / ".config/Code/User/settings.json") is not None

    cache_root = home / ".cache"
    vscode_cache = cache_root / "vscode-cpptools"
    vscode_cache.mkdir(parents=True)
    (vscode_cache / "index.db").write_bytes(b"index")
    review = build_review([vscode_cache], allowed_root=cache_root, active_paths=())
    assert review.items[0].path == vscode_cache.resolve()
    result = RuleEngine().evaluate(Node(vscode_cache, vscode_cache.name, True, 5))
    assert "Feche o VS Code; os índices serão recriados." in result.warnings
    assert result.risk is Risk.MODERATE

    go_cache = cache_root / "go-build"
    go_cache.mkdir()
    assert _protected_rule_match(go_cache) is None


def test_active_application_is_a_distinct_review_block(tmp_path: Path) -> None:
    root, target = make_target(tmp_path)
    active = ActiveProcessPath(target, "Visual Studio Code")
    with pytest.raises(
        ActiveApplicationError,
        match="Visual Studio Code.*Feche.*tente novamente",
    ) as exc:
        build_review([target], allowed_root=root, active_paths=(active,))
    assert _error_kind(exc.value) == "application_in_use"

    review = build_review([target], allowed_root=root, active_paths=())
    result = ItemExecutor(MemoryHistory(), active_paths=(active,)).execute_one(review, target)
    assert not result.success
    assert result.record["failure_kind"] == "application_in_use"
    assert "Visual Studio Code" in result.record["failure_message"]


def test_outside_scan_root_has_distinct_classification(tmp_path: Path) -> None:
    root, _target = make_target(tmp_path)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    with pytest.raises(OutsideScanRootError, match="fora da raiz do scan") as exc:
        build_review([outside], allowed_root=root, active_paths=())
    assert _error_kind(exc.value) == "outside_scan_root"


def test_protected_comparison_canonicalizes_symlink_target_and_rejects_parent_hops(
    tmp_path: Path, monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    ssh = home / ".ssh"
    ssh.mkdir()
    alias = tmp_path / "ssh-alias"
    alias.symlink_to(ssh, target_is_directory=True)
    assert _protected_rule_match(alias / "id_ed25519") == (
        "SSH credentials", ssh.resolve()
    )

    root, target = make_target(tmp_path)
    with pytest.raises(UnsafePathError, match="'..'"):
        build_review([root / "sub" / ".." / target.name], allowed_root=root, active_paths=())

    external = tmp_path / "external"
    external.write_text("outside", encoding="utf-8")
    escape = root / "escape"
    escape.symlink_to(external)
    with pytest.raises(OutsideScanRootError, match="Symlink aponta para fora"):
        build_review([escape], allowed_root=root, active_paths=())
