from __future__ import annotations

import subprocess
from pathlib import Path

from clearspace.contracts import Node, Risk
from clearspace.rules import PROCEDURES, RuleEngine


def test_generic_categories_return_expected_risks(tmp_path: Path) -> None:
    engine = RuleEngine()
    cases = [
        (tmp_path / "project" / "node_modules", True, Risk.MODERATE),
        (tmp_path / ".local" / "share" / "Trash", True, Risk.USER_DATA),
        (tmp_path / ".config" / "google-chrome", True, Risk.USER_DATA),
        (tmp_path / "docker" / "volumes" / "db" / "_data", True, Risk.USER_DATA),
        (tmp_path / ".cache" / "huggingface" / "models", True, Risk.USER_DATA),
        (tmp_path / ".ssh", True, Risk.CRITICAL),
    ]

    for path, is_dir, risk in cases:
        evaluation = engine.evaluate(Node(path, path.name, is_dir, 10))
        assert evaluation.risk is risk
        assert evaluation.warnings


def test_procedure_recommendation_only_appears_when_tool_exists(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr("clearspace.contracts.shutil.which", lambda _tool: None)
    engine = RuleEngine()
    cache = Node(tmp_path / "go-build", "go-build", True, 100)

    assert engine.evaluate(cache).recommended_procedure is None
    assert engine.available_procedures() == ()

    monkeypatch.setattr("clearspace.contracts.shutil.which", lambda tool: f"/bin/{tool}")
    result = engine.evaluate(cache)
    assert result.recommended_procedure is not None
    assert result.recommended_procedure.id == "go-build-cache"


def test_git_status_uses_argv_without_shell_and_warns_on_changes(
    tmp_path: Path, monkeypatch
) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / ".git").mkdir()
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout=" M file.txt\n", stderr="")

    monkeypatch.setattr("clearspace.rules.shutil.which", lambda tool: "/usr/bin/git")
    engine = RuleEngine(command_runner=runner)
    result = engine.evaluate(Node(repo_path, "repo", True, 20))

    assert result.category == "git_repository"
    assert result.git_has_uncommitted_changes is True
    assert any("não commitadas" in warning for warning in result.warnings)
    argv, options = calls[0]
    assert argv == ["git", "-C", str(repo_path), "status", "--porcelain"]
    assert options["shell"] is False


def test_git_status_failure_is_reported(tmp_path: Path, monkeypatch) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / ".git").mkdir()

    def runner(argv, **_kwargs):
        return subprocess.CompletedProcess(argv, 128, stdout="", stderr="permission denied")

    monkeypatch.setattr("clearspace.rules.shutil.which", lambda tool: "/usr/bin/git")
    evaluation = RuleEngine(command_runner=runner).evaluate(
        Node(repo_path, "repo", True, 20)
    )

    assert evaluation.git_has_uncommitted_changes is None
    assert any("permission denied" in warning for warning in evaluation.warnings)


def test_admin_procedures_are_copy_only_and_tool_detected(monkeypatch) -> None:
    journal = next(item for item in PROCEDURES if item.id == "journal-trim")
    monkeypatch.setattr("clearspace.contracts.shutil.which", lambda tool: "/usr/bin/journalctl")

    assert journal.available
    assert journal.requires_admin
    assert journal.command_to_copy == ("journalctl", "--vacuum-size=200M")
