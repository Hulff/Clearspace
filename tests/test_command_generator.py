from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path

import pytest

from clearspace.command_generator import (
    BlockedItem,
    CommandGenerationResult,
    GeneratedItem,
    default_protected_paths,
    generate_commands,
)
from clearspace.core import History
from clearspace.provider_contract import (
    ClassifiedError,
    ProtectedPath,
    ProviderResult,
    Row,
)


def _base_protected(home: Path) -> tuple[ProtectedPath, ...]:
    return default_protected_paths(home=home)


def test_hostile_filenames_roundtrip_exact_argv_without_expansion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("subprocess.run forbidden")),
    )
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("subprocess.Popen forbidden")),
    )

    fake_home = tmp_path / "home"
    cache_root = fake_home / ".cache"
    cache_root.mkdir(parents=True)

    hostile_names = [
        "space in file name.tmp",
        "single'quote'cache.bin",
        'double"quote"cache.bin',
        "$(touch pwned_subshell)",
        "`touch pwned_backtick`",
        "semi;colon & background",
        "-rf",
        "--no-preserve-root",
        "unicode_çãõ_日本語_🚀.cache",
        "literal_*_star_?_question_[a-z].bak",
    ]

    rows: list[Row] = []
    expected_paths: list[str] = []
    for idx, name in enumerate(hostile_names):
        target = cache_root / name
        target.write_bytes(b"x" * 64)
        expected_paths.append(str(target.resolve(strict=True)))
        rows.append(
            Row(
                id=f"cache.hostile.{idx}",
                label=f"Item de cache {idx}",
                size_bytes=4096,
                risk="low",
                action="trash_path",
                path=target,
                allowed_root=cache_root,
            )
        )

    result = generate_commands(rows, protected_paths=_base_protected(fake_home))

    assert result.blocked == ()
    assert len(result.generated) == len(hostile_names)

    for generated_item, expected_path in zip(result.generated, expected_paths, strict=True):
        parsed = shlex.split(generated_item.command_line)
        assert parsed == ["gio", "trash", "--", expected_path]

    command_lines = [
        line
        for line in result.script.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert command_lines[0] == "df -h --output=avail /"
    assert command_lines[-1] == "df -h --output=avail /"
    for cmd_line, expected_path in zip(command_lines[1:-1], expected_paths, strict=True):
        assert shlex.split(cmd_line) == ["gio", "trash", "--", expected_path]


def test_control_and_format_characters_are_blocked_and_absent_from_script(
    tmp_path: Path,
) -> None:
    fake_home = tmp_path / "home"
    cache_root = fake_home / ".cache"
    cache_root.mkdir(parents=True)

    valid_file = cache_root / "safe.bin"
    valid_file.write_bytes(b"ok")

    newline_file = cache_root / "line1\nrm -rf /"
    newline_file.write_bytes(b"bad")

    cr_file = cache_root / "line1\rbad"
    cr_file.write_bytes(b"bad")

    esc_file = cache_root / "ansi\x1b[31mred"
    esc_file.write_bytes(b"bad")

    bidi_file = cache_root / "spoof_\u202etxt.sh"
    bidi_file.write_bytes(b"bad")

    linesep_file = cache_root / "sep_\u2028_next"
    linesep_file.write_bytes(b"bad")

    surrogate_name = os.fsdecode(b"bad_\xff_byte")
    surrogate_path = cache_root / surrogate_name

    rows = [
        Row(
            id="bad.newline.path",
            label="Cache normal",
            size_bytes=512,
            risk="low",
            action="trash_path",
            path=newline_file,
            allowed_root=cache_root,
        ),
        Row(
            id="bad.cr.path",
            label="Cache CR",
            size_bytes=512,
            risk="low",
            action="trash_path",
            path=cr_file,
            allowed_root=cache_root,
        ),
        Row(
            id="bad.nul.path",
            label="Cache NUL",
            size_bytes=512,
            risk="low",
            action="trash_path",
            path=Path(str(cache_root) + "/nul\x00file"),
            allowed_root=cache_root,
        ),
        Row(
            id="bad.esc.path",
            label="Cache ESC",
            size_bytes=512,
            risk="low",
            action="trash_path",
            path=esc_file,
            allowed_root=cache_root,
        ),
        Row(
            id="bad.bidi.path",
            label="Cache RLO",
            size_bytes=512,
            risk="low",
            action="trash_path",
            path=bidi_file,
            allowed_root=cache_root,
        ),
        Row(
            id="bad.linesep.path",
            label="Cache Zl",
            size_bytes=512,
            risk="low",
            action="trash_path",
            path=linesep_file,
            allowed_root=cache_root,
        ),
        Row(
            id="bad.surrogate.path",
            label="Cache surrogate",
            size_bytes=512,
            risk="low",
            action="trash_path",
            path=surrogate_path,
            allowed_root=cache_root,
        ),
        Row(
            id="bad.newline.label",
            label="Rótulo malicioso\nsudo rm -rf /",
            size_bytes=512,
            risk="low",
            action="trash_path",
            path=valid_file,
            allowed_root=cache_root,
        ),
        Row(
            id="bad.control.argv",
            label="Ferramenta ruim",
            size_bytes=512,
            risk="low",
            action="tool_command",
            argv=["pip", "cache", "purge\nrm"],
        ),
    ]

    result = generate_commands(rows, protected_paths=_base_protected(fake_home))

    assert result.generated == ()
    assert result.script == ""
    assert len(result.blocked) == len(rows)
    assert all(item.reason.kind == "unsafe_name" for item in result.blocked)


def test_script_structure_admin_isolation_and_no_forbidden_constructs(
    tmp_path: Path,
) -> None:
    fake_home = tmp_path / "home"
    cache_root = fake_home / ".cache"
    target = cache_root / "gradle"
    target.mkdir(parents=True)

    rows = [
        Row(
            id="cache.gradle",
            label="Cache do Gradle",
            size_bytes=10 * 1024 * 1024,
            risk="low",
            action="trash_path",
            path=target,
            allowed_root=cache_root,
            warnings=["Será baixado novamente"],
        ),
        Row(
            id="cache.go",
            label="Cache de build do Go",
            size_bytes=4 * 1024 * 1024,
            risk="low",
            action="tool_command",
            argv=["go", "clean", "-cache"],
            needs_admin=False,
        ),
        Row(
            id="logs.journal",
            label="Journal do sistema",
            size_bytes=250 * 1024 * 1024,
            risk="medium",
            action="tool_command",
            argv=["journalctl", "--vacuum-size=200M"],
            needs_admin=True,
        ),
        Row(
            id="pkg.paccache",
            label="Cache de pacotes do pacman",
            size_bytes=500 * 1024 * 1024,
            risk="medium",
            action="tool_command",
            argv=["paccache", "-r"],
            needs_admin=True,
        ),
    ]

    result = generate_commands(rows, protected_paths=_base_protected(fake_home))

    assert result.blocked == ()
    assert len(result.generated) == 4
    assert "revise" in result.script.casefold()

    admin_marker = "# === Requer administrador"
    assert admin_marker in result.script
    before_admin, admin_section = result.script.split(admin_marker, maxsplit=1)

    assert "sudo" not in before_admin
    assert "df -h --output=avail /" in before_admin
    assert "# Cache do Gradle" in before_admin
    assert "# Cache de build do Go" in before_admin
    assert "# Journal do sistema" in admin_section
    assert "# Cache de pacotes do pacman" in admin_section
    assert admin_section.strip().endswith("df -h --output=avail /")

    for section, allow_sudo in ((before_admin, False), (admin_section, True)):
        for line in section.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            assert "&&" not in stripped
            assert "||" not in stripped
            assert "|" not in stripped
            assert "$(" not in stripped
            assert "`" not in stripped
            tokens = shlex.split(stripped)
            assert tokens[0] != "rm"
            assert "rm" not in tokens
            if not allow_sudo:
                assert "sudo" not in tokens
            elif tokens[0] != "df":
                assert tokens[0] == "sudo"


def test_protected_critical_inspect_only_and_user_data_never_generate_commands(
    tmp_path: Path,
) -> None:
    fake_home = tmp_path / "home"
    ssh_dir = fake_home / ".ssh"
    ssh_dir.mkdir(parents=True)
    ssh_key = ssh_dir / "id_ed25519"
    ssh_key.write_bytes(b"secret")

    vscode_user = fake_home / ".config" / "Code" / "User"
    vscode_user.mkdir(parents=True)
    settings = vscode_user / "settings.json"
    settings.write_bytes(b"{}")

    # Sibling starting with ".ssh" prefix must NOT be falsely matched as ~/.ssh
    ssh_named_cache = fake_home / ".ssh_known_cache"
    ssh_named_cache.mkdir(parents=True)

    critical_file = fake_home / "creds.pem"
    critical_file.write_bytes(b"pem")

    rows = [
        Row(
            id="fs.root",
            label="Raiz do sistema",
            size_bytes=4096,
            risk="high",
            action="trash_path",
            path=Path("/"),
            allowed_root=Path("/"),
        ),
        Row(
            id="fs.home_exact",
            label="Diretório home",
            size_bytes=4096,
            risk="high",
            action="trash_path",
            path=fake_home,
            allowed_root=tmp_path,
        ),
        Row(
            id="fs.ssh_key",
            label="Chave SSH",
            size_bytes=512,
            risk="high",
            action="trash_path",
            path=ssh_key,
            allowed_root=fake_home,
        ),
        Row(
            id="fs.vscode_settings",
            label="Configuração do editor",
            size_bytes=512,
            risk="medium",
            action="trash_path",
            path=settings,
            allowed_root=fake_home,
        ),
        Row(
            id="fs.critical",
            label="Credencial crítica",
            size_bytes=512,
            risk="critical",
            action="trash_path",
            path=critical_file,
            allowed_root=fake_home,
        ),
        Row(
            id="docker.volumes",
            label="Volumes Docker",
            size_bytes=1024 * 1024,
            risk="high",
            action="inspect_only",
        ),
        Row(
            id="trash.items",
            label="Itens na Lixeira",
            size_bytes=2048,
            risk="high",
            action="inspect_only",
        ),
        Row(
            id="cargo.placeholder",
            label="Cargo com placeholder proibido",
            size_bytes=4096,
            risk="low",
            action="tool_command",
            argv=["cargo", "clean", "--manifest-path", "{path}/Cargo.toml"],
        ),
        Row(
            id="cache.ssh_prefix_sibling",
            label="Cache legítimo com prefixo parecido",
            size_bytes=4096,
            risk="low",
            action="trash_path",
            path=ssh_named_cache,
            allowed_root=fake_home,
        ),
    ]

    result = generate_commands(rows, protected_paths=_base_protected(fake_home))

    assert [item.row_id for item in result.generated] == ["cache.ssh_prefix_sibling"]
    blocked_by_id = {item.row_id: item.reason.kind for item in result.blocked}
    assert blocked_by_id["fs.root"] == "protected"
    assert blocked_by_id["fs.home_exact"] == "protected"
    assert blocked_by_id["fs.ssh_key"] == "protected"
    assert blocked_by_id["fs.vscode_settings"] == "protected"
    assert blocked_by_id["fs.critical"] == "critical"
    assert blocked_by_id["docker.volumes"] == "inspect_only"
    assert blocked_by_id["trash.items"] == "inspect_only"
    assert blocked_by_id["cargo.placeholder"] == "invalid_row"
    assert "volumes" not in result.script.casefold()


def test_revalidation_blocks_deleted_symlink_escaped_and_deduplicates_ancestors(
    tmp_path: Path,
) -> None:
    fake_home = tmp_path / "home"
    cache_root = fake_home / ".cache"
    cache_root.mkdir(parents=True)

    outside_dir = tmp_path / "outside_secret"
    outside_dir.mkdir()
    outside_file = outside_dir / "keep.txt"
    outside_file.write_bytes(b"keep")

    ssh_dir = fake_home / ".ssh"
    ssh_dir.mkdir(parents=True)
    ssh_secret = ssh_dir / "config"
    ssh_secret.write_bytes(b"Host *")

    vanished = cache_root / "vanished.tmp"
    vanished.write_bytes(b"gone soon")

    replaced_outside = cache_root / "escape_link"
    replaced_outside.write_bytes(b"will become symlink")

    replaced_protected = cache_root / "ssh_link"
    replaced_protected.write_bytes(b"will become protected symlink")

    replaced_inside = cache_root / "inside_target"
    replaced_inside.write_bytes(b"inside")
    inside_link = cache_root / "inside_link"
    inside_link.symlink_to(replaced_inside)

    # Intermediate directory turned into symlink after scan
    mid_dir = cache_root / "mid"
    mid_dir.mkdir()
    nested_target = outside_dir / "nested.bin"
    nested_target.write_bytes(b"nested")

    # Ancestor + child deduplication + in_use informational warning
    parent_cache = cache_root / "npm"
    child_cache = parent_cache / "_cacache"
    child_cache.mkdir(parents=True)

    # Mutate filesystem BEFORE generate_commands (simulating TOCTOU after scan)
    vanished.unlink()
    replaced_outside.unlink()
    replaced_outside.symlink_to(outside_file)
    replaced_protected.unlink()
    replaced_protected.symlink_to(ssh_secret)
    mid_dir.rmdir()
    mid_dir.symlink_to(outside_dir, target_is_directory=True)

    rows = [
        Row(
            id="toctou.vanished",
            label="Item removido",
            size_bytes=512,
            risk="low",
            action="trash_path",
            path=vanished,
            allowed_root=cache_root,
        ),
        Row(
            id="toctou.escape_outside",
            label="Symlink para fora",
            size_bytes=512,
            risk="low",
            action="trash_path",
            path=replaced_outside,
            allowed_root=cache_root,
        ),
        Row(
            id="toctou.escape_protected",
            label="Symlink para protegido",
            size_bytes=512,
            risk="low",
            action="trash_path",
            path=replaced_protected,
            allowed_root=cache_root,
        ),
        Row(
            id="toctou.inside_symlink",
            label="Symlink interno",
            size_bytes=512,
            risk="low",
            action="trash_path",
            path=inside_link,
            allowed_root=cache_root,
        ),
        Row(
            id="toctou.intermediate_symlink",
            label="Diretório intermediário virou symlink",
            size_bytes=512,
            risk="low",
            action="trash_path",
            path=cache_root / "mid" / "nested.bin",
            allowed_root=cache_root,
        ),
        Row(
            id="path.dotdot",
            label="Caminho com ..",
            size_bytes=512,
            risk="low",
            action="trash_path",
            path=cache_root / "npm" / ".." / ".." / "outside",
            allowed_root=cache_root,
        ),
        Row(
            id="cache.npm.parent",
            label="Cache npm",
            size_bytes=8192,
            risk="low",
            action="trash_path",
            path=parent_cache,
            allowed_root=cache_root,
            warnings=["Aplicação em uso: node está usando o diretório"],
        ),
        Row(
            id="cache.npm.child",
            label="Subpasta npm",
            size_bytes=4096,
            risk="low",
            action="trash_path",
            path=child_cache,
            allowed_root=cache_root,
        ),
    ]

    result = generate_commands(rows, protected_paths=_base_protected(fake_home))

    assert [item.row_id for item in result.generated] == ["cache.npm.parent"]
    assert any("Aplicação em uso" in warning for warning in result.warnings)

    blocked_kinds = {item.row_id: item.reason.kind for item in result.blocked}
    assert blocked_kinds["toctou.vanished"] == "not_found"
    assert blocked_kinds["toctou.escape_outside"] == "outside_root"
    assert blocked_kinds["toctou.escape_protected"] == "protected"
    assert blocked_kinds["toctou.inside_symlink"] == "symlink"
    assert blocked_kinds["toctou.intermediate_symlink"] == "outside_root"
    assert blocked_kinds["path.dotdot"] == "outside_root"


def test_history_records_only_command_generated_without_claiming_success(
    tmp_path: Path,
) -> None:
    fake_home = tmp_path / "home"
    cache_root = fake_home / ".cache"
    item = cache_root / "pip"
    item.mkdir(parents=True)

    rows = [
        Row(
            id="cache.pip",
            label="Cache do pip",
            size_bytes=2048,
            risk="low",
            action="trash_path",
            path=item,
            allowed_root=cache_root,
        ),
        Row(
            id="docker.volumes",
            label="Volumes Docker",
            size_bytes=4096,
            risk="high",
            action="inspect_only",
        ),
    ]

    result = generate_commands(rows, protected_paths=_base_protected(fake_home))
    history_file = tmp_path / "history.jsonl"
    history = History(history_file)
    history.record_command_generated(result, timestamp=1700000000.0)

    lines = history_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])

    assert record["event"] == "command_generated"
    assert record["record_type"] == "command_generated"
    assert "result" not in record
    assert "success" not in lines[0].casefold()
    assert str(item) not in lines[0]
    assert record["generated"] == [
        {
            "row_id": "cache.pip",
            "action": "trash_path",
            "size_bytes": 2048,
            "needs_admin": False,
        }
    ]
    assert record["blocked"] == [
        {
            "row_id": "docker.volumes",
            "reason_kind": "inspect_only",
        }
    ]


def test_provider_result_enforces_immutable_tuples_and_gtk_free_imports() -> None:
    import sys

    import clearspace.command_generator as cg_mod
    import clearspace.provider_contract as pc_mod

    assert "gi" not in cg_mod.__dict__
    assert "gi" not in pc_mod.__dict__

    row = Row(
        id="cache.pip.tool",
        label="Limpar cache pip",
        size_bytes=1024,
        risk="low",
        action="tool_command",
        argv=["pip", "cache", "purge"],
        warnings=["Será baixado novamente"],
    )
    res = ProviderResult(rows=[row], smaller_count=2, smaller_bytes=512, error=None)
    assert isinstance(row.argv, tuple)
    assert isinstance(row.warnings, tuple)
    assert isinstance(res.rows, tuple)
    assert res.smaller_count == 2
    assert res.smaller_bytes == 512
