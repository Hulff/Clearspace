from __future__ import annotations

import json
import subprocess
from pathlib import Path

from clearspace.command_generator import default_protected_paths, generate_commands
from clearspace.provider_contract import (
    CommandProbeResult,
    ProviderContext,
)
from clearspace.providers import PROVIDERS, DockerProvider, PackagesProvider, get_provider


def _make_context(
    tmp_path: Path,
    *,
    run_readonly_command=None,
    which=None,
    os_release_text: str = 'ID=arch\nNAME="Arch Linux"\n',
    pacman_cache_dir: Path | None = None,
) -> ProviderContext:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    os_release = tmp_path / "os-release"
    os_release.write_text(os_release_text, encoding="utf-8")
    if pacman_cache_dir is None:
        pacman_cache_dir = tmp_path / "pacman-pkg"
    return ProviderContext(
        xdg_cache_home=home / ".cache",
        xdg_data_home=home / ".local" / "share",
        xdg_state_home=home / ".local" / "state",
        xdg_config_home=home / ".config",
        downloads_dir=home / "Downloads",
        scan_db_path=None,
        scan_root=None,
        os_release_path=os_release,
        run_readonly_command=run_readonly_command
        or (lambda argv, timeout=5.0: CommandProbeResult(returncode=0, stdout="", stderr="")),
        protected_paths=default_protected_paths(home=home),
        home_dir=home,
        which=which or (lambda cmd: f"/usr/bin/{cmd}"),
        pacman_cache_dir=pacman_cache_dir,
    )


def test_docker_and_packages_are_registered() -> None:
    assert isinstance(get_provider("docker"), DockerProvider)
    assert isinstance(get_provider("packages"), PackagesProvider)
    for mode_id, provider in PROVIDERS.items():
        assert provider.id == mode_id
        assert isinstance(provider.label, str) and provider.label
        assert callable(provider.load)


def test_docker_provider_parses_jsonl_and_keeps_volumes_inspect_only(tmp_path: Path) -> None:
    jsonl_output = "\n".join(
        [
            json.dumps(
                {
                    "Type": "Images",
                    "TotalCount": "5",
                    "Active": "2",
                    "Size": "1.5GB",
                    "Reclaimable": "1.2GB (80%)",
                }
            ),
            json.dumps(
                {
                    "Type": "Containers",
                    "TotalCount": "3",
                    "Active": "1",
                    "Size": "250MB",
                    "Reclaimable": "200MB",
                }
            ),
            json.dumps(
                {
                    "Type": "Local Volumes",
                    "TotalCount": "4",
                    "Active": "2",
                    "Size": "3.0GB",
                    "Reclaimable": "500MB",
                }
            ),
            json.dumps(
                {
                    "Type": "Build Cache",
                    "TotalCount": "12",
                    "Active": "0",
                    "Size": "800MiB",
                    "Reclaimable": "800MiB",
                }
            ),
        ]
    )

    called: list[tuple[str, ...]] = []

    def fake_probe(argv, timeout=5.0):
        called.append(tuple(argv))
        return CommandProbeResult(returncode=0, stdout=jsonl_output, stderr="")

    ctx = _make_context(tmp_path, run_readonly_command=fake_probe)
    result = DockerProvider().load(ctx)

    assert called == [("docker", "system", "df", "--format", "{{json .}}")]
    assert result.error is None
    assert len(result.rows) == 4

    by_id = {row.id: row for row in result.rows}
    assert by_id["docker.images"].action == "tool_command"
    assert by_id["docker.images"].argv == ("docker", "image", "prune")
    assert by_id["docker.images"].size_bytes == 1_200_000_000

    assert by_id["docker.containers"].action == "tool_command"
    assert by_id["docker.containers"].argv == ("docker", "container", "prune")
    assert by_id["docker.containers"].size_bytes == 200_000_000

    assert by_id["docker.build_cache"].action == "tool_command"
    assert by_id["docker.build_cache"].argv == ("docker", "builder", "prune")
    assert by_id["docker.build_cache"].size_bytes == 800 * 1024 * 1024

    volumes = by_id["docker.volumes"]
    assert volumes.action == "inspect_only"
    assert volumes.risk == "high"
    assert volumes.argv is None
    assert volumes.size_bytes == 500_000_000

    # Volumes must be blocked if ever passed to command generator
    gen = generate_commands(result.rows, protected_paths=ctx.protected_paths)
    assert [item.row_id for item in gen.blocked] == ["docker.volumes"]
    assert all("volume" not in item.command_line for item in gen.generated)


def test_docker_provider_classifies_tool_missing_socket_denied_stopped_and_timeout(
    tmp_path: Path,
) -> None:
    missing_ctx = _make_context(tmp_path, which=lambda _cmd: None)
    missing_res = DockerProvider().load(missing_ctx)
    assert missing_res.rows == ()
    assert missing_res.error is not None
    assert missing_res.error.kind == "tool_missing"

    denied_ctx = _make_context(
        tmp_path,
        run_readonly_command=lambda argv, timeout=5.0: CommandProbeResult(
            returncode=1,
            stdout="",
            stderr="permission denied while trying to connect to the Docker daemon socket",
        ),
    )
    denied_res = DockerProvider().load(denied_ctx)
    assert denied_res.rows == ()
    assert denied_res.error is not None
    assert denied_res.error.kind == "socket_denied"

    stopped_ctx = _make_context(
        tmp_path,
        run_readonly_command=lambda argv, timeout=5.0: CommandProbeResult(
            returncode=1,
            stdout="",
            stderr="Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
        ),
    )
    stopped_res = DockerProvider().load(stopped_ctx)
    assert stopped_res.rows == ()
    assert stopped_res.error is not None
    assert stopped_res.error.kind == "unexpected"

    def raise_timeout(argv, timeout=5.0):
        raise subprocess.TimeoutExpired(cmd=list(argv), timeout=timeout)

    timeout_ctx = _make_context(tmp_path, run_readonly_command=raise_timeout)
    timeout_res = DockerProvider().load(timeout_ctx)
    assert timeout_res.rows == ()
    assert timeout_res.error is not None
    assert timeout_res.error.kind == "timeout"


def test_packages_provider_skips_non_arch_without_invoking_pacman(tmp_path: Path) -> None:
    called = False

    def fail_if_called(argv, timeout=5.0):
        nonlocal called
        called = True
        raise AssertionError("pacman should not be invoked on non-Arch")

    ctx = _make_context(
        tmp_path,
        os_release_text="ID=ubuntu\nID_LIKE=debian\n",
        run_readonly_command=fail_if_called,
    )
    result = PackagesProvider().load(ctx)
    assert not called
    assert result.error is None
    assert result.rows == ()


def test_packages_provider_measures_pacman_cache_and_lists_orphans_safely(
    tmp_path: Path,
) -> None:
    pkg_dir = tmp_path / "pacman-pkg"
    pkg_dir.mkdir()
    pkg_file = pkg_dir / "foo-1.0-1-x86_64.pkg.tar.zst"
    pkg_file.write_bytes(b"x" * 16384)
    expected_bytes = pkg_file.stat().st_blocks * 512

    called: list[tuple[str, ...]] = []

    def fake_probe(argv, timeout=5.0):
        called.append(tuple(argv))
        return CommandProbeResult(
            returncode=0,
            stdout="orphan-alpha\norphan-beta\n",
            stderr="",
        )

    ctx = _make_context(
        tmp_path,
        os_release_text="ID=endeavouros\nID_LIKE=arch\n",
        pacman_cache_dir=pkg_dir,
        run_readonly_command=fake_probe,
    )
    result = PackagesProvider().load(ctx)

    assert called == [("pacman", "-Qdtq")]
    assert result.error is None

    by_id = {row.id: row for row in result.rows}
    cache_row = by_id["packages.pacman.cache"]
    assert cache_row.action == "tool_command"
    assert cache_row.argv == ("paccache", "-r")
    assert cache_row.needs_admin is True
    assert cache_row.size_bytes == expected_bytes

    orphans_row = by_id["packages.pacman.orphans"]
    assert orphans_row.action == "inspect_only"
    assert orphans_row.argv is None
    assert "2" in orphans_row.label

    gen = generate_commands(result.rows, protected_paths=ctx.protected_paths)
    assert "sudo paccache -r" in gen.admin_script
    assert "sudo" not in gen.user_script
    assert "$(pacman" not in gen.script
    assert [b.row_id for b in gen.blocked] == ["packages.pacman.orphans"]


def test_packages_provider_handles_zero_orphans_returncode_1_without_error(
    tmp_path: Path,
) -> None:
    pkg_dir = tmp_path / "pacman-pkg"
    pkg_dir.mkdir()
    (pkg_dir / "bar.pkg.tar.zst").write_bytes(b"y" * 8192)

    def fake_probe(argv, timeout=5.0):
        return CommandProbeResult(
            returncode=1,
            stdout="",
            stderr="",
        )

    ctx = _make_context(
        tmp_path,
        os_release_text="ID=arch\n",
        pacman_cache_dir=pkg_dir,
        run_readonly_command=fake_probe,
        which=lambda cmd: "/usr/bin/pacman" if cmd == "pacman" else None,
    )
    result = PackagesProvider().load(ctx)
    assert result.error is None
    by_id = {row.id: row for row in result.rows}
    assert by_id["packages.pacman.cache"].argv == ("pacman", "-Sc")
    assert "packages.pacman.orphans" not in by_id
