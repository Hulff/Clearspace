# Linux Disk Cleanup Playbook: Arch Linux Developer Workstation

> Purpose: guide a cleanup library, CLI, or desktop app that helps users identify and safely reclaim disk space on Linux developer systems similar to this Arch Linux workstation.
>
> Core principle: **measure first, explain the impact, and get explicit confirmation before deleting anything.** Prefer package-manager and application-native cleanup commands over manually deleting directories.

## 1. Observed system profile

Collected from the troubleshooting session:

- OS: Arch Linux (inferred from `yay`, pacman cache, and user environment).
- Root filesystem: `/dev/nvme0n1p6`, 143 GB total.
- Initially: 117 GB used, 19 GB available, 87% utilization.
- After Docker build-cache cleanup: 105 GB used, 31 GB available, 78% utilization.
- `/boot`: `/dev/nvme0n1p5`, 1 GB total.
- Docker is installed and used for development.
- Developer tools/caches include Docker, Node.js/npm/pnpm, Go, VS Code C/C++ tools, Hugging Face, Yay, Unity/Godot, Firefox, PrismLauncher, and Python/pip.

The `df` values may not add exactly due to rounding and filesystem accounting.

## 2. Commands and tools used in the session

### Filesystem overview

```bash
df -h
df -h /
df -h /home/hulff/repos
```

Purpose:
- `df -h`: show mounted filesystems, total/used/free capacity, and utilization.
- `df -h /`: report the filesystem that contains `/`.
- `df -h /home/hulff/repos`: confirm which filesystem holds the repositories.

### Find top-level disk consumers

```bash
sudo du -xhd1 / 2>/dev/null | sort -h
du -xhd1 /home/hulff 2>/dev/null | sort -h
sudo du -xhd1 /var 2>/dev/null | sort -h
sudo du -xhd1 /usr 2>/dev/null | sort -h
```

Purpose:
- `du`: estimate disk usage by directory.
- `-x`: stay on the same filesystem.
- `-h`: human-readable units.
- `-d1`: limit depth to one directory level.
- `2>/dev/null`: suppress permission/error noise.
- `sort -h`: sort human-readable sizes.

For nested breakdowns:

```bash
du -xhd2 ~/.cache 2>/dev/null | sort -h
du -xhd2 ~/.local 2>/dev/null | sort -h | tail -20
du -xhd2 ~/.config 2>/dev/null | sort -h | tail -20
du -xhd2 ~/repos 2>/dev/null | sort -h | tail -30
```

### Find very large files

```bash
sudo find /home /var /opt -xdev -type f -size +1G \
  -printf '%s %p\n' 2>/dev/null |
  sort -nr |
  numfmt --field=1 --to=iec |
  head -25
```

Also considered:

```bash
sudo find / -xdev -type f -size +1G \
  -printf '%s %p\n' 2>/dev/null |
  sort -nr | head -30 |
  numfmt --field=1 --to=iec
```

Purpose: locate large individual files. The `/home /var /opt` version focuses on likely cleanup targets. On non-GNU systems, `find -printf` and `numfmt` may not be available.

## 3. Docker inspection and cleanup

### Inspect Docker usage

```bash
docker system df
docker system df -v
docker image ls
docker container ls -a
docker volume ls
```

Observed initial Docker report:

| Resource | Total | Active | Size | Reclaimable |
|---|---:|---:|---:|---:|
| Images | 18 | 4 | 7.019 GB | 3.658 GB (52%) |
| Containers | 4 | 0 | 6.926 MB | 6.926 MB (100%) |
| Local volumes | 47 | 4 | 3.218 GB | 2.817 GB (87%) |
| Build cache | 164 | 0 | 15.21 GB | 10.45 GB |

After build-cache cleanup and some image cleanup, the reported output was:

| Resource | Total | Active | Size | Reclaimable |
|---|---:|---:|---:|---:|
| Images | 15 | 4 | 6.65 GB | 4.238 GB (63%) |
| Containers | 4 | 0 | 6.926 MB | 6.926 MB (100%) |
| Local volumes | 47 | 4 | 3.218 GB | 2.817 GB (87%) |
| Build cache | 0 | 0 | 0 B | 0 B |

Root filesystem changed from 117 GB used / 19 GB available / 87% to 105 GB used / 31 GB available / 78%.

### Docker cleanup commands discussed

Inspect before cleaning:

```bash
docker system df
docker system df -v
```

Remove dangling images:

```bash
docker image prune
```

Remove images not referenced by any existing container:

```bash
docker image prune -a
```

Remove build cache:

```bash
docker builder prune
docker builder prune -a
```

Remove unused containers, networks, images, and build cache:

```bash
docker system prune -a
```

**Never recommend this by default:**

```bash
docker system prune -a --volumes
```

Volumes can hold databases and other persistent data.

The session included stopped containers:
- `nexusDB` using `postgres:14`
- `keycloak-auth` using `quay.io/keycloak/keycloak:26.4.5`
- `minio` using `bitnamilegacy/minio:latest`
- `mailhog` using `mailhog/mailhog`

Volumes with recognizable names included:
- `docker_postgres_data`
- `docker_postgres_data_dev`
- `docker_minio_data`

These should be treated as potentially valuable application data.

Inspect a volume:

```bash
docker volume inspect docker_postgres_data
docker volume inspect docker_postgres_data_dev
docker volume inspect docker_minio_data
```

Important Docker behavior:
- An image referenced by an existing stopped container is not considered unused by `docker image prune -a`.
- An unused volume can still contain important data.
- Docker's reclaimable size is an estimate; shared layers affect actual reclaimed space.
- Build cache can be recreated, but builds may become slower.
- Always show the user the command and impact before execution.

## 4. Arch Linux package cache

Inspect pacman cache:

```bash
du -sh /var/cache/pacman/pkg
```

If `paccache` is installed, retain three recent cached package versions:

```bash
sudo paccache -r
```

Retain only the newest cached version:

```bash
sudo paccache -rk1
```

Install `pacman-contrib` if needed:

```bash
sudo pacman -S pacman-contrib
```

Yay cache observed:

```text
/home/hulff/.cache/yay    4.0G
```

Command discussed:

```bash
yay -Sc
```

Review prompts before confirming. Avoid aggressive `yay -Scc` by default. The app should detect the package manager and explain that package downloads/build artifacts may need to be downloaded or rebuilt.

## 5. Journal logs

Inspect:

```bash
journalctl --disk-usage
```

Reduce archived journal usage to approximately 200 MB:

```bash
sudo journalctl --vacuum-size=200M
```

This removes older archived journal entries. It does not necessarily shrink the active journal immediately. The app should show the current journal size and proposed limit first.

## 6. Node.js, npm, and pnpm

### npm

Observed:

```text
/home/hulff/.npm         6.0G
/home/hulff/.npm-global 150M
```

Inspect:

```bash
du -xhd2 ~/.npm 2>/dev/null | sort -h | tail -20
```

Verify npm cache:

```bash
npm cache verify
```

Clear npm cache:

```bash
npm cache clean --force
```

This command emits a warning similar to `npm warn using --force Recommended protections disabled.` The warning is expected when using `--force`, but the app should explain that cached packages will need to be downloaded again. Prefer `npm cache verify` first.

### pnpm

Observed:

```text
/home/hulff/.cache/pnpm       457M
/home/hulff/.local/share/pnpm 864M
```

Commands:

```bash
pnpm store path
pnpm store status
pnpm store prune
```

`pnpm store prune` removes packages no longer referenced by projects known to pnpm; packages can be fetched again if needed. Do not manually delete the store while package-manager processes are running.

## 7. Go cache

Observed:

```text
/home/hulff/.cache/go-build 2.9G
/home/hulff/go              2.5G
```

Command:

```bash
go clean -cache
```

This clears Go's build cache, not source code or downloaded modules. Future builds will recompile packages. Do not delete `~/go` wholesale; it may contain source, modules, or binaries.

## 8. VS Code C/C++ cache

Observed:

```text
/home/hulff/.cache/vscode-cpptools 3.2G
```

Inspect:

```bash
du -xhd2 ~/.cache/vscode-cpptools 2>/dev/null | sort -h
```

Close VS Code before cleaning extension-generated indexing/cache files. This can cause IntelliSense indexes to be rebuilt. A cleanup app should not remove VS Code user settings, extensions, or workspaces as part of cache cleanup.

Other observed VS Code-related usage:

```text
/home/hulff/.config/Code                 2.7G
/home/hulff/.config/Code/CachedExtensionVSIXs 1.3G
/home/hulff/.config/Code/WebStorage       642M
/home/hulff/.config/Code/User             627M
/home/hulff/.config/Code/CachedData        93M
/home/hulff/.config/Code/Cache            79M
/home/hulff/.config/Code/Partitions       25M
/home/hulff/.config/Code/GPUCache         16M
```

Treat `CachedExtensionVSIXs` as cached extension installer files only after confirming the user's desired retention policy. Do not clear `User`, `WebStorage`, or `Partitions` blindly; they may contain settings, state, or extension data. Prefer application-supported cache cleanup.

## 9. Hugging Face cache

Observed:

```text
/home/hulff/.cache/huggingface 2.3G
```

Inspect:

```bash
du -xhd3 ~/.cache/huggingface 2>/dev/null | sort -h | tail -25
```

This may contain model weights and datasets that are expensive to redownload. Never remove the whole directory automatically. Identify specific cached models/datasets and use Hugging Face tooling when possible. Require explicit user confirmation for deleting model assets.

## 10. Trash

Observed:

```text
/home/hulff/.local/share/Trash 6.5G
```

Inspect:

```bash
du -xhd2 ~/.local/share/Trash 2>/dev/null | sort -h
ls -lah ~/.local/share/Trash/files | head -30
```

The session discussed this manual command:

```bash
rm -rf ~/.local/share/Trash/files/* ~/.local/share/Trash/info/*
```

**This permanently deletes Trash contents.** It should never run without explicit confirmation and a clear warning. Prefer the desktop Trash API or file manager. If a CLI is offered, show a preview of file names/sizes and require a separate confirmation. Handle hidden files safely; shell globs like `*` do not match dotfiles by default.

## 11. Other observed directories worth investigating

### `~/.local`

Observed total was reported as 11–12 GB depending on output/rounding:

```text
~/.local/share/Trash       6.5G
~/.local/share/PrismLauncher 2.4G
~/.local/share/godot       1.3G
~/.local/share/pnpm        864M
~/.local/bin               313M
~/.local/share/GitKrakenCLI 231M
```

PrismLauncher can hold Minecraft instances, modpacks, and worlds. Godot data may include editor assets and project content. Do not remove either wholesale. Inspect the contents and ask whether the user still needs the instances/projects.

### `~/.config`

Observed total: 7.4 GB.

```text
~/.config/mozilla/firefox 3.4G
~/.config/Code            2.7G
~/.config/Postman         758M
~/.config/unityhub        618M
~/.config/unityhub/Templates 573M
```

Firefox profiles, Postman data, VS Code user data, and Unity templates can be valuable. Avoid deleting these directories wholesale. Use application-specific storage management or inspect subdirectories first.

### Repositories and downloads

Observed:

```text
~/repos    11G
~/Downloads 2.1G
~/.gradle  1.4G
~/.codex   1.6G
```

Inspect repositories for generated build directories, duplicate dependencies, large datasets, archives, and model files. Never remove source code or uncommitted work automatically. Inspect Gradle caches before using Gradle's native cache cleanup. Inspect downloads and ask before deleting user documents.

## 12. Initial full directory breakdown

Command:

```bash
sudo du -xhd1 / 2>/dev/null | sort -h
```

Observed:

```text
4.0K  /mnt
12K   /srv
16K   /lost+found
4.2M  /root
11M   /etc
1.1G  /opt
12G   /usr
18G   /var
63G   /home
101G  /
```

Note: `du` totals and `df` used space differ because of filesystem metadata, reserved blocks, deleted-but-open files, and rounding. Do not treat the difference as missing data without further checks.

## 13. Recommended cleanup workflow for an app/library

### Phase A — Inventory (read-only)

1. Detect Linux distribution and package manager (`pacman`, `apt`, `dnf`, etc.).
2. Detect filesystems and mount points (`df -hT`, `findmnt`).
3. Identify largest directories (`du`) and large files (`find`).
4. If Docker exists, call `docker system df -v`.
5. Detect relevant tools (npm, pnpm, Go, VS Code, Hugging Face, Yay).
6. Report measured sizes, safe-to-regenerate cache estimates, and persistent-data warnings.

### Phase B — Classify candidates

Use these categories:
- **Low risk / regenerable:** Go build cache; npm cache; selected app caches; Docker build cache.
- **Moderate risk:** old package archives; dangling/unused Docker images; pnpm store prune; VS Code indexes; shader caches.
- **User data / confirmation required:** Trash; Hugging Face model downloads; PrismLauncher instances/worlds; Godot projects/assets; browser profiles; Postman data; databases; Docker volumes; repository files; downloads.
- **System-critical / never manually delete:** `/usr`, `/etc`, `/boot`, unknown files under `/var/lib`, and active application data.

### Phase C — Preview

For every proposed action, display:
- Target and current measured size.
- Exact command/action.
- Whether data is recoverable or can be recreated.
- Possible side effects.
- Estimated space recovery, labeled as an estimate.
- Whether admin privileges are needed.
- Whether active applications should be closed.
- A clear `Preview`, `Cancel`, and explicit `Confirm cleanup` step.

### Phase D — Execute one action at a time

- Use native tools: Docker prune commands, `go clean`, npm/pnpm cache commands, `paccache`, `journalctl --vacuum-size`.
- Do not concatenate destructive operations into one shell command.
- Never use broad commands such as `rm -rf ~/.cache/*`, `docker system prune -a --volumes`, or `yay -Scc` as default behavior.
- Do not run privileged deletion commands unless necessary and explicitly approved.
- Avoid deleting a cache while its application is active.
- Record the command, start/end time, exit status, and output; do not claim cleanup succeeded if the command failed.

### Phase E — Verify

After each cleanup:

```bash
df -h /
```

Recheck the relevant directory or tool report:
- Docker: `docker system df`
- Cache: `du -sh <target>`
- Logs: `journalctl --disk-usage`

Show actual before/after deltas. Account for filesystem rounding and shared Docker layers.

### Phase F — Long-term policy

- Offer configurable thresholds (e.g. warn at 80%, critical at 90%) rather than hard-coded assumptions.
- Allow exclusions and per-directory policies.
- Keep an audit log and provide a dry-run mode.
- Support a scheduled report, but never schedule destructive cleanup without explicit opt-in.
- Explain that caches may be rebuilt and data may be redownloaded.
- Prefer human-readable sizes and clear distinctions between “unused,” “reclaimable,” and “safe to delete.”
- Treat `du` results as disk usage, not a guarantee of reclaimable bytes.
- Do not require network access to perform local inventory.

## 14. Safety and implementation notes

- Use a structured process API (argument arrays), not string-concatenated shell commands.
- Validate paths and canonicalize them before any deletion; reject `/`, home root, system roots, and unexpected symlink targets.
- For shell globs and filenames with unusual characters, use APIs or NUL-delimited processing.
- Require confirmation for permanent deletion, Docker volume pruning, model removal, and deletion of user data.
- Never infer that a Docker volume is unimportant just because no container currently references it.
- Check available disk space before/after and distinguish filesystem space from apparent file sizes.
- Handle permissions and mount points carefully; stay on the target filesystem when measuring.
- Consider deleted-but-open files: if `df` reports much more usage than `du`, inspect `sudo lsof +L1` if `lsof` is installed.
- Explain that `npm cache clean --force` prints a warning because protections are bypassed; it is not by itself evidence of failure.
- Commands in this document are examples for an Arch Linux workstation and should be checked against the installed tool version before being offered to other distributions.

## 15. Session outcome

After cleaning Docker build cache and some images, root filesystem usage changed approximately as follows:

| Metric | Before | After |
|---|---:|---:|
| Root used | 117 GB | 105 GB |
| Root available | 19 GB | 31 GB |
| Root utilization | 87% | 78% |
| Docker build cache | 15.21 GB reported | 0 B reported |

The most promising additional targets identified were:
- Trash: 6.5 GB (permanent deletion; inspect first)
- Yay cache: 4.0 GB
- Go build cache: 2.9 GB
- VS Code C/C++ cache: 3.2 GB
- Hugging Face cache: 2.3 GB (model data; inspect first)
- npm cache: 6.0 GB
- Docker images: 4.238 GB reported reclaimable at the latest Docker report
- Docker volumes: 2.817 GB reported reclaimable, but persistent data risk is high

These are observed measurements from one session, not universal defaults.
