# Clearspace

Clearspace is a local-first Linux disk cleanup app. It measures common disk consumers, explains what can be reclaimed, and runs native cleanup tools only after the user reviews and confirms an action.

## Run

```sh
python app.py
```

Build the standalone Rust scanner:

```sh
cargo build --release --manifest-path scanner/Cargo.toml
```

The GTK scan screen currently uses the Python scanner so its folder-level live
progress, pause, cancellation, and partial results have consistent behavior.
The Rust binary currently implements JSONL protocol v1 and is not selected by
that screen; the app can switch back after the binary supports the scanner
agnostic progress/control contract in protocol v2. `CLEARSPACE_SCAN_BIN` still
selects a binary for the headless Rust adapter.

Na primeira abertura, a árvore começa em `/home`, para mostrar as pastas de
usuários diretamente. Caminhos de cada usuário e dados de aplicações ativas
continuam sujeitos às proteções do executor.

GTK 4 and its Python bindings (`python-gobject`) are required. On Arch Linux, install them with `sudo pacman -S gtk4 python-gobject`.

Clearspace stores a structured, local JSONL action history at `~/.local/share/clearspace/history.jsonl`. It records action IDs, measured sizes, timestamps, command arguments, exit status, and output. It does not store file contents or send data over the network. This history format is intended to provide a future retrieval layer for personalized recommendations; no LLM or RAG functionality is included yet.

## Safety

- Scanning is read-only and stays on the filesystem containing the scanned path.
- The standalone Rust scanner measures the tree in a background process, includes
  hidden files, counts allocated disk blocks and hardlinks once, and never follows
  symlinks. `RustTreeScanner` queries its SQLite database one directory at a time.
- The GTK-free Python scanner powers the live scanning screen and supports its
  cooperative controls and partial results.
- The scanning screen reports folder progress with an estimated total, file/byte
  counters, elapsed time, a smoothed ETA, and a bounded list of the four largest
  observed entries. Pause and cancel are cooperative; cancellation keeps clearly
  marked partial results. The UI polls a shared snapshot instead of receiving one
  GTK callback per filesystem entry.
- Scanner errors remain attached to their nodes. Each directory retains its 100 largest
  children plus an informational aggregate row for the rest. GTK row objects are created
  only when a directory is expanded. The scan report shows scan duration, GTK model-build
  time, time until the tree is mapped, and process peak RSS.
- A GTK-free rule engine classifies caches, builds, personal data, credentials, repositories,
  browser profiles, game data, and container volumes. It reports Git worktree changes and
  recommends installed native procedures; administrator procedures are copy-only.
- File actions use a reviewed, one-item executor: Gio trash is the default, permanent
  removal requires typing a confirmation phrase, and critical-risk paths are blocked.
  Paths are revalidated against protected roots, active data, filesystem boundaries, and
  symlinks before acting. Each attempt records its result and filesystem capacity in JSONL.
- Cleanup runs one native command at a time, with a confirmation dialog showing the command and expected impact.
- Data-bearing targets such as Trash, Docker volumes, browser profiles, model downloads, and project directories are inspection-only.
- The app does not invoke a shell or request administrator privileges.
