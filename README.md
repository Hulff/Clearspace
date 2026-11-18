# Clearspace

Clearspace is a local-first Linux disk cleanup advisor. It measures common disk consumers across dedicated modes (Caches, Trash, Large Files, Logs, Docker, Arch Packages, and Folders), explains what can be reclaimed, and generates safe, comment-free terminal commands for the user to review and paste (Clearspace never executes cleanup commands).

## Run

```sh
python app.py
```

Build the standalone Rust scanner:

```sh
cargo build --release --manifest-path scanner/Cargo.toml
```

The GTK scan screen uses the standalone Rust scanner through its versioned JSONL
protocol. It reports the current path, an estimated directory total, filesystem
capacity context, and the four largest observed files while scanning. A prior
complete scan of the same canonical root can provide a better folder estimate;
this metadata stays in the local history. `CLEARSPACE_SCAN_BIN` can select a
specific scanner binary for headless integration tests.

Na primeira abertura, Clearspace mostra o seletor de pasta com Home selecionada.
Caches e Downloads aparecem como atalhos quando existem. A lista de pastas é
somente para leitura; tamanhos só são calculados depois de iniciar a varredura.
O usuário pode escolher outra pasta, incluir pastas ocultas ou limitar a busca
ao filesystem selecionado. O último scan concluído fica no histórico local para
consulta na linha Recent.

GTK 4 and its Python bindings (`python-gobject`) are required. On Arch Linux, install them with `sudo pacman -S gtk4 python-gobject`.

Clearspace stores a structured, local JSONL action history at `~/.local/share/clearspace/history.jsonl`. It records action IDs, measured sizes, timestamps, command arguments, exit status, and output. It does not store file contents or send data over the network. This history format is intended to provide a future retrieval layer for personalized recommendations; no LLM or RAG functionality is included yet.

## Safety

- Scanning is read-only and stays on the filesystem containing the scanned path.
- The standalone Rust scanner measures the tree in a background process, includes
  hidden files, counts allocated disk blocks and hardlinks once, and never follows
  symlinks. `RustTreeScanner` queries its SQLite database one directory at a time.
- The GTK-free Python scanner remains available for parity checks and supports
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
- The Results screen includes a local rule-based assistant summary and prompt chips.
  Messages remain in memory for the current app session. Proposals can only highlight
  a node or open a review for items the user already selected; they never change cleanup
  checkboxes or execute actions. The assistant does not load a model or use the network.
- The tree supports keyboard navigation (Space toggles cleanup selection, Left/Right
  collapses/expands rows). The assistant/details panel collapses automatically below
  1000 px and can be reopened with the toolbar toggle.
- Command generation (never executed by the app): selected safe paths emit independent `gio trash -- <quoted-path>` lines, and native tool cleanups emit fixed registry commands (`shlex.join`). Permanent deletion (`rm`) is never generated. Administrator commands (`sudo ...`) are isolated into their own review block and copy button. Generated command blocks omit `#` comments so pasting into interactive `zsh` or `bash` works without error.
- Revalidation happens at script-generation time against protected roots, symlinks, filesystem boundaries, control/NUL characters, and `inspect_only` / `critical` rules. Each generation records a `command_generated` event in JSONL history (`~/.local/share/clearspace/history.jsonl`).
- Data-bearing targets such as Trash, Docker volumes, browser profiles, model downloads, orphan package lists, and project directories are inspection-only.
- The app does not invoke a shell or request administrator privileges.
