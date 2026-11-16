# Clearspace

Clearspace is a local-first Linux disk cleanup app. It measures common disk consumers, explains what can be reclaimed, and runs native cleanup tools only after the user reviews and confirms an action.

## Run

```sh
python app.py
```

GTK 4 and its Python bindings (`python-gobject`) are required. On Arch Linux, install them with `sudo pacman -S gtk4 python-gobject`.

Clearspace stores a structured, local JSONL action history at `~/.local/share/clearspace/history.jsonl`. It records action IDs, measured sizes, timestamps, command arguments, exit status, and output. It does not store file contents or send data over the network. This history format is intended to provide a future retrieval layer for personalized recommendations; no LLM or RAG functionality is included yet.

## Safety

- Scanning is read-only and stays on the filesystem containing the scanned path.
- The GTK-free tree scanner loads one directory level on demand, includes hidden files,
  counts allocated disk blocks, counts hardlinked files once, and never follows symlinks.
- Scanner errors remain attached to their nodes; large directories collapse the remaining
  entries into a non-selectable informational row.
- A GTK-free rule engine classifies caches, builds, personal data, credentials, repositories,
  browser profiles, game data, and container volumes. It reports Git worktree changes and
  recommends installed native procedures; administrator procedures are copy-only.
- Cleanup runs one native command at a time, with a confirmation dialog showing the command and expected impact.
- Data-bearing targets such as Trash, Docker volumes, browser profiles, model downloads, and project directories are inspection-only.
- The app does not invoke a shell or request administrator privileges.
