# Scan Results and Nested Symlink Fixes Implementation Plan

**Goal:** Ensure consecutive scans replace the displayed tree and directories containing symlinks can be reviewed without following link targets.

**Architecture:** Keep one persistent GTK `ScrolledWindow` as the tree host and replace its child for each completed scan. Treat symlinks encountered below a selected directory as opaque entries; sizing and review never traverse targets, and permanent deletion unlinks only the symlink entry.

**Tech Stack:** Python 3, GTK 4, pathlib, dir-fd filesystem operations, pytest.

**Spec:** User report of stale prior scan results and review failure at `.venv/bin/python`.

## Global Constraints

- Never follow symlinks during scan, review sizing, or deletion.
- Keep root containment, protected-path, active-application, filesystem-device, and confirmation checks.
- No sudo, dependencies, or changes to the separate `spike/` tree.
- Pure executor tests use `tmp_path`; GTK dialogs are reported as unverified.

## Review Focus

- A symlink targeting outside the selected root must remain opaque, and its target must remain untouched.
- A symlink that changes after review must not redirect an action outside the root.
- Selecting a symlink directly remains blocked by canonical root validation.
- A selected directory must not count or delete bytes at a symlink target.
- A later scan must attach its new tree to the live GTK host, not a detached placeholder.

### Task 1: Keep nested symlinks opaque in executor review and deletion

**Files:** `clearspace/executor.py`, `tests/test_executor.py`

- [x] Change the nested-symlink review regression to assert that review succeeds for a parent directory, its size excludes the outside target, and the target remains unchanged.
- [x] Add a permanent-delete regression asserting that an outside-root symlink entry is removed while the target remains.
- [x] Run each regression before implementation and confirm it fails on the current behavior.
- [x] Skip symlink targets during nested review; unlink only link entries during permanent deletion using the existing directory-descriptor flow.
- [x] Run `pytest -q tests/test_executor.py`.

### Task 2: Replace results in a persistent GTK tree host

**Files:** `app.py`

- [x] Store the result `Gtk.ScrolledWindow` on the application instance when building the results view.
- [x] Set each completed scan's `Gtk.ColumnView` as that host's child, replacing the previous view.
- [x] Check syntax and the complete non-GTK test suite; report that visual GTK verification remains outstanding.

### Task 3: Final verification

- [x] Run the full Python test suite, `compileall`, and `git diff --check`.
- [x] Review the focused diff and leave all unrelated local changes untouched.
- [x] Report GTK dialogs not visually verified.
