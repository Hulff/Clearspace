# Live Scan Progress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate live scan progress with bounded top consumers, current path, a useful directory estimate, and local filesystem capacity context.

**Architecture:** Keep `ProgressEvent` GTK-free and gather capacity once from Python `os.statvfs`. Upgrade the Rust scanner progress stream to carry bounded traversal metadata, then adapt it into the Python event and UI. Reuse the existing local JSONL scan history for a prior completed directory count for the same canonical root.

**Tech Stack:** Python 3, Rust, GTK 4 UI adapter, JSONL, SQLite scanner, pytest, Cargo tests.

**Spec:** User request in the task prompt; scanner stream compatibility is defined in `docs/scanner-contract.md`.

## Global Constraints

- No subprocess, `df`, shell, network, or telemetry for filesystem capacity or progress.
- `os.statvfs` supplies `fs_used_bytes`, `fs_total_bytes`, and `fs_used_inodes`; all are nonnegative integers.
- Mount-root percent uses scanned allocated bytes divided by filesystem used bytes and is capped at 99% until completion.
- For subfolders, filesystem capacity is context only; progress uses completed plus queued directory estimates, preferring the last complete same-root scan when available.
- Top-K remains bounded to four entries; preserve lazy loading, top-200 child pages, and no widget per scanner node.
- Preserve all AGENTS.md scan invariants: read-only, no symlink traversal, same `st_dev`, and hardlink accounting.
- Do not implement the TreeSize-like layout in Step 3 under this plan.

## Review Focus

- Empty or zero filesystem counters, or statvfs failure: avoid division by zero; retain directory progress where valid and visibly label unavailable capacity context.
- Partial or cancelled previous scan: do not use it as the preferred completed directory estimate.
- Same root spelled differently: use the canonical scan root when matching local history.
- High fan-out or deep trees: directory estimates and top-K must remain bounded and monotonic where their contract requires it.
- Paths with unusual characters: JSONL progress must escape names and paths correctly; path data remains display-only.

---

### Task 1: Progress event and pure progress math

**Files:**
- Modify: `clearspace/progress.py`
- Test: `tests/test_progress.py`

**Interfaces:**
- Extend `ProgressEvent` with `fs_used_bytes: int | None`, `fs_total_bytes: int | None`, and `fs_used_inodes: int | None`.
- Add `filesystem_error: str | None` so a failed statvfs query remains visible while the scan continues with unavailable capacity context.
- Add `filesystem_stats(path: Path, statvfs=os.statvfs) -> tuple[int, int, int]` using `f_frsize` (falling back to `f_bsize`), `f_blocks - f_bfree`, and `f_files - f_ffree`, clamped at zero.
- Extend `progress_percent(event: ProgressEvent, *, root_is_mountpoint: bool = False) -> int | None`; preserve terminal `DONE -> 100`, use `event.bytes / event.fs_used_bytes` for mount roots, and otherwise use `dirs_done / dirs_total_est`.

- [x] **Step 1: Write failing tests** for statvfs field conversion with a mocked statvfs result, visible statvfs failure, zero-used-filesystem handling, mount-root byte percentage and 99% cap, and subfolder directory percentage.
- [x] **Step 2: Run** `python3 -m pytest -q tests/test_progress.py`; confirm failures are from missing fields/function/behavior.
- [x] **Step 3: Implement** only the event fields, validation, statvfs helper, and percentage branch.
- [x] **Step 4: Re-run** `python3 -m pytest -q tests/test_progress.py`; all focused tests pass.

### Task 2: Rust live progress protocol

**Files:**
- Modify: `scanner/src/main.rs`
- Test: Rust unit tests in `scanner/src/main.rs`
- Modify: `docs/scanner-contract.md`

**Interfaces:**
- Emit JSONL progress protocol version `2` with cumulative `dirs_done`, `dirs_queued`, `dirs_total_est`, `current_path`, and `largest_items` in addition to existing counters.
- Define the scanner's live estimate as `dirs_total_est = dirs_done + dirs_queued`; the Python adapter prefers the prior completed same-root count with `max(prior_count, dirs_total_est)`.
- Keep `largest_items` to four observed regular files, each `{name, path, bytes}`. Directory totals are only complete after traversal and aggregating them during parallel traversal would require unbounded per-directory state.
- Estimate directories from the root plus accepted directories discovered in `process_read_dir`; `dirs_done` counts directory entries consumed by the walker and `dirs_queued = dirs_total_est - dirs_done` for each live snapshot.
- Treat `current_path` and item paths as local display-only values; do not use them to authorize actions.

- [x] **Step 1: Update `docs/scanner-contract.md` first** to define protocol version 2, fields, monotonic counters, terminal behavior, and path privacy/display-only semantics. State that `fs_*` values are added by the Python adapter from local `statvfs`, not emitted by Rust.
- [x] **Step 2: Write failing Rust tests** for queue-estimate arithmetic, bounded top-K ordering, JSON escaping of a path containing quotes/non-ASCII characters, protocol fields, and final progress on small trees.
- [x] **Step 3: Run** `cargo test -q --manifest-path scanner/Cargo.toml`; verify expected failures.
- [x] **Step 4: Implement** bounded directory traversal accounting and top-K emission at the existing batched progress boundary; retain the current read-only traversal and `st_dev` rules.
- [x] **Step 5: Run** scanner Rust tests, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings` from `scanner/`.

### Task 3: Python adapter, prior-scan estimate, and live screen binding

**Files:**
- Modify: `clearspace/rust_scanner.py`
- Modify: `clearspace/core.py`
- Modify: `app.py`
- Test: `tests/test_rust_scanner.py`, `tests/test_progress.py`, and existing history tests

**Interfaces:**
- Validate protocol version 2 progress fields in `RustTreeScanner`; continue forwarding the progress object without fabricating a current path.
- Extend `History.record_scan(..., directories: int | None = None)` and add `History.latest_scan_for(path: Path) -> dict | None`, matching canonical paths and ignoring partial or legacy records without a directory count.
- In `app.py`, query `filesystem_stats(scan_root)` once in the scan worker, detect `scan_root.is_mount()`, fetch the prior same-root complete directory count, and populate all `ProgressEvent` fields from the Rust event plus statvfs snapshot. If statvfs raises `OSError`, keep scanning, set capacity fields to `None`, and expose the error through `filesystem_error` in the scan context label.
- Set the UI denominator to `max(event.dirs_total_est, prior_same_root_directories or 0)` for subfolders; ignore partial and legacy history entries without a directory count.
- Bind the existing “Biggest so far” rows and current-path label to the resulting event fields; show filesystem numbers as context, not as the subfolder denominator.
- Record the completed scan's directory count in existing local JSONL history; do not store top-K paths in scan history.

- [x] **Step 1: Write failing tests** for protocol v2 validation, same-canonical-root history lookup (including partial/legacy filtering), and propagation of current path/top-K/filesystem stats into `ProgressEvent`.
- [x] **Step 2: Run** the focused Python tests and verify the failures describe the missing contract/adaptation.
- [x] **Step 3: Implement** adapter validation, local-history lookup, and the scan callback/UI binding without GTK in unit tests.
- [x] **Step 4: Run** focused tests, then `python3 -m pytest -q` and `python3 -m compileall -q app.py clearspace tests`. Focused tests and compileall pass; full suite has two unchanged selection failures in `tests/test_contracts.py`.
- [x] **Step 5: Measure** the release scanner on the generated 11,701-file/585-directory fixture before and after, recording elapsed scan time and peak RSS; report observations without claiming improvement.

## Step 3 Proposal Only: TreeSize-like Scan Layout

Do not implement without a separate approval. Proposed follow-up: a live `Gtk.ColumnView` fed from the existing SQLite scan database with Size, Allocated, Files, Folders, % of Parent, Modified, Accessed, Owner, and Risk columns; a compact toolbar and drives panel; lazy rows only for visible/expanded nodes; top 200 children plus an aggregate “N smaller items” row. No per-node widgets and no eager in-memory tree. Review this as a separate UI/UX plan because it changes the scan screen substantially.
