# Permanent Delete Speed and Confirmation Plan

**Goal:** Reduce the time spent in explicitly confirmed permanent deletion and require a separate unchecked confirmation checkbox.

**Architecture:** Keep deletion inside the executor's directory-descriptor traversal. Validate the complete selected tree immediately before deletion, then validate each entry's type, device, protected/active path, and parent descriptor without recursively rewalking descendants. Keep typed confirmation and require the UI checkbox as an additional gate.

**Tech Stack:** Python 3, GTK 4, POSIX dir-fd filesystem operations.

**Spec:** User request to make permanent deletion faster and add a confirm checkbox.

## Global Constraints

- Trash remains the default; permanent deletion stays per-item and explicitly confirmed.
- Never follow symlinks or cross filesystems; preserve protected-path and active-application checks.
- No sudo and no shell command execution.
- Keep risk-critical paths blocked and preserve JSONL history.

## Review Focus

- Confirm the checkbox is unchecked initially and permanent action remains disabled until checkbox and typed phrase match.
- Confirm symlink targets, cross-device mounts, protected paths, and active application paths remain untouched.
- Confirm per-item failures remain recorded and later items continue.
- Confirm traversal cost is linear in visited entries rather than revalidating full descendant trees.
- Confirm Trash action remains unchanged.

### Task 1: Measure and optimize executor traversal

**Files:** `clearspace/executor.py`

- [x] Measure permanent deletion time on a temporary synthetic nested tree before editing: 2,641 entries; review 4.989 s, execution 12.797 s (single run).
- [x] Remove recursive `_validate_path` calls for each entry while retaining execution-time validation of the selected tree and per-entry protected/active checks.
- [x] Replace repeated guard construction with per-operation cached protected and active paths; check opened directory descriptors with `fstat` before descent.
- [x] Measure the same synthetic tree after the change: 2,641 entries; review median 1.677 s and execution median 3.289 s across three runs. Every run completed successfully.

### Task 2: Add explicit UI confirmation

**Files:** `app.py`

- [x] Add an unchecked confirmation checkbox to the typed permanent-delete dialog.
- [x] Keep the permanent-delete button disabled until both the checkbox is active and the typed phrase matches.
- [x] Recheck both conditions in the response callback before starting execution.
- [x] Run `compileall`; GTK dialog interaction remains a manual check.

### Task 3: Final verification

- [x] Run `git diff --check` and review only the focused diff.
- [x] Report benchmark evidence, test status, and GTK verification limits.
