# Batch Cleanup Confirmation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace per-item dialogs and typed permanent confirmation with one reviewed batch confirmation, and avoid automatically rescanning after cleanup.

**Architecture:** GTK presents all reviewed items ordered by descending risk and size, then a single explicit action launches sequential per-item executor calls. Each item retains path revalidation and JSONL history; critical-risk entries remain blocked. The summary offers an explicit rescan action instead of starting a scan when closed.

**Tech Stack:** Python 3, GTK 4, Gio, existing Clearspace executor.

**Spec:** User requests in this conversation and updated `AGENTS.md` cleanup invariants.

## Global Constraints

- Trash remains the default action; permanent deletion requires a distinct explicit action.
- Critical-risk paths remain blocked.
- Revalidate and log every item separately; one failure does not stop later items.
- No shell, sudo, or automatic fallback.
- No automatic full rescan after cleanup; show stale-results state and provide explicit rescan.

## Review Focus

- Mixed critical and non-critical selections: critical entries stay blocked while other items can proceed.
- User data in a batch: require a separate batch acknowledgment before enabling either action.
- Unsupported trash: never silently switch to permanent deletion.
- Per-item execution failures: continue through the remaining reviewed items and preserve every history result.
- Closing the summary: keep stale results non-actionable until the user explicitly rescans.

---

### Task 1: Batch review and execution UI

**Files:**
- Modify: `app.py`
- Modify: `AGENTS.md`

- [x] Sort reviewed items by risk descending, then allocated size descending, and show all paths, sizes, risks, and warnings in one scrollable review dialog.
- [x] Require one batch acknowledgment when any item has user-data risk; the selected action button confirms the batch.
- [x] Execute eligible items sequentially in one worker without per-item dialogs; retain per-item executor validation and result collection.
- [x] Keep critical entries blocked and continue through eligible entries.
- [x] Remove typed confirmation; require an explicit permanent-action button and never fall back from trash.
- [x] Add a deliberate rescan action to the completion summary and mark results stale when it is not chosen.

### Task 2: Verification and evidence

**Files:**
- Verify: `app.py`, `clearspace/executor.py`, `AGENTS.md`

- [x] Run syntax compilation and `git diff --check`.
- [x] Inspect the final diff for unchanged per-item path validation, failure continuation, and JSONL history.
- [x] Report that pytest and GTK dialogs were not verified if pytest is unavailable or GTK cannot be displayed.
