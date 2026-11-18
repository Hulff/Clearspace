# Analysis Modes and Command Generation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add declarative analysis providers for Docker, caches, logs, large files, Trash, and Arch packages, and generate safe copy-only commands from reviewed rows.

**Architecture:** GTK-free provider modules return bounded, classified rows from runtime/XDG paths, the existing scanner database, and allowlisted read-only tool calls. A pure command generator revalidates selected rows and returns a script plus blocked items; GTK only displays/copies the result. Existing directory analysis remains the primary flow until the user approves the `AGENTS.md` contract change.

**Tech Stack:** Python standard library, GTK 4 UI, existing Rust SQLite scanner; no new dependencies.

**Spec:** `docs/clearspace_update_guide.md` (v2), with the `AGENTS.md` diff proposed separately for approval.

## Global Constraints

- Providers and command generation must not import `gi` or run cleanup subprocesses.
- Every command is copy-only; the application never executes generated cleanup commands.
- Trash is the default path action; no `rm`, permanent deletion, or automatic fallback.
- User data, `inspect_only`, and `critical` rows never produce commands.
- Tool argv comes from fixed registry entries; no shell, dynamic interpolation, or input from file contents.
- Scan-only and UI performance invariants from `AGENTS.md` remain in force.

## Review Focus

- Hostile filenames and shell metacharacters: quote and round-trip exact argv without execution.
- Newline/NUL/control characters: block the row and omit it from the script.
- Symlink, vanished, protected, and out-of-root paths: block at generation time.
- Admin-required procedures: appear only in a separate labeled block with visible `sudo`; never execute in the app.
- Provider/tool failures: classify and show retryable errors without leaving a mode loading.

---

### Phase 1: Contracts and approval

- [x] Draft `docs/provider-contract.md` and `docs/command-generator.md`.
- [x] Propose (do not apply) the `AGENTS.md` diff.
- [ ] Wait for user approval before implementing the contract change or any code.

### Phase 2: Pure command generator

- [ ] Update/approve the `AGENTS.md` invariants before implementation.
- [ ] Add GTK-free models and the pure generator; test quoting, hostile/control paths, revalidation, protected/critical/inspect-only handling, admin separation, and history semantics.
- [ ] Keep every command independent; never execute generated text.

### Phase 3: Providers and UI

- [ ] Add provider registry and lazy per-mode loading for Caches and Trash, then Logs and Large Files, then Docker and Arch Packages.
- [ ] Keep provider subprocesses read-only, argv-based, timeout-bounded, and mockable.
- [ ] Add the empty mode sidebar only after the docs-only Phase 1 approval; keep the existing directory scan unchanged.
- [ ] Render rows, warnings, blocked entries, generated script, copy action, and admin block in pt-BR.

### Phase 4: Verification

- [ ] Run pure Python tests, Rust/database contract tests where applicable, lint, and scanner parity checks required by `AGENTS.md`.
- [ ] Verify no cleanup subprocess or automatic action was introduced; report UI, Docker, and non-Arch limitations.
