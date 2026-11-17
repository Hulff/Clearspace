Read AGENTS.md first. Work in phases, one commit per phase. Report per phase:
what changed, evidence (tests/measurements), risks, and what was NOT verified.

GOAL
Implement the approved Clearspace UI: (1) a Scanning screen with live progress,
(2) a Results screen with the size-sorted tree, risk badges, action bar and a
collapsible assistant panel. Keep the app general (no machine-specific paths/names).
The UI must not care which scanner runs (Python now, Rust later via JSONL), so
everything goes through a scanner-agnostic progress contract.

ASSUMPTIONS (I decided these; flag any you think is wrong, don't silently change them)
- Progress unit = folders: "done / estimated total". The total is an ESTIMATE that may
  grow as folders are discovered; the UI labels it as estimated. If no estimate exists
  yet, show an indeterminate (pulsing) bar instead of a fake percentage.
- Percentage is clamped to 99% until the scan really finishes.
- Cancel stops the scan and keeps partial results, clearly marked "partial".
- The assistant panel is collapsible and cheap. No LLM is loaded in this task.

DESIGN TOKENS (dark theme, apply with Gtk.CssProvider)
bg #181a1b | surface #232627 | panel #1c1f20 | border #34383a | track #34383a
text #eceeef | muted #a9b0b3 | accent #5aa9ff | accent-text #0b1620
risk badges: Low bg #1f3a2a text #8fe0b0 | Moderate bg #3d3418 text #f2d27a |
Your data bg #1c3350 text #9cc8ff (badge always has a text label, never color alone)
Font: Inter if installed, else system sans. Radius 10-16px. Touch/click targets >= 40px.
Text contrast >= 4.5:1. Real Gtk buttons/checkbuttons with accessible labels.

SCREEN 1: SCANNING
- Title "Scanning your disk…"; subtitle: root path + "Everything stays on your
  computer and nothing is deleted."
- Card with: big counter "43 / 428 folders" (done muted-suffix), percentage on the
  right in accent color, a 14px rounded progress bar (Gtk.ProgressBar styled via CSS,
  accessible name "Scan progress").
- Four stat tiles: files analyzed (thousands separators), size measured so far
  (GiB), elapsed (m:ss), estimated time left ("~6 min").
- ETA: smoothed rate (EMA); hide it until >= 5% or >= 5 s; label as estimate;
  never show absurd values (cap, or show "calculating…").
- Line "Now scanning: <current path>" (monospace, truncated in the middle).
- Buttons: Pause/Resume and Cancel.
- "Biggest so far (updates live)": top 4 entries with bar + size, refreshed at ~1 Hz,
  bounded memory (small heap, not the whole tree).
- Footnote: "Time left is an estimate. The total can change as new folders are found."
- Update the UI at most ~5-10 Hz via a GLib timeout reading a shared snapshot;
  NEVER one idle_add per file/folder.

SCREEN 2: RESULTS
- Header: "Disk cleanup", right side "40.0 GiB free of 142.1 GiB · scanned N folders
  in m:ss" (real values).
- Column header + the lazy tree (Gtk.ColumnView + TreeListModel + SortListModel):
  checkbox (tri-state), name with disclosure arrow, usage bar relative to the largest
  sibling, size, risk badge. Biggest first at every level. No widget per node.
- Bottom action bar: "N items selected · X GiB · highest risk: Y" and the note
  "Items go to the Trash first. Space is freed when you empty it." Primary button
  "Review and clean…" (disabled when nothing is selected).
- Right panel (340px, collapsible with a toggle): "Assistant" header; greeting built
  from REAL scan data (folders scanned, duration, free/total, two biggest consumers);
  three suggestion chips ("Suggest a safe cleanup", "What is using the most space?",
  "Explain the risk of <selected item>"); text input with the line "Runs on your
  computer. It only suggests; you always confirm."
- Implement the panel with a LocalRuleAssistant behind the Assistant Protocol
  (rule/template answers from scan data, no network, no model). Free text it cannot
  answer gets a short friendly fallback. Its proposed actions can only highlight a node
  or open the review dialog; they never select, delete or run anything by themselves.
- Partial scans show a "partial results" banner with a Scan again button.

PHASE 0 - Contracts (no UI)
- ProgressEvent dataclass: dirs_done, dirs_total_est (nullable), files, bytes,
  elapsed_ms, current_path, state (running/paused/cancelled/done/error), partial.
- ScanController API: start, pause, resume, cancel, latest_snapshot(); GTK-free.
- Document the matching JSONL line format in docs/scanner-contract.md so the Rust
  scanner can emit it later (pause/resume for a child process via SIGSTOP/SIGCONT,
  no shell).
- Pure functions (unit-tested): percent (clamped), ETA with EMA, size/time formatting,
  top-K tracker.

PHASE 1 - Scanning screen
- Wire the existing Python scanner to emit ProgressEvents (estimate total as
  discovered folders; it may grow). Build screen 1 against ScanController only.

PHASE 2 - Results screen
- Polish the tree/rows/badges/action bar to the spec using existing risk rules and
  the existing executor/review flow. Keep lazy loading and the top-N + "N smaller
  items" aggregation.

PHASE 3 - Assistant panel
- Panel shell, greeting from real data, chips, LocalRuleAssistant, collapse toggle.

PHASE 4 - Polish and QA
- Keyboard navigation (Tab order, Space toggles checkboxes, arrows in the tree),
  accessible names, narrow-window behavior (panel collapses under ~1000px).

PARALLELISM
After Phase 0, three agents on disjoint files: (a) scanner progress emission,
(b) scanning screen, (c) assistant panel + LocalRuleAssistant. One integrator merges
and runs everything. Never two agents on the same file.

TESTS
Pure-logic tests with no GTK: percent clamp and 99% cap, ETA smoothing and the
"calculating" rule, top-K bounded memory, throttling, pause/resume/cancel with a fake
scanner, partial flag on cancel, LocalRuleAssistant answers from a synthetic scan,
and a test that assistant proposals cannot trigger deletion. Fixtures only in
tmp_path; nothing reads the real home.

CONSTRAINTS
All AGENTS.md invariants hold: read-only scan, no shell, no sudo, Trash by default,
protected paths, per-item logging. No new dependencies without asking. If no display
is available, say the GTK screens were NOT visually verified and give me a manual
checklist (progress moves, pause/cancel work, tree stays responsive, panel collapses).