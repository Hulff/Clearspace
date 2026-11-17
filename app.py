#!/usr/bin/env python3
"""Clearspace GTK 4 desktop application."""

from __future__ import annotations

import shlex
import os
import resource
import stat
import threading
import time
from collections import OrderedDict
from dataclasses import replace
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
gi.require_version("Gio", "2.0")
from gi.repository import Gdk, Gio, GLib, GObject, Gtk

from clearspace.assistant import (
    AssistantScanContext,
    LocalRuleAssistant,
    ScanConsumer,
)
from clearspace.contracts import (
    Node,
    ProposedActionKind,
    Risk,
    SelectionModel,
    SelectionState,
)
from clearspace.core import History, format_bytes, inspection_only_paths
from clearspace.progress import (
    EtaEstimator,
    ProgressEvent,
    ScanController,
    ScanState,
    format_elapsed,
    format_size_gib,
    filesystem_stats,
    progress_percent,
    relative_size_fraction,
)
from clearspace.executor import (
    ActiveApplicationError,
    PERMANENT_CONFIRMATION,
    CleanupReview,
    FileAction,
    ItemExecutor,
    ReviewedItem,
    build_review,
    discover_active_paths,
    gio_trash_supported,
)
from clearspace.locations import (
    ScanOptions,
    ScanRootError,
    canonical_directory,
    format_age,
    resolve_xdg_locations,
    validate_scan_root,
)
from clearspace.rules import RuleEngine, RuleEvaluation
from clearspace.rust_scanner import (
    RustScannerError,
    RustTreeScanner,
    progress_event_from_rust,
)


def _bounded_setting(name: str, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(os.environ.get(name, str(default))))
    except ValueError:
        return default


TREE_PAGE_SIZE = _bounded_setting("CLEARSPACE_TREE_PAGE_SIZE", 200, 1)
TREE_NODE_CAP = _bounded_setting("CLEARSPACE_MAX_TREE_NODES", 20_000, 256)
TREE_EXPANDED_CACHE = _bounded_setting("CLEARSPACE_TREE_CACHE_FOLDERS", 32, 1)
TREE_EVICT_DELAY_MS = _bounded_setting("CLEARSPACE_TREE_EVICT_DELAY_MS", 1200, 0)


class TreeEntry(GObject.Object):
    """GTK list item wrapper around a GTK-free filesystem Node."""

    def __init__(
        self,
        node: Node,
        evaluation: RuleEvaluation | None = None,
        *,
        loading=False,
        parent_entry=None,
    ):
        super().__init__()
        self.node = node
        self.evaluation = evaluation
        self.loading = loading
        self.parent_entry = parent_entry
        self.children_store = None
        self.children_model = None
        self.loading_children = False
        self.scanner = None
        self.bound_rows = set()
        self.load_generation = 0
        self.is_expanded = False


class Clearspace(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="org.clearspace.DiskCleanup")
        self.history = History()
        self.rule_engine = RuleEngine()
        self.scan_root = Path(GLib.get_home_dir())
        self.scan_options = ScanOptions()
        self.chosen_scan_path = self.scan_root
        self.browser_path = self.scan_root
        self.scanner: RustTreeScanner | None = None
        self.root_node: Node | None = None
        self.root_entry: TreeEntry | None = None
        self.selection: SelectionModel | None = None
        self.entries: dict[Path, TreeEntry] = {}
        self.inspection_only_roots: tuple[Path, ...] = ()
        self.check_buttons: dict[Path, list[Gtk.CheckButton]] = {}
        self._syncing_checks = False
        self._review: CleanupReview | None = None
        self._review_action: FileAction | None = None
        self._review_index = 0
        self._execution_results = []
        self._workflow_busy = False
        self._scan_generation = 0
        self._scan_started_at = 0.0
        self.scan_controller = ScanController()
        self._scan_poll_source = None
        self._scan_eta = EtaEstimator()
        self._scan_largest_items = ()
        self._scan_last_top_render = 0.0
        self.local_assistant = LocalRuleAssistant()
        self.assistant_context = AssistantScanContext(0, 0, 0, 0)
        self.assistant_messages: list[tuple[str, str]] = []
        self._responsive_poll_source = None
        self._window_is_narrow: bool | None = None
        self._auto_collapsed_for_width = False
        self._responsive_toggle = False
        self._folder_listing_generation = 0
        self._folder_rows = ()
        self._child_store_cache: dict[int, Gio.ListStore] = {}
        self._expanded_cache: OrderedDict[int, TreeEntry] = OrderedDict()
        self._live_entry_count = 0
        self._reserved_node_count = 0
        self._selected_evaluations: dict[Path, RuleEvaluation] = {}

    def do_activate(self):
        self.window = Gtk.ApplicationWindow(application=self, title="Clearspace")
        self.window.set_default_size(1280, 820)
        self._install_theme()
        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        self.window.set_child(self.stack)
        self._build_scanning_screen()
        self._build_folder_chooser()
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        outer.set_margin_top(20)
        outer.set_margin_bottom(16)
        outer.set_margin_start(20)
        outer.set_margin_end(20)
        self.stack.add_named(outer, "results")

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        outer.append(header)
        heading = Gtk.Label(label="Disk cleanup", xalign=0, hexpand=True)
        heading.add_css_class("title-1")
        header.append(heading)
        intro = Gtk.Label(
            label="Explore the local tree, understand risks, and review each item before acting."
        )
        intro.set_xalign(0)
        intro.add_css_class("dim-label")
        outer.append(intro)

        self.disk_label = Gtk.Label(label="", xalign=1, wrap=True)
        self.disk_label.add_css_class("scan-muted")
        header.append(self.disk_label)
        self.partial_banner = Gtk.Box(spacing=10)
        self.partial_banner.add_css_class("scan-chip")
        partial_label = Gtk.Label(label="These are partial results.", xalign=0, hexpand=True)
        self.partial_banner.append(partial_label)
        self.partial_scan_button = Gtk.Button(label="Scan again")
        self.partial_scan_button.connect("clicked", lambda *_: self.scan())
        self.partial_banner.append(self.partial_scan_button)
        self.partial_banner.set_visible(False)
        outer.append(self.partial_banner)

        scan_bar = Gtk.Box(spacing=8)
        self.scan_button = Gtk.Button(label="Choose folder…")
        self.scan_button.connect("clicked", self.show_folder_chooser)
        scan_bar.append(self.scan_button)
        self.scan_report_button = Gtk.Button(label="Relatório da varredura")
        self.scan_report_button.set_sensitive(False)
        self.scan_report_button.connect("clicked", self.show_scan_report)
        scan_bar.append(self.scan_report_button)
        self.assistant_panel_button = Gtk.ToggleButton(label="Hide assistant panel")
        self.assistant_panel_button.set_active(True)
        self.assistant_panel_button.connect(
            "toggled", self._assistant_panel_toggled
        )
        self._set_accessible_label(
            self.assistant_panel_button, "Show or hide assistant panel"
        )
        scan_bar.append(self.assistant_panel_button)
        outer.append(scan_bar)
        self.panes = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL, vexpand=True)
        outer.append(self.panes)

        tree_scroll = Gtk.ScrolledWindow(hexpand=True, vexpand=True)
        tree_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.panes.set_start_child(tree_scroll)
        self.tree_placeholder = Gtk.Label(label="Loading folder…", xalign=0)
        tree_scroll.set_child(self.tree_placeholder)

        self.details = self._build_details_panel()
        self.panes.set_end_child(self.details)
        self.panes.set_position(900)

        footer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        footer.add_css_class("results-footer")
        footer_row = Gtk.Box(spacing=12)
        self.selection_label = Gtk.Label(label="0 items selected", xalign=0, hexpand=True)
        footer_row.append(self.selection_label)
        self.review_button = Gtk.Button(label="Review and clean…")
        self.review_button.add_css_class("suggested-action")
        self.review_button.set_sensitive(False)
        self.review_button.connect("clicked", self.review_selection)
        footer_row.append(self.review_button)
        footer.append(footer_row)
        trash_note = Gtk.Label(
            label="Items go to the Trash first. Space is freed when you empty it.",
            xalign=0,
        )
        trash_note.add_css_class("selection-note")
        footer.append(trash_note)
        outer.append(footer)

        self.stack.set_visible_child_name("choose")
        self._set_chosen_folder(self.scan_root, browse=True, quick_pick="home")
        self.window.present()
        self._responsive_poll_source = GLib.timeout_add(
            500, self._check_responsive_panel
        )

    def _install_theme(self):
        css = """
        * { font-family: Inter, sans-serif; color: #eceeef; }
        window, .clearspace-root { background: #181a1b; }
        .scan-card, .scan-stat { background: #232627; border: 1px solid #34383a;
            border-radius: 14px; }
        .scan-card { padding: 22px; }
        .scan-stat { padding: 14px; }
        .scan-muted { color: #a9b0b3; }
        .size-value { font-family: monospace; font-variant-numeric: tabular-nums; }
        .scan-accent { color: #5aa9ff; }
        progressbar trough { min-height: 14px; border-radius: 8px; background: #34383a; }
        progressbar progress { min-height: 14px; border-radius: 8px; background: #5aa9ff; }
        button { min-height: 40px; }
        checkbutton { min-width: 40px; min-height: 40px; }
        entry { min-height: 40px; }
        .scan-current-path { font-family: monospace; color: #a9b0b3; }
        .quick-pick, .ready-card, .folder-browser { background: #232627;
            border: 1px solid #34383a; border-radius: 14px; padding: 14px; }
        .folder-hidden { color: #e5b567; font-size: 0.85em; }
        .folder-error, .error { color: #ff8b82; }
        .scan-chip { background: #1c1f20; border-radius: 8px; padding: 8px 10px; }
        .badge { border-radius: 999px; padding: 4px 9px; font-weight: 600; }
        .risk-low { background: #1f3a2a; color: #8fe0b0; }
        .risk-moderate { background: #3d3418; color: #f2d27a; }
        .risk-user-data { background: #1c3350; color: #9cc8ff; }
        .risk-critical { background: #49252b; color: #ffc1c5; }
        .selection-note { color: #a9b0b3; font-size: 0.9em; }
        .results-footer { background: #1c1f20; border: 1px solid #34383a;
            border-radius: 12px; padding: 10px 14px; }
        """
        provider = Gtk.CssProvider()
        provider.load_from_data(css.encode("utf-8"))
        display = Gdk.Display.get_default()
        if display is not None:
            Gtk.StyleContext.add_provider_for_display(
                display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
        self._css_provider = provider

    def _build_scanning_screen(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        page.add_css_class("clearspace-root")
        page.set_halign(Gtk.Align.FILL)
        page.set_valign(Gtk.Align.FILL)
        page.set_margin_top(36)
        page.set_margin_bottom(30)
        page.set_margin_start(40)
        page.set_margin_end(40)

        title = Gtk.Label(label="Scanning your disk…", xalign=0)
        title.add_css_class("title-1")
        page.append(title)
        self.scan_subtitle = Gtk.Label(xalign=0, wrap=True)
        self.scan_subtitle.add_css_class("scan-muted")
        page.append(self.scan_subtitle)

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        card.add_css_class("scan-card")
        page.append(card)
        progress_header = Gtk.Box(spacing=12)
        card.append(progress_header)
        self.scan_counter_label = Gtk.Label(xalign=0, hexpand=True)
        self.scan_counter_label.add_css_class("title-2")
        progress_header.append(self.scan_counter_label)
        self.scan_percent_label = Gtk.Label(label="", xalign=1)
        self.scan_percent_label.add_css_class("title-2")
        self.scan_percent_label.add_css_class("scan-accent")
        progress_header.append(self.scan_percent_label)
        self.scan_progress_bar = Gtk.ProgressBar(hexpand=True)
        self.scan_progress_bar.set_show_text(False)
        self._set_accessible_label(self.scan_progress_bar, "Scan progress")
        card.append(self.scan_progress_bar)

        stats = Gtk.Grid(column_spacing=12, row_spacing=12)
        stats.set_column_homogeneous(True)
        for index, (heading, attribute) in enumerate((
            ("Files analyzed", "scan_files_value"),
            ("Measured", "scan_bytes_value"),
            ("Elapsed", "scan_elapsed_value"),
            ("Time left · estimate", "scan_eta_value"),
        )):
            tile = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            tile.add_css_class("scan-stat")
            label = Gtk.Label(label=heading, xalign=0)
            label.add_css_class("scan-muted")
            value = Gtk.Label(label="—", xalign=0)
            value.add_css_class("title-3")
            tile.append(label)
            tile.append(value)
            setattr(self, attribute, value)
            stats.attach(tile, index, 0, 1, 1)
        card.append(stats)

        self.scan_path_label = Gtk.Label(xalign=0, wrap=False, ellipsize=2)
        self.scan_path_label.add_css_class("scan-current-path")
        card.append(self.scan_path_label)

        biggest_title = Gtk.Label(label="Biggest so far", xalign=0)
        biggest_title.add_css_class("heading")
        card.append(biggest_title)
        self.scan_biggest_box = Gtk.Grid(column_spacing=12, row_spacing=7)
        self.scan_biggest_box.set_hexpand(True)
        self._scan_biggest_rows = []
        for row_index in range(4):
            name_label = Gtk.Label(xalign=0, hexpand=True, ellipsize=3)
            bar = Gtk.ProgressBar()
            bar.set_size_request(160, 8)
            size_label = Gtk.Label(xalign=1)
            size_label.set_width_chars(10)
            size_label.set_xalign(1.0)
            size_label.add_css_class("size-value")
            size_label.add_css_class("scan-muted")
            self.scan_biggest_box.attach(name_label, 0, row_index, 1, 1)
            self.scan_biggest_box.attach(bar, 1, row_index, 1, 1)
            self.scan_biggest_box.attach(size_label, 2, row_index, 1, 1)
            self._scan_biggest_rows.append((name_label, bar, size_label))
        card.append(self.scan_biggest_box)

        controls = Gtk.Box(spacing=10)
        self.scan_pause_button = Gtk.Button(label="Pause")
        self.scan_pause_button.connect("clicked", self._toggle_scan_pause)
        controls.append(self.scan_pause_button)
        self.scan_cancel_button = Gtk.Button(label="Cancel")
        self.scan_cancel_button.connect("clicked", self._cancel_scan)
        controls.append(self.scan_cancel_button)
        card.append(controls)
        footnote = Gtk.Label(
            label=(
                "Time left is an estimate. The estimated folder total can change "
                "as new folders are found."
            ),
            xalign=0,
            wrap=True,
        )
        footnote.add_css_class("scan-muted")
        page.append(footnote)
        self.stack.add_named(page, "scanning")

    def _build_folder_chooser(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        page.add_css_class("clearspace-root")
        page.set_margin_top(28)
        page.set_margin_bottom(24)
        page.set_margin_start(30)
        page.set_margin_end(30)

        title = Gtk.Label(label="Where do you want to start?", xalign=0)
        title.add_css_class("title-1")
        page.append(title)
        subtitle = Gtk.Label(
            label="Pick a folder to scan. Smaller scans are faster and use less memory. Nothing is deleted.",
            xalign=0,
            wrap=True,
        )
        subtitle.add_css_class("scan-muted")
        page.append(subtitle)

        locations = resolve_xdg_locations(
            home_dir=GLib.get_home_dir(),
            cache_dir=GLib.get_user_cache_dir(),
            downloads_dir=GLib.get_user_special_dir(
                GLib.UserDirectory.DIRECTORY_DOWNLOAD
            ),
            config_dir=GLib.get_user_config_dir(),
            environ=os.environ,
        )
        quick_specs = (
            ("home", "Home", "Recommended", locations["home"]),
            ("caches", "Caches", "Often safe to clean", locations["caches"]),
            ("downloads", "Downloads", "Personal files", locations["downloads"]),
        )
        self.quick_pick_paths: dict[str, Path] = {}
        self.quick_pick_buttons: dict[str, Gtk.ToggleButton] = {}
        self._updating_quick_picks = False
        quick_row = Gtk.Box(spacing=12)
        for key, label, hint, raw_path in quick_specs:
            if raw_path is None:
                continue
            path = Path(raw_path)
            try:
                info = path.lstat()
            except OSError:
                continue
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                continue
            self.quick_pick_paths[key] = path
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
            name_label = Gtk.Label(label=label, xalign=0)
            name_label.add_css_class("heading")
            hint_label = Gtk.Label(label=hint, xalign=0)
            hint_label.add_css_class("scan-muted")
            path_label = Gtk.Label(label=str(path), xalign=0, ellipsize=2)
            path_label.add_css_class("scan-muted")
            card.append(name_label)
            card.append(hint_label)
            card.append(path_label)
            button = Gtk.ToggleButton()
            button.set_child(card)
            button.add_css_class("quick-pick")
            button.set_hexpand(True)
            button.connect("toggled", self._quick_pick_toggled, key)
            self._set_accessible_label(button, f"Scan {label}: {hint}")
            self.quick_pick_buttons[key] = button
            quick_row.append(button)
        page.append(quick_row)

        browser_and_ready = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=18, vexpand=True
        )
        page.append(browser_and_ready)

        browser = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, hexpand=True)
        browser.add_css_class("folder-browser")
        breadcrumb_scroll = Gtk.ScrolledWindow(hexpand=True)
        breadcrumb_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.NEVER)
        self.folder_breadcrumb = Gtk.Box(spacing=2)
        breadcrumb_scroll.set_child(self.folder_breadcrumb)
        browser.append(breadcrumb_scroll)

        browser_controls = Gtk.Box(spacing=8)
        self.folder_back_button = Gtk.Button(label="‹ Back")
        self.folder_back_button.connect("clicked", self._folder_back_clicked)
        self.folder_back_button.set_sensitive(False)
        browser_controls.append(self.folder_back_button)
        self.folder_open_button = Gtk.Button(label="Open ›")
        self.folder_open_button.connect("clicked", self._open_selected_subfolder)
        self.folder_open_button.set_sensitive(False)
        browser_controls.append(self.folder_open_button)
        self.choose_another_button = Gtk.Button(label="Choose another folder…")
        self.choose_another_button.connect("clicked", self._choose_another_folder)
        browser_controls.append(self.choose_another_button)
        browser.append(browser_controls)

        self.folder_status_label = Gtk.Label(label="", xalign=0, wrap=True)
        self.folder_status_label.add_css_class("scan-muted")
        browser.append(self.folder_status_label)
        self.folder_strings = Gtk.StringList.new([])
        self.folder_selection = Gtk.SingleSelection.new(self.folder_strings)
        self.folder_selection.set_autoselect(False)
        self.folder_selection.set_can_unselect(True)
        self.folder_selection.connect(
            "notify::selected", self._folder_selection_changed
        )
        folder_factory = Gtk.SignalListItemFactory.new()
        folder_factory.connect("setup", self._folder_row_setup)
        folder_factory.connect("bind", self._folder_row_bind)
        self.folder_list = Gtk.ListView.new(self.folder_selection, folder_factory)
        self.folder_list.set_single_click_activate(False)
        self._set_accessible_label(self.folder_list, "Subfolders")
        self.folder_list.connect("activate", self._folder_row_activated)
        folder_scroll = Gtk.ScrolledWindow(vexpand=True)
        folder_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        folder_scroll.set_child(self.folder_list)
        browser.append(folder_scroll)
        browser_and_ready.append(browser)

        ready = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        ready.set_size_request(320, -1)
        ready.add_css_class("ready-card")
        ready_title = Gtk.Label(label="Ready to scan", xalign=0)
        ready_title.add_css_class("title-2")
        ready.append(ready_title)
        self.ready_path_label = Gtk.Label(label="", xalign=0, wrap=True, selectable=True)
        ready.append(self.ready_path_label)
        self.ready_space_label = Gtk.Label(label="", xalign=0, wrap=True)
        self.ready_space_label.add_css_class("scan-muted")
        ready.append(self.ready_space_label)
        self.ready_error_label = Gtk.Label(label="", xalign=0, wrap=True)
        self.ready_error_label.add_css_class("error")
        ready.append(self.ready_error_label)

        self.include_hidden_check = Gtk.CheckButton(label="Include hidden folders")
        self.include_hidden_check.set_active(True)
        self._set_accessible_label(
            self.include_hidden_check, "Include hidden folders in the scan"
        )
        ready.append(self.include_hidden_check)
        self.stay_on_disk_check = Gtk.CheckButton(label="Stay on this disk only")
        self.stay_on_disk_check.set_active(True)
        self._set_accessible_label(
            self.stay_on_disk_check, "Stay on the selected filesystem"
        )
        ready.append(self.stay_on_disk_check)
        self.start_scan_button = Gtk.Button(label="Start scan")
        self.start_scan_button.add_css_class("suggested-action")
        self.start_scan_button.set_sensitive(False)
        self.start_scan_button.connect("clicked", self._start_selected_scan)
        ready.append(self.start_scan_button)
        self.recent_scan_label = Gtk.Label(label="Recent: no scans yet", xalign=0, wrap=True)
        self.recent_scan_label.add_css_class("selection-note")
        ready.append(self.recent_scan_label)
        self.use_recent_button = Gtk.Button(label="Use recent folder")
        self.use_recent_button.set_sensitive(False)
        self.use_recent_button.connect("clicked", self._use_recent_scan)
        ready.append(self.use_recent_button)
        browser_and_ready.append(ready)

        self._recent_scan = None
        self._update_recent_scan_line()
        self.stack.add_named(page, "choose")

    def _quick_pick_toggled(self, button, key: str) -> None:
        if self._updating_quick_picks or not button.get_active():
            return
        self._set_chosen_folder(
            self.quick_pick_paths[key], browse=True, quick_pick=key
        )

    def _set_chosen_folder(
        self,
        path: Path,
        *,
        browse: bool,
        quick_pick: str | None = None,
    ) -> None:
        self.chosen_scan_path = Path(path)
        self._updating_quick_picks = True
        try:
            for key, button in self.quick_pick_buttons.items():
                button.set_active(
                    key == quick_pick
                    or (quick_pick is None and self.quick_pick_paths[key] == self.chosen_scan_path)
                )
        finally:
            self._updating_quick_picks = False
        self._refresh_ready_panel()
        if browse:
            self._set_browser_folder(self.chosen_scan_path)

    def _refresh_ready_panel(self) -> None:
        self.ready_path_label.set_text(str(self.chosen_scan_path))
        try:
            canonical = validate_scan_root(self.chosen_scan_path)
        except ScanRootError as error:
            self.ready_error_label.set_text(str(error))
            self.start_scan_button.set_sensitive(False)
        else:
            self.ready_error_label.set_text("")
            self.start_scan_button.set_sensitive(True)
            self.chosen_scan_path = canonical
        try:
            usage = os.statvfs(self.chosen_scan_path)
            total = usage.f_blocks * usage.f_frsize
            free = usage.f_bavail * usage.f_frsize
            self.ready_space_label.set_text(
                f"{format_bytes(free)} free of {format_bytes(total)} on this filesystem"
            )
        except OSError as error:
            self.ready_space_label.set_text(
                f"Filesystem space unavailable: {error.strerror or error}"
            )

    def _set_browser_folder(self, path: Path) -> None:
        try:
            canonical = canonical_directory(path)
        except ScanRootError as error:
            self.folder_status_label.set_text(str(error))
            return
        self.browser_path = canonical
        self.folder_back_button.set_sensitive(canonical.parent != canonical)
        self._render_folder_breadcrumb()
        self._load_folder_listing(canonical)

    def _render_folder_breadcrumb(self) -> None:
        child = self.folder_breadcrumb.get_first_child()
        while child is not None:
            self.folder_breadcrumb.remove(child)
            child = self.folder_breadcrumb.get_first_child()
        parts = self.browser_path.parts
        current = Path(parts[0])
        for index, part in enumerate(parts):
            if index:
                self.folder_breadcrumb.append(Gtk.Label(label="/", xalign=0.5))
                current = current / part
            label = part if index else parts[0]
            button = Gtk.Button(label=label)
            button.set_tooltip_text(str(current))
            button.connect("clicked", self._breadcrumb_clicked, current)
            self.folder_breadcrumb.append(button)

    def _breadcrumb_clicked(self, _button, path: Path) -> None:
        self._set_chosen_folder(path, browse=True)

    def _folder_back_clicked(self, _button) -> None:
        parent = self.browser_path.parent
        if parent != self.browser_path:
            self._set_chosen_folder(parent, browse=True)

    def _load_folder_listing(self, path: Path) -> None:
        self._folder_listing_generation += 1
        generation = self._folder_listing_generation
        self._folder_rows = ()
        self.folder_strings.splice(0, self.folder_strings.get_n_items(), [])
        self.folder_open_button.set_sensitive(False)
        self.folder_status_label.set_text("Loading folders…")
        threading.Thread(
            target=self._folder_listing_worker,
            args=(generation, path),
            name="clearspace-folder-list",
            daemon=True,
        ).start()

    def _folder_listing_worker(self, generation: int, path: Path) -> None:
        rows = []
        error_message = None
        try:
            with os.scandir(path) as iterator:
                for entry in iterator:
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError as error:
                        rows.append((
                            entry.name,
                            entry.path,
                            entry.name.startswith("."),
                            f"Cannot inspect: {error.strerror or error}",
                        ))
                        continue
                    if not stat.S_ISDIR(info.st_mode):
                        continue
                    child_path = Path(entry.path)
                    unreadable = None
                    try:
                        with os.scandir(child_path) as child_entries:
                            next(child_entries, None)
                    except OSError as error:
                        unreadable = f"Cannot read: {error.strerror or error}"
                    rows.append((entry.name, str(child_path), entry.name.startswith("."), unreadable))
        except OSError as error:
            error_message = f"Cannot list folders: {error.strerror or error}"
        rows.sort(key=lambda row: row[0].casefold())
        GLib.idle_add(
            self._show_folder_listing,
            generation,
            path,
            tuple(rows),
            error_message,
        )

    def _show_folder_listing(self, generation, path, rows, error_message):
        if generation != self._folder_listing_generation or path != self.browser_path:
            return GLib.SOURCE_REMOVE
        self._folder_rows = rows
        self.folder_strings.splice(
            0,
            self.folder_strings.get_n_items(),
            [name for name, _path, _hidden, _error in rows],
        )
        if error_message:
            self.folder_status_label.set_text(error_message)
        elif not rows:
            self.folder_status_label.set_text("No subfolders here.")
        else:
            self.folder_status_label.set_text(
                f"{len(rows):,} subfolders · hidden folders are tagged"
            )
        self.folder_selection.set_selected(Gtk.INVALID_LIST_POSITION)
        self.folder_open_button.set_sensitive(False)
        return GLib.SOURCE_REMOVE

    def _folder_row_setup(self, _factory, list_item):
        row = Gtk.Box(spacing=10)
        icon = Gtk.Image.new_from_icon_name("folder-symbolic")
        name = Gtk.Label(xalign=0, hexpand=True, ellipsize=2)
        hidden = Gtk.Label(label="hidden")
        hidden.add_css_class("folder-hidden")
        reason = Gtk.Label(xalign=0)
        reason.add_css_class("folder-error")
        open_hint = Gtk.Label(label="Open ›")
        open_hint.add_css_class("scan-muted")
        row.append(icon)
        row.append(name)
        row.append(hidden)
        row.append(reason)
        row.append(open_hint)
        list_item.set_child(row)
        row._clearspace_folder_widgets = (icon, name, hidden, reason, open_hint)

    def _folder_row_bind(self, _factory, list_item):
        position = list_item.get_position()
        if position < 0 or position >= len(self._folder_rows):
            return
        folder_name, folder_path, hidden_value, error = self._folder_rows[position]
        icon, name, hidden, reason, open_hint = list_item.get_child()._clearspace_folder_widgets
        name.set_text(folder_name)
        hidden.set_visible(hidden_value)
        reason.set_text(error or "")
        reason.set_visible(bool(error))
        open_hint.set_visible(not error)
        list_item.set_selectable(not error)
        list_item.set_activatable(not error)
        list_item.set_accessible_label(folder_name)
        list_item.set_accessible_description(error or str(folder_path))
        list_item.get_child().set_sensitive(not error)

    def _folder_selection_changed(self, selection, _property):
        position = selection.get_selected()
        if position == Gtk.INVALID_LIST_POSITION or position >= len(self._folder_rows):
            self.folder_open_button.set_sensitive(False)
            return
        name, path, _hidden, error = self._folder_rows[position]
        self.folder_open_button.set_sensitive(not error)
        if not error:
            self._set_chosen_folder(Path(path), browse=False)

    def _folder_row_activated(self, _list_view, position):
        self._open_folder_row(position)

    def _open_selected_subfolder(self, _button):
        self._open_folder_row(self.folder_selection.get_selected())

    def _open_folder_row(self, position: int) -> None:
        if position < 0 or position >= len(self._folder_rows):
            return
        _name, path, _hidden, error = self._folder_rows[position]
        if error:
            return
        self._set_chosen_folder(Path(path), browse=True)

    def _choose_another_folder(self, _button) -> None:
        dialog = Gtk.FileDialog.new()
        dialog.set_title("Choose a folder to scan")
        try:
            dialog.set_initial_folder(Gio.File.new_for_path(str(self.browser_path)))
        except GLib.Error:
            pass
        dialog.select_folder(self.window, None, self._folder_dialog_finished, None)

    def _folder_dialog_finished(self, dialog, result, _data) -> None:
        try:
            folder = dialog.select_folder_finish(result)
        except GLib.Error:
            return
        path = folder.get_path()
        if path:
            self._set_chosen_folder(Path(path), browse=True)

    def _start_selected_scan(self, _button) -> None:
        try:
            root = validate_scan_root(self.chosen_scan_path)
        except ScanRootError as error:
            self.ready_error_label.set_text(str(error))
            self.start_scan_button.set_sensitive(False)
            return
        options = ScanOptions(
            include_hidden=self.include_hidden_check.get_active(),
            stay_on_disk_only=self.stay_on_disk_check.get_active(),
        )
        self.scan(root, options)

    def _update_recent_scan_line(self) -> None:
        try:
            self._recent_scan = self.history.latest_scan()
        except OSError as error:
            self._recent_scan = None
            self.recent_scan_label.set_text(
                f"Recent scan history unavailable: {error.strerror or error}"
            )
            self.use_recent_button.set_sensitive(False)
            return
        record = self._recent_scan
        if record is None:
            self.recent_scan_label.set_text("Recent: no scans yet")
            self.use_recent_button.set_sensitive(False)
            return
        age = format_age(time.time() - float(record["timestamp"]))
        partial = " · partial" if record.get("partial") else ""
        self.recent_scan_label.set_text(
            f"Recent: {record['path']} · {age} · "
            f"{format_bytes(record['size_bytes'])}{partial}"
        )
        try:
            validate_scan_root(record["path"])
        except ScanRootError:
            self.use_recent_button.set_sensitive(False)
        else:
            self.use_recent_button.set_sensitive(True)

    def _use_recent_scan(self, _button) -> None:
        if self._recent_scan:
            self._set_chosen_folder(Path(self._recent_scan["path"]), browse=True)

    def show_folder_chooser(self, _button=None) -> None:
        self.stack.set_visible_child_name("choose")

    @staticmethod
    def _set_accessible_label(widget, label):
        try:
            widget.update_property([Gtk.AccessibleProperty.LABEL], [label])
        except (AttributeError, TypeError):
            widget.set_tooltip_text(label)

    def _build_details_panel(self) -> Gtk.Widget:
        panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        panel.set_margin_start(16)
        panel.set_margin_top(8)
        panel.set_size_request(340, -1)

        assistant_header = Gtk.Box(spacing=8)
        title = Gtk.Label(label="Assistant", xalign=0, hexpand=True)
        title.add_css_class("title-3")
        assistant_header.append(title)
        self.assistant_toggle = Gtk.ToggleButton(label="Collapse")
        self.assistant_toggle.set_active(False)
        self.assistant_toggle.connect("toggled", self._toggle_assistant_panel)
        assistant_header.append(self.assistant_toggle)
        panel.append(assistant_header)

        self.assistant_body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        panel.append(self.assistant_body)
        self.assistant_greeting = Gtk.Label(
            label="The scan summary will appear here when scanning finishes.",
            xalign=0,
            wrap=True,
        )
        self.assistant_body.append(self.assistant_greeting)
        messages_scroll = Gtk.ScrolledWindow(vexpand=True)
        messages_scroll.set_min_content_height(96)
        self.assistant_messages_scroll = messages_scroll
        self.assistant_message_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=6
        )
        messages_scroll.set_child(self.assistant_message_box)
        self.assistant_body.append(messages_scroll)

        self.assistant_chips = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=5
        )
        self.assistant_body.append(self.assistant_chips)
        for label, prompt in (
            ("Suggest a safe cleanup", "Suggest a safe cleanup"),
            ("What is using the most space?", "What is using the most space?"),
        ):
            self._add_assistant_chip(label, prompt)
        self.explain_risk_chip = Gtk.Button(label="Explain the risk of the selected item")
        self.explain_risk_chip.set_halign(Gtk.Align.START)
        self.explain_risk_chip.connect(
            "clicked", self._assistant_chip_clicked, "Explain the risk"
        )
        self.assistant_chips.append(self.explain_risk_chip)

        input_row = Gtk.Box(spacing=6)
        self.assistant_input = Gtk.Entry(hexpand=True)
        self.assistant_input.set_placeholder_text("Ask about this scan")
        self._set_accessible_label(self.assistant_input, "Ask about this scan")
        self.assistant_input.connect("activate", self._assistant_input_activated)
        input_row.append(self.assistant_input)
        self.assistant_send_button = Gtk.Button(label="Send")
        self.assistant_send_button.connect("clicked", self._assistant_send_clicked)
        input_row.append(self.assistant_send_button)
        self.assistant_body.append(input_row)
        assistant_note = Gtk.Label(
            label="Runs on your computer. It only suggests; you always confirm.",
            xalign=0,
            wrap=True,
        )
        assistant_note.add_css_class("selection-note")
        self.assistant_body.append(assistant_note)

        panel.append(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))
        details_title = Gtk.Label(label="Details", xalign=0)
        details_title.add_css_class("title-3")
        panel.append(details_title)
        self.detail_title = Gtk.Label(label="Selecione um item", xalign=0, wrap=True)
        self.detail_title.add_css_class("heading")
        panel.append(self.detail_title)
        self.detail_size = Gtk.Label(label="", xalign=0, wrap=True)
        panel.append(self.detail_size)
        self.detail_path = Gtk.Label(label="", xalign=0, wrap=True, selectable=True)
        self.detail_path.add_css_class("dim-label")
        panel.append(self.detail_path)
        self.detail_warning = Gtk.Label(label="", xalign=0, wrap=True, selectable=True)
        panel.append(self.detail_warning)
        self.detail_procedure = Gtk.Label(label="", xalign=0, wrap=True, selectable=True)
        self.detail_procedure.add_css_class("dim-label")
        panel.append(self.detail_procedure)
        self.copy_procedure_button = Gtk.Button(label="Copiar comando")
        self.copy_procedure_button.set_visible(False)
        self.copy_procedure_button.connect("clicked", self.copy_procedure)
        panel.append(self.copy_procedure_button)
        self.open_folder_button = Gtk.Button(label="Abrir pasta")
        self.open_folder_button.set_sensitive(False)
        self.open_folder_button.connect("clicked", self.open_selected_folder)
        panel.append(self.open_folder_button)
        self._detail_entry: TreeEntry | None = None
        self._detail_procedure_argv: tuple[str, ...] | None = None
        return panel

    def _add_assistant_chip(self, label: str, prompt: str) -> None:
        button = Gtk.Button(label=label)
        button.set_halign(Gtk.Align.START)
        button.connect("clicked", self._assistant_chip_clicked, prompt)
        self.assistant_chips.append(button)

    def _toggle_assistant_panel(self, button) -> None:
        collapsed = button.get_active()
        self.assistant_body.set_visible(not collapsed)
        button.set_label("Expand" if collapsed else "Collapse")

    def _assistant_panel_toggled(self, button) -> None:
        visible = button.get_active()
        self._set_assistant_panel_visible(visible)
        button.set_label("Hide assistant panel" if visible else "Show assistant panel")
        if not self._responsive_toggle:
            self._auto_collapsed_for_width = False

    def _set_assistant_panel_visible(self, visible: bool) -> None:
        if visible:
            if self.panes.get_end_child() is None:
                self.panes.set_end_child(self.details)
                self.panes.set_position(max(1, self.window.get_width() - 360))
        elif self.panes.get_end_child() is not None:
            self.panes.set_end_child(None)

    def _check_responsive_panel(self):
        width = self.window.get_width()
        if width <= 0:
            return GLib.SOURCE_CONTINUE
        narrow = width < 1000
        if self._window_is_narrow is None:
            self._window_is_narrow = narrow
            if narrow and self.assistant_panel_button.get_active():
                self._auto_collapsed_for_width = True
                self._responsive_toggle = True
                self.assistant_panel_button.set_active(False)
                self._responsive_toggle = False
        elif narrow != self._window_is_narrow:
            self._window_is_narrow = narrow
            if narrow and self.assistant_panel_button.get_active():
                self._auto_collapsed_for_width = True
                self._responsive_toggle = True
                self.assistant_panel_button.set_active(False)
                self._responsive_toggle = False
            elif not narrow and self._auto_collapsed_for_width:
                self._auto_collapsed_for_width = False
                self._responsive_toggle = True
                self.assistant_panel_button.set_active(True)
                self._responsive_toggle = False
        return GLib.SOURCE_CONTINUE

    def scan(self, root: Path | None = None, options: ScanOptions | None = None):
        try:
            scan_root = validate_scan_root(root or self.scan_root)
        except ScanRootError as error:
            self.stack.set_visible_child_name("choose")
            self.ready_error_label.set_text(str(error))
            return
        scan_options = options or self.scan_options
        self.scan_root = scan_root
        self.scan_options = scan_options
        self._scan_generation += 1
        self._scan_started_at = time.monotonic()
        self._scan_eta = EtaEstimator()
        self._scan_largest_items = ()
        self._scan_last_top_render = 0.0
        self.stack.set_visible_child_name("scanning")
        self.scan_subtitle.set_text(
            f"{scan_root} · Everything stays on your computer and nothing is deleted."
        )
        self.scan_counter_label.set_text("0 / estimating folders")
        self.scan_percent_label.set_text("")
        self.scan_progress_bar.set_fraction(0)
        self.scan_files_value.set_text("0")
        self.scan_bytes_value.set_text("0.0 GiB")
        self.scan_elapsed_value.set_text("0:00")
        self.scan_eta_value.set_text("Calculating…")
        self.scan_eta_value.set_visible(False)
        self.scan_path_label.set_text(f"Now scanning: {scan_root}")
        self._render_biggest_so_far()
        self.scan_pause_button.set_label("Pause")
        self.scan_pause_button.set_sensitive(True)
        self.scan_cancel_button.set_sensitive(True)
        self.scan_cancel_button.set_label("Cancel")
        self.selection = None
        self._workflow_busy = True
        self.scan_button.set_sensitive(False)
        self.review_button.set_sensitive(False)
        if hasattr(self, "tree_view"):
            self.tree_view.set_sensitive(False)
        self.disk_label.set_text(f"Scanning {scan_root}…")
        self.scan_report_button.set_sensitive(False)
        self.partial_banner.set_visible(False)
        self.scan_controller = ScanController()

        def scan_task(publish, cancel_event, pause_event):
            import shutil

            filesystem_error = None
            try:
                fs_used_bytes, fs_total_bytes, fs_used_inodes = filesystem_stats(scan_root)
            except OSError as error:
                fs_used_bytes = fs_total_bytes = fs_used_inodes = None
                filesystem_error = error.strerror or str(error)
            root_is_mountpoint = scan_root.is_mount()
            previous_scan = self.history.latest_scan_for(scan_root)
            prior_directories = (
                previous_scan.get("directories") if previous_scan is not None else None
            )
            publish(ProgressEvent(
                dirs_total_est=prior_directories,
                current_path=str(scan_root),
                fs_used_bytes=fs_used_bytes,
                fs_total_bytes=fs_total_bytes,
                fs_used_inodes=fs_used_inodes,
                filesystem_error=filesystem_error,
                root_is_mountpoint=root_is_mountpoint,
            ))

            if not RustTreeScanner.available():
                raise RustScannerError(
                    "The SQLite scanner is unavailable. Build it with cargo build --release --manifest-path scanner/Cargo.toml."
                )
            started = time.monotonic()

            def publish_live_progress(event: dict) -> None:
                progress = progress_event_from_rust(
                    event,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    prior_directories=prior_directories,
                )
                publish(replace(
                    progress,
                    fs_used_bytes=fs_used_bytes,
                    fs_total_bytes=fs_total_bytes,
                    fs_used_inodes=fs_used_inodes,
                    filesystem_error=filesystem_error,
                    root_is_mountpoint=root_is_mountpoint,
                ))

            scanner = RustTreeScanner(
                scan_root,
                max_visible_children=TREE_PAGE_SIZE,
                include_hidden=scan_options.include_hidden,
                stay_on_device=scan_options.stay_on_disk_only,
                progress=publish_live_progress,
            )
            root = scanner.scan_root(
                cancel_event=cancel_event,
                pause_event=pause_event,
            )
            evaluation = self.rule_engine.evaluate(root)
            inspection_roots = inspection_only_paths(scan_root)
            usage = shutil.disk_usage(scan_root)
            consumers = []
            for node in scanner.load_children_page(root, offset=0, limit=4, include_more=False):
                node_evaluation = self.rule_engine.evaluate(node)
                consumers.append(ScanConsumer(
                    node.path,
                    node.name,
                    node.size_bytes,
                    node_evaluation.risk,
                    " ".join(node_evaluation.warnings),
                ))
                if len(consumers) == 4:
                    break
            assistant_context = AssistantScanContext(
                dirs_scanned=int(scanner.report.get("directories", 0)),
                duration_ms=int(float(scanner.report.get("elapsed_seconds", 0)) * 1000),
                free_bytes=usage.free,
                total_bytes=usage.total,
                biggest_consumers=tuple(consumers),
            )
            return scanner, root, evaluation, usage, inspection_roots, assistant_context

        self.scan_controller.start(scan_task)
        if self._scan_poll_source:
            GLib.source_remove(self._scan_poll_source)
        self._scan_poll_source = GLib.timeout_add(150, self._poll_scan)

    def _poll_scan(self):
        controller = self.scan_controller
        event = controller.latest_snapshot()
        self._update_scanning_view(event)
        if event.state not in {ScanState.DONE, ScanState.CANCELLED, ScanState.ERROR}:
            return GLib.SOURCE_CONTINUE
        self._scan_poll_source = None
        if event.state is ScanState.CANCELLED:
            self.scan_button.set_sensitive(True)
            self._workflow_busy = False
            self.stack.set_visible_child_name("choose")
            return GLib.SOURCE_REMOVE
        if controller.error:
            self._finish_scan_error(controller.error)
            return GLib.SOURCE_REMOVE
        result = controller.result
        if not result:
            self._finish_scan_error(RuntimeError("scanner returned no result"))
            return GLib.SOURCE_REMOVE
        scanner, root, evaluation, usage, inspection_roots, assistant_context = result
        self.assistant_context = assistant_context
        report = dict(scanner.report)
        report["partial"] = bool(
            event.partial
            or event.state is ScanState.CANCELLED
            or report.get("errors", 0)
        )
        self._show_scan(
            self._scan_generation,
            scanner,
            root,
            evaluation,
            usage,
            inspection_roots,
            report,
            None,
        )
        try:
            self.history.record_scan(
                self.scan_root,
                root.size_bytes,
                partial=report["partial"],
                directories=int(report.get("directories", 0)),
            )
            self._update_recent_scan_line()
        except OSError as error:
            self.recent_scan_label.set_text(
                f"Could not save scan history: {error.strerror or error}"
            )
        if report["partial"]:
            self.partial_banner.set_visible(True)
        self._update_assistant_greeting(assistant_context)
        return GLib.SOURCE_REMOVE

    def _update_assistant_greeting(self, context: AssistantScanContext) -> None:
        greeting = self.local_assistant.greeting(context)
        self.assistant_greeting.set_text(greeting)

    def _assistant_input_activated(self, entry) -> None:
        self._submit_assistant_message(entry.get_text())

    def _assistant_send_clicked(self, _button) -> None:
        self._submit_assistant_message(self.assistant_input.get_text())

    def _assistant_chip_clicked(self, _button, prompt: str) -> None:
        self._submit_assistant_message(prompt)

    def _assistant_context_for_selection(self) -> AssistantScanContext:
        entry = self._detail_entry
        selected_consumer = None
        if entry and not entry.loading and not entry.node.aggregate_count:
            evaluation = entry.evaluation or self.rule_engine.evaluate(entry.node)
            entry.evaluation = evaluation
            selected_consumer = ScanConsumer(
                entry.node.path,
                entry.node.name,
                entry.node.size_bytes,
                evaluation.risk,
                " ".join(evaluation.warnings),
            )
        return AssistantScanContext(
            dirs_scanned=self.assistant_context.dirs_scanned,
            duration_ms=self.assistant_context.duration_ms,
            free_bytes=self.assistant_context.free_bytes,
            total_bytes=self.assistant_context.total_bytes,
            biggest_consumers=self.assistant_context.biggest_consumers,
            selected_consumer=selected_consumer,
        )

    def _submit_assistant_message(self, message: str) -> None:
        prompt = message.strip()
        if not prompt:
            return
        self.assistant_input.set_text("")
        self._append_assistant_message("You", prompt)
        reply = self.local_assistant.respond(
            prompt, self._assistant_context_for_selection()
        )
        self._append_assistant_message("Assistant", reply.text)
        self._handle_assistant_proposals(reply.proposed_actions)

    def _append_assistant_message(self, speaker: str, message: str) -> None:
        self.assistant_messages.append((speaker, message))
        label = Gtk.Label(label=f"{speaker}: {message}", xalign=0, wrap=True)
        label.set_selectable(True)
        label.add_css_class("scan-chip")
        self.assistant_message_box.append(label)
        if len(self.assistant_messages) > 80:
            self.assistant_messages.pop(0)
            oldest = self.assistant_message_box.get_first_child()
            if oldest is not None:
                self.assistant_message_box.remove(oldest)
        GLib.idle_add(self._scroll_assistant_messages)

    def _scroll_assistant_messages(self):
        adjustment = self.assistant_messages_scroll.get_vadjustment()
        adjustment.set_value(max(
            adjustment.get_lower(),
            adjustment.get_upper() - adjustment.get_page_size(),
        ))
        return GLib.SOURCE_REMOVE

    def _handle_assistant_proposals(self, proposals) -> None:
        for proposal in proposals:
            if proposal.kind is ProposedActionKind.HIGHLIGHT_NODE:
                self._highlight_assistant_node(proposal.target)
            elif (
                proposal.kind is ProposedActionKind.OPEN_REVIEW
                and self.selection
                and self.selection.selected_paths
            ):
                self.review_selection(None)

    def _highlight_assistant_node(self, target: str) -> None:
        try:
            path = Path(target)
        except (TypeError, ValueError):
            return
        entry = self.entries.get(path)
        if entry is None or not hasattr(self, "tree_model"):
            return
        for position in range(self.tree_model.get_n_items()):
            row = self.tree_model.get_row(position)
            if row and row.get_item() is entry:
                self.tree_selection.set_selected(position)
                return

    def _update_scanning_view(self, event: ProgressEvent):
        total = event.dirs_total_est
        if total:
            self.scan_counter_label.set_text(
                f"{event.dirs_done:,} / ~{total:,} folders"
            )
        else:
            self.scan_counter_label.set_text(f"{event.dirs_done:,} / estimating folders")
        percent = progress_percent(
            event,
            root_is_mountpoint=event.root_is_mountpoint,
        )
        if percent is None:
            self.scan_percent_label.set_text("")
            self.scan_progress_bar.pulse()
        else:
            self.scan_percent_label.set_text(f"{percent}%")
            self.scan_progress_bar.set_fraction(percent / 100)
        self.scan_files_value.set_text(f"{event.files:,}")
        self.scan_bytes_value.set_text(format_size_gib(event.bytes))
        elapsed_ms = max(
            event.elapsed_ms,
            int((time.monotonic() - self._scan_started_at) * 1000),
        )
        self.scan_elapsed_value.set_text(format_elapsed(elapsed_ms))
        self.scan_eta_value.set_visible(
            bool((percent is not None and percent >= 5) or elapsed_ms >= 5_000)
        )
        eta = self._scan_eta.remaining_seconds(event)
        if eta is None:
            self.scan_eta_value.set_text("Calculating…")
        else:
            self.scan_eta_value.set_text(f"~{format_elapsed(eta * 1000)}")
        path = event.current_path or str(self.scan_root)
        self.scan_path_label.set_text(f"Now scanning: {path}")
        if event.filesystem_error:
            self.scan_subtitle.set_text(
                f"Filesystem capacity unavailable: {event.filesystem_error}"
            )
        elif event.fs_used_bytes is not None and event.fs_total_bytes is not None:
            self.scan_subtitle.set_text(
                f"Filesystem use: {format_bytes(event.fs_used_bytes)} of "
                f"{format_bytes(event.fs_total_bytes)} · inode use: {event.fs_used_inodes}"
            )
        self._scan_largest_items = tuple(getattr(event, "largest_items", ()))[:4]
        now = time.monotonic()
        if self._scan_largest_items and now - self._scan_last_top_render >= 1.0:
            self._render_biggest_so_far()
            self._scan_last_top_render = now
        if event.state is ScanState.PAUSED:
            self.scan_pause_button.set_label("Resume")
        elif event.state is ScanState.RUNNING:
            self.scan_pause_button.set_label("Pause")

    def _render_biggest_so_far(self):
        largest = self._scan_largest_items
        maximum = max((size for _name, _path, size in largest), default=0)
        for row_index, row_widgets in enumerate(self._scan_biggest_rows):
            name_label, bar, size_label = row_widgets
            if row_index >= len(largest):
                for widget in row_widgets:
                    widget.set_visible(False)
                continue
            name, path, size = largest[row_index]
            name_label.set_text(name)
            name_label.set_tooltip_text(path)
            bar.set_fraction(relative_size_fraction(size, maximum))
            self._set_accessible_label(bar, f"{name} size")
            size_label.set_text(format_bytes(size))
            for widget in row_widgets:
                widget.set_visible(True)

    def _toggle_scan_pause(self, _button):
        event = self.scan_controller.latest_snapshot()
        if event.state is ScanState.PAUSED:
            self.scan_controller.resume()
        else:
            self.scan_controller.pause()
        self._update_scanning_view(self.scan_controller.latest_snapshot())

    def _cancel_scan(self, _button):
        self.scan_cancel_button.set_sensitive(False)
        self.scan_cancel_button.set_label("Cancelling…")
        self.scan_pause_button.set_sensitive(False)
        self.scan_controller.cancel()

    def _finish_scan_error(self, error):
        self.disk_label.set_text(f"Could not read the tree: {error}")
        self.scan_button.set_sensitive(True)
        self._workflow_busy = False
        self.stack.set_visible_child_name("results")

    def _show_scan(self, generation, scanner, root, evaluation, usage,
                   inspection_roots, report, error):
        if generation != self._scan_generation:
            return GLib.SOURCE_REMOVE
        if error or root is None or scanner is None:
            self.disk_label.set_text(f"Não foi possível ler a árvore: {error}")
            self.scan_button.set_sensitive(True)
            self._workflow_busy = False
            return GLib.SOURCE_REMOVE
        old_scanner = self.scanner
        if old_scanner is not None and old_scanner is not scanner:
            old_scanner.close()
        self.scanner = scanner
        self.scan_report = report
        self.scan_report_button.set_sensitive(True)
        self.root_node = root
        ui_build_started = time.monotonic()
        self.inspection_only_roots = inspection_roots
        self.selection = SelectionModel([root])
        self._selected_evaluations.clear()
        self.entries.clear()
        self.check_buttons.clear()
        self._child_store_cache.clear()
        self._expanded_cache.clear()
        self._live_entry_count = 0
        self._reserved_node_count = 0
        self.root_entry = self._new_entry(root, evaluation)
        root_store = Gio.ListStore.new(TreeEntry)
        root_store.append(self.root_entry)
        tree_model = Gtk.TreeListModel.new(root_store, False, False,
                                           self._create_children_model, None)
        self.tree_model = tree_model
        self.tree_selection = Gtk.SingleSelection.new(tree_model)
        self.tree_selection.set_autoselect(False)
        self.tree_selection.set_can_unselect(True)
        self.tree_selection.connect("notify::selected-item", self._selected_item_changed)
        self.tree_view = Gtk.ColumnView.new(self.tree_selection)
        self.tree_view.connect("map", self._tree_mapped)
        self.tree_view.set_show_row_separators(True)
        self.tree_view.set_show_column_separators(False)
        self.tree_view.set_tab_behavior(Gtk.ListTabBehavior.CELL)
        self._set_accessible_label(self.tree_view, "Disk usage file tree")
        key_controller = Gtk.EventControllerKey()
        key_controller.connect("key-pressed", self._tree_key_pressed)
        self.tree_view.add_controller(key_controller)
        self.tree_view.append_column(self._checkbox_column())
        name_column = self._name_column()
        name_column.set_expand(True)
        self.tree_view.append_column(name_column)
        self.tree_view.append_column(self._usage_column())
        self.tree_view.append_column(self._size_column())
        self.tree_view.append_column(self._risk_column())
        parent = self.tree_placeholder.get_parent()
        if parent:
            parent.set_child(self.tree_view)
        root_row = tree_model.get_row(0)
        if root_row:
            root_row.set_expanded(True)
        report["gtk_model_build_seconds"] = round(time.monotonic() - ui_build_started, 3)
        report["python_peak_rss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if usage:
            elapsed_ms = int(float(report.get("elapsed_seconds", 0)) * 1000)
            self.disk_label.set_text(
                f"{format_size_gib(usage.free)} free of {format_size_gib(usage.total)} · "
                f"scanned {report.get('directories', 0):,} folders in "
                f"{format_elapsed(elapsed_ms)}"
            )
        self.scan_button.set_sensitive(True)
        self._workflow_busy = False
        self._refresh_selection_summary()
        self.stack.set_visible_child_name("results")
        return GLib.SOURCE_REMOVE

    def _tree_mapped(self, _tree_view):
        if hasattr(self, "scan_report") and self._scan_started_at:
            self.scan_report["time_to_tree_mapped_seconds"] = round(
                time.monotonic() - self._scan_started_at, 3
            )
            self.scan_report["python_peak_rss_kib"] = resource.getrusage(
                resource.RUSAGE_SELF
            ).ru_maxrss

    def show_scan_report(self, _button):
        if not hasattr(self, "scan_report"):
            return
        report = self.scan_report
        detail = (
            f"Tempo total: {report.get('elapsed_seconds', 0):.3f} s\n"
            f"Construção do modelo GTK: {report.get('gtk_model_build_seconds', 0):.3f} s\n"
            f"Tempo até a árvore ser mapeada: "
            f"{report.get('time_to_tree_mapped_seconds', 'aguardando UI')} s\n"
            f"Tempo até os itens da raiz aparecerem: "
            f"{report.get('time_to_root_children_seconds', 'aguardando UI')} s\n"
            f"Pico de memória Python: "
            f"{report.get('python_peak_rss_kib', 0) / 1024:.1f} MiB\n"
            f"Diretórios lidos: {report.get('directories', 0)}\n"
            f"Arquivos lidos: {report.get('files', 0)}\n"
            f"Erros de leitura: {report.get('errors', 0)}\n"
            f"Symlinks ignorados: {report.get('symlinks_skipped', 0)}\n"
            f"Outros filesystems ignorados: {report.get('other_filesystems_skipped', 0)}\n"
            f"Itens ocultos ignorados: {report.get('hidden_skipped', 0)}\n"
            f"Uso alocado encontrado: {format_bytes(report.get('allocated_bytes', 0))}\n\n"
            "Relatório agregado, sem nomes de arquivos ou conteúdo pessoal."
        )
        self._show_message("Relatório da varredura", detail)

    def _new_entry(
        self,
        node: Node,
        evaluation: RuleEvaluation | None,
        *,
        loading: bool = False,
        parent_entry: TreeEntry | None = None,
    ) -> TreeEntry:
        if any(
            node.path == protected
            or node.path.is_relative_to(protected)
            or protected.is_relative_to(node.path)
            for protected in self.inspection_only_roots
        ):
            node.selectable = False
        entry = TreeEntry(node, evaluation, loading=loading, parent_entry=parent_entry)
        entry.scanner = self.scanner
        self._live_entry_count += 1
        if node.selectable and not node.aggregate_count and not node.is_more_row:
            self.entries[node.path] = entry
        return entry

    def _size_sorter(self):
        return None

    @staticmethod
    def _compare_entries(left: TreeEntry, right: TreeEntry, _data=None):
        if left.node.size_bytes > right.node.size_bytes:
            return Gtk.Ordering.SMALLER
        if left.node.size_bytes < right.node.size_bytes:
            return Gtk.Ordering.LARGER
        if left.node.name.casefold() < right.node.name.casefold():
            return Gtk.Ordering.SMALLER
        if left.node.name.casefold() > right.node.name.casefold():
            return Gtk.Ordering.LARGER
        return Gtk.Ordering.EQUAL

    def _create_children_model(self, entry: TreeEntry, _data=None):
        """Return a cached empty model only; GTK may call this as an expandability probe."""
        node = entry.node
        if (
            entry.loading
            or not node.is_dir
            or node.error
            or node.child_count <= 0
            or node.node_id is None
        ):
            return None
        if entry.children_store is None:
            entry.children_store = self._child_store_cache.get(node.node_id)
            if entry.children_store is None:
                entry.children_store = Gio.ListStore.new(TreeEntry)
                self._child_store_cache[node.node_id] = entry.children_store
        entry.children_model = entry.children_store
        return entry.children_model

    def _row_expanded_changed(self, row, _property, entry: TreeEntry):
        node_id = entry.node.node_id
        if row.get_expanded():
            entry.is_expanded = True
            if node_id is not None:
                self._expanded_cache[node_id] = entry
                self._expanded_cache.move_to_end(node_id)
            self._start_page_load(entry, entry.node.loaded_child_count)
            self._trim_expanded_cache()
            return
        entry.load_generation += 1
        entry.is_expanded = False
        entry.loading_children = False
        self._remove_loading_rows(entry)
        if node_id is not None:
            self._expanded_cache.pop(node_id, None)
        GLib.timeout_add(
            TREE_EVICT_DELAY_MS,
            self._evict_after_collapse,
            entry,
            entry.load_generation,
        )

    def _entry_is_expanded(self, entry: TreeEntry) -> bool:
        return entry.is_expanded or any(
            row.get_expanded() for row in tuple(entry.bound_rows)
        )

    def _trim_expanded_cache(self) -> None:
        for node_id, entry in tuple(self._expanded_cache.items()):
            if len(self._expanded_cache) <= TREE_EXPANDED_CACHE:
                break
            if self._entry_is_expanded(entry):
                continue
            self._expanded_cache.pop(node_id, None)
            self._evict_entry_children(entry)

    def _make_room_for_page(self, needed: int, keep: TreeEntry) -> bool:
        while self._live_entry_count + self._reserved_node_count + needed > TREE_NODE_CAP:
            victim = next(
                (
                    (node_id, entry)
                    for node_id, entry in self._expanded_cache.items()
                    if entry is not keep and not self._entry_is_expanded(entry)
                ),
                None,
            )
            if victim is None:
                return False
            node_id, entry = victim
            self._expanded_cache.pop(node_id, None)
            self._evict_entry_children(entry)
        return True

    def _start_page_load(self, entry: TreeEntry, offset: int) -> None:
        if entry.loading_children or not entry.node.is_dir or entry.children_store is None:
            return
        self._remove_loading_rows(entry)
        self._remove_page_tail(entry)
        if offset >= entry.node.child_count:
            return
        requested = min(TREE_PAGE_SIZE, entry.node.child_count - offset)
        if not self._make_room_for_page(requested + 3, entry):
            requested = max(
                0,
                min(
                    requested,
                    TREE_NODE_CAP
                    - self._live_entry_count
                    - self._reserved_node_count
                    - 3,
                ),
            )
        if requested <= 0:
            self.disk_label.set_text(
                f"Node limit ({TREE_NODE_CAP:,}) reached; collapse a folder to continue"
            )
            return

        entry.load_generation += 1
        generation = entry.load_generation
        entry.loading_children = True
        self._reserved_node_count += requested + 2
        loading_node = Node(
            entry.node.path / ".clearspace-loading-row",
            "Loading…",
            False,
            0,
            selectable=False,
        )
        loading_entry = self._new_entry(loading_node, None, loading=True, parent_entry=entry)
        store = entry.children_store
        start = store.get_n_items()
        remove = 0
        if start and store.get_item(start - 1).node.path == loading_node.path:
            remove = 1
            start -= 1
        store.splice(start, remove, [loading_entry])
        scanner = entry.scanner
        if scanner is None:
            self._complete_page_load(entry, generation, offset, requested + 2, (), "Scanner is unavailable")
            return
        threading.Thread(
            target=self._load_children_worker,
            args=(entry, generation, offset, requested, requested + 2),
            name="clearspace-tree-page",
            daemon=True,
        ).start()

    def _remove_page_tail(self, entry: TreeEntry) -> None:
        store = entry.children_store
        if store is None:
            return
        remove = 0
        count = store.get_n_items()
        while count - remove > 0:
            item = store.get_item(count - remove - 1)
            if not (item.node.aggregate_count or item.node.is_more_row):
                break
            self._drop_entry(item, drop_store=False)
            remove += 1
        if remove:
            store.splice(count - remove, remove, [])

    def _remove_loading_rows(self, entry: TreeEntry) -> None:
        store = entry.children_store
        if store is None:
            return
        remove_at = []
        for index in range(store.get_n_items()):
            item = store.get_item(index)
            if item.loading:
                remove_at.append(index)
                self._drop_entry(item, drop_store=False)
        for index in reversed(remove_at):
            store.remove(index)

    def _load_children_worker(
        self,
        entry: TreeEntry,
        generation: int,
        offset: int,
        limit: int,
        reservation: int,
    ):
        try:
            children = entry.scanner.load_children_page(
                entry.node,
                offset=offset,
                limit=limit,
                include_more=True,
            )
            evaluated = tuple(
                (
                    node,
                    None if node.aggregate_count or node.is_more_row
                    else self.rule_engine.evaluate(node),
                )
                for node in children
            )
            error = None
        except Exception as exc:
            evaluated = ()
            error = str(exc)
        GLib.idle_add(
            self._complete_page_load,
            entry,
            generation,
            offset,
            reservation,
            evaluated,
            error,
        )

    def _complete_page_load(
        self,
        entry: TreeEntry,
        generation: int,
        offset: int,
        reservation: int,
        evaluated,
        error,
    ):
        if generation != entry.load_generation:
            self._reserved_node_count = max(0, self._reserved_node_count - reservation)
            return GLib.SOURCE_REMOVE
        if not self._entry_is_expanded(entry):
            self._reserved_node_count = max(0, self._reserved_node_count - reservation)
            entry.loading_children = False
            self._remove_loading_rows(entry)
            return GLib.SOURCE_REMOVE
        store = entry.children_store
        if store is None:
            self._reserved_node_count = max(0, self._reserved_node_count - reservation)
            entry.loading_children = False
            return GLib.SOURCE_REMOVE
        entries = []
        if error:
            entry.node.error = f"não foi possível ler: {error}"
            entry.node.size_is_partial = entry.node.size_bytes > 0
            error_node = Node(entry.node.path / ".clearspace-read-error", entry.node.error,
                              False, 0, error=entry.node.error, selectable=False)
            entries.append(self._new_entry(error_node, None, parent_entry=entry))
        else:
            for node, evaluation in evaluated:
                entries.append(self._new_entry(node, evaluation, parent_entry=entry))
        loading_index = next(
            (
                index for index in range(store.get_n_items() - 1, -1, -1)
                if store.get_item(index).loading
            ),
            store.get_n_items(),
        )
        loading_count = store.get_n_items() - loading_index
        for index in range(loading_index, store.get_n_items()):
            self._drop_entry(store.get_item(index), drop_store=False)
        store.splice(loading_index, loading_count, entries)
        self._reserved_node_count = max(0, self._reserved_node_count - reservation)
        new_real_nodes = [
            node for node, _evaluation in evaluated
            if not node.aggregate_count and not node.is_more_row
        ]
        if offset == 0:
            entry.node.children = new_real_nodes
        else:
            entry.node.children.extend(new_real_nodes)
        entry.node.loaded_child_count = min(
            entry.node.child_count, offset + len(new_real_nodes)
        )
        entry.node.loaded_child_size_bytes += sum(node.size_bytes for node in new_real_nodes)
        entry.node.children_loaded = True
        entry.loading_children = False
        if self._detail_entry is entry:
            self._show_details(entry)
        self._refresh_selection_summary()
        return GLib.SOURCE_REMOVE

    def _evict_after_collapse(self, entry: TreeEntry, generation: int):
        if generation == entry.load_generation and not self._entry_is_expanded(entry):
            self._evict_entry_children(entry)
        return GLib.SOURCE_REMOVE

    def _evict_entry_children(self, entry: TreeEntry) -> None:
        if self._entry_is_expanded(entry):
            return
        store = entry.children_store
        if store is not None:
            for index in range(store.get_n_items() - 1, -1, -1):
                self._drop_entry(store.get_item(index), drop_store=True)
            store.remove_all()
        entry.node.children.clear()
        entry.node.loaded_child_count = 0
        entry.node.loaded_child_size_bytes = 0
        entry.node.children_loaded = False
        entry.children_store = None
        entry.children_model = None
        entry.loading_children = False
        entry.load_generation += 1
        node_id = entry.node.node_id
        if node_id is not None:
            self._child_store_cache.pop(node_id, None)
            self._expanded_cache.pop(node_id, None)

    def _drop_entry(self, entry: TreeEntry, *, drop_store: bool) -> None:
        if drop_store and entry.children_store is not None:
            for index in range(entry.children_store.get_n_items() - 1, -1, -1):
                self._drop_entry(entry.children_store.get_item(index), drop_store=True)
            entry.children_store.remove_all()
        node_id = entry.node.node_id
        if node_id is not None:
            self._child_store_cache.pop(node_id, None)
            self._expanded_cache.pop(node_id, None)
        if self.entries.get(entry.node.path) is entry:
            self.entries.pop(entry.node.path, None)
        self.check_buttons.pop(entry.node.path, None)
        self._live_entry_count = max(0, self._live_entry_count - 1)

    def _checkbox_column(self):
        factory = Gtk.SignalListItemFactory.new()
        factory.connect("setup", self._checkbox_setup)
        factory.connect("bind", self._checkbox_bind)
        factory.connect("unbind", self._checkbox_unbind)
        column = Gtk.ColumnViewColumn.new("Selecionar", factory)
        column.set_fixed_width(112)
        return column

    def _checkbox_setup(self, _factory, list_item):
        checkbox = Gtk.CheckButton()
        checkbox.connect("toggled", self._checkbox_toggled)
        list_item.set_child(checkbox)

    def _checkbox_bind(self, _factory, list_item):
        checkbox = list_item.get_child()
        tree_row = list_item.get_item()
        entry = tree_row.get_item()
        checkbox._clearspace_entry = entry
        self._set_accessible_label(checkbox, f"Select {entry.node.name}")
        checkbox.set_sensitive(entry.node.selectable and not entry.loading)
        if entry.node.selectable:
            self.check_buttons.setdefault(entry.node.path, []).append(checkbox)
        self._set_checkbox_state(checkbox, entry)

    def _checkbox_unbind(self, _factory, list_item):
        checkbox = list_item.get_child()
        entry = getattr(checkbox, "_clearspace_entry", None)
        if entry and entry.node.path in self.check_buttons:
            buttons = self.check_buttons[entry.node.path]
            if checkbox in buttons:
                buttons.remove(checkbox)

    def _set_checkbox_state(self, checkbox, entry):
        if not self.selection or not entry.node.selectable:
            checkbox.set_active(False)
            checkbox.set_inconsistent(False)
            return
        state = self.selection.state(entry.node)
        self._syncing_checks = True
        checkbox.set_active(state is SelectionState.CHECKED)
        checkbox.set_inconsistent(state is SelectionState.PARTIAL)
        self._syncing_checks = False

    def _checkbox_toggled(self, checkbox):
        if self._syncing_checks or not self.selection:
            return
        entry = getattr(checkbox, "_clearspace_entry", None)
        if not entry or not entry.node.selectable:
            return
        self.selection.set_checked(entry.node, checkbox.get_active())
        self._refresh_all_checkboxes()
        self._refresh_selection_summary()

    def _refresh_all_checkboxes(self):
        for buttons in self.check_buttons.values():
            for checkbox in tuple(buttons):
                entry = getattr(checkbox, "_clearspace_entry", None)
                if entry:
                    self._set_checkbox_state(checkbox, entry)

    def _name_column(self):
        factory = Gtk.SignalListItemFactory.new()
        factory.connect("setup", self._name_setup)
        factory.connect("bind", self._name_bind)
        factory.connect("unbind", self._name_unbind)
        column = Gtk.ColumnViewColumn.new("Arquivo ou pasta", factory)
        return column

    def _name_setup(self, _factory, list_item):
        expander = Gtk.TreeExpander()
        box = Gtk.Box(spacing=8)
        icon = Gtk.Image()
        label = Gtk.Label(xalign=0, hexpand=True, ellipsize=3)
        more_button = Gtk.Button(label="Show more")
        more_button.set_visible(False)
        more_button.add_css_class("flat")
        more_button.connect("clicked", self._show_more_clicked)
        box.append(icon)
        box.append(label)
        box.append(more_button)
        expander.set_child(box)
        list_item.set_child(expander)

    def _name_bind(self, _factory, list_item):
        expander = list_item.get_child()
        tree_row = list_item.get_item()
        entry = tree_row.get_item()
        expander.set_list_row(tree_row)
        old_signal = getattr(list_item, "_clearspace_expanded_signal", None)
        if old_signal:
            old_row, handler_id = old_signal
            if old_row.handler_is_connected(handler_id):
                old_row.disconnect(handler_id)
            old_entry = old_row.get_item()
            if old_entry is not None:
                old_entry.bound_rows.discard(old_row)
        handler_id = tree_row.connect(
            "notify::expanded", self._row_expanded_changed, entry
        )
        list_item._clearspace_expanded_signal = (tree_row, handler_id)
        entry.bound_rows.add(tree_row)
        box = expander.get_child()
        icon = box.get_first_child()
        label = icon.get_next_sibling()
        more_button = label.get_next_sibling()
        if entry.loading:
            icon.set_from_icon_name("content-loading-symbolic")
            label.set_text("Lendo…")
            more_button.set_visible(False)
        elif entry.node.is_more_row:
            icon.set_from_icon_name("view-more-symbolic")
            label.set_text(entry.node.name)
            more_button.set_visible(True)
            more_button.set_sensitive(True)
            more_button._clearspace_entry = entry
        else:
            icon.set_from_icon_name("folder-symbolic" if entry.node.is_dir else "text-x-generic-symbolic")
            label.set_text(entry.node.name)
            label.set_tooltip_text(entry.node.error)
            more_button.set_visible(False)
            if entry.node.error:
                label.add_css_class("error")
            else:
                label.remove_css_class("error")
        if tree_row.get_expanded():
            self._row_expanded_changed(tree_row, None, entry)

    def _name_unbind(self, _factory, list_item):
        signal = getattr(list_item, "_clearspace_expanded_signal", None)
        if signal:
            row, handler_id = signal
            entry = row.get_item()
            if entry is not None:
                entry.bound_rows.discard(row)
            if row.handler_is_connected(handler_id):
                row.disconnect(handler_id)
            list_item._clearspace_expanded_signal = None

    def _show_more_clicked(self, button):
        entry = getattr(button, "_clearspace_entry", None)
        if entry is not None and entry.parent_entry is not None:
            self._start_page_load(entry.parent_entry, entry.node.more_offset)

    def _usage_column(self):
        factory = Gtk.SignalListItemFactory.new()
        factory.connect("setup", self._usage_setup)
        factory.connect("bind", self._usage_bind)
        column = Gtk.ColumnViewColumn.new("Relative usage", factory)
        column.set_fixed_width(145)
        return column

    def _usage_setup(self, _factory, list_item):
        progress = Gtk.ProgressBar(hexpand=True)
        progress.set_size_request(95, 8)
        list_item.set_child(progress)

    def _usage_bind(self, _factory, list_item):
        entry = list_item.get_item().get_item()
        progress = list_item.get_child()
        if entry.parent_entry:
            siblings = entry.parent_entry.node.children
        else:
            siblings = (self.root_node,) if self.root_node else ()
        max_size = max((node.size_bytes for node in siblings), default=1)
        max_size = max(1, max_size)
        fraction = relative_size_fraction(entry.node.size_bytes, max_size)
        progress.set_fraction(fraction)
        self._set_accessible_label(
            progress,
            f"{entry.node.name}: {fraction:.0%} of largest sibling",
        )

    def _size_column(self):
        factory = Gtk.SignalListItemFactory.new()
        factory.connect("setup", self._size_setup)
        factory.connect("bind", self._size_bind)
        column = Gtk.ColumnViewColumn.new("Size", factory)
        column.set_fixed_width(110)
        return column

    def _size_setup(self, _factory, list_item):
        detail = Gtk.Label(xalign=1)
        detail.set_width_chars(12)
        detail.set_xalign(1.0)
        detail.add_css_class("size-value")
        list_item.set_child(detail)

    def _size_bind(self, _factory, list_item):
        entry = list_item.get_item().get_item()
        detail = list_item.get_child()
        text = self._size_in_mib_or_gib(entry.node.size_bytes)
        if entry.node.size_is_partial:
            text += " · parcial"
        detail.set_text(text)

    @staticmethod
    def _size_in_mib_or_gib(size_bytes: int) -> str:
        mib = size_bytes / (1024 ** 2)
        if mib >= 1024:
            return f"{mib / 1024:.2f} GiB"
        return f"{mib:.1f} MiB"

    def _risk_column(self):
        factory = Gtk.SignalListItemFactory.new()
        factory.connect("setup", self._risk_setup)
        factory.connect("bind", self._risk_bind)
        column = Gtk.ColumnViewColumn.new("Risco", factory)
        column.set_fixed_width(150)
        return column

    def _risk_setup(self, _factory, list_item):
        label = Gtk.Label(xalign=0)
        label.add_css_class("badge")
        list_item.set_child(label)

    def _risk_bind(self, _factory, list_item):
        entry = list_item.get_item().get_item()
        label = list_item.get_child()
        for css in ("risk-low", "risk-moderate", "risk-user-data", "risk-critical"):
            label.remove_css_class(css)
        if entry.node.aggregate_count or entry.node.is_more_row or entry.loading:
            label.set_text("—")
            return
        risk = entry.evaluation.risk if entry.evaluation else Risk.MODERATE
        label.set_text({
            Risk.LOW: "Low",
            Risk.MODERATE: "Moderate",
            Risk.USER_DATA: "Your data",
            Risk.CRITICAL: "Critical",
        }[risk])
        css_class = {
            Risk.LOW: "risk-low",
            Risk.MODERATE: "risk-moderate",
            Risk.USER_DATA: "risk-user-data",
            Risk.CRITICAL: "risk-critical",
        }[risk]
        label.add_css_class(css_class)

    def _selected_item_changed(self, selection, _property):
        tree_row = selection.get_selected_item()
        self._show_details(tree_row.get_item() if tree_row else None)

    def _tree_key_pressed(self, _controller, keyval, _keycode, _state):
        tree_row = self.tree_selection.get_selected_item()
        if tree_row is None:
            return False
        entry = tree_row.get_item()
        if keyval == Gdk.KEY_space:
            if not entry.node.selectable:
                return True
            current = self.selection.state(entry.node)
            self.selection.set_checked(
                entry.node, current is not SelectionState.CHECKED
            )
            self._refresh_all_checkboxes()
            self._refresh_selection_summary()
            return True
        if keyval == Gdk.KEY_Right and entry.node.is_dir:
            if tree_row.get_expanded():
                child_row = tree_row.get_child_row(0)
                if child_row is not None:
                    self.tree_selection.set_selected(child_row.get_position())
            else:
                tree_row.set_expanded(True)
            return True
        if keyval == Gdk.KEY_Left:
            if tree_row.get_expanded():
                tree_row.set_expanded(False)
                return True
        if keyval in (Gdk.KEY_Return, Gdk.KEY_KP_Enter) and entry.node.is_more_row:
            self._start_page_load(entry.parent_entry, entry.node.more_offset)
            return True
            parent_row = tree_row.get_parent()
            if parent_row is not None:
                self.tree_selection.set_selected(parent_row.get_position())
                return True
        return False

    def _show_details(self, entry: TreeEntry | None):
        self._detail_entry = entry
        selected_name = (
            entry.node.name
            if entry and not entry.loading and not entry.node.aggregate_count
            and not entry.node.is_more_row
            else "the selected item"
        )
        self.explain_risk_chip.set_label(f"Explain the risk of {selected_name}")
        if not entry or entry.loading:
            self.detail_title.set_text("Select an item")
            self.detail_size.set_text("")
            self.detail_path.set_text("")
            self.detail_warning.set_text("")
            self.detail_procedure.set_text("")
            self.copy_procedure_button.set_visible(False)
            self.open_folder_button.set_sensitive(False)
            return
        self.detail_title.set_text(entry.node.name)
        size_text = format_bytes(entry.node.size_bytes)
        if entry.node.size_is_partial:
            size_text += " · tamanho parcial"
        if entry.node.error:
            size_text += f"\n{entry.node.error}"
        if not entry.node.selectable and not entry.node.error:
            size_text += "\nAlvo somente para inspeção; seleção bloqueada."
        self.detail_size.set_text(size_text)
        self.detail_path.set_text(
            f"Agrupa {entry.node.aggregate_count} itens menores nesta pasta."
            if entry.node.aggregate_count else str(entry.node.path)
        )
        if entry.node.aggregate_count or entry.node.is_more_row:
            self.detail_warning.set_text("Linha informativa; os itens agrupados não podem ser selecionados individualmente.")
            self.detail_procedure.set_text("")
            self.copy_procedure_button.set_visible(False)
            self.open_folder_button.set_sensitive(False)
            return
        evaluation = entry.evaluation or self.rule_engine.evaluate(entry.node)
        entry.evaluation = evaluation
        warnings = "\n".join(f"• {warning}" for warning in evaluation.warnings)
        risk_label = {
            Risk.LOW: "Low",
            Risk.MODERATE: "Moderate",
            Risk.USER_DATA: "Your data",
            Risk.CRITICAL: "Critical",
        }[evaluation.risk]
        self.detail_warning.set_text(f"Risk: {risk_label}\n{warnings}")
        procedure = evaluation.recommended_procedure
        self._detail_procedure_argv = None
        if procedure:
            self.detail_procedure.set_text(
                f"Recommended procedure: {procedure.label}\n"
                f"Effects: {procedure.side_effects}"
            )
            if procedure.requires_admin:
                self._detail_procedure_argv = procedure.command_to_copy
                self.copy_procedure_button.set_visible(True)
            else:
                self.copy_procedure_button.set_visible(False)
        else:
            self.detail_procedure.set_text("No native procedure is available.")
            self.copy_procedure_button.set_visible(False)
        self.open_folder_button.set_sensitive(entry.node.is_dir and not entry.node.error)

    def copy_procedure(self, _button):
        if self._detail_procedure_argv:
            clipboard = Gdk.Display.get_default().get_clipboard()
            clipboard.set(shlex.join(self._detail_procedure_argv))

    def open_selected_folder(self, _button):
        entry = self._detail_entry
        if not entry or not entry.node.is_dir:
            return
        launcher = Gtk.FileLauncher.new(Gio.File.new_for_path(str(entry.node.path)))
        launcher.launch(self.window, None, self._open_folder_done, None)

    def _open_folder_done(self, launcher, result, _data):
        try:
            launcher.launch_finish(result)
        except GLib.Error as error:
            self._show_message("Não foi possível abrir a pasta", str(error))

    def _refresh_selection_summary(self):
        if not self.selection:
            return
        paths = self.selection.selected_paths
        total = self.selection.estimated_size_bytes
        max_risk = max(
            (
                self._selected_evaluations[path].risk
                for path in paths if path in self._selected_evaluations
            ),
            key=self._risk_rank,
            default=None,
        )
        risk_text = {
            Risk.LOW: "Low",
            Risk.MODERATE: "Moderate",
            Risk.USER_DATA: "Your data",
            Risk.CRITICAL: "Critical",
        }.get(max_risk, "None")
        self.selection_label.set_text(
            f"{len(paths)} items selected · {format_size_gib(total)} · "
            f"highest risk: {risk_text}"
        )
        self.review_button.set_sensitive(bool(paths) and not self._workflow_busy)

    @staticmethod
    def _risk_rank(risk: Risk) -> int:
        return {Risk.LOW: 0, Risk.MODERATE: 1, Risk.USER_DATA: 2, Risk.CRITICAL: 3}[risk]

    def review_selection(self, _button):
        if not self.selection or not self.selection.selected_paths:
            return
        self._set_workflow_busy(True)
        self.disk_label.set_text("Validando caminhos e calculando revisão…")
        paths = tuple(self.selection.selected_paths)
        risks = {}
        warnings = {}
        for path in paths:
            entry = self.entries.get(path)
            evaluation = entry.evaluation if entry else None
            risks[path] = evaluation.risk if evaluation else Risk.MODERATE
            warnings[path] = evaluation.warnings if evaluation else ()
        threading.Thread(
            target=self._review_worker,
            args=(paths, risks, warnings),
            daemon=True,
        ).start()

    def _review_worker(self, paths, risks, warnings):
        try:
            scan_root = self.scanner.root_path if self.scanner else self.scan_root
            active = discover_active_paths(scan_root) + self.inspection_only_roots
            review = build_review(
                paths,
                allowed_root=scan_root,
                risks=risks,
                warnings=warnings,
                active_paths=active,
                trash_support=gio_trash_supported,
            )
            error = None
        except ActiveApplicationError as exc:
            review = None
            error = exc
        except Exception as exc:
            review = None
            error = str(exc)
        GLib.idle_add(self._show_review, review, error)

    def _show_review(self, review: CleanupReview | None, error: str | Exception | None):
        self._refresh_selection_summary()
        if error or review is None:
            self._set_workflow_busy(False)
            if isinstance(error, ActiveApplicationError):
                dialog = Gtk.AlertDialog()
                dialog.set_message("Aplicação em uso")
                dialog.set_detail(str(error))
                dialog.set_buttons(["Fechar e tentar novamente", "Cancelar"])
                dialog.set_cancel_button(1)
                dialog.set_default_button(1)
                dialog.choose(self.window, None, self._active_application_review_response, None)
                return GLib.SOURCE_REMOVE
            self._show_message("Revisão bloqueada", error or "Não foi possível revisar a seleção.")
            return GLib.SOURCE_REMOVE
        self._review = review
        self._execution_results = []
        lines = []
        for item in review.items:
            lines.append(
                f"• {item.path}\n  {format_bytes(item.size_bytes)} · risco {item.risk.value}"
            )
            lines.extend(f"  Aviso: {warning}" for warning in item.warnings)
        detail = (
            "\n".join(lines)
            + f"\n\nTotal estimado: {format_bytes(review.total_size_bytes)}"
            + f"\nRisco máximo: {review.maximum_risk.value}"
            + f"\n\n{review.notice}"
        )
        dialog = Gtk.AlertDialog()
        dialog.set_message("Revise cada item antes de confirmar")
        dialog.set_detail(detail)
        if review.maximum_risk is Risk.CRITICAL:
            self._set_workflow_busy(False)
            dialog.set_buttons(["Fechar · risco crítico bloqueia a ação"])
            dialog.choose(self.window, None, self._critical_review_closed, None)
        else:
            dialog.set_buttons(["Cancelar", "Mover para lixeira", "Excluir permanentemente"])
            dialog.set_cancel_button(0)
            dialog.set_default_button(0)
            dialog.choose(self.window, None, self._review_response, review)
        return GLib.SOURCE_REMOVE

    def _active_application_review_response(self, dialog, result, _data):
        try:
            choice = dialog.choose_finish(result)
        except GLib.Error:
            return
        if choice == 0:
            self.review_selection(None)

    def _critical_review_closed(self, dialog, result, _data):
        try:
            dialog.choose_finish(result)
        except GLib.Error:
            pass

    def _review_response(self, dialog, result, review):
        try:
            choice = dialog.choose_finish(result)
        except GLib.Error:
            return
        if choice not in (1, 2):
            self._cancel_review_plan()
            return
        self._review = review
        self._review_action = FileAction.TRASH if choice == 1 else FileAction.PERMANENT
        if self._review_action is FileAction.PERMANENT and any(
            item.risk is Risk.CRITICAL for item in review.items
        ):
            self._cancel_review_plan()
            self._show_message("Ação bloqueada", "Exclusão permanente bloqueada para risco crítico.")
            return
        self._review_index = 0
        self._confirm_next_item()

    def _confirm_next_item(self):
        review = self._review
        action = self._review_action
        if not review or not action:
            return
        if self._review_index >= len(review.items):
            self._show_message("Revisão concluída", "Todas as ações confirmadas terminaram.")
            self.scan()
            return
        item = review.items[self._review_index]
        if item.risk is Risk.CRITICAL:
            self._show_message("Ação bloqueada", f"Risco crítico: {item.path}")
            self._cancel_review_plan()
            return
        if item.risk is Risk.USER_DATA:
            dialog = Gtk.AlertDialog()
            dialog.set_message("Confirmação reforçada · dados pessoais")
            dialog.set_detail(
                f"Este item pode conter dados pessoais:\n{item.path}\n\n"
                "Confirme que revisou o aviso e deseja continuar."
            )
            dialog.set_buttons(["Cancelar plano", "Entendo e quero continuar"])
            dialog.set_cancel_button(0)
            dialog.choose(self.window, None, self._user_data_response, item)
        else:
            self._ask_item_confirmation(item)

    def _user_data_response(self, dialog, result, item):
        try:
            choice = dialog.choose_finish(result)
        except GLib.Error:
            return
        if choice != 1:
            self._cancel_review_plan()
            return
        self._ask_item_confirmation(item, user_data_confirmed=True)

    def _ask_item_confirmation(self, item: ReviewedItem, *, user_data_confirmed=False):
        action = self._review_action
        if action is FileAction.TRASH and item.trash_supported is False:
            self._ask_unavailable_trash_confirmation(item, user_data_confirmed)
            return
        action_label = "Mover para lixeira" if action is FileAction.TRASH else "Excluir permanentemente"
        dialog = Gtk.AlertDialog()
        dialog.set_message(f"Confirmar item {self._review_index + 1} de {len(self._review.items)}")
        dialog.set_detail(
            f"{item.path}\n{format_bytes(item.size_bytes)} · risco {item.risk.value}\n\n"
            f"Ação: {action_label}"
        )
        dialog.set_buttons(["Cancelar plano", action_label])
        dialog.set_cancel_button(0)
        dialog.set_default_button(0)
        callback = self._permanent_item_response if action is FileAction.PERMANENT else self._trash_item_response
        dialog.choose(self.window, None, callback, (item, user_data_confirmed))

    def _ask_unavailable_trash_confirmation(self, item, user_data_confirmed):
        dialog = Gtk.Dialog(title="Lixeira indisponível", transient_for=self.window, modal=True)
        dialog.add_button("Cancelar plano", Gtk.ResponseType.CANCEL)
        dialog.add_button("Continuar sem este item", Gtk.ResponseType.APPLY)
        dialog.add_button("Excluir permanentemente", Gtk.ResponseType.ACCEPT)
        content = dialog.get_content_area()
        content.append(Gtk.Label(
            label=f"Este local não tem lixeira (partição diferente do home)\n{item.path}",
            xalign=0, wrap=True,
        ))
        option = Gtk.CheckButton(label="Excluir permanentemente")
        option.set_active(False)
        content.append(option)
        command = "rm -r -- " + shlex.quote(str(item.path))
        content.append(Gtk.Label(label=f"Comando equivalente (para uso por conta própria):\n{command}",
                                 xalign=0, wrap=True, selectable=True))
        dialog.connect("response", self._unavailable_trash_response,
                       item, user_data_confirmed, option)
        dialog.present()

    def _unavailable_trash_response(self, dialog, response, item, user_data_confirmed, option):
        selected = option.get_active()
        dialog.destroy()
        if response == Gtk.ResponseType.CANCEL:
            self._cancel_review_plan()
        elif response == Gtk.ResponseType.ACCEPT and selected:
            self._typed_confirmation_dialog(item, user_data_confirmed)
        else:
            result = ItemExecutor(self.history, active_paths=()).record_skip(self._review, item)
            self._item_finished(result)

    def _trash_item_response(self, dialog, result, state):
        try:
            choice = dialog.choose_finish(result)
        except GLib.Error:
            return
        if choice != 1:
            self._cancel_review_plan()
            return
        item, user_data_confirmed = state
        self._execute_item(item, FileAction.TRASH, user_data_confirmed, None)

    def _permanent_item_response(self, dialog, result, state):
        try:
            choice = dialog.choose_finish(result)
        except GLib.Error:
            return
        if choice != 1:
            self._cancel_review_plan()
            return
        item, user_data_confirmed = state
        self._typed_confirmation_dialog(item, user_data_confirmed)

    def _typed_confirmation_dialog(self, item, user_data_confirmed):
        dialog = Gtk.Dialog(title="Confirmação de exclusão permanente", transient_for=self.window,
                            modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Excluir permanentemente", Gtk.ResponseType.ACCEPT)
        content = dialog.get_content_area()
        prompt = Gtk.Label(
            label=f"Digite {PERMANENT_CONFIRMATION} para excluir:\n{item.path}",
            xalign=0,
            wrap=True,
        )
        content.append(prompt)
        entry = Gtk.Entry()
        entry.set_placeholder_text(PERMANENT_CONFIRMATION)
        content.append(entry)
        dialog.connect("response", self._typed_confirmation_response,
                       item, user_data_confirmed, entry)
        dialog.present()

    def _typed_confirmation_response(self, dialog, response, item, user_data_confirmed, entry):
        typed = entry.get_text()
        dialog.destroy()
        if response != Gtk.ResponseType.ACCEPT:
            self._cancel_review_plan()
            return
        self._execute_item(item, FileAction.PERMANENT, user_data_confirmed, typed)

    def _execute_item(self, item, action, user_data_confirmed, typed_confirmation):
        self._set_workflow_busy(True)
        self.disk_label.set_text(f"Executando uma ação: {item.path.name}…")
        scan_root = self._review.allowed_root
        executor = ItemExecutor(
            self.history,
            active_paths=lambda: discover_active_paths(scan_root)
            + self.inspection_only_roots,
        )
        threading.Thread(
            target=self._execute_worker,
            args=(executor, self._review, item, action, user_data_confirmed, typed_confirmation),
            daemon=True,
        ).start()

    def _execute_worker(self, executor, review, item, action, user_data_confirmed, typed):
        result = executor.execute_one(
            review,
            item.path,
            action,
            user_data_confirmed=user_data_confirmed,
            typed_confirmation=typed,
        )
        GLib.idle_add(self._item_finished, result)

    def _item_finished(self, result):
        self._execution_results.append(result)
        self._review_index += 1
        if self._review_index >= len(self._review.items):
            self._show_execution_summary()
            return GLib.SOURCE_REMOVE
        self._confirm_next_item()
        return GLib.SOURCE_REMOVE

    def _show_execution_summary(self):
        results = tuple(self._execution_results)
        succeeded = sum(result.success for result in results)
        failed = len(results) - succeeded
        verb = "movidos" if self._review_action is FileAction.TRASH else "excluídos"
        dialog = Gtk.Dialog(title="Resumo da execução", transient_for=self.window, modal=True)
        dialog.add_button("Fechar", Gtk.ResponseType.CLOSE)
        content = dialog.get_content_area()
        content.append(Gtk.Label(label=f"{succeeded} {verb}, {failed} falharam", xalign=0))
        if self._review_action is FileAction.TRASH:
            content.append(Gtk.Label(
                label="O espaço só é liberado ao esvaziar a lixeira.", xalign=0
            ))
        for result in results:
            if result.success:
                continue
            record = result.record
            kind = record.get("failure_kind")
            messages = {
                "app_protected": "Bloqueado pelas proteções do Clearspace",
                "application_in_use": "Aplicação em uso; feche e tente novamente",
                "outside_scan_root": "Caminho fora da raiz do scan",
                "filesystem_permission": "Sem permissão do sistema de arquivos",
                "trash_unavailable": "Lixeira indisponível neste filesystem",
                "missing": "O item não existe mais",
            }
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            detail = Gtk.Label(
                label=f"{messages.get(kind, 'Falha na operação')}: {result.path}\n"
                f"{record.get('failure_message') or record.get('failure_details') or ''}",
                xalign=0,
                wrap=True,
                hexpand=True,
            )
            row.append(detail)
            copy_button = Gtk.Button(label="Copiar caminho")
            copy_button.connect("clicked", self._copy_failed_path, str(result.path))
            row.append(copy_button)
            content.append(row)
        dialog.connect("response", self._execution_summary_closed)
        dialog.present()

    def _copy_failed_path(self, _button, path):
        self.window.get_display().get_clipboard().set(path)

    def _execution_summary_closed(self, dialog, _response):
        dialog.destroy()
        self._review = None
        self._review_action = None
        self._execution_results = []
        self._set_workflow_busy(False)
        self.scan()

    @staticmethod
    def _free_space_text(record):
        if "free_bytes" not in record:
            return record.get("error", "indisponível")
        return format_bytes(record["free_bytes"])

    def _show_message(self, title, message):
        dialog = Gtk.AlertDialog()
        dialog.set_message(title)
        dialog.set_detail(message)
        dialog.show(self.window)

    def _set_workflow_busy(self, busy: bool):
        self._workflow_busy = busy
        if hasattr(self, "tree_view"):
            self.tree_view.set_sensitive(not busy)
        if hasattr(self, "scan_button"):
            self.scan_button.set_sensitive(not busy)
        if hasattr(self, "scan_report_button"):
            self.scan_report_button.set_sensitive(
                not busy and hasattr(self, "scan_report")
            )
        if hasattr(self, "review_button"):
            self.review_button.set_sensitive(
                bool(self.selection and self.selection.selected_paths) and not busy
            )

    def _cancel_review_plan(self):
        self._review = None
        self._review_action = None
        self._set_workflow_busy(False)
        self._refresh_selection_summary()


if __name__ == "__main__":
    application = Clearspace()
    raise SystemExit(application.run())
