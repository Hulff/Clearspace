#!/usr/bin/env python3
"""Clearspace GTK 4 desktop application."""

import threading

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk

from clearspace.core import Candidate, History, discover_candidates, execute_cleanup, format_bytes


class Clearspace(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="org.clearspace.DiskCleanup")
        self.history = History()
        self.rows = {}

    def do_activate(self):
        self.window = Gtk.ApplicationWindow(application=self, title="Clearspace")
        self.window.set_default_size(820, 680)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        outer.set_margin_top(24); outer.set_margin_bottom(20)
        outer.set_margin_start(24); outer.set_margin_end(24)
        self.window.set_child(outer)

        heading = Gtk.Label(label="Disk cleanup")
        heading.add_css_class("title-1"); heading.set_xalign(0)
        outer.append(heading)
        intro = Gtk.Label(label="Measure local disk use, review the impact, then choose what to clean.")
        intro.set_xalign(0); intro.add_css_class("dim-label")
        outer.append(intro)

        self.disk_label = Gtk.Label(label="")
        self.disk_label.set_xalign(0)
        self.disk_label.add_css_class("heading")
        outer.append(self.disk_label)

        bar = Gtk.Box(spacing=8)
        outer.append(bar)
        self.scan_button = Gtk.Button(label="Scan again")
        self.scan_button.connect("clicked", lambda *_: self.scan())
        bar.append(self.scan_button)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        outer.append(scroll)
        self.list_box = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.list_box.add_css_class("boxed-list")
        scroll.set_child(self.list_box)

        history_title = Gtk.Label(label="Recent cleanup history")
        history_title.set_xalign(0); history_title.add_css_class("heading")
        outer.append(history_title)
        self.history_label = Gtk.Label(label="")
        self.history_label.set_xalign(0); self.history_label.set_wrap(True)
        self.history_label.add_css_class("dim-label")
        outer.append(self.history_label)
        self.refresh_history()
        self.scan()
        self.window.present()

    def scan(self):
        self.disk_label.set_text("Scanning…")
        self.scan_button.set_sensitive(False)
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        import shutil
        from pathlib import Path
        usage = shutil.disk_usage(Path.home())
        candidates = discover_candidates()
        GLib.idle_add(self._show_scan, usage.total, usage.free, candidates)

    def _show_scan(self, total, free, candidates):
        self.disk_label.set_text(f"Home filesystem: {format_bytes(free)} free of {format_bytes(total)}")
        child = self.list_box.get_first_child()
        while child:
            next_child = child.get_next_sibling()
            self.list_box.remove(child)
            child = next_child
        for candidate in sorted(candidates, key=lambda item: (item.size or 0), reverse=True):
            self.list_box.append(self._candidate_row(candidate))
        if not candidates:
            row = Gtk.ListBoxRow()
            row.set_child(Gtk.Label(label="No cleanup candidates found."))
            self.list_box.append(row)
        self.scan_button.set_sensitive(True)
        return GLib.SOURCE_REMOVE

    def _candidate_row(self, item: Candidate):
        row = Gtk.ListBoxRow()
        box = Gtk.Box(spacing=12)
        box.set_margin_top(10); box.set_margin_bottom(10)
        box.set_margin_start(12); box.set_margin_end(12)
        row.set_child(box)
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, hexpand=True)
        box.append(body)
        title = Gtk.Label(label=item.title, xalign=0)
        title.add_css_class("heading"); body.append(title)
        size = format_bytes(item.size) if item.size is not None else "Size not measured"
        status = []
        if item.partial:
            status.append("tamanho parcial")
        if item.read_error:
            status.append(f"Não foi possível ler: {item.read_error}")
        status_text = f"\n{' · '.join(status)}" if status else ""
        detail = Gtk.Label(label=f"{size} · {item.risk}{status_text}\n{item.description}", xalign=0, wrap=True)
        detail.add_css_class("dim-label"); body.append(detail)
        if item.command:
            button = Gtk.Button(label="Review cleanup")
            button.connect("clicked", self.confirm_cleanup, item)
            box.append(button)
        elif item.path and item.available:
            button = Gtk.Button(label="Open folder")
            button.connect("clicked", self.open_folder, item.path)
            box.append(button)
        elif item.id == "journal":
            button = Gtk.Button(label="View details")
            button.connect("clicked", self.show_message, "System journal", item.description)
            box.append(button)
        return row

    def open_folder(self, _button, path):
        import subprocess
        subprocess.Popen(["xdg-open", path], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)

    def confirm_cleanup(self, _button, item):
        dialog = Gtk.AlertDialog()
        command = " ".join(item.command)
        dialog.set_message(f"Run {item.title} cleanup?")
        dialog.set_detail(f"{item.description}\n\nCommand: {command}\n\nThis may require downloading or rebuilding data later.")
        dialog.set_buttons(["Cancel", "Run cleanup"])
        dialog.set_cancel_button(0)
        dialog.set_default_button(0)
        dialog.choose(self.window, None, self._confirm_response, item)

    def _confirm_response(self, dialog, result, item):
        try:
            choice = dialog.choose_finish(result)
        except Exception:
            return
        if choice != 1:
            return
        self.show_message("Cleanup running", f"Running {item.title}…")
        threading.Thread(target=execute_cleanup,
                         args=(item, self.history, lambda record: GLib.idle_add(self._cleanup_done, record)),
                         daemon=True).start()

    def show_message(self, title, message):
        dialog = Gtk.AlertDialog()
        dialog.set_message(title); dialog.set_detail(message)
        dialog.show(self.window)

    def _cleanup_done(self, record):
        if record["exit_code"] == 0:
            message = "Cleanup command completed successfully. Rescan to refresh measured sizes."
        else:
            message = f"Cleanup command exited with status {record['exit_code']}. See recent history for details."
        self.show_message("Cleanup finished", message)
        self.refresh_history()
        return GLib.SOURCE_REMOVE

    def refresh_history(self):
        entries = self.history.recent(5)
        if not entries:
            self.history_label.set_text("No cleanup actions recorded yet. History stays on this device.")
            return
        lines = []
        for item in entries:
            status = "completed" if item.get("exit_code") == 0 else f"exit {item.get('exit_code')}"
            before, after = item.get("before_bytes"), item.get("after_bytes")
            if before is not None and after is not None:
                delta = max(0, before - after)
                status += f" · {format_bytes(delta)} reclaimed (measured)"
            lines.append(f"{item.get('title', item.get('action_id'))} · {status}")
        self.history_label.set_text("\n".join(lines))


if __name__ == "__main__":
    app = Clearspace()
    raise SystemExit(app.run())
