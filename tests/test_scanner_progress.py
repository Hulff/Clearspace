from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from clearspace.progress import ProgressEvent, ProgressThrottle, ScanState
from clearspace.scanner import TreeScanner


def test_scanner_emits_throttled_folder_progress_and_allocated_bytes(tmp_path: Path) -> None:
    root_path = tmp_path / "root"
    nested = root_path / "nested"
    nested.mkdir(parents=True)
    (root_path / "first.bin").write_bytes(b"first payload" * 100)
    (nested / "second.bin").write_bytes(b"second payload" * 100)
    events: list[ProgressEvent] = []

    scanner = TreeScanner(root_path)
    root = scanner.scan_root(progress=events.append)

    assert events
    assert events[0].state is ScanState.RUNNING
    assert events[-1].state is ScanState.DONE
    assert events[-1].dirs_done == events[-1].dirs_total_est == 2
    assert events[-1].files == 2
    assert events[-1].bytes == root.size_bytes
    assert scanner.report["allocated_bytes"] == root.size_bytes
    assert all(first.bytes <= second.bytes for first, second in zip(events, events[1:]))
    assert all(first.dirs_total_est <= second.dirs_total_est
               for first, second in zip(events, events[1:]))
    assert scanner.top_items.snapshot()


def test_cancel_keeps_a_partial_tree_and_emits_cancelled_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root_path = tmp_path / "root"
    nested = root_path / "nested"
    nested.mkdir(parents=True)
    (nested / "payload.bin").write_bytes(b"some payload")
    (root_path / "another.bin").write_bytes(b"another payload")
    cancel_event = threading.Event()
    events: list[ProgressEvent] = []
    monkeypatch.setattr(
        "clearspace.scanner.ProgressThrottle",
        lambda: ProgressThrottle(0.000001),
    )

    def cancel_after_nested_directory_is_discovered(event: ProgressEvent) -> None:
        events.append(event)
        if event.dirs_total_est >= 2:
            cancel_event.set()

    root = TreeScanner(root_path).scan_root(
        progress=cancel_after_nested_directory_is_discovered,
        cancel_event=cancel_event,
    )

    assert root.children
    assert root.size_is_partial
    assert events[-1].state is ScanState.CANCELLED
    assert events[-1].partial
    assert any(child.name == "nested" and child.size_is_partial for child in root.children)


def test_pause_event_blocks_scanning_until_resumed(tmp_path: Path) -> None:
    root_path = tmp_path / "root"
    root_path.mkdir()
    (root_path / "payload.bin").write_bytes(b"payload")
    pause_event = threading.Event()
    pause_event.clear()
    started = threading.Event()
    finished = threading.Event()
    result = []

    def scan() -> None:
        started.set()
        result.append(TreeScanner(root_path).scan_root(pause_event=pause_event))
        finished.set()

    thread = threading.Thread(target=scan)
    thread.start()
    assert started.wait(timeout=1)
    time.sleep(0.03)
    assert not finished.is_set()
    pause_event.set()
    thread.join(timeout=1)

    assert finished.is_set()
    assert result[0].size_bytes > 0
