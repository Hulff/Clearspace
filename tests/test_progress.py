from __future__ import annotations

import threading
import time

from clearspace.progress import (
    EtaEstimator,
    ProgressEvent,
    ProgressThrottle,
    ScanController,
    ScanState,
    TopKTracker,
    format_elapsed,
    format_size_gib,
    progress_percent,
)


def test_percent_is_indeterminate_and_clamped_until_done() -> None:
    assert progress_percent(ProgressEvent()) is None
    assert progress_percent(ProgressEvent(dirs_done=50, dirs_total_est=100)) == 50
    assert progress_percent(ProgressEvent(dirs_done=200, dirs_total_est=100)) == 99
    assert progress_percent(ProgressEvent(
        dirs_done=80, dirs_total_est=100, state=ScanState.DONE
    )) == 100


def test_eta_waits_for_signal_and_smooths_rate() -> None:
    eta = EtaEstimator(alpha=0.5)
    assert eta.remaining_seconds(ProgressEvent(
        dirs_done=1, dirs_total_est=100, elapsed_ms=4_999
    )) is None
    assert eta.remaining_seconds(ProgressEvent(
        dirs_done=10, dirs_total_est=100, elapsed_ms=5_000
    )) == 45
    first = eta.remaining_seconds(ProgressEvent(
        dirs_done=20, dirs_total_est=100, elapsed_ms=10_000
    ))
    second = eta.remaining_seconds(ProgressEvent(
        dirs_done=30, dirs_total_est=100, elapsed_ms=15_000
    ))
    assert first == 40
    assert second == 35
    assert eta.remaining_seconds(ProgressEvent(
        dirs_done=31, dirs_total_est=10**9, elapsed_ms=20_000
    )) is None
    early_eta = EtaEstimator().remaining_seconds(ProgressEvent(
        dirs_done=5, dirs_total_est=100, elapsed_ms=1_000
    ))
    assert early_eta == 19


def test_top_k_is_bounded_and_returns_largest_entries() -> None:
    tracker = TopKTracker(4)
    for index in range(100_000):
        tracker.add(f"item-{index}", f"/root/{index}", index)
    assert len(tracker._heap) == 4
    assert [size for _, _, size in tracker.snapshot()] == [99_999, 99_998, 99_997, 99_996]


def test_progress_throttle_caps_updates_and_allows_terminal_event() -> None:
    throttle = ProgressThrottle(0.15)
    assert throttle.should_publish(10.0)
    assert not throttle.should_publish(10.05)
    assert throttle.should_publish(10.15)
    assert throttle.should_publish(10.16, terminal=True)


def test_scan_controller_pause_resume_cancel_keeps_partial_result() -> None:
    controller = ScanController()
    started = threading.Event()
    release = threading.Event()
    observed = []

    def fake_scanner(publish, cancel_event, pause_event):
        started.set()
        publish(ProgressEvent(dirs_done=2, dirs_total_est=5, files=3, bytes=30))
        if not pause_event.wait(timeout=1):
            raise AssertionError("initial scan was unexpectedly paused")
        while not release.wait(timeout=0.01):
            if cancel_event.is_set():
                break
        observed.append(cancel_event.is_set())
        return "partial inventory"

    controller.start(fake_scanner)
    assert started.wait(timeout=1)
    controller.pause()
    assert controller.latest_snapshot().state is ScanState.PAUSED
    controller.resume()
    assert controller.latest_snapshot().state is ScanState.RUNNING
    controller.cancel()
    release.set()
    thread = controller._thread
    assert thread is not None
    thread.join(timeout=1)

    snapshot = controller.latest_snapshot()
    assert observed == [True]
    assert controller.result == "partial inventory"
    assert snapshot.state is ScanState.CANCELLED
    assert snapshot.partial


def test_progress_formatting() -> None:
    assert format_size_gib(1024**3) == "1.0 GiB"
    assert format_elapsed(65_999) == "1:05"
