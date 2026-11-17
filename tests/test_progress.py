from __future__ import annotations

import threading
import time
import random
from dataclasses import replace
from types import SimpleNamespace
from pathlib import Path

import pytest
import clearspace.progress as progress_module

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


def test_progress_event_caps_live_largest_items_at_four() -> None:
    items = tuple((str(index), f"/root/{index}", index) for index in range(5))
    try:
        ProgressEvent(largest_items=items)
    except ValueError as error:
        assert "four" in str(error)
    else:
        raise AssertionError("ProgressEvent accepted an unbounded largest item list")


def test_progress_throttle_caps_updates_and_allows_terminal_event() -> None:
    throttle = ProgressThrottle(0.15)
    assert throttle.should_publish(10.0)
    assert not throttle.should_publish(10.05)
    assert throttle.should_publish(10.15)
    assert throttle.should_publish(10.16, terminal=True)


def test_scan_controller_pause_resume_cancel_keeps_partial_result() -> None:
    controller = ScanController()
    started = threading.Event()
    checkpoint = threading.Event()
    release = threading.Event()
    observed = []

    def fake_scanner(publish, cancel_event, pause_event):
        started.set()
        publish(ProgressEvent(dirs_done=2, dirs_total_est=5, files=3, bytes=30))
        assert checkpoint.wait(timeout=1)
        controller.wait_if_paused()
        while not release.wait(timeout=0.01):
            if cancel_event.is_set():
                break
        observed.append(cancel_event.is_set())
        return "partial inventory"

    controller.start(fake_scanner)
    assert started.wait(timeout=1)
    controller.pause()
    assert controller.latest_snapshot().state is ScanState.RUNNING
    checkpoint.set()
    deadline = time.monotonic() + 1
    while controller.latest_snapshot().state is not ScanState.PAUSED and time.monotonic() < deadline:
        time.sleep(0.001)
    assert controller.latest_snapshot().state is ScanState.PAUSED
    controller.resume()
    deadline = time.monotonic() + 1
    while controller.latest_snapshot().state is not ScanState.RUNNING and time.monotonic() < deadline:
        time.sleep(0.001)
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


def test_scan_controller_terminal_snapshot_is_absorbing_for_controls() -> None:
    controller = ScanController()
    task_started = threading.Event()
    finish_task = threading.Event()
    def fake_scanner(_publish, _cancel_event, _pause_event):
        task_started.set()
        assert finish_task.wait(timeout=1)
        return "completed inventory"

    controller.start(fake_scanner)
    assert task_started.wait(timeout=1)
    controller.pause()
    finish_task.set()
    scan_thread = controller._thread
    assert scan_thread is not None
    scan_thread.join(timeout=1)
    terminal = controller.latest_snapshot()
    assert terminal.state is ScanState.DONE
    controller.pause()
    controller.resume()
    controller.cancel()
    assert controller.latest_snapshot() is terminal


def test_scan_controller_publishes_error_terminal_state_when_task_raises() -> None:
    controller = ScanController()

    def failing_scanner(_publish, _cancel_event, _pause_event):
        raise OSError("synthetic scan failure")

    controller.start(failing_scanner)
    thread = controller._thread
    assert thread is not None
    thread.join(timeout=1)

    assert controller.latest_snapshot().state is ScanState.ERROR
    assert controller.latest_snapshot().partial
    assert isinstance(controller.error, OSError)
    assert str(controller.error) == "synthetic scan failure"


def test_controls_and_late_progress_cannot_change_a_done_snapshot() -> None:
    controller = ScanController()

    def completed_scan(publish, _cancel_event, _pause_event):
        publish(ProgressEvent(dirs_done=3, dirs_total_est=9, files=4, bytes=80))
        return "inventory"

    controller.start(completed_scan)
    thread = controller._thread
    assert thread is not None
    thread.join(timeout=1)
    terminal = controller.latest_snapshot()

    assert terminal.state is ScanState.DONE
    assert terminal.dirs_total_est == terminal.dirs_done
    assert progress_percent(terminal) == 100
    controller.pause()
    controller.resume()
    controller.cancel()
    controller.publish(ProgressEvent(dirs_done=0, dirs_total_est=1, state=ScanState.RUNNING))

    assert controller.latest_snapshot() == terminal
    assert not controller._cancel.is_set()


def test_pause_and_resume_only_apply_snapshot_state_in_worker_thread() -> None:
    controller = ScanController()
    started = threading.Event()
    checkpoint = threading.Event()
    release_worker = threading.Event()

    def scanner(_publish, _cancel_event, _pause_event):
        started.set()
        assert checkpoint.wait(timeout=1)
        if not controller.wait_if_paused():
            return "cancelled"
        assert release_worker.wait(timeout=1)
        return "inventory"

    controller.start(scanner)
    assert started.wait(timeout=1)
    controller.pause()
    assert controller.latest_snapshot().state is ScanState.RUNNING
    checkpoint.set()
    deadline = time.monotonic() + 1
    while controller.latest_snapshot().state is not ScanState.PAUSED and time.monotonic() < deadline:
        time.sleep(0.001)
    assert controller.latest_snapshot().state is ScanState.PAUSED
    controller.resume()
    assert controller.latest_snapshot().state is ScanState.PAUSED
    release_worker.set()
    thread = controller._thread
    assert thread is not None
    thread.join(timeout=1)
    assert controller.latest_snapshot().state is ScanState.DONE


def test_random_control_interleavings_preserve_monotonic_and_absorbing_state() -> None:
    terminal_states = {ScanState.DONE, ScanState.CANCELLED, ScanState.ERROR}
    for seed in range(32):
        rng = random.Random(seed)
        controller = ScanController()
        started = threading.Event()
        finish = threading.Event()

        def scanner(publish, cancel_event, _pause_event):
            started.set()
            for index in range(20):
                if not controller.wait_if_paused():
                    break
                publish(ProgressEvent(
                    dirs_done=index,
                    dirs_total_est=20,
                    files=index,
                    bytes=index * 512,
                    current_path=f"/synthetic/{index}",
                ))
                if cancel_event.is_set():
                    break
                time.sleep(0.0002)
            finish.wait(timeout=1)
            return "partial inventory"

        controller.start(scanner)
        assert started.wait(timeout=1)
        observed = []
        for _ in range(12):
            action = rng.choice((controller.pause, controller.resume, controller.cancel))
            action()
            observed.append(controller.latest_snapshot())
            time.sleep(rng.random() * 0.001)
        controller.resume()
        finish.set()
        thread = controller._thread
        assert thread is not None
        thread.join(timeout=1)
        observed.append(controller.latest_snapshot())

        final = controller.latest_snapshot()
        assert final.state in terminal_states
        for before, after in zip(observed, observed[1:]):
            assert after.dirs_done >= before.dirs_done
            assert after.files >= before.files
            assert after.bytes >= before.bytes
            assert after.unreadable_count >= before.unreadable_count
        controller.pause()
        controller.resume()
        controller.cancel()
        controller.publish(ProgressEvent(dirs_done=0, dirs_total_est=0))
        assert controller.latest_snapshot() == final


def test_watchdog_announces_stalled_current_path_and_resets_on_progress() -> None:
    watchdog_type = getattr(progress_module, "ProgressWatchdog", None)
    assert watchdog_type is not None, "ProgressWatchdog must report stalled scans"
    watchdog = watchdog_type(timeout_seconds=5)
    event = ProgressEvent(
        dirs_done=2,
        dirs_total_est=20,
        files=10,
        current_path="/synthetic/large-folder",
    )

    assert watchdog.update(event, now=10.0) is None
    assert watchdog.update(event, now=14.9) is None
    assert watchdog.update(event, now=15.0) == "Still working on /synthetic/large-folder"
    assert watchdog.update(
        replace(event, files=11, current_path="/synthetic/next-folder"), now=15.1
    ) is None


def test_eta_text_uses_finishing_instead_of_zero_and_done_is_exact() -> None:
    eta_label = getattr(progress_module, "eta_label", None)
    assert callable(eta_label), "eta_label must format finishing and terminal states"
    running = ProgressEvent(dirs_done=99, dirs_total_est=100)
    done = ProgressEvent(dirs_done=5, dirs_total_est=9, state=ScanState.DONE)

    assert eta_label(running, 0, 99) == "Finishing..."
    assert eta_label(running, 1, 99) == "Finishing..."
    assert eta_label(done, 0, 100) == "Complete"


def test_progress_event_includes_unreadable_count() -> None:
    assert "unreadable_count" in ProgressEvent.__dataclass_fields__
    event = ProgressEvent(unreadable_count=3)
    assert event.unreadable_count == 3

def test_progress_formatting() -> None:
    assert format_size_gib(1024**3) == "1.0 GiB"
    assert format_elapsed(65_999) == "1:05"


def test_filesystem_stats_uses_statvfs_block_and_inode_counts(tmp_path: Path) -> None:
    fake_statvfs = SimpleNamespace(
        f_frsize=4096,
        f_bsize=1024,
        f_blocks=100,
        f_bfree=25,
        f_files=20,
        f_ffree=7,
    )

    filesystem_stats = _required_filesystem_stats()
    result = filesystem_stats(tmp_path, statvfs=lambda _path: fake_statvfs)

    assert result == (307_200, 409_600, 13)


def test_filesystem_stats_falls_back_to_block_size_and_clamps_negative_counts(
    tmp_path: Path,
) -> None:
    fake_statvfs = SimpleNamespace(
        f_frsize=0,
        f_bsize=2048,
        f_blocks=10,
        f_bfree=12,
        f_files=4,
        f_ffree=8,
    )

    filesystem_stats = _required_filesystem_stats()
    result = filesystem_stats(tmp_path, statvfs=lambda _path: fake_statvfs)

    assert result == (0, 20_480, 0)


def test_filesystem_stats_keeps_statvfs_errors_visible(tmp_path: Path) -> None:
    def failing_statvfs(_path: Path):
        raise PermissionError("statvfs denied")

    filesystem_stats = _required_filesystem_stats()
    with pytest.raises(PermissionError, match="statvfs denied"):
        filesystem_stats(tmp_path, statvfs=failing_statvfs)


def test_mount_root_progress_uses_filesystem_used_bytes_and_caps_at_99() -> None:
    event = ProgressEvent()
    assert hasattr(event, "fs_used_bytes"), "ProgressEvent must carry filesystem usage"
    assert progress_percent(
        ProgressEvent(bytes=80, fs_used_bytes=100), root_is_mountpoint=True
    ) == 80
    assert progress_percent(
        ProgressEvent(bytes=120, fs_used_bytes=100), root_is_mountpoint=True
    ) == 99
    assert progress_percent(
        ProgressEvent(bytes=1, fs_used_bytes=0), root_is_mountpoint=True
    ) is None
    assert progress_percent(
        ProgressEvent(state=ScanState.DONE, fs_used_bytes=100),
        root_is_mountpoint=True,
    ) == 100


def test_subfolder_progress_uses_directory_estimate_not_filesystem_ceiling() -> None:
    event = ProgressEvent()
    assert hasattr(event, "fs_total_bytes"), "ProgressEvent must carry filesystem context"
    event = ProgressEvent(
        dirs_done=25,
        dirs_total_est=100,
        bytes=900,
        fs_used_bytes=1_000,
        fs_total_bytes=2_000,
    )

    assert progress_percent(event, root_is_mountpoint=False) == 25


def test_progress_event_can_expose_statvfs_failure() -> None:
    event = ProgressEvent()
    assert hasattr(event, "filesystem_error"), "statvfs errors must remain visible"
    event = ProgressEvent(filesystem_error="statvfs denied")
    assert event.filesystem_error == "statvfs denied"


def test_relative_size_fraction_scales_to_largest_with_zero_and_single_edges() -> None:
    fraction = getattr(progress_module, "relative_size_fraction", None)
    assert callable(fraction), "relative_size_fraction must be provided for usage bars"

    largest = int(1.8 * 1024**3)
    assert fraction(largest, largest) == 1.0
    assert fraction(int(587.9 * 1024**2), largest) == pytest.approx(
        int(587.9 * 1024**2) / largest
    )
    assert fraction(12 * 1024, largest) == pytest.approx(12 * 1024 / largest)
    assert fraction(0, largest) == 0.0
    assert fraction(42, 42) == 1.0
    assert fraction(0, 0) == 0.0


def _required_filesystem_stats():
    function = getattr(progress_module, "filesystem_stats", None)
    assert callable(function), "filesystem_stats must derive capacity from statvfs"
    return function
