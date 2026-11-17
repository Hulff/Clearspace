"""GTK-free scan progress, control, and bounded live summaries."""

from __future__ import annotations

import heapq
import os
import threading
import time
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Callable, Protocol, TypeVar


class ScanState(StrEnum):
    RUNNING = "running"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    DONE = "done"
    ERROR = "error"


class StatVfsInfo(Protocol):
    f_frsize: int
    f_bsize: int
    f_blocks: int
    f_bfree: int
    f_files: int
    f_ffree: int


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    dirs_done: int = 0
    dirs_total_est: int | None = None
    files: int = 0
    bytes: int = 0
    elapsed_ms: int = 0
    current_path: str = ""
    state: ScanState = ScanState.RUNNING
    partial: bool = False
    largest_items: tuple[tuple[str, str, int], ...] = ()
    fs_used_bytes: int | None = None
    fs_total_bytes: int | None = None
    fs_used_inodes: int | None = None
    filesystem_error: str | None = None
    root_is_mountpoint: bool = False

    def __post_init__(self) -> None:
        for name in ("dirs_done", "files", "bytes", "elapsed_ms"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} cannot be negative")
        if self.dirs_total_est is not None and self.dirs_total_est < 0:
            raise ValueError("dirs_total_est cannot be negative")
        for name in ("fs_used_bytes", "fs_total_bytes", "fs_used_inodes"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"{name} cannot be negative")
        if self.filesystem_error is not None and not isinstance(self.filesystem_error, str):
            raise ValueError("filesystem_error must be a string or None")
        if len(self.largest_items) > 4:
            raise ValueError("largest_items cannot contain more than four entries")
        if any(
            not isinstance(name, str)
            or not isinstance(path, str)
            or not isinstance(size, int)
            or size < 0
            for name, path, size in self.largest_items
        ):
            raise ValueError("largest_items entries must be (name, path, nonnegative size)")


T = TypeVar("T")
ProgressCallback = Callable[[ProgressEvent], None]


class ScanTask(Protocol[T]):
    def __call__(
        self,
        publish: ProgressCallback,
        cancel_event: threading.Event,
        pause_event: threading.Event,
    ) -> T: ...


class ScanController:
    """Run a scanner in a worker thread and expose its latest immutable snapshot.

    A task should call ``publish`` periodically, inspect ``cancel_event``, and
    wait on ``pause_event`` before continuing filesystem work. Cancellation is
    cooperative so the scanner can return its partial inventory safely.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshot = ProgressEvent()
        self._cancel = threading.Event()
        self._pause = threading.Event()
        self._pause.set()
        self._thread: threading.Thread | None = None
        self._result: object | None = None
        self._error: BaseException | None = None
        self._started_at = 0.0
        self._terminal = False

    def start(self, task: ScanTask[T]) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("a scan is already running")
            self._cancel = threading.Event()
            self._pause = threading.Event()
            self._pause.set()
            self._result = None
            self._error = None
            self._terminal = False
            self._started_at = time.monotonic()
            self._snapshot = ProgressEvent(state=ScanState.RUNNING)
            self._thread = threading.Thread(
                target=self._run, args=(task,), name="clearspace-scan", daemon=True
            )
            self._thread.start()

    def _run(self, task: ScanTask[T]) -> None:
        completed = False
        try:
            self._result = task(self.publish, self._cancel, self._pause)
            completed = True
        except BaseException as error:
            self._error = error
        finally:
            with self._lock:
                current = self._snapshot
                if self._error is not None:
                    state = ScanState.ERROR
                    partial = True
                elif self._cancel.is_set():
                    state = ScanState.CANCELLED
                    partial = True
                elif completed:
                    state = ScanState.DONE
                    partial = current.partial
                else:
                    state = ScanState.ERROR
                    partial = True
                try:
                    self._snapshot = replace(
                        current,
                        state=state,
                        partial=partial,
                        elapsed_ms=max(
                            current.elapsed_ms,
                            int((time.monotonic() - self._started_at) * 1000),
                        ),
                    )
                except BaseException as error:
                    if self._error is None:
                        self._error = error
                    self._snapshot = ProgressEvent(
                        state=ScanState.ERROR,
                        partial=True,
                        elapsed_ms=max(
                            0,
                            int((time.monotonic() - self._started_at) * 1000),
                        ),
                    )
                self._terminal = True

    def publish(self, event: ProgressEvent) -> None:
        """Publish a scanner snapshot, filling elapsed time if it was omitted."""
        if event.elapsed_ms == 0 and self._started_at:
            event = replace(event, elapsed_ms=int((time.monotonic() - self._started_at) * 1000))
        with self._lock:
            if self._terminal:
                return
            self._snapshot = event

    def pause(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            self._pause.clear()
            current = self.latest_snapshot()
            self.publish(replace(current, state=ScanState.PAUSED))

    def resume(self) -> None:
        self._pause.set()
        current = self.latest_snapshot()
        if current.state is ScanState.PAUSED:
            self.publish(replace(current, state=ScanState.RUNNING))

    def cancel(self) -> None:
        self._cancel.set()
        self._pause.set()

    def latest_snapshot(self) -> ProgressEvent:
        with self._lock:
            return self._snapshot

    def wait_if_paused(self) -> bool:
        """Block a cooperative scanner until resumed; return false if cancelled."""
        while not self._pause.wait(timeout=0.1):
            if self._cancel.is_set():
                return False
        return not self._cancel.is_set()

    @property
    def result(self) -> object | None:
        return self._result

    @property
    def error(self) -> BaseException | None:
        return self._error


def filesystem_stats(
    path: Path,
    statvfs: Callable[[Path], StatVfsInfo] = os.statvfs,
) -> tuple[int, int, int]:
    """Return used bytes, total bytes, and used inodes from local statvfs."""
    info = statvfs(path)
    block_size = info.f_frsize or info.f_bsize
    total_bytes = max(0, info.f_blocks) * block_size
    used_blocks = max(0, info.f_blocks - info.f_bfree)
    used_inodes = max(0, info.f_files - info.f_ffree)
    return used_blocks * block_size, total_bytes, used_inodes


def progress_percent(
    event: ProgressEvent,
    *,
    root_is_mountpoint: bool = False,
) -> int | None:
    """Return mount usage or folder-estimate progress, capped at 99% while running."""
    if event.state is ScanState.DONE:
        return 100
    if root_is_mountpoint:
        used = event.fs_used_bytes
        if used is None or used <= 0:
            return None
        return min(99, max(0, event.bytes * 100 // used))
    total = event.dirs_total_est
    if total is None or total <= 0:
        return None
    percent = max(0, min(100, int(event.dirs_done * 100 / total)))
    if event.state is not ScanState.DONE:
        return min(99, percent)
    return percent


def relative_size_fraction(size_bytes: int, largest_size_bytes: int) -> float:
    """Return a bounded usage-bar fraction relative to the largest entry."""
    if largest_size_bytes <= 0:
        return 0.0
    return min(1.0, max(0.0, size_bytes / largest_size_bytes))


class EtaEstimator:
    """Estimate remaining seconds from an exponentially smoothed folder rate."""

    def __init__(self, alpha: float = 0.25, *, maximum_seconds: int = 24 * 60 * 60):
        if not 0 < alpha <= 1:
            raise ValueError("alpha must be in (0, 1]")
        self.alpha = alpha
        self.maximum_seconds = maximum_seconds
        self._rate: float | None = None
        self._last: tuple[int, int] | None = None

    def remaining_seconds(self, event: ProgressEvent) -> int | None:
        if event.dirs_total_est is None:
            return None
        current = (event.dirs_done, event.elapsed_ms)
        if self._last:
            done_delta = event.dirs_done - self._last[0]
            time_delta = (event.elapsed_ms - self._last[1]) / 1000
            if done_delta >= 0 and time_delta >= 0.1:
                rate = done_delta / time_delta
                if rate > 0:
                    self._rate = rate if self._rate is None else (
                        self.alpha * rate + (1 - self.alpha) * self._rate
                    )
        self._last = current
        percent = event.dirs_done / max(1, event.dirs_total_est)
        if event.elapsed_ms < 5_000 and percent < 0.05:
            return None
        if self._rate is None or self._rate <= 0:
            elapsed_seconds = event.elapsed_ms / 1000
            if elapsed_seconds <= 0 or event.dirs_done <= 0:
                return None
            self._rate = event.dirs_done / elapsed_seconds
        remaining = max(0, event.dirs_total_est - event.dirs_done) / self._rate
        if remaining > self.maximum_seconds:
            return None
        return int(remaining)


def format_size_gib(size_bytes: int) -> str:
    return f"{size_bytes / (1024 ** 3):,.1f} GiB"


def format_elapsed(milliseconds: int) -> str:
    seconds = max(0, milliseconds // 1000)
    return f"{seconds // 60}:{seconds % 60:02d}"


class TopKTracker:
    """Keep only the K largest observed entries in bounded memory."""

    def __init__(self, limit: int = 4) -> None:
        if limit < 1:
            raise ValueError("limit must be positive")
        self.limit = limit
        self._heap: list[tuple[int, int, str, str]] = []
        self._sequence = 0

    def add(self, name: str, path: str | Path, size_bytes: int) -> None:
        if size_bytes < 0:
            raise ValueError("size_bytes cannot be negative")
        self._sequence += 1
        if len(self._heap) < self.limit:
            heapq.heappush(
                self._heap, (size_bytes, self._sequence, name, str(path))
            )
        elif size_bytes > self._heap[0][0]:
            heapq.heapreplace(
                self._heap, (size_bytes, self._sequence, name, str(path))
            )

    def snapshot(self) -> tuple[tuple[str, str, int], ...]:
        return tuple(
            (name, path, size)
            for size, _sequence, name, path in sorted(self._heap, reverse=True)
        )


class ProgressThrottle:
    """Allow UI snapshots at a bounded rate, independent of file count."""

    def __init__(self, interval_seconds: float = 0.15) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self.interval_seconds = interval_seconds
        self._last_publish = 0.0

    def should_publish(self, now: float | None = None, *, terminal: bool = False) -> bool:
        if terminal:
            self._last_publish = time.monotonic() if now is None else now
            return True
        current = time.monotonic() if now is None else now
        if current - self._last_publish < self.interval_seconds:
            return False
        self._last_publish = current
        return True
