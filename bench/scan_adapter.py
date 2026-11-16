"""Headless scanner adapter for bench/scan_bench.py. No GTK. Prints ONE JSON line.

TODO(Codex): wire scan() to the REAL Clearspace scanner (Python or the Rust binary)
and return {"files", "dirs", "bytes", "first_progress_ms"}; bytes = disk usage
(st_blocks * 512). reference_scan() is only a smoke test for the harness, never a
Clearspace measurement.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from clearspace.rust_scanner import RustTreeScanner
from clearspace.scanner import TreeScanner


def reference_scan(root: Path) -> dict:
    t0 = time.perf_counter()
    files = dirs = total = 0
    first = None
    seen: set[tuple[int, int]] = set()
    dev = root.stat().st_dev
    stack = [str(root)]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                entries = list(it)
            total += os.lstat(d).st_blocks * 512
        except OSError:
            continue
        dirs += 1
        if first is None:
            first = (time.perf_counter() - t0) * 1000
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if st.st_dev != dev:
                continue
            if e.is_dir(follow_symlinks=False):
                stack.append(e.path)
                continue
            files += 1
            if st.st_nlink > 1:
                key = (st.st_dev, st.st_ino)
                if key in seen:
                    continue
                seen.add(key)
            total += st.st_blocks * 512
    return {"files": files, "dirs": dirs, "bytes": total, "first_progress_ms": first}


def scan(root: Path) -> dict:
    root = Path(root)
    started = time.perf_counter()
    first_progress_ms = None

    if RustTreeScanner.available():
        def on_progress(_event: dict) -> None:
            nonlocal first_progress_ms
            if first_progress_ms is None:
                first_progress_ms = (time.perf_counter() - started) * 1000

        scanner = RustTreeScanner(root, progress=on_progress)
        try:
            scanner.scan_root()
            report = scanner.report
        finally:
            scanner.close()
    else:
        class ProgressTreeScanner(TreeScanner):
            def __init__(self, root_path: Path) -> None:
                super().__init__(root_path)
                self.first_progress_ms = None

            def expand(self, node):
                nonlocal first_progress_ms
                children = super().expand(node)
                if first_progress_ms is None:
                    first_progress_ms = (time.perf_counter() - started) * 1000
                return children

        scanner = ProgressTreeScanner(root)
        scanner.scan_root()
        report = scanner.report

    return {
        "files": int(report["files"]),
        "dirs": int(report.get("directories", 0)),
        "bytes": int(report["allocated_bytes"]),
        "first_progress_ms": first_progress_ms,
    }


if __name__ == "__main__":
    print(json.dumps(scan(Path(sys.argv[1]).resolve())))
