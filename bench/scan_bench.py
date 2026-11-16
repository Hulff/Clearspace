#!/usr/bin/env python3
"""Scan benchmark: wall time, CPU time and peak RSS per run, each in a fresh process.

Works for any scanner (Python adapter or a Rust binary). No GTK, no shell, no sudo.
Peak RSS is polled from /proc/<pid>/status every ~20 ms, so a spike in the last 20 ms
can be missed. It covers only the measured process: if the scanner spawns children,
point --cmd directly at the binary.
Usage:
  python -m bench.scan_bench                      # synthetic tree, 3 runs, vs du
  python -m bench.scan_bench /some/dir --runs 5
  python -m bench.scan_bench /some/dir --cmd ./clearspace-scan {root} --json
A custom scanner must print ONE JSON line on stdout:
  {"files": int, "dirs": int, "bytes": int, "first_progress_ms": float|null}
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Run:
    label: str
    argv: list[str]
    wall_s: float
    cpu_s: float
    peak_rss_mib: float
    rss_source: str  # "VmHWM" (polled, exec-clean) or "ru_maxrss" (very short runs)
    returncode: int | None
    timed_out: bool
    stderr_lines: int
    stdout: str  # last 4000 chars


def read_hwm_mib(pid: int) -> float | None:
    """Peak RSS of a live process from /proc (resets at exec, unlike wait4's ru_maxrss,
    which is inflated by the parent's RSS at fork time)."""
    try:
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) / 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def run_measured(label: str, argv: list[str], timeout_s: float = 900.0) -> Run:
    """Run argv in its own process group; measure it with wait4 (per-run peak RSS)."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        start = time.perf_counter()
        proc = subprocess.Popen(
            argv,
            stdout=out,
            stderr=err,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = start + timeout_s
        timed_out = False
        hwm = None
        while True:
            pid, status, ru = os.wait4(proc.pid, os.WNOHANG)
            if pid:
                break
            sample = read_hwm_mib(proc.pid)
            if sample is not None:
                hwm = sample if hwm is None else max(hwm, sample)
            if time.perf_counter() > deadline:
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                pid, status, ru = os.wait4(proc.pid, 0)
                break
            time.sleep(0.02)
        wall = time.perf_counter() - start
        proc.returncode = os.waitstatus_to_exitcode(status)  # keeps Popen consistent
        out.seek(0)
        err.seek(0)
        stdout = out.read().decode(errors="replace")
        stderr_lines = err.read().decode(errors="replace").count("\n")
    return Run(
        label=label,
        argv=argv,
        wall_s=wall,
        cpu_s=ru.ru_utime + ru.ru_stime,
        peak_rss_mib=(
            hwm if hwm is not None else ru.ru_maxrss / 1024
        ),  # ru_maxrss is KiB on Linux
        rss_source="VmHWM" if hwm is not None else "ru_maxrss",
        returncode=None if timed_out else proc.returncode,
        timed_out=timed_out,
        stderr_lines=stderr_lines,
        stdout=stdout[-4000:],
    )


def parse_last_json(text: str) -> dict:
    for line in reversed(text.strip().splitlines()):
        try:
            data = json.loads(line)
        except ValueError:
            continue
        if isinstance(data, dict):
            return data
    return {}


def du_bytes(path: Path, timeout_s: float) -> tuple[int | None, Run]:
    """`du` exits 1 on unreadable dirs but still prints a total: accept it as partial."""
    run = run_measured("du", ["du", "-sx", "-B1", str(path)], timeout_s)
    try:
        value = int(run.stdout.strip().splitlines()[-1].split()[0])
    except (IndexError, ValueError):
        value = None
    return value, run


def make_tree(
    root: Path, depth: int = 3, fanout: int = 8, files: int = 20, size: int = 4096
) -> None:
    payload = b"x" * size

    def build(d: Path, level: int) -> None:
        d.mkdir(parents=True, exist_ok=True)
        for i in range(files):
            (d / f"f{i}.dat").write_bytes(payload)
        if level < depth:
            for j in range(fanout):
                build(d / f"d{j}", level + 1)

    build(root, 0)
    os.link(root / "f0.dat", root / "hardlink.dat")
    os.symlink(root / "f1.dat", root / "symlink.dat")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "root", nargs="?", type=Path, help="directory to scan (default: synthetic tree)"
    )
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=900.0)
    ap.add_argument("--no-du", action="store_true", help="skip the du baseline")
    ap.add_argument(
        "--json", action="store_true", help="save results to bench/results/"
    )
    ap.add_argument(
        "--cmd",
        nargs=argparse.REMAINDER,
        help="custom scanner argv; {root} is replaced (must be last)",
    )
    args = ap.parse_args()

    tmp = None
    root = args.root
    if root is None:
        tmp = tempfile.TemporaryDirectory(prefix="clearspace-bench-")
        root = Path(tmp.name) / "tree"
        make_tree(root)
    root = root.resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    template = args.cmd or [sys.executable, "-m", "bench.scan_adapter", "{root}"]
    argv = [a.replace("{root}", str(root)) for a in template]

    du_value, du_run = (None, None) if args.no_du else du_bytes(root, args.timeout)
    runs: list[Run] = []
    for i in range(1, args.runs + 1):
        runs.append(run_measured(f"scan#{i}", argv, args.timeout))

    print(f"root: {root}")
    print(f"{'run':<8}{'wall s':>9}{'cpu s':>9}{'peak MiB':>10}{'rc':>5}")
    for r in ([du_run] if du_run else []) + runs:
        flag = " TIMEOUT" if r.timed_out else ""
        print(
            f"{r.label:<8}{r.wall_s:>9.2f}{r.cpu_s:>9.2f}{r.peak_rss_mib:>10.1f}{str(r.returncode):>5}{flag}"
        )

    ok = [r for r in runs if r.returncode == 0 and not r.timed_out]
    summary: dict = {"ok_runs": len(ok), "total_runs": len(runs)}
    if ok:
        summary["median_wall_s"] = statistics.median(r.wall_s for r in ok)
        summary["median_peak_rss_mib"] = statistics.median(r.peak_rss_mib for r in ok)
        data = parse_last_json(ok[-1].stdout)
        summary["scanner"] = data
        print(
            f"median: {summary['median_wall_s']:.2f}s, {summary['median_peak_rss_mib']:.1f} MiB peak"
        )
        if data:
            print(
                f"scanner: {data.get('files')} files, {data.get('dirs')} dirs, "
                f"first progress {data.get('first_progress_ms')} ms"
            )
        if du_value and data.get("bytes") is not None:
            delta = (data["bytes"] - du_value) / du_value * 100
            summary["bytes_vs_du_pct"] = delta
            print(f"bytes: scanner {data['bytes']} vs du {du_value} ({delta:+.2f}%)")
    else:
        print("no successful scan runs; see stderr/returncode above", file=sys.stderr)

    if args.json:
        out_dir = Path(__file__).parent / "results"
        out_dir.mkdir(exist_ok=True)
        path = out_dir / f"{time.strftime('%Y%m%d-%H%M%S')}.json"
        path.write_text(
            json.dumps(
                {"summary": summary, "du": du_value, "runs": [asdict(r) for r in runs]},
                indent=2,
            )
        )
        print(f"saved {path}")
    if tmp:
        tmp.cleanup()
    return 0 if ok and len(ok) == len(runs) else 1


if __name__ == "__main__":
    sys.exit(main())
