# Clearspace UI toolkit spike

Isolated workspace. The application and scanner are not dependencies of these
crates. All widgets read the same generated SQLite fixture and do not access
filesystem paths outside `spike/data/`.

Generate the common synthetic fixture once with:

```sh
python3 spike/generate_dataset.py spike/data/nodes.sqlite
```

Each crate is built and benchmarked independently. `--bench <database>` runs
the same headless SQLite workload and prints one JSON line. This measures the
data/model path only; it does not measure window startup, frame pacing, idle
CPU, or rendering. Those fields remain `null` until the spike has a GUI-driven
benchmark harness.

```sh
cargo build --release --manifest-path spike/gtk4-rs/Cargo.toml
cargo build --release --manifest-path spike/slint/Cargo.toml
cargo build --release --manifest-path spike/rune/Cargo.toml
spike/target/release/clearspace-spike-gtk --bench spike/data/nodes.sqlite
spike/target/release/clearspace-spike-slint --bench spike/data/nodes.sqlite
spike/target/release/clearspace-spike-rune --bench spike/data/nodes.sqlite
```

The JSON schema is shared: `first_page_ms` is the first measured page query,
`expand_p95_ms` is the p95 across all measured page queries, and
`live_nodes_peak` is the page size plus three synthetic support rows.
`binary_mib` is the debug executable size in this exploratory build. GUI-only
metrics are explicitly null for headless runs. The benchmark reads five pages
of 200 records from the generated wide directory (1,000 children), repeated
ten times. The fixture contains 1,201,202 rows by default.

## Current headless baseline

Measured on the generated default fixture with three consecutive debug runs
per toolkit. Values below are medians of those runs; query timings are in ms.
This is a SQLite/model-path smoke baseline, not a UI performance comparison.

| Toolkit | First page | Expand p95 | Live nodes peak | Debug binary |
| --- | ---: | ---: | ---: | ---: |
| GTK-rs | 1.063 | 0.995 | 203 | 59.592 MiB |
| Slint | 1.076 | 1.342 | 203 | 341.982 MiB |
| Rune | 1.203 | 0.935 | 203 | 589.303 MiB |

First-page timing includes opening the SQLite connection and can vary with
cache state. Debug executable sizes are not representative of release builds.
The next measurement step is a GUI-driven run under a compositor that records
time to first presented frame, frame-time p95/missed frames during scripted
expand/scroll interactions, and idle CPU. Until then those fields remain null.
