# Scanner SQLite and progress contract

Database schema version: `1`
Progress JSONL protocol version: `2`

This contract separates filesystem traversal from the GTK process. The scanner
is read-only. It receives a root and a SQLite database path as separate command
arguments; it never invokes a shell, requests elevation, or accesses the network.

## SQLite database

The scanner creates the database and publishes it only after closing its final
write transaction. Readers open the completed database read-only. Identifiers
are stable for the lifetime of one scan only.

```sql
PRAGMA foreign_keys = ON;
PRAGMA user_version = 1;

CREATE TABLE nodes (
    id          INTEGER PRIMARY KEY,
    parent_id   INTEGER REFERENCES nodes(id),
    name        TEXT NOT NULL,
    is_dir      INTEGER NOT NULL CHECK (is_dir IN (0, 1)),
    size_blocks INTEGER NOT NULL CHECK (size_blocks >= 0),
    mtime       INTEGER,
    error       TEXT,
    partial     INTEGER NOT NULL DEFAULT 0 CHECK (partial IN (0, 1)),
    child_count INTEGER NOT NULL DEFAULT 0,
    child_size_blocks INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX nodes_parent_size_idx ON nodes(parent_id, size_blocks DESC, name COLLATE BINARY ASC);
```

The root is the single row whose `parent_id` is `NULL`. `name` is a basename,
not an absolute path. `size_blocks` counts allocated 512-byte blocks, matching
`st_blocks`; clients convert to bytes with `size_blocks * 512`. A hardlinked
regular-file inode contributes its blocks once per scan (`st_dev`, `st_ino`).
Directories include their own allocated blocks plus the measured descendants.
`mtime` is nullable and, when present, stores `st_mtime_ns` (nanoseconds since
the Unix epoch). `error` contains a safe-to-display read or traversal failure;
it must not contain file contents. `partial=1` means the size is incomplete,
including a directory with unreadable descendants. Symlinks are not followed
and are omitted from `nodes`; paths on another `st_dev` are omitted.

Insert and update rows in bounded transactions. Directory totals may be updated
after children finish. A failed child read remains represented by an error row
and must not be reported as a complete size. The database contains filesystem
names and metadata, so it is local, temporary scan state and must not be added
to action history or sent elsewhere.

### Query patterns

Fetch a directory's largest children without loading the whole tree:

```sql
SELECT id, parent_id, name, is_dir, size_blocks, mtime, error, partial
FROM nodes
WHERE parent_id = ?
ORDER BY size_blocks DESC, name COLLATE BINARY ASC
LIMIT ?;
```

To show the omitted row, run a second aggregate query with the same ordering and
offset equal to the visible limit:

```sql
SELECT COUNT(*) AS item_count, COALESCE(SUM(size_blocks), 0) AS size_blocks
FROM (
    SELECT size_blocks
    FROM nodes
    WHERE parent_id = ?
    ORDER BY size_blocks DESC, name COLLATE BINARY ASC
    LIMIT -1 OFFSET ?
);
```

The aggregate is a UI row, not a filesystem node and is never selectable. The
sum of visible rows and the aggregate row must equal the directory's measured
children total.

## Progress stream

The process writes UTF-8 JSON Lines to stdout: exactly one JSON object per line,
terminated by `\n`. Stdout is reserved for this protocol; diagnostics go to
stderr. Every object has `protocol_version: 2` and an `event` string. Progress
objects include local display paths and bounded item names, but never file
contents. These values are untrusted display data and cannot authorize an action.

Example stream:

```jsonl
{"protocol_version":2,"event":"started"}
{"protocol_version":2,"event":"progress","directories":43,"dirs_done":43,"dirs_queued":9,"dirs_total_est":52,"files":2048,"errors":1,"allocated_bytes":73400320,"current_path":"/scan/root/example","largest_items":[{"name":"large.bin","path":"/scan/root/large.bin","bytes":7340032}]}
{"protocol_version":2,"event":"completed","root_id":1,"nodes":2177,"directories":130,"dirs_done":130,"dirs_queued":0,"dirs_total_est":130,"files":2048,"errors":1,"symlinks_skipped":3,"other_filesystems_skipped":0,"allocated_bytes":75497472,"current_path":"/scan/root","largest_items":[{"name":"large.bin","path":"/scan/root/large.bin","bytes":7340032}],"duration_ms":932}
```

`started` is emitted once after argument parsing and before filesystem traversal. `progress`
is emitted at the bounded batch interval and once more before `completed`, so
small trees also publish their final folder count. `directories`, `dirs_done`, `dirs_total_est`,
`files`, `errors`, and `allocated_bytes` are cumulative and monotonic. `dirs_queued`
is the number of discovered directories whose enumeration has not completed and may
decrease. At each snapshot `dirs_total_est = dirs_done + dirs_queued`; it rises as
new child directories are discovered. The live `largest_items` list is the four
largest observed regular files, ordered by allocated bytes descending; it may
change as larger files are found. Directory totals are aggregated after traversal,
so they are not included in this live list.

The final event is exactly one of:

- `completed`: traversal finished. It includes `root_id`, node and skip/error
  counts, allocated bytes, `dirs_done`, `dirs_queued=0`, final `dirs_total_est`,
  `current_path`, and `duration_ms`. A nonzero `errors` count means the inventory
  is partial even though the process completed successfully.
- `failed`: fatal setup or database error. It contains a stable `code` and a
  human-readable `message`; no success may be inferred from earlier progress.

After the terminal event, stdout closes. Exit code `0` means the scan completed,
possibly with per-node partial errors. A nonzero exit code means it failed. The
Python caller must reject a missing terminal event, malformed JSON, an
unsupported protocol version, or a mismatch between exit status and terminal
event.

### GTK-independent progress view

The Python application adapts the Rust protocol v2 events (or Python scanner
callbacks) to a scanner-independent GTK-free `ProgressEvent`. It obtains
filesystem context locally with `os.statvfs`; `fs_used_bytes`, `fs_total_bytes`,
and `fs_used_inodes` are not sent over the scanner protocol. For a scan root that
is a mount point, the UI may compare scanned allocated bytes with `fs_used_bytes`.
For subfolders, filesystem capacity is context only and folder progress uses the
directory estimate, optionally informed by a previous complete scan of the same
root stored in local JSONL history.

```jsonl
{"protocol_version":2,"event":"progress","dirs_done":43,"dirs_queued":9,"dirs_total_est":52,"files":2048,"errors":0,"unreadable_count":0,"bytes":73400320,"elapsed_ms":1200,"current_path":"/scan/root/example","largest_items":[{"name":"example","path":"/scan/root/example","bytes":7340032}],"state":"running","partial":false}
{"protocol_version":2,"event":"progress","dirs_done":47,"dirs_queued":14,"dirs_total_est":61,"files":2100,"errors":2,"unreadable_count":2,"bytes":75497472,"elapsed_ms":1300,"current_path":"/scan/root/another","largest_items":[{"name":"example","path":"/scan/root/example","bytes":7340032}],"state":"running","partial":true}
{"protocol_version":2,"event":"completed","dirs_done":61,"dirs_queued":0,"dirs_total_est":61,"files":2177,"errors":2,"unreadable_count":2,"bytes":75497472,"elapsed_ms":1500,"largest_items":[{"name":"example","path":"/scan/root/example","bytes":7340032}],"state":"done","partial":true}
```

`dirs_total_est` is nonnegative and may increase as directories are discovered.
`dirs_done`, `dirs_queued`, `files`,
`bytes`, `errors`, `unreadable_count`, and `elapsed_ms` are nonnegative cumulative values; `unreadable_count` mirrors the count of per-entry read errors and each stored node error carries a stable `[permission]`, `[not_found]`, or `[io]` category. `bytes` means
allocated bytes (`st_blocks * 512`). `current_path` is local display data only;
it is untrusted and cannot authorize an action. `largest_items` is an optional
bounded list of up to four observed entries with display name, local path, and
allocated bytes; consumers never use it to authorize an action. `state` is one of `running`,
`paused`, `cancelled`, `done`, or `error`. Cancellation is cooperative and a
terminal `cancelled` event sets `partial` to true; the partial inventory remains
available.

The Rust binary emits protocol v2 live progress fields. Process pause/resume
applies `SIGSTOP`/`SIGCONT` only to the directly spawned scanner child process
(never through a shell); the controller owns that process handle and does not
signal arbitrary process IDs. A thread-based scanner instead cooperates through
its pause event.

## Process and safety requirements

The Python caller invokes `clearspace-scan` with an argument vector and
`shell=False`, reads stdout incrementally, and treats all event data as
untrusted. The scanner is read-only, does not follow symlinks, stays on the root
filesystem, and does not use `sudo`, `pkexec`, or any other elevation. Root and
excluded paths are explicit arguments/configuration, never machine-specific
constants. The SQLite database is created in a private temporary directory
outside the scan root and published atomically only after a successful
finalization. This keeps the database out of scans such as `/home` itself.

The Rust implementation lives in the independent `scanner/` crate. It uses
`jwalk` for parallel directory enumeration and `rusqlite` with bundled SQLite
for local database writes, avoiding a dependency on a system SQLite CLI or
shared library. Build it with `cargo build --release --manifest-path
scanner/Cargo.toml`; invoke it as
`clearspace-scan <root> --db <database> [--exclude <path> ...]` (or `clearspace-scan --version` to print binary, SQLite schema, and protocol versions). The `completed` event includes `"schema_version": 1`, matching `PRAGMA user_version` in the SQLite file.
