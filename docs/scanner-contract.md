# Scanner SQLite and progress contract

Version: `1`

This contract separates filesystem traversal from the GTK process. The scanner
is read-only. It receives a root and a SQLite database path as separate command
arguments; it never invokes a shell, requests elevation, or accesses the network.

## SQLite database

The scanner creates the database and publishes it only after closing its final
write transaction. Readers open the completed database read-only. Identifiers
are stable for the lifetime of one scan only.

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE nodes (
    id          INTEGER PRIMARY KEY,
    parent_id   INTEGER REFERENCES nodes(id),
    name        TEXT NOT NULL,
    is_dir      INTEGER NOT NULL CHECK (is_dir IN (0, 1)),
    size_blocks INTEGER NOT NULL CHECK (size_blocks >= 0),
    mtime       INTEGER,
    error       TEXT,
    partial     INTEGER NOT NULL DEFAULT 0 CHECK (partial IN (0, 1))
);

CREATE INDEX nodes_parent_size_idx ON nodes(parent_id, size_blocks DESC);
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
stderr. Every object has `protocol_version: 1` and an `event` string. Progress
objects contain counters only, not file names or contents.

Example stream:

```jsonl
{"protocol_version":1,"event":"started"}
{"protocol_version":1,"event":"progress","directories":128,"files":2048,"errors":1,"allocated_bytes":73400320}
{"protocol_version":1,"event":"completed","root_id":1,"nodes":2177,"directories":129,"files":2048,"errors":1,"symlinks_skipped":3,"other_filesystems_skipped":0,"allocated_bytes":75497472,"duration_ms":932}
```

`started` is emitted once after argument and database initialization. `progress`
may be emitted zero or more times; its counters are cumulative and monotonic.
The final event is exactly one of:

- `completed`: traversal finished. It includes `root_id`, node and skip/error
  counts, allocated bytes, and `duration_ms`. A nonzero `errors` count means the
  inventory is partial even though the process completed successfully.
- `failed`: fatal setup or database error. It contains a stable `code` and a
  human-readable `message`; no success may be inferred from earlier progress.

After the terminal event, stdout closes. Exit code `0` means the scan completed,
possibly with per-node partial errors. A nonzero exit code means it failed. The
Python caller must reject a missing terminal event, malformed JSON, an
unsupported protocol version, or a mismatch between exit status and terminal
event.

## Process and safety requirements

The Python caller invokes `clearspace-scan` with an argument vector and
`shell=False`, reads stdout incrementally, and treats all event data as
untrusted. The scanner is read-only, does not follow symlinks, stays on the root
filesystem, and does not use `sudo`, `pkexec`, or any other elevation. Root and
excluded paths are explicit arguments/configuration, never machine-specific
constants. The SQLite database is created in Clearspace's private state/cache
directory and replaced atomically only after a successful finalization.

The Rust implementation lives in the independent `scanner/` crate. It uses
`jwalk` for parallel directory enumeration and `rusqlite` with bundled SQLite
for local database writes, avoiding a dependency on a system SQLite CLI or
shared library. Build it with `cargo build --release --manifest-path
scanner/Cargo.toml`; invoke it as
`clearspace-scan <root> --db <database> [--exclude <path> ...]`.
