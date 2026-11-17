#!/usr/bin/env python3
"""Generate the shared, fully synthetic toolkit benchmark database."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path


SCHEMA = """
CREATE TABLE nodes (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER,
    name TEXT NOT NULL,
    is_dir INTEGER NOT NULL,
    size_blocks INTEGER NOT NULL,
    risk INTEGER NOT NULL,
    child_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX nodes_parent_size_idx ON nodes(parent_id, size_blocks DESC, name ASC);
"""


def generate(path: Path, *, wide_nodes: int = 1_000_000) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    connection = sqlite3.connect(path)
    try:
        connection.executescript(SCHEMA)
        connection.execute("PRAGMA journal_mode=OFF")
        connection.execute("PRAGMA synchronous=OFF")
        connection.execute("INSERT INTO nodes VALUES (1,NULL,'synthetic',1,0,0,0)")
        # Shape A: one directory with 200,000 direct children.
        connection.execute("INSERT INTO nodes VALUES (2,1,'huge-folder',1,0,0,200000)")
        connection.executemany(
            "INSERT INTO nodes(id,parent_id,name,is_dir,size_blocks,risk,child_count) "
            "VALUES (?,2,?,0,?,?,0)",
            (
                (3 + index, f"child-{index:06}.dat", (index % 128) + 1, index % 4)
                for index in range(200_000)
            ),
        )
        next_id = 200_003
        # Shape B: chain of depth 200.
        parent = 1
        chain_rows = []
        for depth in range(200):
            current = next_id + depth
            chain_rows.append((current, parent, f"chain-{depth:03}", 1, 1, 0, 1 if depth < 199 else 0))
            parent = current
        connection.executemany("INSERT INTO nodes VALUES (?,?,?,?,?,?,?)", chain_rows)
        next_id += len(chain_rows)
        # Shape C: a wide tree with exactly wide_nodes rows, including its root.
        wide_root = next_id
        connection.execute(
            "INSERT INTO nodes VALUES (?,?,?,1,0,0,?)",
            (wide_root, 1, "wide-tree", wide_nodes - 1),
        )
        remaining = wide_nodes - 1
        branch_count = min(1_000, remaining)
        branches = []
        for branch in range(branch_count):
            branch_id = next_id + 1 + branch
            child_count = remaining // branch_count + (branch < remaining % branch_count)
            branches.append((branch_id, wide_root, f"branch-{branch:04}", 1, 0, 0, child_count))
        connection.executemany("INSERT INTO nodes VALUES (?,?,?,?,?,?,?)", branches)
        leaf_id = next_id + 1 + branch_count
        batch = []
        for row in branches:
            children = row[-1]
            for offset in range(children):
                batch.append((leaf_id, row[0], f"entry-{offset:04}", 0,
                              (offset % 128) + 1, offset % 4, 0))
                leaf_id += 1
                if len(batch) == 10_000:
                    connection.executemany("INSERT INTO nodes VALUES (?,?,?,?,?,?,?)", batch)
                    batch.clear()
        if batch:
            connection.executemany("INSERT INTO nodes VALUES (?,?,?,?,?,?,?)", batch)
        connection.execute(
            "UPDATE nodes SET child_count=(SELECT COUNT(*) FROM nodes child "
            "WHERE child.parent_id=nodes.id) WHERE is_dir=1"
        )
        directory_ids = [
            row[0] for row in connection.execute(
                "SELECT id FROM nodes WHERE is_dir=1 ORDER BY id DESC"
            )
        ]
        connection.executemany(
            "UPDATE nodes SET size_blocks=(SELECT COALESCE(SUM(size_blocks),0) "
            "FROM nodes child WHERE child.parent_id=nodes.id) WHERE id=?",
            ((node_id,) for node_id in directory_ids),
        )
        connection.commit()
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--wide-nodes", type=int, default=1_000_000)
    args = parser.parse_args()
    generate(args.output, wide_nodes=args.wide_nodes)
    print(args.output.resolve())


if __name__ == "__main__":
    main()
