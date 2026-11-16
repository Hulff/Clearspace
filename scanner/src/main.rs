use jwalk::WalkDir;
use rusqlite::{Connection, params};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Instant;

#[derive(Default)]
struct Counts {
    nodes: u64,
    directories: u64,
    files: u64,
    errors: u64,
    symlinks_skipped: u64,
    other_filesystems_skipped: u64,
    allocated_bytes: u64,
    first_progress_ms: Option<u128>,
}

struct TempDatabase(PathBuf);

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn emit(event: &str, fields: &str) -> io::Result<()> {
    writeln!(
        io::stdout().lock(),
        "{{\"protocol_version\":1,\"event\":\"{event}\"{fields}}}"
    )?;
    io::stdout().flush()
}

fn json_escape(value: &str) -> String {
    let mut result = String::new();
    for ch in value.chars() {
        match ch {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => result.push_str(&format!("\\u{:04x}", c as u32)),
            c => result.push(c),
        }
    }
    result
}

fn parse_args() -> Result<(PathBuf, PathBuf, Vec<PathBuf>), String> {
    let mut args = env::args_os().skip(1);
    let root = PathBuf::from(
        args.next()
            .ok_or("usage: clearspace-scan <root> --db <path> [--exclude <path> ...]")?,
    );
    let mut db = None;
    let mut excludes = Vec::new();
    while let Some(arg) = args.next() {
        if arg == "--db" {
            db = Some(PathBuf::from(args.next().ok_or("--db requires a path")?));
        } else if arg == "--exclude" {
            excludes.push(PathBuf::from(
                args.next().ok_or("--exclude requires a path")?,
            ));
        } else {
            return Err(format!("unknown argument: {}", arg.to_string_lossy()));
        }
    }
    Ok((root, db.ok_or("--db is required")?, excludes))
}

struct NodeRow<'a> {
    parent_id: Option<i64>,
    name: &'a str,
    is_dir: bool,
    blocks: u64,
    mtime: Option<i64>,
    error: Option<&'a str>,
    partial: bool,
    path: &'a Path,
    depth: usize,
}

fn insert(conn: &Connection, row: NodeRow<'_>) -> rusqlite::Result<i64> {
    conn.execute("INSERT INTO nodes(parent_id,name,is_dir,size_blocks,mtime,error,partial) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![row.parent_id, row.name, row.is_dir, row.blocks as i64, row.mtime, row.error, row.partial])?;
    let id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO scan_paths(path,id,depth) VALUES (?1,?2,?3)",
        params![row.path.to_string_lossy(), id, row.depth as i64],
    )?;
    Ok(id)
}

fn aggregate_directories(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE INDEX nodes_parent_idx ON nodes(parent_id);
         UPDATE nodes SET
           size_blocks=size_blocks+COALESCE((SELECT SUM(child.size_blocks) FROM nodes child WHERE child.parent_id=nodes.id AND child.is_dir=0),0),
           partial=CASE WHEN EXISTS(SELECT 1 FROM nodes child WHERE child.parent_id=nodes.id AND child.partial=1) THEN 1 ELSE partial END
         WHERE is_dir=1;",
    )
    .map_err(|error| format!("aggregate direct children: {error}"))?;

    let directories: Vec<(i64, Option<i64>)> = {
        let mut statement = conn
            .prepare("SELECT nodes.id,nodes.parent_id FROM nodes JOIN scan_paths ON scan_paths.id=nodes.id WHERE nodes.is_dir=1 ORDER BY scan_paths.depth DESC")
            .map_err(|error| format!("prepare directory aggregation: {error}"))?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|error| format!("read directory aggregation order: {error}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("collect directory aggregation order: {error}"))?
    };
    for (directory_id, parent_id) in directories {
        let Some(parent_id) = parent_id else { continue };
        let (blocks, partial): (i64, bool) = conn
            .query_row(
                "SELECT size_blocks,partial FROM nodes WHERE id=?1",
                [directory_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| format!("read directory total: {error}"))?;
        conn.execute(
            "UPDATE nodes SET size_blocks=size_blocks+?1,partial=CASE WHEN ?2 THEN 1 ELSE partial END WHERE id=?3",
            params![blocks, partial, parent_id],
        )
        .map_err(|error| format!("propagate directory total: {error}"))?;
    }
    conn.execute_batch("DROP INDEX nodes_parent_idx")
        .map_err(|error| format!("drop temporary aggregation index: {error}"))?;
    Ok(())
}

fn mtime_ns(metadata: &fs::Metadata) -> i64 {
    metadata
        .mtime()
        .saturating_mul(1_000_000_000)
        .saturating_add(metadata.mtime_nsec())
}

fn parent_id(conn: &Connection, path: &Path, root: &Path) -> Result<Option<i64>, String> {
    if path == root {
        return Ok(None);
    }
    let parent_path = path
        .parent()
        .ok_or_else(|| format!("entry has no parent: {}", path.display()))?;
    conn.query_row(
        "SELECT id FROM scan_paths WHERE path=?1",
        [parent_path.to_string_lossy().as_ref()],
        |row| row.get(0),
    )
    .map(Some)
    .map_err(|error| format!("parent row missing for {}: {error}", path.display()))
}

fn process(
    root_arg: &Path,
    db_arg: &Path,
    exclusions: &[PathBuf],
) -> Result<(Counts, i64), String> {
    let absolute_root = if root_arg.is_absolute() {
        root_arg.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|e| e.to_string())?
            .join(root_arg)
    };
    let mut current = PathBuf::from("/");
    for component in absolute_root.components().skip(1) {
        current.push(component);
        let info = fs::symlink_metadata(&current)
            .map_err(|e| format!("root component {}: {e}", current.display()))?;
        if info.file_type().is_symlink() {
            return Err(format!(
                "root contains symlink component: {}",
                current.display()
            ));
        }
    }
    let root = fs::canonicalize(&absolute_root).map_err(|e| format!("root: {e}"))?;
    let root_meta = fs::symlink_metadata(&root).map_err(|e| format!("root metadata: {e}"))?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return Err("root must be a real directory, not a symlink".into());
    }
    let device = root_meta.dev();
    let cwd = env::current_dir().map_err(|e| e.to_string())?;
    let db = if db_arg.is_absolute() {
        db_arg.to_path_buf()
    } else {
        cwd.join(db_arg)
    };
    if db.starts_with(&root) {
        return Err("database must be outside scan root".into());
    }
    let excludes: HashSet<PathBuf> = exclusions
        .iter()
        .filter_map(|p| fs::canonicalize(p).ok())
        .collect();
    let parent = db.parent().ok_or("database path has no parent")?;
    fs::create_dir_all(parent).map_err(|e| format!("database directory: {e}"))?;
    let temp = db.with_extension(format!(
        "scan-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    if temp.exists() {
        return Err("temporary database path already exists".into());
    }
    let _temp_guard = TempDatabase(temp.clone());
    let conn = Connection::open(&temp).map_err(|e| format!("database: {e}"))?;
    conn.execute_batch("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA foreign_keys=ON;
        CREATE TABLE nodes(id INTEGER PRIMARY KEY,parent_id INTEGER REFERENCES nodes(id),name TEXT NOT NULL,is_dir INTEGER NOT NULL CHECK(is_dir IN (0,1)),size_blocks INTEGER NOT NULL CHECK(size_blocks>=0),mtime INTEGER,error TEXT,partial INTEGER NOT NULL DEFAULT 0 CHECK(partial IN (0,1)));
        CREATE TABLE scan_paths(path TEXT PRIMARY KEY,id INTEGER NOT NULL,depth INTEGER NOT NULL);")
        .map_err(|e|format!("schema: {e}"))?;
    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| e.to_string())?;
    let root_name = root
        .file_name()
        .unwrap_or(root.as_os_str())
        .to_string_lossy();
    let root_id = insert(
        &conn,
        NodeRow {
            parent_id: None,
            name: &root_name,
            is_dir: true,
            blocks: root_meta.blocks(),
            mtime: Some(mtime_ns(&root_meta)),
            error: None,
            partial: false,
            path: &root,
            depth: 0,
        },
    )
    .map_err(|e| format!("root row: {e}"))?;
    let mut counts = Counts {
        nodes: 1,
        directories: 1,
        allocated_bytes: root_meta.blocks().saturating_mul(512),
        ..Counts::default()
    };
    let mut hardlinks = HashSet::new();
    let skipped_mounts = Arc::new(AtomicU64::new(0));
    let skipped_mounts_cb = Arc::clone(&skipped_mounts);
    let skipped_symlinks = Arc::new(AtomicU64::new(0));
    let skipped_symlinks_cb = Arc::clone(&skipped_symlinks);
    let excluded_cb = Arc::new(excludes);
    let excluded_for_cb = Arc::clone(&excluded_cb);
    let walker = WalkDir::new(&root)
        .skip_hidden(false)
        .follow_links(false)
        .process_read_dir(move |_depth, _path, _state, entries| {
            entries.retain_mut(|item| {
                let Ok(entry) = item else {
                    return true;
                };
                let path = entry.path();
                if excluded_for_cb.contains(&path) {
                    entry.read_children_path = None;
                    return false;
                }
                match entry.metadata() {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        skipped_symlinks_cb.fetch_add(1, Ordering::Relaxed);
                        false
                    }
                    Ok(meta) if meta.dev() != device => {
                        skipped_mounts_cb.fetch_add(1, Ordering::Relaxed);
                        entry.read_children_path = None;
                        false
                    }
                    Ok(_) => true,
                    Err(_) => true,
                }
            });
        });
    let progress_started = Instant::now();
    let mut batch = 0u64;
    for item in walker.try_into_iter().map_err(|e| format!("walker: {e}"))? {
        let entry = match item {
            Ok(entry) => entry,
            Err(error) => {
                counts.errors += 1;
                let path = error.path().unwrap_or(&root);
                let msg = format!("não foi possível ler: {error}");
                if path == root {
                    conn.execute(
                        "UPDATE nodes SET error=?1,partial=1 WHERE id=?2",
                        params![msg, root_id],
                    )
                    .map_err(|e| format!("mark root partial: {e}"))?;
                    continue;
                }
                let parent = parent_id(&conn, path, &root)?;
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                insert(
                    &conn,
                    NodeRow {
                        parent_id: parent,
                        name: &name,
                        is_dir: false,
                        blocks: 0,
                        mtime: None,
                        error: Some(&msg),
                        partial: true,
                        path,
                        depth: entry_depth_hint(path, &root),
                    },
                )
                .map_err(|e| format!("insert read error: {e}"))?;
                counts.nodes += 1;
                continue;
            }
        };
        if entry.depth() == 0 {
            if let Some(error) = &entry.read_children_error {
                counts.errors += 1;
                conn.execute(
                    "UPDATE nodes SET error=?1,partial=1 WHERE id=?2",
                    params![format!("não foi possível ler: {error}"), root_id],
                )
                .map_err(|e| e.to_string())?;
            }
            continue;
        }
        let path = entry.path();
        let traversal_error = entry
            .read_children_error
            .as_ref()
            .map(|e| format!("não foi possível ler: {e}"));
        if traversal_error.is_some() {
            counts.errors += 1;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                counts.errors += 1;
                let parent = parent_id(&conn, &path, &root)?;
                let msg = format!("não foi possível ler: {error}");
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                insert(
                    &conn,
                    NodeRow {
                        parent_id: parent,
                        name: &name,
                        is_dir: false,
                        blocks: 0,
                        mtime: None,
                        error: Some(&msg),
                        partial: true,
                        path: &path,
                        depth: entry.depth(),
                    },
                )
                .map_err(|e| format!("insert metadata error: {e}"))?;
                counts.nodes += 1;
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            counts.symlinks_skipped += 1;
            continue;
        }
        if metadata.dev() != device {
            counts.other_filesystems_skipped += 1;
            continue;
        }
        let parent = parent_id(&conn, &path, &root)?;
        let is_dir = metadata.is_dir();
        let mut blocks = metadata.blocks();
        if !is_dir && metadata.nlink() > 1 && !hardlinks.insert((metadata.dev(), metadata.ino())) {
            blocks = 0;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        insert(
            &conn,
            NodeRow {
                parent_id: parent,
                name: &name,
                is_dir,
                blocks,
                mtime: Some(mtime_ns(&metadata)),
                error: traversal_error.as_deref(),
                partial: traversal_error.is_some(),
                path: &path,
                depth: entry.depth(),
            },
        )
        .map_err(|e| format!("insert node: {e}"))?;
        counts.nodes += 1;
        counts.allocated_bytes = counts
            .allocated_bytes
            .saturating_add(blocks.saturating_mul(512));
        if is_dir {
            counts.directories += 1;
        } else {
            counts.files += 1;
        }
        batch += 1;
        if batch >= 1000 {
            if counts.first_progress_ms.is_none() {
                counts.first_progress_ms = Some(progress_started.elapsed().as_millis());
            }
            conn.execute_batch("COMMIT; BEGIN IMMEDIATE")
                .map_err(|e| format!("commit batch: {e}"))?;
            emit(
                "progress",
                &format!(
                    ",\"directories\":{},\"files\":{},\"errors\":{},\"allocated_bytes\":{}",
                    counts.directories, counts.files, counts.errors, counts.allocated_bytes
                ),
            )
            .map_err(|e| e.to_string())?;
            batch = 0;
        }
    }
    aggregate_directories(&conn)?;
    counts.other_filesystems_skipped = skipped_mounts.load(Ordering::Relaxed);
    counts.symlinks_skipped = skipped_symlinks.load(Ordering::Relaxed);
    conn.execute_batch("DROP TABLE scan_paths; CREATE INDEX nodes_parent_size_idx ON nodes(parent_id,size_blocks DESC); COMMIT;")
        .map_err(|e|format!("finalize database: {e}"))?;
    drop(conn);
    fs::rename(&temp, &db).map_err(|e| format!("publish database: {e}"))?;
    Ok((counts, root_id))
}

fn entry_depth_hint(path: &Path, root: &Path) -> usize {
    path.strip_prefix(root)
        .map(|p| p.components().count())
        .unwrap_or(0)
}

fn main() {
    let started = Instant::now();
    let (root, db, excludes) = match parse_args() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2)
        }
    };
    if let Err(e) = emit("started", "") {
        eprintln!("{e}");
        std::process::exit(1);
    }
    match process(&root, &db, &excludes) {
        Ok((c, root_id)) => {
            let first_progress_ms = c
                .first_progress_ms
                .map_or_else(|| "null".to_owned(), |value| value.to_string());
            let fields = format!(
                ",\"root_id\":{root_id},\"nodes\":{},\"directories\":{},\"dirs\":{},\"files\":{},\"errors\":{},\"symlinks_skipped\":{},\"other_filesystems_skipped\":{},\"allocated_bytes\":{},\"bytes\":{},\"first_progress_ms\":{},\"duration_ms\":{}",
                c.nodes,
                c.directories,
                c.directories,
                c.files,
                c.errors,
                c.symlinks_skipped,
                c.other_filesystems_skipped,
                c.allocated_bytes,
                c.allocated_bytes,
                first_progress_ms,
                started.elapsed().as_millis()
            );
            let _ = emit("completed", &fields);
        }
        Err(error) => {
            let fields = format!(
                ",\"code\":\"scan_failed\",\"message\":\"{}\"",
                json_escape(&error)
            );
            let _ = emit("failed", &fields);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempTree(PathBuf);
    impl TempTree {
        fn new() -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path =
                env::temp_dir().join(format!("clearspace-scan-test-{}-{id}", std::process::id()));
            fs::create_dir_all(&path).expect("create test temp directory");
            Self(path)
        }
    }
    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn scans_hidden_files_hardlinks_symlinks_and_aggregates() {
        let temp = TempTree::new();
        let root = temp.0.join("root");
        fs::create_dir_all(root.join("nested")).expect("create nested directory");
        fs::write(root.join(".hidden"), vec![1u8; 8192]).expect("write hidden file");
        fs::write(root.join("nested/payload"), vec![2u8; 4096]).expect("write payload");
        fs::hard_link(root.join("nested/payload"), root.join("hardlink")).expect("create hardlink");
        let outside = temp.0.join("outside");
        fs::create_dir_all(&outside).expect("create outside directory");
        fs::write(outside.join("secret"), vec![3u8; 4096]).expect("write outside payload");
        std::os::unix::fs::symlink(&outside, root.join("linked")).expect("create symlink");
        let db = temp.0.join("state/scan.sqlite");

        let (counts, root_id) = process(&root, &db, &[]).expect("scan fixture");
        let conn = Connection::open(&db).expect("open output database");
        let root_size: i64 = conn
            .query_row(
                "SELECT size_blocks FROM nodes WHERE id=?1",
                [root_id],
                |r| r.get(0),
            )
            .expect("query root size");
        let hidden: i64 = conn
            .query_row("SELECT COUNT(*) FROM nodes WHERE name='.hidden'", [], |r| {
                r.get(0)
            })
            .expect("query hidden file");
        let linked: i64 = conn
            .query_row("SELECT COUNT(*) FROM nodes WHERE name='linked'", [], |r| {
                r.get(0)
            })
            .expect("query symlink");
        let payload_blocks: u64 = fs::metadata(root.join("nested/payload"))
            .expect("stat payload")
            .blocks();
        assert_eq!(hidden, 1);
        assert_eq!(linked, 0);
        assert_eq!(counts.symlinks_skipped, 1);
        assert_eq!(counts.files, 3);
        assert_eq!(
            root_size as u64,
            fs::metadata(&root).expect("stat root").blocks()
                + fs::metadata(root.join(".hidden"))
                    .expect("stat hidden")
                    .blocks()
                + fs::metadata(root.join("nested"))
                    .expect("stat nested")
                    .blocks()
                + payload_blocks
        );
    }

    #[test]
    fn records_unreadable_directory_as_partial_when_permissions_are_enforced() {
        let temp = TempTree::new();
        let root = temp.0.join("root");
        let blocked = root.join("blocked");
        fs::create_dir_all(&blocked).expect("create blocked directory");
        fs::write(blocked.join("secret"), b"data").expect("write child");
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000))
            .expect("remove permissions");
        let can_read = fs::read_dir(&blocked).is_ok();
        let db = temp.0.join("scan.sqlite");
        let (counts, _) = process(&root, &db, &[]).expect("scan permission fixture");
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o700))
            .expect("restore permissions");
        if !can_read {
            let conn = Connection::open(db).expect("open output database");
            let partial: i64 = conn
                .query_row("SELECT partial FROM nodes WHERE name='blocked'", [], |r| {
                    r.get(0)
                })
                .expect("query partial marker");
            assert_eq!(partial, 1);
            assert!(counts.errors > 0);
        }
    }

    #[test]
    fn scans_a_large_synthetic_tree_without_using_home() {
        let temp = TempTree::new();
        let root = temp.0.join("root");
        fs::create_dir_all(&root).expect("create root");
        for i in 0..1500 {
            fs::write(root.join(format!("file-{i}")), b"x").expect("write synthetic file");
        }
        let db = temp.0.join("scan.sqlite");
        let (counts, _) = process(&root, &db, &[]).expect("scan large fixture");
        assert_eq!(counts.files, 1500);
    }
}
