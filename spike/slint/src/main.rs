use rusqlite::{Connection, params};
use slint::{Color, ModelRc, VecModel};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    path::PathBuf,
    rc::Rc,
    thread,
    time::Instant,
};

slint::include_modules!();
const PAGE: usize = 200;
const BENCH_PARENT: i64 = 200_203;
#[derive(Clone, Debug)]
struct Node {
    id: i64,
    parent: i64,
    name: String,
    dir: bool,
    blocks: i64,
    risk: i64,
    count: i64,
    depth: i32,
    generation: u64,
    expanded: bool,
    loaded: usize,
}
struct UiState {
    nodes: HashMap<i64, Node>,
    order: Vec<i64>,
    expanded: HashSet<i64>,
    selected: HashSet<i64>,
    generations: HashMap<i64, u64>,
    loading: HashSet<i64>,
    aggregates: HashMap<i64, (usize, i64)>,
    database: PathBuf,
    model: Rc<VecModel<TreeRow>>,
    window: slint::Weak<MainWindow>,
    started: Instant,
    first_page: Option<f64>,
    bench: bool,
}
thread_local! { static APP_STATE: RefCell<Option<Rc<RefCell<UiState>>>> = const { RefCell::new(None) }; }

fn row_for(n: &Node, kind: i32, name: String, size: i64, indent: i32) -> TreeRow {
    let (risk, color) = match n.risk {
        0 => ("Low", Color::from_rgb_u8(110, 205, 130)),
        1 => ("Moderate", Color::from_rgb_u8(240, 190, 90)),
        2 => ("Your data", Color::from_rgb_u8(240, 130, 90)),
        _ => ("Critical", Color::from_rgb_u8(250, 90, 100)),
    };
    TreeRow {
        id: n.id as i32,
        depth: n.depth,
        name: name.into(),
        size: format!("{:.1} MiB", size as f64 * 512.0 / 1048576.0).into(),
        risk: risk.into(),
        risk_color: color,
        indent: indent * 18,
        expanded: n.expanded,
        expandable: n.dir && n.count > 0,
        checked: false,
        kind,
    }
}
fn db_page(path: PathBuf, parent: i64, offset: usize) -> Result<(Vec<Node>, usize, i64), String> {
    let db = Connection::open(path).map_err(|e| e.to_string())?;
    let total: i64 = db
        .query_row("SELECT child_count FROM nodes WHERE id=?", [parent], |r| {
            r.get(0)
        })
        .map_err(|e| e.to_string())?;
    let mut q=db.prepare("SELECT id,parent_id,name,is_dir,size_blocks,risk,child_count FROM nodes WHERE parent_id=? ORDER BY size_blocks DESC,name ASC LIMIT 200 OFFSET ?").map_err(|e|e.to_string())?;
    let items = q
        .query_map(params![parent, offset as i64], |r| {
            Ok(Node {
                id: r.get(0)?,
                parent: r.get(1)?,
                name: r.get(2)?,
                dir: r.get::<_, i64>(3)? != 0,
                blocks: r.get(4)?,
                risk: r.get(5)?,
                count: r.get(6)?,
                depth: 0,
                generation: 0,
                expanded: false,
                loaded: 0,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let remaining = (total as usize).saturating_sub(offset + items.len());
    Ok((items, remaining, 0))
}
fn bench_database(database: PathBuf) {
    let binary = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::metadata(p).ok())
        .map_or(0, |m| m.len()) as f64
        / 1048576.0;
    let mut samples = Vec::new();
    let mut first = None;
    let mut live = 0usize;
    for _ in 0..10 {
        for offset in (0..1000).step_by(PAGE) {
            let started = Instant::now();
            let (page, _, _) =
                db_page(database.clone(), BENCH_PARENT, offset).expect("synthetic SQLite query");
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            if first.is_none() {
                first = Some(ms);
            }
            samples.push(ms);
            live = live.max(page.len() + 3);
        }
    }
    samples.sort_by(f64::total_cmp);
    let p95 = samples[((samples.len() * 95).div_ceil(100)).saturating_sub(1)];
    println!(
        "{{\"first_frame_ms\":null,\"first_page_ms\":{:.3},\"expand_p95_ms\":{p95:.3},\"frame_p95_ms\":null,\"missed_frames\":null,\"live_nodes_peak\":{live},\"idle_cpu_pct\":null,\"binary_mib\":{binary:.3}}}",
        first.unwrap_or(0.0)
    );
}
fn refresh(state: &UiState) {
    let mut rows = Vec::new();
    let mut stack = vec![1i64];
    while let Some(id) = stack.pop() {
        let Some(n) = state.nodes.get(&id) else {
            continue;
        };
        rows.push(row_for(n, 0, n.name.clone(), n.blocks, n.depth));
        if state.loading.contains(&id) {
            let mut loading = n.clone();
            loading.depth += 1;
            rows.push(row_for(&loading, 3, "Loading…".into(), 0, loading.depth));
        }
        if state.expanded.contains(&id) {
            let children = state
                .order
                .iter()
                .filter(|child| state.nodes.get(child).is_some_and(|n| n.parent == id))
                .copied()
                .collect::<Vec<_>>();
            if let Some((remaining, blocks)) = state.aggregates.get(&id) {
                let mut aggregate = n.clone();
                aggregate.depth += 1;
                rows.push(row_for(
                    &aggregate,
                    1,
                    format!("{remaining} smaller items"),
                    *blocks,
                    aggregate.depth,
                ));
                let more = aggregate.clone();
                rows.push(row_for(
                    &more,
                    2,
                    format!("Show more · {remaining} remaining"),
                    0,
                    more.depth,
                ));
            }
            for child in children.into_iter().rev() {
                stack.push(child);
            }
        }
    }
    state.model.set_vec(rows);
    let bytes = state
        .selected
        .iter()
        .filter_map(|id| state.nodes.get(id))
        .map(|n| n.blocks * 512)
        .sum::<i64>();
    if let Some(w) = state.window.upgrade() {
        w.set_selection_summary(
            format!(
                "{} items selected - {:.2} GiB",
                state.selected.len(),
                bytes as f64 / 1073741824.0
            )
            .into(),
        );
    }
}
fn load(state: Rc<RefCell<UiState>>, id: i64, offset: usize) {
    let (path, generation) = {
        let mut s = state.borrow_mut();
        let Some(depth) = s.nodes.get(&id).map(|n| n.depth) else {
            return;
        };
        if s.expanded.contains(&id) && offset == 0 {
            s.expanded.remove(&id);
            let mut remove = HashSet::new();
            let mut todo = vec![id];
            while let Some(parent) = todo.pop() {
                for child in s
                    .nodes
                    .values()
                    .filter(|c| c.parent == parent && c.depth > depth)
                    .map(|c| c.id)
                    .collect::<Vec<_>>()
                {
                    remove.insert(child);
                    todo.push(child);
                }
            }
            s.nodes.retain(|key, _| !remove.contains(key));
            s.order.retain(|key| !remove.contains(key));
            s.aggregates.remove(&id);
            let generation_ref = s.generations.entry(id).or_default();
            *generation_ref += 1;
            refresh(&s);
            return;
        }
        s.expanded.insert(id);
        s.loading.insert(id);
        let generation_ref = s.generations.entry(id).or_default();
        *generation_ref += 1;
        let g = *generation_ref;
        (s.database.clone(), g)
    };
    refresh(&state.borrow());
    let weak = state.borrow().window.clone();
    thread::spawn(move || {
        let result = db_page(path, id, offset);
        let _ = slint::invoke_from_event_loop(move || {
            if weak.upgrade().is_none() {
                return;
            }
            APP_STATE.with(|slot| {
                let Some(state) = slot.borrow().clone() else {
                    return;
                };
                let mut s = state.borrow_mut();
                if s.generations.get(&id).copied() != Some(generation) || !s.expanded.contains(&id)
                {
                    return;
                }
                match result {
                    Ok((items, remaining, hidden_blocks)) => {
                        let depth = s.nodes.get(&id).map_or(0, |n| n.depth) + 1;
                        s.loading.remove(&id);
                        let mut ids = Vec::new();
                        for mut node in items {
                            node.depth = depth;
                            node.generation = generation;
                            s.order.retain(|old| *old != node.id);
                            ids.push(node.id);
                            s.nodes.insert(node.id, node);
                        }
                        let loaded = ids.len();
                        s.order.extend(ids);
                        let parent = s.nodes.get_mut(&id).unwrap();
                        parent.loaded = offset + loaded;
                        if remaining > 0 {
                            s.aggregates.insert(id, (remaining, hidden_blocks));
                        } else {
                            s.aggregates.remove(&id);
                        }
                        if s.first_page.is_none() {
                            s.first_page = Some(s.started.elapsed().as_secs_f64() * 1000.0);
                        }
                        refresh(&s);
                    }
                    Err(error) => {
                        s.loading.remove(&id);
                        eprintln!("Slint page read failed: {error}");
                        refresh(&s);
                    }
                }
            });
        });
    });
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let bench_index = args.iter().position(|a| a == "--bench");
    let bench = bench_index.is_some();
    if bench {
        let database = bench_index
            .and_then(|index| args.get(index + 1))
            .map_or_else(|| PathBuf::from("spike/data/nodes.sqlite"), PathBuf::from);
        bench_database(database);
        return;
    }
    let window = MainWindow::new().expect("create Slint window");
    let model = Rc::new(VecModel::from(vec![]));
    window.set_rows(ModelRc::from(model.clone()));
    let root = Node {
        id: 1,
        parent: 0,
        name: "Synthetic benchmark tree".into(),
        dir: true,
        blocks: 0,
        risk: 0,
        count: 3,
        depth: 0,
        generation: 0,
        expanded: false,
        loaded: 0,
    };
    let state = Rc::new(RefCell::new(UiState {
        nodes: HashMap::from([(1, root)]),
        order: vec![1],
        expanded: HashSet::from([1]),
        selected: HashSet::new(),
        generations: HashMap::new(),
        loading: HashSet::new(),
        aggregates: HashMap::new(),
        database: PathBuf::from("spike/data/nodes.sqlite"),
        model,
        window: window.as_weak(),
        started: Instant::now(),
        first_page: None,
        bench,
    }));
    APP_STATE.with(|slot| *slot.borrow_mut() = Some(state.clone()));
    window.on_toggle_expand({
        let s = state.clone();
        move |id| load(s.clone(), id as i64, 0)
    });
    window.on_toggle_select({
        let s = state.clone();
        move |id| {
            let mut s = s.borrow_mut();
            let id = id as i64;
            if !s.selected.insert(id) {
                s.selected.remove(&id);
            }
            refresh(&s);
        }
    });
    window.on_show_more({
        let s = state.clone();
        move |id| {
            let id = id as i64;
            let offset = s.borrow().nodes.get(&id).map_or(0, |n| n.loaded);
            load(s.clone(), id, offset)
        }
    });
    refresh(&state.borrow());
    // Initial list load uses the same worker path as subsequent expansion.
    load(state.clone(), 1, 0);
    let _ = window.run();
}
