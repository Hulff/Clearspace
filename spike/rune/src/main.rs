use rune::tok::{self, space, type_};
use rune::{
    App, AppHandle, AppSpec, Cx, El, ScrollSpec, TextEdit, Tx, col, el, row, text, text_input,
};
use rusqlite::{Connection, params};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::OnceLock,
    thread,
    time::Instant,
};

const PAGE: i64 = 200;
const CAP: usize = 20_000;
const DB: &str = "spike/data/nodes.sqlite";
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
    depth: u32,
}
struct State {
    nodes: HashMap<i64, Node>,
    order: Vec<i64>,
    expanded: HashSet<i64>,
    selected: HashSet<i64>,
    loading: HashSet<i64>,
    generation: HashMap<i64, u64>,
    lru: VecDeque<i64>,
    aggregate: HashMap<i64, (usize, i64)>,
    chat: TextEdit,
    notice: String,
    started: Instant,
}
impl Default for State {
    fn default() -> Self {
        let root = Node {
            id: 1,
            parent: 0,
            name: "Synthetic benchmark tree".into(),
            dir: true,
            blocks: 0,
            risk: 0,
            count: 3,
            depth: 0,
        };
        Self {
            nodes: HashMap::from([(1, root)]),
            order: vec![1],
            expanded: HashSet::new(),
            selected: HashSet::new(),
            loading: HashSet::new(),
            generation: HashMap::new(),
            lru: VecDeque::new(),
            aggregate: HashMap::new(),
            chat: TextEdit::new(""),
            notice: "Loading synthetic fixture…".into(),
            started: Instant::now(),
        }
    }
}

static HANDLE: OnceLock<AppHandle<State>> = OnceLock::new();

fn query(database: &str, parent: i64, offset: usize) -> Result<(Vec<Node>, usize, i64), String> {
    let db = Connection::open(database).map_err(|e| e.to_string())?;
    let count: i64 = db
        .query_row("SELECT child_count FROM nodes WHERE id=?", [parent], |r| {
            r.get(0)
        })
        .map_err(|e| e.to_string())?;
    let mut stmt=db.prepare("SELECT id,parent_id,name,is_dir,size_blocks,risk,child_count FROM nodes WHERE parent_id=? ORDER BY size_blocks DESC,name ASC LIMIT 200 OFFSET ?").map_err(|e|e.to_string())?;
    let mut nodes = stmt
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
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let remaining = (count as usize).saturating_sub(offset + nodes.len());
    for n in &mut nodes {
        n.depth = 1;
    }
    Ok((nodes, remaining, 0))
}

fn request_page(id: i64, offset: usize, s: &mut State) {
    if offset == 0 && s.expanded.contains(&id) {
        s.expanded.remove(&id);
        let mut remove = HashSet::new();
        let mut todo = vec![id];
        while let Some(parent) = todo.pop() {
            for child in s
                .nodes
                .values()
                .filter(|n| n.parent == parent)
                .map(|n| n.id)
                .collect::<Vec<_>>()
            {
                remove.insert(child);
                todo.push(child);
            }
        }
        s.nodes.retain(|key, _| !remove.contains(key));
        s.order.retain(|key| !remove.contains(key));
        s.aggregate.remove(&id);
        s.loading.remove(&id);
        *s.generation.entry(id).or_default() += 1;
        s.notice = "Collapsed; child rows released".into();
        return;
    }
    s.expanded.insert(id);
    s.loading.insert(id);
    s.lru.retain(|old| *old != id);
    s.lru.push_back(id);
    let generation_ref = s.generation.entry(id).or_default();
    *generation_ref += 1;
    let generation = *generation_ref;
    let database = DB.to_string();
    let handle = HANDLE.get().expect("app handle installed").clone();
    thread::spawn(move || {
        let started = Instant::now();
        let result = query(&database, id, offset);
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;
        handle.update(move |s, _| {
            if s.generation.get(&id).copied() != Some(generation) || !s.expanded.contains(&id) {
                return;
            }
            s.loading.remove(&id);
            match result {
                Ok((mut page, remaining, blocks)) => {
                    let depth = s.nodes.get(&id).map_or(0, |n| n.depth + 1);
                    let ids: Vec<_> = page
                        .iter_mut()
                        .map(|n| {
                            n.depth = depth;
                            n.id
                        })
                        .collect();
                    s.nodes
                        .retain(|key, n| n.parent != id || !s.order.contains(key));
                    for n in page {
                        s.nodes.insert(n.id, n);
                    }
                    s.order.retain(|key| !ids.contains(key));
                    s.order.extend(ids);
                    if remaining > 0 {
                        s.aggregate.insert(id, (remaining, blocks));
                    } else {
                        s.aggregate.remove(&id);
                    }
                    s.notice = format!(
                        "{} rows loaded from SQLite in {elapsed:.2} ms",
                        s.nodes.len().saturating_sub(1)
                    );
                }
                Err(error) => s.notice = format!("SQLite error: {error}"),
            }
            // Keep only the bounded working set; collapsed branches are least-recently-used first.
            while s.nodes.len() > CAP {
                let Some(victim) = s.lru.pop_front() else {
                    break;
                };
                if victim == id {
                    continue;
                }
                s.expanded.remove(&victim);
                let mut remove = HashSet::new();
                let mut todo = vec![victim];
                while let Some(parent) = todo.pop() {
                    for child in s
                        .nodes
                        .values()
                        .filter(|n| n.parent == parent)
                        .map(|n| n.id)
                        .collect::<Vec<_>>()
                    {
                        remove.insert(child);
                        todo.push(child);
                    }
                }
                s.nodes.retain(|key, _| !remove.contains(key));
                s.order.retain(|key| !remove.contains(key));
                s.aggregate.remove(&victim);
            }
        });
    });
}

fn bench_database(database: String) {
    let binary = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::metadata(p).ok())
        .map_or(0, |m| m.len()) as f64
        / 1048576.0;
    let mut samples = Vec::new();
    let mut first = None;
    let mut live = 0usize;
    for _ in 0..10 {
        for offset in (0..1000).step_by(PAGE as usize) {
            let started = Instant::now();
            let (page, _, _) =
                query(&database, BENCH_PARENT, offset).expect("synthetic SQLite query");
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

fn view(s: &State, cx: &mut Cx<State>) -> El {
    let t = tok::theme(cx.system_dark());
    let mut list = col().key("visible-rows").gap(2.0);
    for id in &s.order {
        let Some(n) = s.nodes.get(id) else { continue };
        let selected = s.selected.contains(id);
        let indent = n.depth as f32 * 18.0;
        let label = if n.dir {
            if s.expanded.contains(id) {
                "▾ "
            } else {
                "▸ "
            }
        } else {
            "  "
        };
        let text_value = format!("{label}{}", n.name);
        let id = *id;
        let button = el()
            .key(format!("row-{id}"))
            .role("button")
            .label(text_value.clone())
            .h(32.0)
            .fill(rune::color::hex("#232627").unwrap())
            .border(1.0, rune::color::hex("#34383a").unwrap())
            .on_press_tx(move |s: &mut State, _tx: &mut Tx| request_page(id, 0, s))
            .child(
                text(text_value)
                    .font(type_::BODY)
                    .color(rune::color::hex("#eceeef").unwrap()),
            );
        let check_id = id;
        let check = el()
            .key(format!("check-{check_id}"))
            .role("checkbox")
            .label(format!("Select {}", n.name))
            .checked(selected)
            .focusable(true)
            .size(18.0, 18.0)
            .fill(if selected {
                rune::color::hex("#5aa9ff").unwrap()
            } else {
                t.control_off
            })
            .on_press(move |s: &mut State| {
                if !s.selected.insert(check_id) {
                    s.selected.remove(&check_id);
                }
            });
        let size = format!("{:.1} MiB", n.blocks as f64 * 512.0 / 1048576.0);
        let risk = match n.risk {
            0 => "Low",
            1 => "Moderate",
            2 => "Your data",
            _ => "Critical",
        };
        let bar = el()
            .key(format!("usage-{id}"))
            .w(84.0)
            .h(7.0)
            .radius(3.0)
            .fill(t.control_off)
            .child(
                el().w(48.0)
                    .h(7.0)
                    .radius(3.0)
                    .fill(rune::color::hex("#5aa9ff").unwrap()),
            );
        let line = row()
            .key(format!("line-{id}"))
            .h(34.0)
            .gap(8.0)
            .center_y()
            .child(el().w(indent).h(1.0))
            .child(check)
            .child(button.grow(1.0))
            .child(bar)
            .child(
                text(size)
                    .font(type_::LABEL)
                    .color(t.text_secondary)
                    .w(84.0),
            )
            .child(
                text(risk)
                    .font(type_::LABEL)
                    .color(if n.risk >= 2 {
                        rune::color::hex("#ee9b73").unwrap()
                    } else {
                        t.text_secondary
                    })
                    .w(76.0),
            );
        list = list.child(line);
        if s.loading.contains(&id) {
            list = list.child(text("Loading…").font(type_::LABEL).color(t.text_secondary));
        }
        if let Some((remaining, _)) = s.aggregate.get(&id) {
            list = list.child(
                text(format!("{remaining} smaller items"))
                    .font(type_::LABEL)
                    .color(t.text_secondary),
            );
            let more_id = id;
            list = list.child(
                row()
                    .key(format!("more-{more_id}"))
                    .h(30.0)
                    .child(
                        text(format!("Show more · {remaining} remaining"))
                            .font(type_::LABEL)
                            .color(tok::accent(0, true)),
                    )
                    .on_press_tx(move |s: &mut State, _| {
                        let offset = s.nodes.values().filter(|n| n.parent == more_id).count();
                        request_page(more_id, offset, s);
                    }),
            );
        }
    }
    let selected_bytes = s
        .selected
        .iter()
        .filter_map(|id| s.nodes.get(id))
        .map(|n| n.blocks * 512)
        .sum::<i64>();
    let footer = format!(
        "{} items selected - {:.2} GiB",
        s.selected.len(),
        selected_bytes as f64 / 1073741824.0
    );
    let field = text_input(&s.chat, type_::BODY)
        .key("assistant-input")
        .label("Assistant chat input")
        .w_full()
        .h(34.0)
        .padding(space::S2)
        .fill(rune::color::hex("#232627").unwrap())
        .color(t.text)
        .on_edit(|s: &mut State| &mut s.chat);
    col()
        .key("root")
        .w_full()
        .h_full()
        .padding(16.0)
        .gap(8.0)
        .fill(rune::color::hex("#181a1b").unwrap())
        .child(
            text("Clearspace UI toolkit spike")
                .font(type_::TITLE)
                .color(t.text),
        )
        .child(
            text("☑  Name                                      Usage        Size       Risk")
                .font(type_::LABEL)
                .color(t.text_secondary),
        )
        .child(
            text(s.notice.clone())
                .key("status")
                .font(type_::LABEL)
                .color(t.text_secondary),
        )
        .child(
            list.scroll(ScrollSpec {
                stick_bottom: false,
            })
            .shrink()
            .min_h(0.0),
        )
        .child(
            row()
                .key("footer")
                .gap(12.0)
                .child(text(footer).font(type_::LABEL).color(t.text).grow(1.0))
                .child(field),
        )
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if let Some(index) = args.iter().position(|a| a == "--bench") {
        bench_database(args.get(index + 1).cloned().unwrap_or_else(|| DB.into()));
        return;
    }
    let app = App::new(AppSpec::new(
        "Clearspace Rune spike",
        (1000.0, 760.0),
        State::default,
        view,
    ));
    let handle = app.handle();
    let _ = HANDLE.set(handle.clone());
    let initial = handle.clone();
    thread::spawn(move || {
        let result = query(DB, 1, 0);
        initial.update(move |s, _| match result {
            Ok((mut page, remaining, blocks)) => {
                let ids: Vec<_> = page
                    .iter_mut()
                    .map(|n| {
                        n.depth = 1;
                        n.id
                    })
                    .collect();
                for n in page {
                    s.nodes.insert(n.id, n);
                }
                s.order.extend(ids);
                s.expanded.insert(1);
                if remaining > 0 {
                    s.aggregate.insert(1, (remaining, blocks));
                }
                s.notice = "SQLite first page ready".into();
            }
            Err(e) => s.notice = format!("SQLite error: {e}"),
        });
    });
    app.run();
}
