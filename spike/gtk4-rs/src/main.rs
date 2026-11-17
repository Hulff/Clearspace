use std::{
    cell::RefCell,
    rc::Rc,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use gtk::{gio, glib, prelude::*};
use rusqlite::{Connection, params};

const PAGE: i64 = 200;
const CAP: usize = 20_000;
const DB: &str = "spike/data/nodes.sqlite";
const BENCH_PARENT: i64 = 200_203;

#[derive(Clone, Debug)]
struct Record {
    id: i64,
    parent: i64,
    name: String,
    dir: bool,
    blocks: i64,
    risk: i64,
    count: i64,
}

#[derive(Default)]
struct Entry {
    record: Option<Record>,
    store: Option<gio::ListStore>,
    generation: u64,
    loaded: usize,
    loading: bool,
    expanded: bool,
    depth: usize,
    selected: bool,
    aggregate: bool,
    more: bool,
    placeholder: bool,
    expansion_signal: bool,
}

type Row = Rc<RefCell<Entry>>;
fn boxed(row: Row) -> glib::BoxedAnyObject {
    glib::BoxedAnyObject::new(row)
}
fn row_from(obj: &glib::Object) -> Row {
    obj.downcast_ref::<glib::BoxedAnyObject>()
        .unwrap()
        .borrow::<Row>()
        .clone()
}
fn rec(row: &Row) -> Record {
    row.borrow().record.as_ref().unwrap().clone()
}

#[derive(Debug)]
struct Page {
    owner: i64,
    generation: u64,
    offset: usize,
    records: Vec<Record>,
    remaining: usize,
}

struct AppState {
    sender: mpsc::Sender<Result<Page, String>>,
    receiver: mpsc::Receiver<Result<Page, String>>,
    rows: std::collections::HashMap<i64, Row>,
    tree: gtk::TreeListModel,
    view: gtk::ColumnView,
    summary: gtk::Label,
    status: gtk::Label,
    selected_bytes: i64,
    started: Instant,
    bench: bool,
    first_page_ms: Option<f64>,
    frame_samples: Vec<f64>,
    frame_last: Instant,
    bench_round: u32,
    bench_pages: u32,
    bench_start: Option<Instant>,
    scroll_index: usize,
    live_peak: usize,
    bench_out: bool,
}

fn query_page(
    database: String,
    owner: i64,
    generation: u64,
    offset: usize,
    limit: usize,
) -> Result<Page, String> {
    let connection = Connection::open(database).map_err(|e| e.to_string())?;
    let mut stmt=connection.prepare("SELECT id,parent_id,name,is_dir,size_blocks,risk,child_count FROM nodes WHERE parent_id=? ORDER BY size_blocks DESC,name ASC LIMIT ? OFFSET ?").map_err(|e|e.to_string())?;
    let records = stmt
        .query_map(params![owner, limit as i64, offset as i64], |r| {
            Ok(Record {
                id: r.get(0)?,
                parent: r.get(1)?,
                name: r.get(2)?,
                dir: r.get::<_, i64>(3)? != 0,
                blocks: r.get(4)?,
                risk: r.get(5)?,
                count: r.get(6)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let total: i64 = connection
        .query_row("SELECT child_count FROM nodes WHERE id=?", [owner], |r| {
            r.get(0)
        })
        .map_err(|e| e.to_string())?;
    Ok(Page {
        owner,
        generation,
        offset,
        remaining: (total as usize).saturating_sub(offset + records.len()),
        records,
    })
}

fn record_row(record: Record, depth: usize) -> Row {
    Rc::new(RefCell::new(Entry {
        record: Some(record),
        depth,
        ..Default::default()
    }))
}

fn make_loading(owner: i64, depth: usize) -> Row {
    Rc::new(RefCell::new(Entry {
        record: Some(Record {
            id: -owner,
            name: "Loading…".into(),
            parent: owner,
            dir: false,
            blocks: 0,
            risk: 0,
            count: 0,
        }),
        depth,
        placeholder: true,
        ..Default::default()
    }))
}

fn start_load(state: &Rc<RefCell<AppState>>, row: Row, offset: usize) {
    let (record, generation, store) = {
        let mut e = row.borrow_mut();
        let Some(record) = e.record.clone() else {
            return;
        };
        if e.loading || !record.dir || record.count == 0 {
            return;
        }
        e.loading = true;
        e.expanded = true;
        e.generation += 1;
        (record, e.generation, e.store.clone())
    };
    let Some(store) = store else { return };
    store.remove_all();
    store.append(&boxed(make_loading(record.id, 0)));
    let sender = state.borrow().sender.clone();
    let database = DB.to_string();
    let id = record.id;
    thread::spawn(move || {
        let result = query_page(database, id, generation, offset, PAGE as usize);
        let _ = sender.send(result);
    });
}

fn append_page(state: &Rc<RefCell<AppState>>, page: Page) {
    let owner = state.borrow().rows.get(&page.owner).cloned();
    let Some(owner) = owner else { return };
    let (store, generation, depth) = {
        let e = owner.borrow();
        (e.store.clone(), e.generation, e.depth)
    };
    if page.generation != generation || !owner.borrow().expanded {
        return;
    }
    let Some(store) = store else { return };
    let rows = page
        .records
        .into_iter()
        .map(|r| record_row(r, depth + 1))
        .collect::<Vec<_>>();
    let loaded = page.offset + rows.len();
    let mut objects: Vec<glib::Object> = rows
        .iter()
        .cloned()
        .map(boxed)
        .map(|b| b.upcast())
        .collect();
    if page.remaining > 0 {
        let aggregate = Rc::new(RefCell::new(Entry {
            record: Some(Record {
                id: -page.owner,
                name: format!("{} smaller items", page.remaining),
                parent: page.owner,
                dir: false,
                blocks: 0,
                risk: 0,
                count: 0,
            }),
            depth: depth + 1,
            aggregate: true,
            ..Default::default()
        }));
        objects.push(boxed(aggregate).upcast());
        let more = Rc::new(RefCell::new(Entry {
            record: Some(Record {
                id: -page.owner - 1,
                name: format!(
                    "Showing the biggest {loaded} of {} · Show more",
                    rec(&owner).count
                ),
                parent: page.owner,
                dir: false,
                blocks: 0,
                risk: 0,
                count: 0,
            }),
            depth: depth + 1,
            more: true,
            ..Default::default()
        }));
        objects.push(boxed(more).upcast());
    }
    // Single model splice replaces Loading and publishes the complete page at once.
    store.splice(0, store.n_items(), &objects);
    {
        let mut e = owner.borrow_mut();
        e.loading = false;
        e.loaded = loaded;
    }
    {
        let mut s = state.borrow_mut();
        for r in rows {
            if let Some(rec) = r.borrow().record.as_ref() {
                s.rows.insert(rec.id, r.clone());
            }
        }
        let live = s.rows.len().min(CAP);
        s.live_peak = s.live_peak.max(live);
        let elapsed = s.started.elapsed().as_secs_f64() * 1000.0;
        if s.first_page_ms.is_none() {
            s.first_page_ms = Some(elapsed);
        }
        if s.bench && page.owner == 2 {
            s.bench_pages += 1;
        }
    }
}

fn percentile95(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    values[((values.len() * 95).div_ceil(100))
        .saturating_sub(1)
        .min(values.len() - 1)]
}

fn bench_database(database: String) {
    let binary = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::metadata(p).ok())
        .map_or(0, |m| m.len()) as f64
        / 1048576.0;
    let mut page_times = Vec::new();
    let mut first = None;
    let mut live_peak = 0usize;
    for _round in 0..10 {
        for offset in (0..1000).step_by(PAGE as usize) {
            let started = Instant::now();
            let result = query_page(database.clone(), BENCH_PARENT, 1, offset, PAGE as usize)
                .expect("synthetic SQLite query");
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            if first.is_none() {
                first = Some(elapsed);
            }
            page_times.push(elapsed);
            live_peak = live_peak.max(result.records.len() + 3);
        }
    }
    let p95 = percentile95(&mut page_times);
    let first = first.unwrap_or(0.0);
    println!(
        "{{\"first_frame_ms\":null,\"first_page_ms\":{first:.3},\"expand_p95_ms\":{p95:.3},\"frame_p95_ms\":null,\"missed_frames\":null,\"live_nodes_peak\":{live_peak},\"idle_cpu_pct\":null,\"binary_mib\":{binary:.3}}}"
    );
}

fn make_column(
    title: &str,
    width: i32,
    bind: impl Fn(&gtk::ListItem) + 'static,
) -> gtk::ColumnViewColumn {
    let factory = gtk::SignalListItemFactory::new();
    factory.connect_setup(|_, item| item.set_child(Some(&gtk::Label::new(None))));
    factory.connect_bind(move |_, item| bind(item));
    let column = gtk::ColumnViewColumn::new(Some(title), Some(factory));
    column.set_fixed_width(width);
    column
}

fn build_ui(app: &gtk::Application, bench: bool) {
    let (sender, receiver) = mpsc::channel();
    let root = record_row(
        Record {
            id: 1,
            parent: 0,
            name: "Synthetic benchmark tree".into(),
            dir: true,
            blocks: 0,
            risk: 0,
            count: 3,
        },
        0,
    );
    let root_store = gio::ListStore::new::<glib::BoxedAnyObject>();
    root_store.append(&boxed(root.clone()));
    let tree = gtk::TreeListModel::new(root_store, false, false, |obj| {
        let r = row_from(obj);
        let e = r.borrow();
        let Some(rec) = e.record.as_ref() else {
            return None;
        };
        if !rec.dir || rec.count == 0 {
            return None;
        }
        let store = gio::ListStore::new::<glib::BoxedAnyObject>();
        drop(e);
        r.borrow_mut().store = Some(store.clone());
        Some(store.upcast())
    });
    let selection = gtk::MultiSelection::new(Some(tree.clone()));
    let view = gtk::ColumnView::new(Some(selection));
    view.set_show_row_separators(true);
    view.set_hexpand(true);
    view.set_vexpand(true);
    view.append_column(&make_column("✓", 48, |item| {
        let label = item.child().and_downcast::<gtk::Label>().unwrap();
        label.set_text("☐");
    }));
    let state_link: Rc<RefCell<Option<std::rc::Weak<RefCell<AppState>>>>> =
        Rc::new(RefCell::new(None));
    let name_factory = gtk::SignalListItemFactory::new();
    name_factory.connect_setup(|_, item| {
        let expander = gtk::TreeExpander::new();
        let label = gtk::Label::new(None);
        label.set_xalign(0.0);
        expander.set_child(Some(&label));
        item.set_child(Some(&expander));
    });
    name_factory.connect_bind({
        let state_link = state_link.clone();
        move |_, item| {
            let expander = item.child().and_downcast::<gtk::TreeExpander>().unwrap();
            let row = item.item().and_downcast::<gtk::TreeListRow>().unwrap();
            expander.set_list_row(Some(&row));
            let entry = row.item().map(|o| row_from(&o));
            if let Some(entry) = entry {
                let (text, attach) = {
                    let mut e = entry.borrow_mut();
                    let text = if e.aggregate || e.more || e.placeholder {
                        e.record.as_ref().unwrap().name.clone()
                    } else {
                        format!(
                            "{}{}",
                            if e.record.as_ref().unwrap().dir {
                                "▸ "
                            } else {
                                "   "
                            },
                            e.record.as_ref().unwrap().name
                        )
                    };
                    let attach = !e.expansion_signal;
                    e.expansion_signal = true;
                    (text, attach)
                };
                expander
                    .child()
                    .and_downcast::<gtk::Label>()
                    .unwrap()
                    .set_text(&text);
                if attach {
                    let weak = state_link.borrow().clone();
                    row.connect_notify_local(Some("expanded"), move |tree_row, _| {
                        let Some(state) = weak.as_ref().and_then(std::rc::Weak::upgrade) else {
                            return;
                        };
                        let Some(object) = tree_row.item() else {
                            return;
                        };
                        let entry = row_from(&object);
                        if tree_row.is_expanded() {
                            start_load(&state, entry, 0);
                        } else {
                            let mut e = entry.borrow_mut();
                            e.expanded = false;
                            e.loading = false;
                            e.generation += 1;
                            if let Some(store) = e.store.as_ref() {
                                store.remove_all();
                            }
                        }
                    });
                }
            }
        }
    });
    view.append_column(&gtk::ColumnViewColumn::new(
        Some("Name"),
        Some(name_factory),
    ));
    view.append_column(&make_column("Usage", 130, |item| {
        let label = item.child().and_downcast::<gtk::Label>().unwrap();
        label.set_text("▰▰▰▱▱");
    }));
    view.append_column(&make_column("Size", 100, |item| {
        let label = item.child().and_downcast::<gtk::Label>().unwrap();
        let row = item.item().and_downcast::<gtk::TreeListRow>().unwrap();
        let n = row
            .item()
            .map(|o| row_from(&o).borrow().record.as_ref().unwrap().blocks * 512)
            .unwrap_or(0);
        label.set_text(&format!("{:.1} MiB", n as f64 / 1048576.0));
    }));
    view.append_column(&make_column("Risk", 100, |item| {
        let label = item.child().and_downcast::<gtk::Label>().unwrap();
        label.set_text("Low");
    }));
    let status = gtk::Label::new(Some("Ready · synthetic database only"));
    status.set_xalign(0.0);
    let summary = gtk::Label::new(Some("0 items selected - 0.0 GiB"));
    summary.set_xalign(0.0);
    let input = gtk::Entry::new();
    input.set_placeholder_text(Some("Ask about this folder…"));
    input.set_hexpand(true);
    let bottom = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    bottom.append(&summary);
    bottom.append(&input);
    let layout = gtk::Box::new(gtk::Orientation::Vertical, 8);
    layout.set_margin_top(12);
    layout.set_margin_bottom(12);
    layout.set_margin_start(12);
    layout.set_margin_end(12);
    layout.append(&status);
    layout.append(&view);
    layout.append(&bottom);
    let window = gtk::ApplicationWindow::new(app);
    window.set_title(Some("Clearspace toolkit spike"));
    window.set_default_size(1000, 760);
    window.set_child(Some(&layout));
    let state = Rc::new(RefCell::new(AppState {
        sender,
        receiver,
        rows: std::collections::HashMap::from([(1, root.clone())]),
        tree: tree.clone(),
        view: view.clone(),
        summary,
        status,
        selected_bytes: 0,
        started: Instant::now(),
        bench,
        first_page_ms: None,
        frame_samples: vec![],
        frame_last: Instant::now(),
        bench_round: 0,
        bench_pages: 0,
        bench_start: None,
        scroll_index: 0,
        live_peak: 1,
        bench_out: false,
    }));
    *state_link.borrow_mut() = Some(Rc::downgrade(&state));
    view.connect_activate({
        let state = state.clone();
        move |_, position| {
            if let Some(item) = state.borrow().tree.item(position) {
                if let Ok(row) = item.downcast::<gtk::TreeListRow>() {
                    let e = row.item().map(|o| row_from(&o));
                    if let Some(e) = e {
                        start_load(&state, e, 0);
                    }
                }
            }
        }
    });
    glib::timeout_add_local(Duration::from_millis(16), {
        let state = state.clone();
        move || {
            loop {
                let result = state.borrow().receiver.try_recv();
                match result {
                    Ok(Ok(page)) => append_page(&state, page),
                    Ok(Err(e)) => eprintln!("page error: {e}"),
                    Err(_) => break,
                }
            }
            let mut s = state.borrow_mut();
            let now = Instant::now();
            let frame_ms = now.duration_since(s.frame_last).as_secs_f64() * 1000.0;
            s.frame_samples.push(frame_ms);
            s.frame_last = now;
            if s.bench && s.bench_start.is_none() {
                s.bench_start = Some(now);
            }
            glib::ControlFlow::Continue
        }
    });
    window.present();
    if let Some(row) = tree.row(0) {
        row.set_expanded(true);
        start_load(&state, root, 0);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(index) = args.iter().position(|a| a == "--bench") {
        bench_database(args.get(index + 1).cloned().unwrap_or_else(|| DB.into()));
        return;
    }
    let bench = false;
    let app = gtk::Application::builder()
        .application_id("org.clearspace.spike.gtk")
        .build();
    app.connect_activate(move |app| build_ui(app, bench));
    app.run();
}
