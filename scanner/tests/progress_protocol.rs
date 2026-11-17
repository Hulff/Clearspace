use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temporary_root() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("clearspace-progress-{nonce}"))
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        Self(temporary_root())
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.with_extension("sqlite"));
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn field(line: &str, name: &str) -> u64 {
    let key = format!("\"{name}\":");
    let start = line.find(&key).expect("field present") + key.len();
    let digits = line[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    digits.parse().expect("unsigned integer field")
}

#[test]
fn progress_v2_reports_estimate_path_and_bounded_largest_files() {
    let temp = TempRoot::new();
    let root = &temp.0;
    fs::create_dir_all(root).expect("create fixture root");
    for index in 0..1000 {
        fs::write(
            root.join(format!("file-{index:04}.bin")),
            vec![b'x'; index + 1],
        )
        .expect("create fixture file");
    }
    fs::write(root.join("quote-\"-café.bin"), vec![b'z'; 5000]).expect("create escaped file");
    let database = root.with_extension("sqlite");

    let output = Command::new(env!("CARGO_BIN_EXE_clearspace-scan"))
        .arg(root)
        .arg("--db")
        .arg(&database)
        .output()
        .expect("run scanner");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 protocol output");
    let progress = stdout
        .lines()
        .find(|line| line.contains("\"event\":\"progress\""))
        .expect("progress snapshot");
    let completed = stdout
        .lines()
        .find(|line| line.contains("\"event\":\"completed\""))
        .expect("completed snapshot");

    assert!(output.status.success());
    assert!(progress.contains("\"protocol_version\":2"));
    assert!(progress.contains("\"dirs_done\":"));
    assert!(progress.contains("\"dirs_queued\":"));
    assert!(progress.contains("\"dirs_total_est\":"));
    assert!(progress.contains("\"current_path\":"));
    assert!(progress.contains("\"largest_items\":"));
    assert!(completed.contains("quote-\\\"-café.bin"));
    assert!(progress.matches("\"bytes\":").count() <= 4);
    assert_eq!(
        field(progress, "dirs_done") + field(progress, "dirs_queued"),
        field(progress, "dirs_total_est")
    );
}

#[test]
fn small_scan_emits_a_final_progress_snapshot() {
    let temp = TempRoot::new();
    let root = &temp.0;
    fs::create_dir_all(root.join("nested")).expect("create fixture root");
    fs::write(root.join("nested/payload"), b"small scan").expect("create fixture file");
    let database = root.with_extension("sqlite");

    let output = Command::new(env!("CARGO_BIN_EXE_clearspace-scan"))
        .arg(root)
        .arg("--db")
        .arg(&database)
        .output()
        .expect("run scanner");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 protocol output");
    let progress = stdout
        .lines()
        .find(|line| line.contains("\"event\":\"progress\""))
        .expect("final progress snapshot for small scan");

    assert!(output.status.success());
    assert_eq!(field(progress, "dirs_done"), 2);
    assert_eq!(field(progress, "dirs_queued"), 0);
    assert_eq!(field(progress, "dirs_total_est"), 2);
    assert!(progress.contains("nested/payload"));
}
