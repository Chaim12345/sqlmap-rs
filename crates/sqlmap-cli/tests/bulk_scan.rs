//! CLI-level test for -m/--bulk-file: the compiled sqlmap-rs binary scans
//! every URL in the file against the local test app (tests/vulnapp.py) and
//! reports each target's injections. Requires python3 on PATH.

use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct VulnApp(Child, u16);

impl VulnApp {
    fn start(port: u16) -> Self {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let app = format!("{manifest}/../../tests/vulnapp.py");
        let child = Command::new("python3")
            .arg(&app)
            .arg(port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to start vulnapp.py (python3 required)");
        let va = VulnApp(child, port);
        va.wait_ready();
        va
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", self.1)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("vulnapp did not come up on port {}", self.1);
    }
}

impl Drop for VulnApp {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

#[test]
fn bulk_file_scans_every_target() {
    let app = VulnApp::start(8805);
    let base = format!("http://127.0.0.1:{}", app.1);
    let file = std::env::temp_dir().join(format!("sqlmaprs-bulk-{}.txt", std::process::id()));
    std::fs::write(
        &file,
        format!(
            "# targets for the bulk test\n\n{base}/get?id=1\n{base}/item?name=widget\n{base}/search\n"
        ),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sqlmap-rs"))
        .arg("-m")
        .arg(&file)
        .arg("--technique")
        .arg("B")
        .output()
        .expect("run sqlmap-rs");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(out.status.success(), "exit status: {:?}\n{stdout}", out.status);
    // Both injectable targets were visited and reported.
    assert!(stdout.contains(&format!("target: {base}/get?id=1")), "{stdout}");
    assert!(stdout.contains(&format!("target: {base}/item?name=widget")), "{stdout}");
    assert!(stdout.contains(&format!("target: {base}/search")), "{stdout}");
    assert!(stdout.contains("id (Get) - Boolean"), "{stdout}");
    assert!(stdout.contains("name (Get) - Boolean"), "{stdout}");
    // The blank and comment lines produced no extra targets.
    assert_eq!(stdout.matches("[*] target: ").count(), 3, "{stdout}");

    let _ = std::fs::remove_file(&file);
}

#[test]
fn bulk_targets_run_in_parallel_with_threads() {
    let app = VulnApp::start(8806);
    let base = format!("http://127.0.0.1:{}", app.1);
    let file = std::env::temp_dir().join(format!("sqlmaprs-bulkpar-{}.txt", std::process::id()));
    // Four time-based targets: each detection needs two 1s sleeps, so a
    // sequential walk costs at least ~8s; --threads 4 should finish sooner.
    std::fs::write(&file, (0..4).map(|_| format!("{base}/get?id=1\n")).collect::<String>()).unwrap();

    let start = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_sqlmap-rs"))
        .arg("-m")
        .arg(&file)
        .arg("--technique")
        .arg("T")
        .arg("--time-sec")
        .arg("1")
        .arg("--threads")
        .arg("4")
        .output()
        .expect("run sqlmap-rs");
    let elapsed = start.elapsed();
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(out.status.success(), "exit status: {:?}\n{stdout}", out.status);
    assert_eq!(stdout.matches("id (Get) - Time").count(), 4, "{stdout}");
    assert!(
        elapsed < Duration::from_secs(7),
        "4 time-based targets on --threads 4 should beat the ~8s sequential floor: {elapsed:?}"
    );

    let _ = std::fs::remove_file(&file);
}
