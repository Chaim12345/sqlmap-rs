//! CLI-level test for --proxy: the compiled sqlmap-rs binary routes every
//! request through a tiny local forward proxy (tests/tinyproxy.py) on the
//! way to the local test app (tests/vulnapp.py). Requires python3 on PATH.

use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn spawn(args: &[String]) -> Proc {
    Proc(Command::new("python3")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start python helper (python3 required)"))
}

fn wait_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("nothing came up on port {port}");
}

#[test]
fn scan_routes_through_proxy() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let vulnapp = format!("{manifest}/../../tests/vulnapp.py");
    let tinyproxy = format!("{manifest}/../../tests/tinyproxy.py");

    let log = std::env::temp_dir().join(format!("sqlmaprs-proxy-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&log);

    let _app = spawn(&[vulnapp, "8811".into()]);
    let _proxy = spawn(&[tinyproxy, "8812".into(), log.to_string_lossy().into_owned()]);
    wait_ready(8811);
    wait_ready(8812);

    let out = Command::new(env!("CARGO_BIN_EXE_sqlmap-rs"))
        .arg("-u")
        .arg("http://127.0.0.1:8811/get?id=1")
        .arg("--technique")
        .arg("B")
        .arg("--proxy")
        .arg("http://127.0.0.1:8812")
        .output()
        .expect("run sqlmap-rs");
    let stdout = String::from_utf8_lossy(&out.stdout);

    // The scan still works end to end through the proxy.
    assert!(out.status.success(), "exit status: {:?}\n{stdout}", out.status);
    assert!(stdout.contains("id (Get) - Boolean"), "{stdout}");

    // And the proxy actually carried the traffic to the origin.
    let deadline = Instant::now() + Duration::from_secs(5);
    let logtext = loop {
        if let Ok(text) = std::fs::read_to_string(&log) {
            if text.lines().count() >= 3 {
                break text;
            }
        }
        assert!(Instant::now() < deadline, "proxy log stayed empty/short");
        std::thread::sleep(Duration::from_millis(100));
    };
    let hits = logtext
        .lines()
        .filter(|l| l.contains("127.0.0.1:8811/get"))
        .count();
    assert!(hits >= 3, "expected proxied /get requests, got {hits}:\n{logtext}");

    let _ = std::fs::remove_file(&log);
}
