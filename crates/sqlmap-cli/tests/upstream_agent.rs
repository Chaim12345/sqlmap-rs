//! CLI-level pins from the original Python sqlmap test suite
//! (tests/test_agent.py, upstream pinned at
//! sqlmapproject/sqlmap 8b78b676c1376ae28feccd957b03bbecea05eff1).
//! Upstream's file tests agent.py in process; the adaptation observes the
//! same contracts on the wire, through the local test proxy:
//!  - prefixQuery pads a space between value+prefix and the payload for
//!    non-stacked techniques ("1 AND ...", not "1AND ...")
//!  - stacked queries get NO such space ("1;SELECT ...")
//!  - cleanupPayload leaves no [RANDNUM]/[RANDSTR] markers on the wire

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

fn run_scan(app_port: u16, proxy_port: u16, technique: &str, log: &std::path::Path) -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let vulnapp = format!("{manifest}/../../tests/vulnapp.py");
    let tinyproxy = format!("{manifest}/../../tests/tinyproxy.py");

    let _ = std::fs::remove_file(log);
    let _app = spawn(&[vulnapp, app_port.to_string()]);
    let _proxy = spawn(&[tinyproxy, proxy_port.to_string(), log.to_string_lossy().into_owned()]);
    wait_ready(app_port);
    wait_ready(proxy_port);

    let out = Command::new(env!("CARGO_BIN_EXE_sqlmap-rs"))
        .arg("-u")
        .arg(format!("http://127.0.0.1:{app_port}/get?id=1"))
        .arg("--technique")
        .arg(technique)
        .arg("--proxy")
        .arg(format!("http://127.0.0.1:{proxy_port}"))
        .output()
        .expect("run sqlmap-rs");
    assert!(out.status.success(), "scan failed: {:?}", out.status);

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(text) = std::fs::read_to_string(log) {
            if text.lines().count() >= 3 {
                return text;
            }
        }
        assert!(Instant::now() < deadline, "proxy log stayed empty/short");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn boolean_payloads_are_space_padded_and_marker_free() {
    let log = std::env::temp_dir().join(format!("sqlmaprs-agent-b-{}.log", std::process::id()));
    let text = run_scan(8872, 8873, "B", &log);

    // prefixQuery spacing: "1 AND 51135=51135", never "1AND".
    assert!(
        text.contains("id=1 AND") || text.contains("id=1+AND") || text.contains("id=1%20AND"),
        "expected a space between value and boolean payload:\n{text}"
    );
    assert!(!text.contains("id=1AND"), "missing prefixQuery space:\n{text}");

    // cleanupPayload: no template markers survive to the wire.
    assert!(!text.contains("[RANDNUM]"), "unsubstituted RANDNUM on the wire:\n{text}");
    assert!(!text.contains("[RANDSTR]"), "unsubstituted RANDSTR on the wire:\n{text}");

    let _ = std::fs::remove_file(&log);
}

#[test]
fn stacked_payloads_get_no_space() {
    let log = std::env::temp_dir().join(format!("sqlmaprs-agent-s-{}.log", std::process::id()));
    let text = run_scan(8874, 8875, "S", &log);

    assert!(
        text.contains("id=1;SELECT") || text.contains("id=1%3BSELECT"),
        "stacked payload must follow the value with no space:\n{text}"
    );
    assert!(
        !text.contains("id=1 ;SELECT") && !text.contains("id=1 %3BSELECT") && !text.contains("id=1+;SELECT"),
        "stacked payload must not be space-padded:\n{text}"
    );

    let _ = std::fs::remove_file(&log);
}
