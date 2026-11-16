//! CLI-level tests for authenticating and SOCKS proxies: the compiled
//! sqlmap-rs binary scans the local test app (tests/vulnapp.py) through
//! tests/tinyproxy.py --auth (Basic proxy auth, via --proxy-cred) and
//! tests/tinysocks.py (a minimal SOCKS5 server). Requires python3 on PATH.

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

fn read_log(log: &std::path::Path, min_lines: usize) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(text) = std::fs::read_to_string(log) {
            if text.lines().count() >= min_lines {
                return text;
            }
        }
        assert!(Instant::now() < deadline, "proxy log stayed empty/short");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn sqlmap() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sqlmap-rs"))
}

#[test]
fn scan_through_authenticating_proxy() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let vulnapp = format!("{manifest}/../../tests/vulnapp.py");
    let tinyproxy = format!("{manifest}/../../tests/tinyproxy.py");

    let log = std::env::temp_dir().join(format!("sqlmaprs-pauth-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&log);

    let _app = spawn(&[vulnapp, "8868".into()]);
    let _proxy = spawn(&[
        tinyproxy,
        "8869".into(),
        log.to_string_lossy().into_owned(),
        "--auth".into(),
        "alice:wonder".into(),
    ]);
    wait_ready(8868);
    wait_ready(8869);

    // Without credentials the authenticating proxy must refuse every request:
    // the scan finds nothing injectable.
    let out = sqlmap()
        .arg("-u")
        .arg("http://127.0.0.1:8868/get?id=1")
        .arg("--technique")
        .arg("B")
        .arg("--proxy")
        .arg("http://127.0.0.1:8869")
        .output()
        .expect("run sqlmap-rs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("id (Get) - Boolean"),
        "scan without creds should not reach the origin:\n{stdout}"
    );

    // With --proxy-cred the same scan works end to end.
    let out = sqlmap()
        .arg("-u")
        .arg("http://127.0.0.1:8868/get?id=1")
        .arg("--technique")
        .arg("B")
        .arg("--proxy")
        .arg("http://127.0.0.1:8869")
        .arg("--proxy-cred")
        .arg("alice:wonder")
        .output()
        .expect("run sqlmap-rs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "exit status: {:?}\n{stdout}", out.status);
    assert!(stdout.contains("id (Get) - Boolean"), "{stdout}");

    let logtext = read_log(&log, 3);
    assert!(
        logtext.lines().any(|l| l.contains("auth=missing")),
        "expected refused unauthenticated requests:\n{logtext}"
    );
    let ok_hits = logtext
        .lines()
        .filter(|l| l.contains("127.0.0.1:8868/get") && l.contains("auth=ok"))
        .count();
    assert!(
        ok_hits >= 3,
        "expected authenticated proxied /get requests, got {ok_hits}:\n{logtext}"
    );

    let _ = std::fs::remove_file(&log);
}

#[test]
fn scan_through_socks5_proxy() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let vulnapp = format!("{manifest}/../../tests/vulnapp.py");
    let tinysocks = format!("{manifest}/../../tests/tinysocks.py");

    let log = std::env::temp_dir().join(format!("sqlmaprs-socks-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&log);

    let _app = spawn(&[vulnapp, "8870".into()]);
    let _proxy = spawn(&[tinysocks, "8871".into(), log.to_string_lossy().into_owned()]);
    wait_ready(8870);
    wait_ready(8871);

    let out = sqlmap()
        .arg("-u")
        .arg("http://127.0.0.1:8870/get?id=1")
        .arg("--technique")
        .arg("B")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:8871")
        .output()
        .expect("run sqlmap-rs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "exit status: {:?}\n{stdout}", out.status);
    assert!(stdout.contains("id (Get) - Boolean"), "{stdout}");

    // The SOCKS server must have accepted a CONNECT tunnel to the origin.
    let logtext = read_log(&log, 1);
    assert!(
        logtext.lines().any(|l| l.contains("CONNECT 127.0.0.1:8870")),
        "expected CONNECT to the origin in the SOCKS log:\n{logtext}"
    );

    let _ = std::fs::remove_file(&log);
}
