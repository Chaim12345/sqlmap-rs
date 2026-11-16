//! End-to-end detection of stacked-query (S) and inline-query (Q) injections
//! against the local deliberately-vulnerable app (tests/vulnapp.py).
//! Both techniques confirm by time delay, exactly like upstream sqlmap:
//! the emulator sleeps when the reconstructed statement holds SLEEP(n).
//! Requires python3 on PATH.

use sqlmap_core::config::{Config, Technique};
use sqlmap_http::client::Client;
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

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.1, path)
    }
}

impl Drop for VulnApp {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn scan(conf: &Config) -> sqlmap_core::kb::KnowledgeBase {
    let client = Client::new(conf);
    sqlmap_detection::Engine::new(&client, conf).scan().kb
}

#[test]
fn stacked_queries_confirm_by_delay() {
    let app = VulnApp::start(8815);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        techniques: vec![Technique::Stacked],
        time_sec: 1,
        ..Config::default()
    };
    let kb = scan(&conf);
    let inj = kb
        .injections
        .iter()
        .find(|i| i.technique == Technique::Stacked)
        .expect("expected a stacked-query injection");
    assert_eq!(inj.parameter, "id");
    assert!(inj.payload.contains(";SELECT SLEEP(1)"), "{}", inj.payload);
    assert!(inj.note.contains("two delayed responses"), "{}", inj.note);
}

#[test]
fn inline_queries_confirm_by_delay() {
    let app = VulnApp::start(8816);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        techniques: vec![Technique::Inline],
        time_sec: 1,
        ..Config::default()
    };
    let kb = scan(&conf);
    let inj = kb
        .injections
        .iter()
        .find(|i| i.technique == Technique::Inline)
        .expect("expected an inline-query injection");
    assert_eq!(inj.parameter, "id");
    // The whole value was replaced by the subquery (no leading "1").
    assert!(inj.payload.starts_with("(SELECT "), "{}", inj.payload);
}

#[test]
fn no_false_positives_on_static_page() {
    let app = VulnApp::start(8817);
    let conf = Config {
        target_url: app.url("/search"),
        techniques: vec![Technique::Stacked, Technique::Inline],
        time_sec: 1,
        ..Config::default()
    };
    let kb = scan(&conf);
    assert!(kb.injections.is_empty(), "{:?}", kb.injections);
}
