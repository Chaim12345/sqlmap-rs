//! Data retrieval through the delay-confirmed channels (techniques T, S, Q)
//! against the local test app in --tiny mode (a shrunken fake DB: every true
//! inference condition costs a real second of sleep).
//!
//! The emulator evaluates sqlmap's conditional-sleep vector
//! SLEEP(n-(IF(<cond>,0,n))) against its in-memory DB, so the recovered
//! values are real inference, not canned output. Requires python3 on PATH.

use sqlmap_core::config::{Config, Technique};
use sqlmap_http::client::Client;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct VulnApp(Child, u16);

impl VulnApp {
    fn start_tiny(port: u16) -> Self {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let app = format!("{manifest}/../../tests/vulnapp.py");
        let child = Command::new("python3")
            .arg(&app)
            .arg(port.to_string())
            .arg("--tiny")
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
fn time_based_channel_enumerates_databases() {
    let app = VulnApp::start_tiny(8851);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        techniques: vec![Technique::Time],
        enum_dbs: true,
        time_sec: 1,
        ..Config::default()
    };
    let kb = scan(&conf);
    assert!(
        kb.injections.iter().any(|i| i.technique == Technique::Time),
        "{:?}",
        kb.injections
    );
    assert_eq!(kb.enumeration.databases, vec!["shop"]);
}

#[test]
fn stacked_channel_enumerates_columns() {
    let app = VulnApp::start_tiny(8852);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        techniques: vec![Technique::Stacked],
        enum_columns: true,
        target_db: Some("shop".into()),
        target_table: Some("users".into()),
        time_sec: 1,
        ..Config::default()
    };
    let kb = scan(&conf);
    assert!(
        kb.injections.iter().any(|i| i.technique == Technique::Stacked),
        "{:?}",
        kb.injections
    );
    assert_eq!(kb.enumeration.columns.len(), 1);
    assert_eq!(kb.enumeration.columns[0].columns, vec!["id", "pw"]);
}

#[test]
fn inline_channel_dumps_a_table() {
    let app = VulnApp::start_tiny(8853);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        techniques: vec![Technique::Inline],
        dump: true,
        target_db: Some("shop".into()),
        target_table: Some("users".into()),
        time_sec: 1,
        ..Config::default()
    };
    let kb = scan(&conf);
    assert!(
        kb.injections.iter().any(|i| i.technique == Technique::Inline),
        "{:?}",
        kb.injections
    );
    assert_eq!(kb.enumeration.dumps.len(), 1);
    assert_eq!(kb.enumeration.dumps[0].columns, vec!["id", "pw"]);
    assert_eq!(kb.enumeration.dumps[0].rows, vec![vec!["1", "x"]]);
}
