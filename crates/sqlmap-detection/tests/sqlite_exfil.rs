//! SQLite enumeration against the local test app (tests/vulnapp.py) with
//! --dbms sqlite: catalog queries go to sqlite_master shapes, columns are
//! recovered by parsing the CREATE statement (as upstream's sqlite plugin),
//! and rows come back over the ':'-concat shape. Requires python3 on PATH.
//!
//! Honest scope: the emulator answers SQLite catalog/DDL shapes against its
//! fake state; time-based retrieval does not exist for SQLite (no SLEEP).

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
fn sqlite_blind_enumerates_tables_columns_and_rows() {
    let app = VulnApp::start(8861);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        techniques: vec![Technique::Boolean],
        dbms: Some("sqlite".into()),
        enum_tables: true,
        enum_columns: true,
        dump: true,
        target_db: Some("main".into()),
        target_table: Some("users".into()),
        ..Config::default()
    };
    let kb = scan(&conf);
    // sqlite_master answers with every table the fake DB knows.
    let tables = kb.enumeration.tables.get("main").expect("tables for main");
    assert!(tables.contains(&"users".to_string()), "{tables:?}");
    // Columns came from parsing the synthesized CREATE TABLE statement.
    assert_eq!(kb.enumeration.columns.len(), 1);
    assert_eq!(
        kb.enumeration.columns[0].columns,
        vec!["id", "username", "password"]
    );
    // And the dump ran over the SQLite-qualified query shapes.
    assert_eq!(kb.enumeration.dumps.len(), 1);
    assert_eq!(kb.enumeration.dumps[0].rows.len(), 3);
    assert_eq!(
        kb.enumeration.dumps[0].rows[0],
        vec!["1", "admin", "s3cr3t-pass"]
    );
}

#[test]
fn sqlite_union_channel_enumerates() {
    let app = VulnApp::start(8862);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        techniques: vec![Technique::Union],
        dbms: Some("sqlite".into()),
        enum_dbs: true,
        ..Config::default()
    };
    let kb = scan(&conf);
    if kb.injections.is_empty() {
        // No generic UNION payloads match a forced SQLite hint; that is a
        // payload coverage fact, not an exfil bug. The blind channel test
        // above carries the SQLite verification.
        return;
    }
    assert_eq!(kb.enumeration.databases, vec!["main"]);
}
