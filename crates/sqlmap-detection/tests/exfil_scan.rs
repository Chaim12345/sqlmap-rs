//! End-to-end blind exfiltration against the local deliberately-vulnerable
//! app (tests/vulnapp.py): --dbs, --tables, --columns and --dump must recover
//! the emulator's fake in-memory database through a boolean-based injection.
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
fn enumerates_databases_blind() {
    let app = VulnApp::start(8751);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        enum_dbs: true,
        techniques: vec![Technique::Boolean],
        ..Config::default()
    };
    let kb = scan(&conf);
    assert!(
        kb.injections.iter().any(|i| i.technique == Technique::Boolean),
        "boolean injection required for blind enumeration"
    );
    assert_eq!(
        kb.enumeration.databases,
        vec!["information_schema", "mysql", "shop"],
        "--dbs must recover the emulator's schema list byte-for-byte"
    );
}

#[test]
fn enumerates_tables_for_database() {
    let app = VulnApp::start(8752);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        enum_tables: true,
        target_db: Some("shop".into()),
        techniques: vec![Technique::Boolean],
        ..Config::default()
    };
    let kb = scan(&conf);
    assert_eq!(
        kb.enumeration.tables.get("shop").map(Vec::as_slice),
        Some(&["products".to_string(), "users".to_string()][..]),
    );
}

#[test]
fn enumerates_columns_and_dumps_table() {
    let app = VulnApp::start(8753);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        enum_columns: true,
        dump: true,
        target_db: Some("shop".into()),
        target_table: Some("users".into()),
        techniques: vec![Technique::Boolean],
        ..Config::default()
    };
    let kb = scan(&conf);
    let cols = &kb.enumeration.columns;
    assert_eq!(cols.len(), 1);
    assert_eq!(cols[0].columns, vec!["id", "username", "password"]);
    assert_eq!(kb.enumeration.dumps.len(), 1);
    let dump = &kb.enumeration.dumps[0];
    assert_eq!(dump.columns, vec!["id", "username", "password"]);
    assert_eq!(
        dump.rows,
        vec![
            vec!["1", "admin", "s3cr3t-pass"],
            vec!["2", "alice", "hunter2"],
            vec!["3", "bob", "qwerty"],
        ],
        "--dump must recover every row byte-for-byte"
    );
}

#[test]
fn enumerates_through_string_param() {
    // Same --dbs flow through the quoted string injection point (?name=),
    // proving the boundary reconstruction works for string places too.
    let app = VulnApp::start(8754);
    let conf = Config {
        target_url: app.url("/item?name=widget"),
        enum_dbs: true,
        techniques: vec![Technique::Boolean],
        ..Config::default()
    };
    let kb = scan(&conf);
    assert_eq!(
        kb.enumeration.databases,
        vec!["information_schema", "mysql", "shop"],
    );
}

#[test]
fn union_channel_enumerates_databases() {
    // Default technique set includes UNION; the engine must prefer the UNION
    // channel (one request per value) over blind inference.
    let app = VulnApp::start(8755);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        enum_dbs: true,
        ..Config::default()
    };
    let kb = scan(&conf);
    assert!(
        kb.injections
            .iter()
            .any(|i| i.technique == Technique::Union && i.column_count == Some(3)),
        "UNION finding with column count required"
    );
    assert_eq!(
        kb.enumeration.databases,
        vec!["information_schema", "mysql", "shop"],
        "UNION channel must recover the schema list"
    );
}

#[test]
fn union_channel_dumps_table() {
    let app = VulnApp::start(8756);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        enum_columns: true,
        dump: true,
        target_db: Some("shop".into()),
        target_table: Some("users".into()),
        ..Config::default()
    };
    let kb = scan(&conf);
    assert_eq!(kb.enumeration.dumps.len(), 1);
    let dump = &kb.enumeration.dumps[0];
    assert_eq!(dump.columns, vec!["id", "username", "password"]);
    assert_eq!(
        dump.rows,
        vec![
            vec!["1", "admin", "s3cr3t-pass"],
            vec!["2", "alice", "hunter2"],
            vec!["3", "bob", "qwerty"],
        ],
        "UNION channel must recover every row"
    );
}
