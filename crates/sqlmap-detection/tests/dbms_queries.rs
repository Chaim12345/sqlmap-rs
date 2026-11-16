//! End-to-end proof that enumeration picks the query set of the forced /
//! fingerprinted DBMS: a scan with --dbms postgresql against the local
//! (MySQL-emulating) test app must issue PostgreSQL-shaped SQL. Traffic is
//! routed through the tiny forward proxy (tests/tinyproxy.py) whose log
//! records every request URI. Requires python3 on PATH.
//!
//! Honest scope: the emulator only understands MySQL, so no data comes back;
//! what is asserted is WHICH queries were issued.

use sqlmap_core::config::{Config, Technique};
use sqlmap_http::client::Client;
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
fn forced_postgresql_issues_postgresql_shaped_queries() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let vulnapp = format!("{manifest}/../../tests/vulnapp.py");
    let tinyproxy = format!("{manifest}/../../tests/tinyproxy.py");
    let log = std::env::temp_dir().join(format!("sqlmaprs-dbmsq-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&log);

    let _app = spawn(&[vulnapp, "8821".into()]);
    let _proxy = spawn(&[tinyproxy, "8822".into(), log.to_string_lossy().into_owned()]);
    wait_ready(8821);
    wait_ready(8822);

    let conf = Config {
        target_url: "http://127.0.0.1:8821/get?id=1".into(),
        techniques: vec![Technique::Boolean],
        dbms: Some("postgresql".into()),
        enum_dbs: true,
        proxy: Some("http://127.0.0.1:8822".into()),
        ..Config::default()
    };
    let client = Client::new(&conf);
    let kb = sqlmap_detection::Engine::new(&client, &conf).scan().kb;
    assert!(
        kb.injections.iter().any(|i| i.parameter == "id"),
        "boolean injection should still be found: {:?}",
        kb.injections
    );

    let logtext = std::fs::read_to_string(&log).expect("proxy log");
    // MySQL-flavored exfil would say "LIMIT 0,1"; the PostgreSQL set says
    // "LIMIT 1 OFFSET 0" (URL-encoded in transit, OFFSET stays verbatim).
    assert!(
        logtext.contains("OFFSET"),
        "expected PostgreSQL LIMIT/OFFSET queries in proxy log:\n{logtext}"
    );
    assert!(
        !logtext.contains("LIMIT+0%2C1") && !logtext.contains("LIMIT%200%2C1"),
        "MySQL-style LIMIT i,1 should not appear:\n{logtext}"
    );

    let _ = std::fs::remove_file(&log);
}
