//! Resumable session file tests: a second scan of the same target with the
//! same session file must return the stored results WITHOUT contacting the
//! app (proven by killing the server first), and --flush-session must force
//! fresh tests. Requires python3 on PATH.

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

fn scan(conf: &Config) -> sqlmap_detection::ScanResult {
    let client = Client::new(conf);
    sqlmap_detection::forms_scan::scan_auto(&client, conf)
}

#[test]
fn session_file_resumes_without_contacting_target() {
    let file = std::env::temp_dir().join(format!("sqlmaprs-session-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&file);
    let app = VulnApp::start(8796);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        enum_dbs: true,
        techniques: vec![Technique::Boolean],
        session_file: Some(file.to_string_lossy().into()),
        ..Config::default()
    };

    // First run: real scan, results saved.
    let first = scan(&conf);
    assert_eq!(
        first.kb.enumeration.databases,
        vec!["information_schema", "mysql", "shop"]
    );
    assert!(!first.kb.injections.is_empty());
    assert!(file.exists(), "session file not written");

    // Server down: a resumed scan must succeed purely from the session file.
    drop(app);
    let second = scan(&conf);
    assert_eq!(second.kb.enumeration.databases, first.kb.enumeration.databases);
    assert_eq!(second.kb.injections.len(), first.kb.injections.len());
    assert!(
        second.log.iter().any(|l| l.contains("session: loaded stored results")),
        "resume note missing: {:?}",
        second.log
    );

    // --flush-session ignores the stored results and re-tests; with the
    // server still down that finds nothing and overwrites the file.
    let mut conf_flush = conf.clone();
    conf_flush.flush_session = true;
    let third = scan(&conf_flush);
    assert!(third.kb.injections.is_empty(), "flush must re-test");
    let fourth = scan(&conf);
    assert!(
        fourth.kb.injections.is_empty(),
        "flushed session must not revive old results"
    );

    let _ = std::fs::remove_file(&file);
}
