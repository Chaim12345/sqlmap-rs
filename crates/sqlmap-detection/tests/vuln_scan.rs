//! End-to-end scan against the local deliberately-vulnerable app
//! (tests/vulnapp.py), mirroring how sqlmap is validated against its own
//! testbed. Requires python3 on PATH.

use sqlmap_core::config::{Config, Technique};
use sqlmap_http::client::Client;
use std::io::Read;
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
fn finds_numeric_injection_all_techniques() {
    let app = VulnApp::start(8741);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        techniques: vec![Technique::Boolean, Technique::Error, Technique::Time],
        time_sec: 1,
        timeout: 15,
        ..Config::default()
    };
    let kb = scan(&conf);
    for tech in [Technique::Boolean, Technique::Error, Technique::Time] {
        assert!(
            kb.injections.iter().any(|i| i.technique == tech && i.parameter == "id"),
            "expected {tech:?} injection on id, got {:?}",
            kb.injections.iter().map(|i| (i.parameter.clone(), i.technique)).collect::<Vec<_>>()
        );
    }
}

#[test]
fn finds_string_injection_and_fingerprints_mysql() {
    let app = VulnApp::start(8742);
    let conf = Config {
        target_url: app.url("/item?name=widget"),
        techniques: vec![Technique::Boolean, Technique::Error],
        timeout: 15,
        ..Config::default()
    };
    let kb = scan(&conf);
    assert!(kb.injections.iter().any(|i| i.parameter == "name"));
    assert_eq!(kb.fingerprinted_dbms.as_deref(), Some("mysql"));
}

#[test]
fn finds_post_body_injection() {
    let app = VulnApp::start(8744);
    let conf = Config {
        target_url: app.url("/login"),
        data: Some("user=admin&pass=x".into()),
        techniques: vec![Technique::Boolean, Technique::Error],
        timeout: 15,
        ..Config::default()
    };
    let kb = scan(&conf);
    for tech in [Technique::Boolean, Technique::Error] {
        assert!(
            kb.injections.iter().any(|i| i.place == sqlmap_core::config::Place::Post && i.parameter == "user" && i.technique == tech),
            "expected POST {tech:?} injection on user"
        );
    }
    // 'pass' must not be flagged by anything: it is never mutated to error.
    assert!(kb.injections.iter().all(|i| i.parameter != "pass"));
}

#[test]
fn finds_cookie_injection() {
    let app = VulnApp::start(8745);
    let conf = Config {
        target_url: app.url("/session"),
        cookie: Some("sid=abc123".into()),
        techniques: vec![Technique::Boolean, Technique::Error],
        timeout: 15,
        ..Config::default()
    };
    let kb = scan(&conf);
    assert!(
        kb.injections.iter().any(|i| i.place == sqlmap_core::config::Place::Cookie && i.parameter == "sid"),
        "expected Cookie injection on sid, got {:?}", kb.injections
    );
}

#[test]
fn tamper_chain_still_detects() {
    let app = VulnApp::start(8746);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        techniques: vec![Technique::Boolean],
        tampers: vec!["space2comment".into(), "randomcase".into()],
        timeout: 15,
        ..Config::default()
    };
    let kb = scan(&conf);
    assert!(
        kb.injections.iter().any(|i| i.technique == Technique::Boolean),
        "tampered boolean injection not found"
    );
}

#[test]
fn union_probing_finds_column_count() {
    let app = VulnApp::start(8747);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        techniques: vec![Technique::Union],
        timeout: 15,
        ..Config::default()
    };
    let kb = scan(&conf);
    let inj = kb
        .injections
        .iter()
        .find(|i| i.technique == Technique::Union)
        .expect("expected union probing finding");
    assert!(inj.note.contains("column count = 3"), "note: {}", inj.note);
}

#[test]
fn level3_finds_user_agent_injection() {
    let app = VulnApp::start(8748);
    let conf = Config {
        target_url: app.url("/track"),
        level: 3,
        techniques: vec![Technique::Boolean, Technique::Error],
        timeout: 15,
        ..Config::default()
    };
    let kb = scan(&conf);
    assert!(
        kb.injections.iter().any(|i| i.place == sqlmap_core::config::Place::UserAgent && i.parameter == "User-Agent"),
        "expected User-Agent injection, got {:?}", kb.injections
    );
}

#[test]
fn clean_param_reports_nothing() {
    let app = VulnApp::start(8743);
    // /other has no params at all - engine must report no testables, not crash.
    let conf = Config {
        target_url: app.url("/other"),
        timeout: 15,
        ..Config::default()
    };
    let kb = scan(&conf);
    assert!(kb.injections.is_empty());
}
