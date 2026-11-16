//! Tamper-script coverage for the second batch (symboliclogical, uppercase,
//! versionedmorekeywords): boolean detection against the local test app
//! (tests/vulnapp.py) must succeed through each tamper and through the
//! composed chain. Requires python3 on PATH.

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

fn boolean_scan_finds_id(port: u16, tampers: &[&str]) {
    let app = VulnApp::start(port);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        techniques: vec![Technique::Boolean],
        tampers: tampers.iter().map(|s| s.to_string()).collect(),
        ..Config::default()
    };
    let client = Client::new(&conf);
    let kb = sqlmap_detection::Engine::new(&client, &conf).scan().kb;
    assert!(
        kb.injections
            .iter()
            .any(|i| i.parameter == "id" && i.technique == Technique::Boolean),
        "no boolean injection with tampers {tampers:?}: {:?}",
        kb.injections
    );
}

#[test]
fn detection_through_symboliclogical() {
    boolean_scan_finds_id(8801, &["symboliclogical"]);
}

#[test]
fn detection_through_uppercase() {
    boolean_scan_finds_id(8802, &["uppercase"]);
}

#[test]
fn detection_through_versionedmorekeywords() {
    boolean_scan_finds_id(8803, &["versionedmorekeywords"]);
}

#[test]
fn detection_through_composed_chain() {
    boolean_scan_finds_id(8804, &["symboliclogical", "versionedmorekeywords", "uppercase"]);
}
