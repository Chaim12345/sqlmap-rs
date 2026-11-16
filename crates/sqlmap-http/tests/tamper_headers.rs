//! Header-based tampers (xforwardedfor, varnish) reach the server: the
//! client's requests carry the tamper-derived X-Forwarded-For header, and
//! the local test app's /whoami route echoes it. Requires python3 on PATH.

use sqlmap_core::config::Config;
use sqlmap_http::client::{Client, RequestSpec};
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

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/whoami", self.1)
    }
}

impl Drop for VulnApp {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn fetch_whoami(tampers: &[&str], port: u16) -> String {
    let app = VulnApp::start(port);
    let conf = Config {
        target_url: app.url(),
        tampers: tampers.iter().map(|s| s.to_string()).collect(),
        ..Config::default()
    };
    let client = Client::new(&conf);
    client
        .request(&RequestSpec {
            url: conf.target_url.clone(),
            method: "GET".into(),
            body: None,
            headers: Vec::new(),
            cookie: None,
        })
        .expect("request")
        .body
}

#[test]
fn varnish_sets_localhost_forwarded_for() {
    let body = fetch_whoami(&["varnish"], 8831);
    assert!(body.contains("xff:127.0.0.1"), "{body}");
}

#[test]
fn xforwardedfor_sets_a_random_ipv4() {
    let body = fetch_whoami(&["xforwardedfor"], 8832);
    let xff = body.split("xff:").nth(1).expect("xff echo").trim_end_matches("</body></html>");
    assert_ne!(xff, "none", "{body}");
    assert_eq!(xff.split('.').count(), 4, "{body}");
}

#[test]
fn no_tamper_means_no_forwarded_for() {
    let body = fetch_whoami(&[], 8833);
    assert!(!body.contains("xff:"), "{body}");
}
