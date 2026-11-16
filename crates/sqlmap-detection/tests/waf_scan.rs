//! WAF identification end-to-end tests against the local test app
//! (tests/vulnapp.py), which emulates ModSecurity on /wafed (406 + marker
//! page) and Cloudflare on /cdn (403 + Server header + block page).
//! Requires python3 on PATH.

use sqlmap_core::config::Config;
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

fn identify(url: &str) -> (Vec<String>, Vec<String>) {
    let conf = Config {
        target_url: url.to_string(),
        ..Config::default()
    };
    let client = Client::new(&conf);
    sqlmap_detection::waf::identify(&client, &conf)
}

#[test]
fn identifies_modsecurity_body_signature() {
    let app = VulnApp::start(8781);
    let (found, log) = identify(&app.url("/wafed"));
    assert_eq!(found, vec!["ModSecurity"], "log: {log:?}");
}

#[test]
fn identifies_cloudflare_via_header() {
    let app = VulnApp::start(8782);
    let (found, log) = identify(&app.url("/cdn"));
    assert_eq!(found, vec!["Cloudflare"], "log: {log:?}");
}

#[test]
fn no_waf_on_plain_app() {
    let app = VulnApp::start(8783);
    let (found, log) = identify(&app.url("/get?id=1"));
    assert!(found.is_empty(), "false positive: {found:?}");
    assert!(log.iter().any(|l| l.contains("no WAF/IPS identified")));
}

#[test]
fn identify_waf_flows_through_scan_auto() {
    // --identify-waf composes with a normal scan: the identification is
    // recorded in the knowledge base and logged, and the scan still runs.
    let app = VulnApp::start(8784);
    let conf = Config {
        target_url: app.url("/cdn"),
        identify_waf: true,
        ..Config::default()
    };
    let client = Client::new(&conf);
    let result = sqlmap_detection::forms_scan::scan_auto(&client, &conf);
    assert_eq!(result.kb.wafs, vec!["Cloudflare"]);
    assert!(
        result.log.iter().any(|l| l.contains("WAF/IPS identified: Cloudflare")),
        "log: {:?}",
        result.log
    );
}
