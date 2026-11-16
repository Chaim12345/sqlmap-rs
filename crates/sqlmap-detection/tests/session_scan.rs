//! Session-cookie persistence tests against the local test app
//! (tests/vulnapp.py): /rot rotates the sid via Set-Cookie and /whoami
//! echoes the sid the client sent, so tests observe exactly which cookies
//! later requests carried. Requires python3 on PATH.

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

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.1, path)
    }
}

impl Drop for VulnApp {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn get(url: &str, cookie: Option<&str>) -> RequestSpec {
    RequestSpec {
        url: url.to_string(),
        method: "GET".into(),
        body: None,
        headers: Vec::new(),
        cookie: cookie.map(str::to_string),
    }
}

fn sid_of(body: &str) -> &str {
    body.strip_prefix("<html><body>sid:")
        .and_then(|b| b.strip_suffix("</body></html>"))
        .expect("whoami page shape")
}

#[test]
fn set_cookie_updates_later_requests() {
    let app = VulnApp::start(8786);
    let conf = Config {
        target_url: app.url("/"),
        cookie: Some("sid=abc123".into()),
        ..Config::default()
    };
    let client = Client::new(&conf);

    // The seeded --cookie value is sent before any Set-Cookie arrives.
    let r = client.request(&get(&app.url("/whoami"), None)).unwrap();
    assert_eq!(sid_of(&r.body), "abc123");

    // The server rotates the sid; the next request must carry the new one.
    client.request(&get(&app.url("/rot"), None)).unwrap();
    let r = client.request(&get(&app.url("/whoami"), None)).unwrap();
    assert_eq!(sid_of(&r.body), "rotated99", "jar must track Set-Cookie");
}

#[test]
fn explicit_spec_cookie_wins_over_jar() {
    let app = VulnApp::start(8787);
    let conf = Config {
        target_url: app.url("/"),
        ..Config::default()
    };
    let client = Client::new(&conf);
    client.request(&get(&app.url("/rot"), None)).unwrap();
    let r = client
        .request(&get(&app.url("/whoami"), Some("sid=manual")))
        .unwrap();
    assert_eq!(sid_of(&r.body), "manual", "explicit cookie must win");
}

#[test]
fn ignore_set_cookie_keeps_original_cookies() {
    let app = VulnApp::start(8788);
    let conf = Config {
        target_url: app.url("/"),
        cookie: Some("sid=abc123".into()),
        ignore_set_cookies: true,
        ..Config::default()
    };
    let client = Client::new(&conf);
    client.request(&get(&app.url("/rot"), None)).unwrap();
    let r = client.request(&get(&app.url("/whoami"), None)).unwrap();
    assert_eq!(sid_of(&r.body), "abc123", "--ignore-set-cookie must keep the jar");
}
