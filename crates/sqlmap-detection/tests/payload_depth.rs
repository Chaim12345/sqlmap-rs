//! Payload-depth tests against the local test app (tests/vulnapp.py):
//! second-wave payloads (UpdateXML error-based, subquery SLEEP time-based,
//! MySQL '#' comment boolean) must be emulated by the app and usable by the
//! engine - /legacy suppresses ExtractValue errors so the UpdateXML payload
//! has to fire for detection to succeed. Requires python3 on PATH.

use sqlmap_core::config::{Config, Technique};
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

fn get(client: &Client, url: &str) -> sqlmap_http::client::Response {
    client
        .request(&RequestSpec {
            url: url.to_string(),
            method: "GET".into(),
            body: None,
            headers: Vec::new(),
            cookie: None,
        })
        .unwrap()
}

#[test]
fn updatexml_echoes_marker_like_extractvalue() {
    let app = VulnApp::start(8791);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        ..Config::default()
    };
    let client = Client::new(&conf);
    let r = get(&client, &app.url("/get?id=1%20AND%20UpdateXML(1,CONCAT(0x7e,mark99),1)"));
    assert!(r.body.contains("mark99"), "marker not echoed: {}", r.body);
}

#[test]
fn legacy_route_forces_second_wave_error_payload() {
    // /legacy suppresses ExtractValue error echoes; an error-based scan must
    // fall through to the UpdateXML payload to confirm the injection.
    let app = VulnApp::start(8792);
    let conf = Config {
        target_url: app.url("/legacy?id=1"),
        techniques: vec![Technique::Error],
        ..Config::default()
    };
    let client = Client::new(&conf);
    let kb = sqlmap_detection::Engine::new(&client, &conf).scan().kb;
    let inj = kb
        .injections
        .iter()
        .find(|i| i.technique == Technique::Error)
        .expect("error-based injection on /legacy");
    assert!(
        inj.payload.contains("UpdateXML"),
        "expected the UpdateXML payload to fire, got: {}",
        inj.payload
    );
}

#[test]
fn subquery_sleep_shape_delays_response() {
    let app = VulnApp::start(8793);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        ..Config::default()
    };
    let client = Client::new(&conf);
    let r = get(
        &client,
        &app.url("/get?id=1%20AND%20(SELECT%201%20FROM%20(SELECT(SLEEP(1)))x)"),
    );
    assert!(
        r.elapsed >= Duration::from_millis(900),
        "subquery SLEEP did not delay: {:?}",
        r.elapsed
    );
}

#[test]
fn mysql_hash_comment_boolean_pair() {
    let app = VulnApp::start(8794);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        ..Config::default()
    };
    let client = Client::new(&conf);
    let t = get(&client, &app.url("/get?id=1%20AND%201=1%23"));
    let f = get(&client, &app.url("/get?id=1%20AND%201=2%23"));
    assert!(t.body.contains("Item 1"), "true page changed: {}", t.body);
    assert!(f.body.contains("No results"), "false page unchanged: {}", f.body);
}
