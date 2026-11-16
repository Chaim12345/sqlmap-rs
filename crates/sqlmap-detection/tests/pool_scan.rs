//! Worker-pool end-to-end test against the local deliberately-vulnerable app
//! (tests/vulnapp.py): requests that each sleep ~1s server-side finish in
//! about 1s on a 4-worker pool instead of ~4s sequentially, and results keep
//! request order. Requires python3 on PATH.

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

fn get(url: String) -> RequestSpec {
    RequestSpec {
        url,
        method: "GET".into(),
        body: None,
        headers: Vec::new(),
        cookie: None,
    }
}

#[test]
fn pool_runs_independent_requests_concurrently() {
    let app = VulnApp::start(8771);
    let conf = Config {
        target_url: app.url("/get?id=1"),
        ..Config::default()
    };
    let client = Client::new(&conf);
    // SLEEP(1) makes the server hold each of these for ~1s.
    let slow = || get(app.url("/get?id=1%20AND%20SLEEP(1)"));
    let fast = || get(app.url("/get?id=1"));

    // Four ~1s requests on 4 workers: ~1s wall, not ~4s.
    let started = Instant::now();
    let out = sqlmap_http::pool::run_requests(&client, vec![slow(), slow(), slow(), slow()], 4);
    let parallel = started.elapsed();
    assert!(out.iter().all(|r| r.is_ok()), "all ok: {out:?}");
    assert!(
        parallel < Duration::from_millis(2500),
        "4x1s requests on 4 workers took {parallel:?} - not concurrent"
    );

    // Same four on 1 worker: genuinely sequential, ~4s.
    let started = Instant::now();
    let out = sqlmap_http::pool::run_requests(&client, vec![slow(), slow(), slow(), slow()], 1);
    let serial = started.elapsed();
    assert!(out.iter().all(|r| r.is_ok()));
    assert!(
        serial >= Duration::from_millis(3500),
        "1 worker finished 4x1s in {serial:?} - baseline not sequential"
    );
    assert!(
        serial > parallel * 2,
        "pool ({parallel:?}) not clearly faster than serial ({serial:?})"
    );

    // Results stay in request order: alternating slow/fast specs map to
    // their own measured elapsed times positionally.
    let out = sqlmap_http::pool::run_requests(&client, vec![slow(), fast(), slow(), fast()], 4);
    let elapseds: Vec<Duration> = out.iter().map(|r| r.as_ref().unwrap().elapsed).collect();
    let threshold = Duration::from_millis(800);
    assert!(elapseds[0] >= threshold, "spec 0 was slow: {elapseds:?}");
    assert!(elapseds[1] < threshold, "spec 1 was fast: {elapseds:?}");
    assert!(elapseds[2] >= threshold, "spec 2 was slow: {elapseds:?}");
    assert!(elapseds[3] < threshold, "spec 3 was fast: {elapseds:?}");
}

#[test]
fn default_thread_count_is_four() {
    assert_eq!(Config::default().threads, 4);
}
