//! Crawler end-to-end tests against the local deliberately-vulnerable app
//! (tests/vulnapp.py): the index page links to every injectable route, so a
//! crawl from "/" must collect them without leaving the host, and a
//! `--crawl` scan must find their injection points. Requires python3 on PATH.

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

#[test]
fn crawl_stays_same_host_and_respects_depth() {
    let app = VulnApp::start(8761);
    let conf = Config {
        target_url: app.url("/"),
        ..Config::default()
    };
    let client = Client::new(&conf);

    // Depth 1: start page plus the pages it links to on this host.
    let pages = sqlmap_http::crawl::crawl(&client, &conf.target_url, 1);
    let urls: Vec<&str> = pages.iter().map(|p| p.url.as_str()).collect();
    for want in ["/", "/search", "/get?id=1", "/item?name=widget", "/detail"] {
        let want = app.url(want);
        assert!(urls.contains(&want.as_str()), "missing {want}: {urls:?}");
    }
    // Depth 1 must NOT reach /deep (linked only from /detail).
    let deep = app.url("/deep");
    assert!(!urls.contains(&deep.as_str()), "depth 1 reached /deep");
    // Every collected page is on the start host: no example.com, no
    // javascript:/mailto: links, no fragments, no static assets.
    let home = app.url("");
    assert!(
        urls.iter().all(|u| u.starts_with(&home)),
        "left the host: {urls:?}"
    );
    let start = app.url("/");
    assert_eq!(pages[0].url, start);
    assert_eq!(pages[0].depth, 0);

    // Depth 2 reaches /deep, and the / -> /detail -> / cycle terminates.
    let pages = sqlmap_http::crawl::crawl(&client, &conf.target_url, 2);
    let urls: Vec<&str> = pages.iter().map(|p| p.url.as_str()).collect();
    assert!(urls.contains(&deep.as_str()), "depth 2 missed /deep: {urls:?}");
    let deep_count = urls.iter().filter(|u| **u == deep.as_str()).count();
    assert_eq!(deep_count, 1, "each page visited once: {urls:?}");
}

#[test]
fn crawl_scan_tests_every_collected_page() {
    let app = VulnApp::start(8762);
    let conf = Config {
        target_url: app.url("/"),
        crawl_depth: 1,
        techniques: vec![Technique::Boolean],
        ..Config::default()
    };
    let client = Client::new(&conf);
    let result = sqlmap_detection::forms_scan::scan_auto(&client, &conf);
    assert!(
        result.log.iter().any(|l| l.contains("crawler collected")),
        "crawl log missing: {:?}",
        result.log
    );
    // Both injectable routes linked from the index were found and tested.
    let params: Vec<&str> = result
        .kb
        .injections
        .iter()
        .map(|i| i.parameter.as_str())
        .collect();
    assert!(params.contains(&"id"), "no id injection: {params:?}");
    assert!(params.contains(&"name"), "no name injection: {params:?}");
}
