//! Scope guards on the HTTP layer: redirects are followed manually and only
//! while the target stays on the exact same origin (scheme://host:port), so
//! session credentials can never be carried off-origin by a redirect, and
//! cross-port targets stay out of scope. Regression cover for the crawler
//! scope review (the crawler compares full origins, not upstream-style
//! hostnames).

use sqlmap_core::config::Config;
use sqlmap_http::client::{Client, RequestSpec};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
struct Hit {
    request_line: String,
    had_cookie: bool,
    had_proxy_auth: bool,
}

type Hits = Arc<Mutex<Vec<Hit>>>;

struct Mini {
    port: u16,
    hits: Hits,
}

impl Mini {
    /// Routes:
    ///   /start-same   -> 302 Location: /landed          (same origin)
    ///   /landed       -> 200 "LANDED"
    ///   /start-cross  -> 302 Location: http://127.0.0.1:<cross_port>/b   (off-origin)
    ///   /loop         -> 302 Location: /loop             (redirect loop)
    /// kind "b": every request -> 200 "B-HIT"
    fn start(kind: &'static str, cross_port: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits: Hits = Arc::new(Mutex::new(Vec::new()));
        let seen = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let seen = seen.clone();
                std::thread::spawn(move || handle_conn(stream, kind, cross_port, seen));
            }
        });
        Mini { port, hits }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }
}

fn handle_conn(mut stream: std::net::TcpStream, kind: &str, cross_port: u16, seen: Hits) {
    loop {
        let mut reader = BufReader::new(match stream.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        });
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let request_line = line.trim().to_string();
        let mut had_cookie = false;
        let mut had_proxy_auth = false;
        let mut content_length = 0usize;
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                break;
            }
            let hl = h.to_ascii_lowercase();
            if hl.starts_with("cookie:") {
                had_cookie = true;
            }
            if hl.starts_with("proxy-authorization:") {
                had_proxy_auth = true;
            }
            if let Some(v) = hl.strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
        if content_length > 0 {
            let mut body = vec![0u8; content_length];
            let _ = reader.read_exact(&mut body);
        }
        seen.lock().unwrap().push(Hit {
            request_line: request_line.clone(),
            had_cookie,
            had_proxy_auth,
        });
        let path = request_line.split_whitespace().nth(1).unwrap_or("/");
        let (status, location, body) = route(kind, path, cross_port);
        let mut out = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
        if let Some(loc) = location {
            out.push_str(&format!("Location: {loc}\r\n"));
        }
        out.push_str("\r\n");
        out.push_str(&body);
        if stream.write_all(out.as_bytes()).is_err() {
            return;
        }
    }
}

fn route(kind: &str, path: &str, cross_port: u16) -> (&'static str, Option<String>, String) {
    if kind == "b" {
        return ("200 OK", None, "B-HIT".to_string());
    }
    match path {
        "/start-same" => (
            "302 Found",
            Some("/landed".to_string()),
            String::new(),
        ),
        "/landed" => ("200 OK", None, "LANDED".to_string()),
        "/start-cross" => (
            "302 Found",
            Some(format!("http://127.0.0.1:{cross_port}/b")),
            String::new(),
        ),
        "/loop" => ("302 Found", Some("/loop".to_string()), String::new()),
        _ => ("404 Not Found", None, "nope".to_string()),
    }
}

fn client() -> Client {
    let conf = Config {
        target_url: "http://127.0.0.1/".into(),
        follow_redirects: true,
        cookie: Some("sid=abc".into()),
        ..Config::default()
    };
    Client::new(&conf)
}

fn get(client: &Client, url: &str) -> sqlmap_http::client::Response {
    client
        .request(&RequestSpec {
            url: url.to_string(),
            method: "GET".into(),
            body: None,
            headers: vec![],
            cookie: None,
        })
        .expect("request failed")
}

#[test]
fn same_origin_redirect_is_followed_with_cookie() {
    let a = Mini::start("a", 0);
    let resp = get(&client(), &a.url("/start-same"));
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, "LANDED");
    let hits = a.hits.lock().unwrap();
    let landed = hits
        .iter()
        .find(|h| h.request_line.contains("/landed"))
        .expect("no /landed hit");
    assert!(landed.had_cookie, "session cookie must ride same-origin hops");
}

#[test]
fn cross_port_redirect_is_not_followed_and_cookie_never_leaves() {
    let b = Mini::start("b", 0);
    let a = Mini::start("a", b.port);
    let resp = get(&client(), &a.url("/start-cross"));
    assert_eq!(resp.status, 302, "off-origin redirect returned unfollowed");
    assert_eq!(
        b.hits.lock().unwrap().len(),
        0,
        "cross-port origin received a request; cookie would have leaked with it"
    );
}

#[test]
fn redirect_loop_terminates() {
    let a = Mini::start("a", 0);
    let resp = get(&client(), &a.url("/loop"));
    assert_eq!(resp.status, 302);
    let loops = a
        .hits
        .lock()
        .unwrap()
        .iter()
        .filter(|h| h.request_line.contains("/loop"))
        .count();
    assert!(loops <= 11, "redirect cap exceeded: {loops} hops");
}

#[test]
fn crawler_scope_stays_strict_origin() {
    // The crawler's same-origin decision compares full origins, not
    // upstream checkSameHost hostnames: a cross-port link is out of scope
    // even though upstream's helper would call it the same host.
    let a = Mini::start("a", 0);
    let b = Mini::start("b", 0);
    assert!(sqlmap_http::crawl::same_host(&a.url("/x"), &b.url("/y")));
}

struct Proc(std::process::Child);

impl Proc {
    fn spawn(args: &[String]) -> Self {
        let child = std::process::Command::new("python3")
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to start fixture (python3 required)");
        Proc(child)
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn wait_port(port: u16) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("fixture did not come up on port {port}");
}

#[test]
fn proxy_consumes_proxy_authorization_and_origin_never_sees_it() {
    let origin = Mini::start("b", 0);
    let manifest = env!("CARGO_MANIFEST_DIR");
    let log = std::env::temp_dir().join(format!("sqlmaprs-scope-proxy-{}.log", std::process::id()));
    let _proxy = Proc::spawn(&[
        format!("{manifest}/../../tests/tinyproxy.py"),
        "--auth".into(),
        "testuser:testpass".into(),
        "8876".into(),
        log.to_string_lossy().into_owned(),
    ]);
    wait_port(8876);
    let conf = Config {
        target_url: origin.url("/b"),
        proxy: Some("http://127.0.0.1:8876".into()),
        proxy_cred: Some("testuser:testpass".into()),
        ..Config::default()
    };
    let client = Client::new(&conf);
    let resp = get(&client, &origin.url("/b"));
    assert_eq!(resp.status, 200, "request through auth proxy reached origin");
    let hits = origin.hits.lock().unwrap();
    assert!(!hits.is_empty(), "origin saw no request");
    assert!(
        hits.iter().all(|h| !h.had_proxy_auth),
        "Proxy-Authorization leaked to the origin through the proxy"
    );
    drop(hits);
    let proxy_log = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        proxy_log.contains("auth=ok"),
        "proxy did not record an authenticated request: {proxy_log}"
    );
}

#[test]
fn direct_request_without_proxy_never_sets_proxy_authorization() {
    let origin = Mini::start("b", 0);
    let resp = get(&client(), &origin.url("/b"));
    assert_eq!(resp.status, 200);
    let hits = origin.hits.lock().unwrap();
    assert!(hits.iter().all(|h| !h.had_proxy_auth));
}
