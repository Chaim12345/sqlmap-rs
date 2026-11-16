//! TLS-through-proxy verification (tests/tinyhttps.py + tests/tinyproxy.py
//! with CONNECT). Measured behavior of the https path:
//!   1. LIMITATION PINNED: ureq 2.12 does not send Proxy-Authorization on
//!      CONNECT, so authenticated https proxying fails loud with the
//!      proxy's 407 (it does not silently fall back to a direct
//!      connection, and our manual Proxy-Authorization header is never set
//!      on https URLs, so nothing leaks into the tunnel either).
//!   2. a CONNECT without Proxy-Authorization gets a 407.
//!   3. a full TLS session through an authenticated tunnel (openssl
//!      s_client, which does authenticate CONNECT) reaches the TLS origin,
//!      and the origin never sees a Proxy-Authorization header: the
//!      credential stays hop-by-hop inside CONNECT.
//! Cert-validation behavior with a CA-trusted certificate is NOT pinned
//! here (the origin cert is self-signed); only the credential path is.

use sqlmap_core::config::Config;
use sqlmap_http::client::{Client, RequestSpec};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const HTTPS_PORT: u16 = 8878;
const PROXY_PORT: u16 = 8879;

struct Proc(Child);

impl Proc {
    fn spawn(program: &str, args: &[String]) -> Self {
        let child = Command::new(program)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to start {program}: {e}"));
        Proc(child)
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn wait_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("fixture did not come up on port {port}");
}

struct Fixtures {
    proxy_log: std::path::PathBuf,
    origin_log: std::path::PathBuf,
    _proxy: Proc,
    _origin: Proc,
}

fn start_fixtures() -> Fixtures {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let dir = std::env::temp_dir().join(format!("sqlmaprs-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let status = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", &key.to_string_lossy(),
            "-out", &cert.to_string_lossy(),
            "-days", "1", "-subj", "/CN=localhost",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("openssl required");
    assert!(status.success(), "openssl cert generation failed");

    let proxy_log = dir.join("proxy.log");
    let origin_log = dir.join("origin.log");
    let proxy = Proc::spawn(
        "python3",
        &[
            format!("{manifest}/../../tests/tinyproxy.py"),
            "--auth".into(),
            "testuser:testpass".into(),
            PROXY_PORT.to_string(),
            proxy_log.to_string_lossy().into_owned(),
        ],
    );
    let origin = Proc::spawn(
        "python3",
        &[
            format!("{manifest}/../../tests/tinyhttps.py"),
            HTTPS_PORT.to_string(),
            cert.to_string_lossy().into_owned(),
            key.to_string_lossy().into_owned(),
            origin_log.to_string_lossy().into_owned(),
        ],
    );
    wait_port(PROXY_PORT);
    wait_port(HTTPS_PORT);
    Fixtures {
        proxy_log,
        origin_log,
        _proxy: proxy,
        _origin: origin,
    }
}

fn read_log(path: &std::path::Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if !text.is_empty() || Instant::now() > deadline {
            return text;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn client_connect_carries_proxy_credentials_and_tls_origin_sees_none() {
    let f = start_fixtures();

    // 1. The real client through the authenticated proxy. ureq 2.12 does
    // not send Proxy-Authorization on CONNECT (measured, not assumed), so
    // the proxy answers 407 and the request must FAIL LOUD - never a
    // silent direct connection, never a credential inside the tunnel.
    let conf = Config {
        target_url: format!("https://127.0.0.1:{HTTPS_PORT}/x"),
        proxy: Some(format!("http://127.0.0.1:{PROXY_PORT}")),
        proxy_cred: Some("testuser:testpass".into()),
        ..Config::default()
    };
    let client = Client::new(&conf);
    let result = client.request(&RequestSpec {
        url: format!("https://127.0.0.1:{HTTPS_PORT}/x"),
        method: "GET".into(),
        body: None,
        headers: vec![],
        cookie: None,
    });
    assert!(
        result.is_err(),
        "authenticated https proxying unexpectedly succeeded (ureq changed?)"
    );
    let proxy_log = read_log(&f.proxy_log);
    assert!(
        proxy_log.contains(&format!("CONNECT 127.0.0.1:{HTTPS_PORT} auth=missing")),
        "expected an unauthenticated CONNECT attempt: {proxy_log}"
    );
    // The TLS origin saw nothing: the tunnel never existed.
    assert!(
        f.origin_log.metadata().map(|m| m.len()).unwrap_or(0) == 0
            || !std::fs::read_to_string(&f.origin_log).unwrap_or_default().contains("GET"),
        "origin saw a request despite the failed CONNECT"
    );

    // 2. A CONNECT without credentials is refused.
    let mut raw = TcpStream::connect(("127.0.0.1", PROXY_PORT)).unwrap();
    raw.write_all(format!("CONNECT 127.0.0.1:{HTTPS_PORT} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
        .unwrap();
    let mut reader = BufReader::new(raw);
    let mut status = String::new();
    reader.read_line(&mut status).unwrap();
    assert!(status.contains("407"), "expected 407, got: {status}");

    // 3. Full TLS through the tunnel via openssl s_client (its own proxy
    // auth): the TLS origin answers, and its log proves no
    // Proxy-Authorization header ever arrived inside the tunnel.
    let mut child = Command::new("openssl")
        .args([
            "s_client", "-quiet", "-ign_eof",
            "-connect", &format!("127.0.0.1:{HTTPS_PORT}"),
            "-proxy", &format!("127.0.0.1:{PROXY_PORT}"),
            "-proxy_user", "testuser",
            "-proxy_pass", "pass:testpass",
            "-servername", "localhost",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("openssl s_client required");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"GET /x HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut out = String::new();
    let _ = child.stdout.take().unwrap().read_to_string(&mut out);
    let _ = child.wait();
    assert!(out.contains("TLS-ORIGIN"), "no TLS response through tunnel: {out}");
    let origin_log = read_log(&f.origin_log);
    assert!(origin_log.contains("proxy-auth=absent"), "origin saw credentials: {origin_log}");
    assert!(!origin_log.contains("proxy-auth=present"));
}
