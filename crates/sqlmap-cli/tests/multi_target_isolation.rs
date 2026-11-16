//! Runtime proof of multi-target (-m) session isolation across distinct
//! local origins. Target A sets a session cookie (Set-Cookie on every
//! response); target B, scanned in the same -m run, records every Cookie
//! header it receives. B must see the user-configured --cookie (seeded
//! into every target's client by design, matching sqlmap) and must NEVER
//! see the cookie A set. This is the runtime counterpart of the code
//! review (per-target Client -> per-target jar).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};

type Hits = Arc<Mutex<Vec<String>>>;

/// Mini origin: records Cookie headers; optionally sets its own cookie.
fn start_server(set_cookie: Option<&'static str>) -> (u16, Hits) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits: Hits = Arc::new(Mutex::new(Vec::new()));
    let seen = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || loop {
                let mut reader = BufReader::new(match stream.try_clone() {
                    Ok(s) => s,
                    Err(_) => return,
                });
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let mut cookie = String::new();
                let mut content_length = 0usize;
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                        break;
                    }
                    let hl = h.to_ascii_lowercase();
                    if let Some(v) = hl.strip_prefix("cookie:") {
                        cookie = v.trim().to_string();
                    }
                    if let Some(v) = hl.strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                if content_length > 0 {
                    let mut buf = vec![0u8; content_length];
                    let _ = reader.read_exact(&mut buf);
                }
                seen.lock().unwrap().push(cookie);
                let body = "<html><body>static page, nothing injectable</body></html>";
                let mut out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n", body.len());
                if let Some(sc) = set_cookie {
                    out.push_str(&format!("Set-Cookie: {sc}\r\n"));
                }
                out.push_str("\r\n");
                out.push_str(body);
                if stream.write_all(out.as_bytes()).is_err() {
                    return;
                }
            });
        }
    });
    (port, hits)
}

#[test]
fn cookies_set_by_one_target_never_reach_another() {
    let (a_port, _a_hits) = start_server(Some("leaked=AAA; Path=/"));
    let (b_port, b_hits) = start_server(None);

    let file = std::env::temp_dir().join(format!("sqlmaprs-isol-{}.txt", std::process::id()));
    std::fs::write(
        &file,
        format!(
            "http://127.0.0.1:{a_port}/get?id=1\nhttp://127.0.0.1:{b_port}/get?id=1\n"
        ),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sqlmap-rs"))
        .arg("-m")
        .arg(&file)
        .arg("--technique")
        .arg("B")
        .arg("--cookie")
        .arg("configured=yes")
        .output()
        .expect("run sqlmap-rs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("[*] target: "), "scan produced no targets: {stdout}");

    let cookies = b_hits.lock().unwrap();
    assert!(!cookies.is_empty(), "target B received no requests: {stdout}");
    assert!(
        cookies.iter().all(|c| !c.contains("leaked=AAA")),
        "cookie set by target A leaked to target B: {:?}",
        *cookies
    );
    assert!(
        cookies.iter().any(|c| c.contains("configured=yes")),
        "user-configured --cookie missing at target B (seeded by design): {:?}",
        *cookies
    );

    let _ = std::fs::remove_file(&file);
}
