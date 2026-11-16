//! Form-action scope guard: a form whose action URL leaves the target
//! origin is skipped, never submitted. The engine shares the scan client,
//! whose session cookies belong to the target origin; an off-origin
//! submission would forward them there. Pins the skip with two in-process
//! mini servers on different ports (different origins).

use sqlmap_core::config::Config;
use sqlmap_http::client::Client;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

type Hits = Arc<Mutex<Vec<String>>>;

fn start_server(body: &'static str) -> (u16, Hits) {
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
                let request_line = line.trim().to_string();
                let mut content_length = 0usize;
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                if content_length > 0 {
                    let mut buf = vec![0u8; content_length];
                    let _ = reader.read_exact(&mut buf);
                }
                seen.lock().unwrap().push(request_line);
                let out = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                if stream.write_all(out.as_bytes()).is_err() {
                    return;
                }
            });
        }
    });
    (port, hits)
}

#[test]
fn off_origin_form_action_is_skipped() {
    let (b_port, b_hits) = start_server("exfil receiver");
    // The target page carries one form whose action points at another
    // origin (different port). If the engine submitted it, B would see
    // requests.
    let page = format!(
        "<html><body><form method=\"GET\" action=\"http://127.0.0.1:{b_port}/collect\">\
         <input type=\"text\" name=\"q\" value=\"1\"></form></body></html>"
    );
    let leaked: &'static str = Box::leak(page.into_boxed_str());
    let (a_port, _a_hits) = start_server(leaked);

    let conf = Config {
        target_url: format!("http://127.0.0.1:{a_port}/search"),
        cookie: Some("sid=secret".into()),
        forms: true,
        ..Config::default()
    };
    let client = Client::new(&conf);
    let result = sqlmap_detection::forms_scan::scan_auto(&client, &conf);
    assert!(
        result.log.iter().any(|l| l.contains("off-origin action")),
        "skip was not logged: {:?}",
        result.log
    );
    assert_eq!(
        b_hits.lock().unwrap().len(),
        0,
        "off-origin form action received requests (session cookie would have gone with them)"
    );
}
