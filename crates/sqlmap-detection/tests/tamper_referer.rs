//! Payload-embedding header tamper (upstream referer.py): with
//! --tamper referer every injected request carries the assembled payload in
//! its Referer header. Verified through the tiny forward proxy's request
//! log (tests/tinyproxy.py). Requires python3 on PATH.

use sqlmap_core::config::{Config, Technique};
use sqlmap_http::client::Client;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn spawn(args: &[String]) -> Proc {
    Proc(Command::new("python3")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start python helper (python3 required)"))
}

fn wait_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("nothing came up on port {port}");
}

#[test]
fn referer_tamper_embeds_payload_in_header() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let vulnapp = format!("{manifest}/../../tests/vulnapp.py");
    let tinyproxy = format!("{manifest}/../../tests/tinyproxy.py");
    let log = std::env::temp_dir().join(format!("sqlmaprs-referer-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&log);

    let _app = spawn(&[vulnapp, "8841".into()]);
    let _proxy = spawn(&[tinyproxy, "8842".into(), log.to_string_lossy().into_owned()]);
    wait_ready(8841);
    wait_ready(8842);

    let conf = Config {
        target_url: "http://127.0.0.1:8841/get?id=1".into(),
        techniques: vec![Technique::Boolean],
        tampers: vec!["referer".into()],
        proxy: Some("http://127.0.0.1:8842".into()),
        ..Config::default()
    };
    let client = Client::new(&conf);
    let kb = sqlmap_detection::Engine::new(&client, &conf).scan().kb;
    // The payload also travels normally (GET param), so detection still works.
    assert!(kb.injections.iter().any(|i| i.parameter == "id"), "{:?}", kb.injections);

    let logtext = std::fs::read_to_string(&log).expect("proxy log");
    assert!(
        logtext
            .lines()
            .any(|l| l.contains("referer=") && l.contains("AND")),
        "expected a Referer header carrying the boolean payload:\n{logtext}"
    );

    let _ = std::fs::remove_file(&log);
}
