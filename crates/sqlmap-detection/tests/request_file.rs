//! Request-file (-r) end-to-end test against the local test app
//! (tests/vulnapp.py): a saved raw POST request must parse into a Config
//! whose scan finds the POST injection on /login. Requires python3 on PATH.

use sqlmap_core::config::{Config, Technique};
use sqlmap_core::Place;
use sqlmap_core::requestfile::parse_request_file;
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
}

impl Drop for VulnApp {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

#[test]
fn saved_post_request_scans_to_injection() {
    let app = VulnApp::start(8797);
    let raw = format!(
        "POST /login HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUser-Agent: sqlmap-rs-test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nuser=admin&pass=x\r\n",
        app.1
    );
    let parsed = parse_request_file(&raw, "http").expect("request file parses");
    assert_eq!(parsed.method, "POST");
    assert_eq!(parsed.url, format!("http://127.0.0.1:{}/login", app.1));
    assert_eq!(parsed.body.as_deref(), Some("user=admin&pass=x"));

    let conf = Config {
        target_url: parsed.url,
        data: parsed.body,
        cookie: parsed.cookie,
        headers: parsed.headers,
        techniques: vec![Technique::Boolean],
        ..Config::default()
    };
    let client = Client::new(&conf);
    let kb = sqlmap_detection::Engine::new(&client, &conf).scan().kb;
    let inj = kb
        .injections
        .iter()
        .find(|i| i.parameter == "user")
        .expect("POST 'user' injection not found");
    assert_eq!(inj.place, Place::Post);
}
