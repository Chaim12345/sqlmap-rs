//! A pure reflection endpoint is NOT an injection point: /echo renders the
//! q parameter verbatim with no SQL interpretation. Before the reflection
//! guard (port of upstream stripReflection), the echoed true/false payloads
//! made the two pages differ and boolean detection false-positived here.

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
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", va.1)).is_ok() {
                return va;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("vulnapp did not come up on port {port}");
    }
}

impl Drop for VulnApp {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

#[test]
fn pure_echo_is_not_flagged_boolean() {
    let app = VulnApp::start(8877);
    let conf = Config {
        target_url: format!("http://127.0.0.1:{}/echo?q=hello-world", app.1),
        techniques: vec![Technique::Boolean],
        ..Config::default()
    };
    let client = Client::new(&conf);
    let result = sqlmap_detection::engine::Engine::new(&client, &conf).scan();
    assert!(
        result.kb.injections.is_empty(),
        "echo endpoint flagged injectable: {:?}",
        result.kb.injections
    );
}
