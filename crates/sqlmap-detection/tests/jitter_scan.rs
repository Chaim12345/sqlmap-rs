//! Jitter resilience for boolean-blind extraction (port of the defense
//! upstream's tests/test_boolean_jitter.py exercises): the /jit fixture
//! route injects a deterministic transient 503 junk page every 4th request.
//! Without the anomaly guard a junk response matches neither page model and
//! silently flips a bisection bit; with it, the probe is re-requested and
//! extraction still recovers the emulator's schema list byte-for-byte.

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
fn blind_extraction_survives_deterministic_jitter() {
    let app = VulnApp::start(8880);
    let conf = Config {
        target_url: app.url("/jit?id=1"),
        enum_dbs: true,
        techniques: vec![Technique::Boolean],
        ..Config::default()
    };
    let client = Client::new(&conf);
    let result = sqlmap_detection::forms_scan::scan_auto(&client, &conf);
    let kb = &result.kb;
    assert!(
        kb.injections.iter().any(|i| i.technique == Technique::Boolean),
        "boolean injection must still be detected under jitter: {:?}",
        result.log
    );
    assert_eq!(
        kb.enumeration.databases,
        vec!["information_schema", "mysql", "shop"],
        "--dbs must recover the emulator's schema list byte-for-byte despite every-4th-request junk"
    );
}
