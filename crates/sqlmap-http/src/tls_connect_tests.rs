//! Local CONNECT authentication and TLS verification regressions.
//! No certificate-validation bypass is used. Only these tests trust their CA.

use super::{Client, RequestSpec};
use sqlmap_core::config::Config;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(args: &[String]) -> Proc {
    Proc(
        Command::new("python3")
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("fixture failed to start on {port}");
}

fn openssl(args: &[&str]) {
    let output = Command::new("openssl")
        .args(args)
        .output()
        .expect("openssl required");
    assert!(
        output.status.success(),
        "openssl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Fixtures {
    dir: PathBuf,
    cert_der: PathBuf,
    proxy_log: PathBuf,
    origin_log: PathBuf,
    proxy_port: u16,
    origin_port: u16,
    _proxy: Proc,
    _origin: Proc,
}
impl Drop for Fixtures {
    fn drop(&mut self) {
        let _ = self._proxy.0.kill();
        let _ = self._origin.0.kill();
        let _ = self._proxy.0.wait();
        let _ = self._origin.0.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fixtures {
    fn start() -> Self {
        let dir = std::env::temp_dir().join(format!("sqlmaprs-connect-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let cert_der = dir.join("ca.der");
        let ca = dir.join("ca.pem");
        let ca_key = dir.join("ca-key.pem");
        let csr = dir.join("origin.csr");
        let extensions = dir.join("origin.ext");
        std::fs::write(&extensions,
            "subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n").unwrap();
        openssl(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            ca_key.to_str().unwrap(),
            "-out",
            ca.to_str().unwrap(),
            "-days",
            "1",
            "-subj",
            "/CN=Local Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]);
        openssl(&[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            csr.to_str().unwrap(),
            "-subj",
            "/CN=localhost",
        ]);
        openssl(&[
            "x509",
            "-req",
            "-in",
            csr.to_str().unwrap(),
            "-CA",
            ca.to_str().unwrap(),
            "-CAkey",
            ca_key.to_str().unwrap(),
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            extensions.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
        ]);
        openssl(&[
            "x509",
            "-in",
            ca.to_str().unwrap(),
            "-outform",
            "DER",
            "-out",
            cert_der.to_str().unwrap(),
        ]);
        let proxy_log = dir.join("proxy.log");
        let origin_log = dir.join("origin.log");
        // Do not accept stale output from a previous test process with a reused PID.
        std::fs::write(&proxy_log, "").unwrap();
        std::fs::write(&origin_log, "").unwrap();
        let proxy_port = free_port();
        let mut origin_port = free_port();
        while origin_port == proxy_port {
            origin_port = free_port();
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let proxy = spawn(&[
            root.join("tests/tinyproxy.py")
                .to_string_lossy()
                .into_owned(),
            proxy_port.to_string(),
            proxy_log.to_string_lossy().into_owned(),
            "--auth".into(),
            "testuser:testpass".into(),
        ]);
        let origin = spawn(&[
            root.join("tests/tinyhttps.py")
                .to_string_lossy()
                .into_owned(),
            origin_port.to_string(),
            cert.to_string_lossy().into_owned(),
            key.to_string_lossy().into_owned(),
            origin_log.to_string_lossy().into_owned(),
        ]);
        wait_port(proxy_port);
        wait_port(origin_port);
        Self {
            dir,
            cert_der,
            proxy_log,
            origin_log,
            proxy_port,
            origin_port,
            _proxy: proxy,
            _origin: origin,
        }
    }

    fn config(&self, credentials: Option<&str>, url_userinfo: bool) -> Config {
        Config {
            timeout: 5,
            proxy: Some(if url_userinfo {
                format!(
                    "http://{}@127.0.0.1:{}",
                    credentials.unwrap(),
                    self.proxy_port
                )
            } else {
                format!("http://127.0.0.1:{}", self.proxy_port)
            }),
            proxy_cred: if url_userinfo {
                None
            } else {
                credentials.map(str::to_string)
            },
            ..Config::default()
        }
    }

    fn trusted_client(&self, conf: &Config) -> Client {
        use ureq::rustls::{pki_types::CertificateDer, ClientConfig, RootCertStore};
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(std::fs::read(&self.cert_der).unwrap()))
            .unwrap();
        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Client::with_builder(conf, ureq::AgentBuilder::new().tls_config(Arc::new(tls)))
    }

    fn request(&self, client: &Client, host: &str, path: &str) -> Result<super::Response, String> {
        client.request(&RequestSpec {
            url: format!("https://{host}:{}/{path}", self.origin_port),
            method: "GET".into(),
            body: None,
            headers: vec![],
            cookie: None,
        })
    }

    fn origin_log(&self) -> String {
        std::fs::read_to_string(&self.origin_log).unwrap()
    }
}

#[test]
fn authenticated_connect_respects_tls_and_keeps_proxy_credentials_hop_by_hop() {
    let f = Fixtures::start();
    // Both supported credential sources must work through the real Client.
    for (source, userinfo) in [("flag", false), ("url", true)] {
        let conf = f.config(Some("testuser:testpass"), userinfo);
        let client = f.trusted_client(&conf);
        let response = f
            .request(&client, "localhost", source)
            .expect("authenticated TLS request");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "TLS-ORIGIN");
        let log = f.origin_log();
        assert!(
            log.contains(&format!("/{source} proxy-auth=absent")),
            "{log}"
        );
        assert!(
            !log.contains("proxy-auth=present"),
            "proxy credentials reached origin"
        );
    }
    assert!(std::fs::read_to_string(&f.proxy_log)
        .unwrap()
        .contains(&format!("CONNECT localhost:{} auth=ok", f.origin_port)));

    // Missing or wrong credentials must fail without reaching the origin.
    for credentials in [None, Some("testuser:wrong")] {
        let before = f.origin_log();
        let client = f.trusted_client(&f.config(credentials, false));
        assert!(f.request(&client, "localhost", "unauthorized").is_err());
        assert_eq!(
            f.origin_log(),
            before,
            "failed proxy auth fell back to direct transport"
        );
    }

    // Production trust must reject the local untrusted CA, not disable verification.
    let conf = f.config(Some("testuser:testpass"), false);
    let before = f.origin_log();
    let error = f
        .request(&Client::new(&conf), "localhost", "untrusted")
        .unwrap_err();
    assert!(
        error.contains("UnknownIssuer"),
        "unexpected certificate error: {error}"
    );
    assert_eq!(f.origin_log(), before);

    // Trusting the CA must not bypass hostname verification.
    let client = f.trusted_client(&conf);
    let error = f.request(&client, "127.0.0.1", "wrong-host").unwrap_err();
    assert!(
        error.contains("not valid for name"),
        "unexpected hostname error: {error}"
    );
    assert_eq!(f.origin_log(), before);

    // Regression for the fixture itself: Basic's scheme is case-insensitive,
    // but the credential bytes remain case-sensitive.
    for (scheme, encoded, expected) in [
        ("Basic", "dGVzdHVzZXI6dGVzdHBhc3M=", "200"),
        ("basic", "dGVzdHVzZXI6dGVzdHBhc3M=", "200"),
        ("bAsIc", "dGVzdHVzZXI6dGVzdHBhc3M=", "200"),
        ("Basic", "ZHVtbXk6d3Jvbmc=", "407"),
        ("Bearer", "dGVzdHVzZXI6dGVzdHBhc3M=", "407"),
    ] {
        let mut raw = TcpStream::connect(("127.0.0.1", f.proxy_port)).unwrap();
        raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(raw, "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nProxy-Authorization: {scheme} {encoded}\r\n\r\n", f.origin_port, f.origin_port).unwrap();
        let mut status = String::new();
        BufReader::new(raw).read_line(&mut status).unwrap();
        assert!(status.contains(expected), "{scheme}: {status}");
    }
    // Fixtures stop their children and remove their local test keys on drop.
    assert!(f.dir.is_dir());
}
