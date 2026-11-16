//! Blocking HTTP client over ureq (port of sqlmap `lib/request/connect.py` essentials).

use sqlmap_core::config::Config;
use std::time::{Duration, Instant};

/// One request to fire. Mirrors what sqlmap assembles per payload round.
#[derive(Debug, Clone)]
pub struct RequestSpec {
    pub url: String,
    pub method: String,
    pub body: Option<String>,
    /// Extra headers (already tampered if applicable).
    pub headers: Vec<(String, String)>,
    /// Cookie header value, if any.
    pub cookie: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// Wall time for the request - the raw signal for time-based detection.
    pub elapsed: Duration,
}

pub struct Client {
    agent: ureq::Agent,
    timeout: Duration,
    user_agent: String,
    follow_redirects: bool,
    ignore_set_cookies: bool,
    /// Session cookie jar (port of sqlmap's Set-Cookie tracking in
    /// `lib/request/connect.py`: unless --ignore-set-cookie, every response's
    /// Set-Cookie updates the cookies sent on later requests). Mutex because
    /// the worker pool shares the client across threads.
    jar: std::sync::Mutex<std::collections::BTreeMap<String, String>>,
}

impl Client {
    pub fn new(conf: &Config) -> Self {
        let mut builder = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(conf.timeout.max(1)))
            .https_only(false);
        if !conf.follow_redirects {
            builder = builder.redirects(0);
        }
        if let Some(proxy) = &conf.proxy {
            // Fail loudly: silently dropping --proxy would leak requests the
            // user meant to route through it.
            let proxy = ureq::Proxy::new(proxy.as_str())
                .unwrap_or_else(|e| panic!("invalid --proxy {proxy}: {e}"));
            builder = builder.proxy(proxy);
        }
        // Seed the jar from --cookie so those cookies persist alongside
        // whatever the server sets later.
        let mut jar = std::collections::BTreeMap::new();
        if let Some(raw) = &conf.cookie {
            for (k, v) in crate::params::parse_pairs(raw, ';') {
                jar.insert(k, v);
            }
        }
        Self {
            agent: builder.build(),
            timeout: Duration::from_secs(conf.timeout.max(1)),
            user_agent: conf
                .user_agent
                .clone()
                .unwrap_or_else(|| "sqlmap-rs/0.1 (https://github.com/Chaim12345/sqlmap-rs)".into()),
            follow_redirects: conf.follow_redirects,
            ignore_set_cookies: conf.ignore_set_cookies,
            jar: std::sync::Mutex::new(jar),
        }
    }

    /// Merge a response's Set-Cookie headers into the jar.
    fn absorb_cookies(&self, resp: &Response) {
        if self.ignore_set_cookies {
            return;
        }
        let mut jar = self.jar.lock().unwrap();
        for (k, v) in &resp.headers {
            if !k.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            // Only the leading name=value pair; attributes are dropped.
            if let Some(pair) = v.split(';').next() {
                if let Some((name, value)) = pair.split_once('=') {
                    jar.insert(name.trim().to_string(), value.trim().to_string());
                }
            }
        }
    }

    /// Cookie header for a request: the spec's explicit cookie wins,
    /// otherwise the jar (when non-empty).
    fn cookie_header(&self, spec: &RequestSpec) -> Option<String> {
        if let Some(c) = &spec.cookie {
            return Some(c.clone());
        }
        let jar = self.jar.lock().unwrap();
        if jar.is_empty() {
            return None;
        }
        Some(
            jar.iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    /// True when the server held the connection past `time_sec` (server-side sleep).
    /// sqlmap distinguishes a deliberate SLEEP from a slow network by comparing
    /// against the original page's baseline response time.
    pub fn request(&self, spec: &RequestSpec) -> Result<Response, String> {
        let started = Instant::now();
        let mut req = match spec.method.to_ascii_uppercase().as_str() {
            "POST" => self.agent.post(&spec.url),
            "PUT" => self.agent.put(&spec.url),
            "HEAD" => self.agent.head(&spec.url),
            "DELETE" => self.agent.delete(&spec.url),
            _ => self.agent.get(&spec.url),
        };
        req = req.set("User-Agent", &self.user_agent);
        // Note: applied before spec.headers so a User-Agent entry there wins
        // (level>=3 header-place injection).
        for (k, v) in &spec.headers {
            req = req.set(k, v);
        }
        if let Some(c) = self.cookie_header(spec) {
            req = req.set("Cookie", &c);
        }
        let result = match spec.method.to_ascii_uppercase().as_str() {
            "POST" | "PUT" => req.send_string(spec.body.as_deref().unwrap_or("")),
            _ => req.call(),
        };
        let elapsed = started.elapsed();
        match result {
            Ok(resp) => {
                let resp = read_response(resp, elapsed);
                self.absorb_cookies(&resp);
                Ok(resp)
            }
            Err(ureq::Error::Status(code, resp)) => {
                // sqlmap treats HTTP error pages as valid responses for error-based detection.
                let _ = code;
                let resp = read_response(resp, elapsed);
                self.absorb_cookies(&resp);
                Ok(resp)
            }
            Err(ureq::Error::Transport(t)) => Err(format!("transport error: {t}")),
        }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn follow_redirects(&self) -> bool {
        self.follow_redirects
    }
}

fn read_response(resp: ureq::Response, elapsed: Duration) -> Response {
    let status = resp.status();
    let headers = resp
        .headers_names()
        .iter()
        .map(|n| (n.clone(), resp.header(n).unwrap_or("").to_string()))
        .collect();
    let body = resp.into_string().unwrap_or_default();
    Response {
        status,
        headers,
        body,
        elapsed,
    }
}
