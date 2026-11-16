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
}

impl Client {
    pub fn new(conf: &Config) -> Self {
        let mut builder = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(conf.timeout.max(1)))
            .https_only(false);
        if !conf.follow_redirects {
            builder = builder.redirects(0);
        }
        Self {
            agent: builder.build(),
            timeout: Duration::from_secs(conf.timeout.max(1)),
            user_agent: conf
                .user_agent
                .clone()
                .unwrap_or_else(|| "sqlmap-rs/0.1 (https://github.com/Chaim12345/sqlmap-rs)".into()),
            follow_redirects: conf.follow_redirects,
        }
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
        for (k, v) in &spec.headers {
            req = req.set(k, v);
        }
        if let Some(c) = &spec.cookie {
            req = req.set("Cookie", c);
        }
        let result = match spec.method.to_ascii_uppercase().as_str() {
            "POST" | "PUT" => req.send_string(spec.body.as_deref().unwrap_or("")),
            _ => req.call(),
        };
        let elapsed = started.elapsed();
        match result {
            Ok(resp) => Ok(read_response(resp, elapsed)),
            Err(ureq::Error::Status(code, resp)) => {
                // sqlmap treats HTTP error pages as valid responses for error-based detection.
                let _ = code;
                Ok(read_response(resp, elapsed))
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
