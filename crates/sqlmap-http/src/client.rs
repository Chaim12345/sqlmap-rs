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
    /// Headers injected by header-based tamper scripts (xforwardedfor,
    /// varnish). Applied to every request; explicit spec.headers win.
    tamper_headers: Vec<(String, String)>,
    /// Proxy-Authorization for plain-HTTP forwarding only. For HTTPS,
    /// ureq authenticates the CONNECT request from proxy URL userinfo;
    /// never put this header inside the TLS tunnel to the origin.
    proxy_auth: Option<String>,
    /// Session cookie jar (port of sqlmap's Set-Cookie tracking in
    /// `lib/request/connect.py`: unless --ignore-set-cookie, every response's
    /// Set-Cookie updates the cookies sent on later requests). Mutex because
    /// the worker pool shares the client across threads.
    jar: std::sync::Mutex<std::collections::BTreeMap<String, String>>,
}

impl Client {
    pub fn new(conf: &Config) -> Self {
        Self::with_builder(conf, ureq::AgentBuilder::new())
    }

    // Private builder injection lets tests trust only their generated local
    // CA while exercising the production proxy and request setup unchanged.
    fn with_builder(conf: &Config, builder: ureq::AgentBuilder) -> Self {
        let mut builder = builder
            .timeout(Duration::from_secs(conf.timeout.max(1)))
            .https_only(false)
            // Redirects are followed manually in request() with a strict
            // same-origin check: ureq's auto-follow carries the request's
            // headers (session cookies included) to any Location target,
            // which would let a redirect move credentials off-origin.
            .redirects(0);
        let mut proxy_auth = None;
        if let Some(proxy) = &conf.proxy {
            // Fail loudly: silently dropping --proxy would leak requests the
            // user meant to route through it.
            let mut proxy_url = proxy.clone();
            if let Some(cred) = &conf.proxy_cred {
                // --proxy-cred supplies the userinfo when the URL has none.
                if !proxy_url.rsplit('/').next().unwrap_or_default().contains('@') {
                    let (scheme, rest) = proxy_url
                        .split_once("://")
                        .map(|(a, b)| (format!("{a}://"), b.to_string()))
                        .unwrap_or_default();
                    proxy_url = format!("{scheme}{cred}@{rest}");
                }
            }
            let proxy = ureq::Proxy::new(proxy_url.as_str())
                .unwrap_or_else(|e| panic!("invalid --proxy {proxy_url}: {e}"));
            if proxy_url.starts_with("http://") || !proxy_url.contains("://") {
                if let Some(userinfo) = proxy_url
                    .split_once("://")
                    .and_then(|(_, rest)| rest.split_once('@'))
                    .map(|(u, _)| u.to_string())
                {
                    use base64::Engine;
                    proxy_auth = Some(format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD.encode(userinfo)
                    ));
                }
            }
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
            tamper_headers: sqlmap_tamper::header_mutations(&conf.tampers, 0xC0FFEE),
            proxy_auth,
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

    /// Fire one request, following redirects manually when enabled.
    /// Unlike ureq's auto-follow, a redirect is only followed while the
    /// Location target stays on the exact same origin (scheme://host:port)
    /// as the URL being redirected: our requests carry session credentials
    /// (Cookie header), and those must never be forwarded off-origin.
    pub fn request(&self, spec: &RequestSpec) -> Result<Response, String> {
        let mut current = spec.clone();
        let mut resp = self.fire(&current)?;
        for _ in 0..MAX_REDIRECTS {
            if !self.follow_redirects || !matches!(resp.status, 301 | 302 | 303 | 307 | 308) {
                return Ok(resp);
            }
            let location = resp
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.clone());
            let Some(location) = location else { return Ok(resp) };
            let next = match resolve_location(&current.url, &location) {
                Some(u) => u,
                None => return Ok(resp),
            };
            // Strict origin boundary: a redirect that would leave the
            // origin is returned to the caller unfollowed.
            if crate::crawl::origin(&next) != crate::crawl::origin(&current.url) {
                return Ok(resp);
            }
            current.url = next;
            // 301/302/303 rewrite to GET (browser and urllib2 behavior);
            // 307/308 preserve method and body.
            if matches!(resp.status, 301 | 302 | 303) {
                current.method = "GET".to_string();
                current.body = None;
            }
            resp = self.fire(&current)?;
        }
        Ok(resp)
    }

    /// True when the server held the connection past `time_sec` (server-side sleep).
    /// sqlmap distinguishes a deliberate SLEEP from a slow network by comparing
    /// against the original page's baseline response time.
    fn fire(&self, spec: &RequestSpec) -> Result<Response, String> {
        let started = Instant::now();
        let mut req = match spec.method.to_ascii_uppercase().as_str() {
            "POST" => self.agent.post(&spec.url),
            "PUT" => self.agent.put(&spec.url),
            "HEAD" => self.agent.head(&spec.url),
            "DELETE" => self.agent.delete(&spec.url),
            _ => self.agent.get(&spec.url),
        };
        req = req.set("User-Agent", &self.user_agent);
        if spec.url.starts_with("http://") {
            if let Some(h) = &self.proxy_auth {
                req = req.set("Proxy-Authorization", h);
            }
        }
        for (k, v) in &self.tamper_headers {
            req = req.set(k, v);
        }
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

/// Maximum redirect hops followed manually (matches ureq's default of 10).
const MAX_REDIRECTS: usize = 10;

/// Resolve a Location header against the URL that produced it. Absolute
/// URLs pass through; root-relative and path-relative locations resolve
/// against the request URL. Anything unparseable returns None (not followed).
fn resolve_location(base: &str, location: &str) -> Option<String> {
    let location = location.trim();
    if location.is_empty() {
        return None;
    }
    if location.contains("://") {
        return Some(location.to_string());
    }
    let origin_end = base.find("://").map(|i| {
        let rest = &base[i + 3..];
        rest.find('/').map(|j| i + 3 + j).unwrap_or(base.len())
    })?;
    if let Some(path) = location.strip_prefix('/') {
        let _ = path;
        return Some(format!("{}{}", &base[..origin_end], location));
    }
    // path-relative: replace the last path segment of the base
    let up_to_slash = base[..base.find('?').unwrap_or(base.len())].rfind('/')?;
    Some(format!("{}{}", &base[..up_to_slash + 1], location))
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

#[cfg(test)]
#[path = "tls_connect_tests.rs"]
mod tls_connect_tests;
