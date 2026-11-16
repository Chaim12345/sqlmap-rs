//! The scanning engine itself.

use sqlmap_core::config::{Config, Place, Technique};
use sqlmap_core::injection::{Boundary, Injection};
use sqlmap_core::kb::KnowledgeBase;
use sqlmap_http::client::{Client, RequestSpec, Response};
use sqlmap_http::comparison::{filtered_page, ratio};
use sqlmap_http::params::{self, Param};
use sqlmap_payloads as pl;
use std::time::Duration;

/// Outcome of a full scan: findings plus a human-readable decision log
/// (sqlmap writes this to the console; we return it for the CLI to print).
pub struct ScanResult {
    pub kb: KnowledgeBase,
    pub log: Vec<String>,
}

pub struct Engine<'a> {
    client: &'a Client,
    conf: &'a Config,
    log: Vec<String>,
    kb: KnowledgeBase,
}

fn rand_num(seed: u64) -> u32 {
    // Deterministic pseudo-random like sqlmap's randomInt; seeded per request.
    let mut x = seed.max(1);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    (x % 90000 + 10000) as u32
}

fn rand_str(seed: u64) -> String {
    let mut x = seed.max(1);
    let mut s = String::new();
    for _ in 0..6 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.push((b'a' + (x % 26) as u8) as char);
    }
    s
}

impl<'a> Engine<'a> {
    pub fn new(client: &'a Client, conf: &'a Config) -> Self {
        Self {
            client,
            conf,
            log: Vec::new(),
            kb: KnowledgeBase::default(),
        }
    }

    fn say(&mut self, msg: impl Into<String>) {
        self.log.push(msg.into());
    }

    /// Build the request for `param` carrying `new_value` (port of the request
    /// assembly in sqlmap `agent.payload` + `connect.getPage`).
    fn build_request(&self, param: &Param, new_value: &str) -> RequestSpec {
        let (base, _) = params::split_url(&self.conf.target_url);
        match param.place {
            Place::Get => {
                let query_raw = self
                    .conf
                    .target_url
                    .split_once('?')
                    .map(|(_, q)| q)
                    .unwrap_or("");
                let query = params::mutate(Place::Get, query_raw, &param.name, new_value);
                RequestSpec {
                    url: format!("{base}?{query}"),
                    method: "GET".into(),
                    body: self.conf.data.clone(),
                    headers: parse_headers(&self.conf.headers),
                    cookie: self.conf.cookie.clone(),
                }
            }
            Place::Post => {
                let body = params::mutate(
                    Place::Post,
                    self.conf.data.as_deref().unwrap_or(""),
                    &param.name,
                    new_value,
                );
                RequestSpec {
                    url: self.conf.target_url.clone(),
                    method: "POST".into(),
                    body: Some(body),
                    headers: parse_headers(&self.conf.headers),
                    cookie: self.conf.cookie.clone(),
                }
            }
            Place::Cookie => {
                let cookie = params::mutate(
                    Place::Cookie,
                    self.conf.cookie.as_deref().unwrap_or(""),
                    &param.name,
                    new_value,
                );
                RequestSpec {
                    url: self.conf.target_url.clone(),
                    method: if self.conf.data.is_some() { "POST".into() } else { "GET".into() },
                    body: self.conf.data.clone(),
                    headers: parse_headers(&self.conf.headers),
                    cookie: Some(cookie),
                }
            }
            // UA/Referer/header places: level>=3 territory, not yet wired.
            other => {
                let _ = other;
                RequestSpec {
                    url: self.conf.target_url.clone(),
                    method: "GET".into(),
                    body: self.conf.data.clone(),
                    headers: parse_headers(&self.conf.headers),
                    cookie: self.conf.cookie.clone(),
                }
            }
        }
    }

    fn fetch(&self, spec: &RequestSpec) -> Result<Response, String> {
        self.client.request(spec)
    }

    /// Full scan over all testable parameters (port of `start()`'s per-param loop).
    pub fn scan(mut self) -> ScanResult {
        let mut all = params::extract_params(
            &self.conf.target_url,
            self.conf.data.as_deref(),
            self.conf.cookie.as_deref(),
        );
        if let Some(only) = &self.conf.test_param {
            all.retain(|p| p.name == *only);
        }
        if let Some(skip) = &self.conf.skip_param {
            all.retain(|p| p.name != *skip);
        }
        if all.is_empty() {
            self.say("no testable parameters found in URL/POST data/cookie".to_string());
            return ScanResult { kb: self.kb, log: self.log };
        }
        self.say(format!("testing {} parameter(s)", all.len()));

        for param in all.clone() {
            if self.kb.tested_params.contains(&param.name) {
                continue;
            }
            self.scan_param(&param);
            self.kb.tested_params.push(param.name.clone());
        }
        ScanResult { kb: self.kb, log: self.log }
    }

    fn scan_param(&mut self, param: &Param) {
        self.say(format!("testing '{}' ({:?})", param.name, param.place));

        // Original page (baseline) - sqlmap `kb.originalPage`.
        let orig = match self.fetch(&self.build_request(param, &param.value)) {
            Ok(r) => r,
            Err(e) => {
                self.say(format!("  baseline request failed: {e}"));
                return;
            }
        };
        let orig_page = filtered_page(&orig.body);
        let baseline = orig.elapsed;

        // Fingerprint from any error already on the page.
        if let Some(dbms) = sqlmap_dbms::best_guess(&orig.body) {
            self.say(format!("  original page leaks {dbms} error text"));
            self.kb.fingerprinted_dbms = Some(dbms.to_string());
        }

        // Heuristic check: single quote appended (sqlmap `checkDynParam` +
        // heuristic error scan).
        let probe = format!("{}'", param.value);
        if let Ok(r) = self.fetch(&self.build_request(param, &probe)) {
            if let Some(dbms) = sqlmap_dbms::best_guess(&r.body) {
                self.say(format!("  heuristic: '{dbms}' error triggered by quote probe - parameter looks dynamic"));
                self.kb.fingerprinted_dbms = Some(dbms.to_string());
            }
        }

        let boundaries = pl::boundaries();
        let forced = self.conf.dbms.as_deref().map(|s| s.to_ascii_lowercase());
        let dbms_hint = forced.or_else(|| self.kb.fingerprinted_dbms.clone());

        for tech in self.conf.techniques.clone() {
            match tech {
                Technique::Boolean => self.check_boolean(param, &orig_page, &boundaries, dbms_hint.as_deref()),
                Technique::Error => self.check_error(param, &boundaries, dbms_hint.as_deref()),
                Technique::Time => self.check_time(param, baseline, &boundaries, dbms_hint.as_deref()),
                other => self.say(format!("  technique {other:?} not ported yet - skipped")),
            }
        }
    }

    /// Assemble final injected value: origValue + prefix + payload + suffix,
    /// with tamper chain applied (sqlmap `agent.payload` assembly order).
    fn assemble(&mut self, param: &Param, boundary: &Boundary, payload_q: &str, seed: u64) -> String {
        let rn = rand_num(seed);
        let rn1 = rand_num(seed.wrapping_mul(7).wrapping_add(1));
        let rs = rand_str(seed.wrapping_mul(13).wrapping_add(3));
        let rendered = pl::render(payload_q, self.conf.time_sec, rn, rn1, &rs);
        let suffix = boundary
            .suffix
            .replace("[RANDSTR]", &rs)
            .replace("[RANDNUM]", &rn.to_string());
        let prefix = boundary.prefix.clone();
        let mut joined = format!("{}{}{}{}", param.value, prefix, rendered, suffix);
        if !self.conf.tampers.is_empty() {
            match sqlmap_tamper::apply_all(&self.conf.tampers, &joined, seed) {
                Ok(t) => joined = t,
                Err(e) => self.log.push(format!("  tamper error: {e}")),
            }
        }
        joined
    }

    fn payload_ok_static(level: u8, risk: u8, p: &pl::Payload, dbms_hint: Option<&str>) -> bool {
        if p.level > level || p.risk > risk {
            return false;
        }
        match (p.dbms, dbms_hint) {
            (Some(tag), Some(hint)) => tag == hint,
            _ => true,
        }
    }

    /// Boolean-based blind (port of the boolean branch of `checkSqlInjection`):
    /// true payload must render the original page; false payload must differ.
    fn check_boolean(&mut self, param: &Param, orig_page: &str, boundaries: &[Boundary], dbms_hint: Option<&str>) {
        if !self.conf.techniques.contains(&Technique::Boolean) {
            return;
        }
        let threshold = self.conf.page_ratio_threshold;
        let (lvl, rsk) = (self.conf.level, self.conf.risk);
        for p in pl::boolean_payloads().into_iter().filter(|p| Self::payload_ok_static(lvl, rsk, p, dbms_hint)) {
            let pl::Check::Boolean { true_q, false_q } = p.check else { continue };
            for (bi, boundary) in boundaries.iter().enumerate() {
                // Numeric-looking values get numeric boundaries first; strings get quotes.
                let numeric_value = param.value.chars().all(|c| c.is_ascii_digit()) && !param.value.is_empty();
                if numeric_value != (boundary.ptype == sqlmap_core::injection::PType::Numeric) && bi < 6 {
                    continue;
                }
                let seed = 1000 + bi as u64;
                let true_val = self.assemble(param, boundary, true_q, seed);
                let true_resp = match self.fetch(&self.build_request(param, &true_val)) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let true_ratio = ratio(orig_page, &filtered_page(&true_resp.body));
                if true_ratio < threshold {
                    continue;
                }
                let false_val = self.assemble(param, boundary, false_q, seed);
                let false_resp = match self.fetch(&self.build_request(param, &false_val)) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let false_ratio = ratio(&filtered_page(&true_resp.body), &filtered_page(&false_resp.body));
                if false_ratio < threshold {
                    self.say(format!(
                        "  INJECTABLE (boolean): '{}' with {} [{}], true_ratio={true_ratio:.3} false_ratio={false_ratio:.3}",
                        param.name, p.title, boundary.prefix
                    ));
                    self.kb.add_injection(Injection {
                        place: param.place,
                        parameter: param.name.clone(),
                        technique: Technique::Boolean,
                        boundary: boundary.clone(),
                        payload: true_val,
                        dbms: dbms_hint.map(|s| s.to_string()),
                        note: format!("true page matches original (r={true_ratio:.3}), false page differs (r={false_ratio:.3})"),
                    });
                    return;
                }
            }
        }
    }

    /// Error-based (port of `checkErrorBased`): the payload embeds a marker the
    /// DBMS must echo inside its own error message.
    fn check_error(&mut self, param: &Param, boundaries: &[Boundary], dbms_hint: Option<&str>) {
        let (lvl, rsk) = (self.conf.level, self.conf.risk);
        for p in pl::error_payloads().into_iter().filter(|p| Self::payload_ok_static(lvl, rsk, p, dbms_hint)) {
            let pl::Check::Error { q } = p.check else { continue };
            for (bi, boundary) in boundaries.iter().enumerate() {
                let numeric_value = param.value.chars().all(|c| c.is_ascii_digit()) && !param.value.is_empty();
                if numeric_value != (boundary.ptype == sqlmap_core::injection::PType::Numeric) && bi < 6 {
                    continue;
                }
                let seed = 5000 + bi as u64;
                let val = self.assemble(param, boundary, q, seed);
                let marker = rand_str(seed.wrapping_mul(13).wrapping_add(3));
                let resp = match self.fetch(&self.build_request(param, &val)) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if let Some(dbms) = sqlmap_dbms::error_contains_marker(&resp.body, &marker) {
                    self.say(format!(
                        "  INJECTABLE (error-based): '{}' with {} - {dbms} error echoed marker",
                        param.name, p.title
                    ));
                    self.kb.fingerprinted_dbms = Some(dbms.to_string());
                    self.kb.add_injection(Injection {
                        place: param.place,
                        parameter: param.name.clone(),
                        technique: Technique::Error,
                        boundary: boundary.clone(),
                        payload: val,
                        dbms: Some(dbms.to_string()),
                        note: format!("{dbms} error contained payload marker '{marker}'"),
                    });
                    return;
                }
            }
        }
    }

    /// Time-based blind (port of the time branch of `checkSqlInjection`):
    /// response must be delayed by ~time_sec, confirmed on a second request.
    fn check_time(&mut self, param: &Param, baseline: Duration, boundaries: &[Boundary], dbms_hint: Option<&str>) {
        let need = Duration::from_secs(self.conf.time_sec as u64);
        let (lvl, rsk) = (self.conf.level, self.conf.risk);
        for p in pl::time_payloads().into_iter().filter(|p| Self::payload_ok_static(lvl, rsk, p, dbms_hint)) {
            let pl::Check::Time { q } = p.check else { continue };
            for (bi, boundary) in boundaries.iter().enumerate() {
                let numeric_value = param.value.chars().all(|c| c.is_ascii_digit()) && !param.value.is_empty();
                if numeric_value != (boundary.ptype == sqlmap_core::injection::PType::Numeric) && bi < 6 {
                    continue;
                }
                let seed = 9000 + bi as u64;
                let val = self.assemble(param, boundary, q, seed);
                let first = match self.fetch(&self.build_request(param, &val)) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if first.elapsed < need {
                    continue;
                }
                // Confirm once more (sqlmap repeats to rule out network jitter).
                let second = match self.fetch(&self.build_request(param, &val)) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if second.elapsed >= need {
                    self.say(format!(
                        "  INJECTABLE (time-based): '{}' with {} - {:.1?}/{:.1?} vs baseline {:.1?}",
                        param.name, p.title, first.elapsed, second.elapsed, baseline
                    ));
                    self.kb.add_injection(Injection {
                        place: param.place,
                        parameter: param.name.clone(),
                        technique: Technique::Time,
                        boundary: boundary.clone(),
                        payload: val,
                        dbms: dbms_hint.map(|s| s.to_string()),
                        note: format!("two delayed responses >= {}s (baseline {:.2?})", self.conf.time_sec, baseline),
                    });
                    return;
                }
            }
        }
    }
}

fn parse_headers(raw: &[String]) -> Vec<(String, String)> {
    raw.iter()
        .filter_map(|h| {
            h.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}
