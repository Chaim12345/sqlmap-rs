//! `--forms` orchestration (port of the forms branch of sqlmap
//! `lib/core/target.py::processTarget`): fetch the page, parse its forms,
//! and run the engine against each form's request shape.

use crate::engine::{Engine, ScanResult};
use sqlmap_core::config::Config;
use sqlmap_core::kb::KnowledgeBase;
use sqlmap_http::client::{Client, RequestSpec};
use sqlmap_http::forms::{self, Form};
use sqlmap_http::params;

fn form_conf(conf: &Config, form: &Form) -> Config {
    let mut c = conf.clone();
    c.forms = false;
    if form.method == "POST" {
        c.target_url = form.action.clone();
        c.data = Some(params::build_pairs(&form.inputs));
    } else {
        // GET form: inputs go into the action URL's query string.
        let query = params::build_pairs(&form.inputs);
        c.target_url = if form.action.contains('?') {
            format!("{}&{query}", form.action)
        } else {
            format!("{}?{query}", form.action)
        };
        c.data = None;
    }
    c
}

fn merge(dst: &mut ScanResult, src: ScanResult) {
    for inj in src.kb.injections {
        dst.kb.add_injection(inj);
    }
    if dst.kb.fingerprinted_dbms.is_none() {
        dst.kb.fingerprinted_dbms = src.kb.fingerprinted_dbms;
    }
    if dst.kb.enumeration.is_empty() {
        dst.kb.enumeration = src.kb.enumeration;
    }
    for w in src.kb.wafs {
        if !dst.kb.wafs.contains(&w) {
            dst.kb.wafs.push(w);
        }
    }
    dst.log.extend(src.log);
}

/// Scan a target, expanding session resume, `--identify-waf`, `--crawl`
/// and `--forms` when set. The session file and WAF identification are
/// handled once, on the outermost call.
pub fn scan_auto(client: &Client, conf: &Config) -> ScanResult {
    if conf.session_file.is_some() {
        if !conf.flush_session {
            if let Some(kb) = crate::session::load(conf) {
                return ScanResult {
                    kb,
                    log: vec![
                        "session: loaded stored results for this target - tests skipped \
                         (use --flush-session to re-test)"
                            .to_string(),
                    ],
                };
            }
        }
        let mut inner = conf.clone();
        inner.session_file = None;
        inner.flush_session = false;
        let out = scan_auto(client, &inner);
        let mut out = out;
        match crate::session::save(conf, &out.kb) {
            Ok(()) => out.log.push(format!(
                "session: results saved to {}",
                conf.session_file.as_deref().unwrap_or_default()
            )),
            Err(e) => out.log.push(format!("session: could not save results: {e}")),
        }
        return out;
    }
    if conf.identify_waf {
        let (names, log) = crate::waf::identify(client, conf);
        let mut inner = conf.clone();
        inner.identify_waf = false;
        let mut out = scan_auto(client, &inner);
        out.kb.wafs = names;
        let mut full_log = log;
        full_log.extend(out.log);
        out.log = full_log;
        return out;
    }
    if conf.crawl_depth > 0 {
        return crawl_scan(client, conf);
    }
    if !conf.forms {
        return Engine::new(client, conf).scan();
    }
    let mut out = ScanResult {
        kb: KnowledgeBase::default(),
        log: Vec::new(),
    };
    let page = client.request(&RequestSpec {
        url: conf.target_url.clone(),
        method: if conf.data.is_some() { "POST".into() } else { "GET".into() },
        body: conf.data.clone(),
        headers: Vec::new(),
        cookie: conf.cookie.clone(),
    });
    let Ok(resp) = page else {
        out.log.push("could not fetch the target page to parse forms".to_string());
        return out;
    };
    let parsed = forms::parse_forms(&resp.body, &conf.target_url);
    if parsed.is_empty() {
        out.log
            .push("no forms found on the target page - scanning URL parameters".to_string());
        merge(&mut out, Engine::new(client, conf).scan());
        return out;
    }
    out.log.push(format!("found {} form(s) to test", parsed.len()));
    for form in &parsed {
        out.log.push(format!(
            "testing form: {} {} ({} field(s))",
            form.method,
            form.action,
            form.inputs.len()
        ));
        let fconf = form_conf(conf, form);
        merge(&mut out, Engine::new(client, &fconf).scan());
    }
    out
}

/// `--crawl` orchestration (port of sqlmap `lib/utils/crawler.py` + the
/// controller loop over collected targets): walk same-host links from the
/// target up to the configured depth, then scan every page collected. Each
/// page goes back through `scan_auto`, so `--forms` composes with `--crawl`.
fn crawl_scan(client: &Client, conf: &Config) -> ScanResult {
    let mut out = ScanResult {
        kb: KnowledgeBase::default(),
        log: Vec::new(),
    };
    let pages = sqlmap_http::crawl::crawl(client, &conf.target_url, conf.crawl_depth, conf.threads);
    out.log.push(format!(
        "crawler collected {} page(s) up to depth {}",
        pages.len(),
        conf.crawl_depth
    ));
    for page in &pages {
        out.log.push(format!("testing crawled page: {}", page.url));
        let mut pconf = conf.clone();
        pconf.crawl_depth = 0;
        pconf.target_url = page.url.clone();
        merge(&mut out, scan_auto(client, &pconf));
    }
    out
}
