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
    dst.log.extend(src.log);
}

/// Scan a target, expanding `--forms` when set.
pub fn scan_auto(client: &Client, conf: &Config) -> ScanResult {
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
