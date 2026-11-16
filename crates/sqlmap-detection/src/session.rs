//! Resumable session file (subset of sqlmap's session store, `-s FILE`):
//! a scan's knowledge base is cached per target URL; a later run with the
//! same target loads it instead of re-testing. `--flush-session` discards
//! the cache and re-tests. Upstream sqlmap keeps the store in sqlite; the
//! port keeps the same load/save semantics over a JSON document (covering
//! injections, DBMS fingerprint, enumeration results and WAF
//! identifications).

use serde::{Deserialize, Serialize};
use sqlmap_core::config::Config;
use sqlmap_core::kb::KnowledgeBase;

#[derive(Serialize, Deserialize)]
struct Session {
    target_url: String,
    kb: KnowledgeBase,
}

/// Load stored results for `conf.target_url`, if the session file holds any.
pub fn load(conf: &Config) -> Option<KnowledgeBase> {
    let path = conf.session_file.as_ref()?;
    let text = std::fs::read_to_string(path).ok()?;
    let s: Session = serde_json::from_str(&text).ok()?;
    if s.target_url == conf.target_url {
        Some(s.kb)
    } else {
        None
    }
}

/// Persist results for `conf.target_url` (overwrites any previous entry).
pub fn save(conf: &Config, kb: &KnowledgeBase) -> Result<(), String> {
    let path = conf
        .session_file
        .as_ref()
        .ok_or_else(|| "no session file configured".to_string())?;
    let s = Session {
        target_url: conf.target_url.clone(),
        kb: kb.clone(),
    };
    let text = serde_json::to_string_pretty(&s).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| e.to_string())
}
