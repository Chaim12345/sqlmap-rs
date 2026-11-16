//! Knowledge base (port of sqlmap `kb` object, subset).

use crate::injection::Injection;
use serde::{Deserialize, Serialize};

/// Accumulated findings for a scan (sqlmap `kb.injection`, `kb.fingerprint`).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct KnowledgeBase {
    pub injections: Vec<Injection>,
    /// Fingerprinted DBMS name once identified.
    pub fingerprinted_dbms: Option<String>,
    /// Pages already compared, keyed loosely (sqlmap uses kb.pageComparisons).
    pub tested_params: Vec<String>,
}

impl KnowledgeBase {
    pub fn add_injection(&mut self, inj: Injection) {
        if !self.injections.iter().any(|i| {
            i.place == inj.place && i.parameter == inj.parameter && i.technique == inj.technique
        }) {
            self.injections.push(inj);
        }
    }
}
