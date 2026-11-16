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
    /// Results of --dbs/--tables/--columns/--dump enumeration, if requested.
    pub enumeration: Enumeration,
    /// WAF/IPS products identified in front of the target (--identify-waf).
    pub wafs: Vec<String>,
}

/// Enumeration/exfiltration results (port of sqlmap `kb.data` outputs).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enumeration {
    pub databases: Vec<String>,
    /// Database name -> table names.
    pub tables: std::collections::BTreeMap<String, Vec<String>>,
    pub columns: Vec<ColumnEntry>,
    pub dumps: Vec<TableDump>,
}

impl Enumeration {
    pub fn is_empty(&self) -> bool {
        self.databases.is_empty() && self.tables.is_empty() && self.columns.is_empty() && self.dumps.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnEntry {
    pub db: String,
    pub table: String,
    pub columns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableDump {
    pub db: String,
    pub table: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
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
