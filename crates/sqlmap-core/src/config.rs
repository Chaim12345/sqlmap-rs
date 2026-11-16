//! Runtime configuration (port of sqlmap `conf` object, subset).

use serde::{Deserialize, Serialize};

/// Injection point location (sqlmap PLACE enum subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Place {
    Get,
    Post,
    Cookie,
    UserAgent,
    Referer,
    CustomHeader,
}

/// Detection technique (sqlmap TECHNIQUE enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Technique {
    Boolean,
    Error,
    Union,
    Time,
    Stacked,
    Inline,
}

/// Subset of sqlmap's `conf` needed by the ported engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub target_url: String,
    /// Raw POST body (sqlmap --data).
    pub data: Option<String>,
    /// Raw Cookie header value (sqlmap --cookie).
    pub cookie: Option<String>,
    /// Extra headers, "Name: value" pairs (sqlmap --headers).
    pub headers: Vec<String>,
    /// Test only this parameter (sqlmap -p).
    pub test_param: Option<String>,
    /// Skip this parameter (sqlmap --skip).
    pub skip_param: Option<String>,
    /// Techniques to use, in order (sqlmap --technique, default "BEUT").
    pub techniques: Vec<Technique>,
    /// sqlmap --level (1-5); gates which places/payloads are used.
    pub level: u8,
    /// sqlmap --risk (1-3); gates dangerous payloads.
    pub risk: u8,
    /// Force a DBMS assumption (sqlmap --dbms).
    pub dbms: Option<String>,
    /// Tamper script names to apply (sqlmap --tamper).
    pub tampers: Vec<String>,
    /// Seconds a time-based payload asks the DB to sleep (sqlmap --time-sec).
    pub time_sec: u32,
    /// HTTP timeout seconds (sqlmap --timeout).
    pub timeout: u64,
    /// Follow redirects (sqlmap --follow-redirects).
    pub follow_redirects: bool,
    /// Random User-Agent per request is not ported; fixed UA string override (sqlmap --user-agent).
    pub user_agent: Option<String>,
    /// Comparison ratio threshold for boolean detection (sqlmap --string/--not-string are not ported).
    pub page_ratio_threshold: f64,
    /// Enumerate databases (sqlmap --dbs). Blind inference only.
    pub enum_dbs: bool,
    /// Enumerate tables (sqlmap --tables; -D narrows to one database).
    pub enum_tables: bool,
    /// Enumerate columns (sqlmap --columns; requires -D and -T).
    pub enum_columns: bool,
    /// Dump table rows (sqlmap --dump; requires -D and -T).
    pub dump: bool,
    /// Target database (sqlmap -D).
    pub target_db: Option<String>,
    /// Target table (sqlmap -T).
    pub target_table: Option<String>,
    /// Parse and test the target page's HTML forms (sqlmap --forms).
    pub forms: bool,
    /// Crawl same-host links from the target up to this depth and test every
    /// page found; 0 disables crawling (sqlmap --crawl).
    pub crawl_depth: u8,
}

impl Config {
    /// True when any enumeration/exfiltration flag is set.
    pub fn wants_enumeration(&self) -> bool {
        self.enum_dbs || self.enum_tables || self.enum_columns || self.dump
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            data: None,
            cookie: None,
            headers: Vec::new(),
            test_param: None,
            skip_param: None,
            techniques: vec![
                Technique::Boolean,
                Technique::Error,
                Technique::Union,
                Technique::Time,
            ],
            level: 1,
            risk: 1,
            dbms: None,
            tampers: Vec::new(),
            time_sec: 2,
            timeout: 30,
            follow_redirects: false,
            user_agent: None,
            page_ratio_threshold: 0.90,
            enum_dbs: false,
            enum_tables: false,
            enum_columns: false,
            dump: false,
            target_db: None,
            target_table: None,
            forms: false,
            crawl_depth: 0,
        }
    }
}
