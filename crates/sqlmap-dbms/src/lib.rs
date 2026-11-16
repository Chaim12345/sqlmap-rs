//! DBMS identification from error messages.
//! Port of the head entries of sqlmap `data/xml/errors.xml` (per-DBMS regex
//! tables) plus the matching half of `plugins/dbms/*/fingerprint.py`.

use regex::Regex;
use std::sync::LazyLock;

/// Supported DBMS tags (sqlmap `SUPPORTED_DBMS` subset).
pub const DBMS_TAGS: [&str; 5] = ["mysql", "postgresql", "mssql", "oracle", "sqlite"];

struct Patterns(&'static str, &'static [&'static str]);

static TABLES: LazyLock<Vec<Patterns>> = LazyLock::new(|| {
    vec![
        // Ported from sqlmap errors.xml <dbms value="MySQL">
        Patterns("mysql", &[
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"check the manual that (corresponds to|fits) your (MySQL|MariaDB) server version",
            r"com\.mysql\.jdbc\.exceptions",
        ]),
        // <dbms value="PostgreSQL">
        Patterns("postgresql", &[
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
        ]),
        // <dbms value="Microsoft SQL Server">
        Patterns("mssql", &[
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"Warning.*mssql_.*",
            r"System\.Data\.SqlClient\.SqlException",
            r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
            r"\[SQL Server\]",
        ]),
        // <dbms value="Oracle">
        Patterns("oracle", &[
            r"\bORA-\d{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_.*",
            r"quoted string not properly terminated",
        ]),
        // <dbms value="SQLite">
        Patterns("sqlite", &[
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_.*",
            r"\[SQLITE_ERROR\]",
            r"sqlite3\.OperationalError",
        ]),
    ]
});

static COMPILED: LazyLock<Vec<(&'static str, Vec<Regex>)>> = LazyLock::new(|| {
    TABLES
        .iter()
        .map(|p| {
            (
                p.0,
                p.1.iter()
                    .map(|r| Regex::new(&format!("(?i){r}")).expect("static regex must compile"))
                    .collect(),
            )
        })
        .collect()
});

/// All (dbms, pattern) hits found in a response body.
/// Port of sqlmap's `errors.xml` scan inside `checkErrorBased` / fingerprinting.
pub fn identify_from_errors(body: &str) -> Vec<(&'static str, &'static str)> {
    let mut hits = Vec::new();
    for (dbms, regexes) in COMPILED.iter() {
        for (i, re) in regexes.iter().enumerate() {
            if re.is_match(body) {
                hits.push((*dbms, TABLES.iter().find(|t| t.0 == *dbms).unwrap().1[i]));
            }
        }
    }
    hits
}

/// The most likely DBMS for a body, by number of distinct pattern hits.
pub fn best_guess(body: &str) -> Option<&'static str> {
    let hits = identify_from_errors(body);
    let mut best: Option<(&str, usize)> = None;
    for dbms in DBMS_TAGS {
        let n = hits.iter().filter(|(d, _)| *d == dbms).count();
        if n > 0 && best.map(|(_, m)| n > m).unwrap_or(true) {
            best = Some((dbms, n));
        }
    }
    best.map(|(d, _)| d)
}

/// True when the body contains a DBMS error mentioning `marker` - the contract
/// an error-based payload must satisfy (the injected [RANDSTR] echoed back).
pub fn error_contains_marker(body: &str, marker: &str) -> Option<&'static str> {
    if !body.contains(marker) {
        return None;
    }
    best_guess(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mysql_syntax_error_detected() {
        let body = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'x7eabc'' at line 1";
        assert_eq!(best_guess(body), Some("mysql"));
    }

    #[test]
    fn postgres_error_detected() {
        assert!(identify_from_errors("PostgreSQL query failed: ERROR: invalid input syntax").len() >= 1);
    }

    #[test]
    fn marker_must_be_present() {
        let body = "SQL syntax error MySQL near 'zz'";
        assert_eq!(error_contains_marker(body, "abc123"), None);
        assert_eq!(error_contains_marker(body, "zz"), Some("mysql"));
    }

    #[test]
    fn clean_page_no_hits() {
        assert!(identify_from_errors("<html>Welcome to the shop</html>").is_empty());
    }
}
