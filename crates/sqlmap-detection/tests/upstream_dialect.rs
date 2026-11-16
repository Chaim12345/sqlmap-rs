//! Compatibility pins from the original Python sqlmap test suite
//! (tests/test_dialect.py, upstream pinned at
//! sqlmapproject/sqlmap 8b78b676c1376ae28feccd957b03bbecea05eff1).
//! Upstream pins agent.limitQuery / nullAndCastField / hexConvertField /
//! forgeUnionQuery per dialect. We pin our paging shapes against the same
//! input: exact where we match upstream, explicit divergence records where
//! we deliberately differ.

use sqlmap_detection::queries::Dbms;

const SELECT: &str = "SELECT name FROM users";

/// Upstream limitQuery(0, "SELECT name FROM users", "name") per dialect,
/// from tests/test_dialect.py.
const UPSTREAM_LIMIT: &[(&str, &str)] = &[
    ("mysql", "SELECT name FROM users LIMIT 0,1"),
    ("postgresql", "SELECT name FROM users OFFSET 0 LIMIT 1"),
    (
        "oracle",
        "SELECT name FROM (SELECT name,ROWNUM AS CAP FROM users) WHERE CAP=1",
    ),
    // MSSQL is TOP-based upstream: starts with "SELECT TOP 1 name FROM users
    // WHERE", contains "ORDER BY 1".
];

#[test]
fn mysql_paging_matches_upstream_text() {
    let q = Dbms::parse("mysql").unwrap();
    assert_eq!(q.at(SELECT, 0), UPSTREAM_LIMIT[0].1);
}

/// Dialects where our paging is intentionally different SQL text. The pin
/// locks OUR text and carries upstream's verbatim, so the divergence is
/// visible and any accidental change in either direction fails loudly.
#[test]
fn divergent_paging_is_pinned() {
    let pg = Dbms::parse("postgresql").unwrap();
    assert_eq!(pg.at(SELECT, 0), "SELECT name FROM users LIMIT 1 OFFSET 0");
    // upstream: "SELECT name FROM users OFFSET 0 LIMIT 1" - semantically
    // equal, different clause order (we share SQLite's shape).

    let oracle = Dbms::parse("oracle").unwrap();
    assert_eq!(
        oracle.at(SELECT, 0),
        "SELECT * FROM (SELECT x.*, ROWNUM rn FROM (SELECT name FROM users) x) WHERE rn=1"
    );
    // upstream: "SELECT name FROM (SELECT name,ROWNUM AS CAP FROM users)
    // WHERE CAP=1" - we wrap the whole query so arbitrary projection lists
    // page correctly; upstream's form only handles simple shapes.

    let mssql = Dbms::parse("mssql").unwrap();
    assert_eq!(
        mssql.at(SELECT, 0),
        "SELECT name FROM users ORDER BY 1 OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY"
    );
    // upstream is TOP-based ("SELECT TOP 1 name FROM users WHERE ... ORDER
    // BY 1"); we use the modern OFFSET/FETCH syntax (SQL Server 2012+).
}

/// Upstream pins nullAndCastField / hexConvertField per dialect (e.g. MySQL
/// "IFNULL(CAST(col AS NCHAR),' ')", "HEX(name)"). Our exfil does not cast
/// or null-wrap fields at all (CONCAT_WS skips NULLs on MySQL; rows with
/// NULLs on pg/mssql concat are a known gap - see the compat doc). This test
/// pins that the divergence is still the current behavior: our row_select
/// emits bare column names.
#[test]
fn row_select_does_not_cast_or_null_wrap() {
    let q = Dbms::parse("mysql").unwrap();
    let row = q.row_select("shop", "users", &["id".into(), "pw".into()]);
    assert!(!row.contains("CAST("), "casting appeared: {row}");
    assert!(!row.contains("IFNULL("), "null-wrapping appeared: {row}");
}
