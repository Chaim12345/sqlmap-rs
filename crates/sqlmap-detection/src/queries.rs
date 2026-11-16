//! DBMS-specific enumeration query sets (port of the SQL embedded in
//! sqlmap's `plugins/dbms/{mysql,pgsql,mssql,oracle}/enumeration.py`,
//! subset). Selected by the fingerprinted or forced DBMS.
//!
//! Honest scope: only the MySQL set can retrieve data from the bundled test
//! app (a MySQL emulator); the other sets are pinned by unit tests and by an
//! integration test proving the right SQL text is issued. SQLite has no set
//! yet (its `sqlite_master`/`PRAGMA` shape does not fit the scalar-subquery
//! exfil channels) and falls back to MySQL with a log note.

/// Encode a string literal the way the MySQL exfil path always did:
/// 0x-hex, which sidesteps quote handling entirely.
fn hex(s: &str) -> String {
    let mut out = String::from("0x");
    for b in s.bytes() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dbms {
    MySql,
    PostgreSql,
    MsSql,
    Oracle,
    /// Catalog via sqlite_master; columns are recovered by parsing the
    /// table's CREATE statement (see parse_columns_from_ddl), as upstream's
    /// sqlite plugin does. There is no schema list: the attached database
    /// is "main", answered by a literal one-row query. Time-based retrieval
    /// does not apply (SQLite has no SLEEP; sqlmap relies on heavy
    /// RANDOMBLOB LIKEs, which this port does not emulate).
    Sqlite,
}

impl Dbms {
    pub fn parse(tag: &str) -> Option<Self> {
        match tag.to_ascii_lowercase().as_str() {
            "mysql" => Some(Self::MySql),
            "postgresql" | "pgsql" | "postgres" => Some(Self::PostgreSql),
            "mssql" | "microsoft sql server" => Some(Self::MsSql),
            "oracle" => Some(Self::Oracle),
            "sqlite" => Some(Self::Sqlite),
            _ => None,
        }
    }

    /// String literal accepted inside this DBMS's queries.
    fn literal(&self, s: &str) -> String {
        match self {
            Self::MySql => hex(s),
            _ => format!("'{}'", s.replace('\'', "''")),
        }
    }

    /// `select` restricted to the row at ordinal `i` (0-based).
    pub fn at(&self, select: &str, i: u32) -> String {
        match self {
            Self::MySql => format!("{select} LIMIT {i},1"),
            Self::PostgreSql | Self::Sqlite => format!("{select} LIMIT 1 OFFSET {i}"),
            Self::MsSql => {
                format!("{select} ORDER BY 1 OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY")
            }
            Self::Oracle => {
                format!("SELECT * FROM (SELECT x.*, ROWNUM rn FROM ({select}) x) WHERE rn={}", i + 1)
            }
        }
    }

    /// Aggregate a text column into one ':'-joined scalar (UNION channel).
    fn agg(&self, expr: &str) -> String {
        match self {
            Self::MySql => format!("GROUP_CONCAT({expr} SEPARATOR 0x3a)"),
            Self::PostgreSql | Self::MsSql => format!("STRING_AGG({expr},':')"),
            Self::Sqlite => format!("GROUP_CONCAT({expr},':')"),
            Self::Oracle => format!("LISTAGG({expr},':') WITHIN GROUP (ORDER BY {expr})"),
        }
    }

    pub fn schemata_count(&self) -> String {
        match self {
            Self::Sqlite => "SELECT COUNT(*) FROM (SELECT 'main' AS schema_name)".into(),
            Self::Oracle => "SELECT COUNT(DISTINCT owner) FROM all_tables".into(),
            _ => "SELECT COUNT(schema_name) FROM information_schema.schemata".into(),
        }
    }

    pub fn schemata_select(&self) -> String {
        match self {
            Self::Sqlite => "SELECT 'main'".into(),
            Self::Oracle => "SELECT DISTINCT owner FROM all_tables".into(),
            _ => "SELECT schema_name FROM information_schema.schemata".into(),
        }
    }

    pub fn schemata_agg(&self) -> String {
        match self {
            Self::Sqlite => "SELECT 'main'".into(),
            Self::Oracle => format!(
                "SELECT {} FROM (SELECT DISTINCT owner AS schema_name FROM all_tables)",
                self.agg("schema_name")
            ),
            _ => format!(
                "SELECT {} FROM information_schema.schemata",
                self.agg("schema_name")
            ),
        }
    }

    pub fn tables_count(&self, db: &str) -> String {
        match self {
            Self::Sqlite => "SELECT COUNT(name) FROM sqlite_master WHERE type='table'".into(),
            Self::Oracle => {
                format!("SELECT COUNT(table_name) FROM all_tables WHERE owner={}", self.literal(db))
            }
            _ => format!(
                "SELECT COUNT(table_name) FROM information_schema.tables WHERE table_schema={}",
                self.literal(db)
            ),
        }
    }

    pub fn tables_select(&self, db: &str) -> String {
        match self {
            Self::Sqlite => "SELECT name FROM sqlite_master WHERE type='table'".into(),
            Self::Oracle => {
                format!("SELECT table_name FROM all_tables WHERE owner={}", self.literal(db))
            }
            _ => format!(
                "SELECT table_name FROM information_schema.tables WHERE table_schema={}",
                self.literal(db)
            ),
        }
    }

    pub fn tables_agg(&self, db: &str) -> String {
        match self {
            Self::Sqlite => "SELECT GROUP_CONCAT(name,':') FROM sqlite_master WHERE type='table'".into(),
            Self::Oracle => format!(
                "SELECT {} FROM all_tables WHERE owner={}",
                self.agg("table_name"),
                self.literal(db)
            ),
            _ => format!(
                "SELECT {} FROM information_schema.tables WHERE table_schema={}",
                self.agg("table_name"),
                self.literal(db)
            ),
        }
    }

    pub fn columns_count(&self, db: &str, table: &str) -> String {
        match self {
            Self::Oracle => format!(
                "SELECT COUNT(column_name) FROM all_tab_columns WHERE owner={} AND table_name={}",
                self.literal(db),
                self.literal(table)
            ),
            _ => format!(
                "SELECT COUNT(column_name) FROM information_schema.columns WHERE table_schema={} AND table_name={}",
                self.literal(db),
                self.literal(table)
            ),
        }
    }

    pub fn columns_select(&self, db: &str, table: &str) -> String {
        match self {
            Self::Oracle => format!(
                "SELECT column_name FROM all_tab_columns WHERE owner={} AND table_name={}",
                self.literal(db),
                self.literal(table)
            ),
            _ => format!(
                "SELECT column_name FROM information_schema.columns WHERE table_schema={} AND table_name={}",
                self.literal(db),
                self.literal(table)
            ),
        }
    }

    pub fn columns_agg(&self, db: &str, table: &str) -> String {
        match self {
            Self::Oracle => format!(
                "SELECT {} FROM all_tab_columns WHERE owner={} AND table_name={}",
                self.agg("column_name"),
                self.literal(db),
                self.literal(table)
            ),
            _ => format!(
                "SELECT {} FROM information_schema.columns WHERE table_schema={} AND table_name={}",
                self.agg("column_name"),
                self.literal(db),
                self.literal(table)
            ),
        }
    }

    /// Qualified table reference for row access. PostgreSQL cannot reach
    /// across databases from one connection; sqlmap enumerates the current
    /// one, so the reference is the bare table.
    fn table_ref(&self, db: &str, table: &str) -> String {
        match self {
            Self::PostgreSql | Self::Sqlite => table.to_string(),
            Self::MsSql => format!("{db}..{table}"),
            _ => format!("{db}.{table}"),
        }
    }

    pub fn rows_count(&self, db: &str, table: &str) -> String {
        format!("SELECT COUNT(*) FROM {}", self.table_ref(db, table))
    }

    /// One row's columns joined with ':' as a single scalar (no LIMIT).
    /// Note: non-text columns need casts on MSSQL/PostgreSQL in the general
    /// case; the test app's tables are all-text.
    pub fn row_select(&self, db: &str, table: &str, cols: &[String]) -> String {
        let joined = match self {
            Self::MySql => format!("CONCAT_WS(0x3a,{})", cols.join(",")),
            Self::MsSql => cols.join("+':'+"),
            _ => cols.join("||':'||"),
        };
        format!("SELECT {joined} FROM {}", self.table_ref(db, table))
    }
}

impl Dbms {
    /// SQLite: the SELECT recovering a table's CREATE statement (columns are
    /// parsed out of the DDL client-side, like upstream's sqlite plugin).
    pub fn sqlite_ddl_select(&self, table: &str) -> Option<String> {
        match self {
            Self::Sqlite => Some(format!(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name={}",
                self.literal(table)
            )),
            _ => None,
        }
    }
}

/// Parse column names out of a CREATE TABLE statement (sqlmap's sqlite
/// enumeration does the same client-side parse). Constraint clauses are
/// skipped; quoted/bracketed identifiers are stripped.
pub fn parse_columns_from_ddl(ddl: &str) -> Vec<String> {
    let Some(open) = ddl.find('(') else { return Vec::new() };
    let mut depth = 0;
    let mut end = ddl.len();
    for (i, c) in ddl[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = open + i;
                    break;
                }
            }
            _ => {}
        }
    }
    let inner = &ddl[open + 1..end];
    // split at top-level commas
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut cur = String::new();
    for c in inner.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }
    parts
        .iter()
        .filter_map(|part| {
            let first = part.split_whitespace().next()?;
            if matches!(
                first.to_ascii_uppercase().as_str(),
                "PRIMARY" | "UNIQUE" | "CHECK" | "FOREIGN" | "CONSTRAINT"
            ) {
                return None;
            }
            Some(first.trim_matches(|c| c == '"' || c == '`' || c == '[' || c == ']').to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mysql_matches_the_legacy_hardcoded_queries() {
        let q = Dbms::MySql;
        assert_eq!(q.schemata_count(), "SELECT COUNT(schema_name) FROM information_schema.schemata");
        assert_eq!(q.at(&q.schemata_select(), 2), "SELECT schema_name FROM information_schema.schemata LIMIT 2,1");
        assert_eq!(q.schemata_agg(), "SELECT GROUP_CONCAT(schema_name SEPARATOR 0x3a) FROM information_schema.schemata");
        assert_eq!(q.tables_select("shop"), "SELECT table_name FROM information_schema.tables WHERE table_schema=0x73686f70");
        assert_eq!(q.rows_count("shop", "users"), "SELECT COUNT(*) FROM shop.users");
        assert_eq!(
            q.at(&q.row_select("shop", "users", &["id".into(), "name".into()]), 0),
            "SELECT CONCAT_WS(0x3a,id,name) FROM shop.users LIMIT 0,1"
        );
    }

    #[test]
    fn postgresql_set() {
        let q = Dbms::PostgreSql;
        assert_eq!(q.at(&q.schemata_select(), 2), "SELECT schema_name FROM information_schema.schemata LIMIT 1 OFFSET 2");
        assert_eq!(q.tables_select("shop"), "SELECT table_name FROM information_schema.tables WHERE table_schema='shop'");
        assert_eq!(q.schemata_agg(), "SELECT STRING_AGG(schema_name,':') FROM information_schema.schemata");
        assert_eq!(q.rows_count("shop", "users"), "SELECT COUNT(*) FROM users");
        assert_eq!(q.row_select("shop", "users", &["id".into(), "name".into()]), "SELECT id||':'||name FROM users");
    }

    #[test]
    fn mssql_set() {
        let q = Dbms::MsSql;
        assert_eq!(
            q.at(&q.schemata_select(), 1),
            "SELECT schema_name FROM information_schema.schemata ORDER BY 1 OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY"
        );
        assert_eq!(q.tables_agg("shop"), "SELECT STRING_AGG(table_name,':') FROM information_schema.tables WHERE table_schema='shop'");
        assert_eq!(q.rows_count("shop", "users"), "SELECT COUNT(*) FROM shop..users");
        assert_eq!(q.row_select("shop", "users", &["id".into()]), "SELECT id FROM shop..users");
    }

    #[test]
    fn oracle_set() {
        let q = Dbms::Oracle;
        assert_eq!(q.schemata_count(), "SELECT COUNT(DISTINCT owner) FROM all_tables");
        assert_eq!(
            q.at(&q.schemata_select(), 3),
            "SELECT * FROM (SELECT x.*, ROWNUM rn FROM (SELECT DISTINCT owner FROM all_tables) x) WHERE rn=4"
        );
        assert_eq!(q.tables_select("SHOP"), "SELECT table_name FROM all_tables WHERE owner='SHOP'");
        assert_eq!(q.columns_count("SHOP", "USERS"), "SELECT COUNT(column_name) FROM all_tab_columns WHERE owner='SHOP' AND table_name='USERS'");
        assert_eq!(q.row_select("SHOP", "USERS", &["ID".into(), "NAME".into()]), "SELECT ID||':'||NAME FROM SHOP.USERS");
        // quote doubling in literals
        assert_eq!(q.tables_select("o'brien"), "SELECT table_name FROM all_tables WHERE owner='o''brien'");
    }

    #[test]
    fn parse_tags_and_fallback() {
        assert_eq!(Dbms::parse("mysql"), Some(Dbms::MySql));
        assert_eq!(Dbms::parse("PostgreSQL"), Some(Dbms::PostgreSql));
        assert_eq!(Dbms::parse("mssql"), Some(Dbms::MsSql));
        assert_eq!(Dbms::parse("oracle"), Some(Dbms::Oracle));
        assert_eq!(Dbms::parse("sqlite"), Some(Dbms::Sqlite));
        assert_eq!(Dbms::parse("access"), None);
    }

    #[test]
    fn sqlite_set() {
        let q = Dbms::Sqlite;
        assert_eq!(Dbms::parse("sqlite"), Some(Dbms::Sqlite));
        assert_eq!(q.schemata_agg(), "SELECT 'main'");
        assert_eq!(q.tables_count("main"), "SELECT COUNT(name) FROM sqlite_master WHERE type='table'");
        assert_eq!(q.at(&q.tables_select("main"), 1), "SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET 1");
        assert_eq!(q.tables_agg("main"), "SELECT GROUP_CONCAT(name,':') FROM sqlite_master WHERE type='table'");
        assert_eq!(q.rows_count("main", "users"), "SELECT COUNT(*) FROM users");
        assert_eq!(
            q.at(&q.row_select("main", "users", &["id".into(), "pw".into()]), 0),
            "SELECT id||':'||pw FROM users LIMIT 1 OFFSET 0"
        );
        assert_eq!(
            q.sqlite_ddl_select("users").as_deref(),
            Some("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")
        );
        assert!(Dbms::MySql.sqlite_ddl_select("users").is_none());
    }

    #[test]
    fn ddl_column_parsing() {
        assert_eq!(
            parse_columns_from_ddl("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, pw VARCHAR(40))"),
            vec!["id", "name", "pw"]
        );
        assert_eq!(
            parse_columns_from_ddl("CREATE TABLE t (a TEXT, CONSTRAINT c UNIQUE(a), b INT)"),
            vec!["a", "b"]
        );
        assert_eq!(parse_columns_from_ddl(r#"CREATE TABLE d (`x` TEXT, [y] INT, "z" REAL)"#), vec!["x", "y", "z"]);
        assert!(parse_columns_from_ddl("not ddl").is_empty());
    }
}
