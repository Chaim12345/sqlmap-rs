//! sqlmap-rs command-line entry point.
//! Port of the option surface of `sqlmap.py` / `lib/parse/cmdline.py` (subset)
//! and the controller flow of `lib/controller/controller.py::start()`.

use clap::Parser;
use sqlmap_core::config::Config;
use sqlmap_core::parse_techniques;

/// sqlmap-rs - Rust port of sqlmap's SQL injection detection engine.
/// Authorized testing only.
#[derive(Parser, Debug)]
#[command(name = "sqlmap-rs", version, about, long_about = None)]
struct Args {
    /// Target URL (sqlmap -u)
    #[arg(short = 'u', long, required_unless_present_any = ["request_file", "bulk_file"])]
    url: Option<String>,

    /// Load the target from a raw HTTP request file (sqlmap -r)
    #[arg(short = 'r', long = "request-file")]
    request_file: Option<String>,

    /// Data string for POST requests (sqlmap --data)
    #[arg(long)]
    data: Option<String>,

    /// HTTP Cookie header value (sqlmap --cookie)
    #[arg(long)]
    cookie: Option<String>,

    /// Extra headers, e.g. "X-Forwarded-For: 127.0.0.1" (repeatable; sqlmap --headers)
    #[arg(long = "header")]
    headers: Vec<String>,

    /// Testable parameter(s) (sqlmap -p)
    #[arg(short = 'p', long)]
    param: Option<String>,

    /// Skip given parameter(s) (sqlmap --skip)
    #[arg(long)]
    skip: Option<String>,

    /// SQL injection techniques to use (sqlmap --technique, default BEUT)
    #[arg(long, default_value = "BEUT")]
    technique: String,

    /// Level of tests to perform, 1-5 (sqlmap --level)
    #[arg(long, default_value_t = 1)]
    level: u8,

    /// Risk of tests to perform, 1-3 (sqlmap --risk)
    #[arg(long, default_value_t = 1)]
    risk: u8,

    /// Force back-end DBMS (sqlmap --dbms)
    #[arg(long)]
    dbms: Option<String>,

    /// Tamper scripts, comma separated (sqlmap --tamper)
    #[arg(long, value_delimiter = ',')]
    tamper: Vec<String>,

    /// Seconds to delay responses for time-based checks (sqlmap --time-sec)
    #[arg(long, default_value_t = 2)]
    time_sec: u32,

    /// HTTP timeout in seconds (sqlmap --timeout)
    #[arg(long, default_value_t = 30)]
    timeout: u64,

    /// Custom User-Agent (sqlmap --user-agent)
    #[arg(long)]
    user_agent: Option<String>,

    /// Follow redirects (sqlmap --follow-redirects)
    #[arg(long)]
    follow_redirects: bool,

    /// Print findings as JSON instead of text
    #[arg(long)]
    json: bool,

    /// Enumerate databases (sqlmap --dbs, blind inference)
    #[arg(long)]
    dbs: bool,

    /// Enumerate tables (sqlmap --tables; use -D to narrow)
    #[arg(long)]
    tables: bool,

    /// Enumerate columns (sqlmap --columns; requires -D and -T)
    #[arg(long)]
    columns: bool,

    /// Dump table rows (sqlmap --dump; requires -D and -T)
    #[arg(long)]
    dump: bool,

    /// Target database (sqlmap -D)
    #[arg(short = 'D', long)]
    db: Option<String>,

    /// Target table (sqlmap -T)
    #[arg(short = 'T', long)]
    table: Option<String>,

    /// Parse and test target page's HTML forms (sqlmap --forms)
    #[arg(long)]
    forms: bool,

    /// Crawl the target same-host up to this depth and test every page found (sqlmap --crawl)
    #[arg(long, default_value_t = 0)]
    crawl: u8,

    /// Worker threads for concurrent HTTP requests (sqlmap --threads)
    #[arg(long, default_value_t = 4)]
    threads: usize,

    /// Identify a WAF/IPS in front of the target (sqlmap --identify-waf)
    #[arg(long)]
    identify_waf: bool,

    /// Do not update session cookies from Set-Cookie responses (sqlmap --ignore-set-cookie)
    #[arg(long)]
    ignore_set_cookie: bool,

    /// Session file for resumable scans (sqlmap -s/--session)
    #[arg(short = 's', long)]
    session: Option<String>,

    /// Ignore and overwrite the session file (sqlmap --flush-session)
    #[arg(long)]
    flush_session: bool,

    /// Scan multiple targets listed in a text file, one URL per line (sqlmap -m)
    /// Route requests through this HTTP proxy (sqlmap --proxy)
    #[arg(long)]
    proxy: Option<String>,
    /// Scan every target URL listed in the file (sqlmap -m)
    #[arg(short = 'm', long = "bulk-file")]
    bulk_file: Option<String>,
}

fn main() {
    let args = Args::parse();
    // sqlmap -r: a saved raw request supplies URL/body/cookie/headers;
    // explicit command-line flags win over the file's values.
    let parsed = args.request_file.as_ref().map(|file| {
        let text = std::fs::read_to_string(file)
            .unwrap_or_else(|e| {
                eprintln!("[-] cannot read request file {file}: {e}");
                std::process::exit(2);
            });
        sqlmap_core::requestfile::parse_request_file(&text, "http")
            .unwrap_or_else(|e| {
                eprintln!("[-] cannot parse request file {file}: {e}");
                std::process::exit(2);
            })
    });
    let conf = Config {
        target_url: args
            .url
            .clone()
            .or_else(|| parsed.as_ref().map(|p| p.url.clone()))
            .unwrap_or_default(),
        data: args
            .data
            .clone()
            .or_else(|| parsed.as_ref().and_then(|p| p.body.clone())),
        cookie: args
            .cookie
            .clone()
            .or_else(|| parsed.as_ref().and_then(|p| p.cookie.clone())),
        headers: {
            let mut h = parsed
                .as_ref()
                .map(|p| p.headers.clone())
                .unwrap_or_default();
            h.extend(args.headers.clone());
            h
        },
        test_param: args.param,
        skip_param: args.skip,
        techniques: parse_techniques(&args.technique),
        level: args.level.clamp(1, 5),
        risk: args.risk.clamp(1, 3),
        dbms: args.dbms,
        tampers: args.tamper,
        time_sec: args.time_sec,
        timeout: args.timeout,
        follow_redirects: args.follow_redirects,
        user_agent: args.user_agent,
        enum_dbs: args.dbs,
        enum_tables: args.tables,
        enum_columns: args.columns,
        dump: args.dump,
        target_db: args.db,
        target_table: args.table,
        forms: args.forms,
        crawl_depth: args.crawl,
        threads: args.threads.max(1),
        identify_waf: args.identify_waf,
        ignore_set_cookies: args.ignore_set_cookie,
        proxy: args.proxy,
        session_file: args.session,
        flush_session: args.flush_session,
        ..Config::default()
    };

    // sqlmap -m: every non-empty, non-comment line is a target scanned with
    // the same options; the exit status reflects whether ANY target was
    // injectable. Targets run --threads at a time (sqlmap walks them
    // sequentially; here the worker pool's width is reused across targets).
    if let Some(file) = &args.bulk_file {
        let text = std::fs::read_to_string(file).unwrap_or_else(|e| {
            eprintln!("[-] cannot read bulk file {file}: {e}");
            std::process::exit(2);
        });
        let targets: Vec<String> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect();
        let width = conf.threads.max(1);
        let mut any = false;
        let mut i = 0;
        while i < targets.len() {
            let end = (i + width).min(targets.len());
            let results = std::thread::scope(|s| {
                targets[i..end]
                    .iter()
                    .map(|target| {
                        let mut tconf = conf.clone();
                        tconf.target_url = target.clone();
                        tconf.session_file = None; // per-target caches are keyed by URL; bulk keeps it simple
                        s.spawn(move || run_target(&tconf, args.json))
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|h| h.join().unwrap_or(false))
                    .collect::<Vec<_>>()
            });
            any |= results.into_iter().any(|x| x);
            i = end;
        }
        std::process::exit(if any { 0 } else { 1 });
    }

    std::process::exit(if run_target(&conf, args.json) { 0 } else { 1 });
}

/// Scan one target and report; true when injection points were found.
fn run_target(conf: &Config, json: bool) -> bool {
    if !json {
        println!("sqlmap-rs {} - Rust port of sqlmap (GPL-2.0)", env!("CARGO_PKG_VERSION"));
        println!("[*] target: {}", conf.target_url);
    }

    let client = sqlmap_http::client::Client::new(conf);
    let result = sqlmap_detection::forms_scan::scan_auto(&client, conf);

    let kb = &result.kb;
    if json {
        let out = serde_json::json!({
            "target": conf.target_url,
            "fingerprinted_dbms": kb.fingerprinted_dbms,
            "injections": kb.injections,
            "enumeration": kb.enumeration,
            "wafs": kb.wafs,
            "log": result.log,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return !kb.injections.is_empty();
    }
    for line in &result.log {
        println!("[*] {line}");
    }
    if let Some(dbms) = &kb.fingerprinted_dbms {
        println!("[+] back-end DBMS: {dbms}");
    }
    if !kb.wafs.is_empty() {
        println!("[+] WAF/IPS identified: {}", kb.wafs.join(", "));
    }
    if kb.injections.is_empty() {
        println!("[-] no injection points found");
        return false;
    }
    println!("[+] {} injection point(s) found:", kb.injections.len());
    for inj in &kb.injections {
        println!(
            "    {} ({:?}) - {:?} - payload: {}",
            inj.parameter, inj.place, inj.technique, inj.payload
        );
    }
    let en = &kb.enumeration;
    if !en.is_empty() {
        if !en.databases.is_empty() {
            println!("[+] databases: {}", en.databases.join(", "));
        }
        for (db, tables) in &en.tables {
            println!("[+] {db}: {}", tables.join(", "));
        }
        for c in &en.columns {
            println!("[+] {}.{}: {}", c.db, c.table, c.columns.join(", "));
        }
        for d in &en.dumps {
            println!("[+] dump {}.{} ({} row(s)):", d.db, d.table, d.rows.len());
            println!("    {}", d.columns.join(" | "));
            for row in &d.rows {
                println!("    {}", row.join(" | "));
            }
        }
    }
    true
}
