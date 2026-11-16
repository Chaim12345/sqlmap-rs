# Compatibility with the original Python sqlmap test suite

Upstream suite pinned at sqlmapproject/sqlmap commit
[`8b78b676c1376ae28feccd957b03bbecea05eff1`](https://github.com/sqlmapproject/sqlmap/tree/8b78b676c1376ae28feccd957b03bbecea05eff1/tests)
(2026-11-12, 112 `tests/test_*.py` files). Our adaptations landed in commits `be01d13` and later on main. All execution is against this repo's local fixtures only
(`tests/vulnapp.py`, `tests/tinyproxy.py`, `tests/tinysocks.py`); no external
target is ever touched.

## Can the original tests run unchanged on this port? No.

All 112 files bootstrap sqlmap's Python runtime
([`tests/_testutils.py`](https://github.com/sqlmapproject/sqlmap/blob/8b78b676c1376ae28feccd957b03bbecea05eff1/tests/_testutils.py)
initializes `conf`/`kb`, loads `queries.xml`) and import Python modules
(`lib.*`, `tamper.*`, `thirdparty.*`, `cloak.py`) to exercise them in
process, most with the network seam mocked by an in-process oracle. They
assert on Python module internals a Rust port does not have, so **zero
upstream test files execute unchanged against sqlmap-rs**. That is
structural, not a test failure. `tests/integration/audit/` is a Docker
compose harness auditing `sqlmap.py` against live containerized DBMS
instances - also Python-internal and out of scope for unchanged execution.

The meaningful question is which files pin a *behavioral contract* that is
observable at our CLI, our generated SQL text, or our I/O formats with
local fixtures. The per-file triage below answers that.

## A. Transferable - behavioral contract, feature exists in this port (22 files)

Concrete cases from these belong in `crates/*/tests/upstream_*.rs` with
verbatim upstream inputs/expectations.

| Upstream file | Contract | Adaptation status |
| --- | --- | --- |
| [test_tamper.py](https://github.com/sqlmapproject/sqlmap/blob/8b78b676c1376ae28feccd957b03bbecea05eff1/tests/test_tamper.py) | tamper input->output transforms | **partial (15/17)**: `crates/sqlmap-tamper/tests/upstream_cases.rs` - 15 doctest cases byte-exact, 1 pinned divergence (symboliclogical: raw `&&`/`||` encoded at transport), 1 pinned not-ported (greatest) |
| [test_agent.py](https://github.com/sqlmapproject/sqlmap/blob/8b78b676c1376ae28feccd957b03bbecea05eff1/tests/test_agent.py) | forged query shapes (prefix/suffix, marker cleanup) | **partial**: `crates/sqlmap-cli/tests/upstream_agent.rs` pins the wire-level contracts (prefixQuery space padding for non-stacked, no space for stacked, no [RANDNUM]/[RANDSTR] on the wire) - and the pin first caught that we sent `1AND ...` unpadded, fixed to upstream's rule. In-process helper pins (getFields, nullAndCastField, concatQuery folding) remain open; our row-concat shapes are deliberately simpler than upstream's IFNULL/CAST wrapping (divergence: rows containing NULLs are not restored to ' ' as upstream does) |
| [test_comparison.py](https://github.com/sqlmapproject/sqlmap/blob/8b78b676c1376ae28feccd957b03bbecea05eff1/tests/test_comparison.py) | page-comparison oracle (true/false/None, ratio semantics) | **partial**: `crates/sqlmap-http/tests/upstream_cases.rs` pins difflib ratio values (computed from CPython difflib) and the 0.02/0.98 bounds. The --string/--not-string/--regexp/--code match classes and the negative-logic flip are **not ported** (no CLI flags) - gaps, not passes. Reflection masking (removeReflectiveValues) is **not ported**: our filtered_page only strips volatile whitespace and hex tokens. Divergence: on pages >200 chars upstream's difflib applies its autojunk heuristic; our port disables it (pins stay under 200 chars so they are exact) |
| [test_dialect.py](https://github.com/sqlmapproject/sqlmap/blob/8b78b676c1376ae28feccd957b03bbecea05eff1/tests/test_dialect.py) | per-DBMS paging/cast/hex/union forging | **partial**: `crates/sqlmap-detection/tests/upstream_dialect.rs` - MySQL paging is byte-exact with upstream limitQuery; pg/oracle/mssql paging are pinned divergences (upstream text carried verbatim in the pin comments); nullAndCastField/hexConvertField are **not ported** (no cast/null-wrap in our exfil; pinned as current behavior with the NULL-row gap called out) |
| test_dialectdbms.py | operator/typing dialect heuristics | partial - our fingerprinting is narrower |
| test_settings_regex.py | settings.py *_REGEX battery (IP, PERMISSION_DENIED, PARAMETER_SPLITTING, HTML_TITLE, META_CHARSET, META_REFRESH) | NICHT UEBERTRAGBAR: die gepinnten Muster haben keine Rust-Entsprechung (keine IP-/Titel-/Meta-Extraktion, kein generisches Parameter-Splitting im Port). Unsere WAF-/Error-Signaturen in waf.rs und der Error-Detection sind eigene Implementierungen mit eigenen Tests, aber nicht gegen upstream-Cases gepinnt. |
| test_heuristic_signatures.py | non-SQL heuristic signatures | partial - our heuristics are narrower |
| [test_crawler.py](https://github.com/sqlmapproject/sqlmap/blob/8b78b676c1376ae28feccd957b03bbecea05eff1/tests/test_crawler.py) | crawl target dedup shapes | **partial**: `crates/sqlmap-http/tests/upstream_crawler.rs` - 4/5 cases adapted exactly (value-collapse, distinct endpoints, param names, hosts). Our crawler previously scanned every value variant; dedup_targets now collapses them like upstream. POST-body folding not adapted: our crawler is GET-only |
| test_urls.py | checkSameHost, paramToDict, urlencode | PINNED partial (upstream_urls.rs): checkSameHost inkl. www-Normalisierung + Port-Ignoranz als Kompat-Hilfsfunktion gepinnt - bewusst NICHT im Crawler verdrahtet: Crawl-Scope bleibt strikter Origin-Vergleich (scheme://host:port), siehe scope_guard.rs; paramToDict-Cases auf parse_pairs; urlencode(safe="")-Vollkodierung bewusste Divergenz (Payload-Transport-Encoding) |
| test_targeturl.py | parseTargetUrl (Scheme/Default-Port/Userinfo-Normalisierung) | NICHT UEBERTRAGBAR: kein Rust-Aequivalent - es gibt keinen separaten URL-Normalisierungsschritt; ureq parst die volle URL intern beim Request. Verhalten bei inline-credentials (user:pass@host) ist bewusst ungepinnt und undokumentiert in unserem Port. |
| test_target_parsing.py | target option plumbing | partial - only implemented options |
| test_payload_marking.py | JSON/JSON_LIKE/XML recognition regexes + body marking + HPP comma-join reconstruction | FEATURE-GAP: JSON-/XML-Body-Injection-Marking und HPP sind nicht portiert (kein recognition-regex, kein Body-Marking). GET `*`-Marking ist bereits durch upstream_agent.rs gepinnt. |
| [test_payloads_structure.py](https://github.com/sqlmapproject/sqlmap/blob/8b78b676c1376ae28feccd957b03bbecea05eff1/tests/test_payloads_structure.py) | payload/boundary structural invariants | **partial**: `crates/sqlmap-payloads/tests/upstream_structure.rs` pins unique/non-empty titles, level/risk ranges, clean marker rendering. Upstream's floors (>=200 payloads, >=30 boundaries) are NOT claimed - level 1-2 subset; current counts (22/8) pinned instead. Boundary-level ranges not pinned: our Boundary struct has no level field |
| test_fingerprint.py / test_parse_modules.py | per-DBMS fingerprint cascade (checkBooleanExpression/getValue oracle, version ranges) | FEATURE-GAP: der Versions-Fingerprint-Kaskaden-Mechanismus ist nicht portiert; unsere DBMS-Identifikation ist fehler/banner-basiert (engine + error detection), ohne Versionsbereichs-Aufloesung. |
| test_checks.py | checks.py decision logic: heuristic check verdicts, null connection (HEAD/Range Content-Length), stability prompts, internet check | FEATURE-GAP: null-connection, Stabilitaets-Abfragen und Internet-Check sind nicht portiert. Unsere heuristische Detection ist in engine/detection integriert und durch eigene Tests gedeckt, nicht durch upstream-Cases. |
| test_reflection.py | removeReflectiveValues (masking of reflected parameter values before page comparison) | FEATURE-GAP: Reflection-Masking ist nicht portiert; unser Vergleich arbeitet auf unmaskierten Seiten (in upstream_dialect/Comparisons dokumentiert). |
| test_charset.py / test_decodepage.py | checkCharEncoding canonicalization, META_CHARSET/META_REFRESH extraction, misdecoded-UTF8 detection | FEATURE-GAP: Charset-Kanonisierung und Misdecode-Erkennung sind nicht portiert; Dekodierung laeuft auf ureq-Ebene ohne Kanonisierung. |
| test_comparison_json.py | JSON-aware comparison oracle | **gap first**: no JSON comparator in our port; adapt after building it |
| test_boolean_jitter.py / test_jitter_stress.py | engines under response jitter | **gap first**: our engines are single-measurement (README-admitted); adapt after retry/jitter handling exists |

## B. Related coverage in this repo (6 files) - NOT upstream conformance

These run sqlmap's engines against a mocked in-process oracle. This repo
proves similar extraction contracts end-to-end against its own local
emulator - but those are DIFFERENT fixtures and harnesses, so they do NOT
establish that the original upstream contracts pass; they are recorded as
related coverage only, never as conformance: test_error_engine.rs -> `crates/sqlmap-detection/tests/` error-based
exfil; test_union_engine.py and test_inference_engine.py and
test_techniques.py -> union/boolean/time/stacked/inline exfil integration
tests; test_databases_enum.py / test_users_enum.py -> `--dbs`/`--tables`/
`--columns`/`--dump` integration tests.

## C. Feature not ported - test cannot transfer (kept visible as gaps)

GraphQL, HQL, NoSQL, OData, SPARQL, SSTI, XPath, XSLT, XXE, LDAP, JWT,
WebSocket, gRPC-Web, HTTP/2 (client + timeless timing), multi-bit
inference, DNS exfiltration (deliberately out), takeover/file read-write
(deliberately out), dork search, brute force, hash primitives + dictionary
cracking, Kerberos auth, OpenAPI/HAR target inputs, audit acquisition,
automatic WAF-bypass tamper selection, auth-refresh hook, the esperanto
regression harness, `-d` SQLAlchemy connector, `-c` INI config files, JSON
scan report, CSV/HTML/JSONL dump writers (our `--dump` is stdout-only),
search enum, plugins/generic entries, keyset-pagination dump engine,
`--profile`, the REST API server, and the DBMS-plugin enum overrides beyond
our SQLite set (test_dbms_enum.py). Files: test_graphql, test_hql,
test_nosql, test_odata, test_sparql, test_ssti, test_xpath, test_xslt,
test_xxe, test_ldap, test_jwt, test_websocket, test_websocket_response,
test_grpcweb, test_dns_engine, test_dns_server, test_generic_takeover,
test_filesystem, test_dork_search, test_brute, test_hash, test_hash_crack,
test_kerberos, test_http2, test_timeless, test_multibit, test_openapi,
test_openapi_drift, test_har, test_audit, test_wafbypass,
test_authrefresh, test_esperanto, test_sqlalchemy, test_configfile,
test_report, test_dump_format, test_dump_jsonl, test_identifiers_output,
test_search_enum, test_dbms_enum, test_entries, test_keyset_engine,
test_profiling, test_api.

## D. Implementation-specific Python internals (no Rust-port contract)

Option/config normalization internals, Python codecs and container types,
vendored parsers (sgmllib forks), session SQLite writer, decorators,
dependency probes, repo data-file invariants, progress bar, wordlist
iterator, purge, cloak, GUI helpers, https handler, DB wire protocols,
property-fuzz of Python parsers, SQL lint/parse helpers, library facade,
misc helpers: test_bigarray, test_brotli,
test_cloak, test_common, test_common_helpers, test_compat, test_convert,
test_datafiles, test_datatypes, test_dbwire, test_decorators, test_deps,
test_dicts, test_encoding, test_gui_helpers, test_hashdb,
test_html_parser_forks, test_httpshandler, test_jit_guard, test_kbchars,
test_library, test_misc, test_option, test_pagecontent, test_progress,
test_property, test_purge, test_replication, test_request_basic,
test_safe2bin, test_serialize, test_sgmllib, test_sqllint, test_sqlparse,
test_strings, test_texthelpers, test_threads, test_utils, test_wordlist.

## Bugs the adaptation already caught (fixed in `be01d13` and later)

Running upstream's doctest cases against our tamper ports surfaced four
real fidelity bugs, each re-pinned against the upstream scripts' actual
runtime output: `between` (naive char swap -> upstream's operand-aware
rewrite), `percentage` (was prefixing spaces), `halfversionedmorekeywords`/
`versionedkeywords` (missing upstream's space-eating post-pass),
`bluecoat` (was replacing every space instead of keyword-suffixed `%09`
plus guarded `=` -> ` LIKE `). Pinning difflib ratio values caught a fifth:
our SequenceMatcher DP carried chain lengths within the same round instead
of across rounds, undercounting matches (and panicking on adjacent repeated
characters); fixed to difflib's newlengths-swap semantics and pinned exact.

## Discipline

No expected-gap assertion counts as a parity pass. Divergences are pinned
with reasons, unported scripts are named and asserted absent, gaps are
listed as gaps (above), and every adapted case carries the upstream source
at the pinned revision.
