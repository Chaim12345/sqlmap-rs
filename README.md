# sqlmap-rs

A Rust port of [sqlmap](https://github.com/sqlmapproject/sqlmap) - the automatic SQL
injection detection tool originally written by Bernardo Damele A. G. (@inquisb)
and Miroslav Stampar (@stamparm), maintained by the sqlmapproject team.

**License:** GPL-2.0-only, the same license as upstream sqlmap. This is a derivative
work; all credit for the original architecture, payload sets, tamper scripts and
detection logic goes to the sqlmap authors and contributors. See LICENSE.

## What works today

Detects SQL injection on a target URL using the three core blind/error techniques,
with automatic MySQL/PostgreSQL/MSSQL/Oracle/SQLite error-based fingerprinting:

```
cargo run -p sqlmap-cli -- -u "http://localhost/item.php?id=1" --technique BET
```

Verified end-to-end by integration tests that spawn a local deliberately-vulnerable
app (`tests/vulnapp.py`, a MySQL emulator) and confirm real detection on numeric
(GET), string (GET), POST-body and Cookie parameters, including through a tamper
chain. `cargo test --workspace` runs everything; CI runs the same on every push.

### Module map

| sqlmap-rs crate | Upstream sqlmap | Status |
|---|---|---|
| `sqlmap-core` | `lib/core/{data,enums}.py`, conf/kb objects | ported (subset) |
| `sqlmap-http` | `lib/request/connect.py`, `lib/core/comparison.py` | ported (subset) |
| `sqlmap-dbms` | `data/xml/errors.xml`, DBMS fingerprint matching | ported (5 DBMS error tables) |
| `sqlmap-payloads` | `data/xml/boundaries.xml`, `payloads/{boolean_blind,error_based,time_blind}.xml` | ported (level 1-2 head entries) |
| `sqlmap-tamper` | `tamper/*.py` | partial: 6 scripts |
| `sqlmap-detection` | `lib/controller/checks.py` | ported: boolean, error-based, time-based; union partial |
| `sqlmap-cli` | `sqlmap.py`, `lib/parse/cmdline.py` | partial (core options) |

### Deliberately not ported

- Data exfiltration (`--dump`, UNION query data retrieval, DNS exfiltration)
- Takeover features (`--os-shell`, `--os-pwn`, file read/write)
- Stacked-queries and inline-query techniques
- User-Agent/Referer/header injection places (sqlmap level 3+)
- UNION data exfiltration (column-count probing via ORDER BY IS ported; the finding reports the column count, but no UNION SELECT data retrieval)
- The remaining ~60 tamper scripts, WAF identification, session persistence,
  multi-target modes, crawling, forms auto-discovery, proxy support, threading

The boundary between ported and not-ported is enforced by the code: the engine
skips unknown techniques/tampers with a log line rather than pretending.

## Fidelity notes

- Page comparison uses the same `difflib.SequenceMatcher` ratio semantics as
  sqlmap's `comparison.py` (2*M/T over recursive longest-match blocks).
- Payload assembly order matches upstream: original value + boundary prefix +
  payload + boundary suffix, then tamper chain.
- Time-based confirmation repeats the delayed request, like upstream, to rule
  out network jitter.
- Error-based detection requires the payload marker to be echoed inside a
  DBMS error - same contract as upstream's error payloads.

## Development

```
cargo build --workspace
cargo test --workspace          # unit + integration (needs python3 for the test app)
```

CI: `.github/workflows/ci.yml` builds and tests on every push.

## Legal / ethics

Like sqlmap, this tool is for authorized security testing of your own systems
only. Running it against targets without permission is illegal.
