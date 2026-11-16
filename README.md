# sqlmap-rs

A Rust port of [sqlmap](https://github.com/sqlmapproject/sqlmap) - the automatic SQL
injection detection tool originally written by Bernardo Damele A. G. (@inquisb)
and Miroslav Stampar (@stamparm), maintained by the sqlmapproject team.

**License:** GPL-2.0-only, the same license as upstream sqlmap. This is a derivative
work; all credit for the original architecture, payload sets, tamper scripts and
detection logic goes to the sqlmap authors and contributors. See LICENSE.

## What works today

Detects SQL injection on a target URL using the three core blind/error techniques
plus UNION column-count probing, with automatic MySQL/PostgreSQL/MSSQL/Oracle/SQLite
error-based fingerprinting. Once an injection is found, it enumerates and dumps data through
the fastest confirmed channel: UNION SELECT echo when a UNION injection was
confirmed (one request per value), otherwise blind inference (sqlmap's
bisection oracle):

```
# find the injection
cargo run -p sqlmap-cli -- -u "http://localhost/item.php?id=1" --technique BEUT
# enumerate
cargo run -p sqlmap-cli -- -u "http://localhost/item.php?id=1" --dbs
cargo run -p sqlmap-cli -- -u "http://localhost/item.php?id=1" --tables -D shop
# dump
cargo run -p sqlmap-cli -- -u "http://localhost/item.php?id=1" --dump -D shop -T users
```

```
cargo run -p sqlmap-cli -- -u "http://localhost/item.php?id=1" --technique BET
```

Verified end-to-end by integration tests that spawn a local deliberately-vulnerable
app (`tests/vulnapp.py`, a MySQL emulator holding a fake in-memory database) and
confirm: real detection on numeric (GET), string (GET), POST-body, Cookie and
User-Agent (level >= 3) parameters, including through a tamper chain; and
byte-for-byte recovery of databases, tables, columns and full table dumps via
BOTH exfil channels (UNION echo and blind inference). `--json` emits findings
as JSON. `cargo test --workspace` runs everything; CI runs the same on every
push.

### Module map

| sqlmap-rs crate | Upstream sqlmap | Status |
|---|---|---|
| `sqlmap-core` | `lib/core/{data,enums}.py`, conf/kb objects | ported (subset) |
| `sqlmap-http` | `lib/request/connect.py`, `lib/core/comparison.py`, forms parsing of `lib/core/target.py` | ported (subset); `--forms` discovery |
| `sqlmap-dbms` | `data/xml/errors.xml`, DBMS fingerprint matching | ported (5 DBMS error tables) |
| `sqlmap-payloads` | `data/xml/boundaries.xml`, `payloads/{boolean_blind,error_based,time_blind}.xml` | ported (level 1-2 head entries) |
| `sqlmap-tamper` | `tamper/*.py` | partial: 19 scripts |
| `sqlmap-detection` | `lib/controller/checks.py`, `lib/request/inference.py`, `lib/techniques/union/use.py` | ported: boolean, error-based, time-based; UNION (column probing + data retrieval); exfiltration `--dbs/--tables/--columns/--dump` over both channels |
| `sqlmap-cli` | `sqlmap.py`, `lib/parse/cmdline.py` | partial (core options) |

### Deliberately not ported

- DNS exfiltration, takeover features (`--os-shell`, `--os-pwn`, file read/write)
- Stacked-queries and inline-query techniques
- Enumeration query sets for non-MySQL DBMS (fingerprinting works for 5 DBMS;
  the information_schema queries used by --dbs/--dump are MySQL-flavored)
- The remaining ~50 tamper scripts, WAF identification, session persistence,
  multi-target modes, crawling, proxy support, threading

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
- Blind inference uses sqlmap's bisection semantics (`expr > mid` probes with a
  final equality confirmation per character); string literals in enumeration
  queries are hex-encoded (0x...) like upstream, so string boundaries stay intact.
- UNION exfiltration probes each SELECT-list position with a delimited constant
  to find the reflected column, then rides values back inside `CONCAT(marker,
  (scalar), marker)` - the same echo contract as upstream's `unionUse`.

## Development

```
cargo build --workspace
cargo test --workspace          # unit + integration (needs python3 for the test app)
```

CI: `.github/workflows/ci.yml` builds and tests on every push.

## Legal / ethics

Like sqlmap, this tool is for authorized security testing of your own systems
only. Running it against targets without permission is illegal.
