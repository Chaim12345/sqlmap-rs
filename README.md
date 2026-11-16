# sqlmap-rs

A Rust port of [sqlmap](https://github.com/sqlmapproject/sqlmap) - the automatic SQL
injection and database takeover tool by Bernardo Damele A. G. (@stamparm) and
Miroslav Stampar (@stamparm) / the sqlmapproject team.

**License:** GPL-2.0-only, the same license as upstream sqlmap. This is a derivative
work; all credit for the original architecture, payload sets, tamper scripts and
detection logic goes to the sqlmap authors and contributors. See LICENSE.

## Status

Work in progress. This port re-implements sqlmap's core engine in Rust, subsystem
by subsystem, mirroring upstream's architecture. See the module map below for
exactly what is ported, partial, or not started.

### Module map

| sqlmap-rs crate | Upstream sqlmap | Status |
|---|---|---|
| `sqlmap-core` | `lib/core/{option,data,agent}.py` | scaffolded |
| `sqlmap-http` | `lib/request/*`, `lib/core/comparison.py` | scaffolded |
| `sqlmap-dbms` | `data/xml/errors.xml`, `plugins/dbms/*` | scaffolded |
| `sqlmap-payloads` | `data/xml/payloads/*.xml`, `data/xml/boundaries.xml` | scaffolded |
| `sqlmap-tamper` | `tamper/*.py` | scaffolded |
| `sqlmap-detection` | `lib/controller/checks.py` | scaffolded |
| `sqlmap-cli` | `sqlmap.py`, `lib/parse/cmdline.py` | scaffolded |

### Not ported (out of scope for now)

Everything not listed above, including: takeover features (`--os-shell` etc.),
database dumping (`--dump`), UNION query data exfiltration, WAF identification
scripts beyond the tamper subset, and the full DBMS plugin directory.

## Legal / ethics

Like sqlmap, this tool is for authorized security testing of your own systems
only. Running it against targets without permission is illegal.
