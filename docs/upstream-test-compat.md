# Compatibility with the original Python sqlmap test suite

Status as of commit with this document (upstream snapshot: sqlmapproject/sqlmap
master, cloned 2026-11-16, tests/ at 112 test files).

## Can the original tests run unchanged on this port? No.

All 112 files under upstream `tests/` bootstrap sqlmap's Python runtime
(`tests/_testutils.py` initializes `conf`/`kb`, loads `queries.xml`) and
import Python modules (`lib.*`, `tamper.*`, `thirdparty.*`, `cloak.py`) to
exercise them in process, most with the network seam mocked by an in-process
oracle. They test Python module internals this Rust port does not have, so
**zero upstream test files can execute unchanged against sqlmap-rs** — this
is a structural fact of a Rust re-implementation, not a test failure. Any
claim of "the Python suite passes" on a Rust port would be vacuous.

`tests/integration/audit/` is a Docker compose harness that audits the
Python sqlmap against live containerized DBMS instances; it likewise drives
`sqlmap.py` internals and is out of scope for unchanged execution.

## What we do instead: adapted behavioral pins

Where an upstream test pins concrete, externally observable behavior, the
case is ported verbatim (same input, same expected output) into a Rust test
against our implementation, and the mapping is recorded here.

| Upstream test | Adaptation | Status |
| --- | --- | --- |
| `tests/test_tamper.py` `TestKnownTransforms` (17 doctest input→output cases) | `crates/sqlmap-tamper/tests/upstream_cases.rs` | 15 byte-exact matches; 1 intentional divergence (`symboliclogical` emits raw `&&`/`||` instead of `%26%26`/`%7C%7C` — our HTTP layer encodes at transport, avoiding double-encoding; pinned with reason); 1 not ported (`greatest`, needs SQL expression parsing — see README not-ported) |

Adapting that file surfaced and fixed four real fidelity bugs in our tamper
ports, verified against the upstream scripts' actual runtime output:

1. `between` was a naive character swap; rewritten to upstream's
   operand-aware rewrite (`A > B` -> `A NOT BETWEEN 0 AND B`,
   `a=b` -> `a BETWEEN b AND b`, compound-operator and BENCHMARK guards,
   WHEN-anchored pass). All five upstream doctest cases pinned.
2. `percentage` prefixed spaces with `%`; upstream leaves spaces bare.
3. `halfversionedmorekeywords` / `versionedkeywords` missed upstream's
   post-pass that eats spaces around the versioned comments
   (`" /*!0"` -> `"/*!0"`, `" */"` handling).
4. `bluecoat` replaced every space with `%09`; upstream appends `%09` only
   after SQL keyword words and rewrites `=` to ` LIKE ` with
   compound-operator guards.

## Everything else: unsupported by structure

The remaining 111 files have no behavior-level contract to adapt — they
assert on Python internals: option/config plumbing (`test_option`,
`test_configfile`), Python codecs and parsers (`test_sqlparse`,
`test_sgmllib`, `test_charset`, `test_urls`), mocked-oracle engine runs of
`lib/techniques/*` (`test_techniques`, `test_inference_engine`,
`test_union_engine`, `test_error_engine`), API/DNS/GUI helpers, etc. Our
Rust equivalents of those behaviors are covered by this repo's own unit and
integration tests (detection, exfiltration, tampers, proxying, sessions,
crawler), listed in the README. Where a behavior here diverges from
upstream intentionally, it is pinned with a reason (as above) rather than
silently dropped.

## Failures

None outstanding in the adapted set. New adaptations belong in
`crates/*/tests/upstream_*.rs` with the same discipline: verbatim upstream
inputs and expectations, divergences pinned with reasons, unported scripts
named.
