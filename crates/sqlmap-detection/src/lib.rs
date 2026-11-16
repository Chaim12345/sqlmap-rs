//! Detection engine (port of sqlmap `lib/controller/checks.py`).
//!
//! Flow per parameter, mirroring upstream `checkSqlInjection`:
//!   heuristic quote check (fingerprint DBMS from error text)
//!   -> boolean-based blind (true page ~ original, false page differs)
//!   -> error-based (payload marker echoed inside a DBMS error)
//!   -> time-based blind (response delayed by ~SLEEPTIME, confirmed twice)
//!
//! UNION-based and stacked-queries checks are not ported yet.

pub mod engine;

pub use engine::{Engine, ScanResult};
