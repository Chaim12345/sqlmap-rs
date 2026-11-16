//! Detection engine (port of sqlmap `lib/controller/checks.py`).
//!
//! Flow per parameter, mirroring upstream `checkSqlInjection`:
//!   heuristic quote check (fingerprint DBMS from error text)
//!   -> boolean-based blind (true page ~ original, false page differs)
//!   -> error-based (payload marker echoed inside a DBMS error)
//!   -> time-based blind (response delayed by ~SLEEPTIME, confirmed twice)
//!
//! UNION-based is partial (column-count probing); stacked-queries is not ported.
//!
//! After detection, `exfil` runs --dbs/--tables/--columns/--dump through
//! blind inference on a confirmed boolean injection.

pub mod engine;
pub mod exfil;
pub mod forms_scan;
pub mod queries;
pub mod session;
pub mod waf;

pub use engine::{Engine, ScanResult};
