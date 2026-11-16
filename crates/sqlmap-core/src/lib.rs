//! Core configuration, target and knowledge-base types.
//! Port of sqlmap `lib/core/data.py` (conf/kb), `lib/core/enums.py` (subset)
//! and the configuration half of `lib/core/option.py`.

pub mod config;
pub mod injection;
pub mod kb;

pub use config::{Config, Place, Technique};
pub use injection::{Boundary, Injection};
pub use kb::KnowledgeBase;

/// Parse a sqlmap-style technique string ("BEUTSQ") into flags.
pub fn parse_techniques(s: &str) -> Vec<Technique> {
    let mut out = Vec::new();
    for c in s.chars() {
        let t = match c {
            'B' => Technique::Boolean,
            'E' => Technique::Error,
            'U' => Technique::Union,
            'T' => Technique::Time,
            'S' => Technique::Stacked,
            'Q' => Technique::Inline,
            _ => continue,
        };
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}
