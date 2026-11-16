//! Injection finding types (port of sqlmap `kb.injection` entries and boundaries).

use serde::{Deserialize, Serialize};
use crate::config::{Place, Technique};

/// A boundary: how the payload is wrapped around the original value
/// (port of sqlmap `data/xml/boundaries.xml` entries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Boundary {
    /// Where-clause context the boundary suits (1 = appended AND, like sqlmap where=1).
    pub r#where: u8,
    /// Prefix, e.g. "'" or "')".
    pub prefix: String,
    /// Suffix, e.g. "" or "-- -" (comment to neutralize the rest).
    pub suffix: String,
    /// sqlmap ptype: parameter value type the boundary targets (numeric/string).
    pub ptype: PType,
    /// sqlmap clause: which SQL clause contexts it fits (0 = all).
    pub clause: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PType {
    Numeric,
    String,
}

/// A confirmed (or candidate) injection point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Injection {
    pub place: Place,
    pub parameter: String,
    pub technique: Technique,
    /// Boundary that made the injection work.
    pub boundary: Boundary,
    /// Payload string that demonstrated the injection.
    pub payload: String,
    /// DBMS identified or assumed during the check, if any.
    pub dbms: Option<String>,
    /// Evidence note (e.g. matched error text, observed delay).
    pub note: String,
    /// For UNION-technique findings: the probed column count (drives UNION exfil).
    #[serde(default)]
    pub column_count: Option<u32>,
}
