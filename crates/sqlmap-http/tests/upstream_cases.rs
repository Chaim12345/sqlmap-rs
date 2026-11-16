//! Compatibility pins from the original Python sqlmap test suite /
//! lib/request/comparison.py (upstream pinned at
//! sqlmapproject/sqlmap 8b78b676c1376ae28feccd957b03bbecea05eff1).
//!
//! The expected ratio values were produced by running Python's
//! difflib.SequenceMatcher(None, a, b).ratio() - the exact oracle upstream's
//! boolean engine uses - on the pinned inputs. All pairs stay under 200
//! characters per side so difflib's autojunk heuristic is inactive and the
//! pins are exact; on longer pages upstream's difflib applies autojunk while
//! our port disables it (documented divergence in
//! docs/upstream-test-compat.md).
//!
//! Upstream's --string / --not-string / --regexp / --code match switches and
//! its negative-logic flip are NOT ported (no CLI flags for them), so the
//! corresponding test_comparison.py classes have no cases to adapt here.
//! Reflection masking (removeReflectiveValues) is likewise not ported yet;
//! our filtered_page only strips volatile whitespace and hex tokens.

use sqlmap_http::comparison::{filtered_page, ratio, LOWER_RATIO_BOUND, UPPER_RATIO_BOUND};

/// (a, b, difflib ratio) - expected values computed with CPython 3 difflib.
const RATIO_PINS: &[(&str, &str, f64)] = &[
    (
        "<html><body><h1>Item 1</h1><p>Widget - in stock: 12</p></body></html>",
        "<html><body><h1>Item 1</h1><p>Widget - in stock: 13</p></body></html>",
        0.9855072463768116,
    ),
    (
        "the quick brown fox jumps over the lazy dog",
        "the quick brown fox jumps over the lazy cat",
        0.9302325581395349,
    ),
    ("aaaaabbbbbccccc", "aaaaaBBBBBccccc", 0.6666666666666666),
    ("id=1 name=admin", "id=2 name=alice", 0.7333333333333333),
    ("SELECT", "INSERT", 0.5),
    ("x", "xy", 0.6666666666666666),
];

#[test]
fn ratio_matches_difflib_sequence_matcher() {
    for (a, b, expected) in RATIO_PINS {
        let got = ratio(a, b);
        assert!(
            (got - expected).abs() < 1e-12,
            "ratio({a:?}, {b:?}) = {got}, difflib says {expected}"
        );
    }
    assert_eq!(ratio("same", "same"), 1.0);
    assert_eq!(ratio("", "nonempty"), 0.0);
}

#[test]
fn ratio_bounds_match_upstream_settings() {
    // lib/core/settings.py: LOWER_RATIO_BOUND / UPPER_RATIO_BOUND
    assert_eq!(LOWER_RATIO_BOUND, 0.02);
    assert_eq!(UPPER_RATIO_BOUND, 0.98);
}

#[test]
fn filtered_page_collapses_volatile_whitespace() {
    // Our filtered_page's documented behavior (it is NOT upstream's
    // removeDynamicContent/removeReflectiveValues; see the compat doc).
    let a = filtered_page("<p>stock:\n\n   12</p>");
    let b = filtered_page("<p>stock: 12</p>");
    assert_eq!(a, b);
}
