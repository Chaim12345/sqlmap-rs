//! Compatibility pins from the original Python sqlmap test suite
//! (tests/test_reflection.py, upstream pinned at
//! sqlmapproject/sqlmap 8b78b676c1376ae28feccd957b03bbecea05eff1).
//!
//! Upstream has two guards. We port stripReflection (lib/utils/nonsql.py):
//! deterministic, stateless, removes the raw/decoded/encoded forms of the
//! payload. We deliberately do NOT port removeReflectiveValues
//! (lib/core/common.py): it carries global state and switches itself off
//! after REFLECTIVE_MISS_THRESHOLD misses, on regex timeout, and during
//! heuristic mode - upstream's own second guard exists because a detection
//! guard must not stop guarding mid-scan. The blind-spot cases upstream
//! pins for the heuristic do not exist here.

use sqlmap_http::comparison::{strip_reflection, REFLECTED_VALUE_MARKER};

const PAYLOAD: &str = "x') or true() or ('";

#[test]
fn removes_the_payload() {
    let out = strip_reflection(&format!("you searched for: {PAYLOAD}"), PAYLOAD);
    assert!(!out.contains(PAYLOAD));
    assert!(out.contains(REFLECTED_VALUE_MARKER));
}

#[test]
fn removes_the_url_encoded_form() {
    // upstream case: page echoes the percent-encoded form of the payload
    let out = strip_reflection(
        "you searched for: x%27%29%20or%20true%28%29",
        "x') or true()",
    );
    assert!(out.contains(REFLECTED_VALUE_MARKER));
}

#[test]
fn two_different_payloads_collapse_to_the_same_page() {
    // the whole point: a pure echo endpoint must stop looking like a
    // boolean oracle
    let t = strip_reflection(
        &format!("you searched for: {PAYLOAD}"),
        PAYLOAD,
    );
    let f_payload = "x') and false() and ('";
    let f = strip_reflection(
        &format!("you searched for: {f_payload}"),
        f_payload,
    );
    assert_eq!(t, f);
}

#[test]
fn a_real_differential_is_preserved() {
    // a genuine oracle differs in the application's own output; stripping
    // must not erase it
    let t = strip_reflection(&format!("results: luther, fluffy, wu [{PAYLOAD}]"), PAYLOAD);
    let f = strip_reflection(&format!("results: none [{PAYLOAD}]"), PAYLOAD);
    assert_ne!(t, f);
}

#[test]
fn covers_the_alphanumeric_blind_spot() {
    // upstream's heuristic leaves purely-alphanumeric payloads in place;
    // the deterministic guard does not
    let out = strip_reflection("you searched for: abcdefghij", "abcdefghij");
    assert!(out.contains(REFLECTED_VALUE_MARKER));
}

#[test]
fn empty_inputs_are_safe() {
    assert_eq!(strip_reflection("abc", ""), "abc");
    assert_eq!(strip_reflection("", PAYLOAD), "");
}

#[test]
fn absent_payload_leaves_content_identical() {
    let content = "nothing to see here";
    assert_eq!(strip_reflection(content, PAYLOAD), content);
}

#[test]
fn every_occurrence_is_removed() {
    let out = strip_reflection(&format!("{PAYLOAD} middle {PAYLOAD}"), PAYLOAD);
    assert!(!out.contains(PAYLOAD));
    assert_eq!(out.matches(REFLECTED_VALUE_MARKER).count(), 2);
}
