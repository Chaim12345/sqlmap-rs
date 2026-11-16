//! Compatibility pins from the original Python sqlmap test suite
//! (tests/test_comparison_json.py + jsonMinimize doctests, upstream pinned
//! at sqlmapproject/sqlmap 8b78b676c1376ae28feccd957b03bbecea05eff1).
//!
//! The structured (JSON) oracle: jsonMinimize leaf-path projection +
//! Content-Type-gated comparison. Headline assertions mirror upstream: the
//! JSON path is BETTER than the text path on the same inputs, and every
//! non-JSON/unparseable case falls back to the exact text behavior, so the
//! HTML oracle is untouched. Upstream's --text-only escape hatch is a
//! call-site flag our port does not have; the bypass is pinned here at the
//! function level (text path always available) and recorded in the compat
//! doc.

use sqlmap_http::comparison::{json_minimize, ratio, ratio_aware, filtered_page, UPPER_RATIO_BOUND};

#[test]
fn doctest_cases_byte_exact() {
    // lib/core/common.py jsonMinimize doctests, verbatim
    assert_eq!(
        json_minimize("{\"b\": 2, \"a\": 1}"),
        json_minimize("{\"a\":1,  \"b\":2}")
    );
    assert_eq!(json_minimize("{\"a\": {\"b\": 1}}"), Some(".a.b=1".to_string()));
    assert_eq!(json_minimize("not json"), None);
    assert_eq!(json_minimize("{}"), Some(String::new()));
}

#[test]
fn order_and_whitespace_immune() {
    assert_eq!(
        json_minimize("{\"b\":2,\"a\":1}"),
        json_minimize("{ \"a\": 1,\n  \"b\": 2 }")
    );
}

#[test]
fn value_flip_differs() {
    assert_ne!(json_minimize("{\"ok\":true}"), json_minimize("{\"ok\":false}"));
    // Python-str rendering is pinned: bools become True/False
    assert_eq!(json_minimize("{\"ok\":true}"), Some(".ok=True".to_string()));
}

#[test]
fn array_length_registers() {
    assert_ne!(
        json_minimize("{\"r\":[1,2,3]}"),
        json_minimize("{\"r\":[1,2,3,4]}")
    );
    assert_eq!(
        json_minimize("{\"r\":[1,2]}"),
        Some(".r.__len__=2\n.r[0]=1\n.r[1]=2".to_string())
    );
}

#[test]
fn parse_failure_is_none() {
    for bad in ["", "{bad", "<html></html>", "{'a':1}"] {
        assert_eq!(json_minimize(bad), None, "{bad:?}");
    }
}

#[test]
fn valid_edge_shapes_are_not_none() {
    for ok in ["[1,2]", "42", "null", "\"x\""] {
        assert!(json_minimize(ok).is_some(), "{ok:?}");
    }
    // Python-str style scalars at top level
    assert_eq!(json_minimize("null"), Some("=None".to_string()));
    assert_eq!(json_minimize("42"), Some("=42".to_string()));
}

#[test]
fn noise_immunity_beats_text_path() {
    // upstream headline: reordered + reindented same data -> JSON path
    // ~identical, text path measurably lower
    let a = "{\"id\":1,\"name\":\"alice\",\"role\":\"admin\"}";
    let b = "{ \"role\": \"admin\",\n  \"name\": \"alice\",\n  \"id\": 1 }";
    let json_ratio = ratio_aware(a, b, Some("application/json"));
    let text_ratio = ratio_aware(a, b, Some("text/html"));
    assert!(json_ratio >= UPPER_RATIO_BOUND, "json ratio {json_ratio}");
    assert!(text_ratio < json_ratio, "text {text_ratio} vs json {json_ratio}");
}

#[test]
fn real_difference_still_detected() {
    let a = "{\"role\":\"admin\"}";
    let b = "{\"role\":\"guest\"}";
    assert!(ratio_aware(a, b, Some("application/json")) < UPPER_RATIO_BOUND);
}

#[test]
fn html_content_type_uses_exact_text_path() {
    let a = "{\"id\":1,\"name\":\"alice\"}";
    let b = "{ \"name\": \"alice\", \"id\": 1 }";
    assert_eq!(
        ratio_aware(a, b, Some("text/html")),
        ratio_aware(a, b, None)
    );
    assert_eq!(
        ratio_aware(a, b, None),
        ratio(&filtered_page(a), &filtered_page(b))
    );
}

#[test]
fn unparseable_json_falls_back_to_text() {
    let a = "<html>x</html>";
    let b = "<html>y</html>";
    assert_eq!(
        ratio_aware(a, b, Some("application/json")),
        ratio_aware(a, b, Some("text/html"))
    );
}

#[test]
fn structured_suffix_content_type_gated_in() {
    let a = "{\"id\":1,\"name\":\"alice\",\"role\":\"admin\"}";
    let b = "{ \"role\":\"admin\", \"name\":\"alice\", \"id\":1 }";
    assert!(
        ratio_aware(a, b, Some("application/vnd.api+json; charset=utf-8")) >= UPPER_RATIO_BOUND
    );
}
