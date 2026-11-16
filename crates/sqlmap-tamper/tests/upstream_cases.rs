//! Compatibility pins taken VERBATIM from the original Python sqlmap test
//! suite (tests/test_tamper.py, class TestKnownTransforms - "authoritative
//! input->output taken from each tamper's own doctest"). Each case is the
//! exact input and expected output the upstream suite asserts, run here
//! against our Rust port of the same script.
//!
//! Upstream's suite is Python-internal (it imports lib.* modules), so these
//! cases cannot be executed unchanged against the Rust binary; this file is
//! the documented adaptation. Cases whose upstream script we deliberately
//! did not port (greatest) or where our port intentionally differs are
//! pinned separately with their reason, never silently dropped.

use sqlmap_tamper::apply_all;

fn run(name: &str, input: &str) -> String {
    apply_all(&[name.to_string()], input, 0xC0FFEE).expect("known tamper")
}

/// Cases expected to match upstream output byte-for-byte.
const MATCHING: &[(&str, &str, &str)] = &[
    ("space2comment", "SELECT id FROM users", "SELECT/**/id/**/FROM/**/users"),
    ("between", "1 AND A > B--", "1 AND A NOT BETWEEN 0 AND B--"),
    (
        "charencode",
        "SELECT FIELD FROM%20TABLE",
        "%53%45%4C%45%43%54%20%46%49%45%4C%44%20%46%52%4F%4D%20%54%41%42%4C%45",
    ),
    ("apostrophemask", "1 AND '1'='1", "1 AND %EF%BC%871%EF%BC%87=%EF%BC%871"),
    ("equaltolike", "SELECT * FROM users WHERE id=1", "SELECT * FROM users WHERE id LIKE 1"),
    (
        "percentage",
        "SELECT FIELD FROM TABLE",
        "%S%E%L%E%C%T %F%I%E%L%D %F%R%O%M %T%A%B%L%E",
    ),
    ("space2plus", "1 AND 2>1", "1+AND+2>1"),
    ("unionalltounion", "1 UNION ALL SELECT 2", "1 UNION SELECT 2"),
    ("halfversionedmorekeywords", "1 AND 2>1", "1/*!0AND 2>1"),
    ("versionedkeywords", "1 AND 2>1", "1/*!AND*/2>1"),
    ("appendnullbyte", "1", "1%00"),
    ("base64encode", "1 AND 1=1", "MSBBTkQgMT0x"),
    ("ifnull2ifisnull", "IFNULL(a,b)", "IF(ISNULL(a),b,a)"),
    ("bluecoat", "1 AND 2=2", "1 AND%092 LIKE 2"),
    ("apostrophenullencode", "'", "%00%27"),
];

/// Upstream cases we intentionally diverge from, with the reason. The pin
/// records our actual behavior so a silent behavior change fails loudly.
const DIVERGENT: &[(&str, &str, &str, &str)] = &[
    (
        "symboliclogical",
        "1 AND 2 OR 3",
        // upstream emits URL-encoded operators: "1 %26%26 2 %7C%7C 3"
        "1 && 2 || 3",
        "our port emits the raw && / || operators and lets the HTTP layer \
         encode them, so double-encoding cannot occur; the emulator and the \
         end-to-end tamper tests cover the transported form",
    ),
];

/// Upstream cases whose script we deliberately did not port (documented in
/// the crate docs and README not-ported list). Named so a future port has
/// the pin ready.
const NOT_PORTED: &[(&str, &str, &str)] = &[
    ("greatest", "1 AND A>B", "1 AND GREATEST(A,B+1)=A"),
];

#[test]
fn upstream_doctest_transforms_match() {
    for (name, input, expected) in MATCHING {
        assert_eq!(&run(name, input), expected, "tamper {name}({input:?})");
    }
}

#[test]
fn intentional_divergences_are_pinned() {
    for (name, input, ours, _reason) in DIVERGENT {
        assert_eq!(&run(name, input), ours, "tamper {name}({input:?}) behavior changed");
    }
}

#[test]
fn not_ported_scripts_stay_absent() {
    for (name, input, _upstream_expected) in NOT_PORTED {
        assert!(
            apply_all(&[name.to_string()], input, 0xC0FFEE).is_err(),
            "tamper {name} is now ported - move its case into MATCHING"
        );
    }
}
