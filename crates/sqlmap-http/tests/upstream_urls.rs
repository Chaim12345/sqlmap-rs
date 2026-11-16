//! Compatibility pins from the original Python sqlmap test suite
//! (tests/test_urls.py, upstream pinned at
//! sqlmapproject/sqlmap 8b78b676c1376ae28feccd957b03bbecea05eff1).
//! checkSameHost and paramToDict cases adapt directly; upstream's generic
//! urlencode(safe="") full-encoding contract is pinned as a divergence:
//! our transport encoding deliberately leaves SQL payload characters raw,
//! as sqlmap's own payload transport does.

use sqlmap_http::crawl::same_host;
use sqlmap_http::params::{encode, parse_pairs};

#[test]
fn same_host_matches_upstream_cases() {
    // tests/test_urls.py TestSameHost
    assert!(same_host("http://h/a", "http://h/b"));
    assert!(same_host("http://h:80/a", "http://h:80/b"));
    // documented upstream behavior: a leading www. is normalized away
    assert!(same_host("http://example.com/a", "http://www.example.com/b"));
    assert!(!same_host("http://h/a", "http://other/b"));
    assert!(!same_host("http://example.com/a", "http://evil.com/b"));
    // upstream compares hostnames only: ports do not participate
    assert!(same_host("http://h:8080/a", "http://h:80/b"));
}

#[test]
fn param_to_dict_cases() {
    // tests/test_urls.py TestParamToDict (PLACE.GET)
    let d = parse_pairs("a=1&b=2&c=3", '&');
    let get = |k: &str| d.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    assert_eq!(get("a"), Some("1"));
    assert_eq!(get("b"), Some("2"));
    assert_eq!(get("c"), Some("3"));
    let single = parse_pairs("id=42", '&');
    assert_eq!(single[0], ("id".to_string(), "42".to_string()));
}

#[test]
fn encoding_divergence_is_pinned() {
    // Upstream: urlencode("a b&c=d", safe="") == "a%20b%26c%3Dd" (generic
    // full encoding). Our params::encode is the payload-transport encoding
    // (sqlmap leaves SQL characters raw on the wire), so the same input
    // encodes differently on purpose.
    assert_eq!(encode("a b&c=d"), "a b%26c=d");
}
