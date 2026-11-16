//! Compatibility pins from the original Python sqlmap test suite
//! (tests/test_crawler.py, upstream pinned at
//! sqlmapproject/sqlmap 8b78b676c1376ae28feccd957b03bbecea05eff1).
//! Upstream's cases drive its crawler dedup in process; the adaptation calls
//! our dedup_targets with the same URLs and asserts the same kept sets.
//! Upstream's POST-body folding case is adapted to a note: our crawler is
//! GET-only, so there is no body to fold (recorded in the compat doc).

use sqlmap_http::crawl::{dedup_targets, CrawledPage};

fn pages(urls: &[&str]) -> Vec<CrawledPage> {
    urls.iter().map(|u| CrawledPage { url: u.to_string(), depth: 1 }).collect()
}

fn kept(urls: &[&str]) -> Vec<String> {
    dedup_targets(pages(urls)).into_iter().map(|p| p.url).collect()
}

#[test]
fn value_only_variants_collapse() {
    assert_eq!(
        kept(&["http://h/item?id=1", "http://h/item?id=2", "http://h/item?id=3"]),
        vec!["http://h/item?id=1".to_string()]
    );
}

#[test]
fn distinct_endpoints_sharing_action_are_kept() {
    let got: std::collections::HashSet<String> = kept(&[
        "http://h/users/edit?id=1",
        "http://h/products/edit?id=1",
        "http://h/orders/edit?id=1",
        "http://h/users/edit?id=2",
    ])
    .into_iter()
    .collect();
    let want: std::collections::HashSet<String> = [
        "http://h/users/edit?id=1",
        "http://h/products/edit?id=1",
        "http://h/orders/edit?id=1",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(got, want);
}

#[test]
fn different_parameter_names_are_kept() {
    assert_eq!(kept(&["http://h/p?id=1", "http://h/p?name=x"]).len(), 2);
}

#[test]
fn different_hosts_are_kept() {
    assert_eq!(kept(&["http://a.tld/edit?id=1", "http://b.tld/edit?id=1"]).len(), 2);
}
