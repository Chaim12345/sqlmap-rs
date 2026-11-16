//! Compatibility pins from the original Python sqlmap test suite
//! (tests/test_payloads_structure.py, upstream pinned at
//! sqlmapproject/sqlmap 8b78b676c1376ae28feccd957b03bbecea05eff1).
//! Upstream asserts structural invariants over its payloads.xml/boundaries.xml;
//! the adaptation asserts the same invariants over our Rust payload sets.
//! Upstream's floors (>=200 payloads, >=30 boundaries) are NOT claimed: this
//! is a level 1-2 subset port, so the current counts are pinned instead -
//! a shrunken set fails loudly, and reaching upstream's floors is open work.

use sqlmap_payloads as pl;

fn all_payloads() -> Vec<&'static pl::Payload> {
    // Leak the Vecs to get 'static references for convenient iteration;
    // test-only and tiny.
    let sets: [&'static [pl::Payload]; 5] = [
        Box::leak(Box::new(pl::boolean_payloads())),
        Box::leak(Box::new(pl::error_payloads())),
        Box::leak(Box::new(pl::time_payloads())),
        Box::leak(Box::new(pl::stacked_payloads())),
        Box::leak(Box::new(pl::inline_payloads())),
    ];
    sets.into_iter().flat_map(|s| s.iter()).collect()
}

#[test]
fn titles_unique_and_non_empty() {
    let payloads = all_payloads();
    let mut titles: Vec<&str> = payloads.iter().map(|p| p.title).collect();
    assert!(titles.iter().all(|t| !t.trim().is_empty()), "empty payload title");
    let n = titles.len();
    titles.sort();
    titles.dedup();
    assert_eq!(n, titles.len(), "duplicate payload titles exist");
}

#[test]
fn level_and_risk_in_range() {
    for p in all_payloads() {
        assert!((1..=5).contains(&p.level), "{}: bad level {}", p.title, p.level);
        assert!((1..=3).contains(&p.risk), "{}: bad risk {}", p.title, p.risk);
    }
}

#[test]
fn payloads_render_clean() {
    // Every template must render without leftover markers (upstream's
    // cleanupPayload contract applied structurally).
    for p in all_payloads() {
        let templates: Vec<&str> = match p.check {
            pl::Check::Boolean { true_q, false_q } => vec![true_q, false_q],
            pl::Check::Error { q } | pl::Check::Time { q } => vec![q],
        };
        for t in templates {
            assert!(!t.trim().is_empty(), "{}: empty payload", p.title);
            let rendered = pl::render(t, 5, 1234, 5678, "abcdef");
            assert!(!rendered.contains("[SLEEPTIME]"), "{}: leftover marker", p.title);
            assert!(!rendered.contains("[RANDNUM]"), "{}: leftover marker", p.title);
            assert!(!rendered.contains("[RANDNUM1]"), "{}: leftover marker", p.title);
            assert!(!rendered.contains("[RANDSTR]"), "{}: leftover marker", p.title);
        }
    }
}

#[test]
fn boundaries_well_formed() {
    let boundaries = pl::boundaries();
    // Upstream asserts boundary level ranges; our Boundary struct carries no
    // level field (level gating lives on payloads), so there is nothing to pin.
    // Upstream suffixes either complete a quoted expression or comment out the
    // remainder - both shapes exist in our ported set, so no stricter
    // invariant is claimed here.
    for b in &boundaries {
        assert!(b.r#where >= 1, "boundary {:?}: bad where", b.prefix);
    }
}

#[test]
fn subset_port_counts_are_pinned() {
    // Upstream floors are >=200 payloads and >=30 boundaries. This port
    // carries the level 1-2 subset; pin the current counts so silent
    // shrinkage fails and growth is visible.
    assert_eq!(all_payloads().len(), 22, "payload count changed");
    assert_eq!(pl::boundaries().len(), 8, "boundary count changed");
}
