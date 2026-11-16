//! Same-host crawler (port of the crawling half of sqlmap
//! `lib/utils/crawler.py`): breadth-first walk from a start URL up to a
//! configurable depth, collecting candidate pages to test. Stays on the
//! start URL's scheme://authority, GETs pages only, and skips static
//! resources a scanner would never test.

use crate::client::{Client, RequestSpec};
use crate::forms::resolve_url;
use crate::pool;
use std::collections::HashSet;
use std::sync::LazyLock;

static HREF_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?is)<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#).unwrap()
});

/// Static-resource extensions: collected by crawlers, never test targets.
const SKIP_EXTS: &[&str] = &[
    ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
    ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3", ".webp",
];

/// A page the crawler fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawledPage {
    pub url: String,
    /// Depth the page was found at (0 = the start URL itself).
    pub depth: u8,
}

/// scheme://authority of a URL - the boundary the crawl never crosses
/// (sqlmap's crawler is likewise restricted to the target host).
/// Port of sqlmap's checkSameHost (lib/core/common.py) for upstream-suite
/// compatibility ONLY: hostnames compare equal after stripping a leading
/// "www." (case-insensitive); scheme and port do not participate.
///
/// This is NOT a crawl-scope or authorization decision. The crawler stays
/// on the exact start origin (scheme://host:port) via origin() below;
/// do not use this helper to decide which URLs may be fetched.
pub fn same_host(a: &str, b: &str) -> bool {
    fn host(url: &str) -> String {
        let rest = match url.find("://") {
            Some(i) => &url[i + 3..],
            None => url,
        };
        let host = rest.split(['/', ':', '?']).next().unwrap_or(rest);
        host.strip_prefix("www.").unwrap_or(host).to_ascii_lowercase()
    }
    !a.is_empty() && !b.is_empty() && host(a) == host(b)
}

pub(crate) fn origin(url: &str) -> &str {
    match url.find("://") {
        Some(i) => {
            let rest = &url[i + 3..];
            let end = rest.find('/').map(|j| i + 3 + j).unwrap_or(url.len());
            &url[..end]
        }
        None => url,
    }
}

/// True for URLs whose path ends in a static-resource extension.
fn is_static_resource(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let lower = path.to_ascii_lowercase();
    SKIP_EXTS.iter().any(|e| lower.ends_with(e))
}

/// True when `raw` carries an explicit scheme that is not http(s)
/// (javascript:, mailto:, tel:, ...). A scheme starts with a letter and
/// contains only letters, digits, '+', '-' or '.'; a ':' appearing after a
/// '/' is part of the path, not a scheme.
fn has_non_http_scheme(raw: &str) -> bool {
    let Some(i) = raw.find(':') else { return false };
    let scheme = &raw[..i];
    let looks_like_scheme = scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    looks_like_scheme
        && !scheme.eq_ignore_ascii_case("http")
        && !scheme.eq_ignore_ascii_case("https")
}

/// Extract href targets from an HTML page, resolved to absolute http(s) URLs
/// against `page_url`. Bare fragments and non-HTTP schemes are dropped.
pub fn extract_links(html: &str, page_url: &str) -> Vec<String> {
    let mut out = Vec::new();
    for cap in HREF_RE.captures_iter(html) {
        let raw = cap
            .get(1)
            .or_else(|| cap.get(2))
            .or_else(|| cap.get(3))
            .map(|m| m.as_str().trim())
            .unwrap_or("");
        if raw.is_empty() || raw.starts_with('#') || has_non_http_scheme(raw) {
            continue;
        }
        let resolved = resolve_url(page_url, raw);
        let resolved = resolved.split('#').next().unwrap_or(&resolved).to_string();
        if resolved.starts_with("http://") || resolved.starts_with("https://") {
            out.push(resolved);
        }
    }
    out
}

/// Breadth-first crawl from `start_url`, staying on its scheme://authority,
/// following links up to `max_depth` hops. Every fetched page is returned in
/// discovery order; each URL is visited once, so link cycles terminate. Each
/// depth level's pages are fetched concurrently on `threads` workers.
pub fn crawl(client: &Client, start_url: &str, max_depth: u8, threads: usize) -> Vec<CrawledPage> {
    let start = start_url.split('#').next().unwrap_or(start_url).to_string();
    let mut seen: HashSet<String> = HashSet::from([start.clone()]);
    let home = origin(&start).to_string();
    let mut frontier: Vec<(String, u8)> = vec![(start, 0)];
    let mut pages = Vec::new();
    while !frontier.is_empty() {
        let specs: Vec<RequestSpec> = frontier
            .iter()
            .map(|(url, _)| RequestSpec {
                url: url.clone(),
                method: "GET".into(),
                body: None,
                headers: Vec::new(),
                cookie: None,
            })
            .collect();
        let results = pool::run_requests(client, specs, threads);
        let mut next = Vec::new();
        for ((url, depth), resp) in frontier.into_iter().zip(results) {
            let Ok(resp) = resp else { continue };
            if depth < max_depth {
                for link in extract_links(&resp.body, &url) {
                    if is_static_resource(&link) || origin(&link) != home {
                        continue;
                    }
                    if seen.insert(link.clone()) {
                        next.push((link, depth + 1));
                    }
                }
            }
            pages.push(CrawledPage { url, depth });
        }
        frontier = next;
    }
    dedup_targets(pages)
}

/// sqlmap crawler target dedup (tests/test_crawler.py): scan targets that
/// differ only in parameter VALUES collapse to one; distinct paths, distinct
/// parameter names and distinct hosts are all kept. (Our crawler is GET-only
/// and same-host, so upstream's POST-body folding and host cases collapse to
/// the same shape function.)
pub fn dedup_targets(pages: Vec<CrawledPage>) -> Vec<CrawledPage> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for page in pages {
        if seen.insert(shape(&page.url)) {
            out.push(page);
        }
    }
    out
}

fn shape(url: &str) -> String {
    let (base, query) = crate::params::split_url(url);
    let mut names: Vec<String> = query.into_iter().map(|(n, _)| n).collect();
    names.sort();
    names.dedup();
    format!("{}?{}", base, names.join("&"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_and_resolves_links() {
        let html = r##"<html><body>
            <a href="/abs">a</a>
            <a href="rel">b</a>
            <a href="http://other.host/x">c</a>
            <a href='single?q=1'>d</a>
            <a href=unquoted>e</a>
            <a href="#frag">f</a>
            <a href="javascript:void(0)">g</a>
            <a href="mailto:a@b.c">h</a>
            <a href="/page#section">i</a>
        </body></html>"##;
        let links = extract_links(html, "http://host/dir/page");
        assert_eq!(
            links,
            vec![
                "http://host/abs",
                "http://host/dir/rel",
                "http://other.host/x",
                "http://host/dir/single?q=1",
                "http://host/dir/unquoted",
                "http://host/page",
            ]
        );
    }

    #[test]
    fn scheme_detection() {
        assert!(has_non_http_scheme("javascript:void(0)"));
        assert!(has_non_http_scheme("mailto:a@b.c"));
        assert!(!has_non_http_scheme("http://h/x"));
        assert!(!has_non_http_scheme("https://h/x"));
        assert!(!has_non_http_scheme("/path/with:colon"));
        assert!(!has_non_http_scheme("rel/page"));
    }

    #[test]
    fn static_resources_detected() {
        assert!(is_static_resource("http://h/a/style.css"));
        assert!(is_static_resource("http://h/a/logo.PNG?x=1"));
        assert!(!is_static_resource("http://h/item?id=1"));
        assert!(!is_static_resource("http://h/search"));
    }

    #[test]
    fn origin_boundary() {
        assert_eq!(origin("http://h:8080/a/b"), "http://h:8080");
        assert_eq!(origin("https://h"), "https://h");
    }
}
