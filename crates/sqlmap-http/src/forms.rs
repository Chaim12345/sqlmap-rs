//! HTML form discovery (port of sqlmap `--forms` handling in
//! `lib/core/target.py`: parse the page's forms and turn each into a
//! testable request). Regex-based, like the rest of the port - no HTML
//! parser dependency.

use std::sync::LazyLock;

/// One parsed form, ready to be turned into a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form {
    /// Absolute URL the form submits to.
    pub action: String,
    /// GET or POST (anything else is treated as GET, like browsers do).
    pub method: String,
    /// (name, value) pairs from input fields; empty values get "1" (sqlmap
    /// fills empty fields with a default so they are testable).
    pub inputs: Vec<(String, String)>,
}

static FORM_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?is)<form\b([^>]*)>(.*?)</form\s*>").unwrap());
static INPUT_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?is)<input\b([^>]*)/?\s*>").unwrap());
static ATTR_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"(?is)(\w[\w-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap());

fn attr<'a>(attrs: &'a str, name: &str) -> Option<String> {
    for cap in ATTR_RE.captures_iter(attrs) {
        if cap[1].eq_ignore_ascii_case(name) {
            return Some(
                cap.get(2)
                    .or_else(|| cap.get(3))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default(),
            );
        }
    }
    None
}

/// Resolve a form action against the page URL (absolute kept, `/path` joined
/// to the origin, empty means the page itself, relative joined to the dir).
pub fn resolve_url(page_url: &str, action: &str) -> String {
    if action.starts_with("http://") || action.starts_with("https://") {
        return action.to_string();
    }
    // scheme://host prefix of the page URL
    let origin_end = page_url
        .find("://")
        .and_then(|i| page_url[i + 3..].find('/').map(|j| i + 3 + j))
        .unwrap_or(page_url.len());
    let origin = &page_url[..origin_end];
    if action.is_empty() {
        return page_url.split('#').next().unwrap_or(page_url).to_string();
    }
    if let Some(rest) = action.strip_prefix('/') {
        return format!("{origin}/{rest}");
    }
    // relative: join to the page's directory
    let dir = page_url[..page_url.rfind('/').map(|i| i + 1).unwrap_or(page_url.len())].to_string();
    format!("{dir}{action}")
}

/// Parse all forms in `html`, resolved against `page_url`.
pub fn parse_forms(html: &str, page_url: &str) -> Vec<Form> {
    let mut out = Vec::new();
    for cap in FORM_RE.captures_iter(html) {
        let attrs = &cap[1];
        let body = &cap[2];
        let action = resolve_url(page_url, &attr(attrs, "action").unwrap_or_default());
        let method = attr(attrs, "method")
            .map(|m| m.to_ascii_uppercase())
            .filter(|m| m == "POST")
            .unwrap_or_else(|| "GET".into());
        let mut inputs = Vec::new();
        for icap in INPUT_RE.captures_iter(body) {
            let iattrs = &icap[1];
            let itype = attr(iattrs, "type").unwrap_or_else(|| "text".into());
            // Browsers submit text/hidden/password/search/(unset); skip buttons.
            if matches!(itype.to_ascii_lowercase().as_str(), "submit" | "button" | "image" | "reset" | "file" | "checkbox" | "radio") {
                continue;
            }
            let Some(name) = attr(iattrs, "name") else { continue };
            if name.is_empty() {
                continue;
            }
            let value = attr(iattrs, "value").filter(|v| !v.is_empty()).unwrap_or_else(|| "1".into());
            inputs.push((name, value));
        }
        if !inputs.is_empty() {
            out.push(Form { action, method, inputs });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get_and_post_forms() {
        let html = r#"<html><body>
            <form action="/item" method="get">
              <input type="text" name="name" value="widget">
            </form>
            <form action="/login" method="POST">
              <input type="text" name="user" value="admin">
              <input type="password" name="pass">
              <input type="submit" value="Go">
            </form>
        </body></html>"#;
        let forms = parse_forms(html, "http://t/search");
        assert_eq!(forms.len(), 2);
        assert_eq!(forms[0].action, "http://t/item");
        assert_eq!(forms[0].method, "GET");
        assert_eq!(forms[0].inputs, vec![("name".to_string(), "widget".to_string())]);
        assert_eq!(forms[1].method, "POST");
        assert_eq!(forms[1].inputs[1], ("pass".to_string(), "1".to_string()));
    }

    #[test]
    fn resolves_actions() {
        assert_eq!(resolve_url("http://t/a/b", "/x"), "http://t/x");
        assert_eq!(resolve_url("http://t/a/b", "c"), "http://t/a/c");
        assert_eq!(resolve_url("http://t/a/b", ""), "http://t/a/b");
        assert_eq!(resolve_url("http://t/a", "http://o/z"), "http://o/z");
    }

    #[test]
    fn skips_formless_pages() {
        assert!(parse_forms("<html>hi</html>", "http://t/").is_empty());
    }
}
