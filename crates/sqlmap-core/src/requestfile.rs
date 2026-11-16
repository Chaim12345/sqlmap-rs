//! Raw HTTP request file parsing (port of sqlmap `-r FILE` handling in
//! `lib/core/option.py::loadRequestFile` subset): a Burp-style saved request
//! becomes target URL, method, headers, cookie and POST data.

/// A parsed request file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRequest {
    pub method: String,
    pub url: String,
    /// "Name: value" pairs, Host/Content-Length excluded (Host is in the
    /// URL; a stale Content-Length would corrupt the mutated requests).
    pub headers: Vec<String>,
    pub cookie: Option<String>,
    pub body: Option<String>,
}

/// Parse a raw HTTP request. `scheme` ("http"/"https") completes the URL
/// when the request line carries a path rather than an absolute URL.
pub fn parse_request_file(text: &str, scheme: &str) -> Result<ParsedRequest, String> {
    let normalized = text.replace("\r\n", "\n");
    let (head, body) = match normalized.split_once("\n\n") {
        Some((h, b)) => (h, b.trim_end_matches('\n')),
        None => (normalized.as_str(), ""),
    };
    let mut lines = head.lines();
    let request_line = lines.next().ok_or("empty request file")?.trim();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("missing method")?.to_ascii_uppercase();
    let path = parts.next().ok_or("missing request path")?;
    if parts.next().is_none_or(|v| !v.starts_with("HTTP/")) {
        return Err(format!("malformed request line: {request_line}"));
    }

    let mut host: Option<String> = None;
    let mut cookie: Option<String> = None;
    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            host = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("cookie") {
            cookie = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("content-length") {
            // dropped: the mutated requests recompute it
        } else {
            headers.push(format!("{name}: {value}"));
        }
    }

    let url = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        let host = host.ok_or("no Host header and no absolute URL in request line")?;
        format!("{scheme}://{host}{path}")
    };
    let body = if body.is_empty() { None } else { Some(body.to_string()) };
    Ok(ParsedRequest { method, url, headers, cookie, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_post_request() {
        let raw = "POST /login HTTP/1.1\r\nHost: 127.0.0.1:8734\r\nUser-Agent: Mozilla/5.0\r\nCookie: sid=abc123\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 17\r\n\r\nuser=admin&pass=x\r\n";
        let r = parse_request_file(raw, "http").unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.url, "http://127.0.0.1:8734/login");
        assert_eq!(r.cookie.as_deref(), Some("sid=abc123"));
        assert_eq!(r.body.as_deref(), Some("user=admin&pass=x"));
        assert!(r.headers.contains(&"User-Agent: Mozilla/5.0".to_string()));
        assert!(r.headers.contains(&"Content-Type: application/x-www-form-urlencoded".to_string()));
        assert!(!r.headers.iter().any(|h| h.starts_with("Content-Length")));
    }

    #[test]
    fn absolute_url_needs_no_host() {
        let r = parse_request_file("GET http://h/item?id=1 HTTP/1.1\n\n", "http").unwrap();
        assert_eq!(r.url, "http://h/item?id=1");
        assert_eq!(r.body, None);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_request_file("", "http").is_err());
        assert!(parse_request_file("GET /x\nHost: h\n", "http").is_err());
        assert!(parse_request_file("GET /x HTTP/1.1\n", "http").is_err()); // no Host
    }
}
