//! Parameter extraction and mutation for GET/POST/Cookie places.
//! Port of the parameter handling half of sqlmap `lib/core/target.py`.

use sqlmap_core::config::Place;

/// One testable parameter pulled from the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub place: Place,
    pub name: String,
    pub value: String,
}

/// Parse "a=1&b=2" style strings (query string, POST body, or cookie header
/// with ';' separators handled by the caller splitting first).
pub fn parse_pairs(s: &str, sep: char) -> Vec<(String, String)> {
    s.split(sep)
        .filter_map(|kv| {
            let kv = kv.trim();
            if kv.is_empty() {
                return None;
            }
            let mut it = kv.splitn(2, '=');
            let k = it.next()?.trim().to_string();
            let v = it.next().unwrap_or("").trim().to_string();
            if k.is_empty() {
                None
            } else {
                Some((k, v))
            }
        })
        .collect()
}

/// Split URL into (base, query pairs).
pub fn split_url(url: &str) -> (String, Vec<(String, String)>) {
    match url.split_once('?') {
        Some((base, query)) => (base.to_string(), parse_pairs(query, '&')),
        None => (url.to_string(), Vec::new()),
    }
}

/// Rebuild "a=1&b=2", percent-encoding values (sqlmap keeps most chars but
/// encodes the payload's specials; we encode conservatively).
pub fn build_pairs(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Rebuild cookie header ("; " separators, no encoding of name).
pub fn build_cookies(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Minimal percent-encoding for injection payloads: keep alphanumerics and the
/// SQL-significant characters readable, encode space as %20 handled by caller
/// choice. sqlmap defaults keep quotes/operators raw in most cases.
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => out.push(b as char),
            // sqlmap leaves these raw in payloads: ' " ( ) , . - ; < > = whitespace handled by caller
            b'\'' | b'"' | b'(' | b')' | b',' | b'.' | b'-' | b';' | b'<' | b'>' | b'=' | b' '
            | b'*' | b'/' | b'%' | b'!' | b'_' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// All candidate params for a request, in sqlmap's GET, POST, Cookie order
/// (level gates UA/Referer/header places; the caller filters).
pub fn extract_params(url: &str, data: Option<&str>, cookie: Option<&str>) -> Vec<Param> {
    let mut out = Vec::new();
    let (_, query) = split_url(url);
    for (name, value) in query {
        out.push(Param { place: Place::Get, name, value });
    }
    if let Some(d) = data {
        for (name, value) in parse_pairs(d, '&') {
            out.push(Param { place: Place::Post, name, value });
        }
    }
    if let Some(c) = cookie {
        for (name, value) in parse_pairs(c, ';') {
            out.push(Param { place: Place::Cookie, name, value });
        }
    }
    out
}

/// Apply `new_value` to param `name` within the given place's raw string.
/// Returns the rebuilt string for that place.
pub fn mutate(place: Place, raw: &str, name: &str, new_value: &str) -> String {
    let sep = match place {
        Place::Cookie => ';',
        _ => '&',
    };
    let pairs: Vec<(String, String)> = parse_pairs(raw, sep)
        .into_iter()
        .map(|(k, v)| {
            if k == name {
                (k, new_value.to_string())
            } else {
                (k, v)
            }
        })
        .collect();
    match place {
        Place::Cookie => build_cookies(&pairs),
        _ => build_pairs(&pairs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_rebuild_roundtrip() {
        let (base, pairs) = split_url("http://t/get?id=1&cat=2");
        assert_eq!(base, "http://t/get");
        assert_eq!(pairs, vec![("id".into(), "1".into()), ("cat".into(), "2".into())]);
        assert_eq!(build_pairs(&pairs), "id=1&cat=2");
    }

    #[test]
    fn extract_all_places() {
        let p = extract_params("http://t/g?id=1", Some("q=x"), Some("sid=abc; lang=en"));
        assert_eq!(p.len(), 4);
        assert_eq!(p[0].place, Place::Get);
        assert_eq!(p[1].place, Place::Post);
        assert_eq!(p[2].place, Place::Cookie);
        assert_eq!(p[2].name, "sid");
        assert_eq!(p[2].value, "abc");
        assert_eq!(p[3].name, "lang");
    }

    #[test]
    fn mutate_get_value() {
        assert_eq!(mutate(Place::Get, "id=1&cat=2", "id", "1 AND 1=1"), "id=1 AND 1=1&cat=2");
    }

    #[test]
    fn mutate_cookie_value() {
        assert_eq!(mutate(Place::Cookie, "sid=abc;lang=en", "sid", "x'"), "sid=x'; lang=en");
    }

    #[test]
    fn encode_keeps_sql_chars() {
        assert_eq!(encode("1' AND '1'='1"), "1' AND '1'='1");
        assert_eq!(encode("a#b"), "a%23b");
    }
}
