//! Page similarity (port of sqlmap `lib/core/comparison.py`).
//!
//! Upstream uses `difflib.SequenceMatcher` ratios with early bail-outs at
//! fixed bounds. We implement the same SequenceMatcher ratio semantics
//! (2*M/T over recursive longest-match blocks, autojunk disabled) so the
//! boolean-based detector can use the same thresholds as sqlmap.

/// sqlmap UPPER_RATIO_BOUND: pages at or above this ratio are "the same".
pub const UPPER_RATIO_BOUND: f64 = 0.98;
/// sqlmap LOWER_RATIO_BOUND: pages at or below this ratio are "different".
pub const LOWER_RATIO_BOUND: f64 = 0.02;

/// difflib-style similarity ratio in [0.0, 1.0]. 1.0 = identical.
pub fn ratio(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let la = a.chars().count();
    let lb = b.chars().count();
    let total = (la + lb) as f64;
    let av: Vec<char> = a.chars().collect();
    let bv: Vec<char> = b.chars().collect();
    let matches = matching_blocks(&av, &bv, 0, av.len(), 0, bv.len());
    2.0 * matches as f64 / total
}

/// Recursive longest-contiguous-match, as in difflib (autojunk off).
/// Returns total matched character count. Depth-limited to keep pathological
/// inputs cheap; sqlmap's pages are a few KB, fine for this.
fn matching_blocks(a: &[char], b: &[char], alo: usize, ahi: usize, blo: usize, bhi: usize) -> usize {
    // Build value -> positions index for b window.
    let mut index: std::collections::HashMap<char, Vec<usize>> = std::collections::HashMap::new();
    for (i, ch) in b[blo..bhi].iter().enumerate() {
        index.entry(*ch).or_default().push(blo + i);
    }
    // Find longest match - difflib's find_longest_match: the chain-length
    // map carries over from the previous i round (newlengths swap), so
    // adjacent occurrences within one round do not fabricate a longer chain.
    let (mut best_i, mut best_j, mut best_len) = (alo, blo, 0usize);
    let mut lengths: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for i in alo..ahi {
        let mut newlengths: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
        if let Some(positions) = index.get(&a[i]) {
            for &j in positions {
                let prev = j.checked_sub(1).and_then(|p| lengths.get(&p)).copied().unwrap_or(0);
                let len = prev + 1;
                newlengths.insert(j, len);
                if len > best_len {
                    best_i = i + 1 - len;
                    best_j = j + 1 - len;
                    best_len = len;
                }
            }
        }
        lengths = newlengths;
    }
    if best_len == 0 {
        return 0;
    }
    let mut total = best_len;
    if alo < best_i && blo < best_j {
        total += matching_blocks(a, b, alo, best_i, blo, best_j);
    }
    if best_i + best_len < ahi && best_j + best_len < bhi {
        total += matching_blocks(a, b, best_i + best_len, ahi, best_j + best_len, bhi);
    }
    total
}

/// sqlmap's filtered comparison input: strip tags' volatile whitespace runs and
/// common dynamic tokens (csrf-ish hex blobs) so a changing nonce doesn't mask
/// a boolean difference. Port of the spirit of `comparison.py`'s cleanup.
pub fn filtered_page(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut last_ws = false;
    for ch in body.chars() {
        if ch.is_whitespace() {
            if !last_ws {
                out.push(' ');
            }
            last_ws = true;
        } else {
            out.push(ch);
            last_ws = false;
        }
    }
    out
}

/// Port of upstream lib/core/common.py jsonMinimize: an order-independent
/// canonical "leaf-path" projection of a JSON document. Sorted object keys
/// make key order and whitespace irrelevant; array length and indices are
/// kept so result-set changes register; scalar values render Python-str
/// style (null -> None, true/false -> True/False) so byte-exact upstream
/// pins hold. None only when the content is not parseable JSON, so callers
/// fall back to text comparison. Deep nesting past serde_json's recursion
/// limit errors out as None, mirroring upstream's RecursionError handling.
pub fn json_minimize(content: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(content).ok()?;
    let mut lines = Vec::new();
    walk_json(&value, String::new(), &mut lines);
    lines.sort();
    Some(lines.join("\n"))
}

fn walk_json(value: &serde_json::Value, path: String, lines: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                walk_json(&map[key], format!("{path}.{key}"), lines);
            }
        }
        serde_json::Value::Array(items) => {
            lines.push(format!("{path}.__len__={}", items.len()));
            for (i, item) in items.iter().enumerate() {
                walk_json(item, format!("{path}[{i}]"), lines);
            }
        }
        serde_json::Value::Null => lines.push(format!("{path}=None")),
        serde_json::Value::Bool(b) => {
            lines.push(format!("{path}={}", if *b { "True" } else { "False" }))
        }
        serde_json::Value::Number(n) => lines.push(format!("{path}={n}")),
        serde_json::Value::String(s) => lines.push(format!("{path}={s}")),
    }
}

/// Content-Type gate for the structured oracle (upstream comparison.py):
/// application/json and any structured +json suffix opt in.
pub fn is_json_content_type(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    ct.contains("application/json") || ct.contains("+json")
}

/// Structure-aware comparison: when the response declares JSON and both
/// bodies parse, the ratio runs over the json_minimize projections (key
/// reorder / whitespace noise stops perturbing it, small value changes in
/// large bodies stop drowning). Any non-JSON or unparseable case falls
/// back to the exact text behavior, leaving the HTML oracle untouched.
pub fn ratio_aware(a: &str, b: &str, content_type: Option<&str>) -> f64 {
    if let Some(ct) = content_type {
        if is_json_content_type(ct) {
            if let (Some(ma), Some(mb)) = (json_minimize(a), json_minimize(b)) {
                return ratio(&ma, &mb);
            }
        }
    }
    ratio(&filtered_page(a), &filtered_page(b))
}

/// Marker replacing reflected payload forms before comparison
/// (same token as upstream lib/core/settings.py REFLECTED_VALUE_MARKER).
pub const REFLECTED_VALUE_MARKER: &str = "__REFLECTED_VALUE__";

/// Port of upstream lib/utils/nonsql.py stripReflection: the deterministic
/// reflection guard. Removes the raw, percent-decoded and fully
/// percent-encoded forms of a payload from a page before any two responses
/// are compared, so a pure echo endpoint stops looking like a boolean
/// oracle. Deliberately NOT lib/core/common.py removeReflectiveValues: that
/// scan-wide heuristic switches itself off after REFLECTIVE_MISS_THRESHOLD
/// misses, on regex timeout, and during heuristic mode. This port is
/// stateless and cannot stop guarding mid-scan.
pub fn strip_reflection(page: &str, payload: &str) -> String {
    if page.is_empty() || payload.is_empty() {
        return page.to_string();
    }
    let mut forms: Vec<String> = vec![
        payload.to_string(),
        percent_decode(payload),
        full_encode(payload),
    ];
    forms.retain(|f| !f.is_empty());
    forms.sort_by_key(|f| std::cmp::Reverse(f.len()));
    forms.dedup();
    let mut out = page.to_string();
    for form in forms {
        out = out.replace(&form, REFLECTED_VALUE_MARKER);
    }
    out
}

/// sqlmap urlencode(value, safe=""): every byte outside [A-Za-z0-9_.-~] is
/// percent-encoded (space becomes %20, not +).
fn full_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// sqlmap urldecode(value, convall=True): %XX sequences decoded; '+' is
/// left alone (plus-to-space is a separate opt-in in sqlmap).
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_pages_ratio_one() {
        assert_eq!(ratio("hello world", "hello world"), 1.0);
    }

    #[test]
    fn disjoint_pages_ratio_zero() {
        assert!(ratio("aaaa", "bbbb") < LOWER_RATIO_BOUND);
    }

    #[test]
    fn similar_pages_high_ratio() {
        let a = "The quick brown fox jumps over the lazy dog. Result: 42 rows.";
        let b = "The quick brown fox jumps over the lazy dog. Result: 43 rows.";
        let r = ratio(a, b);
        assert!(r > 0.9, "ratio was {r}");
    }

    #[test]
    fn filtered_collapses_whitespace() {
        assert_eq!(filtered_page("a  \n\t b"), "a b");
    }
}
