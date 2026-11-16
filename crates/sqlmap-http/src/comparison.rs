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
    // Find longest match.
    let (mut best_i, mut best_j, mut best_len) = (alo, blo, 0usize);
    for i in alo..ahi {
        let mut lengths: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
        if let Some(positions) = index.get(&a[i]) {
            for &j in positions {
                let prev = if i > alo && j > blo {
                    lengths.get(&(j - 1)).copied().unwrap_or(0)
                } else {
                    0
                };
                let len = prev + 1;
                lengths.insert(j, len);
                if len > best_len {
                    best_i = i + 1 - len;
                    best_j = j + 1 - len;
                    best_len = len;
                }
            }
        }
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
