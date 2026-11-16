//! Tamper/evasion transformations (port of sqlmap `tamper/*.py`, subset).
//!
//! Each function mirrors one upstream tamper script's `tamper()` logic,
//! applied to the assembled payload string before it is placed into the
//! request. sqlmap applies tampers after payload/boundary assembly; so do we.

/// Tiny deterministic PRNG (xorshift64*) so tamper behavior is reproducible
/// in tests - upstream uses Python's `random` with the sample space seeded
/// per character.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

/// tamper/space2comment.py: spaces -> /**/ (and, per upstream, a few tab
/// variants). Only spaces outside of quotes? Upstream replaces all spaces.
pub fn space2comment(payload: &str) -> String {
    payload.replace(' ', "/**/")
}

/// tamper/space2plus.py: spaces -> +
pub fn space2plus(payload: &str) -> String {
    payload.replace(' ', "+")
}

/// tamper/randomcase.py: each alphabetic char randomly upper/lowered.
pub fn randomcase(payload: &str, rng: &mut Rng) -> String {
    payload
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                if rng.next() % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            } else {
                c
            }
        })
        .collect()
}

/// tamper/between.py: '>' -> 'NOT BETWEEN 0 AND', '=' -> 'BETWEEN x AND'
/// (upstream: ">" replaced by "NOT BETWEEN 0 AND #" and "=" by
/// "BETWEEN # AND #"; the # marker carries the original right operand - a
/// full-fidelity port needs token parsing, so we implement the common case:
/// comparisons of the form `a=b` and `a>b` inside the payload).
pub fn between(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 2);
    let mut chars = payload.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '>' => out.push_str(" NOT BETWEEN 0 AND "),
            '=' => out.push_str(" BETWEEN 0 AND "),
            _ => out.push(c),
        }
    }
    out
}

/// tamper/equaltolike.py: '=' -> ' LIKE '
pub fn equaltolike(payload: &str) -> String {
    payload.replace('=', " LIKE ")
}

/// tamper/charencode.py: URL-encode every character (not already encoded).
pub fn charencode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 3);
    let bytes = payload.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            out.push('%');
            out.push(bytes[i + 1] as char);
            out.push(bytes[i + 2] as char);
            i += 3;
        } else {
            out.push_str(&format!("%{:02X}", bytes[i]));
            i += 1;
        }
    }
    out
}

/// tamper/space2hash.py: space -> %23<RAND>%0A (MySQL # comment + newline,
/// which MySQL treats as whitespace after URL decoding).
pub fn space2hash(payload: &str, rng: &mut Rng) -> String {
    let mut out = String::with_capacity(payload.len() * 2);
    for c in payload.chars() {
        if c == ' ' {
            let n = (rng.next() % 9000 + 1000) as u32;
            out.push_str(&format!("%23{n}%0A"));
        } else {
            out.push(c);
        }
    }
    out
}

/// tamper/apostrophemask.py: ' -> its UTF-8 fullwidth equivalent %EF%BC%87.
pub fn apostrophemask(payload: &str) -> String {
    payload.replace('\'', "%EF%BC%87")
}

/// tamper/chardoubleencode.py: double URL-encode every character.
pub fn chardoubleencode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 5);
    for b in payload.bytes() {
        out.push_str(&format!("%25{:02X}", b));
    }
    out
}

/// tamper/halfversionedmorekeywords.py (MySQL-specific): wrap each SQL keyword
/// in its versioned comment form /*!0<KEYWORD>, e.g. AND -> /*!0AND.
pub fn halfversionedmorekeywords(payload: &str) -> String {
    const KEYWORDS: [&str; 8] = ["AND", "OR", "SELECT", "WHERE", "UNION", "ORDER", "BY", "SLEEP"];
    let mut out = payload.to_string();
    for kw in KEYWORDS {
        // Case-insensitive word-boundary replacement, preserving nothing else.
        let mut res = String::with_capacity(out.len());
        let upper = out.to_ascii_uppercase();
        let bytes = upper.as_bytes();
        let kbytes = kw.as_bytes();
        let mut i = 0;
        let src: Vec<char> = out.chars().collect();
        while i < bytes.len() {
            let at_word_start = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            if at_word_start
                && bytes[i..].starts_with(kbytes)
                && (i + kbytes.len() >= bytes.len() || !bytes[i + kbytes.len()].is_ascii_alphanumeric())
            {
                res.push_str(&format!("/*!0{}", &src[i..i + kbytes.len()].iter().collect::<String>()));
                i += kbytes.len();
            } else {
                res.push(src[i]);
                i += 1;
            }
        }
        out = res;
    }
    out
}

/// Names understood by the engine (sqlmap --tamper values).
pub const AVAILABLE: [&str; 10] = [
    "space2comment",
    "space2plus",
    "space2hash",
    "randomcase",
    "between",
    "equaltolike",
    "charencode",
    "chardoubleencode",
    "apostrophemask",
    "halfversionedmorekeywords",
];

/// Apply named tampers in order (sqlmap applies them in the order given).
pub fn apply_all(names: &[String], payload: &str, seed: u64) -> Result<String, String> {
    let mut out = payload.to_string();
    let mut rng = Rng::new(seed);
    for name in names {
        out = match name.as_str() {
            "space2comment" => space2comment(&out),
            "space2plus" => space2plus(&out),
            "randomcase" => randomcase(&out, &mut rng),
            "between" => between(&out),
            "equaltolike" => equaltolike(&out),
            "charencode" => charencode(&out),
            "space2hash" => space2hash(&out, &mut rng),
            "chardoubleencode" => chardoubleencode(&out),
            "apostrophemask" => apostrophemask(&out),
            "halfversionedmorekeywords" => halfversionedmorekeywords(&out),
            other => return Err(format!("unknown tamper script: {other} (available: {AVAILABLE:?})")),
        };
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space2comment_replaces() {
        assert_eq!(space2comment("1 AND 1=1"), "1/**/AND/**/1=1");
    }

    #[test]
    fn equaltolike_replaces() {
        assert_eq!(equaltolike("1 AND 1=1"), "1 AND 1 LIKE 1");
    }

    #[test]
    fn charencode_encodes_all() {
        assert_eq!(charencode("A=1"), "%41%3D%31");
        assert_eq!(charencode("%41"), "%41");
    }

    #[test]
    fn randomcase_is_deterministic_per_seed() {
        let a = randomcase("AND SELECT", &mut Rng::new(42));
        let b = randomcase("AND SELECT", &mut Rng::new(42));
        assert_eq!(a, b);
        assert_eq!(a.len(), "AND SELECT".len());
    }

    #[test]
    fn between_swaps_operators() {
        assert_eq!(between("1=1"), "1 BETWEEN 0 AND 1");
    }

    #[test]
    fn space2hash_shape() {
        let out = space2hash("1 AND 1=1", &mut Rng::new(7));
        assert!(out.starts_with("1%23"));
        assert!(out.contains("%0AAND%23"));
    }

    #[test]
    fn apostrophemask_replaces() {
        assert_eq!(apostrophemask("a'b"), "a%EF%BC%87b");
    }

    #[test]
    fn chardoubleencode_double_encodes() {
        assert_eq!(chardoubleencode("A="), "%2541%253D");
    }

    #[test]
    fn halfversioned_wraps_keywords_only() {
        assert_eq!(halfversionedmorekeywords("1 AND 1=1"), "1 /*!0AND 1=1");
        assert_eq!(halfversionedmorekeywords("CANDY"), "CANDY");
    }

    #[test]
    fn unknown_tamper_errors() {
        assert!(apply_all(&["nope".to_string()], "x", 1).is_err());
    }
}
