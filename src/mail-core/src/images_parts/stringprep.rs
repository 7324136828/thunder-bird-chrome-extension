//! RFC 3491 `nameprep` exactly as Python's `encodings.idna.nameprep`
//! applies it (RFC 3454 tables B.1, B.2, C.1.2-C.9, D.1, D.2): map, NFKC,
//! prohibit, check bidi.
//!
//! The tables that depend on Unicode 3.2 data (B.2 case folding, the `Zs` and
//! `Co` categories, the bidirectional classes) are generated from Python's
//! `stringprep` module into `stringprep_tables.rs`. NFKC uses the current
//! Unicode data except that code points unassigned in Unicode 3.2 pass
//! through unchanged (as starters), like `unicodedata.ucd_3_2_0.normalize`.

use unicode_normalization::UnicodeNormalization;

#[path = "stringprep_tables.rs"]
mod tables;

use tables::{B1, B2_EXCEPTIONS, C12, C3, D1, D2, UNASSIGNED};

/// A `UnicodeError` raised by `nameprep` (prohibited code point or a bidi
/// violation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NameprepError;

fn in_ranges(ranges: &[(u32, u32)], c: char) -> bool {
    let c = c as u32;
    ranges
        .binary_search_by(|(start, end)| {
            if *end < c {
                std::cmp::Ordering::Less
            } else if *start > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// `stringprep.map_table_b2(c)` (B.2 case folding for NFKC).
fn map_b2(c: char, out: &mut String) {
    match B2_EXCEPTIONS.binary_search_by_key(&(c as u32), |(code, _)| *code) {
        Ok(index) => out.push_str(B2_EXCEPTIONS[index].1),
        Err(_) => out.extend(c.to_lowercase()),
    }
}

/// `unicodedata.ucd_3_2_0.normalize("NFKC", text)`: code points that were
/// unassigned in Unicode 3.2 have no decomposition and block composition.
fn nfkc_3_2(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut segment = String::new();
    for c in text.chars() {
        if in_ranges(UNASSIGNED, c) {
            out.extend(segment.nfkc());
            segment.clear();
            out.push(c);
        } else {
            segment.push(c);
        }
    }
    out.extend(segment.nfkc());
    out
}

/// Tables C.1.2, C.2.2, C.3, C.4, C.5, C.6, C.7, C.8 and C.9.
fn prohibited(c: char) -> bool {
    let code = c as u32;
    in_ranges(C12, c)
        // C.2.2: non-ASCII controls and the listed specials.
        || (0x80..=0x9F).contains(&code)
        || matches!(
            code,
            0x06DD
                | 0x070F
                | 0x180E
                | 0x200C
                | 0x200D
                | 0x2028
                | 0x2029
                | 0x2060..=0x2063
                | 0x206A..=0x206F
                | 0xFEFF
                | 0xFFF9..=0xFFFC
                | 0x1D173..=0x1D17A
        )
        || in_ranges(C3, c)
        // C.4: non-character code points.
        || (0xFDD0..0xFDF0).contains(&code)
        || matches!(code & 0xFFFF, 0xFFFE | 0xFFFF)
        // C.6, C.7, C.8, C.9.
        || (0xFFF9..=0xFFFD).contains(&code)
        || (0x2FF0..=0x2FFB).contains(&code)
        || matches!(code, 0x0340 | 0x0341 | 0x200E | 0x200F | 0x202A..=0x202E)
        || code == 0xE0001
        || (0xE0020..=0xE007F).contains(&code)
}

/// `encodings.idna.nameprep(label)`.
pub(crate) fn nameprep(label: &str) -> Result<String, NameprepError> {
    // Map: B.1 to nothing, B.2 case folding.
    let mut mapped = String::with_capacity(label.len());
    for c in label.chars() {
        if B1.binary_search(&(c as u32)).is_ok() {
            continue;
        }
        map_b2(c, &mut mapped);
    }
    // Normalize.
    let label = nfkc_3_2(&mapped);
    // Prohibit.
    if label.chars().any(prohibited) {
        return Err(NameprepError);
    }
    // Check bidi (RFC 3454 section 6).
    let rand_al: Vec<bool> = label.chars().map(|c| in_ranges(D1, c)).collect();
    if rand_al.iter().any(|value| *value) {
        if label.chars().any(|c| in_ranges(D2, c)) {
            return Err(NameprepError);
        }
        if !rand_al.first().copied().unwrap_or(false) || !rand_al.last().copied().unwrap_or(false) {
            return Err(NameprepError);
        }
    }
    Ok(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_matches_python_nameprep() {
        assert_eq!(nameprep("Stra\u{df}e").unwrap(), "strasse");
        assert_eq!(nameprep("\u{3c2}").unwrap(), "\u{3c3}");
        assert_eq!(nameprep("\u{2102}af\u{e9}").unwrap(), "caf\u{e9}");
        assert_eq!(nameprep("a\u{ad}b\u{200b}c").unwrap(), "abc");
        assert_eq!(nameprep("\u{ff21}").unwrap(), "a");
        assert_eq!(nameprep("\u{1f80}").unwrap(), "\u{1f00}\u{3b9}");
        // Unassigned in Unicode 3.2: no compatibility decomposition.
        assert_eq!(nameprep("\u{213b}").unwrap(), "\u{213b}");
        assert_eq!(nameprep("\u{558}").unwrap(), "\u{558}");
    }

    #[test]
    fn prohibited_and_bidi_violations_fail() {
        // NFKC turns these spaces into U+0020, which C.1.2 does not prohibit.
        assert_eq!(nameprep("a\u{a0}b").unwrap(), "a b");
        assert_eq!(nameprep("a\u{3000}b").unwrap(), "a b");
        for label in [
            "a\u{1680}b",
            "a\u{e000}",
            "a\u{200e}",
            "a\u{2ff0}",
            "a\u{e0041}",
            "a\u{fffd}",
            "a\u{2028}",
            "\u{5d0}a\u{5d1}",
            "a\u{5d0}",
            "\u{5d0}1",
        ] {
            assert_eq!(nameprep(label), Err(NameprepError), "{label:?}");
        }
        assert_eq!(nameprep("\u{5d0}\u{5d1}").unwrap(), "\u{5d0}\u{5d1}");
        assert_eq!(nameprep("\u{5d0}1\u{5d1}").unwrap(), "\u{5d0}1\u{5d1}");
    }
}
