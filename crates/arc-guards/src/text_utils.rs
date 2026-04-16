//! Text canonicalization utilities shared across content-safety guards.
//!
//! These functions normalize free-form text before running regex-based signal
//! detection.  Canonicalization is deliberately conservative: the output is a
//! lowercase ASCII-biased form that preserves the general shape of the input
//! but strips common obfuscation techniques (zero-width splicing, homoglyph
//! substitution, punctuation runs, case flipping).
//!
//! This module is shared infrastructure for the
//! [`crate::prompt_injection::PromptInjectionGuard`] and the forthcoming
//! jailbreak guard.  It has no external dependencies beyond the standard
//! library and is safe to use in fail-closed guard paths.

/// The canonical-form representation of an input string.
///
/// The returned `String` has:
///
/// - all ASCII letters lowercased;
/// - common Unicode homoglyphs of Latin letters folded to their ASCII
///   counterparts (e.g. Cyrillic `а` -> `a`, full-width digits -> ASCII);
/// - zero-width and Unicode formatting characters removed;
/// - runs of two or more separator-class punctuation characters collapsed
///   to a single space.
///
/// This is NOT a security-grade Unicode normaliser.  It is a best-effort
/// heuristic that defeats the most common copy-paste prompt injection
/// tricks seen in the wild.  Callers still need to bound the input length
/// (`max_scan_bytes`) and fail-closed on internal errors.
pub fn canonicalize(input: &str) -> String {
    // First pass: strip zero-width / format characters, fold homoglyphs,
    // lowercase ASCII letters in one sweep.  We also collect a secondary
    // pass indicator: whether the previous emitted character was a
    // punctuation run that should be collapsed.
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if is_zero_width(ch) {
            continue;
        }
        let mapped = fold_homoglyph(ch);
        // Lowercase only for ASCII letters; leave folded ASCII as-is.
        if mapped.is_ascii_uppercase() {
            out.push(mapped.to_ascii_lowercase());
        } else {
            out.push(mapped);
        }
    }

    // Second pass: collapse whitespace runs and separator-punctuation runs
    // to a single space, and trim the result.
    collapse_runs(&out)
}

/// Return true if `ch` is a zero-width or Unicode formatting character
/// commonly used to obfuscate prompt content.
///
/// The set is a subset of the Unicode "formatting / joining" category plus a
/// handful of BOM/LRM/RLM codepoints; it is not exhaustive but covers the
/// characters that appear in observed injection payloads.
pub fn is_zero_width(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' // ZERO WIDTH SPACE
            | '\u{200C}' // ZWNJ
            | '\u{200D}' // ZWJ
            | '\u{200E}' // LRM
            | '\u{200F}' // RLM
            | '\u{202A}'..='\u{202E}' // LRE/RLE/PDF/LRO/RLO
            | '\u{2060}' // WORD JOINER
            | '\u{2061}'..='\u{2064}' // invisible function/plus/separator
            | '\u{FEFF}' // BOM / zero-width no-break space
            | '\u{180E}' // Mongolian vowel separator
            | '\u{034F}' // combining grapheme joiner
            | '\u{061C}' // arabic letter mark
    )
}

/// Fold a single character to its ASCII analogue when it is a commonly-used
/// homoglyph.  Returns the original character when no fold is known.
///
/// The table is intentionally small: we prioritise characters that actually
/// appear in observed prompt-injection payloads (Cyrillic letters that look
/// like Latin, full-width digits and letters, Greek alpha/omicron, etc.).
/// Expanding the table later is purely additive.
fn fold_homoglyph(ch: char) -> char {
    match ch {
        // Cyrillic -> Latin look-alikes.
        'А' => 'A',
        'а' => 'a',
        'В' => 'B',
        'С' => 'C',
        'с' => 'c',
        'Е' => 'E',
        'е' => 'e',
        'Н' => 'H',
        'К' => 'K',
        'М' => 'M',
        'О' => 'O',
        'о' => 'o',
        'Р' => 'P',
        'р' => 'p',
        'Т' => 'T',
        'Х' => 'X',
        'х' => 'x',
        'У' => 'Y',
        'у' => 'y',
        'і' => 'i',
        'І' => 'I',
        // Greek -> Latin look-alikes.
        'Α' => 'A',
        'α' => 'a',
        'Β' => 'B',
        'Ε' => 'E',
        'ε' => 'e',
        'Η' => 'H',
        'Ι' => 'I',
        'ι' => 'i',
        'Κ' => 'K',
        'Μ' => 'M',
        'Ν' => 'N',
        'Ο' => 'O',
        'ο' => 'o',
        'Ρ' => 'P',
        'Τ' => 'T',
        'Υ' => 'Y',
        'Χ' => 'X',
        // Full-width ASCII -> ASCII.
        '\u{FF01}'..='\u{FF5E}' => {
            // Full-width punctuation and Latin block maps directly via offset.
            // SAFETY: the subtraction stays inside the BMP; every codepoint
            // in the range has a valid ASCII analogue at offset 0xFEE0.
            let raw = ch as u32 - 0xFEE0;
            char::from_u32(raw).unwrap_or(ch)
        }
        // Full-width digits 0-9 handled by the FF01-FF5E range above.
        _ => ch,
    }
}

/// Collapse runs of whitespace and separator punctuation into a single space,
/// then trim leading/trailing whitespace.  This prevents attackers from
/// evading regex matchers by splicing extra punctuation into key phrases.
fn collapse_runs(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_was_break = false;
    for ch in input.chars() {
        let is_break = ch.is_whitespace() || is_separator_punct(ch);
        if is_break {
            if !prev_was_break && !out.is_empty() {
                out.push(' ');
            }
            prev_was_break = true;
        } else {
            out.push(ch);
            prev_was_break = false;
        }
    }
    let trimmed = out.trim_end().to_string();
    trimmed
}

/// ASCII-centric separator punctuation run detector.  We collapse runs of
/// these so "ignore---all---previous" normalises cleanly.  We do NOT collapse
/// single punctuation characters: only runs of two or more are affected by
/// `collapse_runs`.
///
/// Note: `:` and `/` are intentionally excluded so URL-shaped substrings
/// (`https://`) survive canonicalization and remain matchable by the
/// exfiltration-framing signal.
fn is_separator_punct(ch: char) -> bool {
    matches!(
        ch,
        '-' | '_' | '~' | '=' | '*' | '+' | '.' | ',' | ';' | '|' | '\\'
    )
}

/// Truncate `input` to at most `max_bytes` bytes while preserving UTF-8
/// boundaries.  Returns the truncated slice and a `bool` indicating whether
/// truncation happened.  Guards use this to bound scan cost without splitting
/// multi-byte characters.
pub fn truncate_at_char_boundary(input: &str, max_bytes: usize) -> (&str, bool) {
    if input.len() <= max_bytes {
        return (input, false);
    }
    // Walk backwards from max_bytes to the nearest char boundary.
    let mut end = max_bytes.min(input.len());
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    (&input[..end], true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_lowercases_ascii() {
        assert_eq!(canonicalize("IGNORE ALL"), "ignore all");
    }

    #[test]
    fn canonicalize_strips_zero_width() {
        let sneaky = "ig\u{200B}no\u{200C}re all";
        assert_eq!(canonicalize(sneaky), "ignore all");
    }

    #[test]
    fn canonicalize_folds_homoglyphs() {
        // Cyrillic U+0440 (er) -> ASCII "p"; lowercase and fold together.
        let disguised = "igno\u{0440}e";
        assert_eq!(canonicalize(disguised), "ignope");
        // Full-width ASCII folds via the 0xFEE0 offset.
        assert_eq!(canonicalize("ＩＧＮＯＲＥ"), "ignore");
    }

    #[test]
    fn canonicalize_collapses_separators() {
        assert_eq!(
            canonicalize("ignore---all___previous"),
            "ignore all previous"
        );
    }

    #[test]
    fn truncate_respects_utf8_boundary() {
        let input = "héllo"; // é is two bytes
        let (out, truncated) = truncate_at_char_boundary(input, 2);
        assert!(truncated);
        assert_eq!(out, "h");
    }

    #[test]
    fn truncate_short_input_unchanged() {
        let (out, truncated) = truncate_at_char_boundary("hi", 100);
        assert!(!truncated);
        assert_eq!(out, "hi");
    }
}
