use super::detectors::build_compiled_patterns;
use super::validators::{is_luhn_valid_card_number, is_valid_ssn_fragments, shannon_entropy_ascii};
use super::*;

#[test]
fn built_in_detectors_compile_to_full_set() {
    let patterns = build_compiled_patterns().unwrap();
    assert_eq!(patterns.len(), 16);
    for id in ["pii_ssn", "pii_credit_card", "pii_email", "pii_mrn"] {
        assert!(patterns.iter().any(|pattern| pattern.id == id), "{id}");
    }
}

#[test]
fn redacts_medical_record_number() {
    let sanitizer = OutputSanitizer::new();
    for input in ["MRN: 123456789", "mrn #0012345", "Patient MRN 987654321012"] {
        let result = sanitizer.sanitize_text(input);
        assert!(result.was_redacted, "{input}");
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.id == "pii_mrn"),
            "{input}"
        );
        let digits: String = input.chars().filter(char::is_ascii_digit).collect();
        assert!(!result.sanitized.contains(&digits), "{input}");
    }
}

#[test]
fn medical_record_number_requires_marker_and_digit_count() {
    let sanitizer = OutputSanitizer::new();
    for input in ["MRN 12345", "SMRN 1234567", "MRN 1234567890123"] {
        let result = sanitizer.sanitize_text(input);
        assert!(
            !result
                .findings
                .iter()
                .any(|finding| finding.id == "pii_mrn"),
            "{input}"
        );
    }
}

// ---- OutputSanitizer unit tests ----

#[test]
fn luhn_rejects_random_16_digit_number() {
    assert!(!is_luhn_valid_card_number("1234567890123456"));
    // Known-valid test card (Visa).
    assert!(is_luhn_valid_card_number("4111 1111 1111 1111"));
    // One digit flipped: no longer valid.
    assert!(!is_luhn_valid_card_number("4111 1111 1111 1112"));
}

#[test]
fn output_sanitizer_clone_preserves_token_vault() {
    let mut config = OutputSanitizerConfig::default();
    config
        .redaction_strategies
        .insert(SensitiveCategory::Pii, RedactionStrategy::Tokenize);
    let sanitizer = OutputSanitizer::with_config(config).unwrap();
    let cloned = sanitizer.clone();

    let result = cloned.sanitize_text("Contact john@example.com for access");
    let token = result
        .redactions
        .iter()
        .find_map(|redaction| {
            redaction
                .replacement
                .strip_prefix("[TOKEN:")
                .and_then(|value| value.strip_suffix(']'))
        })
        .unwrap();

    assert_eq!(
        sanitizer.token_vault().get(token).as_deref(),
        Some("john@example.com")
    );
}

#[test]
fn shannon_entropy_basic() {
    let e = shannon_entropy_ascii("aaaaaa").unwrap();
    assert!(e < 0.01);
    let e2 = shannon_entropy_ascii("abcdefghij0123456789").unwrap();
    assert!(e2 > 4.0);
}

#[test]
fn ssn_fragments_validator_rejects_invalid_areas() {
    assert!(!is_valid_ssn_fragments("000-12-3456"));
    assert!(!is_valid_ssn_fragments("666-12-3456"));
    assert!(!is_valid_ssn_fragments("900-12-3456"));
    assert!(!is_valid_ssn_fragments("123-00-4567"));
    assert!(!is_valid_ssn_fragments("123-45-0000"));
    assert!(is_valid_ssn_fragments("123-45-6789"));
}
