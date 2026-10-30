//! Duplicate refusal and numeric contracts at JSON entry points.

use chio_binding_helpers::{
    canonicalize_json_str, parse_capability_json, parse_signed_manifest_json,
    sign_wrapped_json_ed25519, verify_wrapped_json, ErrorCode, Result,
};

const REPEATED_KEY: &str = "urn:chio:error:attest:signed-json-invalid-input";
const SEED_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const SCHEMA_ID: &str = "chio.receipt.v1";

fn assert_refused<T: std::fmt::Debug>(result: Result<T>) {
    let error = result
        .err()
        .unwrap_or_else(|| panic!("repeated key accepted"));
    assert_eq!(error.code(), ErrorCode::UntrustedInput);
    assert_eq!(error.to_string(), REPEATED_KEY);
}

#[test]
fn json_entry_points_refuse_a_repeated_key() -> Result<()> {
    let repeated = r#"{"a":{"b":1,"b":2}}"#;

    assert_eq!(
        canonicalize_json_str(r#"{"a":{"b":1}}"#)?,
        r#"{"a":{"b":1}}"#
    );
    assert_refused(canonicalize_json_str(repeated));

    let signed = sign_wrapped_json_ed25519(SCHEMA_ID, r#"{"a":{"b":2}}"#, SEED_HEX)?;
    assert_refused(sign_wrapped_json_ed25519(SCHEMA_ID, repeated, SEED_HEX));
    verify_wrapped_json(
        SCHEMA_ID,
        r#"{"a":{"b":2}}"#,
        &signed.public_key_hex,
        &signed.signature_hex,
    )?;
    assert_refused(verify_wrapped_json(
        SCHEMA_ID,
        repeated,
        &signed.public_key_hex,
        &signed.signature_hex,
    ));

    assert_refused(parse_capability_json(r#"{"id":"cap","id":"cap"}"#));
    assert_refused(parse_signed_manifest_json(
        r#"{"manifest":{},"manifest":{}}"#,
    ));
    Ok(())
}

#[test]
fn canonical_helpers_normalize_numbers_and_signed_readers_refuse_them() -> Result<()> {
    let exponent = r#"{"a":{"b":2e0}}"#;
    let integer = r#"{"a":{"b":2}}"#;
    assert_eq!(canonicalize_json_str(exponent)?, integer);
    let normalized = sign_wrapped_json_ed25519(SCHEMA_ID, exponent, SEED_HEX)?;
    let signed = sign_wrapped_json_ed25519(SCHEMA_ID, integer, SEED_HEX)?;
    assert_eq!(normalized.canonical_json, signed.canonical_json);
    assert_eq!(normalized.signature_hex, signed.signature_hex);
    for text in [exponent, integer] {
        verify_wrapped_json(
            SCHEMA_ID,
            text,
            &signed.public_key_hex,
            &signed.signature_hex,
        )?;
    }
    assert_refused(parse_capability_json(r#"{"issued_at":1e0}"#));
    assert_refused(parse_signed_manifest_json(r#"{"version":1e0}"#));
    Ok(())
}

#[test]
fn json_entry_points_refuse_input_over_the_bound() {
    let error = canonicalize_json_str(&" ".repeat(1024 * 1024 + 1))
        .err()
        .unwrap_or_else(|| panic!("oversized input accepted"));
    assert_eq!(error.code(), ErrorCode::UntrustedInput);
    assert_eq!(
        error.to_string(),
        "urn:chio:error:attest:signed-json-too-large"
    );
}
