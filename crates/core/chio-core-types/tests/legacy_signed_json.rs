use chio_core_types::canonical::{canonical_json_bytes, parse_legacy_signed_json};
use chio_core_types::Error;

#[test]
fn both_existing_writers_preserve_signed_values() -> Result<(), Box<dyn std::error::Error>> {
    let value = serde_json::json!({
        "unsigned": u64::MAX,
        "signed": i64::MIN,
        "floats": [1.0, -0.0, 1e30, 5e-324, 0.12345678901234568],
        "escaped": "\\\" 0.123456789012345678901 \\\\ \"",
        "nested": [null, {"𐀀": true, "\u{e000}": false}],
    });
    let canonical = canonical_json_bytes(&value)?;
    for bytes in [
        serde_json::to_vec(&value)?,
        serde_json::to_vec_pretty(&value)?,
        canonical.clone(),
    ] {
        let parsed = parse_legacy_signed_json(std::str::from_utf8(&bytes)?)?;
        assert_eq!(canonical_json_bytes(&parsed)?, canonical);
    }
    Ok(())
}

#[test]
fn duplicate_and_lossy_tokens_reject_before_value_construction() {
    for (input, cause) in [
        (r#"{"x":null,"x":true}"#, "duplicate object key"),
        (r#"[{"x":false,"\u0078":true}]"#, "duplicate object key"),
        ("0.123456789012345678901", "number token"),
        ("1.0000000000000000001", "number token"),
        ("9007199254740993.0", "number token"),
        ("18446744073709551616", "number token"),
        ("1e-999", "number token"),
        ("true false", "trailing characters"),
    ] {
        assert!(
            matches!(
                parse_legacy_signed_json(input),
                Err(Error::CanonicalJson(reason)) if reason.contains(cause)
            ),
            "accepted or misclassified {input}"
        );
    }
}
