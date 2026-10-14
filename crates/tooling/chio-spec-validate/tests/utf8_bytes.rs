use std::path::Path;

use chio_spec_validate::{validate_value, ValidateError};
use serde_json::json;

#[test]
fn protected_text_keyword_measures_decoded_utf8_bytes() {
    let schema = json!({"type": "string", "x-maxUtf8Bytes": 4});
    for value in ["xxxx", "éé", "😀"] {
        assert!(validate_value(
            Path::new("<schema>"),
            &schema,
            Path::new("<document>"),
            &json!(value)
        )
        .is_ok());
    }
    for value in ["xxxxx", "ééé", "😀x"] {
        assert!(matches!(
            validate_value(
                Path::new("<schema>"),
                &schema,
                Path::new("<document>"),
                &json!(value)
            ),
            Err(ValidateError::SchemaViolation(..))
        ));
    }
}

#[test]
fn protected_text_keyword_requires_a_positive_interoperable_integer_bound() {
    for limit in [
        json!(0),
        json!(-1),
        json!(1.5),
        json!(true),
        json!("unbounded"),
        json!(9007199254740992u64),
    ] {
        let schema = json!({"type": "string", "x-maxUtf8Bytes": limit});
        assert!(matches!(
            validate_value(
                Path::new("<schema>"),
                &schema,
                Path::new("<document>"),
                &json!("text")
            ),
            Err(ValidateError::SchemaCompile(..))
        ));
    }
}
