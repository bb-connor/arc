//! Algorithm contract against the existing complete-envelope encoder.
//! These controls grant neither native dispatch nor finishing finance.
use super::*;
use serde::ser::SerializeStruct;
use std::cell::Cell;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct LaterField<'a>(&'a Cell<usize>);

impl Serialize for LaterField<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.set(self.0.get() + 1);
        serializer.serialize_bool(true)
    }
}

struct BorrowedEnvelope<'a> {
    output: &'a str,
    later: LaterField<'a>,
}

impl Serialize for BorrowedEnvelope<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("BorrowedEnvelope", 2)?;
        fields.serialize_field("output", self.output)?;
        fields.serialize_field("later", &self.later)?;
        fields.end()
    }
}

#[test]
fn oversized_retained_envelope_stops_before_later_fields() -> TestResult {
    let later = Cell::new(0);
    let output = "x".repeat(16 * 1024);
    let envelope = BorrowedEnvelope {
        output: &output,
        later: LaterField(&later),
    };
    let result = bounded("raw_invocation", &envelope, 512);
    assert!(
        matches!(result, Err(ToolOutcomeError::TooLarge {
            field: "raw_invocation", actual, maximum: 512,
        }) if actual > 512),
        "oversized complete envelope must preserve the size error contract"
    );
    assert!(
        later.get() == 0,
        "exhausted envelope still encoded subsequent retained fields"
    );
    Ok(())
}

#[test]
fn supported_retained_envelope_matches_original_canonical_bytes() -> TestResult {
    let later = Cell::new(0);
    let envelope = BorrowedEnvelope {
        output: "bounded\nvalue",
        later: LaterField(&later),
    };
    let encoded = bounded("raw_invocation", &envelope, 512)?;
    assert_eq!(encoded, br#"{"later":true,"output":"bounded\nvalue"}"#);
    assert_eq!(later.get(), 1);
    Ok(())
}

#[test]
fn legacy_complete_envelopes_preserve_canonical_bytes_at_the_exact_limit() -> TestResult {
    let mut deep = serde_json::json!({"private": "retained"});
    for _ in 0..40 {
        deep = serde_json::Value::Array(vec![deep]);
    }
    let dense = serde_json::Value::Array((0..5_000).map(serde_json::Value::from).collect());
    let cases = [
        serde_json::json!({
            "z": "\u{0000}\n\t\"\\",
            "\u{e000}": "bmp",
            "\u{10000}": "supplementary"
        }),
        serde_json::json!({
            "negative_zero": -0.0,
            "small": 1.0e-7,
            "large": 1.0e21,
            "wide": u64::MAX
        }),
        deep,
        dense,
    ];
    for value in cases {
        let expected = chio_core::canonical::canonical_json_bytes(&value)?;
        let actual = super::bounded("legacy_canonical_control", &value, expected.len())?;
        assert!(
            actual == expected,
            "legacy complete envelope canonical bytes changed"
        );
    }
    let expected = chio_core::canonical::canonical_json_bytes(&0.1_f32)?;
    let actual = super::bounded("legacy_float_control", &0.1_f32, expected.len())?;
    assert!(
        actual == expected,
        "legacy float envelope canonical bytes changed"
    );
    Ok(())
}

#[derive(serde::Serialize)]
enum LegacyTaggedFixture {
    Unit,
    Value(u64),
    Tuple(&'static str, bool),
    Record { text: &'static str, enabled: bool },
}

#[test]
fn legacy_tagged_and_optional_envelopes_preserve_canonical_bytes() -> TestResult {
    for value in [
        LegacyTaggedFixture::Unit,
        LegacyTaggedFixture::Value(u64::MAX),
        LegacyTaggedFixture::Tuple("bounded", true),
        LegacyTaggedFixture::Record {
            text: "quoted\"value",
            enabled: false,
        },
    ] {
        let expected = chio_core::canonical::canonical_json_bytes(&value)?;
        let actual = super::bounded("legacy_tagged_control", &value, expected.len())?;
        assert!(
            actual == expected,
            "legacy tagged envelope canonical bytes changed"
        );
    }
    for value in [Some("bounded"), None] {
        let expected = chio_core::canonical::canonical_json_bytes(&value)?;
        let actual = super::bounded("legacy_optional_control", &value, expected.len())?;
        assert!(
            actual == expected,
            "legacy optional envelope canonical bytes changed"
        );
    }
    let mut map = std::collections::BTreeMap::new();
    map.insert(-1_i64, "negative");
    map.insert(7, "positive");
    let expected = chio_core::canonical::canonical_json_bytes(&map)?;
    let actual = super::bounded("legacy_map_key_control", &map, expected.len())?;
    assert!(actual == expected, "legacy map key canonical bytes changed");
    Ok(())
}
