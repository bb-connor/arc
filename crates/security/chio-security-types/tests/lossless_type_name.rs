use serde::{Deserialize, Serialize};

chio_security_types::lossless_serde! {
    #[derive(Debug, PartialEq, Serialize)]
    #[serde(untagged, rename = "wire-value")]
    enum ScalarValue {
        Count(u64),
        Text(String),
    }
}

chio_security_types::lossless_serde! {
    #[derive(Debug, PartialEq, Serialize)]
    #[serde(untagged, expecting = "a count or text")]
    enum CustomExpectation {
        Count(u64),
        Text(String),
    }
}

#[test]
fn untagged_mismatch_names_the_declared_type_on_both_entry_points() {
    let expected = "data did not match any variant of untagged enum ScalarValue";
    let direct = ScalarValue::deserialize(&mut serde_json::Deserializer::from_str("true"));
    let decoded = serde_json::from_str::<ScalarValue>("true");
    for result in [direct, decoded] {
        assert_eq!(
            result.err().map(|error| error.to_string()).as_deref(),
            Some(expected)
        );
    }
}

#[test]
fn custom_serde_expectation_is_preserved() {
    let direct = CustomExpectation::deserialize(&mut serde_json::Deserializer::from_str("true"));
    let decoded = serde_json::from_str::<CustomExpectation>("true");
    for result in [direct, decoded] {
        assert_eq!(
            result.err().map(|error| error.to_string()).as_deref(),
            Some("a count or text")
        );
    }
}

#[test]
fn valid_untagged_variants_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    for (text, expected) in [
        ("7", ScalarValue::Count(7)),
        ("\"seven\"", ScalarValue::Text("seven".into())),
    ] {
        let direct = ScalarValue::deserialize(&mut serde_json::Deserializer::from_str(text))?;
        let decoded: ScalarValue = serde_json::from_str(text)?;
        assert_eq!(direct, expected);
        assert_eq!(decoded, expected);
        assert_eq!(serde_json::to_string(&decoded)?, text);
    }
    Ok(())
}
