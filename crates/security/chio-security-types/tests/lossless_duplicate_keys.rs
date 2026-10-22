//! `lossless_serde!` reads its input refusing a repeated object key at every
//! depth, on both raw entry points, and leaves every other input unchanged.

use chio_security_types::strict_serde::DUPLICATE_KEY;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

chio_security_types::lossless_serde! {
    #[derive(Debug, Clone, PartialEq, Serialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    enum Probe {
        Unit,
        Record {
            count: u64,
            ratio: f64,
            items: Vec<Value>,
            nested: Value,
        },
    }
}

fn direct(text: &str) -> Result<Probe, String> {
    <Probe>::deserialize(&mut serde_json::Deserializer::from_str(text))
        .map_err(|error| error.to_string())
}

fn decoded(text: &str) -> Result<Probe, String> {
    serde_json::from_str::<Probe>(text).map_err(|error| error.to_string())
}

fn assert_refused(text: &str, key: &str) {
    let expected = format!("{DUPLICATE_KEY}: {key:?}");
    for (path, result) in [("deserialize", direct(text)), ("from_str", decoded(text))] {
        let error = result.err().unwrap_or_default();
        assert!(error.starts_with(&expected), "{path} {text}: {error}");
    }
}

#[test]
fn a_repeated_key_refuses_at_every_depth_on_both_raw_paths() {
    assert_refused(r#"{"kind":"unit","kind":"unit"}"#, "kind");
    assert_refused(
        r#"{"kind":"record","count":1,"count":2,"ratio":1.5,"items":[],"nested":{}}"#,
        "count",
    );
    assert_refused(
        r#"{"kind":"record","count":1,"ratio":1.5,"items":[],"nested":{"a":{"b":1,"b":2}}}"#,
        "b",
    );
    assert_refused(
        r#"{"kind":"record","count":1,"ratio":1.5,"items":[{"x":1},[{"y":1,"y":2}]],"nested":{}}"#,
        "y",
    );
}

#[test]
fn inputs_without_duplicates_decode_unchanged() -> Result<(), Box<dyn std::error::Error>> {
    let input = json!({
        "kind": "record",
        "count": u64::MAX,
        "ratio": 100.0,
        "items": [{"x": 1}, [1, 2.5, "s", null, true]],
        "nested": {"a": {"b": [9_007_199_254_740_993_u64, -1]}},
    });
    let text = input.to_string();
    for probe in [direct(&text)?, decoded(&text)?] {
        assert_eq!(serde_json::to_value(&probe)?, input);
    }
    assert_eq!(direct(r#"{"kind":"unit"}"#)?, Probe::Unit);
    assert_eq!(decoded(r#"{"kind":"unit"}"#)?, Probe::Unit);
    Ok(())
}
