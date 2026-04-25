#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const CANONICAL_VECTOR: &[u8] =
    include_bytes!("../corpus/fuzz_canonical_json/binding-canonical-v1.json");

fn contains_float_backed_number(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Number(number) => number.as_i64().is_none() && number.as_u64().is_none(),
        serde_json::Value::Array(values) => values.iter().any(contains_float_backed_number),
        serde_json::Value::Object(values) => values.values().any(contains_float_backed_number),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::String(_) => {
            false
        }
    }
}

fn assert_canonical_roundtrip(value: &serde_json::Value, enforce_idempotence: bool) {
    let Ok(first) = chio_core::canonical::canonicalize(value) else {
        return;
    };

    let reparsed: serde_json::Value = match serde_json::from_str(&first) {
        Ok(value) => value,
        Err(error) => panic!("canonical JSON did not parse back as JSON: {error}"),
    };

    let second = match chio_core::canonical::canonicalize(&reparsed) {
        Ok(value) => value,
        Err(error) => panic!("canonical JSON failed to canonicalize after roundtrip: {error}"),
    };

    if enforce_idempotence {
        assert_eq!(first, second);
    }
    assert!(!first.contains('\n'));
    assert!(!first.contains('\r'));
    assert!(!first.contains('\t'));
    assert!(!second.contains('\n'));
    assert!(!second.contains('\r'));
    assert!(!second.contains('\t'));
}

fn exercise_binding_vector(value: &serde_json::Value, enforce_expected: bool) {
    let Some(cases) = value.get("cases").and_then(|cases| cases.as_array()) else {
        return;
    };

    for case in cases {
        let Some(input_json) = case.get("input_json").and_then(|input| input.as_str()) else {
            continue;
        };
        let Some(expected) = case
            .get("canonical_json")
            .and_then(|expected| expected.as_str())
        else {
            continue;
        };

        let parsed: serde_json::Value = match serde_json::from_str(input_json) {
            Ok(parsed) => parsed,
            Err(_) => continue,
        };
        let actual = match chio_core::canonical::canonicalize(&parsed) {
            Ok(actual) => actual,
            Err(_) => continue,
        };
        if enforce_expected {
            assert_eq!(actual, expected);
        } else if actual != expected {
            continue;
        }
        assert_canonical_roundtrip(&parsed, true);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    exercise_binding_vector(&value, data == CANONICAL_VECTOR);
    assert_canonical_roundtrip(&value, !contains_float_backed_number(&value));
});
