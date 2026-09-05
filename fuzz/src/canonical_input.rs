//! Strict raw-JSON intake used by MCP adoption and signed payload consumers.

use chio_core_types::canonical::{canonical_json_string, canonical_json_string_from_str};

pub fn check(data: &[u8]) {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(canonical) = canonical_json_string_from_str(text) else {
        return;
    };
    let value = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(value) => value,
        Err(error) => panic!("strict parser accepted invalid JSON: {error}"),
    };
    assert_eq!(
        canonical_json_string(&value).ok().as_ref(),
        Some(&canonical)
    );
    assert_eq!(
        canonical_json_string_from_str(&canonical).ok().as_ref(),
        Some(&canonical),
    );
}
