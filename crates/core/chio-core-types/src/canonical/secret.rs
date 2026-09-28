//! Canonical serialization with custody of intermediate JSON strings.
use super::{write_canonical_value, Result};
use alloc::string::String;
use alloc::vec::Vec;
use serde::Serialize;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

/// Serialize canonical JSON while wiping the completed intermediate value tree's
/// strings and retaining the output in zeroizing ownership. Callers remain
/// responsible for their input and for any allocations inside custom serializers.
pub fn canonical_json_bytes_zeroizing<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let tree = WipingJsonTree(serde_json::to_value(value)?);
    let mut output = Zeroizing::new(String::new());
    write_canonical_value(&tree.0, &mut output)?;
    Ok(Zeroizing::new(core::mem::take(&mut *output).into_bytes()))
}

struct WipingJsonTree(Value);

impl Drop for WipingJsonTree {
    fn drop(&mut self) {
        wipe_strings(&mut self.0);
    }
}

fn wipe_string(value: &mut String) {
    value.zeroize();
    #[cfg(test)]
    {
        assert!(value.is_empty(), "intermediate string was not wiped");
        WIPED_STRINGS.with(|count| count.set(count.get() + 1));
    }
}

fn wipe_strings(value: &mut Value) {
    match value {
        Value::String(value) => wipe_string(value),
        Value::Array(values) => {
            for value in values {
                wipe_strings(value);
            }
        }
        Value::Object(values) => {
            // Keys are immutable while resident in a map. Drain ownership before
            // wiping them so its ordering invariant is never changed in place.
            for (mut key, mut value) in core::mem::take(values) {
                wipe_string(&mut key);
                wipe_strings(&mut value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
std::thread_local! {
    static WIPED_STRINGS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_json_bytes, UntrustedJsonText};
    use chio_test_support::prelude::*;
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    #[test]
    fn private_canonical_output_matches_public_bytes_and_wipes_all_tree_strings() {
        let value = json!({
            "z": ["fixture secret", {"nested": "\n\t\u{0001}\"\\"}],
            "\u{1f600}": "unicode value",
            "n": u64::MAX,
            "f": 0.125,
        });
        WIPED_STRINGS.with(|count| count.set(0));
        let private = canonical_json_bytes_zeroizing(&value).test_expect("fixture canonical JSON");
        assert_eq!(
            &*private,
            &canonical_json_bytes(&value).test_expect("fixture canonical JSON")
        );
        // Five object keys and three string values, including the nested array.
        assert_eq!(WIPED_STRINGS.with(|count| count.get()), 8);
    }

    #[test]
    fn canonical_private_decode_retains_zeroizing_fields_and_rejects_duplicate_text() {
        #[derive(Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Custody {
            seed: String,
        }
        impl Drop for Custody {
            fn drop(&mut self) {
                self.seed.zeroize();
            }
        }
        let canonical = br#"{"seed":"fixture only"}"#;
        WIPED_STRINGS.with(|count| count.set(0));
        let value: Custody = UntrustedJsonText::from_wire(canonical, 1024)
            .test_expect("fixture canonical JSON")
            .decode_canonical()
            .test_expect("fixture canonical JSON");
        assert_eq!(value.seed, "fixture only");
        assert_eq!(WIPED_STRINGS.with(|count| count.get()), 2);
        assert!(matches!(
            UntrustedJsonText::from_wire(br#"{"seed":"first","seed":"second"}"#, 1024)
                .test_expect("fixture canonical JSON")
                .decode_canonical::<Custody>(),
            Err(crate::canonical::UntrustedJsonError::Decode(_))
        ));
    }
}
