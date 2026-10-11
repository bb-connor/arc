//! Canonical serialization with custody of intermediate JSON strings.
use super::{write_canonical_value, CanonicalOutput, Error, Result};
use alloc::string::String;
use alloc::vec::Vec;
use serde::Serialize;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

/// Serialize canonical JSON while wiping the completed intermediate value tree's
/// strings and retaining the output in zeroizing ownership. The output is fully
/// allocated before any secret bytes are copied and cannot grow while encoding.
/// Callers remain responsible for their input and for any allocations inside
/// custom serializers.
pub fn canonical_json_bytes_zeroizing<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let tree = WipingJsonTree(serde_json::to_value(value)?);
    let mut count = CountOutput::default();
    write_canonical_value(&tree.0, &mut count)?;
    let mut output = Zeroizing::new(alloc::vec![0; count.len]);
    write_canonical_into(&tree.0, &mut output)?;
    Ok(output)
}

#[derive(Default)]
struct CountOutput {
    len: usize,
}

impl CanonicalOutput for CountOutput {
    fn write_str(&mut self, value: &str) -> Result<()> {
        self.len = self
            .len
            .checked_add(value.len())
            .filter(|len| isize::try_from(*len).is_ok())
            .ok_or_else(|| Error::CanonicalJson("canonical output length overflow".into()))?;
        Ok(())
    }
}

/// This writer only borrows a slice, so appending cannot reallocate a buffer
/// containing an unwiped secret prefix. Even a counting mismatch fails closed.
struct FixedOutput<'a> {
    bytes: &'a mut [u8],
    written: usize,
}

impl CanonicalOutput for FixedOutput<'_> {
    fn write_str(&mut self, value: &str) -> Result<()> {
        let end = self
            .written
            .checked_add(value.len())
            .ok_or_else(|| Error::CanonicalJson("canonical output length overflow".into()))?;
        let target = self.bytes.get_mut(self.written..end).ok_or_else(|| {
            Error::CanonicalJson("canonical output exceeded counted length".into())
        })?;
        target.copy_from_slice(value.as_bytes());
        self.written = end;
        Ok(())
    }
}

impl FixedOutput<'_> {
    fn finish(self) -> Result<()> {
        if self.written != self.bytes.len() {
            return Err(Error::CanonicalJson(
                "canonical output did not fill counted length".into(),
            ));
        }
        Ok(())
    }
}

fn write_canonical_into(value: &Value, bytes: &mut [u8]) -> Result<()> {
    let mut output = FixedOutput { bytes, written: 0 };
    write_canonical_value(value, &mut output)?;
    output.finish()
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

    fn long_secret_value() -> Value {
        json!({
            "governanceAuthoritySeeds": [
                {"id": "governance-first", "seedHex": "a".repeat(16_383)},
                {"id": "governance-second", "seedHex": "b".repeat(16_385)},
            ],
            "leaseAuthoritySeeds": [
                {"id": "lease-first", "seedHex": "c".repeat(16_387)},
                {"id": "lease-second", "seedHex": "d".repeat(16_389)},
            ],
            "\u{1f600}": ["\n\t\u{0001}\"\\".repeat(257), {"\u{0000}": "tail"}],
            "\u{e000}": "UTF-16 ordering",
        })
    }

    #[test]
    fn private_output_uses_exact_counted_allocation_for_long_secret_values() {
        let value = long_secret_value();
        let output = canonical_json_bytes_zeroizing(&value).test_expect("private output");
        assert_eq!(
            output.capacity(),
            output.len(),
            "custody output must allocate its full counted length before writing secrets"
        );
        assert_eq!(
            &*output,
            &canonical_json_bytes(&value).test_expect("public output")
        );
    }

    #[test]
    fn fixed_output_cannot_grow_and_rejects_an_oversized_chunk_atomically() {
        let mut bytes = *b"----";
        {
            let mut output = FixedOutput {
                bytes: &mut bytes,
                written: 0,
            };
            output.write_str("ab").test_expect("initial fragment");
            assert!(matches!(
                output.write_str("fixture secret"),
                Err(Error::CanonicalJson(_))
            ));
            assert_eq!(output.written, 2);
            assert_eq!(output.bytes, b"ab--");
            output.write_str("cd").test_expect("remaining fragment");
            output.finish().test_expect("exactly filled output");
        }
        assert_eq!(bytes, *b"abcd");
    }

    #[test]
    fn fixed_canonical_output_checks_both_under_and_overestimated_lengths() {
        let value = long_secret_value();
        let expected = canonical_json_bytes(&value).test_expect("public output");
        let mut output = Zeroizing::new(alloc::vec![0; expected.len()]);
        let allocation = output.as_ptr();
        let capacity = output.capacity();
        write_canonical_into(&value, &mut output).test_expect("exact output length");
        assert_eq!(output.as_ptr(), allocation);
        assert_eq!(output.capacity(), capacity);
        assert_eq!(&*output, &expected);

        let mut short = Zeroizing::new(alloc::vec![0; expected.len() - 1]);
        assert!(matches!(
            write_canonical_into(&value, &mut short),
            Err(Error::CanonicalJson(_))
        ));
        let mut long = Zeroizing::new(alloc::vec![0; expected.len() + 1]);
        assert!(matches!(
            write_canonical_into(&value, &mut long),
            Err(Error::CanonicalJson(_))
        ));
    }

    #[test]
    fn counted_output_rejects_length_overflow_without_changing_the_count() {
        let mut output = CountOutput { len: usize::MAX };
        assert!(matches!(
            output.write_str("x"),
            Err(Error::CanonicalJson(_))
        ));
        assert_eq!(output.len, usize::MAX);

        let limit = usize::try_from(isize::MAX).test_expect("allocation limit fits usize");
        let mut output = CountOutput { len: limit };
        assert!(matches!(
            output.write_str("x"),
            Err(Error::CanonicalJson(_))
        ));
        assert_eq!(output.len, limit);
    }

    #[test]
    fn private_output_preserves_native_number_and_escape_contracts() {
        for (value, expected) in [
            (json!(i64::MIN), "-9223372036854775808"),
            (json!(u64::MAX), "18446744073709551615"),
            (json!(-0.0), "0"),
            (json!(0.125), "0.125"),
            (json!(1e-7), "1e-7"),
            (json!(1e-6), "0.000001"),
            (json!(1e20), "100000000000000000000"),
            (json!(1e21), "1e+21"),
            (json!(f64::from_bits(1)), "5e-324"),
            (
                json!("\u{0000}\u{0008}\u{000c}\n\r\t\"\\\u{007f}\u{0085}\u{1f600}"),
                "\"\\u0000\\b\\f\\n\\r\\t\\\"\\\\\u{007f}\u{0085}\u{1f600}\"",
            ),
        ] {
            let output = canonical_json_bytes_zeroizing(&value).test_expect("private output");
            assert_eq!(&*output, expected.as_bytes());
        }
        let value = json!({"\u{e000}": 2, "\u{1f600}": 1});
        let output = canonical_json_bytes_zeroizing(&value).test_expect("private output");
        assert_eq!(&*output, "{\"\u{1f600}\":1,\"\u{e000}\":2}".as_bytes());
    }

    #[test]
    fn private_output_preserves_the_serializer_error_variant() {
        struct Failing;
        impl Serialize for Failing {
            fn serialize<S>(&self, _serializer: S) -> core::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom("fixture serializer failure"))
            }
        }
        let error = canonical_json_bytes_zeroizing(&Failing).test_expect_err("serializer fails");
        assert!(matches!(&error, Error::Json(_)));
        assert!(core::error::Error::source(&error).is_some());
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
