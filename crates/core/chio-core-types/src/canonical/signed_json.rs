//! Lossless parsing for signed typed JSON.
//! Keep full-width integer tokens. Reject duplicate keys before they disappear
//! into a map, and numeric spellings neither canonical nor typed writers can emit.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// Parse signed typed JSON without discarding duplicate keys or numeric
/// precision, including full-width integers and integer-valued floats.
/// Whitespace and object ordering are immaterial. No signature is verified here.
/// The verifier must reconstruct the typed signing body and verify its signature.
/// Protocols constrained to I-JSON use [`super::canonical_json_bytes_from_str`].
pub(super) fn parse_signed_json(input: &str) -> crate::error::Result<Value> {
    parse(input).map_err(crate::error::Error::CanonicalJson)
}

fn parse(input: &str) -> Result<Value, String> {
    // Deserialize directly from tokens so nested duplicate keys remain visible.
    let value: StoredValue = serde_json::from_str(input).map_err(|error| error.to_string())?;
    validate_number_tokens(input)?;
    Ok(value.0)
}

struct StoredValue(Value);

impl<'de> Deserialize<'de> for StoredValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StoredValueVisitor)
    }
}

struct StoredValueVisitor;

impl<'de> Visitor<'de> for StoredValueVisitor {
    type Value = StoredValue;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("receipt JSON without duplicate keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StoredValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StoredValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StoredValue(Value::Number(value.into())))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(|number| StoredValue(Value::Number(number)))
            .ok_or_else(|| E::custom("non-finite receipt JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StoredValue(Value::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StoredValue(Value::String(value)))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StoredValue(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(StoredValue(value)) = seq.next_element()? {
            items.push(value);
        }
        Ok(StoredValue(Value::Array(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut values = Map::new();
        while let Some((key, StoredValue(value))) = map.next_entry::<String, StoredValue>()? {
            if values.insert(key.clone(), value).is_some() {
                return Err(de::Error::custom(format!("duplicate object key: {key:?}")));
            }
        }
        Ok(StoredValue(Value::Object(values)))
    }
}

// Input is already proven syntactically valid above. Inspect original number
// tokens because an f64 visitor cannot recover discarded fractional digits.
#[allow(
    clippy::indexing_slicing,
    reason = "Each cursor access is guarded by cursor < bytes.len(); token endpoints only advance through ASCII numeric bytes."
)]
fn validate_number_tokens(input: &str) -> Result<(), String> {
    let bytes = input.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            cursor += 1;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'\\' => cursor += 2,
                    b'"' => {
                        cursor += 1;
                        break;
                    }
                    _ => cursor += 1,
                }
            }
        } else if bytes[cursor].is_ascii_digit() || bytes[cursor] == b'-' {
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len()
                && matches!(
                    bytes[cursor],
                    b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-'
                )
            {
                cursor += 1;
            }
            let token = &input[start..cursor];
            let number: Number = serde_json::from_str(token).map_err(|error| error.to_string())?;
            if token != number.to_string() {
                let canonical =
                    super::canonical_json_bytes(&number).map_err(|error| error.to_string())?;
                if token.as_bytes() != canonical {
                    return Err(format!(
                        "number token {token} loses precision or changes representation"
                    ));
                }
            }
        } else {
            cursor += 1;
        }
    }
    Ok(())
}
