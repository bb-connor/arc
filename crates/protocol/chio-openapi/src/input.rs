//! Original document decoding with bounded YAML expansion and duplicate rejection.
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

/// Maximum original OpenAPI document size, including leading whitespace.
pub const MAX_OPENAPI_BYTES: usize = 8 * 1024 * 1024;
const MAX_NODES: usize = 100_000;
const MAX_DEPTH: usize = 64;

pub(crate) fn decode(input: &[u8]) -> crate::Result<Value> {
    if input.len() > MAX_OPENAPI_BYTES {
        return Err(chio_core_types::canonical::UntrustedJsonError::TooLarge {
            bytes: input.len(),
            bound: MAX_OPENAPI_BYTES,
        }
        .into());
    }
    // UTF-8 is validated before format detection; no lossy conversion is allowed.
    let text = std::str::from_utf8(input)?;
    if matches!(text.trim_start().as_bytes().first(), Some(b'{' | b'[')) {
        return Ok(chio_core_types::canonical::UntrustedJsonText::from_wire(
            input,
            MAX_OPENAPI_BYTES,
        )?
        .decode_signed()?);
    }
    let mut budget = Budget {
        nodes: MAX_NODES,
        bytes: MAX_OPENAPI_BYTES,
    };
    let mut documents = serde_yaml::Deserializer::from_slice(input);
    let document = documents.next().ok_or(crate::OpenApiError::EmptyDocument)?;
    let value = Seed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(document)?;
    if documents.next().is_some() {
        return Err(crate::OpenApiError::MultipleDocuments);
    }
    Ok(value)
}

struct Budget {
    nodes: usize,
    bytes: usize,
}
struct Seed<'a> {
    budget: &'a mut Budget,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        if self.depth > MAX_DEPTH {
            return Err(de::Error::custom("OpenAPI nesting limit"));
        }
        self.budget.nodes = self
            .budget
            .nodes
            .checked_sub(1)
            .ok_or_else(|| de::Error::custom("OpenAPI node limit"))?;
        decoder.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded OpenAPI value")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(value.into())
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(value.into())
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite OpenAPI number"))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        self.budget.bytes = self
            .budget
            .bytes
            .checked_sub(value.len())
            .ok_or_else(|| E::custom("OpenAPI expanded string limit"))?;
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        self.visit_str(&value)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(Seed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key_seed(Seed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            let Value::String(key) = key else {
                return Err(de::Error::custom("OpenAPI keys must be strings"));
            };
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate OpenAPI key"));
            }
            let value = map.next_value_seed(Seed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn original_duplicates_and_whitespace_oversize_are_rejected() {
        assert!(matches!(
            decode(br#"{"openapi":"3.0.3","openapi":"3.1.0"}"#),
            Err(crate::OpenApiError::UntrustedInput(_))
        ));
        assert!(matches!(
            decode(b"openapi: '3.0.3'\nopenapi: '3.1.0'"),
            Err(crate::OpenApiError::InvalidYaml(_))
        ));
        assert!(matches!(
            decode(&vec![b' '; MAX_OPENAPI_BYTES + 1]),
            Err(crate::OpenApiError::UntrustedInput(
                chio_core_types::canonical::UntrustedJsonError::TooLarge { .. }
            ))
        ));
    }
    #[test]
    fn yaml_aliases_share_a_total_expansion_budget() {
        let mut input = format!("base: &base {}\nexpanded:\n", "x".repeat(16_384));
        for _ in 0..600 {
            input.push_str("  - *base\n");
        }
        assert!(input.len() < MAX_OPENAPI_BYTES);
        let error = decode(input.as_bytes()).unwrap_err();
        assert!(matches!(error, crate::OpenApiError::InvalidYaml(_)));
        assert_eq!(
            error.to_string(),
            "urn:chio:error:transport:invalid-request-shape"
        );
    }
    #[test]
    fn yaml_depth_documents_and_nonstring_keys_are_rejected() {
        for input in [
            format!("x: {}0{}", "[".repeat(80), "]".repeat(80)),
            "x: 1\n---\ny: 2".to_owned(),
            "1: value".to_owned(),
        ] {
            assert!(decode(input.as_bytes()).is_err(), "{input}");
        }
        assert!(matches!(decode(&[0xff]), Err(crate::OpenApiError::Utf8(_))));
        assert_eq!(
            decode(b"id: 18446744073709551615").unwrap()["id"].as_u64(),
            Some(u64::MAX)
        );
    }
}
