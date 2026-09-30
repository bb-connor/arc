//! Explicit format selection and bounded YAML expansion before typed projection.
use crate::CliError;
use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::{fmt, path::Path};
const MAX_NODES: usize = 100_000;
const MAX_DEPTH: usize = 64;

pub(crate) fn load<T: DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    let bytes = super::read(path)?;
    if path
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| matches!(s, "yml" | "yaml"))
    {
        super::project(yaml(&bytes)?)
    } else {
        Ok(super::json(&bytes)?)
    }
}

fn yaml(bytes: &[u8]) -> Result<Value, CliError> {
    chio_core::canonical::UntrustedJsonText::from_wire(bytes, super::MAX_DOCUMENT_BYTES)?;
    let mut budget = Budget {
        nodes: MAX_NODES,
        bytes: super::MAX_DOCUMENT_BYTES,
    };
    let mut documents = serde_yml::Deserializer::from_slice(bytes);
    let document = documents
        .next()
        .ok_or_else(|| CliError::cli_other_error("configuration document is empty"))?;
    let value = Seed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(document)
    .map_err(|source| {
        CliError::with_source(&chio_errors::_generated::error_codes::CLI_YAML, source)
    })?;
    if documents.next().is_some() {
        return Err(CliError::cli_other_error(
            "configuration must contain one document",
        ));
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
            return Err(de::Error::custom("configuration nesting limit"));
        }
        self.budget.nodes = self
            .budget
            .nodes
            .checked_sub(1)
            .ok_or_else(|| de::Error::custom("configuration node limit"))?;
        decoder.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded configuration value")
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
            .ok_or_else(|| E::custom("non-finite configuration number"))
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
            .ok_or_else(|| E::custom("configuration expanded string limit"))?;
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
                return Err(de::Error::custom("configuration keys must be strings"));
            };
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate configuration key"));
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
