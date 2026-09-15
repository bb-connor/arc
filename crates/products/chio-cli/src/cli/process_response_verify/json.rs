//! Preserve ordinary worker JSON values without accepting duplicate keys or rounded literals.

use std::{collections::BTreeMap, fmt};

use serde::{
    de::{MapAccess, Visitor},
    Deserializer,
};
use serde_json::{value::RawValue, Value};

use super::{fail, CliError};

pub(super) fn parse(text: &str) -> Result<Value, CliError> {
    parse_at(text, 0)
}

fn parse_at(text: &str, depth: usize) -> Result<Value, CliError> {
    if depth > 64 {
        return Err(fail("process document nesting exceeds 64 levels"));
    }
    let raw: &RawValue = serde_json::from_str(text).map_err(fail)?;
    let text = raw.get();
    match text.as_bytes().first() {
        Some(b'{') => {
            let mut deserializer = serde_json::Deserializer::from_str(text);
            let entries = deserializer.deserialize_map(UniqueObject).map_err(fail)?;
            let mut object = serde_json::Map::new();
            for (key, value) in entries {
                object.insert(key, parse_at(value.get(), depth + 1)?);
            }
            Ok(Value::Object(object))
        }
        Some(b'[') => {
            let entries: Vec<Box<RawValue>> = serde_json::from_str(text).map_err(fail)?;
            entries
                .iter()
                .map(|value| parse_at(value.get(), depth + 1))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
        _ => {
            let value: Value = serde_json::from_str(text).map_err(fail)?;
            if value.is_number() {
                let rendered = serde_json::to_string(&value).map_err(fail)?;
                if decimal_identity(text)? != decimal_identity(&rendered)? {
                    return Err(fail("process document contains a precision-losing number"));
                }
            }
            Ok(value)
        }
    }
}

struct UniqueObject;

impl<'de> Visitor<'de> for UniqueObject {
    type Value = BTreeMap<String, Box<RawValue>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object with unique keys")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut entries = BTreeMap::new();
        while let Some((key, value)) = map.next_entry::<String, Box<RawValue>>()? {
            if entries.insert(key, value).is_some() {
                return Err(serde::de::Error::custom("duplicate process document key"));
            }
        }
        Ok(entries)
    }
}

// Compare exact decimal values, not their f64 approximations. JSON syntax has
// already been checked by serde. Equivalent spellings (1, 1.0, 1e0) remain valid.
fn decimal_identity(text: &str) -> Result<(bool, String, i64), CliError> {
    let negative = text.starts_with('-');
    let unsigned = text.strip_prefix('-').unwrap_or(text);
    let (mantissa, exponent) = match unsigned.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i64>().map_err(fail)?),
        None => (unsigned, 0),
    };
    let fractional = mantissa
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len());
    let digits = mantissa.replace('.', "");
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Ok((false, "0".to_string(), 0));
    }
    let significant = digits.trim_end_matches('0');
    let power = exponent
        .checked_sub(i64::try_from(fractional).map_err(fail)?)
        .and_then(|power| power.checked_add((digits.len() - significant.len()) as i64))
        .ok_or_else(|| fail("process document number exponent overflow"))?;
    Ok((negative, significant.to_string(), power))
}
