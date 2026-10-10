//! Validation for the decoded UTF-8 byte bounds of protected wire text.

use jsonschema::{paths::Location, Keyword, ValidationError};
use serde_json::{Map, Value};

const MAX_INTEROPERABLE_INTEGER: u64 = 9_007_199_254_740_991;

struct Utf8ByteBound {
    maximum: u64,
}

impl Keyword for Utf8ByteBound {
    fn validate<'i>(&self, instance: &'i Value) -> Result<(), ValidationError<'i>> {
        if self.is_valid(instance) {
            Ok(())
        } else {
            Err(ValidationError::custom(format!(
                "string exceeds the {} byte UTF-8 bound",
                self.maximum
            )))
        }
    }

    fn is_valid(&self, instance: &Value) -> bool {
        // JSON Schema string keywords do not constrain other instance types.
        // The owning schema enforces its string type independently.
        instance
            .as_str()
            .is_none_or(|text| u64::try_from(text.len()).is_ok_and(|length| length <= self.maximum))
    }
}

pub(super) fn keyword<'a>(
    _parent: &'a Map<String, Value>,
    value: &'a Value,
    _path: Location,
) -> Result<Box<dyn Keyword>, ValidationError<'a>> {
    let maximum = value
        .as_u64()
        .filter(|maximum| (1..=MAX_INTEROPERABLE_INTEGER).contains(maximum))
        .ok_or_else(|| {
            ValidationError::schema("x-maxUtf8Bytes must be a positive interoperable integer")
        })?;
    Ok(Box::new(Utf8ByteBound { maximum }))
}
