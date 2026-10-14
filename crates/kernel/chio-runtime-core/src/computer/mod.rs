//! Bounded resource descriptions without session or execution authority.

pub mod branches;
mod types;
pub(crate) mod validation;

pub use types::*;
pub use validation::{namespace_digest, revision_digest, validate_computer};

use serde::{de::DeserializeOwned, Serialize};

pub const COMPUTER_DESCRIPTION_SCHEMA: &str = "chio.computer.description.v1";
pub const MAX_DESCRIPTION_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Computer description rejected: {code}")]
pub struct DescriptionError {
    pub code: &'static str,
}

pub(crate) fn refuse<T>(code: &'static str) -> Result<T, DescriptionError> {
    Err(DescriptionError { code })
}

pub(crate) fn digest<T: Serialize>(domain: &str, body: &T) -> Result<String, DescriptionError> {
    let bytes = chio_core_types::crypto::canonical_json_bytes(&serde_json::json!({
        "domain": domain,
        "body": body,
    }))
    .map_err(|_| DescriptionError { code: "canonical" })?;
    Ok(chio_core_types::crypto::sha256_hex(&bytes))
}

pub(crate) fn wire_bound<T: Serialize>(value: &T, bound: usize) -> Result<(), DescriptionError> {
    struct Counter {
        bytes: usize,
        bound: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, value: &[u8]) -> std::io::Result<usize> {
            self.bytes = self.bytes.saturating_add(value.len());
            if self.bytes > self.bound {
                return Err(std::io::Error::other("description byte limit"));
            }
            Ok(value.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Counter { bytes: 0, bound }, value)
        .map_err(|_| DescriptionError { code: "wire_bytes" })
}

fn integer_token(token: &str) -> Result<String, DescriptionError> {
    if token.len() > 1024 {
        return refuse("json_number");
    }
    let negative = token.starts_with('-');
    let unsigned = token.strip_prefix('-').unwrap_or(token);
    let (mantissa, exponent) = unsigned.split_once(['e', 'E']).unwrap_or((unsigned, "0"));
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let exponent_digits = exponent.trim_start_matches(['+', '-']);
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || (whole.starts_with('0') && whole.len() > 1)
        || (mantissa.contains('.') && fraction.is_empty())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || exponent_digits.is_empty()
        || !exponent_digits.bytes().all(|byte| byte.is_ascii_digit())
        || exponent.len().saturating_sub(exponent_digits.len()) > 1
    {
        return refuse("json_shape");
    }
    let combined = format!("{whole}{fraction}");
    let mut digits = combined.trim_start_matches('0').to_owned();
    if digits.is_empty() {
        return Ok("0".into());
    }
    if negative || exponent_digits.trim_start_matches('0').len() > 4 {
        return refuse("json_number");
    }
    let power = exponent.parse::<i32>().map_err(|_| DescriptionError {
        code: "json_number",
    })? - i32::try_from(fraction.len()).map_err(|_| DescriptionError {
        code: "json_number",
    })?;
    if power < 0 {
        let removed = usize::try_from(-power).map_err(|_| DescriptionError {
            code: "json_number",
        })?;
        let retained = digits.len().checked_sub(removed).ok_or(DescriptionError {
            code: "json_number",
        })?;
        let suffix = digits.as_bytes().get(retained..).ok_or(DescriptionError {
            code: "json_number",
        })?;
        if !suffix.iter().all(|byte| *byte == b'0') {
            return refuse("json_number");
        }
        digits.truncate(retained);
    } else {
        let added = usize::try_from(power).map_err(|_| DescriptionError {
            code: "json_number",
        })?;
        if digits.len() + added > 16 {
            return refuse("json_number");
        }
        digits.push_str(&"0".repeat(added));
    }
    if digits.len() > 16 || (digits.len() == 16 && digits.as_str() > "9007199254740991") {
        return refuse("json_number");
    }
    Ok(digits)
}

fn normalize_numbers(bytes: &[u8], bound: usize) -> Result<Vec<u8>, DescriptionError> {
    let mut result = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut quoted = false;
    let mut escaped = false;
    while let Some(byte) = bytes.get(index).copied() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if byte.is_ascii_digit() || byte == b'-' {
            let start = index;
            index += 1;
            while bytes
                .get(index)
                .is_some_and(|byte| byte.is_ascii_digit() || b".eE+-".contains(byte))
            {
                index += 1;
            }
            let token = bytes
                .get(start..index)
                .ok_or(DescriptionError { code: "json_shape" })?;
            let token =
                std::str::from_utf8(token).map_err(|_| DescriptionError { code: "json_shape" })?;
            let integer = integer_token(token)?;
            if result.len() + integer.len() > bound {
                return refuse("wire_bytes");
            }
            result.extend_from_slice(integer.as_bytes());
            continue;
        }
        if result.len() == bound {
            return refuse("wire_bytes");
        }
        result.push(byte);
        index += 1;
    }
    Ok(result)
}

pub(crate) fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    bound: usize,
) -> Result<T, DescriptionError> {
    if bytes.len() > bound {
        return refuse("wire_bytes");
    }
    let mut depth = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > 96 {
                        return refuse("json_depth");
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    let normalized = normalize_numbers(bytes, bound)?;
    let value: serde_json::Value =
        chio_core_types::canonical::UntrustedJsonText::from_wire(&normalized, bound)
            .and_then(|input| input.decode_document())
            .map_err(|_| DescriptionError { code: "json_shape" })?;
    let mut pending = vec![&value];
    let mut entries = 0_usize;
    while let Some(value) = pending.pop() {
        match value {
            serde_json::Value::String(value) if value.len() > 1024 => {
                return refuse("string_bytes");
            }
            serde_json::Value::Array(values) => {
                entries += values.len();
                if entries > 65_536 * (bound / MAX_DESCRIPTION_BYTES) {
                    return refuse("json_entries");
                }
                pending.extend(values);
            }
            serde_json::Value::Object(values) => {
                entries += values.len();
                if entries > 65_536 * (bound / MAX_DESCRIPTION_BYTES) {
                    return refuse("json_entries");
                }
                if values.keys().any(|key| key.len() > 1024) {
                    return refuse("string_bytes");
                }
                pending.extend(values.values());
            }
            _ => {}
        }
    }
    serde_json::from_value(value).map_err(|_| DescriptionError { code: "json_shape" })
}

impl ComputerDescription {
    pub fn from_json(bytes: &[u8]) -> Result<Self, DescriptionError> {
        let description = decode(bytes, MAX_DESCRIPTION_BYTES)?;
        validate_computer(&description)?;
        Ok(description)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_numbers_retain_exact_integral_identity() -> Result<(), Box<dyn std::error::Error>> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/bindings/vectors/computer/v1.json"
        )))?;
        for case in fixture["numbers"]
            .as_array()
            .ok_or("missing numbers")?
            .iter()
            .chain(fixture["wireStrings"].as_array().ok_or("missing strings")?)
        {
            let source = case["source"].as_str().ok_or("missing source")?;
            let result = decode::<serde_json::Value>(source.as_bytes(), MAX_DESCRIPTION_BYTES);
            if let Some(error) = case["error"].as_str() {
                assert_eq!(
                    result.err().map(|error| error.code),
                    Some(error),
                    "{source}"
                );
            } else {
                assert_eq!(result?, case["value"], "{source}");
            }
        }
        let quoted = br#"{"text":"quote\"1.00000000000000001","value":1.0}"#;
        assert_eq!(
            decode::<serde_json::Value>(quoted, MAX_DESCRIPTION_BYTES)?,
            serde_json::json!({"text": "quote\"1.00000000000000001", "value": 1})
        );
        assert_eq!(
            decode::<serde_json::Value>(br#"{"value":{"id":1.0,"id":1e0}}"#, MAX_DESCRIPTION_BYTES)
                .err(),
            Some(DescriptionError { code: "json_shape" })
        );
        Ok(())
    }

    #[test]
    fn wire_parser_limits_are_exact() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            (
                format!("0{}", " ".repeat(MAX_DESCRIPTION_BYTES - 1)),
                " ",
                "wire_bytes",
            ),
            (
                format!("{}0{}", "[".repeat(96), "]".repeat(96)),
                "depth",
                "json_depth",
            ),
            (
                serde_json::to_string(&vec![0; 65_536])?,
                "entry",
                "json_entries",
            ),
            (
                serde_json::to_string(&"é".repeat(512))?,
                "string",
                "string_bytes",
            ),
        ];
        for (maximum, kind, error) in cases {
            decode::<serde_json::Value>(maximum.as_bytes(), MAX_DESCRIPTION_BYTES)?;
            let overflow = match kind {
                "depth" => format!("[{maximum}]"),
                "entry" => serde_json::to_string(&vec![0; 65_537])?,
                "string" => serde_json::to_string(&format!("{}a", "é".repeat(512)))?,
                _ => format!("{maximum} "),
            };
            assert_eq!(
                decode::<serde_json::Value>(overflow.as_bytes(), MAX_DESCRIPTION_BYTES).err(),
                Some(DescriptionError { code: error })
            );
        }
        for count in [262_144, 262_145] {
            let bytes = serde_json::to_vec(&vec![0; count])?;
            let result = decode::<serde_json::Value>(&bytes, crate::program::MAX_COMPILED_BYTES);
            if count == 262_144 {
                assert_eq!(result?.as_array().ok_or("array")?.len(), count);
            } else {
                assert_eq!(
                    result.err(),
                    Some(DescriptionError {
                        code: "json_entries"
                    })
                );
            }
        }
        Ok(())
    }
}
