//! Preserve ordinary worker JSON values without accepting duplicate keys or rounded literals.

use std::{collections::BTreeMap, fmt};

use serde::{
    de::{MapAccess, Visitor},
    Deserializer,
};
use serde_json::{value::RawValue, Value};

use super::{fail, CliError};

pub(super) fn parse(text: &str) -> Result<Value, CliError> {
    chio_core::canonical::UntrustedJsonText::from_wire(
        text.as_bytes(),
        crate::input::MAX_DOCUMENT_BYTES,
    )?;
    parse_at(text, 0)
}

fn parse_at(text: &str, depth: usize) -> Result<Value, CliError> {
    if depth > 64 {
        return Err(fail("process document nesting exceeds 64 levels"));
    }
    let raw: &RawValue = serde_json::from_str(text).map_err(|source| {
        CliError::with_source(&chio_errors::_generated::error_codes::CLI_JSON, source)
    })?;
    let text = raw.get();
    match text.as_bytes().first() {
        Some(b'{') => {
            let mut deserializer = serde_json::Deserializer::from_str(text);
            let entries = deserializer
                .deserialize_map(UniqueObject)
                .map_err(|source| {
                    CliError::with_source(&chio_errors::_generated::error_codes::CLI_JSON, source)
                })?;
            let mut object = serde_json::Map::new();
            for (key, value) in entries {
                object.insert(key, parse_at(value.get(), depth + 1)?);
            }
            Ok(Value::Object(object))
        }
        Some(b'[') => {
            // Borrow every subtree from the bounded source. Ancestor frames
            // must not retain another owned copy of all descendant bytes.
            let entries: Vec<&RawValue> = serde_json::from_str(text).map_err(|source| {
                CliError::with_source(&chio_errors::_generated::error_codes::CLI_JSON, source)
            })?;
            entries
                .iter()
                .map(|value| parse_at(value.get(), depth + 1))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
        _ => {
            let value: Value = serde_json::from_str(text).map_err(|source| {
                CliError::with_source(&chio_errors::_generated::error_codes::CLI_JSON, source)
            })?;
            if value.is_number() {
                let rendered = serde_json::to_string(&value).map_err(|source| {
                    CliError::with_source(&chio_errors::_generated::error_codes::CLI_JSON, source)
                })?;
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
    type Value = BTreeMap<String, &'de RawValue>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object with unique keys")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut entries = BTreeMap::new();
        while let Some((key, value)) = map.next_entry::<String, &'de RawValue>()? {
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
        Some((mantissa, exponent)) => (
            mantissa,
            exponent.parse::<i64>().map_err(|source| {
                CliError::with_source(&chio_errors::_generated::error_codes::CLI_JSON, source)
            })?,
        ),
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
        .checked_sub(i64::try_from(fractional).map_err(|source| {
            CliError::with_source(&chio_errors::_generated::error_codes::CLI_JSON, source)
        })?)
        .and_then(|power| power.checked_add((digits.len() - significant.len()) as i64))
        .ok_or_else(|| fail("process document number exponent overflow"))?;
    Ok((negative, significant.to_string(), power))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn nested_document_fits_a_bounded_process() {
        const CHILD: &str = "CHIO_JSON_MEMORY_REGRESSION_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let text = format!(
                "{}\"{}\"{}",
                "[".repeat(60),
                "x".repeat(12 * 1024 * 1024),
                "]".repeat(60)
            );
            let value = parse(&text).unwrap();
            let mut leaf = &value;
            for _ in 0..60 {
                leaf = &leaf[0];
            }
            assert_eq!(leaf.as_str().unwrap().len(), 12 * 1024 * 1024);
            return;
        }

        use std::os::unix::process::CommandExt;
        let current = std::thread::current();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", current.name().unwrap(), "--test-threads=1"]);
        command.env(CHILD, "1");
        // SAFETY: the child callback uses only async-signal-safe setrlimit
        // and errno conversion before exec, without allocations or locks.
        let apply_limit = || {
            let bound = libc::rlimit {
                rlim_cur: 512 * 1024 * 1024,
                rlim_max: 512 * 1024 * 1024,
            };
            // SAFETY: bound is initialized and lives for this synchronous syscall.
            if unsafe { libc::setrlimit(libc::RLIMIT_AS, &bound) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        };
        // SAFETY: the child hook only sets a resource limit and constructs an
        // OS error, without allocation or locks between fork and exec.
        unsafe { command.pre_exec(apply_limit) };
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "bounded parser child failed: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn nested_documents_keep_duplicate_precision_and_depth_guards() {
        for source in [r#"[{"x":1,"x":2}]"#, r#"{"x":[0.123456789012345678901]}"#] {
            assert!(parse(source).is_err());
        }
        assert!(parse(&format!("{}0{}", "[".repeat(64), "]".repeat(64))).is_ok());
        assert!(parse(&format!("{}0{}", "[".repeat(65), "]".repeat(65))).is_err());
        assert_eq!(
            parse(r#"{"x":[18446744073709551615]}"#).unwrap()["x"][0].as_u64(),
            Some(u64::MAX)
        );
    }

    #[test]
    fn ordinary_worker_numbers_accept_equivalent_decimal_spellings_without_rounding() {
        for source in ["1e0", "1.00", "0e10", "100e-2"] {
            let value = parse(source).unwrap();
            assert_eq!(
                value.as_f64(),
                Some(if source == "0e10" { 0.0 } else { 1.0 })
            );
        }
        assert!(matches!(
            parse("0.123456789012345678901"),
            Err(CliError::Chio(_))
        ));
        let error = parse(r#"{"private-marker":1,"private-marker":2}"#).unwrap_err();
        assert!(matches!(error, CliError::RegisteredSource(_)));
        assert!(!error.to_string().contains("private-marker"));
    }
}
