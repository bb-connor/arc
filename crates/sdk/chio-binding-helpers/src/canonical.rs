use serde_json::Value;

use crate::Result;

/// Parse a raw JSON string and return its RFC 8785 canonical form.
pub fn canonicalize_json_str(input: &str) -> Result<String> {
    let value: Value = chio_core::canonical::UntrustedJsonText::from_wire(
        input.as_bytes(),
        crate::MAX_JSON_INPUT_BYTES,
    )
    .and_then(|text| text.decode_signed())
    .map_err(|error| chio_core::Error::UntrustedInput(error.into()))?;
    Ok(chio_core::canonicalize(&value)?)
}

#[cfg(test)]
mod tests {
    use super::canonicalize_json_str;

    #[test]
    fn canonicalize_json_string_input() -> crate::Result<()> {
        let canonical = canonicalize_json_str(r#"{"z":1,"a":2}"#)?;
        assert_eq!(canonical, r#"{"a":2,"z":1}"#);
        Ok(())
    }
}
