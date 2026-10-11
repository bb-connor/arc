//! Unsigned reviewed tool schemas do not relax signed provisioning custody.
use super::*;
use chio_core::canonical::UntrustedJsonError;
use chio_test_support::ctx::{TestUnwrap, TestUnwrapErr};
use serde_json::Value;

#[test]
fn reviewed_tools_fixture_accepts_unsigned_schema_number_spellings() {
    for (token, expected) in [("0.50", 0.5), ("1e-05", 0.00001), ("1.00", 1.0)] {
        let tool = format!(
            r#"{{"name":"scale","inputSchema":{{"type":"number","multipleOf":{token}}},"outputSchema":{{"type":"number","minimum":{token}}}}}"#
        );
        for raw in [format!("[{tool}]"), format!(r#"{{"tools":[{tool}]}}"#)] {
            let tools = decode_tools_fixture(raw.as_bytes(), Path::new("tools.json"))
                .test_unwrap("unsigned reviewed tools fixture");
            assert_eq!(tools.len(), 1);
            let tool = tools.first().test_unwrap("reviewed tool");
            assert_eq!(
                tool.input_schema.get("multipleOf").and_then(Value::as_f64),
                Some(expected)
            );
            assert_eq!(
                tool.output_schema
                    .as_ref()
                    .and_then(|schema| schema.get("minimum"))
                    .and_then(Value::as_f64),
                Some(expected)
            );
        }
    }
}

#[test]
fn reviewed_tools_fixture_still_rejects_nested_duplicate_keys() {
    let raw = br#"[{"name":"scale","inputSchema":{"minimum":1,"minimum":2}}]"#;
    let error = decode_tools_fixture(raw, Path::new("tools.json"))
        .test_unwrap_err("duplicate schema key must be rejected");
    assert!(error
        .to_string()
        .contains("urn:chio:error:attest:signed-json-invalid-input"));
}

#[test]
fn reviewed_tools_fixture_keeps_record_and_execution_metadata_limits() {
    let tool = serde_json::json!({"name":"scale","inputSchema":{"type":"number"}});
    let too_many = serde_json::to_vec(&vec![tool; 4097]).test_unwrap("tools corpus");
    let error = decode_tools_fixture(&too_many, Path::new("tools.json"))
        .test_unwrap_err("tool record ceiling");
    assert!(error.to_string().contains("between 1 and 4096 tools"));
    let raw = br#"[{"name":"scale","inputSchema":{},"execution":{}}]"#;
    let error = decode_tools_fixture(raw, Path::new("tools.json"))
        .test_unwrap_err("unbound execution metadata");
    assert!(error
        .to_string()
        .contains("execution metadata that the signed manifest cannot bind"));
}

#[test]
fn reviewed_tools_file_keeps_the_four_mib_bound() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("tools.json");
    let raw = br#"[{"name":"scale","inputSchema":{"type":"number"}}]"#;
    let mut bytes = raw.to_vec();
    bytes.resize(usize::try_from(MAX_TOOLS_FIXTURE_BYTES)?, b' ');
    std::fs::write(&path, &bytes)?;
    let bounded =
        read_bounded_regular_file(&path, MAX_TOOLS_FIXTURE_BYTES, false, "tools fixture")?;
    assert_eq!(decode_tools_fixture(&bounded, &path)?.len(), 1);
    bytes.push(b' ');
    std::fs::write(&path, &bytes)?;
    let error = read_bounded_regular_file(&path, MAX_TOOLS_FIXTURE_BYTES, false, "tools fixture")
        .test_unwrap_err("oversized fixture");
    assert!(error.to_string().contains("exceeds 4194304 bytes"));
    Ok(())
}

#[test]
fn unsigned_tool_compatibility_does_not_relax_signed_or_canonical_custody() {
    let raw = br#"{"amount":0.50}"#;
    assert!(matches!(
        crate::input::json::<Value>(raw),
        Err(UntrustedJsonError::SignedInput(_))
    ));
    let value = serde_json::json!({"amount":0.5});
    assert!(require_canonical_json(&value, raw, "signed provisioning artifact").is_err());
    let canonical = chio_core::canonical_json_bytes(&value).test_unwrap("canonical control");
    require_canonical_json(&value, &canonical, "signed provisioning artifact")
        .test_unwrap("canonical custody remains accepted");
}
