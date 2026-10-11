//! The unsigned discovery envelope keeps ordinary JSON numeric spellings.
use super::*;
use chio_test_support::ctx::TestUnwrap;
use std::io::Seek;

#[test]
fn discovery_accepts_unsigned_schema_number_spellings() {
    for (token, expected) in [("0.50", 0.5), ("1e-05", 0.00001), ("1.00", 1.0)] {
        let raw = format!(
            r#"{{"jsonrpc":"2.0","id":2,"result":{{"tools":[{{"name":"scale","inputSchema":{{"type":"number","multipleOf":{token}}}}}]}}}}"#
        );
        let reply = parse_message(raw.as_bytes()).test_unwrap("unsigned discovery response");
        let Some(DiscoveryReply::Tools(tools)) = reply else {
            panic!("discovery did not return its tools array");
        };
        assert_eq!(
            tools
                .pointer("/0/inputSchema/multipleOf")
                .and_then(Value::as_f64),
            Some(expected),
            "numeric meaning changed for {token}"
        );
    }
}

#[test]
fn discovery_still_rejects_nested_duplicate_schema_keys() {
    let raw = br#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"scale","inputSchema":{"minimum":1,"minimum":2}}]}}"#;
    assert!(matches!(parse_message(raw), Err(error) if error ==
        "the target sent invalid JSON-RPC: urn:chio:error:attest:signed-json-invalid-input"));
}

#[test]
fn discovery_keeps_the_original_response_line_bound() -> std::io::Result<()> {
    let stdin = tempfile::tempfile()?;
    let mut stdout = tempfile::tempfile()?;
    stdout.write_all(&vec![b' '; MAX_RESPONSE_LINE_BYTES + 1])?;
    stdout.rewind()?;
    let outcome = exchange_until(
        stdin,
        stdout,
        tempfile::tempfile()?,
        Instant::now() + Duration::from_secs(5),
    );
    assert_eq!(
        outcome,
        Err("MCP response exceeds the size limit".to_string())
    );
    Ok(())
}
