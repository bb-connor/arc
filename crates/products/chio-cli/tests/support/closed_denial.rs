use serde_json::Value;

/// A kernel denial reaches the client as its closed code and fixed text only;
/// the detail stays in the signed receipt.
pub(crate) fn assert_closed_denial(result: &Value, code: &str) {
    let denial = chio_kernel::ClientDenialCode::from_code(code).expect("closed denial code");
    assert_eq!(result["isError"], true, "{result:#}");
    assert_eq!(
        result["structuredContent"]["code"].as_str(),
        Some(code),
        "{result:#}"
    );
    assert_eq!(
        result["content"][0]["text"].as_str(),
        Some(denial.text()),
        "{result:#}"
    );
}
