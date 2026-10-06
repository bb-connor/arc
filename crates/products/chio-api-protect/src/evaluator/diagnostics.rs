//! Closed local projection of native capability input failures before conversion.
use chio_core_types::canonical::{SharedUntrustedJsonError, UntrustedJsonError};
use std::error::Error;

pub(super) fn record_capability_input_error(error: &SharedUntrustedJsonError) {
    let mut causes = Vec::new();
    let mut source: Option<&(dyn Error + 'static)> = Some(error);
    for _ in 0..4 {
        let Some(cause) = source else { break };
        let cause_record = if let Some(error) = cause.downcast_ref::<SharedUntrustedJsonError>() {
            serde_json::json!({"class":"shared_json", "code":error.code()})
        } else if let Some(error) = cause.downcast_ref::<UntrustedJsonError>() {
            serde_json::json!({"class":"original_json", "code":error.code()})
        } else if let Some(error) = cause.downcast_ref::<serde_json::Error>() {
            let category = match error.classify() {
                serde_json::error::Category::Io => "io",
                serde_json::error::Category::Syntax => "syntax",
                serde_json::error::Category::Data => "data",
                serde_json::error::Category::Eof => "eof",
            };
            serde_json::json!({"class":"json_parser", "category":category, "line":error.line(), "column":error.column()})
        } else if cause.is::<chio_core_types::Error>() {
            serde_json::json!({"class":"core_validation"})
        } else {
            serde_json::json!({"class":"native_error"})
        };
        causes.push(cause_record);
        source = cause.source();
    }
    // Arbitrary parser messages, credentials, caller identifiers and request
    // metadata remain out of this operator projection and all peer results.
    let event = serde_json::json!({
        "event":"api_protect_capability_input_error",
        "code":error.code(), "causes":causes, "truncated":source.is_some(),
    });
    use std::io::Write as _;
    if let Ok(mut encoded) = serde_json::to_vec(&event) {
        if encoded.len() < 2048 {
            encoded.push(b'\n');
            let _ = std::io::stderr().lock().write_all(&encoded);
        }
    }
}
