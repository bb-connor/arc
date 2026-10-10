//! Closed operator cause projection for the hosted HTTP error boundary.
use super::{ClockError, HostedEdgeError};

// Only closed native cause classes enter the operator sink. Parser messages
// can contain credentials or rejected fields and stay in the typed source.
fn operator_error_diagnostic(error: &HostedEdgeError) -> serde_json::Value {
    let mut causes = Vec::new();
    let mut source = std::error::Error::source(error);
    for _ in 0..4 {
        let Some(cause) = source else {
            break;
        };
        let value = if let Some(error) =
            cause.downcast_ref::<chio_core_types::canonical::SharedUntrustedJsonError>()
        {
            serde_json::json!({ "class": "shared_json", "code": error.code() })
        } else if let Some(error) =
            cause.downcast_ref::<chio_core_types::canonical::UntrustedJsonError>()
        {
            serde_json::json!({ "class": "original_json", "code": error.code() })
        } else if let Some(error) = cause.downcast_ref::<serde_json::Error>() {
            serde_json::json!({ "class": "json_parser", "category": format!("{:?}", error.classify()), "line": error.line(), "column": error.column() })
        } else if let Some(error) = cause.downcast_ref::<ClockError>() {
            serde_json::json!({ "class": "authority_clock", "code": error.code() })
        } else if cause.is::<chio_core_types::Error>() {
            serde_json::json!({ "class": "core_validation" })
        } else {
            serde_json::json!({ "class": "native_error" })
        };
        causes.push(value);
        source = cause.source();
    }
    serde_json::json!({ "event": "hosted_request_error", "code": error.code(), "status": error.http_status(), "retryable": error.retryable(), "causes": causes, "truncated": source.is_some() })
}

pub(super) fn record(error: &HostedEdgeError) {
    use std::io::Write as _;
    if let Ok(mut record) = serde_json::to_vec(&operator_error_diagnostic(error)) {
        if record.len() < 2048 {
            record.push(b'\n');
            let _ = std::io::stderr().lock().write_all(&record);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{error_response, to_bytes, StatusCode};
    use super::*;

    #[tokio::test]
    async fn hosted_http_diagnostic_records_operator_cause_without_peer_disclosure(
    ) -> Result<(), Box<dyn std::error::Error>> {
        const CHILD: &str = "CHIO_HOSTED_DIAGNOSTIC_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let source = chio_core_types::canonical::UntrustedJsonText::from_wire(
                br#"{"private-marker\nline":1,"private-marker\nline":2}"#,
                1024,
            )?
            .decode_signed::<serde_json::Value>()
            .err()
            .ok_or("duplicate accepted")?;
            let response = error_response(
                HostedEdgeError::CorruptInput(source.into()),
                "\r\nprivate-request",
            );
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let bytes = to_bytes(response.into_body(), 4096).await?;
            assert!(!String::from_utf8_lossy(&bytes).contains("private"));
            return Ok(());
        }
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "server::operator_diagnostics::tests::hosted_http_diagnostic_records_operator_cause_without_peer_disclosure", "--nocapture"])
            .env(CHILD, "1").output()?;
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let diagnostic = String::from_utf8(output.stderr)?;
        assert!(
            diagnostic.contains("integrity_failure"),
            "operator category lost: {diagnostic}"
        );
        assert!(
            diagnostic.contains("signed-json-invalid-input"),
            "native parser category lost: {diagnostic}"
        );
        assert!(!diagnostic.contains("private"));
        assert!(diagnostic.len() <= 2048);
        assert_eq!(diagnostic.lines().count(), 1);
        Ok(())
    }
}
