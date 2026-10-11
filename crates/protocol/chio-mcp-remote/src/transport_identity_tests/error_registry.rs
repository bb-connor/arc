use super::*;
use chio_errors::{lookup_error_code, Domain, Severity};

fn assert_registered_proxy_refusal(error: ProxyRejection, expected_string_code: &str) {
    let urn = error.to_string();
    let spec = lookup_error_code(&urn)
        .unwrap_or_else(|| panic!("production proxy refusal is absent from registry: {urn}"));
    assert_eq!(spec.domain, Domain::Transport);
    assert_eq!(spec.severity, Severity::Error);
    assert_eq!(spec.string_code, expected_string_code);
    assert!(spec.consumed_by.contains(&"chio-mcp-remote"));
    let diagnostic = chio_errors::Diagnostic::from_spec(spec, "proxy rejected");
    assert_eq!(diagnostic.registry_spec(), Some(spec));
    assert!(diagnostic.help().is_some_and(|help| !help.is_empty()));
}

#[test]
fn ambiguous_proxy_header_emits_registered_diagnostic() -> TestResult {
    let mut headers = HeaderMap::new();
    headers.append(PROXY_AUTH, HeaderValue::from_static("first"));
    headers.append(PROXY_AUTH, HeaderValue::from_static("second"));
    let error = match single_header(&headers, PROXY_AUTH, 512) {
        Err(error) => error,
        Ok(_) => return Err("ambiguous proxy credential admitted".into()),
    };
    assert!(matches!(error, ProxyRejection::Untrusted));
    assert_registered_proxy_refusal(error, "CHIO-TRANSPORT-UNTRUSTED-PROXY");
    Ok(())
}

#[test]
fn non_text_proxy_header_emits_registered_diagnostic() -> TestResult {
    let mut headers = HeaderMap::new();
    headers.insert(PROXY_AUTH, HeaderValue::from_bytes(b"private-marker\xff")?);
    let error = match single_header(&headers, PROXY_AUTH, 512) {
        Err(error) => error,
        Ok(_) => return Err("non-text proxy credential admitted".into()),
    };
    assert!(matches!(error, ProxyRejection::Header(_)));
    assert!(std::error::Error::source(&error)
        .is_some_and(|source| source.is::<axum::http::header::ToStrError>()));
    assert!(!format!("{error:?} {error}").contains("private-marker"));
    assert_registered_proxy_refusal(error, "CHIO-TRANSPORT-INVALID-PROXY-HEADER");
    Ok(())
}
