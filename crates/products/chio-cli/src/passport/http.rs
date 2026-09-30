//! Bounded remote documents; HTTP error bodies never become CLI diagnostics.
use crate::{input, CliError};
use serde::de::DeserializeOwned;
use std::time::Duration;

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build()
}

fn response_bytes(response: Result<ureq::Response, ureq::Error>) -> Result<Vec<u8>, CliError> {
    let response = response.map_err(|source| {
        CliError::with_source(
            &chio_errors::_generated::error_codes::TRANSPORT_HTTP_FAILED,
            source,
        )
    })?;
    Ok(input::read_stream(
        response.into_reader(),
        input::MAX_DOCUMENT_BYTES,
    )?)
}

pub(super) fn fetch_json_url<T: DeserializeOwned>(url: &str) -> Result<T, CliError> {
    Ok(input::json(&response_bytes(agent().get(url).call())?)?)
}

pub(super) fn fetch_text_url(url: &str) -> Result<String, CliError> {
    String::from_utf8(response_bytes(agent().get(url).call())?).map_err(|source| {
        CliError::with_source(&chio_errors::_generated::error_codes::CLI_JSON, source)
    })
}

pub(super) fn post_json_url<B: serde::Serialize, T: DeserializeOwned>(
    url: &str,
    body: &B,
) -> Result<T, CliError> {
    Ok(input::json(&response_bytes(
        agent().post(url).send_json(serde_json::to_value(body)?),
    )?)?)
}

pub(super) fn post_form_url<T: DeserializeOwned>(
    url: &str,
    fields: &[(&str, &str)],
) -> Result<T, CliError> {
    let body = serde_urlencoded::to_string(fields).map_err(|source| {
        CliError::with_source(
            &chio_errors::_generated::error_codes::TRANSPORT_HTTP_FAILED,
            source,
        )
    })?;
    Ok(input::json(&response_bytes(
        agent()
            .post(url)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&body),
    )?)?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn remote_document_limits_and_original_duplicate_rejection() {
        let response = ureq::Response::new(200, "OK", r#"{"rule":1,"rule":2}"#).unwrap();
        let bytes = response_bytes(Ok(response)).unwrap();
        assert!(input::json::<serde_json::Value>(&bytes).is_err());
        let large = "x".repeat(input::MAX_DOCUMENT_BYTES + 1);
        let response = ureq::Response::new(200, "OK", &large).unwrap();
        assert!(response_bytes(Ok(response)).is_err());
        let response = ureq::Response::new(403, "Forbidden", "private-marker").unwrap();
        let error = response_bytes(Err(ureq::Error::Status(403, response))).unwrap_err();
        assert!(std::error::Error::source(&error).is_some());
        assert!(!format!("{error:?} {error}").contains("private-marker"));
    }
}
