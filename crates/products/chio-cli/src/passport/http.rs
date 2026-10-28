//! Bounded remote documents; HTTP error bodies never become CLI diagnostics.
use crate::{input, CliError};
use serde::de::DeserializeOwned;
use std::time::Duration;

fn agent() -> ureq::Agent {
    // CHIO_EGRESS_LINT_ALLOW_DIRECT_UREQ: operator CLI fetch of a document URL the operator named
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
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    fn read_request_head(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
            head.push(byte[0]);
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    #[test]
    fn redirect_to_a_second_authority_is_not_followed() {
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let second_address = second.local_addr().unwrap();
        let second_server = std::thread::spawn(move || {
            let (mut stream, _) = second.accept().unwrap();
            let head = read_request_head(&mut stream);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            );
            head.starts_with("GET /document ")
        });
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/document", first.local_addr().unwrap());
        let first_server = std::thread::spawn(move || {
            let (mut stream, _) = first.accept().unwrap();
            read_request_head(&mut stream);
            let reply = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{second_address}/document\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(reply.as_bytes());
        });

        let outcome = fetch_json_url::<serde_json::Value>(&url);
        first_server.join().unwrap();
        let _ = TcpStream::connect(second_address)
            .and_then(|mut probe| probe.write_all(b"GET /probe HTTP/1.1\r\n\r\n"));
        assert!(
            !second_server.join().unwrap(),
            "the passport document fetch followed a redirect to a second authority"
        );
        assert!(outcome.is_err());
    }

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
