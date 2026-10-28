//! Bounded remote documents; HTTP error bodies never become CLI diagnostics.
use crate::{input, CliError};
use chio_egress_contract::{
    BlockingContractAgent, BlockingContractRequest, BlockingContractResponse, HttpEgressContract,
    HttpEgressError,
};
use serde::de::DeserializeOwned;
use std::time::Duration;

const DOCUMENT_PHASE_TIMEOUT: Duration = Duration::from_secs(30);
const DOCUMENT_DEADLINE: Duration = Duration::from_secs(60);

/// A non-success status. Only the code is kept, never the body.
#[derive(Debug)]
struct UnexpectedStatus(u16);

impl std::fmt::Display for UnexpectedStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "remote document request returned HTTP {}", self.0)
    }
}

impl std::error::Error for UnexpectedStatus {}

fn transport_failure(source: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::with_source(
        &chio_errors::_generated::error_codes::TRANSPORT_HTTP_FAILED,
        source,
    )
}

/// Each document URL gets a contract for its own authority: `https`, or
/// plaintext `http` to a loopback host, no redirects, and the document size
/// ceiling.
fn request(
    url: &str,
    method: fn(&BlockingContractAgent, &str) -> Result<BlockingContractRequest, HttpEgressError>,
) -> Result<BlockingContractRequest, CliError> {
    let contract = HttpEgressContract::single_endpoint(
        "passport-document",
        url,
        input::MAX_DOCUMENT_BYTES as u64,
    )
    .map_err(transport_failure)?;
    let agent = BlockingContractAgent::new(&contract, DOCUMENT_PHASE_TIMEOUT, DOCUMENT_DEADLINE)
        .map_err(transport_failure)?;
    method(&agent, url).map_err(transport_failure)
}

fn document_bytes(
    response: Result<BlockingContractResponse, HttpEgressError>,
) -> Result<Vec<u8>, CliError> {
    let response = response.map_err(transport_failure)?;
    if !(200..300).contains(&response.status()) {
        return Err(transport_failure(UnexpectedStatus(response.status())));
    }
    Ok(response.body().to_vec())
}

pub(super) fn fetch_json_url<T: DeserializeOwned>(url: &str) -> Result<T, CliError> {
    let bytes = document_bytes(request(url, BlockingContractAgent::get)?.call())?;
    Ok(input::json(&bytes)?)
}

pub(super) fn fetch_text_url(url: &str) -> Result<String, CliError> {
    let bytes = document_bytes(request(url, BlockingContractAgent::get)?.call())?;
    String::from_utf8(bytes).map_err(|source| {
        CliError::with_source(&chio_errors::_generated::error_codes::CLI_JSON, source)
    })
}

pub(super) fn post_json_url<B: serde::Serialize, T: DeserializeOwned>(
    url: &str,
    body: &B,
) -> Result<T, CliError> {
    let body = serde_json::to_vec(body)?;
    let bytes = document_bytes(
        request(url, BlockingContractAgent::post)?
            .header("Content-Type", "application/json")
            .send_bytes(&body),
    )?;
    Ok(input::json(&bytes)?)
}

pub(super) fn post_form_url<T: DeserializeOwned>(
    url: &str,
    fields: &[(&str, &str)],
) -> Result<T, CliError> {
    let body = serde_urlencoded::to_string(fields).map_err(transport_failure)?;
    let bytes = document_bytes(
        request(url, BlockingContractAgent::post)?
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send_bytes(body.as_bytes()),
    )?;
    Ok(input::json(&bytes)?)
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

    fn serve_once(reply: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/document", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request_head(&mut stream);
            let _ = stream.write_all(&reply);
        });
        (url, server)
    }

    fn reply(status: &str, body: &[u8]) -> Vec<u8> {
        let mut reply = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        reply.extend_from_slice(body);
        reply
    }

    fn egress_refusal(error: &CliError) -> Option<HttpEgressError> {
        let mut source = std::error::Error::source(error);
        while let Some(cause) = source {
            if let Some(refusal) = cause.downcast_ref::<HttpEgressError>() {
                return Some(refusal.clone());
            }
            source = cause.source();
        }
        None
    }

    #[test]
    fn remote_document_limits_and_original_duplicate_rejection() {
        let (url, server) = serve_once(reply("200 OK", br#"{"rule":1,"rule":2}"#));
        assert!(fetch_json_url::<serde_json::Value>(&url).is_err());
        server.join().unwrap();

        let large = vec![b'x'; input::MAX_DOCUMENT_BYTES + 1];
        let (url, server) = serve_once(reply("200 OK", &large));
        let error = fetch_text_url(&url).unwrap_err();
        assert_eq!(
            egress_refusal(&error),
            Some(HttpEgressError::ResponseTooLarge {
                observed: input::MAX_DOCUMENT_BYTES as u64 + 1,
                max: input::MAX_DOCUMENT_BYTES as u64,
            })
        );
        server.join().unwrap();

        let (url, server) = serve_once(reply("403 Forbidden", b"private-marker"));
        let error = fetch_text_url(&url).unwrap_err();
        assert!(std::error::Error::source(&error).is_some());
        assert!(!format!("{error:?} {error}").contains("private-marker"));
        server.join().unwrap();
    }

    #[test]
    fn non_public_and_plaintext_document_urls_are_refused_before_dispatch() {
        for (url, refusal) in [
            (
                "https://169.254.169.254/latest/meta-data",
                HttpEgressError::LinkLocalDenied {
                    host: "169.254.169.254".to_string(),
                },
            ),
            (
                "https://10.0.0.1/document",
                HttpEgressError::PrivateNetworkDenied {
                    host: "10.0.0.1".to_string(),
                },
            ),
            (
                "http://verifier.example/document",
                HttpEgressError::SchemeDenied {
                    scheme: "http".to_string(),
                },
            ),
        ] {
            let error = fetch_text_url(url).unwrap_err();
            assert_eq!(egress_refusal(&error), Some(refusal), "{url}");
        }
    }
}
