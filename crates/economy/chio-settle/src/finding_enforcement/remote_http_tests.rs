//! A remote JSON client resolves and checks its endpoint name for every post,
//! dials only the checked addresses and sends its bearer token.
use super::remote_http::RemoteJsonClient;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use chio_egress_contract::{ContractLookup, HttpEgressContract, HttpEgressError};

const TIMEOUT: Duration = Duration::from_secs(5);

pub(super) const METADATA: &str = "169.254.169.254:80";

/// A plaintext client for `host` on port 80 that allows loopback and refuses
/// link-local answers, so a loopback listener can stand in for the endpoint.
pub(super) fn plaintext_client(
    host: &str,
    lookup: ContractLookup,
) -> Result<RemoteJsonClient, String> {
    let mut contract = HttpEgressContract::permissive_for_tests(&format!("{host}:80"));
    contract.max_response_bytes = 1024;
    contract.deny_link_local = true;
    RemoteJsonClient::new(
        contract,
        &format!("http://{host}/"),
        "remote-token",
        TIMEOUT,
        lookup,
    )
    .map_err(|error| error.to_string())
}

/// A lookup that answers its first call with `first` and every later call with
/// `later`, counting calls.
pub(super) fn rotating_lookup(
    first: SocketAddr,
    later: SocketAddr,
) -> (ContractLookup, Arc<AtomicUsize>) {
    let lookups = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&lookups);
    let lookup = ContractLookup::new(move |_host: &str, _port: u16| {
        let answer = if counted.fetch_add(1, Ordering::SeqCst) == 0 {
            first
        } else {
            later
        };
        Ok(vec![answer])
    });
    (lookup, lookups)
}

/// Answers one connection per response, in order, and returns each request.
pub(super) fn serve(
    responses: Vec<String>,
) -> Result<(SocketAddr, JoinHandle<Vec<String>>), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    let addr = listener.local_addr().map_err(|error| error.to_string())?;
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for response in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            requests.push(read_request(&mut stream));
            let _ = stream.write_all(response.as_bytes());
        }
        requests
    });
    Ok((addr, handle))
}

fn read_request(stream: &mut TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(TIMEOUT));
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    while let Ok(read) = stream.read(&mut chunk) {
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        let text = String::from_utf8_lossy(&request);
        if let Some(head_end) = text.find("\r\n\r\n") {
            let body_len = text[..head_end]
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if request.len() >= head_end + 4 + body_len {
                break;
            }
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

pub(super) fn ok_json(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn each_post_resolves_the_endpoint_name_again() -> Result<(), String> {
    let (first_addr, first) = serve(vec![ok_json(r#"{"n":1}"#)])?;
    let (rotated_addr, rotated) = serve(vec![ok_json(r#"{"n":2}"#)])?;
    let (lookup, lookups) = rotating_lookup(first_addr, rotated_addr);
    let client = plaintext_client("remote.example", lookup)?;

    let first_body = client
        .post_json("/v1/first", br#"{"a":1}"#)
        .map_err(|error| error.to_string())?;
    let rotated_body = client
        .post_json("/v1/second", br#"{"a":2}"#)
        .map_err(|error| error.to_string())?;

    assert_eq!(first_body.body(), br#"{"n":1}"#);
    assert_eq!(rotated_body.body(), br#"{"n":2}"#);
    assert_eq!(lookups.load(Ordering::SeqCst), 2);
    let first = first.join().map_err(|_| "server panicked")?.concat();
    let rotated = rotated.join().map_err(|_| "server panicked")?.concat();
    for (request, path, body) in [
        (first, "/v1/first", r#"{"a":1}"#),
        (rotated, "/v1/second", r#"{"a":2}"#),
    ] {
        let request = request.to_ascii_lowercase();
        assert!(request.starts_with(&format!("post {path} ")), "{request}");
        assert!(
            request.contains("authorization: bearer remote-token"),
            "{request}"
        );
        assert!(
            request.contains("content-type: application/json"),
            "{request}"
        );
        assert!(request.ends_with(body), "{request}");
    }
    Ok(())
}

#[test]
fn rotated_link_local_answer_is_refused_before_it_is_dialed() -> Result<(), String> {
    let (first_addr, first) = serve(vec![ok_json("{}")])?;
    let metadata: SocketAddr = METADATA.parse().map_err(|_| "address")?;
    let (lookup, lookups) = rotating_lookup(first_addr, metadata);
    let client = plaintext_client("remote.example", lookup)?;

    client
        .post_json("/v1/first", b"{}")
        .map_err(|error| error.to_string())?;
    let error = match client.post_json("/v1/second", b"{}") {
        Ok(response) => return Err(format!("link-local answer was dialed: {response:?}")),
        Err(error) => error,
    };

    assert!(
        matches!(
            &error,
            HttpEgressError::LinkLocalDenied { host }
                if host == "remote.example resolved to 169.254.169.254"
        ),
        "{error:?}"
    );
    assert_eq!(lookups.load(Ordering::SeqCst), 2);
    first.join().map_err(|_| "server panicked")?;
    Ok(())
}
