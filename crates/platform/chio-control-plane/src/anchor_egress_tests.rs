//! An anchor client resolves and checks the anchor name for every request,
//! dials only the checked addresses, sends its bearer token, and refuses
//! redirects without following them.
use super::test_support::{answer_with, SilentListener};
use super::*;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use chio_egress_contract::{ContractLookup, HttpEgressContract, HttpEgressError};

const ANCHOR: &str = "anchor.example:80";
const TIMEOUT: Duration = Duration::from_secs(5);

/// A plaintext client for `ANCHOR` that allows loopback and refuses
/// link-local answers, so a loopback listener can stand in for the anchor.
fn plaintext_client(lookup: ContractLookup) -> Result<AnchorClient, String> {
    let mut contract = HttpEgressContract::permissive_for_tests(ANCHOR);
    contract.max_response_bytes = 1024;
    contract.deny_link_local = true;
    AnchorClient::with_contract(contract, "anchor-token", TIMEOUT, lookup)
}

/// A lookup that answers its first call with `first` and every later call with
/// `later`, counting calls.
fn rotating_lookup(first: SocketAddr, later: SocketAddr) -> (ContractLookup, Arc<AtomicUsize>) {
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
fn serve(responses: Vec<String>) -> Result<(SocketAddr, JoinHandle<Vec<String>>), String> {
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

fn read_request(stream: &mut std::net::TcpStream) -> String {
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

fn ok_json(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn each_request_resolves_the_anchor_name_again() -> Result<(), String> {
    let (first_addr, first) = serve(vec![ok_json(r#"{"n":1}"#)])?;
    let (rotated_addr, rotated) = serve(vec![ok_json(r#"{"n":2}"#)])?;
    let (lookup, lookups) = rotating_lookup(first_addr, rotated_addr);
    let client = plaintext_client(lookup)?;

    let posted = client
        .post_json("http://anchor.example/v1/anchor", br#"{"a":1}"#)
        .map_err(|error| error.to_string())?;
    let fetched = client
        .get("http://anchor.example/v1/anchor")
        .map_err(|error| error.to_string())?;

    assert_eq!(posted, br#"{"n":1}"#);
    assert_eq!(fetched, br#"{"n":2}"#);
    assert_eq!(lookups.load(Ordering::SeqCst), 2);
    let first = first.join().map_err(|_| "server panicked".to_string())?;
    let rotated = rotated.join().map_err(|_| "server panicked".to_string())?;
    let post = first.concat().to_ascii_lowercase();
    assert!(post.starts_with("post /v1/anchor "), "{post}");
    assert!(
        post.contains("authorization: bearer anchor-token"),
        "{post}"
    );
    assert!(post.contains("content-type: application/json"), "{post}");
    assert!(post.ends_with(r#"{"a":1}"#), "{post}");
    let get = rotated.concat().to_ascii_lowercase();
    assert!(get.starts_with("get /v1/anchor "), "{get}");
    assert!(get.contains("authorization: bearer anchor-token"), "{get}");
    Ok(())
}

#[test]
fn rotated_answer_is_checked_before_it_is_dialed() -> Result<(), String> {
    let (first_addr, first) = serve(vec![ok_json("{}")])?;
    let metadata: SocketAddr = "169.254.169.254:80".parse().map_err(|_| "address")?;
    let (lookup, lookups) = rotating_lookup(first_addr, metadata);
    let client = plaintext_client(lookup)?;

    client
        .get("http://anchor.example/v1/anchor")
        .map_err(|error| error.to_string())?;
    let error = match client.get("http://anchor.example/v1/anchor") {
        Ok(body) => return Err(format!("link-local answer was dialed: {body:?}")),
        Err(error) => error,
    };

    assert!(
        matches!(
            &error,
            AnchorHttpError::Egress(HttpEgressError::LinkLocalDenied { host })
                if host == "anchor.example resolved to 169.254.169.254"
        ),
        "{error:?}"
    );
    assert_eq!(lookups.load(Ordering::SeqCst), 2);
    first.join().map_err(|_| "server panicked".to_string())?;
    Ok(())
}

#[test]
fn redirect_is_refused_without_being_followed() -> Result<(), String> {
    let target = SilentListener::bind()?;
    let redirect = format!(
        "HTTP/1.1 302 Found\r\nlocation: http://{}/v1/anchor\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        target.addr()
    );
    let (served, server) = serve(vec![redirect])?;
    let client = plaintext_client(answer_with(served))?;

    let error = match client.get("http://anchor.example/v1/anchor") {
        Ok(body) => return Err(format!("redirect was accepted with body {body:?}")),
        Err(error) => error,
    };

    assert!(matches!(error, AnchorHttpError::Status(302)), "{error:?}");
    assert!(!target.connected()?);
    server.join().map_err(|_| "server panicked".to_string())?;
    Ok(())
}

#[test]
fn anchor_name_answering_loopback_is_refused_before_connecting() -> Result<(), String> {
    let listener = SilentListener::bind()?;
    let endpoint = url::Url::parse("https://anchor.example/api").map_err(|e| e.to_string())?;
    let client = AnchorClient::new(
        &endpoint,
        "control-plane.test-anchor",
        1024,
        "anchor-token",
        TIMEOUT,
        answer_with(listener.addr()),
    )?;

    let error = match client.get("https://anchor.example/api/v1/anchor") {
        Ok(body) => return Err(format!("loopback answer was dialed: {body:?}")),
        Err(error) => error,
    };

    let expected = format!("anchor.example resolved to {}", listener.addr().ip());
    assert!(
        matches!(
            &error,
            AnchorHttpError::Egress(HttpEgressError::LoopbackDenied { host }) if *host == expected
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!("loopback egress target denied: {expected}")
    );
    assert!(!listener.connected()?);
    Ok(())
}
