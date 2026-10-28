use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

fn serve_once(response: &'static str) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let authority = listener.local_addr().expect("address").to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).expect("read") == 0 {
                break;
            }
            request.push(byte[0]);
        }
        stream.write_all(response.as_bytes()).expect("write");
    });
    (authority, handle)
}

fn agent_for(authority: &str, max_response_bytes: u64) -> BlockingContractAgent {
    let mut contract = HttpEgressContract::permissive_for_tests(authority);
    contract.max_response_bytes = max_response_bytes;
    BlockingContractAgent::new(&contract, Duration::from_secs(2)).expect("agent")
}

#[test]
fn request_outside_the_authority_set_is_refused_before_dispatch() {
    let agent = agent_for("127.0.0.1:9", 1024);
    let refusal = agent
        .get("http://127.0.0.2:9/")
        .expect_err("authority outside the contract");
    assert_eq!(
        refusal,
        HttpEgressError::AuthorityDenied {
            authority: "127.0.0.2:9".to_string()
        }
    );
}

#[test]
fn resolver_refusal_surfaces_as_the_contract_error() {
    let agent = agent_for("127.0.0.1:9", 1024);
    let outcome = agent.agent.get("http://unlisted.invalid:9/").call();
    let Err(ureq::Error::Transport(transport)) = outcome else {
        panic!("resolver must refuse the unlisted host");
    };
    assert_eq!(
        transport_failure(transport),
        HttpEgressError::AuthorityDenied {
            authority: "unlisted.invalid".to_string()
        }
    );
}

#[test]
fn error_and_redirect_statuses_are_returned_unfollowed() {
    let (authority, handle) = serve_once(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.2:9/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let response = agent_for(&authority, 1024)
        .get(&format!("http://{authority}/"))
        .expect("allowed")
        .call()
        .expect("response");
    assert_eq!(response.status(), 302);
    handle.join().expect("server");

    let (authority, handle) = serve_once(
        "HTTP/1.1 402 Payment Required\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    );
    let response = agent_for(&authority, 1024)
        .post(&format!("http://{authority}/"))
        .expect("allowed")
        .send_bytes(b"{}")
        .expect("response");
    assert_eq!(response.status(), 402);
    assert_eq!(response.body(), b"{}");
    handle.join().expect("server");
}

#[test]
fn response_over_the_byte_ceiling_is_refused() {
    let (authority, handle) = serve_once(
        "HTTP/1.1 200 OK\r\nContent-Length: 32\r\nConnection: close\r\n\r\n0123456789abcdef0123456789abcdef",
    );
    let refusal = agent_for(&authority, 16)
        .get(&format!("http://{authority}/"))
        .expect("allowed")
        .call()
        .expect_err("body over the ceiling");
    assert_eq!(
        refusal,
        HttpEgressError::ResponseTooLarge {
            observed: 17,
            max: 16
        }
    );
    handle.join().expect("server");
}
