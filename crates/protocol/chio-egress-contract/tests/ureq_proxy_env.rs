//! Runs in its own process because it sets proxy variables for the whole
//! process before any other thread starts.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_egress_contract::{BlockingContractAgent, HttpEgressContract};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

#[test]
fn proxy_environment_variables_are_ignored() {
    let proxy = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy.set_nonblocking(true).expect("nonblocking proxy");
    let proxy_url = format!("http://{}", proxy.local_addr().expect("proxy address"));
    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        std::env::set_var(name, &proxy_url);
    }
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");

    let server = TcpListener::bind("127.0.0.1:0").expect("bind server");
    let authority = server.local_addr().expect("server address").to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = server.accept().expect("accept");
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).expect("read") == 0 {
                break;
            }
            request.push(byte[0]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write");
    });

    let contract = HttpEgressContract::permissive_for_tests(&authority);
    let agent =
        BlockingContractAgent::new(&contract, Duration::from_secs(2), Duration::from_secs(5))
            .expect("agent");
    let response = agent
        .get(&format!("http://{authority}/"))
        .expect("allowed")
        .call()
        .expect("direct response");
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"ok");
    handle.join().expect("server");

    let proxied = proxy.accept().map(|_| ()).map_err(|error| error.kind());
    assert_eq!(proxied, Err(ErrorKind::WouldBlock));
}
