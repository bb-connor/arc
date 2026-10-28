//! Scripted loopback HTTP server that answers a fixed sequence of JSON responses, one
//! connection each, and hands every captured request back to the test.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub(crate) fn spawn_once_json_server(
    status_code: u16,
    body: serde_json::Value,
) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    spawn_json_server(vec![(status_code, body)])
}

pub(crate) fn spawn_json_server(
    responses: Vec<(u16, serde_json::Value)>,
) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let address = listener
        .local_addr()
        .expect("listener should expose local address");
    let (request_tx, request_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        for (status_code, body) in responses {
            let mut stream = accept_bounded(&listener);
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("server should configure read timeout");
            let request = read_request(&mut stream);
            request_tx
                .send(request)
                .expect("request should be sent to test");
            let body_text = body.to_string();
            let response = format!(
                "HTTP/1.1 {status_code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_text(status_code),
                body_text.len(),
                body_text
            );
            stream
                .write_all(response.as_bytes())
                .expect("server should write response");
        }
    });
    (format!("http://{address}"), request_rx, handle)
}

const ACCEPT_POLL: Duration = Duration::from_millis(10);
const ACCEPT_ATTEMPTS: u32 = 500;

/// Accept the next request, or fail the scripted server after about five seconds so a
/// request the adapter never sends fails the test instead of hanging it.
fn accept_bounded(listener: &TcpListener) -> TcpStream {
    listener
        .set_nonblocking(true)
        .expect("listener should become nonblocking");
    for _ in 0..ACCEPT_ATTEMPTS {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("stream should become blocking");
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(error) => panic!("scripted server accept failed: {error}"),
        }
    }
    panic!("scripted server expected a request that never arrived");
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let mut header_end = None;
    let mut content_length = 0_usize;
    loop {
        let read = stream
            .read(&mut chunk)
            .expect("server should read request bytes");
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if header_end.is_none() {
            header_end = find_header_end(&request);
            if let Some(end) = header_end {
                content_length = parse_content_length(&request[..end]);
            }
        }
        if let Some(end) = header_end {
            if request.len() >= end + content_length {
                break;
            }
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers);
    text.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn status_text(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        402 => "Payment Required",
        _ => "Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_request_fails_the_scripted_server_instead_of_hanging() {
        let (_url, _requests, handle) = spawn_once_json_server(200, serde_json::json!({}));
        let failure = handle
            .join()
            .expect_err("a scripted server whose request never arrives must fail");
        assert_eq!(
            failure.downcast_ref::<&str>(),
            Some(&"scripted server expected a request that never arrived")
        );
    }
}
