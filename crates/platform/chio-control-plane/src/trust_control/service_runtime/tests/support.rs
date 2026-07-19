use chio_test_support::prelude::*;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CapturedRequest {
    pub(super) method: String,
    pub(super) target: String,
    pub(super) headers: BTreeMap<String, String>,
    pub(super) body: String,
}

pub(super) struct StaticResponseServer {
    pub(super) url: String,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    shutdown: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

pub(super) struct ScriptedResponse {
    pub(super) status: u16,
    pub(super) body: String,
    pub(super) content_type: &'static str,
}

pub(super) struct ScriptedResponseServer {
    pub(super) url: String,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    shutdown: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl ScriptedResponseServer {
    pub(super) fn spawn(responses: Vec<ScriptedResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").test_expect("bind scripted server");
        listener
            .set_nonblocking(true)
            .test_expect("set scripted server nonblocking");
        let addr = listener.local_addr().test_expect("scripted server address");
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = Arc::clone(&captured);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let join = thread::spawn(move || {
            for response in responses {
                let Some(mut stream) = accept_until_shutdown(&listener, &worker_shutdown) else {
                    return;
                };
                let request = read_http_request(&mut stream);
                captured_requests
                    .lock()
                    .test_expect("capture scripted request")
                    .push(request);
                write!(
                    stream,
                    "HTTP/1.1 {} test\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n{}",
                    response.status,
                    response.body.len(),
                    response.content_type,
                    response.body
                )
                .test_expect("write scripted response");
                stream.flush().test_expect("flush scripted response");
            }
        });
        Self {
            url: format!("http://{addr}"),
            captured,
            shutdown,
            join: Some(join),
        }
    }

    pub(super) fn spawn_dynamic<F>(expected_requests: usize, handler: F) -> Self
    where
        F: Fn(&CapturedRequest) -> ScriptedResponse + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").test_expect("bind scripted server");
        listener
            .set_nonblocking(true)
            .test_expect("set dynamic scripted server nonblocking");
        let addr = listener.local_addr().test_expect("scripted server address");
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = Arc::clone(&captured);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let join = thread::spawn(move || {
            for _ in 0..expected_requests {
                let Some(mut stream) = accept_until_shutdown(&listener, &worker_shutdown) else {
                    return;
                };
                let request = read_http_request(&mut stream);
                let response = handler(&request);
                captured_requests
                    .lock()
                    .test_expect("capture scripted request")
                    .push(request);
                write!(
                    stream,
                    "HTTP/1.1 {} test\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n{}",
                    response.status,
                    response.body.len(),
                    response.content_type,
                    response.body
                )
                .test_expect("write scripted response");
                stream.flush().test_expect("flush scripted response");
            }
        });
        Self {
            url: format!("http://{addr}"),
            captured,
            shutdown,
            join: Some(join),
        }
    }

    pub(super) fn requests(&self) -> Vec<CapturedRequest> {
        self.captured
            .lock()
            .test_expect("scripted requests")
            .clone()
    }
}

impl Drop for ScriptedResponseServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let result = join.join();
            if !thread::panicking() {
                result.test_expect("join scripted server");
            }
        }
    }
}

impl StaticResponseServer {
    pub(super) fn spawn(
        status: u16,
        body: &str,
        content_type: &str,
        expected_requests: usize,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").test_expect("bind static response server");
        listener
            .set_nonblocking(true)
            .test_expect("set static response server nonblocking");
        let addr = listener.local_addr().test_expect("server local addr");
        let body = body.to_string();
        let content_type = content_type.to_string();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = Arc::clone(&captured);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let join = thread::spawn(move || {
            for _ in 0..expected_requests {
                let Some(mut stream) = accept_until_shutdown(&listener, &worker_shutdown) else {
                    return;
                };
                let request = read_http_request(&mut stream);
                captured_requests
                    .lock()
                    .test_expect("capture request")
                    .push(request);
                write!(
                    stream,
                    "HTTP/1.1 {status} test\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .test_expect("write response");
                stream.flush().test_expect("flush response");
            }
        });
        Self {
            url: format!("http://{addr}"),
            captured,
            shutdown,
            join: Some(join),
        }
    }

    pub(super) fn requests(&self) -> Vec<CapturedRequest> {
        self.captured
            .lock()
            .test_expect("captured requests")
            .clone()
    }
}

impl Drop for StaticResponseServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let result = join.join();
            if !thread::panicking() {
                result.test_expect("join response server");
            }
        }
    }
}

fn accept_until_shutdown(listener: &TcpListener, shutdown: &AtomicBool) -> Option<TcpStream> {
    loop {
        if shutdown.load(Ordering::Acquire) {
            return None;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .test_expect("set accepted test stream blocking");
                return Some(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("accept test HTTP request failed: {error}"),
        }
    }
}

fn read_http_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut headers_end = None;
    let mut content_length = 0usize;
    loop {
        let read = stream.read(&mut chunk).test_expect("read HTTP request");
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if headers_end.is_none() {
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                headers_end = Some(position + 4);
                content_length =
                    parse_content_length(&String::from_utf8_lossy(&buffer[..position + 4]));
            }
        }
        if let Some(headers_end) = headers_end {
            if buffer.len() >= headers_end + content_length {
                break;
            }
        }
    }

    let headers_end = headers_end.test_expect("HTTP request headers terminator");
    let header_text = String::from_utf8_lossy(&buffer[..headers_end]);
    let mut lines = header_text.split("\r\n").filter(|line| !line.is_empty());
    let request_line = lines.next().test_expect("request line");
    let mut request_line_parts = request_line.split_whitespace();
    let method = request_line_parts
        .next()
        .test_expect("request method")
        .to_string();
    let target = request_line_parts
        .next()
        .test_expect("request target")
        .to_string();
    let headers = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect::<BTreeMap<_, _>>();
    let body = String::from_utf8_lossy(&buffer[headers_end..]).to_string();

    CapturedRequest {
        method,
        target,
        headers,
        body,
    }
}

fn parse_content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

pub(super) fn assert_bearer_request(
    request: &CapturedRequest,
    method: &str,
    path_prefix: &str,
    fragments: &[&str],
) {
    assert_eq!(request.method, method);
    assert!(
        request.target.starts_with(path_prefix),
        "unexpected target: {}",
        request.target
    );
    for fragment in fragments {
        assert!(
            request.target.contains(fragment),
            "expected `{}` in target `{}`",
            fragment,
            request.target
        );
    }
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer secret")
    );
}

pub(super) fn assert_json_post(request: &CapturedRequest, path: &str, body_fragments: &[&str]) {
    assert_bearer_request(request, "POST", path, &[]);
    let content_type = request
        .headers
        .get("content-type")
        .test_expect("content-type header");
    assert!(content_type.starts_with("application/json"));
    for fragment in body_fragments {
        assert!(
            request.body.contains(fragment),
            "expected `{}` in body `{}`",
            fragment,
            request.body
        );
    }
}
