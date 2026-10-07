//! The actual recovery CLI keeps a pinned local host, one attempt, and bounded output.
use chio_core_types::{
    Keypair, canonical_json_bytes,
    capability::{
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    },
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Observations = Vec<Vec<u8>>;

fn fixture_io_error(
    phase: &str,
    error: &std::io::Error,
    request_bytes: usize,
    response_bytes: usize,
    observed_requests: usize,
) {
    eprintln!(
        "CLI_FIXTURE_IO_ERROR phase={phase} kind={:?} os_code={:?} \
         request_bytes={request_bytes} response_bytes={response_bytes} \
         observed_requests={observed_requests}",
        error.kind(),
        error.raw_os_error(),
    );
}

struct LocalHost {
    endpoint: String,
    stop: Arc<AtomicBool>,
    body_withheld: Arc<AtomicBool>,
    worker: Option<JoinHandle<std::io::Result<Observations>>>,
}

struct HeldResponseBodies {
    streams: Vec<TcpStream>,
    active: Arc<AtomicBool>,
}

impl Drop for HeldResponseBodies {
    fn drop(&mut self) {
        // Clear the proof state before closing any pending socket. An EOF
        // cannot stand in for refusal while a response body is unavailable.
        self.active.store(false, Ordering::SeqCst);
    }
}

impl LocalHost {
    fn start(response: Vec<u8>) -> TestResult<Self> {
        Self::start_inner(response, None)
    }

    fn withhold_body(headers: Vec<u8>, sent: Sender<()>) -> TestResult<Self> {
        Self::start_inner(headers, Some(sent))
    }

    fn start_inner(response: Vec<u8>, headers_sent: Option<Sender<()>>) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let stop = Arc::new(AtomicBool::new(false));
        let body_withheld = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker_withheld = body_withheld.clone();
        let worker = thread::spawn(move || {
            let started = Instant::now();
            let mut observations = Vec::new();
            let mut held = HeldResponseBodies {
                streams: Vec::new(),
                active: worker_withheld,
            };
            while !worker_stop.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(10)
            {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::park_timeout(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => {
                        fixture_io_error("accept", &error, 0, response.len(), observations.len());
                        return Err(error);
                    }
                };
                // Normalize accepted sockets before timed blocking IO on
                // platforms that inherit the listener's nonblocking mode.
                stream.set_nonblocking(false).inspect_err(|error| {
                    fixture_io_error(
                        "configure_blocking_mode",
                        error,
                        0,
                        response.len(),
                        observations.len(),
                    );
                })?;
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .inspect_err(|error| {
                        fixture_io_error(
                            "configure_read_timeout",
                            error,
                            0,
                            response.len(),
                            observations.len(),
                        );
                    })?;
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .inspect_err(|error| {
                        fixture_io_error(
                            "configure_write_timeout",
                            error,
                            0,
                            response.len(),
                            observations.len(),
                        );
                    })?;
                let mut wire = Vec::new();
                loop {
                    let mut part = [0; 4096];
                    let length = stream.read(&mut part).inspect_err(|error| {
                        fixture_io_error(
                            "request_read",
                            error,
                            wire.len(),
                            response.len(),
                            observations.len(),
                        );
                    })?;
                    if length == 0 {
                        return Err(std::io::Error::other("truncated recovery request"));
                    }
                    wire.extend_from_slice(&part[..length]);
                    if wire.len() > 65536 {
                        return Err(std::io::Error::other(
                            "recovery request exceeds fixture bound",
                        ));
                    }
                    if let Some(header_end) = wire.windows(4).position(|part| part == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&wire[..header_end])
                            .map_err(std::io::Error::other)?;
                        let content_length = headers.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then_some(value.trim())
                        });
                        let content_length = content_length
                            .map(str::parse::<usize>)
                            .transpose()
                            .map_err(std::io::Error::other)?
                            .unwrap_or(0);
                        if wire.len() >= header_end + 4 + content_length {
                            break;
                        }
                    }
                }
                eprintln!(
                    "CLI_FIXTURE_REQUEST_COMPLETE request_bytes={} response_bytes={} \
                     observed_requests={}",
                    wire.len(),
                    response.len(),
                    observations.len() + 1,
                );
                observations.push(wire);
                if let Err(error) = stream.write_all(&response) {
                    fixture_io_error(
                        "response_write",
                        &error,
                        observations.last().map_or(0, Vec::len),
                        response.len(),
                        observations.len(),
                    );
                    if !matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ) {
                        return Err(error);
                    }
                } else if let Some(sent) = &headers_sent {
                    held.streams.push(stream);
                    held.active.store(true, Ordering::SeqCst);
                    sent.send(()).map_err(std::io::Error::other)?;
                }
            }
            Ok(observations)
        });
        Ok(Self {
            endpoint,
            stop,
            body_withheld,
            worker: Some(worker),
        })
    }

    fn finish(mut self) -> TestResult<Observations> {
        self.stop.store(true, Ordering::SeqCst);
        let worker = self.worker.take().ok_or("host worker missing")?;
        worker.thread().unpark();
        Ok(worker.join().map_err(|_| "host worker panicked")??)
    }
}

impl Drop for LocalHost {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
    }
}

fn response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut wire = format!("HTTP/1.1 {status}\r\nConnection: close\r\n{headers}\r\n").into_bytes();
    wire.extend_from_slice(body);
    wire
}

fn capability() -> TestResult<Vec<u8>> {
    let key = Keypair::from_seed(&[18; 32]);
    Ok(canonical_json_bytes(&CapabilityToken::sign(
        CapabilityTokenBody {
            id: "recovery-transport-capability".into(),
            issuer: key.public_key(),
            subject: key.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "chio.recovery".into(),
                    tool_name: "inspect".into(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..Default::default()
            },
            issued_at: 1,
            expires_at: 2,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &key,
    )?)?)
}

fn prepared_invocation(endpoint: &str, proxy: &str) -> TestResult<(tempfile::TempDir, Command)> {
    let directory = tempfile::tempdir()?;
    let cap_file = directory.path().join("capability.json");
    let command_file = directory.path().join("command.json");
    std::fs::write(&cap_file, capability()?)?;
    // The transport retains these exact opaque bytes; only the native host
    // decides whether the command is valid or has authority.
    std::fs::write(&command_file, br#"{"command_id":"original-command"}"#)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command
        .args([
            "recovery",
            "command",
            "--endpoint",
            endpoint,
            "--capability",
        ])
        .arg(cap_file)
        .arg("--command")
        .arg(command_file)
        .env("HTTP_PROXY", proxy)
        .env("http_proxy", proxy)
        .env("HTTPS_PROXY", proxy)
        .env("https_proxy", proxy)
        .env("ALL_PROXY", proxy)
        .env("all_proxy", proxy)
        .env("NO_PROXY", "")
        .env("no_proxy", "");
    Ok((directory, command))
}

fn record_child_output(output: &Output) {
    eprintln!(
        "CLI_CHILD_OUTPUT success={} exit_code={:?} stdout_bytes={} stderr_bytes={}",
        output.status.success(),
        output.status.code(),
        output.stdout.len(),
        output.stderr.len(),
    );
}

fn invoke(endpoint: &str, proxy: &str) -> TestResult<Output> {
    let (_directory, mut command) = prepared_invocation(endpoint, proxy)?;
    let output = command
        .output()
        .inspect_err(|error| fixture_io_error("child_output", error, 0, 0, 0))?;
    record_child_output(&output);
    Ok(output)
}

fn invoke_before_body(endpoint: &str, headers_sent: &Receiver<()>) -> TestResult<(Output, bool)> {
    let (_directory, mut command) = prepared_invocation(endpoint, "")?;
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let received_headers = headers_sent.recv_timeout(Duration::from_secs(10)).is_ok();
    let completed = (|| -> std::io::Result<bool> {
        if !received_headers {
            return Ok(false);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if child.try_wait()?.is_some() {
                return Ok(true);
            }
            thread::park_timeout(Duration::from_millis(5));
        }
        Ok(false)
    })();
    // Reap the child even if monitoring fails or the refusal never arrives.
    // A forced exit is reported as a failed timing proof, never as a refusal.
    let cleanup = if matches!(completed, Ok(true)) {
        Ok(())
    } else {
        child.kill()
    };
    let output = child.wait_with_output()?;
    record_child_output(&output);
    cleanup?;
    let completed = completed?;
    eprintln!(
        "CLI_DECLARED_SIZE_PROOF headers_sent={received_headers} \
         exited_before_body_release={completed}",
    );
    Ok((output, completed))
}

#[test]
fn recovery_cli_ignores_ambient_proxies_for_the_pinned_native_host() -> TestResult {
    let host = LocalHost::start(response("200 OK", "Content-Length: 2\r\n", b"{}"))?;
    let proxy = LocalHost::start(response("502 Bad Gateway", "Content-Length: 0\r\n", b""))?;
    let output = invoke(&host.endpoint, &proxy.endpoint)?;
    let host_requests = host.finish()?;
    let proxy_requests = proxy.finish()?;
    eprintln!(
        "CLI_NETWORK_OBSERVATIONS pinned_requests={} proxy_requests={} success={}",
        host_requests.len(),
        proxy_requests.len(),
        output.status.success()
    );
    assert!(
        output.status.success(),
        "pinned host failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host_requests.len(),
        1,
        "pinned native host was not reached exactly once"
    );
    assert!(
        proxy_requests.is_empty(),
        "ambient proxy received native authority bytes"
    );
    assert!(host_requests[0].starts_with(b"POST /v1/recovery/commands "));
    let body_start = host_requests[0]
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .ok_or("request header")?
        + 4;
    let request: serde_json::Value = serde_json::from_slice(&host_requests[0][body_start..])?;
    assert_eq!(request["command"], r#"{"command_id":"original-command"}"#);
    assert_eq!(
        request["capability"]
            .as_str()
            .ok_or("capability field")?
            .as_bytes(),
        capability()?
    );
    Ok(())
}

#[test]
fn recovery_cli_refuses_redirects_without_forwarding_authority() -> TestResult {
    let target = LocalHost::start(response("200 OK", "Content-Length: 2\r\n", b"{}"))?;
    let host = LocalHost::start(response(
        "307 Temporary Redirect",
        &format!(
            "Content-Length: 0\r\nLocation: {}/secret\r\n",
            target.endpoint
        ),
        b"",
    ))?;
    let output = invoke(&host.endpoint, "")?;
    assert_eq!(host.finish()?.len(), 1);
    assert!(
        target.finish()?.is_empty(),
        "redirect destination received native authority"
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("secret"));
    Ok(())
}

#[test]
fn recovery_cli_refuses_oversized_content_length_before_operator_output() -> TestResult {
    let (sent, headers_sent) = mpsc::channel();
    let host =
        LocalHost::withhold_body(response("200 OK", "Content-Length: 262145\r\n", b""), sent)?;
    let (output, completed) = invoke_before_body(&host.endpoint, &headers_sent)?;
    let body_was_withheld = host.body_withheld.load(Ordering::SeqCst);
    assert_eq!(host.finish()?.len(), 1);
    assert!(
        completed,
        "the declared byte ceiling must refuse before body availability"
    );
    assert!(
        body_was_withheld,
        "an EOF or body timeout must not satisfy this refusal"
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn recovery_cli_refuses_oversized_chunked_response_before_operator_output() -> TestResult {
    let mut chunked = b"40001\r\n".to_vec();
    chunked.extend(std::iter::repeat_n(b' ', 262145));
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");
    let host = LocalHost::start(response(
        "200 OK",
        "Transfer-Encoding: chunked\r\n",
        &chunked,
    ))?;
    let output = invoke(&host.endpoint, "")?;
    assert_eq!(host.finish()?.len(), 1);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    Ok(())
}
