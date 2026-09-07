//! A tool server behind a loopback TCP socket, with a client that carries the
//! kernel's dispatch identity and proves reachability before a dispatch.
//!
//! One newline-delimited JSON request per connection:
//! `{"request_id", "idempotency_key", "attempt_id", "tool", "arguments"}`; the
//! server answers `{"result": <arguments>}` or misbehaves as the test directs.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chio_kernel::{BlockingToolServerConnection, KernelError, ToolDispatchContext};

use crate::support::{TestResult, SERVER_ID, TOOL_NAME};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const READ_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug)]
pub enum Behavior {
    /// Answer every request with its arguments.
    Respond,
    /// Read the request and close the connection without answering.
    CloseAfterRead,
    /// Read the request, wait past the client's read timeout, then answer.
    DelayResponse(Duration),
}

pub struct LoopbackServer {
    address: SocketAddr,
    behavior: Mutex<Behavior>,
    requests: Mutex<Vec<serde_json::Value>>,
    stopped: Arc<AtomicBool>,
    invocations: Arc<AtomicUsize>,
}

impl LoopbackServer {
    pub fn start(invocations: Arc<AtomicUsize>) -> TestResult<Arc<Self>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let server = Arc::new(Self {
            address: listener.local_addr()?,
            behavior: Mutex::new(Behavior::Respond),
            requests: Mutex::new(Vec::new()),
            stopped: Arc::new(AtomicBool::new(false)),
            invocations,
        });
        server.serve(listener)?;
        Ok(server)
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn set_behavior(&self, behavior: Behavior) -> TestResult {
        *self.behavior.lock().map_err(|_| "behavior lock")? = behavior;
        Ok(())
    }

    pub fn requests(&self) -> TestResult<Vec<serde_json::Value>> {
        Ok(self.requests.lock().map_err(|_| "requests lock")?.clone())
    }

    /// Stop accepting connections; the address stays reserved for `restart`.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        // The accept loop polls the flag; give it one poll interval to close.
        thread::sleep(Duration::from_millis(50));
    }

    pub fn restart(self: &Arc<Self>) -> TestResult {
        let listener = TcpListener::bind(self.address)?;
        self.stopped.store(false, Ordering::SeqCst);
        self.serve(listener)
    }

    fn serve(self: &Arc<Self>, listener: TcpListener) -> TestResult {
        listener.set_nonblocking(true)?;
        let server = Arc::clone(self);
        thread::Builder::new()
            .name("loopback-tool-server".into())
            .spawn(move || {
                while !server.stopped.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => server.handle(stream),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            })?;
        Ok(())
    }

    fn handle(&self, stream: TcpStream) {
        let behavior = self
            .behavior
            .lock()
            .map(|behavior| *behavior)
            .unwrap_or(Behavior::CloseAfterRead);
        let mut line = String::new();
        let mut reader = BufReader::new(match stream.try_clone() {
            Ok(reader) => reader,
            Err(_) => return,
        });
        if reader.read_line(&mut line).is_err() {
            return;
        }
        let Ok(request) = serde_json::from_str::<serde_json::Value>(line.trim_end()) else {
            return;
        };
        self.invocations.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut requests) = self.requests.lock() {
            requests.push(request.clone());
        }
        let mut stream = stream;
        match behavior {
            Behavior::Respond => {
                let _ = writeln!(
                    stream,
                    "{}",
                    serde_json::json!({ "result": request["arguments"] })
                );
            }
            Behavior::CloseAfterRead => {}
            Behavior::DelayResponse(delay) => {
                thread::sleep(delay);
                let _ = writeln!(
                    stream,
                    "{}",
                    serde_json::json!({ "result": request["arguments"] })
                );
            }
        }
    }
}

/// Where a crash test ends its own process, at the transport boundaries a
/// kernel cannot observe: before anything reaches the server, after the
/// request is on the wire, and after the response was read but not yet
/// returned to the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortPoint {
    BeforeDelivery,
    AfterDelivery,
    AfterResponse,
}

impl AbortPoint {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "before-delivery" => Some(Self::BeforeDelivery),
            "after-delivery" => Some(Self::AfterDelivery),
            "after-response" => Some(Self::AfterResponse),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::BeforeDelivery => "before-delivery",
            Self::AfterDelivery => "after-delivery",
            Self::AfterResponse => "after-response",
        }
    }
}

/// The kernel-side transport: connects per dispatch, forwards the identity
/// and classifies failures the way a remote transport must.
pub struct LoopbackClient {
    address: SocketAddr,
    abort_at: Option<AbortPoint>,
}

impl LoopbackClient {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            abort_at: None,
        }
    }

    pub fn aborting_at(address: SocketAddr, abort_at: AbortPoint) -> Self {
        Self {
            address,
            abort_at: Some(abort_at),
        }
    }

    fn abort_if(&self, point: AbortPoint) {
        if self.abort_at == Some(point) {
            std::process::abort();
        }
    }
}

impl BlockingToolServerConnection for LoopbackClient {
    fn server_id(&self) -> &str {
        SERVER_ID
    }

    fn tool_names(&self) -> Vec<String> {
        vec![TOOL_NAME.into()]
    }

    fn invoke_blocking(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::ToolServerError(
            "loopback transport requires a dispatch identity".to_string(),
        ))
    }

    fn prepare_delivery_blocking(&self, _context: &ToolDispatchContext) -> Result<(), KernelError> {
        self.abort_if(AbortPoint::BeforeDelivery);
        TcpStream::connect_timeout(&self.address, CONNECT_TIMEOUT)
            .map(drop)
            .map_err(|error| {
                KernelError::ToolServerError(format!(
                    "tool server {} is unreachable: {error}",
                    self.address
                ))
            })
    }

    fn invoke_blocking_in_context(
        &self,
        context: &ToolDispatchContext,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        let mut stream =
            TcpStream::connect_timeout(&self.address, CONNECT_TIMEOUT).map_err(|error| {
                KernelError::ToolServerError(format!(
                    "tool server {} refused the connection: {error}",
                    self.address
                ))
            })?;
        stream
            .set_read_timeout(Some(READ_TIMEOUT))
            .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
        let request = serde_json::json!({
            "request_id": context.request_id(),
            "idempotency_key": context.idempotency_key(),
            "attempt_id": context.attempt_id(),
            "tool": tool_name,
            "arguments": arguments,
        });
        writeln!(stream, "{request}").map_err(|error| {
            KernelError::RequestIncomplete(format!("request could not be delivered: {error}"))
        })?;
        self.abort_if(AbortPoint::AfterDelivery);
        let mut line = String::new();
        let read = BufReader::new(stream)
            .read_line(&mut line)
            .map_err(|error| {
                KernelError::RequestIncomplete(format!("no response after delivery: {error}"))
            })?;
        if read == 0 {
            return Err(KernelError::RequestIncomplete(
                "connection closed after delivery without a response".to_string(),
            ));
        }
        let response: serde_json::Value =
            serde_json::from_str(line.trim_end()).map_err(|error| {
                KernelError::RequestIncomplete(format!("malformed response: {error}"))
            })?;
        self.abort_if(AbortPoint::AfterResponse);
        response
            .get("result")
            .cloned()
            .ok_or_else(|| KernelError::RequestIncomplete("response carried no result".to_string()))
    }
}
