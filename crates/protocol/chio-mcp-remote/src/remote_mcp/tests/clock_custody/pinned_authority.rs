//! Exercise the pinned authority through the actual session factory.
use super::*;
use chio_core::capability::{scope::ChioScope, token::CapabilityTokenBody};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::thread::JoinHandle;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const AUTHORITY_PATH: &str = "/v1/authority";
const ISSUE_CAPABILITY_PATH: &str = "/v1/capabilities/issue";
const LINEAGE_RECORD_PATH: &str = "/v1/lineage";

struct ReadTransport;

impl McpTransport for ReadTransport {
    fn list_tools(&self) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, AdapterError> {
        Ok(vec![chio_mcp_adapter::edge::McpToolInfo {
            name: "read".into(),
            title: None,
            description: Some("Read".into()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            annotations: Some(json!({"readOnlyHint": true, "destructiveHint": false})),
            execution: None,
        }])
    }

    fn call_tool(
        &self,
        tool_name: &str,
        arguments: Value,
    ) -> Result<chio_mcp_adapter::edge::McpToolResult, AdapterError> {
        TestSessionTransport.call_tool(tool_name, arguments)
    }
}

#[derive(Default)]
struct PreIssuanceClock {
    armed: AtomicBool,
    reads: AtomicUsize,
}

impl PreIssuanceClock {
    fn arm(&self) {
        self.reads.store(0, Ordering::SeqCst);
        self.armed.store(true, Ordering::SeqCst);
    }
}

impl Clock for PreIssuanceClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        // Ignore construction reads. After authority discovery, the kernel's
        // precheck succeeds and the authority's own pre-issuance read fails.
        if self.armed.load(Ordering::SeqCst) && self.reads.fetch_add(1, Ordering::SeqCst) != 0 {
            return Err(ClockError::Unavailable);
        }
        reading(109_000, 0)
    }
}

struct ControlServer {
    address: SocketAddr,
    stopped: Arc<AtomicBool>,
    issuances: Arc<AtomicUsize>,
    thread: Option<JoinHandle<TestResult<()>>>,
    public_key: PublicKey,
}

impl ControlServer {
    fn start() -> TestResult<Self> {
        Self::start_with_clock(None)
    }

    fn start_with_clock(clock: Option<Arc<PreIssuanceClock>>) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let signer = Keypair::from_seed(&[84; 32]);
        let public_key = signer.public_key();
        let stopped = Arc::new(AtomicBool::new(false));
        let issuances = Arc::new(AtomicUsize::new(0));
        let server_stopped = stopped.clone();
        let server_issuances = issuances.clone();
        let thread = std::thread::spawn(move || -> TestResult {
            loop {
                let (mut stream, _) = listener.accept()?;
                if server_stopped.load(Ordering::SeqCst) {
                    return Ok(());
                }
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                let (headers, body) = read_request(&mut stream)?;
                let response = respond(&headers, &body, &signer, &server_issuances)?;
                if headers.starts_with(&format!("GET {AUTHORITY_PATH} HTTP/1.1\r\n")) {
                    if let Some(clock) = &clock {
                        clock.arm();
                    }
                }
                let bytes = serde_json::to_vec(&response)?;
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                )?;
                stream.write_all(&bytes)?;
            }
        });
        Ok(Self {
            address,
            stopped,
            issuances,
            thread: Some(thread),
            public_key,
        })
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }

    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
    }

    fn finish(mut self) -> TestResult<usize> {
        self.stop();
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| "control server panicked")??;
        }
        Ok(self.issuances.load(Ordering::SeqCst))
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> TestResult<(String, Vec<u8>)> {
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        read_chunk(stream, &mut bytes)?;
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec())?;
    let length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>())
        .transpose()?
        .unwrap_or(0);
    if length > 1024 * 1024 {
        return Err("control request exceeds fixture bound".into());
    }
    while bytes.len() < header_end + length {
        read_chunk(stream, &mut bytes)?;
    }
    Ok((headers, bytes[header_end..header_end + length].to_vec()))
}

fn read_chunk(stream: &mut TcpStream, bytes: &mut Vec<u8>) -> TestResult {
    let mut chunk = [0; 4096];
    let length = stream.read(&mut chunk)?;
    if length == 0 || bytes.len() + length > 1024 * 1024 + 8192 {
        return Err("incomplete or oversized control request".into());
    }
    bytes.extend_from_slice(&chunk[..length]);
    Ok(())
}

fn respond(
    headers: &str,
    bytes: &[u8],
    signer: &Keypair,
    issuances: &AtomicUsize,
) -> TestResult<Value> {
    if headers.starts_with(&format!("GET {AUTHORITY_PATH} HTTP/1.1\r\n")) {
        assert!(headers
            .to_ascii_lowercase()
            .contains("\r\nauthorization: bearer workload-secret\r\n"));
        return Ok(json!({
            "configured": true, "backend": "test", "publicKey": signer.public_key().to_hex(),
            "generation": null, "rotatedAt": null, "appliesToFutureSessionsOnly": true,
            "trustedPublicKeys": [signer.public_key().to_hex()]
        }));
    }
    if headers.starts_with(&format!("POST {ISSUE_CAPABILITY_PATH} HTTP/1.1\r\n")) {
        assert!(headers
            .to_ascii_lowercase()
            .contains("\r\nauthorization: bearer workload-secret\r\n"));
        issuances.fetch_add(1, Ordering::SeqCst);
        let body: Value = serde_json::from_slice(bytes)?;
        let subject = PublicKey::from_hex(
            body["subjectPublicKey"]
                .as_str()
                .ok_or("missing issuance subject")?,
        )?;
        let scope: ChioScope = serde_json::from_value(body["scope"].clone())?;
        assert_eq!(body["ttlSeconds"].as_u64(), Some(1));
        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: format!("pinned-clock-{}", issuances.load(Ordering::SeqCst)),
                issuer: signer.public_key(),
                subject,
                scope,
                issued_at: 109,
                expires_at: 110,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            signer,
        )?;
        return Ok(json!({"capability": capability}));
    }
    if headers.starts_with(&format!("POST {LINEAGE_RECORD_PATH} HTTP/1.1\r\n")) {
        assert!(headers
            .to_ascii_lowercase()
            .contains("\r\nauthorization: bearer service-secret\r\n"));
        return Ok(json!({}));
    }
    Err("unexpected control request".into())
}

fn factory(
    directory: &std::path::Path,
    server: &ControlServer,
    clock: RemoteClock,
) -> TestResult<RemoteSessionFactory> {
    let mut config = test_remote_config();
    config.clock = clock;
    config.policy_path = directory.join("policy.yaml");
    config.wrapped_args.clear();
    config.test_transport = Some(Arc::new(ReadTransport));
    config.control_url = Some(server.endpoint());
    config.control_token = Some("service-secret".into());
    config.remote_authority_workload_token = Some("workload-secret".into());
    config.control_authority_public_key = Some(server.public_key.clone());
    std::fs::write(
        &config.policy_path,
        "kernel:\n  allow_ephemeral_receipt_log: true\n  allow_ephemeral_revocation_store: true\n  durable_admission_mode: off\n  allow_unsafe_durable_admission_off: true\ncapabilities:\n  default:\n    tools:\n      - {server: srv, tool: read, operations: [invoke], ttl: 1}\n",
    )?;
    configure_signed_manifest(&mut config, directory);
    Ok(RemoteSessionFactory::new(config)?)
}

#[test]
fn f048_pinned_session_factory_uses_injected_clock_for_response_expiry() -> TestResult {
    let directory = tempfile::tempdir()?;
    let server = ControlServer::start()?;
    let source = Arc::new(TestClock(StdMutex::new(reading(109_000, 0))));
    let factory = factory(directory.path(), &server, RemoteClock::new(source.clone()))?;
    let auth = SessionAuthContext::streamable_http_static_bearer("agent", "session-secret", None);
    let session = factory.spawn_session(auth.clone())?;
    assert_eq!(session.issued_capabilities.len(), 1);
    assert_eq!(session.issued_capabilities[0].issued_at, 109);
    assert_eq!(session.issued_capabilities[0].expires_at, 110);
    session.shutdown_upstream_transport()?;
    drop(session);
    *source.0.lock().map_err(|_| "clock fixture poisoned")? = reading(110_000, 1_000_000_000);
    let expired = factory
        .spawn_session(auth)
        .err()
        .ok_or("expired response accepted")?;
    assert!(expired.to_string().contains("already expired"), "{expired}");
    drop(factory);
    assert_eq!(server.finish()?, 2);
    Ok(())
}

#[test]
fn f048_pinned_session_factory_blocks_network_issuance_after_owner_clock_fault() -> TestResult {
    let directory = tempfile::tempdir()?;
    let source = Arc::new(PreIssuanceClock::default());
    let server = ControlServer::start_with_clock(Some(source.clone()))?;
    let factory = factory(directory.path(), &server, RemoteClock::new(source.clone()))?;
    let auth = SessionAuthContext::streamable_http_static_bearer("agent", "session-secret", None);
    let result = factory.spawn_session(auth);
    drop(factory);
    assert_eq!(
        server.finish()?,
        0,
        "owner clock fault must prevent the remote issuance side effect"
    );
    // The shared initial-capability helper preserves this refusal as CLI text.
    // Typed clock provenance is checked at the direct pinned builder boundary.
    let error = result.err().ok_or("owner clock fault accepted")?;
    assert!(
        error
            .to_string()
            .contains(&ClockError::Unavailable.to_string()),
        "{error}"
    );
    assert_eq!(source.reads.load(Ordering::SeqCst), 2);
    Ok(())
}
