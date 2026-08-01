struct TestDir(PathBuf);

impl std::ops::Deref for TestDir {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0.as_path()
    }
}

impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        self.0.as_path()
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn unique_test_dir() -> TestDir {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let counter = UNIQUE_TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "chio-cli-mcp-http-{}-{nonce}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create private MCP HTTP test directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("secure private MCP HTTP test directory");
    }
    TestDir(path)
}

macro_rules! skip_when_loopback_denied {
    ($test_name:ident) => {
        if skip_when_loopback_bind_denied(stringify!($test_name)) {
            return;
        }
    };
}

struct ServerGuard {
    child: Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct ControlTlsProxy {
    base_url: String,
    root_ca_path: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ControlTlsProxy {
    fn spawn(dir: &Path, backend: SocketAddr) -> Self {
        let (server_config, root_ca_path) = control_tls_material(dir);
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind control TLS proxy");
        listener
            .set_nonblocking(true)
            .expect("set control TLS proxy listener nonblocking");
        let listen = listener.local_addr().expect("control TLS proxy address");
        let (shutdown, shutdown_receiver) = tokio::sync::oneshot::channel();
        let worker = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build control TLS proxy runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)
                    .expect("adopt control TLS proxy listener");
                let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
                let mut shutdown_receiver = shutdown_receiver;
                let mut connections = tokio::task::JoinSet::new();

                loop {
                    tokio::select! {
                        _ = &mut shutdown_receiver => break,
                        accepted = listener.accept() => {
                            let Ok((inbound, _)) = accepted else {
                                continue;
                            };
                            let acceptor = acceptor.clone();
                            connections.spawn(async move {
                                let Ok(mut inbound) = acceptor.accept(inbound).await else {
                                    return;
                                };
                                let Ok(mut outbound) = tokio::net::TcpStream::connect(backend).await else {
                                    return;
                                };
                                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                            });
                        }
                        completed = connections.join_next(), if !connections.is_empty() => {
                            let _ = completed;
                        }
                    }
                }

                connections.abort_all();
                while connections.join_next().await.is_some() {}
            });
        });

        Self {
            base_url: format!("https://{listen}"),
            root_ca_path,
            shutdown: Some(shutdown),
            worker: Some(worker),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn root_ca_path(&self) -> &Path {
        &self.root_ca_path
    }
}

impl Drop for ControlTlsProxy {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn control_tls_material(dir: &Path) -> (Arc<ureq::rustls::ServerConfig>, PathBuf) {
    let _ = ureq::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut root_params =
        CertificateParams::new(Vec::<String>::new()).expect("control root CA parameters");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.distinguished_name = DistinguishedName::new();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "Chio Control Test Root");
    let root_key = RcgenKeyPair::generate().expect("generate control root CA key");
    let root_cert = root_params
        .self_signed(&root_key)
        .expect("self-sign control root CA");

    let mut server_params = CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("control TLS server parameters");
    server_params.distinguished_name = DistinguishedName::new();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "127.0.0.1");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = RcgenKeyPair::generate().expect("generate control TLS server key");
    let server_cert = server_params
        .signed_by(&server_key, &root_cert, &root_key)
        .expect("sign control TLS server certificate");

    let root_ca_path = dir.join("control-tls-root-ca.pem");
    fs::write(&root_ca_path, root_cert.pem()).expect("write control TLS root CA");

    let private_key =
        ureq::rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()).into();
    let server_config = ureq::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![server_cert.der().clone(), root_cert.der().clone()],
            private_key,
        )
        .expect("build control TLS server configuration");
    (Arc::new(server_config), root_ca_path)
}

#[derive(Debug)]
enum StartupError {
    BindCollision(String),
    EarlyExit(String),
    Timeout(&'static str),
}

impl StartupError {
    fn from_child_exit(status: std::process::ExitStatus, stderr: String) -> Self {
        if is_bind_collision(&stderr) {
            Self::BindCollision(stderr)
        } else {
            Self::EarlyExit(format!(
                "process exited before readiness with status {status}: {}",
                stderr.trim()
            ))
        }
    }

    fn panic_context(&self, label: &str) -> String {
        match self {
            Self::BindCollision(stderr) => format!(
                "{label} failed to bind after retry budget was exhausted: {}",
                stderr.trim()
            ),
            Self::EarlyExit(message) => format!("{label} {message}"),
            Self::Timeout(message) => format!("{label} {message}"),
        }
    }
}

fn is_bind_collision(stderr: &str) -> bool {
    stderr.contains("Address already in use")
        || stderr.contains("os error 48")
        || stderr.contains("os error 98")
}

fn read_child_stderr(child: &mut Child) -> String {
    let mut stderr = String::new();
    if let Some(stderr_pipe) = child.stderr.as_mut() {
        let _ = stderr_pipe.read_to_string(&mut stderr);
    }
    stderr
}

fn spawn_with_bind_retry<F, W>(
    client: &Client,
    label: &str,
    mut spawn: F,
    mut wait: W,
) -> (SocketAddr, ServerGuard)
where
    F: FnMut(SocketAddr) -> ServerGuard,
    W: FnMut(&Client, &str, &mut ServerGuard) -> Result<(), StartupError>,
{
    const MAX_ATTEMPTS: usize = 8;

    for attempt in 1..=MAX_ATTEMPTS {
        let listen = reserve_listen_addr();
        let mut guard = spawn(listen);
        let base_url = format!("http://{listen}");
        match wait(client, &base_url, &mut guard) {
            Ok(()) => return (listen, guard),
            Err(StartupError::BindCollision(_)) if attempt < MAX_ATTEMPTS => {
                drop(guard);
                continue;
            }
            Err(error) => panic!("{}", error.panic_context(label)),
        }
    }

    unreachable!("bind retry loop must return or panic");
}

fn write_mock_server_script(dir: &Path) -> PathBuf {
    let script = r##"
import json
import os
import sys
import threading
import time

CLIENT_CAPABILITIES = {}
STARTUP_MARKER_PATH = os.environ.get("CHIO_MCP_STARTUP_MARKER_PATH")
WRITE_LOCK = threading.Lock()

if STARTUP_MARKER_PATH:
    with open(STARTUP_MARKER_PATH, "a", encoding="utf-8") as handle:
        handle.write(f"{os.getpid()}\n")

TOOLS = [
    {
        "name": "echo_json",
        "title": "Echo JSON",
        "description": "Return structured JSON",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "echo": {"type": "string"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "sampled_echo",
        "description": "Uses sampling/createMessage before responding",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "sampled": {"type": "object"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "slow_echo",
        "description": "Sleeps briefly before responding",
        "inputSchema": {"type": "object"},
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "slow_cancelable_echo",
        "description": "Sleeps longer before responding so cancellation stays in flight",
        "inputSchema": {"type": "object"},
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "emit_fixture_notifications",
        "description": "Emits resource notifications before responding",
        "inputSchema": {
            "type": "object",
            "properties": {
                "count": {"type": "integer"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "emit_late_fixture_notifications",
        "description": "Responds first and emits resource notifications later",
        "inputSchema": {
            "type": "object",
            "properties": {
                "count": {"type": "integer"},
                "delayMs": {"type": "integer"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "drop_stream_mid_call",
        "description": "Closes the wrapped MCP process before completing the tool response",
        "inputSchema": {"type": "object"},
        "annotations": {
            "readOnlyHint": True
        }
    }
]

RESOURCES = [
    {
        "uri": "fixture://docs/0",
        "name": "Fixture Doc",
        "mimeType": "text/plain"
    }
]

def respond(payload):
    with WRITE_LOCK:
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.stdout.flush()

for line in sys.stdin:
    if not line.strip():
        continue

    message = json.loads(line)
    method = message.get("method")

    if method == "initialize":
        CLIENT_CAPABILITIES = message.get("params", {}).get("capabilities", {})
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "tools": {},
                    "resources": {
                        "subscribe": True,
                        "listChanged": True
                    }
                },
                "serverInfo": {
                    "name": "mock-http-upstream",
                    "version": "0.1.0"
                }
            }
        })
        continue

    if method == "notifications/initialized":
        continue

    if method == "tools/list":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"tools": TOOLS}
        })
        continue

    if method == "resources/list":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"resources": RESOURCES}
        })
        continue

    if method == "resources/templates/list":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"resourceTemplates": []}
        })
        continue

    if method == "resources/read":
        uri = message.get("params", {}).get("uri", "fixture://docs/0")
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "text/plain",
                        "text": "fixture resource"
                    }
                ]
            }
        })
        continue

    if method == "resources/subscribe" or method == "resources/unsubscribe":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {}
        })
        continue

    if method == "tools/call":
        tool_name = message["params"]["name"]
        arguments = message["params"].get("arguments", {})

        if tool_name == "echo_json":
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": "echoed"}],
                    "structuredContent": {"echo": arguments.get("message", "hello")},
                    "isError": False
                }
            })
            continue

        if tool_name == "slow_echo":
            time.sleep(1.0)
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": "slow response"}],
                    "isError": False
                }
            })
            continue

        if tool_name == "slow_cancelable_echo":
            time.sleep(3.0)
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": "slow cancellation response"}],
                    "isError": False
                }
            })
            continue

        if tool_name == "emit_fixture_notifications":
            count = max(1, int(arguments.get("count", 1)))
            for index in range(count):
                if index % 2 == 0:
                    respond({
                        "jsonrpc": "2.0",
                        "method": "notifications/resources/list_changed"
                    })
                else:
                    respond({
                        "jsonrpc": "2.0",
                        "method": "notifications/resources/updated",
                        "params": {"uri": f"fixture://docs/{index}"}
                    })
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": f"emitted {count} notifications"}],
                    "structuredContent": {"count": count},
                    "isError": False
                }
            })
            continue

        if tool_name == "emit_late_fixture_notifications":
            count = max(1, int(arguments.get("count", 1)))
            delay_ms = max(10, int(arguments.get("delayMs", 150)))

            def emit_late_notifications():
                time.sleep(delay_ms / 1000.0)
                for index in range(count):
                    if index % 2 == 0:
                        respond({
                            "jsonrpc": "2.0",
                            "method": "notifications/resources/list_changed"
                        })
                    else:
                        respond({
                            "jsonrpc": "2.0",
                            "method": "notifications/resources/updated",
                            "params": {"uri": f"fixture://docs/{index}"}
                        })

            threading.Thread(target=emit_late_notifications, daemon=True).start()
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": f"scheduled {count} late notifications"}],
                    "structuredContent": {"count": count, "delayMs": delay_ms},
                    "isError": False
                }
            })
            continue

        if tool_name == "drop_stream_mid_call":
            sys.stdout.flush()
            sys.exit(0)

        if tool_name == "sampled_echo":
            if "sampling" not in CLIENT_CAPABILITIES:
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": "sampling not negotiated"}],
                        "isError": True
                    }
                })
                continue

            sample_request_id = f"sample-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": sample_request_id,
                "method": "sampling/createMessage",
                "params": {
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": arguments.get("message", "sample me")
                            }
                        }
                    ],
                    "maxTokens": 128
                }
            })

            while True:
                sample_response = json.loads(sys.stdin.readline())
                if sample_response.get("id") != sample_request_id or sample_response.get("method"):
                    continue
                if sample_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": sample_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    break

                sampled = sample_response["result"]
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(sampled)}],
                        "structuredContent": {"sampled": sampled},
                        "isError": False
                    }
                })
                break
            continue

    if method == "tasks/get":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {
                "code": -32602,
                "message": "unknown method: tasks/get"
            }
        })
        continue

    respond({
        "jsonrpc": "2.0",
        "id": message.get("id"),
        "error": {"code": -32601, "message": f"unknown method: {method}"}
    })
"##;

    let path = dir.join("mock_http_mcp_server.py");
    fs::write(&path, script).expect("write mock server script");
    path
}

fn http_security_material(
    dir: &Path,
    script_path: &Path,
) -> mcp_security::NativeMcpSecurityMaterial {
    static MATERIALS: OnceLock<
        Mutex<HashMap<PathBuf, Arc<OnceLock<mcp_security::NativeMcpSecurityMaterial>>>>,
    > = OnceLock::new();

    let canonical_dir = fs::canonicalize(dir).expect("canonicalize remote MCP test directory");
    let material = {
        let mut materials = MATERIALS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(
            materials
                .entry(canonical_dir.clone())
                .or_insert_with(|| Arc::new(OnceLock::new())),
        )
    };

    material
        .get_or_init(|| {
            let target_command = mcp_security::resolve_executable("python3");
            let script_path =
                fs::canonicalize(script_path).expect("canonicalize mock MCP server script");
            let target_args = vec![script_path
                .to_str()
                .expect("mock MCP server path is UTF-8")
                .to_string()];
            mcp_security::materialize_mcp_security(
                &canonical_dir.join("security"),
                Path::new(env!("CARGO_BIN_EXE_chio")),
                &target_command,
                &target_args,
                &canonical_dir,
                "wrapped-http-mock",
                "Wrapped HTTP Mock",
                "0.1.0",
            )
        })
        .clone()
}

fn spawn_secured_http_command(
    mut command: Command,
    dir: &Path,
    script_path: &Path,
    label: &str,
) -> ServerGuard {
    let security = http_security_material(dir, script_path);
    command
        .current_dir(dir)
        .args([
            "--server-version",
            "0.1.0",
            "--signed-manifest",
            security
                .signed_manifest_path
                .to_str()
                .expect("signed manifest path"),
            "--manifest-public-key",
            &security.manifest_public_key,
            "--cage-policy",
            security
                .cage_policy_path
                .to_str()
                .expect("cage policy path"),
            "--cage-policy-signer",
            &security.cage_policy_signer,
            "--",
            security
                .target_command
                .to_str()
                .expect("MCP target command path"),
        ])
        .args(&security.target_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let child = command
        .spawn()
        .unwrap_or_else(|error| panic!("{label}: {error}"));
    ServerGuard { child }
}

fn write_policy_with_tools_and_ttl(dir: &Path, tools: &[&str], ttl: u64) -> PathBuf {
    let mut policy = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
  allow_sampling: true
capabilities:
  default:
    tools:
"#
    .to_string();
    for tool in tools {
        policy.push_str(&format!(
            "      - server: wrapped-http-mock\n        tool: {tool}\n        operations: [invoke]\n        ttl: {ttl}\n"
        ));
    }

    let path = dir.join("http-policy.yaml");
    fs::write(&path, policy).expect("write HTTP policy");
    path
}

fn write_policy_with_tools(dir: &Path, tools: &[&str]) -> PathBuf {
    write_policy_with_tools_and_ttl(dir, tools, 300)
}

fn write_policy(dir: &Path) -> PathBuf {
    write_policy_with_tools(
        dir,
        &[
            "echo_json",
            "sampled_echo",
            "slow_echo",
            "slow_cancelable_echo",
            "emit_fixture_notifications",
            "emit_late_fixture_notifications",
            "drop_stream_mid_call",
        ],
    )
}

fn write_resume_hmac_keyring(dir: &Path) -> PathBuf {
    let path = dir.join("remote-resume-hmac-keyring.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&json!({
            "schema": "chio.remote-mcp.resume-hmac-keyring.v1",
            "current": {
                "keyId": "cli-integration-resume",
                "version": 1,
                "keyBase64": URL_SAFE_NO_PAD.encode([73_u8; 32]),
            },
            "previous": [],
        }))
        .expect("serialize resume HMAC keyring"),
    )
    .expect("write resume HMAC keyring");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("secure resume HMAC keyring permissions");
    }
    path
}

fn spawn_http_server(dir: &Path, listen: SocketAddr, token: &str) -> ServerGuard {
    spawn_http_server_with_session_lifecycle_tuning(dir, listen, token, None, None, None, None)
}

fn spawn_http_server_with_session_lifecycle_tuning(
    dir: &Path,
    listen: SocketAddr,
    token: &str,
    session_db_path: Option<&Path>,
    idle_expiry_millis: Option<u64>,
    drain_grace_millis: Option<u64>,
    reaper_interval_millis: Option<u64>,
) -> ServerGuard {
    spawn_http_server_with_session_lifecycle_env_prefix(
        dir,
        listen,
        token,
        session_db_path,
        idle_expiry_millis,
        drain_grace_millis,
        reaper_interval_millis,
        "CHIO",
    )
}

fn spawn_http_server_with_session_lifecycle_env_prefix(
    dir: &Path,
    listen: SocketAddr,
    token: &str,
    session_db_path: Option<&Path>,
    idle_expiry_millis: Option<u64>,
    drain_grace_millis: Option<u64>,
    reaper_interval_millis: Option<u64>,
    env_prefix: &str,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    spawn_http_server_with_policy_path_and_session_lifecycle_env_prefix(
        dir,
        &policy_path,
        listen,
        token,
        session_db_path,
        idle_expiry_millis,
        drain_grace_millis,
        reaper_interval_millis,
        env_prefix,
    )
}

fn spawn_http_server_with_policy_path_and_session_lifecycle_env_prefix(
    dir: &Path,
    policy_path: &Path,
    listen: SocketAddr,
    token: &str,
    session_db_path: Option<&Path>,
    idle_expiry_millis: Option<u64>,
    drain_grace_millis: Option<u64>,
    reaper_interval_millis: Option<u64>,
    env_prefix: &str,
) -> ServerGuard {
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.args([
        "--receipt-db",
        receipt_db_path.to_str().expect("receipt db path"),
        "--revocation-db",
        revocation_db_path.to_str().expect("revocation db path"),
        "--authority-seed-file",
        authority_seed_path.to_str().expect("authority seed path"),
    ]);
    if let Some(path) = session_db_path {
        command.args(["--session-db", path.to_str().expect("session db path")]);
        let resume_hmac_keyring = write_resume_hmac_keyring(dir);
        command.args([
            "--resume-hmac-keyring",
            resume_hmac_keyring
                .to_str()
                .expect("resume HMAC keyring path"),
        ]);
    }
    command.args([
        "mcp",
        "serve-http",
        "--policy",
        policy_path.to_str().expect("policy path"),
        "--server-id",
        "wrapped-http-mock",
        "--server-name",
        "Wrapped HTTP Mock",
        "--listen",
        &listen.to_string(),
        "--auth-token",
        token,
    ]);
    if let Some(value) = idle_expiry_millis {
        command.env(
            format!("{env_prefix}_MCP_SESSION_IDLE_EXPIRY_MILLIS"),
            value.to_string(),
        );
    }
    if let Some(value) = drain_grace_millis {
        command.env(
            format!("{env_prefix}_MCP_SESSION_DRAIN_GRACE_MILLIS"),
            value.to_string(),
        );
    }
    if let Some(value) = reaper_interval_millis {
        command.env(
            format!("{env_prefix}_MCP_SESSION_REAPER_INTERVAL_MILLIS"),
            value.to_string(),
        );
    }
    spawn_secured_http_command(command, dir, &script_path, "spawn chio mcp serve-http")
}

fn spawn_http_server_with_policy_path_and_jwt_auth(
    dir: &Path,
    policy_path: &Path,
    listen: SocketAddr,
    jwt_public_key_hex: &str,
    issuer: &str,
    audience: &str,
    admin_token: &str,
    session_db_path: Option<&Path>,
) -> ServerGuard {
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.args([
        "--receipt-db",
        receipt_db_path.to_str().expect("receipt db path"),
        "--revocation-db",
        revocation_db_path.to_str().expect("revocation db path"),
        "--authority-seed-file",
        authority_seed_path.to_str().expect("authority seed path"),
    ]);
    if let Some(path) = session_db_path {
        command.args(["--session-db", path.to_str().expect("session db path")]);
        let resume_hmac_keyring = write_resume_hmac_keyring(dir);
        command.args([
            "--resume-hmac-keyring",
            resume_hmac_keyring
                .to_str()
                .expect("resume HMAC keyring path"),
        ]);
    }
    command.args([
        "mcp",
        "serve-http",
        "--policy",
        policy_path.to_str().expect("policy path"),
        "--server-id",
        "wrapped-http-mock",
        "--server-name",
        "Wrapped HTTP Mock",
        "--listen",
        &listen.to_string(),
        "--auth-jwt-public-key",
        jwt_public_key_hex,
        "--auth-jwt-issuer",
        issuer,
        "--auth-jwt-audience",
        audience,
        "--auth-scope",
        "mcp:invoke",
        "--admin-token",
        admin_token,
    ]);
    spawn_secured_http_command(
        command,
        dir,
        &script_path,
        "spawn chio mcp serve-http with jwt auth",
    )
}

fn spawn_http_server_with_shared_owner(
    dir: &Path,
    listen: SocketAddr,
    token: &str,
    startup_marker_path: &Path,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command
        .env(
            "CHIO_MCP_STARTUP_MARKER_PATH",
            startup_marker_path.to_str().expect("startup marker path"),
        )
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
            "--authority-seed-file",
            authority_seed_path.to_str().expect("authority seed path"),
            "mcp",
            "serve-http",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-http-mock",
            "--server-name",
            "Wrapped HTTP Mock",
            "--listen",
            &listen.to_string(),
            "--auth-token",
            token,
            "--shared-hosted-owner",
        ]);
    spawn_secured_http_command(command, dir, &script_path, "spawn chio mcp serve-http")
}

fn spawn_http_server_with_authority_db(
    dir: &Path,
    listen: SocketAddr,
    token: &str,
    authority_db_path: &Path,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.args([
        "--receipt-db",
        receipt_db_path.to_str().expect("receipt db path"),
        "--revocation-db",
        revocation_db_path.to_str().expect("revocation db path"),
        "--authority-db",
        authority_db_path.to_str().expect("authority db path"),
        "mcp",
        "serve-http",
        "--policy",
        policy_path.to_str().expect("policy path"),
        "--server-id",
        "wrapped-http-mock",
        "--server-name",
        "Wrapped HTTP Mock",
        "--listen",
        &listen.to_string(),
        "--auth-token",
        token,
    ]);
    spawn_secured_http_command(command, dir, &script_path, "spawn chio mcp serve-http")
}

fn spawn_http_server_with_jwt_auth(
    dir: &Path,
    listen: SocketAddr,
    jwt_public_key_hex: &str,
    issuer: &str,
    audience: &str,
    admin_token: &str,
) -> ServerGuard {
    spawn_http_server_with_jwt_auth_and_identity_federation(
        dir,
        listen,
        jwt_public_key_hex,
        issuer,
        audience,
        admin_token,
        None,
    )
}

fn spawn_http_server_with_shared_owner_and_jwt_auth(
    dir: &Path,
    listen: SocketAddr,
    jwt_public_key_hex: &str,
    issuer: &str,
    audience: &str,
    admin_token: &str,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.args([
        "--receipt-db",
        receipt_db_path.to_str().expect("receipt db path"),
        "--revocation-db",
        revocation_db_path.to_str().expect("revocation db path"),
        "--authority-seed-file",
        authority_seed_path.to_str().expect("authority seed path"),
        "mcp",
        "serve-http",
        "--policy",
        policy_path.to_str().expect("policy path"),
        "--server-id",
        "wrapped-http-mock",
        "--server-name",
        "Wrapped HTTP Mock",
        "--listen",
        &listen.to_string(),
        "--auth-jwt-public-key",
        jwt_public_key_hex,
        "--auth-jwt-issuer",
        issuer,
        "--auth-jwt-audience",
        audience,
        "--auth-scope",
        "mcp:invoke",
        "--admin-token",
        admin_token,
        "--shared-hosted-owner",
    ]);
    spawn_secured_http_command(
        command,
        dir,
        &script_path,
        "spawn chio mcp serve-http with shared-owner jwt auth",
    )
}

fn spawn_http_server_with_jwt_auth_and_identity_federation(
    dir: &Path,
    listen: SocketAddr,
    jwt_public_key_hex: &str,
    issuer: &str,
    audience: &str,
    admin_token: &str,
    identity_federation_seed_path: Option<&Path>,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.args([
        "--receipt-db",
        receipt_db_path.to_str().expect("receipt db path"),
        "--revocation-db",
        revocation_db_path.to_str().expect("revocation db path"),
        "--authority-seed-file",
        authority_seed_path.to_str().expect("authority seed path"),
        "mcp",
        "serve-http",
        "--policy",
        policy_path.to_str().expect("policy path"),
        "--server-id",
        "wrapped-http-mock",
        "--server-name",
        "Wrapped HTTP Mock",
        "--listen",
        &listen.to_string(),
        "--auth-jwt-public-key",
        jwt_public_key_hex,
        "--auth-jwt-issuer",
        issuer,
        "--auth-jwt-audience",
        audience,
        "--auth-scope",
        "mcp:invoke",
        "--admin-token",
        admin_token,
    ]);
    if let Some(path) = identity_federation_seed_path {
        command.args([
            "--identity-federation-seed-file",
            path.to_str().expect("identity federation seed path"),
        ]);
    }
    spawn_secured_http_command(command, dir, &script_path, "spawn chio mcp serve-http")
}

fn spawn_http_server_with_jwt_auth_and_local_discovery(
    dir: &Path,
    listen: SocketAddr,
    jwt_public_key_hex: &str,
    issuer: &str,
    audience: &str,
    admin_token: &str,
    authorization_endpoint: &str,
    token_endpoint: &str,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");
    let public_base_url = format!("http://{listen}");

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.args([
        "--receipt-db",
        receipt_db_path.to_str().expect("receipt db path"),
        "--revocation-db",
        revocation_db_path.to_str().expect("revocation db path"),
        "--authority-seed-file",
        authority_seed_path.to_str().expect("authority seed path"),
        "mcp",
        "serve-http",
        "--policy",
        policy_path.to_str().expect("policy path"),
        "--server-id",
        "wrapped-http-mock",
        "--server-name",
        "Wrapped HTTP Mock",
        "--listen",
        &listen.to_string(),
        "--auth-jwt-public-key",
        jwt_public_key_hex,
        "--auth-jwt-issuer",
        issuer,
        "--auth-jwt-audience",
        audience,
        "--admin-token",
        admin_token,
        "--public-base-url",
        &public_base_url,
        "--auth-server",
        issuer,
        "--auth-authorization-endpoint",
        authorization_endpoint,
        "--auth-token-endpoint",
        token_endpoint,
        "--auth-scope",
        "mcp:invoke",
    ]);
    spawn_secured_http_command(command, dir, &script_path, "spawn chio mcp serve-http")
}

fn write_oidc_discovery_fixture_with_jwks(
    dir: &Path,
    idp_listen: SocketAddr,
    issuer_path: &str,
    jwks: Value,
) -> (PathBuf, String, String) {
    let root = dir.join("oidc-idp");
    fs::create_dir_all(&root).expect("create oidc root");
    let issuer_path = issuer_path.trim_start_matches('/');
    let issuer = format!("http://127.0.0.1:{}/{}", idp_listen.port(), issuer_path);
    let issuer_dir = root.join(issuer_path);
    let discovery_dir = issuer_dir.join(".well-known");
    fs::create_dir_all(&discovery_dir).expect("create oidc discovery dir");
    let discovery_path = discovery_dir.join("openid-configuration");
    let jwks_path = root.join("jwks.json");
    let discovery_url = format!("{issuer}/.well-known/openid-configuration");
    let jwks_uri = format!("http://127.0.0.1:{}/jwks.json", idp_listen.port());

    fs::write(
        &discovery_path,
        serde_json::to_vec_pretty(&json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
            "token_endpoint": format!("{issuer}/oauth2/token"),
            "registration_endpoint": format!("{issuer}/oauth2/register"),
            "jwks_uri": jwks_uri,
        }))
        .expect("serialize oidc discovery document"),
    )
    .expect("write oidc discovery document");
    fs::write(
        &jwks_path,
        serde_json::to_vec_pretty(&jwks).expect("serialize oidc jwks"),
    )
    .expect("write oidc jwks");

    (root, issuer, discovery_url)
}

fn write_oidc_discovery_fixture(
    dir: &Path,
    idp_listen: SocketAddr,
    issuer_path: &str,
    signing_key: &Keypair,
) -> (PathBuf, String, String) {
    write_oidc_discovery_fixture_with_jwks(
        dir,
        idp_listen,
        issuer_path,
        json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "x": URL_SAFE_NO_PAD.encode(signing_key.public_key().as_bytes()),
            }]
        }),
    )
}

fn write_introspection_server_script(dir: &Path) -> PathBuf {
    let script = r#"
import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

RESPONSES_PATH = os.environ["CHIO_INTROSPECTION_RESPONSES_PATH"]
EXPECTED_AUTH = os.environ.get("CHIO_INTROSPECTION_EXPECTED_AUTH")

with open(RESPONSES_PATH, "r", encoding="utf-8") as handle:
    RESPONSES = json.load(handle)

class Handler(BaseHTTPRequestHandler):
    def _write_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._write_json(200, {"ok": True})
            return
        self._write_json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/introspect":
            self._write_json(404, {"error": "not_found"})
            return
        if EXPECTED_AUTH is not None and self.headers.get("Authorization") != EXPECTED_AUTH:
            self._write_json(401, {"error": "invalid_client"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        params = urllib.parse.parse_qs(body)
        token = params.get("token", [""])[0]
        self._write_json(200, RESPONSES.get(token, {"active": False}))

    def log_message(self, format, *args):
        return

HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
"#;
    let script_path = dir.join("introspection_server.py");
    fs::write(&script_path, script).expect("write introspection server script");
    script_path
}

fn spawn_introspection_server(
    script_path: &Path,
    listen: SocketAddr,
    responses_path: &Path,
    expected_auth: Option<&str>,
) -> ServerGuard {
    let mut command = Command::new("python3");
    command
        .env(
            "CHIO_INTROSPECTION_RESPONSES_PATH",
            responses_path
                .to_str()
                .expect("introspection responses path"),
        )
        .args([
            script_path.to_str().expect("introspection script path"),
            &listen.port().to_string(),
        ]);
    if let Some(expected_auth) = expected_auth {
        command.env("CHIO_INTROSPECTION_EXPECTED_AUTH", expected_auth);
    }
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn introspection server");
    ServerGuard { child }
}

fn spawn_static_http_fixture_server(root: &Path, listen: SocketAddr) -> ServerGuard {
    let child = Command::new("python3")
        .args([
            "-m",
            "http.server",
            &listen.port().to_string(),
            "--bind",
            "127.0.0.1",
            "--directory",
            root.to_str().expect("fixture root path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn static fixture server");
    ServerGuard { child }
}

fn wait_for_http_fixture_url(client: &Client, url: &str, guard: &mut ServerGuard) {
    for _ in 0..100 {
        if let Some(status) = guard.child.try_wait().expect("poll fixture child") {
            panic!(
                "{}",
                StartupError::from_child_exit(status, read_child_stderr(&mut guard.child))
                    .panic_context("fixture server")
            );
        }
        match client.get(url).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(_) | Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
    panic!("fixture server did not become ready");
}

fn spawn_http_server_with_oidc_discovery_and_identity_federation(
    dir: &Path,
    listen: SocketAddr,
    discovery_url: &str,
    provider_profile: Option<&str>,
    audience: &str,
    admin_token: &str,
    identity_federation_seed_path: Option<&Path>,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.args([
        "--receipt-db",
        receipt_db_path.to_str().expect("receipt db path"),
        "--revocation-db",
        revocation_db_path.to_str().expect("revocation db path"),
        "--authority-seed-file",
        authority_seed_path.to_str().expect("authority seed path"),
        "mcp",
        "serve-http",
        "--policy",
        policy_path.to_str().expect("policy path"),
        "--server-id",
        "wrapped-http-mock",
        "--server-name",
        "Wrapped HTTP Mock",
        "--listen",
        &listen.to_string(),
        "--auth-jwt-discovery-url",
        discovery_url,
        "--auth-jwt-audience",
        audience,
        "--auth-scope",
        "mcp:invoke",
        "--admin-token",
        admin_token,
    ]);
    if let Some(profile) = provider_profile {
        command.args(["--auth-jwt-provider-profile", profile]);
    }
    if let Some(path) = identity_federation_seed_path {
        command.args([
            "--identity-federation-seed-file",
            path.to_str().expect("identity federation seed path"),
        ]);
    }
    spawn_secured_http_command(
        command,
        dir,
        &script_path,
        "spawn chio mcp serve-http with oidc discovery",
    )
}

fn spawn_http_server_with_token_introspection_and_identity_federation(
    dir: &Path,
    listen: SocketAddr,
    introspection_url: &str,
    introspection_client_id: &str,
    introspection_client_secret: &str,
    issuer: &str,
    audience: &str,
    admin_token: &str,
    identity_federation_seed_path: Option<&Path>,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.args([
        "--receipt-db",
        receipt_db_path.to_str().expect("receipt db path"),
        "--revocation-db",
        revocation_db_path.to_str().expect("revocation db path"),
        "--authority-seed-file",
        authority_seed_path.to_str().expect("authority seed path"),
        "mcp",
        "serve-http",
        "--policy",
        policy_path.to_str().expect("policy path"),
        "--server-id",
        "wrapped-http-mock",
        "--server-name",
        "Wrapped HTTP Mock",
        "--listen",
        &listen.to_string(),
        "--auth-introspection-url",
        introspection_url,
        "--auth-introspection-client-id",
        introspection_client_id,
        "--auth-introspection-client-secret",
        introspection_client_secret,
        "--auth-jwt-issuer",
        issuer,
        "--auth-jwt-audience",
        audience,
        "--auth-scope",
        "mcp:invoke",
        "--admin-token",
        admin_token,
    ]);
    if let Some(path) = identity_federation_seed_path {
        command.args([
            "--identity-federation-seed-file",
            path.to_str().expect("identity federation seed path"),
        ]);
    }
    spawn_secured_http_command(
        command,
        dir,
        &script_path,
        "spawn chio mcp serve-http with token introspection",
    )
}

fn spawn_trust_control_service(
    listen: SocketAddr,
    service_token: &str,
    receipt_db_path: &Path,
    revocation_db_path: &Path,
    authority_db_path: &Path,
    budget_db_path: &Path,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio trust control service");

    ServerGuard { child }
}

fn spawn_http_server_with_control_plane(
    dir: &Path,
    listen: SocketAddr,
    token: &str,
    control_url: &str,
    control_token: &str,
    authority_db_path: &Path,
    control_authority_public_key: &str,
    control_authority_trusted_public_keys: &[String],
    control_tls_root_ca_path: &Path,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command
        .args(["--authority-db"])
        .arg(authority_db_path)
        .args([
            "--control-url",
            control_url,
            "--control-token",
            control_token,
            "--control-authority-public-key",
            control_authority_public_key,
            "mcp",
            "serve-http",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-http-mock",
            "--server-name",
            "Wrapped HTTP Mock",
            "--listen",
            &listen.to_string(),
            "--auth-token",
            token,
        ]);
    if !control_authority_trusted_public_keys.is_empty() {
        command
            .arg("--control-authority-trusted-public-keys")
            .arg(control_authority_trusted_public_keys.join(","));
    }
    command.env("CHIO_CONTROL_TLS_ROOT_CA_FILE", control_tls_root_ca_path);
    spawn_secured_http_command(
        command,
        dir,
        &script_path,
        "spawn control-backed chio mcp serve-http",
    )
}

fn wait_for_server_result(
    client: &Client,
    base_url: &str,
    guard: &mut ServerGuard,
) -> Result<(), StartupError> {
    let deadline = Instant::now() + SERVER_STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        if let Some(status) = guard.child.try_wait().expect("poll remote MCP child") {
            return Err(StartupError::from_child_exit(
                status,
                read_child_stderr(&mut guard.child),
            ));
        }
        match client.get(format!("{base_url}/mcp")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::UNAUTHORIZED => return Ok(()),
            Ok(_) | Err(_) => thread::sleep(SERVER_STARTUP_POLL_INTERVAL),
        }
    }
    Err(StartupError::Timeout(
        "remote MCP server did not become ready",
    ))
}

fn wait_for_server(client: &Client, base_url: &str) {
    let deadline = Instant::now() + SERVER_STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        match client.get(format!("{base_url}/mcp")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::UNAUTHORIZED => return,
            Ok(_) | Err(_) => thread::sleep(SERVER_STARTUP_POLL_INTERVAL),
        }
    }
    panic!("remote MCP server did not become ready");
}

fn wait_for_control_service_result(
    client: &Client,
    base_url: &str,
    guard: &mut ServerGuard,
) -> Result<(), StartupError> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Some(status) = guard.child.try_wait().expect("poll trust control child") {
            return Err(StartupError::from_child_exit(
                status,
                read_child_stderr(&mut guard.child),
            ));
        }
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return Ok(()),
            Ok(_) | Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
    Err(StartupError::Timeout(
        "trust control service did not become ready",
    ))
}

fn post_json(
    client: &Client,
    base_url: &str,
    token: &str,
    session_id: Option<&str>,
    protocol_version: Option<&str>,
    body: &Value,
) -> Response {
    let mut request = client
        .post(format!("{base_url}/mcp"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(ACCEPT, "application/json, text/event-stream")
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(body).expect("serialize request body"));

    if let Some(session_id) = session_id {
        request = request.header("MCP-Session-Id", session_id);
    }
    if let Some(protocol_version) = protocol_version {
        request = request.header("MCP-Protocol-Version", protocol_version);
    }

    request.send().expect("send HTTP MCP request")
}

fn post_json_no_auth(client: &Client, base_url: &str, body: &Value) -> Response {
    client
        .post(format!("{base_url}/mcp"))
        .header(ACCEPT, "application/json, text/event-stream")
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(body).expect("serialize request body"))
        .send()
        .expect("send unauthenticated HTTP MCP request")
}

fn post_raw(
    client: &Client,
    base_url: &str,
    token: Option<&str>,
    session_id: Option<&str>,
    accept: &str,
    content_type: &str,
    body: &Value,
) -> Response {
    let mut request = client
        .post(format!("{base_url}/mcp"))
        .header(ACCEPT, accept)
        .header(CONTENT_TYPE, content_type)
        .body(serde_json::to_vec(body).expect("serialize request body"));

    if let Some(token) = token {
        request = request.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(session_id) = session_id {
        request = request.header("MCP-Session-Id", session_id);
    }

    request.send().expect("send raw HTTP MCP request")
}

fn post_bytes(
    client: &Client,
    base_url: &str,
    token: Option<&str>,
    session_id: Option<&str>,
    accept: &str,
    content_type: &str,
    body: &[u8],
) -> Response {
    let mut request = client
        .post(format!("{base_url}/mcp"))
        .header(ACCEPT, accept)
        .header(CONTENT_TYPE, content_type)
        .body(body.to_vec());

    if let Some(token) = token {
        request = request.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(session_id) = session_id {
        request = request.header("MCP-Session-Id", session_id);
    }

    request.send().expect("send raw byte HTTP MCP request")
}
