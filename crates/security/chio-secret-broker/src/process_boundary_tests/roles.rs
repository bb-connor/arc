use super::*;

struct StaticResolver(IpAddr);

impl DestinationResolver for StaticResolver {
    fn resolve(&self, host: &str, _port: u16) -> Result<Vec<IpAddr>> {
        if host != UPSTREAM_HOST {
            return Err(BrokerError::AuthorizationDenied(
                "process-boundary resolver received an unknown host".to_string(),
            ));
        }
        Ok(vec![self.0])
    }
}

pub(super) fn run_broker_helper() -> Result<()> {
    harden_broker_process_custody()?;
    let config = BrokerDaemonConfig::load(required_environment(CONFIG_ENV))?;
    let certificate = fs::read(required_environment(CERT_ENV))
        .map_err(|_| BrokerError::Storage("test root certificate read failed".to_string()))?;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate))
        .map_err(|_| BrokerError::InvalidRequest("test root certificate is invalid".to_string()))?;
    let builder =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .map_err(|_| BrokerError::Invariant("test TLS protocols are invalid".to_string()))?;
    let mut client_config = builder.with_root_certificates(roots).with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let https = Arc::new(GenericHttpsExecutor::new(
        Arc::new(StaticResolver(loopback)),
        Arc::new(RustlsPinnedHttpsTransport::with_tls_config(Arc::new(
            client_config,
        ))),
        NetworkPolicy {
            allow_loopback_test: true,
            allow_exact_address: Some(loopback),
        },
    ));
    let master_key = inherited_key_file(MASTER_FD_ENV, "master key")?;
    let signing_key = inherited_key_file(SIGNING_FD_ENV, "signing key")?;
    BrokerDaemonRuntime::build_for_process_boundary_test(config, master_key, signing_key, https)?
        .serve()
}

fn inherited_key_file(environment: &str, label: &str) -> Result<File> {
    let descriptor = required_environment(environment)
        .parse::<u32>()
        .map_err(|_| BrokerError::Custody(format!("{label} descriptor is invalid")))?;
    // SAFETY: the controller clears CLOEXEC only for this broker spawn and
    // transfers the descriptor exclusively. No Rust value in the child owns
    // the original descriptor number.
    #[allow(unsafe_code)]
    let file = unsafe { adopt_inherited_key_file(descriptor, label) }?;
    secure_inherited_key_file(file, label)
}

pub(super) fn run_calling_tool_helper() {
    let probe = CanaryProbe::from_environment();
    let request_bytes =
        hex::decode(required_environment(REQUEST_ENV)).test_expect("execute request encoding");
    probe.assert_absent(&request_bytes, "tool execute request");
    let request: BrokerExecuteRequest =
        serde_json::from_slice(&request_bytes).test_expect("tool execute request");
    assert_eq!(
        canonical_json_bytes(&request).test_expect("canonical tool execute request"),
        request_bytes
    );
    let receipt_signer_bytes = hex::decode(required_environment(RECEIPT_SIGNER_ENV))
        .test_expect("receipt signer encoding");
    let receipt_signer: PublicKey =
        serde_json::from_slice(&receipt_signer_bytes).test_expect("receipt signer");

    let stdin = io::stdin();
    let descriptor = stdin
        .as_fd()
        .try_clone_to_owned()
        .test_expect("tool broker descriptor");
    let transcript = BrokerIpcClient::execute_evidenced_on_authenticated_stream(
        UnixStream::from(descriptor),
        TENANT_SCOPE,
        &request,
        &receipt_signer,
    )
    .test_expect("production preconnected broker execution");
    probe.assert_absent(&transcript.canonical_request_frame, "tool IPC request");
    probe.assert_absent(&transcript.canonical_response_frame, "tool IPC response");
    let response = match transcript.outcome {
        BrokerIpcExecutionOutcome::Success(response) => *response,
        BrokerIpcExecutionOutcome::Failure(_) => panic!("tool execution was denied"),
    };
    let execute_response =
        canonical_json_bytes(&response).test_expect("canonical tool execute response");
    let receipt = canonical_json_bytes(&response.receipt).test_expect("canonical tool receipt");
    probe.assert_absent(&execute_response, "tool execute response");
    probe.assert_absent(&receipt, "tool receipt");

    let broker_pid = required_environment(BROKER_PID_ENV)
        .parse::<u32>()
        .test_expect("broker process ID");
    scan_tool_process_surfaces(&probe, broker_pid);

    let report = ToolBoundaryReport {
        schema: "chio.process-boundary-tool-report.v1".to_string(),
        request_frame_hex: hex::encode(&transcript.canonical_request_frame),
        response_frame_hex: hex::encode(&transcript.canonical_response_frame),
        execute_response_hex: hex::encode(&execute_response),
        receipt_hex: hex::encode(&receipt),
        scanned_surfaces: TOOL_SCANNED_SURFACES
            .iter()
            .map(|surface| (*surface).to_string())
            .collect(),
    };
    let report = serde_json::to_string(&report).test_expect("tool report");
    println!("{TOOL_REPORT_PREFIX}{report}");
    io::stdout().flush().test_expect("tool report flush");
    eprintln!("{TOOL_LOG_MARKER}");
}

pub(super) fn run_unavailable_tool_helper() {
    let probe = CanaryProbe::from_environment();
    let request_bytes = hex::decode(required_environment(REQUEST_ENV))
        .test_expect("unavailable execute request encoding");
    probe.assert_absent(&request_bytes, "unavailable tool execute request");
    let request: BrokerExecuteRequest =
        serde_json::from_slice(&request_bytes).test_expect("unavailable execute request");
    assert_eq!(
        canonical_json_bytes(&request).test_expect("canonical unavailable execute request"),
        request_bytes
    );
    let receipt_signer_bytes = hex::decode(required_environment(RECEIPT_SIGNER_ENV))
        .test_expect("unavailable receipt signer encoding");
    let receipt_signer: PublicKey =
        serde_json::from_slice(&receipt_signer_bytes).test_expect("unavailable receipt signer");
    scan_own_args_and_environment(&probe);
    scan_regular_tree(&probe, Path::new("."));
    scan_process_fds(&probe, std::process::id(), "unavailable tool");

    let stdin = io::stdin();
    let descriptor = stdin
        .as_fd()
        .try_clone_to_owned()
        .test_expect("unavailable broker descriptor");
    let error = BrokerIpcClient::execute_evidenced_on_authenticated_stream(
        UnixStream::from(descriptor),
        TENANT_SCOPE,
        &request,
        &receipt_signer,
    )
    .err()
    .test_expect("dead broker descriptor must fail closed");
    assert!(matches!(error, BrokerError::AuthorityUnavailable(_)));
    probe.assert_absent(error.to_string().as_bytes(), "unavailable broker error");
    scan_own_args_and_environment(&probe);
    scan_regular_tree(&probe, Path::new("."));
    scan_process_fds(&probe, std::process::id(), "unavailable tool after failure");
    println!("{FALLBACK_MARKER}");
    io::stdout()
        .flush()
        .test_expect("unavailable tool output flush");
}

fn scan_tool_process_surfaces(probe: &CanaryProbe, broker_pid: u32) {
    assert_no_ptrace_capability();
    scan_own_args_and_environment(probe);
    let self_proc = PathBuf::from(format!("/proc/{}", std::process::id()));
    let broker_proc = PathBuf::from(format!("/proc/{broker_pid}"));
    scan_required_file(probe, &self_proc.join("cmdline"), "tool proc cmdline");
    scan_required_file(probe, &self_proc.join("environ"), "tool proc environment");
    scan_required_file(probe, &broker_proc.join("cmdline"), "broker proc cmdline");
    assert_process_surface_denied(&broker_proc.join("environ"), "broker proc environment");
    assert_process_surface_denied(&broker_proc.join("mem"), "broker process memory");
    scan_regular_tree(probe, Path::new("."));
    scan_process_fds(probe, std::process::id(), "tool");
    assert_process_fd_access_denied(broker_pid);
}

fn assert_no_ptrace_capability() {
    const CAP_SYS_PTRACE: u64 = 1 << 19;
    let status = fs::read_to_string("/proc/self/status").test_expect("tool proc status");
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .test_expect("tool effective capability set");
    let effective =
        u64::from_str_radix(effective, 16).test_expect("tool effective capability encoding");
    assert_eq!(effective & CAP_SYS_PTRACE, 0);
}

fn assert_process_surface_denied(path: &Path, surface: &str) {
    match File::open(path) {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
        Err(error) => panic!("{surface} denial failed with unexpected error: {error}"),
        Ok(_) => panic!("{surface} remained readable"),
    }
}

fn assert_process_fd_access_denied(process_id: u32) {
    let directory = PathBuf::from(format!("/proc/{process_id}/fd"));
    let entries = match fs::read_dir(&directory) {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("broker descriptor denial failed: {error}"),
        Ok(entries) => entries,
    };
    for entry in entries {
        let path = entry.test_expect("broker descriptor denial entry").path();
        match fs::read_link(&path) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
                ) => {}
            Err(error) => panic!("broker descriptor target denial failed: {error}"),
            Ok(_) => panic!("broker descriptor target remained readable"),
        }
    }
}

fn scan_own_args_and_environment(probe: &CanaryProbe) {
    for argument in std::env::args_os() {
        probe.assert_absent(argument.as_bytes(), "tool argv");
    }
    for (name, value) in std::env::vars_os() {
        probe.assert_absent(name.as_bytes(), "tool environment name");
        probe.assert_absent(value.as_bytes(), "tool environment value");
    }
}

fn scan_required_file(probe: &CanaryProbe, path: &Path, surface: &str) {
    let bytes = fs::read(path).test_expect("required process surface");
    probe.assert_absent(&bytes, surface);
}

fn scan_regular_tree(probe: &CanaryProbe, root: &Path) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).test_expect("boundary file metadata");
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path).test_expect("boundary symlink target");
            probe.assert_absent(
                target.as_os_str().as_bytes(),
                "readable file symlink target",
            );
        } else if metadata.is_dir() {
            for entry in fs::read_dir(&path).test_expect("boundary directory") {
                pending.push(entry.test_expect("boundary directory entry").path());
            }
        } else if metadata.is_file() {
            assert!(metadata.len() <= MAX_SCANNED_FILE_BYTES);
            let bytes = fs::read(&path).test_expect("boundary readable file");
            probe.assert_absent(&bytes, "readable file");
        }
    }
}

fn scan_process_fds(probe: &CanaryProbe, process_id: u32, process_label: &str) {
    let directory = PathBuf::from(format!("/proc/{process_id}/fd"));
    for entry in fs::read_dir(directory).test_expect("process descriptor directory") {
        let entry = entry.test_expect("process descriptor entry");
        let path = entry.path();
        let target = match fs::read_link(&path) {
            Ok(target) => target,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => panic!("{process_label} descriptor target failed: {error}"),
        };
        probe.assert_absent(target.as_os_str().as_bytes(), "descriptor target");
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => panic!("{process_label} descriptor metadata failed: {error}"),
        };
        if metadata.is_file() {
            assert!(metadata.len() <= MAX_SCANNED_FILE_BYTES);
            match fs::read(&path) {
                Ok(bytes) => probe.assert_absent(&bytes, "open readable descriptor"),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => panic!("{process_label} readable descriptor failed: {error}"),
            }
        }
    }
}

pub(super) fn run_fake_upstream_helper() {
    let probe = CanaryProbe::from_environment();
    let certificate = CertificateDer::from(
        fs::read(required_environment(CERT_ENV)).test_expect("upstream certificate"),
    );
    let private_key = PrivatePkcs8KeyDer::from(
        fs::read(required_environment(KEY_ENV)).test_expect("upstream private key"),
    )
    .into();
    let builder =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .test_expect("upstream TLS protocols");
    let mut server_config = builder
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .test_expect("upstream TLS identity");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let stdin = io::stdin();
    let descriptor = stdin
        .as_fd()
        .try_clone_to_owned()
        .test_expect("upstream listener descriptor");
    let listener = TcpListener::from(descriptor);
    let upstream_port = listener
        .local_addr()
        .test_expect("upstream listener address")
        .port();
    listener
        .set_nonblocking(true)
        .test_expect("upstream nonblocking listener");
    let accept_deadline = Instant::now() + Duration::from_secs(10);
    let socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < accept_deadline,
                    "upstream connection timed out"
                );
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("upstream connection failed: {error}"),
        }
    };
    let io_timeout = Some(Duration::from_secs(5));
    socket
        .set_read_timeout(io_timeout)
        .test_expect("upstream read timeout");
    socket
        .set_write_timeout(io_timeout)
        .test_expect("upstream write timeout");
    let connection =
        ServerConnection::new(Arc::new(server_config)).test_expect("upstream TLS connection");
    let mut stream = StreamOwned::new(connection, socket);
    let request = read_boundary_http_request(&mut stream);
    assert_no_trailing_http_plaintext(&mut stream);
    let matching_offsets = probe.matching_offsets(&request.raw);
    assert_eq!(matching_offsets.len(), 1);
    assert_eq!(request.method, "POST");
    assert_eq!(request.path_and_query, UPSTREAM_PATH_AND_QUERY);
    assert_eq!(request.http_version, "HTTP/1.1");
    assert_eq!(request.body, UPSTREAM_REQUEST_BODY);
    let expected_host = format!("{UPSTREAM_HOST}:{upstream_port}");
    let host = only_header(&request, "host");
    assert_eq!(host, expected_host.as_bytes());
    assert_eq!(only_header(&request, "connection"), b"close");
    assert_eq!(only_header(&request, "accept-encoding"), b"identity");
    assert_eq!(header_count(&request, "content-length"), 1);
    assert_eq!(header_count(&request, "transfer-encoding"), 0);
    assert_eq!(header_count(&request, "proxy-authorization"), 0);
    assert_eq!(header_count(&request, "expect"), 0);
    let authorization_header_count = header_count(&request, "authorization");
    assert_eq!(authorization_header_count, 1);
    let authorization = only_header(&request, "authorization");
    let authorization_credential = authorization
        .strip_prefix(b"Bearer ")
        .test_expect("upstream exact Bearer authorization");
    let authorization_digest: [u8; 32] = Sha256::digest(authorization_credential).into();
    let authorization_exact_bearer_canary =
        authorization_credential.len() == probe.length && authorization_digest == probe.sha256;
    assert!(authorization_exact_bearer_canary);
    let header_names = request
        .headers
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        header_names,
        [
            "host",
            "connection",
            "accept-encoding",
            "content-length",
            "authorization"
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>()
    );
    stream
        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
        .test_expect("upstream response");
    stream.flush().test_expect("upstream response flush");
    drop(stream);

    let fallback_marker = PathBuf::from(required_environment(FALLBACK_MARKER_ENV));
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut connection_count = 1;
    while !fallback_marker.exists() {
        match listener.accept() {
            Ok((extra, _)) => {
                connection_count += 1;
                drop(extra);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("upstream fallback observation failed: {error}"),
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    let quiet_deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < quiet_deadline {
        match listener.accept() {
            Ok((extra, _)) => {
                connection_count += 1;
                drop(extra);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("upstream final observation failed: {error}"),
        }
    }
    let content_length_header_count = header_count(&request, "content-length");
    let transfer_encoding_header_count = header_count(&request, "transfer-encoding");
    let body_hex = hex::encode(&request.body);
    let body_sha256 = body_digest(&request.body);
    let request_sha256 = hex::encode(Sha256::digest(&request.raw));
    let report = UpstreamBoundaryReport {
        schema: "chio.process-boundary-upstream-report.v2".to_string(),
        method: request.method,
        path_and_query: request.path_and_query,
        http_version: request.http_version,
        host: expected_host,
        header_names,
        body_hex,
        body_sha256,
        credential_matches: matching_offsets.len(),
        authorization_header_count,
        authorization_exact_bearer_canary,
        content_length_header_count,
        transfer_encoding_header_count,
        connection_count,
        request_sha256,
    };
    println!(
        "{UPSTREAM_REPORT_PREFIX}{}",
        serde_json::to_string(&report).test_expect("upstream report")
    );
}

struct ParsedBoundaryHttpRequest {
    raw: Vec<u8>,
    method: String,
    path_and_query: String,
    http_version: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

fn read_boundary_http_request(reader: &mut impl Read) -> ParsedBoundaryHttpRequest {
    let mut request_head = Vec::new();
    let mut byte = [0_u8; 1];
    while !request_head.ends_with(b"\r\n\r\n") {
        assert!(request_head.len() < MAX_WIRE_BYTES);
        reader
            .read_exact(&mut byte)
            .test_expect("upstream request head");
        request_head.push(byte[0]);
    }
    for (offset, byte) in request_head.iter().enumerate() {
        if *byte == b'\n' {
            assert!(offset > 0 && request_head[offset - 1] == b'\r');
        } else if *byte == b'\r' {
            assert!(request_head.get(offset + 1) == Some(&b'\n'));
        }
    }
    let head = std::str::from_utf8(&request_head[..request_head.len() - 4])
        .test_expect("upstream request head encoding");
    let mut lines = head.split("\r\n");
    let request_line = lines.next().test_expect("upstream request line");
    let request_line_parts = request_line.split(' ').collect::<Vec<_>>();
    assert_eq!(request_line_parts.len(), 3);
    assert!(request_line_parts.iter().all(|part| !part.is_empty()));
    let method = request_line_parts[0].to_string();
    let path_and_query = request_line_parts[1].to_string();
    let http_version = request_line_parts[2].to_string();
    let mut names = std::collections::BTreeSet::new();
    let mut headers = Vec::new();
    for line in lines {
        assert!(!line.is_empty());
        assert!(!line
            .as_bytes()
            .first()
            .is_some_and(|byte| matches!(*byte, b' ' | b'\t')));
        let (name, value) = line
            .split_once(':')
            .test_expect("upstream header delimiter");
        assert!(!name.is_empty());
        assert!(name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'));
        let normalized_name = name.to_ascii_lowercase();
        assert!(names.insert(normalized_name.clone()));
        let value = value
            .trim_matches(|character| matches!(character, ' ' | '\t'))
            .as_bytes()
            .to_vec();
        headers.push((normalized_name, value));
    }
    let content_length_value = headers
        .iter()
        .find_map(|(name, value)| (name == "content-length").then_some(value.as_slice()))
        .test_expect("upstream content length");
    let content_length_text =
        std::str::from_utf8(content_length_value).test_expect("upstream content length encoding");
    let content_length = content_length_text
        .parse::<usize>()
        .test_expect("upstream content length value");
    assert_eq!(content_length_text, content_length.to_string());
    assert!(!headers.iter().any(|(name, _)| name == "transfer-encoding"));
    assert!(
        request_head.len().saturating_add(content_length) <= MAX_WIRE_BYTES,
        "upstream request exceeded bound"
    );
    let mut body = vec![0; content_length];
    reader
        .read_exact(&mut body)
        .test_expect("upstream request body");
    let mut raw = request_head;
    raw.extend_from_slice(&body);
    ParsedBoundaryHttpRequest {
        raw,
        method,
        path_and_query,
        http_version,
        headers,
        body,
    }
}

fn assert_no_trailing_http_plaintext(
    stream: &mut StreamOwned<ServerConnection, std::net::TcpStream>,
) {
    stream
        .sock
        .set_read_timeout(Some(Duration::from_millis(100)))
        .test_expect("upstream trailing-byte timeout");
    let mut trailing = [0_u8; 1];
    match stream.read(&mut trailing) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => {}
        Ok(0) => {}
        Ok(_) => panic!("upstream request contained trailing or pipelined plaintext"),
        Err(error) => panic!("upstream trailing-byte observation failed: {error}"),
    }
    stream
        .sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .test_expect("restore upstream read timeout");
}

fn header_count(request: &ParsedBoundaryHttpRequest, name: &str) -> usize {
    request
        .headers
        .iter()
        .filter(|(observed, _)| observed == name)
        .count()
}

fn only_header<'a>(request: &'a ParsedBoundaryHttpRequest, name: &str) -> &'a [u8] {
    assert_eq!(header_count(request, name), 1);
    request
        .headers
        .iter()
        .find_map(|(observed, value)| (observed == name).then_some(value.as_slice()))
        .test_expect("upstream required header")
}

pub(super) fn assert_raw_absent(canary: &[u8], bytes: &[u8], surface: &str) {
    assert!(
        !bytes
            .windows(canary.len())
            .any(|candidate| candidate == canary),
        "credential canary crossed {surface}"
    );
}

pub(super) fn scan_tree_for_raw_canary(canary: &[u8], root: &Path) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).test_expect("persisted surface metadata");
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).test_expect("persisted surface directory") {
                pending.push(entry.test_expect("persisted surface entry").path());
            }
        } else if metadata.is_file() {
            let bytes = fs::read(&path).test_expect("persisted surface file");
            assert_raw_absent(canary, &bytes, "persisted file");
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path).test_expect("persisted surface symlink");
            assert_raw_absent(canary, target.as_os_str().as_bytes(), "persisted symlink");
        }
    }
}
