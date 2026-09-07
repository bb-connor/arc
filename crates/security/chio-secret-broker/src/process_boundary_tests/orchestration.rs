use super::fixture::*;
use super::roles::{assert_raw_absent, scan_tree_for_raw_canary};
use super::*;
use std::os::unix::process::CommandExt;

struct ManagedChild {
    child: Option<Child>,
}

impl ManagedChild {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().test_expect("managed child").id()
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child
            .as_mut()
            .test_expect("managed child")
            .try_wait()
            .test_expect("managed child status")
    }

    fn wait_output(&mut self) -> Output {
        self.child
            .take()
            .test_expect("managed child")
            .wait_with_output()
            .test_expect("managed child output")
    }

    fn kill_and_output(&mut self) -> Output {
        let mut child = self.child.take().test_expect("managed child");
        assert!(
            child
                .try_wait()
                .test_expect("managed child status")
                .is_none(),
            "managed child exited before required termination"
        );
        child.kill().test_expect("managed child termination");
        let output = child
            .wait_with_output()
            .test_expect("managed child terminated output");
        assert!(!output.status.success());
        output
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn helper_command(test_name: &str, role: &str, current_directory: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().test_expect("current test executable"));
    command
        .arg(test_name)
        .arg("--exact")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env_clear()
        .env(ROLE_ENV, role)
        .current_dir(current_directory)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn spawn_with_stdin(mut command: Command, descriptor: OwnedFd, label: &str) -> ManagedChild {
    command.stdin(Stdio::from(descriptor));
    ManagedChild::new(command.spawn().test_expect(label))
}

fn inherit_seed_descriptors_in_child(command: &mut Command, descriptors: [i32; 2]) {
    assert!(descriptors.iter().all(|descriptor| *descriptor >= 3));
    assert_ne!(descriptors[0], descriptors[1]);
    // SAFETY: pre_exec runs after fork in the broker child. The closure invokes
    // only async-signal-safe fcntl calls on live descriptors retained by the
    // controller, clearing CLOEXEC in that child immediately before exec.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(move || {
            for descriptor in descriptors {
                if libc::fcntl(descriptor, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

fn report_from_output<T: for<'de> Deserialize<'de>>(output: &[u8], prefix: &str) -> T {
    let text = std::str::from_utf8(output).test_expect("helper UTF-8 output");
    let line = text
        .lines()
        .find_map(|line| line.split_once(prefix).map(|(_, report)| report))
        .test_expect("helper report marker");
    serde_json::from_str(line).test_expect("helper report payload")
}

fn wait_for_broker(broker: &mut ManagedChild, config: &BrokerDaemonConfig) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !(config.ipc_socket_path.exists() && config.privileged_audit.socket_path.exists()) {
        assert!(
            broker.try_wait().is_none(),
            "broker helper exited before readiness"
        );
        assert!(
            Instant::now() < deadline,
            "broker helper readiness timed out"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn expected_boundary_http_request(request: &BrokerExecuteRequest, canary: &[u8]) -> Vec<u8> {
    let destination = &request.request.destination;
    assert!(request.request.headers.is_empty());
    let mut expected = Vec::new();
    expected.extend_from_slice(destination.method.as_bytes());
    expected.push(b' ');
    expected.extend_from_slice(destination.exact_path_and_query.as_bytes());
    expected.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    expected.extend_from_slice(destination.authority().as_bytes());
    expected.extend_from_slice(
        b"\r\nConnection: close\r\nAccept-Encoding: identity\r\nContent-Length: ",
    );
    expected.extend_from_slice(request.request.body.len().to_string().as_bytes());
    expected.extend_from_slice(b"\r\nauthorization: Bearer ");
    expected.extend_from_slice(canary);
    expected.extend_from_slice(b"\r\n\r\n");
    expected.extend_from_slice(&request.request.body);
    expected
}

pub(super) fn run_boundary_test() {
    let tempdir = crate::private_tempdir().test_expect("process-boundary tempdir");
    fs::set_permissions(tempdir.path(), fs::Permissions::from_mode(0o700))
        .test_expect("process-boundary directory permissions");
    let directory = fs::canonicalize(tempdir.path()).test_expect("process-boundary directory");

    let canary = random_canary();
    let probe = CanaryProbe::from_bytes(&canary);
    let master_seed = sealed_seed("boundary-master", &[201; 32]);
    let signing_seed_bytes = [202; 32];
    let broker_key = Keypair::from_seed(&signing_seed_bytes);
    let signing_seed = sealed_seed("boundary-signing", &signing_seed_bytes);
    let service_uid = master_seed
        .metadata()
        .test_expect("master seed metadata")
        .uid();
    let capability_issuer = Keypair::from_seed(&[203; 32]);
    let authority_key = Keypair::from_seed(&[204; 32]);
    let caller = Keypair::from_seed(&[208; 32]);

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .test_expect("process-boundary upstream listener");
    let upstream_port = listener
        .local_addr()
        .test_expect("process-boundary upstream address")
        .port();
    let fixture = boundary_fixture(
        &directory,
        upstream_port,
        broker_key.public_key(),
        capability_issuer.public_key(),
        authority_key.public_key(),
        service_uid,
    );
    let authority_server = AuthorityRpcServer::bind(
        &fixture.config.authority_socket_path,
        broker_key.public_key(),
        Arc::new(Ed25519Backend::new(authority_key.clone())),
        Arc::new(BoundaryAuthority),
        30,
    )
    .test_expect("process-boundary authority server");
    let mut authority = AuthorityServerGuard::start(authority_server);

    let mut upstream_command = helper_command(UPSTREAM_HELPER, "upstream", &directory);
    upstream_command
        .env(CERT_ENV, &fixture.certificate_path)
        .env(KEY_ENV, &fixture.private_key_path)
        .env(FALLBACK_MARKER_ENV, &fixture.fallback_marker_path)
        .env(CANARY_LENGTH_ENV, probe.length.to_string())
        .env(CANARY_DIGEST_ENV, hex::encode(probe.sha256));
    let mut upstream = spawn_with_stdin(
        upstream_command,
        OwnedFd::from(listener),
        "process-boundary upstream helper",
    );

    let mut broker_command = helper_command(BROKER_HELPER, "broker", &directory);
    broker_command
        .stdin(Stdio::null())
        .env(CONFIG_ENV, &fixture.config_path)
        .env(CERT_ENV, &fixture.certificate_path)
        .env(MASTER_FD_ENV, master_seed.as_raw_fd().to_string())
        .env(SIGNING_FD_ENV, signing_seed.as_raw_fd().to_string());
    inherit_seed_descriptors_in_child(
        &mut broker_command,
        [master_seed.as_raw_fd(), signing_seed.as_raw_fd()],
    );
    let broker_spawn = broker_command.spawn();
    for seed in [&master_seed, &signing_seed] {
        assert!(fcntl_getfd(seed)
            .test_expect("parent seed descriptor flags after broker spawn")
            .contains(FdFlags::CLOEXEC));
    }
    let mut broker = ManagedChild::new(broker_spawn.test_expect("process-boundary broker helper"));
    wait_for_broker(&mut broker, &fixture.config);
    authority.assert_healthy();

    let credential = CredentialRef {
        provider: CREDENTIAL_PROVIDER.to_string(),
        credential_id: CREDENTIAL_ID.to_string(),
        version: 1,
    };
    let provision_response = provision_credential(
        &fixture.config.ipc_socket_path,
        &credential,
        &canary,
        &fixture.approver,
        &fixture.admin_subject,
    );
    assert_raw_absent(&canary, &provision_response.response, "provision response");

    let request = execution_request(upstream_port, credential, &capability_issuer, &caller);
    let expected_upstream_request = expected_boundary_http_request(&request, &canary);
    let registration = boundary_registration(&request).test_expect("boundary registration");
    let broker_identity = BrokerPeerIdentity {
        process_id: broker.id(),
        user_id: service_uid,
        group_id: rustix::process::getegid().as_raw(),
    };
    let client = BrokerIpcClient::new(
        BrokerIpcClientConfig {
            socket_path: fixture.config.ipc_socket_path.clone(),
            tenant_scope: TENANT_SCOPE.to_string(),
            timeout_ms: 3_000,
            expected_peer: broker_identity,
            trusted_receipt_signer: broker_key.public_key(),
        },
        Arc::new(Ed25519Backend::new(authority_key.clone())),
    )
    .test_expect("process-boundary IPC client");
    let _ = client
        .register_attempt(&registration, &request)
        .test_expect("registered process-boundary attempt");
    let prepared = client
        .prepare_dispatch(&registration, &request)
        .test_expect("prepared process-boundary dispatch");
    assert_eq!(
        prepared.prepared_dispatch_id,
        prepared_dispatch_id(&registration, &request).test_expect("prepared dispatch binding")
    );

    let request_bytes =
        canonical_json_bytes(&request).test_expect("canonical process-boundary execute request");
    let frame = execute_frame(&request);
    assert_raw_absent(&canary, &frame, "controller execute frame");
    let receipt_signer_bytes = canonical_json_bytes(&broker_key.public_key())
        .test_expect("canonical process-boundary receipt signer");
    let broker_stream = client
        .connect_authenticated()
        .test_expect("authenticated tool broker descriptor");
    let mut tool_command = helper_command(TOOL_HELPER, "tool", &directory);
    tool_command
        .env(REQUEST_ENV, hex::encode(&request_bytes))
        .env(RECEIPT_SIGNER_ENV, hex::encode(&receipt_signer_bytes))
        .env(CANARY_LENGTH_ENV, probe.length.to_string())
        .env(CANARY_DIGEST_ENV, hex::encode(probe.sha256))
        .env(BROKER_PID_ENV, broker.id().to_string());
    let mut tool = spawn_with_stdin(
        tool_command,
        OwnedFd::from(broker_stream),
        "process-boundary tool helper",
    );
    let tool_output = tool.wait_output();
    assert!(!tool_output.status.success());
    assert_raw_absent(&canary, &tool_output.stdout, "tool stdout");
    assert_raw_absent(&canary, &tool_output.stderr, "tool stderr and panic output");
    let tool_stderr = std::str::from_utf8(&tool_output.stderr).test_expect("tool stderr encoding");
    assert!(tool_stderr.contains(TOOL_LOG_MARKER));
    assert!(tool_stderr.contains(TOOL_PANIC_MARKER));
    let tool_report: ToolBoundaryReport =
        report_from_output(&tool_output.stdout, TOOL_REPORT_PREFIX);
    assert_eq!(tool_report.schema, "chio.process-boundary-tool-report.v1");
    assert_eq!(
        hex::decode(&tool_report.request_frame_hex).test_expect("reported request frame"),
        frame
    );
    let response_frame =
        hex::decode(&tool_report.response_frame_hex).test_expect("reported response frame");
    assert_raw_absent(&canary, &response_frame, "reported IPC response");
    let outer: IpcResponse =
        serde_json::from_slice(&response_frame).test_expect("reported response envelope");
    assert!(outer.accepted);
    assert_eq!(outer.operation, IpcOperation::Execute);
    assert_eq!(
        canonical_json_bytes(&outer).test_expect("canonical outer response"),
        response_frame
    );
    let response: BrokerExecuteResponse =
        serde_json::from_slice(&outer.response).test_expect("reported execute response");
    assert_raw_absent(&canary, &outer.response, "nested execute response");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok");
    assert_eq!(response.evidence.attempt_id, registration.ids.attempt_id);
    verify_execution_receipt(&response.receipt, &broker_key.public_key())
        .test_expect("process-boundary receipt signature");
    let expected_request_digest =
        broker_request_digest(&request).test_expect("logical process-boundary request digest");
    let expected_capability_digest =
        capability_digest(&request.capability).test_expect("process-boundary capability digest");
    let expected_credential_reference =
        credential_reference_hash(&request.capability.body.credential)
            .test_expect("process-boundary credential reference hash");
    assert_eq!(response.evidence.request_digest, expected_request_digest);
    assert_eq!(
        response.evidence.capability_digest,
        expected_capability_digest
    );
    assert_eq!(response.receipt.body.evidence, response.evidence);
    assert_eq!(
        response.receipt.body.operation_id,
        registration.ids.operation_id
    );
    assert_eq!(
        response.receipt.body.authorize_event_id,
        registration.ids.authorize_event_id
    );
    assert_eq!(
        response.receipt.body.capture_event_id,
        registration.ids.capture_event_id
    );
    assert_eq!(response.receipt.body.quotas, registration.quotas);
    assert_eq!(
        response.receipt.body.outcome,
        BrokerExecutionOutcome::Completed
    );
    assert_eq!(
        response.receipt.body.normalized_destination,
        request.request.destination
    );
    assert_eq!(
        response.receipt.body.request_body_sha256,
        body_digest(&request.request.body)
    );
    assert_eq!(
        response.receipt.body.caller_headers_sha256,
        caller_header_digest(&request.request.headers)
            .test_expect("process-boundary caller header digest")
    );
    assert_eq!(
        response.receipt.body.caller_options_sha256,
        caller_option_digest(&request.request.options)
            .test_expect("process-boundary caller option digest")
    );
    assert_eq!(
        response.receipt.body.request_body_bytes,
        u64::try_from(request.request.body.len()).test_expect("request body length")
    );
    assert_eq!(response.receipt.body.response_body_bytes, 2);
    assert_eq!(
        response.receipt.body.source_receipt_ids,
        vec!["source-receipt-process-boundary".to_string()]
    );
    assert_eq!(
        response.receipt.body.credential_reference_hash,
        expected_credential_reference
    );
    assert_eq!(
        response.receipt.body.credential_version,
        request.capability.body.credential.version
    );
    assert_eq!(
        response.receipt.body.parent_capability_id,
        request.capability.body.parent_capability_id
    );
    assert_eq!(
        response.receipt.body.broker_capability_id,
        request.capability.body.capability_id
    );
    assert_eq!(
        response.receipt.body.subject,
        request.capability.body.subject
    );
    assert_eq!(
        response.receipt.body.provider_adapter_id,
        request.capability.body.provider_adapter_id
    );
    assert_eq!(
        response.receipt.body.provider_adapter_version,
        request.capability.body.provider_adapter_version
    );
    assert_eq!(
        response.receipt_reference,
        format!(
            "broker-receipt-sha256-{}",
            receipt_digest(&response.receipt).test_expect("process-boundary receipt digest")
        )
    );
    let canonical_response =
        canonical_json_bytes(&response).test_expect("canonical process-boundary response");
    let canonical_receipt =
        canonical_json_bytes(&response.receipt).test_expect("canonical process-boundary receipt");
    assert_raw_absent(&canary, &canonical_response, "canonical execute response");
    assert_raw_absent(&canary, &canonical_receipt, "canonical execution receipt");
    assert_eq!(
        hex::decode(&tool_report.execute_response_hex).test_expect("reported execute response"),
        canonical_response
    );
    assert_eq!(
        hex::decode(&tool_report.receipt_hex).test_expect("reported receipt"),
        canonical_receipt
    );
    assert_eq!(
        tool_report.scanned_surfaces,
        TOOL_SCANNED_SURFACES
            .iter()
            .map(|surface| (*surface).to_string())
            .collect::<Vec<_>>()
    );

    let killed_broker_stream = client
        .connect_authenticated()
        .test_expect("authenticated broker-death descriptor");
    let broker_output = broker.kill_and_output();
    assert_raw_absent(&canary, &broker_output.stdout, "broker stdout");
    assert_raw_absent(&canary, &broker_output.stderr, "broker stderr");
    authority.stop();

    let mut unavailable_command = helper_command(TOOL_HELPER, "tool_unavailable", &directory);
    unavailable_command
        .env(REQUEST_ENV, hex::encode(&request_bytes))
        .env(RECEIPT_SIGNER_ENV, hex::encode(&receipt_signer_bytes))
        .env(CANARY_LENGTH_ENV, probe.length.to_string())
        .env(CANARY_DIGEST_ENV, hex::encode(probe.sha256));
    let mut unavailable = spawn_with_stdin(
        unavailable_command,
        OwnedFd::from(killed_broker_stream),
        "unavailable process-boundary tool helper",
    );
    let unavailable_output = unavailable.wait_output();
    assert!(unavailable_output.status.success());
    assert_raw_absent(
        &canary,
        &unavailable_output.stdout,
        "unavailable tool stdout",
    );
    assert_raw_absent(
        &canary,
        &unavailable_output.stderr,
        "unavailable tool stderr",
    );
    let unavailable_stdout =
        std::str::from_utf8(&unavailable_output.stdout).test_expect("unavailable tool output");
    assert!(unavailable_stdout.contains(FALLBACK_MARKER));

    write_private(&fixture.fallback_marker_path, b"complete");
    let upstream_output = upstream.wait_output();
    assert!(upstream_output.status.success());
    assert_raw_absent(&canary, &upstream_output.stdout, "upstream stdout");
    assert_raw_absent(&canary, &upstream_output.stderr, "upstream stderr");
    let upstream_report: UpstreamBoundaryReport =
        report_from_output(&upstream_output.stdout, UPSTREAM_REPORT_PREFIX);
    assert_eq!(
        upstream_report.schema,
        "chio.process-boundary-upstream-report.v2"
    );
    assert_eq!(upstream_report.method, request.request.destination.method);
    assert_eq!(
        upstream_report.path_and_query,
        request.request.destination.exact_path_and_query
    );
    assert_eq!(upstream_report.http_version, "HTTP/1.1");
    assert_eq!(
        upstream_report.host,
        request.request.destination.authority()
    );
    assert_eq!(
        upstream_report.header_names,
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
    assert_eq!(
        hex::decode(&upstream_report.body_hex).test_expect("upstream observed body"),
        request.request.body
    );
    assert_eq!(
        upstream_report.body_sha256,
        body_digest(&request.request.body)
    );
    assert_eq!(upstream_report.credential_matches, 1);
    assert_eq!(upstream_report.authorization_header_count, 1);
    assert!(upstream_report.authorization_exact_bearer_canary);
    assert_eq!(upstream_report.content_length_header_count, 1);
    assert_eq!(upstream_report.transfer_encoding_header_count, 0);
    assert_eq!(upstream_report.connection_count, 1);
    assert_eq!(
        upstream_report.request_sha256,
        hex::encode(Sha256::digest(&expected_upstream_request))
    );

    let receipt_sink = SqliteBrokerReceiptSink::open(
        &fixture.config.databases.receipt_database_path,
        broker_key.public_key(),
    )
    .test_expect("durable process-boundary receipt store");
    let durable = receipt_sink
        .load_completed(&registration.ids.attempt_id)
        .test_expect("durable completed response")
        .test_expect("durable completed response exists");
    assert_eq!(
        canonical_json_bytes(&durable).test_expect("canonical durable response"),
        canonical_response
    );
    let durable_receipt = receipt_sink
        .load(&response.receipt.body.receipt_id)
        .test_expect("durable execution receipt")
        .test_expect("durable execution receipt exists");
    assert_eq!(
        canonical_json_bytes(&durable_receipt).test_expect("canonical durable receipt"),
        canonical_receipt
    );
    drop(receipt_sink);

    scan_tree_for_raw_canary(&canary, &directory);
}
