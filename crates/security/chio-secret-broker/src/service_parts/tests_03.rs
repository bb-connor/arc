#[cfg(unix)]
#[test]
fn handler_error_classification_table_separates_service_faults() {
    let cases = vec![
        (
            BrokerError::InvalidRequest("test".to_string()),
            false,
            "invalid_request",
        ),
        (
            BrokerError::AuthorizationDenied("test".to_string()),
            false,
            "authorization_denied",
        ),
        (
            BrokerError::AuthorityUnavailable("test".to_string()),
            false,
            "authority_unavailable",
        ),
        (BrokerError::Conflict("test".to_string()), false, "conflict"),
        (
            BrokerError::Invariant("test".to_string()),
            true,
            "invariant",
        ),
        (BrokerError::Storage("test".to_string()), true, "storage"),
        (BrokerError::Upstream("test".to_string()), false, "upstream"),
        (
            BrokerError::ResponseRejected("test".to_string()),
            false,
            "response_rejected",
        ),
        (BrokerError::Custody("test".to_string()), true, "custody"),
    ];

    for (error, internal, diagnostic_code) in cases {
        let classified = classify_broker_ipc_handler_result(IpcOperation::Status, Err(error));
        if internal {
            let BrokerIpcServeFailure::Internal(error) =
                classified.test_expect_err("service fault must propagate")
            else {
                panic!("service fault was classified as a client fault");
            };
            assert_eq!(error.diagnostic_code(), diagnostic_code);
        } else {
            let response = classified.test_expect("recoverable handler error is structured");
            assert_eq!(response.operation, IpcOperation::Status);
            assert!(!response.accepted);
            assert!(response.response.is_empty());
            assert_eq!(response.error_code.as_deref(), Some(diagnostic_code));
        }
    }
}

#[cfg(unix)]
#[test]
fn pre_evidence_execute_fault_closes_only_its_client_connection() {
    let classified = classify_broker_ipc_handler_result(
        IpcOperation::Execute,
        Err(BrokerError::InvalidRequest(
            "malformed execute payload".to_string(),
        )),
    );

    assert!(matches!(
        classified,
        Err(BrokerIpcServeFailure::Client(BrokerError::InvalidRequest(message)))
            if message == "malformed execute payload"
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn pre_evidence_execute_fault_does_not_stop_the_endpoint() {
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let directory = tempfile::tempdir().test_expect("IPC directory");
    let socket_path = directory.path().join("broker.sock");
    let uid = rustix::process::geteuid().as_raw();
    let endpoint = UnixBrokerEndpoint::bind(
        &socket_path,
        Arc::new(EndpointTestHandler {
            invalid_envelope: false,
            response_gate: None,
            response_bytes: None,
        }),
        uid,
        uid,
    )
    .test_expect("bind endpoint");
    let server = thread::spawn(move || (endpoint.serve_one(), endpoint.serve_one()));

    let request = |operation| AuthenticatedIpcRequest {
        operation,
        tenant_scope: "tenant-pre-evidence-fault".to_string(),
        authorization: vec![1].into(),
        payload: vec![2].into(),
    };
    let mut execute = UnixStream::connect(&socket_path).test_expect("connect execute client");
    execute
        .set_read_timeout(Some(Duration::from_secs(2)))
        .test_expect("execute read timeout");
    let execute_frame = canonical_ipc_request_bytes(&request(IpcOperation::Execute))
        .test_expect("execute request frame");
    write_bounded_frame(&mut execute, &execute_frame).test_expect("write execute request");
    assert!(read_bounded_frame(&mut execute).is_err());

    let mut status = UnixStream::connect(&socket_path).test_expect("connect status client");
    status
        .set_read_timeout(Some(Duration::from_secs(2)))
        .test_expect("status read timeout");
    let status_frame = canonical_ipc_request_bytes(&request(IpcOperation::Status))
        .test_expect("status request frame");
    write_bounded_frame(&mut status, &status_frame).test_expect("write status request");
    let response_frame = read_bounded_frame(&mut status).test_expect("status response frame");
    let response: IpcResponse =
        serde_json::from_slice(&response_frame).test_expect("status response envelope");

    let (execute_outcome, status_outcome) = server.join().test_expect("endpoint server thread");
    assert_eq!(
        execute_outcome.test_expect("execute client fault"),
        BrokerIpcServeOutcome::ClientFault {
            diagnostic_code: "conflict"
        }
    );
    assert_eq!(
        status_outcome.test_expect("status response"),
        BrokerIpcServeOutcome::ResponseWritten
    );
    assert!(!response.accepted);
    assert_eq!(response.error_code.as_deref(), Some("conflict"));
}

#[cfg(unix)]
#[test]
fn response_write_error_classification_table_preserves_peer_faults() {
    use std::io::ErrorKind;

    for kind in [
        ErrorKind::BrokenPipe,
        ErrorKind::ConnectionReset,
        ErrorKind::ConnectionAborted,
        ErrorKind::NotConnected,
        ErrorKind::UnexpectedEof,
        ErrorKind::WriteZero,
        ErrorKind::WouldBlock,
        ErrorKind::TimedOut,
    ] {
        assert_eq!(
            classify_broker_ipc_write_error(kind, false),
            BrokerIpcWriteFailureClass::Client
        );
        assert_eq!(
            classify_broker_ipc_write_error(kind, true),
            BrokerIpcWriteFailureClass::DeadlineInternal
        );
    }
    for kind in [
        ErrorKind::InvalidInput,
        ErrorKind::InvalidData,
        ErrorKind::PermissionDenied,
        ErrorKind::Other,
    ] {
        assert_eq!(
            classify_broker_ipc_write_error(kind, false),
            BrokerIpcWriteFailureClass::OperatingSystemInternal
        );
    }
}

#[cfg(unix)]
#[test]
fn response_envelope_validation_table_enforces_success_and_error_shapes() {
    let response = |operation, accepted, response: Vec<u8>, error_code: Option<&str>| IpcResponse {
        operation,
        accepted,
        response,
        error_code: error_code.map(str::to_string),
    };
    let cases = vec![
        (response(IpcOperation::Status, true, vec![1], None), true),
        (
            response(IpcOperation::Status, true, Vec::new(), None),
            false,
        ),
        (
            response(
                IpcOperation::Status,
                true,
                vec![1; MAX_WIRE_BYTES + 1],
                None,
            ),
            false,
        ),
        (
            response(IpcOperation::Status, true, vec![1], Some("conflict")),
            false,
        ),
        (
            response(IpcOperation::Status, false, Vec::new(), Some("conflict")),
            true,
        ),
        (
            response(IpcOperation::Status, false, vec![1], Some("conflict")),
            false,
        ),
        (
            response(IpcOperation::Status, false, Vec::new(), None),
            false,
        ),
        (
            response(IpcOperation::Execute, false, Vec::new(), Some("conflict")),
            false,
        ),
    ];
    for (candidate, valid) in cases {
        assert_eq!(
            validate_broker_ipc_response_envelope(IpcOperation::Status, &candidate).is_ok(),
            valid
        );
    }

    for valid in [
        "conflict",
        "invalid_request",
        "authority_unavailable",
        "response_rejected",
        "protocol_v2",
    ] {
        assert!(is_well_formed_broker_ipc_error_code(valid));
    }
    for invalid in [
        "",
        "Conflict",
        "conflict-code",
        "conflict code",
        "_conflict",
        "conflict_",
        "conflict__code",
        ".conflict",
        "conflict.",
        "-conflict",
        "conflict-",
        "chio.broker.authorization_denied",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert!(!is_well_formed_broker_ipc_error_code(invalid));
    }
}

#[cfg(unix)]
fn signed_ipc_execute_failure(diagnostic_code: &str) -> BrokerExecuteFailure {
    let receipt = sign_failure_receipt(
        BrokerFailureReceiptBody {
            schema: BROKER_FAILURE_RECEIPT_SCHEMA.to_string(),
            receipt_id: "broker-failure-terminal-ipc-validator".to_string(),
            issued_at_unix_seconds: 1,
            stage: BrokerFailureStage::Admission,
            outcome: BrokerFailureOutcome::Denied,
            diagnostic_code: diagnostic_code.to_string(),
            request_digest: "ab".repeat(32),
            capability_digest: None,
            attempt_id: None,
            invocation_id: None,
            hold_id: None,
            parent_capability_id: None,
            broker_capability_id: None,
            dispatch_knowledge: BrokerDispatchKnowledge::NotStarted,
        },
        &Ed25519Backend::new(Keypair::from_seed(&[91; 32])),
    )
    .test_expect("signed IPC execute failure");
    let receipt_reference = format!(
        "broker-failure-receipt-sha256-{}",
        failure_receipt_digest(&receipt).test_expect("failure receipt digest")
    );
    BrokerExecuteFailure {
        diagnostic_code: diagnostic_code.to_string(),
        receipt_reference,
        receipt,
    }
}

#[cfg(unix)]
#[test]
fn response_envelope_accepts_exact_canonical_signed_execute_failure() {
    let failure = signed_ipc_execute_failure("chio.broker.authorization_denied");
    let response = IpcResponse {
        operation: IpcOperation::Execute,
        accepted: false,
        response: canonical_json_bytes(&failure).test_expect("canonical execute failure"),
        error_code: Some(failure.diagnostic_code.clone()),
    };

    validate_broker_ipc_response_envelope(IpcOperation::Execute, &response)
        .test_expect("signed execute denial envelope");
}

#[cfg(unix)]
#[test]
fn response_envelope_rejects_malformed_or_tampered_execute_failures() {
    let diagnostic_code = "chio.broker.authorization_denied";
    let failure = signed_ipc_execute_failure(diagnostic_code);
    let envelope = |operation, failure: &BrokerExecuteFailure, error_code: &str| IpcResponse {
        operation,
        accepted: false,
        response: canonical_json_bytes(failure).test_expect("canonical execute failure"),
        error_code: Some(error_code.to_string()),
    };

    let mut diagnostic_rebound = failure.clone();
    diagnostic_rebound.diagnostic_code = "chio.broker.conflict".to_string();

    let mut signed_body_tampered = failure.clone();
    signed_body_tampered.diagnostic_code = "chio.broker.conflict".to_string();
    signed_body_tampered.receipt.body.diagnostic_code = "chio.broker.conflict".to_string();
    signed_body_tampered.receipt_reference = format!(
        "broker-failure-receipt-sha256-{}",
        failure_receipt_digest(&signed_body_tampered.receipt)
            .test_expect("tampered failure receipt digest")
    );

    let mut reference_tampered = failure.clone();
    reference_tampered.receipt_reference =
        format!("broker-failure-receipt-sha256-{}", "00".repeat(32));

    let malformed = IpcResponse {
        operation: IpcOperation::Execute,
        accepted: false,
        response: b"{}".to_vec(),
        error_code: Some(diagnostic_code.to_string()),
    };
    let noncanonical = IpcResponse {
        operation: IpcOperation::Execute,
        accepted: false,
        response: serde_json::to_vec_pretty(&failure).test_expect("noncanonical execute failure"),
        error_code: Some(diagnostic_code.to_string()),
    };
    let empty_execute_denial = IpcResponse {
        operation: IpcOperation::Execute,
        accepted: false,
        response: Vec::new(),
        error_code: Some(diagnostic_code.to_string()),
    };
    let wrong_domain_failure = signed_ipc_execute_failure("chio.kernel.authorization_denied");
    let candidates = [
        envelope(IpcOperation::Execute, &failure, "chio.broker.conflict"),
        envelope(
            IpcOperation::Execute,
            &diagnostic_rebound,
            "chio.broker.conflict",
        ),
        envelope(
            IpcOperation::Execute,
            &signed_body_tampered,
            "chio.broker.conflict",
        ),
        envelope(IpcOperation::Execute, &reference_tampered, diagnostic_code),
        envelope(IpcOperation::Status, &failure, diagnostic_code),
        envelope(
            IpcOperation::Execute,
            &wrong_domain_failure,
            "chio.kernel.authorization_denied",
        ),
        malformed,
        noncanonical,
        empty_execute_denial,
    ];

    for candidate in candidates {
        assert!(
            validate_broker_ipc_response_envelope(candidate.operation, &candidate).is_err(),
            "invalid denial envelope was accepted: {candidate:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn provisional_socket_cleanup_removes_exact_socket_after_validation_failure() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let directory = tempfile::tempdir().test_expect("IPC directory");
    let socket_path = directory.path().join("broker.sock");
    let listener = UnixListener::bind(&socket_path).test_expect("bind provisional socket");
    let cleanup =
        ProvisionalBrokerSocketCleanup::new(&socket_path).test_expect("capture exact identity");
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666))
        .test_expect("inject insecure socket mode");
    validate_broker_socket_identity(&socket_path, rustix::process::geteuid().as_raw())
        .test_expect_err("injected post-bind validation failure");

    drop(cleanup);
    assert!(!socket_path.exists());
    drop(listener);
}

#[cfg(target_os = "linux")]
#[test]
fn trickling_same_uid_client_cannot_extend_the_absolute_read_deadline() {
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let directory = tempfile::tempdir().test_expect("IPC directory");
    let socket_path = directory.path().join("broker.sock");
    let uid = rustix::process::geteuid().as_raw();
    let endpoint = UnixBrokerEndpoint::bind_with_deadlines(
        &socket_path,
        Arc::new(EndpointTestHandler {
            invalid_envelope: false,
            response_gate: None,
            response_bytes: None,
        }),
        uid,
        uid,
        BrokerIpcDeadlines::from_millis(100, 1_000).test_expect("bounded deadlines"),
    )
    .test_expect("bind endpoint");
    let server = thread::spawn(move || (endpoint.serve_one(), endpoint.serve_one()));

    let mut trickling = UnixStream::connect(&socket_path).test_expect("connect trickling client");
    thread::sleep(Duration::from_millis(25));
    let encoded = canonical_ipc_request_bytes(&endpoint_test_request()).test_expect("IPC request");
    let length = u32::try_from(encoded.len())
        .test_expect("request length")
        .to_be_bytes();
    let mut written = 0_usize;
    for byte in length.into_iter().chain(encoded.iter().copied()).take(20) {
        if trickling.write_all(&[byte]).is_err() {
            break;
        }
        written += 1;
        thread::sleep(Duration::from_millis(35));
    }
    assert!(
        written < 20,
        "trickle traffic extended the absolute read deadline"
    );

    let mut responsive = UnixStream::connect(&socket_path).test_expect("connect next client");
    responsive
        .set_read_timeout(Some(Duration::from_secs(2)))
        .test_expect("responsive read timeout");
    send_endpoint_test_request(&mut responsive);
    let response = read_bounded_frame(&mut responsive).test_expect("next response");
    let response: IpcResponse = serde_json::from_slice(&response).test_expect("decode response");
    let (trickling_outcome, responsive_outcome) =
        server.join().test_expect("endpoint server thread");
    assert!(matches!(
        trickling_outcome.test_expect("trickling client is contained"),
        BrokerIpcServeOutcome::ClientFault { .. }
    ));
    assert_eq!(
        responsive_outcome.test_expect("next request is served"),
        BrokerIpcServeOutcome::ResponseWritten
    );
    assert_eq!(response.error_code.as_deref(), Some("conflict"));
}

#[cfg(target_os = "linux")]
#[test]
fn nonreading_client_write_backpressure_is_bounded_and_next_request_succeeds() {
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let directory = tempfile::tempdir().test_expect("IPC directory");
    let socket_path = directory.path().join("broker.sock");
    let uid = rustix::process::geteuid().as_raw();
    let endpoint = UnixBrokerEndpoint::bind_with_deadlines(
        &socket_path,
        Arc::new(EndpointTestHandler {
            invalid_envelope: false,
            response_gate: None,
            response_bytes: Some(500_000),
        }),
        uid,
        uid,
        BrokerIpcDeadlines::from_millis(1_000, 500).test_expect("bounded deadlines"),
    )
    .test_expect("bind endpoint");
    let server = thread::spawn(move || (endpoint.serve_one(), endpoint.serve_one()));

    let mut nonreading = UnixStream::connect(&socket_path).test_expect("connect nonreader");
    rustix::net::sockopt::set_socket_recv_buffer_size(&nonreading, 1_024)
        .test_expect("bound nonreader receive buffer");
    send_endpoint_test_request(&mut nonreading);
    thread::sleep(Duration::from_millis(750));

    let mut responsive = UnixStream::connect(&socket_path).test_expect("connect next client");
    responsive
        .set_read_timeout(Some(Duration::from_secs(3)))
        .test_expect("responsive read timeout");
    send_endpoint_test_request(&mut responsive);
    let response = read_bounded_frame(&mut responsive).test_expect("next response");
    let response: IpcResponse = serde_json::from_slice(&response).test_expect("decode response");
    let (nonreading_outcome, responsive_outcome) =
        server.join().test_expect("endpoint server thread");
    assert!(matches!(
        nonreading_outcome.test_expect("write backpressure is contained"),
        BrokerIpcServeOutcome::ClientFault { .. }
    ));
    assert_eq!(
        responsive_outcome.test_expect("next request is served"),
        BrokerIpcServeOutcome::ResponseWritten
    );
    assert!(response.accepted);
    assert_eq!(response.response.len(), 500_000);
}

#[cfg(target_os = "linux")]
#[test]
fn endpoint_drop_never_unlinks_a_replacement_socket() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let directory = tempfile::tempdir().test_expect("IPC directory");
    let socket_path = directory.path().join("broker.sock");
    let uid = rustix::process::geteuid().as_raw();
    let endpoint = UnixBrokerEndpoint::bind(
        &socket_path,
        Arc::new(EndpointTestHandler {
            invalid_envelope: false,
            response_gate: None,
            response_bytes: None,
        }),
        uid,
        uid,
    )
    .test_expect("bind endpoint");
    std::fs::remove_file(&socket_path).test_expect("unlink original socket name");
    let replacement = UnixListener::bind(&socket_path).test_expect("bind replacement socket");
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .test_expect("secure replacement socket");

    drop(endpoint);
    assert!(socket_path.exists());
    drop(replacement);
}

#[cfg(target_os = "linux")]
#[test]
fn endpoint_lifecycle_lock_precedes_bind_and_releases_on_drop() {
    let directory = tempfile::tempdir().test_expect("IPC directory");
    let socket_path = directory.path().join("broker.sock");
    let uid = rustix::process::geteuid().as_raw();
    let handler = || -> Arc<dyn BrokerIpcHandler> {
        Arc::new(EndpointTestHandler {
            invalid_envelope: false,
            response_gate: None,
            response_bytes: None,
        })
    };
    let first = UnixBrokerEndpoint::bind(&socket_path, handler(), uid, uid)
        .test_expect("bind first endpoint");
    let error = match UnixBrokerEndpoint::bind(&socket_path, handler(), uid, uid) {
        Ok(_) => panic!("second endpoint acquired an owned socket"),
        Err(error) => error,
    };
    assert!(matches!(error, BrokerError::AuthorityUnavailable(_)));

    drop(first);
    let replacement = UnixBrokerEndpoint::bind(&socket_path, handler(), uid, uid)
        .test_expect("released lifecycle lock permits rebuild");
    drop(replacement);
}

fn audit_reference_for_execution(
    fixture: &Fixture,
    request: &BrokerExecuteRequest,
    exact_match: bool,
) -> (
    crate::audit::BrokerAuditReferenceRequest,
    crate::audit::BrokerAuditReferencePrecommitment,
) {
    let (request_head, request_body) = audit_reference_parts(fixture, request, exact_match);
    crate::audit::BrokerAuditReferenceRequest::new_with_precommitment(request_head, request_body)
        .test_expect("audit reference request")
}

fn audit_reference_parts(
    fixture: &Fixture,
    request: &BrokerExecuteRequest,
    exact_match: bool,
) -> (Vec<u8>, Vec<u8>) {
    let destination = &request.request.destination;
    let mut request_head = Vec::new();
    if exact_match {
        request_head.extend_from_slice(destination.method.as_bytes());
    } else {
        request_head.extend_from_slice(b"GET");
    }
    request_head.push(b' ');
    request_head.extend_from_slice(destination.exact_path_and_query.as_bytes());
    request_head.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    if destination.normalized_host.contains(':') {
        request_head.push(b'[');
        request_head.extend_from_slice(destination.normalized_host.as_bytes());
        request_head.push(b']');
    } else {
        request_head.extend_from_slice(destination.normalized_host.as_bytes());
    }
    if destination.explicit_port != 443 {
        request_head.push(b':');
        request_head.extend_from_slice(destination.explicit_port.to_string().as_bytes());
    }
    request_head.extend_from_slice(
        b"\r\nConnection: close\r\nAccept-Encoding: identity\r\nContent-Length: ",
    );
    request_head.extend_from_slice(request.request.body.len().to_string().as_bytes());
    request_head.extend_from_slice(b"\r\n");
    for header in &request.request.headers {
        request_head.extend_from_slice(header.name.as_bytes());
        request_head.extend_from_slice(b": ");
        request_head.extend_from_slice(&header.value);
        request_head.extend_from_slice(b"\r\n");
    }
    request_head.extend_from_slice(b"authorization: Bearer ");
    request_head.extend_from_slice(&fixture.canary);
    request_head.extend_from_slice(b"\r\n\r\n");
    (request_head, request.request.body.clone())
}

fn audit_trust(fixture: &Fixture) -> crate::audit::BrokerAuditTrustConfiguration<'_> {
    crate::audit::BrokerAuditTrustConfiguration {
        trusted_capability_issuer: &fixture.audit_trusted_issuer,
        broker_audience: "broker-service",
        parent_audience: "broker-parent",
        provider_adapter_id: "generic-bearer",
        provider_adapter_version: 1,
        receipt_signer: &fixture.audit_receipt_signer,
        maximum_clock_skew_seconds: 2,
        maximum_liveness_snapshot_age_seconds: 5,
        maximum_revocation_snapshot_age_seconds: 5,
        trusted_authority: &fixture.audit_authority,
        deployment_id: "test-deployment",
        broker_instance_id: "test-broker-instance",
        tenant_scope: "tenant-a",
        runner_id: "test-enterprise-runner",
        trusted_runner: &fixture.audit_runner_key,
        governed_admin_policy: fixture.audit_admin.policy(),
    }
}

#[cfg(target_os = "linux")]
struct SocketAuditHandler {
    service: Arc<BrokerService>,
    admin: Arc<GovernedAdminAuthorizer>,
    trusted_runner: PublicKey,
}

#[cfg(target_os = "linux")]
impl crate::privileged_audit::BrokerPrivilegedAuditHandler for SocketAuditHandler {
    fn now_unix_seconds(&self) -> Result<u64> {
        Ok(20)
    }

    fn compare(
        &self,
        request: &BrokerExecuteRequest,
        reference: crate::audit::BrokerAuditReferenceRequest,
        runner_authorization: &crate::audit::SignedBrokerAuditRunnerAuthorization,
        admin_authorization: &AdminAuthorization,
    ) -> Result<crate::audit::CompletedBrokerAuditComparison> {
        let verified_runner = crate::audit::verify_broker_audit_runner_authorization(
            runner_authorization,
            request,
            &reference,
            crate::audit::BrokerAuditRunnerTrust {
                deployment_id: "test-deployment",
                broker_instance_id: "test-broker-instance",
                tenant_scope: "tenant-a",
                runner_id: "test-enterprise-runner",
                trusted_runner: &self.trusted_runner,
            },
            20,
        )?;
        self.service.audit_compare_outbound_request(
            request,
            reference,
            verified_runner,
            admin_authorization,
            self.admin.as_ref(),
            20,
        )
    }
}

#[cfg(target_os = "linux")]
struct TerminalPersistenceFailureAuditHandler;

#[cfg(target_os = "linux")]
impl crate::privileged_audit::BrokerPrivilegedAuditHandler
    for TerminalPersistenceFailureAuditHandler
{
    fn now_unix_seconds(&self) -> Result<u64> {
        Ok(20)
    }

    fn compare(
        &self,
        _request: &BrokerExecuteRequest,
        _reference: crate::audit::BrokerAuditReferenceRequest,
        _runner_authorization: &crate::audit::SignedBrokerAuditRunnerAuthorization,
        _admin_authorization: &AdminAuthorization,
    ) -> Result<crate::audit::CompletedBrokerAuditComparison> {
        Err(BrokerError::Storage(
            "injected terminal audit persistence failure".to_string(),
        ))
    }
}

#[cfg(target_os = "linux")]
#[test]
fn privileged_audit_socket_round_trip_retains_runner_reference_precommitment() {
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use crate::privileged_audit::{
        read_privileged_audit_challenge_frame, read_privileged_audit_evidence_frame,
        verify_broker_privileged_audit_challenge_reference, write_privileged_audit_commit_frame,
        write_privileged_audit_open_frame, BrokerPrivilegedAuditCommitRequest,
        BrokerPrivilegedAuditEndpoint, BrokerPrivilegedAuditEndpointConfig,
        BrokerPrivilegedAuditOpenRequest, BrokerPrivilegedAuditServeOutcome,
        BROKER_PRIVILEGED_AUDIT_COMMIT_SCHEMA,
    };

    let fixture = fixture(1, false, false);
    let (request, _trusted) = execution(&fixture, 144, 1);
    let (reference_head, reference_body) = audit_reference_parts(&fixture, &request, true);
    let reference_precommitment =
        crate::audit::BrokerAuditReferencePrecommitment::generate(&reference_head, &reference_body)
            .test_expect("runner reference precommitment");
    assert_eq!(
        reference_precommitment.commitment_sha256(),
        crate::audit::broker_audit_reference_commitment_sha256(
            reference_precommitment.commitment_salt(),
            &reference_head,
            &reference_body,
        )
        .test_expect("derive retained reference commitment")
    );
    let mut mutated_open = BrokerPrivilegedAuditOpenRequest::new(
        "audit-socket-mutation".to_string(),
        "legacy-provider-observation".to_string(),
        "combined-authority".to_string(),
        request.clone(),
        reference_head.clone(),
        reference_body.clone(),
        &reference_precommitment,
    )
    .test_expect("construct mutation probe open request");
    mutated_open.reference_request_body.push(b'!');
    assert!(mutated_open.validate().is_err());
    let mut salt_rebound_open = BrokerPrivilegedAuditOpenRequest::new(
        "audit-socket-salt-mutation".to_string(),
        "legacy-provider-observation".to_string(),
        "combined-authority".to_string(),
        request.clone(),
        reference_head.clone(),
        reference_body.clone(),
        &reference_precommitment,
    )
    .test_expect("construct salt mutation probe open request");
    let replacement = if salt_rebound_open.reference_commitment_salt.starts_with('0') {
        "1"
    } else {
        "0"
    };
    salt_rebound_open
        .reference_commitment_salt
        .replace_range(0..1, replacement);
    assert!(salt_rebound_open.validate().is_err());

    let directory = tempfile::tempdir().test_expect("privileged audit socket directory");
    let socket_path = directory.path().join("privileged-audit").join("audit.sock");
    let service_uid = rustix::process::geteuid().as_raw();
    let runner_gid = rustix::process::getegid().as_raw();
    let broker_signer: Arc<dyn SigningBackend> =
        Arc::new(Ed25519Backend::new(Keypair::from_seed(&[3; 32])));
    let trusted_broker = broker_signer.public_key();
    assert_eq!(trusted_broker, fixture.audit_receipt_signer);
    let endpoint = BrokerPrivilegedAuditEndpoint::bind(
        BrokerPrivilegedAuditEndpointConfig {
            socket_path: socket_path.clone(),
            trusted_service_uid: service_uid,
            authorized_runner_uid: service_uid,
            authorized_runner_gid: runner_gid,
            read_timeout_ms: 2_000,
            write_timeout_ms: 2_000,
            authorization_lifetime_seconds: 60,
            deployment_id: "test-deployment".to_string(),
            broker_instance_id: "test-broker-instance".to_string(),
            tenant_scope: "tenant-a".to_string(),
            runner_id: "test-enterprise-runner".to_string(),
        },
        broker_signer,
        Arc::new(SocketAuditHandler {
            service: Arc::clone(&fixture.service),
            admin: Arc::clone(&fixture.audit_admin),
            trusted_runner: fixture.audit_runner_key.clone(),
        }),
    )
    .test_expect("bind privileged audit endpoint");
    let server = thread::spawn(move || endpoint.try_serve_one());

    let mut stream = UnixStream::connect(&socket_path).test_expect("connect privileged audit");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .test_expect("privileged audit client read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .test_expect("privileged audit client write timeout");
    let open = BrokerPrivilegedAuditOpenRequest::new(
        "audit-socket-144".to_string(),
        "legacy-provider-observation".to_string(),
        "combined-authority".to_string(),
        request.clone(),
        reference_head.clone(),
        reference_body.clone(),
        &reference_precommitment,
    )
    .test_expect("construct privileged audit open request");
    write_privileged_audit_open_frame(&mut stream, &open)
        .test_expect("write privileged audit open request");
    let challenge = read_privileged_audit_challenge_frame(
        &mut stream,
        &trusted_broker,
        &reference_precommitment,
    )
    .test_expect("read runner-bound privileged audit challenge");
    let runner_authorization = crate::audit::SignedBrokerAuditRunnerAuthorization::sign(
        challenge.body.runner_authorization_body.clone(),
        fixture.audit_runner.as_ref(),
    )
    .test_expect("sign privileged audit runner authorization");
    let governed_intent =
        crate::audit::broker_audit_governed_intent_for_runner_authorization(&runner_authorization)
            .test_expect("derive privileged audit governed intent");
    let admin = governed_audit_authorization(&fixture, &governed_intent);
    let commit = BrokerPrivilegedAuditCommitRequest {
        schema: BROKER_PRIVILEGED_AUDIT_COMMIT_SCHEMA.to_string(),
        session_nonce: challenge.body.session_nonce.clone(),
        session_commitment_sha256: challenge.body.session_commitment_sha256.clone(),
        runner_authorization,
        governed_admin_authorization: admin.as_bytes().to_vec(),
    };
    write_privileged_audit_commit_frame(&mut stream, &commit, &challenge)
        .test_expect("write privileged audit commit");
    let evidence = read_privileged_audit_evidence_frame(&mut stream, &trusted_broker)
        .test_expect("read privileged audit evidence");
    let outcome = server
        .join()
        .test_expect("join privileged audit server")
        .test_expect("privileged audit server result")
        .test_expect("privileged audit served one connection");
    assert_eq!(outcome, BrokerPrivilegedAuditServeOutcome::EvidenceWritten);

    let (liveness, revocation) = evidence
        .verified_authority_exchanges()
        .test_expect("verify returned authority exchanges");
    let evidence_admin = evidence
        .admin_authorization()
        .test_expect("recover governed audit evidence");
    crate::audit::verify_broker_audit_evidence(
        crate::audit::BrokerAuditEvidenceBundle {
            comparison: &evidence.comparison,
            runner_authorization: &evidence.runner_authorization,
            admin_authorization: &evidence_admin,
            authority: crate::audit::BrokerAuditAuthorityEvidence {
                liveness: &liveness,
                revocation: &revocation,
            },
        },
        crate::audit::BrokerAuditExpectedContext {
            request: &request,
            audit_id: "audit-socket-144",
            reference_source: "legacy-provider-observation",
            reference_precommitment: &reference_precommitment,
            revocation_authority_domain: "combined-authority",
            trust: audit_trust(&fixture),
            not_before_unix_seconds: 19,
            expires_at_unix_seconds: 21,
        },
    )
    .test_expect("independently verify privileged audit socket evidence");

    let mut rebound_head = reference_head;
    rebound_head[0] ^= 1;
    let rebound_precommitment =
        crate::audit::BrokerAuditReferencePrecommitment::generate(&rebound_head, &reference_body)
            .test_expect("rebound runner reference precommitment");
    assert!(verify_broker_privileged_audit_challenge_reference(
        &evidence.challenge,
        &trusted_broker,
        &rebound_precommitment,
    )
    .is_err());
    assert!(crate::audit::verify_broker_audit_evidence(
        crate::audit::BrokerAuditEvidenceBundle {
            comparison: &evidence.comparison,
            runner_authorization: &evidence.runner_authorization,
            admin_authorization: &evidence_admin,
            authority: crate::audit::BrokerAuditAuthorityEvidence {
                liveness: &liveness,
                revocation: &revocation,
            },
        },
        crate::audit::BrokerAuditExpectedContext {
            request: &request,
            audit_id: "audit-socket-144",
            reference_source: "legacy-provider-observation",
            reference_precommitment: &rebound_precommitment,
            revocation_authority_domain: "combined-authority",
            trust: audit_trust(&fixture),
            not_before_unix_seconds: 19,
            expires_at_unix_seconds: 21,
        },
    )
    .is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn privileged_audit_socket_propagates_terminal_persistence_failure() {
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use crate::privileged_audit::{
        read_privileged_audit_challenge_frame, write_privileged_audit_commit_frame,
        write_privileged_audit_open_frame, BrokerPrivilegedAuditCommitRequest,
        BrokerPrivilegedAuditEndpoint, BrokerPrivilegedAuditEndpointConfig,
        BrokerPrivilegedAuditOpenRequest, BROKER_PRIVILEGED_AUDIT_COMMIT_SCHEMA,
    };

    let fixture = fixture(1, false, false);
    let (request, _trusted) = execution(&fixture, 145, 1);
    let (reference_head, reference_body) = audit_reference_parts(&fixture, &request, true);
    let reference_precommitment =
        crate::audit::BrokerAuditReferencePrecommitment::generate(&reference_head, &reference_body)
            .test_expect("runner reference precommitment");
    let directory = tempfile::tempdir().test_expect("privileged audit socket directory");
    let socket_path = directory.path().join("privileged-audit").join("audit.sock");
    let service_uid = rustix::process::geteuid().as_raw();
    let runner_gid = rustix::process::getegid().as_raw();
    let broker_signer: Arc<dyn SigningBackend> =
        Arc::new(Ed25519Backend::new(Keypair::from_seed(&[3; 32])));
    let trusted_broker = broker_signer.public_key();
    let endpoint = BrokerPrivilegedAuditEndpoint::bind(
        BrokerPrivilegedAuditEndpointConfig {
            socket_path: socket_path.clone(),
            trusted_service_uid: service_uid,
            authorized_runner_uid: service_uid,
            authorized_runner_gid: runner_gid,
            read_timeout_ms: 2_000,
            write_timeout_ms: 2_000,
            authorization_lifetime_seconds: 60,
            deployment_id: "test-deployment".to_string(),
            broker_instance_id: "test-broker-instance".to_string(),
            tenant_scope: "tenant-a".to_string(),
            runner_id: "test-enterprise-runner".to_string(),
        },
        broker_signer,
        Arc::new(TerminalPersistenceFailureAuditHandler),
    )
    .test_expect("bind privileged audit endpoint");
    let server = thread::spawn(move || endpoint.try_serve_one());

    let mut stream = UnixStream::connect(&socket_path).test_expect("connect privileged audit");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .test_expect("privileged audit client read timeout");
    let open = BrokerPrivilegedAuditOpenRequest::new(
        "audit-socket-persistence-145".to_string(),
        "legacy-provider-observation".to_string(),
        "combined-authority".to_string(),
        request,
        reference_head,
        reference_body,
        &reference_precommitment,
    )
    .test_expect("construct privileged audit open request");
    write_privileged_audit_open_frame(&mut stream, &open)
        .test_expect("write privileged audit open request");
    let challenge = read_privileged_audit_challenge_frame(
        &mut stream,
        &trusted_broker,
        &reference_precommitment,
    )
    .test_expect("read runner-bound privileged audit challenge");
    let runner_authorization = crate::audit::SignedBrokerAuditRunnerAuthorization::sign(
        challenge.body.runner_authorization_body.clone(),
        fixture.audit_runner.as_ref(),
    )
    .test_expect("sign privileged audit runner authorization");
    let commit = BrokerPrivilegedAuditCommitRequest {
        schema: BROKER_PRIVILEGED_AUDIT_COMMIT_SCHEMA.to_string(),
        session_nonce: challenge.body.session_nonce.clone(),
        session_commitment_sha256: challenge.body.session_commitment_sha256.clone(),
        runner_authorization,
        governed_admin_authorization: vec![1],
    };
    write_privileged_audit_commit_frame(&mut stream, &commit, &challenge)
        .test_expect("write privileged audit commit");
    let error = server
        .join()
        .test_expect("join privileged audit server")
        .test_expect_err("terminal persistence failure must reach supervision");
    assert!(matches!(error, BrokerError::Storage(_)));
}

fn verify_completed_audit(
    completed: &crate::audit::CompletedBrokerAuditComparison,
    runner: &crate::audit::SignedBrokerAuditRunnerAuthorization,
    admin: &AdminAuthorization,
    expected: crate::audit::BrokerAuditExpectedContext<'_>,
) -> Result<()> {
    crate::audit::verify_broker_audit_evidence(
        crate::audit::BrokerAuditEvidenceBundle {
            comparison: &completed.comparison,
            runner_authorization: runner,
            admin_authorization: admin,
            authority: completed.authority_evidence(),
        },
        expected,
    )
}

fn completed_audit_context<'a>(
    request: &'a BrokerExecuteRequest,
    audit_id: &'a str,
    reference_source: &'a str,
    reference_precommitment: &'a crate::audit::BrokerAuditReferencePrecommitment,
    trust: crate::audit::BrokerAuditTrustConfiguration<'a>,
) -> crate::audit::BrokerAuditExpectedContext<'a> {
    crate::audit::BrokerAuditExpectedContext {
        request,
        audit_id,
        reference_source,
        reference_precommitment,
        revocation_authority_domain: "combined-authority",
        trust,
        not_before_unix_seconds: 19,
        expires_at_unix_seconds: 21,
    }
}

#[test]
fn audit_comparison_is_exact_non_dispatching_non_accounting_and_secret_free() {
    let fixture = fixture(1, false, false);
    let (request, trusted) = execution(&fixture, 140, 1);
    let (matching_reference, matching_precommitment) =
        audit_reference_for_execution(&fixture, &request, true);
    let reference_debug = format!("{matching_reference:?}");
    let canary = std::str::from_utf8(&fixture.canary).test_expect("credential canary UTF-8");
    assert!(!reference_debug.contains(canary));
    assert!(reference_debug.contains("<redacted>"));
    let (matching_runner, matching_admin, matching_signed_runner) = authorized_audit(
        &fixture,
        &request,
        &matching_reference,
        "audit-exact-140",
        20,
    );

    let matching = fixture
        .service
        .audit_compare_outbound_request(
            &request,
            matching_reference,
            matching_runner,
            &matching_admin,
            fixture.audit_admin.as_ref(),
            20,
        )
        .test_expect("matching audit comparison");
    let (mismatching_reference, mismatching_precommitment) =
        audit_reference_for_execution(&fixture, &request, false);
    let (mismatching_runner, mismatching_admin, mismatching_signed_runner) = authorized_audit(
        &fixture,
        &request,
        &mismatching_reference,
        "audit-mismatch-140",
        20,
    );
    let mismatching = fixture
        .service
        .audit_compare_outbound_request(
            &request,
            mismatching_reference,
            mismatching_runner,
            &mismatching_admin,
            fixture.audit_admin.as_ref(),
            20,
        )
        .test_expect("mismatching audit comparison");

    assert!(matching.body.projections_equal);
    assert_eq!(
        matching.body.broker_outbound_projection_commitment_sha256,
        matching
            .body
            .reference_outbound_projection_commitment_sha256
    );
    assert!(!mismatching.body.projections_equal);
    assert_ne!(
        mismatching
            .body
            .broker_outbound_projection_commitment_sha256,
        mismatching
            .body
            .reference_outbound_projection_commitment_sha256
    );
    assert_eq!(matching.body.network_dispatch_count, 0);
    assert_eq!(matching.body.accounting_mutation_count, 0);
    assert!(!matching.body.raw_credential_returned);

    crate::audit::verify_broker_audit_evidence(
        crate::audit::BrokerAuditEvidenceBundle {
            comparison: &matching.comparison,
            runner_authorization: &matching_signed_runner,
            admin_authorization: &matching_admin,
            authority: matching.authority_evidence(),
        },
        crate::audit::BrokerAuditExpectedContext {
            request: &request,
            audit_id: "audit-exact-140",
            reference_source: "legacy-provider-observation",
            reference_precommitment: &matching_precommitment,
            revocation_authority_domain: "combined-authority",
            trust: audit_trust(&fixture),
            not_before_unix_seconds: 19,
            expires_at_unix_seconds: 21,
        },
    )
    .test_expect("verify matching comparison");
    crate::audit::verify_broker_audit_evidence(
        crate::audit::BrokerAuditEvidenceBundle {
            comparison: &mismatching.comparison,
            runner_authorization: &mismatching_signed_runner,
            admin_authorization: &mismatching_admin,
            authority: mismatching.authority_evidence(),
        },
        crate::audit::BrokerAuditExpectedContext {
            request: &request,
            audit_id: "audit-mismatch-140",
            reference_source: "legacy-provider-observation",
            reference_precommitment: &mismatching_precommitment,
            revocation_authority_domain: "combined-authority",
            trust: audit_trust(&fixture),
            not_before_unix_seconds: 19,
            expires_at_unix_seconds: 21,
        },
    )
    .test_expect("verify mismatching comparison");
    for comparison in [&matching, &mismatching] {
        let canonical = comparison
            .canonical_bytes()
            .test_expect("canonical audit comparison");
        let canonical_text =
            std::str::from_utf8(&canonical).test_expect("canonical comparison UTF-8");
        let debug = format!("{comparison:?}");
        assert!(!canonical_text.contains(canary));
        assert!(!canonical_text.contains("Bearer "));
        assert!(!canonical_text.contains("authorization"));
        assert!(!debug.contains(canary));
        assert!(!debug.contains("Bearer "));
        assert!(!debug.contains("\"authorization\""));
    }

    assert!(fixture
        .observed_authorizations
        .lock()
        .test_expect("observed authorization lock")
        .is_empty());
    assert_eq!(fixture.resolver_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.live_authority_calls.load(Ordering::SeqCst), 4);
    assert_eq!(fixture.authority.captured_count(), 0);
    let authority_state = fixture
        .authority
        .state
        .lock()
        .test_expect("audit authority state");
    assert!(authority_state.holds.is_empty());
    assert!(authority_state.quotas.is_empty());
    assert!(authority_state.hold_quotas.is_empty());
    drop(authority_state);
    assert!(fixture
        .service
        .retained_prepared_dispatches()
        .test_expect("retained prepared dispatches")
        .is_empty());
    assert!(fixture
        .receipts
        .lock()
        .test_expect("audit receipt lock")
        .is_empty());
    let registration = test_attempt_registration(
        &request,
        &trusted.admission_operation_id,
        &trusted.quotas,
        &trusted.authority_metadata_digest,
        &trusted.revocation_authority_domain,
    );
    assert!(fixture
        .attempts
        .load_attempt(&registration.ids.attempt_id)
        .test_expect("load audit attempt")
        .is_none());

    let mut unsafe_claim = matching;
    unsafe_claim.comparison.body.network_dispatch_count = 1;
    assert!(crate::audit::verify_broker_audit_comparison(
        &unsafe_claim.comparison,
        &fixture.audit_receipt_signer,
    )
    .is_err());
}

#[test]
fn audit_evidence_verifier_recomputes_every_external_trust_binding() {
    let fixture = fixture(1, false, false);
    let (request, _trusted) = execution(&fixture, 143, 1);
    let (reference, reference_precommitment) =
        audit_reference_for_execution(&fixture, &request, true);
    let (verified_runner, admin, signed_runner) =
        authorized_audit(&fixture, &request, &reference, "audit-evidence-143", 20);
    let completed = fixture
        .service
        .audit_compare_outbound_request(
            &request,
            reference,
            verified_runner,
            &admin,
            fixture.audit_admin.as_ref(),
            20,
        )
        .test_expect("completed audit evidence");
    verify_completed_audit(
        &completed,
        &signed_runner,
        &admin,
        completed_audit_context(
            &request,
            "audit-evidence-143",
            "legacy-provider-observation",
            &reference_precommitment,
            audit_trust(&fixture),
        ),
    )
    .test_expect("independently verify audit evidence");

    assert!(verify_completed_audit(
        &completed,
        &signed_runner,
        &admin,
        completed_audit_context(
            &request,
            "another-audit",
            "legacy-provider-observation",
            &reference_precommitment,
            audit_trust(&fixture),
        ),
    )
    .is_err());
    assert!(verify_completed_audit(
        &completed,
        &signed_runner,
        &admin,
        completed_audit_context(
            &request,
            "audit-evidence-143",
            "another-reference-source",
            &reference_precommitment,
            audit_trust(&fixture),
        ),
    )
    .is_err());

    let wrong_authority = Keypair::from_seed(&[73; 32]).public_key();
    let mut wrong_authority_trust = audit_trust(&fixture);
    wrong_authority_trust.trusted_authority = &wrong_authority;
    assert!(verify_completed_audit(
        &completed,
        &signed_runner,
        &admin,
        completed_audit_context(
            &request,
            "audit-evidence-143",
            "legacy-provider-observation",
            &reference_precommitment,
            wrong_authority_trust,
        ),
    )
    .is_err());

    let wrong_runner = Keypair::from_seed(&[74; 32]).public_key();
    let mut wrong_runner_trust = audit_trust(&fixture);
    wrong_runner_trust.trusted_runner = &wrong_runner;
    assert!(verify_completed_audit(
        &completed,
        &signed_runner,
        &admin,
        completed_audit_context(
            &request,
            "audit-evidence-143",
            "legacy-provider-observation",
            &reference_precommitment,
            wrong_runner_trust,
        ),
    )
    .is_err());

    let wrong_receipt_signer = Keypair::from_seed(&[75; 32]).public_key();
    let mut wrong_receipt_trust = audit_trust(&fixture);
    wrong_receipt_trust.receipt_signer = &wrong_receipt_signer;
    assert!(verify_completed_audit(
        &completed,
        &signed_runner,
        &admin,
        completed_audit_context(
            &request,
            "audit-evidence-143",
            "legacy-provider-observation",
            &reference_precommitment,
            wrong_receipt_trust,
        ),
    )
    .is_err());

    let wrong_subject = Keypair::from_seed(&[76; 32]).public_key();
    let wrong_policy = crate::provision::GovernedAdminPolicy {
        trusted_approvers: vec![fixture.audit_approver.public_key()],
        subject: wrong_subject,
        threshold: 1,
        maximum_token_lifetime_seconds: 300,
    };
    let mut wrong_policy_trust = audit_trust(&fixture);
    wrong_policy_trust.governed_admin_policy = &wrong_policy;
    assert!(verify_completed_audit(
        &completed,
        &signed_runner,
        &admin,
        completed_audit_context(
            &request,
            "audit-evidence-143",
            "legacy-provider-observation",
            &reference_precommitment,
            wrong_policy_trust,
        ),
    )
    .is_err());

    let mut wrong_provider_trust = audit_trust(&fixture);
    wrong_provider_trust.provider_adapter_id = "another-provider-adapter";
    assert!(verify_completed_audit(
        &completed,
        &signed_runner,
        &admin,
        completed_audit_context(
            &request,
            "audit-evidence-143",
            "legacy-provider-observation",
            &reference_precommitment,
            wrong_provider_trust,
        ),
    )
    .is_err());

    assert!(crate::audit::verify_broker_audit_evidence(
        crate::audit::BrokerAuditEvidenceBundle {
            comparison: &completed.comparison,
            runner_authorization: &signed_runner,
            admin_authorization: &admin,
            authority: crate::audit::BrokerAuditAuthorityEvidence {
                liveness: &completed.liveness_authority_exchange,
                revocation: &completed.liveness_authority_exchange,
            },
        },
        crate::audit::BrokerAuditExpectedContext {
            request: &request,
            audit_id: "audit-evidence-143",
            reference_source: "legacy-provider-observation",
            reference_precommitment: &reference_precommitment,
            revocation_authority_domain: "combined-authority",
            trust: audit_trust(&fixture),
            not_before_unix_seconds: 19,
            expires_at_unix_seconds: 21,
        },
    )
    .is_err());
}

#[test]
fn audit_comparison_rejects_invalid_proof_and_capability_before_secret_use() {
    let fixture = fixture(1, false, false);
    let (request, _trusted) = execution(&fixture, 141, 1);

    let mut invalid_proof = request.clone();
    invalid_proof.request.body.push(b'!');
    let (invalid_proof_reference, _invalid_proof_precommitment) =
        audit_reference_for_execution(&fixture, &request, true);
    let (invalid_proof_runner, invalid_proof_admin, _) = authorized_audit(
        &fixture,
        &invalid_proof,
        &invalid_proof_reference,
        "audit-invalid-proof-141",
        20,
    );
    let proof_error = fixture
        .service
        .audit_compare_outbound_request(
            &invalid_proof,
            invalid_proof_reference,
            invalid_proof_runner,
            &invalid_proof_admin,
            fixture.audit_admin.as_ref(),
            20,
        )
        .test_expect_err("changed request must invalidate the proof");
    assert!(matches!(proof_error, BrokerError::AuthorizationDenied(_)));

    let mut invalid_capability = request.clone();
    invalid_capability.capability.body.provider_adapter_version = 2;
    let (invalid_capability_reference, _invalid_capability_precommitment) =
        audit_reference_for_execution(&fixture, &request, true);
    let (invalid_capability_runner, invalid_capability_admin, _) = authorized_audit(
        &fixture,
        &invalid_capability,
        &invalid_capability_reference,
        "audit-invalid-capability-141",
        20,
    );
    let capability_error = fixture
        .service
        .audit_compare_outbound_request(
            &invalid_capability,
            invalid_capability_reference,
            invalid_capability_runner,
            &invalid_capability_admin,
            fixture.audit_admin.as_ref(),
            20,
        )
        .test_expect_err("changed capability must invalidate its signature");
    assert!(matches!(
        capability_error,
        BrokerError::AuthorizationDenied(_)
    ));

    assert_eq!(fixture.live_authority_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.resolver_calls.load(Ordering::SeqCst), 0);
    assert!(fixture
        .observed_authorizations
        .lock()
        .test_expect("observed authorization lock")
        .is_empty());
    assert_eq!(fixture.authority.captured_count(), 0);
    assert!(fixture
        .authority
        .state
        .lock()
        .test_expect("audit authority state")
        .holds
        .is_empty());
    assert!(fixture
        .service
        .retained_prepared_dispatches()
        .test_expect("retained prepared dispatches")
        .is_empty());
    assert!(fixture
        .receipts
        .lock()
        .test_expect("audit receipt lock")
        .is_empty());
}

#[test]
fn audit_comparison_requires_exact_runner_and_durable_one_shot_governance() {
    let fixture = fixture(1, false, false);
    let (request, _trusted) = execution(&fixture, 142, 1);
    let (reference, _reference_precommitment) =
        audit_reference_for_execution(&fixture, &request, true);
    let (verified_runner, admin, signed_runner) =
        authorized_audit(&fixture, &request, &reference, "audit-governed-142", 20);
    let governed_intent = verified_runner.governed_intent_sha256().to_string();

    let (wrong_reference, _wrong_reference_precommitment) =
        audit_reference_for_execution(&fixture, &request, true);
    assert!(crate::audit::verify_broker_audit_runner_authorization(
        &signed_runner,
        &request,
        &wrong_reference,
        crate::audit::BrokerAuditRunnerTrust {
            deployment_id: "test-deployment",
            broker_instance_id: "test-broker-instance",
            tenant_scope: "tenant-a",
            runner_id: "test-enterprise-runner",
            trusted_runner: &fixture.audit_runner.public_key(),
        },
        20,
    )
    .is_err());
    let wrong_runner = Keypair::from_seed(&[64; 32]).public_key();
    assert!(crate::audit::verify_broker_audit_runner_authorization(
        &signed_runner,
        &request,
        &reference,
        crate::audit::BrokerAuditRunnerTrust {
            deployment_id: "test-deployment",
            broker_instance_id: "test-broker-instance",
            tenant_scope: "tenant-a",
            runner_id: "test-enterprise-runner",
            trusted_runner: &wrong_runner,
        },
        20,
    )
    .is_err());

    fixture
        .service
        .audit_compare_outbound_request(
            &request,
            reference,
            verified_runner,
            &admin,
            fixture.audit_admin.as_ref(),
            20,
        )
        .test_expect("governed audit comparison");
    assert!(matches!(
        fixture
            .audit_admin
            .authorize_intent_digest(&admin, &governed_intent),
        Err(BrokerError::AuthorizationDenied(_))
    ));

    let reopened = GovernedAdminAuthorizer::open(
        &fixture.audit_admin_path,
        crate::provision::GovernedAdminPolicy {
            trusted_approvers: vec![fixture.audit_approver.public_key()],
            subject: fixture.audit_subject.clone(),
            threshold: 1,
            maximum_token_lifetime_seconds: 300,
        },
        fixture.service.receipt_signer.public_key(),
        Arc::new(AuditClock),
    )
    .test_expect("reopen audit replay store");
    assert!(matches!(
        reopened.authorize_intent_digest(&admin, &governed_intent),
        Err(BrokerError::AuthorizationDenied(_))
    ));
    assert_eq!(fixture.resolver_calls.load(Ordering::SeqCst), 0);
    assert!(fixture
        .observed_authorizations
        .lock()
        .test_expect("observed authorization lock")
        .is_empty());
}
