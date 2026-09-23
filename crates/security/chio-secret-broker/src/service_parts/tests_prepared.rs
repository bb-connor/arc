use super::*;
use crate::registration::{
    sign_register_attempt_authorization, verify_register_attempt_authorization,
    AuthenticatedAttemptRequest, RegisterAttemptAction, SignedRegisterAttemptAuthorization,
};

// These tests exercise framing and descriptor lifetime. The native process
// tests separately require the production daemon and original kernel capture.
struct PreparedHandler {
    executes: Arc<AtomicU64>,
    // Framing cases share a fixed authorization clock. Real connection expiry
    // and frame deadlines below continue to use the production clock.
    verified_at_unix_seconds: u64,
}

impl PreparedHandler {
    fn handle(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        if request.operation == IpcOperation::Execute {
            self.executes.fetch_add(1, Ordering::SeqCst);
        }
        Ok(IpcResponse {
            operation: request.operation,
            accepted: true,
            response: b"{}".to_vec(),
            error_code: None,
        })
    }
}

impl BrokerIpcHandler for PreparedHandler {
    endpoint_test_handler_method!(register_attempt);
    endpoint_test_handler_method!(prepare_dispatch);
    endpoint_test_handler_method!(release_attempt);
    endpoint_test_handler_method!(issue);
    endpoint_test_handler_method!(revoke);
    endpoint_test_handler_method!(status);
    endpoint_test_handler_method!(execute);
    endpoint_test_handler_method!(provision);
    endpoint_test_handler_method!(rotate);
    endpoint_test_handler_method!(disable);
    endpoint_test_handler_method!(delete);

    fn prepare_connection(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
        let authenticated: AuthenticatedAttemptRequest =
            serde_json::from_slice(&request.payload)
                .map_err(|_| BrokerError::InvalidRequest("invalid preparation".into()))?;
        let authorization: SignedRegisterAttemptAuthorization =
            serde_json::from_slice(&request.authorization)
                .map_err(|_| BrokerError::AuthorizationDenied("invalid authorization".into()))?;
        let now = self.verified_at_unix_seconds;
        verify_register_attempt_authorization(
            &authorization,
            &authenticated.registration,
            RegisterAttemptAction::Prepare,
            &request.tenant_scope,
            &authority().public_key(),
            now,
            0,
        )?;
        let ack = PrepareDispatchAcknowledgement::new(
            &authenticated.registration,
            &authenticated.request,
            now,
        )?;
        Ok(IpcResponse {
            operation: IpcOperation::PrepareConnection,
            accepted: true,
            response: canonical_json_bytes(&ack).test_expect("canonical acknowledgement"),
            error_code: None,
        })
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .test_expect("current time")
        .as_secs()
}

fn authority() -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[86; 32]))
}

fn requests(issued_at_unix_seconds: u64) -> (AuthenticatedIpcRequest, AuthenticatedIpcRequest) {
    let fixture = fixture(1, false, false);
    let (mut request, trusted) = execution(&fixture, 87, 1);
    let mut body = request.capability.body;
    body.issued_at_unix_seconds = issued_at_unix_seconds;
    body.not_before_unix_seconds = body.issued_at_unix_seconds;
    body.expires_at_unix_seconds = body.issued_at_unix_seconds + 120;
    request.capability = issue_capability(body, &Ed25519Backend::new(fixture.issuer.clone()), true)
        .test_expect("current signed capability");
    request.proof = issue_request_proof(
        &request.capability,
        &request.request,
        "nonce-prepared-connection".into(),
        issued_at_unix_seconds,
        &fixture.caller,
    )
    .test_expect("current signed proof");
    let registration = test_attempt_registration(
        &request,
        &trusted.admission_operation_id,
        &trusted.quotas,
        &trusted.authority_metadata_digest,
        &trusted.revocation_authority_domain,
    );
    let authorization = sign_register_attempt_authorization(
        RegisterAttemptAction::Prepare,
        "tenant-prepared".into(),
        &registration,
        issued_at_unix_seconds,
        &authority(),
    )
    .test_expect("signed preparation");
    let prepare = AuthenticatedIpcRequest {
        operation: IpcOperation::PrepareConnection,
        tenant_scope: "tenant-prepared".into(),
        authorization: canonical_json_bytes(&authorization)
            .test_expect("authorization")
            .into(),
        payload: canonical_json_bytes(&AuthenticatedAttemptRequest {
            registration,
            request: request.clone(),
        })
        .test_expect("prepared request")
        .into(),
    };
    let execute = AuthenticatedIpcRequest {
        operation: IpcOperation::Execute,
        tenant_scope: prepare.tenant_scope.clone(),
        authorization: canonical_json_bytes(&request.proof)
            .test_expect("execute proof")
            .into(),
        payload: canonical_json_bytes(&request)
            .test_expect("execute request")
            .into(),
    };
    (prepare, execute)
}

fn endpoint(
    root: &Path,
    executes: Arc<AtomicU64>,
    verified_at_unix_seconds: u64,
) -> UnixBrokerEndpoint {
    let uid = rustix::process::geteuid().as_raw();
    UnixBrokerEndpoint::bind_with_deadlines(
        root.join("broker.sock"),
        Arc::new(PreparedHandler {
            executes,
            verified_at_unix_seconds,
        }),
        uid,
        uid,
        BrokerIpcDeadlines::from_millis(100, 1_000).test_expect("ordinary deadlines"),
    )
    .test_expect("prepared endpoint")
}

fn exchange(
    endpoint: &UnixBrokerEndpoint,
    request: &AuthenticatedIpcRequest,
) -> (UnixStream, IpcResponse) {
    let mut stream = UnixStream::connect(&endpoint.socket_path).test_expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .test_expect("read bound");
    let frame = canonical_ipc_request_bytes(request).test_expect("canonical frame");
    write_bounded_frame(&mut stream, &frame).test_expect("send frame");
    assert_eq!(
        endpoint.serve_one().test_expect("serve frame"),
        BrokerIpcServeOutcome::ResponseWritten
    );
    let response =
        serde_json::from_slice(&read_bounded_frame(&mut stream).test_expect("response frame"))
            .test_expect("response envelope");
    (stream, response)
}

#[test]
fn prepared_connection_waits_without_blocking_control_and_executes_once() {
    let directory = crate::private_tempdir().test_expect("directory");
    let executes = Arc::new(AtomicU64::new(0));
    let issued_at = now();
    let endpoint = endpoint(directory.path(), Arc::clone(&executes), issued_at);
    let (prepare, execute) = requests(issued_at);
    let (mut stream, ack) = exchange(&endpoint, &prepare);
    assert!(ack.accepted);
    thread::sleep(Duration::from_millis(150));
    assert!(exchange(&endpoint, &endpoint_test_request()).1.accepted);
    assert!(endpoint
        .try_serve_prepared()
        .test_expect("idle poll")
        .is_none());
    write_bounded_frame(
        &mut stream,
        &canonical_ipc_request_bytes(&execute).test_expect("execute frame"),
    )
    .test_expect("send execution");
    assert_eq!(
        endpoint.try_serve_prepared().test_expect("execute"),
        Some(BrokerIpcServeOutcome::ResponseWritten)
    );
    let response: IpcResponse =
        serde_json::from_slice(&read_bounded_frame(&mut stream).test_expect("completed frame"))
            .test_expect("completed response");
    assert!(response.accepted);
    assert_eq!(executes.load(Ordering::SeqCst), 1);
    assert!(!endpoint.prepared.busy.load(Ordering::Acquire));
    assert!(
        read_bounded_frame(&mut stream).is_err(),
        "one-use connection remained open"
    );
    assert!(endpoint
        .try_serve_prepared()
        .test_expect("completed poll")
        .is_none());
}

#[test]
fn prepared_connection_rejects_unauthorized_capacity_and_substituted_frames() {
    let directory = crate::private_tempdir().test_expect("directory");
    let executes = Arc::new(AtomicU64::new(0));
    let issued_at = now();
    let endpoint = endpoint(directory.path(), Arc::clone(&executes), issued_at);
    let (mut prepare, execute) = requests(issued_at);
    let authorization = prepare.authorization.as_slice().to_vec();
    prepare.authorization = b"invalid".to_vec().into();
    assert!(!exchange(&endpoint, &prepare).1.accepted);
    assert!(!endpoint.prepared.busy.load(Ordering::Acquire));
    prepare.authorization = authorization.into();
    let frame = canonical_ipc_request_bytes(&execute).test_expect("original frame");
    for field in ["operation", "tenantScope", "authorization", "payload"] {
        let (mut stream, ack) = exchange(&endpoint, &prepare);
        assert!(ack.accepted);
        assert!(
            !exchange(&endpoint, &prepare).1.accepted,
            "unbounded prepared capacity"
        );
        let mut changed: serde_json::Value =
            serde_json::from_slice(&frame).test_expect("wire value");
        changed[field] = match field {
            "operation" => serde_json::json!("status"),
            "tenantScope" => serde_json::json!("other-tenant"),
            _ => serde_json::json!([1, 2, 3]),
        };
        write_bounded_frame(
            &mut stream,
            &canonical_json_bytes(&changed).test_expect("changed frame"),
        )
        .test_expect("send substitution");
        assert!(matches!(
            endpoint
                .try_serve_prepared()
                .test_expect("reject substitution"),
            Some(BrokerIpcServeOutcome::ClientFault { .. })
        ));
        assert_eq!(executes.load(Ordering::SeqCst), 0);
        assert!(!endpoint.prepared.busy.load(Ordering::Acquire));
    }
}

#[test]
fn prepared_connection_expiry_eof_and_trickle_release_capacity() {
    let directory = crate::private_tempdir().test_expect("directory");
    let executes = Arc::new(AtomicU64::new(0));
    let issued_at = now();
    let endpoint = endpoint(directory.path(), Arc::clone(&executes), issued_at);
    let (prepare, _) = requests(issued_at);
    let (stream, ack) = exchange(&endpoint, &prepare);
    assert!(ack.accepted);
    // Advance the private test deadline without waiting for the production cap.
    endpoint
        .prepared
        .pending
        .lock()
        .test_expect("slot")
        .as_mut()
        .test_expect("prepared connection")
        .deadline = Instant::now();
    assert!(matches!(
        endpoint.try_serve_prepared().test_expect("expire"),
        Some(BrokerIpcServeOutcome::ClientFault { .. })
    ));
    drop(stream);
    assert!(!endpoint.prepared.busy.load(Ordering::Acquire));
    let (stream, ack) = exchange(&endpoint, &prepare);
    assert!(ack.accepted);
    drop(stream);
    assert!(endpoint.try_serve_prepared().test_expect("EOF").is_none());
    assert!(!endpoint.prepared.busy.load(Ordering::Acquire));
    let (mut stream, ack) = exchange(&endpoint, &prepare);
    assert!(ack.accepted);
    stream.write_all(&[0]).test_expect("first prefix byte");
    thread::scope(|scope| {
        scope.spawn(move || {
            for byte in [0, 1, 0].into_iter().chain(std::iter::repeat_n(b'x', 40)) {
                thread::sleep(Duration::from_millis(25));
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
            }
        });
        let started = Instant::now();
        assert!(matches!(
            endpoint.try_serve_prepared().test_expect("trickle"),
            Some(BrokerIpcServeOutcome::ClientFault { .. })
        ));
        assert!(
            started.elapsed() < Duration::from_millis(700),
            "trickle extended the frame deadline"
        );
    });
    assert!(!endpoint.prepared.busy.load(Ordering::Acquire));
    assert_eq!(executes.load(Ordering::SeqCst), 0);
}

#[test]
fn prepared_connection_lifetime_respects_capability_and_nonce_expiry() {
    let (prepare, _) = requests(now());
    let mut authenticated: AuthenticatedAttemptRequest =
        serde_json::from_slice(&prepare.payload).test_expect("prepared request");
    let (_, deadline) = prepared_connection_binding(&prepare.tenant_scope, &authenticated)
        .test_expect("bounded lifetime");
    assert!(deadline.duration_since(Instant::now()) <= Duration::from_secs(30));
    for nonce_expires_first in [false, true] {
        authenticated
            .request
            .capability
            .body
            .expires_at_unix_seconds = now() + 120;
        authenticated.registration.nonce_expires_at_unix_seconds = now() + 120;
        if nonce_expires_first {
            authenticated.registration.nonce_expires_at_unix_seconds = now() + 1;
        } else {
            authenticated
                .request
                .capability
                .body
                .expires_at_unix_seconds = now() + 1;
        }
        let (_, deadline) = prepared_connection_binding(&prepare.tenant_scope, &authenticated)
            .test_expect("short lifetime");
        assert!(deadline.duration_since(Instant::now()) <= Duration::from_secs(1));
    }
    authenticated.registration.nonce_expires_at_unix_seconds = now();
    assert!(prepared_connection_binding(&prepare.tenant_scope, &authenticated).is_err());
}
