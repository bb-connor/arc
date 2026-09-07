    #[test]
    fn migration_custody_denial_precedes_credential_materialization() {
        let fixture = fixture(1, false, false);
        let (request, trusted) = execution(&fixture, 90, 1);
        let registration = test_attempt_registration(
            &request,
            &trusted.admission_operation_id,
            &trusted.quotas,
            &trusted.authority_metadata_digest,
            &trusted.revocation_authority_domain,
        );
        fixture
            .service
            .register_attempt(&registration, &request, 20)
            .test_expect("register migration custody attempt");
        fixture
            .authority
            .authorize_execution_hold(&AuthorizeExecutionHoldRequest {
                operation_id: registration.ids.operation_id.clone(),
                invocation_id: request.invocation_id.clone(),
                parent_capability_id: request.capability.body.parent_capability_id.clone(),
                broker_capability_id: request.capability.body.capability_id.clone(),
                hold_id: registration.ids.hold_id.clone(),
                authorize_event_id: registration.ids.authorize_event_id.clone(),
                quotas: trusted.quotas.clone(),
                authority_metadata_digest: trusted.authority_metadata_digest.clone(),
            })
            .test_expect("authorize migration custody attempt");
        fixture
            .backend
            .delete(&request.capability.body.credential)
            .test_expect("remove credential before custody denial");
        fixture
            .migration_enforcer
            .set_credential_custody_enforced(false);

        let error = fixture
            .service
            .prepare_dispatch(&registration, &request, 20)
            .test_expect_err("migration custody denial must stop preparation");
        assert!(error
            .to_string()
            .contains("credential custody migration enforcement denied"));
        assert_eq!(
            fixture
                .attempts
                .load_attempt(&registration.ids.attempt_id)
                .test_expect("load custody-denied attempt")
                .test_expect("custody-denied attempt exists")
                .state,
            AttemptState::Registered
        );
        assert!(fixture
            .service
            .retained_prepared_dispatches()
            .test_expect("retained custody-denied dispatches")
            .is_empty());
    }

    #[test]
    fn migration_quota_denial_precedes_capture_and_network_dispatch() {
        let fixture = fixture(1, false, false);
        let (request, trusted) = execution(&fixture, 91, 1);
        let ids = register_prepared_execution(&fixture, &request, &trusted, 20);
        fixture
            .migration_enforcer
            .set_quota_enforcement_enforced(false);

        let failure = fixture
            .service
            .execute_inner(&request, &trusted, 21, &|| Ok(21))
            .test_expect_err("migration quota denial must stop execution");
        assert!(failure
            .error
            .to_string()
            .contains("quota enforcement migration enforcement denied"));
        assert_eq!(fixture.authority.captured_count(), 0);
        assert!(fixture
            .observed_authorizations
            .lock()
            .test_expect("quota-denied transport observations")
            .is_empty());
        assert_eq!(
            fixture
                .attempts
                .load_attempt(&ids.attempt_id)
                .test_expect("load quota-denied attempt")
                .test_expect("quota-denied attempt exists")
                .state,
            AttemptState::Prepared
        );
    }

    #[test]
    fn post_capture_migration_change_preserves_truthful_failure_evidence() {
        let fixture = fixture(1, false, false);
        let (request, trusted) = execution(&fixture, 92, 1);
        let ids = register_prepared_execution(&fixture, &request, &trusted, 20);
        fixture.authority.deny_migration_after_next_capture(Arc::clone(
            &fixture.migration_enforcer,
        ));

        let outcome = fixture
            .service
            .execute_evidenced(&request, &trusted, 21)
            .test_expect("post-capture migration denial evidence");
        let BrokerExecuteOutcome::Failure(failure) = outcome else {
            panic!("post-capture migration change dispatched instead of denying");
        };
        let failure = *failure;
        assert_eq!(failure.receipt.body.stage, BrokerFailureStage::Capture);
        assert_eq!(failure.receipt.body.outcome, BrokerFailureOutcome::Denied);
        assert_eq!(
            failure.receipt.body.dispatch_knowledge,
            BrokerDispatchKnowledge::NotCommitted
        );
        let attempt = fixture
            .attempts
            .load_attempt(&ids.attempt_id)
            .test_expect("load post-capture migration attempt")
            .test_expect("post-capture migration attempt exists");
        assert_eq!(attempt.state, AttemptState::Failed);
        assert!(attempt.revocation_set_digest.is_some());
        assert!(attempt.budget_commit_index.is_some());
        assert!(fixture
            .observed_authorizations
            .lock()
            .test_expect("post-capture transport observations")
            .is_empty());
    }

    #[test]
    fn framing_rejects_empty_and_oversized_frames() {
        let empty_bytes = 0_u32.to_be_bytes();
        let mut empty = empty_bytes.as_slice();
        assert!(read_bounded_frame(&mut empty).is_err());
        let oversized_bytes = u32::try_from(MAX_WIRE_BYTES + 1)
            .test_expect("u32")
            .to_be_bytes();
        let mut oversized = oversized_bytes.as_slice();
        assert!(read_bounded_frame(&mut oversized).is_err());
    }

    #[test]
    fn partial_sensitive_frame_is_zeroized_before_the_read_error_escapes() {
        let mut frame = Zeroizing::new(vec![0xaa; 32]);
        let mut partial = b"partial-secret-frame".as_slice();
        assert!(read_sensitive_frame_body(&mut partial, &mut frame).is_err());
        assert!(frame.is_empty());
    }

    struct SensitiveIpcTraitProbe<T>(std::marker::PhantomData<T>);

    trait SensitiveIpcDebugAmbiguity<Marker> {
        fn assert_absent() {}
    }

    impl<T> SensitiveIpcDebugAmbiguity<()> for SensitiveIpcTraitProbe<T> {}
    impl<T: std::fmt::Debug> SensitiveIpcDebugAmbiguity<u8> for SensitiveIpcTraitProbe<T> {}

    trait SensitiveIpcCloneAmbiguity<Marker> {
        fn assert_absent() {}
    }

    impl<T> SensitiveIpcCloneAmbiguity<()> for SensitiveIpcTraitProbe<T> {}
    impl<T: Clone> SensitiveIpcCloneAmbiguity<u8> for SensitiveIpcTraitProbe<T> {}

    trait SensitiveIpcSerializeAmbiguity<Marker> {
        fn assert_absent() {}
    }

    impl<T> SensitiveIpcSerializeAmbiguity<()> for SensitiveIpcTraitProbe<T> {}
    impl<T: serde::Serialize> SensitiveIpcSerializeAmbiguity<u8> for SensitiveIpcTraitProbe<T> {}

    #[test]
    fn sensitive_ipc_envelope_is_strictly_canonical_and_zeroizing() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<AuthenticatedIpcRequest>();
        assert_zeroize_on_drop::<SensitiveIpcBytes>();
        assert_zeroize_on_drop::<BoundedZeroizingByteArray<65_536>>();
        assert_zeroize_on_drop::<AdminAuthorization>();
        assert_zeroize_on_drop::<Zeroizing<Vec<u8>>>();
        type RequestProbe = SensitiveIpcTraitProbe<AuthenticatedIpcRequest>;
        type BytesProbe = SensitiveIpcTraitProbe<SensitiveIpcBytes>;
        type AdminProbe = SensitiveIpcTraitProbe<AdminAuthorization>;
        <RequestProbe as SensitiveIpcDebugAmbiguity<_>>::assert_absent();
        <RequestProbe as SensitiveIpcCloneAmbiguity<_>>::assert_absent();
        <RequestProbe as SensitiveIpcSerializeAmbiguity<_>>::assert_absent();
        <BytesProbe as SensitiveIpcDebugAmbiguity<_>>::assert_absent();
        <BytesProbe as SensitiveIpcCloneAmbiguity<_>>::assert_absent();
        <BytesProbe as SensitiveIpcSerializeAmbiguity<_>>::assert_absent();
        <AdminProbe as SensitiveIpcDebugAmbiguity<_>>::assert_absent();
        <AdminProbe as SensitiveIpcCloneAmbiguity<_>>::assert_absent();
        <AdminProbe as SensitiveIpcSerializeAmbiguity<_>>::assert_absent();

        reset_sensitive_drop_observer();
        let canonical = br#"{"authorization":[1],"operation":"provision","payload":[2,3],"tenantScope":"tenant-ipc"}"#;
        let decoded = decode_canonical_ipc_request(canonical).test_expect("canonical request");
        assert_eq!(decoded.operation, IpcOperation::Provision);
        assert_eq!(decoded.payload.as_slice(), [2, 3]);
        assert_eq!(
            canonical_ipc_request_bytes(&decoded)
                .test_expect("canonical request encoding")
                .as_slice(),
            canonical
        );
        drop(decoded);
        assert_eq!(sensitive_drop_observation(), (0, 2));

        let canonical_escaped =
            r#"{"authorization":[1],"operation":"provision","payload":[2,3],"tenantScope":"tenant-\"-\\-😀"}"#
                .as_bytes();
        let escaped = decode_canonical_ipc_request(canonical_escaped)
            .test_expect("canonical escaped request");
        assert_eq!(escaped.tenant_scope.as_str(), "tenant-\"-\\-😀");
        assert_eq!(
            canonical_ipc_request_bytes(&escaped)
                .test_expect("canonical escaped request encoding")
                .as_slice(),
            canonical_escaped
        );

        let reordered = br#"{"operation":"provision","authorization":[1],"payload":[2,3],"tenantScope":"tenant-ipc"}"#;
        assert!(decode_canonical_ipc_request(reordered).is_err());
        let duplicate = br#"{"authorization":[1],"operation":"provision","payload":[2,3],"payload":[4],"tenantScope":"tenant-ipc"}"#;
        assert!(decode_canonical_ipc_request(duplicate).is_err());
        let unknown = br#"{"authorization":[1],"operation":"provision","payload":[2,3],"tenantScope":"tenant-ipc","unexpected":true}"#;
        assert!(decode_canonical_ipc_request(unknown).is_err());
        let escaped_key = br#"{"authoriz\u0061tion":[1],"operation":"provision","payload":[2,3],"tenantScope":"tenant-ipc"}"#;
        assert!(decode_canonical_ipc_request(escaped_key).is_err());
        let surrogate_pair = br#"{"authorization":[1],"operation":"provision","payload":[2,3],"tenantScope":"\ud83d\ude00"}"#;
        assert!(decode_canonical_ipc_request(surrogate_pair).is_err());
        let exponent_byte = br#"{"authorization":[1],"operation":"provision","payload":[2e0],"tenantScope":"tenant-ipc"}"#;
        assert!(decode_canonical_ipc_request(exponent_byte).is_err());
        let negative_byte = br#"{"authorization":[1],"operation":"provision","payload":[-1],"tenantScope":"tenant-ipc"}"#;
        assert!(decode_canonical_ipc_request(negative_byte).is_err());
        let fractional_byte = br#"{"authorization":[1],"operation":"provision","payload":[2.0],"tenantScope":"tenant-ipc"}"#;
        assert!(decode_canonical_ipc_request(fractional_byte).is_err());
        let trailing_data = br#"{"authorization":[1],"operation":"provision","payload":[2,3],"tenantScope":"tenant-ipc"}true"#;
        assert!(decode_canonical_ipc_request(trailing_data).is_err());
        let deep_nesting = br#"{"authorization":[1],"operation":"provision","payload":[[[[2]]]],"tenantScope":"tenant-ipc"}"#;
        assert!(decode_canonical_ipc_request(deep_nesting).is_err());

        let mut malformed_utf8 = Zeroizing::new(
            br#"{"authorization":[1],"operation":"provision","payload":[2,3],"tenantScope":""#
                .to_vec(),
        );
        malformed_utf8.push(0xff);
        malformed_utf8.extend_from_slice(br#""}"#);
        assert!(decode_canonical_ipc_request(&malformed_utf8).is_err());

        reset_sensitive_drop_observer();
        let malformed_nested = br#"{"authorization":[1],"operation":"provision","payload":[2,"secret-canary"],"tenantScope":"tenant-ipc"}"#;
        assert!(decode_canonical_ipc_request(malformed_nested).is_err());
        assert!(sensitive_drop_observation().0 >= 1);
    }

    #[test]
    fn long_sensitive_ipc_envelope_uses_one_exact_canonical_allocation() {
        let request = AuthenticatedIpcRequest {
            operation: IpcOperation::Provision,
            tenant_scope: "t".repeat(512),
            authorization: vec![255; 65_536].into(),
            payload: vec![255; 180_000].into(),
        };
        let canonical = canonical_ipc_request_bytes(&request).test_expect("long IPC request");
        assert_eq!(canonical.len(), canonical.capacity());
        assert!(canonical.len() < MAX_WIRE_BYTES);
    }

    #[cfg(target_os = "linux")]
    struct EndpointTestHandler {
        invalid_envelope: bool,
        response_gate: Option<Arc<Barrier>>,
        response_bytes: Option<usize>,
    }

    #[cfg(target_os = "linux")]
    impl EndpointTestHandler {
        fn handle(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
            if let Some(gate) = &self.response_gate {
                gate.wait();
            }
            if self.invalid_envelope {
                return Ok(IpcResponse {
                    operation: request.operation,
                    accepted: true,
                    response: Vec::new(),
                    error_code: Some("invalid_test_envelope".to_string()),
                });
            }
            if let Some(response_bytes) = self.response_bytes {
                return Ok(IpcResponse {
                    operation: request.operation,
                    accepted: true,
                    response: vec![7; response_bytes],
                    error_code: None,
                });
            }
            Err(BrokerError::Conflict(
                "structured test rejection".to_string(),
            ))
        }
    }

    #[cfg(target_os = "linux")]
    macro_rules! endpoint_test_handler_method {
        ($name:ident) => {
            fn $name(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse> {
                self.handle(request)
            }
        };
    }

    #[cfg(target_os = "linux")]
    impl BrokerIpcHandler for EndpointTestHandler {
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
    }

    #[cfg(target_os = "linux")]
    fn endpoint_test_request() -> AuthenticatedIpcRequest {
        AuthenticatedIpcRequest {
            operation: IpcOperation::Status,
            tenant_scope: "tenant-ipc-deadline-test".to_string(),
            authorization: vec![1].into(),
            payload: vec![2].into(),
        }
    }

    #[cfg(target_os = "linux")]
    fn send_endpoint_test_request(stream: &mut std::os::unix::net::UnixStream) {
        let encoded =
            canonical_ipc_request_bytes(&endpoint_test_request()).test_expect("IPC request");
        write_bounded_frame(stream, &encoded).test_expect("write IPC request");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stalled_same_uid_client_is_bounded_and_next_request_is_served() {
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        let directory = crate::private_tempdir().test_expect("IPC directory");
        let socket_path = directory.path().join("broker.sock");
        let uid = rustix::process::geteuid().as_raw();
        let deadlines =
            BrokerIpcDeadlines::from_millis(100, 1_000).test_expect("bounded deadlines");
        let endpoint = UnixBrokerEndpoint::bind_with_deadlines(
            &socket_path,
            Arc::new(EndpointTestHandler {
                invalid_envelope: false,
                response_gate: None,
                response_bytes: None,
            }),
            uid,
            uid,
            deadlines,
        )
        .test_expect("bind endpoint");
        let server = thread::spawn(move || {
            let stalled = endpoint.serve_one();
            let responsive = endpoint.serve_one();
            (stalled, responsive)
        });

        let stalled = UnixStream::connect(&socket_path).test_expect("connect stalled client");
        thread::sleep(Duration::from_millis(250));
        let mut responsive =
            UnixStream::connect(&socket_path).test_expect("connect responsive client");
        responsive
            .set_read_timeout(Some(Duration::from_secs(2)))
            .test_expect("responsive read timeout");
        send_endpoint_test_request(&mut responsive);
        let response_frame =
            read_bounded_frame(&mut responsive).test_expect("structured IPC response");
        let response: IpcResponse =
            serde_json::from_slice(&response_frame).test_expect("decode IPC response");
        drop(stalled);

        let (stalled_outcome, responsive_outcome) =
            server.join().test_expect("endpoint server thread");
        assert_eq!(
            stalled_outcome.test_expect("stalled client is contained"),
            BrokerIpcServeOutcome::ClientFault {
                diagnostic_code: "invalid_request"
            }
        );
        assert_eq!(
            responsive_outcome.test_expect("next request is served"),
            BrokerIpcServeOutcome::ResponseWritten
        );
        assert_eq!(response.operation, IpcOperation::Status);
        assert!(!response.accepted);
        assert!(response.response.is_empty());
        assert_eq!(response.error_code.as_deref(), Some("conflict"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn invalid_handler_envelope_is_surfaced_as_an_internal_failure() {
        use std::os::unix::net::UnixStream;

        let directory = crate::private_tempdir().test_expect("IPC directory");
        let socket_path = directory.path().join("broker.sock");
        let uid = rustix::process::geteuid().as_raw();
        let endpoint = UnixBrokerEndpoint::bind(
            &socket_path,
            Arc::new(EndpointTestHandler {
                invalid_envelope: true,
                response_gate: None,
                response_bytes: None,
            }),
            uid,
            uid,
        )
        .test_expect("bind endpoint");
        let server = thread::spawn(move || endpoint.serve_one());
        let mut client = UnixStream::connect(&socket_path).test_expect("connect client");
        send_endpoint_test_request(&mut client);

        let error = server
            .join()
            .test_expect("endpoint server thread")
            .test_expect_err("invalid handler envelope must reach supervision");
        assert!(matches!(error, BrokerError::Invariant(_)));

        let rebuilt = UnixBrokerEndpoint::bind(
            &socket_path,
            Arc::new(EndpointTestHandler {
                invalid_envelope: false,
                response_gate: None,
                response_bytes: None,
            }),
            uid,
            uid,
        )
        .test_expect("fatal endpoint drop must release the exact socket path");
        drop(rebuilt);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn response_write_disconnect_is_classified_as_a_client_fault() {
        use std::net::Shutdown;
        use std::os::unix::net::UnixStream;

        let directory = crate::private_tempdir().test_expect("IPC directory");
        let socket_path = directory.path().join("broker.sock");
        let uid = rustix::process::geteuid().as_raw();
        let response_gate = Arc::new(Barrier::new(2));
        let endpoint = UnixBrokerEndpoint::bind(
            &socket_path,
            Arc::new(EndpointTestHandler {
                invalid_envelope: false,
                response_gate: Some(Arc::clone(&response_gate)),
                response_bytes: None,
            }),
            uid,
            uid,
        )
        .test_expect("bind endpoint");
        let server = thread::spawn(move || endpoint.serve_one());
        let mut client = UnixStream::connect(&socket_path).test_expect("connect client");
        send_endpoint_test_request(&mut client);
        client
            .shutdown(Shutdown::Read)
            .test_expect("close client response direction");
        response_gate.wait();

        let outcome = server
            .join()
            .test_expect("endpoint server thread")
            .test_expect("peer-controlled response write failure is contained");
        assert_eq!(
            outcome,
            BrokerIpcServeOutcome::ClientFault {
                diagnostic_code: "invalid_request"
            }
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn broker_endpoint_peer_uid_is_kernel_observed_and_fail_closed() {
        use std::os::unix::net::UnixStream;

        let (client, _server) = UnixStream::pair().test_expect("Unix stream pair");
        let observed_uid = rustix::process::geteuid().as_raw();
        validate_broker_peer_uid(&client, observed_uid).test_expect("matching client UID");

        let error = validate_broker_peer_uid(&client, observed_uid.wrapping_add(1))
            .test_expect_err("a self-declared or substituted client UID must fail");
        assert!(error
            .to_string()
            .contains("IPC client UID is not authorized"));
    }

    #[test]
    fn release_before_registration_persists_an_exact_idempotent_tombstone() {
        let fixture = fixture(1, false, false);
        let (request, trusted) = execution(&fixture, 90, 1);
        let registration = test_attempt_registration(
            &request,
            &trusted.admission_operation_id,
            &trusted.quotas,
            &trusted.authority_metadata_digest,
            &trusted.revocation_authority_domain,
        );

        let first = fixture
            .service
            .release_attempt(&registration, &request, 21)
            .test_expect("persist release tombstone before registration");
        let retry = fixture
            .service
            .release_attempt(&registration, &request, 22)
            .test_expect("retry exact release tombstone");
        assert_eq!(retry, first);
        assert_eq!(first.released_at_unix_seconds, 21);
        assert_eq!(
            fixture
                .attempts
                .load_attempt(&registration.ids.attempt_id)
                .test_expect("load release tombstone")
                .test_expect("release tombstone exists")
                .state,
            AttemptState::Failed
        );
        assert!(matches!(
            fixture
                .service
                .register_attempt(&registration, &request, 22),
            Err(BrokerError::AuthorizationDenied(_))
        ));
        assert!(fixture
            .observed_authorizations
            .lock()
            .test_expect("observed authorization lock")
            .is_empty());
    }

    #[test]
    fn stale_release_after_capture_preserves_the_dispatch_owners_material() {
        let fixture = fixture(1, false, false);
        let (request, trusted) = execution(&fixture, 91, 1);
        let registration = test_attempt_registration(
            &request,
            &trusted.admission_operation_id,
            &trusted.quotas,
            &trusted.authority_metadata_digest,
            &trusted.revocation_authority_domain,
        );
        register_execution(&fixture, &request, &trusted, 21);
        let (ids, capture_evidence) = captured_attempt_evidence(&fixture, &request, &trusted);
        fixture
            .attempts
            .transition(
                &ids.attempt_id,
                AttemptState::Prepared,
                AttemptState::Captured,
                &capture_evidence,
                22,
            )
            .test_expect("persist captured broker attempt");
        assert!(fixture
            .service
            .retained_prepared_dispatches()
            .test_expect("retained prepared dispatches")
            .contains_key(&ids.operation_id));

        assert!(matches!(
            fixture.service.release_attempt(&registration, &request, 23),
            Err(BrokerError::Conflict(_))
        ));
        assert_eq!(
            fixture
                .attempts
                .load_attempt(&ids.attempt_id)
                .test_expect("load captured attempt")
                .test_expect("captured attempt exists")
                .state,
            AttemptState::Captured
        );
        assert!(fixture
            .service
            .retained_prepared_dispatches()
            .test_expect("retained prepared dispatches")
            .contains_key(&ids.operation_id));
    }

    #[test]
    fn invalid_proof_registration_failure_can_be_durably_tombstoned() {
        let fixture = fixture(1, false, false);
        let (mut request, trusted) = execution(&fixture, 91, 1);
        request.request.body.push(0xff);
        let registration = test_attempt_registration(
            &request,
            &trusted.admission_operation_id,
            &trusted.quotas,
            &trusted.authority_metadata_digest,
            &trusted.revocation_authority_domain,
        );

        assert!(matches!(
            fixture
                .service
                .register_attempt(&registration, &request, 21),
            Err(BrokerError::AuthorizationDenied(_) | BrokerError::InvalidRequest(_))
        ));
        assert!(fixture
            .attempts
            .load_attempt(&registration.ids.attempt_id)
            .test_expect("load failed registration")
            .is_none());
        fixture
            .service
            .release_attempt(&registration, &request, 21)
            .test_expect("tombstone invalid-proof registration failure");
        assert_eq!(
            fixture
                .attempts
                .load_attempt(&registration.ids.attempt_id)
                .test_expect("load invalid-proof tombstone")
                .test_expect("invalid-proof tombstone exists")
                .state,
            AttemptState::Failed
        );
    }

    #[test]
    fn invalid_provider_registration_failure_can_be_durably_tombstoned() {
        let fixture = fixture(1, false, false);
        let (mut request, trusted) = execution(&fixture, 92, 1);
        let mut body = request.capability.body.clone();
        body.provider_adapter_id = "unselected-provider".to_string();
        request.capability =
            issue_capability(body, &Ed25519Backend::new(fixture.issuer.clone()), true)
                .test_expect("issue unsupported-provider capability");
        request.proof = issue_request_proof(
            &request.capability,
            &request.request,
            "nonce-provider-mismatch".to_string(),
            20,
            &fixture.caller,
        )
        .test_expect("issue unsupported-provider proof");
        let registration = test_attempt_registration(
            &request,
            &trusted.admission_operation_id,
            &trusted.quotas,
            &trusted.authority_metadata_digest,
            &trusted.revocation_authority_domain,
        );

        assert!(matches!(
            fixture
                .service
                .register_attempt(&registration, &request, 21),
            Err(BrokerError::AuthorizationDenied(_))
        ));
        fixture
            .service
            .release_attempt(&registration, &request, 21)
            .test_expect("tombstone invalid-provider registration failure");
        assert_eq!(
            fixture
                .attempts
                .load_attempt(&registration.ids.attempt_id)
                .test_expect("load invalid-provider tombstone")
                .test_expect("invalid-provider tombstone exists")
                .state,
            AttemptState::Failed
        );
    }

    #[test]
    fn failure_receipt_without_durable_attempt_is_unbound_and_not_predated() {
        let fixture = fixture(1, false, false);
        let (request, _trusted) = execution(&fixture, 41, 1);
        let request_digest = broker_request_digest(&request).test_expect("request digest");
        let failure = fixture
            .service
            .persist_admission_failure(
                &request,
                5,
                &BrokerError::AuthorizationDenied("injected admission denial".to_string()),
            )
            .test_expect("unregistered failure receipt");
        let body = &failure.receipt.body;

        assert_eq!(
            body.issued_at_unix_seconds,
            request.proof.body.issued_at_unix_seconds
        );
        assert_eq!(body.stage, BrokerFailureStage::Admission);
        assert_eq!(body.outcome, BrokerFailureOutcome::Denied);
        assert_eq!(body.dispatch_knowledge, BrokerDispatchKnowledge::NotStarted);
        assert_eq!(body.request_digest, request_digest);
        assert!(body.receipt_id.starts_with("broker-failure-terminal-"));
        assert_eq!(body.receipt_id.len(), "broker-failure-terminal-".len() + 64);
        assert!(body.attempt_id.is_none());
        assert!(body.invocation_id.is_none());
        assert!(body.hold_id.is_none());
        assert!(body.parent_capability_id.is_none());
        assert!(body.broker_capability_id.is_none());
        let replayed = fixture
            .service
            .persist_admission_failure(
                &request,
                99,
                &BrokerError::AuthorityUnavailable("later transient error".to_string()),
            )
            .test_expect("replay original unregistered failure");
        assert_eq!(replayed, failure);
        assert_eq!(fixture.receipts.lock().test_expect("receipt lock").len(), 1);

        let registration = test_attempt_registration(
            &request,
            "kernel-operation-after-terminal-failure",
            &[
                ExecutionQuota {
                    key_id: request.capability.body.broker_quota_key_id.clone(),
                    maximum_executions: request.capability.body.maximum_executions,
                },
                ExecutionQuota {
                    key_id: "parent-quota-after-terminal-failure".to_string(),
                    maximum_executions: 1,
                },
            ],
            &"e".repeat(64),
            "combined-authority",
        );
        fixture
            .live_authority_unavailable
            .store(true, Ordering::SeqCst);
        assert!(matches!(
            fixture
                .service
                .register_attempt(&registration, &request, 100),
            Err(BrokerError::AuthorizationDenied(_))
        ));
        assert!(matches!(
            fixture
                .service
                .prepare_dispatch(&registration, &request, 100),
            Err(BrokerError::AuthorizationDenied(_))
        ));
        assert_eq!(
            fixture.live_authority_calls.load(Ordering::SeqCst),
            0,
            "durable failure must replay before live liveness or revocation checks"
        );
        assert_eq!(
            fixture.resolver_calls.load(Ordering::SeqCst),
            0,
            "durable failure must replay before DNS or dispatch preparation"
        );
        assert!(fixture
            .attempts
            .load_attempt(&registration.ids.attempt_id)
            .test_expect("load absent post-failure attempt")
            .is_none());
        assert!(fixture
            .service
            .retained_prepared_dispatches()
            .test_expect("retained dispatch lock")
            .is_empty());
    }

    #[test]
    fn failure_receipt_with_durable_attempt_uses_persisted_binding_and_monotonic_time() {
        let fixture = fixture(1, false, false);
        let (request, trusted) = execution(&fixture, 42, 1);
        let request_digest = broker_request_digest(&request).test_expect("request digest");
        let expected_ids = derive_attempt_ids(
            &request.capability.body.capability_id,
            &request.invocation_id,
            &request.proof.body.nonce,
            &request_digest,
        )
        .test_expect("attempt ids");
        let prepared_ids = register_prepared_execution(&fixture, &request, &trusted, 30);
        fixture
            .authority
            .set_hold_state(&prepared_ids.hold_id, ExecutionHoldState::Denied);

        let failure = fixture
            .service
            .persist_admission_failure(
                &request,
                5,
                &BrokerError::AuthorizationDenied("injected registered denial".to_string()),
            )
            .test_expect("registered failure receipt");
        let body = &failure.receipt.body;

        assert_eq!(body.issued_at_unix_seconds, 30);
        assert!(body.issued_at_unix_seconds >= request.proof.body.issued_at_unix_seconds);
        assert_eq!(body.stage, BrokerFailureStage::Hold);
        assert_eq!(body.outcome, BrokerFailureOutcome::Denied);
        assert_eq!(
            body.dispatch_knowledge,
            BrokerDispatchKnowledge::NotCommitted
        );
        assert_eq!(body.request_digest, request_digest);
        assert_eq!(
            body.attempt_id.as_deref(),
            Some(expected_ids.attempt_id.as_str())
        );
        assert_eq!(
            body.invocation_id.as_deref(),
            Some(request.invocation_id.as_str())
        );
        assert_eq!(body.hold_id.as_deref(), Some(expected_ids.hold_id.as_str()));
        assert_eq!(
            body.parent_capability_id.as_deref(),
            Some(request.capability.body.parent_capability_id.as_str())
        );
        assert_eq!(
            body.broker_capability_id.as_deref(),
            Some(request.capability.body.capability_id.as_str())
        );
        assert_eq!(
            fixture
                .attempts
                .load_attempt(&expected_ids.attempt_id)
                .test_expect("load terminalized attempt")
                .test_expect("terminalized attempt exists")
                .state,
            AttemptState::Failed
        );
        assert!(fixture
            .service
            .retained_prepared_dispatches()
            .test_expect("retained dispatch lock")
            .is_empty());
    }

    #[test]
    fn failure_terminal_and_concurrent_execution_cannot_cross_capture() {
        let attempts = Arc::new(SqliteAttemptStore::open_in_memory().test_expect("attempt store"));
        let receipts = Arc::new(Mutex::new(Vec::new()));
        let failure_persist_entered = Arc::new(Barrier::new(2));
        let failure_persist_release = Arc::new(Barrier::new(2));
        let receipt_sink = Arc::new(InspectingReceiptSink {
            canary: b"unique-service-credential-canary".to_vec(),
            receipts: Arc::clone(&receipts),
            failures: Mutex::new(BTreeMap::new()),
            completed: Mutex::new(BTreeMap::new()),
            failure_persist_entered: Some(Arc::clone(&failure_persist_entered)),
            failure_persist_release: Some(Arc::clone(&failure_persist_release)),
            fail_completed: false,
        });
        let fixture = fixture_with_stores(
            1,
            false,
            false,
            Arc::clone(&attempts),
            receipt_sink,
            Arc::clone(&receipts),
        );
        let (request, trusted) = execution(&fixture, 43, 1);
        let request_digest = broker_request_digest(&request).test_expect("request digest");
        let ids = derive_attempt_ids(
            &request.capability.body.capability_id,
            &request.invocation_id,
            &request.proof.body.nonce,
            &request_digest,
        )
        .test_expect("attempt ids");
        let prepared_ids = register_prepared_execution(&fixture, &request, &trusted, 30);
        fixture
            .authority
            .set_hold_state(&prepared_ids.hold_id, ExecutionHoldState::Denied);

        let failure_service = Arc::clone(&fixture.service);
        let failure_request = request.clone();
        let failure_worker = thread::spawn(move || {
            failure_service.persist_admission_failure(
                &failure_request,
                31,
                &BrokerError::AuthorityUnavailable("injected admission timeout".to_string()),
            )
        });
        failure_persist_entered.wait();
        let gate_index = attempt_operation_gate_index(
            &failure_receipt_key_digest(&request).test_expect("failure receipt key digest"),
        )
        .test_expect("attempt operation gate index");
        assert!(fixture.service.attempt_operation_gates[gate_index]
            .try_lock()
            .is_err());

        let contender_started = Arc::new(Barrier::new(2));
        let execution_service = Arc::clone(&fixture.service);
        let execution_request = request.clone();
        let execution_trusted = trusted.clone();
        let execution_started = Arc::clone(&contender_started);
        let execution_worker = thread::spawn(move || {
            execution_started.wait();
            execution_service.execute_evidenced(&execution_request, &execution_trusted, 32)
        });
        contender_started.wait();
        failure_persist_release.wait();

        let failure = failure_worker
            .join()
            .test_expect("join failure worker")
            .test_expect("persist terminal failure");
        let replayed = execution_worker
            .join()
            .test_expect("join execution worker")
            .test_expect("replay terminal failure");
        assert_eq!(replayed, BrokerExecuteOutcome::Failure(Box::new(failure)));
        assert_eq!(
            attempts
                .load_attempt(&ids.attempt_id)
                .test_expect("load raced attempt")
                .test_expect("raced attempt exists")
                .state,
            AttemptState::Failed
        );
        assert!(fixture
            .observed_authorizations
            .lock()
            .test_expect("observed authorization lock")
            .is_empty());
        assert!(fixture
            .service
            .retained_prepared_dispatches()
            .test_expect("retained dispatch lock")
            .is_empty());
        assert_eq!(receipts.lock().test_expect("receipt lock").len(), 1);
    }

    #[test]
    fn post_capture_admission_failure_is_refused_without_losing_recovery_state() {
        let fixture = fixture(1, false, false);
        let (request, trusted) = execution(&fixture, 44, 1);
        register_execution(&fixture, &request, &trusted, 30);
        let (ids, evidence) = captured_attempt_evidence(&fixture, &request, &trusted);
        fixture
            .attempts
            .transition(
                &ids.attempt_id,
                AttemptState::Prepared,
                AttemptState::Captured,
                &evidence,
                31,
            )
            .test_expect("journal captured attempt");

        assert!(matches!(
            fixture.service.persist_admission_failure(
                &request,
                32,
                &BrokerError::AuthorityUnavailable("late authority timeout".to_string()),
            ),
            Err(BrokerError::AuthorityUnavailable(_))
        ));
        assert_eq!(
            fixture
                .attempts
                .load_attempt(&ids.attempt_id)
                .test_expect("load captured attempt")
                .test_expect("captured attempt exists")
                .state,
            AttemptState::Captured
        );
        assert!(fixture
            .receipts
            .lock()
            .test_expect("receipt lock")
            .is_empty());
    }

    #[test]
    fn held_or_transient_admission_failure_remains_nonterminal_and_retryable() {
        let fixture = fixture(1, false, false);
        let (request, trusted) = execution(&fixture, 46, 1);
        let ids = register_prepared_execution(&fixture, &request, &trusted, 30);

        assert!(matches!(
            fixture.service.persist_admission_failure(
                &request,
                31,
                &BrokerError::AuthorityUnavailable("transient admission timeout".to_string()),
            ),
            Err(BrokerError::AuthorityUnavailable(_))
        ));
        assert_eq!(
            fixture
                .attempts
                .load_attempt(&ids.attempt_id)
                .test_expect("load retryable attempt")
                .test_expect("retryable attempt exists")
                .state,
            AttemptState::Prepared
        );
        assert!(fixture
            .receipts
            .lock()
            .test_expect("receipt lock")
            .is_empty());

        assert!(fixture.service.execute(&request, &trusted, 33).is_ok());
    }
