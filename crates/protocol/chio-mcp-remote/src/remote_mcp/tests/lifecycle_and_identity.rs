#[test]
fn remote_session_new_preserves_ready_lifecycle_on_restore() {
    let (input_tx, _input_rx) = mpsc::channel::<Value>();
    let (event_tx, _) = broadcast::channel::<RemoteSessionEvent>(8);
    let retained_notification_events =
        Arc::new(StdMutex::new(VecDeque::<RetainedRemoteSessionEvent>::new()));
    let next_event_id = Arc::new(AtomicU64::new(0));
    let lifecycle_policy = SessionLifecyclePolicy {
        idle_expiry_millis: 5_000,
        drain_grace_millis: 1_000,
        reaper_interval_millis: 100,
        tombstone_retention_millis: 10_000,
    };
    let session = RemoteSession::new(RemoteSessionInit {
        session_id: "session-restore".to_string(),
        kernel_session_id: SessionId::new("kernel-session-restore"),
        agent_id: "agent-restore".to_string(),
        capabilities: Vec::new(),
        issued_capabilities: Vec::new(),
        auth_context: SessionAuthContext::streamable_http_static_bearer(
            "agent-restore",
            "restore-token",
            None,
        ),
        auth_mode_fingerprint: "auth-contract-v1".to_string(),
        policy_fingerprint: "policy-contract-v1".to_string(),
        hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
        capability_issuance_binding: sample_capability_issuance_binding(),
        lifecycle_policy: lifecycle_policy.clone(),
        protocol_version: None,
        peer_capabilities: Some(PeerCapabilities::default()),
        initialize_params: Some(json!({})),
        lifecycle_snapshot: Some(RemoteSessionLifecycleSnapshot {
            state: RemoteSessionState::Ready,
            created_at: 11,
            last_seen_at: 12,
            idle_expires_at: 13,
            drain_deadline_at: Some(14),
        }),
        input_tx,
        event_tx,
        retained_notification_events,
        next_event_id,
        session_db_path: None,
        session_store_lease: None,
        resume_hmac_keyring: Some(test_resume_hmac_keyring()),
        resume_generation: 9,
        upstream_transport: Arc::new(SharedUpstreamNotificationTap {
            queue: Arc::new(StdMutex::new(VecDeque::new())),
        }),
    });

    let lifecycle = session.lifecycle_snapshot();
    assert_eq!(lifecycle.state, RemoteSessionState::Ready);
    assert_eq!(lifecycle.created_at, 11);
    assert_eq!(lifecycle.last_seen_at, 12);
    assert_eq!(lifecycle.idle_expires_at, 13);
    assert_eq!(lifecycle.drain_deadline_at, None);
    let record = session
        .resume_record()
        .expect("ready restored session remains resumable");
    assert_eq!(
        record.kernel_session_id,
        SessionId::new("kernel-session-restore")
    );
    assert_eq!(record.resume_generation, 10);
    assert_eq!(record.resume_integrity.key_id, "resume-test-key");
    assert_eq!(record.resume_integrity.key_version, 1);
}
#[tokio::test]
#[cfg(target_os = "linux")]
async fn terminalization_failure_removes_live_dispatch_authority() {
    let directory = tempfile::tempdir().expect("create shutdown-failure terminal directory");
    let path = directory.path().join("sessions.sqlite3");
    #[cfg(unix)]
    let session_store_lease = Arc::new(
        RemoteSessionStoreLifecycleLease::acquire(&path)
            .expect("acquire shutdown-failure session store lease"),
    );
    let keyring = test_resume_hmac_keyring();
    let shutdown_count = Arc::new(AtomicU64::new(0));
    let transport = Arc::new(ShutdownProbeTransport {
        shutdown_count: Arc::clone(&shutdown_count),
        failure: Some("durable terminal receipt append failed"),
    });
    let upstream_transport: Arc<dyn McpTransport> = transport;
    let mut session = terminal_test_session("terminal-failure", upstream_transport);
    let session_mut = Arc::get_mut(&mut session).expect("session is uniquely owned during setup");
    session_mut.session_db_path = Some(path.clone());
    #[cfg(unix)]
    {
        session_mut.session_store_lease = Some(Arc::clone(&session_store_lease));
    }
    session_mut.resume_hmac_keyring = Some(Arc::clone(&keyring));
    let active = session
        .resume_record()
        .expect("create shutdown-failure active resume record");
    persist_active_session_record(&path, &active, &keyring)
        .expect("persist shutdown-failure active resume record");
    let ledger = RemoteSessionLedger::new(
        SessionLifecyclePolicy {
            idle_expiry_millis: 5_000,
            drain_grace_millis: 1_000,
            reaper_interval_millis: 100,
            tombstone_retention_millis: 10_000,
        },
        Some(path.clone()),
        Some(Arc::clone(&keyring)),
    )
    .expect("create session ledger");
    ledger.insert_active(Arc::clone(&session)).await;

    let error = ledger
        .mark_closed(&session)
        .await
        .expect_err("terminal receipt failure must reject terminalization");

    assert!(error
        .to_string()
        .contains("durable terminal receipt append failed"));
    assert_eq!(
        session.lifecycle_snapshot().state,
        RemoteSessionState::Closed
    );
    assert_eq!(shutdown_count.load(Ordering::SeqCst), 1);
    assert!(matches!(
        ledger.lookup("terminal-failure").await,
        Some(RemoteSessionEntry::Terminal(_))
    ));
    assert!(
        load_active_session_records(&path, &keyring)
            .expect("load active rows after shutdown failure")
            .records
            .is_empty()
    );
    assert!(load_terminal_session_records(&path, &keyring)
        .expect("load finalized tombstone after shutdown failure")
        .contains_key("terminal-failure"));
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn durable_terminalization_failure_after_shutdown_retains_resume_fence() {
    let directory = tempfile::tempdir().expect("create durable terminal directory");
    let path = directory.path().join("sessions.sqlite3");
    #[cfg(unix)]
    let session_store_lease = Arc::new(
        RemoteSessionStoreLifecycleLease::acquire(&path)
            .expect("acquire durable-terminal session store lease"),
    );
    let keyring = test_resume_hmac_keyring();
    let shutdown_count = Arc::new(AtomicU64::new(0));
    let transport = Arc::new(ShutdownProbeTransport {
        shutdown_count: Arc::clone(&shutdown_count),
        failure: None,
    });
    let upstream_transport: Arc<dyn McpTransport> = transport;
    let mut session = terminal_test_session("terminal-finalize-failure", upstream_transport);
    let session_mut = Arc::get_mut(&mut session).expect("session is uniquely owned during setup");
    session_mut.session_db_path = Some(path.clone());
    #[cfg(unix)]
    {
        session_mut.session_store_lease = Some(Arc::clone(&session_store_lease));
    }
    session_mut.resume_hmac_keyring = Some(Arc::clone(&keyring));
    let active = session
        .resume_record()
        .expect("create durable active resume record");
    persist_active_session_record(&path, &active, &keyring)
        .expect("persist durable active resume record");

    let ledger = RemoteSessionLedger::new(
        SessionLifecyclePolicy {
            idle_expiry_millis: 5_000,
            drain_grace_millis: 1_000,
            reaper_interval_millis: 100,
            tombstone_retention_millis: 10_000,
        },
        Some(path.clone()),
        Some(Arc::clone(&keyring)),
    )
    .expect("create durable session ledger");
    ledger.insert_active(Arc::clone(&session)).await;
    let conn = open_session_state_db(&path).expect("open durable terminal DB");
    conn.execute_batch(&format!(
        "CREATE TRIGGER fail_terminal_tombstone_insert
         BEFORE INSERT ON {table}
         BEGIN SELECT RAISE(ABORT, 'injected tombstone finalization failure'); END;",
        table = SESSION_TOMBSTONE_TABLE,
    ))
    .expect("install tombstone finalization failure trigger");
    drop(conn);

    let error = ledger
        .mark_closed(&session)
        .await
        .expect_err("injected tombstone finalization failure must propagate");
    assert!(error
        .to_string()
        .contains("injected tombstone finalization failure"));
    assert_eq!(shutdown_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        session.lifecycle_snapshot().state,
        RemoteSessionState::Closed
    );
    assert!(matches!(
        ledger.lookup("terminal-finalize-failure").await,
        Some(RemoteSessionEntry::Terminal(_))
    ));

    let conn = open_session_state_db(&path).expect("reopen durable terminal DB");
    let active_count: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {table}", table = SESSION_ACTIVE_TABLE),
            [],
            |row| row.get(0),
        )
        .expect("count active rows after shutdown boundary");
    let tombstone_count: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {table}", table = SESSION_TOMBSTONE_TABLE),
            [],
            |row| row.get(0),
        )
        .expect("count tombstones after shutdown boundary");
    let fence_count: i64 = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM {table}",
                table = SESSION_TERMINAL_FENCE_TABLE
            ),
            [],
            |row| row.get(0),
        )
        .expect("count fences after shutdown boundary");
    assert_eq!((active_count, tombstone_count, fence_count), (0, 0, 1));
    conn.execute(
        &format!(
            "INSERT INTO {table} (session_id, updated_at, record_json) VALUES (?1, ?2, ?3)",
            table = SESSION_ACTIVE_TABLE,
        ),
        params![
            active.session_id.as_str(),
            session_now_millis() as i64,
            serde_json::to_string(&active).expect("serialize replayed active record"),
        ],
    )
    .expect("inject active replay after shutdown boundary");
    drop(conn);

    let loaded = load_active_session_records(&path, &keyring)
        .expect("load active rows after shutdown boundary");
    assert!(loaded.records.is_empty());
    assert_eq!(loaded.invalid_session_ids, vec![active.session_id]);
    assert!(
        load_terminal_session_records(&path, &keyring)
            .expect("load terminal diagnostics after finalization failure")
            .is_empty()
    );
}

#[tokio::test]
async fn shutdown_all_active_persists_terminal_state_once() {
    let shutdown_count = Arc::new(AtomicU64::new(0));
    let transport = Arc::new(ShutdownProbeTransport {
        shutdown_count: Arc::clone(&shutdown_count),
        failure: None,
    });
    let upstream_transport: Arc<dyn McpTransport> = transport;
    let session = terminal_test_session("terminal-success", upstream_transport);
    let ledger = RemoteSessionLedger::new(
        SessionLifecyclePolicy {
            idle_expiry_millis: 5_000,
            drain_grace_millis: 1_000,
            reaper_interval_millis: 100,
            tombstone_retention_millis: 10_000,
        },
        None,
        None,
    )
    .expect("create session ledger");
    ledger.insert_active(session).await;

    ledger
        .shutdown_all_active()
        .await
        .expect("terminalize all active sessions");

    assert_eq!(shutdown_count.load(Ordering::SeqCst), 1);
    let Some(RemoteSessionEntry::Terminal(record)) = ledger.lookup("terminal-success").await else {
        panic!("terminalized session must resolve to its tombstone");
    };
    assert_eq!(record.lifecycle.state, RemoteSessionState::Closed);
    ledger
        .shutdown_all_active()
        .await
        .expect("repeated global shutdown is idempotent");
    assert_eq!(shutdown_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_terminalization_shuts_down_upstream_once() {
    let shutdown_count = Arc::new(AtomicU64::new(0));
    let transport = Arc::new(ShutdownProbeTransport {
        shutdown_count: Arc::clone(&shutdown_count),
        failure: None,
    });
    let upstream_transport: Arc<dyn McpTransport> = transport;
    let session = terminal_test_session("terminal-race", upstream_transport);
    let ledger = RemoteSessionLedger::new(
        SessionLifecyclePolicy {
            idle_expiry_millis: 5_000,
            drain_grace_millis: 1_000,
            reaper_interval_millis: 100,
            tombstone_retention_millis: 10_000,
        },
        None,
        None,
    )
    .expect("create session ledger");
    ledger.insert_active(Arc::clone(&session)).await;

    let (first, second) = tokio::join!(ledger.mark_closed(&session), ledger.mark_closed(&session));

    first.expect("first terminalization succeeds");
    second.expect("concurrent terminalization observes the committed state");
    assert_eq!(shutdown_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        session.lifecycle_snapshot().state,
        RemoteSessionState::Closed
    );
}

#[test]
fn chio_oauth_discovery_profile_metadata_advertises_sender_constraints() {
    let metadata =
        build_chio_oauth_authorization_profile_metadata().expect("build Chio auth profile");
    let profile: ChioOAuthAuthorizationProfile =
        serde_json::from_value(metadata.clone()).expect("parse Chio auth profile");
    assert_eq!(profile.id, CHIO_OAUTH_AUTHORIZATION_PROFILE_ID);
    assert_eq!(profile.schema, CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA);
    assert_eq!(
        profile.sender_constraints.subject_binding,
        CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT
    );
    assert!(profile
        .sender_constraints
        .proof_types_supported
        .iter()
        .any(|proof| proof == CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP));
    assert!(profile
        .sender_constraints
        .proof_types_supported
        .iter()
        .any(|proof| proof == chio_kernel::operator_report::CHIO_OAUTH_SENDER_PROOF_CHIO_MTLS));
    assert!(profile.sender_constraints.proof_types_supported.iter().any(
        |proof| proof == chio_kernel::operator_report::CHIO_OAUTH_SENDER_PROOF_CHIO_ATTESTATION
    ));
    assert_eq!(
        profile
            .request_time_contract
            .authorization_details_parameter
            .as_str(),
        CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_PARAMETER
    );
    assert!(
        profile
            .resource_binding
            .request_resource_must_match_protected_resource
    );
    assert!(
        !profile
            .artifact_boundary
            .reviewer_evidence_runtime_admission_supported
    );
    assert_eq!(metadata["discoveryInformationalOnly"].as_bool(), Some(true));
}

#[test]
fn chio_oauth_discovery_validation_rejects_profile_mismatch() {
    let protected_resource_metadata = ProtectedResourceMetadata {
        resource: "https://edge.example/mcp".to_string(),
        resource_metadata_url: "https://edge.example/.well-known/oauth-protected-resource/mcp"
            .to_string(),
        authorization_servers: vec!["https://edge.example/oauth".to_string()],
        scopes_supported: vec!["mcp:invoke".to_string()],
        chio_authorization_profile: build_chio_oauth_authorization_profile_metadata()
            .expect("build protected Chio auth profile"),
    };
    let authorization_server_metadata = AuthorizationServerMetadata {
        metadata_path: "/.well-known/oauth-authorization-server/oauth".to_string(),
        document: json!({
            "issuer": "https://edge.example/oauth",
            "chio_authorization_profile": {
                "schema": CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA,
                "id": "mismatched-profile",
                "authoritativeSource": "governed_receipt_projection",
                "authorizationDetailTypes": ["chio_governed_tool"],
                "transactionContextFields": ["intentId", "intentHash"],
                "senderConstraints": {
                    "schema": "chio.oauth.sender-constraint.v1",
                    "subjectBinding": CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT,
                    "proofTypesSupported": [CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP],
                    "proofRequiredWhen": "matchedGrant.dpopRequired == true",
                    "runtimeAssuranceBindingFields": ["runtimeAssuranceTier"],
                    "delegatedCallChainField": "callChain",
                    "unsupportedSenderShapesFailClosed": true
                },
                "unsupportedShapesFailClosed": true
            }
        }),
    };

    let error = validate_chio_oauth_discovery_metadata_pair(
        &protected_resource_metadata,
        &authorization_server_metadata,
    )
    .expect_err("mismatched discovery metadata should fail");
    assert!(
        error.to_string().contains("Chio authorization profile id"),
        "unexpected error: {error}"
    );
}

#[test]
fn local_authorization_server_issues_unique_codes_for_same_second_approvals() {
    for _ in 0..8 {
        let server = test_local_authorization_server();
        let first = authorization_code_from_redirect(
            server
                .approve_authorization(test_authorization_approval_form())
                .expect("first approval succeeds"),
        );
        let first_expires_at = stored_authorization_code_expiry(&server, &first);
        let second = authorization_code_from_redirect(
            server
                .approve_authorization(test_authorization_approval_form())
                .expect("second approval succeeds"),
        );
        let second_expires_at = stored_authorization_code_expiry(&server, &second);

        if first_expires_at == second_expires_at {
            assert_ne!(first, second);
            return;
        }
    }

    panic!("test could not issue two authorization codes in the same second");
}

#[test]
fn remote_session_auth_context_uses_static_bearer_fingerprint_and_origin() {
    let mut headers = HeaderMap::new();
    headers.insert(ORIGIN, HeaderValue::from_static("http://localhost:3000"));

    let auth_context = build_static_bearer_session_auth_context(&headers, "test-token");
    assert_eq!(auth_context.transport, SessionTransport::StreamableHttp);
    assert_eq!(
        auth_context.origin.as_deref(),
        Some("http://localhost:3000")
    );
    assert!(auth_context.is_authenticated());

    match &auth_context.method {
        SessionAuthMethod::StaticBearer {
            principal,
            token_fingerprint,
        } => {
            assert_eq!(token_fingerprint, &sha256_hex(b"test-token"));
            assert!(principal.starts_with("static-bearer:"));
        }
        other => panic!("unexpected auth method: {other:?}"),
    }
}

#[test]
fn jwt_bearer_verifier_builds_oauth_session_auth_context() {
    let keypair = Keypair::generate();
    let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
    let token = sign_jwt(
        &keypair,
        &json!({
            "iss": "https://issuer.example",
            "sub": "user-123",
            "aud": "chio-mcp",
            "scope": "tools.read tools.write",
            "client_id": "client-abc",
            "tid": "tenant-123",
            "org_id": "org-789",
            "groups": ["ops", "eng"],
            "roles": ["reviewer", "operator"],
            "exp": unix_now() + 300,
        }),
    );
    let verifier = JwtBearerVerifier {
        key_source: JwtVerificationKeySource::Static(keypair.public_key()),
        issuer: Some("https://issuer.example".to_string()),
        audience: Some("chio-mcp".to_string()),
        required_scopes: vec![],
        provider_profile: JwtProviderProfile::Generic,
        enterprise_provider_registry: None,
        sender_dpop_nonce_store,
        sender_dpop_config,
    };

    let auth_context = verifier
        .authenticate_token(
            &token,
            &empty_header_map(),
            Some("http://localhost:3000".to_string()),
            None,
            "POST",
            "chio-mcp",
        )
        .unwrap();
    assert_eq!(auth_context.transport, SessionTransport::StreamableHttp);
    assert_eq!(
        auth_context.origin.as_deref(),
        Some("http://localhost:3000")
    );

    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            principal,
            issuer,
            subject,
            audience,
            scopes,
            federated_claims,
            enterprise_identity,
            token_fingerprint,
        } => {
            assert_eq!(
                principal.as_deref(),
                Some("oidc:https://issuer.example#sub:user-123")
            );
            assert_eq!(issuer.as_deref(), Some("https://issuer.example"));
            assert_eq!(subject.as_deref(), Some("user-123"));
            assert_eq!(audience.as_deref(), Some("chio-mcp"));
            assert_eq!(
                scopes,
                &vec!["tools.read".to_string(), "tools.write".to_string()]
            );
            assert_eq!(federated_claims.client_id.as_deref(), Some("client-abc"));
            assert_eq!(federated_claims.tenant_id.as_deref(), Some("tenant-123"));
            assert_eq!(federated_claims.organization_id.as_deref(), Some("org-789"));
            assert_eq!(
                federated_claims.groups,
                vec!["eng".to_string(), "ops".to_string()]
            );
            assert_eq!(
                federated_claims.roles,
                vec!["operator".to_string(), "reviewer".to_string()]
            );
            assert_eq!(
                token_fingerprint.as_deref(),
                Some(sha256_hex(token.as_bytes()).as_str())
            );
            let enterprise_identity = enterprise_identity
                .as_ref()
                .expect("enterprise identity should be populated");
            assert_eq!(enterprise_identity.provider_id, "https://issuer.example");
            assert_eq!(enterprise_identity.provider_record_id, None);
            assert_eq!(enterprise_identity.provider_kind, "oidc_jwks");
            assert_eq!(
                enterprise_identity.federation_method,
                EnterpriseFederationMethod::Jwt
            );
            assert_eq!(
                enterprise_identity.principal,
                "oidc:https://issuer.example#sub:user-123"
            );
            assert_eq!(
                enterprise_identity.subject_key,
                derive_enterprise_subject_key(
                    "https://issuer.example",
                    "oidc:https://issuer.example#sub:user-123",
                )
            );
            assert_eq!(enterprise_identity.tenant_id.as_deref(), Some("tenant-123"));
            assert_eq!(
                enterprise_identity.organization_id.as_deref(),
                Some("org-789")
            );
            assert_eq!(
                enterprise_identity.attribute_sources.get("principal"),
                Some(&"sub".to_string())
            );
            assert_eq!(
                enterprise_identity.attribute_sources.get("groups"),
                Some(&"groups".to_string())
            );
            assert_eq!(
                enterprise_identity.attribute_sources.get("roles"),
                Some(&"roles".to_string())
            );
        }
        other => panic!("unexpected auth method: {other:?}"),
    }
}
