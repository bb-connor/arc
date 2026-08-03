fn test_local_authorization_server() -> LocalAuthorizationServer {
    let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
    LocalAuthorizationServer {
        signing_key: Keypair::generate(),
        issuer: "https://auth.example".to_string(),
        default_audience: "https://edge.example/mcp".to_string(),
        supported_scopes: vec!["mcp:invoke".to_string()],
        subject: "operator".to_string(),
        code_ttl_secs: 300,
        access_token_ttl_secs: 600,
        codes: Arc::new(StdMutex::new(HashMap::new())),
        sender_dpop_nonce_store,
        sender_dpop_config,
    }
}

fn test_authorization_approval_form() -> AuthorizationApprovalForm {
    AuthorizationApprovalForm {
        response_type: "code".to_string(),
        client_id: "client-abc".to_string(),
        redirect_uri: "https://client.example/callback".to_string(),
        state: Some("state-1".to_string()),
        scope: Some("mcp:invoke".to_string()),
        resource: Some("https://edge.example/mcp".to_string()),
        authorization_details: None,
        chio_transaction_context: None,
        code_challenge: "challenge".to_string(),
        code_challenge_method: "S256".to_string(),
        chio_sender_dpop_public_key: None,
        chio_sender_mtls_thumbprint_sha256: None,
        chio_sender_attestation_sha256: None,
        decision: "approve".to_string(),
    }
}

fn authorization_code_from_redirect(redirect: Redirect) -> String {
    let response = redirect.into_response();
    let location = response
        .headers()
        .get(axum::http::header::LOCATION)
        .expect("redirect has location")
        .to_str()
        .expect("location is valid header text");
    Url::parse(location)
        .expect("parse redirect location")
        .query_pairs()
        .find_map(|(key, value)| (key == "code").then(|| value.to_string()))
        .expect("redirect includes authorization code")
}

fn stored_authorization_code_expiry(server: &LocalAuthorizationServer, code: &str) -> u64 {
    let guard = server.codes.lock().expect("lock authorization codes");
    guard
        .get(code)
        .expect("authorization code stored")
        .expires_at
}

fn sample_resume_record() -> RemoteSessionResumeRecord {
    let keyring = test_resume_hmac_keyring();
    let mut record = RemoteSessionResumeRecord {
        session_id: "session-valid".to_string(),
        kernel_session_id: SessionId::new("kernel-session-valid"),
        agent_id: "agent-valid".to_string(),
        auth_context: SessionAuthContext::streamable_http_oauth_bearer(
            Some("principal-valid".to_string()),
            Some("https://issuer.example".to_string()),
            Some("subject-valid".to_string()),
            Some("audience-valid".to_string()),
            vec!["mcp:invoke".to_string(), "mcp:read".to_string()],
            Some("token-fingerprint".to_string()),
            None,
        ),
        auth_mode_fingerprint: Some("auth-contract-v1".to_string()),
        policy_fingerprint: Some("policy-contract-v1".to_string()),
        hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
        capability_issuance_binding: sample_capability_issuance_binding(),
        lifecycle: RemoteSessionLifecycleSnapshot {
            state: RemoteSessionState::Ready,
            created_at: 10,
            last_seen_at: 11,
            idle_expires_at: 12,
            drain_deadline_at: None,
        },
        protocol_version: Some("2025-06-18".to_string()),
        peer_capabilities: PeerCapabilities::default(),
        initialize_params: json!({}),
        issued_capabilities: Vec::new(),
        resume_generation: 1,
        resume_integrity: keyring.empty_tag_for_current(),
    };
    record.resume_integrity.tag = compute_resume_record_integrity_tag(&keyring.current, &record)
        .expect("sign sample resume record");
    record
}

fn signed_resume_record(
    session_id: &str,
    generation: u64,
    keyring: &RemoteSessionHmacKeyring,
) -> RemoteSessionResumeRecord {
    let mut record = sample_resume_record();
    record.session_id = session_id.to_string();
    record.kernel_session_id = SessionId::new(format!("kernel-{session_id}"));
    record.resume_generation = generation;
    record.resume_integrity = keyring.empty_tag_for_current();
    record.resume_integrity.tag = compute_resume_record_integrity_tag(&keyring.current, &record)
        .expect("sign resume record fixture");
    record
}

#[cfg(target_os = "linux")]
fn terminal_diagnostic_record(
    session_id: &str,
    terminal_at: u64,
) -> RemoteSessionDiagnosticRecord {
    RemoteSessionDiagnosticRecord {
        session_id: session_id.to_string(),
        auth_context: SessionAuthContext::streamable_http_static_bearer(
            format!("agent-{session_id}"),
            "terminal-token-fingerprint",
            None,
        ),
        capabilities: Vec::new(),
        lifecycle: RemoteSessionLifecycleSnapshot {
            state: RemoteSessionState::Deleted,
            created_at: 10,
            last_seen_at: terminal_at,
            idle_expires_at: terminal_at,
            drain_deadline_at: None,
        },
        protocol_version: Some("2025-06-18".to_string()),
        ownership: RemoteSessionOwnershipSnapshot::default(),
        terminal_at,
    }
}

#[test]
fn shared_hosted_owner_notification_fanout_replays_to_all_live_taps() {
    let subscriber_a = Arc::new(StdMutex::new(VecDeque::<Value>::new()));
    let subscriber_b = Arc::new(StdMutex::new(VecDeque::<Value>::new()));
    let stats = SharedUpstreamNotificationStats::default();
    let subscribers: NotificationSubscriberList = Arc::new(StdMutex::new(vec![
        Arc::downgrade(&subscriber_a),
        Arc::downgrade(&subscriber_b),
    ]));

    fan_out_shared_upstream_notifications(
        &subscribers,
        &stats,
        vec![json!({
            "jsonrpc": "2.0",
            "method": "notifications/resources/list_changed"
        })],
    );

    let subscriber_a = subscriber_a.lock().expect("lock subscriber a");
    let subscriber_b = subscriber_b.lock().expect("lock subscriber b");
    assert_eq!(subscriber_a.len(), 1);
    assert_eq!(subscriber_b.len(), 1);
    assert_eq!(
        subscriber_a[0]["method"].as_str(),
        Some("notifications/resources/list_changed")
    );
    assert_eq!(subscriber_a.as_slices(), subscriber_b.as_slices());
    assert_eq!(stats.fanout_batches.load(Ordering::Relaxed), 1);
    assert_eq!(stats.fanout_notifications.load(Ordering::Relaxed), 1);
    assert_eq!(stats.fanout_targets.load(Ordering::Relaxed), 2);
}

#[test]
fn shared_hosted_owner_notification_fanout_tracks_pruned_dead_subscribers() {
    let stats = SharedUpstreamNotificationStats::default();
    let live = Arc::new(StdMutex::new(VecDeque::<Value>::new()));
    let dropped = Arc::new(StdMutex::new(VecDeque::<Value>::new()));
    let subscribers: NotificationSubscriberList = Arc::new(StdMutex::new(vec![
        Arc::downgrade(&live),
        Arc::downgrade(&dropped),
    ]));
    drop(dropped);

    fan_out_shared_upstream_notifications(
        &subscribers,
        &stats,
        vec![json!({
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed"
        })],
    );

    assert_eq!(stats.pruned_subscribers.load(Ordering::Relaxed), 1);
    assert_eq!(stats.fanout_targets.load(Ordering::Relaxed), 1);
}

#[test]
fn validate_resume_record_integrity_rejects_tampered_auth_context() {
    let keyring = test_resume_hmac_keyring();
    let mut record = sample_resume_record();
    if let SessionAuthMethod::OAuthBearer { scopes, .. } = &mut record.auth_context.method {
        scopes.push("mcp:admin".to_string());
    } else {
        panic!("expected OAuth bearer auth context");
    }

    let error = validate_resume_record_integrity_with_keyring(
        &keyring,
        &record,
        session_now_millis(),
    )
        .expect_err("tampered auth context should fail integrity validation");
    assert!(error
        .to_string()
        .contains("failed resumable integrity validation"));
}

#[test]
fn resume_integrity_binds_authoritative_kernel_session_id() {
    let keyring = test_resume_hmac_keyring();
    let mut record = sample_resume_record();
    record.kernel_session_id = SessionId::new("different-kernel-session");

    let error = validate_resume_record_integrity_with_keyring(
        &keyring,
        &record,
        session_now_millis(),
    )
        .expect_err("tampered kernel session id should fail integrity validation");
    assert!(error
        .to_string()
        .contains("failed resumable integrity validation"));
}

#[test]
fn resume_integrity_binds_capability_issuance_context() {
    let keyring = test_resume_hmac_keyring();
    let mut record = sample_resume_record();
    record.capability_issuance_binding.context_generation += 1;

    let error = validate_resume_record_integrity_with_keyring(
        &keyring,
        &record,
        session_now_millis(),
    )
        .expect_err("tampered capability issuance context should fail integrity validation");
    assert!(error
        .to_string()
        .contains("failed resumable integrity validation"));
}

#[test]
#[cfg(target_os = "linux")]
fn distinct_servers_cannot_share_one_remote_session_database() {
    let directory = tempfile::tempdir().expect("create session ownership directory");
    let path = directory.path().join("sessions.sqlite3");
    let first_listen: std::net::SocketAddr = "127.0.0.1:41001"
        .parse()
        .expect("parse first server address");
    let second_listen: std::net::SocketAddr = "127.0.0.1:41002"
        .parse()
        .expect("parse second server address");
    assert_ne!(first_listen, second_listen);

    let first = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("first server acquires session database");
    let second = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect_err("second server must not share the session database");
    assert!(second.to_string().contains("already owned"));
    let third = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect_err("a rejected second acquire must not release the first lease");
    assert!(third.to_string().contains("already owned"));
    first.ensure_owned().expect("first server retains ownership");
    drop(first);

    RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("ownership is recoverable after the first server exits");
}

#[test]
#[cfg(target_os = "linux")]
fn remote_session_database_ownership_rejects_link_aliases() {
    let directory = tempfile::tempdir().expect("create session alias directory");
    let path = directory.path().join("sessions.sqlite3");
    let lease = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("acquire original session database");
    drop(lease);

    let hardlink = directory.path().join("sessions-hardlink.sqlite3");
    std::fs::hard_link(&path, &hardlink).expect("create session database hard link");
    assert!(RemoteSessionStoreLifecycleLease::acquire(&path).is_err());
    std::fs::remove_file(&hardlink).expect("remove session database hard link");

    let symlink = directory.path().join("sessions-symlink.sqlite3");
    std::os::unix::fs::symlink(&path, &symlink).expect("create session database symlink");
    assert!(RemoteSessionStoreLifecycleLease::acquire(&symlink).is_err());
}

#[test]
#[cfg(target_os = "linux")]
fn remote_session_database_rejects_path_replacement_after_lease() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().expect("create session replacement directory");
    let path = directory.path().join("sessions.sqlite3");
    let displaced = directory.path().join("sessions-displaced.sqlite3");
    let lease = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("acquire original session database");
    std::fs::rename(&path, &displaced).expect("displace leased session database");
    std::fs::write(&path, []).expect("create replacement session database");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("secure replacement session database");

    assert!(lease.ensure_owned().is_err());
    assert!(open_session_state_db(&path).is_err());
}

#[test]
#[cfg(target_os = "linux")]
fn remote_session_database_rejects_untrusted_sidecars_before_sqlite_open() {
    let directory = tempfile::tempdir().expect("create session sidecar directory");
    let path = directory.path().join("sessions.sqlite3");
    let _lease = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("acquire session database before sidecar substitution");
    let target = directory.path().join("sidecar-target");
    std::fs::write(&target, []).expect("create sidecar target");
    let wal = PathBuf::from(format!("{}-wal", path.display()));
    std::os::unix::fs::symlink(&target, &wal).expect("substitute WAL sidecar symlink");

    assert!(open_session_state_db(&path).is_err());
}

#[test]
#[cfg(target_os = "linux")]
fn remote_session_database_requires_a_real_lease_even_in_tests() {
    let directory = tempfile::tempdir().expect("create unleased session directory");
    let path = directory.path().join("sessions.sqlite3");

    assert!(open_session_state_db(&path).is_err());
}

#[test]
#[cfg(target_os = "linux")]
fn remote_session_database_rejects_writable_ancestor_directory() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().expect("create untrusted ancestor directory");
    let writable = directory.path().join("writable");
    std::fs::create_dir(&writable).expect("create writable session ancestor");
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777))
        .expect("make session ancestor writable");
    let path = writable.join("sessions.sqlite3");

    assert!(RemoteSessionStoreLifecycleLease::acquire(&path).is_err());
}

#[test]
fn plain_remote_capabilities_install_a_signed_session_context_without_a_broker() {
    let authority_key = Keypair::generate();
    let agent = Keypair::generate();
    let agent_id = agent.public_key().to_hex();
    let mut binding = sample_capability_issuance_binding();
    binding.principal_id = "oauth-subject-remote-session".to_string();
    let kernel_session_id = SessionId::new(binding.security_session_id.clone());
    let capability = restore_incarnation_capability(
        &authority_key,
        &agent.public_key(),
        &binding,
        "cap-plain-remote-bound",
    );
    let resolver = session_core_factory::RemoteBoundSecurityInvocationContextAuthority::new(
        &agent_id,
        &kernel_session_id,
        &binding,
        "restore-incarnation-server",
        std::slice::from_ref(&capability),
    )
    .expect("install plain remote signed-context resolver");
    let operation_context = chio_core::session::OperationContext::new(
        kernel_session_id,
        chio_core::session::RequestId::new("request-plain-remote-bound"),
        agent_id,
    );
    let resolved = chio_kernel::SecurityInvocationContextAuthority::resolve_security_invocation_context(
        &resolver,
        &operation_context,
        &restore_incarnation_operation(capability),
    )
    .expect("resolve plain remote signed context");
    assert_eq!(
        resolved.as_v1().principal_id().as_str(),
        "oauth-subject-remote-session"
    );
    assert_eq!(
        resolved.as_v1().session_id().as_str(),
        binding.security_session_id.as_str()
    );
    assert_eq!(resolved.as_v1().context_generation(), binding.context_generation);
    assert_eq!(
        resolved.as_v1().flow_state_generation(),
        Some(binding.context_generation)
    );

    let mut mutations = Vec::new();
    let mut mutated = binding.clone();
    mutated.tenant_id = "tenant-mutated".to_string();
    mutations.push(mutated);
    let mut mutated = binding.clone();
    mutated.lineage_id = "lineage-mutated".to_string();
    mutations.push(mutated);
    let mut mutated = binding.clone();
    mutated.security_session_id = "security-session-mutated".to_string();
    mutations.push(mutated);
    let mut mutated = binding.clone();
    mutated.principal_id = "principal-mutated".to_string();
    mutations.push(mutated);
    let mut mutated = binding.clone();
    mutated.isolation_epoch_id = "isolation-mutated".to_string();
    mutations.push(mutated);
    let mut mutated = binding.clone();
    mutated.context_generation += 1;
    mutations.push(mutated);

    for (index, mutated) in mutations.into_iter().enumerate() {
        let mutated_capability = restore_incarnation_capability(
            &authority_key,
            &agent.public_key(),
            &mutated,
            &format!("cap-plain-remote-mutated-{index}"),
        );
        assert!(session_core_factory::RemoteBoundSecurityInvocationContextAuthority::new(
            &agent.public_key().to_hex(),
            &SessionId::new(binding.security_session_id.clone()),
            &binding,
            "restore-incarnation-server",
            std::slice::from_ref(&mutated_capability),
        )
        .is_err());
    }
}

#[test]
#[cfg(target_os = "linux")]
fn restore_incarnation_is_persisted_before_launch_and_rotates_capability_context() {
    let directory = tempfile::tempdir().expect("create restore incarnation directory");
    let path = directory.path().join("sessions.sqlite3");
    #[cfg(unix)]
    let _session_store_lease = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("acquire restore incarnation session store lease");
    let keyring = test_resume_hmac_keyring();
    let mut config = test_remote_config();
    config.session_db_path = Some(path.clone());
    let agent_public_key = Keypair::generate().public_key();
    let mut record = sample_resume_record();
    record.session_id = "restore-incarnation".to_string();
    record.kernel_session_id = SessionId::new("restore-incarnation-kernel");
    record.agent_id = agent_public_key.to_hex();
    record.auth_context = SessionAuthContext::streamable_http_static_bearer(
        record.agent_id.clone(),
        "restore-incarnation-token",
        None,
    );
    record.capability_issuance_binding = session_core_factory::derive_capability_issuance_binding(
        &config,
        &record.auth_context,
        &record.kernel_session_id,
        &agent_public_key,
    )
    .expect("derive first restore issuance binding");

    let authority = Keypair::generate();
    let old_capability = restore_incarnation_capability(
        &authority,
        &agent_public_key,
        &record.capability_issuance_binding,
        "cap-old-incarnation",
    );
    let old_capability_id = old_capability.id.clone();
    let old_security_binding = old_capability
        .security_binding()
        .expect("parse old capability security binding")
        .expect("old capability is security bound");
    record.issued_capabilities = vec![old_capability.clone()];
    record.resume_integrity = keyring.empty_tag_for_current();
    record.resume_integrity.tag = compute_resume_record_integrity_tag(&keyring.current, &record)
        .expect("sign first restore incarnation");
    persist_active_session_record(&path, &record, &keyring)
        .expect("persist first restore incarnation");

    let next = session_core_factory::persist_next_restore_incarnation(
        &config,
        &keyring,
        &record,
        &agent_public_key,
    )
    .expect("persist next restore incarnation before launch");
    assert_eq!(next.resume_generation, record.resume_generation + 1);
    assert_eq!(
        next.capability_issuance_binding.context_generation,
        record.capability_issuance_binding.context_generation + 1
    );
    assert_ne!(
        next.capability_issuance_binding.isolation_epoch_id,
        record.capability_issuance_binding.isolation_epoch_id
    );
    assert!(next.issued_capabilities.is_empty());
    assert_ne!(
        old_security_binding.isolation_epoch_id,
        next.capability_issuance_binding.isolation_epoch_id
    );
    assert_ne!(
        old_security_binding.context_generation,
        next.capability_issuance_binding.context_generation
    );
    assert!(!next
        .issued_capabilities
        .iter()
        .any(|capability| capability.id == old_capability_id));

    let loaded = load_active_session_records(&path, &keyring)
        .expect("load persisted restore incarnation");
    assert_eq!(loaded.records.len(), 1);
    assert_eq!(
        loaded.records[0]
            .capability_issuance_binding
            .context_generation,
        next.capability_issuance_binding.context_generation
    );
    assert_eq!(
        loaded.records[0]
            .capability_issuance_binding
            .isolation_epoch_id,
        next.capability_issuance_binding.isolation_epoch_id
    );

    let mut kernel_config = test_kernel_config();
    kernel_config.keypair = authority.clone();
    let mut kernel = chio_kernel::ChioKernel::new(kernel_config);
    kernel
        .set_capability_authority(Box::new(RestoreIncarnationCapabilityAuthority {
            keypair: authority.clone(),
            workload: chio_kernel::authority::CapabilityAuthorityWorkloadBinding {
                tenant_id: next.capability_issuance_binding.tenant_id.clone(),
                workload_id: "restore-incarnation-workload".to_string(),
                server_id: "restore-incarnation-server".to_string(),
                signer_public_key: authority.public_key(),
            },
        }))
        .expect("install restore incarnation capability authority");
    let invocations = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(RestoreIncarnationProbeServer {
        invocations: Arc::clone(&invocations),
    }));
    let new_context =
        session_core_factory::security_context_from_issuance_binding(
            &next.capability_issuance_binding,
        )
            .expect("build new invocation context");
    let old_error = kernel
        .evaluate_tool_call_blocking_with_security_context(
            &restore_incarnation_request(old_capability),
            &new_context,
        )
        .expect_err("old incarnation capability must fail before dispatch");
    assert!(old_error
        .to_string()
        .contains("does not match the live invocation"));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);

    let new_capability = restore_incarnation_capability(
        &authority,
        &agent_public_key,
        &next.capability_issuance_binding,
        "cap-new-incarnation",
    );
    kernel
        .evaluate_tool_call_blocking_with_security_context(
            &restore_incarnation_request(new_capability),
            &new_context,
        )
        .expect("new incarnation capability authorizes its process context");
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn legacy_resume_record_without_kernel_session_id_is_rejected() {
    let mut value =
        serde_json::to_value(sample_resume_record()).expect("serialize resumable session record");
    value
        .as_object_mut()
        .expect("resume record serializes as an object")
        .remove("kernel_session_id");

    let error = serde_json::from_value::<RemoteSessionResumeRecord>(value)
        .expect_err("legacy record must fail closed");
    assert!(error.to_string().contains("kernel_session_id"));
}

#[test]
fn legacy_resume_record_without_capability_issuance_binding_is_rejected() {
    let mut value =
        serde_json::to_value(sample_resume_record()).expect("serialize resumable session record");
    value
        .as_object_mut()
        .expect("resume record serializes as an object")
        .remove("capability_issuance_binding");

    let error = serde_json::from_value::<RemoteSessionResumeRecord>(value)
        .expect_err("legacy record must fail closed");
    assert!(error.to_string().contains("capability_issuance_binding"));
}

#[test]
fn stored_capability_issuer_revalidation_rejects_untrusted_restart_issuer() {
    let old_authority = Keypair::generate();
    let subject = Keypair::generate().public_key();
    let stale_capability = CapabilityToken::sign(
        chio_core::capability::token::CapabilityTokenBody {
            id: "cap-stale-issuer".to_string(),
            issuer: old_authority.public_key(),
            subject,
            scope: chio_core::capability::scope::ChioScope::default(),
            issued_at: 1,
            expires_at: u64::MAX,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &old_authority,
    )
    .expect("sign stale capability");

    let restarted_kernel = chio_kernel::ChioKernel::new(test_kernel_config());
    assert!(!stored_capability_issuers_are_trusted(
        &restarted_kernel,
        std::slice::from_ref(&stale_capability)
    ));

    let mut config = test_kernel_config();
    config.keypair = old_authority;
    let trusted_kernel = chio_kernel::ChioKernel::new(config);
    assert!(stored_capability_issuers_are_trusted(
        &trusted_kernel,
        &[stale_capability]
    ));
}

#[test]
fn validate_restored_peer_capabilities_rejects_tampered_record() {
    let mut record = sample_resume_record();
    record.initialize_params = json!({
        "capabilities": {
            "tools": { "listChanged": true },
            "resources": { "subscribe": true, "listChanged": true },
            "prompts": { "listChanged": true }
        }
    });
    record.peer_capabilities = PeerCapabilities::default();

    let error = validate_restored_peer_capabilities(&record)
        .expect_err("tampered peer capabilities should fail restore validation");
    assert!(error
        .to_string()
        .contains("failed peer capability re-validation"));
}

#[test]
fn expected_resume_agent_id_is_revalidated_from_identity_federation_seed() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let seed_path = std::env::temp_dir().join(format!(
        "chio-identity-federation-resume-{}-{nonce}.seed",
        std::process::id()
    ));
    let mut config = test_remote_config();
    config.identity_federation_seed_path = Some(seed_path.clone());
    let auth_context = SessionAuthContext::streamable_http_oauth_bearer(
        Some("oidc:https://issuer.example#sub:user-123".to_string()),
        Some("https://issuer.example".to_string()),
        Some("user-123".to_string()),
        Some("audience-valid".to_string()),
        vec!["mcp:invoke".to_string()],
        Some("token-fingerprint".to_string()),
        None,
    );

    let expected = expected_resume_agent_id(&config, &auth_context)
        .expect("derive expected agent id")
        .expect("expected agent id");
    let foreign =
        derive_federated_agent_keypair(&seed_path, "oidc:https://issuer.example#sub:user-456")
            .expect("derive foreign principal keypair")
            .public_key()
            .to_hex();

    assert_ne!(expected, foreign);

    let _ = std::fs::remove_file(seed_path);
}

#[test]
#[cfg(target_os = "linux")]
fn load_active_session_records_skips_malformed_rows() {
    let path = std::env::temp_dir().join(format!(
        "chio-remote-active-{}-{}.sqlite3",
        std::process::id(),
        session_now_millis()
    ));
    #[cfg(unix)]
    let _session_store_lease = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("acquire malformed-row session store lease");
    let keyring = test_resume_hmac_keyring();
    let valid_record = sample_resume_record();
    persist_active_session_record(&path, &valid_record, &keyring)
        .expect("persist valid session row");

    let conn = open_session_state_db(&path).expect("open session state db");
    conn.execute(
        &format!(
            "INSERT OR REPLACE INTO {table} (session_id, updated_at, record_json)
                 VALUES (?1, ?2, ?3)",
            table = SESSION_ACTIVE_TABLE,
        ),
        params!["session-bad", session_now_millis() as i64, "{not json"],
    )
    .expect("insert malformed session row");
    drop(conn);

    let loaded = load_active_session_records(&path, &keyring).expect("load active session records");
    assert_eq!(loaded.records.len(), 1);
    assert_eq!(loaded.records[0].session_id, "session-valid");
    assert_eq!(loaded.invalid_session_ids, vec!["session-bad".to_string()]);

    let _ = std::fs::remove_file(path);
}

#[test]
#[cfg(target_os = "linux")]
fn load_active_session_records_skips_terminal_tombstoned_rows() {
    let path = std::env::temp_dir().join(format!(
        "chio-remote-tombstoned-active-{}-{}.sqlite3",
        std::process::id(),
        session_now_millis()
    ));
    #[cfg(unix)]
    let _session_store_lease = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("acquire tombstoned-active session store lease");
    let keyring = test_resume_hmac_keyring();
    let active_record = signed_resume_record("session-terminal", 7, &keyring);
    persist_active_session_record(&path, &active_record, &keyring)
        .expect("persist active session row");
    let (tombstone, fence) = sign_terminal_session_records(
        &keyring,
        terminal_diagnostic_record("session-terminal", 13),
        8,
        8,
    )
    .expect("sign terminal session state");
    persist_terminal_session_transition(&path, &tombstone, &fence, &keyring)
        .expect("persist terminal session transition");

    let conn = open_session_state_db(&path).expect("open session DB for rollback fixture");
    conn.execute(
        &format!(
            "INSERT INTO {table} (session_id, updated_at, record_json) VALUES (?1, ?2, ?3)",
            table = SESSION_ACTIVE_TABLE,
        ),
        params![
            active_record.session_id.as_str(),
            14_i64,
            serde_json::to_string(&active_record).expect("serialize replayed active row"),
        ],
    )
    .expect("replay older valid authenticated active row");
    drop(conn);

    let loaded = load_active_session_records(&path, &keyring).expect("load active session records");
    assert!(loaded.records.is_empty());
    assert_eq!(
        loaded.invalid_session_ids,
        vec!["session-terminal".to_string()]
    );

    let _ = std::fs::remove_file(path);
}

#[test]
#[cfg(target_os = "linux")]
fn load_active_session_records_blocks_active_row_when_matching_tombstone_is_malformed() {
    let path = std::env::temp_dir().join(format!(
        "chio-remote-malformed-tombstone-active-{}-{}.sqlite3",
        std::process::id(),
        session_now_millis()
    ));
    #[cfg(unix)]
    let _session_store_lease = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("acquire malformed-tombstone session store lease");
    let keyring = test_resume_hmac_keyring();
    let active_record = signed_resume_record("session-resumable", 3, &keyring);
    persist_active_session_record(&path, &active_record, &keyring)
        .expect("persist active session row");

    let conn = open_session_state_db(&path).expect("open session state db");
    conn.execute(
        &format!(
            "INSERT INTO {table} (session_id, terminal_at, record_json)
                 VALUES (?1, ?2, ?3)",
            table = SESSION_TOMBSTONE_TABLE,
        ),
        params!["session-resumable", 13_i64, "{not json"],
    )
    .expect("insert malformed terminal row");
    drop(conn);

    let loaded = load_active_session_records(&path, &keyring).expect("load active session records");
    assert!(loaded.records.is_empty());
    assert_eq!(
        loaded.invalid_session_ids,
        vec!["session-resumable".to_string()]
    );

    let _ = std::fs::remove_file(path);
}

#[test]
#[cfg(target_os = "linux")]
fn load_terminal_session_records_skips_mismatched_payload_session_id() {
    let path = std::env::temp_dir().join(format!(
        "chio-remote-terminal-mismatch-{}-{}.sqlite3",
        std::process::id(),
        session_now_millis()
    ));
    #[cfg(unix)]
    let _session_store_lease = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("acquire mismatched-terminal session store lease");
    let keyring = test_resume_hmac_keyring();
    let (tombstone, _fence) = sign_terminal_session_records(
        &keyring,
        terminal_diagnostic_record("session-payload", 13),
        2,
        2,
    )
    .expect("sign terminal record");
    let conn = open_session_state_db(&path).expect("open session state db");
    conn.execute(
        &format!(
            "INSERT INTO {table} (session_id, terminal_at, record_json)
                 VALUES (?1, ?2, ?3)",
            table = SESSION_TOMBSTONE_TABLE,
        ),
        params![
            "session-row",
            tombstone.record.terminal_at as i64,
            serde_json::to_string(&tombstone).expect("serialize terminal record")
        ],
    )
    .expect("insert mismatched terminal row");
    drop(conn);

    let records =
        load_terminal_session_records(&path, &keyring).expect("load terminal session records");
    assert!(
        records.is_empty(),
        "terminal tombstone payloads must match their row session_id"
    );

    let _ = std::fs::remove_file(path);
}

#[test]
#[cfg(target_os = "linux")]
fn remote_session_ledger_startup_skips_malformed_terminal_tombstones() {
    let path = std::env::temp_dir().join(format!(
        "chio-remote-terminal-malformed-{}-{}.sqlite3",
        std::process::id(),
        session_now_millis()
    ));
    #[cfg(unix)]
    let _session_store_lease = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("acquire malformed-terminal session store lease");
    let keyring = test_resume_hmac_keyring();
    let (tombstone, fence) = sign_terminal_session_records(
        &keyring,
        terminal_diagnostic_record("session-valid", 13),
        2,
        2,
    )
    .expect("sign terminal record");
    persist_terminal_session_transition(&path, &tombstone, &fence, &keyring)
        .expect("persist valid terminal session tombstone");

    let conn = open_session_state_db(&path).expect("open session state db");
    conn.execute(
        &format!(
            "INSERT INTO {table} (session_id, terminal_at, record_json)
                 VALUES (?1, ?2, ?3)",
            table = SESSION_TOMBSTONE_TABLE,
        ),
        params!["session-bad", 14_i64, "{not json"],
    )
    .expect("insert malformed terminal row");
    drop(conn);

    let lifecycle_policy = SessionLifecyclePolicy {
        idle_expiry_millis: 5_000,
        drain_grace_millis: 1_000,
        reaper_interval_millis: 100,
        tombstone_retention_millis: 10_000,
    };
    RemoteSessionLedger::new(lifecycle_policy, Some(path.clone()), Some(keyring.clone()))
        .expect("malformed terminal tombstone should not abort ledger startup");

    let records =
        load_terminal_session_records(&path, &keyring).expect("load terminal session records");
    assert_eq!(records.len(), 1);
    assert!(records.contains_key("session-valid"));

    let _ = std::fs::remove_file(path);
}

#[test]
#[cfg(target_os = "linux")]
fn purge_terminal_session_records_keeps_tombstones_for_stale_active_rows() {
    let path = std::env::temp_dir().join(format!(
        "chio-remote-terminal-retain-active-{}-{}.sqlite3",
        std::process::id(),
        session_now_millis()
    ));
    #[cfg(unix)]
    let _session_store_lease = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("acquire terminal-purge session store lease");
    let keyring = test_resume_hmac_keyring();
    let active_record = signed_resume_record("session-terminal", 4, &keyring);
    persist_active_session_record(&path, &active_record, &keyring)
        .expect("persist active session row");
    let (tombstone, fence) = sign_terminal_session_records(
        &keyring,
        terminal_diagnostic_record("session-terminal", 10),
        5,
        5,
    )
    .expect("sign terminal state");
    persist_terminal_session_transition(&path, &tombstone, &fence, &keyring)
        .expect("persist terminal session transition");
    let conn = open_session_state_db(&path).expect("open session state DB");
    conn.execute(
        &format!(
            "INSERT INTO {table} (session_id, updated_at, record_json) VALUES (?1, ?2, ?3)",
            table = SESSION_ACTIVE_TABLE,
        ),
        params![
            active_record.session_id.as_str(),
            10_i64,
            serde_json::to_string(&active_record).expect("serialize stale active row"),
        ],
    )
    .expect("insert stale active row");
    drop(conn);

    purge_terminal_session_records_before(&path, 11)
        .expect("purge should keep tombstone while active row remains");
    let records = load_terminal_session_records(&path, &keyring)
        .expect("load terminal session records after purge");
    assert!(records.contains_key("session-terminal"));

    delete_active_session_record(&path, "session-terminal").expect("delete active session row");
    purge_terminal_session_records_before(&path, 11)
        .expect("purge should remove tombstone after active row is gone");
    let records = load_terminal_session_records(&path, &keyring)
        .expect("load terminal session records after second purge");
    assert!(!records.contains_key("session-terminal"));

    let _ = std::fs::remove_file(path);
}

fn write_resume_hmac_keyring_fixture(path: &FsPath, value: &Value) {
    write_resume_hmac_keyring_bytes(
        path,
        &serde_json::to_vec_pretty(value).expect("serialize resume HMAC keyring fixture"),
    );
}

fn write_resume_hmac_keyring_bytes(path: &FsPath, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write resume HMAC keyring fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("secure resume HMAC keyring fixture permissions");
    }
}

#[test]
fn resume_hmac_keyring_rejects_duplicate_security_fields() {
    let directory = tempfile::tempdir().expect("create duplicate keyring directory");
    let keyring_path = directory.path().join("resume-keyring.json");
    let key = URL_SAFE_NO_PAD.encode([71_u8; 32]);
    let now = session_now_millis();
    let fixtures = [
        (
            "keyId",
            format!(
                r#"{{"schema":"{REMOTE_SESSION_HMAC_KEYRING_SCHEMA}","current":{{"keyId":"a","keyId":"b","version":2,"keyBase64":"{key}"}},"previous":[]}}"#
            ),
        ),
        (
            "version",
            format!(
                r#"{{"schema":"{REMOTE_SESSION_HMAC_KEYRING_SCHEMA}","current":{{"keyId":"a","version":1,"version":2,"keyBase64":"{key}"}},"previous":[]}}"#
            ),
        ),
        (
            "keyBase64",
            format!(
                r#"{{"schema":"{REMOTE_SESSION_HMAC_KEYRING_SCHEMA}","current":{{"keyId":"a","version":2,"keyBase64":"{key}","keyBase64":"{key}"}},"previous":[]}}"#
            ),
        ),
        (
            "verifyUntilMillis",
            format!(
                r#"{{"schema":"{REMOTE_SESSION_HMAC_KEYRING_SCHEMA}","current":{{"keyId":"b","version":2,"keyBase64":"{key}"}},"previous":[{{"keyId":"a","version":1,"keyBase64":"{key}","verifyUntilMillis":{},"verifyUntilMillis":{}}}]}}"#,
                now + 1_000,
                now + 2_000,
            ),
        ),
    ];
    let mut config = test_remote_config();
    config.session_db_path = Some(directory.path().join("sessions.sqlite3"));
    config.resume_hmac_keyring_path = Some(keyring_path.clone());
    for (field, fixture) in fixtures {
        write_resume_hmac_keyring_bytes(&keyring_path, fixture.as_bytes());
        let error = match load_resume_hmac_keyring_at(&config, now) {
            Err(error) => error,
            Ok(_) => panic!("duplicate {field} must fail strict keyring parsing"),
        };
        assert!(
            error.to_string().contains("duplicate field"),
            "duplicate {field} returned unexpected error: {error}"
        );
    }
}

#[test]
fn resume_hmac_keyring_accepts_ijson_member_reordering_and_whitespace() {
    let directory = tempfile::tempdir().expect("create strict I-JSON keyring directory");
    let keyring_path = directory.path().join("resume-keyring.json");
    let key = URL_SAFE_NO_PAD.encode([73_u8; 32]);
    let fixture = format!(
        "{{\n  \"previous\" : [ ],\n  \"current\" : {{ \"keyBase64\" : \"{key}\", \"version\" : 1, \"keyId\" : \"resume-v1\" }},\n  \"schema\" : \"{REMOTE_SESSION_HMAC_KEYRING_SCHEMA}\"\n}}\n"
    );
    write_resume_hmac_keyring_bytes(&keyring_path, fixture.as_bytes());
    let mut config = test_remote_config();
    config.session_db_path = Some(directory.path().join("sessions.sqlite3"));
    config.resume_hmac_keyring_path = Some(keyring_path);
    let keyring = load_resume_hmac_keyring(&config)
        .expect("parse strict I-JSON keyring")
        .expect("configured strict I-JSON keyring");
    assert_eq!(keyring.current.key_id, "resume-v1");
    assert_eq!(keyring.current.version, 1);
}

#[cfg(unix)]
#[test]
fn resume_hmac_keyring_owner_must_be_effective_user_or_root() {
    assert!(resume_hmac_keyring_owner_is_trusted(1_001, 1_001));
    assert!(resume_hmac_keyring_owner_is_trusted(0, 1_001));
    assert!(!resume_hmac_keyring_owner_is_trusted(1_002, 1_001));
}

#[cfg(unix)]
#[test]
fn resume_hmac_keyring_open_refuses_symbolic_links() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("create symlink keyring directory");
    let target = directory.path().join("target.json");
    let link = directory.path().join("resume-keyring.json");
    write_resume_hmac_keyring_fixture(
        &target,
        &json!({
            "schema": REMOTE_SESSION_HMAC_KEYRING_SCHEMA,
            "current": {
                "keyId": "resume-v1",
                "version": 1,
                "keyBase64": URL_SAFE_NO_PAD.encode([72_u8; 32]),
            },
            "previous": [],
        }),
    );
    symlink(&target, &link).expect("create resume keyring symlink");
    let mut config = test_remote_config();
    config.session_db_path = Some(directory.path().join("sessions.sqlite3"));
    config.resume_hmac_keyring_path = Some(link);
    assert!(load_resume_hmac_keyring(&config).is_err());
}

#[cfg(unix)]
#[test]
fn resume_hmac_keyring_open_refuses_hard_link_aliases() {
    let directory = tempfile::tempdir().expect("create hard-linked keyring directory");
    let keyring_path = directory.path().join("resume-keyring.json");
    let alias = directory.path().join("resume-keyring-alias.json");
    write_resume_hmac_keyring_fixture(
        &keyring_path,
        &json!({
            "schema": REMOTE_SESSION_HMAC_KEYRING_SCHEMA,
            "current": {
                "keyId": "resume-v1",
                "version": 1,
                "keyBase64": URL_SAFE_NO_PAD.encode([74_u8; 32]),
            },
            "previous": [],
        }),
    );
    std::fs::hard_link(&keyring_path, alias).expect("create resume keyring hard-link alias");
    let mut config = test_remote_config();
    config.session_db_path = Some(directory.path().join("sessions.sqlite3"));
    config.resume_hmac_keyring_path = Some(keyring_path);
    assert!(load_resume_hmac_keyring(&config).is_err());
}

#[test]
fn resume_hmac_validation_rejects_noncanonical_or_wrong_length_tags() {
    let keyring = test_resume_hmac_keyring();
    let mut padded = signed_resume_record("noncanonical-tag", 1, &keyring);
    let raw_tag = URL_SAFE_NO_PAD
        .decode(padded.resume_integrity.tag.as_bytes())
        .expect("decode fixture HMAC tag");
    padded.resume_integrity.tag = base64::engine::general_purpose::URL_SAFE.encode(raw_tag);
    assert!(validate_resume_record_integrity_with_keyring(
        &keyring,
        &padded,
        session_now_millis()
    )
    .is_err());

    let mut short = signed_resume_record("short-tag", 1, &keyring);
    short.resume_integrity.tag = URL_SAFE_NO_PAD.encode([0_u8; 31]);
    assert!(validate_resume_record_integrity_with_keyring(
        &keyring,
        &short,
        session_now_millis()
    )
    .is_err());
}

#[test]
fn durable_resume_without_dedicated_hmac_keyring_fails_closed() {
    let mut config = test_remote_config();
    config.session_db_path = Some(PathBuf::from("sessions.sqlite3"));
    let error = match load_resume_hmac_keyring(&config) {
        Err(error) => error,
        Ok(_) => panic!("durable resume without a dedicated keyring must fail"),
    };
    assert!(error.to_string().contains("--resume-hmac-keyring"));
}

#[test]
#[cfg(target_os = "linux")]
fn deleted_tombstone_still_blocks_replayed_active_generation_via_terminal_fence() {
    let directory = tempfile::tempdir().expect("create terminal fence directory");
    let path = directory.path().join("sessions.sqlite3");
    #[cfg(unix)]
    let _session_store_lease = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("acquire terminal-fence session store lease");
    let keyring = test_resume_hmac_keyring();
    let active = signed_resume_record("deleted-tombstone", 11, &keyring);
    persist_active_session_record(&path, &active, &keyring).expect("persist active record");
    let (tombstone, fence) = sign_terminal_session_records(
        &keyring,
        terminal_diagnostic_record("deleted-tombstone", 20),
        12,
        12,
    )
    .expect("sign terminal state");
    persist_terminal_session_transition(&path, &tombstone, &fence, &keyring)
        .expect("persist terminal transition");

    let conn = open_session_state_db(&path).expect("open terminal state DB");
    conn.execute(
        &format!(
            "DELETE FROM {table} WHERE session_id = ?1",
            table = SESSION_TOMBSTONE_TABLE,
        ),
        params![active.session_id.as_str()],
    )
    .expect("delete tombstone fixture");
    conn.execute(
        &format!(
            "INSERT INTO {table} (session_id, updated_at, record_json) VALUES (?1, ?2, ?3)",
            table = SESSION_ACTIVE_TABLE,
        ),
        params![
            active.session_id.as_str(),
            21_i64,
            serde_json::to_string(&active).expect("serialize replayed active record"),
        ],
    )
    .expect("replay older active record");
    drop(conn);

    let loaded = load_active_session_records(&path, &keyring).expect("load active records");
    assert!(loaded.records.is_empty());
    assert_eq!(loaded.invalid_session_ids, vec![active.session_id]);
}

#[test]
#[cfg(target_os = "linux")]
fn active_resume_persistence_rejects_authenticated_generation_rollback() {
    let directory = tempfile::tempdir().expect("create active generation directory");
    let path = directory.path().join("sessions.sqlite3");
    #[cfg(unix)]
    let _session_store_lease = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("acquire generation-rollback session store lease");
    let keyring = test_resume_hmac_keyring();
    let generation_two = signed_resume_record("active-generation", 2, &keyring);
    persist_active_session_record(&path, &generation_two, &keyring)
        .expect("persist current active generation");
    let generation_one = signed_resume_record("active-generation", 1, &keyring);
    let error = persist_active_session_record(&path, &generation_one, &keyring)
        .expect_err("authenticated older generation must not replace current state");
    assert!(error.to_string().contains("refusing to roll back"));
}

#[test]
#[cfg(target_os = "linux")]
fn corrupt_authenticated_tombstone_still_blocks_replay_and_is_not_reported() {
    let directory = tempfile::tempdir().expect("create corrupt tombstone directory");
    let path = directory.path().join("sessions.sqlite3");
    #[cfg(unix)]
    let _session_store_lease = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("acquire corrupt-tombstone session store lease");
    let keyring = test_resume_hmac_keyring();
    let active = signed_resume_record("corrupt-tombstone", 4, &keyring);
    persist_active_session_record(&path, &active, &keyring).expect("persist active record");
    let (tombstone, fence) = sign_terminal_session_records(
        &keyring,
        terminal_diagnostic_record("corrupt-tombstone", 30),
        5,
        5,
    )
    .expect("sign terminal state");
    persist_terminal_session_transition(&path, &tombstone, &fence, &keyring)
        .expect("persist terminal transition");

    let conn = open_session_state_db(&path).expect("open terminal state DB");
    let mut corrupt = tombstone.clone();
    corrupt.record.lifecycle.state = RemoteSessionState::Ready;
    conn.execute(
        &format!(
            "UPDATE {table} SET record_json = ?2 WHERE session_id = ?1",
            table = SESSION_TOMBSTONE_TABLE,
        ),
        params![
            active.session_id.as_str(),
            serde_json::to_string(&corrupt).expect("serialize corrupt tombstone"),
        ],
    )
    .expect("corrupt tombstone fixture");
    conn.execute(
        &format!(
            "INSERT INTO {table} (session_id, updated_at, record_json) VALUES (?1, ?2, ?3)",
            table = SESSION_ACTIVE_TABLE,
        ),
        params![
            active.session_id.as_str(),
            31_i64,
            serde_json::to_string(&active).expect("serialize replayed active record"),
        ],
    )
    .expect("replay active record");
    drop(conn);

    let loaded = load_active_session_records(&path, &keyring).expect("load active records");
    assert!(loaded.records.is_empty());
    assert_eq!(loaded.invalid_session_ids, vec![active.session_id.clone()]);
    assert!(
        load_terminal_session_records(&path, &keyring)
            .expect("load terminal records")
            .is_empty()
    );
}

#[test]
#[cfg(target_os = "linux")]
fn terminal_intent_crash_boundaries_never_reopen_resume() {
    let directory = tempfile::tempdir().expect("create terminal intent directory");
    let path = directory.path().join("sessions.sqlite3");
    #[cfg(unix)]
    let _session_store_lease = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("acquire terminal-intent session store lease");
    let keyring = test_resume_hmac_keyring();
    let active = signed_resume_record("terminal-boundaries", 8, &keyring);
    persist_active_session_record(&path, &active, &keyring).expect("persist active record");

    let before_intent =
        load_active_session_records(&path, &keyring).expect("load state before terminal intent");
    assert_eq!(before_intent.records.len(), 1);
    assert!(before_intent.invalid_session_ids.is_empty());

    let (tombstone, fence) = sign_terminal_session_records(
        &keyring,
        terminal_diagnostic_record("terminal-boundaries", 41),
        9,
        9,
    )
    .expect("sign terminal intent");
    prepare_terminal_session_transition(&path, &fence, &keyring)
        .expect("prepare terminal intent before shutdown");
    let after_intent =
        load_active_session_records(&path, &keyring).expect("load state after terminal intent");
    assert!(after_intent.records.is_empty());
    assert!(after_intent.invalid_session_ids.is_empty());
    assert!(
        load_terminal_session_records(&path, &keyring)
            .expect("load diagnostics before finalization")
            .is_empty()
    );

    let conn = open_session_state_db(&path).expect("open terminal intent DB");
    conn.execute(
        &format!(
            "INSERT INTO {table} (session_id, updated_at, record_json) VALUES (?1, ?2, ?3)",
            table = SESSION_ACTIVE_TABLE,
        ),
        params![
            active.session_id.as_str(),
            42_i64,
            serde_json::to_string(&active).expect("serialize replayed active record"),
        ],
    )
    .expect("inject active replay after prepared intent");
    drop(conn);
    let replay =
        load_active_session_records(&path, &keyring).expect("load replay after terminal intent");
    assert!(replay.records.is_empty());
    assert_eq!(replay.invalid_session_ids, vec![active.session_id.clone()]);
    delete_active_session_record(&path, &active.session_id).expect("remove replay fixture");

    finalize_terminal_session_transition(&path, &tombstone, &keyring)
        .expect("finalize terminal diagnostic after shutdown boundary");
    let finalized =
        load_terminal_session_records(&path, &keyring).expect("load finalized terminal record");
    assert_eq!(finalized.len(), 1);
    assert!(finalized.contains_key(&active.session_id));
    assert!(
        load_active_session_records(&path, &keyring)
            .expect("load active state after terminal finalization")
            .records
            .is_empty()
    );
}

#[test]
#[cfg(target_os = "linux")]
fn terminal_intent_rolls_back_fence_when_active_delete_fails() {
    let directory = tempfile::tempdir().expect("create transaction rollback directory");
    let path = directory.path().join("sessions.sqlite3");
    #[cfg(unix)]
    let _session_store_lease = RemoteSessionStoreLifecycleLease::acquire(&path)
        .expect("acquire terminal-rollback session store lease");
    let keyring = test_resume_hmac_keyring();
    let active = signed_resume_record("partial-terminal", 2, &keyring);
    persist_active_session_record(&path, &active, &keyring).expect("persist active record");
    let conn = open_session_state_db(&path).expect("open terminal state DB");
    conn.execute_batch(&format!(
        "CREATE TRIGGER fail_terminal_active_delete
         BEFORE DELETE ON {table}
         BEGIN SELECT RAISE(ABORT, 'injected active delete failure'); END;",
        table = SESSION_ACTIVE_TABLE,
    ))
    .expect("install active delete failure trigger");
    drop(conn);
    let (tombstone, fence) = sign_terminal_session_records(
        &keyring,
        terminal_diagnostic_record("partial-terminal", 40),
        3,
        3,
    )
    .expect("sign terminal state");

    persist_terminal_session_transition(&path, &tombstone, &fence, &keyring)
        .expect_err("partial terminal transition must roll back");
    let conn = open_session_state_db(&path).expect("reopen terminal state DB");
    let active_count: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {table}", table = SESSION_ACTIVE_TABLE),
            [],
            |row| row.get(0),
        )
        .expect("count active records");
    let tombstone_count: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {table}", table = SESSION_TOMBSTONE_TABLE),
            [],
            |row| row.get(0),
        )
        .expect("count tombstones");
    let fence_count: i64 = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM {table}",
                table = SESSION_TERMINAL_FENCE_TABLE
            ),
            [],
            |row| row.get(0),
        )
        .expect("count terminal fences");
    assert_eq!((active_count, tombstone_count, fence_count), (1, 0, 0));
}

#[test]
fn resume_hmac_rotation_grace_is_bounded_and_unrelated_secret_rotation_is_ignored() {
    let directory = tempfile::tempdir().expect("create resume keyring directory");
    let keyring_path = directory.path().join("resume-keyring.json");
    let session_db_path = directory.path().join("sessions.sqlite3");
    let now = session_now_millis();
    let key_v1 = URL_SAFE_NO_PAD.encode([61_u8; 32]);
    let key_v2 = URL_SAFE_NO_PAD.encode([62_u8; 32]);
    write_resume_hmac_keyring_fixture(
        &keyring_path,
        &json!({
            "schema": REMOTE_SESSION_HMAC_KEYRING_SCHEMA,
            "current": {"keyId": "resume-v1", "version": 1, "keyBase64": key_v1},
            "previous": [],
        }),
    );
    let mut config = test_remote_config();
    config.session_db_path = Some(session_db_path);
    config.resume_hmac_keyring_path = Some(keyring_path.clone());
    let keyring_v1 = load_resume_hmac_keyring_at(&config, now)
        .expect("load v1 resume keyring")
        .expect("configured v1 resume keyring");
    let record = signed_resume_record("rotation-grace", 1, &keyring_v1);

    config.auth_token = Some("rotated-edge-auth".to_string());
    config.admin_token = Some("rotated-admin-auth".to_string());
    config.control_token = Some("rotated-control-auth".to_string());
    config.authority_seed_path = Some(directory.path().join("different-authority.seed"));
    config.authority_db_path = Some(directory.path().join("different-authority.sqlite3"));
    validate_resume_record_integrity(&config, &record)
        .expect("unrelated authority and bearer rotation must not affect resume HMAC");

    write_resume_hmac_keyring_fixture(
        &keyring_path,
        &json!({
            "schema": REMOTE_SESSION_HMAC_KEYRING_SCHEMA,
            "current": {"keyId": "resume-v2", "version": 2, "keyBase64": key_v2},
            "previous": [{
                "keyId": "resume-v1",
                "version": 1,
                "keyBase64": URL_SAFE_NO_PAD.encode([61_u8; 32]),
                "verifyUntilMillis": now + 60_000,
            }],
        }),
    );
    let keyring_v2 = load_resume_hmac_keyring_at(&config, now)
        .expect("load rotated resume keyring")
        .expect("configured rotated resume keyring");
    validate_resume_record_integrity_with_keyring(&keyring_v2, &record, now)
        .expect("previous resume key must verify during grace");

    write_resume_hmac_keyring_fixture(
        &keyring_path,
        &json!({
            "schema": REMOTE_SESSION_HMAC_KEYRING_SCHEMA,
            "current": {
                "keyId": "resume-v2",
                "version": 2,
                "keyBase64": URL_SAFE_NO_PAD.encode([62_u8; 32]),
            },
            "previous": [{
                "keyId": "resume-v1",
                "version": 1,
                "keyBase64": URL_SAFE_NO_PAD.encode([61_u8; 32]),
                "verifyUntilMillis": now.saturating_sub(1),
            }],
        }),
    );
    let expired_keyring = load_resume_hmac_keyring_at(&config, now)
        .expect("load keyring with expired grace key")
        .expect("configured keyring with expired grace key");
    let error = validate_resume_record_integrity_with_keyring(&expired_keyring, &record, now)
        .expect_err("expired grace key must fail validation");
    assert!(error.to_string().contains("unknown or expired"));
}
