use super::*;
use chio_core::session::{SessionAuthMethod, SessionTransport};
use p256::ecdsa::signature::Signer as _;
use rsa::pkcs1v15::SigningKey as RsaPkcs1v15SigningKey;
use rsa::pss::BlindedSigningKey as RsaPssSigningKey;
use rsa::rand_core::OsRng;
use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _};
#[cfg(target_os = "linux")]
use rusqlite::params;
use serde_json::json;
use std::net::ToSocketAddrs as _;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

static MANIFEST_FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn sample_capability_issuance_binding() -> RemoteCapabilityIssuanceBinding {
    RemoteCapabilityIssuanceBinding {
        tenant_id: "tenant-valid".to_string(),
        lineage_id: "lineage-valid".to_string(),
        security_session_id: "security-session-valid".to_string(),
        principal_id: "principal-valid".to_string(),
        isolation_epoch_id: "isolation-epoch-valid".to_string(),
        context_generation: 1,
    }
}

#[derive(Clone)]
struct TestNativeLaunchFactory {
    authorization_digest: String,
}

struct ShutdownProbeTransport {
    shutdown_count: Arc<AtomicU64>,
    failure: Option<&'static str>,
}

impl McpTransport for ShutdownProbeTransport {
    fn list_tools(&self) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, AdapterError> {
        Err(AdapterError::ConnectionFailed(
            "shutdown probe does not support tool discovery".to_string(),
        ))
    }

    fn call_tool(
        &self,
        _tool_name: &str,
        _arguments: Value,
    ) -> Result<chio_mcp_adapter::edge::McpToolResult, AdapterError> {
        Err(AdapterError::ConnectionFailed(
            "shutdown probe does not support tool calls".to_string(),
        ))
    }

    fn shutdown(&self) -> Result<(), AdapterError> {
        self.shutdown_count.fetch_add(1, Ordering::SeqCst);
        self.failure.map_or(Ok(()), |message| {
            Err(AdapterError::ConnectionFailed(message.to_string()))
        })
    }
}

struct TestMigrationStore {
    state: chio_security_types::EnterpriseMigrationState,
}

impl chio_security_types::EnterpriseMigrationStateStore for TestMigrationStore {
    fn register(
        &self,
        _transition: &chio_security_types::EnterpriseMigrationTransition,
    ) -> chio_security_types::ports::PortResult<
        chio_security_types::EnterpriseMigrationRegisterOutcome,
    > {
        Ok(chio_security_types::EnterpriseMigrationRegisterOutcome::Existing(self.state.clone()))
    }

    fn load(
        &self,
        key: &chio_security_types::EnterpriseMigrationKey,
    ) -> chio_security_types::ports::PortResult<Option<chio_security_types::EnterpriseMigrationState>>
    {
        Ok((key == &self.state.key).then(|| self.state.clone()))
    }

    fn compare_and_promote(
        &self,
        _transition: &chio_security_types::EnterpriseMigrationTransition,
    ) -> chio_security_types::ports::PortResult<chio_security_types::EnterpriseMigrationCasOutcome>
    {
        Ok(chio_security_types::EnterpriseMigrationCasOutcome::Conflict(self.state.clone()))
    }
}

impl chio_mcp_adapter::transport::NativeMcpLaunchFactory for TestNativeLaunchFactory {
    fn authorization_contract_digest(
        &self,
    ) -> Result<String, chio_mcp_adapter::edge::AdapterError> {
        Ok(self.authorization_digest.clone())
    }

    fn prepare_launch(
        &self,
        _command: &str,
        _args: &[&str],
        expected_server_id: &str,
        admitted_manifest_registry: Arc<chio_manifest::VerifiedManifestRegistry>,
    ) -> Result<chio_mcp_adapter::transport::NativeMcpLaunch, chio_mcp_adapter::edge::AdapterError>
    {
        let key = chio_security_types::EnterpriseMigrationKey {
            deployment_id: chio_security_types::ports::RecordId::new("test-deployment").map_err(
                |error| chio_mcp_adapter::edge::AdapterError::ConnectionFailed(error.to_string()),
            )?,
            scope_kind: chio_security_types::EnterpriseMigrationScopeKind::ToolServer,
            scope_id: chio_security_types::ports::RecordId::new(expected_server_id).map_err(
                |error| chio_mcp_adapter::edge::AdapterError::ConnectionFailed(error.to_string()),
            )?,
            control: chio_security_types::EnterpriseMigrationControl::CageEnforcement,
        };
        let posture = chio_security_types::ports::Digest32::new([0x21; 32]);
        let state = chio_security_types::EnterpriseMigrationState {
            schema_version: chio_security_types::ENTERPRISE_MIGRATION_STATE_SCHEMA_VERSION,
            key: key.clone(),
            stage: chio_security_types::EnterpriseMigrationStage::Shadow,
            generation: 1,
            transition_digest: chio_security_types::ports::Digest32::new([0x22; 32]),
            prior_head_digest: Some(chio_security_types::ports::Digest32::new([0x23; 32])),
            posture_digest: posture,
            evidence_digest: chio_security_types::ports::Digest32::new([0x24; 32]),
            authorization_digest: chio_security_types::ports::Digest32::new([0x25; 32]),
            intent_digest: chio_security_types::ports::Digest32::new([0x26; 32]),
            updated_at_unix_ms: 1,
            signer_public_key: "test-signer".to_string(),
        };
        let concrete = Arc::new(TestMigrationStore { state });
        let store: Arc<dyn chio_security_types::EnterpriseMigrationStateStore> = concrete;
        let binding = chio_security_types::EnterpriseMigrationRuntimeBinding::load(
            &store,
            &key,
            chio_security_types::EnterpriseMigrationStage::Shadow,
            posture,
        )
        .map_err(|error| {
            chio_mcp_adapter::edge::AdapterError::ConnectionFailed(error.to_string())
        })?;
        let authorization = chio_mcp_adapter::transport::LegacyNativeLaunchAuthorization::new(
            expected_server_id,
            binding,
            admitted_manifest_registry,
        )?;
        Ok(chio_mcp_adapter::transport::NativeMcpLaunch::LegacyAuthorized(Box::new(
            authorization,
        )))
    }
}

fn test_native_launch_factory() -> Arc<dyn chio_mcp_adapter::transport::NativeMcpLaunchFactory> {
    Arc::new(TestNativeLaunchFactory {
        authorization_digest: "21".repeat(32),
    })
}

fn test_resume_hmac_keyring() -> Arc<RemoteSessionHmacKeyring> {
    Arc::new(RemoteSessionHmacKeyring {
        current: RemoteSessionHmacKey {
            key_id: "resume-test-key".to_string(),
            version: 1,
            key: Zeroizing::new([7; 32]),
            verify_until_millis: None,
        },
        previous: Vec::new(),
    })
}

fn terminal_test_session(
    session_id: &str,
    upstream_transport: Arc<dyn McpTransport>,
) -> Arc<RemoteSession> {
    let (input_tx, _input_rx) = mpsc::channel::<Value>();
    let (event_tx, _) = broadcast::channel::<RemoteSessionEvent>(8);
    Arc::new(RemoteSession::new(RemoteSessionInit {
        session_id: session_id.to_string(),
        kernel_session_id: SessionId::new(format!("kernel-{session_id}")),
        agent_id: format!("agent-{session_id}"),
        capabilities: Vec::new(),
        issued_capabilities: Vec::new(),
        auth_context: SessionAuthContext::streamable_http_static_bearer(
            format!("agent-{session_id}"),
            format!("token-{session_id}"),
            None,
        ),
        auth_mode_fingerprint: "auth-contract-v1".to_string(),
        policy_fingerprint: "policy-contract-v1".to_string(),
        hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
        capability_issuance_binding: sample_capability_issuance_binding(),
        lifecycle_policy: SessionLifecyclePolicy {
            idle_expiry_millis: 5_000,
            drain_grace_millis: 1_000,
            reaper_interval_millis: 100,
            tombstone_retention_millis: 10_000,
        },
        protocol_version: Some("2025-06-18".to_string()),
        peer_capabilities: Some(PeerCapabilities::default()),
        initialize_params: Some(json!({})),
        lifecycle_snapshot: Some(RemoteSessionLifecycleSnapshot {
            state: RemoteSessionState::Ready,
            created_at: 11,
            last_seen_at: 12,
            idle_expires_at: u64::MAX,
            drain_deadline_at: None,
        }),
        input_tx,
        event_tx,
        retained_notification_events: Arc::new(StdMutex::new(VecDeque::new())),
        next_event_id: Arc::new(AtomicU64::new(0)),
        session_db_path: None,
        session_store_lease: None,
        resume_hmac_keyring: Some(test_resume_hmac_keyring()),
        resume_generation: 0,
        upstream_transport,
    }))
}

fn sign_jwt_with_header(
    header: Value,
    claims: &serde_json::Value,
    sign: impl Fn(&[u8]) -> Vec<u8>,
) -> String {
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("serialize JWT header"));
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("serialize JWT claims"));
    let signing_input = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(sign(signing_input.as_bytes()));
    format!("{signing_input}.{signature}")
}

#[test]
fn mcp_rate_limiter_caps_session_window() {
    let limiter = McpRateLimiter::new();
    for _ in 0..MCP_RATE_LIMIT_MAX_REQUESTS {
        assert!(limiter.check("session:test".to_string(), 120).is_ok());
    }

    let retry_after = limiter
        .check("session:test".to_string(), 120)
        .expect_err("session should be rate limited after the window budget is exhausted");
    assert_eq!(retry_after, 60);
    assert!(limiter.check("session:test".to_string(), 180).is_ok());
}

#[test]
fn mcp_rate_limiter_caps_tracked_keys() {
    let limiter = McpRateLimiter::new();
    for idx in 0..MCP_RATE_LIMIT_MAX_KEYS {
        assert!(limiter.check(format!("session:{idx}"), 120).is_ok());
    }

    let retry_after = limiter
        .check("session:overflow".to_string(), 120)
        .expect_err("new rate-limit keys should be capped within a window");
    assert_eq!(retry_after, 60);
    assert!(limiter.check("session:0".to_string(), 120).is_ok());
}

#[test]
fn mcp_rate_limit_key_ignores_unverified_client_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(
        MCP_SESSION_ID_HEADER,
        HeaderValue::from_static("session-secret"),
    );
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer token-secret"),
    );

    let key = mcp_rate_limit_key("127.0.0.1:8080".parse().unwrap());
    assert_eq!(key, "ip:127.0.0.1");
    assert!(!key.contains("session-secret"));
    assert!(!key.contains("token-secret"));
}

#[test]
fn mcp_session_id_header_classifies_missing_invalid_and_valid_values() {
    let mut headers = HeaderMap::new();
    assert_eq!(mcp_session_id_header(&headers), McpSessionIdHeader::Missing);

    headers.insert(MCP_SESSION_ID_HEADER, HeaderValue::from_static(""));
    assert_eq!(mcp_session_id_header(&headers), McpSessionIdHeader::Invalid);

    headers.insert(
        MCP_SESSION_ID_HEADER,
        HeaderValue::from_static(" session-123"),
    );
    assert_eq!(mcp_session_id_header(&headers), McpSessionIdHeader::Invalid);

    headers.insert(
        MCP_SESSION_ID_HEADER,
        HeaderValue::from_static("session-123 "),
    );
    assert_eq!(mcp_session_id_header(&headers), McpSessionIdHeader::Invalid);

    headers.insert(
        MCP_SESSION_ID_HEADER,
        HeaderValue::from_static("session-123"),
    );
    assert_eq!(
        mcp_session_id_header(&headers),
        McpSessionIdHeader::Valid("session-123".to_string())
    );
}

fn sign_jwt_rs256(
    private_key: &rsa::RsaPrivateKey,
    claims: &serde_json::Value,
    kid: &str,
) -> String {
    let signing_key = RsaPkcs1v15SigningKey::<Sha256>::new(private_key.clone());
    sign_jwt_with_header(
        json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        }),
        claims,
        |message| signing_key.sign(message).to_vec(),
    )
}

fn sign_jwt_es256(
    signing_key: &p256::ecdsa::SigningKey,
    claims: &serde_json::Value,
    kid: &str,
) -> String {
    sign_jwt_with_header(
        json!({
            "alg": "ES256",
            "typ": "JWT",
            "kid": kid,
        }),
        claims,
        |message| {
            let signature: p256::ecdsa::Signature = signing_key.sign(message);
            signature.to_bytes().to_vec()
        },
    )
}

fn sign_jwt_ps256(
    private_key: &rsa::RsaPrivateKey,
    claims: &serde_json::Value,
    kid: &str,
) -> String {
    let signing_key = RsaPssSigningKey::<Sha256>::new(private_key.clone());
    sign_jwt_with_header(
        json!({
            "alg": "PS256",
            "typ": "JWT",
            "kid": kid,
        }),
        claims,
        |message| signing_key.sign_with_rng(&mut OsRng, message).to_vec(),
    )
}

fn sign_jwt_es384(
    signing_key: &p384::ecdsa::SigningKey,
    claims: &serde_json::Value,
    kid: &str,
) -> String {
    sign_jwt_with_header(
        json!({
            "alg": "ES384",
            "typ": "JWT",
            "kid": kid,
        }),
        claims,
        |message| {
            let signature: p384::ecdsa::Signature = signing_key.sign(message);
            signature.to_bytes().to_vec()
        },
    )
}

fn test_introspection_verifier(
    issuer: Option<&str>,
    audience: Option<&str>,
    required_scopes: &[&str],
) -> IntrospectionBearerVerifier {
    let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
    IntrospectionBearerVerifier {
        client: HttpClient::builder().build().expect("build http client"),
        introspection_url: Url::parse("http://127.0.0.1:9/introspect")
            .expect("parse introspection url"),
        client_id: None,
        client_secret: None,
        issuer: issuer.map(ToOwned::to_owned),
        audience: audience.map(ToOwned::to_owned),
        required_scopes: required_scopes
            .iter()
            .map(|scope| (*scope).to_string())
            .collect(),
        provider_profile: JwtProviderProfile::Generic,
        enterprise_provider_registry: None,
        sender_dpop_nonce_store,
        sender_dpop_config,
        egress_contract: None,
    }
}

fn test_sender_dpop_runtime() -> (Arc<DpopNonceStore>, DpopConfig) {
    let config = DpopConfig::default();
    let store = Arc::new(DpopNonceStore::new(
        config.nonce_store_capacity,
        Duration::from_secs(config.proof_ttl_secs),
    ));
    (store, config)
}

fn test_kernel_config() -> chio_kernel::KernelConfig {
    chio_kernel::KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "test-policy-hash".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
    }
}

fn empty_header_map() -> HeaderMap {
    HeaderMap::new()
}

fn test_remote_config() -> RemoteServeHttpConfig {
    RemoteServeHttpConfig {
        listen: "127.0.0.1:0".parse().expect("parse listen addr"),
        auth_token: Some("remote-auth-token".to_string()),
        auth_jwt_public_key: None,
        auth_jwt_discovery_url: None,
        auth_introspection_url: None,
        auth_introspection_client_id: None,
        auth_introspection_client_secret: None,
        auth_jwt_provider_profile: None,
        auth_server_seed_path: None,
        identity_federation_seed_path: None,
        enterprise_providers_file: None,
        auth_jwt_issuer: None,
        auth_jwt_audience: None,
        admin_token: Some("admin-token".to_string()),
        control_url: None,
        control_token: None,
        remote_authority_workload_token: None,
        control_authority_public_key: None,
        control_authority_trusted_public_keys: Vec::new(),
        control_authority_successors: Vec::new(),
        control_authority_key_log_policy_path: None,
        control_authority_key_log_verifier_db_path: None,
        remote_authority_tenant_id: None,
        remote_authority_workload_id: None,
        remote_authority_workload_seed_path: None,
        remote_authority_session_admission_seed_path: None,
        remote_kernel_evidence_seed_path: None,
        public_base_url: None,
        auth_servers: vec![],
        auth_authorization_endpoint: None,
        auth_token_endpoint: None,
        auth_registration_endpoint: None,
        auth_jwks_uri: None,
        auth_scopes: vec!["mcp:invoke".to_string()],
        auth_subject: "operator".to_string(),
        auth_code_ttl_secs: 300,
        auth_access_token_ttl_secs: 600,
        receipt_db_path: None,
        revocation_db_path: None,
        authority_seed_path: None,
        keyring_config_path: None,
        broker_config_path: None,
        authority_db_path: None,
        budget_db_path: None,
        aggregate_invocation_admission: false,
        admission_operation_db_path: None,
        approval_db_path: None,
        approver_directory_path: None,
        threshold_proposal_authority_public_key: None,
        session_db_path: None,
        resume_hmac_keyring_path: None,
        policy_path: PathBuf::from("policy.yaml"),
        server_id: "srv".to_string(),
        server_name: "srv".to_string(),
        server_version: "0.1.0".to_string(),
        signed_manifest_path: None,
        manifest_public_key: None,
        native_launch_factory: test_native_launch_factory(),
        page_size: 50,
        tools_list_changed: false,
        shared_hosted_owner: false,
        wrapped_command: "python3".to_string(),
        wrapped_args: vec!["mock.py".to_string()],
        egress_contract: None,
    }
}

fn configure_signed_manifest(config: &mut RemoteServeHttpConfig) -> PathBuf {
    configure_signed_manifest_with_flow(config, None)
}

fn configure_signed_manifest_with_flow(
    config: &mut RemoteServeHttpConfig,
    flow: Option<chio_manifest::ToolFlowDeclaration>,
) -> PathBuf {
    let signer = Keypair::generate();
    let public_key = signer.public_key().to_hex();
    let signed = chio_manifest::sign_manifest(
        &ToolManifest {
            schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: config.server_id.clone(),
            name: config.server_name.clone(),
            description: None,
            version: config.server_version.clone(),
            tools: vec![chio_manifest::ToolDefinition {
                name: "read".to_string(),
                description: "Read".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: true,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                },
                latency_hint: None,
                flow,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: public_key.clone(),
        },
        &signer,
    )
    .expect("sign explicit remote MCP test manifest");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let sequence = MANIFEST_FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "chio-remote-mcp-manifest-{}-{nonce}-{sequence}.json",
        std::process::id()
    ));
    std::fs::write(
        &path,
        serde_json::to_vec(&signed).expect("serialize explicit remote MCP test manifest"),
    )
    .expect("write explicit remote MCP test manifest");
    config.signed_manifest_path = Some(path.clone());
    config.manifest_public_key = Some(public_key);
    path
}

struct ThresholdProductServer;

#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for ThresholdProductServer {
    fn server_id(&self) -> &str {
        "payments"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["transfer".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, chio_kernel::KernelError> {
        Ok(json!({"transferred": true}))
    }
}

#[cfg(target_os = "linux")]
struct RestoreIncarnationProbeServer {
    invocations: Arc<AtomicU64>,
}

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for RestoreIncarnationProbeServer {
    fn server_id(&self) -> &str {
        "restore-incarnation-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["invoke".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, chio_kernel::KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"invoked": true}))
    }
}

#[cfg(target_os = "linux")]
struct RestoreIncarnationCapabilityAuthority {
    keypair: Keypair,
    workload: chio_kernel::authority::CapabilityAuthorityWorkloadBinding,
}

#[cfg(target_os = "linux")]
impl chio_kernel::CapabilityAuthority for RestoreIncarnationCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    fn workload_binding(
        &self,
    ) -> Option<chio_kernel::authority::CapabilityAuthorityWorkloadBinding> {
        Some(self.workload.clone())
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: chio_core::capability::scope::ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        CapabilityToken::sign(
            chio_core::capability::token::CapabilityTokenBody {
                id: format!("cap-{}", Keypair::generate().public_key().to_hex()),
                issuer: self.keypair.public_key(),
                subject: subject.clone(),
                scope,
                issued_at: now,
                expires_at: now.saturating_add(ttl_seconds),
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &self.keypair,
        )
        .map_err(|error| chio_kernel::KernelError::CapabilityIssuanceFailed(error.to_string()))
    }
}

fn restore_incarnation_capability(
    authority: &Keypair,
    subject: &PublicKey,
    binding: &RemoteCapabilityIssuanceBinding,
    id: &str,
) -> CapabilityToken {
    use chio_core::capability::caveat::CapabilitySecurityBinding;
    use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "restore-incarnation-server".to_string(),
            tool_name: "invoke".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };
    CapabilityToken::sign_with_security_binding(
        chio_core::capability::token::CapabilityTokenBody {
            id: id.to_string(),
            issuer: authority.public_key(),
            subject: subject.clone(),
            scope,
            issued_at: now,
            expires_at: now.saturating_add(300),
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        CapabilitySecurityBinding {
            schema: chio_core::capability::caveat::CAPABILITY_SECURITY_BINDING_SCHEMA.to_string(),
            tenant_id: binding.tenant_id.clone(),
            lineage_id: binding.lineage_id.clone(),
            session_id: binding.security_session_id.clone(),
            principal_id: binding.principal_id.clone(),
            isolation_epoch_id: binding.isolation_epoch_id.clone(),
            context_generation: binding.context_generation,
            workload_id: "restore-incarnation-workload".to_string(),
            server_id: "restore-incarnation-server".to_string(),
            workload_signer_public_key: authority.public_key().to_hex(),
        },
        authority,
    )
    .expect("sign restore incarnation capability")
}

#[cfg(target_os = "linux")]
fn restore_incarnation_request(capability: CapabilityToken) -> chio_kernel::ToolCallRequest {
    chio_kernel::ToolCallRequest {
        request_id: format!("request-{}", capability.id),
        agent_id: capability.subject.to_hex(),
        capability,
        tool_name: "invoke".to_string(),
        server_id: "restore-incarnation-server".to_string(),
        arguments: json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

fn restore_incarnation_operation(
    capability: CapabilityToken,
) -> chio_core::session::ToolCallOperation {
    chio_core::session::ToolCallOperation {
        capability,
        server_id: "restore-incarnation-server".to_string(),
        tool_name: "invoke".to_string(),
        arguments: json!({}),
        supplemental_authorization: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
        declassification_grant: None,
    }
}

fn threshold_product_request(
    kernel: &chio_kernel::ChioKernel,
    request_id: &str,
    capability: chio_core::capability::token::CapabilityToken,
    runtime_policy_hash: &str,
    proposal_authority: &Keypair,
    approvers: &[Keypair],
    approval_ids: &[&str],
) -> chio_kernel::ToolCallRequest {
    use chio_core::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        GovernedToolInvocationIntentBody, GovernedTransactionIntent,
    };
    use chio_core::capability::scope::MonetaryAmount;
    use chio_core::capability::threshold_approval::{
        ThresholdApprovalProposal, ThresholdApprovalProposalBody, ThresholdApprovalRequest,
    };

    let intent = GovernedTransactionIntent::tool_invocation(GovernedToolInvocationIntentBody {
        id: format!("intent-{request_id}"),
        server_id: "payments".to_string(),
        tool_name: "transfer".to_string(),
        purpose: "approved product transfer".to_string(),
        max_amount: Some(MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
    });
    let requirement = kernel
        .threshold_approval_requirement_resolver()
        .expect("product threshold resolver")
        .resolve_threshold_approval_requirement(
            &ThresholdApprovalRequest::new(request_id, "payments", "transfer")
                .expect("threshold request"),
            runtime_policy_hash,
        )
        .expect("threshold requirement");
    let intent_hash = intent.binding_hash().expect("governed intent hash");
    let capability_hash =
        chio_kernel::threshold_approval::authorization_capability_hash(&capability)
            .expect("authorization capability hash");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody::new(
            format!("proposal-{request_id}"),
            request_id,
            intent_hash.clone(),
            capability.subject.clone(),
            capability_hash,
            runtime_policy_hash,
            requirement.required(),
            requirement.eligible_set_digest(),
            now,
            requirement.proposal_timeout_seconds(),
            capability.expires_at,
            capability.expires_at,
        )
        .expect("threshold proposal body"),
        proposal_authority,
    )
    .expect("signed threshold proposal");
    let proposal_hash = proposal.proposal_hash().expect("threshold proposal hash");
    let deadline = proposal.body().proposal_deadline();
    let approval_tokens = approvers
        .iter()
        .zip(approval_ids)
        .map(|(approver, approval_id)| {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: (*approval_id).to_string(),
                    approver: approver.public_key(),
                    subject: capability.subject.clone(),
                    governed_intent_hash: intent_hash.clone(),
                    threshold_proposal_hash: Some(proposal_hash.clone()),
                    request_id: request_id.to_string(),
                    issued_at: now,
                    expires_at: deadline,
                    decision: GovernedApprovalDecision::Approved,
                },
                approver,
            )
            .expect("signed threshold approval")
        })
        .collect();
    let agent_id = capability.subject.to_hex();

    chio_kernel::ToolCallRequest {
        request_id: request_id.to_string(),
        capability,
        tool_name: "transfer".to_string(),
        server_id: "payments".to_string(),
        agent_id,
        arguments: json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(intent),
        approval_token: None,
        approval_tokens,
        threshold_approval_proposal: Some(proposal),
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

#[test]
fn remote_session_factory_requires_both_manifest_trust_inputs() {
    let config = test_remote_config();
    let error = match RemoteSessionFactory::new(config) {
        Ok(_) => panic!("missing signed manifest must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("publisher-signed manifest"));

    let mut config = test_remote_config();
    config.signed_manifest_path = Some(PathBuf::from("missing-signed-manifest.json"));
    let error = match RemoteSessionFactory::new(config) {
        Ok(_) => panic!("missing registered key must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("registered manifest public key"));
}

#[test]
fn broker_contract_is_hard_bound_to_the_resume_auth_fingerprint() {
    let config = test_remote_config();
    let without_broker = fingerprint_remote_auth_contract(&config, None, "runtime-contract-a")
        .expect("fingerprint broker-free remote auth contract");
    let broker_a =
        fingerprint_remote_auth_contract(&config, Some("broker-contract-a"), "runtime-contract-a")
            .expect("fingerprint first broker product contract");
    let broker_b =
        fingerprint_remote_auth_contract(&config, Some("broker-contract-b"), "runtime-contract-a")
            .expect("fingerprint second broker product contract");

    assert_ne!(without_broker, broker_a);
    assert_ne!(broker_a, broker_b);
}

#[test]
fn resume_runtime_contract_binds_registry_and_upstream_service_identity() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let upstream_directory = std::env::temp_dir().join(format!(
        "chio-remote-mcp-upstream-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&upstream_directory).expect("upstream fixture directory");
    let upstream_path = upstream_directory.join("upstream-service");
    std::fs::write(&upstream_path, b"upstream-service-a").expect("first upstream fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&upstream_path, std::fs::Permissions::from_mode(0o700))
            .expect("executable upstream fixture");
    }
    let mut config_a = test_remote_config();
    config_a.wrapped_command = upstream_path.to_string_lossy().into_owned();
    let path_a = configure_signed_manifest(&mut config_a);
    let factory_a = RemoteSessionFactory::new_for_local_manifest_test(config_a.clone())
        .expect("first admitted runtime contract");
    let baseline = factory_a.resume_runtime_contract_digest.clone();
    factory_a
        .require_current_resume_runtime_contract()
        .expect("unchanged runtime contract");

    let mut substituted_service = config_a.clone();
    substituted_service.wrapped_args = vec!["different-service-entrypoint".to_string()];
    let substituted_service = fingerprint_remote_runtime_contract(
        &substituted_service,
        factory_a.manifest_registry.as_ref(),
    )
    .expect("substituted service contract");
    assert_ne!(baseline, substituted_service);

    let mut substituted_launch_policy = config_a.clone();
    substituted_launch_policy.native_launch_factory = Arc::new(TestNativeLaunchFactory {
        authorization_digest: "22".repeat(32),
    });
    let substituted_launch_policy = fingerprint_remote_runtime_contract(
        &substituted_launch_policy,
        factory_a.manifest_registry.as_ref(),
    )
    .expect("substituted launch policy contract");
    assert_ne!(baseline, substituted_launch_policy);

    std::fs::write(&upstream_path, b"upstream-service-b").expect("substituted upstream fixture");
    let changed_runtime = factory_a
        .require_current_resume_runtime_contract()
        .expect_err("live upstream substitution must fail closed");
    assert!(changed_runtime
        .to_string()
        .contains("upstream service identity changed"));
    let substituted_upstream = config_a.clone();
    let substituted = fingerprint_remote_runtime_contract(
        &substituted_upstream,
        factory_a.manifest_registry.as_ref(),
    )
    .expect("substituted upstream contract");
    assert_ne!(baseline, substituted);

    let auth_baseline =
        fingerprint_remote_auth_contract(&config_a, None, &baseline).expect("baseline auth");
    let auth_substituted =
        fingerprint_remote_auth_contract(&config_a, None, &substituted).expect("substituted auth");
    assert_ne!(auth_baseline, auth_substituted);

    std::fs::write(&upstream_path, b"upstream-service-a")
        .expect("restore upstream fixture before registry substitution");

    let mut config_b = test_remote_config();
    config_b.wrapped_command = upstream_path.to_string_lossy().into_owned();
    let path_b = configure_signed_manifest(&mut config_b);
    let factory_b = RemoteSessionFactory::new_for_local_manifest_test(config_b)
        .expect("second admitted runtime contract");
    assert_ne!(baseline, factory_b.resume_runtime_contract_digest);

    std::fs::remove_file(path_a).expect("remove first manifest");
    std::fs::remove_file(path_b).expect("remove second manifest");
    std::fs::remove_file(upstream_path).expect("remove upstream fixture");
    std::fs::remove_dir(upstream_directory).expect("remove upstream fixture directory");
}

#[test]
fn remote_session_factory_derives_local_topology_for_wrapped_process() {
    let mut config = test_remote_config();
    let path = configure_signed_manifest(&mut config);
    let factory = RemoteSessionFactory::new(config)
        .unwrap_or_else(|error| panic!("construct local wrapped-process factory: {error}"));
    std::fs::remove_file(path).expect("remove explicit remote MCP test manifest");

    assert!(factory
        .manifest_registry
        .bridge_security("srv", "read")
        .is_some_and(|security| !security.effective_egress()));
}

#[test]
fn local_manifest_fixture_preserves_admitted_security_for_factory_tests() {
    let mut config = test_remote_config();
    let path = configure_signed_manifest(&mut config);
    let factory = RemoteSessionFactory::new_for_local_manifest_test(config)
        .unwrap_or_else(|error| panic!("construct verified local factory: {error}"));
    assert!(factory
        .manifest_registry
        .bridge_security("srv", "read")
        .is_some_and(|security| security.has_registry_coordinates()));
    std::fs::remove_file(path).expect("remove explicit remote MCP test manifest");
}

#[test]
fn remote_session_factory_rejects_flow_manifest_without_security_runtime() {
    let mut config = test_remote_config();
    let path = configure_signed_manifest_with_flow(
        &mut config,
        Some(chio_manifest::ToolFlowDeclaration::public_egress()),
    );
    let result = RemoteSessionFactory::new(config);
    std::fs::remove_file(path).expect("remove explicit remote MCP test manifest");

    let error = match result {
        Ok(_) => panic!("an unprotected remote factory must reject flow declarations"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("requires an installed active defense runtime"));
}

#[test]
fn remote_session_factory_has_one_process_wide_authority() {
    let mut config = test_remote_config();
    let path = configure_signed_manifest(&mut config);
    let factory = RemoteSessionFactory::new_for_local_manifest_test(config)
        .unwrap_or_else(|error| panic!("construct verified factory: {error}"));
    let selected = factory.authority_public_key();
    assert_eq!(factory.authority_public_key(), selected);
    assert_eq!(factory.kernel_keypair.public_key(), selected);
    std::fs::remove_file(path).expect("remove explicit remote MCP test manifest");
}

#[test]
fn remote_session_factory_accepts_local_authority_with_remote_control_plane() {
    let directory = tempfile::tempdir().expect("remote authority seed directory");
    let seed_path = directory.path().join("authority.seed");
    let local_authority = Keypair::from_seed(&[41_u8; 32]);
    chio_control_plane::persist_authority_keypair(&seed_path, &local_authority)
        .expect("persist remote authority seed");
    let mut config = test_remote_config();
    config.authority_seed_path = Some(seed_path);
    config.control_url = Some("https://control.example".to_string());
    config.control_token = Some("control-token".to_string());
    config.control_authority_public_key = Some(Keypair::generate().public_key());
    config.session_db_path = Some(directory.path().join("sessions.sqlite3"));
    config.policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/chio-cli/src/policies/code_agent.yaml");
    let manifest_path = configure_signed_manifest(&mut config);

    let factory = RemoteSessionFactory::new_for_local_manifest_test(config)
        .expect("local authority and remote control plane must compose");
    assert!(!factory.uses_remote_authority());
    assert_eq!(factory.kernel_keypair.public_key(), local_authority.public_key());
    assert!(factory.remote_control_authority_trust.is_none());
    assert!(factory.remote_authority_workload_signer.is_none());
    assert!(factory.remote_authority_session_admission_signer.is_none());
    let kernel = factory
        .compose_product_kernel(
            factory
                .load_configured_policy()
                .expect("load local-control policy"),
        )
        .expect("compose local authority with remote receipt and revocation stores");
    assert_eq!(kernel.public_key(), local_authority.public_key());
    std::fs::remove_file(manifest_path).expect("remove local-control test manifest");
}

#[test]
fn true_remote_authority_still_requires_every_custody_and_key_log_input() {
    let directory = tempfile::tempdir().expect("remote authority input directory");
    let mut config = test_remote_config();
    config.control_url = Some("https://control.example".to_string());
    config.control_token = Some("service-token".to_string());
    config.remote_authority_workload_token = Some("workload-token".to_string());
    config.control_authority_public_key = Some(Keypair::generate().public_key());
    config.remote_authority_tenant_id = Some("tenant-production-edge".to_string());
    config.remote_authority_workload_id = Some("workload-production-edge".to_string());
    config.remote_authority_workload_seed_path = Some(directory.path().join("workload.seed"));
    config.remote_authority_session_admission_seed_path =
        Some(directory.path().join("session-admission.seed"));
    config.remote_kernel_evidence_seed_path = Some(directory.path().join("kernel.seed"));
    config.control_authority_key_log_policy_path = Some(directory.path().join("key-log.json"));
    config.control_authority_key_log_verifier_db_path =
        Some(directory.path().join("verifier.sqlite3"));
    session_core_authority_mode::validate_remote_authority_factory_config(&config)
        .expect("complete remote authority inputs");

    for (label, mutated) in [
        ("workload token", {
            let mut value = config.clone();
            value.remote_authority_workload_token = None;
            value
        }),
        ("workload signer", {
            let mut value = config.clone();
            value.remote_authority_workload_seed_path = None;
            value
        }),
        ("session-admission signer", {
            let mut value = config.clone();
            value.remote_authority_session_admission_seed_path = None;
            value
        }),
        ("kernel signer", {
            let mut value = config.clone();
            value.remote_kernel_evidence_seed_path = None;
            value
        }),
        ("key-log policy", {
            let mut value = config.clone();
            value.control_authority_key_log_policy_path = None;
            value
        }),
        ("key-log verifier", {
            let mut value = config.clone();
            value.control_authority_key_log_verifier_db_path = None;
            value
        }),
    ] {
        let error = session_core_authority_mode::validate_remote_authority_factory_config(&mutated)
            .expect_err("incomplete remote authority custody must fail closed");
        assert!(
            error.to_string().contains("requires distinct service and workload tokens"),
            "missing {label} produced the wrong error: {error}"
        );
    }
}

#[test]
fn future_remote_kernels_reload_rotated_seed_authority() {
    let directory = tempfile::tempdir().expect("remote authority seed directory");
    let seed_path = directory.path().join("authority.seed");
    chio_control_plane::persist_authority_keypair(&seed_path, &Keypair::from_seed(&[44_u8; 32]))
        .expect("persist existing authority seed");
    let mut config = test_remote_config();
    config.policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/chio-cli/src/policies/code_agent.yaml");
    config.authority_seed_path = Some(seed_path.clone());
    let manifest_path = configure_signed_manifest(&mut config);
    let factory = RemoteSessionFactory::new_for_local_manifest_test(config)
        .expect("construct seed-backed remote factory");

    let existing_kernel = factory
        .compose_product_kernel(
            factory
                .load_configured_policy()
                .expect("load policy for existing seed-backed kernel"),
        )
        .expect("compose existing seed-backed kernel");
    let existing_public_key = existing_kernel.public_key();
    let rotated_public_key =
        rotate_authority_keypair(&seed_path).expect("rotate remote authority seed");
    assert_ne!(rotated_public_key, existing_public_key);

    let future_kernel = factory
        .compose_product_kernel(
            factory
                .load_configured_policy()
                .expect("load policy for future seed-backed kernel"),
        )
        .expect("compose future seed-backed kernel");
    assert_eq!(future_kernel.public_key(), rotated_public_key);
    assert_eq!(existing_kernel.public_key(), existing_public_key);

    std::fs::remove_file(&seed_path).expect("remove rotated authority seed");
    let missing_seed_result = factory.compose_product_kernel(
        factory
            .load_configured_policy()
            .expect("load policy for missing-seed rejection"),
    );
    assert!(missing_seed_result.is_err());
    std::fs::remove_file(manifest_path).expect("remove seed rotation test manifest");
}

#[test]
fn future_remote_kernels_reload_rotated_sqlite_authority() {
    let directory = tempfile::tempdir().expect("remote SQLite authority directory");
    let authority_db_path = directory.path().join("authority.sqlite3");
    drop(
        SqliteCapabilityAuthority::open(&authority_db_path)
            .expect("provision existing SQLite authority"),
    );
    let mut config = test_remote_config();
    config.policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/chio-cli/src/policies/code_agent.yaml");
    config.authority_db_path = Some(authority_db_path.clone());
    let manifest_path = configure_signed_manifest(&mut config);
    let factory = RemoteSessionFactory::new_for_local_manifest_test(config)
        .expect("construct SQLite-backed remote factory");

    let existing_kernel = factory
        .compose_product_kernel(
            factory
                .load_configured_policy()
                .expect("load policy for existing SQLite-backed kernel"),
        )
        .expect("compose existing SQLite-backed kernel");
    let existing_public_key = existing_kernel.public_key();
    let rotated_public_key = SqliteCapabilityAuthority::open_existing(&authority_db_path)
        .expect("open existing remote authority database")
        .rotate()
        .expect("rotate remote SQLite authority")
        .public_key;
    assert_ne!(rotated_public_key, existing_public_key);

    let future_kernel = factory
        .compose_product_kernel(
            factory
                .load_configured_policy()
                .expect("load policy for future SQLite-backed kernel"),
        )
        .expect("compose future SQLite-backed kernel");
    assert_eq!(future_kernel.public_key(), rotated_public_key);
    assert_eq!(existing_kernel.public_key(), existing_public_key);

    std::fs::remove_file(manifest_path).expect("remove SQLite rotation test manifest");
}

#[test]
fn remote_control_factory_accepts_existing_local_sqlite_authority() {
    let directory = tempfile::tempdir().expect("remote SQLite authority directory");
    let authority_db_path = directory.path().join("authority.sqlite3");
    let local_authority = SqliteCapabilityAuthority::open(&authority_db_path)
        .expect("provision local SQLite authority")
        .local_keypair()
        .expect("load local SQLite authority keypair");
    let mut config = test_remote_config();
    config.authority_db_path = Some(authority_db_path.clone());
    config.control_url = Some("https://control.example".to_string());
    config.control_token = Some("control-token".to_string());
    config.control_authority_public_key = Some(Keypair::generate().public_key());
    let manifest_path = configure_signed_manifest(&mut config);

    let factory = RemoteSessionFactory::new_for_local_manifest_test(config)
        .expect("local SQLite authority and remote control plane must compose");
    assert!(!factory.uses_remote_authority());
    assert_eq!(factory.kernel_keypair.public_key(), local_authority.public_key());
    assert!(authority_db_path.exists());
    std::fs::remove_file(manifest_path).expect("remove local SQLite control test manifest");
}

#[test]
fn remote_factory_validates_complete_inputs_successors_and_cross_role_key_collisions() {
    let directory = tempfile::tempdir().expect("remote authority role directory");
    let current = Keypair::from_seed(&[80_u8; 32]);
    let historical = Keypair::from_seed(&[81_u8; 32]);
    let successor = Keypair::from_seed(&[82_u8; 32]);
    let workload = Keypair::from_seed(&[83_u8; 32]);
    let session_admission = Keypair::from_seed(&[84_u8; 32]);
    let kernel_evidence = Keypair::from_seed(&[85_u8; 32]);
    let persist = |name: &str, keypair: &Keypair| {
        let path = directory.path().join(name);
        chio_control_plane::persist_authority_keypair(&path, keypair)
            .unwrap_or_else(|error| panic!("persist {name}: {error}"));
        path
    };
    let workload_path = persist("workload.seed", &workload);
    let session_admission_path = persist("session-admission.seed", &session_admission);
    let kernel_evidence_path = persist("kernel-evidence.seed", &kernel_evidence);
    let mut config = test_remote_config();
    config.control_url = Some("https://control.example".to_string());
    config.control_token = Some("service-token".to_string());
    config.remote_authority_workload_token = Some("workload-token".to_string());
    config.control_authority_public_key = Some(current.public_key());
    config.control_authority_trusted_public_keys = vec![historical.public_key()];
    config.control_authority_successors = vec![
        trust_control::service_runtime::PinnedAuthoritySuccessor {
            generation: 2,
            public_key: successor.public_key(),
        },
    ];
    config.remote_authority_tenant_id = Some("tenant-production-edge".to_string());
    config.remote_authority_workload_id = Some("workload-production-edge".to_string());
    config.remote_authority_workload_seed_path = Some(workload_path);
    config.remote_authority_session_admission_seed_path = Some(session_admission_path);
    config.remote_kernel_evidence_seed_path = Some(kernel_evidence_path);
    config.control_authority_key_log_policy_path = Some(directory.path().join("key-log-policy.json"));
    config.control_authority_key_log_verifier_db_path =
        Some(directory.path().join("key-log-verifier.sqlite3"));

    session_core_authority_mode::validate_remote_authority_factory_config(&config)
        .expect("complete remote authority configuration");
    assert_eq!(config.control_authority_successors.len(), 1);
    assert_eq!(
        config.control_authority_successors[0].public_key,
        successor.public_key()
    );
    session_core_authority_mode::validate_remote_authority_role_keys(
        &config,
        &workload.public_key(),
        &session_admission.public_key(),
        &kernel_evidence.public_key(),
    )
    .expect("distinct remote authority signer roles");

    for (role, collision) in [
        ("workload", current.clone()),
        ("session-admission", historical.clone()),
        ("kernel-evidence", successor.clone()),
    ] {
        let (workload_key, session_key, kernel_key) = match role {
            "workload" => (
                collision.public_key(),
                session_admission.public_key(),
                kernel_evidence.public_key(),
            ),
            "session-admission" => (
                workload.public_key(),
                collision.public_key(),
                kernel_evidence.public_key(),
            ),
            "kernel-evidence" => (
                workload.public_key(),
                session_admission.public_key(),
                collision.public_key(),
            ),
            _ => panic!("unknown signer role"),
        };
        let error = session_core_authority_mode::validate_remote_authority_role_keys(
            &config,
            &workload_key,
            &session_key,
            &kernel_key,
        )
        .expect_err("cross-role signer collision must fail closed");
        assert!(error.to_string().contains("signer roles require distinct keys"));
    }
}

#[tokio::test]
async fn ready_factory_rejects_policy_drift_before_session_admission() {
    let directory = tempfile::tempdir().expect("remote policy directory");
    let policy_path = directory.path().join("policy.yaml");
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/chio-cli/src/policies/code_agent.yaml");
    let original = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|error| panic!("read policy fixture {}: {error}", fixture_path.display()));
    std::fs::write(&policy_path, &original).expect("write pinned remote policy");
    let mut config = test_remote_config();
    config.policy_path = policy_path.clone();
    let manifest_path = configure_signed_manifest(&mut config);
    let factory = RemoteSessionFactory::new_ready_for_local_manifest_test(config)
        .await
        .expect("construct ready factory with pinned policy");

    let changed = original.replacen("max_capability_ttl: 3600", "max_capability_ttl: 7200", 1);
    assert_ne!(changed, original);
    std::fs::write(&policy_path, changed).expect("replace pinned remote policy");
    let auth_context = SessionAuthContext::streamable_http_static_bearer(
        "agent-policy-drift",
        "token-policy-drift",
        None,
    );
    let error = match factory.spawn_session(auth_context) {
        Ok(_) => panic!("a changed policy must not admit a remote session"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("policy or active-defense rule material changed after startup"));

    std::fs::remove_file(manifest_path).expect("remove explicit remote MCP policy-drift manifest");
}

#[test]
fn remote_product_constructor_preserves_two_of_three_replay_denial_across_restart_without_broker() {
    use chio_core::capability::scope::{
        ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant,
    };

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "chio-remote-threshold-product-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create threshold product directory");
    let policy_path = root.join("policy.yaml");
    let approver_directory_path = root.join("approvers.yaml");
    let operation_path = root.join("admission-operations.sqlite3");
    let approval_path = root.join("approvals.sqlite3");
    let budget_path = root.join("budgets.sqlite3");
    let authority_seed_path = root.join("authority.seed");
    let approvers = [
        Keypair::from_seed(&[81_u8; 32]),
        Keypair::from_seed(&[82_u8; 32]),
        Keypair::from_seed(&[83_u8; 32]),
    ];
    let proposal_authority = Keypair::from_seed(&[84_u8; 32]);
    std::fs::write(
            &policy_path,
            format!(
                "hushspec: \"0.1.0\"\nextensions:\n  chio:\n    human_in_loop:\n      approvers:\n        n: 2\n        of:\n          - \"{}\"\n          - \"{}\"\n          - \"{}\"\n",
                approvers[0].public_key().to_hex(),
                approvers[1].public_key().to_hex(),
                approvers[2].public_key().to_hex(),
            ),
        )
        .expect("write threshold product policy");
    std::fs::write(
        &approver_directory_path,
        format!(
            "version: 9\napprover_ids:\n  - \"{}\"\n  - \"{}\"\n  - \"{}\"\n",
            approvers[0].public_key().to_hex(),
            approvers[1].public_key().to_hex(),
            approvers[2].public_key().to_hex(),
        ),
    )
    .expect("write authenticated approver directory");

    let mut config = test_remote_config();
    let manifest_path = configure_signed_manifest(&mut config);
    config.policy_path = policy_path;
    config.authority_seed_path = Some(authority_seed_path);
    config.receipt_db_path = Some(root.join("receipts.sqlite3"));
    config.approver_directory_path = Some(approver_directory_path);
    config.threshold_proposal_authority_public_key = Some(proposal_authority.public_key());
    config.admission_operation_db_path = Some(operation_path);
    config.approval_db_path = Some(approval_path);
    config.budget_db_path = Some(budget_path);

    let factory = RemoteSessionFactory::new_for_local_manifest_test(config.clone())
        .expect("construct threshold product factory");
    let loaded = factory
        .load_configured_policy()
        .expect("load configured threshold policy");
    let runtime_policy_hash = loaded.identity.runtime_hash.clone();
    let mut kernel = factory
        .compose_product_kernel(loaded)
        .expect("compose threshold product kernel");
    kernel.register_tool_server(Box::new(ThresholdProductServer));
    let subject = Keypair::from_seed(&[85_u8; 32]);
    let capability = kernel
        .issue_capability(
            &subject.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "payments".to_string(),
                    tool_name: "transfer".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![
                        Constraint::GovernedIntentRequired,
                        Constraint::RequireApprovalAbove {
                            threshold_units: 50,
                        },
                    ],
                    max_invocations: None,
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 1_000,
                        currency: "USD".to_string(),
                    }),
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            3_600,
        )
        .expect("issue governed product capability");
    let first = threshold_product_request(
        &kernel,
        "threshold-before-restart",
        capability.clone(),
        &runtime_policy_hash,
        &proposal_authority,
        &approvers[..2],
        &["approval-replay-a", "approval-replay-b"],
    );
    let allowed = kernel
        .evaluate_tool_call_blocking(&first)
        .expect("first threshold product evaluation");
    assert_eq!(allowed.verdict, chio_kernel::Verdict::Allow);
    drop(kernel);
    drop(factory);

    let restarted_factory = RemoteSessionFactory::new_for_local_manifest_test(config)
        .expect("reconstruct threshold product factory");
    let loaded = restarted_factory
        .load_configured_policy()
        .expect("reload configured threshold policy");
    let mut restarted = restarted_factory
        .compose_product_kernel(loaded)
        .expect("recompose threshold product kernel");
    restarted.register_tool_server(Box::new(ThresholdProductServer));
    let replay = threshold_product_request(
        &restarted,
        "threshold-after-restart",
        capability,
        &runtime_policy_hash,
        &proposal_authority,
        &approvers[..2],
        &["approval-replay-a", "approval-replay-b"],
    );
    let denial_reason = match restarted.evaluate_tool_call_blocking(&replay) {
        Ok(response) => {
            assert_eq!(response.verdict, chio_kernel::Verdict::Deny);
            response.reason.unwrap_or_default()
        }
        Err(error) => error.to_string(),
    };
    assert!(
        denial_reason.contains("approval token") || denial_reason.contains("replay"),
        "unexpected post-restart replay denial: {denial_reason}"
    );
    drop(restarted);
    drop(restarted_factory);

    std::fs::remove_file(manifest_path).expect("remove threshold product manifest");
    std::fs::remove_dir_all(root).expect("remove threshold product directory");
}

include!("authorization_and_resume.rs");
include!("lifecycle_and_identity.rs");
include!("transport_and_security.rs");
