use super::*;

pub(super) struct BoundaryAuthority;

impl BrokerAuthorityHandler for BoundaryAuthority {
    fn handle(&self, operation: &AuthorityOperation) -> Result<AuthorityResult> {
        match operation {
            AuthorityOperation::Capabilities => Ok(AuthorityResult::Capabilities(
                ExecutionAuthorityCapabilities {
                    profile: ExecutionAuthorityProfile::AuthoritativeHoldEvent,
                    atomic_multi_key_holds: true,
                    combined_capture_and_revocation: true,
                    query_by_id: true,
                    shared_revocation_write_domain: true,
                },
            )),
            AuthorityOperation::PrepareExecution(request) => Ok(AuthorityResult::Prepared(
                trusted_execution_context(request.as_ref())?,
            )),
            AuthorityOperation::VerifyLiveParent(request) => {
                Ok(AuthorityResult::LiveParent(LiveParentCapability {
                    capability_id: request.parent_capability_id.clone(),
                    subject: request.expected_subject.clone(),
                    audience: request.expected_audience.clone(),
                    delegation_ancestor_ids: vec![
                        "ancestor-capability-process-boundary".to_string()
                    ],
                    expires_at_unix_seconds: request.now_unix_seconds.checked_add(600).ok_or_else(
                        || BrokerError::Invariant("parent expiry overflowed".to_string()),
                    )?,
                    verified_at_unix_seconds: request.now_unix_seconds,
                    authority_snapshot_digest: "aa".repeat(32),
                }))
            }
            AuthorityOperation::CheckBrokerRevocation(request) => {
                Ok(AuthorityResult::Revocation(BrokerRevocationSnapshot {
                    revoked: false,
                    observed_at_unix_seconds: request.now_unix_seconds,
                    commit_index: 7,
                    authority_domain: AUTHORITY_DOMAIN.to_string(),
                }))
            }
            AuthorityOperation::QueryExecutionHold(_) => {
                Ok(AuthorityResult::Hold(ExecutionHoldState::Held))
            }
            AuthorityOperation::AuthorizeExecutionHold(_) => {
                Ok(AuthorityResult::Hold(ExecutionHoldState::Held))
            }
            AuthorityOperation::ReverseExecutionHold(_) => {
                Ok(AuthorityResult::Hold(ExecutionHoldState::Reversed))
            }
            AuthorityOperation::CaptureExecutionHold(request) => Ok(AuthorityResult::Hold(
                ExecutionHoldState::Captured(CombinedCaptureCommit {
                    checked_revocation_set_digest: request.revocation_set_digest.clone(),
                    budget_commit_index: 101,
                    revocation_commit_index: 102,
                    authority_commit_index: 103,
                    leader_epoch: 104,
                }),
            )),
            AuthorityOperation::Control(_) => Err(BrokerError::AuthorizationDenied(
                "process-boundary authority rejects control operations".to_string(),
            )),
        }
    }
}

fn boundary_quotas(request: &BrokerExecuteRequest) -> Result<Vec<ExecutionQuota>> {
    canonicalize_quotas(vec![
        ExecutionQuota {
            key_id: request.capability.body.broker_quota_key_id.clone(),
            maximum_executions: request.capability.body.maximum_executions,
        },
        ExecutionQuota {
            key_id: PARENT_QUOTA_KEY.to_string(),
            maximum_executions: 4,
        },
    ])
}

pub(super) fn boundary_registration(request: &BrokerExecuteRequest) -> Result<AttemptRegistration> {
    let request_digest = broker_request_digest(request)?;
    let ids = derive_attempt_ids_for_operation(
        &request.capability.body.capability_id,
        &request.invocation_id,
        &request.proof.body.nonce,
        &request_digest,
        OPERATION_ID,
    )?;
    let nonce_expires_at_unix_seconds = request
        .proof
        .body
        .issued_at_unix_seconds
        .checked_add(request.capability.body.proof.nonce_ttl_seconds)
        .ok_or_else(|| BrokerError::Invariant("proof nonce expiry overflowed".to_string()))?;
    let registration = AttemptRegistration {
        ids,
        invocation_id: request.invocation_id.clone(),
        parent_capability_id: request.capability.body.parent_capability_id.clone(),
        broker_capability_id: request.capability.body.capability_id.clone(),
        request_digest,
        request_canonical_digest: broker_execute_request_registration_digest(request)?,
        proof_digest: proof_digest(&request.proof)?,
        proof_key_id: request.proof.body.authority_key.to_hex(),
        proof_nonce: request.proof.body.nonce.clone(),
        nonce_expires_at_unix_seconds,
        quotas: boundary_quotas(request)?,
        authority_metadata_digest: "bb".repeat(32),
        revocation_authority_domain: AUTHORITY_DOMAIN.to_string(),
    };
    registration.validate()?;
    Ok(registration)
}

fn trusted_execution_context(request: &BrokerExecuteRequest) -> Result<TrustedExecutionContext> {
    let registration = boundary_registration(request)?;
    Ok(TrustedExecutionContext {
        admission_operation_id: OPERATION_ID.to_string(),
        prepared_dispatch_id: prepared_dispatch_id(&registration, request)?,
        quotas: registration.quotas,
        authority_metadata_digest: "bb".repeat(32),
        revocation_authority_domain: AUTHORITY_DOMAIN.to_string(),
        source_receipt_ids: vec!["source-receipt-process-boundary".to_string()],
    })
}

pub(super) struct AuthorityServerGuard {
    stop: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl AuthorityServerGuard {
    pub(super) fn start(server: AuthorityRpcServer) -> Self {
        server
            .set_nonblocking(true)
            .test_expect("nonblocking authority server");
        let stop = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_failed = Arc::clone(&failed);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match server.try_serve_one() {
                    Ok(true) => {}
                    Ok(false) => thread::sleep(Duration::from_millis(2)),
                    Err(_) => {
                        thread_failed.store(true, Ordering::Release);
                        return;
                    }
                }
            }
        });
        Self {
            stop,
            failed,
            thread: Some(thread),
        }
    }

    pub(super) fn assert_healthy(&self) {
        assert!(!self.failed.load(Ordering::Acquire));
    }

    pub(super) fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().test_expect("authority server thread");
        }
        self.assert_healthy();
    }
}

impl Drop for AuthorityServerGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(super) fn sealed_seed(name: &str, seed: &[u8; 32]) -> File {
    let descriptor = memfd_create(name, MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC)
        .test_expect("sealed memfd");
    let mut file = File::from(descriptor);
    assert!(fcntl_getfd(&file)
        .test_expect("sealed seed descriptor flags")
        .contains(FdFlags::CLOEXEC));
    file.write_all(seed).test_expect("sealed seed write");
    file.seek(SeekFrom::Start(0))
        .test_expect("sealed seed seek");
    fcntl_add_seals(
        &file,
        SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
    )
    .test_expect("sealed seed seals");
    let read_only = File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .test_expect("reopen sealed seed read-only");
    assert!(fcntl_getfd(&read_only)
        .test_expect("read-only sealed seed descriptor flags")
        .contains(FdFlags::CLOEXEC));
    read_only
}

pub(super) fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).test_expect("private test file write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .test_expect("private test file permissions");
}

fn enforced_broker_migration(directory: &Path) -> BrokerDaemonMigrationConfig {
    let directory = fs::canonicalize(directory).test_expect("canonical migration directory");
    let state_database_path = directory.join("enterprise-migration.sqlite3");
    let signer = Keypair::from_seed(&[159; 32]);
    let store = SqliteEnterpriseMigrationStateStore::open(
        &state_database_path,
        SqliteEnterpriseMigrationOpenPolicy::new(vec![signer.public_key()], Vec::new())
            .test_expect("migration open policy"),
    )
    .test_expect("open migration ledger");
    let deployment_id = RecordId::new(DEPLOYMENT_ID).test_expect("migration deployment identifier");
    let credential_provider =
        RecordId::new(CREDENTIAL_PROVIDER).test_expect("migration provider identifier");
    let mut minimum_heads = Vec::new();
    for (control, seed) in [
        (EnterpriseMigrationControl::BrokerCredentialCustody, 0x41_u8),
        (EnterpriseMigrationControl::BrokerQuotaEnforcement, 0x51_u8),
    ] {
        let key = EnterpriseMigrationKey {
            deployment_id: deployment_id.clone(),
            scope_kind: EnterpriseMigrationScopeKind::Provider,
            scope_id: credential_provider.clone(),
            control,
        };
        let genesis = EnterpriseMigrationTransitionBody::genesis(
            key.clone(),
            production_broker_migration_posture_digest(
                &deployment_id,
                &credential_provider,
                control,
                EnterpriseMigrationStage::Disabled,
            )
            .test_expect("disabled migration posture"),
            Digest32::new([seed; 32]),
            Digest32::new([seed.saturating_add(1); 32]),
            Digest32::new([seed.saturating_add(2); 32]),
            1,
            signer.public_key().to_hex(),
        )
        .test_expect("migration genesis");
        let genesis = sign_enterprise_migration_transition(genesis, &signer)
            .test_expect("signed migration genesis");
        let _ = store
            .register(&genesis)
            .test_expect("registered migration genesis");
        let mut state = store
            .load(&key)
            .test_expect("loaded migration genesis")
            .test_expect("migration genesis exists");
        while state.stage < EnterpriseMigrationStage::Enforced {
            let next_stage = state.stage.next().test_expect("next migration stage");
            let generation = next_stage.generation();
            let promotion = EnterpriseMigrationTransitionBody::promotion(
                &state,
                production_broker_migration_posture_digest(
                    &deployment_id,
                    &credential_provider,
                    control,
                    next_stage,
                )
                .test_expect("promoted migration posture"),
                Digest32::new([seed.saturating_add(generation as u8 * 3); 32]),
                Digest32::new([seed.saturating_add(generation as u8 * 3 + 1); 32]),
                Digest32::new([seed.saturating_add(generation as u8 * 3 + 2); 32]),
                generation + 1,
                signer.public_key().to_hex(),
            )
            .test_expect("migration promotion");
            let promotion = sign_enterprise_migration_transition(promotion, &signer)
                .test_expect("signed migration promotion");
            let _ = store
                .compare_and_promote(&promotion)
                .test_expect("promoted migration state");
            state = store
                .load(&key)
                .test_expect("loaded promoted migration state")
                .test_expect("promoted migration state exists");
        }
        minimum_heads.push(state.minimum_head());
    }
    minimum_heads.sort_unstable();
    drop(store);
    fs::set_permissions(&state_database_path, fs::Permissions::from_mode(0o600))
        .test_expect("migration ledger permissions");
    BrokerDaemonMigrationConfig {
        state_database_path,
        deployment_id,
        credential_provider,
        trusted_transition_signers: vec![signer.public_key()],
        minimum_heads,
        credential_custody_stage: EnterpriseMigrationStage::Enforced,
        quota_enforcement_stage: EnterpriseMigrationStage::Enforced,
    }
}

pub(super) struct BoundaryFixture {
    pub(super) config: BrokerDaemonConfig,
    pub(super) config_path: PathBuf,
    pub(super) certificate_path: PathBuf,
    pub(super) private_key_path: PathBuf,
    pub(super) fallback_marker_path: PathBuf,
    pub(super) approver: Keypair,
    pub(super) admin_subject: chio_core_types::PublicKey,
}

pub(super) fn boundary_fixture(
    directory: &Path,
    upstream_port: u16,
    broker_identity: chio_core_types::PublicKey,
    capability_issuer: chio_core_types::PublicKey,
    authority_identity: chio_core_types::PublicKey,
    service_uid: u32,
) -> BoundaryFixture {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec![UPSTREAM_HOST.to_string()])
            .test_expect("process-boundary certificate");
    let certificate_path = directory.join("upstream-cert.der");
    let private_key_path = directory.join("upstream-key.der");
    write_private(&certificate_path, cert.der().as_ref());
    write_private(&private_key_path, &key_pair.serialize_der());
    let approver = Keypair::from_seed(&[205; 32]);
    let admin_subject = Keypair::from_seed(&[206; 32]).public_key();
    let broker_socket = directory.join("broker.sock");
    let authority_socket = directory.join("authority.sock");
    let audit_socket = directory.join("privileged-audit").join("audit.sock");
    let config = BrokerDaemonConfig {
        schema: BROKER_DAEMON_CONFIG_SCHEMA.to_string(),
        deployment_id: DEPLOYMENT_ID.to_string(),
        broker_instance_id: BROKER_INSTANCE_ID.to_string(),
        tenant_scope: TENANT_SCOPE.to_string(),
        audit_runner_id: "audit-runner-process-boundary".to_string(),
        trusted_audit_runner: Keypair::from_seed(&[207; 32]).public_key(),
        ipc_socket_path: broker_socket,
        authority_socket_path: authority_socket,
        trusted_capability_issuer: capability_issuer,
        trusted_authority: authority_identity,
        broker_identity,
        broker_audience: BROKER_AUDIENCE.to_string(),
        parent_audience: PARENT_AUDIENCE.to_string(),
        provider_adapter_id: PROVIDER_ADAPTER_ID.to_string(),
        provider_adapter_version: 1,
        provider_placement: ProviderPlacementConfig::BearerAuthorization,
        trusted_service_uid: service_uid,
        authorized_client_uid: service_uid,
        ipc_read_timeout_ms: 3_000,
        ipc_write_timeout_ms: 3_000,
        authority_timeout_ms: 3_000,
        maximum_clock_skew_seconds: 30,
        maximum_liveness_snapshot_age_seconds: 30,
        maximum_revocation_snapshot_age_seconds: 30,
        databases: BrokerDaemonDatabaseConfig {
            secret_database_path: directory.join("secrets.sqlite3"),
            attempt_database_path: directory.join("attempts.sqlite3"),
            admin_replay_database_path: directory.join("admin.sqlite3"),
            receipt_database_path: directory.join("receipts.sqlite3"),
        },
        enterprise_migration: enforced_broker_migration(directory),
        admin: BrokerDaemonAdminConfig {
            trusted_approvers: vec![approver.public_key()],
            subject: admin_subject.clone(),
            threshold: 1,
            maximum_token_lifetime_seconds: 120,
        },
        privileged_audit: BrokerDaemonPrivilegedAuditConfig {
            socket_path: audit_socket,
            authorized_runner_uid: service_uid,
            authorized_runner_gid: rustix::process::getegid().as_raw(),
            read_timeout_ms: 3_000,
            write_timeout_ms: 3_000,
            authorization_lifetime_seconds: 30,
        },
    };
    let config_path = directory.join("broker-config.json");
    write_private(
        &config_path,
        &canonical_json_bytes(&config).test_expect("canonical broker config"),
    );
    let fallback_marker_path = directory.join(format!("fallback-complete-{upstream_port}"));
    BoundaryFixture {
        config,
        config_path,
        certificate_path,
        private_key_path,
        fallback_marker_path,
        approver,
        admin_subject,
    }
}

pub(super) fn random_canary() -> Vec<u8> {
    let mut random = [0_u8; 32];
    OsRng.fill_bytes(&mut random);
    format!("credential-canary-{}", hex::encode(random)).into_bytes()
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("system clock")
        .as_secs()
}

pub(super) fn provision_credential(
    socket_path: &Path,
    credential: &CredentialRef,
    canary: &[u8],
    approver: &Keypair,
    admin_subject: &chio_core_types::PublicKey,
) -> IpcResponse {
    let payload = encode_credential_mutation_payload(IpcOperation::Provision, credential, canary)
        .test_expect("credential provisioning payload");
    let intent = daemon_admin_intent_digest(IpcOperation::Provision, TENANT_SCOPE, &payload)
        .test_expect("credential provisioning intent");
    let now = now_unix_seconds();
    let approval = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "approval-process-boundary".to_string(),
            approver: approver.public_key(),
            subject: admin_subject.clone(),
            governed_intent_hash: intent,
            threshold_proposal_hash: Some("dd".repeat(32)),
            request_id: "admin-request-process-boundary".to_string(),
            issued_at: now.saturating_sub(1),
            expires_at: now + 60,
            decision: GovernedApprovalDecision::Approved,
        },
        approver,
    )
    .test_expect("credential provisioning approval");
    let authorization = GovernedAdminAuthorizationEnvelope::new(vec![approval])
        .test_expect("credential provisioning envelope")
        .canonical_bytes()
        .test_expect("credential provisioning authorization");
    let frame = canonical_ipc_request_bytes(&AuthenticatedIpcRequest {
        operation: IpcOperation::Provision,
        tenant_scope: TENANT_SCOPE.to_string(),
        authorization: authorization.into(),
        payload: payload.into(),
    })
    .test_expect("credential provisioning frame");
    let mut stream = UnixStream::connect(socket_path).test_expect("credential provisioning socket");
    write_bounded_frame(&mut stream, &frame).test_expect("credential provisioning request");
    let response = read_bounded_frame(&mut stream).test_expect("credential provisioning response");
    CanaryProbe::from_bytes(canary)
        .assert_absent(&response, "credential provisioning IPC response");
    let envelope: IpcResponse =
        serde_json::from_slice(&response).test_expect("credential provisioning envelope");
    assert!(envelope.accepted);
    assert_eq!(envelope.operation, IpcOperation::Provision);
    envelope
}

pub(super) fn execution_request(
    port: u16,
    credential: CredentialRef,
    issuer: &Keypair,
    caller: &Keypair,
) -> BrokerExecuteRequest {
    let destination = BrokerDestination::parse(
        &format!("https://{UPSTREAM_HOST}:{port}{UPSTREAM_PATH_AND_QUERY}"),
        "POST",
        false,
    )
    .test_expect("process-boundary destination");
    let body = UPSTREAM_REQUEST_BODY.to_vec();
    let request = BrokerRequest {
        destination: destination.clone(),
        headers: Vec::new(),
        body: body.clone(),
        approved_preview_sha256: None,
        options: CallerOptions {
            timeout_ms: 3_000,
            streaming: false,
            response_limit_bytes: 1_024,
        },
    };
    let now = now_unix_seconds();
    let capability = issue_capability(
        BrokerCapabilityBody {
            schema: BROKER_CAPABILITY_SCHEMA.to_string(),
            issuer: issuer.public_key(),
            capability_id: "broker-capability-process-boundary".to_string(),
            parent_capability_id: "parent-capability-process-boundary".to_string(),
            subject: caller.public_key(),
            audience: BROKER_AUDIENCE.to_string(),
            issued_at_unix_seconds: now.saturating_sub(1),
            not_before_unix_seconds: now.saturating_sub(1),
            expires_at_unix_seconds: now + 120,
            credential,
            provider_adapter_id: PROVIDER_ADAPTER_ID.to_string(),
            provider_adapter_version: 1,
            destination,
            constraints: RequestConstraints {
                allowed_caller_headers: Vec::new(),
                provider_owned_headers: vec!["authorization".to_string()],
                maximum_body_bytes: body.len() as u64,
                required_body_sha256: body_digest(&body),
                required_preview_sha256: None,
                redirect_policy: RedirectPolicy::Disabled,
                maximum_response_bytes: 1_024,
                streaming_allowed: false,
                maximum_timeout_ms: 3_000,
            },
            broker_quota_key_id: BROKER_QUOTA_KEY.to_string(),
            maximum_executions: 1,
            consumption: AttemptConsumption::CaptureBeforeDispatch,
            revocation_id: "broker-revocation-process-boundary".to_string(),
            proof: ProofBinding {
                mode: ProofMode::PublicKey,
                caller_public_key: caller.public_key(),
                nonce_ttl_seconds: 60,
            },
        },
        &Ed25519Backend::new(issuer.clone()),
        true,
    )
    .test_expect("process-boundary capability");
    let proof = issue_request_proof(
        &capability,
        &request,
        "nonce-process-boundary-0001".to_string(),
        now,
        caller,
    )
    .test_expect("process-boundary request proof");
    BrokerExecuteRequest {
        schema: BROKER_EXECUTE_SCHEMA.to_string(),
        invocation_id: "invocation-process-boundary".to_string(),
        capability,
        proof,
        request,
    }
}

pub(super) fn execute_frame(request: &BrokerExecuteRequest) -> Vec<u8> {
    canonical_ipc_request_bytes(&AuthenticatedIpcRequest {
        operation: IpcOperation::Execute,
        tenant_scope: TENANT_SCOPE.to_string(),
        authorization: canonical_json_bytes(&request.proof)
            .test_expect("execute proof authorization")
            .into(),
        payload: canonical_json_bytes(request)
            .test_expect("execute request payload")
            .into(),
    })
    .test_expect("execute IPC frame")
    .to_vec()
}
