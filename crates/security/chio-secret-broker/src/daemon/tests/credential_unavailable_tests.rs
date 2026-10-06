//! Real governed daemon requests and endpoint containment for unavailable credentials.
use super::*;
use crate::service::{
    canonical_ipc_request_bytes, read_bounded_frame, write_bounded_frame, BrokerIpcServeOutcome,
    UnixBrokerEndpoint,
};
use crate::store::AttemptStore;
use std::{os::unix::net::UnixStream, path::PathBuf, time::Duration};

#[path = "execute_cause_tests.rs"]
mod execute_cause_tests;

struct Fixture {
    directory: tempfile::TempDir,
    _admin_directory: tempfile::TempDir,
    attempts: Arc<SqliteAttemptStore>,
    service: Arc<BrokerService>,
    endpoint: UnixBrokerEndpoint,
    socket_path: PathBuf,
    secret_path: PathBuf,
    approver: Keypair,
    admin_subject: chio_core_types::PublicKey,
    issuer: Keypair,
    caller: Keypair,
    authority_signer: Keypair,
    observed_authorization: Arc<Mutex<Option<Vec<u8>>>>,
    dispatch_calls: Arc<AtomicU64>,
}

impl Fixture {
    fn new() -> Self {
        let directory = crate::private_tempdir().test_expect("private database directory");
        let root = std::fs::canonicalize(directory.path()).test_expect("canonical directory");
        let secret_path = root.join("secrets.sqlite3");
        let attempts = Arc::new(
            SqliteAttemptStore::open(root.join("attempts.sqlite3")).test_expect("attempt database"),
        );
        let canary = b"f011_secret_canary".to_vec();
        let backend = Arc::new(
            EncryptedBlobSecretBackend::open_with_tenant_key(
                &secret_path,
                "tenant-production".into(),
                chio_store_sqlite::TenantKey::from_bytes([81; 32]),
            )
            .test_expect("backend"),
        );
        let issuer = Keypair::from_seed(&[82; 32]);
        let caller = Keypair::from_seed(&[83; 32]);
        let receipt_signer = Keypair::from_seed(&[84; 32]);
        let authority_signer = Keypair::from_seed(&[87; 32]);
        let receipt_signing_backend: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(receipt_signer));
        let authority = Arc::new(FakeAuthority {
            control_calls: AtomicU64::new(0),
            prepare_calls: AtomicU64::new(0),
        });
        let budget: Arc<dyn BrokerExecutionBudget> = authority.clone();
        let liveness: Arc<dyn CapabilityLiveness> = authority.clone();
        let revocations: Arc<dyn BrokerRevocations> = authority.clone();
        let observed_authorization = Arc::new(Mutex::new(None));
        let dispatch_calls = Arc::new(AtomicU64::new(0));
        let service = Arc::new(
            BrokerService::new_for_test(
                BrokerServiceConfig {
                    audience: "broker-service-production".to_string(),
                    parent_audience: "parent-service-production".to_string(),
                    maximum_clock_skew_seconds: 1,
                    maximum_liveness_snapshot_age_seconds: 1,
                    maximum_revocation_snapshot_age_seconds: 1,
                },
                attempts.clone(),
                BrokerServiceAuthorityBundle {
                    trusted_issuer: issuer.public_key(),
                    backend: Arc::clone(&backend),
                    provider: Arc::new(
                        GenericCredentialProvider::new(
                            "generic-bearer".to_string(),
                            1,
                            CredentialPlacement::BearerAuthorization,
                        )
                        .test_expect("provider"),
                    ),
                    https: Arc::new(GenericHttpsExecutor::new(
                        Arc::new(Resolver),
                        Arc::new(execute_cause_tests::CountedTransport::new(
                            Arc::clone(&observed_authorization),
                            Arc::clone(&dispatch_calls),
                        )),
                        NetworkPolicy::production(),
                    )),
                    budget,
                    liveness,
                    revocations,
                    receipt_sink: Arc::new(InspectingReceiptSink {
                        canary: canary.clone(),
                        failures: Mutex::new(BTreeMap::new()),
                        completed: Mutex::new(BTreeMap::new()),
                    }),
                    receipt_signer: Arc::clone(&receipt_signing_backend),
                    migration_enforcer: crate::migration::TestBrokerMigrationEnforcer::new(vec![
                        "generic-https".to_string(),
                    ]),
                },
            )
            .test_expect("service"),
        );
        let admin_directory = crate::private_tempdir().test_expect("admin directory");
        #[cfg(unix)]
        std::fs::set_permissions(
            admin_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .test_expect("harden admin database directory");
        let trusted_admin_directory = std::fs::canonicalize(admin_directory.path())
            .test_expect("canonicalize admin database directory");
        let approver = Keypair::from_seed(&[85; 32]);
        let admin_subject = Keypair::from_seed(&[86; 32]).public_key();
        let admin = Arc::new(
            GovernedAdminAuthorizer::open(
                trusted_admin_directory.join("admin.sqlite3"),
                GovernedAdminPolicy {
                    trusted_approvers: vec![approver.public_key()],
                    subject: admin_subject.clone(),
                    threshold: 1,
                    maximum_token_lifetime_seconds: 60,
                },
                receipt_signing_backend.public_key(),
                Arc::new(FixedClock(100)),
            )
            .test_expect("admin"),
        );
        let admission: Arc<dyn BrokerAdmissionAuthority> = Arc::new(
            execute_cause_tests::ExecuteAdmissionAuthority::new(authority.clone()),
        );
        let handler = BrokerDaemonHandler::new(
            "tenant-production".to_string(),
            "broker-service-production".to_string(),
            issuer.public_key(),
            authority_signer.public_key(),
            1,
            service.clone(),
            admission,
            Arc::clone(&admin),
            receipt_signing_backend,
            Arc::clone(&backend),
            Arc::new(FixedClock(100)),
        )
        .test_expect("handler");

        let uid = rustix::process::geteuid().as_raw();
        let socket_path = root.join("broker.sock");
        let endpoint = UnixBrokerEndpoint::bind(&socket_path, Arc::new(handler), uid, uid)
            .test_expect("real endpoint");
        endpoint
            .set_nonblocking(true)
            .test_expect("nonblocking endpoint");
        Fixture {
            directory,
            _admin_directory: admin_directory,
            attempts,
            service,
            endpoint,
            socket_path,
            secret_path,
            approver,
            admin_subject,
            issuer,
            caller,
            authority_signer,
            observed_authorization,
            dispatch_calls,
        }
    }

    fn credential(version: u64) -> CredentialRef {
        CredentialRef {
            provider: "generic-https".into(),
            credential_id: "f011-credential".into(),
            version,
        }
    }

    fn mutation(
        &self,
        kind: CredentialMutationKind,
        credential: &CredentialRef,
        suffix: &str,
    ) -> AuthenticatedIpcRequest {
        let operation = match kind {
            CredentialMutationKind::Provision => IpcOperation::Provision,
            CredentialMutationKind::Rotate => IpcOperation::Rotate,
            CredentialMutationKind::Disable => IpcOperation::Disable,
            CredentialMutationKind::Delete => IpcOperation::Delete,
        };
        let secret = if matches!(
            kind,
            CredentialMutationKind::Provision | CredentialMutationKind::Rotate
        ) {
            b"f011_secret_canary".as_slice()
        } else {
            &[]
        };
        let payload = credential_mutation_payload_for_test(kind, credential, secret);
        let intent = daemon_admin_intent_digest(operation, "tenant-production", &payload)
            .test_expect("admin intent");
        let authorization = governed_authorization_for(
            &self.approver,
            &self.admin_subject,
            &intent,
            &format!("f011-approval-{suffix}"),
            &format!("f011-admin-{suffix}"),
        );
        AuthenticatedIpcRequest {
            operation,
            tenant_scope: "tenant-production".into(),
            authorization: authorization.into(),
            payload: payload.to_vec().into(),
        }
    }

    fn execution(
        &self,
        credential: CredentialRef,
        suffix: &str,
    ) -> (AttemptRegistration, BrokerExecuteRequest) {
        let destination = BrokerDestination::parse("https://example.com/v1", "post", false)
            .test_expect("destination");
        let broker_request = BrokerRequest {
            destination: destination.clone(),
            headers: Vec::new(),
            body: b"broker-request-body".to_vec(),
            approved_preview_sha256: None,
            options: CallerOptions {
                timeout_ms: 1_000,
                streaming: false,
                response_limit_bytes: 4_096,
            },
        };
        let capability = issue_capability(
            BrokerCapabilityBody {
                schema: BROKER_CAPABILITY_SCHEMA.to_string(),
                issuer: self.issuer.public_key(),
                capability_id: "broker-capability-production".to_string(),
                parent_capability_id: "parent-capability-production".to_string(),
                subject: self.caller.public_key(),
                audience: "broker-service-production".to_string(),
                issued_at_unix_seconds: 90,
                not_before_unix_seconds: 90,
                expires_at_unix_seconds: 110,
                credential,
                provider_adapter_id: "generic-bearer".to_string(),
                provider_adapter_version: 1,
                destination,
                constraints: RequestConstraints {
                    allowed_caller_headers: Vec::new(),
                    provider_owned_headers: vec!["authorization".to_string()],
                    maximum_body_bytes: 4_096,
                    required_body_sha256: body_digest(&broker_request.body),
                    required_preview_sha256: None,
                    redirect_policy: RedirectPolicy::Disabled,
                    maximum_response_bytes: 4_096,
                    streaming_allowed: false,
                    maximum_timeout_ms: 1_000,
                },
                broker_quota_key_id: "broker-quota-production".to_string(),
                maximum_executions: 2,
                consumption: AttemptConsumption::CaptureBeforeDispatch,
                revocation_id: "broker-revocation-production".to_string(),
                proof: ProofBinding {
                    mode: ProofMode::PublicKey,
                    caller_public_key: self.caller.public_key(),
                    nonce_ttl_seconds: 30,
                },
            },
            &Ed25519Backend::new(self.issuer.clone()),
            true,
        )
        .test_expect("capability");
        let proof = issue_request_proof(
            &capability,
            &broker_request,
            format!("f011-proof-{suffix}"),
            100,
            &self.caller,
        )
        .test_expect("proof");
        let execute = BrokerExecuteRequest {
            schema: BROKER_EXECUTE_SCHEMA.to_string(),
            invocation_id: format!("f011-invocation-{suffix}"),
            capability,
            proof,
            request: broker_request,
        };
        let request_digest =
            crate::service::broker_request_digest(&execute).test_expect("broker request digest");
        let ids = derive_attempt_ids_for_operation(
            &execute.capability.body.capability_id,
            &execute.invocation_id,
            &execute.proof.body.nonce,
            &request_digest,
            &format!("f011-operation-{suffix}"),
        )
        .test_expect("attempt ids");
        let registration = AttemptRegistration {
            ids,
            invocation_id: execute.invocation_id.clone(),
            parent_capability_id: execute.capability.body.parent_capability_id.clone(),
            broker_capability_id: execute.capability.body.capability_id.clone(),
            request_digest,
            request_canonical_digest: broker_execute_request_registration_digest(&execute)
                .test_expect("canonical request digest"),
            proof_digest: proof_digest(&execute.proof).test_expect("proof digest"),
            proof_key_id: execute.proof.body.authority_key.to_hex(),
            proof_nonce: execute.proof.body.nonce.clone(),
            nonce_expires_at_unix_seconds: 130,
            quotas: vec![
                ExecutionQuota {
                    key_id: execute.capability.body.broker_quota_key_id.clone(),
                    maximum_executions: execute.capability.body.maximum_executions,
                },
                ExecutionQuota {
                    key_id: "parent-quota-production".to_string(),
                    maximum_executions: 10,
                },
            ],
            authority_metadata_digest: "bb".repeat(32),
            revocation_authority_domain: "combined-production".to_string(),
        };
        (registration, execute)
    }

    fn attempt_request(
        &self,
        registration: &AttemptRegistration,
        execute: &BrokerExecuteRequest,
        action: RegisterAttemptAction,
    ) -> AuthenticatedIpcRequest {
        let operation = match action {
            RegisterAttemptAction::Register => IpcOperation::RegisterAttempt,
            RegisterAttemptAction::Prepare => IpcOperation::PrepareDispatch,
            _ => panic!("fixture action"),
        };
        AuthenticatedIpcRequest {
            operation,
            tenant_scope: "tenant-production".into(),
            authorization: canonical_json_bytes(
                &sign_register_attempt_authorization(
                    action,
                    "tenant-production".into(),
                    registration,
                    100,
                    &Ed25519Backend::new(self.authority_signer.clone()),
                )
                .test_expect("signed registration"),
            )
            .test_expect("authorization bytes")
            .into(),
            payload: canonical_json_bytes(&AuthenticatedAttemptRequest {
                registration: registration.clone(),
                request: execute.clone(),
            })
            .test_expect("registration bytes")
            .into(),
        }
    }

    fn rpc(&self, request: &AuthenticatedIpcRequest) -> crate::Result<IpcResponse> {
        let mut client = UnixStream::connect(&self.socket_path).test_expect("real client");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .test_expect("bounded read");
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .test_expect("bounded write");
        write_bounded_frame(&mut client, &canonical_ipc_request_bytes(request)?)?;
        assert_eq!(
            self.endpoint.try_serve_one()?,
            Some(BrokerIpcServeOutcome::ResponseWritten)
        );
        let bytes = read_bounded_frame(&mut client)?;
        assert!(!bytes
            .windows(b"f011_secret_canary".len())
            .any(|window| window == b"f011_secret_canary"));
        Ok(serde_json::from_slice(&bytes).test_expect("actual endpoint response"))
    }

    fn healthy_next(&self, suffix: &str) {
        let credential = Self::credential(2);
        let provision = self.mutation(CredentialMutationKind::Provision, &credential, suffix);
        assert!(
            self.rpc(&provision)
                .test_expect("next healthy client serviced")
                .accepted
        );
        let (registration, execute) = self.execution(credential, suffix);
        assert!(
            self.rpc(&self.attempt_request(
                &registration,
                &execute,
                RegisterAttemptAction::Register
            ))
            .test_expect("healthy registration")
            .accepted
        );
        assert!(
            self.rpc(&self.attempt_request(
                &registration,
                &execute,
                RegisterAttemptAction::Prepare
            ))
            .test_expect("healthy prepare")
            .accepted
        );
        assert_eq!(
            self.attempts
                .load_attempt(&registration.ids.attempt_id)
                .test_expect("healthy attempt")
                .test_expect("present")
                .state,
            crate::store::AttemptState::Prepared
        );
        assert!(self
            .observed_authorization
            .lock()
            .test_expect("observer")
            .is_none());
    }
}

fn assert_denied(response: &IpcResponse) {
    assert!(!response.accepted);
    assert!(response.response.is_empty());
    assert_eq!(response.error_code.as_deref(), Some("authorization_denied"));
}

#[test]
fn f011_disabled_prepare_keeps_endpoint_alive() {
    let fixture = Fixture::new();
    let credential = Fixture::credential(1);
    assert!(
        fixture
            .rpc(&fixture.mutation(CredentialMutationKind::Provision, &credential, "initial"))
            .test_expect("provision")
            .accepted
    );
    let (registration, execute) = fixture.execution(credential.clone(), "disabled");
    assert!(
        fixture
            .rpc(&fixture.attempt_request(&registration, &execute, RegisterAttemptAction::Register))
            .test_expect("register while valid")
            .accepted
    );
    let disable = fixture.mutation(CredentialMutationKind::Disable, &credential, "disable");
    let disabled = fixture.rpc(&disable).test_expect("disable");
    assert!(disabled.accepted);
    assert_eq!(
        fixture.rpc(&disable).test_expect("exact disable retry"),
        disabled
    );
    let request = fixture.attempt_request(&registration, &execute, RegisterAttemptAction::Prepare);
    assert_denied(
        &fixture
            .rpc(&request)
            .test_expect("disabled credential is a nonfatal refusal"),
    );
    assert_denied(
        &fixture
            .rpc(&request)
            .test_expect("stale client repeat contained"),
    );
    assert_eq!(
        fixture
            .attempts
            .load_attempt(&registration.ids.attempt_id)
            .test_expect("attempt")
            .test_expect("present")
            .state,
        crate::store::AttemptState::Registered
    );
    assert!(fixture
        .observed_authorization
        .lock()
        .test_expect("observer")
        .is_none());
    fixture.healthy_next("healthy-after-disable");
}

#[test]
fn f011_absent_prepare_keeps_endpoint_alive() {
    let fixture = Fixture::new();
    let (registration, execute) = fixture.execution(Fixture::credential(1), "absent");
    assert!(
        fixture
            .rpc(&fixture.attempt_request(&registration, &execute, RegisterAttemptAction::Register))
            .test_expect("absent version may register only")
            .accepted
    );
    assert_denied(
        &fixture
            .rpc(&fixture.attempt_request(&registration, &execute, RegisterAttemptAction::Prepare))
            .test_expect("absent credential refusal"),
    );
    assert_eq!(
        fixture
            .attempts
            .load_attempt(&registration.ids.attempt_id)
            .test_expect("attempt")
            .test_expect("present")
            .state,
        crate::store::AttemptState::Registered
    );
    fixture.healthy_next("healthy-after-absence");
}

fn repeated_admin_refusal(disable: bool) {
    let fixture = Fixture::new();
    let credential = Fixture::credential(1);
    if disable {
        assert!(
            fixture
                .rpc(&fixture.mutation(CredentialMutationKind::Provision, &credential, "initial"))
                .test_expect("provision")
                .accepted
        );
        assert!(
            fixture
                .rpc(&fixture.mutation(
                    CredentialMutationKind::Disable,
                    &credential,
                    "first-disable"
                ))
                .test_expect("first disable")
                .accepted
        );
    }
    let kind = if disable {
        CredentialMutationKind::Disable
    } else {
        CredentialMutationKind::Delete
    };
    let request = fixture.mutation(kind, &credential, "missing-reference");
    assert_denied(
        &fixture
            .rpc(&request)
            .test_expect("missing mutation is nonfatal"),
    );
    assert_denied(
        &fixture
            .rpc(&request)
            .test_expect("same approval repeat remains refusal"),
    );
    fixture.healthy_next("healthy-after-admin-refusal");
}

#[test]
fn f011_disabled_admin_repeat_keeps_endpoint_alive() {
    repeated_admin_refusal(true);
}

#[test]
fn f011_absent_delete_keeps_endpoint_alive() {
    repeated_admin_refusal(false);
}

#[test]
fn f011_corrupt_store_remains_fatal_with_native_cause() {
    let fixture = Fixture::new();
    let credential = Fixture::credential(1);
    assert!(
        fixture
            .rpc(&fixture.mutation(CredentialMutationKind::Provision, &credential, "initial"))
            .test_expect("provision")
            .accepted
    );
    let (registration, execute) = fixture.execution(credential, "corrupt-store");
    assert!(
        fixture
            .rpc(&fixture.attempt_request(&registration, &execute, RegisterAttemptAction::Register))
            .test_expect("register")
            .accepted
    );
    rusqlite::Connection::open(&fixture.secret_path)
        .test_expect("own temporary database")
        .execute_batch("DROP TABLE chio_encrypted_blob_references;")
        .test_expect("actual durable schema fault");
    let error = fixture
        .rpc(&fixture.attempt_request(&registration, &execute, RegisterAttemptAction::Prepare))
        .test_expect_err("real storage fault remains fatal");
    assert_eq!(error.diagnostic_code(), "storage");
    let mut source = std::error::Error::source(&error);
    let mut found = false;
    while let Some(cause) = source {
        if matches!(
            cause.downcast_ref::<chio_store_sqlite::BlobStoreError>(),
            Some(chio_store_sqlite::BlobStoreError::Sqlite(_))
        ) {
            found = true;
            break;
        }
        source = cause.source();
    }
    assert!(found, "real native storage source was discarded");
}

#[test]
fn f011_descriptor_replacement_remains_fatal() {
    let fixture = Fixture::new();
    let (registration, execute) = fixture.execution(Fixture::credential(1), "descriptor-fault");
    assert!(
        fixture
            .rpc(&fixture.attempt_request(&registration, &execute, RegisterAttemptAction::Register))
            .test_expect("register")
            .accepted
    );
    std::fs::rename(
        &fixture.secret_path,
        fixture.directory.path().join("old-secret-database"),
    )
    .test_expect("replace own descriptor path");
    std::fs::write(&fixture.secret_path, []).test_expect("replacement database");
    let error = fixture
        .rpc(&fixture.attempt_request(&registration, &execute, RegisterAttemptAction::Prepare))
        .test_expect_err("descriptor fault remains fatal");
    assert_eq!(error.diagnostic_code(), "storage");
}
