//! Post-Prepare failures exercise the real daemon Execute and IPC boundaries.
use super::*;
use crate::protocol::{BrokerExecuteFailure, BrokerExecuteResponse};
use crate::receipt::{
    verify_failure_receipt, BrokerDispatchKnowledge, BrokerFailureOutcome, BrokerFailureStage,
};
use crate::store::AttemptState;

#[path = "resolver_integrity_tests.rs"]
mod resolver_integrity_tests;

pub(super) struct CountedTransport {
    inner: ObservingTransport,
    calls: Arc<AtomicU64>,
}

impl CountedTransport {
    pub(super) fn new(
        observed_authorization: Arc<Mutex<Option<Vec<u8>>>>,
        calls: Arc<AtomicU64>,
    ) -> Self {
        Self {
            inner: ObservingTransport {
                observed_authorization,
            },
            calls,
        }
    }
}

impl PinnedHttpsTransport for CountedTransport {
    fn dispatch(&self, request: PinnedHttpsRequest) -> Result<RawHttpsResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.dispatch(request)
    }
}

pub(super) struct ExecuteAdmissionAuthority {
    inner: Arc<FakeAuthority>,
}

impl ExecuteAdmissionAuthority {
    pub(super) fn new(inner: Arc<FakeAuthority>) -> Self {
        Self { inner }
    }
}

fn operation_id(request: &BrokerExecuteRequest) -> String {
    format!("f011-execute-operation-{}", request.invocation_id)
}

fn execution_registration(
    mut registration: AttemptRegistration,
    request: &BrokerExecuteRequest,
) -> AttemptRegistration {
    registration.ids = derive_attempt_ids_for_operation(
        &request.capability.body.capability_id,
        &request.invocation_id,
        &request.proof.body.nonce,
        &registration.request_digest,
        &operation_id(request),
    )
    .test_expect("admission-matching attempt IDs");
    registration
}

impl BrokerAdmissionAuthority for ExecuteAdmissionAuthority {
    fn prepare_execution(
        &self,
        request: &BrokerExecuteRequest,
    ) -> Result<crate::service::TrustedExecutionContext> {
        let mut trusted = self.inner.prepare_execution(request)?;
        let request_digest = crate::service::broker_request_digest(request)?;
        let registration = AttemptRegistration {
            ids: derive_attempt_ids_for_operation(
                &request.capability.body.capability_id,
                &request.invocation_id,
                &request.proof.body.nonce,
                &request_digest,
                &operation_id(request),
            )?,
            invocation_id: request.invocation_id.clone(),
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            broker_capability_id: request.capability.body.capability_id.clone(),
            request_digest,
            request_canonical_digest: broker_execute_request_registration_digest(request)?,
            proof_digest: proof_digest(&request.proof)?,
            proof_key_id: request.proof.body.authority_key.to_hex(),
            proof_nonce: request.proof.body.nonce.clone(),
            nonce_expires_at_unix_seconds: 130,
            quotas: trusted.quotas.clone(),
            authority_metadata_digest: trusted.authority_metadata_digest.clone(),
            revocation_authority_domain: trusted.revocation_authority_domain.clone(),
        };
        trusted.admission_operation_id = registration.ids.operation_id.clone();
        trusted.prepared_dispatch_id = prepared_dispatch_id(&registration, request)?;
        Ok(trusted)
    }

    fn control(&self, request: AuthorityControlRequest) -> Result<Vec<u8>> {
        self.inner.control(request)
    }
}

fn provision_and_prepare(
    fixture: &Fixture,
    version: u64,
    suffix: &str,
) -> (AttemptRegistration, BrokerExecuteRequest) {
    let credential = Fixture::credential(version);
    assert!(
        fixture
            .rpc(&fixture.mutation(CredentialMutationKind::Provision, &credential, suffix))
            .test_expect("governed provision before Prepare")
            .accepted
    );
    let (registration, execute) = fixture.execution(credential, suffix);
    let registration = execution_registration(registration, &execute);
    for action in [
        RegisterAttemptAction::Register,
        RegisterAttemptAction::Prepare,
    ] {
        assert!(
            fixture
                .rpc(&fixture.attempt_request(&registration, &execute, action))
                .test_expect("signed register/Prepare while credential is valid")
                .accepted
        );
    }
    let attempt = fixture
        .attempts
        .load_attempt(&registration.ids.attempt_id)
        .test_expect("prepared attempt")
        .test_expect("present");
    assert_eq!(attempt.state, AttemptState::Prepared);
    assert_eq!(fixture.dispatch_calls.load(Ordering::SeqCst), 0);
    (registration, execute)
}

fn execute_request(execute: &BrokerExecuteRequest) -> AuthenticatedIpcRequest {
    AuthenticatedIpcRequest {
        operation: IpcOperation::Execute,
        tenant_scope: "tenant-production".into(),
        authorization: canonical_json_bytes(&execute.proof)
            .test_expect("canonical embedded proof authorization")
            .into(),
        payload: canonical_json_bytes(execute)
            .test_expect("canonical Execute payload")
            .into(),
    }
}

fn assert_native_store_source(error: &BrokerError, sqlite: bool) {
    let mut source = std::error::Error::source(error);
    let mut found = false;
    while let Some(cause) = source {
        if let Some(native) = cause.downcast_ref::<chio_store_sqlite::BlobStoreError>() {
            found = if sqlite {
                matches!(native, chio_store_sqlite::BlobStoreError::Sqlite(_))
            } else {
                matches!(native, chio_store_sqlite::BlobStoreError::NotFound)
            };
            if found {
                break;
            }
        }
        source = cause.source();
    }
    assert!(found, "fresh native credential cause was discarded");
}

fn assert_public_error_is_private(error: &BrokerError, fixture: &Fixture) {
    for rendered in [format!("{error:?}"), error.to_string()] {
        for private in [
            "f011_secret_canary",
            "chio_encrypted_blob_references",
            "no such table",
            fixture.secret_path.to_str().test_expect("test path"),
        ] {
            assert!(
                !rendered.contains(private),
                "public error exposed {private}"
            );
        }
    }
}

fn assert_terminal_failure(
    fixture: &Fixture,
    registration: &AttemptRegistration,
    execute: &BrokerExecuteRequest,
    code: &str,
    outcome: BrokerFailureOutcome,
) -> BrokerExecuteFailure {
    let failure = fixture
        .service
        .replay_failure(execute, 100)
        .test_expect("durable signed terminal lookup")
        .test_expect("signed failure retained after local error");
    assert_eq!(failure.diagnostic_code, code);
    assert_eq!(failure.receipt.body.diagnostic_code, code);
    verify_failure_receipt(
        &failure.receipt,
        &Keypair::from_seed(&[84; 32]).public_key(),
    )
    .test_expect("authentic broker terminal signature");
    assert_eq!(failure.receipt.body.stage, BrokerFailureStage::Capture);
    assert_eq!(failure.receipt.body.outcome, outcome);
    assert_eq!(
        failure.receipt.body.dispatch_knowledge,
        BrokerDispatchKnowledge::NotCommitted
    );
    let attempt = fixture
        .attempts
        .load_attempt(&registration.ids.attempt_id)
        .test_expect("terminal attempt")
        .test_expect("present");
    assert_eq!(attempt.state, AttemptState::Failed);
    assert!(attempt.dispatch_claim_id.is_none());
    assert!(attempt.revocation_set_digest.is_some());
    assert_eq!(attempt.budget_commit_index, Some(10));
    assert_eq!(attempt.revocation_commit_index, Some(11));
    assert_eq!(attempt.authority_commit_index, Some(12));
    assert_eq!(attempt.leader_epoch, Some(13));
    assert!(attempt.response_digest.is_none());
    let database = rusqlite::Connection::open(fixture.directory.path().join("attempts.sqlite3"))
        .test_expect("own durable attempt database");
    let nonce_attempt: String = database
        .query_row(
            "SELECT attempt_id FROM broker_nonces WHERE proof_key_id = ?1 AND proof_nonce = ?2",
            rusqlite::params![registration.proof_key_id, registration.proof_nonce],
            |row| row.get(0),
        )
        .test_expect("consumed nonce remains fenced");
    assert_eq!(nonce_attempt, registration.ids.attempt_id);
    assert_eq!(fixture.dispatch_calls.load(Ordering::SeqCst), 0);
    assert!(fixture
        .observed_authorization
        .lock()
        .test_expect("secret sink observer")
        .is_none());
    failure
}

fn assert_exact_denial_replay(
    fixture: &Fixture,
    execute: &BrokerExecuteRequest,
    failure: &BrokerExecuteFailure,
) -> IpcResponse {
    let request = execute_request(execute);
    let response = fixture.rpc(&request).test_expect("terminal signed replay");
    assert!(!response.accepted);
    assert_eq!(
        response.error_code.as_deref(),
        Some(failure.diagnostic_code.as_str())
    );
    assert_eq!(
        response.response,
        canonical_json_bytes(failure).test_expect("exact signed failure bytes")
    );
    assert_eq!(fixture.rpc(&request).test_expect("exact retry"), response);
    assert_eq!(fixture.dispatch_calls.load(Ordering::SeqCst), 0);
    response
}

fn assert_healthy_execute_once(fixture: &Fixture, suffix: &str) {
    let (registration, execute) = provision_and_prepare(fixture, 2, suffix);
    let request = execute_request(&execute);
    let response = fixture.rpc(&request).test_expect("healthy next Execute");
    assert!(response.accepted);
    assert_eq!(fixture.dispatch_calls.load(Ordering::SeqCst), 1);
    let completed: BrokerExecuteResponse =
        serde_json::from_slice(&response.response).test_expect("healthy signed response");
    assert_eq!(completed.evidence.attempt_id, registration.ids.attempt_id);
    assert_eq!(
        fixture
            .attempts
            .load_attempt(&registration.ids.attempt_id)
            .test_expect("healthy terminal attempt")
            .test_expect("present")
            .state,
        AttemptState::Completed
    );
    assert_eq!(
        fixture.rpc(&request).test_expect("healthy exact retry"),
        response
    );
    assert_eq!(fixture.dispatch_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn f011_execute_corrupt_store_is_fatal_after_signed_projection() {
    let fixture = Fixture::new();
    let (registration, execute) = provision_and_prepare(&fixture, 1, "execute-corrupt-store");
    rusqlite::Connection::open(&fixture.secret_path)
        .test_expect("own secret database")
        .execute_batch("DROP TABLE chio_encrypted_blob_references;")
        .test_expect("actual post-Prepare durable storage fault");
    let error = fixture
        .rpc(&execute_request(&execute))
        .test_expect_err("post-Prepare storage fault must reach fatal IPC consumer");
    assert_eq!(error.diagnostic_code(), "storage");
    assert_native_store_source(&error, true);
    assert_public_error_is_private(&error, &fixture);
    let redacted = error.redacted();
    assert_native_store_source(&redacted, true);
    assert_public_error_is_private(&redacted, &fixture);
    let failure = assert_terminal_failure(
        &fixture,
        &registration,
        &execute,
        "chio.broker.storage",
        BrokerFailureOutcome::Failed,
    );
    assert_exact_denial_replay(&fixture, &execute, &failure);
}

#[test]
fn f011_execute_descriptor_replacement_is_fatal_after_signed_projection() {
    let fixture = Fixture::new();
    let (registration, execute) = provision_and_prepare(&fixture, 1, "execute-descriptor");
    std::fs::rename(
        &fixture.secret_path,
        fixture.directory.path().join("old-secret-database"),
    )
    .test_expect("replace own descriptor path after Prepare");
    std::fs::write(&fixture.secret_path, []).test_expect("replacement database");
    let error = fixture
        .rpc(&execute_request(&execute))
        .test_expect_err("post-Prepare descriptor fault must remain fatal");
    assert_eq!(error.diagnostic_code(), "storage");
    assert_public_error_is_private(&error.redacted(), &fixture);
    let failure = assert_terminal_failure(
        &fixture,
        &registration,
        &execute,
        "chio.broker.storage",
        BrokerFailureOutcome::Failed,
    );
    assert_exact_denial_replay(&fixture, &execute, &failure);
}

fn unavailable_after_prepare(kind: CredentialMutationKind, suffix: &str) {
    let fixture = Fixture::new();
    let (registration, execute) = provision_and_prepare(&fixture, 1, suffix);
    assert!(
        fixture
            .rpc(&fixture.mutation(kind, &execute.capability.body.credential, "remove-prepared"))
            .test_expect("governed credential removal after valid Prepare")
            .accepted
    );
    let response = fixture
        .rpc(&execute_request(&execute))
        .test_expect("unavailable credential remains nonfatal signed denial");
    let failure = assert_terminal_failure(
        &fixture,
        &registration,
        &execute,
        "chio.broker.authorization_denied",
        BrokerFailureOutcome::Denied,
    );
    assert_eq!(
        assert_exact_denial_replay(&fixture, &execute, &failure),
        response
    );
    assert_healthy_execute_once(&fixture, "healthy-after-execute-refusal");
}

#[test]
fn f011_execute_disabled_credential_keeps_signed_denial_and_endpoint_health() {
    unavailable_after_prepare(CredentialMutationKind::Disable, "execute-disabled");
}

#[test]
fn f011_execute_deleted_credential_keeps_signed_denial_and_endpoint_health() {
    unavailable_after_prepare(CredentialMutationKind::Delete, "execute-deleted");
}

#[test]
fn f011_public_execute_retains_native_storage_after_signed_projection() {
    let fixture = Fixture::new();
    let (registration, execute) = provision_and_prepare(&fixture, 1, "public-execute-storage");
    let trusted = ExecuteAdmissionAuthority::new(Arc::new(FakeAuthority {
        control_calls: AtomicU64::new(0),
        prepare_calls: AtomicU64::new(0),
    }))
    .prepare_execution(&execute)
    .test_expect("matching trusted execution context");
    rusqlite::Connection::open(&fixture.secret_path)
        .test_expect("own secret database")
        .execute_batch("DROP TABLE chio_encrypted_blob_references;")
        .test_expect("actual post-Prepare storage fault");
    let error = fixture
        .service
        .execute(&execute, &trusted, 100)
        .test_expect_err("public Execute retains the actual fresh storage error");
    assert_eq!(error.diagnostic_code(), "storage");
    assert_native_store_source(&error, true);
    let redacted = error.redacted();
    assert_native_store_source(&redacted, true);
    assert_public_error_is_private(&redacted, &fixture);
    assert_terminal_failure(
        &fixture,
        &registration,
        &execute,
        "chio.broker.storage",
        BrokerFailureOutcome::Failed,
    );
}
