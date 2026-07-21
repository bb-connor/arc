use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    aggregate_budget::{AggregateInvocationBudget, AggregateInvocationScope},
    crypto_floor::CapabilityCryptoFloor,
    features::{
        CapabilityNegotiation, AGGREGATE_INVOCATION_BUDGET, SUPPLEMENTAL_BROKER_EXECUTION_QUOTA,
    },
    governance::{
        GovernedResponseEffect, GovernedResponsePlanIntentBody, GovernedTransactionIntent,
        CHIO_ACTIVE_RESPONSE_SERVER_ID, CHIO_RESPONSE_PLAN_SCHEMA,
    },
    scope::{ChioScope, MonetaryAmount, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_kernel::budget_store::{
    BudgetCaptureInvocationRequest, BudgetInvocationQuota, BudgetInvocationReservationState,
    BudgetMutationKind, BudgetQuotaKey, BudgetQuotaProfile, BudgetStore,
};
use chio_kernel::supplemental_quota::{
    CanonicalRevocationSet, OpaqueSignedSupplementalQuota, SupplementalQuotaDestination,
    SupplementalQuotaError, SupplementalQuotaVerificationContext, SupplementalQuotaVerifier,
    VerifiedSupplementalQuotaClaimBody,
};
use chio_kernel::{
    AdmissionCaptureAuthority, AdmissionCaptureDecision, AdmissionCaptureRequest,
    AdmissionCaptureRequestInput, AdmissionCleanupAction, AdmissionCleanupActionKind,
    AdmissionDispatchState, AdmissionOperation, AdmissionOperationCasOutcome,
    AdmissionOperationCompareAndSwap, AdmissionOperationCreateOutcome, AdmissionOperationKind,
    AdmissionOperationState, AdmissionOperationStore, ChioKernel, KernelConfig, KernelError,
    NestedFlowBridge, PreparedAdmissionOperation, ToolCallRequest, ToolInvocationCost,
    ToolServerConnection, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_kernel_core::{
    verify_capability_full, CapabilityError, FixedClock, InMemoryBudgetRegistry,
};
use chio_secret_broker::budget::ExecutionQuota;
use chio_secret_broker::sqlite::SqliteAttemptStore;
use chio_secret_broker::store::{
    derive_attempt_ids, AttemptRegistration, AttemptStore, RegisterAttemptOutcome,
};
use chio_secret_broker::BrokerError;
use chio_store_sqlite::budget_store::SqliteCompositeAuthorizeInput;
use chio_store_sqlite::{
    SqliteAdmissionCaptureAuthority, SqliteAdmissionOperationStore, SqliteBudgetStore,
};
use chio_test_support::prelude::*;
use rusqlite::Connection;
use serde_json::json;

fn kernel_config(keypair: Keypair) -> KernelConfig {
    KernelConfig {
        keypair,
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: "33".repeat(32),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    }
}

fn make_kernel(keypair: Keypair) -> ChioKernel {
    ChioKernel::new(kernel_config(keypair))
}

#[derive(Clone)]
struct FixedSupplementalVerifier {
    claim: VerifiedSupplementalQuotaClaimBody,
}

impl SupplementalQuotaVerifier for FixedSupplementalVerifier {
    fn verifier_id(&self) -> &str {
        "conformance-verifier"
    }

    fn verify(
        &self,
        _artifact: &OpaqueSignedSupplementalQuota,
        _context: &SupplementalQuotaVerificationContext,
    ) -> Result<VerifiedSupplementalQuotaClaimBody, SupplementalQuotaError> {
        Ok(self.claim.clone())
    }
}

fn supplemental_fixture() -> (
    OpaqueSignedSupplementalQuota,
    SupplementalQuotaVerificationContext,
    VerifiedSupplementalQuotaClaimBody,
) {
    let subject = Keypair::from_seed(&[11; 32]);
    let issuer = Keypair::from_seed(&[12; 32]);
    let artifact =
        OpaqueSignedSupplementalQuota::new(b"signed-broker-claim".to_vec()).test_unwrap();
    let destination = SupplementalQuotaDestination::new("broker", "execute").test_unwrap();
    let mut negotiated_features = CapabilityNegotiation::t1_default();
    negotiated_features
        .features
        .insert(SUPPLEMENTAL_BROKER_EXECUTION_QUOTA.to_string(), true);
    let context = SupplementalQuotaVerificationContext {
        capability_id: "leaf-capability".to_string(),
        capability_digest: "11".repeat(32),
        subject: subject.public_key(),
        request_id: "request-1".to_string(),
        destination: destination.clone(),
        arguments_digest: "22".repeat(32),
        request_binding_hash: "33".repeat(32),
        now: 100,
        negotiated_profile: BudgetQuotaProfile::SupplementalBrokerExecution,
        negotiated_features: negotiated_features.clone(),
    };
    let negotiated_features_digest =
        sha256_hex(&chio_core::canonical::canonical_json_bytes(&negotiated_features).test_unwrap());
    let body = VerifiedSupplementalQuotaClaimBody {
        capability_id: context.capability_id.clone(),
        capability_digest: context.capability_digest.clone(),
        subject: context.subject.clone(),
        request_id: context.request_id.clone(),
        destination,
        arguments_digest: context.arguments_digest.clone(),
        request_binding_hash: context.request_binding_hash.clone(),
        expires_at: 101,
        broker_capability_id: "broker-capability".to_string(),
        issuer: issuer.public_key(),
        request_constraint_digest: "44".repeat(32),
        max_invocations: 3,
        supplemental_revocation_ids: vec!["broker-capability".to_string()],
        artifact_digest: artifact.digest(),
        negotiated_features_digest,
        profile: BudgetQuotaProfile::SupplementalBrokerExecution,
    };
    (artifact, context, body)
}

fn verify_fixed_supplemental(
    artifact: &OpaqueSignedSupplementalQuota,
    context: &SupplementalQuotaVerificationContext,
    body: VerifiedSupplementalQuotaClaimBody,
) -> Result<chio_kernel::supplemental_quota::VerifiedSupplementalQuota, SupplementalQuotaError> {
    let mut kernel = make_kernel(Keypair::from_seed(&[13; 32]));
    kernel
        .set_supplemental_quota_verifier(Arc::new(FixedSupplementalVerifier { claim: body }))
        .test_unwrap();
    kernel.verify_supplemental_quota(artifact, context)
}

#[test]
fn supplemental_quota_rejects_absence_context_expiry_and_caller_built_unbound_claims() {
    let (artifact, context, body) = supplemental_fixture();
    assert!(matches!(
        make_kernel(Keypair::from_seed(&[14; 32])).verify_supplemental_quota(&artifact, &context),
        Err(SupplementalQuotaError::VerifierUnavailable)
    ));

    let mut unnegotiated = context.clone();
    unnegotiated
        .negotiated_features
        .features
        .remove(SUPPLEMENTAL_BROKER_EXECUTION_QUOTA);
    assert!(matches!(
        verify_fixed_supplemental(&artifact, &unnegotiated, body.clone()),
        Err(SupplementalQuotaError::FeatureNotNegotiated)
    ));

    let mut wrong_subject = body.clone();
    wrong_subject.subject = Keypair::from_seed(&[15; 32]).public_key();
    assert!(matches!(
        verify_fixed_supplemental(&artifact, &context, wrong_subject),
        Err(SupplementalQuotaError::ContextMismatch(field)) if field == "subject"
    ));

    let mut wrong_request = body.clone();
    wrong_request.request_id = "request-2".to_string();
    assert!(matches!(
        verify_fixed_supplemental(&artifact, &context, wrong_request),
        Err(SupplementalQuotaError::ContextMismatch(field)) if field == "request id"
    ));

    let mut wrong_destination = body.clone();
    wrong_destination.destination =
        SupplementalQuotaDestination::new("broker", "other-tool").test_unwrap();
    assert!(matches!(
        verify_fixed_supplemental(&artifact, &context, wrong_destination),
        Err(SupplementalQuotaError::ContextMismatch(field)) if field == "destination"
    ));

    let mut expired = body.clone();
    expired.expires_at = context.now;
    assert!(matches!(
        verify_fixed_supplemental(&artifact, &context, expired),
        Err(SupplementalQuotaError::Expired)
    ));

    let mut unbound_claim = body;
    unbound_claim.artifact_digest = "55".repeat(32);
    assert!(matches!(
        verify_fixed_supplemental(&artifact, &context, unbound_claim),
        Err(SupplementalQuotaError::ContextMismatch(field)) if field == "artifact digest"
    ));
}

fn single_quota(capability_id: &str, maximum: u32) -> BudgetInvocationQuota {
    let key = BudgetQuotaKey::from_persisted_parts(
        BudgetQuotaProfile::GrantInvocation,
        capability_id.to_string(),
        Some(0),
    )
    .test_unwrap();
    BudgetInvocationQuota::from_persisted_parts(key, maximum).test_unwrap()
}

fn leaf_revocation_set(capability_id: &str) -> CanonicalRevocationSet {
    CanonicalRevocationSet::new(capability_id, &[], &[]).test_unwrap()
}

fn authorize_input(
    capability_id: &str,
    hold_id: &str,
    event_id: &str,
) -> SqliteCompositeAuthorizeInput {
    authorize_input_with_binding(
        capability_id,
        hold_id,
        event_id,
        &format!("operation-{hold_id}"),
        &"44".repeat(32),
    )
}

fn authorize_input_with_binding(
    capability_id: &str,
    hold_id: &str,
    event_id: &str,
    operation_id: &str,
    request_binding_hash: &str,
) -> SqliteCompositeAuthorizeInput {
    SqliteCompositeAuthorizeInput {
        operation_id: operation_id.to_string(),
        request_binding_hash: request_binding_hash.to_string(),
        capability_id: capability_id.to_string(),
        grant_index: 0,
        requested_exposure_units: 100,
        max_cost_per_invocation: Some(100),
        max_total_cost_units: Some(1_000),
        hold_id: hold_id.to_string(),
        event_id: event_id.to_string(),
        authority: None,
        invocation_quotas: vec![single_quota(capability_id, 2)],
        revocation_set: leaf_revocation_set(capability_id),
        authorization_artifact_digests: vec!["11".repeat(32)],
    }
}

fn authorize_leaf(path: &std::path::Path, operation_id: &str) {
    let store = SqliteBudgetStore::open(path).test_unwrap();
    let request = authorize_input_with_binding(
        "leaf",
        "hold-1",
        "authorize-1",
        operation_id,
        &"44".repeat(32),
    );
    assert!(store
        .authorize_composite_hold(request)
        .test_unwrap()
        .is_authorized());
}

fn admission_capture_request(
    operation_id: &str,
    request_binding_hash: &str,
    last_observed_revocation_index: Option<u64>,
) -> AdmissionCaptureRequest {
    let revocation_set = leaf_revocation_set("leaf");
    AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
        operation_id: operation_id.to_string(),
        budget: BudgetCaptureInvocationRequest {
            capability_id: "leaf".to_string(),
            grant_index: 0,
            hold_id: Some("hold-1".to_string()),
            event_id: Some("capture-1".to_string()),
            authority: None,
            admission_operation: Some(
                chio_kernel::budget_store::BudgetAdmissionOperationBinding::new(
                    operation_id.to_string(),
                    request_binding_hash.to_string(),
                )
                .test_unwrap(),
            ),
        },
        revocation_set: revocation_set.clone(),
        bound_revocation_set_digest: revocation_set.digest().to_string(),
        authorization_artifact_digests: vec!["11".repeat(32)],
        aggregate_root_capability_id: None,
        aggregate_root_binding_digest: None,
        last_observed_revocation_index,
    })
    .test_unwrap()
}

fn quota_counts(path: &std::path::Path) -> (i64, i64) {
    Connection::open(path)
        .test_unwrap()
        .query_row(
            r#"
            SELECT reserved_invocations, captured_invocations
            FROM budget_invocation_quota_usage
            WHERE profile = 'chio.grant-invocation.v1'
              AND owner_id = 'leaf'
              AND grant_index_key = 0
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .test_unwrap()
}

#[test]
fn combined_capture_and_revocation_have_one_durable_order() {
    let directory = tempfile::tempdir().test_unwrap();

    let captured_path = directory.path().join("captured-first.sqlite3");
    authorize_leaf(&captured_path, "operation-captured");
    let captured_request = admission_capture_request("operation-captured", &"44".repeat(32), None);
    let captured_authority = SqliteAdmissionCaptureAuthority::open(&captured_path).test_unwrap();
    let captured = captured_authority
        .capture_admission(captured_request.clone())
        .test_unwrap();
    assert!(matches!(
        &captured,
        AdmissionCaptureDecision::Captured { .. }
    ));
    assert_eq!(quota_counts(&captured_path), (0, 1));
    let revocation = captured_authority.revoke("leaf").test_unwrap();
    assert_eq!(
        captured_authority
            .capture_admission(captured_request.clone())
            .test_unwrap(),
        captured
    );
    drop(captured_authority);
    assert_eq!(
        SqliteAdmissionCaptureAuthority::open(&captured_path)
            .test_unwrap()
            .capture_admission(captured_request)
            .test_unwrap(),
        captured
    );
    let AdmissionCaptureDecision::Captured { metadata, .. } = captured else {
        panic!("captured-first admission did not produce captured metadata");
    };
    assert!(metadata.authority_commit_index() < revocation.authority_commit_index());

    let revoked_path = directory.path().join("revoked-first.sqlite3");
    authorize_leaf(&revoked_path, "operation-revoked");
    let revoked_authority = SqliteAdmissionCaptureAuthority::open(&revoked_path).test_unwrap();
    let revocation = revoked_authority.revoke("leaf").test_unwrap();
    let revoked_request = admission_capture_request(
        "operation-revoked",
        &"44".repeat(32),
        Some(revocation.revocation_commit_index()),
    );
    let denied = revoked_authority
        .capture_admission(revoked_request.clone())
        .test_unwrap();
    let AdmissionCaptureDecision::Denied(denial) = &denied else {
        panic!("revocation must precede denial");
    };
    assert!(denial.metadata().authority_commit_index() > revocation.authority_commit_index());
    assert_eq!(quota_counts(&revoked_path), (1, 0));
    drop(revoked_authority);
    assert_eq!(
        SqliteAdmissionCaptureAuthority::open(&revoked_path)
            .test_unwrap()
            .capture_admission(revoked_request)
            .test_unwrap(),
        denied
    );
}

#[test]
fn concurrent_capture_and_revocation_preserve_one_linearization_order() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("authority-race.sqlite3");
    authorize_leaf(&path, "operation-race");
    let capture_authority = Arc::new(SqliteAdmissionCaptureAuthority::open(&path).test_unwrap());
    let revocation_authority = Arc::new(SqliteAdmissionCaptureAuthority::open(&path).test_unwrap());
    let request = admission_capture_request("operation-race", &"44".repeat(32), None);
    let barrier = Arc::new(Barrier::new(3));

    let capture_thread = {
        let authority = Arc::clone(&capture_authority);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            authority.capture_admission(request)
        })
    };
    let revocation_thread = {
        let authority = Arc::clone(&revocation_authority);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            authority.revoke("leaf")
        })
    };
    barrier.wait();
    let decision = capture_thread.join().test_unwrap().test_unwrap();
    let revocation = revocation_thread.join().test_unwrap().test_unwrap();

    match decision {
        AdmissionCaptureDecision::Captured { metadata, .. } => {
            assert_eq!(quota_counts(&path), (0, 1));
            assert!(metadata.authority_commit_index() < revocation.authority_commit_index());
        }
        AdmissionCaptureDecision::Denied(denial) => {
            assert_eq!(quota_counts(&path), (1, 0));
            assert!(
                denial.metadata().authority_commit_index() > revocation.authority_commit_index()
            );
        }
    }
}

fn tool_admission_operation() -> AdmissionOperation {
    AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::ToolDispatch,
        coordinator_authority_id: "coordinator-1".to_string(),
        request_id: "request-admission".to_string(),
        capability_id: "leaf".to_string(),
        authorization_capability_hash: "11".repeat(32),
        request_binding_hash: "22".repeat(32),
        policy_hash: "33".repeat(32),
        broker_attempt_id: Some("broker-attempt-1".to_string()),
        budget_hold_id: Some("hold-1".to_string()),
        approval_set_hash: Some("44".repeat(32)),
        execution_nonce_id: Some("nonce-1".to_string()),
        coordinator_lease_epoch: 7,
    })
    .test_unwrap()
}

#[test]
fn admission_authority_commits_and_state_writes_recover_exactly() {
    let directory = tempfile::tempdir().test_unwrap();
    let operation_path = directory.path().join("admission.sqlite3");
    let budget_path = directory.path().join("budget.sqlite3");
    let prepared = tool_admission_operation();
    let operation_id = prepared.operation_id().to_string();
    let request_binding_hash = prepared.request_binding_hash().to_string();

    assert!(matches!(
        SqliteAdmissionOperationStore::open(&operation_path)
            .test_unwrap()
            .create_prepared(prepared.clone())
            .test_unwrap(),
        AdmissionOperationCreateOutcome::Created(_)
    ));
    assert!(matches!(
        SqliteAdmissionOperationStore::open(&operation_path)
            .test_unwrap()
            .create_prepared(prepared)
            .test_unwrap(),
        AdmissionOperationCreateOutcome::Existing(_)
    ));

    let transitions = [
        (
            AdmissionOperationState::BrokerAttemptRegistered,
            AdmissionDispatchState::NotStarted,
        ),
        (
            AdmissionOperationState::BudgetAuthorized,
            AdmissionDispatchState::NotStarted,
        ),
        (
            AdmissionOperationState::DelegatedBudgetReserved,
            AdmissionDispatchState::NotStarted,
        ),
        (
            AdmissionOperationState::PaymentAuthorized,
            AdmissionDispatchState::NotStarted,
        ),
        (
            AdmissionOperationState::ApprovalReserved,
            AdmissionDispatchState::NotStarted,
        ),
        (
            AdmissionOperationState::ReadyToDispatch,
            AdmissionDispatchState::NotStarted,
        ),
        (
            AdmissionOperationState::CapturePending,
            AdmissionDispatchState::NotStarted,
        ),
        (
            AdmissionOperationState::DispatchCommitted,
            AdmissionDispatchState::Committed,
        ),
        (
            AdmissionOperationState::Completed,
            AdmissionDispatchState::EffectCompleted,
        ),
    ];
    let mut expected_version = 0;
    for (next_state, next_dispatch) in transitions {
        if next_state == AdmissionOperationState::BudgetAuthorized {
            let request = authorize_input_with_binding(
                "leaf",
                "hold-1",
                "authorize-1",
                &operation_id,
                &request_binding_hash,
            );
            let store = SqliteBudgetStore::open(&budget_path).test_unwrap();
            let committed = store
                .authorize_composite_hold(request.clone())
                .test_unwrap();
            drop(store);
            assert_eq!(
                SqliteBudgetStore::open(&budget_path)
                    .test_unwrap()
                    .authorize_composite_hold(request)
                    .test_unwrap(),
                committed
            );
        }
        if next_state == AdmissionOperationState::DispatchCommitted {
            let capture = admission_capture_request(&operation_id, &request_binding_hash, None);
            let authority = SqliteAdmissionCaptureAuthority::open(&budget_path).test_unwrap();
            let committed = authority.capture_admission(capture.clone()).test_unwrap();
            drop(authority);
            assert_eq!(
                SqliteAdmissionCaptureAuthority::open(&budget_path)
                    .test_unwrap()
                    .capture_admission(capture)
                    .test_unwrap(),
                committed
            );
            let AdmissionCaptureDecision::Captured { budget, .. } = committed else {
                panic!("combined admission capture must capture the budget hold");
            };
            assert_eq!(
                budget.invocation_state,
                BudgetInvocationReservationState::Captured
            );
        }

        let store = SqliteAdmissionOperationStore::open(&operation_path).test_unwrap();
        let request = || AdmissionOperationCompareAndSwap {
            operation_id: &operation_id,
            expected_version,
            coordinator_lease_epoch: 7,
            next_state,
            next_dispatch_state: next_dispatch,
            next_coordinator_lease_epoch: 7,
            last_error: None,
        };
        let (applied, terminal_action) = if next_state.is_terminal() {
            assert!(matches!(
                store.compare_and_swap(request()),
                Err(error) if error.to_string().contains("atomic terminal receipt action")
            ));
            let current = store.load(&operation_id).test_unwrap().test_unwrap();
            let action = AdmissionCleanupAction::pending(
                &current,
                AdmissionCleanupActionKind::TerminalReceipt,
                &json!({"terminal": next_state.as_str()}),
            )
            .test_unwrap();
            let AdmissionOperationCasOutcome::Applied(applied) = store
                .compare_and_swap_with_cleanup_action(request(), action.clone())
                .test_unwrap()
            else {
                panic!("terminal state advance and receipt outbox insert must apply atomically");
            };
            (applied, Some(action))
        } else {
            let AdmissionOperationCasOutcome::Applied(applied) =
                store.compare_and_swap(request()).test_unwrap()
            else {
                panic!("state advance must apply once");
            };
            (applied, None)
        };
        drop(store);

        let reopened = SqliteAdmissionOperationStore::open(&operation_path).test_unwrap();
        assert_eq!(
            reopened.load(&operation_id).test_unwrap(),
            Some(applied.clone())
        );
        if let Some(action) = terminal_action {
            assert_eq!(
                reopened.load_cleanup_actions(&operation_id).test_unwrap(),
                vec![action.clone()]
            );
            assert!(matches!(
                reopened
                    .compare_and_swap_with_cleanup_action(request(), action)
                    .test_unwrap(),
                AdmissionOperationCasOutcome::Conflict(current) if current == applied
            ));
        } else {
            assert!(reopened
                .load_cleanup_actions(&operation_id)
                .test_unwrap()
                .is_empty());
            assert!(matches!(
                reopened.compare_and_swap(request()).test_unwrap(),
                AdmissionOperationCasOutcome::Conflict(current) if current == applied
            ));
        }
        expected_version = applied.version();
    }
}

fn broker_registration(
    invocation_id: &str,
    request_digest: String,
    proof_nonce: &str,
) -> AttemptRegistration {
    AttemptRegistration {
        ids: derive_attempt_ids(
            "broker-capability",
            invocation_id,
            proof_nonce,
            &request_digest,
        )
        .test_unwrap(),
        invocation_id: invocation_id.to_string(),
        parent_capability_id: "leaf".to_string(),
        broker_capability_id: "broker-capability".to_string(),
        request_canonical_digest: request_digest.clone(),
        request_digest,
        proof_digest: "22".repeat(32),
        proof_key_id: "proof-key-1".to_string(),
        proof_nonce: proof_nonce.to_string(),
        nonce_expires_at_unix_seconds: 200,
        quotas: vec![ExecutionQuota {
            key_id: "broker-quota-1".to_string(),
            maximum_executions: 2,
        }],
        authority_metadata_digest: "33".repeat(32),
        revocation_authority_domain: "combined-authority".to_string(),
    }
}

#[test]
fn broker_attempt_ack_recovery_consumes_nonce_before_budget_authority() {
    let directory = tempfile::tempdir().test_unwrap();
    let directory_path = std::fs::canonicalize(directory.path()).test_unwrap();
    let attempt_path = directory_path.join("attempts.sqlite3");
    let budget_path = directory_path.join("budget.sqlite3");
    let registration =
        broker_registration("invocation-1", "11".repeat(32), "proof-nonce-abcdefghijkl");

    assert!(matches!(
        SqliteAttemptStore::open(&attempt_path)
            .test_unwrap()
            .register_attempt(&registration, 100)
            .test_unwrap(),
        RegisterAttemptOutcome::Inserted(_)
    ));
    let reopened = SqliteAttemptStore::open(&attempt_path).test_unwrap();
    assert!(matches!(
        reopened.register_attempt(&registration, 101).test_unwrap(),
        RegisterAttemptOutcome::ExactRetry(_)
    ));

    let replay = broker_registration("invocation-2", "44".repeat(32), "proof-nonce-abcdefghijkl");
    assert!(matches!(
        reopened.register_attempt(&replay, 101),
        Err(BrokerError::AuthorizationDenied(_))
    ));

    let budget = SqliteBudgetStore::open(&budget_path).test_unwrap();
    assert!(budget
        .list_mutation_events(10, None, None)
        .test_unwrap()
        .is_empty());
    assert!(budget
        .authorize_composite_hold(authorize_input(
            "leaf",
            &registration.ids.hold_id,
            &registration.ids.authorize_event_id,
        ))
        .test_unwrap()
        .is_authorized());
    assert_eq!(
        budget
            .list_mutation_events(10, None, None)
            .test_unwrap()
            .len(),
        1
    );
}

fn active_response_intent_body() -> GovernedResponsePlanIntentBody {
    let canonical_plan_body = json!({
        "actionId": "action-1",
        "affectedSetHash": "a".repeat(64),
        "createdAt": 1_000,
        "expiresAt": 1_200,
        "policyVersion": "policy-7",
        "tenant": "tenant-1"
    });
    let plan_body_hash =
        GovernedResponsePlanIntentBody::compute_plan_body_hash(&canonical_plan_body).test_unwrap();
    GovernedResponsePlanIntentBody::new(
        CHIO_RESPONSE_PLAN_SCHEMA,
        "action-1",
        "operator-capability-1",
        "b".repeat(64),
        1_300,
        Keypair::from_seed(&[21; 32]).public_key(),
        canonical_plan_body,
        plan_body_hash,
        json!({"affectedSetHash": "a".repeat(64), "tenant": "tenant-1"}),
        vec![GovernedResponseEffect::RestrictEgress],
        1_200,
        json!({"contributionId": "action-1", "mode": "remove_contribution"}),
    )
    .test_unwrap()
}

#[test]
fn active_response_intent_rejects_body_hash_mismatch_and_raw_hash_substitution() {
    let body = active_response_intent_body();
    let intent = GovernedTransactionIntent::active_response_plan(body.clone());
    assert_ne!(intent.binding_hash().test_unwrap(), body.plan_body_hash());

    let mut raw_hash = serde_json::to_value(&body).test_unwrap();
    raw_hash["canonicalPlanBody"] = json!("a".repeat(64));
    raw_hash["planBodyHash"] = json!("a".repeat(64));
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(raw_hash).is_err());

    let mut mismatched = serde_json::to_value(&body).test_unwrap();
    mismatched["canonicalPlanBody"]["tenant"] = json!("tenant-2");
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(mismatched).is_err());

    let mut embedded_hash = serde_json::to_value(&body).test_unwrap();
    embedded_hash["canonicalPlanBody"] = json!({"planHash": "a".repeat(64)});
    embedded_hash["planBodyHash"] = json!("a".repeat(64));
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(embedded_hash).is_err());

    let mut expired_binding = serde_json::to_value(&body).test_unwrap();
    expired_binding["expiresAt"] = json!(1_301);
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(expired_binding).is_err());
}

struct TestToolServer {
    server_id: String,
    tool_name: String,
    reported_cost: Option<ToolInvocationCost>,
}

#[async_trait::async_trait]
impl ToolServerConnection for TestToolServer {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![self.tool_name.clone()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(json!({"result": "ok"}))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, bridge).await?;
        Ok((value, self.reported_cost.clone()))
    }
}

fn invoke_request(
    request_id: &str,
    capability: &CapabilityToken,
    tool: &str,
    server: &str,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: capability.clone(),
        tool_name: tool.to_string(),
        server_id: server.to_string(),
        agent_id: capability.subject.to_hex(),
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

fn active_response_grant() -> ToolGrant {
    ToolGrant {
        server_id: CHIO_ACTIVE_RESPONSE_SERVER_ID.to_string(),
        tool_name: GovernedResponseEffect::RestrictEgress
            .tool_name()
            .to_string(),
        operations: vec![Operation::Invoke],
        constraints: Vec::new(),
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_unwrap()
        .as_secs()
}

#[test]
fn operator_scoped_capability_rejects_mutation_expiry_and_revocation() {
    let authority = Keypair::from_seed(&[31; 32]);
    let subject = Keypair::from_seed(&[32; 32]);
    let tool = GovernedResponseEffect::RestrictEgress.tool_name();
    let mut kernel = make_kernel(authority.clone());
    kernel.register_tool_server(Box::new(TestToolServer {
        server_id: CHIO_ACTIVE_RESPONSE_SERVER_ID.to_string(),
        tool_name: tool.to_string(),
        reported_cost: None,
    }));
    let capability = kernel
        .issue_capability(
            &subject.public_key(),
            ChioScope {
                grants: vec![active_response_grant()],
                ..ChioScope::default()
            },
            300,
        )
        .test_unwrap();

    let mut mutated = capability.clone();
    mutated.id.push_str("-mutated");
    let mutated_response = kernel
        .evaluate_tool_call_blocking(&invoke_request(
            "operator-mutated",
            &mutated,
            tool,
            CHIO_ACTIVE_RESPONSE_SERVER_ID,
        ))
        .test_unwrap();
    assert_eq!(mutated_response.verdict, Verdict::Deny);

    kernel.revoke_capability(&capability.id).test_unwrap();
    let revoked_response = kernel
        .evaluate_tool_call_blocking(&invoke_request(
            "operator-revoked",
            &capability,
            tool,
            CHIO_ACTIVE_RESPONSE_SERVER_ID,
        ))
        .test_unwrap();
    assert_eq!(revoked_response.verdict, Verdict::Deny);
    assert!(revoked_response
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("revoked"));

    let now = unix_now();
    let expired = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "expired-operator-capability".to_string(),
            issuer: authority.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![active_response_grant()],
                ..ChioScope::default()
            },
            issued_at: now.saturating_sub(2),
            expires_at: now.saturating_sub(1),
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &authority,
    )
    .test_unwrap();
    let expired_response = kernel
        .evaluate_tool_call_blocking(&invoke_request(
            "operator-expired",
            &expired,
            tool,
            CHIO_ACTIVE_RESPONSE_SERVER_ID,
        ))
        .test_unwrap();
    assert_eq!(expired_response.verdict, Verdict::Deny);
    assert!(expired_response
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("expired"));
}

fn active_response_operation() -> AdmissionOperation {
    AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::GovernedActiveResponse,
        coordinator_authority_id: "response-executor-1".to_string(),
        request_id: "active-response-1".to_string(),
        capability_id: "operator-capability-1".to_string(),
        authorization_capability_hash: "11".repeat(32),
        request_binding_hash: "22".repeat(32),
        policy_hash: "33".repeat(32),
        broker_attempt_id: None,
        budget_hold_id: None,
        approval_set_hash: Some("44".repeat(32)),
        execution_nonce_id: None,
        coordinator_lease_epoch: 9,
    })
    .test_unwrap()
}

#[test]
fn approval_only_admission_recovers_without_budget_or_nonce_participants() {
    let directory = tempfile::tempdir().test_unwrap();
    let operation_path = directory.path().join("response-admission.sqlite3");
    let budget_path = directory.path().join("unused-budget.sqlite3");
    let prepared = active_response_operation();
    assert!(prepared.budget_hold_id().is_none());
    assert!(prepared.execution_nonce_id().is_none());
    let operation_id = prepared.operation_id().to_string();
    let store = SqliteAdmissionOperationStore::open(&operation_path).test_unwrap();
    store.create_prepared(prepared).test_unwrap();
    let AdmissionOperationCasOutcome::Applied(reserved) = store
        .compare_and_swap(AdmissionOperationCompareAndSwap {
            operation_id: &operation_id,
            expected_version: 0,
            coordinator_lease_epoch: 9,
            next_state: AdmissionOperationState::ApprovalReserved,
            next_dispatch_state: AdmissionDispatchState::NotStarted,
            next_coordinator_lease_epoch: 9,
            last_error: None,
        })
        .test_unwrap()
    else {
        panic!("approval reservation must persist");
    };
    drop(store);

    let reopened = SqliteAdmissionOperationStore::open(&operation_path).test_unwrap();
    assert_eq!(
        reopened.load(&operation_id).test_unwrap(),
        Some(reserved.clone())
    );
    let AdmissionOperationCasOutcome::Applied(committed) = reopened
        .compare_and_swap(AdmissionOperationCompareAndSwap {
            operation_id: &operation_id,
            expected_version: reserved.version(),
            coordinator_lease_epoch: 9,
            next_state: AdmissionOperationState::DispatchCommitted,
            next_dispatch_state: AdmissionDispatchState::Committed,
            next_coordinator_lease_epoch: 9,
            last_error: None,
        })
        .test_unwrap()
    else {
        panic!("response dispatch must commit once");
    };
    drop(reopened);

    let reopened = SqliteAdmissionOperationStore::open(&operation_path).test_unwrap();
    assert!(matches!(
        reopened
            .compare_and_swap(AdmissionOperationCompareAndSwap {
                operation_id: &operation_id,
                expected_version: reserved.version(),
                coordinator_lease_epoch: 9,
                next_state: AdmissionOperationState::DispatchCommitted,
                next_dispatch_state: AdmissionDispatchState::Committed,
                next_coordinator_lease_epoch: 9,
                last_error: None,
            })
            .test_unwrap(),
        AdmissionOperationCasOutcome::Conflict(current) if current == committed
    ));
    let terminal_request = || AdmissionOperationCompareAndSwap {
        operation_id: &operation_id,
        expected_version: committed.version(),
        coordinator_lease_epoch: 9,
        next_state: AdmissionOperationState::Completed,
        next_dispatch_state: AdmissionDispatchState::EffectCompleted,
        next_coordinator_lease_epoch: 9,
        last_error: None,
    };
    assert!(matches!(
        reopened.compare_and_swap(terminal_request()),
        Err(error) if error.to_string().contains("atomic terminal receipt action")
    ));
    let terminal_action = AdmissionCleanupAction::pending(
        &committed,
        AdmissionCleanupActionKind::TerminalReceipt,
        &json!({"terminal": AdmissionOperationState::Completed.as_str()}),
    )
    .test_unwrap();
    let AdmissionOperationCasOutcome::Applied(completed) = reopened
        .compare_and_swap_with_cleanup_action(terminal_request(), terminal_action.clone())
        .test_unwrap()
    else {
        panic!("completion and terminal receipt outbox insert must apply atomically");
    };
    drop(reopened);
    let reopened = SqliteAdmissionOperationStore::open(&operation_path).test_unwrap();
    assert_eq!(reopened.load(&operation_id).test_unwrap(), Some(completed));
    assert_eq!(
        reopened.load_cleanup_actions(&operation_id).test_unwrap(),
        vec![terminal_action]
    );
    assert!(SqliteBudgetStore::open(&budget_path)
        .test_unwrap()
        .list_mutation_events(10, None, None)
        .test_unwrap()
        .is_empty());
}

#[test]
fn aggregate_authority_is_denied_when_the_feature_is_unnegotiated() {
    let issuer = Keypair::from_seed(&[41; 32]);
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "aggregate-unnegotiated".to_string(),
            issuer: issuer.public_key(),
            subject: Keypair::from_seed(&[42; 32]).public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: Some(AggregateInvocationBudget {
                scope: AggregateInvocationScope::Capability,
                max_invocations: 2,
                root_binding: None,
            }),
        },
        &issuer,
    )
    .test_unwrap();
    let peer = CapabilityNegotiation::t1_default();
    assert!(!peer.supports(AGGREGATE_INVOCATION_BUDGET));
    let trust_roots = |_issuer: &chio_core::PublicKey| None;
    let mut budgets = InMemoryBudgetRegistry::new();
    let error = verify_capability_full(
        &token,
        &[issuer.public_key()],
        &FixedClock::new(150),
        CapabilityCryptoFloor::AllowClassical,
        &peer,
        &trust_roots,
        &mut budgets,
    )
    .test_unwrap_err();
    assert_eq!(
        error,
        CapabilityError::AttenuationViolation(
            "aggregate invocation budget is not negotiated".to_string()
        )
    );
}

fn monetary_grant() -> ToolGrant {
    ToolGrant {
        server_id: "cost-server".to_string(),
        tool_name: "compute".to_string(),
        operations: vec![Operation::Invoke],
        constraints: Vec::new(),
        max_invocations: Some(2),
        max_cost_per_invocation: Some(MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: 1_000,
            currency: "USD".to_string(),
        }),
        dpop_required: None,
    }
}

#[test]
fn signed_receipt_budget_metadata_matches_durable_store_events() {
    let directory = tempfile::tempdir().test_unwrap();
    let budget_path = directory.path().join("receipt-budget.sqlite3");
    let budget_store = Arc::new(SqliteBudgetStore::open(&budget_path).test_unwrap());
    let mut kernel = make_kernel(Keypair::from_seed(&[51; 32]));
    kernel
        .set_budget_store_handle(budget_store.clone())
        .test_unwrap();
    kernel.register_tool_server(Box::new(TestToolServer {
        server_id: "cost-server".to_string(),
        tool_name: "compute".to_string(),
        reported_cost: Some(ToolInvocationCost {
            units: 75,
            currency: "USD".to_string(),
            breakdown: None,
        }),
    }));
    let subject = Keypair::from_seed(&[52; 32]);
    let capability = kernel
        .issue_capability(
            &subject.public_key(),
            ChioScope {
                grants: vec![monetary_grant()],
                ..ChioScope::default()
            },
            300,
        )
        .test_unwrap();
    let response = kernel
        .evaluate_tool_call_blocking(&invoke_request(
            "receipt-store-parity",
            &capability,
            "compute",
            "cost-server",
        ))
        .test_unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(response.receipt.verify_signature().test_unwrap());

    let events = budget_store
        .list_mutation_events(10, Some(&capability.id), Some(0))
        .test_unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].kind, BudgetMutationKind::AuthorizeExposure);
    assert_eq!(events[1].kind, BudgetMutationKind::ReconcileSpend);
    let budget_metadata = &response.receipt.metadata.as_ref().test_unwrap()["budget_authority"];
    assert_eq!(
        budget_metadata["authorize"]["event_id"].as_str(),
        Some(events[0].event_id.as_str())
    );
    assert_eq!(
        budget_metadata["authorize"]["budget_commit_index"].as_u64(),
        events[0].usage_seq
    );
    assert_eq!(
        budget_metadata["authorize"]["exposure_units"].as_u64(),
        Some(events[0].exposure_units)
    );
    assert_eq!(
        budget_metadata["terminal"]["event_id"].as_str(),
        Some(events[1].event_id.as_str())
    );
    assert_eq!(
        budget_metadata["terminal"]["budget_commit_index"].as_u64(),
        events[1].usage_seq
    );
    assert_eq!(
        budget_metadata["terminal"]["realized_spend_units"].as_u64(),
        Some(events[1].realized_spend_units)
    );
}
