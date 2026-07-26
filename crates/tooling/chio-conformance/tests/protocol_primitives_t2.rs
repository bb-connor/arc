use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    aggregate_budget::{
        issue_aggregate_family_root, verify_direct_aggregate_family_root,
        AggregateFamilyRootResolution, AggregateInvocationBudget, AggregateInvocationScope,
        VerifiedAggregateFamilyRoot,
    },
    attenuation::{
        compute_attenuation_witness, scope_hash, AttenuationProof, DelegationLink,
        DelegationLinkBody,
    },
    crypto_floor::CapabilityCryptoFloor,
    features::{
        CapabilityNegotiation, AGGREGATE_INVOCATION_BUDGET, SUPPLEMENTAL_BROKER_EXECUTION_QUOTA,
    },
    governance::{
        GovernedResponseEffect, GovernedResponsePlanIntentBody, GovernedTransactionIntent,
        CHIO_ACTIVE_RESPONSE_SERVER_ID, CHIO_RESPONSE_PLAN_SCHEMA,
    },
    scope::{ChioScope, MonetaryAmount, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
};
use chio_kernel::budget_store::{
    BudgetAdmissionOperationBinding, BudgetCaptureInvocationRequest, BudgetInvocationQuota,
    BudgetInvocationReservationState, BudgetMutationKind, BudgetQuotaKey, BudgetQuotaProfile,
    BudgetReconcileHoldRequest, BudgetReleaseHoldRequest, BudgetReverseHoldRequest, BudgetStore,
    BudgetStoreError,
};
use chio_kernel::payment::{
    OperationPaymentCaptureRequest, PaymentAdapter, PaymentAuthorizeRequest, PaymentError,
    RailSettlementState, SimPaymentAdapter,
};
use chio_kernel::receipt_store::{ReceiptStore, ReceiptStoreError};
use chio_kernel::supplemental_quota::{
    CanonicalRevocationSet, OpaqueSignedSupplementalQuota, SupplementalQuotaDestination,
    SupplementalQuotaError, SupplementalQuotaVerificationContext, SupplementalQuotaVerifier,
    VerifiedSupplementalQuotaClaimBody,
};
use chio_kernel::{
    AdmissionCaptureAuthority, AdmissionCaptureDecision, AdmissionCaptureError,
    AdmissionCaptureRequest, AdmissionCaptureRequestInput, AdmissionCleanupAction,
    AdmissionCleanupActionCasOutcome, AdmissionCleanupActionClaimOutcome,
    AdmissionCleanupActionKind, AdmissionCleanupActionState, AdmissionDispatchState,
    AdmissionOperation, AdmissionOperationCasOutcome, AdmissionOperationCompareAndSwap,
    AdmissionOperationCreateOutcome, AdmissionOperationError, AdmissionOperationKind,
    AdmissionOperationState, AdmissionOperationStore, ApprovalReservationMember,
    ApprovalSetReservationInput, ApprovalStore, ApprovalStoreError, ChioKernel,
    ExecutionNonceReservationError, ExecutionNonceStore, KernelConfig, KernelError,
    NestedFlowBridge, PreparedAdmissionOperation, ReplayReservationState, RevocationRecord,
    RevocationStoreError, ToolCallRequest, ToolInvocationCost, ToolServerConnection, Verdict,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
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
    SqliteAdmissionCaptureAuthority, SqliteAdmissionOperationStore, SqliteApprovalStore,
    SqliteBudgetStore, SqliteExecutionNonceStore, SqliteReceiptStore,
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
        not_before: 90,
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

fn complete_revocation_set(capability_id: &str) -> CanonicalRevocationSet {
    CanonicalRevocationSet::new(
        capability_id,
        &["ancestor-root".to_string(), "ancestor-parent".to_string()],
        &[
            "broker-capability".to_string(),
            "broker-revocation-id".to_string(),
        ],
    )
    .test_unwrap()
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
    authorize_input_with_binding_and_revocations(
        capability_id,
        hold_id,
        event_id,
        operation_id,
        request_binding_hash,
        complete_revocation_set(capability_id),
    )
}

fn authorize_input_with_binding_and_revocations(
    capability_id: &str,
    hold_id: &str,
    event_id: &str,
    operation_id: &str,
    request_binding_hash: &str,
    revocation_set: CanonicalRevocationSet,
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
        revocation_set,
        authorization_artifact_digests: vec!["11".repeat(32)],
        partition_escrow_evidence: None,
    }
}

fn authorize_leaf(path: &std::path::Path, operation_id: &str) {
    authorize_leaf_with_revocations(path, operation_id, complete_revocation_set("leaf"));
}

fn authorize_leaf_with_revocations(
    path: &std::path::Path,
    operation_id: &str,
    revocation_set: CanonicalRevocationSet,
) {
    let store = SqliteBudgetStore::open(path).test_unwrap();
    let request = authorize_input_with_binding_and_revocations(
        "leaf",
        "hold-1",
        "authorize-1",
        operation_id,
        &"44".repeat(32),
        revocation_set,
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
    admission_capture_request_with_revocations(
        operation_id,
        request_binding_hash,
        last_observed_revocation_index,
        complete_revocation_set("leaf"),
    )
}

fn admission_capture_request_with_revocations(
    operation_id: &str,
    request_binding_hash: &str,
    last_observed_revocation_index: Option<u64>,
    revocation_set: CanonicalRevocationSet,
) -> AdmissionCaptureRequest {
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
    quota_counts_for_owner(path, "leaf")
}

fn quota_counts_for_owner(path: &std::path::Path, owner_id: &str) -> (i64, i64) {
    Connection::open(path)
        .test_unwrap()
        .query_row(
            r#"
            SELECT reserved_invocations, captured_invocations
            FROM budget_invocation_quota_usage
            WHERE profile = 'chio.grant-invocation.v1'
              AND owner_id = ?1
              AND grant_index_key = 0
            "#,
            [owner_id],
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

    for (case, revoked_id) in [
        ("leaf", "leaf"),
        ("ancestor-root", "ancestor-root"),
        ("ancestor-parent", "ancestor-parent"),
        ("broker-capability", "broker-capability"),
        ("broker-revocation", "broker-revocation-id"),
    ] {
        let revoked_path = directory.path().join(format!("revoked-{case}.sqlite3"));
        let operation_id = format!("operation-revoked-{case}");
        authorize_leaf(&revoked_path, &operation_id);
        let revoked_authority = SqliteAdmissionCaptureAuthority::open(&revoked_path).test_unwrap();
        let revocation = revoked_authority.revoke(revoked_id).test_unwrap();
        let revoked_request = admission_capture_request(
            &operation_id,
            &"44".repeat(32),
            Some(revocation.revocation_commit_index()),
        );
        let denied = revoked_authority
            .capture_admission(revoked_request.clone())
            .test_unwrap();
        let AdmissionCaptureDecision::Denied(denial) = &denied else {
            panic!("revocation of {revoked_id} must precede denial");
        };
        assert_eq!(denial.revoked_ids(), &[revoked_id.to_string()]);
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

    let mismatched_sets = [
        (
            "omitted-ancestor",
            CanonicalRevocationSet::new(
                "leaf",
                &["ancestor-root".to_string()],
                &[
                    "broker-capability".to_string(),
                    "broker-revocation-id".to_string(),
                ],
            )
            .test_unwrap(),
        ),
        (
            "added-ancestor",
            CanonicalRevocationSet::new(
                "leaf",
                &[
                    "ancestor-root".to_string(),
                    "ancestor-parent".to_string(),
                    "ancestor-extra".to_string(),
                ],
                &[
                    "broker-capability".to_string(),
                    "broker-revocation-id".to_string(),
                ],
            )
            .test_unwrap(),
        ),
        (
            "mutated-supplemental",
            CanonicalRevocationSet::new(
                "leaf",
                &["ancestor-root".to_string(), "ancestor-parent".to_string()],
                &[
                    "broker-capability".to_string(),
                    "broker-revocation-mutated".to_string(),
                ],
            )
            .test_unwrap(),
        ),
    ];
    for (case, presented_set) in mismatched_sets {
        let path = directory
            .path()
            .join(format!("revocation-set-{case}.sqlite3"));
        let operation_id = format!("operation-revocation-set-{case}");
        authorize_leaf(&path, &operation_id);
        let request = admission_capture_request_with_revocations(
            &operation_id,
            &"44".repeat(32),
            None,
            presented_set,
        );
        assert!(SqliteAdmissionCaptureAuthority::open(&path)
            .test_unwrap()
            .capture_admission(request)
            .is_err());
        assert_eq!(quota_counts(&path), (1, 0));
    }
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

fn tool_admission_operation(
    broker_attempt_id: &str,
    coordinator_authority_id: String,
) -> AdmissionOperation {
    AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::ToolDispatch,
        coordinator_authority_id,
        request_id: "request-admission".to_string(),
        capability_id: "leaf".to_string(),
        authorization_capability_hash: "11".repeat(32),
        request_binding_hash: "22".repeat(32),
        policy_hash: "33".repeat(32),
        broker_attempt_id: Some(broker_attempt_id.to_string()),
        budget_hold_id: Some("hold-1".to_string()),
        approval_set_hash: Some("44".repeat(32)),
        execution_nonce_id: Some("nonce-1".to_string()),
        coordinator_lease_epoch: 7,
    })
    .test_unwrap()
}

const REQUIRED_AUTHORITY_CRASH_BOUNDARIES: &[&str] = &[
    "operation.create_prepared",
    "attempt.register",
    "operation.cas.broker_attempt_registered",
    "budget.authorize_composite_hold",
    "operation.cas.budget_authorized",
    "operation.cas.delegated_budget_reserved",
    "payment.authorize_for_operation",
    "operation.cas.payment_authorized",
    "approval.reserve_approval_set",
    "operation.cas.approval_reserved",
    "nonce.reserve_nonce_for_operation",
    "operation.cas.ready_to_dispatch",
    "operation.cas.capture_pending",
    "approval.commit_approval_reservation",
    "nonce.commit_nonce_reservation",
    "combined.capture_admission",
    "operation.cas.dispatch_committed",
    "payment.capture_for_operation",
    "budget.reconcile_budget_hold",
    "operation.cas.completed_with_terminal_receipt",
    "nonce.reserve_cancel_path",
    "nonce.cancel_nonce_reservation",
    "approval.reserve_cancel_path",
    "approval.cancel_approval_reservation",
    "combined.upsert_revocation",
    "budget.reverse_budget_hold",
    "budget.release_budget_hold",
    "payment.release_for_operation",
    "receipt.append_chio_receipt",
];

#[derive(Default)]
struct AuthorityCrashBoundaryInventory {
    observed: Vec<String>,
    unique: BTreeSet<String>,
}

impl AuthorityCrashBoundaryInventory {
    fn before<T>(&mut self, boundary: &'static str, authority_call: impl FnOnce() -> T) {
        assert!(matches!(
            inject_before_authority_call(authority_call),
            Err(InjectedBeforeAuthorityCall)
        ));
        self.record(boundary, "before");
    }

    fn response_lost(&mut self, boundary: &'static str) {
        self.record(boundary, "response_lost_after_commit");
    }

    fn recovered(&mut self, boundary: &'static str) {
        self.record(boundary, "recovered_exact_retry");
    }

    fn record(&mut self, boundary: &'static str, stage: &'static str) {
        assert!(
            REQUIRED_AUTHORITY_CRASH_BOUNDARIES.contains(&boundary),
            "unregistered authority crash boundary: {boundary}"
        );
        let observation = format!("{boundary}:{stage}");
        assert!(
            self.unique.insert(observation.clone()),
            "authority crash boundary stage repeated: {observation}"
        );
        self.observed.push(observation);
    }

    fn assert_complete(self) {
        let expected = REQUIRED_AUTHORITY_CRASH_BOUNDARIES
            .iter()
            .flat_map(|boundary| {
                [
                    format!("{boundary}:before"),
                    format!("{boundary}:response_lost_after_commit"),
                    format!("{boundary}:recovered_exact_retry"),
                ]
            })
            .collect::<Vec<_>>();
        assert_eq!(self.observed, expected);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InjectedBeforeAuthorityCall;

fn inject_before_authority_call<T>(
    authority_call: impl FnOnce() -> T,
) -> Result<T, InjectedBeforeAuthorityCall> {
    drop(authority_call);
    Err(InjectedBeforeAuthorityCall)
}

fn lose_response_after_commit<T, E>(
    commit: impl FnOnce() -> Result<T, E>,
    acknowledgement_loss: E,
) -> Result<T, E> {
    let _committed = commit()?;
    Err(acknowledgement_loss)
}

fn standalone_crash_matrix_receipt() -> ChioReceipt {
    let signer = Keypair::from_seed(&[79; 32]);
    ChioReceipt::sign(
        ChioReceiptBody {
            id: "protocol-authority-crash-matrix-receipt".to_string(),
            timestamp: unix_now(),
            capability_id: "protocol-authority-crash-matrix-capability".to_string(),
            tool_server: "protocol-authority-crash-matrix-server".to_string(),
            tool_name: "execute".to_string(),
            action: ToolCallAction::from_parameters(json!({"boundary": "receipt-persistence"}))
                .test_unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: sha256_hex(b"protocol-authority-crash-matrix"),
            policy_hash: "55".repeat(32),
            evidence: Vec::new(),
            metadata: None,
            trust_level: Default::default(),
            tenant_id: None,
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
        },
        &signer,
    )
    .test_unwrap()
}

fn terminal_crash_matrix_receipt(operation: &AdmissionOperation, signer: &Keypair) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: format!("terminal-{}", operation.operation_id()),
            timestamp: unix_now(),
            capability_id: operation.capability_id().to_string(),
            tool_server: "protocol-authority-crash-matrix-server".to_string(),
            tool_name: "execute".to_string(),
            action: ToolCallAction::from_parameters(json!({
                "operation_id": operation.operation_id(),
                "request_binding_hash": operation.request_binding_hash(),
                "terminal_state": operation.state().as_str(),
            }))
            .test_unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: sha256_hex(operation.operation_id().as_bytes()),
            policy_hash: operation.policy_hash().to_string(),
            evidence: Vec::new(),
            metadata: Some(json!({
                "receipt_context": {
                    "request_id": operation.request_id(),
                },
                "protocol_admission": {
                    "admission_operation": {
                        "operation_id": operation.operation_id(),
                        "state": operation.state().as_str(),
                        "dispatch_state": operation.dispatch_state().as_str(),
                        "version": operation.version(),
                        "last_error": operation.last_error(),
                    },
                },
            })),
            trust_level: chio_core::receipt::kinds::TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
        },
        signer,
    )
    .test_unwrap()
}

fn recover_terminal_operation_after_lost_response(
    operation_path: &std::path::Path,
    receipt_path: &std::path::Path,
    current: &AdmissionOperation,
    signer: &Keypair,
    inventory: &mut AuthorityCrashBoundaryInventory,
) -> AdmissionOperation {
    const BOUNDARY: &str = "operation.cas.completed_with_terminal_receipt";
    let terminal = current
        .transition_checked(
            AdmissionOperationState::Completed,
            AdmissionDispatchState::EffectCompleted,
            current.coordinator_lease_epoch(),
            None,
        )
        .test_unwrap();
    let receipt = terminal_crash_matrix_receipt(&terminal, signer);
    let payload = json!({
        "schema": "chio.admission-terminal-receipt.v1",
        "operationId": terminal.operation_id(),
        "requestBindingHash": terminal.request_binding_hash(),
        "terminalState": terminal.state().as_str(),
        "terminalDispatchState": terminal.dispatch_state().as_str(),
        "terminalCoordinatorLeaseEpoch": terminal.coordinator_lease_epoch(),
        "terminalVersion": terminal.version(),
        "terminalLastError": terminal.last_error(),
        "receiptAuthorityId": format!("kernel:{}", receipt.kernel_key.to_hex()),
        "receipt": receipt,
    });
    let action = AdmissionCleanupAction::pending(
        current,
        AdmissionCleanupActionKind::TerminalReceipt,
        &payload,
    )
    .test_unwrap();
    let request = || AdmissionOperationCompareAndSwap {
        operation_id: current.operation_id(),
        expected_version: current.version(),
        coordinator_lease_epoch: current.coordinator_lease_epoch(),
        next_state: terminal.state(),
        next_dispatch_state: terminal.dispatch_state(),
        next_coordinator_lease_epoch: terminal.coordinator_lease_epoch(),
        last_error: terminal.last_error().map(ToOwned::to_owned),
    };

    let before = SqliteAdmissionOperationStore::open(operation_path).test_unwrap();
    assert_eq!(
        before.load(current.operation_id()).test_unwrap(),
        Some(current.clone())
    );
    assert!(before
        .load_cleanup_actions(current.operation_id())
        .test_unwrap()
        .is_empty());
    inventory.before(BOUNDARY, || {
        before.compare_and_swap_with_cleanup_action(request(), action.clone())
    });
    drop(before);

    let store = SqliteAdmissionOperationStore::open(operation_path).test_unwrap();
    let lost = lose_response_after_commit(
        || store.compare_and_swap_with_cleanup_action(request(), action.clone()),
        AdmissionOperationError::Unavailable(
            "injected terminal operation acknowledgement loss".to_string(),
        ),
    );
    assert!(matches!(lost, Err(AdmissionOperationError::Unavailable(_))));
    drop(store);
    inventory.response_lost(BOUNDARY);

    let reopened = SqliteAdmissionOperationStore::open(operation_path).test_unwrap();
    let recovered = reopened
        .load(current.operation_id())
        .test_unwrap()
        .test_unwrap();
    assert_eq!(recovered, terminal);
    let recovered_actions = reopened
        .load_cleanup_actions(current.operation_id())
        .test_unwrap();
    assert_eq!(recovered_actions, vec![action.clone()]);
    assert!(matches!(
        reopened
            .compare_and_swap_with_cleanup_action(request(), action.clone())
            .test_unwrap(),
        AdmissionOperationCasOutcome::Conflict(conflict) if conflict == recovered
    ));

    let recovered_payload: serde_json::Value =
        serde_json::from_str(action.payload_json()).test_unwrap();
    assert_eq!(recovered_payload, payload);
    assert_eq!(
        recovered_payload["operationId"].as_str(),
        Some(recovered.operation_id())
    );
    assert_eq!(
        recovered_payload["requestBindingHash"].as_str(),
        Some(recovered.request_binding_hash())
    );
    assert_eq!(
        recovered_payload["terminalVersion"].as_u64(),
        Some(recovered.version())
    );
    assert_eq!(
        recovered_payload["terminalState"].as_str(),
        Some(recovered.state().as_str())
    );
    assert_eq!(
        recovered_payload["terminalDispatchState"].as_str(),
        Some(recovered.dispatch_state().as_str())
    );
    assert_eq!(
        recovered_payload["terminalCoordinatorLeaseEpoch"].as_u64(),
        Some(recovered.coordinator_lease_epoch())
    );
    assert_eq!(
        recovered_payload["receiptAuthorityId"].as_str(),
        Some(recovered.coordinator_authority_id())
    );
    assert!(recovered_payload["terminalLastError"].is_null());
    assert!(recovered_payload.get("executorReceipt").is_none());
    let recovered_receipt: ChioReceipt =
        serde_json::from_value(recovered_payload["receipt"].clone()).test_unwrap();
    assert!(recovered_receipt.verify_signature().test_unwrap());
    assert_eq!(recovered_receipt.kernel_key, signer.public_key());
    assert_eq!(
        recovered_receipt.trust_level,
        chio_core::receipt::kinds::TrustLevel::Mediated
    );
    assert_eq!(
        recovered_receipt.capability_id.as_str(),
        recovered.capability_id()
    );
    assert_eq!(
        recovered_receipt.policy_hash.as_str(),
        recovered.policy_hash()
    );
    let receipt_metadata = recovered_receipt.metadata.as_ref().test_unwrap();
    assert_eq!(
        receipt_metadata
            .pointer("/receipt_context/request_id")
            .and_then(serde_json::Value::as_str),
        Some(recovered.request_id())
    );
    assert_eq!(
        receipt_metadata
            .pointer("/protocol_admission/admission_operation/operation_id")
            .and_then(serde_json::Value::as_str),
        Some(recovered.operation_id())
    );
    assert_eq!(
        receipt_metadata
            .pointer("/protocol_admission/admission_operation/state")
            .and_then(serde_json::Value::as_str),
        Some(recovered.state().as_str())
    );
    assert_eq!(
        receipt_metadata
            .pointer("/protocol_admission/admission_operation/dispatch_state")
            .and_then(serde_json::Value::as_str),
        Some(recovered.dispatch_state().as_str())
    );
    assert_eq!(
        receipt_metadata
            .pointer("/protocol_admission/admission_operation/version")
            .and_then(serde_json::Value::as_u64),
        Some(recovered.version())
    );
    assert!(receipt_metadata
        .pointer("/protocol_admission/admission_operation/last_error")
        .is_some_and(serde_json::Value::is_null));
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(&recovered_receipt).test_unwrap(),
        chio_core::canonical::canonical_json_bytes(&receipt).test_unwrap()
    );

    let receipt_store = SqliteReceiptStore::open(receipt_path).test_unwrap();
    ReceiptStore::append_chio_receipt_with_timeout(
        &receipt_store,
        &recovered_receipt,
        std::time::Duration::from_secs(5),
    )
    .test_unwrap()
    .test_unwrap();
    assert_eq!(
        receipt_store
            .load_chio_receipt(&recovered_receipt.id)
            .test_unwrap()
            .as_ref()
            .map(|stored| chio_core::canonical::canonical_json_bytes(stored).test_unwrap()),
        Some(chio_core::canonical::canonical_json_bytes(&receipt).test_unwrap())
    );

    let claim_token = "terminal-receipt-worker";
    let claim_now = unix_now().saturating_mul(1_000);
    let AdmissionCleanupActionClaimOutcome::Claimed(claimed) = reopened
        .claim_cleanup_action(
            action.action_id(),
            claim_token,
            claim_now,
            claim_now.saturating_add(10_000),
        )
        .test_unwrap()
    else {
        panic!("terminal receipt cleanup action must be claimable after recovery");
    };
    let AdmissionCleanupActionCasOutcome::Applied(completed_action) = reopened
        .acknowledge_cleanup_action(claimed.action_id(), claimed.version(), claim_token)
        .test_unwrap()
    else {
        panic!("persisted terminal receipt cleanup action must be acknowledged");
    };
    assert_eq!(
        completed_action.state(),
        AdmissionCleanupActionState::Completed
    );
    assert_eq!(
        reopened
            .load_cleanup_actions(current.operation_id())
            .test_unwrap(),
        vec![completed_action]
    );
    inventory.recovered(BOUNDARY);
    recovered
}

fn recover_operation_state_after_lost_response(
    path: &std::path::Path,
    current: &AdmissionOperation,
    next_state: AdmissionOperationState,
    next_dispatch_state: AdmissionDispatchState,
    boundary: &'static str,
    inventory: &mut AuthorityCrashBoundaryInventory,
) -> AdmissionOperation {
    assert!(!next_state.is_terminal());
    let operation_id = current.operation_id();
    let request = || AdmissionOperationCompareAndSwap {
        operation_id,
        expected_version: current.version(),
        coordinator_lease_epoch: current.coordinator_lease_epoch(),
        next_state,
        next_dispatch_state,
        next_coordinator_lease_epoch: current.coordinator_lease_epoch(),
        last_error: None,
    };
    let before = SqliteAdmissionOperationStore::open(path).test_unwrap();
    assert_eq!(
        before.load(operation_id).test_unwrap().as_ref(),
        Some(current)
    );
    assert!(before
        .load_cleanup_actions(operation_id)
        .test_unwrap()
        .is_empty());
    inventory.before(boundary, || before.compare_and_swap(request()));
    drop(before);

    let store = SqliteAdmissionOperationStore::open(path).test_unwrap();
    let lost = lose_response_after_commit(
        || store.compare_and_swap(request()),
        AdmissionOperationError::Unavailable(
            "injected operation transition acknowledgement loss".to_string(),
        ),
    );
    assert!(matches!(lost, Err(AdmissionOperationError::Unavailable(_))));
    drop(store);
    inventory.response_lost(boundary);

    let reopened = SqliteAdmissionOperationStore::open(path).test_unwrap();
    let recovered = reopened.load(operation_id).test_unwrap().test_unwrap();
    assert_eq!(recovered.state(), next_state);
    assert_eq!(recovered.dispatch_state(), next_dispatch_state);
    assert!(reopened
        .load_cleanup_actions(operation_id)
        .test_unwrap()
        .is_empty());
    assert!(matches!(
        reopened.compare_and_swap(request()).test_unwrap(),
        AdmissionOperationCasOutcome::Conflict(conflict) if conflict == recovered
    ));
    inventory.recovered(boundary);
    recovered
}

include!("protocol_primitives_t2_tail.inc");
