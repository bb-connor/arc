mod committed_readback;
mod config;
mod expired_resume;
mod request;

use self::config::{readiness, validate_lease_duration};
use self::request::{ActiveResponseRequestSource, RawActiveResponseExecutionRequest};

use super::active_response_validation::{
    decode_lower_hex_digest, digest_is_zero, has_durable_execution_proof, recovery_id,
    valid_prefixed_digest_id,
};
use chio_kernel::{
    derive_active_response_dispatch_id, ActiveResponseCommittedDispatch,
    ActiveResponseEffectEvidence, ActiveResponseExecutionApproval, ActiveResponseExecutionEvidence,
    ActiveResponseExecutionEvidenceParts, ActiveResponseExecutionOutcome,
    ActiveResponseExecutionRequest, ActiveResponseExecutorAuthority,
    ActiveResponseExecutorAuthorityIdentity, ActiveResponseExecutorError,
    ActiveResponseFailedEffectEvidence, ActiveResponseFailureEvidence,
    ActiveResponseReceiptProofSource, AutomaticActiveResponseDispatchFenceOutcome,
};
use chio_quarantine::{
    decode_response_record, prepare_response_dispatch, DurableActiveResponseOutcome,
    ResponseDispatchPreparationRequest, ResponseExecutor,
};
use chio_security_kernel::SecurityClock;
use chio_security_types::ports::{
    AutomaticResponseDispatchFenceOutcome, AutomaticResponseDispatchFenceRequest, Digest32,
    EffectPort, LeaseOwnerId, PortErrorKind, PreparedActiveResponseDispatchBinding, RecordId,
    ResponseDispatchApproval, ResponseDispatchCommitMode, ResponseDispatchCommitOutcome,
    ResponseDispatchKey, ResponseDispatchLease, ResponseDispatchLoadOutcome,
    ResponseDispatchRecord, ResponseDispatchRecoveryOutcome, ResponseDispatchRecoveryRequest,
    ResponseDispatchStore, ResponsePlanKey, ResponsePlanRecord, ScheduledWork, SchedulerWorkKey,
    SecurityAlertPort, SecurityReceiptSink,
    PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
};
use chio_security_types::{ResponseApprovalRequirement, ResponsePlan, ResponseState};
use std::sync::Arc;
use thiserror::Error;

include!("active_response/executor.inc");
#[cfg(test)]
mod tests {
    use super::super::adapters::NativeSecurityReceiptSink;
    use super::*;
    use chio_core::receipt::body::ChioReceipt;
    use chio_core::receipt::security::{ActiveDefenseEffectOutcome, ActiveDefenseReceiptBody};
    use chio_core::{Ed25519Backend, Keypair, SigningBackend};
    use chio_kernel::{
        ActiveResponseExecutionApproval, ActiveResponseExecutorAuthorityIdentity,
        ActiveResponseExecutorError, IndexedSecurityEvidenceStore, ReceiptStoreError,
    };
    use chio_quarantine::{
        build_response_plan, EffectMutation, EffectMutationRequest, EffectReceiptContext,
        ResponseStateMachine, ResponseTransitionRequest,
    };
    use chio_security_kernel::SecurityClock;
    use chio_security_types::ports::{
        ActionId, AlertDeliveryQuery, AlertDeliveryStatus, CanonicalBody, Digest32,
        EffectExecutionStatus, EffectOperation, EffectPort, EffectRequest, EffectResult,
        EffectResultQuery, ErrorCode, OpaqueReceiptRef, PortError, PortResult,
        ReceiptAppendRequest, RecordId, ResponseDispatchKey, ResponseDispatchLoadOutcome,
        ResponseDispatchStore, ResponsePlanKey, ResponseStore, SchedulerClaimRequest,
        SecurityAlert, SecurityAlertPort, SecurityReceiptSink, SessionId, TenantId,
    };
    use chio_security_types::{
        OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind,
        ResponseEffectProgress, ResponseEffectSpec, ResponsePlan, ResponsePlanInput,
        ResponseTarget,
    };
    use chio_store_sqlite::SqliteSecurityStateStore;
    use rusqlite::Connection;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tempfile::TempDir;

    pub(super) type TestExecutor = DurableActiveResponseExecutor<
        SqliteSecurityStateStore,
        TestEffects,
        TestReceipts,
        TestAlerts,
    >;

    const TEST_ACTIVE_RESPONSE_LEASE_OWNER_ID: &str = "active-response-test-worker-a";

    struct FixedClock {
        now_unix_ms: AtomicU64,
        calls: AtomicUsize,
        fail_on_call: AtomicUsize,
    }

    impl FixedClock {
        fn new(now_unix_ms: u64) -> Self {
            Self {
                now_unix_ms: AtomicU64::new(now_unix_ms),
                calls: AtomicUsize::new(0),
                fail_on_call: AtomicUsize::new(0),
            }
        }

        fn set(&self, now_unix_ms: u64) {
            self.now_unix_ms.store(now_unix_ms, Ordering::SeqCst);
        }

        fn fail_after_next_success(&self) {
            self.fail_on_call.store(
                self.calls.load(Ordering::SeqCst).saturating_add(2),
                Ordering::SeqCst,
            );
        }
    }

    impl SecurityClock for FixedClock {
        fn now_unix_ms(&self) -> PortResult<u64> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst).saturating_add(1);
            if self.fail_on_call.load(Ordering::SeqCst) == call {
                self.fail_on_call.store(0, Ordering::SeqCst);
                return Err(PortError::unavailable());
            }
            Ok(self.now_unix_ms.load(Ordering::SeqCst))
        }
    }

    struct TestStoreClock {
        clock: Arc<FixedClock>,
    }

    impl chio_store_sqlite::security_state::SecurityStateClock for TestStoreClock {
        fn now_unix_ms(&self) -> PortResult<u64> {
            Ok(self.clock.now_unix_ms.load(Ordering::SeqCst))
        }
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum EffectMode {
        #[default]
        Normal,
        Rejected,
        Unknown,
        Unavailable,
    }

    #[derive(Default)]
    struct EffectState {
        mode: EffectMode,
        replay: BTreeMap<String, (EffectRequest, EffectResult)>,
        executions: usize,
        apply_executions: usize,
        remove_executions: usize,
        last_fencing_token: Option<u64>,
    }

    #[derive(Default)]
    pub(super) struct TestEffects {
        ready: AtomicBool,
        state: Mutex<EffectState>,
    }

    impl TestEffects {
        fn ready() -> Self {
            Self {
                ready: AtomicBool::new(true),
                state: Mutex::new(EffectState::default()),
            }
        }

        fn set_mode(&self, mode: EffectMode) {
            self.state
                .lock()
                .unwrap_or_else(|_| panic!("effect state mutex poisoned"))
                .mode = mode;
        }

        fn executions(&self) -> usize {
            self.state
                .lock()
                .unwrap_or_else(|_| panic!("effect state mutex poisoned"))
                .executions
        }

        fn last_fencing_token(&self) -> Option<u64> {
            self.state
                .lock()
                .unwrap_or_else(|_| panic!("effect state mutex poisoned"))
                .last_fencing_token
        }

        fn mutation_counts(&self) -> (usize, usize) {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|_| panic!("effect state mutex poisoned"));
            (state.apply_executions, state.remove_executions)
        }
    }

    impl EffectPort for TestEffects {
        fn ensure_effects_ready(&self) -> PortResult<()> {
            if self.ready.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(PortError::unavailable())
            }
        }

        fn execute(&self, request: &EffectRequest) -> PortResult<EffectResult> {
            let mut state = self.state.lock().map_err(|_| PortError::unavailable())?;
            if let Some((stored_request, stored_result)) =
                state.replay.get(request.idempotency_key.as_str())
            {
                if stored_request != request {
                    return Err(PortError::conflict());
                }
                return Ok(stored_result.clone());
            }
            let result = EffectResult {
                effect_id: request.effect_id.clone(),
                resulting_version_hash: match request.operation {
                    EffectOperation::Apply => digest(70),
                    EffectOperation::Remove => request.expected_version_hash,
                },
                applied: request.operation == EffectOperation::Apply,
            };
            state.executions = state.executions.saturating_add(1);
            match request.operation {
                EffectOperation::Apply => {
                    state.apply_executions = state.apply_executions.saturating_add(1);
                }
                EffectOperation::Remove => {
                    state.remove_executions = state.remove_executions.saturating_add(1);
                }
            }
            state.last_fencing_token = Some(request.scheduler_fencing_token);
            state.replay.insert(
                request.idempotency_key.as_str().to_owned(),
                (request.clone(), result.clone()),
            );
            Ok(result)
        }

        fn load_result(&self, query: &EffectResultQuery) -> PortResult<EffectExecutionStatus> {
            let state = self.state.lock().map_err(|_| PortError::unavailable())?;
            match state.mode {
                EffectMode::Rejected => {
                    return Ok(EffectExecutionStatus::Failed {
                        error_code: ErrorCode::new("test.effect_rejected")
                            .map_err(|_| PortError::invalid_data())?,
                    });
                }
                EffectMode::Unknown => return Ok(EffectExecutionStatus::Unknown),
                EffectMode::Unavailable => return Err(PortError::unavailable()),
                EffectMode::Normal => {}
            }
            let Some((request, result)) = state.replay.get(query.idempotency_key.as_str()) else {
                return Ok(EffectExecutionStatus::NotExecuted);
            };
            if request.tenant_id != query.tenant_id
                || request.action_id != query.action_id
                || request.plan_hash != query.plan_hash
                || request.effect_id != query.effect_id
                || request.effect_kind != query.effect_kind
                || request.target != query.target
                || request.plan_expires_at_unix_ms != query.plan_expires_at_unix_ms
                || request.operation != query.operation
                || request.expected_version_hash != query.expected_version_hash
                || request.contribution_hash != query.contribution_hash
                || request.scheduler_lease_owner_id != query.scheduler_lease_owner_id
                || request.scheduler_fencing_token != query.scheduler_fencing_token
            {
                return Err(PortError::conflict());
            }
            Ok(EffectExecutionStatus::Completed {
                result: result.clone(),
            })
        }
    }

    pub(super) struct TestReceipts {
        inner: NativeSecurityReceiptSink,
        ready: AtomicBool,
        fail_next: AtomicBool,
        fail_effect_state: Mutex<Option<String>>,
        appends: AtomicUsize,
    }

    impl TestReceipts {
        fn ready(signer: Arc<dyn SigningBackend>) -> Self {
            let store: Arc<dyn IndexedSecurityEvidenceStore> =
                Arc::new(TestIndexedSecurityEvidenceStore::default());
            Self {
                inner: NativeSecurityReceiptSink::new(store, signer),
                ready: AtomicBool::new(true),
                fail_next: AtomicBool::new(false),
                fail_effect_state: Mutex::new(None),
                appends: AtomicUsize::new(0),
            }
        }

        fn fail_once_on_effect_state(&self, effect_state: &str) {
            *self
                .fail_effect_state
                .lock()
                .unwrap_or_else(|_| panic!("receipt failure state mutex poisoned")) =
                Some(effect_state.to_string());
        }
    }

    impl SecurityReceiptSink for TestReceipts {
        fn ensure_receipts_ready(&self) -> PortResult<()> {
            if self.ready.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(PortError::unavailable())
            }
        }

        fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(PortError::unavailable());
            }
            self.appends.fetch_add(1, Ordering::SeqCst);
            let body: ActiveDefenseReceiptBody =
                serde_json::from_slice(request.canonical_body.as_bytes())
                    .map_err(|_| PortError::invalid_data())?;
            let effect_state = match &body {
                ActiveDefenseReceiptBody::EffectTransition(effect) => Some(match &effect.outcome {
                    ActiveDefenseEffectOutcome::Planned => "planned",
                    ActiveDefenseEffectOutcome::Requested => "apply_requested",
                    ActiveDefenseEffectOutcome::Applied { .. } => "applied",
                    ActiveDefenseEffectOutcome::ApplyFailed { .. } => "apply_failed",
                    ActiveDefenseEffectOutcome::RollbackRequested => "rollback_requested",
                    ActiveDefenseEffectOutcome::Restored { .. } => "restored",
                    ActiveDefenseEffectOutcome::RollbackFailed { .. } => "rollback_failed",
                    ActiveDefenseEffectOutcome::NoRollbackRequired => "no_rollback_required",
                }),
                _ => None,
            };
            let lose_ack = {
                let mut fail_effect_state = self
                    .fail_effect_state
                    .lock()
                    .map_err(|_| PortError::unavailable())?;
                let lose_ack = fail_effect_state
                    .as_deref()
                    .is_some_and(|expected| effect_state == Some(expected));
                if lose_ack {
                    *fail_effect_state = None;
                }
                lose_ack
            };
            let appended = self.inner.sign_and_append(request)?;
            if lose_ack {
                Err(PortError::unavailable())
            } else {
                Ok(appended)
            }
        }
    }

    impl ActiveResponseReceiptProofSource for TestReceipts {
        fn ensure_active_response_receipt_proofs_ready(
            &self,
        ) -> Result<(), ActiveResponseExecutorError> {
            self.inner.ensure_active_response_receipt_proofs_ready()
        }

        fn load_signed_active_response_receipt(
            &self,
            evidence_id: &OpaqueReceiptRef,
        ) -> Result<Option<ChioReceipt>, ActiveResponseExecutorError> {
            self.inner.load_signed_active_response_receipt(evidence_id)
        }
    }

    #[derive(Default)]
    struct TestIndexedSecurityEvidenceStore {
        receipts: Mutex<BTreeMap<String, ChioReceipt>>,
    }

    impl IndexedSecurityEvidenceStore for TestIndexedSecurityEvidenceStore {
        fn ensure_indexed_security_evidence_ready(&self) -> Result<(), ReceiptStoreError> {
            self.receipts.lock().map(|_| ()).map_err(|_| {
                ReceiptStoreError::ReadBoundary(
                    "test active-response receipt index lock is poisoned".to_string(),
                )
            })
        }

        fn append_indexed_security_evidence(
            &self,
            evidence_id: &OpaqueReceiptRef,
            receipt: &ChioReceipt,
        ) -> Result<ChioReceipt, ReceiptStoreError> {
            let mut receipts = self.receipts.lock().map_err(|_| {
                ReceiptStoreError::ReadBoundary(
                    "test active-response receipt index lock is poisoned".to_string(),
                )
            })?;
            if let Some(existing) = receipts.get(evidence_id.as_str()) {
                return Ok(existing.clone());
            }
            receipts.insert(evidence_id.as_str().to_string(), receipt.clone());
            Ok(receipt.clone())
        }

        fn load_indexed_security_evidence(
            &self,
            evidence_id: &OpaqueReceiptRef,
        ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
            self.receipts
                .lock()
                .map_err(|_| {
                    ReceiptStoreError::ReadBoundary(
                        "test active-response receipt index lock is poisoned".to_string(),
                    )
                })
                .map(|receipts| receipts.get(evidence_id.as_str()).cloned())
        }
    }

    pub(super) struct TestAlerts {
        ready: AtomicBool,
    }

    impl TestAlerts {
        fn ready() -> Self {
            Self {
                ready: AtomicBool::new(true),
            }
        }
    }

    impl SecurityAlertPort for TestAlerts {
        fn ensure_alerts_ready(&self) -> PortResult<()> {
            if self.ready.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(PortError::unavailable())
            }
        }

        fn page(&self, alert: &SecurityAlert) -> PortResult<AlertDeliveryStatus> {
            Ok(AlertDeliveryStatus::Delivered {
                attempts: 1,
                delivered_at_unix_ms: alert.occurred_at_unix_ms,
            })
        }

        fn load_delivery(
            &self,
            query: &AlertDeliveryQuery,
        ) -> PortResult<Option<AlertDeliveryStatus>> {
            Ok(Some(AlertDeliveryStatus::Delivered {
                attempts: 1,
                delivered_at_unix_ms: query.alert.occurred_at_unix_ms,
            }))
        }
    }

    pub(super) struct Harness {
        _tempdir: TempDir,
        pub(super) database_path: std::path::PathBuf,
        store: Arc<SqliteSecurityStateStore>,
        effects: Arc<TestEffects>,
        receipts: Arc<TestReceipts>,
        alerts: Arc<TestAlerts>,
        clock: Arc<FixedClock>,
        identity: ActiveResponseExecutorAuthorityIdentity,
        pub(super) executor: TestExecutor,
        now_unix_ms: u64,
    }

    impl Harness {
        pub(super) fn new() -> Self {
            Self::with_lease_duration(30_000)
        }

        fn with_lease_duration(lease_duration_ms: u64) -> Self {
            let now_unix_ms = system_now_unix_ms();
            let tempdir = tempfile::tempdir()
                .unwrap_or_else(|error| panic!("create executor test directory: {error}"));
            let database_path = tempdir.path().join("active-response.sqlite3");
            let clock = Arc::new(FixedClock::new(now_unix_ms));
            let store_clock: Arc<dyn chio_store_sqlite::security_state::SecurityStateClock> =
                Arc::new(TestStoreClock {
                    clock: Arc::clone(&clock),
                });
            let store = Arc::new(
                SqliteSecurityStateStore::open_with_trusted_clock(&database_path, store_clock)
                    .unwrap_or_else(|error| panic!("open security state store: {error}")),
            );
            let effects = Arc::new(TestEffects::ready());
            let signing_key = Keypair::from_seed(&[7_u8; 32]);
            let signer: Arc<dyn SigningBackend> =
                Arc::new(Ed25519Backend::new(signing_key.clone()));
            let receipts = Arc::new(TestReceipts::ready(signer));
            let alerts = Arc::new(TestAlerts::ready());
            let identity =
                ActiveResponseExecutorAuthorityIdentity::new(signing_key.public_key(), 7)
                    .unwrap_or_else(|error| panic!("construct executor identity: {error}"));
            let lease_owner_id = LeaseOwnerId::new(TEST_ACTIVE_RESPONSE_LEASE_OWNER_ID)
                .unwrap_or_else(|error| panic!("construct executor lease owner: {error}"));
            let executor = DurableActiveResponseExecutor::new(
                identity.clone(),
                lease_owner_id,
                Arc::clone(&store),
                Arc::clone(&effects),
                Arc::clone(&receipts),
                Arc::clone(&alerts),
                clock.clone(),
                lease_duration_ms,
            )
            .unwrap_or_else(|error| panic!("construct durable executor: {error}"));
            Self {
                _tempdir: tempdir,
                database_path,
                store,
                effects,
                receipts,
                alerts,
                clock,
                identity,
                executor,
                now_unix_ms,
            }
        }

        fn executor_with_lease_owner(&self, lease_owner_id: &str) -> TestExecutor {
            let lease_owner_id = LeaseOwnerId::new(lease_owner_id)
                .unwrap_or_else(|error| panic!("construct executor lease owner: {error}"));
            DurableActiveResponseExecutor::new(
                self.identity.clone(),
                lease_owner_id,
                Arc::clone(&self.store),
                Arc::clone(&self.effects),
                Arc::clone(&self.receipts),
                Arc::clone(&self.alerts),
                self.clock.clone(),
                30_000,
            )
            .unwrap_or_else(|error| panic!("construct durable executor replica: {error}"))
        }

        pub(super) fn automatic_request(&self) -> RawActiveResponseExecutionRequest {
            let plan = plan(
                self.now_unix_ms,
                &self.identity,
                ResponseApprovalRequirement::Automatic,
                false,
            );
            raw_request(
                plan,
                self.identity.clone(),
                ActiveResponseExecutionApproval::Automatic,
            )
        }

        pub(super) fn governed_request(&self) -> RawActiveResponseExecutionRequest {
            let plan = plan(
                self.now_unix_ms,
                &self.identity,
                ResponseApprovalRequirement::Governed {
                    policy_id: record_id("response-governance-policy"),
                },
                false,
            );
            raw_request(
                plan,
                self.identity.clone(),
                ActiveResponseExecutionApproval::Governed {
                    admission_operation_id: "admission-operation-42".to_string(),
                    admission_operation_version: 3,
                    approval_set_hash: digest_hex(&digest(44)),
                },
            )
        }

        pub(super) fn expired_governed_request(&self) -> RawActiveResponseExecutionRequest {
            let plan = plan(
                self.now_unix_ms,
                &self.identity,
                ResponseApprovalRequirement::Governed {
                    policy_id: record_id("response-governance-policy"),
                },
                true,
            );
            raw_request(
                plan,
                self.identity.clone(),
                ActiveResponseExecutionApproval::Governed {
                    admission_operation_id: "admission-operation-42".to_string(),
                    admission_operation_version: 3,
                    approval_set_hash: digest_hex(&digest(44)),
                },
            )
        }

        pub(super) fn set_clock(&self, now_unix_ms: u64) {
            self.clock.set(now_unix_ms);
        }

        fn initial_work(&self, request: &RawActiveResponseExecutionRequest) -> ScheduledWork {
            match require_success(
                self.store.load_dispatch(&ResponseDispatchKey {
                    tenant_id: request.response_plan.tenant_id.clone(),
                    dispatch_id: request.dispatch_id.clone(),
                }),
                "load committed active-response dispatch",
            ) {
                ResponseDispatchLoadOutcome::Found(record) => record.initial_work,
                ResponseDispatchLoadOutcome::Missing => {
                    panic!("committed active-response dispatch is missing")
                }
            }
        }

        fn claim_due_work(
            &self,
            request: &RawActiveResponseExecutionRequest,
            now_unix_ms: u64,
            claim_suffix: &str,
        ) -> ScheduledWork {
            self.clock.set(now_unix_ms);
            let mut claimed = require_success(
                self.store.claim_due(&SchedulerClaimRequest {
                    tenant_id: request.response_plan.tenant_id.clone(),
                    claim_id: record_id(&format!("active-response-test-claim-{claim_suffix}")),
                    lease_owner_id: LeaseOwnerId::new(TEST_ACTIVE_RESPONSE_LEASE_OWNER_ID)
                        .unwrap_or_else(|error| panic!("construct test lease owner: {error}")),
                    now_unix_ms,
                    lease_expires_at_unix_ms: now_unix_ms.saturating_add(30_000),
                    max_claims: 1,
                }),
                "claim due active-response work",
            );
            assert_eq!(
                claimed.len(),
                1,
                "expected one due active-response work item"
            );
            claimed
                .pop()
                .unwrap_or_else(|| panic!("due active-response work item is missing"))
        }

        fn wait_until_after_real_deadline(&self, deadline_unix_ms: u64) {
            let wait_ms = deadline_unix_ms
                .saturating_sub(system_now_unix_ms())
                .saturating_add(25);
            assert!(wait_ms <= 3_000, "test deadline is unexpectedly distant");
            std::thread::sleep(Duration::from_millis(wait_ms));
            self.clock.set(system_now_unix_ms());
        }

        pub(super) fn fail_clock_after_next_success(&self) {
            self.clock.fail_after_next_success();
        }

        pub(super) fn effect_executions(&self) -> usize {
            self.effects.executions()
        }

        pub(super) fn set_effect_outcome_unknown(&self) {
            self.effects.set_mode(EffectMode::Unknown);
        }

        pub(super) fn response_snapshot(
            &self,
            request: &RawActiveResponseExecutionRequest,
        ) -> chio_security_types::ResponseSnapshot {
            let key = ResponsePlanKey {
                tenant_id: request.response_plan.tenant_id.clone(),
                action_id: request.response_plan.action_id.clone(),
            };
            let record = require_success(self.store.load_plan(&key), "load response snapshot")
                .unwrap_or_else(|| panic!("response snapshot is missing"));
            decode_response_record(&record)
                .unwrap_or_else(|error| panic!("decode response snapshot: {error}"))
        }
    }

    fn identity(generation: u64) -> ActiveResponseExecutorAuthorityIdentity {
        let subject = Keypair::from_seed(&[7_u8; 32]).public_key();
        ActiveResponseExecutorAuthorityIdentity::new(subject, generation)
            .unwrap_or_else(|error| panic!("construct executor identity: {error}"))
    }

    fn system_now_unix_ms() -> u64 {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("system clock before epoch: {error}"));
        u64::try_from(duration.as_millis())
            .unwrap_or_else(|error| panic!("test timestamp does not fit u64: {error}"))
    }

    fn digest(value: u8) -> Digest32 {
        Digest32::new([value; 32])
    }

    fn digest_hex(value: &Digest32) -> String {
        hex::encode(value.as_bytes())
    }

    fn record_id(value: &str) -> RecordId {
        RecordId::new(value)
            .unwrap_or_else(|error| panic!("invalid test record id {value}: {error}"))
    }

    fn plan(
        now_unix_ms: u64,
        identity: &ActiveResponseExecutorAuthorityIdentity,
        approval_requirement: ResponseApprovalRequirement,
        expired: bool,
    ) -> ResponsePlan {
        let (created_at_unix_ms, ttl_ms) = if expired {
            (now_unix_ms.saturating_sub(10_000), 1_000)
        } else {
            (now_unix_ms.saturating_sub(1_000), 120_000)
        };
        let canonical_contribution = CanonicalBody::new(b"{\"posture_rank\":2}".to_vec())
            .unwrap_or_else(|error| panic!("canonical contribution: {error}"));
        let contribution_hash =
            Digest32::new(*chio_core::sha256(canonical_contribution.as_bytes()).as_bytes());
        build_response_plan(ResponsePlanInput {
            action_id: ActionId::new("action-durable-response")
                .unwrap_or_else(|error| panic!("action id: {error}")),
            trigger_finding_id: record_id("finding-durable-response"),
            trigger_finding_hash: digest(31),
            trigger_finding_receipt_id: chio_security_types::ports::OpaqueReceiptRef::new(
                "finding-durable-response-receipt",
            )
            .unwrap_or_else(|error| panic!("finding receipt id: {error}")),
            tenant_id: TenantId::new("tenant-durable-response")
                .unwrap_or_else(|error| panic!("tenant id: {error}")),
            policy_version: record_id("policy-durable-response"),
            policy_hash: digest(32),
            affected_ids: vec![record_id("session-durable-response")],
            effects: vec![ResponseEffectSpec {
                kind: ResponseEffectKind::ThrottleSession,
                target: ResponseTarget::Session {
                    session_id: SessionId::new("session-durable-response")
                        .unwrap_or_else(|error| panic!("session id: {error}")),
                },
                canonical_contribution,
                contribution_hash,
                observed_base_version_hash: digest(20),
            }],
            ttl_ms,
            created_at_unix_ms,
            operator_capability: OperatorCapabilityBinding {
                capability_id: record_id("capability-durable-response"),
                capability_digest: digest(30),
                expires_at_unix_ms: created_at_unix_ms
                    .saturating_add(ttl_ms)
                    .saturating_add(60_000),
                executor_subject: record_id(&identity.subject().to_hex()),
            },
            approval_requirement,
            submitter: record_id("submitter-durable-response"),
            reason_hash: digest(31),
        })
        .unwrap_or_else(|error| panic!("build response plan: {error}"))
    }

    fn raw_request(
        plan: ResponsePlan,
        executor_authority: ActiveResponseExecutorAuthorityIdentity,
        approval: ActiveResponseExecutionApproval,
    ) -> RawActiveResponseExecutionRequest {
        let authorization_capability_hash = digest_hex(&plan.operator_capability.capability_digest);
        let governed_intent_hash = digest_hex(&digest(32));
        let policy_decision_hash = digest_hex(&digest(33));
        let authorized_at_unix_ms = plan.created_at_unix_ms;
        let dispatch_id = derive_active_response_dispatch_id(
            &plan,
            &executor_authority,
            &authorization_capability_hash,
            &governed_intent_hash,
            &policy_decision_hash,
            authorized_at_unix_ms,
            &approval,
        )
        .unwrap_or_else(|error| panic!("derive active-response dispatch id: {error}"));
        RawActiveResponseExecutionRequest {
            dispatch_id,
            request_id: plan.action_id.as_str().to_string(),
            plan_body_hash: digest_hex(&plan.plan_hash),
            authorization_capability_hash,
            governed_intent_hash,
            policy_decision_hash,
            expires_at_unix_ms: plan.expires_at_unix_ms,
            authorized_at_unix_ms,
            dispatch_committed_resume: false,
            response_plan: plan,
            executor_authority,
            approval,
        }
    }

    pub(super) fn require_success<T, E: std::fmt::Display>(
        result: Result<T, E>,
        context: &str,
    ) -> T {
        result.unwrap_or_else(|error| panic!("{context}: {error}"))
    }

    pub(super) fn require_error<T, E>(result: Result<T, E>) -> E {
        match result {
            Ok(_) => panic!("expected operation to fail"),
            Err(error) => error,
        }
    }

    fn active_defense_body(receipt: &ChioReceipt) -> ActiveDefenseReceiptBody {
        let value = receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("active_defense_body"))
            .cloned()
            .unwrap_or_else(|| panic!("signed receipt is missing its active-defense body"));
        serde_json::from_value(value)
            .unwrap_or_else(|error| panic!("signed active-defense body is invalid: {error}"))
    }

    #[test]
    fn fresh_dispatch_commits_executes_and_maps_exact_durable_evidence() {
        let harness = Harness::new();
        let request = harness.automatic_request();
        let evidence = require_success(
            harness.executor.execute_source(&request),
            "fresh active response execution",
        );

        assert!(!evidence.recovered());
        assert_eq!(evidence.dispatch_id(), &request.dispatch_id);
        assert_eq!(evidence.tenant_id(), &request.response_plan.tenant_id);
        assert_eq!(evidence.action_id(), &request.response_plan.action_id);
        assert_eq!(evidence.plan_hash(), &request.response_plan.plan_hash);
        assert_eq!(evidence.executor_authority_generation(), 7);
        assert!(evidence.response_generation() > 0);
        assert!(evidence.failure().is_none());
        assert_eq!(evidence.effects().len(), 1);
        assert_eq!(
            evidence.effects()[0].effect_id(),
            &request.response_plan.effects.as_slice()[0].effect_id
        );
        assert!(evidence.effects()[0].generation() > 0);
        assert_eq!(evidence.effects()[0].resulting_version_hash(), &digest(70));
        assert_eq!(harness.effects.executions(), 1);

        let receipt_cursor = require_success(
            harness.store.load_receipt_cursor(&ResponsePlanKey {
                tenant_id: request.response_plan.tenant_id.clone(),
                action_id: request.response_plan.action_id.clone(),
            }),
            "load terminal response receipt cursor",
        )
        .unwrap_or_else(|| panic!("terminal response receipt cursor is missing"));
        assert_eq!(
            evidence.proof_evidence_id(),
            &receipt_cursor.current_evidence_id
        );

        let loaded = require_success(
            harness.store.load_dispatch(&ResponseDispatchKey {
                tenant_id: request.response_plan.tenant_id.clone(),
                dispatch_id: request.dispatch_id.clone(),
            }),
            "load committed dispatch",
        );
        let ResponseDispatchLoadOutcome::Found(dispatch) = loaded else {
            panic!("fresh dispatch was not durable");
        };
        assert_eq!(
            dispatch.authorization.body.executor_authority_id.as_str(),
            harness.identity.authority_id()
        );
        assert_eq!(dispatch.authorization.body.executor_authority_generation, 7);
    }

    #[test]
    fn governed_dispatch_commits_exact_approval_and_executes() {
        let harness = Harness::new();
        let request = harness.governed_request();
        let evidence = require_success(
            harness.executor.execute_source(&request),
            "governed active response execution",
        );
        assert!(!evidence.recovered());

        let loaded = require_success(
            harness.store.load_dispatch(&ResponseDispatchKey {
                tenant_id: request.response_plan.tenant_id.clone(),
                dispatch_id: request.dispatch_id.clone(),
            }),
            "load governed dispatch",
        );
        let ResponseDispatchLoadOutcome::Found(record) = loaded else {
            panic!("governed dispatch was not durable");
        };
        assert!(matches!(
            record.authorization.body.approval,
            ResponseDispatchApproval::Governed {
                ref admission_operation_id,
                admission_operation_version: 3,
                approval_set_hash,
            } if admission_operation_id.as_str() == "admission-operation-42"
                && approval_set_hash == digest(44)
        ));
        assert_eq!(
            record.authorization.body.authorized_at_unix_ms,
            request.authorized_at_unix_ms
        );
    }

    #[test]
    fn same_dispatch_retry_after_ack_loss_recovers_without_reapplying_effect() {
        let harness = Harness::new();
        let request = harness.automatic_request();
        harness.receipts.fail_next.store(true, Ordering::SeqCst);

        let first = require_error(harness.executor.execute_source(&request));
        assert!(matches!(
            first,
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));
        let recovered = require_success(
            harness.executor.execute_source(&request),
            "recover dispatch after lost acknowledgement",
        );
        let replay = require_success(
            harness.executor.execute_source(&request),
            "replay completed dispatch",
        );

        assert!(recovered.recovered());
        assert!(replay.recovered());
        assert_eq!(
            recovered.response_transition_id(),
            replay.response_transition_id()
        );
        assert_eq!(recovered.response_body_hash(), replay.response_body_hash());
        assert_eq!(recovered.effects(), replay.effects());
        assert_eq!(recovered.response_record(), replay.response_record());
        assert_eq!(recovered.proof_evidence_id(), replay.proof_evidence_id());
        assert_eq!(recovered.proof_body_hash(), replay.proof_body_hash());
        assert_eq!(harness.effects.executions(), 1);
    }

    #[test]
    fn activated_dispatch_replays_original_proof_after_expiry_and_rollback_start() {
        let harness = Harness::new();
        let request = harness.automatic_request();
        let activated = require_success(
            harness.executor.execute_source(&request),
            "activate response before expiry",
        );
        let key = ResponsePlanKey {
            tenant_id: request.response_plan.tenant_id.clone(),
            action_id: request.response_plan.action_id.clone(),
        };
        let active = require_success(harness.store.load_plan(&key), "load active response")
            .unwrap_or_else(|| panic!("active response is missing"));
        let state_machine = ResponseStateMachine::new(Arc::clone(&harness.store));
        let rollback_work = harness.claim_due_work(
            &request,
            request.response_plan.expires_at_unix_ms,
            "rollback-start",
        );
        let rolling_back = require_success(
            state_machine.handle_due_scheduled(
                &active,
                &rollback_work,
                active.generation,
                request.response_plan.expires_at_unix_ms,
            ),
            "advance active response into rollback",
        );
        assert_eq!(
            require_success(
                decode_response_record(&rolling_back),
                "rolling response snapshot",
            )
            .state,
            ResponseState::RollingBack
        );
        harness
            .clock
            .set(request.response_plan.expires_at_unix_ms.saturating_add(1));

        let replay = require_success(
            harness.executor.execute_source(&request),
            "replay activation after expiry",
        );
        assert_eq!(replay.outcome(), ActiveResponseExecutionOutcome::Activated);
        assert_eq!(activated.proof_evidence_id(), replay.proof_evidence_id());
        assert_eq!(activated.proof_body_hash(), replay.proof_body_hash());
        assert_eq!(activated.response_record(), replay.response_record());
        assert_eq!(harness.effects.executions(), 1);
    }

    #[test]
    fn activated_dispatch_replays_original_proof_after_full_lift() {
        let harness = Harness::new();
        let request = harness.automatic_request();
        let activated = require_success(
            harness.executor.execute_source(&request),
            "activate response before lift",
        );
        let key = ResponsePlanKey {
            tenant_id: request.response_plan.tenant_id.clone(),
            action_id: request.response_plan.action_id.clone(),
        };
        let active = require_success(harness.store.load_plan(&key), "load active response")
            .unwrap_or_else(|| panic!("active response is missing"));
        let state_machine = ResponseStateMachine::new(Arc::clone(&harness.store));
        let rollback_time = request.response_plan.expires_at_unix_ms;
        let rollback_work = harness.claim_due_work(&request, rollback_time, "full-lift-rollback");
        let rolling = require_success(
            state_machine.handle_due_scheduled(
                &active,
                &rollback_work,
                active.generation,
                rollback_time,
            ),
            "start response rollback",
        );
        let effect_id = request.response_plan.effects.as_slice()[0]
            .effect_id
            .clone();
        let rollback_requested = require_success(
            state_machine.record_effect_with_receipt_scheduled(
                &rolling,
                &rollback_work,
                &EffectMutationRequest {
                    expected_generation: rolling.generation,
                    effect_id: effect_id.clone(),
                    occurred_at_unix_ms: rollback_time,
                    mutation: EffectMutation::RollbackRequested,
                },
                &EffectReceiptContext {
                    effect_generation: 3,
                    scheduler_lease_owner_id: Some(rollback_work.lease_owner_id.clone()),
                    scheduler_fencing_token: rollback_work.fencing_token,
                    effect_transition_id: Some(record_id("manual-lift-rollback-requested")),
                    prior_receipt_id: None,
                },
            ),
            "record rollback request",
        );
        let restored = require_success(
            state_machine.record_effect_with_receipt_scheduled(
                &rollback_requested,
                &rollback_work,
                &EffectMutationRequest {
                    expected_generation: rollback_requested.generation,
                    effect_id,
                    occurred_at_unix_ms: rollback_time.saturating_add(1),
                    mutation: EffectMutation::RollbackRestored {
                        resulting_version_hash: digest(20),
                    },
                },
                &EffectReceiptContext {
                    effect_generation: 4,
                    scheduler_lease_owner_id: Some(rollback_work.lease_owner_id.clone()),
                    scheduler_fencing_token: rollback_work.fencing_token,
                    effect_transition_id: Some(record_id("manual-lift-restored")),
                    prior_receipt_id: None,
                },
            ),
            "record rollback restoration",
        );
        let lifted = require_success(
            state_machine.transition_scheduled(
                &restored,
                &rollback_work,
                &ResponseTransitionRequest {
                    expected_generation: restored.generation,
                    target_state: ResponseState::Lifted,
                    occurred_at_unix_ms: rollback_time.saturating_add(2),
                    applying_lease_expires_at_unix_ms: None,
                    error_code: None,
                },
            ),
            "finish response lift",
        );
        assert_eq!(
            require_success(decode_response_record(&lifted), "lifted response snapshot").state,
            ResponseState::Lifted
        );
        harness.clock.set(rollback_time.saturating_add(3));

        let replay = require_success(
            harness.executor.execute_source(&request),
            "replay activation after lift",
        );
        assert_eq!(replay.outcome(), ActiveResponseExecutionOutcome::Activated);
        assert_eq!(activated.proof_evidence_id(), replay.proof_evidence_id());
        assert_eq!(activated.proof_body_hash(), replay.proof_body_hash());
        assert_eq!(harness.effects.executions(), 1);

        let cursor = require_success(
            harness.store.load_receipt_cursor(&key),
            "load lifted response receipt cursor",
        )
        .unwrap_or_else(|| panic!("lifted response receipt cursor is missing"));
        let lifted_snapshot =
            require_success(decode_response_record(&lifted), "lifted response snapshot");
        assert_eq!(
            cursor.generation,
            u64::try_from(lifted_snapshot.mutations.len())
                .unwrap_or_else(|error| panic!("lifted mutation count does not fit u64: {error}"))
        );
        assert_ne!(&cursor.current_evidence_id, activated.proof_evidence_id());
        let mut lineage_id = cursor.current_evidence_id;
        let mut descends_from_activation = false;
        for _ in 0..=lifted_snapshot.mutations.len() {
            if &lineage_id == activated.proof_evidence_id() {
                descends_from_activation = true;
                break;
            }
            let receipt = require_success(
                harness
                    .receipts
                    .load_signed_active_response_receipt(&lineage_id),
                "load response receipt lineage member",
            )
            .unwrap_or_else(|| panic!("response receipt lineage member is missing"));
            let body = active_defense_body(&receipt);
            let [prior] = body.header().prior_receipt_ids.as_slice() else {
                panic!("response receipt lineage member must have one parent");
            };
            lineage_id = prior.clone();
        }
        assert!(descends_from_activation);
    }

    #[test]
    fn committed_effect_request_ambiguity_cannot_be_terminal_failed() {
        let harness = Harness::new();
        let request = harness.automatic_request();
        harness.effects.set_mode(EffectMode::Unknown);
        assert!(matches!(
            require_error(harness.executor.execute_source(&request)),
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));
        let key = ResponsePlanKey {
            tenant_id: request.response_plan.tenant_id.clone(),
            action_id: request.response_plan.action_id.clone(),
        };
        let applying = require_success(harness.store.load_plan(&key), "load applying response")
            .unwrap_or_else(|| panic!("applying response is missing"));
        let state_machine = ResponseStateMachine::new(Arc::clone(&harness.store));
        assert!(matches!(
            state_machine.transition(
                &applying,
                &ResponseTransitionRequest {
                    expected_generation: applying.generation,
                    target_state: ResponseState::Failed,
                    occurred_at_unix_ms: harness.now_unix_ms.saturating_add(1),
                    applying_lease_expires_at_unix_ms: None,
                    error_code: Some(
                        ErrorCode::new("test.apply_failed")
                            .unwrap_or_else(|error| panic!("failure code: {error}")),
                    ),
                },
            ),
            Err(chio_quarantine::StateMachineError::InvalidFailureRecord)
        ));
        let snapshot = decode_response_record(&applying)
            .unwrap_or_else(|error| panic!("decode ambiguous applying response: {error}"));
        assert_eq!(snapshot.state, ResponseState::Applying);
        assert!(snapshot
            .mutations
            .as_slice()
            .iter()
            .all(|mutation| !matches!(
                mutation,
                chio_security_types::ResponseMutationRecord::Failed(_)
            )));
        assert!(!has_durable_execution_proof(&snapshot));
        assert_eq!(harness.effects.executions(), 0);
    }

    #[test]
    fn committed_partial_apply_then_full_rollback_returns_signed_terminal_outcome() {
        let harness = Harness::new();
        let request = harness.automatic_request();
        harness.effects.set_mode(EffectMode::Unknown);
        assert!(matches!(
            require_error(harness.executor.execute_source(&request)),
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));
        let key = ResponsePlanKey {
            tenant_id: request.response_plan.tenant_id.clone(),
            action_id: request.response_plan.action_id.clone(),
        };
        let applying = require_success(harness.store.load_plan(&key), "load applying response")
            .unwrap_or_else(|| panic!("applying response is missing"));
        let snapshot = require_success(decode_response_record(&applying), "applying snapshot");
        let effect_id = request.response_plan.effects.as_slice()[0]
            .effect_id
            .clone();
        let state_machine = ResponseStateMachine::new(Arc::clone(&harness.store));
        let initial_work = harness.initial_work(&request);
        let applied = require_success(
            state_machine.record_effect_with_receipt_scheduled(
                &applying,
                &initial_work,
                &EffectMutationRequest {
                    expected_generation: applying.generation,
                    effect_id: effect_id.clone(),
                    occurred_at_unix_ms: harness.now_unix_ms.saturating_add(1),
                    mutation: EffectMutation::Applied {
                        resulting_version_hash: digest(70),
                    },
                },
                &EffectReceiptContext {
                    effect_generation: 2,
                    scheduler_lease_owner_id: Some(initial_work.lease_owner_id.clone()),
                    scheduler_fencing_token: initial_work.fencing_token,
                    effect_transition_id: Some(record_id("manual-effect-applied")),
                    prior_receipt_id: None,
                },
            ),
            "record applied effect",
        );
        let rollback_time = snapshot
            .applying_lease_expires_at_unix_ms
            .unwrap_or_else(|| panic!("applying lease expiry"));
        let rollback_work =
            harness.claim_due_work(&request, rollback_time, "partial-apply-rollback");
        let rolling = require_success(
            state_machine.handle_due_scheduled(
                &applied,
                &rollback_work,
                applied.generation,
                rollback_time,
            ),
            "move partial apply into rollback",
        );
        let rollback_requested = require_success(
            state_machine.record_effect_with_receipt_scheduled(
                &rolling,
                &rollback_work,
                &EffectMutationRequest {
                    expected_generation: rolling.generation,
                    effect_id: effect_id.clone(),
                    occurred_at_unix_ms: rollback_time,
                    mutation: EffectMutation::RollbackRequested,
                },
                &EffectReceiptContext {
                    effect_generation: 3,
                    scheduler_lease_owner_id: Some(rollback_work.lease_owner_id.clone()),
                    scheduler_fencing_token: rollback_work.fencing_token,
                    effect_transition_id: Some(record_id("manual-partial-rollback-requested")),
                    prior_receipt_id: None,
                },
            ),
            "record partial rollback request",
        );
        let restored = require_success(
            state_machine.record_effect_with_receipt_scheduled(
                &rollback_requested,
                &rollback_work,
                &EffectMutationRequest {
                    expected_generation: rollback_requested.generation,
                    effect_id,
                    occurred_at_unix_ms: rollback_time.saturating_add(1),
                    mutation: EffectMutation::RollbackRestored {
                        resulting_version_hash: digest(20),
                    },
                },
                &EffectReceiptContext {
                    effect_generation: 4,
                    scheduler_lease_owner_id: Some(rollback_work.lease_owner_id.clone()),
                    scheduler_fencing_token: rollback_work.fencing_token,
                    effect_transition_id: Some(record_id("manual-partial-restored")),
                    prior_receipt_id: None,
                },
            ),
            "record partial rollback restoration",
        );
        require_success(
            state_machine.transition_scheduled(
                &restored,
                &rollback_work,
                &ResponseTransitionRequest {
                    expected_generation: restored.generation,
                    target_state: ResponseState::Lifted,
                    occurred_at_unix_ms: rollback_time.saturating_add(2),
                    applying_lease_expires_at_unix_ms: None,
                    error_code: None,
                },
            ),
            "finish partial rollback lift",
        );
        harness.effects.set_mode(EffectMode::Normal);
        harness.clock.set(rollback_time.saturating_add(3));

        let evidence = require_success(
            harness.executor.execute_source(&request),
            "reconcile rolled-back partial apply",
        );
        assert_eq!(
            evidence.outcome(),
            ActiveResponseExecutionOutcome::RolledBackAfterPartial
        );
        assert!(evidence.failure().is_none());
        assert_eq!(evidence.effects().len(), 1);
    }

    #[test]
    fn committed_retry_remains_exact_after_wall_clock_advances() {
        let harness = Harness::new();
        let request = harness.automatic_request();
        harness.receipts.fail_next.store(true, Ordering::SeqCst);
        assert!(matches!(
            require_error(harness.executor.execute_source(&request)),
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));
        harness.clock.set(harness.now_unix_ms + 5_000);

        let recovered = require_success(
            harness.executor.execute_source(&request),
            "recover committed response after clock advancement",
        );
        assert!(recovered.recovered());
        assert_eq!(harness.effects.executions(), 1);
    }

    #[test]
    fn authoritative_effect_rejection_returns_failed_before_any_effect_evidence() {
        let harness = Harness::new();
        let request = harness.automatic_request();
        harness.effects.set_mode(EffectMode::Rejected);
        let first = require_success(
            harness.executor.execute_source(&request),
            "execute authoritatively rejected effect",
        );
        assert_eq!(
            first.outcome(),
            ActiveResponseExecutionOutcome::FailedBeforeAnyEffect
        );
        assert!(!first.recovered());
        assert!(first.effects().is_empty());
        let failure = first
            .failure()
            .unwrap_or_else(|| panic!("terminal failure evidence is missing"));
        assert_eq!(failure.error_code().as_str(), "test.effect_rejected");
        let key = ResponsePlanKey {
            tenant_id: request.response_plan.tenant_id.clone(),
            action_id: request.response_plan.action_id.clone(),
        };
        let failed = require_success(harness.store.load_plan(&key), "load failed response")
            .unwrap_or_else(|| panic!("failed response is missing"));
        let failed_snapshot =
            require_success(decode_response_record(&failed), "decode failed response");
        assert_eq!(failed_snapshot.state, ResponseState::Failed);
        let failed_record = match failed_snapshot.mutations.as_slice().iter().rev().nth(1) {
            Some(chio_security_types::ResponseMutationRecord::EffectFailed(effect))
                if effect.error_code.as_str() == "test.effect_rejected" =>
            {
                effect
            }
            _ => panic!("authoritative failed-effect record is missing"),
        };
        let failed_effect = failure
            .failed_effect()
            .unwrap_or_else(|| panic!("failed-effect evidence is missing"));
        assert_eq!(failed_effect.effect_id(), &failed_record.effect_id);
        assert_eq!(
            Some(failed_effect.transition_id()),
            failed_record.effect_transition_id.as_ref()
        );
        assert_eq!(
            failed_effect.generation().saturating_add(1),
            failed_record.effect_generation
        );
        assert_eq!(harness.effects.executions(), 0);

        let replay = require_success(
            harness.executor.execute_source(&request),
            "replay authoritatively rejected effect",
        );
        assert_eq!(
            replay.outcome(),
            ActiveResponseExecutionOutcome::FailedBeforeAnyEffect
        );
        assert!(replay.recovered());
        assert!(replay.effects().is_empty());
        assert_eq!(replay.failure(), first.failure());
        assert_eq!(replay.proof_evidence_id(), first.proof_evidence_id());
        assert_eq!(replay.proof_body_hash(), first.proof_body_hash());
        assert_eq!(replay.response_record(), first.response_record());
        assert_eq!(harness.effects.executions(), 0);
    }

    #[test]
    fn authoritative_effect_rejection_after_scheduler_takeover_terminally_recovers() {
        let harness = Harness::with_lease_duration(2_000);
        let request = harness.automatic_request();
        harness.effects.set_mode(EffectMode::Unknown);
        assert!(matches!(
            require_error(harness.executor.execute_source(&request)),
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));
        let applying = harness.response_snapshot(&request);
        let expired_lease = applying
            .applying_lease_expires_at_unix_ms
            .unwrap_or_else(|| panic!("applying response is missing its scheduler lease"));
        assert!(expired_lease < request.response_plan.expires_at_unix_ms);

        harness.effects.set_mode(EffectMode::Rejected);
        harness.wait_until_after_real_deadline(expired_lease);
        let recovered = require_success(
            harness.executor.execute_source(&request),
            "recover authoritative failure after scheduler takeover",
        );

        assert_eq!(
            recovered.outcome(),
            ActiveResponseExecutionOutcome::FailedBeforeAnyEffect
        );
        assert!(recovered.recovered());
        assert!(recovered.effects().is_empty());
        let failure = recovered
            .failure()
            .unwrap_or_else(|| panic!("takeover failure evidence is missing"));
        assert_eq!(failure.error_code().as_str(), "test.effect_rejected");
        assert!(failure.failed_effect().is_some());
        assert_eq!(
            harness.response_snapshot(&request).state,
            ResponseState::Failed
        );
        assert_eq!(harness.effects.executions(), 0);
    }

    #[test]
    fn persisted_apply_failure_recovers_after_receipt_ack_loss_and_lease_expiry() {
        let harness = Harness::with_lease_duration(2_000);
        let request = harness.automatic_request();
        harness.effects.set_mode(EffectMode::Rejected);
        harness.receipts.fail_once_on_effect_state("apply_failed");
        assert!(matches!(
            require_error(harness.executor.execute_source(&request)),
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));
        let applying = harness.response_snapshot(&request);
        let effect_id = &request.response_plan.effects.as_slice()[0].effect_id;
        assert_eq!(applying.state, ResponseState::Applying);
        assert_eq!(
            applying.effect_progress(effect_id),
            Some(ResponseEffectProgress::ApplyFailed)
        );
        let expired_lease = applying
            .applying_lease_expires_at_unix_ms
            .unwrap_or_else(|| panic!("applying response is missing its scheduler lease"));
        assert!(expired_lease < request.response_plan.expires_at_unix_ms);

        harness.wait_until_after_real_deadline(expired_lease);
        let recovered = require_success(
            harness.executor.execute_source(&request),
            "recover persisted apply failure after receipt acknowledgement loss",
        );

        assert_eq!(
            recovered.outcome(),
            ActiveResponseExecutionOutcome::FailedBeforeAnyEffect
        );
        assert!(recovered.recovered());
        assert!(recovered.effects().is_empty());
        let failure = recovered
            .failure()
            .unwrap_or_else(|| panic!("recovered failure evidence is missing"));
        assert_eq!(failure.error_code().as_str(), "test.effect_rejected");
        assert!(failure.failed_effect().is_some());
        assert_eq!(
            harness.response_snapshot(&request).state,
            ResponseState::Failed
        );
        assert_eq!(harness.effects.executions(), 0);

        let replay = require_success(
            harness.executor.execute_source(&request),
            "replay persisted apply failure",
        );
        assert!(replay.recovered());
        assert_eq!(replay.failure(), recovered.failure());
        assert_eq!(replay.proof_evidence_id(), recovered.proof_evidence_id());
        assert_eq!(replay.proof_body_hash(), recovered.proof_body_hash());
    }

    #[test]
    fn existing_dispatch_rejects_a_foreign_live_scheduler_lease() {
        let harness = Harness::with_lease_duration(2_000);
        let request = harness.automatic_request();
        harness.effects.set_mode(EffectMode::Unknown);
        let first = require_error(harness.executor.execute_source(&request));
        assert!(matches!(
            first,
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));
        let applying = harness.response_snapshot(&request);
        let expired_lease = applying
            .applying_lease_expires_at_unix_ms
            .unwrap_or_else(|| panic!("applying response is missing its scheduler lease"));
        harness.wait_until_after_real_deadline(expired_lease);
        let foreign_executor = harness.executor_with_lease_owner("ordinary-scheduler-worker");
        assert!(matches!(
            require_error(foreign_executor.execute_source(&request)),
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));
        harness.effects.set_mode(EffectMode::Normal);

        let error = require_error(harness.executor.execute_source(&request));
        assert!(matches!(
            error,
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));
        assert_eq!(harness.effects.executions(), 0);
    }

    #[test]
    fn two_workers_sharing_one_executor_signer_cannot_execute_one_live_lease() {
        let harness = Harness::new();
        let request = harness.automatic_request();
        harness.effects.set_mode(EffectMode::Unknown);

        let first = require_error(harness.executor.execute_source(&request));
        assert!(matches!(
            first,
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));
        assert_eq!(harness.effects.executions(), 0);

        let second = harness.executor_with_lease_owner("active-response-test-worker-b");
        let second_error = require_error(second.execute_source(&request));
        assert!(matches!(
            second_error,
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));
        assert_eq!(harness.effects.executions(), 0);

        harness.effects.set_mode(EffectMode::Normal);
        let recovered = require_success(
            harness.executor.execute_source(&request),
            "recover live lease with its exact owner",
        );
        assert!(recovered.recovered());
        assert_eq!(harness.effects.executions(), 1);
        assert_eq!(harness.effects.last_fencing_token(), Some(1));
    }

    #[test]
    fn takeover_recovers_completed_effect_before_rolling_back_expired_lease() {
        let harness = Harness::with_lease_duration(2_000);
        let request = harness.automatic_request();

        harness.effects.set_mode(EffectMode::Unknown);
        let prepared = require_error(harness.executor.execute_source(&request));
        assert!(matches!(
            prepared,
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));
        assert_eq!(harness.effects.executions(), 0);
        harness.effects.set_mode(EffectMode::Normal);
        harness.receipts.fail_next.store(true, Ordering::SeqCst);

        let first = require_error(harness.executor.execute_source(&request));
        assert!(matches!(
            first,
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));
        assert_eq!(harness.effects.executions(), 1);
        assert_eq!(harness.effects.last_fencing_token(), Some(1));
        let applying = harness.response_snapshot(&request);
        let expired_lease = applying
            .applying_lease_expires_at_unix_ms
            .unwrap_or_else(|| panic!("applying response is missing its scheduler lease"));
        harness.wait_until_after_real_deadline(expired_lease);

        let recovered = require_success(
            harness.executor.execute_source(&request),
            "recover completed effect after scheduler takeover",
        );
        assert!(recovered.recovered());
        assert_eq!(harness.effects.executions(), 2);
        assert_eq!(harness.effects.mutation_counts(), (1, 1));
        assert_eq!(harness.effects.last_fencing_token(), Some(2));
    }

    #[test]
    fn existing_dispatch_collision_is_rejected_before_mutation() {
        let harness = Harness::new();
        let request = harness.automatic_request();
        harness.effects.set_mode(EffectMode::Unknown);
        let _ = require_error(harness.executor.execute_source(&request));
        let mut collision = request.clone();
        collision.policy_decision_hash = digest_hex(&digest(99));

        let error = require_error(harness.executor.execute_source(&collision));
        assert!(matches!(
            error,
            ActiveResponseExecutorError::RejectedBeforeCommit(_)
        ));
        assert_eq!(harness.effects.executions(), 0);
    }

    #[test]
    fn readiness_probes_dispatch_effect_receipt_and_alert_durability() {
        let harness = Harness::new();
        require_success(harness.executor.ensure_ready(), "initial readiness");

        harness.effects.ready.store(false, Ordering::SeqCst);
        assert!(matches!(
            require_error(harness.executor.ensure_ready()),
            ActiveResponseExecutorError::NotReady(_)
        ));
        harness.effects.ready.store(true, Ordering::SeqCst);
        harness.receipts.ready.store(false, Ordering::SeqCst);
        assert!(matches!(
            require_error(harness.executor.ensure_ready()),
            ActiveResponseExecutorError::NotReady(_)
        ));
        harness.receipts.ready.store(true, Ordering::SeqCst);
        harness.alerts.ready.store(false, Ordering::SeqCst);
        assert!(matches!(
            require_error(harness.executor.ensure_ready()),
            ActiveResponseExecutorError::NotReady(_)
        ));
        harness.alerts.ready.store(true, Ordering::SeqCst);

        let connection = Connection::open(&harness.database_path)
            .unwrap_or_else(|error| panic!("open readiness corruption connection: {error}"));
        connection
            .execute("DROP TABLE security_response_dispatch_recoveries", [])
            .unwrap_or_else(|error| panic!("corrupt dispatch recovery schema: {error}"));
        drop(connection);
        assert!(matches!(
            require_error(harness.executor.ensure_ready()),
            ActiveResponseExecutorError::NotReady(_)
        ));
    }

    mod automatic_fence_boundary {
        use super::*;
        use chio_security_types::ports as p;

        struct FakeFenceStore {
            outcome: p::AutomaticResponseDispatchFenceOutcome,
            fence_calls: AtomicUsize,
            dispatch_load_calls: AtomicUsize,
        }

        impl FakeFenceStore {
            fn new(outcome: p::AutomaticResponseDispatchFenceOutcome) -> Self {
                Self {
                    outcome,
                    fence_calls: AtomicUsize::new(0),
                    dispatch_load_calls: AtomicUsize::new(0),
                }
            }
        }

        impl p::ResponseStore for FakeFenceStore {
            fn load_plan(
                &self,
                _key: &p::ResponsePlanKey,
            ) -> p::PortResult<Option<p::ResponsePlanRecord>> {
                Err(p::PortError::unavailable())
            }

            fn create(&self, _record: &p::ResponsePlanRecord) -> p::PortResult<p::CreateOutcome> {
                Err(p::PortError::unavailable())
            }

            fn compare_and_swap(
                &self,
                _request: &p::ResponseCasRequest,
            ) -> p::PortResult<p::ResponsePlanRecord> {
                Err(p::PortError::unavailable())
            }

            fn load_effect(
                &self,
                _key: &p::ResponseEffectKey,
            ) -> p::PortResult<Option<p::ResponseEffectRecord>> {
                Err(p::PortError::unavailable())
            }

            fn persist_effect(
                &self,
                _record: &p::ResponseEffectRecord,
            ) -> p::PortResult<p::CreateOutcome> {
                Err(p::PortError::unavailable())
            }

            fn compare_and_swap_effect(
                &self,
                _request: &p::ResponseEffectCasRequest,
            ) -> p::PortResult<p::ResponseEffectRecord> {
                Err(p::PortError::unavailable())
            }

            fn claim_due(
                &self,
                _request: &p::SchedulerClaimRequest,
            ) -> p::PortResult<Vec<p::ScheduledWork>> {
                Err(p::PortError::unavailable())
            }
        }

        impl p::ResponseSchedulerStore for FakeFenceStore {
            fn load_retry(
                &self,
                _key: &p::SchedulerWorkKey,
            ) -> p::PortResult<Option<p::SchedulerRetryState>> {
                Err(p::PortError::unavailable())
            }

            fn validate_lease(&self, _work: &p::ScheduledWork) -> p::PortResult<()> {
                Err(p::PortError::unavailable())
            }

            fn compare_and_swap_scheduled_mutation(
                &self,
                _request: &p::ResponseScheduledMutationCasRequest,
            ) -> p::PortResult<p::ResponsePlanRecord> {
                Err(p::PortError::unavailable())
            }

            fn renew_lease(
                &self,
                _request: &p::SchedulerLeaseRenewRequest,
            ) -> p::PortResult<p::ScheduledWork> {
                Err(p::PortError::unavailable())
            }

            fn record_retry(
                &self,
                _request: &p::SchedulerRetryRequest,
            ) -> p::PortResult<p::SchedulerRetryState> {
                Err(p::PortError::unavailable())
            }

            fn acknowledge_health_event(
                &self,
                _request: &p::SchedulerHealthAckRequest,
            ) -> p::PortResult<p::SchedulerRetryState> {
                Err(p::PortError::unavailable())
            }

            fn release_lease(
                &self,
                _request: &p::SchedulerLeaseReleaseRequest,
            ) -> p::PortResult<()> {
                Err(p::PortError::unavailable())
            }
        }

        impl p::ResponseDispatchStore for FakeFenceStore {
            fn ensure_dispatch_ready(&self) -> p::PortResult<()> {
                Ok(())
            }

            fn fence_uncommitted_automatic_dispatch(
                &self,
                _request: &p::AutomaticResponseDispatchFenceRequest,
            ) -> p::PortResult<p::AutomaticResponseDispatchFenceOutcome> {
                self.fence_calls.fetch_add(1, Ordering::SeqCst);
                Ok(self.outcome.clone())
            }

            fn commit_dispatch(
                &self,
                _request: &p::ResponseDispatchCommitRequest,
            ) -> p::PortResult<p::ResponseDispatchCommitOutcome> {
                Err(p::PortError::unavailable())
            }

            fn load_dispatch(
                &self,
                _key: &p::ResponseDispatchKey,
            ) -> p::PortResult<p::ResponseDispatchLoadOutcome> {
                self.dispatch_load_calls.fetch_add(1, Ordering::SeqCst);
                Err(p::PortError::unavailable())
            }

            fn recover_dispatch_work(
                &self,
                _request: &p::ResponseDispatchRecoveryRequest,
            ) -> p::PortResult<p::ResponseDispatchRecoveryOutcome> {
                Err(p::PortError::unavailable())
            }
        }

        type FenceExecutor =
            DurableActiveResponseExecutor<FakeFenceStore, TestEffects, TestReceipts, TestAlerts>;

        fn automatic_binding_fixture() -> (
            ActiveResponseExecutorAuthorityIdentity,
            ResponsePlan,
            PreparedActiveResponseDispatchBinding,
        ) {
            let identity = identity(7);
            let now_unix_ms = system_now_unix_ms();
            let plan = plan(
                now_unix_ms,
                &identity,
                ResponseApprovalRequirement::Automatic,
                false,
            );
            let request = raw_request(
                plan.clone(),
                identity.clone(),
                ActiveResponseExecutionApproval::Automatic,
            );
            let binding = PreparedActiveResponseDispatchBinding {
                schema_version: PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
                tenant_id: plan.tenant_id.clone(),
                action_id: plan.action_id.clone(),
                plan_hash: plan.plan_hash,
                dispatch_id: request.dispatch_id,
                executor_authority_id: record_id(identity.authority_id()),
                executor_authority_generation: identity.generation(),
                authorized_at_unix_ms: request.authorized_at_unix_ms,
                authorization_capability_hash: digest(30),
                governed_intent_hash: digest(32),
                policy_decision_hash: digest(33),
                approval: ResponseDispatchApproval::Automatic,
            };
            (identity, plan, binding)
        }

        fn fence_record(
            binding: &PreparedActiveResponseDispatchBinding,
        ) -> p::AutomaticResponseDispatchFenceRecord {
            let canonical = chio_core::canonical_json_bytes(binding)
                .unwrap_or_else(|error| panic!("canonicalize fence binding: {error}"));
            p::AutomaticResponseDispatchFenceRecord {
                prepared_dispatch_binding: binding.clone(),
                binding_hash: Digest32::new(*chio_core::sha256(&canonical).as_bytes()),
                fenced_at_unix_ms: system_now_unix_ms(),
            }
        }

        fn executor(
            identity: ActiveResponseExecutorAuthorityIdentity,
            store: Arc<FakeFenceStore>,
        ) -> FenceExecutor {
            let signer: Arc<dyn SigningBackend> =
                Arc::new(Ed25519Backend::new(Keypair::from_seed(&[7_u8; 32])));
            DurableActiveResponseExecutor::new(
                identity,
                LeaseOwnerId::new("active-response-fence-test-worker")
                    .unwrap_or_else(|error| panic!("construct fence test lease owner: {error}")),
                store,
                Arc::new(TestEffects::ready()),
                Arc::new(TestReceipts::ready(signer)),
                Arc::new(TestAlerts::ready()),
                Arc::new(FixedClock::new(system_now_unix_ms())),
                30_000,
            )
            .unwrap_or_else(|error| panic!("construct fence test executor: {error}"))
        }

        #[test]
        fn forged_execution_dispatch_id_is_rejected_before_store_access() {
            let (identity, plan, binding) = automatic_binding_fixture();
            let record = fence_record(&binding);
            let store = Arc::new(FakeFenceStore::new(
                p::AutomaticResponseDispatchFenceOutcome::Fenced(record),
            ));
            let mut request = raw_request(
                plan,
                identity.clone(),
                ActiveResponseExecutionApproval::Automatic,
            );
            request.dispatch_id = record_id(
                "active_response_dispatch_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            );
            let executor = executor(identity, Arc::clone(&store));

            let error = require_error(executor.execute_source(&request));
            assert!(matches!(
                error,
                ActiveResponseExecutorError::RejectedBeforeCommit(_)
            ));
            assert_eq!(store.dispatch_load_calls.load(Ordering::SeqCst), 0);
            assert_eq!(store.fence_calls.load(Ordering::SeqCst), 0);
        }

        #[test]
        fn forged_canonical_shaped_dispatch_id_is_rejected_before_store_mutation() {
            let (identity, plan, mut binding) = automatic_binding_fixture();
            let record = fence_record(&binding);
            let store = Arc::new(FakeFenceStore::new(
                p::AutomaticResponseDispatchFenceOutcome::Fenced(record),
            ));
            binding.dispatch_id = record_id(
                "active_response_dispatch_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            );
            let executor = executor(identity, Arc::clone(&store));

            let error =
                require_error(executor.fence_uncommitted_automatic_dispatch(&plan, &binding));
            assert!(matches!(
                error,
                ActiveResponseExecutorError::RejectedBeforeCommit(_)
            ));
            assert_eq!(store.fence_calls.load(Ordering::SeqCst), 0);
        }

        #[test]
        fn malformed_fenced_outcome_is_reported_as_unknown() {
            let (identity, plan, binding) = automatic_binding_fixture();
            let mut record = fence_record(&binding);
            record.binding_hash = digest(99);
            let store = Arc::new(FakeFenceStore::new(
                p::AutomaticResponseDispatchFenceOutcome::Fenced(record),
            ));
            let executor = executor(identity, Arc::clone(&store));

            let error =
                require_error(executor.fence_uncommitted_automatic_dispatch(&plan, &binding));
            assert!(matches!(
                error,
                ActiveResponseExecutorError::OutcomeUnknown(_)
            ));
            assert_eq!(store.fence_calls.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn malformed_existing_fence_outcome_is_reported_as_unknown() {
            let (identity, plan, binding) = automatic_binding_fixture();
            let mut record = fence_record(&binding);
            record.fenced_at_unix_ms = 0;
            let store = Arc::new(FakeFenceStore::new(
                p::AutomaticResponseDispatchFenceOutcome::ExistingFence(record),
            ));
            let executor = executor(identity, Arc::clone(&store));

            let error =
                require_error(executor.fence_uncommitted_automatic_dispatch(&plan, &binding));
            assert!(matches!(
                error,
                ActiveResponseExecutorError::OutcomeUnknown(_)
            ));
            assert_eq!(store.fence_calls.load(Ordering::SeqCst), 1);
        }
    }

    include!("active_response/tests_tail.inc");
}
