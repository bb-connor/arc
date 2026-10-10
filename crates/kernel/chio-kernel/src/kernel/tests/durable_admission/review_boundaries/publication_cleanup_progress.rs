//! Governed runtime publication and activation must finish every candidate
//! recovery pass before refusing cleanup that another lease holder still owns.
use super::*;
use crate::approval::{
    ApprovalDecision, ApprovalFilter, ApprovalRequest, ApprovalReservation,
    ApprovalReservationMember, ApprovalSetReservationInput, ApprovalStore, ApprovalStoreError,
    ApprovalStoreProfile, InMemoryApprovalStore, ResolvedApproval,
};
use crate::kernel::active_response_operation_binding::ActiveResponseOperationAnchor;
use crate::security_admission_operation::{
    AdmissionCleanupAction, AdmissionCleanupActionClaimOutcome, AdmissionCleanupActionKind,
    AdmissionCleanupActionState, AdmissionDispatchState, AdmissionOperation,
    AdmissionOperationCasOutcome, AdmissionOperationCompareAndSwap,
    AdmissionOperationCreateOutcome, AdmissionOperationError, AdmissionOperationKind,
    AdmissionOperationState, AdmissionOperationStore, AdmissionOperationStoreProfile,
    InMemoryAdmissionOperationStore, ReplayReservationState,
};

const CLEANUP_LEASE_MS: u64 = 30_000;
const FOREIGN_CLAIM_TOKEN: &str = "other";

/// A corrupted journal readback of one operation's completed receipt outbox.
#[derive(Clone)]
enum ReceiptReadbackFault {
    Missing,
    Duplicated,
    Substituted(AdmissionCleanupAction),
}

struct DurableOperations {
    inner: InMemoryAdmissionOperationStore,
    fail_compensation_inventory: AtomicBool,
    fail_receipt_inventory: AtomicBool,
    receipt_readback_fault: std::sync::Mutex<Option<(String, ReceiptReadbackFault)>>,
    candidate_pages: AtomicUsize,
}

impl AdmissionOperationStore for DurableOperations {
    fn authority_profile(&self) -> AdmissionOperationStoreProfile {
        AdmissionOperationStoreProfile::SingleNodeDurable
    }
    fn cleanup_journal_delegate(&self) -> Option<&dyn AdmissionOperationStore> {
        Some(&self.inner)
    }
    fn create_prepared(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationCreateOutcome, AdmissionOperationError> {
        self.inner.create_prepared(operation)
    }
    fn load_cleanup_actions(
        &self,
        operation_id: &str,
    ) -> Result<Vec<AdmissionCleanupAction>, AdmissionOperationError> {
        let mut actions = self.inner.load_cleanup_actions(operation_id)?;
        let fault = self
            .receipt_readback_fault
            .lock()
            .map_err(|_| AdmissionOperationError::Unavailable("readback fault poisoned".into()))?
            .clone();
        let Some((target, fault)) = fault else {
            return Ok(actions);
        };
        if target != operation_id {
            return Ok(actions);
        }
        let Some(receipt) = actions
            .iter()
            .find(|action| {
                action.kind() == AdmissionCleanupActionKind::TerminalReceipt
                    && action.state() == AdmissionCleanupActionState::Completed
            })
            .cloned()
        else {
            return Ok(actions);
        };
        match fault {
            ReceiptReadbackFault::Missing => {
                actions.retain(|action| action.kind() != receipt.kind());
            }
            ReceiptReadbackFault::Duplicated => actions.push(receipt),
            ReceiptReadbackFault::Substituted(other) => {
                actions.retain(|action| action.kind() != receipt.kind());
                actions.push(other);
            }
        }
        Ok(actions)
    }
    fn load(&self, id: &str) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
        self.inner.load(id)
    }
    fn count_unresolved_by_authority(
        &self,
        kind: AdmissionOperationKind,
        authority: &str,
    ) -> Result<u64, AdmissionOperationError> {
        self.inner.count_unresolved_by_authority(kind, authority)
    }
    fn compare_and_swap(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        self.inner.compare_and_swap(request)
    }
    fn list_compensated_with_pending_cleanup_page(
        &self,
        kind: Option<AdmissionOperationKind>,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if self.fail_compensation_inventory.load(Ordering::SeqCst) {
            return Err(AdmissionOperationError::Unavailable(
                "injected compensation inventory failure".into(),
            ));
        }
        self.inner
            .list_compensated_with_pending_cleanup_page(kind, after_operation_id, limit)
    }
    fn list_admission_recovery_candidates_page(
        &self,
        kind: AdmissionOperationKind,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        self.candidate_pages.fetch_add(1, Ordering::SeqCst);
        self.inner
            .list_admission_recovery_candidates_page(kind, after_operation_id, limit)
    }
    fn list_operations_with_pending_cleanup_action_page(
        &self,
        operation_kind: AdmissionOperationKind,
        action_kind: AdmissionCleanupActionKind,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if self.fail_receipt_inventory.load(Ordering::SeqCst) {
            return Err(AdmissionOperationError::Unavailable(
                "injected terminal receipt inventory failure".into(),
            ));
        }
        self.inner.list_operations_with_pending_cleanup_action_page(
            operation_kind,
            action_kind,
            after_operation_id,
            limit,
        )
    }
}

struct DurableApprovals {
    legacy: InMemoryApprovalStore,
    reservations: std::sync::Mutex<BTreeMap<String, ApprovalReservation>>,
}

impl DurableApprovals {
    fn transition(
        &self,
        operation_id: &str,
        next: ReplayReservationState,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        let mut reservations = self
            .reservations
            .lock()
            .map_err(|_| ApprovalStoreError::Backend("reservation map poisoned".into()))?;
        let current = reservations
            .get(operation_id)
            .cloned()
            .ok_or_else(|| ApprovalStoreError::NotFound(operation_id.into()))?;
        if current.state() == next {
            return Ok(current);
        }
        if current.state() != ReplayReservationState::Reserved {
            return Err(ApprovalStoreError::Conflict(format!(
                "reservation {operation_id} is already final"
            )));
        }
        let updated = ApprovalReservation::from_persisted_parts(
            operation_id.into(),
            current.approval_set().clone(),
            next,
        )?;
        reservations.insert(operation_id.into(), updated.clone());
        Ok(updated)
    }

    fn state(&self, operation_id: &str) -> TestResult<ReplayReservationState> {
        Ok(self
            .get_approval_reservation(operation_id)?
            .ok_or("approval reservation")?
            .state())
    }
}

impl ApprovalStore for DurableApprovals {
    fn authority_profile(&self) -> ApprovalStoreProfile {
        ApprovalStoreProfile::SingleNodeDurable
    }
    fn store_pending(&self, request: &ApprovalRequest) -> Result<(), ApprovalStoreError> {
        self.legacy.store_pending(request)
    }
    fn get_pending(&self, id: &str) -> Result<Option<ApprovalRequest>, ApprovalStoreError> {
        self.legacy.get_pending(id)
    }
    fn list_pending(
        &self,
        filter: &ApprovalFilter,
    ) -> Result<Vec<ApprovalRequest>, ApprovalStoreError> {
        self.legacy.list_pending(filter)
    }
    fn resolve(&self, id: &str, decision: &ApprovalDecision) -> Result<(), ApprovalStoreError> {
        self.legacy.resolve(id, decision)
    }
    fn count_approved(&self, subject: &str, policy: &str) -> Result<u64, ApprovalStoreError> {
        self.legacy.count_approved(subject, policy)
    }
    fn record_consumed(&self, token: &str, hash: &str, now: u64) -> Result<(), ApprovalStoreError> {
        self.legacy.record_consumed(token, hash, now)
    }
    fn is_consumed(&self, token: &str, hash: &str) -> Result<bool, ApprovalStoreError> {
        self.legacy.is_consumed(token, hash)
    }
    fn get_resolution(&self, id: &str) -> Result<Option<ResolvedApproval>, ApprovalStoreError> {
        self.legacy.get_resolution(id)
    }
    fn reserve_approval_set(
        &self,
        operation_id: &str,
        approval_set: &ApprovalSetReservationInput,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        let mut reservations = self
            .reservations
            .lock()
            .map_err(|_| ApprovalStoreError::Backend("reservation map poisoned".into()))?;
        if let Some(existing) = reservations.get(operation_id) {
            if existing.approval_set() != approval_set {
                return Err(ApprovalStoreError::Conflict(format!(
                    "reservation {operation_id} is bound to another approval set"
                )));
            }
            return Ok(existing.clone());
        }
        let reserved = ApprovalReservation::from_persisted_parts(
            operation_id.into(),
            approval_set.clone(),
            ReplayReservationState::Reserved,
        )?;
        reservations.insert(operation_id.into(), reserved.clone());
        Ok(reserved)
    }
    fn commit_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        self.transition(operation_id, ReplayReservationState::Committed)
    }
    fn cancel_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        self.transition(operation_id, ReplayReservationState::Cancelled)
    }
    fn get_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<Option<ApprovalReservation>, ApprovalStoreError> {
        Ok(self
            .reservations
            .lock()
            .map_err(|_| ApprovalStoreError::Backend("reservation map poisoned".into()))?
            .get(operation_id)
            .cloned())
    }
}

struct IdleExecutor(crate::ActiveResponseExecutorAuthorityIdentity);

impl crate::ActiveResponseExecutorAuthority for IdleExecutor {
    fn identity(&self) -> crate::ActiveResponseExecutorAuthorityIdentity {
        self.0.clone()
    }
    fn ensure_ready(&self) -> Result<(), crate::ActiveResponseExecutorError> {
        Ok(())
    }
    fn execute_active_response(
        &self,
        _: &crate::ActiveResponseExecutionRequest,
    ) -> Result<crate::ActiveResponseExecutionEvidence, crate::ActiveResponseExecutorError> {
        Err(crate::ActiveResponseExecutorError::NotReady(
            "publication recovery never dispatches".into(),
        ))
    }
}

struct ReadyFindings;

impl crate::ActiveResponseFindingAuthority for ReadyFindings {
    fn ensure_ready(&self) -> Result<(), crate::ActiveResponseFindingAuthorityError> {
        Ok(())
    }
    fn load_correlated_finding(
        &self,
        _: &chio_security_types::ports::OpaqueReceiptRef,
    ) -> Result<
        Option<crate::AuthoritativeCorrelatedFindingEvidence>,
        crate::ActiveResponseFindingAuthorityError,
    > {
        Ok(None)
    }
}

struct ReadyIssuance;

impl crate::CapabilityIssuanceAdmissionAuthority for ReadyIssuance {
    fn ensure_ready(&self) -> chio_security_types::ports::PortResult<()> {
        Ok(())
    }
    fn authorize(
        &self,
        _: &chio_security_types::ports::IssuanceFreezeAdmissionQuery,
    ) -> chio_security_types::ports::PortResult<()> {
        Ok(())
    }
}

struct NoDispatchHook;

impl SecurityPreDispatchHook for NoDispatchHook {
    fn name(&self) -> &str {
        "publication-cleanup-progress"
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(None)
    }
}

struct Harness {
    kernel: ChioKernel,
    operations: Arc<DurableOperations>,
    approvals: Arc<DurableApprovals>,
    executor: crate::ActiveResponseExecutorAuthorityIdentity,
    threshold_authority: PublicKey,
    started_at_ms: u64,
}

impl Harness {
    fn new(started_at_secs: u64) -> TestResult<Self> {
        let mut kernel = active_response_kernel();
        let operations = Arc::new(DurableOperations {
            inner: InMemoryAdmissionOperationStore::new(),
            fail_compensation_inventory: AtomicBool::new(false),
            fail_receipt_inventory: AtomicBool::new(false),
            receipt_readback_fault: std::sync::Mutex::new(None),
            candidate_pages: AtomicUsize::new(0),
        });
        let approvals = Arc::new(DurableApprovals {
            legacy: InMemoryApprovalStore::new(),
            reservations: std::sync::Mutex::new(BTreeMap::new()),
        });
        kernel.admission_operation_store = Some(operations.clone());
        kernel.approval_store = Some(approvals.clone());
        kernel.set_active_response_submission_authority(Keypair::generate().public_key())?;
        Ok(Self {
            kernel,
            operations,
            approvals,
            executor: crate::ActiveResponseExecutorAuthorityIdentity::new(
                Keypair::generate().public_key(),
                1,
            )?,
            threshold_authority: Keypair::generate().public_key(),
            started_at_ms: started_at_secs
                .checked_mul(1_000)
                .ok_or("start time overflow")?,
        })
    }

    fn publication(&self) -> GovernedSecurityRuntimePublication {
        GovernedSecurityRuntimePublication {
            active_response_requirement_resolver: Arc::new(
                |_: &crate::ActiveResponsePolicyRequest,
                 _: &str|
                 -> Result<
                    crate::ActiveResponseRequirement,
                    crate::ActiveResponsePolicyResolutionError,
                > {
                    Err(crate::ActiveResponsePolicyResolutionError::Invalid(
                        "publication recovery resolves no plan".into(),
                    ))
                },
            ),
            threshold_approval_requirement_resolver: Arc::new(
                |_: &str,
                 _: &str,
                 _: &str|
                 -> Result<
                    Option<crate::threshold_approval::ThresholdApprovalRequirement>,
                    String,
                > { Err("publication recovery resolves no threshold".into()) },
            ),
            admission_operation_store: self.operations.clone(),
            approval_store: self.approvals.clone(),
            budget_store: self.kernel.budget_store.clone(),
            finding_authority: Arc::new(ReadyFindings),
            executor_authority: Arc::new(IdleExecutor(self.executor.clone())),
            capability_issuance_admission_authority: Arc::new(ReadyIssuance),
            threshold_policy_authorities: vec![self.threshold_authority.clone()],
            guards: Vec::new(),
            pre_dispatch_hook: Arc::new(NoDispatchHook),
            post_invocation_pipeline: crate::PostInvocationPipeline::new(),
        }
    }

    fn publish(&mut self) -> Result<(), KernelError> {
        let publication = self.publication();
        self.kernel.publish_governed_security_runtime(publication)
    }

    fn install_independent_authorities(&mut self) -> TestResult {
        self.kernel
            .set_active_response_requirement_resolver(Arc::new(
                |_: &crate::ActiveResponsePolicyRequest,
                 _: &str|
                 -> Result<
                    crate::ActiveResponseRequirement,
                    crate::ActiveResponsePolicyResolutionError,
                > {
                    Err(crate::ActiveResponsePolicyResolutionError::Invalid(
                        "activation recovery resolves no plan".into(),
                    ))
                },
            ))?;
        self.kernel
            .set_active_response_finding_authority(Arc::new(ReadyFindings))?;
        self.kernel
            .set_active_response_executor_authority(Arc::new(IdleExecutor(
                self.executor.clone(),
            )))?;
        Ok(())
    }

    fn seed_reserved(
        &self,
        authority_id: &str,
        request_id: &str,
    ) -> TestResult<AdmissionOperation> {
        let token = format!("{request_id}-approval-token");
        let approval_set = ApprovalSetReservationInput::new(
            sha256_hex(format!("{request_id}-approval-set").as_bytes()),
            vec![ApprovalReservationMember::new(
                token.clone(),
                sha256_hex(token.as_bytes()),
            )?],
            self.started_at_ms / 1_000 + 300,
        )?;
        let prepared = prepared_active_response(
            &self.kernel,
            authority_id,
            request_id,
            Some(approval_set.approval_set_hash().into()),
        )?;
        self.operations.create_prepared(prepared.clone())?;
        let anchor = ActiveResponseOperationAnchor {
            plan_hash: sha256_hex(format!("{request_id}-plan").as_bytes()),
            executor_authority_id: authority_id.into(),
            executor_authority_generation: self.executor.generation(),
            authorized_at_unix_ms: self.started_at_ms,
            authorization_capability_hash: prepared.authorization_capability_hash().into(),
            governed_intent_hash: sha256_hex(format!("{request_id}-intent").as_bytes()),
            policy_decision_hash: sha256_hex(format!("{request_id}-decision").as_bytes()),
            admission_artifact_fingerprint: None,
            approval_set_hash: approval_set.approval_set_hash().into(),
        };
        self.kernel
            .journal_active_response_operation_anchor(&prepared, anchor, &approval_set)
            .map_err(|_| "active-response anchor journal")?;
        self.approvals
            .reserve_approval_set(prepared.operation_id(), &approval_set)?;
        Ok(prepared)
    }

    fn seed_committed(&self, request_id: &str) -> TestResult<AdmissionOperation> {
        let prepared = self.seed_reserved(self.executor.authority_id(), request_id)?;
        let AdmissionOperationCasOutcome::Applied(reserved) =
            self.operations
                .compare_and_swap(AdmissionOperationCompareAndSwap {
                    operation_id: prepared.operation_id(),
                    expected_version: prepared.version(),
                    coordinator_lease_epoch: prepared.coordinator_lease_epoch(),
                    next_state: AdmissionOperationState::ApprovalReserved,
                    next_dispatch_state: AdmissionDispatchState::NotStarted,
                    next_coordinator_lease_epoch: prepared.coordinator_lease_epoch(),
                    last_error: None,
                })?
        else {
            return Err("approval reservation transition".into());
        };
        self.approvals
            .commit_approval_reservation(reserved.operation_id())?;
        Ok(reserved)
    }

    fn approval_action(
        &self,
        operation: &AdmissionOperation,
    ) -> TestResult<AdmissionCleanupAction> {
        Ok(self
            .operations
            .load_cleanup_actions(operation.operation_id())?
            .into_iter()
            .find(|action| action.kind() == AdmissionCleanupActionKind::Approval)
            .ok_or("approval cleanup action")?)
    }

    fn hold_foreign_cleanup_lease(&self, operation: &AdmissionOperation) -> TestResult<u64> {
        let deadline = self
            .started_at_ms
            .checked_add(CLEANUP_LEASE_MS)
            .ok_or("lease deadline overflow")?;
        let claimed = self.operations.claim_cleanup_action(
            self.approval_action(operation)?.action_id(),
            FOREIGN_CLAIM_TOKEN,
            self.started_at_ms,
            deadline,
        )?;
        assert!(
            matches!(&claimed, AdmissionCleanupActionClaimOutcome::Claimed(action)
                if action.claim_token() == Some(FOREIGN_CLAIM_TOKEN)),
            "{claimed:?}"
        );
        Ok(deadline)
    }

    fn assert_foreign_lease_retained(
        &self,
        operation: &AdmissionOperation,
        deadline: u64,
    ) -> TestResult {
        let action = self.approval_action(operation)?;
        assert_eq!(action.state(), AdmissionCleanupActionState::Claimed);
        assert_eq!(action.claim_token(), Some(FOREIGN_CLAIM_TOKEN));
        assert_eq!(action.claim_deadline_unix_ms(), Some(deadline));
        assert_eq!(
            self.state(operation)?,
            AdmissionOperationState::CompensationPending
        );
        assert_eq!(
            self.approvals.state(operation.operation_id())?,
            ReplayReservationState::Reserved
        );
        Ok(())
    }

    fn terminal_receipt_action(
        &self,
        operation: &AdmissionOperation,
    ) -> TestResult<AdmissionCleanupAction> {
        Ok(self
            .operations
            .load_cleanup_actions(operation.operation_id())?
            .into_iter()
            .find(|action| action.kind() == AdmissionCleanupActionKind::TerminalReceipt)
            .ok_or("terminal receipt outbox")?)
    }

    /// Another worker committed the atomic terminal transition and still
    /// holds the signed receipt outbox lease while it persists the receipt.
    fn seed_busy_terminal_receipt(
        &self,
        request_id: &str,
    ) -> TestResult<(AdmissionOperation, u64)> {
        let terminal = self.seed_terminal_receipt(self.executor.authority_id(), request_id)?;
        let outbox = self.terminal_receipt_action(&terminal)?;
        let deadline = self
            .started_at_ms
            .checked_add(CLEANUP_LEASE_MS)
            .ok_or("lease deadline overflow")?;
        let claimed = self.operations.claim_cleanup_action(
            outbox.action_id(),
            FOREIGN_CLAIM_TOKEN,
            self.started_at_ms,
            deadline,
        )?;
        assert!(
            matches!(&claimed, AdmissionCleanupActionClaimOutcome::Claimed(action)
                if action.claim_token() == Some(FOREIGN_CLAIM_TOKEN)
                    && action.claim_deadline_unix_ms() == Some(deadline)),
            "{claimed:?}"
        );
        Ok((terminal, deadline))
    }

    /// A compensated operation whose signed receipt outbox was inserted by
    /// the atomic terminal transition and is still unclaimed.
    fn seed_terminal_receipt(
        &self,
        authority_id: &str,
        request_id: &str,
    ) -> TestResult<AdmissionOperation> {
        let prepared = prepared_active_response(&self.kernel, authority_id, request_id, None)?;
        self.operations.create_prepared(prepared.clone())?;
        let staged = self
            .kernel
            .stage_compensation_pending_with_terminal_receipt(
                self.operations.as_ref(),
                &prepared,
                "compensated before dispatch with a signed receipt outbox",
            )?;
        let outbox = self.terminal_receipt_action(&staged)?;
        let AdmissionOperationCasOutcome::Applied(terminal) =
            self.operations.compare_and_swap_with_cleanup_action(
                AdmissionOperationCompareAndSwap {
                    operation_id: staged.operation_id(),
                    expected_version: staged.version(),
                    coordinator_lease_epoch: staged.coordinator_lease_epoch(),
                    next_state: AdmissionOperationState::CompensatedBeforeDispatch,
                    next_dispatch_state: AdmissionDispatchState::NotStarted,
                    next_coordinator_lease_epoch: staged.coordinator_lease_epoch(),
                    last_error: staged.last_error().map(ToOwned::to_owned),
                },
                outbox.clone(),
            )?
        else {
            return Err("atomic terminal receipt transition".into());
        };
        assert_eq!(
            self.terminal_receipt_action(&terminal)?.state(),
            AdmissionCleanupActionState::Pending
        );
        Ok(terminal)
    }

    fn assert_receipt_lease_retained(
        &self,
        operation: &AdmissionOperation,
        deadline: u64,
    ) -> TestResult {
        let outbox = self.terminal_receipt_action(operation)?;
        assert_eq!(outbox.state(), AdmissionCleanupActionState::Claimed);
        assert_eq!(outbox.claim_token(), Some(FOREIGN_CLAIM_TOKEN));
        assert_eq!(outbox.claim_deadline_unix_ms(), Some(deadline));
        assert_eq!(
            self.state(operation)?,
            AdmissionOperationState::CompensatedBeforeDispatch
        );
        Ok(())
    }

    /// The typed claim outcome at the kernel's authority time proves that
    /// another token still holds an unexpired lease on the receipt outbox.
    fn assert_receipt_lease_busy(
        &self,
        operation: &AdmissionOperation,
        deadline: u64,
    ) -> TestResult {
        let now_ms = self.kernel.trusted_now_millis()?.get();
        assert!(now_ms < deadline, "{now_ms} is not before {deadline}");
        let probe = self.operations.claim_cleanup_action(
            self.terminal_receipt_action(operation)?.action_id(),
            "busy-probe",
            now_ms,
            now_ms
                .checked_add(CLEANUP_LEASE_MS)
                .ok_or("probe deadline overflow")?,
        )?;
        assert!(
            matches!(&probe, AdmissionCleanupActionClaimOutcome::Busy(action)
                if action.claim_token() == Some(FOREIGN_CLAIM_TOKEN)
                    && action.claim_deadline_unix_ms() == Some(deadline)),
            "{probe:?}"
        );
        self.assert_receipt_lease_retained(operation, deadline)
    }

    fn state(&self, operation: &AdmissionOperation) -> TestResult<AdmissionOperationState> {
        Ok(self
            .operations
            .load(operation.operation_id())?
            .ok_or("seeded operation")?
            .state())
    }
}

fn assert_cleanup_pending(result: Result<(), KernelError>, operation: &AdmissionOperation) {
    assert!(
        matches!(&result, Err(KernelError::Internal(detail))
        if *detail == format!(
            "active-response cleanup remains pending for {}",
            operation.operation_id()
        )),
        "{result:?}"
    );
}

#[test]
fn publication_recovers_later_candidates_before_refusing_a_busy_cleanup_lease() -> TestResult {
    let started_at_secs = current_unix_timestamp() + 1;
    let _started = chio_test_support::clock::scope_unix_secs(started_at_secs);
    let mut harness = Harness::new(started_at_secs)?;
    let unpublished = harness.kernel.governed_security_runtime_status();
    let authority = harness.executor.authority_id().to_owned();

    let busy = harness.seed_reserved(&authority, "busy-cleanup")?;
    let lease_deadline = harness.hold_foreign_cleanup_lease(&busy)?;
    assert_cleanup_pending(harness.publish(), &busy);
    harness.assert_foreign_lease_retained(&busy, lease_deadline)?;

    let released = harness.seed_reserved(&authority, "later-release")?;
    let committed = harness.seed_committed("later-commit")?;
    assert_eq!(harness.state(&released)?, AdmissionOperationState::Prepared);
    assert_eq!(
        harness.approvals.state(released.operation_id())?,
        ReplayReservationState::Reserved
    );
    assert_eq!(
        harness.state(&committed)?,
        AdmissionOperationState::ApprovalReserved
    );
    assert_eq!(
        harness.approvals.state(committed.operation_id())?,
        ReplayReservationState::Committed
    );

    assert_cleanup_pending(harness.publish(), &busy);
    assert_eq!(
        harness.kernel.governed_security_runtime_status(),
        unpublished
    );
    harness.assert_foreign_lease_retained(&busy, lease_deadline)?;
    assert_eq!(
        harness.state(&released)?,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        harness.approvals.state(released.operation_id())?,
        ReplayReservationState::Cancelled
    );
    assert_eq!(
        harness.state(&committed)?,
        AdmissionOperationState::DispatchCommitted
    );

    let _before_deadline = chio_test_support::clock::scope_unix_secs(lease_deadline / 1_000 - 1);
    assert_cleanup_pending(harness.publish(), &busy);
    harness.assert_foreign_lease_retained(&busy, lease_deadline)?;
    assert_eq!(
        harness.kernel.governed_security_runtime_status(),
        unpublished
    );

    let _at_deadline = chio_test_support::clock::scope_unix_secs(lease_deadline / 1_000);
    harness.publish()?;
    assert_eq!(
        harness.state(&busy)?,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        harness.approvals.state(busy.operation_id())?,
        ReplayReservationState::Cancelled
    );
    let published = harness.kernel.governed_security_runtime_status();
    assert_eq!(published.publication_generation, 1);
    assert!(published.active_response_enabled);
    Ok(())
}

#[test]
fn publication_stops_at_a_fatal_compensation_inventory_failure() -> TestResult {
    let started_at_secs = current_unix_timestamp() + 1;
    let _started = chio_test_support::clock::scope_unix_secs(started_at_secs);
    let mut harness = Harness::new(started_at_secs)?;
    let unpublished = harness.kernel.governed_security_runtime_status();
    let authority = harness.executor.authority_id().to_owned();
    let healthy = harness.seed_reserved(&authority, "healthy-after-fatal")?;
    harness
        .operations
        .fail_compensation_inventory
        .store(true, Ordering::SeqCst);

    let result = harness.publish();
    let expected = format!(
        "security admission operation failed: {}",
        AdmissionOperationError::Unavailable("injected compensation inventory failure".into())
    );
    assert!(
        matches!(&result, Err(KernelError::Internal(detail)) if *detail == expected),
        "{result:?}"
    );
    assert_eq!(harness.operations.candidate_pages.load(Ordering::SeqCst), 0);
    assert_eq!(harness.state(&healthy)?, AdmissionOperationState::Prepared);
    assert_eq!(
        harness.approvals.state(healthy.operation_id())?,
        ReplayReservationState::Reserved
    );
    assert_eq!(
        harness.kernel.governed_security_runtime_status(),
        unpublished
    );
    Ok(())
}

#[test]
fn publication_still_refuses_a_foreign_executor_row() -> TestResult {
    let started_at_secs = current_unix_timestamp() + 1;
    let _started = chio_test_support::clock::scope_unix_secs(started_at_secs);
    let mut harness = Harness::new(started_at_secs)?;
    let unpublished = harness.kernel.governed_security_runtime_status();
    let authority = harness.executor.authority_id().to_owned();
    let foreign = prepared_active_response(
        &harness.kernel,
        &sha256_hex(b"foreign-executor-authority"),
        "foreign-executor-row",
        None,
    )?;
    harness.operations.create_prepared(foreign.clone())?;
    let healthy = harness.seed_reserved(&authority, "healthy-beside-foreign")?;

    let result = harness.publish();
    assert!(
        matches!(&result, Err(KernelError::Internal(detail))
        if *detail == format!(
            "governed active-response operation {} belongs to a different executor authority",
            foreign.operation_id()
        )),
        "{result:?}"
    );
    assert_eq!(
        harness
            .operations
            .load(foreign.operation_id())?
            .ok_or("foreign row")?,
        foreign
    );
    assert_eq!(
        harness.state(&healthy)?,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        harness.kernel.governed_security_runtime_status(),
        unpublished
    );
    Ok(())
}

#[test]
fn publication_without_pending_cleanup_publishes_after_recovery() -> TestResult {
    let started_at_secs = current_unix_timestamp() + 1;
    let _started = chio_test_support::clock::scope_unix_secs(started_at_secs);
    let mut harness = Harness::new(started_at_secs)?;
    let authority = harness.executor.authority_id().to_owned();
    let healthy = harness.seed_reserved(&authority, "healthy-publication")?;

    harness.publish()?;
    assert_eq!(
        harness.state(&healthy)?,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        harness.approvals.state(healthy.operation_id())?,
        ReplayReservationState::Cancelled
    );
    let published = harness.kernel.governed_security_runtime_status();
    assert_eq!(published.publication_generation, 1);
    assert!(published.active_response_enabled);
    assert!(published.threshold_approval_enabled);
    Ok(())
}

#[test]
fn activation_refuses_while_a_busy_cleanup_lease_remains() -> TestResult {
    let started_at_secs = current_unix_timestamp() + 1;
    let _started = chio_test_support::clock::scope_unix_secs(started_at_secs);
    let mut harness = Harness::new(started_at_secs)?;
    harness.install_independent_authorities()?;
    let authority = harness.executor.authority_id().to_owned();
    let busy = harness.seed_reserved(&authority, "activation-busy")?;
    let lease_deadline = harness.hold_foreign_cleanup_lease(&busy)?;
    assert_cleanup_pending(
        harness.kernel.enable_governed_active_response_plans(),
        &busy,
    );
    harness.assert_foreign_lease_retained(&busy, lease_deadline)?;

    let released = harness.seed_reserved(&authority, "activation-later")?;
    assert_cleanup_pending(
        harness.kernel.enable_governed_active_response_plans(),
        &busy,
    );
    harness.assert_foreign_lease_retained(&busy, lease_deadline)?;
    assert!(!harness.kernel.governed_active_response_plans_enabled);
    assert_eq!(
        harness.state(&released)?,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        harness.approvals.state(released.operation_id())?,
        ReplayReservationState::Cancelled
    );

    let _at_deadline = chio_test_support::clock::scope_unix_secs(lease_deadline / 1_000);
    harness.kernel.enable_governed_active_response_plans()?;
    assert!(harness.kernel.governed_active_response_plans_enabled);
    assert_eq!(
        harness.state(&busy)?,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        harness.approvals.state(busy.operation_id())?,
        ReplayReservationState::Cancelled
    );
    Ok(())
}

const RECEIPT_OUTBOXES_REMAIN: &str =
    "one or more terminal receipt outboxes remain after the paged recovery pass";

#[test]
fn publication_services_later_candidates_while_a_terminal_receipt_lease_is_busy() -> TestResult {
    let started_at_secs = current_unix_timestamp() + 1;
    let _started = chio_test_support::clock::scope_unix_secs(started_at_secs);
    let mut harness = Harness::new(started_at_secs)?;
    let unpublished = harness.kernel.governed_security_runtime_status();
    let authority = harness.executor.authority_id().to_owned();

    let (busy, lease_deadline) = harness.seed_busy_terminal_receipt("busy-terminal-receipt")?;
    harness.assert_receipt_lease_busy(&busy, lease_deadline)?;
    let outbox_recovery = harness.kernel.recover_terminal_receipt_outboxes_with_store(
        harness.operations.as_ref(),
        AdmissionOperationKind::GovernedActiveResponse,
        Some(&authority),
    );
    assert!(
        matches!(&outbox_recovery, Err(KernelError::Internal(detail))
            if detail == RECEIPT_OUTBOXES_REMAIN),
        "{outbox_recovery:?}"
    );
    harness.assert_receipt_lease_busy(&busy, lease_deadline)?;

    let released = harness.seed_reserved(&authority, "later-after-busy-receipt")?;
    assert_eq!(released.coordinator_authority_id(), authority);
    assert_eq!(harness.state(&released)?, AdmissionOperationState::Prepared);
    assert_eq!(
        harness.approval_action(&released)?.state(),
        AdmissionCleanupActionState::Pending
    );
    assert_eq!(
        harness.approvals.state(released.operation_id())?,
        ReplayReservationState::Reserved
    );

    let refused = harness.publish();
    assert_eq!(
        harness.kernel.governed_security_runtime_status(),
        unpublished
    );
    harness.assert_receipt_lease_busy(&busy, lease_deadline)?;
    assert_eq!(
        harness.state(&released)?,
        AdmissionOperationState::CompensatedBeforeDispatch,
        "{refused:?}"
    );
    assert_eq!(
        harness.approvals.state(released.operation_id())?,
        ReplayReservationState::Cancelled
    );
    assert_cleanup_pending(refused, &busy);

    let _before_deadline = chio_test_support::clock::scope_unix_secs(lease_deadline / 1_000 - 1);
    assert_cleanup_pending(harness.publish(), &busy);
    harness.assert_receipt_lease_busy(&busy, lease_deadline)?;
    assert_eq!(
        harness.kernel.governed_security_runtime_status(),
        unpublished
    );

    let _at_deadline = chio_test_support::clock::scope_unix_secs(lease_deadline / 1_000);
    harness.publish()?;
    assert_eq!(
        harness.terminal_receipt_action(&busy)?.state(),
        AdmissionCleanupActionState::Completed
    );
    assert_eq!(
        harness.state(&busy)?,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    let published = harness.kernel.governed_security_runtime_status();
    assert_eq!(published.publication_generation, 1);
    assert!(published.active_response_enabled);
    Ok(())
}

#[test]
fn activation_services_later_candidates_while_a_terminal_receipt_lease_is_busy() -> TestResult {
    let started_at_secs = current_unix_timestamp() + 1;
    let _started = chio_test_support::clock::scope_unix_secs(started_at_secs);
    let mut harness = Harness::new(started_at_secs)?;
    harness.install_independent_authorities()?;
    let authority = harness.executor.authority_id().to_owned();
    let (busy, lease_deadline) = harness.seed_busy_terminal_receipt("activation-busy-receipt")?;
    harness.assert_receipt_lease_busy(&busy, lease_deadline)?;
    let released = harness.seed_reserved(&authority, "activation-after-busy-receipt")?;
    assert_eq!(harness.state(&released)?, AdmissionOperationState::Prepared);
    assert_eq!(
        harness.approval_action(&released)?.state(),
        AdmissionCleanupActionState::Pending
    );

    let refused = harness.kernel.enable_governed_active_response_plans();
    assert!(!harness.kernel.governed_active_response_plans_enabled);
    harness.assert_receipt_lease_busy(&busy, lease_deadline)?;
    assert_eq!(
        harness.state(&released)?,
        AdmissionOperationState::CompensatedBeforeDispatch,
        "{refused:?}"
    );
    assert_eq!(
        harness.approvals.state(released.operation_id())?,
        ReplayReservationState::Cancelled
    );
    assert!(
        matches!(&refused, Err(KernelError::Internal(detail))
            if detail == RECEIPT_OUTBOXES_REMAIN),
        "{refused:?}"
    );

    let _at_deadline = chio_test_support::clock::scope_unix_secs(lease_deadline / 1_000);
    harness.kernel.enable_governed_active_response_plans()?;
    assert!(harness.kernel.governed_active_response_plans_enabled);
    assert_eq!(
        harness.terminal_receipt_action(&busy)?.state(),
        AdmissionCleanupActionState::Completed
    );
    Ok(())
}

#[test]
fn publication_stops_at_a_fatal_terminal_receipt_inventory_failure() -> TestResult {
    let started_at_secs = current_unix_timestamp() + 1;
    let _started = chio_test_support::clock::scope_unix_secs(started_at_secs);
    let mut harness = Harness::new(started_at_secs)?;
    let unpublished = harness.kernel.governed_security_runtime_status();
    let authority = harness.executor.authority_id().to_owned();
    let healthy = harness.seed_reserved(&authority, "healthy-after-receipt-fatal")?;
    harness
        .operations
        .fail_receipt_inventory
        .store(true, Ordering::SeqCst);

    let result = harness.publish();
    let expected = format!(
        "security admission operation failed: {}",
        AdmissionOperationError::Unavailable("injected terminal receipt inventory failure".into())
    );
    assert!(
        matches!(&result, Err(KernelError::Internal(detail)) if *detail == expected),
        "{result:?}"
    );
    assert_eq!(harness.operations.candidate_pages.load(Ordering::SeqCst), 0);
    assert_eq!(harness.state(&healthy)?, AdmissionOperationState::Prepared);
    assert_eq!(
        harness.approvals.state(healthy.operation_id())?,
        ReplayReservationState::Reserved
    );
    assert_eq!(
        harness.kernel.governed_security_runtime_status(),
        unpublished
    );
    Ok(())
}

#[test]
fn publication_keeps_a_receipt_inventory_fault_fatal_beside_a_busy_lease() -> TestResult {
    let started_at_secs = current_unix_timestamp() + 1;
    let _started = chio_test_support::clock::scope_unix_secs(started_at_secs);
    let mut harness = Harness::new(started_at_secs)?;
    let unpublished = harness.kernel.governed_security_runtime_status();
    let authority = harness.executor.authority_id().to_owned();
    let (busy, lease_deadline) = harness.seed_busy_terminal_receipt("busy-beside-receipt-fault")?;
    let healthy = harness.seed_reserved(&authority, "healthy-beside-receipt-fault")?;
    harness
        .operations
        .fail_receipt_inventory
        .store(true, Ordering::SeqCst);

    let result = harness.publish();
    let expected = format!(
        "security admission operation failed: {}",
        AdmissionOperationError::Unavailable("injected terminal receipt inventory failure".into())
    );
    assert!(
        matches!(&result, Err(KernelError::Internal(detail)) if *detail == expected),
        "{result:?}"
    );
    assert_eq!(harness.operations.candidate_pages.load(Ordering::SeqCst), 0);
    harness.assert_receipt_lease_busy(&busy, lease_deadline)?;
    assert_eq!(harness.state(&healthy)?, AdmissionOperationState::Prepared);
    assert_eq!(
        harness.approvals.state(healthy.operation_id())?,
        ReplayReservationState::Reserved
    );
    assert_eq!(
        harness.kernel.governed_security_runtime_status(),
        unpublished
    );
    Ok(())
}

fn receipt_item_refusal(failing_operation_id: &str) -> String {
    let item = KernelError::Internal(format!(
        "terminal receipt operation {failing_operation_id} belongs to a different coordinator authority"
    ));
    format!(
        "one or more terminal receipt outboxes remain unfinished: 1 failed, first operation {failing_operation_id}: {item}"
    )
}

#[test]
fn compensated_recovery_resolves_its_own_receipt_beside_a_busy_receipt() -> TestResult {
    let started_at_secs = current_unix_timestamp() + 1;
    let _started = chio_test_support::clock::scope_unix_secs(started_at_secs);
    let harness = Harness::new(started_at_secs)?;
    let authority = harness.executor.authority_id().to_owned();
    let (busy, lease_deadline) = harness.seed_busy_terminal_receipt("coordinator-busy-receipt")?;
    let own = harness.seed_terminal_receipt(&authority, "coordinator-own-receipt")?;

    assert!(harness
        .kernel
        .recover_compensated_admission_operation(own.operation_id())?);
    assert_eq!(
        harness.terminal_receipt_action(&own)?.state(),
        AdmissionCleanupActionState::Completed
    );
    harness.assert_receipt_lease_busy(&busy, lease_deadline)?;

    assert!(!harness
        .kernel
        .recover_compensated_admission_operation(busy.operation_id())?);
    harness.assert_receipt_lease_busy(&busy, lease_deadline)?;

    let _at_deadline = chio_test_support::clock::scope_unix_secs(lease_deadline / 1_000);
    assert!(harness
        .kernel
        .recover_compensated_admission_operation(busy.operation_id())?);
    assert_eq!(
        harness.terminal_receipt_action(&busy)?.state(),
        AdmissionCleanupActionState::Completed
    );
    Ok(())
}

#[test]
fn compensated_recovery_fails_closed_on_a_corrupt_own_receipt_readback() -> TestResult {
    let started_at_secs = current_unix_timestamp() + 1;
    let _started = chio_test_support::clock::scope_unix_secs(started_at_secs);
    for case in ["missing", "duplicated", "substituted"] {
        let harness = Harness::new(started_at_secs)?;
        let authority = harness.executor.authority_id().to_owned();
        let (busy, lease_deadline) =
            harness.seed_busy_terminal_receipt(&format!("readback-busy-{case}"))?;
        let own = harness.seed_terminal_receipt(&authority, &format!("readback-own-{case}"))?;
        let (fault, expected) = match case {
            "missing" => (
                ReceiptReadbackFault::Missing,
                format!(
                    "compensated operation {} does not have exactly one terminal receipt outbox",
                    own.operation_id()
                ),
            ),
            "duplicated" => (
                ReceiptReadbackFault::Duplicated,
                format!(
                    "compensated operation {} does not have exactly one terminal receipt outbox",
                    own.operation_id()
                ),
            ),
            _ => (
                ReceiptReadbackFault::Substituted(harness.terminal_receipt_action(&busy)?),
                format!(
                    "terminal receipt outbox for operation {} changed its immutable binding",
                    own.operation_id()
                ),
            ),
        };
        *harness
            .operations
            .receipt_readback_fault
            .lock()
            .map_err(|_| "readback fault lock")? = Some((own.operation_id().to_owned(), fault));

        let result = harness
            .kernel
            .recover_compensated_admission_operation(own.operation_id());
        assert!(
            matches!(&result, Err(KernelError::Internal(detail)) if *detail == expected),
            "{case}: {result:?}"
        );
        harness.assert_receipt_lease_busy(&busy, lease_deadline)?;
    }
    Ok(())
}

#[test]
fn a_busy_receipt_retried_until_its_lease_expires_is_one_logical_receipt() -> TestResult {
    let started_at_secs = current_unix_timestamp() + 1;
    let _started = chio_test_support::clock::scope_unix_secs(started_at_secs);
    let mut harness = Harness::new(started_at_secs)?;
    let (busy, lease_deadline) = harness.seed_busy_terminal_receipt("retried-busy-receipt")?;
    assert_cleanup_pending(harness.publish(), &busy);
    let _before_deadline = chio_test_support::clock::scope_unix_secs(lease_deadline / 1_000 - 1);
    assert_cleanup_pending(harness.publish(), &busy);
    harness.assert_receipt_lease_busy(&busy, lease_deadline)?;
    let _at_deadline = chio_test_support::clock::scope_unix_secs(lease_deadline / 1_000);
    harness.publish()?;

    let outboxes = harness
        .operations
        .load_cleanup_actions(busy.operation_id())?
        .into_iter()
        .filter(|action| action.kind() == AdmissionCleanupActionKind::TerminalReceipt)
        .collect::<Vec<_>>();
    let [outbox] = outboxes.as_slice() else {
        return Err(format!("{} terminal receipt outboxes", outboxes.len()).into());
    };
    assert_eq!(outbox.state(), AdmissionCleanupActionState::Completed);
    let receipts = harness.kernel.receipt_log().receipts();
    let first = receipts.first().ok_or("recorded terminal receipt")?;
    assert!(receipts.len() > 1, "{} receipt appends", receipts.len());
    let first_bytes = canonical_json_bytes(first)?;
    for receipt in &receipts {
        assert_eq!(receipt.id, first.id);
        assert_eq!(canonical_json_bytes(receipt)?, first_bytes);
    }
    Ok(())
}

#[test]
fn publication_stops_before_candidates_after_a_terminal_receipt_item_failure() -> TestResult {
    let started_at_secs = current_unix_timestamp() + 1;
    let _started = chio_test_support::clock::scope_unix_secs(started_at_secs);
    let mut harness = Harness::new(started_at_secs)?;
    let unpublished = harness.kernel.governed_security_runtime_status();
    let authority = harness.executor.authority_id().to_owned();
    let local = harness.seed_terminal_receipt(&authority, "local-receipt-beside-foreign")?;
    let foreign = harness.seed_terminal_receipt(
        &sha256_hex(b"foreign-receipt-authority"),
        "foreign-receipt-beside-local",
    )?;
    let healthy = harness.seed_reserved(&authority, "healthy-behind-receipt-failure")?;

    let result = harness.publish();
    let expected =
        receipt_item_refusal(std::cmp::max(local.operation_id(), foreign.operation_id()));
    assert!(
        matches!(&result, Err(KernelError::Internal(detail)) if *detail == expected),
        "{result:?}"
    );
    assert_eq!(harness.operations.candidate_pages.load(Ordering::SeqCst), 0);
    assert_eq!(harness.state(&healthy)?, AdmissionOperationState::Prepared);
    assert_eq!(
        harness.approvals.state(healthy.operation_id())?,
        ReplayReservationState::Reserved
    );
    assert_eq!(
        harness.kernel.governed_security_runtime_status(),
        unpublished
    );
    Ok(())
}

#[test]
fn activation_stops_before_candidates_after_a_receipt_item_failure_beside_a_busy_lease(
) -> TestResult {
    let started_at_secs = current_unix_timestamp() + 1;
    let _started = chio_test_support::clock::scope_unix_secs(started_at_secs);
    let mut harness = Harness::new(started_at_secs)?;
    harness.install_independent_authorities()?;
    let authority = harness.executor.authority_id().to_owned();
    let (busy, lease_deadline) =
        harness.seed_busy_terminal_receipt("activation-busy-beside-item")?;
    let foreign = harness.seed_terminal_receipt(
        &sha256_hex(b"foreign-receipt-authority"),
        "activation-foreign-receipt",
    )?;
    let healthy = harness.seed_reserved(&authority, "activation-behind-receipt-failure")?;

    let result = harness.kernel.enable_governed_active_response_plans();
    let expected = receipt_item_refusal(foreign.operation_id());
    assert!(
        matches!(&result, Err(KernelError::Internal(detail)) if *detail == expected),
        "{result:?}"
    );
    assert!(!harness.kernel.governed_active_response_plans_enabled);
    assert_eq!(harness.operations.candidate_pages.load(Ordering::SeqCst), 0);
    harness.assert_receipt_lease_busy(&busy, lease_deadline)?;
    assert_eq!(harness.state(&healthy)?, AdmissionOperationState::Prepared);
    assert_eq!(
        harness.approvals.state(healthy.operation_id())?,
        ReplayReservationState::Reserved
    );
    Ok(())
}
