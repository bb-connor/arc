//! Review regressions against original durable operation and effect boundaries.
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct CommittedApproval {
    legacy: crate::approval::InMemoryApprovalStore,
    original: crate::approval::ApprovalReservation,
}

impl CommittedApproval {
    fn new(
        operation_id: &str,
        approval_set: crate::approval::ApprovalSetReservationInput,
    ) -> TestResult<Self> {
        Ok(Self {
            legacy: crate::approval::InMemoryApprovalStore::new(),
            original: crate::approval::ApprovalReservation::from_persisted_parts(
                operation_id.into(),
                approval_set,
                crate::security_admission_operation::ReplayReservationState::Committed,
            )?,
        })
    }
}

impl crate::approval::ApprovalStore for CommittedApproval {
    fn store_pending(
        &self,
        request: &crate::approval::ApprovalRequest,
    ) -> Result<(), crate::approval::ApprovalStoreError> {
        self.legacy.store_pending(request)
    }
    fn get_pending(
        &self,
        id: &str,
    ) -> Result<Option<crate::approval::ApprovalRequest>, crate::approval::ApprovalStoreError> {
        self.legacy.get_pending(id)
    }
    fn list_pending(
        &self,
        filter: &crate::approval::ApprovalFilter,
    ) -> Result<Vec<crate::approval::ApprovalRequest>, crate::approval::ApprovalStoreError> {
        self.legacy.list_pending(filter)
    }
    fn resolve(
        &self,
        id: &str,
        decision: &crate::approval::ApprovalDecision,
    ) -> Result<(), crate::approval::ApprovalStoreError> {
        self.legacy.resolve(id, decision)
    }
    fn count_approved(
        &self,
        subject: &str,
        policy: &str,
    ) -> Result<u64, crate::approval::ApprovalStoreError> {
        self.legacy.count_approved(subject, policy)
    }
    fn record_consumed(
        &self,
        token: &str,
        parameters: &str,
        now: u64,
    ) -> Result<(), crate::approval::ApprovalStoreError> {
        self.legacy.record_consumed(token, parameters, now)
    }
    fn is_consumed(
        &self,
        token: &str,
        parameters: &str,
    ) -> Result<bool, crate::approval::ApprovalStoreError> {
        self.legacy.is_consumed(token, parameters)
    }
    fn get_resolution(
        &self,
        id: &str,
    ) -> Result<Option<crate::approval::ResolvedApproval>, crate::approval::ApprovalStoreError>
    {
        self.legacy.get_resolution(id)
    }
    fn get_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<Option<crate::approval::ApprovalReservation>, crate::approval::ApprovalStoreError>
    {
        Ok((operation_id == self.original.operation_id()).then(|| self.original.clone()))
    }
    fn commit_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<crate::approval::ApprovalReservation, crate::approval::ApprovalStoreError> {
        self.get_approval_reservation(operation_id)?
            .ok_or_else(|| crate::approval::ApprovalStoreError::NotFound(operation_id.into()))
    }
}

struct FailOnceClock {
    unavailable: std::sync::atomic::AtomicBool,
}

impl chio_security_types::clock::Clock for FailOnceClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        if self.unavailable.swap(false, Ordering::SeqCst) {
            Err(chio_security_types::clock::ClockError::Unavailable)
        } else {
            chio_security_types::clock::Clock::read(&chio_security_types::clock::SystemClock)
        }
    }
}

struct FailApprovalCommitAndClock {
    original: InMemoryGovernedApprovalReplayStore,
    clock: Arc<FailOnceClock>,
    commits: AtomicU64,
}

impl GovernedApprovalReplayStore for FailApprovalCommitAndClock {
    fn reserve_for_dispatch(
        &self,
        subject: &str,
        request: &str,
        intent: &str,
        expiry: u64,
        owner: &str,
    ) -> Result<bool, KernelError> {
        self.original
            .reserve_for_dispatch(subject, request, intent, expiry, owner)
    }
    fn commit_dispatch_reservation(
        &self,
        subject: &str,
        request: &str,
        intent: &str,
        owner: &str,
    ) -> Result<bool, KernelError> {
        if self.commits.fetch_add(1, Ordering::SeqCst) == 0 {
            self.clock.unavailable.store(true, Ordering::SeqCst);
            return Err(KernelError::GovernedTransactionDenied(
                "injected approval commit rejection".into(),
            ));
        }
        self.original
            .commit_dispatch_reservation(subject, request, intent, owner)
    }
    fn rollback_dispatch_reservation(
        &self,
        subject: &str,
        request: &str,
        intent: &str,
        owner: &str,
    ) -> Result<bool, KernelError> {
        self.original
            .rollback_dispatch_reservation(subject, request, intent, owner)
    }
}

#[test]
fn pre_dispatch_cleanup_runs_when_its_deny_timestamp_clock_sample_fails() -> TestResult {
    for nested in [false, true] {
        let mut grant = make_grant("durable-server", "mutate");
        grant.max_invocations = Some(1);
        grant.max_cost_per_invocation = Some(MonetaryAmount {
            units: 10,
            currency: "USD".into(),
        });
        grant.max_total_cost = Some(MonetaryAmount {
            units: 100,
            currency: "USD".into(),
        });
        let (mut kernel, mut request, store, invocations) =
            durable_admission_fixture_with_grants("review-clock-cleanup", vec![grant]);
        let clock = Arc::new(FailOnceClock {
            unavailable: std::sync::atomic::AtomicBool::new(false),
        });
        kernel.clock = clock.clone();
        kernel.set_governed_approval_replay_store(Box::new(FailApprovalCommitAndClock {
            original: InMemoryGovernedApprovalReplayStore::new(8)?,
            clock,
            commits: AtomicU64::new(0),
        }));
        let settlements = Arc::new(std::sync::Mutex::new(Vec::new()));
        kernel.set_payment_adapter(Box::new(QualifiedDurablePaymentAdapter {
            authorization_references: Arc::new(std::sync::Mutex::new(Vec::new())),
            settlement_actions: settlements.clone(),
            settlement_references: Arc::new(std::sync::Mutex::new(Vec::new())),
        }));
        let mut intent = make_governed_intent(
            "review-clock-intent",
            "durable-server",
            "mutate",
            "review cleanup",
            10,
            "USD",
        );
        bind_test_tool_approval(
            &mut kernel,
            &request.capability,
            &request.arguments,
            &request.request_id,
            &mut intent,
        );
        request.approval_token = Some(make_governed_approval_token(
            &kernel.config.keypair,
            &request.capability.subject,
            &intent,
            &request.request_id,
        ));
        request.governed_intent = Some(intent);
        let result = if nested {
            let session = kernel.open_session("review-clock-parent".into(), Vec::new())?;
            kernel.activate_session(&session)?;
            let parent = make_operation_context(
                &session,
                "review-clock-parent-request",
                "review-clock-parent",
            );
            kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
            kernel.evaluate_tool_call_with_nested_flow_client(
                &parent,
                &request,
                &mut NoopNestedFlowClient,
                None,
            )
        } else {
            kernel.evaluate_tool_call_blocking(&request)
        };
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert_eq!(
            settlements
                .lock()
                .map_err(|_| "settlement lock")?
                .as_slice(),
            ["release"],
            "{result:?}"
        );
        let denied = result?;
        assert_eq!(denied.verdict, Verdict::Deny);
        assert!(denied.output.is_none());
        assert!(denied.receipt.verify_signature()?);
        assert!(store
            .payment_journal()
            .is_some_and(|journal| journal.state == PaymentJournalState::Closed));
        assert_eq!(
            store.operation().state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
    }
    Ok(())
}

fn prepared_active_response(
    kernel: &ChioKernel,
    authority: &str,
    request_id: &str,
    approval_set_hash: Option<String>,
) -> TestResult<crate::security_admission_operation::AdmissionOperation> {
    Ok(crate::security_admission_operation::AdmissionOperation::prepared(
        crate::security_admission_operation::PreparedAdmissionOperation {
            kind: crate::security_admission_operation::AdmissionOperationKind::GovernedActiveResponse,
            coordinator_authority_id: authority.into(), request_id: request_id.into(),
            capability_id: "original-operator".into(),
            authorization_capability_hash: sha256_hex(b"original-operator"),
            request_binding_hash: sha256_hex(request_id.as_bytes()),
            policy_hash: kernel.config.policy_hash.clone(), broker_attempt_id: None,
            budget_hold_id: None, approval_set_hash, execution_nonce_id: None,
            coordinator_lease_epoch: 1,
        },
    )?)
}

fn active_response_kernel() -> ChioKernel {
    let mut config = make_config();
    config.policy_hash = sha256_hex(b"review-active-response-recovery");
    make_kernel(config)
}

#[test]
fn active_response_recovery_processes_more_than_one_bounded_page() -> TestResult {
    use crate::security_admission_operation::{AdmissionOperationState, AdmissionOperationStore};
    let kernel = active_response_kernel();
    let store = crate::security_admission_operation::InMemoryAdmissionOperationStore::new();
    let authority = sha256_hex(b"active-response-recovery-authority");
    let mut originals = Vec::new();
    for index in 0..4_097 {
        let operation =
            prepared_active_response(&kernel, &authority, &format!("pending-{index}"), None)?;
        store.create_prepared(operation.clone())?;
        originals.push(operation);
    }
    assert_eq!(
        kernel.recover_nonterminal_active_response_operations_with_authorities(
            &store, None, &authority,
        )?,
        originals.len()
    );
    for original in originals {
        assert_eq!(
            store
                .load(original.operation_id())?
                .ok_or("original operation")?
                .state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
    }
    Ok(())
}

#[test]
fn active_response_recovery_defers_wrong_authority_after_processing_other_operations() -> TestResult
{
    use crate::security_admission_operation::{AdmissionOperationState, AdmissionOperationStore};
    let kernel = active_response_kernel();
    let store = crate::security_admission_operation::InMemoryAdmissionOperationStore::new();
    let authority = sha256_hex(b"active-response-recovery-authority");
    let poison = prepared_active_response(&kernel, &sha256_hex(b"wrong-executor"), "poison", None)?;
    let original = (0..10_000)
        .find_map(|index| {
            let operation =
                prepared_active_response(&kernel, &authority, &format!("later-{index}"), None)
                    .ok()?;
            (operation.operation_id() > poison.operation_id()).then_some(operation)
        })
        .ok_or("later recovery candidate")?;
    store.create_prepared(poison.clone())?;
    store.create_prepared(original.clone())?;
    assert!(
        kernel
            .recover_nonterminal_active_response_operations_with_authorities(
                &store, None, &authority,
            )
            .is_err(),
        "a refused row still fails publication closed"
    );
    assert_eq!(
        store
            .load(poison.operation_id())?
            .ok_or("refused original")?,
        poison
    );
    assert_eq!(
        store
            .load(original.operation_id())?
            .ok_or("processed original")?
            .state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    Ok(())
}

#[test]
fn active_response_recovery_reconciles_committed_approval_before_compensation() -> TestResult {
    use crate::approval::{ApprovalReservationMember, ApprovalSetReservationInput, ApprovalStore};
    use crate::security_admission_operation::{
        AdmissionDispatchState, AdmissionOperationCompareAndSwap, AdmissionOperationState,
        AdmissionOperationStore, ReplayReservationState,
    };
    let mut kernel = active_response_kernel();
    let store =
        Arc::new(crate::security_admission_operation::InMemoryAdmissionOperationStore::new());
    kernel.admission_operation_store = Some(store.clone());
    let authority = sha256_hex(b"active-response-recovery-authority");
    let approval_set = ApprovalSetReservationInput::new(
        sha256_hex(b"original-approval-set"),
        vec![ApprovalReservationMember::new(
            "original-token".into(),
            sha256_hex(b"original-token"),
        )?],
        current_unix_timestamp() + 300,
    )?;
    let prepared = prepared_active_response(
        &kernel,
        &authority,
        "approval-committed-crash-window",
        Some(approval_set.approval_set_hash().into()),
    )?;
    store.create_prepared(prepared.clone())?;
    let anchor = crate::kernel::active_response_operation_binding::ActiveResponseOperationAnchor {
        plan_hash: sha256_hex(b"original-plan"),
        executor_authority_id: authority.clone(),
        executor_authority_generation: 1,
        authorized_at_unix_ms: current_unix_timestamp_ms(),
        authorization_capability_hash: prepared.authorization_capability_hash().into(),
        governed_intent_hash: sha256_hex(b"original-governed-intent"),
        policy_decision_hash: sha256_hex(b"original-policy-decision"),
        approval_set_hash: approval_set.approval_set_hash().into(),
    };
    kernel
        .journal_active_response_operation_anchor(&prepared, anchor, &approval_set)
        .map_err(|_| "original anchor journal")?;
    store.compare_and_swap(AdmissionOperationCompareAndSwap {
        operation_id: prepared.operation_id(),
        expected_version: prepared.version(),
        coordinator_lease_epoch: 1,
        next_state: AdmissionOperationState::ApprovalReserved,
        next_dispatch_state: AdmissionDispatchState::NotStarted,
        next_coordinator_lease_epoch: 1,
        last_error: None,
    })?;
    let approvals = CommittedApproval::new(prepared.operation_id(), approval_set)?;
    kernel.recover_nonterminal_active_response_operations_with_authorities(
        store.as_ref(),
        Some(&approvals),
        &authority,
    )?;
    let recovered = store
        .load(prepared.operation_id())?
        .ok_or("reconciled original")?;
    assert_eq!(
        recovered.state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(
        recovered.dispatch_state(),
        AdmissionDispatchState::Committed
    );
    assert_eq!(
        approvals
            .get_approval_reservation(prepared.operation_id())?
            .ok_or("original approval reservation")?
            .state(),
        ReplayReservationState::Committed
    );
    assert!(!store.load_cleanup_actions(prepared.operation_id())?.iter().any(|action| {
        action.kind() == crate::security_admission_operation::AdmissionCleanupActionKind::TerminalReceipt
    }), "committed approvals cannot yield a compensated receipt");
    Ok(())
}
