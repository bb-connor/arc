//! Native claim time must advance independently of a page eligibility snapshot.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionOperationId, AdmissionOperationStoreError, AdmissionOperationV1,
    AdmissionRecoveryError, AdmissionRecoveryFailureKind, AdmissionRecoveryStatusV1,
};
use chio_kernel::budget_store::BudgetUsageRecord;
use chio_kernel::payment::PaymentJournalRecord;
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use std::sync::Mutex;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Clone, Copy)]
enum Fault {
    Unavailable,
    Regress,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PortRole {
    Kernel,
    Native,
    Observation,
}

struct ClockPort {
    source: Arc<AdvancingClock>,
    role: PortRole,
}

impl Clock for ClockPort {
    fn read(&self) -> Result<ClockReading, ClockError> {
        self.source.read_from(self.role)
    }
}

#[derive(Default)]
struct ClockState {
    elapsed_ms: u64,
    mark_next: bool,
    page_cutoff: Option<u64>,
    fault: Option<Fault>,
    kernel_reads: u32,
    kernel_fault: Option<(u32, Fault)>,
    triggered_kernel_fault: Option<u32>,
}

struct AdvancingClock {
    epoch_ms: u64,
    state: Mutex<ClockState>,
}

impl AdvancingClock {
    fn mark_page_read(&self) -> TestResult {
        let mut state = self.state.lock().map_err(|_| "clock marker lock")?;
        state.mark_next = true;
        state.page_cutoff = None;
        state.kernel_reads = 0;
        state.triggered_kernel_fault = None;
        Ok(())
    }

    fn page_cutoff(&self) -> TestResult<u64> {
        self.state
            .lock()
            .map_err(|_| "clock marker lock")?
            .page_cutoff
            .ok_or_else(|| "actual page clock read is absent".into())
    }

    fn advance_ms(&self, amount: u64) -> TestResult {
        let mut state = self.state.lock().map_err(|_| "clock state lock")?;
        state.elapsed_ms = state
            .elapsed_ms
            .checked_add(amount)
            .ok_or("clock advance overflow")?;
        Ok(())
    }

    fn fault_next_read(&self, fault: Fault) -> TestResult {
        self.state.lock().map_err(|_| "clock state lock")?.fault = Some(fault);
        Ok(())
    }

    fn port(self: &Arc<Self>, role: PortRole) -> Arc<dyn Clock> {
        Arc::new(ClockPort {
            source: self.clone(),
            role,
        })
    }

    fn fault_kernel_read(&self, ordinal: u32, fault: Fault) -> TestResult {
        self.state
            .lock()
            .map_err(|_| "clock state lock")?
            .kernel_fault = Some((ordinal, fault));
        Ok(())
    }

    fn triggered_kernel_fault(&self) -> TestResult<Option<u32>> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "clock state lock")?
            .triggered_kernel_fault)
    }

    fn read_from(&self, role: PortRole) -> Result<ClockReading, ClockError> {
        let mut state = self.state.lock().map_err(|_| ClockError::Unavailable)?;
        let scheduled = if role == PortRole::Kernel {
            state.kernel_reads = state
                .kernel_reads
                .checked_add(1)
                .ok_or(ClockError::Overflow)?;
            if state
                .kernel_fault
                .is_some_and(|(ordinal, _)| ordinal == state.kernel_reads)
            {
                state.triggered_kernel_fault = Some(state.kernel_reads);
                state.kernel_fault.take().map(|(_, fault)| fault)
            } else {
                None
            }
        } else {
            None
        };
        let fault = state.fault.take().or(scheduled);
        if matches!(fault, Some(Fault::Unavailable)) {
            return Err(ClockError::Unavailable);
        }
        state.elapsed_ms = state
            .elapsed_ms
            .checked_add(1)
            .ok_or(ClockError::Overflow)?;
        let now = self
            .epoch_ms
            .checked_add(state.elapsed_ms)
            .ok_or(ClockError::Overflow)?;
        let monotonic = MonotonicInstant::from_nanos(
            state
                .elapsed_ms
                .checked_mul(1_000_000)
                .ok_or(ClockError::Overflow)?,
        );
        if state.mark_next {
            state.mark_next = false;
            state.page_cutoff = Some(now);
        }
        let emitted = if matches!(fault, Some(Fault::Regress)) {
            self.epoch_ms
                .checked_sub(1)
                .ok_or(ClockError::BeforeEpoch)?
        } else {
            now
        };
        Ok(ClockReading::new(UnixMillis::new(emitted), monotonic))
    }
}

impl Clock for AdvancingClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        self.read_from(PortRole::Observation)
    }
}

struct Pending {
    _directory: tempfile::TempDir,
    database: std::path::PathBuf,
    authority: SqliteAuthorityStore,
    operations: Arc<chio_store_sqlite::SqliteAdmissionOperationStore>,
    fence: StoreMutationFence,
    clock: Arc<AdvancingClock>,
    kernel: ChioKernel,
    original_request: ToolCallRequest,
    operation_id: AdmissionOperationId,
    calls: Arc<PaymentCalls>,
    paid_invocations: Arc<AtomicU64>,
    healthy_invocations: Arc<AtomicU64>,
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    operation: AdmissionOperationV1,
    journal: PaymentJournalRecord,
    status: Option<AdmissionRecoveryStatusV1>,
    usage: Option<BudgetUsageRecord>,
    effects: (u64, u64, u64, u64, u64),
}

impl Pending {
    fn new() -> TestResult<Self> {
        let (directory, database, locks) = provision()?;
        let clock = Arc::new(AdvancingClock {
            epoch_ms: chio_test_support::clock::clock().unix_millis()?.get(),
            state: Mutex::new(ClockState::default()),
        });
        let keypair = Keypair::generate();
        let calls = Arc::new(PaymentCalls::default());
        let paid_invocations = Arc::new(AtomicU64::new(0));
        let (original_request, operation_id) = {
            let authority = SqliteAuthorityStore::open_serving_with_clock(
                &database,
                &locks,
                clock.port(PortRole::Native),
            )?;
            let fence = authority.mutation_fence();
            let operations = Arc::new(authority.admission_operation_store());
            let mut kernel = ChioKernel::new_with_clock(
                kernel_config(keypair.clone()),
                clock.port(PortRole::Kernel),
            );
            kernel.set_durable_admission_store(
                operations.clone(),
                Arc::new(authority.tool_outcome_store()),
                fence.clone(),
            )?;
            kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
            kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
                calls: Some(calls.clone()),
            }));
            kernel.register_tool_server(Box::new(PaidMutationServer {
                invocations: paid_invocations.clone(),
            }));
            let capability =
                kernel.issue_capability(&Keypair::generate().public_key(), paid_scope(), 300)?;
            let request = paid_request(&capability);
            calls.fail_next_capture.store(true, Ordering::SeqCst);
            let error = kernel
                .evaluate_tool_call_blocking(&request)
                .err()
                .ok_or("original capture interruption")?;
            ordinary_operation::assert_interrupted_payment(
                &error,
                "injected capture interruption",
            )?;
            let references = calls
                .authorization_references
                .lock()
                .map_err(|_| "authorization trace lock")?;
            let [reference] = references.as_slice() else {
                return Err("one original authorization reference required".into());
            };
            let operation = ordinary_operation::from_rail_reference(
                operations.as_ref(),
                &fence,
                &request,
                reference,
            )?;
            assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
            (request, operation.binding().operation_id().clone())
        };
        let authority = SqliteAuthorityStore::open_serving_with_clock(
            &database,
            &locks,
            clock.port(PortRole::Native),
        )?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        let mut kernel =
            ChioKernel::new_with_clock(kernel_config(keypair), clock.port(PortRole::Kernel));
        kernel.set_durable_admission_store(
            operations.clone(),
            Arc::new(authority.tool_outcome_store()),
            fence.clone(),
        )?;
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        let healthy_invocations = Arc::new(AtomicU64::new(0));
        kernel.register_tool_server(Box::new(MutationServer {
            invocations: healthy_invocations.clone(),
        }));
        // Prime the original shared kernel fence before explicit fault controls.
        kernel.authority_clock_reading()?;
        Ok(Self {
            _directory: directory,
            database,
            authority,
            operations,
            fence,
            clock,
            kernel,
            original_request,
            operation_id,
            calls,
            paid_invocations,
            healthy_invocations,
        })
    }

    fn snapshot(&self) -> TestResult<Snapshot> {
        Ok(Snapshot {
            operation: self
                .operations
                .load_by_operation_id(&self.operation_id)?
                .ok_or("original operation")?,
            journal: self
                .operations
                .load_payment_journal(self.operation_id.as_str(), &self.fence)?
                .ok_or("original journal")?,
            status: self.operations.load_recovery_status(
                &self.operation_id,
                &self.fence,
                self.clock.unix_millis()?.get(),
            )?,
            usage: self
                .authority
                .budget_store()
                .get_usage(&self.original_request.capability.id, 0)?,
            effects: (
                self.calls.authorizations.load(Ordering::SeqCst),
                self.calls.captures.load(Ordering::SeqCst),
                self.calls.releases.load(Ordering::SeqCst),
                self.calls.refunds.load(Ordering::SeqCst),
                self.paid_invocations.load(Ordering::SeqCst),
            ),
        })
    }

    fn observe_native_claim_time(&self, operation: &AdmissionOperationV1) -> TestResult<u64> {
        // Read-only deciding evidence. No row value becomes clock or authority input.
        let connection = rusqlite::Connection::open_with_flags(
            &self.database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let (updated, uuid, lease, epoch, version): (i64, String, String, i64, i64) = connection
            .query_row(
                "SELECT updated_at_unix_ms,recovery_store_uuid,recovery_store_lease_id,
                    recovery_store_owner_epoch,recovery_claimed_version
             FROM admission_operations WHERE operation_id=?1",
                [self.operation_id.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )?;
        assert!(uuid == self.fence.store_uuid && lease == self.fence.lease_id);
        assert_eq!(u64::try_from(epoch)?, self.fence.owner_epoch);
        assert_eq!(u64::try_from(version)?, operation.version());
        Ok(u64::try_from(updated)?)
    }
}

#[test]
fn sqlite_review_advancing_shared_clock_defers_after_newer_native_claim_and_clears() -> TestResult {
    let mut pending = Pending::new()?;
    let before = pending.snapshot()?;
    assert_eq!(before.journal.state, PaymentJournalState::Settling);
    assert_eq!(before.effects, (1, 1, 0, 0, 1));
    assert_eq!(before.status, None);
    pending.clock.mark_page_read()?;
    let result = pending.kernel.reconcile_recoverable_admissions_batch(1);
    let page_cutoff = pending.clock.page_cutoff()?;
    let after = pending.snapshot()?;
    let updated = pending.observe_native_claim_time(&after.operation)?;
    assert!(
        updated > page_cutoff,
        "actual native claim must postdate page eligibility"
    );
    assert_eq!(after.operation, before.operation);
    assert_eq!(after.journal, before.journal);
    assert_eq!(after.usage, before.usage);
    assert_eq!(after.effects, before.effects);
    if let Err(error) = &result {
        assert_eq!(error.report().code, "CHIO-KERNEL-DURABLE-ADMISSION");
        let KernelError::AdmissionRecovery(retained) = error else {
            return Err("typed native clock invariant required".into());
        };
        let cause = error
            .source()
            .ok_or("native invariant source")?
            .downcast_ref::<Box<AdmissionRecoveryError>>()
            .ok_or("native boxed invariant source")?;
        assert!(std::ptr::eq(cause, retained));
        assert!(
            matches!(cause.as_ref(), AdmissionRecoveryError::Store(AdmissionOperationStoreError::Invariant(detail))
            if detail == "trusted operation time regressed")
        );
        assert_eq!(after.status, None);
    }
    assert_eq!(result?, 0);
    let status = after
        .status
        .ok_or("durable unavailable participant deferral")?;
    assert!(status.quarantined);
    assert_eq!(
        status.deferral.failure_kind,
        AdmissionRecoveryFailureKind::ParticipantUnavailable
    );
    assert!(status.deferral.last_failure_unix_ms >= updated);
    // Complete the real bounded cursor cycle while the original retry is not due.
    assert_eq!(pending.kernel.reconcile_recoverable_admissions_batch(1)?, 0);
    assert_eq!(pending.snapshot()?.effects, before.effects);
    let capability =
        pending
            .kernel
            .issue_capability(&Keypair::generate().public_key(), scope(), 300)?;
    let mut healthy = request(&capability);
    healthy.request_id = "healthy-after-advancing-clock-deferral".into();
    assert_eq!(
        pending
            .kernel
            .evaluate_tool_call_blocking(&healthy)?
            .verdict,
        Verdict::Allow
    );
    assert_eq!(pending.healthy_invocations.load(Ordering::SeqCst), 1);
    assert_eq!(pending.snapshot()?.effects, before.effects);
    pending
        .kernel
        .set_payment_adapter(Box::new(ReversiblePaymentAdapter {
            calls: Some(pending.calls.clone()),
        }));
    // Only elapsed trusted time changes; original TTLs and retry deadlines stay fixed.
    pending.clock.advance_ms(60_000)?;
    assert_eq!(pending.kernel.reconcile_recoverable_admissions_batch(1)?, 1);
    let completed = pending.snapshot()?;
    assert_eq!(
        completed.operation.state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(completed.journal.state, PaymentJournalState::Settled);
    assert_eq!(
        completed.journal.authorization_id,
        before.journal.authorization_id
    );
    assert_eq!(
        completed.journal.settle_action,
        before.journal.settle_action
    );
    assert_eq!(
        completed.journal.settle_amount_units,
        before.journal.settle_amount_units
    );
    assert_eq!(completed.effects, (1, 2, 0, 0, 1));
    assert!(
        !completed
            .status
            .ok_or("retained clear tombstone")?
            .quarantined
    );
    assert_eq!(pending.kernel.reconcile_recoverable_admissions_batch(1)?, 0);
    assert_eq!(pending.snapshot()?.effects, completed.effects);
    Ok(())
}

fn clock_refusal(fault: Fault, expected: ClockError) -> TestResult {
    let pending = Pending::new()?;
    let before = pending.snapshot()?;
    pending.clock.fault_next_read(fault)?;
    let error = pending
        .kernel
        .reconcile_recoverable_admissions_batch(1)
        .err()
        .ok_or("clock refusal required")?;
    assert_eq!(error.report().code, expected.code());
    let KernelError::Clock(original) = &error else {
        return Err("original typed clock refusal required".into());
    };
    assert_eq!(*original, expected);
    let source = error
        .source()
        .ok_or("native clock source")?
        .downcast_ref::<ClockError>()
        .ok_or("native clock type")?;
    assert!(std::ptr::eq(source, original));
    assert_eq!(pending.snapshot()?, before);
    Ok(())
}

#[test]
fn sqlite_review_advancing_recovery_clock_unavailable_preserves_original_pending_state(
) -> TestResult {
    clock_refusal(Fault::Unavailable, ClockError::Unavailable)
}

#[test]
fn sqlite_review_advancing_recovery_clock_regression_preserves_original_pending_state() -> TestResult
{
    clock_refusal(Fault::Regress, ClockError::WallClockRegression)
}

// Read1 selects the page; read2 refreshes the original-profile recovery read.
// Terminal replay reads3+4 and persists the native claim. Read5 is the new
// deferral mutation-time sample. Native claim evidence below rejects an earlier
// fault, and the absent marker rejects a fault after deferral.
const DEFERRAL_REFRESH_KERNEL_READ: u32 = 5;

fn clock_refusal_after_claim(fault: Fault, expected: ClockError) -> TestResult {
    let pending = Pending::new()?;
    let before = pending.snapshot()?;
    assert_eq!(
        before.operation.state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(before.journal.state, PaymentJournalState::Settling);
    assert_eq!(before.status, None);
    assert_eq!(before.effects, (1, 1, 0, 0, 1));
    pending.clock.mark_page_read()?;
    pending
        .clock
        .fault_kernel_read(DEFERRAL_REFRESH_KERNEL_READ, fault)?;
    let error = pending
        .kernel
        .reconcile_recoverable_admissions_batch(1)
        .err()
        .ok_or("mutation sampling clock refusal required")?;
    assert_eq!(
        pending.clock.triggered_kernel_fault()?,
        Some(DEFERRAL_REFRESH_KERNEL_READ)
    );
    let after = pending.snapshot()?;
    let native_claim_time = pending.observe_native_claim_time(&after.operation)?;
    assert!(
        native_claim_time > pending.clock.page_cutoff()?,
        "the prior legitimate native claim must have occurred before the clock fault"
    );
    assert_eq!(error.report().code, expected.code());
    let KernelError::Clock(original) = &error else {
        return Err("original mutation-boundary ClockError required".into());
    };
    assert_eq!(*original, expected);
    let source = error
        .source()
        .ok_or("mutation clock source")?
        .downcast_ref::<ClockError>()
        .ok_or("mutation native ClockError type")?;
    assert!(std::ptr::eq(source, original));
    // The claim metadata legitimately advanced. Financial/output/terminal and
    // deferral semantic state must stay closed; this is not whole-DB equality.
    assert_eq!(after.operation, before.operation);
    assert_eq!(after.journal, before.journal);
    assert_eq!(after.usage, before.usage);
    assert_eq!(after.effects, before.effects);
    assert_eq!(after.status, before.status);
    assert_eq!(after.operation.state(), AdmissionOperationState::Finalizing);
    assert_eq!(after.journal.state, PaymentJournalState::Settling);
    Ok(())
}

#[test]
fn sqlite_review_defer_clock_unavailable_after_native_claim_cannot_publish_a_marker_or_effect(
) -> TestResult {
    clock_refusal_after_claim(Fault::Unavailable, ClockError::Unavailable)
}

#[test]
fn sqlite_review_defer_clock_regression_after_native_claim_cannot_publish_a_marker_or_effect(
) -> TestResult {
    clock_refusal_after_claim(Fault::Regress, ClockError::WallClockRegression)
}
