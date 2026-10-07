//! A recovery sweep observes authority time for each page and each item.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionIdentifier, AdmissionOperationBindingInputV1,
    AdmissionOperationBindingV1, AdmissionOperationKind, AdmissionOperationV1,
    AdmissionParticipantRequirements, AdmissionRecoveryDeferralV1, AdmissionRecoveryDeferralWrite,
    AdmissionRecoveryFailureKind, AdmissionRecoveryPageQuery, AdmissionRecoveryPhase,
    AdmissionRequestBindingV1, AuthenticatedRequestNamespace, QualifiedAdmissionOperationStoreExt,
    SideEffectClass,
};

const PAGE: usize = 256;
/// Longer than the SQLite authority's permitted trusted-time skew.
const PAGE_DURATION_MS: u64 = 6 * 60 * 1_000;
/// Outlives setup writes and lapses well before a first deferral is due.
const SETUP_CLAIM_MS: u64 = 30_000;

struct Sweep {
    _directory: tempfile::TempDir,
    database: std::path::PathBuf,
    clock: Arc<SweepClock>,
    serving: Serving,
    kernel: ChioKernel,
    deferred: Vec<AdmissionOperationV1>,
    pending: Vec<AdmissionOperationV1>,
}

fn prepared(fence: &StoreMutationFence, index: usize) -> TestResult<AdmissionOperationV1> {
    let digest = |field: &'static str, byte: &str| AdmissionDigest::try_new(field, byte.repeat(64));
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace: AuthenticatedRequestNamespace::for_local_system(AdmissionIdentifier::try_new(
            "coordinator_authority_id",
            fence.store_uuid.clone(),
        )?)?,
        request_id: AdmissionIdentifier::try_new("request_id", format!("sweep-time-{index:03}"))?,
        capability_id: AdmissionIdentifier::try_new(
            "capability_id",
            format!("sweep-time-capability-{index:03}"),
        )?,
        authorization_capability_hash: digest("authorization_capability_hash", "a")?,
        request_binding: AdmissionRequestBindingV1::new(
            digest("immutable_request_hash", "b")?,
            AdmissionParticipantRequirements {
                broker_attempt: true,
                budget_capture: true,
                ..AdmissionParticipantRequirements::NONE
            },
        )?,
        policy_hash: digest("policy_hash", "c")?,
        effect_class: SideEffectClass::SideEffecting,
    })?;
    Ok(AdmissionOperationV1::prepare(binding, fence.owner_epoch)?)
}

impl Sweep {
    /// `deferred` retained operations hold not-yet-due deferrals. `pending`
    /// retained operations without a deferral sort after all of them.
    fn new(deferred: usize, pending: usize) -> TestResult<Self> {
        let (directory, database, locks) = provision()?;
        let clock = SweepClock::new()?;
        let serving = Serving::open(&database, &locks, &clock)?;
        let kernel = serving.kernel(Keypair::generate(), &clock)?;
        let at = clock.now_ms()?;
        let count = deferred.checked_add(pending).ok_or("operation count")?;
        let mut operations = (0..count)
            .map(|index| prepared(&serving.fence, index))
            .collect::<TestResult<Vec<_>>>()?;
        operations.sort_by(|left, right| {
            left.binding()
                .operation_id()
                .cmp(right.binding().operation_id())
        });
        for operation in &operations {
            serving.operations.begin(operation, &serving.fence, at)?;
        }
        let pending = operations.split_off(deferred);
        let claimant = AdmissionIdentifier::try_new("claimant_id", "sweep-time-setup")?;
        for operation in &operations {
            let lease = serving.operations.claim_recovery(
                operation.binding().operation_id(),
                operation.version(),
                &claimant,
                at,
                at.checked_add(SETUP_CLAIM_MS)
                    .ok_or("setup claim deadline")?,
                &serving.fence,
            )?;
            let deferral = AdmissionRecoveryDeferralV1::after_failure(
                operation,
                None,
                AdmissionRecoveryPhase::Inspection,
                AdmissionRecoveryFailureKind::ParticipantUnavailable,
                AdmissionDigest::try_new("recovery_diagnostic_digest", "d".repeat(64))?,
                at,
            )?;
            serving
                .operations
                .defer_recovery(AdmissionRecoveryDeferralWrite {
                    operation,
                    lease: &lease,
                    expected: None,
                    deferral: &deferral,
                    fence: &serving.fence,
                    trusted_now_unix_ms: at,
                })?;
        }
        // Setup claims lapse while every deferral stays not yet due.
        clock.advance_ms(SETUP_CLAIM_MS + 1_000)?;
        Ok(Self {
            _directory: directory,
            database,
            clock,
            serving,
            kernel,
            deferred: operations,
            pending,
        })
    }

    fn page(
        &self,
        after: Option<&chio_kernel::admission_operation::AdmissionOperationId>,
    ) -> TestResult<chio_kernel::admission_operation::AdmissionRecoveryPageV1> {
        Ok(self
            .serving
            .operations
            .recovery_page(AdmissionRecoveryPageQuery {
                not_after_unix_ms: self.clock.now_ms()?,
                candidate_limit: PAGE,
                after_operation_id: after,
                fence: &self.serving.fence,
            })?)
    }

    /// Store-level proof that the sweep must visit a skipped full page and
    /// then a second page holding only the tail.
    fn assert_two_pages(&self) -> TestResult<AdmissionOperationV1> {
        let [tail] = self.pending.as_slice() else {
            return Err("one tail operation".into());
        };
        let tail = tail.clone();
        assert_eq!(self.deferred.len(), PAGE);
        let first = self.page(None)?;
        assert!(first.operations.is_empty());
        assert_eq!(first.scanned_candidates, PAGE);
        let cursor = first.next_cursor.ok_or("full first page cursor")?;
        assert_eq!(
            Some(&cursor),
            self.deferred
                .last()
                .map(|operation| operation.binding().operation_id())
        );
        let second = self.page(Some(&cursor))?;
        assert_eq!(second.scanned_candidates, 1);
        assert_eq!(second.operations, vec![tail.clone()]);
        assert_eq!(second.next_cursor, None);
        Ok(tail)
    }

    fn state(&self, operation: &AdmissionOperationV1) -> TestResult<AdmissionOperationState> {
        Ok(self
            .serving
            .operations
            .load_by_operation_id(operation.binding().operation_id())?
            .ok_or("retained operation")?
            .state())
    }

    /// Read-only trusted time of the operation's latest durable mutation.
    fn updated_at(&self, operation: &AdmissionOperationV1) -> TestResult<u64> {
        let connection = rusqlite::Connection::open_with_flags(
            &self.database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let updated: i64 = connection.query_row(
            "SELECT updated_at_unix_ms FROM admission_operations WHERE operation_id=?1",
            [operation.binding().operation_id().as_str()],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(updated)?)
    }

    fn assert_deferred_untouched(&self) -> TestResult {
        for operation in &self.deferred {
            let current = self
                .serving
                .operations
                .load_by_operation_id(operation.binding().operation_id())?
                .ok_or("deferred operation")?;
            assert_eq!(&current, operation);
        }
        Ok(())
    }
}

fn causes(error: &KernelError) -> String {
    std::iter::once(format!("{error:?}"))
        .chain(
            std::iter::successors(error.source(), |&cause| cause.source()).map(ToString::to_string),
        )
        .collect::<Vec<_>>()
        .join(" <- ")
}

#[test]
fn sqlite_two_page_sweep_samples_fresh_authority_time_for_the_second_page() -> TestResult {
    let sweep = Sweep::new(PAGE, 1)?;
    let tail = sweep.assert_two_pages()?;
    sweep.clock.arm(Some((1, PAGE_DURATION_MS)))?;
    let result = sweep.kernel.reconcile_recoverable_admissions();
    let reads = sweep.clock.disarm()?;
    let tail_after = sweep.state(&tail)?;
    let [(Role::Kernel, Some(sweep_start)), (Role::Store, Some(first_page)), ..] = reads.as_slice()
    else {
        return Err(format!("sweep did not start with its own first-page read: {reads:?}").into());
    };
    assert!(first_page > sweep_start);
    assert_eq!(
        sweep.clock.advanced_after_read()?,
        Some(2),
        "the authority clock advanced only after the first page was read"
    );
    let changed = result.map_err(|error| {
        format!(
            "two-page sweep aborted with {}; second-page operation left {tail_after:?}",
            causes(&error)
        )
    })?;
    assert_eq!(changed, 1);
    let Some((Role::Kernel, Some(second_page))) = reads.get(2) else {
        return Err(format!("second page did not observe authority time: {reads:?}").into());
    };
    assert!(*second_page > first_page + PAGE_DURATION_MS);
    assert_eq!(
        tail_after,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    sweep.assert_deferred_untouched()
}

#[test]
fn sqlite_two_page_sweep_without_a_clock_advance_recovers_the_second_page() -> TestResult {
    let sweep = Sweep::new(PAGE, 1)?;
    let tail = sweep.assert_two_pages()?;
    sweep.clock.arm(None)?;
    let result = sweep.kernel.reconcile_recoverable_admissions();
    let reads = sweep.clock.disarm()?;
    assert!(matches!(
        reads.as_slice(),
        [(Role::Kernel, Some(_)), (Role::Store, Some(_)), ..]
    ));
    assert_eq!(result?, 1);
    assert_eq!(
        sweep.state(&tail)?,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    sweep.assert_deferred_untouched()
}

#[test]
fn sqlite_single_page_sweep_samples_authority_time_once() -> TestResult {
    let sweep = Sweep::new(3, 0)?;
    let page = sweep.page(None)?;
    assert!(page.operations.is_empty());
    assert_eq!(page.scanned_candidates, 3);
    assert_eq!(page.next_cursor, None);
    sweep.clock.arm(None)?;
    let result = sweep.kernel.reconcile_recoverable_admissions();
    let reads = sweep.clock.disarm()?;
    assert_eq!(result?, 0);
    let [(Role::Kernel, Some(start)), (Role::Store, Some(page))] = reads.as_slice() else {
        return Err(format!("single page read more than its one sample: {reads:?}").into());
    };
    assert!(page > start);
    sweep.assert_deferred_untouched()
}

#[test]
fn sqlite_slow_first_item_does_not_age_the_next_item_in_one_page() -> TestResult {
    let sweep = Sweep::new(0, 2)?;
    let [first, later] = sweep.pending.as_slice() else {
        return Err("two pending operations".into());
    };
    let page = sweep.page(None)?;
    assert_eq!(page.scanned_candidates, 2);
    assert_eq!(page.operations, vec![first.clone(), later.clone()]);
    assert_eq!(page.next_cursor, None);
    // The authority clock advances while the first item is being recovered,
    // right after that item's own status read.
    sweep.clock.arm(Some((2, PAGE_DURATION_MS)))?;
    let result = sweep.kernel.reconcile_recoverable_admissions();
    let reads = sweep.clock.disarm()?;
    let later_after = sweep.state(later)?;
    let [(Role::Kernel, Some(_)), (Role::Store, Some(page_read)), ..] = reads.as_slice() else {
        return Err(format!("sweep did not start with its one page read: {reads:?}").into());
    };
    assert!(sweep.clock.advanced_after_read()?.is_some());
    assert_eq!(
        sweep.state(first)?,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(
        sweep.updated_at(first)? > *page_read + PAGE_DURATION_MS,
        "the first item finished after the authority clock advanced"
    );
    let changed = result.map_err(|error| {
        format!(
            "one-page sweep aborted with {}; later operation left {later_after:?}",
            causes(&error)
        )
    })?;
    assert_eq!(changed, 2);
    assert_eq!(
        later_after,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(sweep.updated_at(later)? > *page_read + PAGE_DURATION_MS);
    assert!(
        matches!(
            reads.as_slice(),
            [
                (Role::Kernel, Some(_)),
                (Role::Store, Some(_)),
                (Role::Kernel, Some(_)),
                (Role::Store, Some(_)),
                ..
            ]
        ),
        "each item samples authority time before its own status read: {reads:?}"
    );
    Ok(())
}

fn second_page_clock_failure(fault: Fault, expected: ClockError) -> TestResult {
    let sweep = Sweep::new(PAGE, 1)?;
    let tail = sweep.assert_two_pages()?;
    sweep.clock.arm(None)?;
    sweep.clock.fail_kernel_read(2, fault)?;
    let result = sweep.kernel.reconcile_recoverable_admissions();
    let reads = sweep.clock.disarm()?;
    assert!(
        matches!(&result, Err(KernelError::Clock(error)) if *error == expected),
        "second-page clock failure must abort the sweep: {result:?}"
    );
    let [(Role::Kernel, Some(_)), (Role::Store, Some(first_page)), (Role::Kernel, second_page)] =
        reads.as_slice()
    else {
        return Err(
            format!("the failed sample must precede any second-page read: {reads:?}").into(),
        );
    };
    match fault {
        Fault::Unavailable => assert_eq!(*second_page, None),
        Fault::Regress => assert!(second_page.is_some_and(|second| second < *first_page)),
    }
    assert_eq!(sweep.state(&tail)?, AdmissionOperationState::Prepared);
    assert_eq!(
        sweep.serving.operations.load_recovery_status(
            tail.binding().operation_id(),
            &sweep.serving.fence,
            sweep.clock.now_ms()?,
        )?,
        None
    );
    sweep.assert_deferred_untouched()
}

#[test]
fn sqlite_second_page_clock_unavailable_aborts_before_the_page_is_read() -> TestResult {
    second_page_clock_failure(Fault::Unavailable, ClockError::Unavailable)
}

#[test]
fn sqlite_second_page_clock_regression_aborts_before_the_page_is_read() -> TestResult {
    second_page_clock_failure(Fault::Regress, ClockError::WallClockRegression)
}
