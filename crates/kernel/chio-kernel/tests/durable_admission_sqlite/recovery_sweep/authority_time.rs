//! A sweep that spans pages observes authority time for each page.
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
    clock: Arc<SweepClock>,
    serving: Serving,
    kernel: ChioKernel,
    deferred: Vec<AdmissionOperationV1>,
    tail: Option<AdmissionOperationV1>,
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
    /// `deferred` retained operations hold not-yet-due deferrals. With a tail,
    /// one more retained operation sorts after all of them.
    fn new(deferred: usize, with_tail: bool) -> TestResult<Self> {
        let (directory, database, locks) = provision()?;
        let clock = SweepClock::new()?;
        let serving = Serving::open(&database, &locks, &clock)?;
        let kernel = serving.kernel(Keypair::generate(), &clock)?;
        let at = clock.now_ms()?;
        let count = deferred
            .checked_add(usize::from(with_tail))
            .ok_or("operation count")?;
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
        let tail = if with_tail { operations.pop() } else { None };
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
            clock,
            serving,
            kernel,
            deferred: operations,
            tail,
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
        let tail = self.tail.clone().ok_or("tail operation")?;
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

#[test]
fn sqlite_two_page_sweep_samples_fresh_authority_time_for_the_second_page() -> TestResult {
    let sweep = Sweep::new(PAGE, true)?;
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
        let causes = std::iter::successors(error.source(), |&cause| cause.source())
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" <- ");
        format!(
            "two-page sweep aborted with {error:?} <- {causes}; second-page operation left {tail_after:?}"
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
    let sweep = Sweep::new(PAGE, true)?;
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
    let sweep = Sweep::new(3, false)?;
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
