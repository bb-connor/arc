//! The pre-dispatch custody owns an evaluation's admitted resources: a drop
//! unwinds them, a denial releases each exactly once, and a handoff to
//! dispatch disarms it.
use super::*;
use crate::kernel::evaluation::pre_dispatch_custody::{
    AdmissionDenial, OperationSettlement, PreparedAdmission, SelectedGrant,
    PANIC_DURING_COMPENSATION,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ADMITTED_AT: u64 = 1_000;

struct CountingRelease {
    releases: Arc<AtomicU64>,
}

impl RuntimeAdmissionHook for CountingRelease {
    fn name(&self) -> &str {
        "custody-counting-release"
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        Ok(RuntimeAdmissionDecision::allow(None))
    }

    fn release_reserved(&self, _metadata: &serde_json::Value) -> Result<(), KernelError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct FailNextRead {
    inner: Arc<dyn chio_security_types::clock::Clock>,
    fail: AtomicBool,
}

impl chio_security_types::clock::Clock for FailNextRead {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err(chio_security_types::clock::ClockError::Unavailable);
        }
        self.inner.read()
    }
}

fn ephemeral_fixture(request_id: &str) -> (ChioKernel, ToolCallRequest, Arc<AtomicU64>) {
    let mut kernel = make_kernel(make_config());
    let releases = Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(Arc::new(CountingRelease {
        releases: releases.clone(),
    }));
    let agent = make_keypair();
    let mut grant = make_grant("custody-srv", "mutate");
    grant.max_invocations = Some(1);
    let capability = make_capability(&kernel, &agent, make_scope(vec![grant]), 300);
    let request = make_request(request_id, &capability, "mutate", "custody-srv");
    (kernel, request, releases)
}

/// Admit the grant the way evaluation does before custody takes it: consume
/// its single invocation slot and hold one runtime reservation.
fn admit(kernel: &ChioKernel, request: &ToolCallRequest) -> TestResult<SelectedGrant> {
    let admitted = kernel.with_budget_store(|store| {
        Ok(store.try_increment(&request.capability.id, 0, Some(1))?)
    })?;
    if !admitted {
        return Err("the fixture's invocation slot was already consumed".into());
    }
    let metadata = Some(serde_json::json!({
        "chio_runtime": {"reserved_destructive_lease_id": "lease-custody"}
    }));
    Ok(SelectedGrant {
        grant_index: 0,
        budget: PreExecutionBudgetMutation::Invocation { grant_index: 0 },
        runtime: RuntimeReservation::from_decision(&RuntimeAdmissionDecision::allow(
            metadata.clone(),
        )),
        metadata,
        evidence: Some(Vec::new()),
        payee: None,
    })
}

fn invocations_used(kernel: &ChioKernel, request: &ToolCallRequest) -> TestResult<u32> {
    Ok(kernel
        .with_budget_store(|store| Ok(store.get_usage(&request.capability.id, 0)?))?
        .map_or(0, |usage| usage.invocation_count))
}

#[test]
fn an_unconsumed_custody_unwinds_its_admission_on_drop() -> TestResult {
    let (kernel, request, releases) = ephemeral_fixture("custody-drop");
    let custody = PreparedAdmission::open(&kernel, &request, ADMITTED_AT, None, None)
        .select(admit(&kernel, &request)?);
    assert_eq!(invocations_used(&kernel, &request)?, 1);

    drop(custody);

    assert_eq!(invocations_used(&kernel, &request)?, 0);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    assert_eq!(
        kernel.receipt_log().len(),
        0,
        "a clean unwind is receipt-free"
    );
    Ok(())
}

#[test]
fn a_denial_consumes_the_custody_and_releases_each_resource_once() -> TestResult {
    let (kernel, request, releases) = ephemeral_fixture("custody-deny");
    let custody = PreparedAdmission::open(&kernel, &request, ADMITTED_AT, None, None)
        .select(admit(&kernel, &request)?);

    let denied = custody.deny(AdmissionDenial::new("custody denial"))?;

    assert_eq!(denied.verdict, Verdict::Deny);
    assert_eq!(denied.reason.as_deref(), Some("custody denial"));
    assert_eq!(denied.receipt.timestamp, ADMITTED_AT);
    assert!(denied.receipt.verify_signature()?);
    assert_eq!(invocations_used(&kernel, &request)?, 0);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    assert_eq!(kernel.receipt_log().len(), 1, "only the denial is recorded");
    Ok(())
}

#[test]
fn a_sampled_denial_falls_back_to_the_admission_sample_and_still_cleans_up() -> TestResult {
    let (mut kernel, request, releases) = ephemeral_fixture("custody-sampled");
    let clock = Arc::new(FailNextRead {
        inner: chio_test_support::clock::clock(),
        fail: AtomicBool::new(false),
    });
    kernel.clock = clock.clone();
    let custody = PreparedAdmission::open(&kernel, &request, ADMITTED_AT, None, None)
        .select(admit(&kernel, &request)?);

    clock.fail.store(true, Ordering::SeqCst);
    let denied = custody.deny(AdmissionDenial::new("sampled denial").sampled())?;

    assert!(
        !clock.fail.load(Ordering::SeqCst),
        "the denial sampled the clock"
    );
    assert_eq!(denied.verdict, Verdict::Deny);
    assert_eq!(denied.receipt.timestamp, ADMITTED_AT);
    assert_eq!(invocations_used(&kernel, &request)?, 0);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn handing_off_to_dispatch_disarms_the_custody() -> TestResult {
    let (kernel, request, releases) = ephemeral_fixture("custody-handoff");
    let mut custody = PreparedAdmission::open(&kernel, &request, ADMITTED_AT, None, None)
        .select(admit(&kernel, &request)?);
    custody.hold_credentials(kernel.reserve_admitted_dispatch_credentials(
        &request,
        false,
        ADMITTED_AT,
        None,
        0,
    )?);

    let dispatch = custody.into_dispatch()?;
    drop(dispatch);

    assert_eq!(
        invocations_used(&kernel, &request)?,
        1,
        "dispatch owns the slot"
    );
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn a_handoff_without_credentials_fails_closed_and_unwinds() -> TestResult {
    let (kernel, request, releases) = ephemeral_fixture("custody-handoff-uncredentialed");
    let custody = PreparedAdmission::open(&kernel, &request, ADMITTED_AT, None, None)
        .select(admit(&kernel, &request)?);

    let refused = custody.into_dispatch();

    assert!(
        matches!(
            refused.as_ref().map_err(KernelError::durable_admission),
            Err(Some(crate::DurableAdmissionError::Invariant(reason)))
                if reason == "pre-dispatch custody lost its dispatch credentials"
        ),
        "{:?}",
        refused.as_ref().err()
    );
    assert_eq!(invocations_used(&kernel, &request)?, 0);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn settling_before_selection_compensates_only_when_asked() -> TestResult {
    let now_unix_ms = current_unix_timestamp_ms();
    for (settlement, expected) in [
        (
            Some(OperationSettlement::Retain),
            AdmissionOperationState::BrokerAttemptRegistered,
        ),
        (
            Some(OperationSettlement::Compensate),
            AdmissionOperationState::CompensatedBeforeDispatch,
        ),
        (None, AdmissionOperationState::CompensatedBeforeDispatch),
    ] {
        let (kernel, request, store, _invocations) =
            durable_admission_fixture(&format!("custody-settlement-{expected:?}"));
        let matching = resolve_required_matching_grants(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )?;
        let admission = kernel
            .begin_durable_tool_admission(&request, &matching, now_unix_ms)?
            .ok_or("covered durable admission")?;
        let custody = PreparedAdmission::open(
            &kernel,
            &request,
            now_unix_ms / 1_000,
            None,
            Some(admission),
        );
        match settlement {
            Some(settlement) => custody.settle_then(settlement, || Ok(()))?,
            None => drop(custody),
        }
        assert_eq!(store.operation().state(), expected, "{settlement:?}");
    }
    Ok(())
}

#[test]
fn a_panicking_compensation_stays_inside_drop_even_while_unwinding() -> TestResult {
    let (kernel, request, releases) = ephemeral_fixture("custody-panic");
    let dropped = PreparedAdmission::open(&kernel, &request, ADMITTED_AT, None, None)
        .select(admit(&kernel, &request)?);

    PANIC_DURING_COMPENSATION.with(|inject| inject.set(true));
    drop(dropped);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = PreparedAdmission::open(&kernel, &request, ADMITTED_AT, None, None);
        std::panic::panic_any("evaluation panicked while holding its custody");
    }));
    PANIC_DURING_COMPENSATION.with(|inject| inject.set(false));

    let payload = unwound.err().ok_or("the evaluation panic was swallowed")?;
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"evaluation panicked while holding its custody")
    );
    // The injected panic replaced the compensation; recovery owns the slot.
    assert_eq!(invocations_used(&kernel, &request)?, 1);
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    Ok(())
}
