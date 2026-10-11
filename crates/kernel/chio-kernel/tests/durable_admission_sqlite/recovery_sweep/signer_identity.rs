//! A retained return whose original receipt signer is not the current signer
//! is refused for that operation only. Later operations still recover.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionOperationV1, AdmissionRecoveryFailureKind, AdmissionRecoveryPageQuery,
    AdmissionRecoveryPhase, AdmissionRecoveryStatusV1,
};

struct Retained {
    signer: Keypair,
    request: ToolCallRequest,
    operation: AdmissionOperationV1,
}

fn signing_kernel(
    serving: &Serving,
    clock: &Arc<SweepClock>,
    signer: &Keypair,
    calls: &Arc<PaymentCalls>,
    invocations: &Arc<AtomicU64>,
) -> TestResult<ChioKernel> {
    let mut kernel = serving.kernel(signer.clone(), clock)?;
    assert_eq!(kernel.receipt_signing_public_key(), signer.public_key());
    kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
        calls: Some(calls.clone()),
    }));
    kernel.register_tool_server(Box::new(PaidMutationServer {
        invocations: invocations.clone(),
    }));
    kernel.register_tool_server(Box::new(MutationServer {
        invocations: invocations.clone(),
    }));
    Ok(kernel)
}

/// Leave one paid operation in `Finalizing` under `signer`.
fn retain(
    serving: &Serving,
    kernel: &ChioKernel,
    calls: &PaymentCalls,
    signer: Keypair,
    request_id: &str,
) -> TestResult<Retained> {
    let capability =
        kernel.issue_capability(&Keypair::generate().public_key(), paid_scope(), 300)?;
    let mut request = paid_request(&capability);
    request.request_id = request_id.to_owned();
    let authorizations = calls.authorizations.load(Ordering::SeqCst);
    calls.fail_next_capture.store(true, Ordering::SeqCst);
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .err()
        .ok_or("original capture interruption")?;
    ordinary_operation::assert_interrupted_payment(&error, "injected capture interruption")?;
    assert_eq!(
        calls.authorizations.load(Ordering::SeqCst),
        authorizations + 1
    );
    let reference = calls
        .authorization_references
        .lock()
        .map_err(|_| "authorization trace lock")?
        .last()
        .cloned()
        .ok_or("original authorization reference")?;
    let operation = ordinary_operation::from_rail_reference(
        serving.operations.as_ref(),
        &serving.fence,
        &request,
        &reference,
    )?;
    assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
    assert_eq!(
        retained_signer(serving, &operation)?,
        serde_json::to_value(signer.public_key())?
    );
    Ok(Retained {
        signer,
        request,
        operation,
    })
}

/// Two kernels on one serving owner, each with its own receipt signer, finish
/// startup before either leaves a retained operation.
fn retain_under_two_signers(
    database: &std::path::Path,
    locks: &std::path::Path,
    clock: &Arc<SweepClock>,
) -> TestResult<(Retained, Retained)> {
    let serving = Serving::open(database, locks, clock)?;
    let calls = Arc::new(PaymentCalls::default());
    let invocations = Arc::new(AtomicU64::new(0));
    let (first_signer, second_signer) = (Keypair::generate(), Keypair::generate());
    let first_kernel = signing_kernel(&serving, clock, &first_signer, &calls, &invocations)?;
    let second_kernel = signing_kernel(&serving, clock, &second_signer, &calls, &invocations)?;
    assert_eq!(first_kernel.reconcile_durable_admission_startup()?, 0);
    assert_eq!(second_kernel.reconcile_durable_admission_startup()?, 0);
    let first = retain(
        &serving,
        &first_kernel,
        &calls,
        first_signer,
        "signer-identity-first",
    )?;
    let second = retain(
        &serving,
        &second_kernel,
        &calls,
        second_signer,
        "signer-identity-second",
    )?;
    assert_eq!(invocations.load(Ordering::SeqCst), 2);
    Ok((first, second))
}

fn retained_signer(
    serving: &Serving,
    operation: &AdmissionOperationV1,
) -> TestResult<serde_json::Value> {
    let raw = serving
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(operation.binding().operation_id())?
        .ok_or("retained raw return")?;
    let identity = raw
        .to_persisted()
        .receipt_signing_identity
        .ok_or("retained receipt signing identity")?;
    Ok(serde_json::to_value(identity)?["public_key"].clone())
}

fn state(serving: &Serving, retained: &Retained) -> TestResult<AdmissionOperationState> {
    Ok(serving
        .operations
        .load_by_operation_id(retained.operation.binding().operation_id())?
        .ok_or("retained operation")?
        .state())
}

fn journal(serving: &Serving, retained: &Retained) -> TestResult<PaymentJournalState> {
    Ok(serving
        .operations
        .load_payment_journal(
            retained.operation.binding().operation_id().as_str(),
            &serving.fence,
        )?
        .ok_or("retained payment journal")?
        .state)
}

fn status(
    serving: &Serving,
    clock: &SweepClock,
    retained: &Retained,
) -> TestResult<Option<AdmissionRecoveryStatusV1>> {
    Ok(serving.operations.load_recovery_status(
        retained.operation.binding().operation_id(),
        &serving.fence,
        clock.now_ms()?,
    )?)
}

#[test]
fn sqlite_replaced_signer_defers_its_operation_and_recovers_the_next() -> TestResult {
    let (_directory, database, locks) = provision()?;
    let clock = SweepClock::new()?;
    let (first, second) = retain_under_two_signers(&database, &locks, &clock)?;
    // The restarted kernel selects the signer of whichever operation sorts
    // second, so the operation whose signer it lacks is visited first.
    let (replaced, healthy) =
        if first.operation.binding().operation_id() < second.operation.binding().operation_id() {
            (first, second)
        } else {
            (second, first)
        };
    let calls = Arc::new(PaymentCalls::default());
    let invocations = Arc::new(AtomicU64::new(0));
    let serving = Serving::open(&database, &locks, &clock)?;
    let kernel = signing_kernel(&serving, &clock, &healthy.signer, &calls, &invocations)?;
    assert_eq!(
        serde_json::to_value(kernel.receipt_signing_public_key())?,
        retained_signer(&serving, &healthy.operation)?
    );
    assert_ne!(
        serde_json::to_value(kernel.receipt_signing_public_key())?,
        retained_signer(&serving, &replaced.operation)?
    );
    let page = serving
        .operations
        .recovery_page(AdmissionRecoveryPageQuery {
            not_after_unix_ms: clock.now_ms()?,
            candidate_limit: 256,
            after_operation_id: None,
            fence: &serving.fence,
        })?;
    assert_eq!(
        page.operations,
        vec![replaced.operation.clone(), healthy.operation.clone()]
    );
    assert_eq!(page.next_cursor, None);
    for retained in [&replaced, &healthy] {
        assert_eq!(
            state(&serving, retained)?,
            AdmissionOperationState::Finalizing
        );
        assert_eq!(journal(&serving, retained)?, PaymentJournalState::Settling);
        assert_eq!(status(&serving, &clock, retained)?, None);
    }

    let result = kernel.reconcile_durable_admission_startup();
    let healthy_after = state(&serving, &healthy)?;
    let recovered = result.map_err(|error| {
        format!("startup recovery aborted with {error:?}; later operation left {healthy_after:?}")
    })?;
    assert_eq!(recovered, 1);
    assert_eq!(healthy_after, AdmissionOperationState::Completed);
    assert_eq!(journal(&serving, &healthy)?, PaymentJournalState::Settled);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
    let replay = kernel.evaluate_tool_call_blocking(&healthy.request)?;
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(replay.receipt.kernel_key, healthy.signer.public_key());
    assert!(replay.receipt.verify_signature()?);

    assert_eq!(
        state(&serving, &replaced)?,
        AdmissionOperationState::Finalizing
    );
    assert_eq!(journal(&serving, &replaced)?, PaymentJournalState::Settling);
    let deferred = status(&serving, &clock, &replaced)?.ok_or("replaced signer deferral")?;
    assert!(deferred.quarantined);
    assert_eq!(
        deferred.deferral.failure_kind,
        AdmissionRecoveryFailureKind::ContractChanged
    );
    assert_eq!(deferred.deferral.phase, AdmissionRecoveryPhase::Returned);
    assert_eq!(deferred.deferral.attempt_count, 1);
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
    let capability = kernel.issue_capability(&Keypair::generate().public_key(), scope(), 300)?;
    let mut fresh = request(&capability);
    fresh.request_id = "signer-identity-fresh".into();
    assert_eq!(
        kernel.evaluate_tool_call_blocking(&fresh)?.verdict,
        Verdict::Allow
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        state(&serving, &replaced)?,
        AdmissionOperationState::Finalizing
    );
    assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
    drop(kernel);
    drop(serving);

    // Restoring the original signer resumes the retained operation once its
    // retry is due.
    let due = deferred
        .deferral
        .retry_not_before_unix_ms
        .checked_sub(clock.now_ms()?)
        .ok_or("retry already due")?;
    clock.advance_ms(due + 1_000)?;
    let serving = Serving::open(&database, &locks, &clock)?;
    let restored = signing_kernel(&serving, &clock, &replaced.signer, &calls, &invocations)?;
    assert_eq!(restored.reconcile_durable_admission_startup()?, 1);
    assert_eq!(
        state(&serving, &replaced)?,
        AdmissionOperationState::Completed
    );
    assert_eq!(journal(&serving, &replaced)?, PaymentJournalState::Settled);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 2);
    assert!(
        !status(&serving, &clock, &replaced)?
            .ok_or("retained clear tombstone")?
            .quarantined
    );
    let replay = restored.evaluate_tool_call_blocking(&replaced.request)?;
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(replay.receipt.kernel_key, replaced.signer.public_key());
    assert!(replay.receipt.verify_signature()?);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
