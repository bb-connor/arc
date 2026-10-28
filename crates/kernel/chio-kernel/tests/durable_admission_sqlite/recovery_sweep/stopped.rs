//! A host restarted during a durable stop retains every returned operation:
//! the sweep neither releases its output nor records a deferral, and resume
//! releases it exactly once.
use super::signer_identity::{journal, retain, signing_kernel, state, status};
use super::*;
use chio_kernel::stop::{
    ResumeCommand, StopAuthorizer, StopCommand, StopControl, StopEpochId, StopReadiness,
    StopRequestPath,
};

fn authorizer() -> StopAuthorizer {
    StopAuthorizer::shared_credential("recovery-sweep-test")
}

#[test]
fn sqlite_restart_while_stopped_retains_finalizing_work_until_resume() -> TestResult {
    let (_directory, database, locks) = provision()?;
    let clock = SweepClock::new()?;
    let calls = Arc::new(PaymentCalls::default());
    let invocations = Arc::new(AtomicU64::new(0));
    let signer = Keypair::generate();
    let retained = {
        let serving = Serving::open(&database, &locks, &clock)?;
        let kernel = signing_kernel(&serving, &clock, &signer, &calls, &invocations)?;
        assert_eq!(kernel.reconcile_durable_admission_startup()?, 0);
        let retained = retain(
            &serving,
            &kernel,
            &calls,
            signer.clone(),
            "stopped-sweep-retained",
        )?;
        let stopped =
            StopControl::durable(&serving.operations, serving.fence.clone()).stop(StopCommand {
                reason: "operator stop before restart".into(),
                authorizer: authorizer(),
                requested_via: StopRequestPath::OfflineCli,
                allow_containment: false,
            })?;
        assert!(stopped.stopped);
        assert_eq!(stopped.durability, "durable");
        retained
    };

    let calls = Arc::new(PaymentCalls::default());
    let serving = Serving::open(&database, &locks, &clock)?;
    let control = StopControl::durable(&serving.operations, serving.fence.clone());
    assert_eq!(control.status().readiness, StopReadiness::ReadyStopped);
    assert_eq!(control.status().withheld_operations, Some(1));
    let mut kernel = signing_kernel(&serving, &clock, &signer, &calls, &invocations)?;
    kernel.set_stop_control(control.clone());

    assert_eq!(kernel.reconcile_durable_admission_startup()?, 0);
    assert_eq!(kernel.reconcile_recoverable_admissions_batch(256)?, 0);
    assert_eq!(
        state(&serving, &retained)?,
        AdmissionOperationState::Finalizing
    );
    assert_eq!(journal(&serving, &retained)?, PaymentJournalState::Settling);
    assert_eq!(status(&serving, &clock, &retained)?, None);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(control.status().withheld_operations, Some(1));

    let head = control.status().head.ok_or("stopped head")?;
    let resumed = control.resume(ResumeCommand {
        expected_epoch: Some(StopEpochId {
            chain_generation: head.chain_generation,
            epoch: head.epoch,
        }),
        authorizer: authorizer(),
        requested_via: StopRequestPath::OfflineCli,
    })?;
    assert!(!resumed.stopped);
    assert_eq!(resumed.withheld_operations, None);
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 1);
    assert_eq!(
        state(&serving, &retained)?,
        AdmissionOperationState::Completed
    );
    assert_eq!(journal(&serving, &retained)?, PaymentJournalState::Settled);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
    let restopped = control.stop(StopCommand {
        reason: "operator stop after release".into(),
        authorizer: authorizer(),
        requested_via: StopRequestPath::OfflineCli,
        allow_containment: false,
    })?;
    assert_eq!(restopped.withheld_operations, Some(0));
    let head = restopped.head.ok_or("restopped head")?;
    control.resume(ResumeCommand {
        expected_epoch: Some(StopEpochId {
            chain_generation: head.chain_generation,
            epoch: head.epoch,
        }),
        authorizer: authorizer(),
        requested_via: StopRequestPath::OfflineCli,
    })?;

    let replay = kernel.evaluate_tool_call_blocking(&retained.request)?;
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(replay.receipt.kernel_key, signer.public_key());
    assert!(replay.receipt.verify_integrity_embedded_key()?);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

struct StopOnCapture {
    inner: ReversiblePaymentAdapter,
    control: StopControl,
    armed: AtomicBool,
}

impl PaymentAdapter for StopOnCapture {
    fn rail_id(&self) -> &'static str {
        self.inner.rail_id()
    }
    fn rail_mode(&self) -> Option<PaymentRailMode> {
        self.inner.rail_mode()
    }
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.inner.authorize(request)
    }
    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        let result = self
            .inner
            .capture(authorization_id, amount_units, currency, reference)?;
        if self.armed.swap(false, Ordering::SeqCst) {
            self.control
                .stop(StopCommand {
                    reason: "stop after capture acknowledgement".into(),
                    authorizer: authorizer(),
                    requested_via: StopRequestPath::OfflineCli,
                    allow_containment: false,
                })
                .map_err(|error| PaymentError::Unavailable(error.to_string()))?;
        }
        Ok(result)
    }
    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.inner.release(authorization_id, reference)
    }
    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.inner
            .refund(transaction_id, amount_units, currency, reference)
    }
    fn replayed_authorization_metadata(
        &self,
        authorization_id: &str,
    ) -> Result<serde_json::Value, PaymentError> {
        self.inner.replayed_authorization_metadata(authorization_id)
    }
}

#[test]
fn sqlite_stop_after_capture_refuses_terminal_transaction_until_resume() -> TestResult {
    let (_directory, database, locks) = provision()?;
    let clock = SweepClock::new()?;
    let calls = Arc::new(PaymentCalls::default());
    let invocations = Arc::new(AtomicU64::new(0));
    let signer = Keypair::generate();
    let serving = Serving::open(&database, &locks, &clock)?;
    let mut kernel = signing_kernel(&serving, &clock, &signer, &calls, &invocations)?;
    assert_eq!(kernel.reconcile_durable_admission_startup()?, 0);
    let retained = retain(
        &serving,
        &kernel,
        &calls,
        signer,
        "stop-terminal-transaction",
    )?;
    let control = StopControl::durable(&serving.operations, serving.fence.clone());
    kernel.set_payment_adapter(Box::new(StopOnCapture {
        inner: ReversiblePaymentAdapter {
            calls: Some(calls.clone()),
        },
        control: control.clone(),
        armed: AtomicBool::new(true),
    }));
    let terminal_rows = || -> TestResult<i64> {
        let connection = rusqlite::Connection::open_with_flags(
            &database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        Ok(connection.query_row(
            "SELECT COUNT(*) FROM admission_operation_terminal_projections WHERE operation_id = ?1",
            [retained.operation.binding().operation_id().as_str()],
            |row| row.get(0),
        )?)
    };
    assert!(!kernel.is_emergency_stopped());
    let result = kernel.evaluate_tool_call_blocking(&retained.request);
    assert!(
        matches!(result, Err(KernelError::OutputWithheld)),
        "{result:?}"
    );
    assert!(!kernel.is_emergency_stopped());
    assert_eq!(control.status().readiness, StopReadiness::ReadyStopped);
    assert_eq!(
        state(&serving, &retained)?,
        AdmissionOperationState::Finalizing
    );
    assert!(kernel.receipt_log().is_empty());
    assert_eq!(terminal_rows()?, 0);
    assert_eq!(status(&serving, &clock, &retained)?, None);
    assert_eq!(kernel.reconcile_recoverable_admissions_batch(256)?, 0);
    assert_eq!(status(&serving, &clock, &retained)?, None);
    assert_eq!(
        state(&serving, &retained)?,
        AdmissionOperationState::Finalizing
    );
    assert!(kernel.receipt_log().is_empty());
    assert_eq!(terminal_rows()?, 0);
    let captures = calls.captures.load(Ordering::SeqCst);
    let head = control.status().head.ok_or("stopped head")?;
    control.resume(ResumeCommand {
        expected_epoch: Some(StopEpochId {
            chain_generation: head.chain_generation,
            epoch: head.epoch,
        }),
        authorizer: authorizer(),
        requested_via: StopRequestPath::OfflineCli,
    })?;
    let released = kernel.evaluate_tool_call_blocking(&retained.request)?;
    assert_eq!(released.verdict, Verdict::Allow);
    assert!(released.output.is_some());
    assert!(released.receipt.verify_integrity_embedded_key()?);
    assert_eq!(
        released
            .receipt
            .metadata
            .as_ref()
            .ok_or("receipt metadata")?["chio_runtime"]["identity_disposition"],
        "terminal"
    );
    assert_eq!(
        state(&serving, &retained)?,
        AdmissionOperationState::Completed
    );
    assert_eq!(terminal_rows()?, 1);
    assert_eq!(calls.captures.load(Ordering::SeqCst), captures);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
