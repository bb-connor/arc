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
