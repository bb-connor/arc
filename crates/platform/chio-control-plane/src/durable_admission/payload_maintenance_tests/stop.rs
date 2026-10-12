//! A durable operator stop holds across a restart and denies until resumed.
use chio_kernel::stop::{
    ResumeCommand, StopAuthorizer, StopCommand, StopReadiness, StopRequestPath,
};

use super::*;

fn stop_command() -> StopCommand {
    StopCommand {
        reason: "incident drill".to_owned(),
        authorizer: StopAuthorizer::shared_credential("durable-admission-test"),
        requested_via: StopRequestPath::OfflineCli,
        allow_containment: true,
    }
}

#[test]
fn durable_stop_survives_restart_denies_and_resumes() -> TestResult {
    let directory = private_tempdir()?;
    let database = directory.path().join("stop.db");
    let calls = Arc::new(AtomicU64::new(0));
    let runtime =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let kernel = configured_kernel(&runtime, calls.clone())?;
    let sibling = configured_kernel(&runtime, calls.clone())?;
    let status = runtime.stop_control().stop(stop_command())?;
    assert_eq!(status.durability, "durable");
    assert!(kernel.is_emergency_stopped() && sibling.is_emergency_stopped());
    drop(sibling);
    drop(kernel);
    drop(runtime);

    let reopened =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let control = reopened.stop_control();
    assert_eq!(control.status().readiness, StopReadiness::ReadyStopped);
    let kernel = configured_kernel(&reopened, calls.clone())?;
    let request = request_with_credentials(&kernel, &reopened.kernel_keypair(), "after-restart")?;
    let denied = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let head = control.status().head.ok_or("stopped head missing")?;
    let resumed = control.resume(ResumeCommand {
        expected_epoch: Some(chio_kernel::stop::StopEpochId {
            chain_generation: head.chain_generation,
            epoch: head.epoch,
        }),
        authorizer: StopAuthorizer::shared_credential("durable-admission-test"),
        requested_via: StopRequestPath::OfflineCli,
    })?;
    assert!(!resumed.stopped);
    let request = request_with_credentials(&kernel, &reopened.kernel_keypair(), "after-resume")?;
    let allowed = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(allowed.verdict, Verdict::Allow, "{:?}", allowed.reason);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}
