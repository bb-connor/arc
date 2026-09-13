//! Real kernel commit before a separately persisted executor claim.
use super::*;
use chio_core::crypto::Keypair;
use chio_kernel::admission_operation::AdmissionIdentifier;
use chio_kernel::caller_delivery::{CallerExecutorIdentityV1, SignedCallerDispatchAuthorizationV1};
use chio_kernel::CallerStartResponse;

#[cfg(unix)]
#[path = "authenticated/process_loss.rs"]
mod process_loss;

#[path = "authenticated/negative_controls.rs"]
mod negative_controls;

#[path = "authenticated/monetary.rs"]
mod monetary;

#[path = "authenticated/private_evidence.rs"]
mod private_evidence;

pub(super) fn fixture() -> TestResult<(Fixture, Keypair)> {
    let mut fixture = Fixture::with_nonce_ttl(300)?;
    let executor = Keypair::generate();
    fixture.caller_executor = Some(CallerExecutorIdentityV1 {
        executor_id: AdmissionIdentifier::try_new("executor_id", "trusted-test-executor")?,
        public_key: executor.public_key(),
        // Deliberately unrelated to the authority's coordinator lease epoch.
        key_epoch: 42,
    });
    Ok((fixture, executor))
}

pub(super) fn start(
    runtime: &Runtime,
    request: &ToolCallRequest,
) -> TestResult<SignedCallerDispatchAuthorizationV1> {
    match runtime.kernel.start_caller_execution_blocking(
        request.execution_nonce.as_ref().ok_or("nonce")?,
        &request.arguments,
    )? {
        CallerStartResponse::Authorized(authorization) => Ok(*authorization),
        CallerStartResponse::Denied(response) => {
            Err(format!("start denied: {:?}", response.reason).into())
        }
    }
}

#[test]
fn authenticated_report_finalizes_after_expiry_and_restart_without_readmission() -> TestResult {
    use chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger;
    let (fixture, executor_key) = fixture()?;
    let executor = fixture.caller_executor.clone().ok_or("executor")?;
    let ledger_path = fixture.directory.path().join("executor.db");
    let ledger = SqliteCallerExecutionLedger::provision(&ledger_path, executor.clone(), 4)?;
    let (request, authorization, report) = {
        let runtime = fixture.open()?;
        let request = reserve(&fixture, &runtime, "late-authenticated-report")?;
        let authorization = start(&runtime, &request)?;
        let report = ledger.execute_once(
            &authorization,
            &fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &executor_key,
            || Ok(super::report()),
        )?;
        (request, authorization, report)
    };
    drop(ledger);
    let expires = request.capability.expires_at.max(u64::try_from(
        request
            .execution_nonce
            .as_ref()
            .ok_or("nonce")?
            .expires_at(),
    )?);
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(expires + 1, []);
    let runtime = fixture.open()?;
    assert_state(&fixture, &request, "awaiting_caller_report")?;
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    assert_eq!(
        authorization,
        start(&runtime, &request)?,
        "recovery cannot renew the old interval"
    );
    let settled = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert_state(&fixture, &request, "completed")?;
    let replay = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(canonical(&settled.receipt)?, canonical(&replay.receipt)?);
    let mut altered = report.clone();
    altered.report.output = serde_json::json!({"substituted": true});
    assert!(runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &altered)
        .is_err());
    // Even a second authentic observation cannot replace the first claim.
    let altered = chio_kernel::caller_delivery::SignedCallerDeliveryReportV1::sign(
        altered.report,
        &executor_key,
    )?;
    assert!(runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &altered)
        .is_err());
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    drop(runtime);
    let reopened = fixture.open()?;
    let replay = reopened
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(canonical(&settled.receipt)?, canonical(&replay.receipt)?);
    Ok(())
}

#[test]
fn start_captures_before_publication_and_retries_original_authorization() -> TestResult {
    let (fixture, _) = fixture()?;
    let runtime = fixture.open()?;
    let request = reserve(&fixture, &runtime, "authenticated-start")?;
    assert_eq!(grant_quota(&runtime, &request)?, (1, 0));
    let authorization = start(&runtime, &request)?;
    assert_state(&fixture, &request, "dispatch_committed")?;
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(authorization.authorization.executor.key_epoch, 42);
    assert_eq!(authorization, start(&runtime, &request)?);
    assert!(runtime
        .kernel
        .start_caller_execution_blocking(
            request.execution_nonce.as_ref().ok_or("nonce")?,
            &serde_json::json!({"different": true}),
        )
        .is_err());
    assert!(
        reconcile(&runtime, &request).is_err(),
        "unsigned report must not bypass start"
    );
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    Ok(())
}
