//! Real kernel commit before a separately persisted executor claim.
use super::*;
use chio_core::crypto::Keypair;
use chio_kernel::admission_operation::AdmissionIdentifier;
use chio_kernel::caller_delivery::{
    CallerExecutorIdentityV1, SignedCallerDeliveryReportV1, SignedCallerDispatchAuthorizationV1,
};
use chio_kernel::CallerStartResponse;
use chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger;

#[cfg(unix)]
#[path = "authenticated/process_loss.rs"]
mod process_loss;

#[path = "authenticated/negative_controls.rs"]
mod negative_controls;

#[path = "authenticated/monetary.rs"]
mod monetary;

#[path = "authenticated/financial_receipt.rs"]
mod financial_receipt;

#[path = "authenticated/payment_custody.rs"]
mod payment_custody;

#[path = "authenticated/payment_credentials.rs"]
mod payment_credentials;

#[path = "authenticated/request_identity.rs"]
mod request_identity;

#[path = "authenticated/private_evidence.rs"]
mod private_evidence;

pub(super) fn fixture() -> TestResult<(Fixture, Keypair)> {
    let mut fixture = Fixture::with_nonce_ttl(300)?;
    let executor = Keypair::generate();
    fixture.caller_executor = Some(CallerExecutorIdentityV1 {
        executor_id: AdmissionIdentifier::try_new("executor_id", "trusted-test-executor")?,
        public_key: executor.public_key(),
        key_epoch: 42,
    });
    SqliteCallerExecutionLedger::provision_with_clock(
        &fixture.directory.path().join("executor.db"),
        fixture.caller_executor.clone().ok_or("executor")?,
        64,
        chio_test_support::clock::clock(),
    )?;
    Ok((fixture, executor))
}

pub(super) fn deliver(
    fixture: &Fixture,
    key: &Keypair,
    runtime: &Runtime,
    request: &ToolCallRequest,
) -> TestResult<(
    SignedCallerDispatchAuthorizationV1,
    SignedCallerDeliveryReportV1,
)> {
    let authorization = start(runtime, request)?;
    let ledger = ledger(fixture)?;
    let report = ledger.execute_once(
        &authorization,
        &fixture.signer.public_key(),
        &authorization.authorization.invocation,
        key,
        || Ok(super::report()),
    )?;
    Ok((authorization, report))
}

pub(super) fn ledger(fixture: &Fixture) -> TestResult<SqliteCallerExecutionLedger> {
    Ok(SqliteCallerExecutionLedger::open_with_clock(
        &fixture.directory.path().join("executor.db"),
        fixture.caller_executor.clone().ok_or("executor")?,
        chio_test_support::clock::clock(),
    )?)
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
    let (fixture, executor_key) = fixture()?;
    let ledger = ledger(&fixture)?;
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
    let _clock = chio_test_support::clock::scope_unix_secs(expires + 1);
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
    let refused = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &altered);
    assert!(
        matches!(refused, Err(chio_kernel::KernelError::DurableAdmission(reason))
        if reason == "caller delivery signature is invalid")
    );
    let altered = chio_kernel::caller_delivery::SignedCallerDeliveryReportV1::sign(
        altered.report,
        &executor_key,
    )?;
    let refused = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &altered);
    assert!(
        matches!(refused, Err(chio_kernel::KernelError::DurableAdmission(reason))
        if reason == "caller report conflicts with retained authenticated delivery")
    );
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
    let (fixture, key) = fixture()?;
    let runtime = fixture.open()?;
    let request = reserve(&fixture, &runtime, "authenticated-start")?;
    assert_eq!(grant_quota(&runtime, &request)?, (1, 0));
    let authorization = start(&runtime, &request)?;
    assert_state(&fixture, &request, "dispatch_committed")?;
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(authorization.authorization.executor.key_epoch, 42);
    assert_eq!(authorization, start(&runtime, &request)?);
    let refused = runtime.kernel.start_caller_execution_blocking(
        request.execution_nonce.as_ref().ok_or("nonce")?,
        &serde_json::json!({"different": true}),
    );
    assert!(
        matches!(refused, Err(chio_kernel::KernelError::DurableAdmission(reason))
        if reason == "caller start arguments differ from the original request")
    );
    let (_, mut report) = deliver(&fixture, &key, &runtime, &request)?;
    report.report.output = serde_json::json!({"substituted": true});
    let refused = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report);
    assert!(
        matches!(refused, Err(chio_kernel::KernelError::DurableAdmission(reason))
        if reason == "caller delivery signature is invalid")
    );
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    Ok(())
}
