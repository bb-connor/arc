//! Actual kernel start and durable executor claim before an external effect.
//! The reservation-only calibration below remains deliberately non-authoritative.

use super::*;
use chio_kernel::admission_operation::{AdmissionIdentifier, AdmissionOperationStore};
use chio_kernel::KernelError;
use chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn an_external_effect_with_a_lost_report_cannot_be_refunded_at_nonce_expiry() -> TestResult {
    let (fixture, executor_key) = super::authenticated::fixture()?;
    let effect = fixture.directory.path().join("external-effect");
    let ledger = SqliteCallerExecutionLedger::provision(
        &fixture.directory.path().join("executor.db"),
        fixture.caller_executor.clone().ok_or("executor")?,
        4,
    )?;
    let execution = {
        let runtime = fixture.open()?;
        let execution = reserve(&fixture, &runtime, "external-effect-report-lost")?;
        let observed_at_ms =
            u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        let selector = AdmissionIdentifier::try_new("request_id", execution.request_id.clone())?;
        let (operation, _) = runtime
            .authority
            .admission_operation_store()
            .load_unambiguous_retained_tool_request(
                &selector,
                &runtime.authority.mutation_fence(),
                observed_at_ms,
            )?
            .ok_or("retained caller operation")?;
        let reservation = runtime
            .authority
            .admission_operation_store()
            .load_execution_nonce_reservation(
                operation.binding().operation_id(),
                &runtime.authority.mutation_fence(),
                observed_at_ms,
            )?
            .ok_or("physical nonce reservation")?;
        assert_eq!(
            canonical(reservation.signed_nonce())?,
            canonical(execution.execution_nonce.as_ref().ok_or("reserved nonce")?)?,
            "the effect follows the actual authority-issued reservation"
        );

        let authorization = super::authenticated::start(&runtime, &execution)?;
        assert_eq!(
            grant_quota(&runtime, &execution)?,
            (0, 1),
            "capture precedes effect"
        );
        // A real effect, under a permanent independent executor claim. The
        // report is persisted at the executor but never reaches the kernel.
        let _lost_report = ledger.execute_once(
            &authorization,
            &fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &executor_key,
            || {
                let write_effect = || -> std::io::Result<()> {
                    let mut external = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&effect)?;
                    external.write_all(b"external effect committed\n")?;
                    external.sync_all()
                };
                write_effect().map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                Ok(report())
            },
        )?;
        assert!(effect.metadata()?.len() > 0);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        execution
    };
    let expiry = u64::try_from(
        execution
            .execution_nonce
            .as_ref()
            .ok_or("reserved nonce")?
            .expires_at(),
    )?;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(
        expiry.checked_add(1).ok_or("expiry overflow")?,
        [],
    );
    let runtime = fixture.open()?;
    assert!(
        effect.metadata()?.len() > 0,
        "the external effect survives restart"
    );
    let retained_usage = grant_quota(&runtime, &execution)?;
    let mut repeated = execution.clone();
    repeated.request_id = "external-effect-second-operation".into();
    repeated.execution_nonce = None;
    let second = runtime
        .kernel
        .reserve_caller_execution_blocking(&repeated)?;
    assert_eq!(
        (retained_usage, second.verdict),
        ((0, 1), Verdict::Deny),
        "report loss and expiry must retain capture and deny another call under the same quota"
    );
    assert_state(&fixture, &execution, "awaiting_caller_report")?;
    Ok(())
}

/// Calibration: treating a reservation as permission reproduces the old bad
/// outcome. This intentionally bypasses start and the executor, and must never
/// be used as an example of authorized execution.
#[test]
fn reservation_only_effect_reproduces_the_original_refund_counterexample() -> TestResult {
    let fixture = Fixture::with_nonce_ttl(300)?;
    let effect = fixture.directory.path().join("unauthorized-effect");
    let execution = {
        let runtime = fixture.open()?;
        let execution = reserve(&fixture, &runtime, "bad-reservation-only-caller")?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&effect)?;
        file.write_all(b"effect without start permission\n")?;
        file.sync_all()?;
        execution
    };
    let expires = u64::try_from(
        execution
            .execution_nonce
            .as_ref()
            .ok_or("nonce")?
            .expires_at(),
    )?;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(expires + 1, []);
    let runtime = fixture.open()?;
    assert!(effect.metadata()?.len() > 0);
    let usage = grant_quota(&runtime, &execution)?;
    let mut repeated = execution.clone();
    repeated.request_id = "bad-caller-second-operation".into();
    repeated.execution_nonce = None;
    let response = runtime
        .kernel
        .reserve_caller_execution_blocking(&repeated)?;
    assert_eq!(
        (usage, response.verdict),
        ((0, 0), Verdict::Allow),
        "calibration must still distinguish the old reservation-only failure"
    );
    Ok(())
}
